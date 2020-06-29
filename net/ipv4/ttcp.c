/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TTCP).
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TTCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TTCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TTCP_ESTABLISHED		connection established
 *
 *	TTCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TTCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TTCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TTCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TTCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TTCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TTCP_CLOSE		socket is finished
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/splice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/time.h>
#include <linux/slab.h>

#include <net/icmp.h>
#include <net/ttcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/netdma.h>
#include <net/sock.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

int sysctl_ttcp_fin_timeout __read_mostly = TTCP_FIN_TIMEOUT;

struct percpu_counter ttcp_orphan_count;
EXPORT_SYMBOL_GPL(ttcp_orphan_count);

long sysctl_ttcp_mem[3] __read_mostly;
int sysctl_ttcp_wmem[3] __read_mostly;
int sysctl_ttcp_rmem[3] __read_mostly;

EXPORT_SYMBOL(sysctl_ttcp_mem);
EXPORT_SYMBOL(sysctl_ttcp_rmem);
EXPORT_SYMBOL(sysctl_ttcp_wmem);

atomic_long_t ttcp_memory_allocated;	/* Current allocated memory. */
EXPORT_SYMBOL(ttcp_memory_allocated);

/*
 * Current number of TTCP sockets.
 */
struct percpu_counter ttcp_sockets_allocated;
EXPORT_SYMBOL(ttcp_sockets_allocated);

/*
 * TTCP splice context
 */
struct ttcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int ttcp_memory_pressure __read_mostly;
EXPORT_SYMBOL(ttcp_memory_pressure);

void ttcp_enter_memory_pressure(struct sock *sk)
{
	if (!ttcp_memory_pressure) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMEMORYPRESSURES);
		ttcp_memory_pressure = 1;
	}
}
EXPORT_SYMBOL(ttcp_enter_memory_pressure);

/* Convert seconds to retransmits based on initial and max timeout */
static u8 secs_to_retrans(int seconds, int timeout, int rto_max)
{
	u8 res = 0;

	if (seconds > 0) {
		int period = timeout;

		res = 1;
		while (seconds > period && res < 255) {
			res++;
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return res;
}

/* Convert retransmits to seconds based on initial and max timeout */
static int retrans_to_secs(u8 retrans, int timeout, int rto_max)
{
	int period = 0;

	if (retrans > 0) {
		period = timeout;
		while (--retrans) {
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return period;
}

/*
 *	Wait for a TTCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int ttcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct ttcp_sock *tp = ttcp_sk(sk);

	sock_poll_wait(file, sk_sleep(sk), wait);
	if (sk->sk_state == TTCP_LISTEN)
		return inet_csk_listen_poll(sk);

	/* Socket is not locked. We are protected from async events
	 * by poll logic and correct handling of state changes
	 * made by other threads is impossible in any case.
	 */

	mask = 0;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if POLLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why POLLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TTCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TTCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TTCPF_SYN_SENT | TTCPF_SYN_RECV)) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);

		if (tp->urg_seq == tp->copied_seq &&
		    !sock_flag(sk, SOCK_URGINLINE) &&
		    tp->urg_data)
			target++;

		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if (tp->rcv_nxt - tp->copied_seq >= target)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		} else
			mask |= POLLOUT | POLLWRNORM;

		if (tp->urg_data & TTCP_URG_VALID)
			mask |= POLLPRI;
	}
	/* This barrier is coupled with smp_wmb() in ttcp_reset() */
	smp_rmb();
	if (sk->sk_err)
		mask |= POLLERR;

	return mask;
}
EXPORT_SYMBOL(ttcp_poll);

int ttcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	int answ;

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TTCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TTCPF_SYN_SENT | TTCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !tp->urg_data ||
			 before(tp->urg_seq, tp->copied_seq) ||
			 !before(tp->urg_seq, tp->rcv_nxt)) {
			struct sk_buff *skb;

			answ = tp->rcv_nxt - tp->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			skb = skb_peek_tail(&sk->sk_receive_queue);
			if (answ && skb)
				answ -= ttcp_hdr(skb)->fin;
		} else
			answ = tp->urg_seq - tp->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TTCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TTCPF_SYN_SENT | TTCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	case SIOCOUTQNSD:
		if (sk->sk_state == TTCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TTCPF_SYN_SENT | TTCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_nxt;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return put_user(answ, (int __user *)arg);
}
EXPORT_SYMBOL(ttcp_ioctl);

static inline void ttcp_mark_push(struct ttcp_sock *tp, struct sk_buff *skb)
{
	TTCP_SKB_CB(skb)->flags |= TTCPHDR_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct ttcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	struct ttcp_skb_cb *tcb = TTCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->flags   = TTCPHDR_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	ttcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	if (tp->nonagle & TTCP_NAGLE_PUSH)
		tp->nonagle &= ~TTCP_NAGLE_PUSH;
}

static inline void ttcp_mark_urg(struct ttcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;
}

static inline void ttcp_push(struct sock *sk, int flags, int mss_now,
			    int nonagle)
{
	if (ttcp_send_head(sk)) {
		struct ttcp_sock *tp = ttcp_sk(sk);

		if (!(flags & MSG_MORE) || forced_push(tp))
			ttcp_mark_push(tp, ttcp_write_queue_tail(sk));

		ttcp_mark_urg(tp, flags);
		__ttcp_push_pending_frames(sk, mss_now,
					  (flags & MSG_MORE) ? TTCP_NAGLE_CORK : nonagle);
	}
}

static int ttcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct ttcp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, offset, tss->pipe, min(rd_desc->count, len),
			      tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

static int __ttcp_splice_read(struct sock *sk, struct ttcp_splice_state *tss)
{
	/* Store TTCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return ttcp_read_sock(sk, &rd_desc, ttcp_splice_data_recv);
}

/**
 *  ttcp_splice_read - splice data from TTCP socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t ttcp_splice_read(struct socket *sock, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct ttcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

	sock_rps_record_flow(sk);
	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);
	while (tss.len) {
		ret = __ttcp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TTCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TTCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}
EXPORT_SYMBOL(ttcp_splice_read);

static unsigned int ttcp_xmit_size_goal(struct sock *sk, u32 mss_now,
				       int large_allowed)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	u32 xmit_size_goal, old_size_goal;

	xmit_size_goal = mss_now;

	if (large_allowed && sk_can_gso(sk)) {
		xmit_size_goal = ((sk->sk_gso_max_size - 1) -
				  inet_csk(sk)->icsk_af_ops->net_header_len -
				  inet_csk(sk)->icsk_ext_hdr_len -
				  tp->ttcp_header_len);

		xmit_size_goal = ttcp_bound_to_half_wnd(tp, xmit_size_goal);

		/* We try hard to avoid divides here */
		old_size_goal = tp->xmit_size_goal_segs * mss_now;

		if (likely(old_size_goal <= xmit_size_goal &&
			   old_size_goal + mss_now > xmit_size_goal)) {
			xmit_size_goal = old_size_goal;
		} else {
			tp->xmit_size_goal_segs = xmit_size_goal / mss_now;
			xmit_size_goal = tp->xmit_size_goal_segs * mss_now;
		}
	}

	return max(xmit_size_goal, mss_now);
}

static int ttcp_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	mss_now = ttcp_current_mss(sk);
	*size_goal = ttcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));

	return mss_now;
}

static ssize_t do_ttcp_sendpages(struct sock *sk, struct page **pages, int poffset,
			 size_t psize, int flags)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TTCPF_ESTABLISHED | TTCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = ttcp_send_mss(sk, &size_goal, flags);
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	while (psize > 0) {
		struct sk_buff *skb = ttcp_write_queue_tail(sk);
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!ttcp_send_head(sk) || (copy = size_goal - skb->len) <= 0) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation);
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			ttcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk_mem_charge(sk, copy);
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TTCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->gso_segs = 0;

		if (!copied)
			TTCP_SKB_CB(skb)->flags &= ~TTCPHDR_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len < size_goal || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			ttcp_mark_push(tp, skb);
			__ttcp_push_pending_frames(sk, mss_now, TTCP_NAGLE_PUSH);
		} else if (skb == ttcp_send_head(sk))
			ttcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			ttcp_push(sk, flags & ~MSG_MORE, mss_now, TTCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = ttcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied)
		ttcp_push(sk, flags, mss_now, tp->nonagle);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

int ttcp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	ssize_t res;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sk->sk_socket, page, offset, size,
					flags);

	lock_sock(sk);
	res = do_ttcp_sendpages(sk, &page, offset, size, flags);
	release_sock(sk);
	return res;
}
EXPORT_SYMBOL(ttcp_sendpage);

#define TTCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TTCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk, int sg)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	int tmp = tp->mss_cache;

	if (sg) {
		if (sk_can_gso(sk))
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_TTCP_HEADER);

			if (tmp >= pgbreak &&
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				tmp = pgbreak;
		}
	}

	return tmp;
}

int ttcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct iovec *iov;
	struct ttcp_sock *tp = ttcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int sg, err, copied;
	long timeo;

	lock_sock(sk);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TTCPF_ESTABLISHED | TTCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = ttcp_send_mss(sk, &size_goal, flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	sg = sk->sk_route_caps & NETIF_F_SG;

	while (--iovlen >= 0) {
		size_t seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy = 0;
			int max = size_goal;

			skb = ttcp_write_queue_tail(sk);
			if (ttcp_send_head(sk)) {
				if (skb->ip_summed == CHECKSUM_NONE)
					max = mss_now;
				copy = max - skb->len;
			}

			if (copy <= 0) {
new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

				skb = sk_stream_alloc_skb(sk,
							  select_size(sk, sg),
							  sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
					skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, skb);
				copy = size_goal;
				max = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);
				if ((err = skb_add_data(skb, from, copy)) != 0)
					goto do_fault;
			} else {
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TTCP_PAGE(sk);
				int off = TTCP_OFF(sk);

				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS || !sg) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					ttcp_mark_push(tp, skb);
					goto new_segment;
				} else if (page) {
					if (off == PAGE_SIZE) {
						put_page(page);
						TTCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				if (!sk_wmem_schedule(sk, copy))
					goto wait_for_memory;

				if (!page) {
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) {
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TTCP_PAGE(sk)) {
						TTCP_PAGE(sk) = page;
						TTCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge) {
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TTCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TTCP_PAGE(sk) = page;
					}
				}

				TTCP_OFF(sk) = off + copy;
			}

			if (!copied)
				TTCP_SKB_CB(skb)->flags &= ~TTCPHDR_PSH;

			tp->write_seq += copy;
			TTCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < max || (flags & MSG_OOB))
				continue;

			if (forced_push(tp)) {
				ttcp_mark_push(tp, skb);
				__ttcp_push_pending_frames(sk, mss_now, TTCP_NAGLE_PUSH);
			} else if (skb == ttcp_send_head(sk))
				ttcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				ttcp_push(sk, flags & ~MSG_MORE, mss_now, TTCP_NAGLE_PUSH);

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = ttcp_send_mss(sk, &size_goal, flags);
		}
	}

out:
	if (copied)
		ttcp_push(sk, flags, mss_now, tp->nonagle);
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		ttcp_unlink_write_queue(skb, sk);
		/* It is the one place in all of TTCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		ttcp_check_send_head(sk, skb);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(ttcp_sendmsg);

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int ttcp_recv_urg(struct sock *sk, struct msghdr *msg, int len, int flags)
{
	struct ttcp_sock *tp = ttcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TTCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TTCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TTCP_URG_VALID) {
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TTCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TTCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * ttcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void ttcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	int time_to_ack = 0;

#if TTCP_DEBUG
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	WARN(skb && !before(tp->copied_seq, TTCP_SKB_CB(skb)->end_seq),
	     "cleanup rbuf bug: copied %X seq %X rcvnxt %X\n",
	     tp->copied_seq, TTCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);
#endif

	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by ttcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = ttcp_receive_window(tp);

		/* Optimize, __ttcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __ttcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	if (time_to_ack)
		ttcp_send_ack(sk);
}

static void ttcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct ttcp_sock *tp = ttcp_sk(sk);

	NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk_backlog_rcv(sk, skb);
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

#ifdef CONFIG_NET_DMA
static void ttcp_service_net_dma(struct sock *sk, bool wait)
{
	dma_cookie_t done, used;
	dma_cookie_t last_issued;
	struct ttcp_sock *tp = ttcp_sk(sk);

	if (!tp->ucopy.dma_chan)
		return;

	last_issued = tp->ucopy.dma_cookie;
	dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

	do {
		if (dma_async_memcpy_complete(tp->ucopy.dma_chan,
					      last_issued, &done,
					      &used) == DMA_SUCCESS) {
			/* Safe to free early-copied skbs now */
			__skb_queue_purge(&sk->sk_async_wait_queue);
			break;
		} else {
			struct sk_buff *skb;
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
						      used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}
	} while (wait);
}
#endif

static inline struct sk_buff *ttcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TTCP_SKB_CB(skb)->seq;
		if (ttcp_hdr(skb)->syn)
			offset--;
		if (offset < skb->len || ttcp_hdr(skb)->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to ttcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int ttcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct ttcp_sock *tp = ttcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TTCP_LISTEN)
		return -ENOTCONN;
	while ((skb = ttcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used < 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/*
			 * If recv_actor drops the lock (e.g. TTCP splice
			 * receive) the skb pointer might be invalid when
			 * getting here: ttcp_collapse might have deleted it
			 * while aggregating skbs from the socket queue.
			 */
			skb = ttcp_recv_skb(sk, seq-1, &offset);
			if (!skb || (offset+1 != skb->len))
				break;
		}
		if (ttcp_hdr(skb)->fin) {
			sk_eat_skb(sk, skb, 0);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
		tp->copied_seq = seq;
	}
	tp->copied_seq = seq;

	ttcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0)
		ttcp_cleanup_rbuf(sk, copied);
	return copied;
}
EXPORT_SYMBOL(ttcp_read_sock);

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */

int ttcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int nonblock, int flags, int *addr_len)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;
	int copied_early = 0;
	struct sk_buff *skb;
	u32 urg_hole = 0;

	lock_sock(sk);

	err = -ENOTCONN;
	if (sk->sk_state == TTCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	skb = skb_peek_tail(&sk->sk_receive_queue);
	{
		int available = 0;

		if (skb)
			available = TTCP_SKB_CB(skb)->seq + skb->len - (*seq);
		if ((available < target) &&
		    (len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
		    !sysctl_ttcp_low_latency &&
		    dma_find_channel(DMA_MEMCPY)) {
			preempt_enable_no_resched();
			tp->ucopy.pinned_list =
					dma_pin_iovec_pages(msg->msg_iov, len);
		} else {
			preempt_enable_no_resched();
		}
	}
#endif

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, TTCP_SKB_CB(skb)->seq),
				 "recvmsg bug: copied %X seq %X rcvnxt %X fl %X\n",
				 *seq, TTCP_SKB_CB(skb)->seq, tp->rcv_nxt,
				 flags))
				break;

			offset = *seq - TTCP_SKB_CB(skb)->seq;
			if (ttcp_hdr(skb)->syn)
				offset--;
			if (offset < skb->len)
				goto found_ok_skb;
			if (ttcp_hdr(skb)->fin)
				goto found_fin_ok;
			WARN(!(flags & MSG_PEEK),
			     "recvmsg bug 2: copied %X seq %X rcvnxt %X fl %X\n",
			     *seq, TTCP_SKB_CB(skb)->seq, tp->rcv_nxt, flags);
		}

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TTCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TTCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		ttcp_cleanup_rbuf(sk, copied);

		if (!sysctl_ttcp_low_latency && tp->ucopy.task == user_recv) {
			/* Install new reader */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len;

			WARN_ON(tp->copied_seq != tp->rcv_nxt &&
				!(flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			if (!skb_queue_empty(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

#ifdef CONFIG_NET_DMA
		if (tp->ucopy.dma_chan)
			dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);
#endif
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			sk_wait_data(sk, &timeo);

#ifdef CONFIG_NET_DMA
		ttcp_service_net_dma(sk, false);  /* Don't block */
		tp->ucopy.wakeup = 0;
#endif

		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			if ((chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
				len -= chunk;
				copied += chunk;
			}

			if (tp->rcv_nxt == tp->copied_seq &&
			    !skb_queue_empty(&tp->ucopy.prequeue)) {
do_prequeue:
				ttcp_prequeue_process(sk);

				if ((chunk = len - tp->ucopy.len) != 0) {
					NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
					len -= chunk;
					copied += chunk;
				}
			}
		}
		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TTCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, task_pid_nr(current));
			peek_seq = tp->copied_seq;
		}
		continue;

	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		if (!(flags & MSG_TRUNC)) {
#ifdef CONFIG_NET_DMA
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);

			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = dma_skb_copy_datagram_iovec(
					tp->ucopy.dma_chan, skb, offset,
					msg->msg_iov, used,
					tp->ucopy.pinned_list);

				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}

				dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				err = skb_copy_datagram_iovec(skb, offset,
						msg->msg_iov, used);
				if (err) {
					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;
		copied += used;
		len -= used;

		ttcp_rcv_space_adjust(sk);

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			ttcp_fast_path_check(sk);
		}
		if (used + offset < skb->len)
			continue;

		if (ttcp_hdr(skb)->fin)
			goto found_fin_ok;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue;

	found_fin_ok:
		/* Process the FIN. */
		++*seq;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		break;
	} while (len > 0);

	if (user_recv) {
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			ttcp_prequeue_process(sk);

			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
				len -= chunk;
				copied += chunk;
			}
		}

		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

#ifdef CONFIG_NET_DMA
	ttcp_service_net_dma(sk, true);  /* Wait for queue to drain */
	tp->ucopy.dma_chan = NULL;

	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	ttcp_cleanup_rbuf(sk, copied);

	release_sock(sk);
	return copied;

out:
	release_sock(sk);
	return err;

recv_urg:
	err = ttcp_recv_urg(sk, msg, len, flags);
	goto out;
}
EXPORT_SYMBOL(ttcp_recvmsg);

void ttcp_set_state(struct sock *sk, int state)
{
	int oldstate = sk->sk_state;

	switch (state) {
	case TTCP_ESTABLISHED:
		if (oldstate != TTCP_ESTABLISHED)
			TTCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;

	case TTCP_CLOSE:
		if (oldstate == TTCP_CLOSE_WAIT || oldstate == TTCP_ESTABLISHED)
			TTCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);
		if (inet_csk(sk)->icsk_bind_hash &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		/* fall through */
	default:
		if (oldstate == TTCP_ESTABLISHED)
			TTCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	sk->sk_state = state;

#ifdef STATE_TRACE
	SOCK_DEBUG(sk, "TTCP sk=%p, State %s -> %s\n", sk, statename[oldstate], statename[state]);
#endif
}
EXPORT_SYMBOL_GPL(ttcp_set_state);

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

static const unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  /* (Invalid)		*/ TTCP_CLOSE,
  /* TTCP_ESTABLISHED	*/ TTCP_FIN_WAIT1 | TTCP_ACTION_FIN,
  /* TTCP_SYN_SENT	*/ TTCP_CLOSE,
  /* TTCP_SYN_RECV	*/ TTCP_FIN_WAIT1 | TTCP_ACTION_FIN,
  /* TTCP_FIN_WAIT1	*/ TTCP_FIN_WAIT1,
  /* TTCP_FIN_WAIT2	*/ TTCP_FIN_WAIT2,
  /* TTCP_TIME_WAIT	*/ TTCP_CLOSE,
  /* TTCP_CLOSE		*/ TTCP_CLOSE,
  /* TTCP_CLOSE_WAIT	*/ TTCP_LAST_ACK  | TTCP_ACTION_FIN,
  /* TTCP_LAST_ACK	*/ TTCP_LAST_ACK,
  /* TTCP_LISTEN		*/ TTCP_CLOSE,
  /* TTCP_CLOSING	*/ TTCP_CLOSING,
};

static int ttcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];
	int ns = next & TTCP_STATE_MASK;

	ttcp_set_state(sk, ns);

	return next & TTCP_ACTION_FIN;
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or sock_set_flag(sk, SOCK_DEAD).
 */

void ttcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	printk(KERN_INFO "shutting down ttcp:\n");
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TTCPF_ESTABLISHED | TTCPF_SYN_SENT |
	     TTCPF_SYN_RECV | TTCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
		if (ttcp_close_state(sk))
			ttcp_send_fin(sk);
	}
}
EXPORT_SYMBOL(ttcp_shutdown);

void ttcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == TTCP_LISTEN) {
		ttcp_set_state(sk, TTCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TTCP_SKB_CB(skb)->end_seq - TTCP_SKB_CB(skb)->seq -
			  ttcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	/* If socket has been already reset (e.g. in ttcp_reset()) - kill it. */
	if (sk->sk_state == TTCP_CLOSE)
		goto adjudge_to_death;

	/* As outlined in RFC 2525, section 2.17, we send a RST here because
	 * data was lost. To witness the awful effects of the old behavior of
	 * always doing a FIN, run an older 2.1.x kernel or 2.0.x, start a bulk
	 * GET in an FTP client, suspend the process, wait for the client to
	 * advertise a zero window, then kill -9 the FTP client, wheee...
	 * Note: timeout is always zero in such a case.
	 */
	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		ttcp_set_state(sk, TTCP_CLOSE);
		ttcp_send_active_reset(sk, sk->sk_allocation);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
	} else if (ttcp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TTCP state
		 * machine. State transitions:
		 *
		 * TTCP_ESTABLISHED -> TTCP_FIN_WAIT1
		 * TTCP_SYN_RECV	-> TTCP_FIN_WAIT1 (forget it, it's impossible)
		 * TTCP_CLOSE_WAIT -> TTCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TTCP_ESTABLISHED, TTCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		ttcp_send_fin(sk);
	}

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);


	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	WARN_ON(sock_owned_by_user(sk));

	percpu_counter_inc(sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TTCP_CLOSE && sk->sk_state == TTCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TTCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TTCP_FIN_WAIT2) {
		struct ttcp_sock *tp = ttcp_sk(sk);
		if (tp->linger2 < 0) {
			ttcp_set_state(sk, TTCP_CLOSE);
			ttcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = ttcp_fin_time(sk);

			if (tmo > TTCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(sk,
						tmo - TTCP_TIMEWAIT_LEN);
			} else {
				ttcp_time_wait(sk, TTCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TTCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (ttcp_too_many_orphans(sk, 0)) {
			if (net_ratelimit())
				printk(KERN_INFO "TTCP: too many of orphaned "
				       "sockets\n");
			ttcp_set_state(sk, TTCP_CLOSE);
			ttcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}

	if (sk->sk_state == TTCP_CLOSE)
		inet_csk_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}
EXPORT_SYMBOL(ttcp_close);

/* These states need RST on ABORT according to RFC793 */

static inline int ttcp_need_reset(int state)
{
	return (1 << state) &
	       (TTCPF_ESTABLISHED | TTCPF_CLOSE_WAIT | TTCPF_FIN_WAIT1 |
		TTCPF_FIN_WAIT2 | TTCPF_SYN_RECV);
}

int ttcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ttcp_sock *tp = ttcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;

	if (old_state != TTCP_CLOSE)
		ttcp_set_state(sk, TTCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TTCP_LISTEN) {
		inet_csk_listen_stop(sk);
	} else if (ttcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TTCPF_CLOSING | TTCPF_LAST_ACK))) {
		/* The last check adjusts for discrepancy of Linux wrt. RFC
		 * states
		 */
		ttcp_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TTCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	ttcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	ttcp_write_queue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	inet->inet_dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	icsk->icsk_backoff = 0;
	tp->snd_cwnd = 2;
	icsk->icsk_probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = TTCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tp->window_clamp = 0;
	ttcp_set_ca_state(sk, TTCP_CA_Open);
	ttcp_clear_retrans(tp);
	inet_csk_delack_init(sk);
	ttcp_init_send_head(sk);
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);

	WARN_ON(inet->inet_num && !icsk->icsk_bind_hash);

	sk->sk_error_report(sk);
	return err;
}
EXPORT_SYMBOL(ttcp_disconnect);

/*
 *	Socket option code for TTCP.
 */
static int do_ttcp_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, unsigned int optlen)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int val;
	int err = 0;

	/* These are data/string values, all the others are ints */
	switch (optname) {
	case TTCP_CONGESTION: {
		char name[TTCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min_t(long, TTCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = ttcp_set_congestion_control(sk, name);
		release_sock(sk);
		return err;
	}
	case TTCP_COOKIE_TRANSACTIONS: {
		struct ttcp_cookie_transactions ctd;
		struct ttcp_cookie_values *cvp = NULL;

		if (sizeof(ctd) > optlen)
			return -EINVAL;
		if (copy_from_user(&ctd, optval, sizeof(ctd)))
			return -EFAULT;

		if (ctd.ttcpct_used > sizeof(ctd.ttcpct_value) ||
		    ctd.ttcpct_s_data_desired > TTCP_MSS_DESIRED)
			return -EINVAL;

		if (ctd.ttcpct_cookie_desired == 0) {
			/* default to global value */
		} else if ((0x1 & ctd.ttcpct_cookie_desired) ||
			   ctd.ttcpct_cookie_desired > TTCP_COOKIE_MAX ||
			   ctd.ttcpct_cookie_desired < TTCP_COOKIE_MIN) {
			return -EINVAL;
		}

		if (TTCP_COOKIE_OUT_NEVER & ctd.ttcpct_flags) {
			/* Supercedes all other values */
			lock_sock(sk);
			if (tp->cookie_values != NULL) {
				kref_put(&tp->cookie_values->kref,
					 ttcp_cookie_values_release);
				tp->cookie_values = NULL;
			}
			tp->rx_opt.cookie_in_always = 0; /* false */
			tp->rx_opt.cookie_out_never = 1; /* true */
			release_sock(sk);
			return err;
		}

		/* Allocate ancillary memory before locking.
		 */
		if (ctd.ttcpct_used > 0 ||
		    (tp->cookie_values == NULL &&
		     (sysctl_ttcp_cookie_size > 0 ||
		      ctd.ttcpct_cookie_desired > 0 ||
		      ctd.ttcpct_s_data_desired > 0))) {
			cvp = kzalloc(sizeof(*cvp) + ctd.ttcpct_used,
				      GFP_KERNEL);
			if (cvp == NULL)
				return -ENOMEM;

			kref_init(&cvp->kref);
		}
		lock_sock(sk);
		tp->rx_opt.cookie_in_always =
			(TTCP_COOKIE_IN_ALWAYS & ctd.ttcpct_flags);
		tp->rx_opt.cookie_out_never = 0; /* false */

		if (tp->cookie_values != NULL) {
			if (cvp != NULL) {
				/* Changed values are recorded by a changed
				 * pointer, ensuring the cookie will differ,
				 * without separately hashing each value later.
				 */
				kref_put(&tp->cookie_values->kref,
					 ttcp_cookie_values_release);
			} else {
				cvp = tp->cookie_values;
			}
		}

		if (cvp != NULL) {
			cvp->cookie_desired = ctd.ttcpct_cookie_desired;

			if (ctd.ttcpct_used > 0) {
				memcpy(cvp->s_data_payload, ctd.ttcpct_value,
				       ctd.ttcpct_used);
				cvp->s_data_desired = ctd.ttcpct_used;
				cvp->s_data_constant = 1; /* true */
			} else {
				/* No constant payload data. */
				cvp->s_data_desired = ctd.ttcpct_s_data_desired;
				cvp->s_data_constant = 0; /* false */
			}

			tp->cookie_values = cvp;
		}
		release_sock(sk);
		return err;
	}
	default:
		/* fallthru */
		break;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TTCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < TTCP_MIN_MSS || val > MAX_TTCP_WINDOW) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TTCP_NODELAY:
		if (val) {
			/* TTCP_NODELAY is weaker than TTCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TTCP_NODELAY is set we make
			 * an explicit push, which overrides even TTCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TTCP_NAGLE_OFF|TTCP_NAGLE_PUSH;
			ttcp_push_pending_frames(sk);
		} else {
			tp->nonagle &= ~TTCP_NAGLE_OFF;
		}
		break;

	case TTCP_THIN_LINEAR_TIMEOUTS:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_lto = val;
		break;

	case TTCP_THIN_DUPACK:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_dupack = val;
		break;

	case TTCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TTCP_CORK can be set together with TTCP_NODELAY and it is
		 * stronger than TTCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TTCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TTCP_NAGLE_CORK;
			if (tp->nonagle&TTCP_NAGLE_OFF)
				tp->nonagle |= TTCP_NAGLE_PUSH;
			ttcp_push_pending_frames(sk);
		}
		break;

	case TTCP_KEEPIDLE:
		if (val < 1 || val > MAX_TTCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TTCPF_CLOSE | TTCPF_LISTEN))) {
				u32 elapsed = keepalive_ttcp_time_elapsed(tp);
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				inet_csk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TTCP_KEEPINTVL:
		if (val < 1 || val > MAX_TTCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TTCP_KEEPCNT:
		if (val < 1 || val > MAX_TTCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TTCP_SYNCNT:
		if (val < 1 || val > MAX_TTCP_SYNCNT)
			err = -EINVAL;
		else
			icsk->icsk_syn_retries = val;
		break;

	case TTCP_LINGER2:
		if (val < 0)
			tp->linger2 = -1;
		else if (val > sysctl_ttcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;

	case TTCP_DEFER_ACCEPT:
		/* Translate value in seconds to number of retransmits */
		icsk->icsk_accept_queue.rskq_defer_accept =
			secs_to_retrans(val, TTCP_TIMEOUT_INIT / HZ,
					TTCP_RTO_MAX / HZ);
		break;

	case TTCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TTCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TTCP_QUICKACK:
		if (!val) {
			icsk->icsk_ack.pingpong = 1;
		} else {
			icsk->icsk_ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TTCPF_ESTABLISHED | TTCPF_CLOSE_WAIT) &&
			    inet_csk_ack_scheduled(sk)) {
				icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
				ttcp_cleanup_rbuf(sk, 1);
				if (!(val & 1))
					icsk->icsk_ack.pingpong = 1;
			}
		}
		break;

#ifdef CONFIG_TTCP_MD5SIG
	case TTCP_MD5SIG:
		/* Read the IP->Key mappings from userspace */
		err = tp->af_specific->md5_parse(sk, optval, optlen);
		break;
#endif
	case TTCP_USER_TIMEOUT:
		/* Cap the max timeout in ms TTCP will retry/retrans
		 * before giving up and aborting (ETIMEDOUT) a connection.
		 */
		icsk->icsk_user_timeout = msecs_to_jiffies(val);
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int ttcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   unsigned int optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TTCP)
		return icsk->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
	return do_ttcp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(ttcp_setsockopt);

#ifdef CONFIG_COMPAT
int compat_ttcp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level != SOL_TTCP)
		return inet_csk_compat_setsockopt(sk, level, optname,
						  optval, optlen);
	return do_ttcp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(compat_ttcp_setsockopt);
#endif

/* Return information about state of ttcp endpoint in API format. */
void ttcp_get_info(struct sock *sk, struct ttcp_info *info)
{
	struct ttcp_sock *tp = ttcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now = ttcp_time_stamp;

	memset(info, 0, sizeof(*info));

	info->ttcpi_state = sk->sk_state;
	info->ttcpi_ca_state = icsk->icsk_ca_state;
	info->ttcpi_retransmits = icsk->icsk_retransmits;
	info->ttcpi_probes = icsk->icsk_probes_out;
	info->ttcpi_backoff = icsk->icsk_backoff;

	if (tp->rx_opt.tstamp_ok)
		info->ttcpi_options |= TTCPI_OPT_TIMESTAMPS;
	if (ttcp_is_sack(tp))
		info->ttcpi_options |= TTCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->ttcpi_options |= TTCPI_OPT_WSCALE;
		info->ttcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->ttcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	}

	if (tp->ecn_flags&TTCP_ECN_OK)
		info->ttcpi_options |= TTCPI_OPT_ECN;

	info->ttcpi_rto = jiffies_to_usecs(icsk->icsk_rto);
	info->ttcpi_ato = jiffies_to_usecs(icsk->icsk_ack.ato);
	info->ttcpi_snd_mss = tp->mss_cache;
	info->ttcpi_rcv_mss = icsk->icsk_ack.rcv_mss;

	if (sk->sk_state == TTCP_LISTEN) {
		info->ttcpi_unacked = sk->sk_ack_backlog;
		info->ttcpi_sacked = sk->sk_max_ack_backlog;
	} else {
		info->ttcpi_unacked = tp->packets_out;
		info->ttcpi_sacked = tp->sacked_out;
	}
	info->ttcpi_lost = tp->lost_out;
	info->ttcpi_retrans = tp->retrans_out;
	info->ttcpi_fackets = tp->fackets_out;

	info->ttcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->ttcpi_last_data_recv = jiffies_to_msecs(now - icsk->icsk_ack.lrcvtime);
	info->ttcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->ttcpi_pmtu = icsk->icsk_pmtu_cookie;
	info->ttcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->ttcpi_rtt = jiffies_to_usecs(tp->srtt)>>3;
	info->ttcpi_rttvar = jiffies_to_usecs(tp->mdev)>>2;
	info->ttcpi_snd_ssthresh = tp->snd_ssthresh;
	info->ttcpi_snd_cwnd = tp->snd_cwnd;
	info->ttcpi_advmss = tp->advmss;
	info->ttcpi_reordering = tp->reordering;

	info->ttcpi_rcv_rtt = jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3;
	info->ttcpi_rcv_space = tp->rcvq_space.space;

	info->ttcpi_total_retrans = tp->total_retrans;
}
EXPORT_SYMBOL_GPL(ttcp_get_info);

static int do_ttcp_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ttcp_sock *tp = ttcp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TTCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TTCPF_CLOSE | TTCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TTCP_NODELAY:
		val = !!(tp->nonagle&TTCP_NAGLE_OFF);
		break;
	case TTCP_CORK:
		val = !!(tp->nonagle&TTCP_NAGLE_CORK);
		break;
	case TTCP_KEEPIDLE:
		val = keepalive_ttcp_time_when(tp) / HZ;
		break;
	case TTCP_KEEPINTVL:
		val = keepalive_ttcp_intvl_when(tp) / HZ;
		break;
	case TTCP_KEEPCNT:
		val = keepalive_ttcp_probes(tp);
		break;
	case TTCP_SYNCNT:
		val = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		break;
	case TTCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_ttcp_fin_timeout) / HZ;
		break;
	case TTCP_DEFER_ACCEPT:
		val = retrans_to_secs(icsk->icsk_accept_queue.rskq_defer_accept,
				      TTCP_TIMEOUT_INIT / HZ, TTCP_RTO_MAX / HZ);
		break;
	case TTCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TTCP_INFO: {
		struct ttcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		ttcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TTCP_QUICKACK:
		val = !icsk->icsk_ack.pingpong;
		break;

	case TTCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TTCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_tca_ops->name, len))
			return -EFAULT;
		return 0;

	case TTCP_COOKIE_TRANSACTIONS: {
		struct ttcp_cookie_transactions ctd;
		struct ttcp_cookie_values *cvp = tp->cookie_values;

		if (get_user(len, optlen))
			return -EFAULT;
		if (len < sizeof(ctd))
			return -EINVAL;

		memset(&ctd, 0, sizeof(ctd));
		ctd.ttcpct_flags = (tp->rx_opt.cookie_in_always ?
				   TTCP_COOKIE_IN_ALWAYS : 0)
				| (tp->rx_opt.cookie_out_never ?
				   TTCP_COOKIE_OUT_NEVER : 0);

		if (cvp != NULL) {
			ctd.ttcpct_flags |= (cvp->s_data_in ?
					    TTCP_S_DATA_IN : 0)
					 | (cvp->s_data_out ?
					    TTCP_S_DATA_OUT : 0);

			ctd.ttcpct_cookie_desired = cvp->cookie_desired;
			ctd.ttcpct_s_data_desired = cvp->s_data_desired;

			memcpy(&ctd.ttcpct_value[0], &cvp->cookie_pair[0],
			       cvp->cookie_pair_size);
			ctd.ttcpct_used = cvp->cookie_pair_size;
		}

		if (put_user(sizeof(ctd), optlen))
			return -EFAULT;
		if (copy_to_user(optval, &ctd, sizeof(ctd)))
			return -EFAULT;
		return 0;
	}
	case TTCP_THIN_LINEAR_TIMEOUTS:
		val = tp->thin_lto;
		break;
	case TTCP_THIN_DUPACK:
		val = tp->thin_dupack;
		break;

	case TTCP_USER_TIMEOUT:
		val = jiffies_to_msecs(icsk->icsk_user_timeout);
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

int ttcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TTCP)
		return icsk->icsk_af_ops->getsockopt(sk, level, optname,
						     optval, optlen);
	return do_ttcp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(ttcp_getsockopt);

#ifdef CONFIG_COMPAT
int compat_ttcp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_TTCP)
		return inet_csk_compat_getsockopt(sk, level, optname,
						  optval, optlen);
	return do_ttcp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(compat_ttcp_getsockopt);
#endif

struct sk_buff *ttcp_tso_segment(struct sk_buff *skb, u32 features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct ttcphdr *th;
	unsigned thlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int mss;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = ttcp_hdr(skb);
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;

		if (unlikely(type &
			     ~(SKB_GSO_TCPV4 |
			       SKB_GSO_DODGY |
			       SKB_GSO_TCP_ECN |
			       SKB_GSO_TCPV6 |
			       0) ||
			     !(type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))))
			goto out;

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	delta = htonl(oldlen + (thlen + mss));

	skb = segs;
	th = ttcp_hdr(skb);
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				       (__force u32)delta));
		if (skb->ip_summed != CHECKSUM_PARTIAL)
			th->check =
			     csum_fold(csum_partial(skb_transport_header(skb),
						    thlen, skb->csum));

		seq += mss;
		skb = skb->next;
		th = ttcp_hdr(skb);

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->transport_header) +
		      skb->data_len);
	th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				(__force u32)delta));
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		th->check = csum_fold(csum_partial(skb_transport_header(skb),
						   thlen, skb->csum));

out:
	return segs;
}
EXPORT_SYMBOL(ttcp_tso_segment);

struct sk_buff **ttcp_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct ttcphdr *th;
	struct ttcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	__be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int i;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*th);
	th = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	skb_gro_pull(skb, thlen);

	len = skb_gro_len(skb);
	flags = ttcp_flag_word(th);

	for (; (p = *head); head = &p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = ttcp_hdr(p);

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	goto out_check_final;

found:
	flush = NAPI_GRO_CB(p)->flush;
	flush |= (__force int)(flags & TTCP_FLAG_CWR);
	flush |= (__force int)((flags ^ ttcp_flag_word(th2)) &
		  ~(TTCP_FLAG_CWR | TTCP_FLAG_FIN | TTCP_FLAG_PSH));
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);
	for (i = sizeof(*th); i < thlen; i += 4)
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	mss = skb_shinfo(p)->gso_size;

	flush |= (len - 1) >= mss;
	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);

	if (flush || skb_gro_receive(head, skb)) {
		mss = 1;
		goto out_check_final;
	}

	p = *head;
	th2 = ttcp_hdr(p);
	ttcp_flag_word(th2) |= flags & (TTCP_FLAG_FIN | TTCP_FLAG_PSH);

out_check_final:
	flush = len < mss;
	flush |= (__force int)(flags & (TTCP_FLAG_URG | TTCP_FLAG_PSH |
					TTCP_FLAG_RST | TTCP_FLAG_SYN |
					TTCP_FLAG_FIN));

	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = head;

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}
EXPORT_SYMBOL(ttcp_gro_receive);

int ttcp_gro_complete(struct sk_buff *skb)
{
	struct ttcphdr *th = ttcp_hdr(skb);

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct ttcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

	if (th->cwr)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

	return 0;
}
EXPORT_SYMBOL(ttcp_gro_complete);

#ifdef CONFIG_TTCP_MD5SIG
static unsigned long ttcp_md5sig_users;
static struct ttcp_md5sig_pool * __percpu *ttcp_md5sig_pool;
static DEFINE_SPINLOCK(ttcp_md5sig_pool_lock);

static void __ttcp_free_md5sig_pool(struct ttcp_md5sig_pool * __percpu *pool)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct ttcp_md5sig_pool *p = *per_cpu_ptr(pool, cpu);
		if (p) {
			if (p->md5_desc.tfm)
				crypto_free_hash(p->md5_desc.tfm);
			kfree(p);
		}
	}
	free_percpu(pool);
}

void ttcp_free_md5sig_pool(void)
{
	struct ttcp_md5sig_pool * __percpu *pool = NULL;

	spin_lock_bh(&ttcp_md5sig_pool_lock);
	if (--ttcp_md5sig_users == 0) {
		pool = ttcp_md5sig_pool;
		ttcp_md5sig_pool = NULL;
	}
	spin_unlock_bh(&ttcp_md5sig_pool_lock);
	if (pool)
		__ttcp_free_md5sig_pool(pool);
}
EXPORT_SYMBOL(ttcp_free_md5sig_pool);

static struct ttcp_md5sig_pool * __percpu *
__ttcp_alloc_md5sig_pool(struct sock *sk)
{
	int cpu;
	struct ttcp_md5sig_pool * __percpu *pool;

	pool = alloc_percpu(struct ttcp_md5sig_pool *);
	if (!pool)
		return NULL;

	for_each_possible_cpu(cpu) {
		struct ttcp_md5sig_pool *p;
		struct crypto_hash *hash;

		p = kzalloc(sizeof(*p), sk->sk_allocation);
		if (!p)
			goto out_free;
		*per_cpu_ptr(pool, cpu) = p;

		hash = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		if (!hash || IS_ERR(hash))
			goto out_free;

		p->md5_desc.tfm = hash;
	}
	return pool;
out_free:
	__ttcp_free_md5sig_pool(pool);
	return NULL;
}

struct ttcp_md5sig_pool * __percpu *ttcp_alloc_md5sig_pool(struct sock *sk)
{
	struct ttcp_md5sig_pool * __percpu *pool;
	int alloc = 0;

retry:
	spin_lock_bh(&ttcp_md5sig_pool_lock);
	pool = ttcp_md5sig_pool;
	if (ttcp_md5sig_users++ == 0) {
		alloc = 1;
		spin_unlock_bh(&ttcp_md5sig_pool_lock);
	} else if (!pool) {
		ttcp_md5sig_users--;
		spin_unlock_bh(&ttcp_md5sig_pool_lock);
		cpu_relax();
		goto retry;
	} else
		spin_unlock_bh(&ttcp_md5sig_pool_lock);

	if (alloc) {
		/* we cannot hold spinlock here because this may sleep. */
		struct ttcp_md5sig_pool * __percpu *p;

		p = __ttcp_alloc_md5sig_pool(sk);
		spin_lock_bh(&ttcp_md5sig_pool_lock);
		if (!p) {
			ttcp_md5sig_users--;
			spin_unlock_bh(&ttcp_md5sig_pool_lock);
			return NULL;
		}
		pool = ttcp_md5sig_pool;
		if (pool) {
			/* oops, it has already been assigned. */
			spin_unlock_bh(&ttcp_md5sig_pool_lock);
			__ttcp_free_md5sig_pool(p);
		} else {
			ttcp_md5sig_pool = pool = p;
			spin_unlock_bh(&ttcp_md5sig_pool_lock);
		}
	}
	return pool;
}
EXPORT_SYMBOL(ttcp_alloc_md5sig_pool);


/**
 *	ttcp_get_md5sig_pool - get md5sig_pool for this user
 *
 *	We use percpu structure, so if we succeed, we exit with preemption
 *	and BH disabled, to make sure another thread or softirq handling
 *	wont try to get same context.
 */
struct ttcp_md5sig_pool *ttcp_get_md5sig_pool(void)
{
	struct ttcp_md5sig_pool * __percpu *p;

	local_bh_disable();

	spin_lock(&ttcp_md5sig_pool_lock);
	p = ttcp_md5sig_pool;
	if (p)
		ttcp_md5sig_users++;
	spin_unlock(&ttcp_md5sig_pool_lock);

	if (p)
		return *this_cpu_ptr(p);

	local_bh_enable();
	return NULL;
}
EXPORT_SYMBOL(ttcp_get_md5sig_pool);

void ttcp_put_md5sig_pool(void)
{
	local_bh_enable();
	ttcp_free_md5sig_pool();
}
EXPORT_SYMBOL(ttcp_put_md5sig_pool);

int ttcp_md5_hash_header(struct ttcp_md5sig_pool *hp,
			struct ttcphdr *th)
{
	struct scatterlist sg;
	int err;

	__sum16 old_checksum = th->check;
	th->check = 0;
	/* options aren't included in the hash */
	sg_init_one(&sg, th, sizeof(struct ttcphdr));
	err = crypto_hash_update(&hp->md5_desc, &sg, sizeof(struct ttcphdr));
	th->check = old_checksum;
	return err;
}
EXPORT_SYMBOL(ttcp_md5_hash_header);

int ttcp_md5_hash_skb_data(struct ttcp_md5sig_pool *hp,
			  struct sk_buff *skb, unsigned header_len)
{
	struct scatterlist sg;
	const struct ttcphdr *tp = ttcp_hdr(skb);
	struct hash_desc *desc = &hp->md5_desc;
	unsigned i;
	const unsigned head_data_len = skb_headlen(skb) > header_len ?
				       skb_headlen(skb) - header_len : 0;
	const struct skb_shared_info *shi = skb_shinfo(skb);
	struct sk_buff *frag_iter;

	sg_init_table(&sg, 1);

	sg_set_buf(&sg, ((u8 *) tp) + header_len, head_data_len);
	if (crypto_hash_update(desc, &sg, head_data_len))
		return 1;

	for (i = 0; i < shi->nr_frags; ++i) {
		const struct skb_frag_struct *f = &shi->frags[i];
		sg_set_page(&sg, f->page, f->size, f->page_offset);
		if (crypto_hash_update(desc, &sg, f->size))
			return 1;
	}

	skb_walk_frags(skb, frag_iter)
		if (ttcp_md5_hash_skb_data(hp, frag_iter, 0))
			return 1;

	return 0;
}
EXPORT_SYMBOL(ttcp_md5_hash_skb_data);

int ttcp_md5_hash_key(struct ttcp_md5sig_pool *hp, struct ttcp_md5sig_key *key)
{
	struct scatterlist sg;

	sg_init_one(&sg, key->key, key->keylen);
	return crypto_hash_update(&hp->md5_desc, &sg, key->keylen);
}
EXPORT_SYMBOL(ttcp_md5_hash_key);
#endif
/**
 * Each Responder maintains up to two secret values concurrently for
 * efficient secret rollover.  Each secret value has 4 states:
 *
 * Generating.  (ttcp_secret_generating != ttcp_secret_primary)
 *    Generates new Responder-Cookies, but not yet used for primary
 *    verification.  This is a short-term state, typically lasting only
 *    one round trip time (RTT).
 *
 * Primary.  (ttcp_secret_generating == ttcp_secret_primary)
 *    Used both for generation and primary verification.
 *
 * Retiring.  (ttcp_secret_retiring != ttcp_secret_secondary)
 *    Used for verification, until the first failure that can be
 *    verified by the newer Generating secret.  At that time, this
 *    cookie's state is changed to Secondary, and the Generating
 *    cookie's state is changed to Primary.  This is a short-term state,
 *    typically lasting only one round trip time (RTT).
 *
 * Secondary.  (ttcp_secret_retiring == ttcp_secret_secondary)
 *    Used for secondary verification, after primary verification
 *    failures.  This state lasts no more than twice the Maximum Segment
 *    Lifetime (2MSL).  Then, the secret is discarded.
 */
struct ttcp_cookie_secret {
	/* The secret is divided into two parts.  The digest part is the
	 * equivalent of previously hashing a secret and saving the state,
	 * and serves as an initialization vector (IV).  The message part
	 * serves as the trailing secret.
	 */
	u32				secrets[COOKIE_WORKSPACE_WORDS];
	unsigned long			expires;
};

#define TTCP_SECRET_1MSL (HZ * TTCP_PAWS_MSL)
#define TTCP_SECRET_2MSL (HZ * TTCP_PAWS_MSL * 2)
#define TTCP_SECRET_LIFE (HZ * 600)

static struct ttcp_cookie_secret ttcp_secret_one;
static struct ttcp_cookie_secret ttcp_secret_two;

/* Essentially a circular list, without dynamic allocation. */
static struct ttcp_cookie_secret *ttcp_secret_generating;
static struct ttcp_cookie_secret *ttcp_secret_primary;
static struct ttcp_cookie_secret *ttcp_secret_retiring;
static struct ttcp_cookie_secret *ttcp_secret_secondary;

static DEFINE_SPINLOCK(ttcp_secret_locker);

/* Select a pseudo-random word in the cookie workspace.
 */
static inline u32 ttcp_cookie_work(const u32 *ws, const int n)
{
	return ws[COOKIE_DIGEST_WORDS + ((COOKIE_MESSAGE_WORDS-1) & ws[n])];
}

/* Fill bakery[COOKIE_WORKSPACE_WORDS] with generator, updating as needed.
 * Called in softirq context.
 * Returns: 0 for success.
 */
int ttcp_cookie_generator(u32 *bakery)
{
	unsigned long jiffy = jiffies;

	if (unlikely(time_after_eq(jiffy, ttcp_secret_generating->expires))) {
		spin_lock_bh(&ttcp_secret_locker);
		if (!time_after_eq(jiffy, ttcp_secret_generating->expires)) {
			/* refreshed by another */
			memcpy(bakery,
			       &ttcp_secret_generating->secrets[0],
			       COOKIE_WORKSPACE_WORDS);
		} else {
			/* still needs refreshing */
			get_random_bytes(bakery, COOKIE_WORKSPACE_WORDS);

			/* The first time, paranoia assumes that the
			 * randomization function isn't as strong.  But,
			 * this secret initialization is delayed until
			 * the last possible moment (packet arrival).
			 * Although that time is observable, it is
			 * unpredictably variable.  Mash in the most
			 * volatile clock bits available, and expire the
			 * secret extra quickly.
			 */
			if (unlikely(ttcp_secret_primary->expires ==
				     ttcp_secret_secondary->expires)) {
				struct timespec tv;

				getnstimeofday(&tv);
				bakery[COOKIE_DIGEST_WORDS+0] ^=
					(u32)tv.tv_nsec;

				ttcp_secret_secondary->expires = jiffy
					+ TTCP_SECRET_1MSL
					+ (0x0f & ttcp_cookie_work(bakery, 0));
			} else {
				ttcp_secret_secondary->expires = jiffy
					+ TTCP_SECRET_LIFE
					+ (0xff & ttcp_cookie_work(bakery, 1));
				ttcp_secret_primary->expires = jiffy
					+ TTCP_SECRET_2MSL
					+ (0x1f & ttcp_cookie_work(bakery, 2));
			}
			memcpy(&ttcp_secret_secondary->secrets[0],
			       bakery, COOKIE_WORKSPACE_WORDS);

			rcu_assign_pointer(ttcp_secret_generating,
					   ttcp_secret_secondary);
			rcu_assign_pointer(ttcp_secret_retiring,
					   ttcp_secret_primary);
			/*
			 * Neither call_rcu() nor synchronize_rcu() needed.
			 * Retiring data is not freed.  It is replaced after
			 * further (locked) pointer updates, and a quiet time
			 * (minimum 1MSL, maximum LIFE - 2MSL).
			 */
		}
		spin_unlock_bh(&ttcp_secret_locker);
	} else {
		rcu_read_lock_bh();
		memcpy(bakery,
		       &rcu_dereference(ttcp_secret_generating)->secrets[0],
		       COOKIE_WORKSPACE_WORDS);
		rcu_read_unlock_bh();
	}
	return 0;
}
EXPORT_SYMBOL(ttcp_cookie_generator);

void ttcp_done(struct sock *sk)
{
	if (sk->sk_state == TTCP_SYN_SENT || sk->sk_state == TTCP_SYN_RECV)
		TTCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);

	ttcp_set_state(sk, TTCP_CLOSE);
	ttcp_clear_xmit_timers(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		inet_csk_destroy_sock(sk);
}
EXPORT_SYMBOL_GPL(ttcp_done);

extern struct ttcp_congestion_ops ttcp_reno;

static __initdata unsigned long thash_entries;
static int __init set_thash_entries(char *str)
{
	if (!str)
		return 0;
	thash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("thash_entries=", set_thash_entries);

void __init ttcp_init(void)
{
	struct sk_buff *skb = NULL;
	unsigned long nr_pages, limit;
	int i, max_share, cnt;
	unsigned long jiffy = jiffies;

	BUILD_BUG_ON(sizeof(struct ttcp_skb_cb) > sizeof(skb->cb));

	percpu_counter_init(&ttcp_sockets_allocated, 0);
	percpu_counter_init(&ttcp_orphan_count, 0);
	ttcp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("ttcp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	ttcp_hashinfo.ehash =
		alloc_large_system_hash("TTCP established",
					sizeof(struct inet_ehash_bucket),
					thash_entries,
					(totalram_pages >= 128 * 1024) ?
					13 : 15,
					0,
					NULL,
					&ttcp_hashinfo.ehash_mask,
					thash_entries ? 0 : 512 * 1024);
	for (i = 0; i <= ttcp_hashinfo.ehash_mask; i++) {
		INIT_HLIST_NULLS_HEAD(&ttcp_hashinfo.ehash[i].chain, i);
		INIT_HLIST_NULLS_HEAD(&ttcp_hashinfo.ehash[i].twchain, i);
	}
	if (inet_ehash_locks_alloc(&ttcp_hashinfo))
		panic("TTCP: failed to alloc ehash_locks");
	ttcp_hashinfo.bhash =
		alloc_large_system_hash("TTCP bind",
					sizeof(struct inet_bind_hashbucket),
					ttcp_hashinfo.ehash_mask + 1,
					(totalram_pages >= 128 * 1024) ?
					13 : 15,
					0,
					&ttcp_hashinfo.bhash_size,
					NULL,
					64 * 1024);
	ttcp_hashinfo.bhash_size = 1 << ttcp_hashinfo.bhash_size;
	for (i = 0; i < ttcp_hashinfo.bhash_size; i++) {
		spin_lock_init(&ttcp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&ttcp_hashinfo.bhash[i].chain);
	}


	cnt = ttcp_hashinfo.ehash_mask + 1;

	ttcp_death_row.sysctl_max_tw_buckets = cnt / 2;
	sysctl_ttcp_max_orphans = cnt / 2;
	sysctl_max_syn_backlog = max(128, cnt / 256);

	/* Set the pressure threshold to be a fraction of global memory that
	 * is up to 1/2 at 256 MB, decreasing toward zero with the amount of
	 * memory, with a floor of 128 pages.
	 */
	nr_pages = totalram_pages - totalhigh_pages;
	limit = min(nr_pages, 1UL<<(28-PAGE_SHIFT)) >> (20-PAGE_SHIFT);
	limit = (limit * (nr_pages >> (20-PAGE_SHIFT))) >> (PAGE_SHIFT-11);
	limit = max(limit, 128UL);
	sysctl_ttcp_mem[0] = limit / 4 * 3;
	sysctl_ttcp_mem[1] = limit;
	sysctl_ttcp_mem[2] = sysctl_ttcp_mem[0] * 2;

	/* Set per-socket limits to no more than 1/128 the pressure threshold */
	limit = ((unsigned long)sysctl_ttcp_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL*1024*1024, limit);

	sysctl_ttcp_wmem[0] = SK_MEM_QUANTUM;
	sysctl_ttcp_wmem[1] = 16*1024;
	sysctl_ttcp_wmem[2] = max(64*1024, max_share);

	sysctl_ttcp_rmem[0] = SK_MEM_QUANTUM;
	sysctl_ttcp_rmem[1] = 87380;
	sysctl_ttcp_rmem[2] = max(87380, max_share);

	printk(KERN_INFO "TTCP: Hash tables configured "
	       "(established %u bind %u)\n",
	       ttcp_hashinfo.ehash_mask + 1, ttcp_hashinfo.bhash_size);

	ttcp_register_congestion_control(&ttcp_reno);

	memset(&ttcp_secret_one.secrets[0], 0, sizeof(ttcp_secret_one.secrets));
	memset(&ttcp_secret_two.secrets[0], 0, sizeof(ttcp_secret_two.secrets));
	ttcp_secret_one.expires = jiffy; /* past due */
	ttcp_secret_two.expires = jiffy; /* past due */
	ttcp_secret_generating = &ttcp_secret_one;
	ttcp_secret_primary = &ttcp_secret_one;
	ttcp_secret_retiring = &ttcp_secret_two;
	ttcp_secret_secondary = &ttcp_secret_two;
}

static inline int ttcp_listen_start(struct sock *sk, int backlog)
{
	return inet_csk_listen_start(sk, backlog);
}

/*
 *	Move a socket into listening state.
 */
int inet_ttcp_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TTCPF_CLOSE | TTCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TTCP_LISTEN) {
		err = ttcp_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_ttcp_listen);
/*
 * Plugable TCP congestion control support and newReno
 * congestion control.
 * Based on ideas from I/O scheduler suport and Web100.
 *
 * Copyright (C) 2005 Stephen Hemminger <shemminger@osdl.org>
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <net/ttcp.h>

int sysctl_ttcp_max_ssthresh = 0;

static DEFINE_SPINLOCK(ttcp_cong_list_lock);
static LIST_HEAD(ttcp_cong_list);

/* Simple linear search, don't expect many entries! */
static struct ttcp_congestion_ops *ttcp_ca_find(const char *name)
{
	struct ttcp_congestion_ops *e;

	list_for_each_entry_rcu(e, &ttcp_cong_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

/*
 * Attach new congestion control algorithm to the list
 * of available options.
 */
int ttcp_register_congestion_control(struct ttcp_congestion_ops *ca)
{
	int ret = 0;

	/* all algorithms must implement ssthresh and cong_avoid ops */
	if (!ca->ssthresh || !ca->cong_avoid) {
		printk(KERN_ERR "TTCP %s does not implement required ops\n",
		       ca->name);
		return -EINVAL;
	}

	spin_lock(&ttcp_cong_list_lock);
	if (ttcp_ca_find(ca->name)) {
		printk(KERN_NOTICE "TTCP %s already registered\n", ca->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ca->list, &ttcp_cong_list);
		printk(KERN_INFO "TTCP %s registered\n", ca->name);
	}
	spin_unlock(&ttcp_cong_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(ttcp_register_congestion_control);

/*
 * Remove congestion control algorithm, called from
 * the module's remove function.  Module ref counts are used
 * to ensure that this can't be done till all sockets using
 * that method are closed.
 */
void ttcp_unregister_congestion_control(struct ttcp_congestion_ops *ca)
{
	spin_lock(&ttcp_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&ttcp_cong_list_lock);
}
EXPORT_SYMBOL_GPL(ttcp_unregister_congestion_control);

/* Assign choice of congestion control. */
void ttcp_init_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ttcp_congestion_ops *ca;

	/* if no choice made yet assign the current value set as default */
	if (icsk->icsk_ca_ops == &ttcp_init_congestion_ops) {
		rcu_read_lock();
		list_for_each_entry_rcu(ca, &ttcp_cong_list, list) {
			if (try_module_get(ca->owner)) {
				icsk->icsk_ca_ops = ca;
				break;
			}

			/* fallback to next available */
		}
		rcu_read_unlock();
	}

	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);
}

/* Manage refcounts on socket close. */
void ttcp_cleanup_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->release)
		icsk->icsk_ca_ops->release(sk);
	module_put(icsk->icsk_ca_ops->owner);
}

/* Used by sysctl to change default congestion control */
int ttcp_set_default_congestion_control(const char *name)
{
	struct ttcp_congestion_ops *ca;
	int ret = -ENOENT;

	spin_lock(&ttcp_cong_list_lock);
	ca = ttcp_ca_find(name);
#ifdef CONFIG_MODULES
	if (!ca && capable(CAP_NET_ADMIN)) {
		spin_unlock(&ttcp_cong_list_lock);

		request_module("ttcp_%s", name);
		spin_lock(&ttcp_cong_list_lock);
		ca = ttcp_ca_find(name);
	}
#endif

	if (ca) {
		ca->flags |= TTCP_CONG_NON_RESTRICTED;	/* default is always allowed */
		list_move(&ca->list, &ttcp_cong_list);
		ret = 0;
	}
	spin_unlock(&ttcp_cong_list_lock);

	return ret;
}

/* Set default value from kernel configuration at bootup */
static int __init ttcp_congestion_default(void)
{
	return ttcp_set_default_congestion_control(CONFIG_DEFAULT_TTCP_CONG);
}
late_initcall(ttcp_congestion_default);


/* Build string with list of available congestion control values */
void ttcp_get_available_congestion_control(char *buf, size_t maxlen)
{
	struct ttcp_congestion_ops *ca;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &ttcp_cong_list, list) {
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Get current default congestion control */
void ttcp_get_default_congestion_control(char *name)
{
	struct ttcp_congestion_ops *ca;
	/* We will always have reno... */
	BUG_ON(list_empty(&ttcp_cong_list));

	rcu_read_lock();
	ca = list_entry(ttcp_cong_list.next, struct ttcp_congestion_ops, list);
	strncpy(name, ca->name, TTCP_CA_NAME_MAX);
	rcu_read_unlock();
}

/* Built list of non-restricted congestion control values */
void ttcp_get_allowed_congestion_control(char *buf, size_t maxlen)
{
	struct ttcp_congestion_ops *ca;
	size_t offs = 0;

	*buf = '\0';
	rcu_read_lock();
	list_for_each_entry_rcu(ca, &ttcp_cong_list, list) {
		if (!(ca->flags & TTCP_CONG_NON_RESTRICTED))
			continue;
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Change list of non-restricted congestion control */
int ttcp_set_allowed_congestion_control(char *val)
{
	struct ttcp_congestion_ops *ca;
	char *saved_clone, *clone, *name;
	int ret = 0;

	saved_clone = clone = kstrdup(val, GFP_USER);
	if (!clone)
		return -ENOMEM;

	spin_lock(&ttcp_cong_list_lock);
	/* pass 1 check for bad entries */
	while ((name = strsep(&clone, " ")) && *name) {
		ca = ttcp_ca_find(name);
		if (!ca) {
			ret = -ENOENT;
			goto out;
		}
	}

	/* pass 2 clear old values */
	list_for_each_entry_rcu(ca, &ttcp_cong_list, list)
		ca->flags &= ~TTCP_CONG_NON_RESTRICTED;

	/* pass 3 mark as allowed */
	while ((name = strsep(&val, " ")) && *name) {
		ca = ttcp_ca_find(name);
		WARN_ON(!ca);
		if (ca)
			ca->flags |= TTCP_CONG_NON_RESTRICTED;
	}
out:
	spin_unlock(&ttcp_cong_list_lock);
	kfree(saved_clone);

	return ret;
}


/* Change congestion control for socket */
int ttcp_set_congestion_control(struct sock *sk, const char *name)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ttcp_congestion_ops *ca;
	int err = 0;

	rcu_read_lock();
	ca = ttcp_ca_find(name);

	/* no change asking for existing value */
	if (ca == icsk->icsk_ca_ops)
		goto out;

#ifdef CONFIG_MODULES
	/* not found attempt to autoload module */
	if (!ca && capable(CAP_NET_ADMIN)) {
		rcu_read_unlock();
		request_module("ttcp_%s", name);
		rcu_read_lock();
		ca = ttcp_ca_find(name);
	}
#endif
	if (!ca)
		err = -ENOENT;

	else if (!((ca->flags & TTCP_CONG_NON_RESTRICTED) || capable(CAP_NET_ADMIN)))
		err = -EPERM;

	else if (!try_module_get(ca->owner))
		err = -EBUSY;

	else {
		ttcp_cleanup_congestion_control(sk);
		icsk->icsk_ca_ops = ca;

		if (sk->sk_state != TTCP_CLOSE && icsk->icsk_ca_ops->init)
			icsk->icsk_ca_ops->init(sk);
	}
 out:
	rcu_read_unlock();
	return err;
}

/* RFC2861 Check whether we are limited by application or congestion window
 * This is the inverse of cwnd check in ttcp_tso_should_defer
 */
int ttcp_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{
	const struct ttcp_sock *tp = ttcp_sk(sk);
	u32 left;

	if (in_flight >= tp->snd_cwnd)
		return 1;

	left = tp->snd_cwnd - in_flight;
	if (sk_can_gso(sk) &&
	    left * sysctl_ttcp_tso_win_divisor < tp->snd_cwnd &&
	    left * tp->mss_cache < sk->sk_gso_max_size)
		return 1;
	return left <= ttcp_max_burst(tp);
}
EXPORT_SYMBOL_GPL(ttcp_is_cwnd_limited);

/*
 * Slow start is used when congestion window is less than slow start
 * threshold. This version implements the basic RFC2581 version
 * and optionally supports:
 * 	RFC3742 Limited Slow Start  	  - growth limited to max_ssthresh
 *	RFC3465 Appropriate Byte Counting - growth limited by bytes acknowledged
 */
void ttcp_slow_start(struct ttcp_sock *tp)
{
	int cnt; /* increase in packets */

	/* RFC3465: ABC Slow start
	 * Increase only after a full MSS of bytes is acked
	 *
	 * TTCP sender SHOULD increase cwnd by the number of
	 * previously unacknowledged bytes ACKed by each incoming
	 * acknowledgment, provided the increase is not more than L
	 */
	if (sysctl_ttcp_abc && tp->bytes_acked < tp->mss_cache)
		return;

	if (sysctl_ttcp_max_ssthresh > 0 && tp->snd_cwnd > sysctl_ttcp_max_ssthresh)
		cnt = sysctl_ttcp_max_ssthresh >> 1;	/* limited slow start */
	else
		cnt = tp->snd_cwnd;			/* exponential increase */

	/* RFC3465: ABC
	 * We MAY increase by 2 if discovered delayed ack
	 */
	if (sysctl_ttcp_abc > 1 && tp->bytes_acked >= 2*tp->mss_cache)
		cnt <<= 1;
	tp->bytes_acked = 0;

	tp->snd_cwnd_cnt += cnt;
	while (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		tp->snd_cwnd_cnt -= tp->snd_cwnd;
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
	}
}
EXPORT_SYMBOL_GPL(ttcp_slow_start);

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
void ttcp_cong_avoid_ai(struct ttcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}
EXPORT_SYMBOL_GPL(ttcp_cong_avoid_ai);

/*
 * TTCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void ttcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct ttcp_sock *tp = ttcp_sk(sk);

	if (!ttcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		ttcp_slow_start(tp);

	/* In dangerous area, increase slowly. */
	else if (sysctl_ttcp_abc) {
		/* RFC3465: Appropriate Byte Count
		 * increase once for each full cwnd acked
		 */
		if (tp->bytes_acked >= tp->snd_cwnd*tp->mss_cache) {
			tp->bytes_acked -= tp->snd_cwnd*tp->mss_cache;
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
		}
	} else {
		ttcp_cong_avoid_ai(tp, tp->snd_cwnd);
	}
}
EXPORT_SYMBOL_GPL(ttcp_reno_cong_avoid);

/* Slow start threshold is half the congestion window (min 2) */
u32 ttcp_reno_ssthresh(struct sock *sk)
{
	const struct ttcp_sock *tp = ttcp_sk(sk);
	return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(ttcp_reno_ssthresh);

/* Lower bound on congestion window with halving. */
u32 ttcp_reno_min_cwnd(const struct sock *sk)
{
	const struct ttcp_sock *tp = ttcp_sk(sk);
	return tp->snd_ssthresh/2;
}
EXPORT_SYMBOL_GPL(ttcp_reno_min_cwnd);

struct ttcp_congestion_ops ttcp_reno = {
	.flags		= TTCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	.owner		= THIS_MODULE,
	.ssthresh	= ttcp_reno_ssthresh,
	.cong_avoid	= ttcp_reno_cong_avoid,
	.min_cwnd	= ttcp_reno_min_cwnd,
};

/* Initial congestion control used (until SYN)
 * really reno under another name so we can tell difference
 * during ttcp_set_default_congestion_control
 */
struct ttcp_congestion_ops ttcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.ssthresh	= ttcp_reno_ssthresh,
	.cong_avoid	= ttcp_reno_cong_avoid,
	.min_cwnd	= ttcp_reno_min_cwnd,
};
EXPORT_SYMBOL_GPL(ttcp_init_congestion_ops);

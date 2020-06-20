/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TTCP protocol sk_state field.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TTCP_STATES_H
#define _LINUX_TTCP_STATES_H

enum {
	TTCP_ESTABLISHED = 1,
	TTCP_SYN_SENT,
	TTCP_SYN_RECV,
	TTCP_FIN_WAIT1,
	TTCP_FIN_WAIT2,
	TTCP_TIME_WAIT,
	TTCP_CLOSE,
	TTCP_CLOSE_WAIT,
	TTCP_LAST_ACK,
	TTCP_LISTEN,
	TTCP_CLOSING,	/* Now a valid state */

	TTCP_MAX_STATES	/* Leave at the end! */
};

#define TTCP_STATE_MASK	0xF

#define TTCP_ACTION_FIN	(1 << 7)

enum {
	TTCPF_ESTABLISHED = (1 << 1),
	TTCPF_SYN_SENT	 = (1 << 2),
	TTCPF_SYN_RECV	 = (1 << 3),
	TTCPF_FIN_WAIT1	 = (1 << 4),
	TTCPF_FIN_WAIT2	 = (1 << 5),
	TTCPF_TIME_WAIT	 = (1 << 6),
	TTCPF_CLOSE	 = (1 << 7),
	TTCPF_CLOSE_WAIT	 = (1 << 8),
	TTCPF_LAST_ACK	 = (1 << 9),
	TTCPF_LISTEN	 = (1 << 10),
	TTCPF_CLOSING	 = (1 << 11) 
};

#endif	/* _LINUX_TTCP_STATES_H */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * tcp.c, Code implementing the TCP protocol.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <socket_impl.h>
#include <socket_inet.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if_types.h>
#include <sys/salib.h>

#include "ipv4.h"
#include "ipv4_impl.h"
#include "mac.h"
#include "mac_impl.h"
#include "v4_sum_impl.h"
#include <sys/bootdebug.h>
#include "tcp_inet.h"
#include "tcp_sack.h"
#include <inet/common.h>
#include <inet/mib2.h>

/*
 * We need to redefine BUMP_MIB/UPDATE_MIB to not have DTrace probes.
 */
#undef BUMP_MIB
#define	BUMP_MIB(x) (x)++

#undef UPDATE_MIB
#define	UPDATE_MIB(x, y) x += y

/*
 * MIB-2 stuff for SNMP
 */
mib2_tcp_t	tcp_mib;	/* SNMP fixed size info */

/* The TCP mib does not include the following errors. */
static uint_t tcp_cksum_errors;
static uint_t tcp_drops;

/* Macros for timestamp comparisons */
#define	TSTMP_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)
#define	TSTMP_LT(a, b)	((int32_t)((a)-(b)) < 0)

/*
 * Parameters for TCP Initial Send Sequence number (ISS) generation.
 * The ISS is calculated by adding three components: a time component
 * which grows by 1 every 4096 nanoseconds (versus every 4 microseconds
 * suggested by RFC 793, page 27);
 * a per-connection component which grows by 125000 for every new connection;
 * and an "extra" component that grows by a random amount centered
 * approximately on 64000.  This causes the the ISS generator to cycle every
 * 4.89 hours if no TCP connections are made, and faster if connections are
 * made.
 */
#define	ISS_INCR	250000
#define	ISS_NSEC_SHT	0

static uint32_t tcp_iss_incr_extra;	/* Incremented for each connection */

#define	TCP_XMIT_LOWATER	4096
#define	TCP_XMIT_HIWATER	49152
#define	TCP_RECV_LOWATER	2048
#define	TCP_RECV_HIWATER	49152

/*
 *  PAWS needs a timer for 24 days.  This is the number of ms in 24 days
 */
#define	PAWS_TIMEOUT	((uint32_t)(24*24*60*60*1000))

/*
 * TCP options struct returned from tcp_parse_options.
 */
typedef struct tcp_opt_s {
	uint32_t	tcp_opt_mss;
	uint32_t	tcp_opt_wscale;
	uint32_t	tcp_opt_ts_val;
	uint32_t	tcp_opt_ts_ecr;
	tcp_t		*tcp;
} tcp_opt_t;

/*
 * RFC1323-recommended phrasing of TSTAMP option, for easier parsing
 */

#ifdef _BIG_ENDIAN
#define	TCPOPT_NOP_NOP_TSTAMP ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | \
	(TCPOPT_TSTAMP << 8) | 10)
#else
#define	TCPOPT_NOP_NOP_TSTAMP ((10 << 24) | (TCPOPT_TSTAMP << 16) | \
	(TCPOPT_NOP << 8) | TCPOPT_NOP)
#endif

/*
 * Flags returned from tcp_parse_options.
 */
#define	TCP_OPT_MSS_PRESENT	1
#define	TCP_OPT_WSCALE_PRESENT	2
#define	TCP_OPT_TSTAMP_PRESENT	4
#define	TCP_OPT_SACK_OK_PRESENT	8
#define	TCP_OPT_SACK_PRESENT	16

/* TCP option length */
#define	TCPOPT_NOP_LEN		1
#define	TCPOPT_MAXSEG_LEN	4
#define	TCPOPT_WS_LEN		3
#define	TCPOPT_REAL_WS_LEN	(TCPOPT_WS_LEN+1)
#define	TCPOPT_TSTAMP_LEN	10
#define	TCPOPT_REAL_TS_LEN	(TCPOPT_TSTAMP_LEN+2)
#define	TCPOPT_SACK_OK_LEN	2
#define	TCPOPT_REAL_SACK_OK_LEN	(TCPOPT_SACK_OK_LEN+2)
#define	TCPOPT_REAL_SACK_LEN	4
#define	TCPOPT_MAX_SACK_LEN	36
#define	TCPOPT_HEADER_LEN	2

/* TCP cwnd burst factor. */
#define	TCP_CWND_INFINITE	65535
#define	TCP_CWND_SS		3
#define	TCP_CWND_NORMAL		5

/* Named Dispatch Parameter Management Structure */
typedef struct tcpparam_s {
	uint32_t	tcp_param_min;
	uint32_t	tcp_param_max;
	uint32_t	tcp_param_val;
	char		*tcp_param_name;
} tcpparam_t;

/* Max size IP datagram is 64k - 1 */
#define	TCP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (struct ip) + \
	sizeof (tcph_t)))

/* Max of the above */
#define	TCP_MSS_MAX	TCP_MSS_MAX_IPV4

/* Largest TCP port number */
#define	TCP_MAX_PORT	(64 * 1024 - 1)

/* Round up the value to the nearest mss. */
#define	MSS_ROUNDUP(value, mss)		((((value) - 1) / (mss) + 1) * (mss))

#define	MS	1L
#define	SECONDS	(1000 * MS)
#define	MINUTES	(60 * SECONDS)
#define	HOURS	(60 * MINUTES)
#define	DAYS	(24 * HOURS)

/* All NDD params in the core TCP became static variables. */
static int	tcp_time_wait_interval = 1 * MINUTES;
static int	tcp_conn_req_max_q = 128;
static int	tcp_conn_req_max_q0 = 1024;
static int	tcp_conn_req_min = 1;
static int	tcp_conn_grace_period = 0 * SECONDS;
static int	tcp_cwnd_max_ = 1024 * 1024;
static int	tcp_smallest_nonpriv_port = 1024;
static int	tcp_ip_abort_cinterval = 3 * MINUTES;
static int	tcp_ip_abort_linterval = 3 * MINUTES;
static int	tcp_ip_abort_interval = 8 * MINUTES;
static int	tcp_ip_notify_cinterval = 10 * SECONDS;
static int	tcp_ip_notify_interval = 10 * SECONDS;
static int	tcp_ipv4_ttl = 64;
static int	tcp_mss_def_ipv4 = 536;
static int	tcp_mss_max_ipv4 = TCP_MSS_MAX_IPV4;
static int	tcp_mss_min = 108;
static int	tcp_naglim_def = (4*1024)-1;
static int	tcp_rexmit_interval_initial = 3 * SECONDS;
static int	tcp_rexmit_interval_max = 60 * SECONDS;
static int	tcp_rexmit_interval_min = 400 * MS;
static int	tcp_dupack_fast_retransmit = 3;
static int	tcp_smallest_anon_port = 32 * 1024;
static int	tcp_largest_anon_port = TCP_MAX_PORT;
static int	tcp_xmit_lowat = TCP_XMIT_LOWATER;
static int	tcp_recv_hiwat_minmss = 4;
static int	tcp_fin_wait_2_flush_interval = 1 * MINUTES;
static int	tcp_max_buf = 1024 * 1024;
static int	tcp_wscale_always = 1;
static int	tcp_tstamp_always = 1;
static int	tcp_tstamp_if_wscale = 1;
static int	tcp_rexmit_interval_extra = 0;
static int	tcp_slow_start_after_idle = 2;
static int	tcp_slow_start_initial = 2;
static int	tcp_sack_permitted = 2;
static int	tcp_ecn_permitted = 2;

/* Extra room to fit in headers. */
static uint_t	tcp_wroff_xtra;

/* Hint for next port to try. */
static in_port_t	tcp_next_port_to_try = 32*1024;

/*
 * Figure out the value of window scale opton.  Note that the rwnd is
 * ASSUMED to be rounded up to the nearest MSS before the calculation.
 * We cannot find the scale value and then do a round up of tcp_rwnd
 * because the scale value may not be correct after that.
 */
#define	SET_WS_VALUE(tcp) \
{ \
	int i; \
	uint32_t rwnd = (tcp)->tcp_rwnd; \
	for (i = 0; rwnd > TCP_MAXWIN && i < TCP_MAX_WINSHIFT; \
	    i++, rwnd >>= 1) \
		; \
	(tcp)->tcp_rcv_ws = i; \
}

/*
 * Set ECN capable transport (ECT) code point in IP header.
 *
 * Note that there are 2 ECT code points '01' and '10', which are called
 * ECT(1) and ECT(0) respectively.  Here we follow the original ECT code
 * point ECT(0) for TCP as described in RFC 2481.
 */
#define	SET_ECT(tcp, iph) \
	if ((tcp)->tcp_ipversion == IPV4_VERSION) { \
		/* We need to clear the code point first. */ \
		((struct ip *)(iph))->ip_tos &= 0xFC; \
		((struct ip *)(iph))->ip_tos |= IPH_ECN_ECT0; \
	}

/*
 * The format argument to pass to tcp_display().
 * DISP_PORT_ONLY means that the returned string has only port info.
 * DISP_ADDR_AND_PORT means that the returned string also contains the
 * remote and local IP address.
 */
#define	DISP_PORT_ONLY		1
#define	DISP_ADDR_AND_PORT	2

/*
 * TCP reassembly macros.  We hide starting and ending sequence numbers in
 * b_next and b_prev of messages on the reassembly queue.  The messages are
 * chained using b_cont.  These macros are used in tcp_reass() so we don't
 * have to see the ugly casts and assignments.
 * Note. use uintptr_t to suppress the gcc warning.
 */
#define	TCP_REASS_SEQ(mp)		((uint32_t)(uintptr_t)((mp)->b_next))
#define	TCP_REASS_SET_SEQ(mp, u)	((mp)->b_next = \
					    (mblk_t *)((uintptr_t)(u)))
#define	TCP_REASS_END(mp)		((uint32_t)(uintptr_t)((mp)->b_prev))
#define	TCP_REASS_SET_END(mp, u)	((mp)->b_prev = \
					    (mblk_t *)((uintptr_t)(u)))

#define	TCP_TIMER_RESTART(tcp, intvl) \
	(tcp)->tcp_rto_timeout = prom_gettime() + intvl; \
	(tcp)->tcp_timer_running = B_TRUE;

static int tcp_accept_comm(tcp_t *, tcp_t *, mblk_t *, uint_t);
static mblk_t *tcp_ack_mp(tcp_t *);
static in_port_t tcp_bindi(in_port_t, in_addr_t *, boolean_t, boolean_t);
static uint16_t tcp_cksum(uint16_t *, uint32_t);
static void tcp_clean_death(int, tcp_t *, int err);
static tcp_t *tcp_conn_request(tcp_t *, mblk_t *mp, uint_t, uint_t);
static char *tcp_display(tcp_t *, char *, char);
static int tcp_drain_input(tcp_t *, int, int);
static void tcp_drain_needed(int, tcp_t *);
static boolean_t tcp_drop_q0(tcp_t *);
static mblk_t *tcp_get_seg_mp(tcp_t *, uint32_t, int32_t *);
static int tcp_header_len(struct inetgram *);
static in_port_t tcp_report_ports(uint16_t *, enum Ports);
static int tcp_input(int);
static void tcp_iss_init(tcp_t *);
static tcp_t *tcp_lookup_ipv4(struct ip *, tcpha_t *, int, int *);
static tcp_t *tcp_lookup_listener_ipv4(in_addr_t, in_port_t, int *);
static int tcp_conn_check(tcp_t *);
static int tcp_close(int);
static void tcp_close_detached(tcp_t *);
static void tcp_eager_cleanup(tcp_t *, boolean_t, int);
static void tcp_eager_unlink(tcp_t *);
static void tcp_free(tcp_t *);
static int tcp_header_init_ipv4(tcp_t *);
static void tcp_mss_set(tcp_t *, uint32_t);
static int tcp_parse_options(tcph_t *, tcp_opt_t *);
static boolean_t tcp_paws_check(tcp_t *, tcph_t *, tcp_opt_t *);
static void tcp_process_options(tcp_t *, tcph_t *);
static int tcp_random(void);
static void tcp_random_init(void);
static mblk_t *tcp_reass(tcp_t *, mblk_t *, uint32_t);
static void tcp_reass_elim_overlap(tcp_t *, mblk_t *);
static void tcp_rcv_drain(int sock_id, tcp_t *);
static void tcp_rcv_enqueue(tcp_t *, mblk_t *, uint_t);
static void tcp_rput_data(tcp_t *, mblk_t *, int);
static int tcp_rwnd_set(tcp_t *, uint32_t);
static int32_t tcp_sack_rxmit(tcp_t *, int);
static void tcp_set_cksum(mblk_t *);
static void tcp_set_rto(tcp_t *, int32_t);
static void tcp_ss_rexmit(tcp_t *, int);
static int tcp_state_wait(int, tcp_t *, int);
static void tcp_timer(tcp_t *, int);
static void tcp_time_wait_append(tcp_t *);
static void tcp_time_wait_collector(void);
static void tcp_time_wait_processing(tcp_t *, mblk_t *, uint32_t,
    uint32_t, int, tcph_t *, int sock_id);
static void tcp_time_wait_remove(tcp_t *);
static in_port_t tcp_update_next_port(in_port_t);
static int tcp_verify_cksum(mblk_t *);
static void tcp_wput_data(tcp_t *, mblk_t *, int);
static void tcp_xmit_ctl(char *, tcp_t *, mblk_t *, uint32_t, uint32_t,
    int, uint_t, int);
static void tcp_xmit_early_reset(char *, int, mblk_t *, uint32_t, uint32_t,
    int, uint_t);
static int tcp_xmit_end(tcp_t *, int);
static void tcp_xmit_listeners_reset(int, mblk_t *, uint_t);
static mblk_t *tcp_xmit_mp(tcp_t *, mblk_t *, int32_t, int32_t *,
    mblk_t **, uint32_t, boolean_t, uint32_t *, boolean_t);
static int tcp_init_values(tcp_t *, struct inetboot_socket *);

#if DEBUG > 1
#define	TCP_DUMP_PACKET(str, mp) \
{ \
	int len = (mp)->b_wptr - (mp)->b_rptr; \
\
	printf("%s: dump TCP(%d): \n", (str), len); \
	hexdump((char *)(mp)->b_rptr, len); \
}
#else
#define	TCP_DUMP_PACKET(str, mp)
#endif

#ifdef DEBUG
#define	DEBUG_1(str, arg)		printf(str, (arg))
#define	DEBUG_2(str, arg1, arg2)	printf(str, (arg1), (arg2))
#define	DEBUG_3(str, arg1, arg2, arg3)	printf(str, (arg1), (arg2), (arg3))
#else
#define	DEBUG_1(str, arg)
#define	DEBUG_2(str, arg1, arg2)
#define	DEBUG_3(str, arg1, arg2, arg3)
#endif

/* Whether it is the first time TCP is used. */
static boolean_t tcp_initialized = B_FALSE;

/* TCP time wait list. */
static tcp_t *tcp_time_wait_head;
static tcp_t *tcp_time_wait_tail;
static uint32_t tcp_cum_timewait;
/* When the tcp_time_wait_collector is run. */
static uint32_t tcp_time_wait_runtime;

#define	TCP_RUN_TIME_WAIT_COLLECTOR() \
	if (prom_gettime() > tcp_time_wait_runtime) \
		tcp_time_wait_collector();

/*
 * Accept will return with an error if there is no connection coming in
 * after this (in ms).
 */
static int tcp_accept_timeout = 60000;

/*
 * Initialize the TCP-specific parts of a socket.
 */
void
tcp_socket_init(struct inetboot_socket *isp)
{
	/* Do some initializations. */
	if (!tcp_initialized) {
		tcp_random_init();
		/* Extra head room for the MAC layer address. */
		if ((tcp_wroff_xtra = mac_get_hdr_len()) & 0x3) {
			tcp_wroff_xtra = (tcp_wroff_xtra & ~0x3) + 0x4;
		}
		/* Schedule the first time wait cleanup time */
		tcp_time_wait_runtime = prom_gettime() + tcp_time_wait_interval;
		tcp_initialized = B_TRUE;
	}
	TCP_RUN_TIME_WAIT_COLLECTOR();

	isp->proto = IPPROTO_TCP;
	isp->input[TRANSPORT_LVL] = tcp_input;
	/* Socket layer should call tcp_send() directly. */
	isp->output[TRANSPORT_LVL] = NULL;
	isp->close[TRANSPORT_LVL] = tcp_close;
	isp->headerlen[TRANSPORT_LVL] = tcp_header_len;
	isp->ports = tcp_report_ports;
	if ((isp->pcb = bkmem_alloc(sizeof (tcp_t))) == NULL) {
		errno = ENOBUFS;
		return;
	}
	if ((errno = tcp_init_values((tcp_t *)isp->pcb, isp)) != 0) {
		bkmem_free(isp->pcb, sizeof (tcp_t));
		return;
	}
	/*
	 * This is set last because this field is used to determine if
	 * a socket is in use or not.
	 */
	isp->type = INETBOOT_STREAM;
}

/*
 * Return the size of a TCP header including TCP option.
 */
static int
tcp_header_len(struct inetgram *igm)
{
	mblk_t *pkt;
	int ipvers;

	/* Just returns the standard TCP header without option */
	if (igm == NULL)
		return (sizeof (tcph_t));

	if ((pkt = igm->igm_mp) == NULL)
		return (0);

	ipvers = ((struct ip *)pkt->b_rptr)->ip_v;
	if (ipvers == IPV4_VERSION) {
		return (TCP_HDR_LENGTH((tcph_t *)(pkt + IPH_HDR_LENGTH(pkt))));
	} else {
		dprintf("tcp_header_len: non-IPv4 packet.\n");
		return (0);
	}
}

/*
 * Return the requested port number in network order.
 */
static in_port_t
tcp_report_ports(uint16_t *tcphp, enum Ports request)
{
	if (request == SOURCE)
		return (*(uint16_t *)(((tcph_t *)tcphp)->th_lport));
	return (*(uint16_t *)(((tcph_t *)tcphp)->th_fport));
}

/*
 * Because inetboot is not interrupt driven, TCP can only poll.  This
 * means that there can be packets stuck in the NIC buffer waiting to
 * be processed.  Thus we need to drain them before, for example, sending
 * anything because an ACK may actually be stuck there.
 *
 * The timeout arguments determine how long we should wait for draining.
 */
static int
tcp_drain_input(tcp_t *tcp, int sock_id, int timeout)
{
	struct inetgram *in_gram;
	struct inetgram *old_in_gram;
	int old_timeout;
	mblk_t *mp;
	int i;

	dprintf("tcp_drain_input(%d): %s\n", sock_id,
	    tcp_display(tcp, NULL, DISP_ADDR_AND_PORT));

	/*
	 * Since the driver uses the in_timeout value in the socket
	 * structure to determine the timeout value, we need to save
	 * the original one so that we can restore that after draining.
	 */
	old_timeout = sockets[sock_id].in_timeout;
	sockets[sock_id].in_timeout = timeout;

	/*
	 * We do this because the input queue may have some user
	 * data already.
	 */
	old_in_gram = sockets[sock_id].inq;
	sockets[sock_id].inq = NULL;

	/* Go out and check the wire */
	for (i = MEDIA_LVL; i < TRANSPORT_LVL; i++) {
		if (sockets[sock_id].input[i] != NULL) {
			if (sockets[sock_id].input[i](sock_id) < 0) {
				sockets[sock_id].in_timeout = old_timeout;
				if (sockets[sock_id].inq != NULL)
					nuke_grams(&sockets[sock_id].inq);
				sockets[sock_id].inq = old_in_gram;
				return (-1);
			}
		}
	}
#if DEBUG
	printf("tcp_drain_input: done with checking packets\n");
#endif
	while ((in_gram = sockets[sock_id].inq) != NULL) {
		/* Remove unknown inetgrams from the head of inq. */
		if (in_gram->igm_level != TRANSPORT_LVL) {
#if DEBUG
			printf("tcp_drain_input: unexpected packet "
			    "level %d frame found\n", in_gram->igm_level);
#endif
			del_gram(&sockets[sock_id].inq, in_gram, B_TRUE);
			continue;
		}
		mp = in_gram->igm_mp;
		del_gram(&sockets[sock_id].inq, in_gram, B_FALSE);
		bkmem_free((caddr_t)in_gram, sizeof (struct inetgram));
		tcp_rput_data(tcp, mp, sock_id);
		sockets[sock_id].in_timeout = old_timeout;

		/*
		 * The other side may have closed this connection or
		 * RST us.  But we need to continue to process other
		 * packets in the socket's queue because they may be
		 * belong to another TCP connections.
		 */
		if (sockets[sock_id].pcb == NULL)
			tcp = NULL;
	}

	if (tcp == NULL || sockets[sock_id].pcb == NULL) {
		if (sockets[sock_id].so_error != 0)
			return (-1);
		else
			return (0);
	}
#if DEBUG
	printf("tcp_drain_input: done with processing packets\n");
#endif
	sockets[sock_id].in_timeout = old_timeout;
	sockets[sock_id].inq = old_in_gram;

	/*
	 * Data may have been received so indicate it is available
	 */
	tcp_drain_needed(sock_id, tcp);
	return (0);
}

/*
 * The receive entry point for upper layer to call to get data.  Note
 * that this follows the current architecture that lower layer receive
 * routines have been called already.  Thus if the inq of socket is
 * not NULL, the packets must be for us.
 */
static int
tcp_input(int sock_id)
{
	struct inetgram *in_gram;
	mblk_t *mp;
	tcp_t *tcp;

	TCP_RUN_TIME_WAIT_COLLECTOR();

	if ((tcp = sockets[sock_id].pcb) == NULL)
		return (-1);

	while ((in_gram = sockets[sock_id].inq) != NULL) {
		/* Remove unknown inetgrams from the head of inq. */
		if (in_gram->igm_level != TRANSPORT_LVL) {
#ifdef DEBUG
			printf("tcp_input: unexpected packet "
			    "level %d frame found\n", in_gram->igm_level);
#endif
			del_gram(&sockets[sock_id].inq, in_gram, B_TRUE);
			continue;
		}
		mp = in_gram->igm_mp;
		del_gram(&sockets[sock_id].inq, in_gram, B_FALSE);
		bkmem_free((caddr_t)in_gram, sizeof (struct inetgram));
		tcp_rput_data(tcp, mp, sock_id);
		/* The TCP may be gone because it gets a RST. */
		if (sockets[sock_id].pcb == NULL)
			return (-1);
	}

	/* Flush the receive list. */
	if (tcp->tcp_rcv_list != NULL) {
		tcp_rcv_drain(sock_id, tcp);
	} else {
		/* The other side has closed the connection, report this up. */
		if (tcp->tcp_state == TCPS_CLOSE_WAIT) {
			sockets[sock_id].so_state |= SS_CANTRCVMORE;
			return (0);
		}
	}
	return (0);
}

/*
 * The send entry point for upper layer to call to send data.  In order
 * to minimize changes to the core TCP code, we need to put the
 * data into mblks.
 */
int
tcp_send(int sock_id, tcp_t *tcp, const void *msg, int len)
{
	mblk_t *mp;
	mblk_t *head = NULL;
	mblk_t *tail;
	int mss = tcp->tcp_mss;
	int cnt = 0;
	int win_size;
	char *buf = (char *)msg;

	TCP_RUN_TIME_WAIT_COLLECTOR();

	/* We don't want to append 0 size mblk. */
	if (len == 0)
		return (0);
	while (len > 0) {
		if (len < mss) {
			mss = len;
		}
		/*
		 * If we cannot allocate more buffer, stop here and
		 * the number of bytes buffered will be returned.
		 *
		 * Note that we follow the core TCP optimization that
		 * each mblk contains only MSS bytes data.
		 */
		if ((mp = allocb(mss + tcp->tcp_ip_hdr_len +
		    TCP_MAX_HDR_LENGTH + tcp_wroff_xtra, 0)) == NULL) {
			break;
		}
		mp->b_rptr += tcp->tcp_hdr_len + tcp_wroff_xtra;
		bcopy(buf, mp->b_rptr, mss);
		mp->b_wptr = mp->b_rptr + mss;
		buf += mss;
		cnt += mss;
		len -= mss;

		if (head == NULL) {
			head = mp;
			tail = mp;
		} else {
			tail->b_cont = mp;
			tail = mp;
		}
	}

	/*
	 * Since inetboot is not interrupt driven, there may be
	 * some ACKs in the MAC's buffer.  Drain them first,
	 * otherwise, we may not be able to send.
	 *
	 * We expect an ACK in two cases:
	 *
	 * 1) We have un-ACK'ed data.
	 *
	 * 2) All ACK's have been received and the sender's window has been
	 * closed.  We need an ACK back to open the window so that we can
	 * send.  In this case, call tcp_drain_input() if the window size is
	 * less than 2 * MSS.
	 */

	/* window size = MIN(swnd, cwnd) - unacked bytes */
	win_size = (tcp->tcp_swnd > tcp->tcp_cwnd) ? tcp->tcp_cwnd :
		tcp->tcp_swnd;
	win_size -= tcp->tcp_snxt;
	win_size += tcp->tcp_suna;
	if (win_size < (2 * tcp->tcp_mss))
		if (tcp_drain_input(tcp, sock_id, 5) < 0)
			return (-1);

	tcp_wput_data(tcp, head, sock_id);
	/*
	 * errno should be reset here as it may be
	 * set to ETIMEDOUT. This may be set by
	 * the MAC driver in case it has timed out
	 * waiting for ARP reply. Any segment which
	 * was not transmitted because of ARP timeout
	 * will be retransmitted by TCP.
	 */
	if (errno == ETIMEDOUT)
		errno = 0;
	return (cnt);
}

/* Free up all TCP related stuff */
static void
tcp_free(tcp_t *tcp)
{
	if (tcp->tcp_iphc != NULL) {
		bkmem_free((caddr_t)tcp->tcp_iphc, tcp->tcp_iphc_len);
		tcp->tcp_iphc = NULL;
	}
	if (tcp->tcp_xmit_head != NULL) {
		freemsg(tcp->tcp_xmit_head);
		tcp->tcp_xmit_head = NULL;
	}
	if (tcp->tcp_rcv_list != NULL) {
		freemsg(tcp->tcp_rcv_list);
		tcp->tcp_rcv_list = NULL;
	}
	if (tcp->tcp_reass_head != NULL) {
		freemsg(tcp->tcp_reass_head);
		tcp->tcp_reass_head = NULL;
	}
	if (tcp->tcp_sack_info != NULL) {
		bkmem_free((caddr_t)tcp->tcp_sack_info,
		    sizeof (tcp_sack_info_t));
		tcp->tcp_sack_info = NULL;
	}
}

static void
tcp_close_detached(tcp_t *tcp)
{
	if (tcp->tcp_listener != NULL)
		tcp_eager_unlink(tcp);
	tcp_free(tcp);
	bkmem_free((caddr_t)tcp, sizeof (tcp_t));
}

/*
 * If we are an eager connection hanging off a listener that hasn't
 * formally accepted the connection yet, get off its list and blow off
 * any data that we have accumulated.
 */
static void
tcp_eager_unlink(tcp_t *tcp)
{
	tcp_t	*listener = tcp->tcp_listener;

	assert(listener != NULL);
	if (tcp->tcp_eager_next_q0 != NULL) {
		assert(tcp->tcp_eager_prev_q0 != NULL);

		/* Remove the eager tcp from q0 */
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		listener->tcp_conn_req_cnt_q0--;
	} else {
		tcp_t   **tcpp = &listener->tcp_eager_next_q;
		tcp_t	*prev = NULL;

		for (; tcpp[0]; tcpp = &tcpp[0]->tcp_eager_next_q) {
			if (tcpp[0] == tcp) {
				if (listener->tcp_eager_last_q == tcp) {
					/*
					 * If we are unlinking the last
					 * element on the list, adjust
					 * tail pointer. Set tail pointer
					 * to nil when list is empty.
					 */
					assert(tcp->tcp_eager_next_q == NULL);
					if (listener->tcp_eager_last_q ==
					    listener->tcp_eager_next_q) {
						listener->tcp_eager_last_q =
						NULL;
					} else {
						/*
						 * We won't get here if there
						 * is only one eager in the
						 * list.
						 */
						assert(prev != NULL);
						listener->tcp_eager_last_q =
						    prev;
					}
				}
				tcpp[0] = tcp->tcp_eager_next_q;
				tcp->tcp_eager_next_q = NULL;
				tcp->tcp_eager_last_q = NULL;
				listener->tcp_conn_req_cnt_q--;
				break;
			}
			prev = tcpp[0];
		}
	}
	tcp->tcp_listener = NULL;
}

/*
 * Reset any eager connection hanging off this listener
 * and then reclaim it's resources.
 */
static void
tcp_eager_cleanup(tcp_t *listener, boolean_t q0_only, int sock_id)
{
	tcp_t	*eager;

	if (!q0_only) {
		/* First cleanup q */
		while ((eager = listener->tcp_eager_next_q) != NULL) {
			assert(listener->tcp_eager_last_q != NULL);
			tcp_xmit_ctl("tcp_eager_cleanup, can't wait",
			    eager, NULL, eager->tcp_snxt, 0, TH_RST, 0,
			    sock_id);
			tcp_close_detached(eager);
		}
		assert(listener->tcp_eager_last_q == NULL);
	}
	/* Then cleanup q0 */
	while ((eager = listener->tcp_eager_next_q0) != listener) {
		tcp_xmit_ctl("tcp_eager_cleanup, can't wait",
		    eager, NULL, eager->tcp_snxt, 0, TH_RST, 0, sock_id);
		tcp_close_detached(eager);
	}
}

/*
 * To handle the shutdown request. Called from shutdown()
 */
int
tcp_shutdown(int sock_id)
{
	tcp_t	*tcp;

	DEBUG_1("tcp_shutdown: sock_id %x\n", sock_id);

	if ((tcp = sockets[sock_id].pcb) == NULL) {
		return (-1);
	}

	/*
	 * Since inetboot is not interrupt driven, there may be
	 * some ACKs in the MAC's buffer.  Drain them first,
	 * otherwise, we may not be able to send.
	 */
	if (tcp_drain_input(tcp, sock_id, 5) < 0) {
		/*
		 * If we return now without freeing TCP, there will be
		 * a memory leak.
		 */
		if (sockets[sock_id].pcb != NULL)
			tcp_clean_death(sock_id, tcp, 0);
		return (-1);
	}

	DEBUG_1("tcp_shutdown: tcp_state %x\n", tcp->tcp_state);
	switch (tcp->tcp_state) {

	case TCPS_SYN_RCVD:
		/*
		 * Shutdown during the connect 3-way handshake
		 */
	case TCPS_ESTABLISHED:
		/*
		 * Transmit the FIN
		 * wait for the FIN to be ACKed,
		 * then remain in FIN_WAIT_2
		 */
		dprintf("tcp_shutdown: sending fin\n");
		if (tcp_xmit_end(tcp, sock_id) == 0 &&
			tcp_state_wait(sock_id, tcp, TCPS_FIN_WAIT_2) < 0) {
			/* During the wait, TCP may be gone... */
			if (sockets[sock_id].pcb == NULL)
				return (-1);
		}
		dprintf("tcp_shutdown: done\n");
		break;

	default:
		break;

	}
	return (0);
}

/* To handle closing of the socket */
static int
tcp_close(int sock_id)
{
	char	*msg;
	tcp_t	*tcp;
	int	error = 0;

	if ((tcp = sockets[sock_id].pcb) == NULL) {
		return (-1);
	}

	TCP_RUN_TIME_WAIT_COLLECTOR();

	/*
	 * Since inetboot is not interrupt driven, there may be
	 * some ACKs in the MAC's buffer.  Drain them first,
	 * otherwise, we may not be able to send.
	 */
	if (tcp_drain_input(tcp, sock_id, 5) < 0) {
		/*
		 * If we return now without freeing TCP, there will be
		 * a memory leak.
		 */
		if (sockets[sock_id].pcb != NULL)
			tcp_clean_death(sock_id, tcp, 0);
		return (-1);
	}

	if (tcp->tcp_conn_req_cnt_q0 != 0 || tcp->tcp_conn_req_cnt_q != 0) {
		/* Cleanup for listener */
		tcp_eager_cleanup(tcp, 0, sock_id);
	}

	msg = NULL;
	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
	case TCPS_IDLE:
	case TCPS_BOUND:
	case TCPS_LISTEN:
		break;
	case TCPS_SYN_SENT:
		msg = "tcp_close, during connect";
		break;
	case TCPS_SYN_RCVD:
		/*
		 * Close during the connect 3-way handshake
		 * but here there may or may not be pending data
		 * already on queue. Process almost same as in
		 * the ESTABLISHED state.
		 */
		/* FALLTHRU */
	default:
		/*
		 * If SO_LINGER has set a zero linger time, abort the
		 * connection with a reset.
		 */
		if (tcp->tcp_linger && tcp->tcp_lingertime == 0) {
			msg = "tcp_close, zero lingertime";
			break;
		}

		/*
		 * Abort connection if there is unread data queued.
		 */
		if (tcp->tcp_rcv_list != NULL ||
				tcp->tcp_reass_head != NULL) {
			msg = "tcp_close, unread data";
			break;
		}
		if (tcp->tcp_state <= TCPS_LISTEN)
			break;

		/*
		 * Transmit the FIN before detaching the tcp_t.
		 * After tcp_detach returns this queue/perimeter
		 * no longer owns the tcp_t thus others can modify it.
		 * The TCP could be closed in tcp_state_wait called by
		 * tcp_wput_data called by tcp_xmit_end.
		 */
		(void) tcp_xmit_end(tcp, sock_id);
		if (sockets[sock_id].pcb == NULL)
			return (0);

		/*
		 * If lingering on close then wait until the fin is acked,
		 * the SO_LINGER time passes, or a reset is sent/received.
		 */
		if (tcp->tcp_linger && tcp->tcp_lingertime > 0 &&
		    !(tcp->tcp_fin_acked) &&
		    tcp->tcp_state >= TCPS_ESTABLISHED) {
			uint32_t stoptime; /* in ms */

			tcp->tcp_client_errno = 0;
			stoptime = prom_gettime() +
			    (tcp->tcp_lingertime * 1000);
			while (!(tcp->tcp_fin_acked) &&
			    tcp->tcp_state >= TCPS_ESTABLISHED &&
			    tcp->tcp_client_errno == 0 &&
			    ((int32_t)(stoptime - prom_gettime()) > 0)) {
				if (tcp_drain_input(tcp, sock_id, 5) < 0) {
					if (sockets[sock_id].pcb != NULL) {
						tcp_clean_death(sock_id,
						    tcp, 0);
					}
					return (-1);
				}
			}
			tcp->tcp_client_errno = 0;
		}
		if (tcp_state_wait(sock_id, tcp, TCPS_TIME_WAIT) < 0) {
			/* During the wait, TCP may be gone... */
			if (sockets[sock_id].pcb == NULL)
				return (0);
			msg = "tcp_close, couldn't detach";
		} else {
			return (0);
		}
		break;
	}

	/* Something went wrong...  Send a RST and report the error */
	if (msg != NULL) {
		if (tcp->tcp_state == TCPS_ESTABLISHED ||
		    tcp->tcp_state == TCPS_CLOSE_WAIT)
			BUMP_MIB(tcp_mib.tcpEstabResets);
		if (tcp->tcp_state == TCPS_SYN_SENT ||
		    tcp->tcp_state == TCPS_SYN_RCVD)
			BUMP_MIB(tcp_mib.tcpAttemptFails);
		tcp_xmit_ctl(msg, tcp, NULL, tcp->tcp_snxt, 0, TH_RST, 0,
		    sock_id);
	}

	tcp_free(tcp);
	bkmem_free((caddr_t)tcp, sizeof (tcp_t));
	sockets[sock_id].pcb = NULL;
	return (error);
}

/* To make an endpoint a listener. */
int
tcp_listen(int sock_id, int backlog)
{
	tcp_t *tcp;

	if ((tcp = (tcp_t *)(sockets[sock_id].pcb)) == NULL) {
		errno = EINVAL;
		return (-1);
	}
	/* We allow calling listen() multiple times to change the backlog. */
	if (tcp->tcp_state > TCPS_LISTEN || tcp->tcp_state < TCPS_BOUND) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	/* The following initialization should only be done once. */
	if (tcp->tcp_state != TCPS_LISTEN) {
		tcp->tcp_eager_next_q0 = tcp->tcp_eager_prev_q0 = tcp;
		tcp->tcp_eager_next_q = NULL;
		tcp->tcp_state = TCPS_LISTEN;
		tcp->tcp_second_ctimer_threshold = tcp_ip_abort_linterval;
	}
	if ((tcp->tcp_conn_req_max = backlog) > tcp_conn_req_max_q) {
		tcp->tcp_conn_req_max = tcp_conn_req_max_q;
	}
	if (tcp->tcp_conn_req_max < tcp_conn_req_min) {
		tcp->tcp_conn_req_max = tcp_conn_req_min;
	}
	return (0);
}

/* To accept connections. */
int
tcp_accept(int sock_id, struct sockaddr *addr, socklen_t *addr_len)
{
	tcp_t *listener;
	tcp_t *eager;
	int sd, new_sock_id;
	struct sockaddr_in *new_addr = (struct sockaddr_in *)addr;
	int timeout;

	/* Sanity check. */
	if ((listener = (tcp_t *)(sockets[sock_id].pcb)) == NULL ||
	    new_addr == NULL || addr_len == NULL ||
	    *addr_len < sizeof (struct sockaddr_in) ||
	    listener->tcp_state != TCPS_LISTEN) {
		errno = EINVAL;
		return (-1);
	}

	if (sockets[sock_id].in_timeout > tcp_accept_timeout)
		timeout = prom_gettime() + sockets[sock_id].in_timeout;
	else
		timeout = prom_gettime() + tcp_accept_timeout;
	while (listener->tcp_eager_next_q == NULL &&
	    timeout > prom_gettime()) {
#if DEBUG
		printf("tcp_accept: Waiting in tcp_accept()\n");
#endif
		if (tcp_drain_input(listener, sock_id, 5) < 0) {
			return (-1);
		}
	}
	/* If there is an eager, don't timeout... */
	if (timeout <= prom_gettime() && listener->tcp_eager_next_q == NULL) {
#if DEBUG
		printf("tcp_accept: timeout\n");
#endif
		errno = ETIMEDOUT;
		return (-1);
	}
#if DEBUG
	printf("tcp_accept: got a connection\n");
#endif

	/* Now create the socket for this new TCP. */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}
	if ((new_sock_id = so_check_fd(sd, &errno)) == -1)
		/* This should not happen! */
		prom_panic("so_check_fd() fails in tcp_accept()");
	/* Free the TCP PCB in the original socket. */
	bkmem_free((caddr_t)(sockets[new_sock_id].pcb), sizeof (tcp_t));
	/* Dequeue the eager and attach it to the socket. */
	eager = listener->tcp_eager_next_q;
	listener->tcp_eager_next_q = eager->tcp_eager_next_q;
	if (listener->tcp_eager_last_q == eager)
		listener->tcp_eager_last_q = NULL;
	eager->tcp_eager_next_q = NULL;
	sockets[new_sock_id].pcb = eager;
	listener->tcp_conn_req_cnt_q--;

	/* Copy in the address info. */
	bcopy(&eager->tcp_remote, &new_addr->sin_addr.s_addr,
	    sizeof (in_addr_t));
	bcopy(&eager->tcp_fport, &new_addr->sin_port, sizeof (in_port_t));
	new_addr->sin_family = AF_INET;

#ifdef DEBUG
	printf("tcp_accept(), new sock_id: %d\n", sd);
#endif
	return (sd);
}

/* Update the next anonymous port to use.  */
static in_port_t
tcp_update_next_port(in_port_t port)
{
	/* Don't allow the port to fall out of the anonymous port range. */
	if (port < tcp_smallest_anon_port || port > tcp_largest_anon_port)
		port = (in_port_t)tcp_smallest_anon_port;

	if (port < tcp_smallest_nonpriv_port)
		port = (in_port_t)tcp_smallest_nonpriv_port;
	return (port);
}

/* To check whether a bind to a port is allowed. */
static in_port_t
tcp_bindi(in_port_t port, in_addr_t *addr, boolean_t reuseaddr,
    boolean_t bind_to_req_port_only)
{
	int i, count;
	tcp_t *tcp;

	count = tcp_largest_anon_port - tcp_smallest_anon_port;
try_again:
	for (i = 0; i < MAXSOCKET; i++) {
		if (sockets[i].type != INETBOOT_STREAM ||
		    ((tcp = (tcp_t *)sockets[i].pcb) == NULL) ||
		    ntohs(tcp->tcp_lport) != port) {
			continue;
		}
		/*
		 * Both TCPs have the same port.  If SO_REUSEDADDR is
		 * set and the bound TCP has a state greater than
		 * TCPS_LISTEN, it is fine.
		 */
		if (reuseaddr && tcp->tcp_state > TCPS_LISTEN) {
			continue;
		}
		if (tcp->tcp_bound_source != INADDR_ANY &&
		    *addr != INADDR_ANY &&
		    tcp->tcp_bound_source != *addr) {
			continue;
		}
		if (bind_to_req_port_only) {
			return (0);
		}
		if (--count > 0) {
			port = tcp_update_next_port(++port);
			goto try_again;
		} else {
			return (0);
		}
	}
	return (port);
}

/* To handle the bind request. */
int
tcp_bind(int sock_id)
{
	tcp_t *tcp;
	in_port_t requested_port, allocated_port;
	boolean_t bind_to_req_port_only;
	boolean_t reuseaddr;

	if ((tcp = (tcp_t *)sockets[sock_id].pcb) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (tcp->tcp_state >= TCPS_BOUND) {
		/* We don't allow multiple bind(). */
		errno = EPROTO;
		return (-1);
	}

	requested_port = ntohs(sockets[sock_id].bind.sin_port);

	/* The bound source can be INADDR_ANY. */
	tcp->tcp_bound_source = sockets[sock_id].bind.sin_addr.s_addr;

	tcp->tcp_ipha->ip_src.s_addr = tcp->tcp_bound_source;

	/* Verify the port is available. */
	if (requested_port == 0)
		bind_to_req_port_only = B_FALSE;
	else			/* T_BIND_REQ and requested_port != 0 */
		bind_to_req_port_only = B_TRUE;

	if (requested_port == 0) {
		requested_port = tcp_update_next_port(++tcp_next_port_to_try);
	}
	reuseaddr = sockets[sock_id].so_opt & SO_REUSEADDR;
	allocated_port = tcp_bindi(requested_port, &(tcp->tcp_bound_source),
	    reuseaddr, bind_to_req_port_only);

	if (allocated_port == 0) {
		errno = EADDRINUSE;
		return (-1);
	}
	tcp->tcp_lport = htons(allocated_port);
	*(uint16_t *)tcp->tcp_tcph->th_lport = tcp->tcp_lport;
	sockets[sock_id].bind.sin_port = tcp->tcp_lport;
	tcp->tcp_state = TCPS_BOUND;
	return (0);
}

/*
 * Check for duplicate TCP connections.
 */
static int
tcp_conn_check(tcp_t *tcp)
{
	int i;
	tcp_t *tmp_tcp;

	for (i = 0; i < MAXSOCKET; i++) {
		if (sockets[i].type != INETBOOT_STREAM)
			continue;
		/* Socket may not be closed but the TCP can be gone. */
		if ((tmp_tcp = (tcp_t *)sockets[i].pcb) == NULL)
			continue;
		/* We only care about TCP in states later than SYN_SENT. */
		if (tmp_tcp->tcp_state < TCPS_SYN_SENT)
			continue;
		if (tmp_tcp->tcp_lport != tcp->tcp_lport ||
		    tmp_tcp->tcp_fport != tcp->tcp_fport ||
		    tmp_tcp->tcp_bound_source != tcp->tcp_bound_source ||
		    tmp_tcp->tcp_remote != tcp->tcp_remote) {
			continue;
		} else {
			return (-1);
		}
	}
	return (0);
}

/* To handle a connect request. */
int
tcp_connect(int sock_id)
{
	tcp_t *tcp;
	in_addr_t dstaddr;
	in_port_t dstport;
	tcph_t	*tcph;
	int mss;
	mblk_t *syn_mp;

	if ((tcp = (tcp_t *)(sockets[sock_id].pcb)) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	TCP_RUN_TIME_WAIT_COLLECTOR();

	dstaddr = sockets[sock_id].remote.sin_addr.s_addr;
	dstport = sockets[sock_id].remote.sin_port;

	/*
	 * Check for attempt to connect to INADDR_ANY or non-unicast addrress.
	 * We don't have enough info to check for broadcast addr, except
	 * for the all 1 broadcast.
	 */
	if (dstaddr == INADDR_ANY || IN_CLASSD(ntohl(dstaddr)) ||
	    dstaddr == INADDR_BROADCAST)  {
		/*
		 * SunOS 4.x and 4.3 BSD allow an application
		 * to connect a TCP socket to INADDR_ANY.
		 * When they do this, the kernel picks the
		 * address of one interface and uses it
		 * instead.  The kernel usually ends up
		 * picking the address of the loopback
		 * interface.  This is an undocumented feature.
		 * However, we provide the same thing here
		 * in order to have source and binary
		 * compatibility with SunOS 4.x.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 *
		 * Fail this for inetboot TCP.
		 */
		errno = EINVAL;
		return (-1);
	}

	/* It is not bound to any address yet... */
	if (tcp->tcp_bound_source == INADDR_ANY) {
		ipv4_getipaddr(&(sockets[sock_id].bind.sin_addr));
		/* We don't have an address! */
		if (ntohl(sockets[sock_id].bind.sin_addr.s_addr) ==
		    INADDR_ANY) {
			errno = EPROTO;
			return (-1);
		}
		tcp->tcp_bound_source = sockets[sock_id].bind.sin_addr.s_addr;
		tcp->tcp_ipha->ip_src.s_addr = tcp->tcp_bound_source;
	}

	/*
	 * Don't let an endpoint connect to itself.
	 */
	if (dstaddr == tcp->tcp_ipha->ip_src.s_addr &&
	    dstport == tcp->tcp_lport) {
		errno = EINVAL;
		return (-1);
	}

	tcp->tcp_ipha->ip_dst.s_addr = dstaddr;
	tcp->tcp_remote = dstaddr;
	tcph = tcp->tcp_tcph;
	*(uint16_t *)tcph->th_fport = dstport;
	tcp->tcp_fport = dstport;

	/*
	 * Don't allow this connection to completely duplicate
	 * an existing connection.
	 */
	if (tcp_conn_check(tcp) < 0) {
		errno = EADDRINUSE;
		return (-1);
	}

	/*
	 * Just make sure our rwnd is at
	 * least tcp_recv_hiwat_mss * MSS
	 * large, and round up to the nearest
	 * MSS.
	 *
	 * We do the round up here because
	 * we need to get the interface
	 * MTU first before we can do the
	 * round up.
	 */
	mss = tcp->tcp_mss - tcp->tcp_hdr_len;
	tcp->tcp_rwnd = MAX(MSS_ROUNDUP(tcp->tcp_rwnd, mss),
	    tcp_recv_hiwat_minmss * mss);
	tcp->tcp_rwnd_max = tcp->tcp_rwnd;
	SET_WS_VALUE(tcp);
	U32_TO_ABE16((tcp->tcp_rwnd >> tcp->tcp_rcv_ws),
	    tcp->tcp_tcph->th_win);
	if (tcp->tcp_rcv_ws > 0 || tcp_wscale_always)
		tcp->tcp_snd_ws_ok = B_TRUE;

	/*
	 * Set tcp_snd_ts_ok to true
	 * so that tcp_xmit_mp will
	 * include the timestamp
	 * option in the SYN segment.
	 */
	if (tcp_tstamp_always ||
	    (tcp->tcp_rcv_ws && tcp_tstamp_if_wscale)) {
		tcp->tcp_snd_ts_ok = B_TRUE;
	}

	if (tcp_sack_permitted == 2 ||
	    tcp->tcp_snd_sack_ok) {
		assert(tcp->tcp_sack_info == NULL);
		if ((tcp->tcp_sack_info = (tcp_sack_info_t *)bkmem_zalloc(
		    sizeof (tcp_sack_info_t))) == NULL) {
			tcp->tcp_snd_sack_ok = B_FALSE;
		} else {
			tcp->tcp_snd_sack_ok = B_TRUE;
		}
	}
	/*
	 * Should we use ECN?  Note that the current
	 * default value (SunOS 5.9) of tcp_ecn_permitted
	 * is 2.  The reason for doing this is that there
	 * are equipments out there that will drop ECN
	 * enabled IP packets.  Setting it to 1 avoids
	 * compatibility problems.
	 */
	if (tcp_ecn_permitted == 2)
		tcp->tcp_ecn_ok = B_TRUE;

	tcp_iss_init(tcp);
	TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	tcp->tcp_active_open = B_TRUE;

	tcp->tcp_state = TCPS_SYN_SENT;
	syn_mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL, tcp->tcp_iss, B_FALSE,
	    NULL, B_FALSE);
	if (syn_mp != NULL) {
		int ret;

		/* Dump the packet when debugging. */
		TCP_DUMP_PACKET("tcp_connect", syn_mp);
		/* Send out the SYN packet. */
		ret = ipv4_tcp_output(sock_id, syn_mp);
		freeb(syn_mp);
		/*
		 * errno ETIMEDOUT is set by the mac driver
		 * in case it is not able to receive ARP reply.
		 * TCP will retransmit this segment so we can
		 * ignore the ARP timeout.
		 */
		if ((ret < 0) && (errno != ETIMEDOUT)) {
			return (-1);
		}
		/* tcp_state_wait() will finish the 3 way handshake. */
		return (tcp_state_wait(sock_id, tcp, TCPS_ESTABLISHED));
	} else {
		errno = ENOBUFS;
		return (-1);
	}
}

/*
 * Common accept code.  Called by tcp_conn_request.
 * cr_pkt is the SYN packet.
 */
static int
tcp_accept_comm(tcp_t *listener, tcp_t *acceptor, mblk_t *cr_pkt,
    uint_t ip_hdr_len)
{
	tcph_t		*tcph;

#ifdef DEBUG
	printf("tcp_accept_comm #######################\n");
#endif

	/*
	 * When we get here, we know that the acceptor header template
	 * has already been initialized.
	 * However, it may not match the listener if the listener
	 * includes options...
	 * It may also not match the listener if the listener is v6 and
	 * and the acceptor is v4
	 */
	acceptor->tcp_lport = listener->tcp_lport;

	if (listener->tcp_ipversion == acceptor->tcp_ipversion) {
		if (acceptor->tcp_iphc_len != listener->tcp_iphc_len) {
			/*
			 * Listener had options of some sort; acceptor inherits.
			 * Free up the acceptor template and allocate one
			 * of the right size.
			 */
			bkmem_free(acceptor->tcp_iphc, acceptor->tcp_iphc_len);
			acceptor->tcp_iphc = bkmem_zalloc(
			    listener->tcp_iphc_len);
			if (acceptor->tcp_iphc == NULL) {
				acceptor->tcp_iphc_len = 0;
				return (ENOMEM);
			}
			acceptor->tcp_iphc_len = listener->tcp_iphc_len;
		}
		acceptor->tcp_hdr_len = listener->tcp_hdr_len;
		acceptor->tcp_ip_hdr_len = listener->tcp_ip_hdr_len;
		acceptor->tcp_tcp_hdr_len = listener->tcp_tcp_hdr_len;

		/*
		 * Copy the IP+TCP header template from listener to acceptor
		 */
		bcopy(listener->tcp_iphc, acceptor->tcp_iphc,
		    listener->tcp_hdr_len);
		acceptor->tcp_ipha = (struct ip *)acceptor->tcp_iphc;
		acceptor->tcp_tcph = (tcph_t *)(acceptor->tcp_iphc +
		    acceptor->tcp_ip_hdr_len);
	} else {
		prom_panic("tcp_accept_comm: version not equal");
	}

	/* Copy our new dest and fport from the connection request packet */
	if (acceptor->tcp_ipversion == IPV4_VERSION) {
		struct ip *ipha;

		ipha = (struct ip *)cr_pkt->b_rptr;
		acceptor->tcp_ipha->ip_dst = ipha->ip_src;
		acceptor->tcp_remote = ipha->ip_src.s_addr;
		acceptor->tcp_ipha->ip_src = ipha->ip_dst;
		acceptor->tcp_bound_source = ipha->ip_dst.s_addr;
		tcph = (tcph_t *)&cr_pkt->b_rptr[ip_hdr_len];
	} else {
		prom_panic("tcp_accept_comm: not IPv4");
	}
	bcopy(tcph->th_lport, acceptor->tcp_tcph->th_fport, sizeof (in_port_t));
	bcopy(acceptor->tcp_tcph->th_fport, &acceptor->tcp_fport,
	    sizeof (in_port_t));
	/*
	 * For an all-port proxy listener, the local port is determined by
	 * the port number field in the SYN packet.
	 */
	if (listener->tcp_lport == 0) {
		acceptor->tcp_lport = *(in_port_t *)tcph->th_fport;
		bcopy(tcph->th_fport, acceptor->tcp_tcph->th_lport,
		    sizeof (in_port_t));
	}
	/* Inherit various TCP parameters from the listener */
	acceptor->tcp_naglim = listener->tcp_naglim;
	acceptor->tcp_first_timer_threshold =
	    listener->tcp_first_timer_threshold;
	acceptor->tcp_second_timer_threshold =
	    listener->tcp_second_timer_threshold;

	acceptor->tcp_first_ctimer_threshold =
	    listener->tcp_first_ctimer_threshold;
	acceptor->tcp_second_ctimer_threshold =
	    listener->tcp_second_ctimer_threshold;

	acceptor->tcp_xmit_hiwater = listener->tcp_xmit_hiwater;

	acceptor->tcp_state = TCPS_LISTEN;
	tcp_iss_init(acceptor);

	/* Process all TCP options. */
	tcp_process_options(acceptor, tcph);

	/* Is the other end ECN capable? */
	if (tcp_ecn_permitted >= 1 &&
	    (tcph->th_flags[0] & (TH_ECE|TH_CWR)) == (TH_ECE|TH_CWR)) {
		acceptor->tcp_ecn_ok = B_TRUE;
	}

	/*
	 * listener->tcp_rq->q_hiwat should be the default window size or a
	 * window size changed via SO_RCVBUF option.  First round up the
	 * acceptor's tcp_rwnd to the nearest MSS.  Then find out the window
	 * scale option value if needed.  Call tcp_rwnd_set() to finish the
	 * setting.
	 *
	 * Note if there is a rpipe metric associated with the remote host,
	 * we should not inherit receive window size from listener.
	 */
	acceptor->tcp_rwnd = MSS_ROUNDUP(
	    (acceptor->tcp_rwnd == 0 ? listener->tcp_rwnd_max :
	    acceptor->tcp_rwnd), acceptor->tcp_mss);
	if (acceptor->tcp_snd_ws_ok)
		SET_WS_VALUE(acceptor);
	/*
	 * Note that this is the only place tcp_rwnd_set() is called for
	 * accepting a connection.  We need to call it here instead of
	 * after the 3-way handshake because we need to tell the other
	 * side our rwnd in the SYN-ACK segment.
	 */
	(void) tcp_rwnd_set(acceptor, acceptor->tcp_rwnd);

	return (0);
}

/*
 * Defense for the SYN attack -
 * 1. When q0 is full, drop from the tail (tcp_eager_prev_q0) the oldest
 *    one that doesn't have the dontdrop bit set.
 * 2. Don't drop a SYN request before its first timeout. This gives every
 *    request at least til the first timeout to complete its 3-way handshake.
 * 3. The current threshold is - # of timeout > q0len/4 => SYN alert on
 *    # of timeout drops back to <= q0len/32 => SYN alert off
 */
static boolean_t
tcp_drop_q0(tcp_t *tcp)
{
	tcp_t	*eager;

	assert(tcp->tcp_eager_next_q0 != tcp->tcp_eager_prev_q0);
	/*
	 * New one is added after next_q0 so prev_q0 points to the oldest
	 * Also do not drop any established connections that are deferred on
	 * q0 due to q being full
	 */

	eager = tcp->tcp_eager_prev_q0;
	while (eager->tcp_dontdrop || eager->tcp_conn_def_q0) {
		/* XXX should move the eager to the head */
		eager = eager->tcp_eager_prev_q0;
		if (eager == tcp) {
			eager = tcp->tcp_eager_prev_q0;
			break;
		}
	}
	dprintf("tcp_drop_q0: listen half-open queue (max=%d) overflow"
	    " (%d pending) on %s, drop one", tcp_conn_req_max_q0,
	    tcp->tcp_conn_req_cnt_q0,
	    tcp_display(tcp, NULL, DISP_PORT_ONLY));

	BUMP_MIB(tcp_mib.tcpHalfOpenDrop);
	bkmem_free((caddr_t)eager, sizeof (tcp_t));
	return (B_TRUE);
}

/* ARGSUSED */
static tcp_t *
tcp_conn_request(tcp_t *tcp, mblk_t *mp, uint_t sock_id, uint_t ip_hdr_len)
{
	tcp_t	*eager;
	struct ip *ipha;
	int	err;

#ifdef DEBUG
	printf("tcp_conn_request ###################\n");
#endif

	if (tcp->tcp_conn_req_cnt_q >= tcp->tcp_conn_req_max) {
		BUMP_MIB(tcp_mib.tcpListenDrop);
		dprintf("tcp_conn_request: listen backlog (max=%d) "
		    "overflow (%d pending) on %s",
		    tcp->tcp_conn_req_max, tcp->tcp_conn_req_cnt_q,
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
		return (NULL);
	}

	assert(OK_32PTR(mp->b_rptr));

	if (tcp->tcp_conn_req_cnt_q0 >=
	    tcp->tcp_conn_req_max + tcp_conn_req_max_q0) {
		/*
		 * Q0 is full. Drop a pending half-open req from the queue
		 * to make room for the new SYN req. Also mark the time we
		 * drop a SYN.
		 */
		tcp->tcp_last_rcv_lbolt = prom_gettime();
		if (!tcp_drop_q0(tcp)) {
			freemsg(mp);
			BUMP_MIB(tcp_mib.tcpListenDropQ0);
			dprintf("tcp_conn_request: listen half-open queue "
			    "(max=%d) full (%d pending) on %s",
			    tcp_conn_req_max_q0,
			    tcp->tcp_conn_req_cnt_q0,
			    tcp_display(tcp, NULL, DISP_PORT_ONLY));
			return (NULL);
		}
	}

	ipha = (struct ip *)mp->b_rptr;
	if (IN_CLASSD(ntohl(ipha->ip_src.s_addr)) ||
	    ipha->ip_src.s_addr == INADDR_BROADCAST ||
	    ipha->ip_src.s_addr == INADDR_ANY ||
	    ipha->ip_dst.s_addr == INADDR_BROADCAST) {
		freemsg(mp);
		return (NULL);
	}
	/*
	 * We allow the connection to proceed
	 * by generating a detached tcp state vector and put it in
	 * the eager queue.  When an accept happens, it will be
	 * dequeued sequentially.
	 */
	if ((eager = (tcp_t *)bkmem_alloc(sizeof (tcp_t))) == NULL) {
		freemsg(mp);
		errno = ENOBUFS;
		return (NULL);
	}
	if ((errno = tcp_init_values(eager, NULL)) != 0) {
		freemsg(mp);
		bkmem_free((caddr_t)eager, sizeof (tcp_t));
		return (NULL);
	}

	/*
	 * Eager connection inherits address form from its listener,
	 * but its packet form comes from the version of the received
	 * SYN segment.
	 */
	eager->tcp_family = tcp->tcp_family;

	err = tcp_accept_comm(tcp, eager, mp, ip_hdr_len);
	if (err) {
		bkmem_free((caddr_t)eager, sizeof (tcp_t));
		return (NULL);
	}

	tcp->tcp_eager_next_q0->tcp_eager_prev_q0 = eager;
	eager->tcp_eager_next_q0 = tcp->tcp_eager_next_q0;
	tcp->tcp_eager_next_q0 = eager;
	eager->tcp_eager_prev_q0 = tcp;

	/* Set tcp_listener before adding it to tcp_conn_fanout */
	eager->tcp_listener = tcp;
	tcp->tcp_conn_req_cnt_q0++;

	return (eager);
}

/*
 * To get around the non-interrupt problem of inetboot.
 * Keep on processing packets until a certain state is reached or the
 * TCP is destroyed because of getting a RST packet.
 */
static int
tcp_state_wait(int sock_id, tcp_t *tcp, int state)
{
	int i;
	struct inetgram *in_gram;
	mblk_t *mp;
	int timeout;
	boolean_t changed = B_FALSE;

	/*
	 * We need to make sure that the MAC does not wait longer
	 * than RTO for any packet so that TCP can do retransmission.
	 * But if the MAC timeout is less than tcp_rto, we are fine
	 * and do not need to change it.
	 */
	timeout = sockets[sock_id].in_timeout;
	if (timeout > tcp->tcp_rto) {
		sockets[sock_id].in_timeout = tcp->tcp_rto;
		changed = B_TRUE;
	}
retry:
	if (sockets[sock_id].inq == NULL) {
		/* Go out and check the wire */
		for (i = MEDIA_LVL; i < TRANSPORT_LVL; i++) {
			if (sockets[sock_id].input[i] != NULL) {
				if (sockets[sock_id].input[i](sock_id) < 0) {
					if (changed) {
						sockets[sock_id].in_timeout =
						    timeout;
					}
					return (-1);
				}
			}
		}
	}

	while ((in_gram = sockets[sock_id].inq) != NULL) {
		if (tcp != NULL && tcp->tcp_state == state)
			break;

		/* Remove unknown inetgrams from the head of inq. */
		if (in_gram->igm_level != TRANSPORT_LVL) {
#ifdef DEBUG
			printf("tcp_state_wait for state %d: unexpected "
			    "packet level %d frame found\n", state,
			    in_gram->igm_level);
#endif
			del_gram(&sockets[sock_id].inq, in_gram, B_TRUE);
			continue;
		}
		mp = in_gram->igm_mp;
		del_gram(&sockets[sock_id].inq, in_gram, B_FALSE);
		bkmem_free((caddr_t)in_gram, sizeof (struct inetgram));
		tcp_rput_data(tcp, mp, sock_id);

		/*
		 * The other side may have closed this connection or
		 * RST us.  But we need to continue to process other
		 * packets in the socket's queue because they may be
		 * belong to another TCP connections.
		 */
		if (sockets[sock_id].pcb == NULL) {
			tcp = NULL;
		}
	}

	/* If the other side has closed the connection, just return. */
	if (tcp == NULL || sockets[sock_id].pcb == NULL) {
#ifdef DEBUG
		printf("tcp_state_wait other side dead: state %d "
		    "error %d\n", state, sockets[sock_id].so_error);
#endif
		if (sockets[sock_id].so_error != 0)
			return (-1);
		else
			return (0);
	}
	/*
	 * TCPS_ALL_ACKED is not a valid TCP state, it is just used as an
	 * indicator to tcp_state_wait to mean that it is being called
	 * to wait till we have received acks for all the new segments sent.
	 */
	if ((state == TCPS_ALL_ACKED) && (tcp->tcp_suna == tcp->tcp_snxt)) {
		goto done;
	}
	if (tcp->tcp_state != state) {
		if (prom_gettime() > tcp->tcp_rto_timeout)
			tcp_timer(tcp, sock_id);
		goto retry;
	}
done:
	if (changed)
		sockets[sock_id].in_timeout = timeout;

	tcp_drain_needed(sock_id, tcp);
	return (0);
}

/* Verify the checksum of a segment. */
static int
tcp_verify_cksum(mblk_t *mp)
{
	struct ip *iph;
	tcpha_t *tcph;
	int len;
	uint16_t old_sum;

	iph = (struct ip *)mp->b_rptr;
	tcph = (tcpha_t *)(iph + 1);
	len = ntohs(iph->ip_len);

	/*
	 * Calculate the TCP checksum.  Need to include the psuedo header,
	 * which is similar to the real IP header starting at the TTL field.
	 */
	iph->ip_sum = htons(len - IP_SIMPLE_HDR_LENGTH);
	old_sum = tcph->tha_sum;
	tcph->tha_sum = 0;
	iph->ip_ttl = 0;
	if (old_sum == tcp_cksum((uint16_t *)&(iph->ip_ttl),
	    len - IP_SIMPLE_HDR_LENGTH + 12)) {
		return (0);
	} else {
		tcp_cksum_errors++;
		return (-1);
	}
}

/* To find a TCP connection matching the incoming segment. */
static tcp_t *
tcp_lookup_ipv4(struct ip *iph, tcpha_t *tcph, int min_state, int *sock_id)
{
	int i;
	tcp_t *tcp;

	for (i = 0; i < MAXSOCKET; i++) {
		if (sockets[i].type == INETBOOT_STREAM &&
		    (tcp = (tcp_t *)sockets[i].pcb) != NULL) {
			if (tcph->tha_lport == tcp->tcp_fport &&
			    tcph->tha_fport == tcp->tcp_lport &&
			    iph->ip_src.s_addr == tcp->tcp_remote &&
			    iph->ip_dst.s_addr == tcp->tcp_bound_source &&
			    tcp->tcp_state >= min_state) {
				*sock_id = i;
				return (tcp);
			}
		}
	}
	/* Find it in the time wait list. */
	for (tcp = tcp_time_wait_head; tcp != NULL;
	    tcp = tcp->tcp_time_wait_next) {
		if (tcph->tha_lport == tcp->tcp_fport &&
		    tcph->tha_fport == tcp->tcp_lport &&
		    iph->ip_src.s_addr == tcp->tcp_remote &&
		    iph->ip_dst.s_addr == tcp->tcp_bound_source &&
		    tcp->tcp_state >= min_state) {
			*sock_id = -1;
			return (tcp);
		}
	}
	return (NULL);
}

/* To find a TCP listening connection matching the incoming segment. */
static tcp_t *
tcp_lookup_listener_ipv4(in_addr_t addr, in_port_t port, int *sock_id)
{
	int i;
	tcp_t *tcp;

	for (i = 0; i < MAXSOCKET; i++) {
		if (sockets[i].type == INETBOOT_STREAM &&
		    (tcp = (tcp_t *)sockets[i].pcb) != NULL) {
			if (tcp->tcp_lport == port &&
			    (tcp->tcp_bound_source == addr ||
			    tcp->tcp_bound_source == INADDR_ANY)) {
				*sock_id = i;
				return (tcp);
			}
		}
	}

	return (NULL);
}

/* To find a TCP eager matching the incoming segment. */
static tcp_t *
tcp_lookup_eager_ipv4(tcp_t *listener, struct ip *iph, tcpha_t *tcph)
{
	tcp_t *tcp;

#ifdef DEBUG
	printf("tcp_lookup_eager_ipv4 ###############\n");
#endif
	for (tcp = listener->tcp_eager_next_q; tcp != NULL;
	    tcp = tcp->tcp_eager_next_q) {
		if (tcph->tha_lport == tcp->tcp_fport &&
		    tcph->tha_fport == tcp->tcp_lport &&
		    iph->ip_src.s_addr == tcp->tcp_remote &&
		    iph->ip_dst.s_addr == tcp->tcp_bound_source) {
			return (tcp);
		}
	}

	for (tcp = listener->tcp_eager_next_q0; tcp != listener;
	    tcp = tcp->tcp_eager_next_q0) {
		if (tcph->tha_lport == tcp->tcp_fport &&
		    tcph->tha_fport == tcp->tcp_lport &&
		    iph->ip_src.s_addr == tcp->tcp_remote &&
		    iph->ip_dst.s_addr == tcp->tcp_bound_source) {
			return (tcp);
		}
	}
#ifdef DEBUG
	printf("No eager found\n");
#endif
	return (NULL);
}

/* To destroy a TCP control block. */
static void
tcp_clean_death(int sock_id, tcp_t *tcp, int err)
{
	tcp_free(tcp);
	if (tcp->tcp_state == TCPS_TIME_WAIT)
		tcp_time_wait_remove(tcp);

	if (sock_id >= 0) {
		sockets[sock_id].pcb = NULL;
		if (err != 0)
			sockets[sock_id].so_error = err;
	}
	bkmem_free((caddr_t)tcp, sizeof (tcp_t));
}

/*
 * tcp_rwnd_set() is called to adjust the receive window to a desired value.
 * We do not allow the receive window to shrink.  After setting rwnd,
 * set the flow control hiwat of the stream.
 *
 * This function is called in 2 cases:
 *
 * 1) Before data transfer begins, in tcp_accept_comm() for accepting a
 *    connection (passive open) and in tcp_rput_data() for active connect.
 *    This is called after tcp_mss_set() when the desired MSS value is known.
 *    This makes sure that our window size is a mutiple of the other side's
 *    MSS.
 * 2) Handling SO_RCVBUF option.
 *
 * It is ASSUMED that the requested size is a multiple of the current MSS.
 *
 * XXX - Should allow a lower rwnd than tcp_recv_hiwat_minmss * mss if the
 * user requests so.
 */
static int
tcp_rwnd_set(tcp_t *tcp, uint32_t rwnd)
{
	uint32_t	mss = tcp->tcp_mss;
	uint32_t	old_max_rwnd;
	uint32_t	max_transmittable_rwnd;

	if (tcp->tcp_rwnd_max != 0)
		old_max_rwnd = tcp->tcp_rwnd_max;
	else
		old_max_rwnd = tcp->tcp_rwnd;

	/*
	 * Insist on a receive window that is at least
	 * tcp_recv_hiwat_minmss * MSS (default 4 * MSS) to avoid
	 * funny TCP interactions of Nagle algorithm, SWS avoidance
	 * and delayed acknowledgement.
	 */
	rwnd = MAX(rwnd, tcp_recv_hiwat_minmss * mss);

	/*
	 * If window size info has already been exchanged, TCP should not
	 * shrink the window.  Shrinking window is doable if done carefully.
	 * We may add that support later.  But so far there is not a real
	 * need to do that.
	 */
	if (rwnd < old_max_rwnd && tcp->tcp_state > TCPS_SYN_SENT) {
		/* MSS may have changed, do a round up again. */
		rwnd = MSS_ROUNDUP(old_max_rwnd, mss);
	}

	/*
	 * tcp_rcv_ws starts with TCP_MAX_WINSHIFT so the following check
	 * can be applied even before the window scale option is decided.
	 */
	max_transmittable_rwnd = TCP_MAXWIN << tcp->tcp_rcv_ws;
	if (rwnd > max_transmittable_rwnd) {
		rwnd = max_transmittable_rwnd -
		    (max_transmittable_rwnd % mss);
		if (rwnd < mss)
			rwnd = max_transmittable_rwnd;
		/*
		 * If we're over the limit we may have to back down tcp_rwnd.
		 * The increment below won't work for us. So we set all three
		 * here and the increment below will have no effect.
		 */
		tcp->tcp_rwnd = old_max_rwnd = rwnd;
	}

	/*
	 * Increment the current rwnd by the amount the maximum grew (we
	 * can not overwrite it since we might be in the middle of a
	 * connection.)
	 */
	tcp->tcp_rwnd += rwnd - old_max_rwnd;
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws, tcp->tcp_tcph->th_win);
	if ((tcp->tcp_rcv_ws > 0) && rwnd > tcp->tcp_cwnd_max)
		tcp->tcp_cwnd_max = rwnd;
	tcp->tcp_rwnd_max = rwnd;

	return (rwnd);
}

/*
 * Extract option values from a tcp header.  We put any found values into the
 * tcpopt struct and return a bitmask saying which options were found.
 */
static int
tcp_parse_options(tcph_t *tcph, tcp_opt_t *tcpopt)
{
	uchar_t		*endp;
	int		len;
	uint32_t	mss;
	uchar_t		*up = (uchar_t *)tcph;
	int		found = 0;
	int32_t		sack_len;
	tcp_seq		sack_begin, sack_end;
	tcp_t		*tcp;

	endp = up + TCP_HDR_LENGTH(tcph);
	up += TCP_MIN_HEADER_LENGTH;
	while (up < endp) {
		len = endp - up;
		switch (*up) {
		case TCPOPT_EOL:
			break;

		case TCPOPT_NOP:
			up++;
			continue;

		case TCPOPT_MAXSEG:
			if (len < TCPOPT_MAXSEG_LEN ||
			    up[1] != TCPOPT_MAXSEG_LEN)
				break;

			mss = BE16_TO_U16(up+2);
			/* Caller must handle tcp_mss_min and tcp_mss_max_* */
			tcpopt->tcp_opt_mss = mss;
			found |= TCP_OPT_MSS_PRESENT;

			up += TCPOPT_MAXSEG_LEN;
			continue;

		case TCPOPT_WSCALE:
			if (len < TCPOPT_WS_LEN || up[1] != TCPOPT_WS_LEN)
				break;

			if (up[2] > TCP_MAX_WINSHIFT)
				tcpopt->tcp_opt_wscale = TCP_MAX_WINSHIFT;
			else
				tcpopt->tcp_opt_wscale = up[2];
			found |= TCP_OPT_WSCALE_PRESENT;

			up += TCPOPT_WS_LEN;
			continue;

		case TCPOPT_SACK_PERMITTED:
			if (len < TCPOPT_SACK_OK_LEN ||
			    up[1] != TCPOPT_SACK_OK_LEN)
				break;
			found |= TCP_OPT_SACK_OK_PRESENT;
			up += TCPOPT_SACK_OK_LEN;
			continue;

		case TCPOPT_SACK:
			if (len <= 2 || up[1] <= 2 || len < up[1])
				break;

			/* If TCP is not interested in SACK blks... */
			if ((tcp = tcpopt->tcp) == NULL) {
				up += up[1];
				continue;
			}
			sack_len = up[1] - TCPOPT_HEADER_LEN;
			up += TCPOPT_HEADER_LEN;

			/*
			 * If the list is empty, allocate one and assume
			 * nothing is sack'ed.
			 */
			assert(tcp->tcp_sack_info != NULL);
			if (tcp->tcp_notsack_list == NULL) {
				tcp_notsack_update(&(tcp->tcp_notsack_list),
				    tcp->tcp_suna, tcp->tcp_snxt,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));

				/*
				 * Make sure tcp_notsack_list is not NULL.
				 * This happens when kmem_alloc(KM_NOSLEEP)
				 * returns NULL.
				 */
				if (tcp->tcp_notsack_list == NULL) {
					up += sack_len;
					continue;
				}
				tcp->tcp_fack = tcp->tcp_suna;
			}

			while (sack_len > 0) {
				if (up + 8 > endp) {
					up = endp;
					break;
				}
				sack_begin = BE32_TO_U32(up);
				up += 4;
				sack_end = BE32_TO_U32(up);
				up += 4;
				sack_len -= 8;
				/*
				 * Bounds checking.  Make sure the SACK
				 * info is within tcp_suna and tcp_snxt.
				 * If this SACK blk is out of bound, ignore
				 * it but continue to parse the following
				 * blks.
				 */
				if (SEQ_LEQ(sack_end, sack_begin) ||
				    SEQ_LT(sack_begin, tcp->tcp_suna) ||
				    SEQ_GT(sack_end, tcp->tcp_snxt)) {
					continue;
				}
				tcp_notsack_insert(&(tcp->tcp_notsack_list),
				    sack_begin, sack_end,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));
				if (SEQ_GT(sack_end, tcp->tcp_fack)) {
					tcp->tcp_fack = sack_end;
				}
			}
			found |= TCP_OPT_SACK_PRESENT;
			continue;

		case TCPOPT_TSTAMP:
			if (len < TCPOPT_TSTAMP_LEN ||
			    up[1] != TCPOPT_TSTAMP_LEN)
				break;

			tcpopt->tcp_opt_ts_val = BE32_TO_U32(up+2);
			tcpopt->tcp_opt_ts_ecr = BE32_TO_U32(up+6);

			found |= TCP_OPT_TSTAMP_PRESENT;

			up += TCPOPT_TSTAMP_LEN;
			continue;

		default:
			if (len <= 1 || len < (int)up[1] || up[1] == 0)
				break;
			up += up[1];
			continue;
		}
		break;
	}
	return (found);
}

/*
 * Set the mss associated with a particular tcp based on its current value,
 * and a new one passed in. Observe minimums and maximums, and reset
 * other state variables that we want to view as multiples of mss.
 *
 * This function is called in various places mainly because
 * 1) Various stuffs, tcp_mss, tcp_cwnd, ... need to be adjusted when the
 *    other side's SYN/SYN-ACK packet arrives.
 * 2) PMTUd may get us a new MSS.
 * 3) If the other side stops sending us timestamp option, we need to
 *    increase the MSS size to use the extra bytes available.
 */
static void
tcp_mss_set(tcp_t *tcp, uint32_t mss)
{
	uint32_t	mss_max;

	mss_max = tcp_mss_max_ipv4;

	if (mss < tcp_mss_min)
		mss = tcp_mss_min;
	if (mss > mss_max)
		mss = mss_max;
	/*
	 * Unless naglim has been set by our client to
	 * a non-mss value, force naglim to track mss.
	 * This can help to aggregate small writes.
	 */
	if (mss < tcp->tcp_naglim || tcp->tcp_mss == tcp->tcp_naglim)
		tcp->tcp_naglim = mss;
	/*
	 * TCP should be able to buffer at least 4 MSS data for obvious
	 * performance reason.
	 */
	if ((mss << 2) > tcp->tcp_xmit_hiwater)
		tcp->tcp_xmit_hiwater = mss << 2;
	tcp->tcp_mss = mss;
	/*
	 * Initialize cwnd according to draft-floyd-incr-init-win-01.txt.
	 * Previously, we use tcp_slow_start_initial to control the size
	 * of the initial cwnd.  Now, when tcp_slow_start_initial * mss
	 * is smaller than the cwnd calculated from the formula suggested in
	 * the draft, we use tcp_slow_start_initial * mss as the cwnd.
	 * Otherwise, use the cwnd from the draft's formula.  The default
	 * of tcp_slow_start_initial is 2.
	 */
	tcp->tcp_cwnd = MIN(tcp_slow_start_initial * mss,
	    MIN(4 * mss, MAX(2 * mss, 4380 / mss * mss)));
	tcp->tcp_cwnd_cnt = 0;
}

/*
 * Process all TCP option in SYN segment.
 *
 * This function sets up the correct tcp_mss value according to the
 * MSS option value and our header size.  It also sets up the window scale
 * and timestamp values, and initialize SACK info blocks.  But it does not
 * change receive window size after setting the tcp_mss value.  The caller
 * should do the appropriate change.
 */
void
tcp_process_options(tcp_t *tcp, tcph_t *tcph)
{
	int options;
	tcp_opt_t tcpopt;
	uint32_t mss_max;
	char *tmp_tcph;

	tcpopt.tcp = NULL;
	options = tcp_parse_options(tcph, &tcpopt);

	/*
	 * Process MSS option.  Note that MSS option value does not account
	 * for IP or TCP options.  This means that it is equal to MTU - minimum
	 * IP+TCP header size, which is 40 bytes for IPv4 and 60 bytes for
	 * IPv6.
	 */
	if (!(options & TCP_OPT_MSS_PRESENT)) {
		tcpopt.tcp_opt_mss = tcp_mss_def_ipv4;
	} else {
		if (tcp->tcp_ipversion == IPV4_VERSION)
			mss_max = tcp_mss_max_ipv4;
		if (tcpopt.tcp_opt_mss < tcp_mss_min)
			tcpopt.tcp_opt_mss = tcp_mss_min;
		else if (tcpopt.tcp_opt_mss > mss_max)
			tcpopt.tcp_opt_mss = mss_max;
	}

	/* Process Window Scale option. */
	if (options & TCP_OPT_WSCALE_PRESENT) {
		tcp->tcp_snd_ws = tcpopt.tcp_opt_wscale;
		tcp->tcp_snd_ws_ok = B_TRUE;
	} else {
		tcp->tcp_snd_ws = B_FALSE;
		tcp->tcp_snd_ws_ok = B_FALSE;
		tcp->tcp_rcv_ws = B_FALSE;
	}

	/* Process Timestamp option. */
	if ((options & TCP_OPT_TSTAMP_PRESENT) &&
	    (tcp->tcp_snd_ts_ok || !tcp->tcp_active_open)) {
		tmp_tcph = (char *)tcp->tcp_tcph;

		tcp->tcp_snd_ts_ok = B_TRUE;
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = prom_gettime();
		assert(OK_32PTR(tmp_tcph));
		assert(tcp->tcp_tcp_hdr_len == TCP_MIN_HEADER_LENGTH);

		/* Fill in our template header with basic timestamp option. */
		tmp_tcph += tcp->tcp_tcp_hdr_len;
		tmp_tcph[0] = TCPOPT_NOP;
		tmp_tcph[1] = TCPOPT_NOP;
		tmp_tcph[2] = TCPOPT_TSTAMP;
		tmp_tcph[3] = TCPOPT_TSTAMP_LEN;
		tcp->tcp_hdr_len += TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcp_hdr_len += TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcph->th_offset_and_rsrvd[0] += (3 << 4);
	} else {
		tcp->tcp_snd_ts_ok = B_FALSE;
	}

	/*
	 * Process SACK options.  If SACK is enabled for this connection,
	 * then allocate the SACK info structure.
	 */
	if ((options & TCP_OPT_SACK_OK_PRESENT) &&
	    (tcp->tcp_snd_sack_ok ||
	    (tcp_sack_permitted != 0 && !tcp->tcp_active_open))) {
		/* This should be true only in the passive case. */
		if (tcp->tcp_sack_info == NULL) {
			tcp->tcp_sack_info = (tcp_sack_info_t *)bkmem_zalloc(
			    sizeof (tcp_sack_info_t));
		}
		if (tcp->tcp_sack_info == NULL) {
			tcp->tcp_snd_sack_ok = B_FALSE;
		} else {
			tcp->tcp_snd_sack_ok = B_TRUE;
			if (tcp->tcp_snd_ts_ok) {
				tcp->tcp_max_sack_blk = 3;
			} else {
				tcp->tcp_max_sack_blk = 4;
			}
		}
	} else {
		/*
		 * Resetting tcp_snd_sack_ok to B_FALSE so that
		 * no SACK info will be used for this
		 * connection.  This assumes that SACK usage
		 * permission is negotiated.  This may need
		 * to be changed once this is clarified.
		 */
		if (tcp->tcp_sack_info != NULL) {
			bkmem_free((caddr_t)tcp->tcp_sack_info,
			    sizeof (tcp_sack_info_t));
			tcp->tcp_sack_info = NULL;
		}
		tcp->tcp_snd_sack_ok = B_FALSE;
	}

	/*
	 * Now we know the exact TCP/IP header length, subtract
	 * that from tcp_mss to get our side's MSS.
	 */
	tcp->tcp_mss -= tcp->tcp_hdr_len;
	/*
	 * Here we assume that the other side's header size will be equal to
	 * our header size.  We calculate the real MSS accordingly.  Need to
	 * take into additional stuffs IPsec puts in.
	 *
	 * Real MSS = Opt.MSS - (our TCP/IP header - min TCP/IP header)
	 */
	tcpopt.tcp_opt_mss -= tcp->tcp_hdr_len -
	    (IP_SIMPLE_HDR_LENGTH + TCP_MIN_HEADER_LENGTH);

	/*
	 * Set MSS to the smaller one of both ends of the connection.
	 * We should not have called tcp_mss_set() before, but our
	 * side of the MSS should have been set to a proper value
	 * by tcp_adapt_ire().  tcp_mss_set() will also set up the
	 * STREAM head parameters properly.
	 *
	 * If we have a larger-than-16-bit window but the other side
	 * didn't want to do window scale, tcp_rwnd_set() will take
	 * care of that.
	 */
	tcp_mss_set(tcp, MIN(tcpopt.tcp_opt_mss, tcp->tcp_mss));
}

/*
 * This function does PAWS protection check.  Returns B_TRUE if the
 * segment passes the PAWS test, else returns B_FALSE.
 */
boolean_t
tcp_paws_check(tcp_t *tcp, tcph_t *tcph, tcp_opt_t *tcpoptp)
{
	uint8_t	flags;
	int	options;
	uint8_t *up;

	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
	/*
	 * If timestamp option is aligned nicely, get values inline,
	 * otherwise call general routine to parse.  Only do that
	 * if timestamp is the only option.
	 */
	if (TCP_HDR_LENGTH(tcph) == (uint32_t)TCP_MIN_HEADER_LENGTH +
	    TCPOPT_REAL_TS_LEN &&
	    OK_32PTR((up = ((uint8_t *)tcph) +
	    TCP_MIN_HEADER_LENGTH)) &&
	    *(uint32_t *)up == TCPOPT_NOP_NOP_TSTAMP) {
		tcpoptp->tcp_opt_ts_val = ABE32_TO_U32((up+4));
		tcpoptp->tcp_opt_ts_ecr = ABE32_TO_U32((up+8));

		options = TCP_OPT_TSTAMP_PRESENT;
	} else {
		if (tcp->tcp_snd_sack_ok) {
			tcpoptp->tcp = tcp;
		} else {
			tcpoptp->tcp = NULL;
		}
		options = tcp_parse_options(tcph, tcpoptp);
	}

	if (options & TCP_OPT_TSTAMP_PRESENT) {
		/*
		 * Do PAWS per RFC 1323 section 4.2.  Accept RST
		 * regardless of the timestamp, page 18 RFC 1323.bis.
		 */
		if ((flags & TH_RST) == 0 &&
		    TSTMP_LT(tcpoptp->tcp_opt_ts_val,
		    tcp->tcp_ts_recent)) {
			if (TSTMP_LT(prom_gettime(),
			    tcp->tcp_last_rcv_lbolt + PAWS_TIMEOUT)) {
				/* This segment is not acceptable. */
				return (B_FALSE);
			} else {
				/*
				 * Connection has been idle for
				 * too long.  Reset the timestamp
				 * and assume the segment is valid.
				 */
				tcp->tcp_ts_recent =
				    tcpoptp->tcp_opt_ts_val;
			}
		}
	} else {
		/*
		 * If we don't get a timestamp on every packet, we
		 * figure we can't really trust 'em, so we stop sending
		 * and parsing them.
		 */
		tcp->tcp_snd_ts_ok = B_FALSE;

		tcp->tcp_hdr_len -= TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcp_hdr_len -= TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcph->th_offset_and_rsrvd[0] -= (3 << 4);
		tcp_mss_set(tcp, tcp->tcp_mss + TCPOPT_REAL_TS_LEN);
		if (tcp->tcp_snd_sack_ok) {
			assert(tcp->tcp_sack_info != NULL);
			tcp->tcp_max_sack_blk = 4;
		}
	}
	return (B_TRUE);
}

/*
 * tcp_get_seg_mp() is called to get the pointer to a segment in the
 * send queue which starts at the given seq. no.
 *
 * Parameters:
 *	tcp_t *tcp: the tcp instance pointer.
 *	uint32_t seq: the starting seq. no of the requested segment.
 *	int32_t *off: after the execution, *off will be the offset to
 *		the returned mblk which points to the requested seq no.
 *
 * Return:
 *	A mblk_t pointer pointing to the requested segment in send queue.
 */
static mblk_t *
tcp_get_seg_mp(tcp_t *tcp, uint32_t seq, int32_t *off)
{
	int32_t	cnt;
	mblk_t	*mp;

	/* Defensive coding.  Make sure we don't send incorrect data. */
	if (SEQ_LT(seq, tcp->tcp_suna) || SEQ_GEQ(seq, tcp->tcp_snxt) ||
	    off == NULL) {
		return (NULL);
	}
	cnt = seq - tcp->tcp_suna;
	mp = tcp->tcp_xmit_head;
	while (cnt > 0 && mp) {
		cnt -= mp->b_wptr - mp->b_rptr;
		if (cnt < 0) {
			cnt += mp->b_wptr - mp->b_rptr;
			break;
		}
		mp = mp->b_cont;
	}
	assert(mp != NULL);
	*off = cnt;
	return (mp);
}

/*
 * This function handles all retransmissions if SACK is enabled for this
 * connection.  First it calculates how many segments can be retransmitted
 * based on tcp_pipe.  Then it goes thru the notsack list to find eligible
 * segments.  A segment is eligible if sack_cnt for that segment is greater
 * than or equal tcp_dupack_fast_retransmit.  After it has retransmitted
 * all eligible segments, it checks to see if TCP can send some new segments
 * (fast recovery).  If it can, it returns 1.  Otherwise it returns 0.
 *
 * Parameters:
 *	tcp_t *tcp: the tcp structure of the connection.
 *
 * Return:
 *	1 if the pipe is not full (new data can be sent), 0 otherwise
 */
static int32_t
tcp_sack_rxmit(tcp_t *tcp, int sock_id)
{
	notsack_blk_t	*notsack_blk;
	int32_t		usable_swnd;
	int32_t		mss;
	uint32_t	seg_len;
	mblk_t		*xmit_mp;

	assert(tcp->tcp_sack_info != NULL);
	assert(tcp->tcp_notsack_list != NULL);
	assert(tcp->tcp_rexmit == B_FALSE);

	/* Defensive coding in case there is a bug... */
	if (tcp->tcp_notsack_list == NULL) {
		return (0);
	}
	notsack_blk = tcp->tcp_notsack_list;
	mss = tcp->tcp_mss;

	/*
	 * Limit the num of outstanding data in the network to be
	 * tcp_cwnd_ssthresh, which is half of the original congestion wnd.
	 */
	usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;

	/* At least retransmit 1 MSS of data. */
	if (usable_swnd <= 0) {
		usable_swnd = mss;
	}

	/* Make sure no new RTT samples will be taken. */
	tcp->tcp_csuna = tcp->tcp_snxt;

	notsack_blk = tcp->tcp_notsack_list;
	while (usable_swnd > 0) {
		mblk_t		*snxt_mp, *tmp_mp;
		tcp_seq		begin = tcp->tcp_sack_snxt;
		tcp_seq		end;
		int32_t		off;

		for (; notsack_blk != NULL; notsack_blk = notsack_blk->next) {
			if (SEQ_GT(notsack_blk->end, begin) &&
			    (notsack_blk->sack_cnt >=
			    tcp_dupack_fast_retransmit)) {
				end = notsack_blk->end;
				if (SEQ_LT(begin, notsack_blk->begin)) {
					begin = notsack_blk->begin;
				}
				break;
			}
		}
		/*
		 * All holes are filled.  Manipulate tcp_cwnd to send more
		 * if we can.  Note that after the SACK recovery, tcp_cwnd is
		 * set to tcp_cwnd_ssthresh.
		 */
		if (notsack_blk == NULL) {
			usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;
			if (usable_swnd <= 0) {
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna;
				assert(tcp->tcp_cwnd > 0);
				return (0);
			} else {
				usable_swnd = usable_swnd / mss;
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna +
				    MAX(usable_swnd * mss, mss);
				return (1);
			}
		}

		/*
		 * Note that we may send more than usable_swnd allows here
		 * because of round off, but no more than 1 MSS of data.
		 */
		seg_len = end - begin;
		if (seg_len > mss)
			seg_len = mss;
		snxt_mp = tcp_get_seg_mp(tcp, begin, &off);
		assert(snxt_mp != NULL);
		/* This should not happen.  Defensive coding again... */
		if (snxt_mp == NULL) {
			return (0);
		}

		xmit_mp = tcp_xmit_mp(tcp, snxt_mp, seg_len, &off,
		    &tmp_mp, begin, B_TRUE, &seg_len, B_TRUE);

		if (xmit_mp == NULL)
			return (0);

		usable_swnd -= seg_len;
		tcp->tcp_pipe += seg_len;
		tcp->tcp_sack_snxt = begin + seg_len;
		TCP_DUMP_PACKET("tcp_sack_rxmit", xmit_mp);
		(void) ipv4_tcp_output(sock_id, xmit_mp);
		freeb(xmit_mp);

		/*
		 * Update the send timestamp to avoid false retransmission.
		 * Note. use uintptr_t to suppress the gcc warning.
		 */
		snxt_mp->b_prev = (mblk_t *)(uintptr_t)prom_gettime();

		BUMP_MIB(tcp_mib.tcpRetransSegs);
		UPDATE_MIB(tcp_mib.tcpRetransBytes, seg_len);
		BUMP_MIB(tcp_mib.tcpOutSackRetransSegs);
		/*
		 * Update tcp_rexmit_max to extend this SACK recovery phase.
		 * This happens when new data sent during fast recovery is
		 * also lost.  If TCP retransmits those new data, it needs
		 * to extend SACK recover phase to avoid starting another
		 * fast retransmit/recovery unnecessarily.
		 */
		if (SEQ_GT(tcp->tcp_sack_snxt, tcp->tcp_rexmit_max)) {
			tcp->tcp_rexmit_max = tcp->tcp_sack_snxt;
		}
	}
	return (0);
}

static void
tcp_rput_data(tcp_t *tcp, mblk_t *mp, int sock_id)
{
	uchar_t		*rptr;
	struct ip	*iph;
	tcp_t		*tcp1;
	tcpha_t		*tcph;
	uint32_t	seg_ack;
	int		seg_len;
	uint_t		ip_hdr_len;
	uint32_t	seg_seq;
	mblk_t		*mp1;
	uint_t		flags;
	uint32_t	new_swnd = 0;
	int		mss;
	boolean_t	ofo_seg = B_FALSE; /* Out of order segment */
	int32_t		gap;
	int32_t		rgap;
	tcp_opt_t	tcpopt;
	int32_t		bytes_acked;
	int		npkt;
	uint32_t	cwnd;
	uint32_t	add;

#ifdef DEBUG
	printf("tcp_rput_data sock %d mp %x mp_datap %x #################\n",
	    sock_id, mp, mp->b_datap);
#endif

	/* Dump the packet when debugging. */
	TCP_DUMP_PACKET("tcp_rput_data", mp);

	assert(OK_32PTR(mp->b_rptr));

	rptr = mp->b_rptr;
	iph = (struct ip *)rptr;
	ip_hdr_len = IPH_HDR_LENGTH(rptr);
	if (ip_hdr_len != IP_SIMPLE_HDR_LENGTH) {
#ifdef DEBUG
		printf("Not simple IP header\n");
#endif
		/* We cannot handle IP option yet... */
		tcp_drops++;
		freeb(mp);
		return;
	}
	/* The TCP header must be aligned. */
	tcph = (tcpha_t *)&rptr[ip_hdr_len];
	seg_seq = ntohl(tcph->tha_seq);
	seg_ack = ntohl(tcph->tha_ack);
	assert((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	seg_len = (int)(mp->b_wptr - rptr) -
	    (ip_hdr_len + TCP_HDR_LENGTH(((tcph_t *)tcph)));
	/* In inetboot, b_cont should always be NULL. */
	assert(mp->b_cont == NULL);

	/* Verify the checksum. */
	if (tcp_verify_cksum(mp) < 0) {
#ifdef DEBUG
		printf("tcp_rput_data: wrong cksum\n");
#endif
		freemsg(mp);
		return;
	}

	/*
	 * This segment is not for us, try to find its
	 * intended receiver.
	 */
	if (tcp == NULL ||
	    tcph->tha_lport != tcp->tcp_fport ||
	    tcph->tha_fport != tcp->tcp_lport ||
	    iph->ip_src.s_addr != tcp->tcp_remote ||
	    iph->ip_dst.s_addr != tcp->tcp_bound_source) {
#ifdef DEBUG
		printf("tcp_rput_data: not for us, state %d\n",
		    tcp->tcp_state);
#endif
		/*
		 * First try to find a established connection.  If none
		 * is found, look for a listener.
		 *
		 * If a listener is found, we need to check to see if the
		 * incoming segment is for one of its eagers.  If it is,
		 * give it to the eager.  If not, listener should take care
		 * of it.
		 */
		if ((tcp1 = tcp_lookup_ipv4(iph, tcph, TCPS_SYN_SENT,
		    &sock_id)) != NULL ||
		    (tcp1 = tcp_lookup_listener_ipv4(iph->ip_dst.s_addr,
		    tcph->tha_fport, &sock_id)) != NULL) {
			if (tcp1->tcp_state == TCPS_LISTEN) {
				if ((tcp = tcp_lookup_eager_ipv4(tcp1,
				    iph, tcph)) == NULL) {
					/* No eager... sent to listener */
#ifdef DEBUG
					printf("found the listener: %s\n",
					    tcp_display(tcp1, NULL,
					    DISP_ADDR_AND_PORT));
#endif
					tcp = tcp1;
				}
#ifdef DEBUG
				else {
					printf("found the eager: %s\n",
					    tcp_display(tcp, NULL,
					    DISP_ADDR_AND_PORT));
				}
#endif
			} else {
				/* Non listener found... */
#ifdef DEBUG
				printf("found the connection: %s\n",
				    tcp_display(tcp1, NULL,
				    DISP_ADDR_AND_PORT));
#endif
				tcp = tcp1;
			}
		} else {
			/*
			 * No connection for this segment...
			 * Send a RST to the other side.
			 */
			tcp_xmit_listeners_reset(sock_id, mp, ip_hdr_len);
			return;
		}
	}

	flags = tcph->tha_flags & 0xFF;
	BUMP_MIB(tcp_mib.tcpInSegs);
	if (tcp->tcp_state == TCPS_TIME_WAIT) {
		tcp_time_wait_processing(tcp, mp, seg_seq, seg_ack,
		    seg_len, (tcph_t *)tcph, sock_id);
		return;
	}
	/*
	 * From this point we can assume that the tcp is not compressed,
	 * since we would have branched off to tcp_time_wait_processing()
	 * in such a case.
	 */
	assert(tcp != NULL && tcp->tcp_state != TCPS_TIME_WAIT);

	/*
	 * After this point, we know we have the correct TCP, so update
	 * the receive time.
	 */
	tcp->tcp_last_recv_time = prom_gettime();

	/* In inetboot, we do not handle urgent pointer... */
	if (flags & TH_URG) {
		freemsg(mp);
		DEBUG_1("tcp_rput_data(%d): received segment with urgent "
		    "pointer\n", sock_id);
		tcp_drops++;
		return;
	}

	switch (tcp->tcp_state) {
	case TCPS_LISTEN:
		if ((flags & (TH_RST | TH_ACK | TH_SYN)) != TH_SYN) {
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}
			if (flags & TH_ACK) {
				tcp_xmit_early_reset("TCPS_LISTEN-TH_ACK",
				    sock_id, mp, seg_ack, 0, TH_RST,
				    ip_hdr_len);
				return;
			}
			if (!(flags & TH_SYN)) {
				freemsg(mp);
				return;
			}
			printf("tcp_rput_data: %d\n", __LINE__);
			prom_panic("inetboot");
		}
		if (tcp->tcp_conn_req_max > 0) {
			tcp = tcp_conn_request(tcp, mp, sock_id, ip_hdr_len);
			if (tcp == NULL) {
				freemsg(mp);
				return;
			}
#ifdef DEBUG
			printf("tcp_rput_data: new tcp created\n");
#endif
		}
		tcp->tcp_irs = seg_seq;
		tcp->tcp_rack = seg_seq;
		tcp->tcp_rnxt = seg_seq + 1;
		U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);
		BUMP_MIB(tcp_mib.tcpPassiveOpens);
		goto syn_rcvd;
	case TCPS_SYN_SENT:
		if (flags & TH_ACK) {
			/*
			 * Note that our stack cannot send data before a
			 * connection is established, therefore the
			 * following check is valid.  Otherwise, it has
			 * to be changed.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_iss) ||
			    SEQ_GT(seg_ack, tcp->tcp_snxt)) {
				if (flags & TH_RST) {
					freemsg(mp);
					return;
				}
				tcp_xmit_ctl("TCPS_SYN_SENT-Bad_seq",
				    tcp, mp, seg_ack, 0, TH_RST,
				    ip_hdr_len, sock_id);
				return;
			}
			assert(tcp->tcp_suna + 1 == seg_ack);
		}
		if (flags & TH_RST) {
			freemsg(mp);
			if (flags & TH_ACK) {
				tcp_clean_death(sock_id, tcp, ECONNREFUSED);
			}
			return;
		}
		if (!(flags & TH_SYN)) {
			freemsg(mp);
			return;
		}

		/* Process all TCP options. */
		tcp_process_options(tcp, (tcph_t *)tcph);
		/*
		 * The following changes our rwnd to be a multiple of the
		 * MIN(peer MSS, our MSS) for performance reason.
		 */
		(void) tcp_rwnd_set(tcp, MSS_ROUNDUP(tcp->tcp_rwnd,
		    tcp->tcp_mss));

		/* Is the other end ECN capable? */
		if (tcp->tcp_ecn_ok) {
			if ((flags & (TH_ECE|TH_CWR)) != TH_ECE) {
				tcp->tcp_ecn_ok = B_FALSE;
			}
		}
		/*
		 * Clear ECN flags because it may interfere with later
		 * processing.
		 */
		flags &= ~(TH_ECE|TH_CWR);

		tcp->tcp_irs = seg_seq;
		tcp->tcp_rack = seg_seq;
		tcp->tcp_rnxt = seg_seq + 1;
		U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);

		if (flags & TH_ACK) {
			/* One for the SYN */
			tcp->tcp_suna = tcp->tcp_iss + 1;
			tcp->tcp_valid_bits &= ~TCP_ISS_VALID;
			tcp->tcp_state = TCPS_ESTABLISHED;

			/*
			 * If SYN was retransmitted, need to reset all
			 * retransmission info.  This is because this
			 * segment will be treated as a dup ACK.
			 */
			if (tcp->tcp_rexmit) {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
				tcp->tcp_rexmit_max = tcp->tcp_snxt;
				tcp->tcp_snd_burst = TCP_CWND_NORMAL;

				/*
				 * Set tcp_cwnd back to 1 MSS, per
				 * recommendation from
				 * draft-floyd-incr-init-win-01.txt,
				 * Increasing TCP's Initial Window.
				 */
				tcp->tcp_cwnd = tcp->tcp_mss;
			}

			tcp->tcp_swl1 = seg_seq;
			tcp->tcp_swl2 = seg_ack;

			new_swnd = BE16_TO_U16(((tcph_t *)tcph)->th_win);
			tcp->tcp_swnd = new_swnd;
			if (new_swnd > tcp->tcp_max_swnd)
				tcp->tcp_max_swnd = new_swnd;

			/*
			 * Always send the three-way handshake ack immediately
			 * in order to make the connection complete as soon as
			 * possible on the accepting host.
			 */
			flags |= TH_ACK_NEEDED;
			/*
			 * Check to see if there is data to be sent.  If
			 * yes, set the transmit flag.  Then check to see
			 * if received data processing needs to be done.
			 * If not, go straight to xmit_check.  This short
			 * cut is OK as we don't support T/TCP.
			 */
			if (tcp->tcp_unsent)
				flags |= TH_XMIT_NEEDED;

			if (seg_len == 0) {
				freemsg(mp);
				goto xmit_check;
			}

			flags &= ~TH_SYN;
			seg_seq++;
			break;
		}
		syn_rcvd:
		tcp->tcp_state = TCPS_SYN_RCVD;
		mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, tcp->tcp_mss,
		    NULL, NULL, tcp->tcp_iss, B_FALSE, NULL, B_FALSE);
		if (mp1 != NULL) {
			TCP_DUMP_PACKET("tcp_rput_data replying SYN", mp1);
			(void) ipv4_tcp_output(sock_id, mp1);
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			freeb(mp1);
			/*
			 * Let's wait till our SYN has been ACKED since we
			 * don't have a timer.
			 */
			if (tcp_state_wait(sock_id, tcp, TCPS_ALL_ACKED) < 0) {
				freemsg(mp);
				return;
			}
		}
		freemsg(mp);
		return;
	default:
		break;
	}
	mp->b_rptr = (uchar_t *)tcph + TCP_HDR_LENGTH((tcph_t *)tcph);
	new_swnd = ntohs(tcph->tha_win) <<
	    ((flags & TH_SYN) ? 0 : tcp->tcp_snd_ws);
	mss = tcp->tcp_mss;

	if (tcp->tcp_snd_ts_ok) {
		if (!tcp_paws_check(tcp, (tcph_t *)tcph, &tcpopt)) {
			/*
			 * This segment is not acceptable.
			 * Drop it and send back an ACK.
			 */
			freemsg(mp);
			flags |= TH_ACK_NEEDED;
			goto ack_check;
		}
	} else if (tcp->tcp_snd_sack_ok) {
		assert(tcp->tcp_sack_info != NULL);
		tcpopt.tcp = tcp;
		/*
		 * SACK info in already updated in tcp_parse_options.  Ignore
		 * all other TCP options...
		 */
		(void) tcp_parse_options((tcph_t *)tcph, &tcpopt);
	}
try_again:;
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	/*
	 * gap is the amount of sequence space between what we expect to see
	 * and what we got for seg_seq.  A positive value for gap means
	 * something got lost.  A negative value means we got some old stuff.
	 */
	if (gap < 0) {
		/* Old stuff present.  Is the SYN in there? */
		if (seg_seq == tcp->tcp_irs && (flags & TH_SYN) &&
		    (seg_len != 0)) {
			flags &= ~TH_SYN;
			seg_seq++;
			/* Recompute the gaps after noting the SYN. */
			goto try_again;
		}
		BUMP_MIB(tcp_mib.tcpInDataDupSegs);
		UPDATE_MIB(tcp_mib.tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		/* Remove the old stuff from seg_len. */
		seg_len += gap;
		/*
		 * Anything left?
		 * Make sure to check for unack'd FIN when rest of data
		 * has been previously ack'd.
		 */
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/*
			 * This segment is "unacceptable".  None of its
			 * sequence space lies within our advertized window.
			 *
			 * Adjust seg_len to the original value for tracing.
			 */
			seg_len -= gap;
#ifdef DEBUG
			printf("tcp_rput: unacceptable, gap %d, rgap "
			    "%d, flags 0x%x, seg_seq %u, seg_ack %u, "
			    "seg_len %d, rnxt %u, snxt %u, %s",
			    gap, rgap, flags, seg_seq, seg_ack,
			    seg_len, tcp->tcp_rnxt, tcp->tcp_snxt,
			    tcp_display(tcp, NULL, DISP_ADDR_AND_PORT));
#endif

			/*
			 * Arrange to send an ACK in response to the
			 * unacceptable segment per RFC 793 page 69. There
			 * is only one small difference between ours and the
			 * acceptability test in the RFC - we accept ACK-only
			 * packet with SEG.SEQ = RCV.NXT+RCV.WND and no ACK
			 * will be generated.
			 *
			 * Note that we have to ACK an ACK-only packet at least
			 * for stacks that send 0-length keep-alives with
			 * SEG.SEQ = SND.NXT-1 as recommended by RFC1122,
			 * section 4.2.3.6. As long as we don't ever generate
			 * an unacceptable packet in response to an incoming
			 * packet that is unacceptable, it should not cause
			 * "ACK wars".
			 */
			flags |=  TH_ACK_NEEDED;

			/*
			 * Continue processing this segment in order to use the
			 * ACK information it contains, but skip all other
			 * sequence-number processing.	Processing the ACK
			 * information is necessary in order to
			 * re-synchronize connections that may have lost
			 * synchronization.
			 *
			 * We clear seg_len and flag fields related to
			 * sequence number processing as they are not
			 * to be trusted for an unacceptable segment.
			 */
			seg_len = 0;
			flags &= ~(TH_SYN | TH_FIN | TH_URG);
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
		do {
			mblk_t	*mp2;
			assert((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
			    (uintptr_t)UINT_MAX);
			gap += (uint_t)(mp->b_wptr - mp->b_rptr);
			if (gap > 0) {
				mp->b_rptr = mp->b_wptr - gap;
				break;
			}
			mp2 = mp;
			mp = mp->b_cont;
			freeb(mp2);
		} while (gap < 0);
	}
	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		mblk_t	*mp2;

		if (tcp->tcp_rwnd == 0)
			BUMP_MIB(tcp_mib.tcpInWinProbe);
		else {
			BUMP_MIB(tcp_mib.tcpInDataPastWinSegs);
			UPDATE_MIB(tcp_mib.tcpInDataPastWinBytes, -rgap);
		}

		/*
		 * seg_len does not include the FIN, so if more than
		 * just the FIN is out of window, we act like we don't
		 * see it.  (If just the FIN is out of window, rgap
		 * will be zero and we will go ahead and acknowledge
		 * the FIN.)
		 */
		flags &= ~TH_FIN;

		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/* Per RFC 793, we need to send back an ACK. */
			flags |= TH_ACK_NEEDED;

			/*
			 * If this is a zero window probe, continue to
			 * process the ACK part.  But we need to set seg_len
			 * to 0 to avoid data processing.  Otherwise just
			 * drop the segment and send back an ACK.
			 */
			if (tcp->tcp_rwnd == 0 && seg_seq == tcp->tcp_rnxt) {
				flags &= ~(TH_SYN | TH_URG);
				seg_len = 0;
				/* Let's see if we can update our rwnd */
				tcp_rcv_drain(sock_id, tcp);
				goto process_ack;
			} else {
				freemsg(mp);
				goto ack_check;
			}
		}
		/* Pitch out of window stuff off the end. */
		rgap = seg_len;
		mp2 = mp;
		do {
			assert((uintptr_t)(mp2->b_wptr -
			    mp2->b_rptr) <= (uintptr_t)INT_MAX);
			rgap -= (int)(mp2->b_wptr - mp2->b_rptr);
			if (rgap < 0) {
				mp2->b_wptr += rgap;
				if ((mp1 = mp2->b_cont) != NULL) {
					mp2->b_cont = NULL;
					freemsg(mp1);
				}
				break;
			}
		} while ((mp2 = mp2->b_cont) != NULL);
	}
ok:;
	/*
	 * TCP should check ECN info for segments inside the window only.
	 * Therefore the check should be done here.
	 */
	if (tcp->tcp_ecn_ok) {
		uchar_t tos = ((struct ip *)rptr)->ip_tos;

		if (flags & TH_CWR) {
			tcp->tcp_ecn_echo_on = B_FALSE;
		}
		/*
		 * Note that both ECN_CE and CWR can be set in the
		 * same segment.  In this case, we once again turn
		 * on ECN_ECHO.
		 */
		if ((tos & IPH_ECN_CE) == IPH_ECN_CE) {
			tcp->tcp_ecn_echo_on = B_TRUE;
		}
	}

	/*
	 * Check whether we can update tcp_ts_recent.  This test is
	 * NOT the one in RFC 1323 3.4.  It is from Braden, 1993, "TCP
	 * Extensions for High Performance: An Update", Internet Draft.
	 */
	if (tcp->tcp_snd_ts_ok &&
	    TSTMP_GEQ(tcpopt.tcp_opt_ts_val, tcp->tcp_ts_recent) &&
	    SEQ_LEQ(seg_seq, tcp->tcp_rack)) {
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = prom_gettime();
	}

	if (seg_seq != tcp->tcp_rnxt || tcp->tcp_reass_head) {
		/*
		 * FIN in an out of order segment.  We record this in
		 * tcp_valid_bits and the seq num of FIN in tcp_ofo_fin_seq.
		 * Clear the FIN so that any check on FIN flag will fail.
		 * Remember that FIN also counts in the sequence number
		 * space.  So we need to ack out of order FIN only segments.
		 */
		if (flags & TH_FIN) {
			tcp->tcp_valid_bits |= TCP_OFO_FIN_VALID;
			tcp->tcp_ofo_fin_seq = seg_seq + seg_len;
			flags &= ~TH_FIN;
			flags |= TH_ACK_NEEDED;
		}
		if (seg_len > 0) {
			/* Fill in the SACK blk list. */
			if (tcp->tcp_snd_sack_ok) {
				assert(tcp->tcp_sack_info != NULL);
				tcp_sack_insert(tcp->tcp_sack_list,
				    seg_seq, seg_seq + seg_len,
				    &(tcp->tcp_num_sack_blk));
			}

			/*
			 * Attempt reassembly and see if we have something
			 * ready to go.
			 */
			mp = tcp_reass(tcp, mp, seg_seq);
			/* Always ack out of order packets */
			flags |= TH_ACK_NEEDED | TH_PUSH;
			if (mp != NULL) {
				assert((uintptr_t)(mp->b_wptr -
				    mp->b_rptr) <= (uintptr_t)INT_MAX);
				seg_len = mp->b_cont ? msgdsize(mp) :
					(int)(mp->b_wptr - mp->b_rptr);
				seg_seq = tcp->tcp_rnxt;
				/*
				 * A gap is filled and the seq num and len
				 * of the gap match that of a previously
				 * received FIN, put the FIN flag back in.
				 */
				if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
				    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
					flags |= TH_FIN;
					tcp->tcp_valid_bits &=
					    ~TCP_OFO_FIN_VALID;
				}
			} else {
				/*
				 * Keep going even with NULL mp.
				 * There may be a useful ACK or something else
				 * we don't want to miss.
				 *
				 * But TCP should not perform fast retransmit
				 * because of the ack number.  TCP uses
				 * seg_len == 0 to determine if it is a pure
				 * ACK.  And this is not a pure ACK.
				 */
				seg_len = 0;
				ofo_seg = B_TRUE;
			}
		}
	} else if (seg_len > 0) {
		BUMP_MIB(tcp_mib.tcpInDataInorderSegs);
		UPDATE_MIB(tcp_mib.tcpInDataInorderBytes, seg_len);
		/*
		 * If an out of order FIN was received before, and the seq
		 * num and len of the new segment match that of the FIN,
		 * put the FIN flag back in.
		 */
		if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
		    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
			flags |= TH_FIN;
			tcp->tcp_valid_bits &= ~TCP_OFO_FIN_VALID;
		}
	}
	if ((flags & (TH_RST | TH_SYN | TH_URG | TH_ACK)) != TH_ACK) {
	if (flags & TH_RST) {
		freemsg(mp);
		switch (tcp->tcp_state) {
		case TCPS_SYN_RCVD:
			(void) tcp_clean_death(sock_id, tcp, ECONNREFUSED);
			break;
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT_1:
		case TCPS_FIN_WAIT_2:
		case TCPS_CLOSE_WAIT:
			(void) tcp_clean_death(sock_id, tcp, ECONNRESET);
			break;
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
			(void) tcp_clean_death(sock_id, tcp, 0);
			break;
		default:
			assert(tcp->tcp_state != TCPS_TIME_WAIT);
			(void) tcp_clean_death(sock_id, tcp, ENXIO);
			break;
		}
		return;
	}
	if (flags & TH_SYN) {
		/*
		 * See RFC 793, Page 71
		 *
		 * The seq number must be in the window as it should
		 * be "fixed" above.  If it is outside window, it should
		 * be already rejected.  Note that we allow seg_seq to be
		 * rnxt + rwnd because we want to accept 0 window probe.
		 */
		assert(SEQ_GEQ(seg_seq, tcp->tcp_rnxt) &&
		    SEQ_LEQ(seg_seq, tcp->tcp_rnxt + tcp->tcp_rwnd));
		freemsg(mp);
		/*
		 * If the ACK flag is not set, just use our snxt as the
		 * seq number of the RST segment.
		 */
		if (!(flags & TH_ACK)) {
			seg_ack = tcp->tcp_snxt;
		}
		tcp_xmit_ctl("TH_SYN", tcp, NULL, seg_ack,
		    seg_seq + 1, TH_RST|TH_ACK, 0, sock_id);
		assert(tcp->tcp_state != TCPS_TIME_WAIT);
		(void) tcp_clean_death(sock_id, tcp, ECONNRESET);
		return;
	}

process_ack:
	if (!(flags & TH_ACK)) {
#ifdef DEBUG
		printf("No ack in segment, dropped it, seq:%x\n", seg_seq);
#endif
		freemsg(mp);
		goto xmit_check;
	}
	}
	bytes_acked = (int)(seg_ack - tcp->tcp_suna);

	if (tcp->tcp_state == TCPS_SYN_RCVD) {
		tcp_t	*listener = tcp->tcp_listener;
#ifdef DEBUG
		printf("Done with eager 3-way handshake\n");
#endif
		/*
		 * NOTE: RFC 793 pg. 72 says this should be 'bytes_acked < 0'
		 * but that would mean we have an ack that ignored our SYN.
		 */
		if (bytes_acked < 1 || SEQ_GT(seg_ack, tcp->tcp_snxt)) {
			freemsg(mp);
			tcp_xmit_ctl("TCPS_SYN_RCVD-bad_ack",
			    tcp, NULL, seg_ack, 0, TH_RST, 0, sock_id);
			return;
		}

		/*
		 * if the conn_req_q is full defer processing
		 * until space is availabe after accept()
		 * processing
		 */
		if (listener->tcp_conn_req_cnt_q <
		    listener->tcp_conn_req_max) {
			tcp_t *tail;

			listener->tcp_conn_req_cnt_q0--;
			listener->tcp_conn_req_cnt_q++;

			/* Move from SYN_RCVD to ESTABLISHED list  */
			tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
				tcp->tcp_eager_prev_q0;
			tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
				tcp->tcp_eager_next_q0;
			tcp->tcp_eager_prev_q0 = NULL;
			tcp->tcp_eager_next_q0 = NULL;

			/*
			 * Insert at end of the queue because sockfs
			 * sends down T_CONN_RES in chronological
			 * order. Leaving the older conn indications
			 * at front of the queue helps reducing search
			 * time.
			 */
			tail = listener->tcp_eager_last_q;
			if (tail != NULL) {
				tail->tcp_eager_next_q = tcp;
			} else {
				listener->tcp_eager_next_q = tcp;
			}
			listener->tcp_eager_last_q = tcp;
			tcp->tcp_eager_next_q = NULL;
		} else {
			/*
			 * Defer connection on q0 and set deferred
			 * connection bit true
			 */
			tcp->tcp_conn_def_q0 = B_TRUE;

			/* take tcp out of q0 ... */
			tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
			    tcp->tcp_eager_next_q0;
			tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
			    tcp->tcp_eager_prev_q0;

			/* ... and place it at the end of q0 */
			tcp->tcp_eager_prev_q0 = listener->tcp_eager_prev_q0;
			tcp->tcp_eager_next_q0 = listener;
			listener->tcp_eager_prev_q0->tcp_eager_next_q0 = tcp;
			listener->tcp_eager_prev_q0 = tcp;
		}

		tcp->tcp_suna = tcp->tcp_iss + 1;	/* One for the SYN */
		bytes_acked--;

		/*
		 * If SYN was retransmitted, need to reset all
		 * retransmission info as this segment will be
		 * treated as a dup ACK.
		 */
		if (tcp->tcp_rexmit) {
			tcp->tcp_rexmit = B_FALSE;
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
			tcp->tcp_rexmit_max = tcp->tcp_snxt;
			tcp->tcp_snd_burst = TCP_CWND_NORMAL;
			tcp->tcp_ms_we_have_waited = 0;
			tcp->tcp_cwnd = mss;
		}

		/*
		 * We set the send window to zero here.
		 * This is needed if there is data to be
		 * processed already on the queue.
		 * Later (at swnd_update label), the
		 * "new_swnd > tcp_swnd" condition is satisfied
		 * the XMIT_NEEDED flag is set in the current
		 * (SYN_RCVD) state. This ensures tcp_wput_data() is
		 * called if there is already data on queue in
		 * this state.
		 */
		tcp->tcp_swnd = 0;

		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
		tcp->tcp_state = TCPS_ESTABLISHED;
		tcp->tcp_valid_bits &= ~TCP_ISS_VALID;
	}
	/* This code follows 4.4BSD-Lite2 mostly. */
	if (bytes_acked < 0)
		goto est;

	/*
	 * If TCP is ECN capable and the congestion experience bit is
	 * set, reduce tcp_cwnd and tcp_ssthresh.  But this should only be
	 * done once per window (or more loosely, per RTT).
	 */
	if (tcp->tcp_cwr && SEQ_GT(seg_ack, tcp->tcp_cwr_snd_max))
		tcp->tcp_cwr = B_FALSE;
	if (tcp->tcp_ecn_ok && (flags & TH_ECE)) {
		if (!tcp->tcp_cwr) {
			npkt = (MIN(tcp->tcp_cwnd, tcp->tcp_swnd) >> 1) / mss;
			tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) * mss;
			tcp->tcp_cwnd = npkt * mss;
			/*
			 * If the cwnd is 0, use the timer to clock out
			 * new segments.  This is required by the ECN spec.
			 */
			if (npkt == 0) {
				TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				/*
				 * This makes sure that when the ACK comes
				 * back, we will increase tcp_cwnd by 1 MSS.
				 */
				tcp->tcp_cwnd_cnt = 0;
			}
			tcp->tcp_cwr = B_TRUE;
			/*
			 * This marks the end of the current window of in
			 * flight data.  That is why we don't use
			 * tcp_suna + tcp_swnd.  Only data in flight can
			 * provide ECN info.
			 */
			tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
			tcp->tcp_ecn_cwr_sent = B_FALSE;
		}
	}

	mp1 = tcp->tcp_xmit_head;
	if (bytes_acked == 0) {
		if (!ofo_seg && seg_len == 0 && new_swnd == tcp->tcp_swnd) {
			int dupack_cnt;

			BUMP_MIB(tcp_mib.tcpInDupAck);
			/*
			 * Fast retransmit.  When we have seen exactly three
			 * identical ACKs while we have unacked data
			 * outstanding we take it as a hint that our peer
			 * dropped something.
			 *
			 * If TCP is retransmitting, don't do fast retransmit.
			 */
			if (mp1 != NULL && tcp->tcp_suna != tcp->tcp_snxt &&
			    ! tcp->tcp_rexmit) {
				/* Do Limited Transmit */
				if ((dupack_cnt = ++tcp->tcp_dupack_cnt) <
				    tcp_dupack_fast_retransmit) {
					/*
					 * RFC 3042
					 *
					 * What we need to do is temporarily
					 * increase tcp_cwnd so that new
					 * data can be sent if it is allowed
					 * by the receive window (tcp_rwnd).
					 * tcp_wput_data() will take care of
					 * the rest.
					 *
					 * If the connection is SACK capable,
					 * only do limited xmit when there
					 * is SACK info.
					 *
					 * Note how tcp_cwnd is incremented.
					 * The first dup ACK will increase
					 * it by 1 MSS.  The second dup ACK
					 * will increase it by 2 MSS.  This
					 * means that only 1 new segment will
					 * be sent for each dup ACK.
					 */
					if (tcp->tcp_unsent > 0 &&
					    (!tcp->tcp_snd_sack_ok ||
					    (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL))) {
						tcp->tcp_cwnd += mss <<
						    (tcp->tcp_dupack_cnt - 1);
						flags |= TH_LIMIT_XMIT;
					}
				} else if (dupack_cnt ==
				    tcp_dupack_fast_retransmit) {

				BUMP_MIB(tcp_mib.tcpOutFastRetrans);
				/*
				 * If we have reduced tcp_ssthresh
				 * because of ECN, do not reduce it again
				 * unless it is already one window of data
				 * away.  After one window of data, tcp_cwr
				 * should then be cleared.  Note that
				 * for non ECN capable connection, tcp_cwr
				 * should always be false.
				 *
				 * Adjust cwnd since the duplicate
				 * ack indicates that a packet was
				 * dropped (due to congestion.)
				 */
				if (!tcp->tcp_cwr) {
					npkt = (MIN(tcp->tcp_cwnd,
					    tcp->tcp_swnd) >> 1) / mss;
					if (npkt < 2)
						npkt = 2;
					tcp->tcp_cwnd_ssthresh = npkt * mss;
					tcp->tcp_cwnd = (npkt +
					    tcp->tcp_dupack_cnt) * mss;
				}
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}

				/*
				 * We do Hoe's algorithm.  Refer to her
				 * paper "Improving the Start-up Behavior
				 * of a Congestion Control Scheme for TCP,"
				 * appeared in SIGCOMM'96.
				 *
				 * Save highest seq no we have sent so far.
				 * Be careful about the invisible FIN byte.
				 */
				if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
				    (tcp->tcp_unsent == 0)) {
					tcp->tcp_rexmit_max = tcp->tcp_fss;
				} else {
					tcp->tcp_rexmit_max = tcp->tcp_snxt;
				}

				/*
				 * Do not allow bursty traffic during.
				 * fast recovery.  Refer to Fall and Floyd's
				 * paper "Simulation-based Comparisons of
				 * Tahoe, Reno and SACK TCP" (in CCR ??)
				 * This is a best current practise.
				 */
				tcp->tcp_snd_burst = TCP_CWND_SS;

				/*
				 * For SACK:
				 * Calculate tcp_pipe, which is the
				 * estimated number of bytes in
				 * network.
				 *
				 * tcp_fack is the highest sack'ed seq num
				 * TCP has received.
				 *
				 * tcp_pipe is explained in the above quoted
				 * Fall and Floyd's paper.  tcp_fack is
				 * explained in Mathis and Mahdavi's
				 * "Forward Acknowledgment: Refining TCP
				 * Congestion Control" in SIGCOMM '96.
				 */
				if (tcp->tcp_snd_sack_ok) {
					assert(tcp->tcp_sack_info != NULL);
					if (tcp->tcp_notsack_list != NULL) {
						tcp->tcp_pipe = tcp->tcp_snxt -
						    tcp->tcp_fack;
						tcp->tcp_sack_snxt = seg_ack;
						flags |= TH_NEED_SACK_REXMIT;
					} else {
						/*
						 * Always initialize tcp_pipe
						 * even though we don't have
						 * any SACK info.  If later
						 * we get SACK info and
						 * tcp_pipe is not initialized,
						 * funny things will happen.
						 */
						tcp->tcp_pipe =
						    tcp->tcp_cwnd_ssthresh;
					}
				} else {
					flags |= TH_REXMIT_NEEDED;
				} /* tcp_snd_sack_ok */

				} else {
					/*
					 * Here we perform congestion
					 * avoidance, but NOT slow start.
					 * This is known as the Fast
					 * Recovery Algorithm.
					 */
					if (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL) {
						flags |= TH_NEED_SACK_REXMIT;
						tcp->tcp_pipe -= mss;
						if (tcp->tcp_pipe < 0)
							tcp->tcp_pipe = 0;
					} else {
					/*
					 * We know that one more packet has
					 * left the pipe thus we can update
					 * cwnd.
					 */
					cwnd = tcp->tcp_cwnd + mss;
					if (cwnd > tcp->tcp_cwnd_max)
						cwnd = tcp->tcp_cwnd_max;
					tcp->tcp_cwnd = cwnd;
					flags |= TH_XMIT_NEEDED;
					}
				}
			}
		} else if (tcp->tcp_zero_win_probe) {
			/*
			 * If the window has opened, need to arrange
			 * to send additional data.
			 */
			if (new_swnd != 0) {
				/* tcp_suna != tcp_snxt */
				/* Packet contains a window update */
				BUMP_MIB(tcp_mib.tcpInWinUpdate);
				tcp->tcp_zero_win_probe = 0;
				tcp->tcp_timer_backoff = 0;
				tcp->tcp_ms_we_have_waited = 0;

				/*
				 * Transmit starting with tcp_suna since
				 * the one byte probe is not ack'ed.
				 * If TCP has sent more than one identical
				 * probe, tcp_rexmit will be set.  That means
				 * tcp_ss_rexmit() will send out the one
				 * byte along with new data.  Otherwise,
				 * fake the retransmission.
				 */
				flags |= TH_XMIT_NEEDED;
				if (!tcp->tcp_rexmit) {
					tcp->tcp_rexmit = B_TRUE;
					tcp->tcp_dupack_cnt = 0;
					tcp->tcp_rexmit_nxt = tcp->tcp_suna;
					tcp->tcp_rexmit_max = tcp->tcp_suna + 1;
				}
			}
		}
		goto swnd_update;
	}

	/*
	 * Check for "acceptability" of ACK value per RFC 793, pages 72 - 73.
	 * If the ACK value acks something that we have not yet sent, it might
	 * be an old duplicate segment.  Send an ACK to re-synchronize the
	 * other side.
	 * Note: reset in response to unacceptable ACK in SYN_RECEIVE
	 * state is handled above, so we can always just drop the segment and
	 * send an ACK here.
	 *
	 * Should we send ACKs in response to ACK only segments?
	 */
	if (SEQ_GT(seg_ack, tcp->tcp_snxt)) {
		BUMP_MIB(tcp_mib.tcpInAckUnsent);
		/* drop the received segment */
		freemsg(mp);

		/* Send back an ACK. */
		mp = tcp_ack_mp(tcp);

		if (mp == NULL) {
			return;
		}
		BUMP_MIB(tcp_mib.tcpOutAck);
		(void) ipv4_tcp_output(sock_id, mp);
		freeb(mp);
		return;
	}

	/*
	 * TCP gets a new ACK, update the notsack'ed list to delete those
	 * blocks that are covered by this ACK.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
		tcp_notsack_remove(&(tcp->tcp_notsack_list), seg_ack,
		    &(tcp->tcp_num_notsack_blk), &(tcp->tcp_cnt_notsack_list));
	}

	/*
	 * If we got an ACK after fast retransmit, check to see
	 * if it is a partial ACK.  If it is not and the congestion
	 * window was inflated to account for the other side's
	 * cached packets, retract it.  If it is, do Hoe's algorithm.
	 */
	if (tcp->tcp_dupack_cnt >= tcp_dupack_fast_retransmit) {
		assert(tcp->tcp_rexmit == B_FALSE);
		if (SEQ_GEQ(seg_ack, tcp->tcp_rexmit_max)) {
			tcp->tcp_dupack_cnt = 0;
			/*
			 * Restore the orig tcp_cwnd_ssthresh after
			 * fast retransmit phase.
			 */
			if (tcp->tcp_cwnd > tcp->tcp_cwnd_ssthresh) {
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh;
			}
			tcp->tcp_rexmit_max = seg_ack;
			tcp->tcp_cwnd_cnt = 0;
			tcp->tcp_snd_burst = TCP_CWND_NORMAL;

			/*
			 * Remove all notsack info to avoid confusion with
			 * the next fast retrasnmit/recovery phase.
			 */
			if (tcp->tcp_snd_sack_ok &&
			    tcp->tcp_notsack_list != NULL) {
				TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
			}
		} else {
			if (tcp->tcp_snd_sack_ok &&
			    tcp->tcp_notsack_list != NULL) {
				flags |= TH_NEED_SACK_REXMIT;
				tcp->tcp_pipe -= mss;
				if (tcp->tcp_pipe < 0)
					tcp->tcp_pipe = 0;
			} else {
				/*
				 * Hoe's algorithm:
				 *
				 * Retransmit the unack'ed segment and
				 * restart fast recovery.  Note that we
				 * need to scale back tcp_cwnd to the
				 * original value when we started fast
				 * recovery.  This is to prevent overly
				 * aggressive behaviour in sending new
				 * segments.
				 */
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh +
					tcp_dupack_fast_retransmit * mss;
				tcp->tcp_cwnd_cnt = tcp->tcp_cwnd;
				BUMP_MIB(tcp_mib.tcpOutFastRetrans);
				flags |= TH_REXMIT_NEEDED;
			}
		}
	} else {
		tcp->tcp_dupack_cnt = 0;
		if (tcp->tcp_rexmit) {
			/*
			 * TCP is retranmitting.  If the ACK ack's all
			 * outstanding data, update tcp_rexmit_max and
			 * tcp_rexmit_nxt.  Otherwise, update tcp_rexmit_nxt
			 * to the correct value.
			 *
			 * Note that SEQ_LEQ() is used.  This is to avoid
			 * unnecessary fast retransmit caused by dup ACKs
			 * received when TCP does slow start retransmission
			 * after a time out.  During this phase, TCP may
			 * send out segments which are already received.
			 * This causes dup ACKs to be sent back.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_rexmit_max)) {
				if (SEQ_GT(seg_ack, tcp->tcp_rexmit_nxt)) {
					tcp->tcp_rexmit_nxt = seg_ack;
				}
				if (seg_ack != tcp->tcp_rexmit_max) {
					flags |= TH_XMIT_NEEDED;
				}
			} else {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
				tcp->tcp_snd_burst = TCP_CWND_NORMAL;
			}
			tcp->tcp_ms_we_have_waited = 0;
		}
	}

	BUMP_MIB(tcp_mib.tcpInAckSegs);
	UPDATE_MIB(tcp_mib.tcpInAckBytes, bytes_acked);
	tcp->tcp_suna = seg_ack;
	if (tcp->tcp_zero_win_probe != 0) {
		tcp->tcp_zero_win_probe = 0;
		tcp->tcp_timer_backoff = 0;
	}

	/*
	 * If tcp_xmit_head is NULL, then it must be the FIN being ack'ed.
	 * Note that it cannot be the SYN being ack'ed.  The code flow
	 * will not reach here.
	 */
	if (mp1 == NULL) {
		goto fin_acked;
	}

	/*
	 * Update the congestion window.
	 *
	 * If TCP is not ECN capable or TCP is ECN capable but the
	 * congestion experience bit is not set, increase the tcp_cwnd as
	 * usual.
	 */
	if (!tcp->tcp_ecn_ok || !(flags & TH_ECE)) {
		cwnd = tcp->tcp_cwnd;
		add = mss;

		if (cwnd >= tcp->tcp_cwnd_ssthresh) {
			/*
			 * This is to prevent an increase of less than 1 MSS of
			 * tcp_cwnd.  With partial increase, tcp_wput_data()
			 * may send out tinygrams in order to preserve mblk
			 * boundaries.
			 *
			 * By initializing tcp_cwnd_cnt to new tcp_cwnd and
			 * decrementing it by 1 MSS for every ACKs, tcp_cwnd is
			 * increased by 1 MSS for every RTTs.
			 */
			if (tcp->tcp_cwnd_cnt <= 0) {
				tcp->tcp_cwnd_cnt = cwnd + add;
			} else {
				tcp->tcp_cwnd_cnt -= add;
				add = 0;
			}
		}
		tcp->tcp_cwnd = MIN(cwnd + add, tcp->tcp_cwnd_max);
	}

	/* Can we update the RTT estimates? */
	if (tcp->tcp_snd_ts_ok) {
		/* Ignore zero timestamp echo-reply. */
		if (tcpopt.tcp_opt_ts_ecr != 0) {
			tcp_set_rto(tcp, (int32_t)(prom_gettime() -
			    tcpopt.tcp_opt_ts_ecr));
		}

		/* If needed, restart the timer. */
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
		/*
		 * Update tcp_csuna in case the other side stops sending
		 * us timestamps.
		 */
		tcp->tcp_csuna = tcp->tcp_snxt;
	} else if (SEQ_GT(seg_ack, tcp->tcp_csuna)) {
		/*
		 * An ACK sequence we haven't seen before, so get the RTT
		 * and update the RTO.
		 * Note. use uintptr_t to suppress the gcc warning.
		 */
		tcp_set_rto(tcp, (int32_t)(prom_gettime() -
		    (uint32_t)(uintptr_t)mp1->b_prev));

		/* Remeber the last sequence to be ACKed */
		tcp->tcp_csuna = seg_ack;
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
	} else {
		BUMP_MIB(tcp_mib.tcpRttNoUpdate);
	}

	/* Eat acknowledged bytes off the xmit queue. */
	for (;;) {
		mblk_t	*mp2;
		uchar_t	*wptr;

		wptr = mp1->b_wptr;
		assert((uintptr_t)(wptr - mp1->b_rptr) <= (uintptr_t)INT_MAX);
		bytes_acked -= (int)(wptr - mp1->b_rptr);
		if (bytes_acked < 0) {
			mp1->b_rptr = wptr + bytes_acked;
			break;
		}
		mp1->b_prev = NULL;
		mp2 = mp1;
		mp1 = mp1->b_cont;
		freeb(mp2);
		if (bytes_acked == 0) {
			if (mp1 == NULL) {
				/* Everything is ack'ed, clear the tail. */
				tcp->tcp_xmit_tail = NULL;
				goto pre_swnd_update;
			}
			if (mp2 != tcp->tcp_xmit_tail)
				break;
			tcp->tcp_xmit_tail = mp1;
			assert((uintptr_t)(mp1->b_wptr -
			    mp1->b_rptr) <= (uintptr_t)INT_MAX);
			tcp->tcp_xmit_tail_unsent = (int)(mp1->b_wptr -
			    mp1->b_rptr);
			break;
		}
		if (mp1 == NULL) {
			/*
			 * More was acked but there is nothing more
			 * outstanding.  This means that the FIN was
			 * just acked or that we're talking to a clown.
			 */
fin_acked:
			assert(tcp->tcp_fin_sent);
			tcp->tcp_xmit_tail = NULL;
			if (tcp->tcp_fin_sent) {
				tcp->tcp_fin_acked = B_TRUE;
			} else {
				/*
				 * We should never got here because
				 * we have already checked that the
				 * number of bytes ack'ed should be
				 * smaller than or equal to what we
				 * have sent so far (it is the
				 * acceptability check of the ACK).
				 * We can only get here if the send
				 * queue is corrupted.
				 *
				 * Terminate the connection and
				 * panic the system.  It is better
				 * for us to panic instead of
				 * continuing to avoid other disaster.
				 */
				tcp_xmit_ctl(NULL, tcp, NULL, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST|TH_ACK, 0, sock_id);
				printf("Memory corruption "
				    "detected for connection %s.\n",
				    tcp_display(tcp, NULL,
					DISP_ADDR_AND_PORT));
				/* We should never get here... */
				prom_panic("tcp_rput_data");
				return;
			}
			goto pre_swnd_update;
		}
		assert(mp2 != tcp->tcp_xmit_tail);
	}
	if (tcp->tcp_unsent) {
		flags |= TH_XMIT_NEEDED;
	}
pre_swnd_update:
	tcp->tcp_xmit_head = mp1;
swnd_update:
	/*
	 * The following check is different from most other implementations.
	 * For bi-directional transfer, when segments are dropped, the
	 * "normal" check will not accept a window update in those
	 * retransmitted segemnts.  Failing to do that, TCP may send out
	 * segments which are outside receiver's window.  As TCP accepts
	 * the ack in those retransmitted segments, if the window update in
	 * the same segment is not accepted, TCP will incorrectly calculates
	 * that it can send more segments.  This can create a deadlock
	 * with the receiver if its window becomes zero.
	 */
	if (SEQ_LT(tcp->tcp_swl2, seg_ack) ||
	    SEQ_LT(tcp->tcp_swl1, seg_seq) ||
	    (tcp->tcp_swl1 == seg_seq && new_swnd > tcp->tcp_swnd)) {
		/*
		 * The criteria for update is:
		 *
		 * 1. the segment acknowledges some data.  Or
		 * 2. the segment is new, i.e. it has a higher seq num. Or
		 * 3. the segment is not old and the advertised window is
		 * larger than the previous advertised window.
		 */
		if (tcp->tcp_unsent && new_swnd > tcp->tcp_swnd)
			flags |= TH_XMIT_NEEDED;
		tcp->tcp_swnd = new_swnd;
		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
	}
est:
	if (tcp->tcp_state > TCPS_ESTABLISHED) {
		switch (tcp->tcp_state) {
		case TCPS_FIN_WAIT_1:
			if (tcp->tcp_fin_acked) {
				tcp->tcp_state = TCPS_FIN_WAIT_2;
				/*
				 * We implement the non-standard BSD/SunOS
				 * FIN_WAIT_2 flushing algorithm.
				 * If there is no user attached to this
				 * TCP endpoint, then this TCP struct
				 * could hang around forever in FIN_WAIT_2
				 * state if the peer forgets to send us
				 * a FIN.  To prevent this, we wait only
				 * 2*MSL (a convenient time value) for
				 * the FIN to arrive.  If it doesn't show up,
				 * we flush the TCP endpoint.  This algorithm,
				 * though a violation of RFC-793, has worked
				 * for over 10 years in BSD systems.
				 * Note: SunOS 4.x waits 675 seconds before
				 * flushing the FIN_WAIT_2 connection.
				 */
				TCP_TIMER_RESTART(tcp,
				    tcp_fin_wait_2_flush_interval);
			}
			break;
		case TCPS_FIN_WAIT_2:
			break;	/* Shutdown hook? */
		case TCPS_LAST_ACK:
			freemsg(mp);
			if (tcp->tcp_fin_acked) {
				(void) tcp_clean_death(sock_id, tcp, 0);
				return;
			}
			goto xmit_check;
		case TCPS_CLOSING:
			if (tcp->tcp_fin_acked) {
				tcp->tcp_state = TCPS_TIME_WAIT;
				tcp_time_wait_append(tcp);
				TCP_TIMER_RESTART(tcp, tcp_time_wait_interval);
			}
			/*FALLTHRU*/
		case TCPS_CLOSE_WAIT:
			freemsg(mp);
			goto xmit_check;
		default:
			assert(tcp->tcp_state != TCPS_TIME_WAIT);
			break;
		}
	}
	if (flags & TH_FIN) {
		/* Make sure we ack the fin */
		flags |= TH_ACK_NEEDED;
		if (!tcp->tcp_fin_rcvd) {
			tcp->tcp_fin_rcvd = B_TRUE;
			tcp->tcp_rnxt++;
			U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);

			switch (tcp->tcp_state) {
			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
				tcp->tcp_state = TCPS_CLOSE_WAIT;
				/* Keepalive? */
				break;
			case TCPS_FIN_WAIT_1:
				if (!tcp->tcp_fin_acked) {
					tcp->tcp_state = TCPS_CLOSING;
					break;
				}
				/* FALLTHRU */
			case TCPS_FIN_WAIT_2:
				tcp->tcp_state = TCPS_TIME_WAIT;
				tcp_time_wait_append(tcp);
				TCP_TIMER_RESTART(tcp, tcp_time_wait_interval);
				if (seg_len) {
					/*
					 * implies data piggybacked on FIN.
					 * break to handle data.
					 */
					break;
				}
				freemsg(mp);
				goto ack_check;
			}
		}
	}
	if (mp == NULL)
		goto xmit_check;
	if (seg_len == 0) {
		freemsg(mp);
		goto xmit_check;
	}
	if (mp->b_rptr == mp->b_wptr) {
		/*
		 * The header has been consumed, so we remove the
		 * zero-length mblk here.
		 */
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
	}
	/*
	 * ACK every other segments, unless the input queue is empty
	 * as we don't have a timer available.
	 */
	if (++tcp->tcp_rack_cnt == 2 || sockets[sock_id].inq == NULL) {
		flags |= TH_ACK_NEEDED;
		tcp->tcp_rack_cnt = 0;
	}
	tcp->tcp_rnxt += seg_len;
	U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);

	/* Update SACK list */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		tcp_sack_remove(tcp->tcp_sack_list, tcp->tcp_rnxt,
		    &(tcp->tcp_num_sack_blk));
	}

	if (tcp->tcp_listener) {
		/*
		 * Side queue inbound data until the accept happens.
		 * tcp_accept/tcp_rput drains this when the accept happens.
		 */
		tcp_rcv_enqueue(tcp, mp, seg_len);
	} else {
		/* Just queue the data until the app calls read. */
		tcp_rcv_enqueue(tcp, mp, seg_len);
		/*
		 * Make sure the timer is running if we have data waiting
		 * for a push bit. This provides resiliency against
		 * implementations that do not correctly generate push bits.
		 */
		if (tcp->tcp_rcv_list != NULL)
			flags |= TH_TIMER_NEEDED;
	}

xmit_check:
	/* Is there anything left to do? */
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_ACK_NEEDED|
	    TH_NEED_SACK_REXMIT|TH_LIMIT_XMIT|TH_TIMER_NEEDED)) == 0)
		return;

	/* Any transmit work to do and a non-zero window? */
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_NEED_SACK_REXMIT|
	    TH_LIMIT_XMIT)) && tcp->tcp_swnd != 0) {
		if (flags & TH_REXMIT_NEEDED) {
			uint32_t snd_size = tcp->tcp_snxt - tcp->tcp_suna;

			if (snd_size > mss)
				snd_size = mss;
			if (snd_size > tcp->tcp_swnd)
				snd_size = tcp->tcp_swnd;
			mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, snd_size,
			    NULL, NULL, tcp->tcp_suna, B_TRUE, &snd_size,
			    B_TRUE);

			if (mp1 != NULL) {
				/* use uintptr_t to suppress the gcc warning */
				tcp->tcp_xmit_head->b_prev =
				    (mblk_t *)(uintptr_t)prom_gettime();
				tcp->tcp_csuna = tcp->tcp_snxt;
				BUMP_MIB(tcp_mib.tcpRetransSegs);
				UPDATE_MIB(tcp_mib.tcpRetransBytes, snd_size);
				(void) ipv4_tcp_output(sock_id, mp1);
				freeb(mp1);
			}
		}
		if (flags & TH_NEED_SACK_REXMIT) {
			if (tcp_sack_rxmit(tcp, sock_id) != 0) {
				flags |= TH_XMIT_NEEDED;
			}
		}
		/*
		 * For TH_LIMIT_XMIT, tcp_wput_data() is called to send
		 * out new segment.  Note that tcp_rexmit should not be
		 * set, otherwise TH_LIMIT_XMIT should not be set.
		 */
		if (flags & (TH_XMIT_NEEDED|TH_LIMIT_XMIT)) {
			if (!tcp->tcp_rexmit) {
				tcp_wput_data(tcp, NULL, sock_id);
			} else {
				tcp_ss_rexmit(tcp, sock_id);
			}
			/*
			 * The TCP could be closed in tcp_state_wait via
			 * tcp_wput_data (tcp_ss_rexmit could call
			 * tcp_wput_data as well).
			 */
			if (sockets[sock_id].pcb == NULL)
				return;
		}
		/*
		 * Adjust tcp_cwnd back to normal value after sending
		 * new data segments.
		 */
		if (flags & TH_LIMIT_XMIT) {
			tcp->tcp_cwnd -= mss << (tcp->tcp_dupack_cnt - 1);
		}

		/* Anything more to do? */
		if ((flags & (TH_ACK_NEEDED|TH_TIMER_NEEDED)) == 0)
			return;
	}
ack_check:
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		if ((mp1 = tcp_ack_mp(tcp)) != NULL) {
			TCP_DUMP_PACKET("tcp_rput_data: ack mp", mp1);
			(void) ipv4_tcp_output(sock_id, mp1);
			BUMP_MIB(tcp_mib.tcpOutAck);
			freeb(mp1);
		}
	}
}

/*
 * tcp_ss_rexmit() is called in tcp_rput_data() to do slow start
 * retransmission after a timeout.
 *
 * To limit the number of duplicate segments, we limit the number of segment
 * to be sent in one time to tcp_snd_burst, the burst variable.
 */
static void
tcp_ss_rexmit(tcp_t *tcp, int sock_id)
{
	uint32_t	snxt;
	uint32_t	smax;
	int32_t		win;
	int32_t		mss;
	int32_t		off;
	int32_t		burst = tcp->tcp_snd_burst;
	mblk_t		*snxt_mp;

	/*
	 * Note that tcp_rexmit can be set even though TCP has retransmitted
	 * all unack'ed segments.
	 */
	if (SEQ_LT(tcp->tcp_rexmit_nxt, tcp->tcp_rexmit_max)) {
		smax = tcp->tcp_rexmit_max;
		snxt = tcp->tcp_rexmit_nxt;
		if (SEQ_LT(snxt, tcp->tcp_suna)) {
			snxt = tcp->tcp_suna;
		}
		win = MIN(tcp->tcp_cwnd, tcp->tcp_swnd);
		win -= snxt - tcp->tcp_suna;
		mss = tcp->tcp_mss;
		snxt_mp = tcp_get_seg_mp(tcp, snxt, &off);

		while (SEQ_LT(snxt, smax) && (win > 0) &&
		    (burst > 0) && (snxt_mp != NULL)) {
			mblk_t	*xmit_mp;
			mblk_t	*old_snxt_mp = snxt_mp;
			uint32_t cnt = mss;

			if (win < cnt) {
				cnt = win;
			}
			if (SEQ_GT(snxt + cnt, smax)) {
				cnt = smax - snxt;
			}
			xmit_mp = tcp_xmit_mp(tcp, snxt_mp, cnt, &off,
			    &snxt_mp, snxt, B_TRUE, &cnt, B_TRUE);

			if (xmit_mp == NULL)
				return;

			(void) ipv4_tcp_output(sock_id, xmit_mp);
			freeb(xmit_mp);

			snxt += cnt;
			win -= cnt;
			/*
			 * Update the send timestamp to avoid false
			 * retransmission.
			 * Note. use uintptr_t to suppress the gcc warning.
			 */
			old_snxt_mp->b_prev =
			    (mblk_t *)(uintptr_t)prom_gettime();
			BUMP_MIB(tcp_mib.tcpRetransSegs);
			UPDATE_MIB(tcp_mib.tcpRetransBytes, cnt);

			tcp->tcp_rexmit_nxt = snxt;
			burst--;
		}
		/*
		 * If we have transmitted all we have at the time
		 * we started the retranmission, we can leave
		 * the rest of the job to tcp_wput_data().  But we
		 * need to check the send window first.  If the
		 * win is not 0, go on with tcp_wput_data().
		 */
		if (SEQ_LT(snxt, smax) || win == 0) {
			return;
		}
	}
	/* Only call tcp_wput_data() if there is data to be sent. */
	if (tcp->tcp_unsent) {
		tcp_wput_data(tcp, NULL, sock_id);
	}
}

/*
 * tcp_timer is the timer service routine.  It handles all timer events for
 * a tcp instance except keepalives.  It figures out from the state of the
 * tcp instance what kind of action needs to be done at the time it is called.
 */
static void
tcp_timer(tcp_t	*tcp, int sock_id)
{
	mblk_t		*mp;
	uint32_t	first_threshold;
	uint32_t	second_threshold;
	uint32_t	ms;
	uint32_t	mss;

	first_threshold =  tcp->tcp_first_timer_threshold;
	second_threshold = tcp->tcp_second_timer_threshold;
	switch (tcp->tcp_state) {
	case TCPS_IDLE:
	case TCPS_BOUND:
	case TCPS_LISTEN:
		return;
	case TCPS_SYN_RCVD:
	case TCPS_SYN_SENT:
		first_threshold =  tcp->tcp_first_ctimer_threshold;
		second_threshold = tcp->tcp_second_ctimer_threshold;
		break;
	case TCPS_ESTABLISHED:
	case TCPS_FIN_WAIT_1:
	case TCPS_CLOSING:
	case TCPS_CLOSE_WAIT:
	case TCPS_LAST_ACK:
		/* If we have data to rexmit */
		if (tcp->tcp_suna != tcp->tcp_snxt) {
			int32_t time_to_wait;

			BUMP_MIB(tcp_mib.tcpTimRetrans);
			if (tcp->tcp_xmit_head == NULL)
				break;
			/* use uintptr_t to suppress the gcc warning */
			time_to_wait = (int32_t)(prom_gettime() -
			    (uint32_t)(uintptr_t)tcp->tcp_xmit_head->b_prev);
			time_to_wait = tcp->tcp_rto - time_to_wait;
			if (time_to_wait > 0) {
				/*
				 * Timer fired too early, so restart it.
				 */
				TCP_TIMER_RESTART(tcp, time_to_wait);
				return;
			}
			/*
			 * When we probe zero windows, we force the swnd open.
			 * If our peer acks with a closed window swnd will be
			 * set to zero by tcp_rput(). As long as we are
			 * receiving acks tcp_rput will
			 * reset 'tcp_ms_we_have_waited' so as not to trip the
			 * first and second interval actions.  NOTE: the timer
			 * interval is allowed to continue its exponential
			 * backoff.
			 */
			if (tcp->tcp_swnd == 0 || tcp->tcp_zero_win_probe) {
				DEBUG_1("tcp_timer (%d): zero win", sock_id);
				break;
			} else {
				/*
				 * After retransmission, we need to do
				 * slow start.  Set the ssthresh to one
				 * half of current effective window and
				 * cwnd to one MSS.  Also reset
				 * tcp_cwnd_cnt.
				 *
				 * Note that if tcp_ssthresh is reduced because
				 * of ECN, do not reduce it again unless it is
				 * already one window of data away (tcp_cwr
				 * should then be cleared) or this is a
				 * timeout for a retransmitted segment.
				 */
				uint32_t npkt;

				if (!tcp->tcp_cwr || tcp->tcp_rexmit) {
					npkt = (MIN((tcp->tcp_timer_backoff ?
					    tcp->tcp_cwnd_ssthresh :
					    tcp->tcp_cwnd),
					    tcp->tcp_swnd) >> 1) /
					    tcp->tcp_mss;
					if (npkt < 2)
						npkt = 2;
					tcp->tcp_cwnd_ssthresh = npkt *
					    tcp->tcp_mss;
				}
				tcp->tcp_cwnd = tcp->tcp_mss;
				tcp->tcp_cwnd_cnt = 0;
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}
			}
			break;
		}
		/*
		 * We have something to send yet we cannot send.  The
		 * reason can be:
		 *
		 * 1. Zero send window: we need to do zero window probe.
		 * 2. Zero cwnd: because of ECN, we need to "clock out
		 * segments.
		 * 3. SWS avoidance: receiver may have shrunk window,
		 * reset our knowledge.
		 *
		 * Note that condition 2 can happen with either 1 or
		 * 3.  But 1 and 3 are exclusive.
		 */
		if (tcp->tcp_unsent != 0) {
			if (tcp->tcp_cwnd == 0) {
				/*
				 * Set tcp_cwnd to 1 MSS so that a
				 * new segment can be sent out.  We
				 * are "clocking out" new data when
				 * the network is really congested.
				 */
				assert(tcp->tcp_ecn_ok);
				tcp->tcp_cwnd = tcp->tcp_mss;
			}
			if (tcp->tcp_swnd == 0) {
				/* Extend window for zero window probe */
				tcp->tcp_swnd++;
				tcp->tcp_zero_win_probe = B_TRUE;
				BUMP_MIB(tcp_mib.tcpOutWinProbe);
			} else {
				/*
				 * Handle timeout from sender SWS avoidance.
				 * Reset our knowledge of the max send window
				 * since the receiver might have reduced its
				 * receive buffer.  Avoid setting tcp_max_swnd
				 * to one since that will essentially disable
				 * the SWS checks.
				 *
				 * Note that since we don't have a SWS
				 * state variable, if the timeout is set
				 * for ECN but not for SWS, this
				 * code will also be executed.  This is
				 * fine as tcp_max_swnd is updated
				 * constantly and it will not affect
				 * anything.
				 */
				tcp->tcp_max_swnd = MAX(tcp->tcp_swnd, 2);
			}
			tcp_wput_data(tcp, NULL, sock_id);
			return;
		}
		/* Is there a FIN that needs to be to re retransmitted? */
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    !tcp->tcp_fin_acked)
			break;
		/* Nothing to do, return without restarting timer. */
		return;
	case TCPS_FIN_WAIT_2:
		/*
		 * User closed the TCP endpoint and peer ACK'ed our FIN.
		 * We waited some time for for peer's FIN, but it hasn't
		 * arrived.  We flush the connection now to avoid
		 * case where the peer has rebooted.
		 */
		/* FALLTHRU */
	case TCPS_TIME_WAIT:
		(void) tcp_clean_death(sock_id, tcp, 0);
		return;
	default:
		DEBUG_3("tcp_timer (%d): strange state (%d) %s", sock_id,
		    tcp->tcp_state, tcp_display(tcp, NULL,
		    DISP_PORT_ONLY));
		return;
	}
	if ((ms = tcp->tcp_ms_we_have_waited) > second_threshold) {
		/*
		 * For zero window probe, we need to send indefinitely,
		 * unless we have not heard from the other side for some
		 * time...
		 */
		if ((tcp->tcp_zero_win_probe == 0) ||
		    ((prom_gettime() - tcp->tcp_last_recv_time) >
		    second_threshold)) {
			BUMP_MIB(tcp_mib.tcpTimRetransDrop);
			/*
			 * If TCP is in SYN_RCVD state, send back a
			 * RST|ACK as BSD does.  Note that tcp_zero_win_probe
			 * should be zero in TCPS_SYN_RCVD state.
			 */
			if (tcp->tcp_state == TCPS_SYN_RCVD) {
				tcp_xmit_ctl("tcp_timer: RST sent on timeout "
				    "in SYN_RCVD",
				    tcp, NULL, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST | TH_ACK, 0, sock_id);
			}
			(void) tcp_clean_death(sock_id, tcp,
			    tcp->tcp_client_errno ?
			    tcp->tcp_client_errno : ETIMEDOUT);
			return;
		} else {
			/*
			 * Set tcp_ms_we_have_waited to second_threshold
			 * so that in next timeout, we will do the above
			 * check (lbolt - tcp_last_recv_time).  This is
			 * also to avoid overflow.
			 *
			 * We don't need to decrement tcp_timer_backoff
			 * to avoid overflow because it will be decremented
			 * later if new timeout value is greater than
			 * tcp_rexmit_interval_max.  In the case when
			 * tcp_rexmit_interval_max is greater than
			 * second_threshold, it means that we will wait
			 * longer than second_threshold to send the next
			 * window probe.
			 */
			tcp->tcp_ms_we_have_waited = second_threshold;
		}
	} else if (ms > first_threshold && tcp->tcp_rtt_sa != 0) {
		/*
		 * We have been retransmitting for too long...  The RTT
		 * we calculated is probably incorrect.  Reinitialize it.
		 * Need to compensate for 0 tcp_rtt_sa.  Reset
		 * tcp_rtt_update so that we won't accidentally cache a
		 * bad value.  But only do this if this is not a zero
		 * window probe.
		 */
		if (tcp->tcp_zero_win_probe == 0) {
			tcp->tcp_rtt_sd += (tcp->tcp_rtt_sa >> 3) +
			    (tcp->tcp_rtt_sa >> 5);
			tcp->tcp_rtt_sa = 0;
			tcp->tcp_rtt_update = 0;
		}
	}
	tcp->tcp_timer_backoff++;
	if ((ms = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcp_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5)) <
	    tcp_rexmit_interval_min) {
		/*
		 * This means the original RTO is tcp_rexmit_interval_min.
		 * So we will use tcp_rexmit_interval_min as the RTO value
		 * and do the backoff.
		 */
		ms = tcp_rexmit_interval_min << tcp->tcp_timer_backoff;
	} else {
		ms <<= tcp->tcp_timer_backoff;
	}
	if (ms > tcp_rexmit_interval_max) {
		ms = tcp_rexmit_interval_max;
		/*
		 * ms is at max, decrement tcp_timer_backoff to avoid
		 * overflow.
		 */
		tcp->tcp_timer_backoff--;
	}
	tcp->tcp_ms_we_have_waited += ms;
	if (tcp->tcp_zero_win_probe == 0) {
		tcp->tcp_rto = ms;
	}
	TCP_TIMER_RESTART(tcp, ms);
	/*
	 * This is after a timeout and tcp_rto is backed off.  Set
	 * tcp_set_timer to 1 so that next time RTO is updated, we will
	 * restart the timer with a correct value.
	 */
	tcp->tcp_set_timer = 1;
	mss = tcp->tcp_snxt - tcp->tcp_suna;
	if (mss > tcp->tcp_mss)
		mss = tcp->tcp_mss;
	if (mss > tcp->tcp_swnd && tcp->tcp_swnd != 0)
		mss = tcp->tcp_swnd;

	if ((mp = tcp->tcp_xmit_head) != NULL) {
		/* use uintptr_t to suppress the gcc warning */
		mp->b_prev = (mblk_t *)(uintptr_t)prom_gettime();
	}
	mp = tcp_xmit_mp(tcp, mp, mss, NULL, NULL, tcp->tcp_suna, B_TRUE, &mss,
	    B_TRUE);
	if (mp == NULL)
		return;
	tcp->tcp_csuna = tcp->tcp_snxt;
	BUMP_MIB(tcp_mib.tcpRetransSegs);
	UPDATE_MIB(tcp_mib.tcpRetransBytes, mss);
	/* Dump the packet when debugging. */
	TCP_DUMP_PACKET("tcp_timer", mp);

	(void) ipv4_tcp_output(sock_id, mp);
	freeb(mp);

	/*
	 * When slow start after retransmission begins, start with
	 * this seq no.  tcp_rexmit_max marks the end of special slow
	 * start phase.  tcp_snd_burst controls how many segments
	 * can be sent because of an ack.
	 */
	tcp->tcp_rexmit_nxt = tcp->tcp_suna;
	tcp->tcp_snd_burst = TCP_CWND_SS;
	if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
	    (tcp->tcp_unsent == 0)) {
		tcp->tcp_rexmit_max = tcp->tcp_fss;
	} else {
		tcp->tcp_rexmit_max = tcp->tcp_snxt;
	}
	tcp->tcp_rexmit = B_TRUE;
	tcp->tcp_dupack_cnt = 0;

	/*
	 * Remove all rexmit SACK blk to start from fresh.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
		TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
		tcp->tcp_num_notsack_blk = 0;
		tcp->tcp_cnt_notsack_list = 0;
	}
}

/*
 * The TCP normal data output path.
 * NOTE: the logic of the fast path is duplicated from this function.
 */
static void
tcp_wput_data(tcp_t *tcp, mblk_t *mp, int sock_id)
{
	int		len;
	mblk_t		*local_time;
	mblk_t		*mp1;
	uchar_t		*rptr;
	uint32_t	snxt;
	int		tail_unsent;
	int		tcpstate;
	int		usable = 0;
	mblk_t		*xmit_tail;
	int32_t		num_burst_seg;
	int32_t		mss;
	int32_t		num_sack_blk = 0;
	int32_t		tcp_hdr_len;
	ipaddr_t	*dst;
	ipaddr_t	*src;

#ifdef DEBUG
	printf("tcp_wput_data(%d) ##############################\n", sock_id);
#endif
	tcpstate = tcp->tcp_state;
	if (mp == NULL) {
		/* Really tacky... but we need this for detached closes. */
		len = tcp->tcp_unsent;
		goto data_null;
	}

	/*
	 * Don't allow data after T_ORDREL_REQ or T_DISCON_REQ,
	 * or before a connection attempt has begun.
	 *
	 * The following should not happen in inetboot....
	 */
	if (tcpstate < TCPS_SYN_SENT || tcpstate > TCPS_CLOSE_WAIT ||
	    (tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
			printf("tcp_wput_data: data after ordrel, %s\n",
			    tcp_display(tcp, NULL, DISP_ADDR_AND_PORT));
		}
		freemsg(mp);
		return;
	}

	/* Strip empties */
	for (;;) {
		assert((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		len = (int)(mp->b_wptr - mp->b_rptr);
		if (len > 0)
			break;
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
		if (mp == NULL) {
			return;
		}
	}

	/* If we are the first on the list ... */
	if (tcp->tcp_xmit_head == NULL) {
		tcp->tcp_xmit_head = mp;
		tcp->tcp_xmit_tail = mp;
		tcp->tcp_xmit_tail_unsent = len;
	} else {
		tcp->tcp_xmit_last->b_cont = mp;
		len += tcp->tcp_unsent;
	}

	/* Tack on however many more positive length mblks we have */
	if ((mp1 = mp->b_cont) != NULL) {
		do {
			int tlen;
			assert((uintptr_t)(mp1->b_wptr -
			    mp1->b_rptr) <= (uintptr_t)INT_MAX);
			tlen = (int)(mp1->b_wptr - mp1->b_rptr);
			if (tlen <= 0) {
				mp->b_cont = mp1->b_cont;
				freeb(mp1);
			} else {
				len += tlen;
				mp = mp1;
			}
		} while ((mp1 = mp->b_cont) != NULL);
	}
	tcp->tcp_xmit_last = mp;
	tcp->tcp_unsent = len;

data_null:
	snxt = tcp->tcp_snxt;
	xmit_tail = tcp->tcp_xmit_tail;
	tail_unsent = tcp->tcp_xmit_tail_unsent;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		int32_t	opt_len;

		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		opt_len = num_sack_blk * sizeof (sack_blk_t) + TCPOPT_NOP_LEN *
		    2 + TCPOPT_HEADER_LEN;
		mss = tcp->tcp_mss - opt_len;
		tcp_hdr_len = tcp->tcp_hdr_len + opt_len;
	} else {
		mss = tcp->tcp_mss;
		tcp_hdr_len = tcp->tcp_hdr_len;
	}

	if ((tcp->tcp_suna == snxt) &&
	    (prom_gettime() - tcp->tcp_last_recv_time) >= tcp->tcp_rto) {
		tcp->tcp_cwnd = MIN(tcp_slow_start_after_idle * mss,
		    MIN(4 * mss, MAX(2 * mss, 4380 / mss * mss)));
	}
	if (tcpstate == TCPS_SYN_RCVD) {
		/*
		 * The three-way connection establishment handshake is not
		 * complete yet. We want to queue the data for transmission
		 * after entering ESTABLISHED state (RFC793). Setting usable to
		 * zero cause a jump to "done" label effectively leaving data
		 * on the queue.
		 */

		usable = 0;
	} else {
		int usable_r = tcp->tcp_swnd;

		/*
		 * In the special case when cwnd is zero, which can only
		 * happen if the connection is ECN capable, return now.
		 * New segments is sent using tcp_timer().  The timer
		 * is set in tcp_rput_data().
		 */
		if (tcp->tcp_cwnd == 0) {
			/*
			 * Note that tcp_cwnd is 0 before 3-way handshake is
			 * finished.
			 */
			assert(tcp->tcp_ecn_ok ||
			    tcp->tcp_state < TCPS_ESTABLISHED);
			return;
		}

		/* usable = MIN(swnd, cwnd) - unacked_bytes */
		if (usable_r > tcp->tcp_cwnd)
			usable_r = tcp->tcp_cwnd;

		/* NOTE: trouble if xmitting while SYN not acked? */
		usable_r -= snxt;
		usable_r += tcp->tcp_suna;

		/* usable = MIN(usable, unsent) */
		if (usable_r > len)
			usable_r = len;

		/* usable = MAX(usable, {1 for urgent, 0 for data}) */
		if (usable_r != 0)
			usable = usable_r;
	}

	/* use uintptr_t to suppress the gcc warning */
	local_time = (mblk_t *)(uintptr_t)prom_gettime();

	/*
	 * "Our" Nagle Algorithm.  This is not the same as in the old
	 * BSD.  This is more in line with the true intent of Nagle.
	 *
	 * The conditions are:
	 * 1. The amount of unsent data (or amount of data which can be
	 *    sent, whichever is smaller) is less than Nagle limit.
	 * 2. The last sent size is also less than Nagle limit.
	 * 3. There is unack'ed data.
	 * 4. Urgent pointer is not set.  Send urgent data ignoring the
	 *    Nagle algorithm.  This reduces the probability that urgent
	 *    bytes get "merged" together.
	 * 5. The app has not closed the connection.  This eliminates the
	 *    wait time of the receiving side waiting for the last piece of
	 *    (small) data.
	 *
	 * If all are satisified, exit without sending anything.  Note
	 * that Nagle limit can be smaller than 1 MSS.  Nagle limit is
	 * the smaller of 1 MSS and global tcp_naglim_def (default to be
	 * 4095).
	 */
	if (usable < (int)tcp->tcp_naglim &&
	    tcp->tcp_naglim > tcp->tcp_last_sent_len &&
	    snxt != tcp->tcp_suna &&
	    !(tcp->tcp_valid_bits & TCP_URG_VALID))
		goto done;

	num_burst_seg = tcp->tcp_snd_burst;
	for (;;) {
		tcph_t		*tcph;
		mblk_t		*new_mp;

		if (num_burst_seg-- == 0)
			goto done;

		len = mss;
		if (len > usable) {
			len = usable;
			if (len <= 0) {
				/* Terminate the loop */
				goto done;
			}
			/*
			 * Sender silly-window avoidance.
			 * Ignore this if we are going to send a
			 * zero window probe out.
			 *
			 * TODO: force data into microscopic window ??
			 *	==> (!pushed || (unsent > usable))
			 */
			if (len < (tcp->tcp_max_swnd >> 1) &&
			    (tcp->tcp_unsent - (snxt - tcp->tcp_snxt)) > len &&
			    !((tcp->tcp_valid_bits & TCP_URG_VALID) &&
			    len == 1) && (! tcp->tcp_zero_win_probe)) {
				/*
				 * If the retransmit timer is not running
				 * we start it so that we will retransmit
				 * in the case when the the receiver has
				 * decremented the window.
				 */
				if (snxt == tcp->tcp_snxt &&
				    snxt == tcp->tcp_suna) {
					/*
					 * We are not supposed to send
					 * anything.  So let's wait a little
					 * bit longer before breaking SWS
					 * avoidance.
					 *
					 * What should the value be?
					 * Suggestion: MAX(init rexmit time,
					 * tcp->tcp_rto)
					 */
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				}
				goto done;
			}
		}

		tcph = tcp->tcp_tcph;

		usable -= len;	/* Approximate - can be adjusted later */
		if (usable > 0)
			tcph->th_flags[0] = TH_ACK;
		else
			tcph->th_flags[0] = (TH_ACK | TH_PUSH);

		U32_TO_ABE32(snxt, tcph->th_seq);

		if (tcp->tcp_valid_bits) {
			uchar_t		*prev_rptr = xmit_tail->b_rptr;
			uint32_t	prev_snxt = tcp->tcp_snxt;

			if (tail_unsent == 0) {
				assert(xmit_tail->b_cont != NULL);
				xmit_tail = xmit_tail->b_cont;
				prev_rptr = xmit_tail->b_rptr;
				tail_unsent = (int)(xmit_tail->b_wptr -
				    xmit_tail->b_rptr);
			} else {
				xmit_tail->b_rptr = xmit_tail->b_wptr -
				    tail_unsent;
			}
			mp = tcp_xmit_mp(tcp, xmit_tail, len, NULL, NULL,
			    snxt, B_FALSE, (uint32_t *)&len, B_FALSE);
			/* Restore tcp_snxt so we get amount sent right. */
			tcp->tcp_snxt = prev_snxt;
			if (prev_rptr == xmit_tail->b_rptr)
				xmit_tail->b_prev = local_time;
			else
				xmit_tail->b_rptr = prev_rptr;

			if (mp == NULL)
				break;

			mp1 = mp->b_cont;

			snxt += len;
			tcp->tcp_last_sent_len = (ushort_t)len;
			while (mp1->b_cont) {
				xmit_tail = xmit_tail->b_cont;
				xmit_tail->b_prev = local_time;
				mp1 = mp1->b_cont;
			}
			tail_unsent = xmit_tail->b_wptr - mp1->b_wptr;
			BUMP_MIB(tcp_mib.tcpOutDataSegs);
			UPDATE_MIB(tcp_mib.tcpOutDataBytes, len);
			/* Dump the packet when debugging. */
			TCP_DUMP_PACKET("tcp_wput_data (valid bits)", mp);
			(void) ipv4_tcp_output(sock_id, mp);
			freeb(mp);
			continue;
		}

		snxt += len;	/* Adjust later if we don't send all of len */
		BUMP_MIB(tcp_mib.tcpOutDataSegs);
		UPDATE_MIB(tcp_mib.tcpOutDataBytes, len);

		if (tail_unsent) {
			/* Are the bytes above us in flight? */
			rptr = xmit_tail->b_wptr - tail_unsent;
			if (rptr != xmit_tail->b_rptr) {
				tail_unsent -= len;
				len += tcp_hdr_len;
				tcp->tcp_ipha->ip_len = htons(len);
				mp = dupb(xmit_tail);
				if (!mp)
					break;
				mp->b_rptr = rptr;
				goto must_alloc;
			}
		} else {
			xmit_tail = xmit_tail->b_cont;
			assert((uintptr_t)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr) <= (uintptr_t)INT_MAX);
			tail_unsent = (int)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr);
		}

		tail_unsent -= len;
		tcp->tcp_last_sent_len = (ushort_t)len;

		len += tcp_hdr_len;
		if (tcp->tcp_ipversion == IPV4_VERSION)
			tcp->tcp_ipha->ip_len = htons(len);

		xmit_tail->b_prev = local_time;

		mp = dupb(xmit_tail);
		if (mp == NULL)
			goto out_of_mem;

		len = tcp_hdr_len;
		/*
		 * There are four reasons to allocate a new hdr mblk:
		 *  1) The bytes above us are in use by another packet
		 *  2) We don't have good alignment
		 *  3) The mblk is being shared
		 *  4) We don't have enough room for a header
		 */
		rptr = mp->b_rptr - len;
		if (!OK_32PTR(rptr) ||
		    rptr < mp->b_datap) {
			/* NOTE: we assume allocb returns an OK_32PTR */

		must_alloc:;
			mp1 = allocb(tcp->tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH +
			    tcp_wroff_xtra, 0);
			if (mp1 == NULL) {
				freemsg(mp);
				goto out_of_mem;
			}
			mp1->b_cont = mp;
			mp = mp1;
			/* Leave room for Link Level header */
			len = tcp_hdr_len;
			rptr = &mp->b_rptr[tcp_wroff_xtra];
			mp->b_wptr = &rptr[len];
		}

		if (tcp->tcp_snd_ts_ok) {
			/* use uintptr_t to suppress the gcc warning */
			U32_TO_BE32((uint32_t)(uintptr_t)local_time,
				(char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		} else {
			assert(tcp->tcp_tcp_hdr_len == TCP_MIN_HEADER_LENGTH);
		}

		mp->b_rptr = rptr;

		/* Copy the template header. */
		dst = (ipaddr_t *)rptr;
		src = (ipaddr_t *)tcp->tcp_iphc;
		dst[0] = src[0];
		dst[1] = src[1];
		dst[2] = src[2];
		dst[3] = src[3];
		dst[4] = src[4];
		dst[5] = src[5];
		dst[6] = src[6];
		dst[7] = src[7];
		dst[8] = src[8];
		dst[9] = src[9];
		len = tcp->tcp_hdr_len;
		if (len -= 40) {
			len >>= 2;
			dst += 10;
			src += 10;
			do {
				*dst++ = *src++;
			} while (--len);
		}

		/*
		 * Set tcph to point to the header of the outgoing packet,
		 * not to the template header.
		 */
		tcph = (tcph_t *)(rptr + tcp->tcp_ip_hdr_len);

		/*
		 * Set the ECN info in the TCP header if it is not a zero
		 * window probe.  Zero window probe is only sent in
		 * tcp_wput_data() and tcp_timer().
		 */
		if (tcp->tcp_ecn_ok && !tcp->tcp_zero_win_probe) {
			SET_ECT(tcp, rptr);

			if (tcp->tcp_ecn_echo_on)
				tcph->th_flags[0] |= TH_ECE;
			if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
				tcph->th_flags[0] |= TH_CWR;
				tcp->tcp_ecn_cwr_sent = B_TRUE;
			}
		}

		/* Fill in SACK options */
		if (num_sack_blk > 0) {
			uchar_t *wptr = rptr + tcp->tcp_hdr_len;
			sack_blk_t *tmp;
			int32_t	i;

			wptr[0] = TCPOPT_NOP;
			wptr[1] = TCPOPT_NOP;
			wptr[2] = TCPOPT_SACK;
			wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
			    sizeof (sack_blk_t);
			wptr += TCPOPT_REAL_SACK_LEN;

			tmp = tcp->tcp_sack_list;
			for (i = 0; i < num_sack_blk; i++) {
				U32_TO_BE32(tmp[i].begin, wptr);
				wptr += sizeof (tcp_seq);
				U32_TO_BE32(tmp[i].end, wptr);
				wptr += sizeof (tcp_seq);
			}
			tcph->th_offset_and_rsrvd[0] += ((num_sack_blk * 2 + 1)
			    << 4);
		}

		if (tail_unsent) {
			mp1 = mp->b_cont;
			if (mp1 == NULL)
				mp1 = mp;
			/*
			 * If we're a little short, tack on more mblks
			 * as long as we don't need to split an mblk.
			 */
			while (tail_unsent < 0 &&
			    tail_unsent + (int)(xmit_tail->b_cont->b_wptr -
			    xmit_tail->b_cont->b_rptr) <= 0) {
				xmit_tail = xmit_tail->b_cont;
				/* Stash for rtt use later */
				xmit_tail->b_prev = local_time;
				mp1->b_cont = dupb(xmit_tail);
				mp1 = mp1->b_cont;
				assert((uintptr_t)(xmit_tail->b_wptr -
				    xmit_tail->b_rptr) <= (uintptr_t)INT_MAX);
				tail_unsent += (int)(xmit_tail->b_wptr -
				    xmit_tail->b_rptr);
				if (mp1 == NULL) {
					freemsg(mp);
					goto out_of_mem;
				}
			}
			/* Trim back any surplus on the last mblk */
			if (tail_unsent > 0)
				mp1->b_wptr -= tail_unsent;
			if (tail_unsent < 0) {
				uint32_t ip_len;

				/*
				 * We did not send everything we could in
				 * order to preserve mblk boundaries.
				 */
				usable -= tail_unsent;
				snxt += tail_unsent;
				tcp->tcp_last_sent_len += tail_unsent;
				UPDATE_MIB(tcp_mib.tcpOutDataBytes,
				    tail_unsent);
				/* Adjust the IP length field. */
				ip_len = ntohs(((struct ip *)rptr)->ip_len) +
				    tail_unsent;
				((struct ip *)rptr)->ip_len = htons(ip_len);
				tail_unsent = 0;
			}
		}

		if (mp == NULL)
			goto out_of_mem;

		/*
		 * Performance hit!  We need to pullup the whole message
		 * in order to do checksum and for the MAC output routine.
		 */
		if (mp->b_cont != NULL) {
			int mp_size;
#ifdef	DEBUG
			printf("Multiple mblk %d\n", msgdsize(mp));
#endif
			new_mp = allocb(msgdsize(mp) + tcp_wroff_xtra, 0);
			new_mp->b_rptr += tcp_wroff_xtra;
			new_mp->b_wptr = new_mp->b_rptr;
			while (mp != NULL) {
				mp_size = mp->b_wptr - mp->b_rptr;
				bcopy(mp->b_rptr, new_mp->b_wptr, mp_size);
				new_mp->b_wptr += mp_size;
				mp = mp->b_cont;
			}
			freemsg(mp);
			mp = new_mp;
		}
		tcp_set_cksum(mp);
		((struct ip *)mp->b_rptr)->ip_ttl = (uint8_t)tcp_ipv4_ttl;
		TCP_DUMP_PACKET("tcp_wput_data", mp);
		(void) ipv4_tcp_output(sock_id, mp);
		freemsg(mp);
	}
out_of_mem:;
	/* Pretend that all we were trying to send really got sent */
	if (tail_unsent < 0) {
		do {
			xmit_tail = xmit_tail->b_cont;
			xmit_tail->b_prev = local_time;
			assert((uintptr_t)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr) <= (uintptr_t)INT_MAX);
			tail_unsent += (int)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr);
		} while (tail_unsent < 0);
	}
done:;
	tcp->tcp_xmit_tail = xmit_tail;
	tcp->tcp_xmit_tail_unsent = tail_unsent;
	len = tcp->tcp_snxt - snxt;
	if (len) {
		/*
		 * If new data was sent, need to update the notsack
		 * list, which is, afterall, data blocks that have
		 * not been sack'ed by the receiver.  New data is
		 * not sack'ed.
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
			/* len is a negative value. */
			tcp->tcp_pipe -= len;
			tcp_notsack_update(&(tcp->tcp_notsack_list),
			    tcp->tcp_snxt, snxt,
			    &(tcp->tcp_num_notsack_blk),
			    &(tcp->tcp_cnt_notsack_list));
		}
		tcp->tcp_snxt = snxt + tcp->tcp_fin_sent;
		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;
		if ((snxt + len) == tcp->tcp_suna) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}
		/*
		 * Note that len is the amount we just sent but with a negative
		 * sign. We update tcp_unsent here since we may come back to
		 * tcp_wput_data from tcp_state_wait.
		 */
		len += tcp->tcp_unsent;
		tcp->tcp_unsent = len;

		/*
		 * Let's wait till all the segments have been acked, since we
		 * don't have a timer.
		 */
		(void) tcp_state_wait(sock_id, tcp, TCPS_ALL_ACKED);
		return;
	} else if (snxt == tcp->tcp_suna && tcp->tcp_swnd == 0) {
		/*
		 * Didn't send anything. Make sure the timer is running
		 * so that we will probe a zero window.
		 */
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	}

	/* Note that len is the amount we just sent but with a negative sign */
	len += tcp->tcp_unsent;
	tcp->tcp_unsent = len;

}

static void
tcp_time_wait_processing(tcp_t *tcp, mblk_t *mp,
    uint32_t seg_seq, uint32_t seg_ack, int seg_len, tcph_t *tcph,
    int sock_id)
{
	int32_t		bytes_acked;
	int32_t		gap;
	int32_t		rgap;
	tcp_opt_t	tcpopt;
	uint_t		flags;
	uint32_t	new_swnd = 0;

#ifdef DEBUG
	printf("Time wait processing called ###############3\n");
#endif

	/* Just make sure we send the right sock_id to tcp_clean_death */
	if ((sockets[sock_id].pcb == NULL) || (sockets[sock_id].pcb != tcp))
		sock_id = -1;

	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
	new_swnd = BE16_TO_U16(tcph->th_win) <<
	    ((tcph->th_flags[0] & TH_SYN) ? 0 : tcp->tcp_snd_ws);
	if (tcp->tcp_snd_ts_ok) {
		if (!tcp_paws_check(tcp, tcph, &tcpopt)) {
			freemsg(mp);
			tcp_xmit_ctl(NULL, tcp, NULL, tcp->tcp_snxt,
			    tcp->tcp_rnxt, TH_ACK, 0, -1);
			return;
		}
	}
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	if (gap < 0) {
		BUMP_MIB(tcp_mib.tcpInDataDupSegs);
		UPDATE_MIB(tcp_mib.tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		seg_len += gap;
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}
			if ((flags & TH_FIN) && seg_len == -1) {
				/*
				 * When TCP receives a duplicate FIN in
				 * TIME_WAIT state, restart the 2 MSL timer.
				 * See page 73 in RFC 793. Make sure this TCP
				 * is already on the TIME_WAIT list. If not,
				 * just restart the timer.
				 */
				tcp_time_wait_remove(tcp);
				tcp_time_wait_append(tcp);
				TCP_TIMER_RESTART(tcp, tcp_time_wait_interval);
				tcp_xmit_ctl(NULL, tcp, NULL, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_ACK, 0, -1);
				freemsg(mp);
				return;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
	}

	if ((flags & TH_SYN) && gap > 0 && rgap < 0) {
		/*
		 * Make sure that when we accept the connection, pick
		 * an ISS greater than (tcp_snxt + ISS_INCR/2) for the
		 * old connection.
		 *
		 * The next ISS generated is equal to tcp_iss_incr_extra
		 * + ISS_INCR/2 + other components depending on the
		 * value of tcp_strong_iss.  We pre-calculate the new
		 * ISS here and compare with tcp_snxt to determine if
		 * we need to make adjustment to tcp_iss_incr_extra.
		 *
		 * Note that since we are now in the global queue
		 * perimeter and need to do a lateral_put() to the
		 * listener queue, there can be other connection requests/
		 * attempts while the lateral_put() is going on.  That
		 * means what we calculate here may not be correct.  This
		 * is extremely difficult to solve unless TCP and IP
		 * modules are merged and there is no perimeter, but just
		 * locks.  The above calculation is ugly and is a
		 * waste of CPU cycles...
		 */
		uint32_t new_iss = tcp_iss_incr_extra;
		int32_t adj;

		/* Add time component and min random (i.e. 1). */
		new_iss += (prom_gettime() >> ISS_NSEC_SHT) + 1;
		if ((adj = (int32_t)(tcp->tcp_snxt - new_iss)) > 0) {
			/*
			 * New ISS not guaranteed to be ISS_INCR/2
			 * ahead of the current tcp_snxt, so add the
			 * difference to tcp_iss_incr_extra.
			 */
			tcp_iss_incr_extra += adj;
		}
		tcp_clean_death(sock_id, tcp, 0);

		/*
		 * This is a passive open.  Right now we do not
		 * do anything...
		 */
		freemsg(mp);
		return;
	}

	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		BUMP_MIB(tcp_mib.tcpInDataPastWinSegs);
		UPDATE_MIB(tcp_mib.tcpInDataPastWinBytes, -rgap);
		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}
	}
	/*
	 * Check whether we can update tcp_ts_recent.  This test is
	 * NOT the one in RFC 1323 3.4.  It is from Braden, 1993, "TCP
	 * Extensions for High Performance: An Update", Internet Draft.
	 */
	if (tcp->tcp_snd_ts_ok &&
	    TSTMP_GEQ(tcpopt.tcp_opt_ts_val, tcp->tcp_ts_recent) &&
	    SEQ_LEQ(seg_seq, tcp->tcp_rack)) {
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = prom_gettime();
	}

	if (seg_seq != tcp->tcp_rnxt && seg_len > 0) {
		/* Always ack out of order packets */
		flags |= TH_ACK_NEEDED;
		seg_len = 0;
	} else if (seg_len > 0) {
		BUMP_MIB(tcp_mib.tcpInDataInorderSegs);
		UPDATE_MIB(tcp_mib.tcpInDataInorderBytes, seg_len);
	}
	if (flags & TH_RST) {
		freemsg(mp);
		(void) tcp_clean_death(sock_id, tcp, 0);
		return;
	}
	if (flags & TH_SYN) {
		freemsg(mp);
		tcp_xmit_ctl("TH_SYN", tcp, NULL, seg_ack, seg_seq + 1,
		    TH_RST|TH_ACK, 0, -1);
		/*
		 * Do not delete the TCP structure if it is in
		 * TIME_WAIT state.  Refer to RFC 1122, 4.2.2.13.
		 */
		return;
	}
process_ack:
	if (flags & TH_ACK) {
		bytes_acked = (int)(seg_ack - tcp->tcp_suna);
		if (bytes_acked <= 0) {
			if (bytes_acked == 0 && seg_len == 0 &&
			    new_swnd == tcp->tcp_swnd)
				BUMP_MIB(tcp_mib.tcpInDupAck);
		} else {
			/* Acks something not sent */
			flags |= TH_ACK_NEEDED;
		}
	}
	freemsg(mp);
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		tcp_xmit_ctl(NULL, tcp, NULL, tcp->tcp_snxt,
		    tcp->tcp_rnxt, TH_ACK, 0, -1);
	}
}

static int
tcp_init_values(tcp_t *tcp, struct inetboot_socket *isp)
{
	int	err;

	tcp->tcp_family = AF_INET;
	tcp->tcp_ipversion = IPV4_VERSION;

	/*
	 * Initialize tcp_rtt_sa and tcp_rtt_sd so that the calculated RTO
	 * will be close to tcp_rexmit_interval_initial.  By doing this, we
	 * allow the algorithm to adjust slowly to large fluctuations of RTT
	 * during first few transmissions of a connection as seen in slow
	 * links.
	 */
	tcp->tcp_rtt_sa = tcp_rexmit_interval_initial << 2;
	tcp->tcp_rtt_sd = tcp_rexmit_interval_initial >> 1;
	tcp->tcp_rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcp_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5) +
	    tcp_conn_grace_period;
	if (tcp->tcp_rto < tcp_rexmit_interval_min)
		tcp->tcp_rto = tcp_rexmit_interval_min;
	tcp->tcp_timer_backoff = 0;
	tcp->tcp_ms_we_have_waited = 0;
	tcp->tcp_last_recv_time = prom_gettime();
	tcp->tcp_cwnd_max = tcp_cwnd_max_;
	tcp->tcp_snd_burst = TCP_CWND_INFINITE;
	tcp->tcp_cwnd_ssthresh = TCP_MAX_LARGEWIN;
	/* For Ethernet, the mtu returned is actually 1550... */
	if (mac_get_type() == IFT_ETHER) {
		tcp->tcp_if_mtu = mac_get_mtu() - 50;
	} else {
		tcp->tcp_if_mtu = mac_get_mtu();
	}
	tcp->tcp_mss = tcp->tcp_if_mtu;

	tcp->tcp_first_timer_threshold = tcp_ip_notify_interval;
	tcp->tcp_first_ctimer_threshold = tcp_ip_notify_cinterval;
	tcp->tcp_second_timer_threshold = tcp_ip_abort_interval;
	/*
	 * Fix it to tcp_ip_abort_linterval later if it turns out to be a
	 * passive open.
	 */
	tcp->tcp_second_ctimer_threshold = tcp_ip_abort_cinterval;

	tcp->tcp_naglim = tcp_naglim_def;

	/* NOTE:  ISS is now set in tcp_adapt_ire(). */

	/* Initialize the header template */
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		err = tcp_header_init_ipv4(tcp);
	}
	if (err)
		return (err);

	/*
	 * Init the window scale to the max so tcp_rwnd_set() won't pare
	 * down tcp_rwnd. tcp_adapt_ire() will set the right value later.
	 */
	tcp->tcp_rcv_ws = TCP_MAX_WINSHIFT;
	tcp->tcp_xmit_lowater = tcp_xmit_lowat;
	if (isp != NULL) {
		tcp->tcp_xmit_hiwater = isp->so_sndbuf;
		tcp->tcp_rwnd = isp->so_rcvbuf;
		tcp->tcp_rwnd_max = isp->so_rcvbuf;
	}
	tcp->tcp_state = TCPS_IDLE;
	return (0);
}

/*
 * Initialize the IPv4 header. Loses any record of any IP options.
 */
static int
tcp_header_init_ipv4(tcp_t *tcp)
{
	tcph_t		*tcph;

	/*
	 * This is a simple initialization. If there's
	 * already a template, it should never be too small,
	 * so reuse it.  Otherwise, allocate space for the new one.
	 */
	if (tcp->tcp_iphc != NULL) {
		assert(tcp->tcp_iphc_len >= TCP_MAX_COMBINED_HEADER_LENGTH);
		bzero(tcp->tcp_iphc, tcp->tcp_iphc_len);
	} else {
		tcp->tcp_iphc_len = TCP_MAX_COMBINED_HEADER_LENGTH;
		tcp->tcp_iphc = bkmem_zalloc(tcp->tcp_iphc_len);
		if (tcp->tcp_iphc == NULL) {
			tcp->tcp_iphc_len = 0;
			return (ENOMEM);
		}
	}
	tcp->tcp_ipha = (struct ip *)tcp->tcp_iphc;
	tcp->tcp_ipversion = IPV4_VERSION;

	/*
	 * Note that it does not include TCP options yet.  It will
	 * after the connection is established.
	 */
	tcp->tcp_hdr_len = sizeof (struct ip) + sizeof (tcph_t);
	tcp->tcp_tcp_hdr_len = sizeof (tcph_t);
	tcp->tcp_ip_hdr_len = sizeof (struct ip);
	tcp->tcp_ipha->ip_v = IP_VERSION;
	/* We don't support IP options... */
	tcp->tcp_ipha->ip_hl = IP_SIMPLE_HDR_LENGTH_IN_WORDS;
	tcp->tcp_ipha->ip_p = IPPROTO_TCP;
	/* We are not supposed to do PMTU discovery... */
	tcp->tcp_ipha->ip_sum = 0;

	tcph = (tcph_t *)(tcp->tcp_iphc + sizeof (struct ip));
	tcp->tcp_tcph = tcph;
	tcph->th_offset_and_rsrvd[0] = (5 << 4);
	return (0);
}

/*
 * Send out a control packet on the tcp connection specified.  This routine
 * is typically called where we need a simple ACK or RST generated.
 *
 * This function is called with or without a mp.
 */
static void
tcp_xmit_ctl(char *str, tcp_t *tcp, mblk_t *mp, uint32_t seq,
    uint32_t ack, int ctl, uint_t ip_hdr_len, int sock_id)
{
	uchar_t		*rptr;
	tcph_t		*tcph;
	struct ip	*iph = NULL;
	int		tcp_hdr_len;
	int		tcp_ip_hdr_len;

	tcp_hdr_len = tcp->tcp_hdr_len;
	tcp_ip_hdr_len = tcp->tcp_ip_hdr_len;

	if (mp) {
		assert(ip_hdr_len != 0);
		rptr = mp->b_rptr;
		tcph = (tcph_t *)(rptr + ip_hdr_len);
		/* Don't reply to a RST segment. */
		if (tcph->th_flags[0] & TH_RST) {
			freeb(mp);
			return;
		}
		freemsg(mp);
		rptr = NULL;
	} else {
		assert(ip_hdr_len == 0);
	}
	/* If a text string is passed in with the request, print it out. */
	if (str != NULL) {
		dprintf("tcp_xmit_ctl(%d): '%s', seq 0x%x, ack 0x%x, "
		    "ctl 0x%x\n", sock_id, str, seq, ack, ctl);
	}
	mp = allocb(tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH + tcp_wroff_xtra, 0);
	if (mp == NULL) {
		dprintf("tcp_xmit_ctl(%d): Cannot allocate memory\n", sock_id);
		return;
	}
	rptr = &mp->b_rptr[tcp_wroff_xtra];
	mp->b_rptr = rptr;
	mp->b_wptr = &rptr[tcp_hdr_len];
	bcopy(tcp->tcp_iphc, rptr, tcp_hdr_len);

	iph = (struct ip *)rptr;
	iph->ip_len = htons(tcp_hdr_len);

	tcph = (tcph_t *)&rptr[tcp_ip_hdr_len];
	tcph->th_flags[0] = (uint8_t)ctl;
	if (ctl & TH_RST) {
		BUMP_MIB(tcp_mib.tcpOutRsts);
		BUMP_MIB(tcp_mib.tcpOutControl);
		/*
		 * Don't send TSopt w/ TH_RST packets per RFC 1323.
		 */
		if (tcp->tcp_snd_ts_ok && tcp->tcp_state > TCPS_SYN_SENT) {
			mp->b_wptr = &rptr[tcp_hdr_len - TCPOPT_REAL_TS_LEN];
			*(mp->b_wptr) = TCPOPT_EOL;
			iph->ip_len = htons(tcp_hdr_len -
			    TCPOPT_REAL_TS_LEN);
			tcph->th_offset_and_rsrvd[0] -= (3 << 4);
		}
	}
	if (ctl & TH_ACK) {
		uint32_t now = prom_gettime();

		if (tcp->tcp_snd_ts_ok) {
			U32_TO_BE32(now,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}
		tcp->tcp_rack = ack;
		tcp->tcp_rack_cnt = 0;
		BUMP_MIB(tcp_mib.tcpOutAck);
	}
	BUMP_MIB(tcp_mib.tcpOutSegs);
	U32_TO_BE32(seq, tcph->th_seq);
	U32_TO_BE32(ack, tcph->th_ack);

	tcp_set_cksum(mp);
	iph->ip_ttl = (uint8_t)tcp_ipv4_ttl;
	TCP_DUMP_PACKET("tcp_xmit_ctl", mp);
	(void) ipv4_tcp_output(sock_id, mp);
	freeb(mp);
}

/* Generate an ACK-only (no data) segment for a TCP endpoint */
static mblk_t *
tcp_ack_mp(tcp_t *tcp)
{
	if (tcp->tcp_valid_bits) {
		/*
		 * For the complex case where we have to send some
		 * controls (FIN or SYN), let tcp_xmit_mp do it.
		 * When sending an ACK-only segment (no data)
		 * into a zero window, always set the seq number to
		 * suna, since snxt will be extended past the window.
		 * If we used snxt, the receiver might consider the ACK
		 * unacceptable.
		 */
		return (tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
		    (tcp->tcp_zero_win_probe) ?
		    tcp->tcp_suna :
		    tcp->tcp_snxt, B_FALSE, NULL, B_FALSE));
	} else {
		/* Generate a simple ACK */
		uchar_t	*rptr;
		tcph_t	*tcph;
		mblk_t	*mp1;
		int32_t	tcp_hdr_len;
		int32_t	num_sack_blk = 0;
		int32_t sack_opt_len;

		/*
		 * Allocate space for TCP + IP headers
		 * and link-level header
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
			num_sack_blk = MIN(tcp->tcp_max_sack_blk,
			    tcp->tcp_num_sack_blk);
			sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
			    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
			tcp_hdr_len = tcp->tcp_hdr_len + sack_opt_len;
		} else {
			tcp_hdr_len = tcp->tcp_hdr_len;
		}
		mp1 = allocb(tcp_hdr_len + tcp_wroff_xtra, 0);
		if (mp1 == NULL)
			return (NULL);

		/* copy in prototype TCP + IP header */
		rptr = mp1->b_rptr + tcp_wroff_xtra;
		mp1->b_rptr = rptr;
		mp1->b_wptr = rptr + tcp_hdr_len;
		bcopy(tcp->tcp_iphc, rptr, tcp->tcp_hdr_len);

		tcph = (tcph_t *)&rptr[tcp->tcp_ip_hdr_len];

		/*
		 * Set the TCP sequence number.
		 * When sending an ACK-only segment (no data)
		 * into a zero window, always set the seq number to
		 * suna, since snxt will be extended past the window.
		 * If we used snxt, the receiver might consider the ACK
		 * unacceptable.
		 */
		U32_TO_ABE32((tcp->tcp_zero_win_probe) ?
		    tcp->tcp_suna : tcp->tcp_snxt, tcph->th_seq);

		/* Set up the TCP flag field. */
		tcph->th_flags[0] = (uchar_t)TH_ACK;
		if (tcp->tcp_ecn_echo_on)
			tcph->th_flags[0] |= TH_ECE;

		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;

		/* fill in timestamp option if in use */
		if (tcp->tcp_snd_ts_ok) {
			uint32_t llbolt = (uint32_t)prom_gettime();

			U32_TO_BE32(llbolt,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}

		/* Fill in SACK options */
		if (num_sack_blk > 0) {
			uchar_t *wptr = (uchar_t *)tcph + tcp->tcp_tcp_hdr_len;
			sack_blk_t *tmp;
			int32_t	i;

			wptr[0] = TCPOPT_NOP;
			wptr[1] = TCPOPT_NOP;
			wptr[2] = TCPOPT_SACK;
			wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
			    sizeof (sack_blk_t);
			wptr += TCPOPT_REAL_SACK_LEN;

			tmp = tcp->tcp_sack_list;
			for (i = 0; i < num_sack_blk; i++) {
				U32_TO_BE32(tmp[i].begin, wptr);
				wptr += sizeof (tcp_seq);
				U32_TO_BE32(tmp[i].end, wptr);
				wptr += sizeof (tcp_seq);
			}
			tcph->th_offset_and_rsrvd[0] += ((num_sack_blk * 2 + 1)
			    << 4);
		}

		((struct ip *)rptr)->ip_len = htons(tcp_hdr_len);
		tcp_set_cksum(mp1);
		((struct ip *)rptr)->ip_ttl = (uint8_t)tcp_ipv4_ttl;
		return (mp1);
	}
}

/*
 * tcp_xmit_mp is called to return a pointer to an mblk chain complete with
 * ip and tcp header ready to pass down to IP.  If the mp passed in is
 * non-NULL, then up to max_to_send bytes of data will be dup'ed off that
 * mblk. (If sendall is not set the dup'ing will stop at an mblk boundary
 * otherwise it will dup partial mblks.)
 * Otherwise, an appropriate ACK packet will be generated.  This
 * routine is not usually called to send new data for the first time.  It
 * is mostly called out of the timer for retransmits, and to generate ACKs.
 *
 * If offset is not NULL, the returned mblk chain's first mblk's b_rptr will
 * be adjusted by *offset.  And after dupb(), the offset and the ending mblk
 * of the original mblk chain will be returned in *offset and *end_mp.
 */
static mblk_t *
tcp_xmit_mp(tcp_t *tcp, mblk_t *mp, int32_t max_to_send, int32_t *offset,
    mblk_t **end_mp, uint32_t seq, boolean_t sendall, uint32_t *seg_len,
    boolean_t rexmit)
{
	int	data_length;
	int32_t	off = 0;
	uint_t	flags;
	mblk_t	*mp1;
	mblk_t	*mp2;
	mblk_t	*new_mp;
	uchar_t	*rptr;
	tcph_t	*tcph;
	int32_t	num_sack_blk = 0;
	int32_t	sack_opt_len = 0;

	/* Allocate for our maximum TCP header + link-level */
	mp1 = allocb(tcp->tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH +
	    tcp_wroff_xtra, 0);
	if (mp1 == NULL)
		return (NULL);
	data_length = 0;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
		    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
		if (max_to_send + sack_opt_len > tcp->tcp_mss)
			max_to_send -= sack_opt_len;
	}

	if (offset != NULL) {
		off = *offset;
		/* We use offset as an indicator that end_mp is not NULL. */
		*end_mp = NULL;
	}
	for (mp2 = mp1; mp && data_length != max_to_send; mp = mp->b_cont) {
		/* This could be faster with cooperation from downstream */
		if (mp2 != mp1 && !sendall &&
		    data_length + (int)(mp->b_wptr - mp->b_rptr) >
		    max_to_send)
			/*
			 * Don't send the next mblk since the whole mblk
			 * does not fit.
			 */
			break;
		mp2->b_cont = dupb(mp);
		mp2 = mp2->b_cont;
		if (mp2 == NULL) {
			freemsg(mp1);
			return (NULL);
		}
		mp2->b_rptr += off;
		assert((uintptr_t)(mp2->b_wptr - mp2->b_rptr) <=
		    (uintptr_t)INT_MAX);

		data_length += (int)(mp2->b_wptr - mp2->b_rptr);
		if (data_length > max_to_send) {
			mp2->b_wptr -= data_length - max_to_send;
			data_length = max_to_send;
			off = mp2->b_wptr - mp->b_rptr;
			break;
		} else {
			off = 0;
		}
	}
	if (offset != NULL) {
		*offset = off;
		*end_mp = mp;
	}
	if (seg_len != NULL) {
		*seg_len = data_length;
	}

	rptr = mp1->b_rptr + tcp_wroff_xtra;
	mp1->b_rptr = rptr;
	mp1->b_wptr = rptr + tcp->tcp_hdr_len + sack_opt_len;
	bcopy(tcp->tcp_iphc, rptr, tcp->tcp_hdr_len);
	tcph = (tcph_t *)&rptr[tcp->tcp_ip_hdr_len];
	U32_TO_ABE32(seq, tcph->th_seq);

	/*
	 * Use tcp_unsent to determine if the PUSH bit should be used assumes
	 * that this function was called from tcp_wput_data. Thus, when called
	 * to retransmit data the setting of the PUSH bit may appear some
	 * what random in that it might get set when it should not. This
	 * should not pose any performance issues.
	 */
	if (data_length != 0 && (tcp->tcp_unsent == 0 ||
	    tcp->tcp_unsent == data_length)) {
		flags = TH_ACK | TH_PUSH;
	} else {
		flags = TH_ACK;
	}

	if (tcp->tcp_ecn_ok) {
		if (tcp->tcp_ecn_echo_on)
			flags |= TH_ECE;

		/*
		 * Only set ECT bit and ECN_CWR if a segment contains new data.
		 * There is no TCP flow control for non-data segments, and
		 * only data segment is transmitted reliably.
		 */
		if (data_length > 0 && !rexmit) {
			SET_ECT(tcp, rptr);
			if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
				flags |= TH_CWR;
				tcp->tcp_ecn_cwr_sent = B_TRUE;
			}
		}
	}

	if (tcp->tcp_valid_bits) {
		uint32_t u1;

		if ((tcp->tcp_valid_bits & TCP_ISS_VALID) &&
		    seq == tcp->tcp_iss) {
			uchar_t	*wptr;

			/*
			 * Tack on the MSS option.  It is always needed
			 * for both active and passive open.
			 */
			wptr = mp1->b_wptr;
			wptr[0] = TCPOPT_MAXSEG;
			wptr[1] = TCPOPT_MAXSEG_LEN;
			wptr += 2;
			/*
			 * MSS option value should be interface MTU - MIN
			 * TCP/IP header.
			 */
			u1 = tcp->tcp_if_mtu - IP_SIMPLE_HDR_LENGTH -
			    TCP_MIN_HEADER_LENGTH;
			U16_TO_BE16(u1, wptr);
			mp1->b_wptr = wptr + 2;
			/* Update the offset to cover the additional word */
			tcph->th_offset_and_rsrvd[0] += (1 << 4);

			/*
			 * Note that the following way of filling in
			 * TCP options are not optimal.  Some NOPs can
			 * be saved.  But there is no need at this time
			 * to optimize it.  When it is needed, we will
			 * do it.
			 */
			switch (tcp->tcp_state) {
			case TCPS_SYN_SENT:
				flags = TH_SYN;

				if (tcp->tcp_snd_ws_ok) {
					wptr = mp1->b_wptr;
					wptr[0] =  TCPOPT_NOP;
					wptr[1] =  TCPOPT_WSCALE;
					wptr[2] =  TCPOPT_WS_LEN;
					wptr[3] = (uchar_t)tcp->tcp_rcv_ws;
					mp1->b_wptr += TCPOPT_REAL_WS_LEN;
					tcph->th_offset_and_rsrvd[0] +=
					    (1 << 4);
				}

				if (tcp->tcp_snd_ts_ok) {
					uint32_t llbolt;

					llbolt = prom_gettime();
					wptr = mp1->b_wptr;
					wptr[0] = TCPOPT_NOP;
					wptr[1] = TCPOPT_NOP;
					wptr[2] = TCPOPT_TSTAMP;
					wptr[3] = TCPOPT_TSTAMP_LEN;
					wptr += 4;
					U32_TO_BE32(llbolt, wptr);
					wptr += 4;
					assert(tcp->tcp_ts_recent == 0);
					U32_TO_BE32(0L, wptr);
					mp1->b_wptr += TCPOPT_REAL_TS_LEN;
					tcph->th_offset_and_rsrvd[0] +=
					    (3 << 4);
				}

				if (tcp->tcp_snd_sack_ok) {
					wptr = mp1->b_wptr;
					wptr[0] = TCPOPT_NOP;
					wptr[1] = TCPOPT_NOP;
					wptr[2] = TCPOPT_SACK_PERMITTED;
					wptr[3] = TCPOPT_SACK_OK_LEN;
					mp1->b_wptr += TCPOPT_REAL_SACK_OK_LEN;
					tcph->th_offset_and_rsrvd[0] +=
					    (1 << 4);
				}

				/*
				 * Set up all the bits to tell other side
				 * we are ECN capable.
				 */
				if (tcp->tcp_ecn_ok) {
					flags |= (TH_ECE | TH_CWR);
				}
				break;
			case TCPS_SYN_RCVD:
				flags |= TH_SYN;

				if (tcp->tcp_snd_ws_ok) {
				    wptr = mp1->b_wptr;
				    wptr[0] =  TCPOPT_NOP;
				    wptr[1] =  TCPOPT_WSCALE;
				    wptr[2] =  TCPOPT_WS_LEN;
				    wptr[3] = (uchar_t)tcp->tcp_rcv_ws;
				    mp1->b_wptr += TCPOPT_REAL_WS_LEN;
				    tcph->th_offset_and_rsrvd[0] += (1 << 4);
				}

				if (tcp->tcp_snd_sack_ok) {
					wptr = mp1->b_wptr;
					wptr[0] = TCPOPT_NOP;
					wptr[1] = TCPOPT_NOP;
					wptr[2] = TCPOPT_SACK_PERMITTED;
					wptr[3] = TCPOPT_SACK_OK_LEN;
					mp1->b_wptr += TCPOPT_REAL_SACK_OK_LEN;
					tcph->th_offset_and_rsrvd[0] +=
					    (1 << 4);
				}

				/*
				 * If the other side is ECN capable, reply
				 * that we are also ECN capable.
				 */
				if (tcp->tcp_ecn_ok) {
					flags |= TH_ECE;
				}
				break;
			default:
				break;
			}
			/* allocb() of adequate mblk assures space */
			assert((uintptr_t)(mp1->b_wptr -
			    mp1->b_rptr) <= (uintptr_t)INT_MAX);
			if (flags & TH_SYN)
				BUMP_MIB(tcp_mib.tcpOutControl);
		}
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    (seq + data_length) == tcp->tcp_fss) {
			if (!tcp->tcp_fin_acked) {
				flags |= TH_FIN;
				BUMP_MIB(tcp_mib.tcpOutControl);
			}
			if (!tcp->tcp_fin_sent) {
				tcp->tcp_fin_sent = B_TRUE;
				switch (tcp->tcp_state) {
				case TCPS_SYN_RCVD:
				case TCPS_ESTABLISHED:
					tcp->tcp_state = TCPS_FIN_WAIT_1;
					break;
				case TCPS_CLOSE_WAIT:
					tcp->tcp_state = TCPS_LAST_ACK;
					break;
				}
				if (tcp->tcp_suna == tcp->tcp_snxt)
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				tcp->tcp_snxt = tcp->tcp_fss + 1;
			}
		}
	}
	tcph->th_flags[0] = (uchar_t)flags;
	tcp->tcp_rack = tcp->tcp_rnxt;
	tcp->tcp_rack_cnt = 0;

	if (tcp->tcp_snd_ts_ok) {
		if (tcp->tcp_state != TCPS_SYN_SENT) {
			uint32_t llbolt = prom_gettime();

			U32_TO_BE32(llbolt,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}
	}

	if (num_sack_blk > 0) {
		uchar_t *wptr = (uchar_t *)tcph + tcp->tcp_tcp_hdr_len;
		sack_blk_t *tmp;
		int32_t	i;

		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK;
		wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
		    sizeof (sack_blk_t);
		wptr += TCPOPT_REAL_SACK_LEN;

		tmp = tcp->tcp_sack_list;
		for (i = 0; i < num_sack_blk; i++) {
			U32_TO_BE32(tmp[i].begin, wptr);
			wptr += sizeof (tcp_seq);
			U32_TO_BE32(tmp[i].end, wptr);
			wptr += sizeof (tcp_seq);
		}
		tcph->th_offset_and_rsrvd[0] += ((num_sack_blk * 2 + 1) << 4);
	}
	assert((uintptr_t)(mp1->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	data_length += (int)(mp1->b_wptr - rptr);
	if (tcp->tcp_ipversion == IPV4_VERSION)
		((struct ip *)rptr)->ip_len = htons(data_length);

	/*
	 * Performance hit!  We need to pullup the whole message
	 * in order to do checksum and for the MAC output routine.
	 */
	if (mp1->b_cont != NULL) {
		int mp_size;
#ifdef DEBUG
		printf("Multiple mblk %d\n", msgdsize(mp1));
#endif
		mp2 = mp1;
		new_mp = allocb(msgdsize(mp1) + tcp_wroff_xtra, 0);
		new_mp->b_rptr += tcp_wroff_xtra;
		new_mp->b_wptr = new_mp->b_rptr;
		while (mp1 != NULL) {
			mp_size = mp1->b_wptr - mp1->b_rptr;
			bcopy(mp1->b_rptr, new_mp->b_wptr, mp_size);
			new_mp->b_wptr += mp_size;
			mp1 = mp1->b_cont;
		}
		freemsg(mp2);
		mp1 = new_mp;
	}
	tcp_set_cksum(mp1);
	/* Fill in the TTL field as it is 0 in the header template. */
	((struct ip *)mp1->b_rptr)->ip_ttl = (uint8_t)tcp_ipv4_ttl;

	return (mp1);
}

/*
 * Generate a "no listener here" reset in response to the
 * connection request contained within 'mp'
 */
static void
tcp_xmit_listeners_reset(int sock_id, mblk_t *mp, uint_t ip_hdr_len)
{
	uchar_t		*rptr;
	uint32_t	seg_len;
	tcph_t		*tcph;
	uint32_t	seg_seq;
	uint32_t	seg_ack;
	uint_t		flags;

	rptr = mp->b_rptr;

	tcph = (tcph_t *)&rptr[ip_hdr_len];
	seg_seq = BE32_TO_U32(tcph->th_seq);
	seg_ack = BE32_TO_U32(tcph->th_ack);
	flags = tcph->th_flags[0];

	seg_len = msgdsize(mp) - (TCP_HDR_LENGTH(tcph) + ip_hdr_len);
	if (flags & TH_RST) {
		freeb(mp);
	} else if (flags & TH_ACK) {
		tcp_xmit_early_reset("no tcp, reset",
		    sock_id, mp, seg_ack, 0, TH_RST, ip_hdr_len);
	} else {
		if (flags & TH_SYN)
			seg_len++;
		tcp_xmit_early_reset("no tcp, reset/ack", sock_id,
		    mp, 0, seg_seq + seg_len,
		    TH_RST | TH_ACK, ip_hdr_len);
	}
}

/* Non overlapping byte exchanger */
static void
tcp_xchg(uchar_t *a, uchar_t *b, int len)
{
	uchar_t	uch;

	while (len-- > 0) {
		uch = a[len];
		a[len] = b[len];
		b[len] = uch;
	}
}

/*
 * Generate a reset based on an inbound packet for which there is no active
 * tcp state that we can find.
 */
static void
tcp_xmit_early_reset(char *str, int sock_id, mblk_t *mp, uint32_t seq,
    uint32_t ack, int ctl, uint_t ip_hdr_len)
{
	struct ip	*iph = NULL;
	ushort_t	len;
	tcph_t		*tcph;
	int		i;
	ipaddr_t	addr;
	mblk_t		*new_mp;

	if (str != NULL) {
		dprintf("tcp_xmit_early_reset: '%s', seq 0x%x, ack 0x%x, "
		    "flags 0x%x\n", str, seq, ack, ctl);
	}

	/*
	 * We skip reversing source route here.
	 * (for now we replace all IP options with EOL)
	 */
	iph = (struct ip *)mp->b_rptr;
	for (i = IP_SIMPLE_HDR_LENGTH; i < (int)ip_hdr_len; i++)
		mp->b_rptr[i] = IPOPT_EOL;
	/*
	 * Make sure that src address is not a limited broadcast
	 * address. Not all broadcast address checking for the
	 * src address is possible, since we don't know the
	 * netmask of the src addr.
	 * No check for destination address is done, since
	 * IP will not pass up a packet with a broadcast dest address
	 * to TCP.
	 */
	if (iph->ip_src.s_addr == INADDR_ANY ||
	    iph->ip_src.s_addr == INADDR_BROADCAST) {
		freemsg(mp);
		return;
	}

	tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	if (tcph->th_flags[0] & TH_RST) {
		freemsg(mp);
		return;
	}
	/*
	 * Now copy the original header to a new buffer.  The reason
	 * for doing this is that we need to put extra room before
	 * the header for the MAC layer address.  The original mblk
	 * does not have this extra head room.
	 */
	len = ip_hdr_len + sizeof (tcph_t);
	if ((new_mp = allocb(len + tcp_wroff_xtra, 0)) == NULL) {
		freemsg(mp);
		return;
	}
	new_mp->b_rptr += tcp_wroff_xtra;
	bcopy(mp->b_rptr, new_mp->b_rptr, len);
	new_mp->b_wptr = new_mp->b_rptr + len;
	freemsg(mp);
	mp = new_mp;
	iph = (struct ip *)mp->b_rptr;
	tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];

	tcph->th_offset_and_rsrvd[0] = (5 << 4);
	tcp_xchg(tcph->th_fport, tcph->th_lport, 2);
	U32_TO_BE32(ack, tcph->th_ack);
	U32_TO_BE32(seq, tcph->th_seq);
	U16_TO_BE16(0, tcph->th_win);
	bzero(tcph->th_sum, sizeof (int16_t));
	tcph->th_flags[0] = (uint8_t)ctl;
	if (ctl & TH_RST) {
		BUMP_MIB(tcp_mib.tcpOutRsts);
		BUMP_MIB(tcp_mib.tcpOutControl);
	}

	iph->ip_len = htons(len);
	/* Swap addresses */
	addr = iph->ip_src.s_addr;
	iph->ip_src = iph->ip_dst;
	iph->ip_dst.s_addr = addr;
	iph->ip_id = 0;
	iph->ip_ttl = 0;
	tcp_set_cksum(mp);
	iph->ip_ttl = (uint8_t)tcp_ipv4_ttl;

	/* Dump the packet when debugging. */
	TCP_DUMP_PACKET("tcp_xmit_early_reset", mp);
	(void) ipv4_tcp_output(sock_id, mp);
	freemsg(mp);
}

static void
tcp_set_cksum(mblk_t *mp)
{
	struct ip *iph;
	tcpha_t *tcph;
	int len;

	iph = (struct ip *)mp->b_rptr;
	tcph = (tcpha_t *)(iph + 1);
	len = ntohs(iph->ip_len);
	/*
	 * Calculate the TCP checksum.  Need to include the psuedo header,
	 * which is similar to the real IP header starting at the TTL field.
	 */
	iph->ip_sum = htons(len - IP_SIMPLE_HDR_LENGTH);
	tcph->tha_sum = 0;
	tcph->tha_sum = tcp_cksum((uint16_t *)&(iph->ip_ttl),
	    len - IP_SIMPLE_HDR_LENGTH + 12);
	iph->ip_sum = 0;
}

static uint16_t
tcp_cksum(uint16_t *buf, uint32_t len)
{
	/*
	 * Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */
	int32_t sum = 0;

	while (len > 1) {
		/*  This is the inner loop */
		sum += *buf++;
		len -= 2;
	}

	/*  Add left-over byte, if any */
	if (len > 0)
		sum += *(unsigned char *)buf * 256;

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ((uint16_t)~sum);
}

/*
 * Type three generator adapted from the random() function in 4.4 BSD:
 */

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Type 3 -- x**31 + x**3 + 1 */
#define	DEG_3		31
#define	SEP_3		3


/* Protected by tcp_random_lock */
static int tcp_randtbl[DEG_3 + 1];

static int *tcp_random_fptr = &tcp_randtbl[SEP_3 + 1];
static int *tcp_random_rptr = &tcp_randtbl[1];

static int *tcp_random_state = &tcp_randtbl[1];
static int *tcp_random_end_ptr = &tcp_randtbl[DEG_3 + 1];

static void
tcp_random_init(void)
{
	int i;
	uint32_t hrt;
	uint32_t wallclock;
	uint32_t result;

	/*
	 *
	 * XXX We don't have high resolution time in standalone...  The
	 * following is just some approximation on the comment below.
	 *
	 * Use high-res timer and current time for seed.  Gethrtime() returns
	 * a longlong, which may contain resolution down to nanoseconds.
	 * The current time will either be a 32-bit or a 64-bit quantity.
	 * XOR the two together in a 64-bit result variable.
	 * Convert the result to a 32-bit value by multiplying the high-order
	 * 32-bits by the low-order 32-bits.
	 *
	 * XXX We don't have gethrtime() in prom and the wallclock....
	 */

	hrt = prom_gettime();
	wallclock = (uint32_t)time(NULL);
	result = wallclock ^ hrt;
	tcp_random_state[0] = result;

	for (i = 1; i < DEG_3; i++)
		tcp_random_state[i] = 1103515245 * tcp_random_state[i - 1]
			+ 12345;
	tcp_random_fptr = &tcp_random_state[SEP_3];
	tcp_random_rptr = &tcp_random_state[0];
	for (i = 0; i < 10 * DEG_3; i++)
		(void) tcp_random();
}

/*
 * tcp_random: Return a random number in the range [1 - (128K + 1)].
 * This range is selected to be approximately centered on TCP_ISS / 2,
 * and easy to compute. We get this value by generating a 32-bit random
 * number, selecting out the high-order 17 bits, and then adding one so
 * that we never return zero.
 */
static int
tcp_random(void)
{
	int i;

	*tcp_random_fptr += *tcp_random_rptr;

	/*
	 * The high-order bits are more random than the low-order bits,
	 * so we select out the high-order 17 bits and add one so that
	 * we never return zero.
	 */
	i = ((*tcp_random_fptr >> 15) & 0x1ffff) + 1;
	if (++tcp_random_fptr >= tcp_random_end_ptr) {
		tcp_random_fptr = tcp_random_state;
		++tcp_random_rptr;
	} else if (++tcp_random_rptr >= tcp_random_end_ptr)
		tcp_random_rptr = tcp_random_state;

	return (i);
}

/*
 * Generate ISS, taking into account NDD changes may happen halfway through.
 * (If the iss is not zero, set it.)
 */
static void
tcp_iss_init(tcp_t *tcp)
{
	tcp_iss_incr_extra += (ISS_INCR >> 1);
	tcp->tcp_iss = tcp_iss_incr_extra;
	tcp->tcp_iss += (prom_gettime() >> ISS_NSEC_SHT) + tcp_random();
	tcp->tcp_valid_bits = TCP_ISS_VALID;
	tcp->tcp_fss = tcp->tcp_iss - 1;
	tcp->tcp_suna = tcp->tcp_iss;
	tcp->tcp_snxt = tcp->tcp_iss + 1;
	tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
	tcp->tcp_csuna = tcp->tcp_snxt;
}

/*
 * Diagnostic routine used to return a string associated with the tcp state.
 * Note that if the caller does not supply a buffer, it will use an internal
 * static string.  This means that if multiple threads call this function at
 * the same time, output can be corrupted...  Note also that this function
 * does not check the size of the supplied buffer.  The caller has to make
 * sure that it is big enough.
 */
static char *
tcp_display(tcp_t *tcp, char *sup_buf, char format)
{
	char		buf1[30];
	static char	priv_buf[INET_ADDRSTRLEN * 2 + 80];
	char		*buf;
	char		*cp;
	char		local_addrbuf[INET_ADDRSTRLEN];
	char		remote_addrbuf[INET_ADDRSTRLEN];
	struct in_addr	addr;

	if (sup_buf != NULL)
		buf = sup_buf;
	else
		buf = priv_buf;

	if (tcp == NULL)
		return ("NULL_TCP");
	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
		cp = "TCP_CLOSED";
		break;
	case TCPS_IDLE:
		cp = "TCP_IDLE";
		break;
	case TCPS_BOUND:
		cp = "TCP_BOUND";
		break;
	case TCPS_LISTEN:
		cp = "TCP_LISTEN";
		break;
	case TCPS_SYN_SENT:
		cp = "TCP_SYN_SENT";
		break;
	case TCPS_SYN_RCVD:
		cp = "TCP_SYN_RCVD";
		break;
	case TCPS_ESTABLISHED:
		cp = "TCP_ESTABLISHED";
		break;
	case TCPS_CLOSE_WAIT:
		cp = "TCP_CLOSE_WAIT";
		break;
	case TCPS_FIN_WAIT_1:
		cp = "TCP_FIN_WAIT_1";
		break;
	case TCPS_CLOSING:
		cp = "TCP_CLOSING";
		break;
	case TCPS_LAST_ACK:
		cp = "TCP_LAST_ACK";
		break;
	case TCPS_FIN_WAIT_2:
		cp = "TCP_FIN_WAIT_2";
		break;
	case TCPS_TIME_WAIT:
		cp = "TCP_TIME_WAIT";
		break;
	default:
		(void) sprintf(buf1, "TCPUnkState(%d)", tcp->tcp_state);
		cp = buf1;
		break;
	}
	switch (format) {
	case DISP_ADDR_AND_PORT:
		/*
		 * Note that we use the remote address in the tcp_b
		 * structure.  This means that it will print out
		 * the real destination address, not the next hop's
		 * address if source routing is used.
		 */
		addr.s_addr = tcp->tcp_bound_source;
		bcopy(inet_ntoa(addr), local_addrbuf, sizeof (local_addrbuf));
		addr.s_addr = tcp->tcp_remote;
		bcopy(inet_ntoa(addr), remote_addrbuf, sizeof (remote_addrbuf));
		(void) snprintf(buf, sizeof (priv_buf), "[%s.%u, %s.%u] %s",
		    local_addrbuf, ntohs(tcp->tcp_lport), remote_addrbuf,
		    ntohs(tcp->tcp_fport), cp);
		break;
	case DISP_PORT_ONLY:
	default:
		(void) snprintf(buf, sizeof (priv_buf), "[%u, %u] %s",
		    ntohs(tcp->tcp_lport), ntohs(tcp->tcp_fport), cp);
		break;
	}

	return (buf);
}

/*
 * Add a new piece to the tcp reassembly queue.  If the gap at the beginning
 * is filled, return as much as we can.  The message passed in may be
 * multi-part, chained using b_cont.  "start" is the starting sequence
 * number for this piece.
 */
static mblk_t *
tcp_reass(tcp_t *tcp, mblk_t *mp, uint32_t start)
{
	uint32_t	end;
	mblk_t		*mp1;
	mblk_t		*mp2;
	mblk_t		*next_mp;
	uint32_t	u1;

	/* Walk through all the new pieces. */
	do {
		assert((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		end = start + (int)(mp->b_wptr - mp->b_rptr);
		next_mp = mp->b_cont;
		if (start == end) {
			/* Empty.  Blast it. */
			freeb(mp);
			continue;
		}
		mp->b_cont = NULL;
		TCP_REASS_SET_SEQ(mp, start);
		TCP_REASS_SET_END(mp, end);
		mp1 = tcp->tcp_reass_tail;
		if (!mp1) {
			tcp->tcp_reass_tail = mp;
			tcp->tcp_reass_head = mp;
			BUMP_MIB(tcp_mib.tcpInDataUnorderSegs);
			UPDATE_MIB(tcp_mib.tcpInDataUnorderBytes, end - start);
			continue;
		}
		/* New stuff completely beyond tail? */
		if (SEQ_GEQ(start, TCP_REASS_END(mp1))) {
			/* Link it on end. */
			mp1->b_cont = mp;
			tcp->tcp_reass_tail = mp;
			BUMP_MIB(tcp_mib.tcpInDataUnorderSegs);
			UPDATE_MIB(tcp_mib.tcpInDataUnorderBytes, end - start);
			continue;
		}
		mp1 = tcp->tcp_reass_head;
		u1 = TCP_REASS_SEQ(mp1);
		/* New stuff at the front? */
		if (SEQ_LT(start, u1)) {
			/* Yes... Check for overlap. */
			mp->b_cont = mp1;
			tcp->tcp_reass_head = mp;
			tcp_reass_elim_overlap(tcp, mp);
			continue;
		}
		/*
		 * The new piece fits somewhere between the head and tail.
		 * We find our slot, where mp1 precedes us and mp2 trails.
		 */
		for (; (mp2 = mp1->b_cont) != NULL; mp1 = mp2) {
			u1 = TCP_REASS_SEQ(mp2);
			if (SEQ_LEQ(start, u1))
				break;
		}
		/* Link ourselves in */
		mp->b_cont = mp2;
		mp1->b_cont = mp;

		/* Trim overlap with following mblk(s) first */
		tcp_reass_elim_overlap(tcp, mp);

		/* Trim overlap with preceding mblk */
		tcp_reass_elim_overlap(tcp, mp1);

	} while (start = end, mp = next_mp);
	mp1 = tcp->tcp_reass_head;
	/* Anything ready to go? */
	if (TCP_REASS_SEQ(mp1) != tcp->tcp_rnxt)
		return (NULL);
	/* Eat what we can off the queue */
	for (;;) {
		mp = mp1->b_cont;
		end = TCP_REASS_END(mp1);
		TCP_REASS_SET_SEQ(mp1, 0);
		TCP_REASS_SET_END(mp1, 0);
		if (!mp) {
			tcp->tcp_reass_tail = NULL;
			break;
		}
		if (end != TCP_REASS_SEQ(mp)) {
			mp1->b_cont = NULL;
			break;
		}
		mp1 = mp;
	}
	mp1 = tcp->tcp_reass_head;
	tcp->tcp_reass_head = mp;
	return (mp1);
}

/* Eliminate any overlap that mp may have over later mblks */
static void
tcp_reass_elim_overlap(tcp_t *tcp, mblk_t *mp)
{
	uint32_t	end;
	mblk_t		*mp1;
	uint32_t	u1;

	end = TCP_REASS_END(mp);
	while ((mp1 = mp->b_cont) != NULL) {
		u1 = TCP_REASS_SEQ(mp1);
		if (!SEQ_GT(end, u1))
			break;
		if (!SEQ_GEQ(end, TCP_REASS_END(mp1))) {
			mp->b_wptr -= end - u1;
			TCP_REASS_SET_END(mp, u1);
			BUMP_MIB(tcp_mib.tcpInDataPartDupSegs);
			UPDATE_MIB(tcp_mib.tcpInDataPartDupBytes, end - u1);
			break;
		}
		mp->b_cont = mp1->b_cont;
		freeb(mp1);
		BUMP_MIB(tcp_mib.tcpInDataDupSegs);
		UPDATE_MIB(tcp_mib.tcpInDataDupBytes, end - u1);
	}
	if (!mp1)
		tcp->tcp_reass_tail = mp;
}

/*
 * Remove a connection from the list of detached TIME_WAIT connections.
 */
static void
tcp_time_wait_remove(tcp_t *tcp)
{
	if (tcp->tcp_time_wait_expire == 0) {
		assert(tcp->tcp_time_wait_next == NULL);
		assert(tcp->tcp_time_wait_prev == NULL);
		return;
	}
	assert(tcp->tcp_state == TCPS_TIME_WAIT);
	if (tcp == tcp_time_wait_head) {
		assert(tcp->tcp_time_wait_prev == NULL);
		tcp_time_wait_head = tcp->tcp_time_wait_next;
		if (tcp_time_wait_head != NULL) {
			tcp_time_wait_head->tcp_time_wait_prev = NULL;
		} else {
			tcp_time_wait_tail = NULL;
		}
	} else if (tcp == tcp_time_wait_tail) {
		assert(tcp != tcp_time_wait_head);
		assert(tcp->tcp_time_wait_next == NULL);
		tcp_time_wait_tail = tcp->tcp_time_wait_prev;
		assert(tcp_time_wait_tail != NULL);
		tcp_time_wait_tail->tcp_time_wait_next = NULL;
	} else {
		assert(tcp->tcp_time_wait_prev->tcp_time_wait_next == tcp);
		assert(tcp->tcp_time_wait_next->tcp_time_wait_prev == tcp);
		tcp->tcp_time_wait_prev->tcp_time_wait_next =
		    tcp->tcp_time_wait_next;
		tcp->tcp_time_wait_next->tcp_time_wait_prev =
		    tcp->tcp_time_wait_prev;
	}
	tcp->tcp_time_wait_next = NULL;
	tcp->tcp_time_wait_prev = NULL;
	tcp->tcp_time_wait_expire = 0;
}

/*
 * Add a connection to the list of detached TIME_WAIT connections
 * and set its time to expire ...
 */
static void
tcp_time_wait_append(tcp_t *tcp)
{
	tcp->tcp_time_wait_expire = prom_gettime() + tcp_time_wait_interval;
	if (tcp->tcp_time_wait_expire == 0)
		tcp->tcp_time_wait_expire = 1;

	if (tcp_time_wait_head == NULL) {
		assert(tcp_time_wait_tail == NULL);
		tcp_time_wait_head = tcp;
	} else {
		assert(tcp_time_wait_tail != NULL);
		assert(tcp_time_wait_tail->tcp_state == TCPS_TIME_WAIT);
		tcp_time_wait_tail->tcp_time_wait_next = tcp;
		tcp->tcp_time_wait_prev = tcp_time_wait_tail;
	}
	tcp_time_wait_tail = tcp;

	/* for ndd stats about compression */
	tcp_cum_timewait++;
}

/*
 * Periodic qtimeout routine run on the default queue.
 * Performs 2 functions.
 * 	1.  Does TIME_WAIT compression on all recently added tcps. List
 *	    traversal is done backwards from the tail.
 *	2.  Blows away all tcps whose TIME_WAIT has expired. List traversal
 *	    is done forwards from the head.
 */
void
tcp_time_wait_collector(void)
{
	tcp_t *tcp;
	uint32_t now;

	/*
	 * In order to reap time waits reliably, we should use a
	 * source of time that is not adjustable by the user
	 */
	now = prom_gettime();
	while ((tcp = tcp_time_wait_head) != NULL) {
		/*
		 * Compare times using modular arithmetic, since
		 * lbolt can wrapover.
		 */
		if ((int32_t)(now - tcp->tcp_time_wait_expire) < 0) {
			break;
		}
		/*
		 * Note that the err must be 0 as there is no socket
		 * associated with this TCP...
		 */
		(void) tcp_clean_death(-1, tcp, 0);
	}
	/* Schedule next run time. */
	tcp_time_wait_runtime = prom_gettime() + 10000;
}

void
tcp_time_wait_report(void)
{
	tcp_t *tcp;

	printf("Current time %u\n", prom_gettime());
	for (tcp = tcp_time_wait_head; tcp != NULL;
	    tcp = tcp->tcp_time_wait_next) {
		printf("%s expires at %u\n", tcp_display(tcp, NULL,
		    DISP_ADDR_AND_PORT), tcp->tcp_time_wait_expire);
	}
}

/*
 * Send up all messages queued on tcp_rcv_list.
 * Have to set tcp_co_norm since we use putnext.
 */
static void
tcp_rcv_drain(int sock_id, tcp_t *tcp)
{
	mblk_t *mp;
	struct inetgram *in_gram;
	mblk_t *in_mp;
	int len;

	/* Don't drain if the app has not finished reading all the data. */
	if (sockets[sock_id].so_rcvbuf <= 0)
		return;

	/* We might have come here just to updated the rwnd */
	if (tcp->tcp_rcv_list == NULL)
		goto win_update;

	if ((in_gram = (struct inetgram *)bkmem_zalloc(
	    sizeof (struct inetgram))) == NULL) {
		return;
	}
	if ((in_mp = allocb(tcp->tcp_rcv_cnt, 0)) == NULL) {
		bkmem_free((caddr_t)in_gram, sizeof (struct inetgram));
		return;
	}
	in_gram->igm_level = APP_LVL;
	in_gram->igm_mp = in_mp;
	in_gram->igm_id = 0;

	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_cont;
		len = mp->b_wptr - mp->b_rptr;
		bcopy(mp->b_rptr, in_mp->b_wptr, len);
		in_mp->b_wptr += len;
		freeb(mp);
	}

	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;
	add_grams(&sockets[sock_id].inq, in_gram);

	/* This means that so_rcvbuf can be less than 0. */
	sockets[sock_id].so_rcvbuf -= in_mp->b_wptr - in_mp->b_rptr;
win_update:
	/*
	 * Increase the receive window to max.  But we need to do receiver
	 * SWS avoidance.  This means that we need to check the increase of
	 * of receive window is at least 1 MSS.
	 */
	if (sockets[sock_id].so_rcvbuf > 0 &&
	    (tcp->tcp_rwnd_max - tcp->tcp_rwnd >= tcp->tcp_mss)) {
		tcp->tcp_rwnd = tcp->tcp_rwnd_max;
		U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
		    tcp->tcp_tcph->th_win);
	}
}

/*
 * Wrapper for recvfrom to call
 */
void
tcp_rcv_drain_sock(int sock_id)
{
	tcp_t *tcp;
	if ((tcp = sockets[sock_id].pcb) == NULL)
		return;
	tcp_rcv_drain(sock_id, tcp);
}

/*
 * If the inq == NULL and the tcp_rcv_list != NULL, we have data that
 * recvfrom could read. Place a magic message in the inq to let recvfrom
 * know that it needs to call tcp_rcv_drain_sock to pullup the data.
 */
static void
tcp_drain_needed(int sock_id, tcp_t *tcp)
{
	struct inetgram *in_gram;
#ifdef DEBUG
	printf("tcp_drain_needed: inq %x, tcp_rcv_list %x\n",
		sockets[sock_id].inq, tcp->tcp_rcv_list);
#endif
	if ((sockets[sock_id].inq != NULL) ||
		(tcp->tcp_rcv_list == NULL))
		return;

	if ((in_gram = (struct inetgram *)bkmem_zalloc(
		sizeof (struct inetgram))) == NULL)
		return;

	in_gram->igm_level = APP_LVL;
	in_gram->igm_mp = NULL;
	in_gram->igm_id = TCP_CALLB_MAGIC_ID;

	add_grams(&sockets[sock_id].inq, in_gram);
}

/*
 * Queue data on tcp_rcv_list which is a b_next chain.
 * Each element of the chain is a b_cont chain.
 *
 * M_DATA messages are added to the current element.
 * Other messages are added as new (b_next) elements.
 */
static void
tcp_rcv_enqueue(tcp_t *tcp, mblk_t *mp, uint_t seg_len)
{
	assert(seg_len == msgdsize(mp));
	if (tcp->tcp_rcv_list == NULL) {
		tcp->tcp_rcv_list = mp;
	} else {
		tcp->tcp_rcv_last_tail->b_cont = mp;
	}
	while (mp->b_cont)
		mp = mp->b_cont;
	tcp->tcp_rcv_last_tail = mp;
	tcp->tcp_rcv_cnt += seg_len;
	tcp->tcp_rwnd -= seg_len;
#ifdef DEBUG
	printf("tcp_rcv_enqueue rwnd %d\n", tcp->tcp_rwnd);
#endif
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws, tcp->tcp_tcph->th_win);
}

/* The minimum of smoothed mean deviation in RTO calculation. */
#define	TCP_SD_MIN	400

/*
 * Set RTO for this connection.  The formula is from Jacobson and Karels'
 * "Congestion Avoidance and Control" in SIGCOMM '88.  The variable names
 * are the same as those in Appendix A.2 of that paper.
 *
 * m = new measurement
 * sa = smoothed RTT average (8 * average estimates).
 * sv = smoothed mean deviation (mdev) of RTT (4 * deviation estimates).
 */
static void
tcp_set_rto(tcp_t *tcp, int32_t rtt)
{
	int32_t m = rtt;
	uint32_t sa = tcp->tcp_rtt_sa;
	uint32_t sv = tcp->tcp_rtt_sd;
	uint32_t rto;

	BUMP_MIB(tcp_mib.tcpRttUpdate);
	tcp->tcp_rtt_update++;

	/* tcp_rtt_sa is not 0 means this is a new sample. */
	if (sa != 0) {
		/*
		 * Update average estimator:
		 *	new rtt = 7/8 old rtt + 1/8 Error
		 */

		/* m is now Error in estimate. */
		m -= sa >> 3;
		if ((int32_t)(sa += m) <= 0) {
			/*
			 * Don't allow the smoothed average to be negative.
			 * We use 0 to denote reinitialization of the
			 * variables.
			 */
			sa = 1;
		}

		/*
		 * Update deviation estimator:
		 *	new mdev = 3/4 old mdev + 1/4 (abs(Error) - old mdev)
		 */
		if (m < 0)
			m = -m;
		m -= sv >> 2;
		sv += m;
	} else {
		/*
		 * This follows BSD's implementation.  So the reinitialized
		 * RTO is 3 * m.  We cannot go less than 2 because if the
		 * link is bandwidth dominated, doubling the window size
		 * during slow start means doubling the RTT.  We want to be
		 * more conservative when we reinitialize our estimates.  3
		 * is just a convenient number.
		 */
		sa = m << 3;
		sv = m << 1;
	}
	if (sv < TCP_SD_MIN) {
		/*
		 * We do not know that if sa captures the delay ACK
		 * effect as in a long train of segments, a receiver
		 * does not delay its ACKs.  So set the minimum of sv
		 * to be TCP_SD_MIN, which is default to 400 ms, twice
		 * of BSD DATO.  That means the minimum of mean
		 * deviation is 100 ms.
		 *
		 */
		sv = TCP_SD_MIN;
	}
	tcp->tcp_rtt_sa = sa;
	tcp->tcp_rtt_sd = sv;
	/*
	 * RTO = average estimates (sa / 8) + 4 * deviation estimates (sv)
	 *
	 * Add tcp_rexmit_interval extra in case of extreme environment
	 * where the algorithm fails to work.  The default value of
	 * tcp_rexmit_interval_extra should be 0.
	 *
	 * As we use a finer grained clock than BSD and update
	 * RTO for every ACKs, add in another .25 of RTT to the
	 * deviation of RTO to accomodate burstiness of 1/4 of
	 * window size.
	 */
	rto = (sa >> 3) + sv + tcp_rexmit_interval_extra + (sa >> 5);

	if (rto > tcp_rexmit_interval_max) {
		tcp->tcp_rto = tcp_rexmit_interval_max;
	} else if (rto < tcp_rexmit_interval_min) {
		tcp->tcp_rto = tcp_rexmit_interval_min;
	} else {
		tcp->tcp_rto = rto;
	}

	/* Now, we can reset tcp_timer_backoff to use the new RTO... */
	tcp->tcp_timer_backoff = 0;
}

/*
 * Initiate closedown sequence on an active connection.
 * Return value zero for OK return, non-zero for error return.
 */
static int
tcp_xmit_end(tcp_t *tcp, int sock_id)
{
	mblk_t	*mp;

	if (tcp->tcp_state < TCPS_SYN_RCVD ||
	    tcp->tcp_state > TCPS_CLOSE_WAIT) {
		/*
		 * Invalid state, only states TCPS_SYN_RCVD,
		 * TCPS_ESTABLISHED and TCPS_CLOSE_WAIT are valid
		 */
		return (-1);
	}

	tcp->tcp_fss = tcp->tcp_snxt + tcp->tcp_unsent;
	tcp->tcp_valid_bits |= TCP_FSS_VALID;
	/*
	 * If there is nothing more unsent, send the FIN now.
	 * Otherwise, it will go out with the last segment.
	 */
	if (tcp->tcp_unsent == 0) {
		mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
		    tcp->tcp_fss, B_FALSE, NULL, B_FALSE);

		if (mp != NULL) {
			/* Dump the packet when debugging. */
			TCP_DUMP_PACKET("tcp_xmit_end", mp);
			(void) ipv4_tcp_output(sock_id, mp);
			freeb(mp);
		} else {
			/*
			 * Couldn't allocate msg.  Pretend we got it out.
			 * Wait for rexmit timeout.
			 */
			tcp->tcp_snxt = tcp->tcp_fss + 1;
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}

		/*
		 * If needed, update tcp_rexmit_snxt as tcp_snxt is
		 * changed.
		 */
		if (tcp->tcp_rexmit && tcp->tcp_rexmit_nxt == tcp->tcp_fss) {
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
		}
	} else {
		tcp_wput_data(tcp, NULL, B_FALSE);
	}

	return (0);
}

int
tcp_opt_set(tcp_t *tcp, int level, int option, const void *optval,
    socklen_t optlen)
{
	switch (level) {
	case SOL_SOCKET: {
		switch (option) {
		case SO_RCVBUF:
			if (optlen == sizeof (int)) {
				int val = *(int *)optval;

				if (val > tcp_max_buf) {
					errno = ENOBUFS;
					break;
				}
				/* Silently ignore zero */
				if (val != 0) {
					val = MSS_ROUNDUP(val, tcp->tcp_mss);
					(void) tcp_rwnd_set(tcp, val);
				}
			} else {
				errno = EINVAL;
			}
			break;
		case SO_SNDBUF:
			if (optlen == sizeof (int)) {
				tcp->tcp_xmit_hiwater = *(int *)optval;
				if (tcp->tcp_xmit_hiwater > tcp_max_buf)
					tcp->tcp_xmit_hiwater = tcp_max_buf;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_LINGER:
			if (optlen == sizeof (struct linger)) {
				struct linger *lgr = (struct linger *)optval;

				if (lgr->l_onoff) {
					tcp->tcp_linger = 1;
					tcp->tcp_lingertime = lgr->l_linger;
				} else {
					tcp->tcp_linger = 0;
					tcp->tcp_lingertime = 0;
				}
			} else {
				errno = EINVAL;
			}
			break;
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case SOL_SOCKET */
	case IPPROTO_TCP: {
		switch (option) {
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case IPPROTO_TCP */
	case IPPROTO_IP: {
		switch (option) {
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case IPPROTO_IP */
	default:
		errno = ENOPROTOOPT;
		break;
	} /* switch (level) */

	if (errno != 0)
		return (-1);
	else
		return (0);
}

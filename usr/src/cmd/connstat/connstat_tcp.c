/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inet/mib2.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/tcp.h>
#include <arpa/inet.h>
#include <ofmt.h>
#include <sys/time.h>
#include "connstat_mib.h"
#include "connstat_tcp.h"

/*
 * The byte order of some of the fields in this code can be a bit confusing.
 * When using sockaddr_in(6) structs, the address and ports are always in
 * Network Byte Order (Big Endian), as required by sockaddr(3SOCKET).
 *
 * When using the structs mib2_tcpConnEntry_t and mib2_tcp6ConnEntry_t, the
 * address fields (tcp(6)ConnLocalAddress and tcp(6)ConnRemAdddress) are in
 * Network Byte Order. Note, however, that the port fields ARE NOT, but are
 * instead in Host Byte Order. This isn't a problem though, since the ports
 * we filter on from the command-line (ca_lport and ca_rport) are kept in
 * Host Byte Order after parsing.
 *
 * Since the t_lport and t_rport fields come from the MIB structs, they are
 * likewise stored in Host Byte Order (and need to be for printing). The
 * t_laddr and t_raddr fields are string representations of the addresses,
 * so they don't require any special attention.
 *
 * All of the statistics (such as bytes read and written, current window
 * sizes, etc.) are in Host Byte Order.
 */

typedef struct tcp_fields_buf_s {
	char t_laddr[INET6_ADDRSTRLEN];
	char t_raddr[INET6_ADDRSTRLEN];
	uint16_t t_lport;
	uint16_t t_rport;
	uint64_t t_inbytes;
	uint64_t t_insegs;
	uint64_t t_inunorderbytes;
	uint64_t t_inunordersegs;
	uint64_t t_outbytes;
	uint64_t t_outsegs;
	uint64_t t_retransbytes;
	uint64_t t_retranssegs;
	uint32_t t_suna;
	uint32_t t_unsent;
	uint32_t t_swnd;
	uint32_t t_cwnd;
	uint32_t t_rwnd;
	uint32_t t_mss;
	uint32_t t_rto;
	uint32_t t_rtt_cnt;
	uint64_t t_rtt_sum;
	int t_state;
	uint64_t t_rtt;
} tcp_fields_buf_t;

static boolean_t print_tcp_state(ofmt_arg_t *, char *, uint_t);

static ofmt_field_t tcp_fields[] = {
	{ "LADDR",	26,
		offsetof(tcp_fields_buf_t, t_laddr),	print_string },
	{ "RADDR",	26,
		offsetof(tcp_fields_buf_t, t_raddr),	print_string },
	{ "LPORT",	6,
		offsetof(tcp_fields_buf_t, t_lport),	print_uint16 },
	{ "RPORT",	6,
		offsetof(tcp_fields_buf_t, t_rport),	print_uint16 },
	{ "INBYTES",	11,
		offsetof(tcp_fields_buf_t, t_inbytes),	print_uint64 },
	{ "INSEGS",	11,
		offsetof(tcp_fields_buf_t, t_insegs),	print_uint64 },
	{ "INUNORDERBYTES",	15,
		offsetof(tcp_fields_buf_t, t_inunorderbytes),	print_uint64 },
	{ "INUNORDERSEGS",	14,
		offsetof(tcp_fields_buf_t, t_inunordersegs),	print_uint64 },
	{ "OUTBYTES",	11,
		offsetof(tcp_fields_buf_t, t_outbytes),	print_uint64 },
	{ "OUTSEGS",	11,
		offsetof(tcp_fields_buf_t, t_outsegs),	print_uint64 },
	{ "RETRANSBYTES",	13,
		offsetof(tcp_fields_buf_t, t_retransbytes),	print_uint64 },
	{ "RETRANSSEGS",	12,
		offsetof(tcp_fields_buf_t, t_retranssegs),	print_uint64 },
	{ "SUNA",	11,
		offsetof(tcp_fields_buf_t, t_suna),	print_uint32 },
	{ "UNSENT",	11,
		offsetof(tcp_fields_buf_t, t_unsent),	print_uint32 },
	{ "SWND",	11,
		offsetof(tcp_fields_buf_t, t_swnd),	print_uint32 },
	{ "CWND",	11,
		offsetof(tcp_fields_buf_t, t_cwnd),	print_uint32 },
	{ "RWND",	11,
		offsetof(tcp_fields_buf_t, t_rwnd),	print_uint32 },
	{ "MSS",	6,
		offsetof(tcp_fields_buf_t, t_mss),	print_uint32 },
	{ "RTO",	8,
		offsetof(tcp_fields_buf_t, t_rto),	print_uint32 },
	{ "RTT",	8,
		offsetof(tcp_fields_buf_t, t_rtt),	print_uint64 },
	{ "RTTS",	8,
		offsetof(tcp_fields_buf_t, t_rtt_sum),	print_uint64 },
	{ "RTTC",	11,
		offsetof(tcp_fields_buf_t, t_rtt_cnt),	print_uint32 },
	{ "STATE",	12,
		offsetof(tcp_fields_buf_t, t_state),	print_tcp_state },
	{ NULL, 0, 0, NULL}
};

static tcp_fields_buf_t fields_buf;


typedef struct tcp_state_info_s {
	int tsi_state;
	const char *tsi_string;
} tcp_state_info_t;

tcp_state_info_t tcp_state_info[] = {
	{ TCPS_CLOSED, "CLOSED" },
	{ TCPS_IDLE, "IDLE" },
	{ TCPS_BOUND, "BOUND" },
	{ TCPS_LISTEN, "LISTEN" },
	{ TCPS_SYN_SENT, "SYN_SENT" },
	{ TCPS_SYN_RCVD, "SYN_RCVD" },
	{ TCPS_ESTABLISHED, "ESTABLISHED" },
	{ TCPS_CLOSE_WAIT, "CLOSE_WAIT" },
	{ TCPS_FIN_WAIT_1, "FIN_WAIT_1" },
	{ TCPS_CLOSING, "CLOSING" },
	{ TCPS_LAST_ACK, "LAST_ACK" },
	{ TCPS_FIN_WAIT_2, "FIN_WAIT_2" },
	{ TCPS_TIME_WAIT, "TIME_WAIT" },
	{ TCPS_CLOSED - 1, NULL }
};

ofmt_field_t *
tcp_get_fields(void)
{
	return (tcp_fields);
}

/*
 * Extract information from the connection info structure into the global
 * output buffer.
 */
static void
tcp_ci2buf(struct tcpConnEntryInfo_s *ci)
{
	fields_buf.t_inbytes =
	    ci->ce_in_data_inorder_bytes + ci->ce_in_data_unorder_bytes;
	fields_buf.t_insegs =
	    ci->ce_in_data_inorder_segs + ci->ce_in_data_unorder_segs;
	fields_buf.t_inunorderbytes = ci->ce_in_data_unorder_bytes;
	fields_buf.t_inunordersegs = ci->ce_in_data_unorder_segs;
	fields_buf.t_outbytes = ci->ce_out_data_bytes;
	fields_buf.t_outsegs = ci->ce_out_data_segs;
	fields_buf.t_retransbytes = ci->ce_out_retrans_bytes;
	fields_buf.t_retranssegs = ci->ce_out_retrans_segs;
	fields_buf.t_suna = ci->ce_snxt - ci->ce_suna;
	fields_buf.t_unsent = ci->ce_unsent;
	fields_buf.t_swnd = ci->ce_swnd;
	fields_buf.t_cwnd = ci->ce_cwnd;
	fields_buf.t_rwnd = ci->ce_rwnd;
	fields_buf.t_mss = ci->ce_mss;
	fields_buf.t_rto = ci->ce_rto;
	fields_buf.t_rtt = (ci->ce_out_data_segs == 0 ? 0 : ci->ce_rtt_sa);
	fields_buf.t_rtt_sum = ci->ce_rtt_sum;
	fields_buf.t_rtt_cnt = ci->ce_rtt_cnt;
	fields_buf.t_state = ci->ce_state;
}

/*
 * Extract information from the connection entry into the global output
 * buffer.
 */
static void
tcp_ipv4_ce2buf(mib2_tcpConnEntry_t *ce)
{
	VERIFY3P(inet_ntop(AF_INET, (void *)&ce->tcpConnLocalAddress,
	    fields_buf.t_laddr, sizeof (fields_buf.t_laddr)), !=, NULL);
	VERIFY3P(inet_ntop(AF_INET, (void *)&ce->tcpConnRemAddress,
	    fields_buf.t_raddr, sizeof (fields_buf.t_raddr)), !=, NULL);

	fields_buf.t_lport = ce->tcpConnLocalPort;
	fields_buf.t_rport = ce->tcpConnRemPort;

	tcp_ci2buf(&ce->tcpConnEntryInfo);
}

static void
tcp_ipv6_ce2buf(mib2_tcp6ConnEntry_t *ce)
{
	VERIFY3P(inet_ntop(AF_INET6, (void *)&ce->tcp6ConnLocalAddress,
	    fields_buf.t_laddr, sizeof (fields_buf.t_laddr)), !=, NULL);
	VERIFY3P(inet_ntop(AF_INET6, (void *)&ce->tcp6ConnRemAddress,
	    fields_buf.t_raddr, sizeof (fields_buf.t_raddr)), !=, NULL);

	fields_buf.t_lport = ce->tcp6ConnLocalPort;
	fields_buf.t_rport = ce->tcp6ConnRemPort;

	tcp_ci2buf(&ce->tcp6ConnEntryInfo);
}

/*
 * Print a single IPv4 connection entry, taking into account possible
 * filters that have been set in state.
 */
static void
tcp_ipv4_print(mib2_tcpConnEntry_t *ce, conn_walk_state_t *state)
{
	if (!(state->cws_flags & CS_LOOPBACK) &&
	    ntohl(ce->tcpConnLocalAddress) == INADDR_LOOPBACK) {
		return;
	}

	if (state->cws_flags & CS_LADDR) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_laddr;
		if (ce->tcpConnLocalAddress != sin->sin_addr.s_addr) {
			return;
		}
	}
	if (state->cws_flags & CS_RADDR) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&state->cws_filter.ca_raddr;
		if (ce->tcpConnRemAddress != sin->sin_addr.s_addr) {
			return;
		}
	}
	if (state->cws_flags & CS_LPORT) {
		if (ce->tcpConnLocalPort != state->cws_filter.ca_lport) {
			return;
		}
	}
	if (state->cws_flags & CS_RPORT) {
		if (ce->tcpConnRemPort != state->cws_filter.ca_rport) {
			return;
		}
	}

	if ((state->cws_flags & CS_STATE) &&
	    ce->tcpConnEntryInfo.ce_state != state->cws_filter.ca_state) {
		return;
	}

	tcp_ipv4_ce2buf(ce);
	ofmt_print(state->cws_ofmt, &fields_buf);
}

/*
 * Print a single IPv6 connection entry, taking into account possible
 * filters that have been set in state.
 */
static void
tcp_ipv6_print(mib2_tcp6ConnEntry_t *ce, conn_walk_state_t *state)
{
	if (!(state->cws_flags & CS_LOOPBACK) &&
	    IN6_IS_ADDR_LOOPBACK(
	    (struct in6_addr *)&ce->tcp6ConnLocalAddress)) {
		return;
	}

	if (state->cws_flags & CS_LADDR) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_laddr;
		if (!IN6_ARE_ADDR_EQUAL(
		    (struct in6_addr *)&ce->tcp6ConnLocalAddress,
		    &sin6->sin6_addr)) {
			return;
		}
	}
	if (state->cws_flags & CS_RADDR) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&state->cws_filter.ca_raddr;
		if (!IN6_ARE_ADDR_EQUAL(
		    (struct in6_addr *)&ce->tcp6ConnRemAddress,
		    &sin6->sin6_addr)) {
			return;
		}
	}
	if (state->cws_flags & CS_LPORT) {
		if (ce->tcp6ConnLocalPort != state->cws_filter.ca_lport) {
			return;
		}
	}
	if (state->cws_flags & CS_RPORT) {
		if (ce->tcp6ConnRemPort != state->cws_filter.ca_rport) {
			return;
		}
	}

	if ((state->cws_flags & CS_STATE) &&
	    ce->tcp6ConnEntryInfo.ce_state != state->cws_filter.ca_state) {
		return;
	}

	tcp_ipv6_ce2buf(ce);
	ofmt_print(state->cws_ofmt, &fields_buf);
}

void
tcp_walk_ipv4(struct strbuf *dbuf, conn_walk_state_t *state)
{
	uint_t nconns = (dbuf->len / sizeof (mib2_tcpConnEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_tcpConnEntry_t *ce = (mib2_tcpConnEntry_t *)dbuf->buf;

	for (; nconns > 0; ce++, nconns--) {
		tcp_ipv4_print(ce, state);
	}
}

void
tcp_walk_ipv6(struct strbuf *dbuf, conn_walk_state_t *state)
{
	uint_t nconns = (dbuf->len / sizeof (mib2_tcp6ConnEntry_t));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	mib2_tcp6ConnEntry_t *ce = (mib2_tcp6ConnEntry_t *)dbuf->buf;

	for (; nconns > 0; ce++, nconns--) {
		tcp_ipv6_print(ce, state);
	}
}

static tcp_state_info_t *
tcp_stateinfobystate(int state)
{
	tcp_state_info_t *sip;

	for (sip = tcp_state_info; sip->tsi_string != NULL; sip++) {
		if (sip->tsi_state == state) {
			return (sip);
		}
	}
	return (NULL);
}

static tcp_state_info_t *
tcp_stateinfobystr(const char *statestr)
{
	tcp_state_info_t *sip;

	for (sip = tcp_state_info; sip->tsi_string != NULL; sip++) {
		if (strncasecmp(statestr, sip->tsi_string,
		    strlen(sip->tsi_string)) == 0) {
			return (sip);
		}
	}
	return (NULL);
}

int
tcp_str2state(const char *statestr)
{
	tcp_state_info_t *sip = tcp_stateinfobystr(statestr);
	return (sip == NULL ? TCPS_CLOSED - 1 : sip->tsi_state);
}

static const char *
tcp_state2str(int state)
{
	tcp_state_info_t *sip = tcp_stateinfobystate(state);
	return (sip == NULL ? NULL : sip->tsi_string);
}

static boolean_t
print_tcp_state(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	int state = *(int *)((char *)ofarg->ofmt_cbarg + ofarg->ofmt_id);
	const char *statestr = tcp_state2str(state);

	if (statestr != NULL) {
		(void) strlcpy(buf, statestr, bufsize);
	} else {
		(void) snprintf(buf, bufsize, "UNKNOWN(%d)", state);
	}

	return (B_TRUE);
}

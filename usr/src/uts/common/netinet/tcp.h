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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_TCP_H
#define	_NETINET_TCP_H

/* tcp.h 1.11 88/08/19 SMI; from UCB 7.2 10/28/86	*/


#include <sys/isa_defs.h>
#include <sys/inttypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	uint32_t	tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	tcp_seq		th_seq;		/* sequence number */
	tcp_seq		th_ack;		/* acknowledgement number */
#ifdef _BIT_FIELDS_LTOH
	uint_t	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#else
	uint_t	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	uchar_t	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;		/* urgent pointer */
};

#define	TCPOPT_EOL	0
#define	TCPOPT_NOP	1
#define	TCPOPT_MAXSEG	2
#define	TCPOPT_WSCALE	3
#define	TCPOPT_SACK_PERMITTED	4
#define	TCPOPT_SACK	5
#define	TCPOPT_TSTAMP	8
#define	TCPOPT_MD5	19	/* RFC 2385 */

/*
 * Default maximum segment size for TCP.
 * With an IP MTU of 576, this is 536.
 */
#define	TCP_MSS	536

/*
 * Options for use with [gs]etsockopt at the TCP level.
 *
 * Note: Some of the TCP_ namespace has conflict with and
 * and is exposed through <xti.h>. (It also requires exposing
 * options not implemented). The options with potential
 * for conflicts use #ifndef guards.
 */
#ifndef TCP_NODELAY
#define	TCP_NODELAY	0x01	/* don't delay send to coalesce packets */
#endif

#ifndef TCP_MAXSEG
#define	TCP_MAXSEG	0x02	/* set maximum segment size */
#endif

#ifndef TCP_KEEPALIVE
#define	TCP_KEEPALIVE	0x8	/* set keepalive timer */
#endif


#define	TCP_NOTIFY_THRESHOLD		0x10
#define	TCP_ABORT_THRESHOLD		0x11
#define	TCP_CONN_NOTIFY_THRESHOLD	0x12
#define	TCP_CONN_ABORT_THRESHOLD	0x13
#define	TCP_RECVDSTADDR			0x14
#define	TCP_INIT_CWND			0x15
#define	TCP_KEEPALIVE_THRESHOLD		0x16
#define	TCP_KEEPALIVE_ABORT_THRESHOLD	0x17
#define	TCP_CORK			0x18
#define	TCP_RTO_INITIAL			0x19
#define	TCP_RTO_MIN			0x1A
#define	TCP_RTO_MAX			0x1B
#define	TCP_LINGER2			0x1C

/* gap for expansion of ``standard'' options */
#define	TCP_ANONPRIVBIND		0x20	/* for internal use only  */
#define	TCP_EXCLBIND			0x21	/* for internal use only  */
#define	TCP_KEEPIDLE			0x22
#define	TCP_KEEPCNT			0x23
#define	TCP_KEEPINTVL			0x24
#define	TCP_CONGESTION			0x25
#define	TCP_QUICKACK			0x26	/* enable/disable quick acks */
#define	TCP_MD5SIG			0x27

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_TCP_H */

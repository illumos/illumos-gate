/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1998, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TCP_TRACE_H
#define	_TCP_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TCP trace buffer size definitions
 *
 * NOTE: Do NOT change the number of TCP_TRACE_NREC. Its is fixed to 10
 * because of limitation of strlog() function which max buffer size is 1024.
 */
#define	TCP_TRACE_NREC		10	/* # of trace packets in tcp_t	*/

/*
 * Flags for tcp_trec_pkttype
 */
#define	TCP_TRACE_NOENT		0	/* No data in this record	*/
#define	TCP_TRACE_SEND_PKT	1	/* Send data record		*/
#define	TCP_TRACE_RECV_PKT	2	/* received data record		*/

/*
 * Trace record structure
 *
 * NOTE: tcp_data has a IP packet size. When we format a data which is
 * loged by strlog(), TCP data size is calculated.
 */
typedef struct tcp_trace_rec {
	hrtime_t	tcptr_iotime;		/* Time of I/O */
	uint32_t	tcptr_tcp_seq;		/* Sequence number */
	uint32_t	tcptr_tcp_ack;		/* Acknowledgement number */
	uint16_t	tcptr_tcp_data;		/* TCP data size */
	uint16_t	tcptr_tcp_win;		/* Window size */
	uint8_t		tcptr_pkttype;		/* 1=sent, 2=received */
	uint8_t		tcptr_ip_hdr_len;	/* Byte len of IP header */
	uint8_t		tcptr_tcp_hdr_len;	/* Byte len of TCP header */
	uint8_t		tcptr_tcp_flags[1];	/* TCP packet flag */
} tcptrcrec_t;

/*
 * Trace buffer record structrure
 */
typedef struct tcp_trace_header {
	hrtime_t	tcptrh_conn_time;	/* time of connection init. */
	int		tcptrh_currec;		/* current trace record */
	int		tcptrh_send_total;	/* # traced sent packets */
	int		tcptrh_recv_total;	/* # traced received packets */
	tcptrcrec_t	tcptrh_evts[TCP_TRACE_NREC];	/* event records */
} tcptrch_t;

struct tcp_s;

/*
 * tcp trace function
 */
extern	void	tcp_record_trace(struct tcp_s *tcp, mblk_t *mp, int flag);

/*
 * Macro for tcp trace
 */
#define	TCP_RECORD_TRACE(tcp, mp, flag) {	\
	if (tcp->tcp_tracebuf != NULL) {			\
		tcp_record_trace(tcp, mp, flag);	\
	}					\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _TCP_TRACE_H */

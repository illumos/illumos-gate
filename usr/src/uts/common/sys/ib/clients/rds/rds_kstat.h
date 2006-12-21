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
 */

#ifndef	_RDS_KSTAT_H
#define	_RDS_KSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/kstat.h>

struct rds_kstat_s {
	kstat_named_t   rds_nports;
	kstat_named_t   rds_nsessions;
	kstat_named_t   rds_tx_bytes;
	kstat_named_t   rds_tx_pkts;
	kstat_named_t   rds_tx_errors;
	kstat_named_t   rds_rx_bytes;
	kstat_named_t   rds_rx_pkts;
	kstat_named_t   rds_rx_pkts_pending;
	kstat_named_t   rds_rx_errors;
	kstat_named_t   rds_tx_acks;
	kstat_named_t   rds_post_recv_buf_called;
	kstat_named_t   rds_stalls_triggered;
	kstat_named_t   rds_stalls_sent;
	kstat_named_t   rds_unstalls_triggered;
	kstat_named_t   rds_unstalls_sent;
	kstat_named_t   rds_stalls_recvd;
	kstat_named_t   rds_unstalls_recvd;
	kstat_named_t   rds_stalls_ignored;
	kstat_named_t   rds_enobufs;
	kstat_named_t   rds_ewouldblocks;
	kstat_named_t   rds_failovers;
	kstat_named_t	rds_port_quota;
	kstat_named_t   rds_port_quota_adjusted;
};

extern void rds_increment_kstat(kstat_named_t *, boolean_t, uint_t);
extern void rds_decrement_kstat(kstat_named_t *, boolean_t, uint_t);
extern void rds_set_kstat(kstat_named_t *, boolean_t, ulong_t);
extern ulong_t rds_get_kstat(kstat_named_t *, boolean_t);

extern struct rds_kstat_s  rds_kstat;

#define	RDS_SET_NPORT(num) \
    rds_set_kstat(&rds_kstat.rds_nports, B_TRUE, num)
#define	RDS_INCR_NPORT() \
    rds_increment_kstat(&rds_kstat.rds_nports, B_TRUE, 1)
#define	RDS_DECR_NPORT() \
    rds_decrement_kstat(&rds_kstat.rds_nports, B_TRUE, 1)
#define	RDS_GET_NPORT() \
    rds_get_kstat(&rds_kstat.rds_nports, B_TRUE)

#define	RDS_INCR_SESS() \
    rds_increment_kstat(&rds_kstat.rds_nsessions, B_FALSE, 1)
#define	RDS_DECR_SESS()  \
    rds_decrement_kstat(&rds_kstat.rds_nsessions, B_FALSE, 1)

#define	RDS_INCR_TXBYTES(num) \
    rds_increment_kstat(&rds_kstat.rds_tx_bytes, B_FALSE, num)

#define	RDS_INCR_TXPKTS(num) \
    rds_increment_kstat(&rds_kstat.rds_tx_pkts, B_FALSE, num)

#define	RDS_INCR_TXERRS() \
    rds_increment_kstat(&rds_kstat.rds_tx_errors, B_FALSE, 1)

#define	RDS_INCR_RXBYTES(num) \
    rds_increment_kstat(&rds_kstat.rds_rx_bytes, B_FALSE, num)

#define	RDS_INCR_RXPKTS(num) \
    rds_increment_kstat(&rds_kstat.rds_rx_pkts, B_FALSE, num)

#define	RDS_INCR_RXPKTS_PEND(num) \
    rds_increment_kstat(&rds_kstat.rds_rx_pkts_pending, B_TRUE, num)
#define	RDS_DECR_RXPKTS_PEND(num) \
    rds_decrement_kstat(&rds_kstat.rds_rx_pkts_pending, B_TRUE, num)
#define	RDS_GET_RXPKTS_PEND() \
    rds_get_kstat(&rds_kstat.rds_rx_pkts_pending, B_TRUE)

#define	RDS_INCR_RXERRS() \
    rds_increment_kstat(&rds_kstat.rds_rx_errors, B_FALSE, 1)

#define	RDS_INCR_TXACKS() \
    rds_increment_kstat(&rds_kstat.rds_tx_acks, B_FALSE, 1)

#define	RDS_INCR_POST_RCV_BUF_CALLS() \
    rds_increment_kstat(&rds_kstat.rds_post_recv_buf_called, B_FALSE, 1)

#define	RDS_INCR_STALLS_TRIGGERED() \
    rds_increment_kstat(&rds_kstat.rds_stalls_triggered, B_FALSE, 1)

#define	RDS_INCR_STALLS_SENT() \
    rds_increment_kstat(&rds_kstat.rds_stalls_sent, B_FALSE, 1)

#define	RDS_INCR_UNSTALLS_TRIGGERED() \
    rds_increment_kstat(&rds_kstat.rds_unstalls_triggered, B_FALSE, 1)

#define	RDS_INCR_UNSTALLS_SENT() \
    rds_increment_kstat(&rds_kstat.rds_unstalls_sent, B_FALSE, 1)

#define	RDS_INCR_STALLS_RCVD() \
    rds_increment_kstat(&rds_kstat.rds_stalls_recvd, B_FALSE, 1)

#define	RDS_INCR_UNSTALLS_RCVD() \
    rds_increment_kstat(&rds_kstat.rds_unstalls_recvd, B_FALSE, 1)

#define	RDS_INCR_STALLS_IGNORED() \
    rds_increment_kstat(&rds_kstat.rds_stalls_ignored, B_FALSE, 1)

#define	RDS_INCR_ENOBUFS() \
    rds_increment_kstat(&rds_kstat.rds_enobufs, B_FALSE, 1)

#define	RDS_INCR_EWOULDBLOCK() \
    rds_increment_kstat(&rds_kstat.rds_ewouldblocks, B_FALSE, 1)

#define	RDS_INCR_FAILOVERS() \
    rds_increment_kstat(&rds_kstat.rds_failovers, B_FALSE, 1)

#define	RDS_SET_PORT_QUOTA(num) \
    rds_set_kstat(&rds_kstat.rds_port_quota, B_TRUE, num)
#define	RDS_GET_PORT_QUOTA() \
    rds_get_kstat(&rds_kstat.rds_port_quota, B_TRUE)

#define	RDS_INCR_PORT_QUOTA_ADJUSTED() \
    rds_increment_kstat(&rds_kstat.rds_port_quota_adjusted, B_FALSE, 1)


#ifdef	__cplusplus
}
#endif

#endif	/* _RDS_KSTAT_H */

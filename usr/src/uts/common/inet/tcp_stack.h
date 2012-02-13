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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_INET_TCP_STACK_H
#define	_INET_TCP_STACK_H

#include <sys/netstack.h>
#include <inet/ip.h>
#include <inet/ipdrop.h>
#include <inet/tcp_stats.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * TCP stack instances
 */
struct tcp_stack {
	netstack_t	*tcps_netstack;	/* Common netstack */

	/*
	 * Extra privileged ports. In host byte order.
	 * Protected by tcp_epriv_port_lock.
	 */
#define	TCP_NUM_EPRIV_PORTS	64
	int		tcps_g_num_epriv_ports;
	in_port_t	tcps_g_epriv_ports[TCP_NUM_EPRIV_PORTS];
	kmutex_t	tcps_epriv_port_lock;

	/*
	 * The smallest anonymous port in the priviledged port range which TCP
	 * looks for free port.  Use in the option TCP_ANONPRIVBIND.
	 */
	in_port_t	tcps_min_anonpriv_port;

	/* holds the tcp tunables */
	struct mod_prop_info_s *tcps_propinfo_tbl;

	/* Hint not protected by any lock */
	uint_t		tcps_next_port_to_try;

	/* TCP bind hash list - all tcp_t with state >= BOUND. */
	struct tf_s	*tcps_bind_fanout;

	/* TCP queue hash list - all tcp_t in case they will be an acceptor. */
	struct tf_s	*tcps_acceptor_fanout;

	/*
	 * MIB-2 stuff for SNMP
	 * Note: tcpInErrs {tcp 15} is accumulated in ip.c
	 */
	kstat_t		*tcps_mibkp;	/* kstat exporting mib2_tcp_t data */
	kstat_t		*tcps_kstat;	/* kstat exporting tcp_stat_t data */

	uint32_t	tcps_iss_incr_extra;
				/* Incremented for each connection */
	kmutex_t	tcps_iss_key_lock;
	MD5_CTX		tcps_iss_key;

	/* Packet dropper for TCP IPsec policy drops. */
	ipdropper_t	tcps_dropper;

	/*
	 * These two variables control the rate for TCP to generate RSTs in
	 * response to segments not belonging to any connections.  We limit
	 * TCP to sent out tcp_rst_sent_rate (ndd param) number of RSTs in
	 * each 1 second interval.  This is to protect TCP against DoS attack.
	 */
	int64_t		tcps_last_rst_intrvl;
	uint32_t	tcps_rst_cnt;

	ldi_ident_t	tcps_ldi_ident;

	/* Used to synchronize access when reclaiming memory */
	mblk_t		*tcps_ixa_cleanup_mp;
	kmutex_t	tcps_ixa_cleanup_lock;
	kcondvar_t	tcps_ixa_cleanup_ready_cv;
	kcondvar_t	tcps_ixa_cleanup_done_cv;

	/* Variables for handling kmem reclaim call back. */
	kmutex_t	tcps_reclaim_lock;
	boolean_t	tcps_reclaim;
	timeout_id_t	tcps_reclaim_tid;
	uint32_t	tcps_reclaim_period;

	/* Listener connection limit configuration. */
	kmutex_t	tcps_listener_conf_lock;
	list_t		tcps_listener_conf;

	/*
	 * Per CPU stats
	 *
	 * tcps_sc: array of pointer to per CPU stats.  The i-th element in the
	 *    array represents the stats of the CPU with cpu_seqid.
	 * tcps_sc_cnt: number of CPU stats in the tcps_sc array.
	 */
	tcp_stats_cpu_t	**tcps_sc;
	int		tcps_sc_cnt;
};

typedef struct tcp_stack tcp_stack_t;

#endif /* _KERNEL */
#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_STACK_H */

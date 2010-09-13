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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_RAWIP_IMPL_H
#define	_RAWIP_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/netstack.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/optcom.h>
#include <inet/tunables.h>

/*
 * ICMP stack instances
 */
struct icmp_stack {
	netstack_t	*is_netstack;	/* Common netstack */
	void		*is_head;	/* Head for list of open icmps */
	mod_prop_info_t	*is_propinfo_tbl; /* holds the icmp tunables */
	kstat_t		*is_ksp;	/* kstats */
	mib2_rawip_t	is_rawip_mib;	/* SNMP fixed size info */
	ldi_ident_t	is_ldi_ident;
};

typedef struct icmp_stack icmp_stack_t;

/* Internal icmp control structure, one per open stream */
typedef	struct icmp_s {
	/*
	 * The addresses and ports in the conn_t and icmp_state are protected by
	 * conn_lock. conn_lock also protects the content of icmp_t.
	 */
	uint_t		icmp_state;	/* TPI state */

	/* Written to only once at the time of opening the endpoint */
	conn_t		*icmp_connp;

	uint_t
	    icmp_hdrincl : 1,		/* IP_HDRINCL option + RAW and IGMP */

	    icmp_pad_to_bit_31: 31;

	icmp6_filter_t	*icmp_filter;		/* ICMP6_FILTER option */

	/* Set at open time and never changed */
	icmp_stack_t	*icmp_is;		/* Stack instance */

	int		icmp_delayed_error;
	kmutex_t	icmp_recv_lock;
	mblk_t		*icmp_fallback_queue_head;
	mblk_t		*icmp_fallback_queue_tail;
	struct sockaddr_storage	icmp_delayed_addr;
} icmp_t;

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	icmp_opt_obj;
extern uint_t		icmp_max_optsize;

extern int	icmp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	icmp_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	icmp_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);
extern mblk_t	*icmp_snmp_get(queue_t *q, mblk_t *mpctl);

extern void	icmp_ddi_g_init(void);
extern void	icmp_ddi_g_destroy(void);

extern sock_lower_handle_t rawip_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);
extern int rawip_fallback(sock_lower_handle_t, queue_t *, boolean_t,
    so_proto_quiesced_cb_t, sock_quiesce_arg_t *);

extern sock_downcalls_t sock_rawip_downcalls;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _RAWIP_IMPL_H */

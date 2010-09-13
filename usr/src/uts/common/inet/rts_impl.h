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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_RTS_IMPL_H
#define	_RTS_IMPL_H

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

/* Named Dispatch Parameter Management Structure */
typedef struct rtsparam_s {
	uint_t	rts_param_min;
	uint_t	rts_param_max;
	uint_t	rts_param_value;
	char	*rts_param_name;
} rtsparam_t;

/*
 * RTS stack instances
 */
struct rts_stack {
	netstack_t		*rtss_netstack;	/* Common netstack */

	caddr_t			rtss_g_nd;
	rtsparam_t		*rtss_params;

	ldi_ident_t		rtss_ldi_ident;
};
typedef struct rts_stack rts_stack_t;

/* Internal routing socket stream control structure, one per open stream */
typedef	struct rts_s {
	krwlock_t	rts_rwlock;	/* Protects most of rts_t */
	uint_t	rts_state;		/* Provider interface state */
	uint_t	rts_error;		/* Routing socket error code */
	uint_t	rts_flag;		/* Pending I/O state */
	uint_t
		rts_hdrincl : 1,	/* IP_HDRINCL option + RAW and IGMP */

		: 0;
	rts_stack_t	*rts_rtss;

	/* Written to only once at the time of opening the endpoint */
	conn_t		*rts_connp;

	kmutex_t	rts_recv_mutex;	/* For recv flow control */
} rts_t;

#define	RTS_WPUT_PENDING	0x1	/* Waiting for write-side to complete */
#define	RTS_WRW_PENDING		0x2	/* Routing socket write in progress */

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	rts_opt_obj;
extern uint_t		rts_max_optsize;

extern void	rts_ddi_g_init(void);
extern void	rts_ddi_g_destroy(void);

extern int	rts_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	rts_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);
extern int	rts_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr);

extern sock_lower_handle_t rts_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);

extern sock_downcalls_t sock_rts_downcalls;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _RTS_IMPL_H */

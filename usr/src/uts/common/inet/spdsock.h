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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_INET_SPDSOCK_H
#define	_INET_SPDSOCK_H

#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SPDSOCK stack instances
 */
struct spd_stack {
	netstack_t		*spds_netstack;	/* Common netstack */

	caddr_t			spds_g_nd;
	struct spdsockparam_s	*spds_params;
	kmutex_t		spds_param_lock;
				/* Protects the NDD variables. */

	/*
	 * To save algorithm update messages that are processed only after
	 * IPsec is loaded.
	 */
	struct spd_ext		*spds_extv_algs[SPD_EXT_MAX + 1];
	mblk_t			*spds_mp_algs;
	struct ipsec_alginfo
			*spds_algs[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];
	int		spds_algs_exec_mode[IPSEC_NALGTYPES];
	kmutex_t		spds_alg_lock;
};
typedef struct spd_stack spd_stack_t;


/*
 * spdsock (PF_POLICY) session state; one per open PF_POLICY socket.
 *
 * These are kept on a linked list by the spdsock module.
 */

typedef struct spdsock_s
{
	uint_t	spdsock_state;	/* TLI gorp */

	minor_t spdsock_minor;

	/*
	 * In-progress SPD_DUMP state, valid if spdsock_dump_req is non-NULL.
	 *
	 * spdsock_dump_req is the request which got us started.
	 * spdsock_dump_head is a reference to a policy head.
	 * spdsock_dump_cur_* tell us where we are in the policy walk,
	 * validated by looking at spdsock_dump_gen vs
	 * dump_head->iph_gen after taking a read lock on the policy
	 * head.
	 */
	mblk_t			*spdsock_dump_req;
	ipsec_policy_head_t 	*spdsock_dump_head;
	uint64_t 		spdsock_dump_gen;
	timeout_id_t		spdsock_timeout;
	mblk_t			*spdsock_timeout_arg;
	int			spdsock_dump_cur_type;
	int			spdsock_dump_cur_af;
	ipsec_policy_t 		*spdsock_dump_cur_rule;
	uint32_t		spdsock_dump_cur_chain;
	uint32_t		spdsock_dump_count;
	spd_stack_t		*spdsock_spds;
	/* These are used for all-polhead dumps. */
	int			spdsock_dump_tun_gen;
	boolean_t		spdsock_dump_active;
	boolean_t		spdsock_dump_tunnel;
	int			spdsock_dump_remaining_polheads;
	ipsec_tun_pol_t		*spdsock_itp;
} spdsock_t;

#define	LOADCHECK_INTERVAL	(drv_usectohz(30000))

/*
 * Socket option boilerplate code.
 */

extern optdb_obj_t	spdsock_opt_obj;
extern uint_t		spdsock_max_optsize;

extern int spdsock_opt_get(queue_t *, int, int, uchar_t *);
extern int spdsock_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
    uint_t *, uchar_t *, void *, cred_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _INET_SPDSOCK_H */

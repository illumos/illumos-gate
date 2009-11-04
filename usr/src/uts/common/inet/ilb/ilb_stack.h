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

#ifndef _INET_ILB_STACK_H
#define	_INET_ILB_STACK_H

#include <sys/netstack.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ilb_rule_s;
struct ilb_hash_s;
struct ilb_timer_s;
struct ilb_conn_s;
struct ilb_conn_hash_s;
struct ilb_sticky_s;
struct ilb_sticky_hash_s;
struct ilb_g_kstat_s;
struct ilb_nat_src_hash_s;

/* Per network stack ILB information */
typedef struct ilb_stack {
	netstack_t			*ilbs_netstack;

	/*
	 * Rule info in a network stack.
	 *
	 * ilbs_rule_head: list of all rules
	 * ilbs_g_lock: lock to protect the rule list
	 * ilbs_rule_hash_size: size of the rule hash table
	 * ilbs_g_hash: the rule hash table
	 * ilbs_rule_taskq: taskq for rule related delayed processing
	 */
	struct ilb_rule_s		*ilbs_rule_head;
	kmutex_t			ilbs_g_lock;
	size_t				ilbs_rule_hash_size;
	struct ilb_hash_s		*ilbs_g_hash;
	taskq_t				*ilbs_rule_taskq;

	/*
	 * NAT connection cache info
	 *
	 * ilbs_conn_hash_szie: size of the conn cache hash table
	 * ilbs_c2s_conn_hash: client to server conn cache hash table
	 * ilbs_s2c_conn_hash: server to client conn cache hash table
	 * ilbs_conn_timer_list: list of all timers for handling conn cache
	 * ilbs_conn_taskq: taskq for conn cache related delayed processing
	 */
	size_t				ilbs_conn_hash_size;
	struct ilb_conn_hash_s		*ilbs_c2s_conn_hash;
	struct ilb_conn_hash_s		*ilbs_s2c_conn_hash;
	struct ilb_timer_s		*ilbs_conn_timer_list;
	taskq_t				*ilbs_conn_taskq;

	/*
	 * Sticky (persistent) cache info
	 *
	 * ilbs_sticky_hash_szie: size of the sticky cache hash table
	 * ilbs_sticky_hash: sticky cache hash table
	 * ilbs_sticky_timer_list: list of all timers for handling sticky cache
	 * ilbs_sticky_taskq: taskq for sticky cache related delayed processing
	 */
	size_t				ilbs_sticky_hash_size;
	struct ilb_sticky_hash_s	*ilbs_sticky_hash;
	struct ilb_timer_s		*ilbs_sticky_timer_list;
	taskq_t				*ilbs_sticky_taskq;

	/*
	 * Info of NAT source address for
	 *
	 * ilbs_nat_src: NAT source hash table
	 * ilbs_nat_src_hash_size: size of the NAT source hash table
	 * ilbs_nat_src_lock: lock for protecting ilbs_nat_src_tid
	 * ilbs_nat_src_tid: ID of the timer handling garbage colllection
	 */
	struct ilb_nat_src_hash_s	*ilbs_nat_src;
	size_t				ilbs_nat_src_hash_size;
	kmutex_t			ilbs_nat_src_lock;
	timeout_id_t			ilbs_nat_src_tid;

	/* NAT conn cache and sticky cache listing related info */

	/* Lock to ensure that all nat listing ops are serialized */
	kmutex_t			ilbs_conn_list_lock;
	kcondvar_t			ilbs_conn_list_cv;
	boolean_t			ilbs_conn_list_busy;
	/* Current position for	listing all conn hash entries */
	size_t				ilbs_conn_list_cur;
	struct ilb_conn_s		*ilbs_conn_list_connp;

	/* Lock to ensure that all sticky listing ops are serialized */
	kmutex_t			ilbs_sticky_list_lock;
	kcondvar_t			ilbs_sticky_list_cv;
	boolean_t			ilbs_sticky_list_busy;
	/* Current position for	listing all sticky hash entries */
	size_t				ilbs_sticky_list_cur;
	struct ilb_sticky_s		*ilbs_sticky_list_curp;

	/* Stack wide ILB kstat */
	kstat_t				*ilbs_ksp;
	struct ilb_g_kstat_s		*ilbs_kstat;
} ilb_stack_t;


#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_STACK_H */

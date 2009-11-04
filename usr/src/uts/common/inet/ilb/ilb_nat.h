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

#ifndef _INET_ILB_NAT_H
#define	_INET_ILB_NAT_H

#include <sys/vmem.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of NAT source address of a rule. */
#define	ILB_MAX_NAT_SRC	10

/* NAT source address hash table. */
typedef struct ilb_nat_src_hash_s {
	list_t		nsh_head;
	kmutex_t	nsh_lock;
	char		nsh_pad[64 - sizeof (list_t) - sizeof (kmutex_t)];
} ilb_nat_src_hash_t;

/*
 * NAT source entry.  Hold the port space for a source addr/back end server
 * pair.
 */
typedef struct ilb_nat_src_entry_s {
	in6_addr_t	nse_src_addr;
	in6_addr_t	nse_serv_addr;
	in_port_t	nse_port;
	vmem_t		*nse_port_arena;
	uint32_t	nse_refcnt;
	kmutex_t	*nse_nsh_lock;
	list_node_t	nse_link;
} ilb_nat_src_entry_t;

/* Struct to hold all NAT source entry of a back end server. */
typedef struct ilb_nat_src_s {
	uint16_t		cur;
	uint16_t		num_src;
	ilb_nat_src_entry_t	*src_list[ILB_MAX_NAT_SRC];
} ilb_nat_src_t;

extern int ilb_create_nat_src(ilb_stack_t *ilbs, ilb_nat_src_t **,
    const in6_addr_t *, in_port_t, const in6_addr_t *, int);
extern void ilb_destroy_nat_src(ilb_nat_src_t **);
extern void ilb_nat_src_timer(void *);
extern void ilb_nat_src_init(ilb_stack_t *);
extern void ilb_nat_src_fini(ilb_stack_t *);

extern ilb_nat_src_entry_t *ilb_alloc_nat_addr(ilb_nat_src_t *, in6_addr_t *,
    in_port_t *, uint16_t *);

extern void ilb_full_nat(int, void *, int, void *, ilb_nat_info_t *, uint32_t,
    uint32_t, boolean_t);
extern void ilb_half_nat(int, void *, int, void *, ilb_nat_info_t *, uint32_t,
    uint32_t, boolean_t);

extern void ilb_nat_icmpv4(mblk_t *, ipha_t *, icmph_t *, ipha_t *,
    in_port_t *, in_port_t *, ilb_nat_info_t *, uint32_t, boolean_t);
extern void ilb_nat_icmpv6(mblk_t *, ip6_t *, icmp6_t *, ip6_t *,
    in_port_t *, in_port_t *, ilb_nat_info_t *, boolean_t);

extern uint32_t ilb_pseudo_sum_v6(ip6_t *, uint8_t);

#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_NAT_H */

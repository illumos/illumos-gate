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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MEMNODE_H
#define	_SYS_MEMNODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#include <sys/lgrp.h>
#include <sys/memlist_plat.h>

/*
 * This file defines the mappings between physical addresses and memory
 * nodes. Memory nodes are defined so that the low-order bits are the
 * memory slice ID and the high-order bits are the SSM nodeid.
 */

/*
 * The MAX_MEM_NODES constant is the maximum number of memory nodes for the
 * unix binary and is used to help size static data structures.  The
 * max_mem_nodes variable is the maximum number of memory nodes for the
 * running platform and may be smaller than MAX_MEM_NODES since the platform
 * may not need to use all of them.
 *
 * The default value of MAX_MEM_NODES is 4 to create enough memory nodes for
 * Chalupa and max_mem_nodes is set to 1 by default since the generic sun4u
 * unix binary mostly includes platforms only needing one memory node.
 * For platforms requiring more than one memory node, max_mem_nodes is set to
 * a bigger value in the lgroup platform initialization routines which are
 * called before the memory nodes are initialized.  Some platforms like
 * Serengeti and Starcat simply define MAX_MEM_NODES to be their respective
 * maximum memory nodes at compile time, since they have their own unix binary
 * and don't share one with any other platform like Enchilada and Chalupa do.
 *
 * For machines that don't support DR, they can set max_mem_nodes to the actual
 * number of memory nodes in the running system instead of the maximum.  The
 * platform controls the mapping of lgroup platform handles and PFNs to memory
 * nodes, so the platform can always make everything work.
 */

#ifndef MAX_MEM_NODES
#define	MAX_MEM_NODES	(4)
#endif	/* MAX_MEM_NODES */

#define	PFN_2_MEM_NODE(pfn)			\
	((max_mem_nodes > 1) ? plat_pfn_to_mem_node(pfn) : 0)

#define	MEM_NODE_2_LGRPHAND(mnode)		\
	((max_mem_nodes > 1) ? plat_mem_node_to_lgrphand(mnode) : \
	    LGRP_DEFAULT_HANDLE)

/*
 * Platmod hooks
 */

extern int plat_pfn_to_mem_node(pfn_t);
extern int plat_lgrphand_to_mem_node(lgrp_handle_t);
extern void plat_assign_lgrphand_to_mem_node(lgrp_handle_t, int);
extern lgrp_handle_t plat_mem_node_to_lgrphand(int);
extern void plat_slice_add(pfn_t, pfn_t);
extern void plat_slice_del(pfn_t, pfn_t);
extern void plat_mem_node_intersect_range(pfn_t, pgcnt_t, int, pgcnt_t *);

#pragma	weak plat_pfn_to_mem_node
#pragma	weak plat_lgrphand_to_mem_node
#pragma	weak plat_mem_node_to_lgrphand
#pragma	weak plat_slice_add
#pragma	weak plat_slice_del
#pragma weak plat_mem_node_intersect_range

struct	mem_node_conf {
	int	exists;		/* only try if set, list may still be empty */
	pfn_t	physbase;	/* lowest PFN in this memnode */
	pfn_t	physmax;	/* highest PFN in this memnode */
};

struct memlist;

extern void startup_build_mem_nodes(prom_memlist_t *, size_t);
extern void mem_node_add_slice(pfn_t, pfn_t);
extern void mem_node_pre_del_slice(pfn_t, pfn_t);
extern void mem_node_post_del_slice(pfn_t, pfn_t, int);
extern int mem_node_alloc(void);
extern pgcnt_t mem_node_memlist_pages(int, struct memlist *);
extern void mem_node_add_slice(pfn_t start, pfn_t end);
extern void mem_node_max_range(pfn_t *, pfn_t *);

extern struct mem_node_conf	mem_node_config[];
extern uint64_t			mem_node_physalign;
extern int			mem_node_pfn_shift;
extern int			max_mem_nodes;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEMNODE_H */

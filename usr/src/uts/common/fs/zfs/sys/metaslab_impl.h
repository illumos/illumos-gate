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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_METASLAB_IMPL_H
#define	_SYS_METASLAB_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/metaslab.h>
#include <sys/space_map.h>
#include <sys/vdev.h>
#include <sys/txg.h>
#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct metaslab_class {
	metaslab_group_t	*mc_rotor;
	uint64_t		mc_allocated;
};

struct metaslab_group {
	kmutex_t		mg_lock;
	avl_tree_t		mg_metaslab_tree;
	uint64_t		mg_aliquot;
	int64_t			mg_bias;
	metaslab_class_t	*mg_class;
	vdev_t			*mg_vd;
	metaslab_group_t	*mg_prev;
	metaslab_group_t	*mg_next;
};

/*
 * Each metaslab's free block list is kept in its own DMU object in the
 * metaslab freelist dataset.  To minimize space consumption, the list
 * is circular.
 *
 * Allocations and frees can happen in multiple transaction groups at
 * the same time, which makes it a bit challening to keep the metaslab
 * consistent.  For example, we cannot allow frees from different
 * transaction groups to be interleaved in the metaslab's free block list.
 *
 * We address this in several ways:
 *
 *	We don't allow allocations from the same metaslab in concurrent
 *	transaction groups.  metaslab_alloc() enforces this by checking
 *	the ms_last_alloc field, which specifies the last txg in which
 *	the metaslab was used for allocations.
 *
 *	We can't segregate frees this way because we can't choose which
 *	DVAs someone wants to free.  So we keep separate in-core freelists
 *	for each active transaction group.  This in-core data is only
 *	written to the metaslab's on-disk freelist in metaslab_sync(),
 *	which solves the interleave problem: we only append frees from
 *	the syncing txg to the on-disk freelist, so the appends all occur
 *	in txg order.
 *
 *	We cannot allow a block which was freed in a given txg to be
 *	allocated again until that txg has closed; otherwise, if we
 *	failed to sync that txg and had to roll back to txg - 1,
 *	changes in txg + 1 could have overwritten the data.  Therefore,
 *	we partition the free blocks into "available" and "limbo" states.
 *	A block is available if the txg in which it was freed has closed;
 *	until then, the block is in limbo.  Each time metaslab_sync() runs,
 *	if first adds any limbo blocks to the avail list, clears the limbo
 *	list, and starts writing the new limbo blocks (i.e. the ones that
 *	were freed in the syncing txg).
 */

struct metaslab {
	kmutex_t	ms_lock;	/* metaslab lock		*/
	space_map_obj_t	*ms_smo;	/* space map object		*/
	uint64_t	ms_last_alloc;	/* txg of last alloc		*/
	uint64_t	ms_usable_end;	/* end of free_obj at last sync	*/
	uint64_t	ms_usable_space; /* usable space at last sync	*/
	metaslab_group_t *ms_group;	/* metaslab group		*/
	avl_node_t	ms_group_node;	/* node in metaslab group tree	*/
	uint64_t	ms_weight;	/* weight vs. others in group	*/
	uint8_t		ms_dirty[TXG_SIZE];	/* per-txg dirty flags	*/
	space_map_t	ms_allocmap[TXG_SIZE];  /* allocated this txg	*/
	space_map_t	ms_freemap[TXG_SIZE];	/* freed this txg	*/
	txg_node_t	ms_txg_node;	/* per-txg dirty metaslab links	*/
	space_map_t	ms_map;		/* in-core free space map	*/
	uint8_t		ms_map_incore;  /* space map contents are valid */
	uint64_t	ms_map_cursor[SPA_ASIZEBITS]; /* XXX -- PPD	*/
};

/*
 * ms_dirty[] flags
 */
#define	MSD_ALLOC	0x01	/* allocated from in this txg		*/
#define	MSD_FREE	0x02	/* freed to in this txg			*/
#define	MSD_ADD		0x04	/* added to the pool in this txg	*/
#define	MSD_CONDENSE	0x08	/* condensed in this txg		*/

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_METASLAB_IMPL_H */

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the RSMPI import side memory segment functions
 * for the Wildcat RSM driver.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <sys/ddimapreq.h>
#include <sys/mkdev.h>
#include <sys/ddi.h>
#include <vm/hat_sfmmu.h>
#include <sys/sunddi.h>

#include <sys/rsm/rsmpi.h>

#include <sys/wrsm_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_plugin.h>

#ifdef DEBUG
#define	DBG_IMPORT		0x004
#define	DBG_IMPORT_EXTRA	0x040
#define	DBG_WARN		0x100

static uint_t wrsm_import_memseg_debug = DBG_WARN;

#define	DPRINTF(a, b) { if (wrsm_import_memseg_debug & a) wrsmdprintf b; }

#else /* DEBUG */
#define	DPRINTF(a, b) { }
#endif /* DEBUG */


/*
 * lock hierarchy:
 *	network->lock
 *	all_importsegs_lock
 *	node->memseg->lock
 *	importseg->rw_lock
 *	iseginfo->lock
 *	iseginfo->network->errorpage_lock
 *
 * Note: it is always safe to take all_importsegs_lock.
 * It is also safe to take network->lock: the network must
 * unregister (unregister_controller), which it can't do
 * until clients all release the network (release_controller).
 * If a client accesses these functions after doing a release
 * controller, all bets are off.
 */


static importseg_t *all_importsegs_hash[WRSM_PTR_HASH_SIZE];


static void send_disconnect_msg(wrsm_node_t *node, iseginfo_t *iseginfo);

static off_t next_smallput_stride = NULL;


/*
 * Find iseginfo in exporting node's hash using segid.
 */
static iseginfo_t *
segid_to_iseginfo(wrsm_node_t *node, rsm_memseg_id_t segid)
{
	iseginfo_t *iseginfo;
	int index;

	ASSERT(MUTEX_HELD(&node->memseg->lock));

	index = WRSM_SEGID_HASH_FUNC(segid);
	ASSERT(index < WRSM_SEGID_HASH_SIZE);
	iseginfo = node->memseg->iseginfo_hash[index];
	DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT, "node %d iseginfo_hash[%d]\n",
	    node->config->cnodeid, index));
	while (iseginfo) {
		DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT, "seg 0x%p segid %d\n",
		    (void *)iseginfo, iseginfo->segid));
		if (iseginfo->segid == segid) {
			return (iseginfo);
		}
		iseginfo = iseginfo->segid_next;
	}
	return (NULL);
}


/*
 * Create a new iseginfo structure, add to hash, lock it.
 *
 * If in the middle of tearing down the session to this node, return
 * a null iseginfo.
 */
static int
new_iseginfo(wrsm_network_t *network, cnodeid_t cnodeid,
    rsm_memseg_id_t segid, iseginfo_t **iseginfop, boolean_t *new)
{
	iseginfo_t *iseginfo, *oseginfo;
	wrsm_node_t *node;
	int index;

	/* allocate memory from our wrsm_arena and zero it */
	iseginfo = wrsm_alloc(sizeof (iseginfo_t), VM_SLEEP);
	bzero(iseginfo, sizeof (iseginfo_t));

	iseginfo->segid = segid;
	iseginfo->send_disconnect = B_TRUE;
	mutex_init(&iseginfo->lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&network->lock);
	node = network->nodes[cnodeid];
	if (node == NULL) {
		/* invalid node */
		mutex_exit(&network->lock);
		mutex_destroy(&iseginfo->lock);
		wrsm_free(iseginfo, sizeof (iseginfo_t));
		return (RSMERR_UNKNOWN_RSM_ADDR);
	}
	mutex_enter(&node->memseg->lock);
	mutex_exit(&network->lock);

	iseginfo->cnodeid = node->config->cnodeid;
	iseginfo->network = network;

	/*
	 * add to node's iseginfo_hash
	 */

	if (node->memseg->removing_session) {
		/*
		 * can't connect to a segment while the exporting
		 * node's session is in the process of being removed
		 */
		mutex_exit(&node->memseg->lock);
		mutex_destroy(&iseginfo->lock);
		wrsm_free(iseginfo, sizeof (iseginfo_t));
		DPRINTF(DBG_IMPORT, (CE_CONT, "new_iseginfo: "
		    "node %d is removing_session; wait_for_unmap %d\n",
		    node->config->cnodeid, node->memseg->wait_for_unmaps));
		return (RSMERR_CONN_ABORTED);
	}

	oseginfo = segid_to_iseginfo(node, segid);
	if (oseginfo) {
		mutex_enter(&oseginfo->lock);
		ASSERT(oseginfo->network->nodes[oseginfo->cnodeid] ==
		    node);

		if (!oseginfo->unpublished) {
			/*
			 * valid iseginfo already exists - return
			 * this segment locked
			 */
			mutex_exit(&node->memseg->lock);
			mutex_destroy(&iseginfo->lock);
			wrsm_free(iseginfo, sizeof (iseginfo_t));
			*iseginfop = oseginfo;
			*new = B_FALSE;
			return (WRSM_SUCCESS);
		} else {
			/*
			 * old iseginfo no longer valid -- can't connect to
			 * this segment id exported by this node until the
			 * old one has been cleaned up.  (This could take a
			 * while if clients have mappings they aren't
			 * releasing.)
			 */

			mutex_exit(&oseginfo->lock);
			mutex_exit(&node->memseg->lock);
			mutex_destroy(&iseginfo->lock);
			wrsm_free(iseginfo, sizeof (iseginfo_t));

			DPRINTF(DBG_IMPORT, (CE_CONT, "new_iseginfo: "
			    "iseginfo %d is unpublished\n", iseginfo->segid));
			return (RSMERR_CONN_ABORTED);
		}
	}

	/*
	 * new iseginfo - add to node's hash
	 */
	index = WRSM_SEGID_HASH_FUNC(segid);
	mutex_enter(&iseginfo->lock);
	iseginfo->segid_next = node->memseg->iseginfo_hash[index];
	node->memseg->iseginfo_hash[index] = iseginfo;
	mutex_exit(&node->memseg->lock);

	*iseginfop = iseginfo;
	*new = B_TRUE;
	return (WRSM_SUCCESS);
}



/*
 * Remove iseginfo structure from exporting node's hash.  Clean up no
 * longer valid mapping information in iseginfo.
 */
static void
remove_iseginfo(iseginfo_t *iseginfo)
{
	wrsm_node_t *node = iseginfo->network->nodes[iseginfo->cnodeid];
	iseginfo_t **isinfop;
	int index;

	DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT, "ctlr %d: remove_iseginfo() "
	    "seg 0x%p segid %d node %d\n", node->network->rsm_ctlr_id,
	    (void *)iseginfo, iseginfo->segid, node->config->cnodeid));

	ASSERT(MUTEX_HELD(&iseginfo->lock));
	ASSERT(node);
	ASSERT(MUTEX_HELD(&node->memseg->lock));

	/*
	 * if session was terminated, other side no longer expects
	 * a disconnect message
	 */
	if (iseginfo->send_disconnect == B_TRUE) {
		send_disconnect_msg(node, iseginfo);
	}

	/*
	 * remove iseginfo from node's hash
	 */

	index = WRSM_SEGID_HASH_FUNC(iseginfo->segid);
	ASSERT(index < WRSM_SEGID_HASH_SIZE);
	isinfop = &(node->memseg->iseginfo_hash[index]);

	/* look for iseginfo in hash */
	while (*isinfop != NULL && *isinfop != iseginfo) {
		isinfop = &((*isinfop)->segid_next);
	}

	if (*isinfop) {
		/* found iseginfo in hash; now remove it */
		*isinfop = iseginfo->segid_next;
#ifdef DEBUG
	} else {
		/* didn't find iseginfo in hash - should never happen */
		DPRINTF(DBG_WARN, (CE_WARN,
		    "iseginfo 0x%p (dev_t %d) not in hash table",
		    (void *)iseginfo, iseginfo->segid));
#endif
	}

	/*
	 * release resources used by iseginfo
	 */
	if (iseginfo->seg_tuples) {
		kmem_free(iseginfo->seg_tuples,
		    iseginfo->num_seg_tuples * sizeof (import_ncslice_t));
		kmem_free(iseginfo->pfns,
		    iseginfo->num_seg_tuples * sizeof (pfn_t));
	}
}

static void
remove_and_destroy_iseginfo(iseginfo_t *iseginfo)
{
	ASSERT(iseginfo->importsegs == NULL);
	remove_iseginfo(iseginfo);
	mutex_exit(&iseginfo->lock);
	mutex_destroy(&iseginfo->lock);
	wrsm_free(iseginfo, sizeof (iseginfo_t));
}


/*
 * Find an iseginfo with specified segid in exporting node's iseginfo hash.
 * Lock both the node and iseginfo (if iseginfo is found).
 */
static iseginfo_t *
lock_node_and_iseginfo(wrsm_node_t *node, rsm_memseg_id_t segid)
{
	iseginfo_t *iseginfo;

	DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT, "ctlr %d: lock_node_and_iseginfo() "
	    "segid %d node %d\n", node->network->rsm_ctlr_id,
	    segid, node->config->cnodeid));

	mutex_enter(&node->memseg->lock);
	iseginfo = segid_to_iseginfo(node, segid);
	if (iseginfo) {
		mutex_enter(&iseginfo->lock);
		if (iseginfo->unpublished) {
			mutex_exit(&iseginfo->lock);
			iseginfo = NULL;
		}
	}
	if (!iseginfo) {
		mutex_exit(&node->memseg->lock);
	}
	return (iseginfo);
}


/*
 * Find an unpublished iseginfo with specified segid in exporting node's
 * iseginfo hash.  Lock both the node and iseginfo (if iseginfo is found).
 */
static iseginfo_t *
lock_node_and_unpublished_iseginfo(wrsm_node_t *node,
    rsm_memseg_id_t segid)
{
	iseginfo_t *iseginfo;

	DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT,
	    "ctlr %d: lock_node_and_unpublished_iseginfo() "
	    "segid %d node %d\n", node->network->rsm_ctlr_id,
	    segid, node->config->cnodeid));

	mutex_enter(&node->memseg->lock);
	iseginfo = segid_to_iseginfo(node, segid);
	if (iseginfo) {
		mutex_enter(&iseginfo->lock);
		if (!iseginfo->unpublished) {
			mutex_exit(&iseginfo->lock);
			iseginfo = NULL;
		}
	}
	if (!iseginfo) {
		mutex_exit(&node->memseg->lock);
	}
	return (iseginfo);
}



/*
 * Find an iseginfo with specified segid in exporting node's iseginfo hash
 * and lock it.
 */
static iseginfo_t *
find_and_lock_iseginfo(wrsm_node_t *node, rsm_memseg_id_t segid)
{
	iseginfo_t *iseginfo;

	iseginfo = lock_node_and_iseginfo(node, segid);
	if (iseginfo) {
		mutex_exit(&node->memseg->lock);
	}
	return (iseginfo);
}





/*
 * Make sure this importseg is still in all_importsegs_hash and still valid
 * (not being destroyed).
 */
int
wrsm_lock_importseg(importseg_t *importseg, krw_t rw)
{
	importseg_t *impsg;
	int err = RSMERR_BAD_SEG_HNDL;
	int index;

	index = WRSM_PTR_HASH_FUNC(importseg);
	ASSERT(index < WRSM_PTR_HASH_SIZE);

	mutex_enter(&all_importsegs_lock);
	impsg = all_importsegs_hash[index];
	while (impsg) {
		if (impsg == importseg) {
			rw_enter(&importseg->rw_lock, rw);
			err = RSM_SUCCESS;
			break;
		}
		impsg = impsg->all_next;
	}
	mutex_exit(&all_importsegs_lock);

	/*
	 * make sure importseg is not currently being removed
	 */
	if (!err && importseg->valid == B_FALSE) {
		rw_exit(&importseg->rw_lock);
		err = RSMERR_BAD_SEG_HNDL;
	}
#ifdef DEBUG
	if (err) {
		DPRINTF(DBG_IMPORT, (CE_CONT, "lock_importseg - "
		    "invalid memseg 0x%p\n", (void *)importseg));
	}
#endif
	return (err);
}



/*
 * Remove kernel mapping to segment.
 */
static void
release_segment_mapping(iseginfo_t *iseginfo)
{
	caddr_t kaddr;
	size_t size;

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	if (iseginfo->size == 0)
		return;

	if (iseginfo->kernel_mapping.seg) {
		kaddr = iseginfo->kernel_mapping.seg;
		size = iseginfo->size;
		DPRINTF(DBG_IMPORT, (CE_CONT, "hat_unload(kas kaddr 0x%p "
		    "size 0x%lx paddr 0x%lx", (void *)kaddr, size,
		    va_to_pa((void *)kaddr)));
		hat_unload(kas.a_hat, kaddr, size, HAT_UNLOAD_UNLOCK);
		DPRINTF(DBG_IMPORT, (CE_CONT, "vmem_free(kaddr 0x%p "
		    "size 0x%lx)", (void *)kaddr, size));
		wrsm_free(kaddr, size);
		iseginfo->kernel_mapping.seg = NULL;
	}
}





/*
 * Remove kernel mappings to barrier page and small put interrupt page.
 */
static void
release_kernel_mappings(iseginfo_t *iseginfo)
{
	int i;
	wrsm_network_t *network = iseginfo->network;

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	DPRINTF(DBG_IMPORT, (CE_CONT, "release_kernel_mappings() iseginfo %d\n",
	    iseginfo->segid));

	if (iseginfo->size == 0)
		return;

	/*
	 * release mapping to barrier page
	 */
	if (iseginfo->kernel_mapping.barrier_page) {
		DPRINTF(DBG_IMPORT, (CE_CONT, "ddi_unmap_regs(kaddr 0x%p "
		    "size 0x%x", (void *)iseginfo->kernel_mapping.barrier_page,
		    MMU_PAGESIZE));
		ddi_unmap_regs(wrsm_ncslice_dip,
		    iseginfo->barrier_tuple.ncslice,
		    &iseginfo->kernel_mapping.barrier_page,
		    iseginfo->barrier_tuple.ncslice_offset,
		    MMU_PAGESIZE);
		iseginfo->kernel_mapping.barrier_page = NULL;
	}

	/*
	 * release mapping to small put interrupt page
	 */
	if (iseginfo->kernel_mapping.small_put_intr) {
		ddi_unmap_regs(wrsm_ncslice_dip,
		    iseginfo->small_put_tuple.ncslice,
		    &iseginfo->kernel_mapping.small_put_intr,
		    iseginfo->small_put_tuple.ncslice_offset,
		    MMU_PAGESIZE);
		iseginfo->kernel_mapping.small_put_intr = NULL;
	}

	if (iseginfo->errorpages) {
		for (i = 0; i < iseginfo->errorpages; i++) {
			wrsm_cmmu_free(network, 1,
			    iseginfo->errorpage_info[i].tuple);
		}
		kmem_free(iseginfo->errorpage_info,
		    iseginfo->errorpages * sizeof (wrsm_errorpage_t));
		iseginfo->errorpages = 0;
	} else {
		mutex_enter(&network->errorpage_lock);
		network->errorpage_mappings -=
		    ((iseginfo->size >> MMU_PAGESHIFT) + 2);
		mutex_exit(&network->errorpage_lock);
	}
}

/*
 * Create kernel mapping to segment.
 */
int
create_segment_mapping(iseginfo_t *iseginfo)
{
	caddr_t kaddr, kaddr8k;
	uint_t seg_perms;
	ddi_map_req_t mr;
	import_ncslice_t *map_tuple;
	int i;
	int err;
	size_t len8k, accumulated_len = 0;
	pfn_t pfn8k;

	DPRINTF(DBG_IMPORT, (CE_CONT, "create_segment_mapping() iseginfo %d\n",
	    iseginfo->segid));

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	if (iseginfo->size == 0)
		return (WRSM_SUCCESS);

	/*
	 * This is not DDI compatible, but there is no DDI compatible way
	 * of mapping in a segment contiguously in the kernel virtual
	 * address space if it is backed by multiple physically
	 * discontiguous regions of "regspec" memory.
	 */

	/*
	 * Allocate a large enough kernel virtual memory region for this
	 * segment
	 */
	ASSERT((iseginfo->size & MMU_PAGEOFFSET) == 0);
	ASSERT(iseginfo->size > 0);
	DPRINTF(DBG_IMPORT, (CE_CONT, "vmem_alloc(size 0x%lx)",
	    iseginfo->size));
	/* allocate memory from our wrsm_arena */
	kaddr = wrsm_alloc(iseginfo->size, VM_NOSLEEP);
	if (kaddr == NULL) {
		/*
		 * not enough space in kernel virtual memory to map
		 * this segment
		 */
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}
	iseginfo->kernel_mapping.seg = kaddr;

	/* LINTED: E_PRECEDENCE_CONFUSION */
	if ((iseginfo->perms == RSM_PERM_RDWR) ||
	    (iseginfo->perms == RSM_PERM_WRITE)) {
		seg_perms = PROT_READ | PROT_WRITE;
	} else {
		seg_perms = PROT_READ;
	}

	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_prot = seg_perms;
	mr.map_flags = DDI_MF_DEVICE_MAPPING;
	mr.map_handlep = NULL;
	mr.map_vers = DDI_MAP_VERSION;

	for (i = 0; i < iseginfo->num_seg_tuples; i++) {
		map_tuple = &(iseginfo->seg_tuples[i]);
		mr.map_obj.rnumber = map_tuple->ncslice;

		/*
		 * get the physical address for this ncslice
		 */
		ASSERT((map_tuple->len & MMU_PAGEOFFSET) == 0);
		accumulated_len += map_tuple->len;
		ASSERT(accumulated_len <= iseginfo->size);
		err = ddi_map(wrsm_ncslice_dip, &mr, map_tuple->ncslice_offset,
		    map_tuple->len, (caddr_t *)&(iseginfo->pfns[i]));
		if (err) {
			return (RSMERR_INSUFFICIENT_RESOURCES);
		}

		/*
		 * set up mapping to segment
		 */
		/*
		 * Force 8k tte entries to be used, so that the error
		 * mapping (which also uses 8k pages) will work without
		 * trouble.  (HAT_LOAD_REMAP doesn't handle switching
		 * from other page sizes to 8k pages.)
		 */
		kaddr8k = kaddr;
		pfn8k = iseginfo->pfns[i];
		for (len8k = 0; len8k < map_tuple->len; len8k += MMU_PAGESIZE) {
			DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT,
			    "hat_devload(kas kaddr "
			    "0x%p size 0x%x paddr 0x%lx perms 0x%x flags 0x%x",
			    (void *)kaddr8k, MMU_PAGESIZE,
			    pfn8k, seg_perms | MEMSEG_DEVLOAD_ATTRS,
			    HAT_LOAD_LOCK));
			hat_devload(kas.a_hat, kaddr8k, MMU_PAGESIZE,
			    pfn8k, seg_perms | MEMSEG_DEVLOAD_ATTRS,
			    HAT_LOAD_LOCK);
			kaddr8k += MMU_PAGESIZE;
			pfn8k += (MMU_PAGESIZE >> MMU_PAGESHIFT);
		}

		DPRINTF(DBG_IMPORT, (CE_CONT, "mapped seg offset 0x%lx "
		    "len 0x%lx to paddr 0x%lx (ncslice 0x%x, offset 0x%lx)\n",
		    map_tuple->seg_offset,
		    map_tuple->len,
		    (iseginfo->pfns[i] << MMU_PAGESHIFT),
		    map_tuple->ncslice,
		    map_tuple->ncslice_offset));

		kaddr += map_tuple->len;
	}

	return (RSM_SUCCESS);
}




/*
 * Create kernel mappings to barrier page and small put interrupt page.
 */
static int
create_kernel_mappings(iseginfo_t *iseginfo)
{
	int err;
	int i;
	int pages;
	wrsm_network_t *network = iseginfo->network;

	DPRINTF(DBG_IMPORT, (CE_CONT, "create_kernel_mappings() iseginfo %d\n",
	    iseginfo->segid));

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	if (iseginfo->size == 0)
		return (WRSM_SUCCESS);

	/*
	 * Reserve mappings to this controller's error page (enough for the
	 * segment, barrier page and interrupt page).  The kernel only
	 * supports a fixed number of locked mappings from one address
	 * space to the same physical address, so if can't reserve enough
	 * mappings, allocate additional error pages (cmmu entries) for
	 * this segment.
	 */
	mutex_enter(&network->errorpage_lock);
	if ((network->errorpage_mappings +
	    (iseginfo->size >> MMU_PAGESHIFT) + 2) < MAX_HBLK_LCKCNT) {
		network->errorpage_mappings +=
		    ((iseginfo->size >> MMU_PAGESHIFT) + 2);
		mutex_exit(&network->errorpage_lock);
	    } else {
		mutex_exit(&network->errorpage_lock);
		/*
		 * Can't set up error mappings using default error page.
		 * Allocate one or more private error pages for this
		 * segment.
		 */
		pages = (iseginfo->size >> MMU_PAGESHIFT) + 2;
		iseginfo->errorpages = (pages / MAX_HBLK_LCKCNT) +
		    ((pages % MAX_HBLK_LCKCNT) ? 1 : 0);
		iseginfo->errorpage_info = kmem_zalloc(iseginfo->errorpages *
		    sizeof (wrsm_errorpage_t), KM_SLEEP);

		for (i = 0; i < iseginfo->errorpages; i++) {
			if ((err = wrsm_nc_create_errorpage(network,
			    &(iseginfo->errorpage_info[i].tuple),
			    &(iseginfo->errorpage_info[i].pfn),
			    B_FALSE)) != WRSM_SUCCESS) {
				int j;
				for (j = 0; j < i; j++) {
					wrsm_cmmu_free(network, 1,
					    iseginfo->errorpage_info[j].tuple);
				}
				kmem_free(iseginfo->errorpage_info,
				    iseginfo->errorpages *
				    sizeof (wrsm_errorpage_t));
				iseginfo->errorpages = 0;

				return (RSMERR_INSUFFICIENT_RESOURCES);
			}
		}
	}


	/*
	 * map in the barrier page
	 */
	err = ddi_map_regs(wrsm_ncslice_dip,
	    iseginfo->barrier_tuple.ncslice,
	    &iseginfo->kernel_mapping.barrier_page,
	    iseginfo->barrier_tuple.ncslice_offset,
	    MMU_PAGESIZE);
	DPRINTF(DBG_IMPORT, (CE_CONT, "kaddr 0x%p = ddi_map_regs(size 0x%x)",
	    (void *)iseginfo->kernel_mapping.barrier_page, MMU_PAGESIZE));
	if (err) {
		release_kernel_mappings(iseginfo);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}
	DPRINTF(DBG_IMPORT, (CE_CONT, "mapped barrier page "
	    "to paddr 0x%lx (ncslice 0x%x, offset 0x%lx)\n",
	    va_to_pa(iseginfo->kernel_mapping.barrier_page),
	    iseginfo->barrier_tuple.ncslice,
	    iseginfo->barrier_tuple.ncslice_offset));


	/*
	 * map in the interrupt page
	 */
	err = ddi_map_regs(wrsm_ncslice_dip,
	    iseginfo->small_put_tuple.ncslice,
	    &iseginfo->kernel_mapping.small_put_intr,
	    iseginfo->small_put_tuple.ncslice_offset,
	    MMU_PAGESIZE);
	DPRINTF(DBG_IMPORT, (CE_CONT, "kaddr 0x%p = ddi_map_regs(size 0x%x)",
	    (void *)iseginfo->kernel_mapping.small_put_intr, MMU_PAGESIZE));
	if (err) {
		release_kernel_mappings(iseginfo);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

	/*
	 * assign each new segment a different stride in which to do
	 * small puts.  Just one stride is used per segment to simplify
	 * flushing outstanding smallput interrupts.
	 */
	iseginfo->kernel_mapping.small_put_offset =
	    iseginfo->kernel_mapping.small_put_intr +
	    next_smallput_stride;
	next_smallput_stride =
	    (next_smallput_stride + WCI_CLUSTER_STRIPE_STRIDE) &
	    WCI_CLUSTER_STRIPE_MASK;

	DPRINTF(DBG_IMPORT, (CE_CONT, "mapped small put page "
	    "to paddr 0x%lx (ncslice 0x%x, offset 0x%lx)\n",
	    va_to_pa(iseginfo->kernel_mapping.small_put_intr),
	    iseginfo->small_put_tuple.ncslice,
	    iseginfo->small_put_tuple.ncslice_offset));

	return (WRSM_SUCCESS);
}


/*
 * Modify kernel mappings to segment, barrier page and small put interrupt
 * page so that they all point to the local loopback error page.
 */
static void
error_kernel_mappings(iseginfo_t *iseginfo)
{
	caddr_t kaddr;
	wrsm_network_t *network = iseginfo->network;
	off_t offset;
	uint_t seg_perms;
	pfn_t errorpage_pfn;
	int i, mappings;

	DPRINTF(DBG_IMPORT, (CE_CONT, "error_kernel_mappings() iseginfo %d\n",
	    iseginfo->segid));

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	if (iseginfo->size == 0)
		return;

	/* LINTED: E_PRECEDENCE_CONFUSION */
	if ((iseginfo->perms == RSM_PERM_RDWR) ||
	    (iseginfo->perms == RSM_PERM_WRITE)) {
		seg_perms = PROT_READ | PROT_WRITE;
	} else {
		seg_perms = PROT_READ;
	}

	/*
	 * Change segment mapping (if there is one) to point to loopback
	 * error page.  Mappings to this page were reserved in
	 * create_kernel_mappings().
	 */
	kaddr = iseginfo->kernel_mapping.seg;
	mappings = 0;
	i = 0;
	errorpage_pfn = iseginfo->errorpages ? iseginfo->errorpage_info[0].pfn :
	    network->errorpage_pfn;
	if (kaddr) {
		offset = 0;
		while (offset < iseginfo->size) {
			DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT,
			    "hat_devload(kas kaddr 0x%p "
			    "size 0x%x paddr 0x%lx perms 0x%x flags 0x%x",
			    (void *)kaddr,
			    MMU_PAGESIZE,
			    errorpage_pfn,
			    seg_perms | MEMSEG_DEVLOAD_ATTRS,
			    HAT_LOAD_REMAP));
			hat_devload(kas.a_hat,
			    kaddr,
			    MMU_PAGESIZE,
			    errorpage_pfn,
			    seg_perms | MEMSEG_DEVLOAD_ATTRS,
			    HAT_LOAD_REMAP);

			offset += MMU_PAGESIZE;
			kaddr += MMU_PAGESIZE;
			mappings++;
			if (mappings == MAX_HBLK_LCKCNT) {
				/*
				 * If there are more than MAX_HBLK_LCKCNT
				 * mappings, we must have allocated private
				 * error pages for it.
				 */
				i++;
				ASSERT(i < iseginfo->errorpages);
				errorpage_pfn =
				    iseginfo->errorpage_info[i].pfn;
				mappings = 0;
			}
		}
	}


	/*
	 * change barrier page mapping to loopback error page
	 */
	if (iseginfo->kernel_mapping.barrier_page) {
		DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT,
		    "hat_devload(kas kaddr 0x%p "
		    "size 0x%x paddr 0x%lx perms 0x%x flags 0x%x",
		    (void *)iseginfo->kernel_mapping.barrier_page,
		    MMU_PAGESIZE,
		    errorpage_pfn,
		    PROT_READ | PROT_WRITE | MEMSEG_DEVLOAD_ATTRS,
		    HAT_LOAD_REMAP));
		hat_devload(kas.a_hat,
		    iseginfo->kernel_mapping.barrier_page,
		    MMU_PAGESIZE,
		    errorpage_pfn,
		    PROT_READ | PROT_WRITE | MEMSEG_DEVLOAD_ATTRS,
		    HAT_LOAD_REMAP);
	}

	mappings++;
	if (mappings == MAX_HBLK_LCKCNT) {
		/*
		 * If there are more than MAX_HBLK_LCKCNT
		 * mappings, we must have allocated private
		 * error pages for it.
		 */
		i++;
		ASSERT(i < iseginfo->errorpages);
		errorpage_pfn = iseginfo->errorpage_info[i].pfn;
		mappings = 0;
	}

	/*
	 * change small put interrupt page mapping to loopback error page
	 */
	if (iseginfo->kernel_mapping.small_put_intr) {
		DPRINTF(DBG_IMPORT_EXTRA, (CE_CONT,
		    "hat_devload(kas kaddr 0x%p "
		    "size 0x%x paddr 0x%lx perms 0x%x flags 0x%x",
		    (void *)iseginfo->kernel_mapping.small_put_intr,
		    MMU_PAGESIZE,
		    errorpage_pfn,
		    PROT_READ | PROT_WRITE | MEMSEG_DEVLOAD_ATTRS,
		    HAT_LOAD_REMAP));
		hat_devload(kas.a_hat,
		    iseginfo->kernel_mapping.small_put_intr,
		    MMU_PAGESIZE,
		    errorpage_pfn,
		    PROT_READ | PROT_WRITE | MEMSEG_DEVLOAD_ATTRS,
		    HAT_LOAD_REMAP);
	}
}


/*
 * Lost access to this iseginfo - tear down mappings and mark
 * related importsegs as no longer valid.
 */
static void
lost_iseginfo(iseginfo_t *iseginfo)
{
	importseg_t *importseg;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: lost_iseginfo() segid %d "
	    "node %d\n", iseginfo->network->rsm_ctlr_id,
	    iseginfo->segid, iseginfo->cnodeid));

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	/*
	 * This iseginfo is no longer backed by the remote node's segment,
	 * so remove it from the remote node's list.  However don't free it
	 * until the last importseg has been freed.
	 */
	if (iseginfo->unpublished) {
		/* already cleaned up after this segment */
		return;
	}

	iseginfo->unpublished = B_TRUE;

	if (iseginfo->kernel_users) {
		/* change kernel mappings to use loopback error page */
		error_kernel_mappings(iseginfo);
	}

	/*
	 * notify any clients that have done mappings that the
	 * mappings are no longer valid
	 */
	for (importseg = iseginfo->importsegs; importseg;
	    importseg = importseg->iseg_next) {
		importseg->unpublished = B_TRUE;
		if (importseg->mappings) {
			/*
			 * Callback client to notify them mappings
			 * are no longer valid.
			 */
			if (importseg->mapping_callback) {
				(*(importseg->mapping_callback))(
				    importseg->mapping_callback_arg);
			}
		}
	}

	if (iseginfo->wait_for_unmaps == 0) {
		/*
		 * All mappings to segment cleaned up. Segment is no longer
		 * valid (except for access from remaining importsegs).
		 */
		remove_iseginfo(iseginfo);
	}
}



/*
 * Send message to specified node to collect information about segment.
 */
static int
send_connect_msg(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	wrsm_network_t *network = node->network;
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	connect_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	connect_resp_t recvargs;
	int err = WRSM_SUCCESS;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_connect_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (connect_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_CONNECT;
	args.segid = iseginfo->segid;

	bcopy(&args, &(msg->body), sizeof (args));
	if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
	    != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not delivered or
		 * response not received).  (Transport Layer tears down the
		 * session if there is a message delivery failure).
		 */
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

#ifdef DEBUG
	if (wrsm_import_memseg_debug & DBG_IMPORT_EXTRA) {
		wrsm_tl_dump_message("CONNECT_RESPONSE: ", recvmsg);
	}
#endif
	if (recvmsg->header.message_type !=
	    WRSM_MSG_SEGMENT_CONNECT_RESPONSE) {
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

	bcopy(&recvmsg->body, &recvargs, sizeof (recvargs));

	if (recvargs.err) {
		switch (recvargs.err) {
			case ENOENT:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
			case EACCES:
				err = RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR;
				break;
			default:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
		}
		return (err);
	}

	/*
	 * save information in iseginfo
	 */
	iseginfo->perms = recvargs.perms;
	iseginfo->size = recvargs.size;
	iseginfo->num_seg_tuples = recvargs.num_seg_tuples;
	iseginfo->seg_tuples = (import_ncslice_t *)kmem_zalloc(
	    iseginfo->num_seg_tuples * sizeof (import_ncslice_t), KM_SLEEP);
	iseginfo->pfns = (pfn_t *)kmem_zalloc(
	    iseginfo->num_seg_tuples * sizeof (pfn_t), KM_SLEEP);

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_connect_msg() "
	    "got num_seg_tuples %d size 0x%lx perms 0x%x\n",
	    network->rsm_ctlr_id, iseginfo->num_seg_tuples,
	    iseginfo->size, iseginfo->perms));

	return (WRSM_SUCCESS);
}




/*
 * Send message to specified node to collect small put page mapping
 * information for segment.
 */
static int
send_smallputmap_msg(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	wrsm_network_t *network = node->network;
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	smallputmap_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	smallputmap_resp_t recvargs;
	int err = WRSM_SUCCESS;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_smallputmap_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (smallputmap_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_SMALLPUTMAP;
	args.segid = iseginfo->segid;

	bcopy(&args, &(msg->body), sizeof (args));
	if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
	    != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not delivered or
		 * response not received).  (Transport Layer tears down the
		 * session if there is a message delivery failure).
		 */
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

#ifdef DEBUG
	if (wrsm_import_memseg_debug & DBG_IMPORT_EXTRA)
		wrsm_tl_dump_message("SMALLPUTMAP_RESPONSE: ", recvmsg);
#endif
	if (recvmsg->header.message_type !=
	    WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE) {
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

	bcopy(&recvmsg->body, &recvargs, sizeof (recvargs));

	if (recvargs.err) {
		switch (recvargs.err) {
			case ENOENT:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
			case EACCES:
				err = RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR;
				break;
			default:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
		}
		return (err);
	}

	/*
	 * save information in iseginfo
	 */
	iseginfo->small_put_tuple = recvargs.small_put_tuple;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_smallputmap_msg() "
	    "got small put intr ncslice %d offset 0x%lx\n",
	    network->rsm_ctlr_id, iseginfo->small_put_tuple.ncslice,
	    iseginfo->small_put_tuple.ncslice_offset));

	return (WRSM_SUCCESS);
}




/*
 * Send message to specified node to collect barrier page mapping
 * information for segment.
 */
static int
send_barriermap_msg(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	wrsm_network_t *network = node->network;
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	barriermap_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	barriermap_resp_t recvargs;
	int err = WRSM_SUCCESS;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_barriermap_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (barriermap_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_BARRIERMAP;
	args.segid = iseginfo->segid;

	bcopy(&args, &(msg->body), sizeof (args));
	if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
	    != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not delivered or
		 * response not received).  (Transport Layer tears down the
		 * session if there is a message delivery failure).
		 */
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

#ifdef DEBUG
	if (wrsm_import_memseg_debug & DBG_IMPORT_EXTRA)
		wrsm_tl_dump_message("BARRIERMAP_RESPONSE: ", recvmsg);
#endif
	if (recvmsg->header.message_type !=
	    WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE) {
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}

	bcopy(&recvmsg->body, &recvargs, sizeof (recvargs));

	if (recvargs.err) {
		switch (recvargs.err) {
			case ENOENT:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
			case EACCES:
				err = RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR;
				break;
			default:
				err = RSMERR_SEG_NOT_PUBLISHED;
				break;
		}
		return (err);
	}

	/*
	 * save information in iseginfo
	 */
	iseginfo->barrier_tuple = recvargs.barrier_tuple;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_barriermap_msg() "
	    "got barrier_page ncslice %d offset 0x%lx\n",
	    network->rsm_ctlr_id, iseginfo->barrier_tuple.ncslice,
	    iseginfo->barrier_tuple.ncslice_offset));

	return (WRSM_SUCCESS);
}





/*
 * Send message to specified node to collect segment mapping information
 * for segment.
 */
static int
send_segmap_msg(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	segmap_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	wrsm_network_t *network = node->network;
	segmap_resp_t recvargs;
	int err = WRSM_SUCCESS;
	int tuple_index;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: send_segmap_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (segmap_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_SEGMAP;
	args.segid = iseginfo->segid;

	tuple_index = 0;
	while (tuple_index < iseginfo->num_seg_tuples) {

		args.tuple_index = tuple_index;

		bcopy(&args, &msg->body, sizeof (args));
		if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
		    != WRSM_SUCCESS) {
			/*
			 * This node is not responding (message not
			 * delivered or response not received).  (Transport
			 * Layer tears down the session if there is a
			 * message delivery failure).
			 */
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}

#ifdef DEBUG
		if (wrsm_import_memseg_debug & DBG_IMPORT_EXTRA)
			wrsm_tl_dump_message("SEGMAP_RESPONSE: ", recvmsg);
#endif
		if (recvmsg->header.message_type !=
		    WRSM_MSG_SEGMENT_SEGMAP_RESPONSE) {
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}

		bcopy(&recvmsg->body, &recvargs, sizeof (recvargs));

		if (recvargs.err) {
			switch (recvargs.err) {
				case ENOENT:
					err = RSMERR_SEG_NOT_PUBLISHED;
					break;
				case EACCES:
					/* tab oddly to make cstyle happy */
				err = RSMERR_SEG_NOT_PUBLISHED_TO_RSM_ADDR;
					break;
				default:
					err = RSMERR_SEG_NOT_PUBLISHED;
					break;
			}
			return (err);
		}

		if (recvargs.num_tuples > MAP_MSG_TUPLES ||
		    (recvargs.num_tuples + tuple_index) >
		    iseginfo->num_seg_tuples) {
			/*
			 * number of tuples in map response can't really
			 * fit in buffer (bad msg?) or doesn't match the
			 * number we were told to expect in connect response
			 */
			DPRINTF(DBG_WARN, (CE_WARN, "send_segmap_msg: "
			    "received %d tuples > max (%d) per message or "
			    "> expected remaining (%d - %d)\n",
			    recvargs.num_tuples, (int)MAP_MSG_TUPLES,
			    iseginfo->num_seg_tuples, tuple_index));
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}

		/*
		 * save information in iseginfo
		 */
		bcopy(&(recvargs.tuples), &(iseginfo->seg_tuples[tuple_index]),
		    recvargs.num_tuples * sizeof (import_ncslice_t));

		tuple_index += recvargs.num_tuples;
	}

	return (WRSM_SUCCESS);
}





/*
 * Notify exporting node that this segment is no longer being accessed.
 */
static void
send_disconnect_msg(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	disconnect_msg_t args;
	wrsm_network_t *network = node->network;

	ASSERT(iseginfo->send_disconnect);

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: "
	    "send_disconnect_msg() node %d\n", network->rsm_ctlr_id,
	    node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (disconnect_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_DISCONNECT;
	args.segid = iseginfo->segid;

	bcopy(&args, &msg->body, sizeof (args));
	(void) wrsm_tl_dg(network, node->config->cnodeid, msg);
}







/*
 * Segment is no longer being published.  Attempt clean up after all
 * connections.  If there are no mappings to segment, notify sender
 * that there are no longer any connections.
 */
void
wrsm_unpublish_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	unpublish_msg_t args;
#ifdef DEBUG
	cnodeid_t cnodeid = msg->header.source_cnode;
#endif
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	unpublish_resp_t respargs;
	iseginfo_t *iseginfo;


	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: unpublish_msg_evt() "
	    "node %d\n", network->rsm_ctlr_id, cnodeid));

	if (node == NULL) {
		/* non-existent node */
		return;
	}

	if (wrsm_tl_rxhandler_sessionid(network, msg) == B_FALSE) {
		/* session must not be valid */
		return;
	}

	bcopy(&msg->body, &args, sizeof (args));

	respmsg->header.message_type = WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE;

	/*
	 * does segment exist?
	 */
	iseginfo = lock_node_and_iseginfo(node, args.segid);
	if (iseginfo == NULL || iseginfo->importsegs == NULL) {
		/*
		 * no iseginfo, or no connections to iseginfo
		 */
		if (iseginfo) {
			/* no connections to iseginfo -- free it */
			ASSERT(iseginfo->wait_for_unmaps == 0);
			iseginfo->send_disconnect = B_FALSE;
			remove_and_destroy_iseginfo(iseginfo);
			mutex_exit(&node->memseg->lock);
		}
		DPRINTF(DBG_IMPORT, (CE_CONT,
		    "sending WC_DISCONNECTED response\n"));
		respargs.status = WC_DISCONNECTED;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	/*
	 * We have some cleanup work to do.  Let the other side
	 * know we got the message, but aren't finished cleaning up.
	 */
	DPRINTF(DBG_IMPORT, (CE_CONT, "sending WC_CONNECTED response\n"));
	respargs.status = WC_CONNECTED;
	bcopy(&respargs, &respmsg->body, sizeof (respargs));
	(void) wrsm_tl_rsp(network, msg, respmsg);

	/*
	 * Tear down mappings to this iseginfo.  Notify remote node
	 * when all mappings have been torn down.
	 */
	lost_iseginfo(iseginfo);

	mutex_exit(&node->memseg->lock);
	mutex_exit(&iseginfo->lock);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));
}





/*
 * Remember new permissions for segment.
 */
void
wrsm_access_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	access_msg_t args;
#ifdef DEBUG
	cnodeid_t cnodeid = msg->header.source_cnode;
#endif
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	iseginfo_t *iseginfo;

	DPRINTF(DBG_IMPORT, (CE_CONT, "ctlr %d: access_msg_evt() "
	    "node %d\n", network->rsm_ctlr_id, cnodeid));

	if (node == NULL) {
		/* non-existent node */
		return;
	}

	if (wrsm_tl_rxhandler_sessionid(network, msg) == B_FALSE) {
		/* session must not be valid */
		return;
	}

	bcopy(&msg->body, &args, sizeof (args));

	/*
	 * Record new permissions
	 */

	iseginfo = find_and_lock_iseginfo(node, args.segid);

	if (iseginfo) {
		iseginfo->perms = args.perms;
		mutex_exit(&iseginfo->lock);
	}

	/*
	 * send acknowledgement
	 */

	respmsg->header.message_type = WRSM_MSG_ACK;
	(void) wrsm_tl_rsp(network, msg, respmsg);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}



/*
 * Collect information about segmenet from exporting node.  Verify that
 * it is valid.
 */
static int
iseginfo_fetch_info(wrsm_node_t *node, iseginfo_t *iseginfo)
{
	int err;
	int i, last_tuple;
	size_t offset;

	ASSERT(MUTEX_HELD(&iseginfo->lock));

	/*
	 * collect segment info from exporter
	 */
	if ((err = send_connect_msg(node, iseginfo)) != WRSM_SUCCESS) {
		/* don't send disconnect message */
		iseginfo->send_disconnect = B_FALSE;
		return (err);
	}

	if (iseginfo->size == 0) {
		/*
		 * no need to fetch mappings for a 0 length segment
		 */
		return (WRSM_SUCCESS);
	}



	/*
	 * collect mapping info for small put interrupt from exporter
	 */
	if ((err = send_smallputmap_msg(node, iseginfo)) != WRSM_SUCCESS) {
		return (err);
	}

	if (iseginfo->small_put_tuple.ncslice !=
	    node->config->exported_ncslices.id[0]) {
		DPRINTF(DBG_WARN, (CE_WARN, "iseginfo_fetch_info: "
		    "received bad small_put_tuple ncslice %d tuple %d\n",
		    iseginfo->small_put_tuple.ncslice,
		    iseginfo->small_put_tuple.ncslice));
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}


	/*
	 * collect mapping info for barrier page from exporter
	 */
	if ((err = send_barriermap_msg(node, iseginfo)) != WRSM_SUCCESS) {
		return (err);
	}

	if (iseginfo->barrier_tuple.ncslice !=
	    node->config->exported_ncslices.id[0]) {
		DPRINTF(DBG_WARN, (CE_WARN, "iseginfo_fetch_info: "
		    "received bad barrier_tuple ncslice %d tuple %d\n",
		    iseginfo->barrier_tuple.ncslice,
		    iseginfo->barrier_tuple.ncslice));
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}


	/*
	 * collect mapping info for segment from exporter
	 */
	if ((err = send_segmap_msg(node, iseginfo)) != WRSM_SUCCESS) {
		return (err);
	}

	offset = 0;
	last_tuple = 0;
	for (i = 0; i < iseginfo->num_seg_tuples; i++) {

		/*
		 * verify that this ncslice is exported by the remote node
		 */
		if (iseginfo->seg_tuples[i].ncslice !=
		    node->config->exported_ncslices.id[last_tuple]) {
			for (last_tuple = 0; last_tuple < WRSM_NODE_NCSLICES;
			    last_tuple++) {
				if (iseginfo->seg_tuples[i].ncslice ==
				    node->config->
				    exported_ncslices.id[last_tuple])
					break;
			}
		}
		if (last_tuple == WRSM_NODE_NCSLICES) {
			/*
			 * Node is claiming it exports an ncslice it doesn't!
			 * Something must be wrong with connection.
			 */
			DPRINTF(DBG_WARN, (CE_WARN, "iseginfo_fetch_info: "
			    "segmap received bad ncslice %d tuple %d\n",
			    iseginfo->seg_tuples[i].ncslice, i));
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}

		if (iseginfo->seg_tuples[i].seg_offset != offset) {
			/* part of segment doesn't have a mapping! */
			DPRINTF(DBG_WARN, (CE_WARN, "iseginfo_fetch_info: "
			    "segmap received bad info in tuple %d\n", i));
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}
		offset += iseginfo->seg_tuples[i].len;
	}

	return (WRSM_SUCCESS);
}



/*
 * The session to the specified node has been torn down.  Clean up
 * references to any segments imported from this node.
 */
boolean_t
iseginfo_sess_teardown(wrsm_node_t *node)
{
	iseginfo_t *iseginfo;
	int i;

	DPRINTF(DBG_IMPORT, (CE_CONT, "iseginfo_sess_teardown"));

	/*
	 * it is presumed that at this point the node was removed from the
	 * cluster_members_bits registers in all wcis
	 */

	ASSERT(MUTEX_HELD(&node->memseg->lock));

	node->memseg->removing_session = B_TRUE;

	/*
	 * Clean up iseginfos imported from remote node.  The node lock
	 * could be held for a long time, but seeing as the node is
	 * considered unreachable, this shouldn't really be a problem.
	 */
	for (i = 0; i < WRSM_SEGID_HASH_SIZE; i++) {
		iseginfo = node->memseg->iseginfo_hash[i];
		while (iseginfo) {
			mutex_enter(&iseginfo->lock);
			iseginfo->send_disconnect = B_FALSE;
			lost_iseginfo(iseginfo);
			mutex_exit(&iseginfo->lock);
			iseginfo = iseginfo->segid_next;
		}
	}

	if (node->memseg->wait_for_unmaps == 0) {
		/*
		 * new session can be established once all mappings
		 * to node are torn down
		 */
		node->memseg->removing_session = B_FALSE;
	}

	return (!node->memseg->removing_session);
}



/*
 * The controller is being removed -- all clients have called
 * release_controller, so it should be ok to remove objects the client may
 * not have bothered to clean up.
 */
void
wrsm_free_importsegs(wrsm_network_t *network)
{
	importseg_t *importseg;
	importseg_t **importsegp, **impisegp;
	iseginfo_t *iseginfo;
	wrsm_node_t *node;
	int i;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_free_importseg: ctlr %d\n",
	    network->rsm_ctlr_id));

	mutex_enter(&network->lock);

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node) {
			mutex_enter(&node->memseg->lock);
			if (node->memseg->removing_session == B_TRUE) {
				/* assume mappings have been removed */
				wrsm_sess_unreferenced(network, i);
				node->memseg->removing_session = B_FALSE;
			}
			mutex_exit(&node->memseg->lock);
		}
	}

	if (network->memseg->import_count == 0) {
		mutex_exit(&network->lock);
		return;
	}

	mutex_enter(&all_importsegs_lock);
	for (i = 0; i < WRSM_SEGID_HASH_SIZE; i++) {
		importsegp = &(all_importsegs_hash[i]);
		while (*importsegp != NULL) {
			importseg = *importsegp;
			if (importseg->network == network) {
				/*
				 * remove importseg from all_importsegs_hash
				 */
				*importsegp = importseg->all_next;
				rw_enter(&importseg->rw_lock, RW_WRITER);
				/*
				 * remove importseg from iseginfo list
				 */
				iseginfo = importseg->iseginfo;
				mutex_enter(&iseginfo->lock);
				impisegp = &(iseginfo->importsegs);
				while (*impisegp != importseg) {
					impisegp = &((*impisegp)->iseg_next);
				}
				ASSERT(*impisegp);
				*impisegp = importseg->iseg_next;
				if (importseg->kernel_user) {
					ASSERT(iseginfo->kernel_users);
					iseginfo->kernel_users--;
					if (iseginfo->kernel_users == 0)
						release_segment_mapping(
						    iseginfo);
				}
				if (iseginfo->importsegs == NULL) {
					release_kernel_mappings(iseginfo);
					mutex_exit(&iseginfo->lock);
					mutex_destroy(&iseginfo->lock);
					kmem_free(iseginfo,
					    sizeof (iseginfo_t));
				} else {
					mutex_exit(&iseginfo->lock);
				}
				rw_exit(&importseg->rw_lock);
				kmem_free(importseg, sizeof (importseg_t));
				ASSERT(network->memseg->import_count > 0);
				network->memseg->import_count--;
			} else {
			    importsegp = &((*importsegp)->all_next);
			}
		}
	}
	mutex_exit(&all_importsegs_lock);

#ifdef DEBUG
	if (network->memseg->import_count > 0) {
		DPRINTF(DBG_WARN, (CE_WARN, "wrsm_free_exportseg: network "
		    "importseg count %d after exportseg cleanup\n",
		    network->memseg->import_count));
	}
#endif
	mutex_exit(&network->lock);
}



/*
 *
 * RSM functions
 *
 */



int
wrsmrsm_connect(rsm_controller_handle_t controller,
    rsm_addr_t addr, rsm_memseg_id_t segid,
    rsm_memseg_import_handle_t *im_memseg)
{
	wrsm_network_t *network = (wrsm_network_t *)controller;
	wrsm_node_t *node;
	importseg_t *importseg;
	iseginfo_t *iseginfo;
	cnodeid_t cnodeid;
	boolean_t new;
	int index;
	int err;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_connect(ctlr %d cnode %ld "
	    "segid %d)\n", network->rsm_ctlr_id, addr, segid));

	if (wrsm_nc_ctlr_to_network(network->rsm_ctlr_id) != network) {
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_connect - "
		    "invalid network 0x%p\n", (void *)network));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	if (addr >= WRSM_MAX_CNODES) {
		/*
		 * wrsm hardware addresses must be cnodeids
		 */
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_connect: bad rsm_addr "
		    "%ld\n", addr));
		return (RSMERR_UNKNOWN_RSM_ADDR);
	}
	cnodeid = addr;
	node = network->nodes[cnodeid];

	/*
	 * create importseg structure for this connection
	 */
	importseg = kmem_zalloc(sizeof (importseg_t), KM_SLEEP);
	importseg->valid = B_TRUE;
	rw_init(&importseg->rw_lock, NULL, RW_DRIVER, NULL);
	importseg->barrier_mode = RSM_BARRIER_MODE_IMPLICIT; /* default */


	/*
	 * get existing or create new iseginfo for this <node, segid>
	 * and return it locked
	 */
	if ((err = new_iseginfo(network, cnodeid, segid, &iseginfo, &new)) !=
	    WRSM_SUCCESS) {
		rw_destroy(&importseg->rw_lock);
		kmem_free(importseg, sizeof (importseg_t));
		return (err);
	}

	if (new) {
		/*
		 * First import of this <node, segid>:  collect mapping
		 * information from the node exporting it.
		 */
		ASSERT(MUTEX_HELD(&iseginfo->lock));
		err = iseginfo_fetch_info(node, iseginfo);
		if (err) {
			/* had a problem collecting mapping info */
			iseginfo->unpublished = B_TRUE;
			mutex_exit(&iseginfo->lock);
			if (lock_node_and_unpublished_iseginfo(node,
			    segid) == iseginfo) {
				remove_and_destroy_iseginfo(iseginfo);
				mutex_exit(&node->memseg->lock);
				kmem_free(importseg, sizeof (importseg_t));
			}
			if (err == RSMERR_RSM_ADDR_UNREACHABLE) {
				wrsm_sess_teardown(network, cnodeid);
			}
			return (err);
		}

		/* set up mappings to interrupt and barrier pages */
		err = create_kernel_mappings(iseginfo);
		if (err) {
			/* had a problem setting up mappings */
			iseginfo->unpublished = B_TRUE;
			mutex_exit(&iseginfo->lock);
			if (lock_node_and_unpublished_iseginfo(node,
			    segid) == iseginfo) {
				remove_and_destroy_iseginfo(iseginfo);
				mutex_exit(&node->memseg->lock);
				kmem_free(importseg, sizeof (importseg_t));
			}
			return (err);
		}
	}


	/*
	 * add importseg to list of importsegs for this iseginfo
	 */
	importseg->iseg_next = iseginfo->importsegs;
	iseginfo->importsegs = importseg;
	importseg->iseginfo = iseginfo;
	importseg->network = iseginfo->network;

	mutex_exit(&iseginfo->lock);

	/*
	 * add to all_importsegs_hash
	 */
	index = WRSM_PTR_HASH_FUNC(importseg);
	mutex_enter(&network->lock);
	network->memseg->import_count++;
	mutex_exit(&network->lock);
	mutex_enter(&all_importsegs_lock);
	importseg->all_next = all_importsegs_hash[index];
	all_importsegs_hash[index] = importseg;
	mutex_exit(&all_importsegs_lock);

	*im_memseg = (rsm_memseg_import_handle_t)importseg;
	return (RSM_SUCCESS);
}





/*
 * destroy this importseg handle
 */
int
wrsmrsm_disconnect(rsm_memseg_import_handle_t im_memseg)
{
	importseg_t *importseg = (importseg_t *)im_memseg;
	importseg_t **importsegp;
	iseginfo_t *iseginfo;
	wrsm_network_t *network;
	int err;
	int index;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_disconnect(0x%p)\n",
	    (void *)importseg));

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	if (importseg->have_mappings) {
		rw_exit(&importseg->rw_lock);
		return (RSMERR_SEG_IN_USE);
	}

	network = importseg->network;
	importseg->valid = B_FALSE;

	/*
	 * remove from iseginfo importseg list
	 */
	iseginfo = importseg->iseginfo;
	mutex_enter(&iseginfo->lock);
	importsegp = &(iseginfo->importsegs);
	while (*importsegp != importseg) {
		importsegp = &((*importsegp)->iseg_next);
	}
	ASSERT(*importsegp);
	*importsegp = (*importsegp)->iseg_next;
	if (importseg->kernel_user) {
		ASSERT(iseginfo->kernel_users);
		iseginfo->kernel_users--;
		if (iseginfo->kernel_users == 0)
			release_segment_mapping(iseginfo);
	}

	if (iseginfo->unpublished && iseginfo->importsegs == NULL) {
		/*
		 * Just removed the last importseg from a no longer valid
		 * iseginfo.  There are now no references to iseginfo, so
		 * it is safe to free it.
		 */
		release_kernel_mappings(iseginfo);
		mutex_exit(&iseginfo->lock);
		mutex_destroy(&iseginfo->lock);
		DPRINTF(DBG_IMPORT, (CE_CONT,
		    "freeing unpublished iseginfo\n"));
		kmem_free(iseginfo, sizeof (iseginfo_t));
	} else {
		mutex_exit(&iseginfo->lock);
	}


	/*
	 * Remove from all_importsegs_hash.
	 * importseg->rw_lock can't be held prior to taking
	 * all_importsegs_lock.
	 */
	index = WRSM_PTR_HASH_FUNC(importseg);
	rw_exit(&importseg->rw_lock);
	mutex_enter(&all_importsegs_lock);
	rw_enter(&importseg->rw_lock, RW_WRITER);
	for (importsegp = &(all_importsegs_hash[index]);
	    *importsegp != NULL;
	    importsegp = &((*importsegp)->all_next)) {
		if (*importsegp == importseg) {
			*importsegp = importseg->all_next;
			break;
		}
	}
	mutex_exit(&all_importsegs_lock);
	rw_exit(&importseg->rw_lock);
	mutex_enter(&network->lock);
	network->memseg->import_count--;
	mutex_exit(&network->lock);

	rw_destroy(&importseg->rw_lock);
	kmem_free(importseg, sizeof (importseg_t));

	return (RSM_SUCCESS);
}



int
wrsmrsm_map(rsm_memseg_import_handle_t im_memseg, off_t offset,
    size_t len, size_t *map_len, dev_info_t **dipp, uint_t *dev_register,
    off_t *dev_offset, rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t arg)
{
	importseg_t *importseg = (importseg_t *)im_memseg;
	wrsm_node_t *node;
	wrsm_network_t *network;
	iseginfo_t *iseginfo;
	import_ncslice_t *seg_tuples;
	int num_seg_tuples, i;
	cnodeid_t cnodeid;
	int err;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_map(0x%p)\n",
	    (void *)importseg));


	if (len <= 0) {
		return (RSMERR_BAD_LENGTH);
	}

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	/* segment size never changes, so check immediately */
	if ((offset + len) > importseg->iseginfo->size) {
		rw_exit(&importseg->rw_lock);
		return (RSMERR_BAD_LENGTH);
	}

	/*
	 * Release the importseg lock, take the exporting node's lock, then
	 * retake the importseg lock.
	 */
	cnodeid = importseg->iseginfo->cnodeid;
	network = importseg->iseginfo->network;
	rw_exit(&importseg->rw_lock);

	mutex_enter(&network->lock);
	if (!network->nodes[cnodeid]) {
		mutex_exit(&network->lock);
		return (RSMERR_CONN_ABORTED);
	}
	node = network->nodes[cnodeid];
	mutex_enter(&node->memseg->lock);
	mutex_exit(&network->lock);

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) !=
	    RSM_SUCCESS) {
		mutex_exit(&node->memseg->lock);
		return (err);
	}

	if (importseg->unpublished) {
		/*
		 * new mappings not allowed on a segment that has
		 * been unpublished
		 */
		mutex_exit(&node->memseg->lock);
		rw_exit(&importseg->rw_lock);
		return (RSMERR_CONN_ABORTED);
	}

	iseginfo = importseg->iseginfo;

	/*
	 * remember that map has been called on this segment
	 */

	if (importseg->have_mappings == B_FALSE) {
		importseg->have_mappings = B_TRUE;

		mutex_enter(&iseginfo->lock);
		iseginfo->wait_for_unmaps++;
		if (iseginfo->wait_for_unmaps == 1) {
			node->memseg->wait_for_unmaps++;
		}

		mutex_exit(&iseginfo->lock);
	}

	mutex_exit(&node->memseg->lock);


	/*
	 * Calculate the ncslice and offset within the slice that maps to
	 * the requested segment offset.  Also determine the size of the
	 * contiguous region starting at this offset that maps to the
	 * segment.
	 */

	num_seg_tuples = importseg->iseginfo->num_seg_tuples;
	seg_tuples = importseg->iseginfo->seg_tuples;

	for (i = 0; i < num_seg_tuples; i++) {
		if (offset < (seg_tuples[i].seg_offset + seg_tuples[i].len)) {
			/*
			 * offset falls within this ncslice region
			 */
			*dev_register = seg_tuples[i].ncslice;
			*dev_offset = seg_tuples[i].ncslice_offset +
				(offset - seg_tuples[i].seg_offset);
			*map_len = seg_tuples[i].len -
			    (offset - seg_tuples[i].seg_offset);
			if (*map_len > len) {
				*map_len = len;
			}
			break;
		}
	}

	/* It is not possible that the desired offset does not have a mapping */
	ASSERT(i < num_seg_tuples);

	*dipp = wrsm_ncslice_dip;


	/*
	 * record the mapping-no-longer-valid callback and arg for this
	 * importseg.
	 */
	importseg->mapping_callback = callback;
	importseg->mapping_callback_arg = arg;

	rw_exit(&importseg->rw_lock);

	return (RSM_SUCCESS);
}


/*
 * one rsm_unmap() call cancels all previous rsm_map calls
 */
int
wrsmrsm_unmap(rsm_memseg_import_handle_t im_memseg)
{
	importseg_t *importseg = (importseg_t *)im_memseg;
	wrsm_network_t *network;
	wrsm_node_t *node;
	iseginfo_t *iseginfo;
	cnodeid_t cnodeid;
	int err;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsmrsm_unmap(0x%p)\n",
	    (void *)importseg));

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	/*
	 * Release the importseg lock, take the exporting node's lock, then
	 * retake the importseg lock.  If this is the last mapping for the
	 * segment, and for this node, change segment/node states to
	 * reflect this.
	 */

	cnodeid = importseg->iseginfo->cnodeid;
	network = importseg->iseginfo->network;
	rw_exit(&importseg->rw_lock);

	mutex_enter(&network->lock);
	if (!network->nodes[cnodeid]) {
		mutex_exit(&network->lock);
		return (RSMERR_CONN_ABORTED);
	}
	node = network->nodes[cnodeid];
	mutex_enter(&node->memseg->lock);
	mutex_exit(&network->lock);

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) !=
	    RSM_SUCCESS) {
		return (err);
	}

	iseginfo = importseg->iseginfo;
	mutex_enter(&iseginfo->lock);

	if (!iseginfo->wait_for_unmaps) {
		/*
		 * segment not mapped, so do nothing
		 */
		mutex_exit(&iseginfo->lock);
		mutex_exit(&node->memseg->lock);
		rw_exit(&importseg->rw_lock);
		return (RSM_SUCCESS);
	}

	importseg->have_mappings = B_FALSE;
	iseginfo->wait_for_unmaps--;

	if (iseginfo->wait_for_unmaps == 0) {
		if (iseginfo->unpublished) {
			remove_iseginfo(iseginfo);
		}

		node->memseg->wait_for_unmaps--;
		if (node->memseg->wait_for_unmaps == 0) {
			if (node->memseg->removing_session == B_TRUE) {

				/*
				 * Make sure session state reflects that
				 * there are no more references to this
				 * node.
				 */
				wrsm_sess_unreferenced(node->network,
				    node->config->cnodeid);
				node->memseg->removing_session = B_FALSE;
			}
		}
	}
	mutex_exit(&node->memseg->lock);
	mutex_exit(&iseginfo->lock);

	importseg->mapping_callback = NULL;
	importseg->mapping_callback_arg = NULL;

	rw_exit(&importseg->rw_lock);

	return (RSM_SUCCESS);
}

/* RSMAPI helper functions */

/*
 * returns the locked iseginfo that corresponds to ctrl_num,
 * remote_cnode, and segid.
 * Returns RSM_SUCCESS upon successful completion.
 * If an iseginfo is successfully returned, the CALLER must RELEASE
 * the iseginfo->mutex.
 */
int
wrsm_memseg_remote_node_to_iseginfo(uint32_t ctrl_num,
    cnodeid_t remote_cnode, rsm_memseg_id_t segid,
    iseginfo_t **iseginfo)

{
	wrsm_network_t *network;
	wrsm_node_t *node;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_memseg_remote_node_to_iseginfo"
	    " controller num %d remote cnode %d", ctrl_num, remote_cnode));

	network = wrsm_nc_ctlr_to_network(ctrl_num);

	if (network == NULL) {
		return (ENXIO);
	}
	mutex_enter(&network->lock);
	node = network->nodes[remote_cnode];

	/*
	 * we know that the network can't be removed because we are using
	 * either an ioctl or mmap to call this function. The driver will
	 * not allow the network to be removed while in use, hence, we do
	 * not need to grab and hold wrsm_networks_lock
	 */
	if (node == NULL) {
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_memseg_remote_node_to"
		    "_iseginfo node NULL"));
		mutex_exit(&network->lock);
		return (EBADF);
	}

	*iseginfo = find_and_lock_iseginfo(node, segid);
	mutex_exit(&network->lock);

	if (*iseginfo == NULL) {
		DPRINTF(DBG_IMPORT, (CE_WARN,
		    "wrsm_memseg_remote_node_to_iseginfo NO iseginfo found"));
		return (EBADF);
	}

	ASSERT ((*iseginfo)->cnodeid == remote_cnode);
	return (RSM_SUCCESS);
}


/* ARGSUSED */
int
wrsm_memseg_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp,
    off_t len, unsigned int prot, unsigned int maxprot,
    unsigned int flags, cred_t *cred)
{
	wrsm_plugin_offset_t pseudo_offset;
	uint32_t rsm_ctrl_id;
	iseginfo_t *iseginfo = NULL;
	int error;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_segmap\n"));
	if (len != WRSM_PAGESIZE) {
		DPRINTF(DBG_IMPORT, (CE_WARN, "Invalid PAGESIZE\n"));
		return (EINVAL);
	}
	/* minor number is the controller number */
	rsm_ctrl_id = getminor(dev);

	pseudo_offset.val = (int64_t)off;
	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_memseg_segmap  segment %d "
	    "for controller id %d export cnode %d ",
	    pseudo_offset.bit.segment_id, rsm_ctrl_id,
	    (cnodeid_t)pseudo_offset.bit.export_cnodeid))

	/*
	 * Get iseginfo for this controller, cnodeid, and segment_id.
	 * iseginfo is returned locked.
	 */
	error = wrsm_memseg_remote_node_to_iseginfo(rsm_ctrl_id,
	    (cnodeid_t)pseudo_offset.bit.export_cnodeid,
	    pseudo_offset.bit.segment_id, &iseginfo);

	if (error != RSM_SUCCESS) {
		cmn_err(CE_WARN, "wrsm_memseg_segmap: unable to find matching "
		    " segment  for controller id %d export cnode %d\n",
		    rsm_ctrl_id, (cnodeid_t)pseudo_offset.bit.export_cnodeid);
		return (error);
	}

	/*
	 * page_type field represents the type of page trying to be mapped.
	 * those types are Interrupt, Barrier,  barrier registers (CESR and
	 * wci_cluster_error_count mapped in via page 0 of ncslice)
	 * and Reconfiguration  counter.
	 */

	if (pseudo_offset.bit.page_type == WRSM_MMAP_RECONFIG) {
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_segmap RECONFIG"));
		if (prot != (PROT_READ | PROT_USER)) {
			DPRINTF(DBG_WARN, (CE_WARN, "wrsm_memseg_segmap failed:"
			    " Only read permission allowed with Reconfig"
			    " mapping  cntrl %d, export_cnode %d, segment %d",
			    rsm_ctrl_id, pseudo_offset.bit.export_cnodeid,
			    pseudo_offset.bit.segment_id));
			mutex_exit(&iseginfo->lock);
			return (EACCES);
		}
	}
	mutex_exit(&iseginfo->lock);
	return (devmap_setup(dev, off, asp, addrp, len, prot,
	    maxprot, flags, cred));
}

/* ARGSUSED */
int
wrsm_memseg_devmap(dev_t dev, devmap_cookie_t handle, offset_t off,
    size_t len, size_t *maplen, uint_t model)

{

	int error;
	offset_t offset;
	wrsm_plugin_offset_t pseudo_offset;
	uint32_t rsm_ctrl_id;
	iseginfo_t *iseginfo = NULL;
	uint_t rnumber;
	dev_info_t *dip;

	/* Set up data access attribute structure */
	struct ddi_device_acc_attr wrsm_acc_attr = {
	    DDI_DEVICE_ATTR_V0,
	    DDI_NEVERSWAP_ACC,
	    DDI_STRICTORDER_ACC
	};

	if (len != WRSM_PAGESIZE) {
		return (EINVAL);
	}

	pseudo_offset.val = (int64_t)off;

	DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_devmap"));
	rsm_ctrl_id = getminor(dev);


	/*
	 * Get iseginfo for this controller, cnodeid, and segment_id.
	 * iseginfo is returned locked.
	 */
	error = wrsm_memseg_remote_node_to_iseginfo(rsm_ctrl_id,
	    (cnodeid_t)pseudo_offset.bit.export_cnodeid,
	    pseudo_offset.bit.segment_id, &iseginfo);

	if (error != RSM_SUCCESS) {
		cmn_err(CE_WARN, "wrsm_devmap: unable to find matching segment"
		    " for controller id %d\n", rsm_ctrl_id);
		return (error);
	}

	switch (pseudo_offset.bit.page_type) {
	case WRSM_MMAP_BARRIER_SCRATCH:
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_devmap barrier scratch"
		    " page for controller id %d", rsm_ctrl_id));

		dip = wrsm_ncslice_dip;
		offset = iseginfo->barrier_tuple.ncslice_offset;
		rnumber = iseginfo->barrier_tuple.ncslice;
		if (iseginfo->barrier_tuple.len != len) {
			mutex_exit(&iseginfo->lock);
			return (ENXIO);
		}
		break;

	case WRSM_MMAP_BARRIER_REGS:
		/*
		 * From WCI-2 CESR, wci_cluster_error_count registers
		 * and write lockout registers are visible through page 0 of
		 * the remotes node's ncslice
		 */
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_devmap barrier  ncslice"
		    " for CRS's on  controller id %d\n", rsm_ctrl_id));

		dip = wrsm_ncslice_dip;
		offset = 0;
		rnumber = iseginfo->barrier_tuple.ncslice;
		if (iseginfo->barrier_tuple.len != len) {
			mutex_exit(&iseginfo->lock);
			return (ENXIO);
		}
		break;

	case WRSM_MMAP_RECONFIG:
		DPRINTF(DBG_IMPORT, (CE_CONT, "wrsm_devmap route_counter, "
		    "rerouting, and striping for controller id %d",
		    rsm_ctrl_id));
		/*
		 * special case of wrsm_devmap. maps kernel memory
		 * rather than device memory for the network->route_counter
		 * and the network->routing and striping.
		 * The plugin needs these counters to implement
		 * barriers.
		 */
		offset = 0;
		if (iseginfo->network->dip == NULL) {
			cmn_err(CE_WARN, "wrsm_devmap network dev_info_t not"
			    " defined for controller id %d", rsm_ctrl_id);
			mutex_exit(&iseginfo->lock);
			return (ENXIO);
		    }
		/* Set up the kernel mapping */
		error = devmap_umem_setup(handle, iseginfo->network->dip,
		    NULL, iseginfo->network->route_cookie, offset, len,
		    PROT_READ | PROT_USER, 0, NULL);
		*maplen = len;
		mutex_exit(&iseginfo->lock);
		if (error != 0)
			return (EINVAL);
		else
			return (RSM_SUCCESS);

	default:
		/* this case should NOT occur */
		cmn_err(CE_WARN, "wrsm_devmap invalid page_type"
		    " for controller id %d", rsm_ctrl_id);
		mutex_exit(&iseginfo->lock);
		return (ENXIO);
	}

	/* Set up the device mapping */
	mutex_exit(&iseginfo->lock);
	error = devmap_devmem_setup(handle, dip, NULL, rnumber,
	    offset, len, PROT_ALL, DEVMAP_DEFAULTS, &wrsm_acc_attr);
	/* acknowledge the entire range */

	*maplen = len;
	if (error != 0)
		return (EINVAL);
	else
		return (RSM_SUCCESS);

}

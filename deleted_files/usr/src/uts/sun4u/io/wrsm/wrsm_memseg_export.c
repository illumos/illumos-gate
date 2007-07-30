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
 * This file implements the RSMPI export side memory segment functions
 * for the Wildcat RSM driver.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/buf.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/ddimapreq.h>

#include <sys/rsm/rsmpi.h>

#include <sys/wrsm_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_intr.h>

#ifdef DEBUG
#define	DBG_WARN		0x001
#define	DBG_EXPORT		0x002
#define	DBG_EXPORT_EXTRA	0x040

static uint_t wrsm_export_memseg_debug = DBG_WARN;

#define	DPRINTF(a, b) { if (wrsm_export_memseg_debug & a) wrsmdprintf b; }

#else /* DEBUG */
#define	DPRINTF(a, b) { }
#endif /* DEBUG */

static int wrsm_hw_protection = 0;


/*
 * lock hierarchy:
 *	network->lock
 *	all_exportsegs_lock
 *	exportseg->lock
 *	node->memseg->lock
 *
 * Note: it is always safe to take all_exportsegs_lock.
 * It is also safe to take network->lock: the network must
 * unregister (unregister_controller), which it can't do
 * until clients all release the network (release_controller).
 * If a client accesses these functions after doing a release
 * controller, all bets are off.
 */


static exportseg_t *all_exportsegs_hash[WRSM_PTR_HASH_SIZE];



/*
 * Find the right starting cmmugrp for offset <off>.  <sz> is the size of
 * the region starting at <off> that falls within this cmmugrp.  <ci> is
 * the index of the cmmu entry within the entire cmmugrp's tuples array of
 * the entry for this offset.
 */
static void
get_start_cmmugrp(cmmugrp_t **grpp, size_t off, unsigned *ci, size_t *sz)
{
	off_t remainder;

	while ((*grpp)->offset + (*grpp)->len < off) {
		(*grpp) = (*grpp)->next;
		ASSERT(grpp);
	}
	ASSERT((*grpp)->offset <= off);
	ASSERT((*grpp)->offset + (*grpp)->len > off);
	remainder = off - (*grpp)->offset;
	ASSERT(remainder < (*grpp)->len);
	*sz = (*grpp)->len - remainder;
	*ci = remainder / (*grpp)->pgbytes;
}


/*
 * Get the next cmmugrp.  <cc> is the index into the new cmmugrp's tuples
 * array.  <ci> is the cmmu entry within the tuple.  (Both are set to 0.)
 */
static void
get_next_cmmugrp(cmmugrp_t **grpp, unsigned *cc, unsigned *ci, size_t *sz,
    wrsm_cmmu_tuple_t **tp)
{
	*grpp = (*grpp)->next;
	ASSERT(*grpp);
	*sz = (*grpp)->len;
	*cc = 0;
	*ci = 0;
	*tp = &((*grpp)->tuples[(*cc)]);
}


/*
 * Get the starting tuple and index into this tuple within cmmugrp <grp>
 * for this offset.  <cc> is the index into the cmmugrp's tuples array.
 * <tp> is the tuple.  The index into the cmmgrup for this offset is passed
 * in through <ci>.  <ci> is modified to contain the cmmu entry within the tuple
 * for this offset.
 */
static void
get_start_entry(cmmugrp_t *grp, wrsm_cmmu_tuple_t **tp, unsigned *cc,
    unsigned *ci)
{
	(*cc) = 0;
	*tp = &(grp->tuples[(*cc)]);
	while ((*tp)->count <= *ci) {
		*ci -= (*tp)->count;
		(*cc)++;
		ASSERT((*cc) < grp->num_tuples);
		(*tp) = &(grp->tuples[(*cc)]);
		ASSERT((*tp));
		ASSERT(*ci < (*tp)->count);
	}

	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "get_start_entry: tuple_index %d "
	    "cmmu_index %d\n", *cc, *ci));
}


/*
 * Get next entry from this tuple.  If no more entries from this tuple, use
 * entries from next tuple.  <cc> is the index into the tuples array.  <tp>
 * is the tuple.  <ci> is the cmmu entry within the tuple for this offset.
 */
void
get_next_entry(wrsm_cmmu_tuple_t *tuple_list, wrsm_cmmu_tuple_t **tp,
    unsigned *cc, unsigned *ci)
{
	(*ci)++;
	if ((*ci) == (*tp)->count) {
		(*cc)++;
		(*tp) = &(tuple_list[(*cc)]);
		(*ci) = 0;
	}
	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "get_next_entry: tuple_index %d "
	    "cmmu_index %d\n", *cc, *ci));
}


/*
 * Get the number of entries in this cmmugrp needed to cover region of size
 * <len>, or the maximum number of entries.  <sz> is the size in bytes of
 * the cmmugrp.  <pgbytes> is the number of bytes covered by each entry.
 * <num> returns the number of entries.
 */
static void
get_num_entries(size_t *len, unsigned *num, size_t sz, size_t pgbytes)
{
	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "get_num_entries start: len 0x%lx "
	    "num %d sz 0x%lx pgbytes 0x%lx\n", *len, *num, sz, pgbytes));
	if ((*len) > sz) {
		(*num) = sz / pgbytes;
		(*len) -= sz;
	} else {
		ASSERT((*len) % pgbytes == 0);
		(*num) = (*len) / pgbytes;
		(*len) = 0;
	}
	ASSERT((*num) >= 1);
	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "get_num_entries end: len 0x%lx "
	    "num %d sz 0x%lx pgbytes 0x%lx\n", *len, *num, sz, pgbytes));
}




/*
 * Find exportseg structure in network exportseg hash from segment id.
 */
static exportseg_t *
segid_to_exportseg(wrsm_network_t *network, rsm_memseg_id_t segid)
{
	int index;
	exportseg_t *exportseg;

	ASSERT(MUTEX_HELD(&network->lock));

	index = WRSM_SEGID_HASH_FUNC(segid);
	ASSERT(index < WRSM_SEGID_HASH_SIZE);
	exportseg = network->memseg->exportseg_hash[index];
	while (exportseg) {
		if (exportseg->segid == segid)
			return (exportseg);
		exportseg = exportseg->segid_next;
	}

	return (NULL);
}



/*
 * Set segid of exportseg, add to network hash table.
 */
static int
exportseg_set_segid(exportseg_t *exportseg, rsm_memseg_id_t segid)
{
	wrsm_network_t *network = exportseg->network;
	int index;
	boolean_t found = B_FALSE;
	exportseg_t *expsg;

	ASSERT(MUTEX_HELD(&exportseg->lock));

	/*
	 * release exportseg lock in order to take network lock
	 */
	index = WRSM_PTR_HASH_FUNC(exportseg);
	mutex_exit(&exportseg->lock);
	mutex_enter(&network->lock);
	mutex_enter(&all_exportsegs_lock);

	expsg = all_exportsegs_hash[index];
	while (expsg) {
		if (expsg == exportseg) {
			mutex_enter(&exportseg->lock);
			found = B_TRUE;
			break;
		}
		expsg = expsg->all_next;
	}
	mutex_exit(&all_exportsegs_lock);
	if (!found) {
		mutex_exit(&network->lock);
		return (RSMERR_BAD_SEG_HNDL);
	}

	if (exportseg->state != memseg_unpublished) {
		/* segment is already published */
		mutex_exit(&network->lock);
		return (RSMERR_SEG_ALREADY_PUBLISHED);
	}

	if (segid_to_exportseg(network, segid)) {
		/* segment id already in use */
		mutex_exit(&network->lock);
		return (RSMERR_SEGID_IN_USE);
	}

	exportseg->segid = segid;
	exportseg->state = memseg_published;
	network->memseg->export_published++;

	/*
	 * add to hash
	 */

	index = WRSM_SEGID_HASH_FUNC(segid);
	ASSERT(index < WRSM_SEGID_HASH_SIZE);
	exportseg->segid_next = network->memseg->exportseg_hash[index];
	network->memseg->exportseg_hash[index] = exportseg;

	mutex_exit(&network->lock);

	return (RSM_SUCCESS);
}


/*
 * Stop using current segment id, and remove exportseg structure from
 * network hash.  Note:  exportseg is prevented from disappearing until
 * exportseg->state is unpublished.
 */
static void
exportseg_unset_segid(exportseg_t *exportseg, rsm_memseg_id_t segid)
{
	wrsm_network_t *network = exportseg->network;
	exportseg_t **exportsegp;
	int index;

	index = WRSM_SEGID_HASH_FUNC(segid);
	ASSERT(index < WRSM_SEGID_HASH_SIZE);

	mutex_enter(&network->lock);

	/*
	 * find and remove exportseg from hash table
	 */
	exportsegp = &(network->memseg->exportseg_hash[index]);

	while (*exportsegp != NULL && *exportsegp != exportseg) {
		exportsegp = &((*exportsegp)->segid_next);
	}

	if (*exportsegp == NULL) {
		/* someone else already unpublished this segment */
		DPRINTF(DBG_EXPORT, (CE_NOTE, "exportseg %p (segid %d) not "
		    "in hash table", (void *) exportseg, exportseg->segid));
		mutex_exit(&network->lock);
		return;
	}

	/*
	 * Found exportseg; remove from segid hash table.
	 * If exportseg is in segid hash table, it cannot
	 * be in unpublished state.
	 */
	mutex_enter(&exportseg->lock);
	*exportsegp = (*exportsegp)->segid_next;
	network->memseg->export_published--;
	mutex_exit(&network->lock);

	ASSERT(exportseg->state != memseg_unpublished);
	exportseg->state = memseg_unpublished;
	mutex_exit(&exportseg->lock);
}


/*
 * Find an exportseg with specified segid in network's exportseg hash and
 * lock it.
 */
static exportseg_t *
find_and_lock_exportseg(wrsm_network_t *network, rsm_memseg_id_t segid)
{
	exportseg_t *exportseg = NULL;
	mutex_enter(&network->lock);
	exportseg = segid_to_exportseg(network, segid);
	if (exportseg)
		mutex_enter(&exportseg->lock);
	mutex_exit(&network->lock);

	return (exportseg);
}




/*
 * Make sure this exportseg is still in all_exportsegs_hash.
 */
static int
lock_exportseg(exportseg_t *exportseg)
{
	exportseg_t *expsg;
	uint_t index;
	int err = RSMERR_BAD_SEG_HNDL;

	index = WRSM_PTR_HASH_FUNC(exportseg);
	ASSERT(index < WRSM_PTR_HASH_SIZE);

	mutex_enter(&all_exportsegs_lock);
	expsg = all_exportsegs_hash[index];
	while (expsg) {
		if (expsg == exportseg) {
			mutex_enter(&exportseg->lock);
			err = RSM_SUCCESS;
			break;
		}
		expsg = expsg->all_next;
	}
	mutex_exit(&all_exportsegs_lock);

	/*
	 * make sure exportseg is not currently being removed
	 */
	if ((err == RSM_SUCCESS) && (exportseg->valid == B_FALSE)) {
		mutex_exit(&exportseg->lock);
		err = RSMERR_BAD_SEG_HNDL;
	}

#ifdef DEBUG
	if (err == RSMERR_BAD_SEG_HNDL) {
		DPRINTF(DBG_EXPORT, (CE_CONT, "lock_exportseg - "
		    "invalid memseg 0x%p\n", (void *)exportseg));
	}
#endif
	return (err);
}





/*
 * Free all cmmu entries for this exported segment.
 */
static void
mseg_free_cmmus(exportseg_t *exportseg)
{
	cmmugrp_t *cmmugrp, *ocmmugrp;
	wrsm_cmmu_t cmmu;
	wrsm_cmmu_index_t index;
	unsigned  count;
	unsigned i, j;

	DPRINTF(DBG_EXPORT, (CE_CONT, "mseg_free_cmmus() exportseg 0x%p\n",
	    (void *)exportseg));

	cmmu.entry_0.bit.valid = B_FALSE;

	cmmugrp = exportseg->cmmugrps;
	while (cmmugrp != NULL) {
		/*
		 * invalidate and free cmmu entries
		 */
		for (i = 0; i < cmmugrp->num_tuples; i++) {
			index = cmmugrp->tuples[i].index;
			count = cmmugrp->tuples[i].count;
			DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT,
			    "mseg_free_cmmus() freeing tuples %d - %d\n",
			    index, index + count - 1));
			for (j = 0; j < count; j++) {
				wrsm_cmmu_update(exportseg->network, &cmmu,
				    index, CMMU_UPDATE_VALID);
				index++;
			}
		}

		wrsm_cmmu_free(exportseg->network, cmmugrp->num_tuples,
		    cmmugrp->tuples);

		/*
		 * free cmmugrp structures
		 */
		ocmmugrp = cmmugrp;
		cmmugrp = cmmugrp->next;
		kmem_free(ocmmugrp, sizeof (cmmugrp_t));
	}

	exportseg->cmmugrps = NULL;
}




/*
 * In the cmmu entries in the range specifed by <seg_offset, len>, set or
 * unset the valid field and set or unset the writable field as specified
 * by <flag>.
 */
static void
update_cmmu_fields(exportseg_t *exportseg, size_t seg_offset, size_t len,
    memseg_cmmufield_t flag)
{
	wrsm_network_t *network = exportseg->network;
	cmmugrp_t *cmmugrp = exportseg->cmmugrps;
	size_t cmmugrp_size;
	unsigned cmmutuples;
	unsigned cmmu_index;
	unsigned num_entries;
	unsigned pfn_index;
	wrsm_cmmu_tuple_t *tuple;
	wrsm_cmmu_t cmmu;
	wrsm_cmmu_flags_t cmmu_flag;

	DPRINTF(DBG_EXPORT, (CE_CONT, "update_cmmu_fields() - "
	    "seg_offset 0x%lx len 0x%lx flag %s\n", seg_offset, len,
	    CMMU_UPDATE_STR(flag)));

	ASSERT(MUTEX_HELD(&exportseg->lock));

	if (exportseg->size == 0) {
		/* nothing to do */
		return;
	}

	/*
	 * Update the valid field; also update the writable field if this
	 * was requested.
	 */
	cmmu_flag = CMMU_UPDATE_VALID;
	if (flag == memseg_set_writeable) {
		cmmu.entry_0.bit.writable = 1;
		cmmu_flag |= CMMU_UPDATE_WRITABLE;
	} else if (flag == memseg_unset_writeable) {
		cmmu.entry_0.bit.writable = 0;
		cmmu_flag |= CMMU_UPDATE_WRITABLE;
	} else if (flag == memseg_unset_valid) {
		cmmu_flag |= CMMU_UPDATE_FLUSH;
	}

	pfn_index = seg_offset >> MMU_PAGESHIFT;

	/*
	 * Find the right cmmugrp structure, tuple, and cmmu entry within
	 * the tuple (as indicated by cmmu_index) for <seg_offset>.
	 */
	get_start_cmmugrp(&cmmugrp, seg_offset, &cmmu_index, &cmmugrp_size);
	get_start_entry(cmmugrp, &tuple, &cmmutuples, &cmmu_index);

	while (len > 0) {
		/*
		 * Calculate the number of entries from this cmmugrp that
		 * should be reset, and subtract covered bytes from len.
		 */
		get_num_entries(&len, &num_entries, cmmugrp_size,
		    cmmugrp->pgbytes);

		while (num_entries) {

			/*
			 * If writable field is being updated, the valid
			 * field also set to true if there is memory
			 * backing the cmmu entry.
			 */
			if (flag == memseg_unset_valid ||
			    exportseg->pfn_list[pfn_index] == PFN_INVALID) {
				cmmu.entry_0.bit.valid = 0;
			} else {
				cmmu.entry_0.bit.valid = 1;
			}
			wrsm_cmmu_update(network, &cmmu,
			    tuple->index + cmmu_index, cmmu_flag);
			DPRINTF(DBG_EXPORT, (CE_CONT, "updated "
			    "index %d\n", tuple->index + cmmu_index));

			/* get next CMMU entry in this cmmugrp */
			get_next_entry(cmmugrp->tuples, &tuple, &cmmutuples,
			    &cmmu_index);
			num_entries--;
			pfn_index += cmmugrp->pgbytes >> MMU_PAGESHIFT;
		}

		if (len == 0)
			break;

		get_next_cmmugrp(&cmmugrp, &cmmutuples, &cmmu_index,
		    &cmmugrp_size, &tuple);
	}
}



/*
 * The lpa fields in cmmu entries in the range specified by <seg_offset,
 * len> are no longer valid.  Set the valid field of all cmmu entries in
 * this range to invalid, and set the affected entries in the pfn_list to
 * PFN_INVALID.
 */
static int
clear_lpa_fields(exportseg_t *exportseg, size_t seg_offset, size_t len,
    boolean_t mapping_required)
{
	wrsm_network_t *network = exportseg->network;
	cmmugrp_t *cmmugrp = exportseg->cmmugrps;
	size_t cmmugrp_size;
	unsigned cmmutuples;
	unsigned cmmu_index;
	unsigned num_entries;
	unsigned pfn_index;
	wrsm_cmmu_tuple_t *tuple;
	wrsm_cmmu_t cmmu;
	int i;

	DPRINTF(DBG_EXPORT, (CE_CONT, "clear_lpa_fields() - "
	    "seg_offset 0x%lx len 0x%lx\n", seg_offset, len));

	/*
	 * Check if any pfn fields are not valid.  Fail with
	 * RSMERR_MEM_NOT_BOUND if it is required that they be valid.
	 */
	pfn_index = seg_offset >> MMU_PAGESHIFT;
	if (mapping_required) {
		for (i = 0; i < (len >> MMU_PAGESHIFT); i++) {
			if (exportseg->pfn_list[pfn_index + i] == PFN_INVALID) {
				return (RSMERR_MEM_NOT_BOUND);
			}
		}
	}

	/*
	 * Invalidate all affected entries in the pfn list.
	 */
	for (i = pfn_index; i < ((seg_offset + len) >> MMU_PAGESHIFT); i++) {
		if (exportseg->pfn_list[i] != PFN_INVALID) {
			network->memseg->bytes_bound -= MMU_PAGESIZE;
		}
		exportseg->pfn_list[i] = PFN_INVALID;
	}

	/*
	 * Set all cmmu entries in range to invalid if segment is published.
	 * Otherwise, they are already set to invalid.
	 */
	if (exportseg->state != memseg_published) {
		return (WRSM_SUCCESS);
	}

	cmmu.entry_0.bit.valid = 0;

	/*
	 * Find the right cmmugrp structure, tuple, and cmmu entry within
	 * the tuple (as indicated by cmmu_index) for <seg_offset>.
	 */
	get_start_cmmugrp(&cmmugrp, seg_offset, &cmmu_index, &cmmugrp_size);
	get_start_entry(cmmugrp, &tuple, &cmmutuples, &cmmu_index);

	while (len > 0) {
		/*
		 * Calculate the number of entries from this cmmugrp that
		 * should be cleared, and subtract covered bytes from len.
		 */
		get_num_entries(&len, &num_entries, cmmugrp_size,
		    cmmugrp->pgbytes);

		while (num_entries) {
			wrsm_cmmu_update(network,
			    &cmmu,
			    tuple->index + cmmu_index,
			    CMMU_UPDATE_VALID);

			/* get next CMMU entry in this cmmugrp */
			get_next_entry(cmmugrp->tuples, &tuple, &cmmutuples,
			    &cmmu_index);
			num_entries--;
		}

		if (len == 0)
			break;

		get_next_cmmugrp(&cmmugrp, &cmmutuples, &cmmu_index,
		    &cmmugrp_size, &tuple);
	}

	return (WRSM_SUCCESS);
}




/*
 * Set up the cmmu lpa fields to point to the physical memory backing the
 * region pointed to by <as, vaddr> or to the pages in the pagelist
 * starting with <startpp>.  Use as many entries as needed to map <len>
 * bytes.
 *
 * For each physical page backing the region, update the lpa fields of as
 * many cmmu entries as are needed to map the page -- either one cmmu entry
 * if the passed in page size matches the CMMU entry page size, or multiple
 * cmmu entries if a large page is passed in but small page cmmu entries
 * are being used.  Also record the pfn for each 8k region in the segment
 * pfn_list, and set the entry to valid if it is published.
 *
 * Update the cmmu entries in cmmugrp/tuple sequential order starting with
 * the entry specified by <seg_offset>.
 */
static int
set_lpa_fields(exportseg_t *exportseg, size_t seg_offset, size_t len,
    struct as *as, caddr_t vaddr, page_t *startpp)
{
	int err = 0;
	int pgbytes;
	size_t bytesleft;
	size_t used_in_group;
	pfn_t pfn, pfn_8k;
	wrsm_network_t *network = exportseg->network;
	cmmugrp_t *cmmugrp = exportseg->cmmugrps;
	size_t cmmugrp_size;
	unsigned cmmutuples;
	unsigned cmmu_index;
	unsigned num_entries;
	unsigned pfn_index;
	wrsm_cmmu_tuple_t *tuple;
	wrsm_cmmu_t cmmu;
	off_t cur_offset = 0;
	page_t *pp = startpp;
	int i;

	DPRINTF(DBG_EXPORT, (CE_CONT, "set_lpa_fields() - "
	    "seg_offset 0x%lx len 0x%lx\n", seg_offset, len));

	ASSERT(cmmugrp);


	/*
	 * If any pfn entries are already valid, fail with
	 * RSMERR_MEM_ALREADY_BOUND.
	 */
	pfn_index = seg_offset >> MMU_PAGESHIFT;
	for (i = 0; i < (len >> MMU_PAGESHIFT); i++) {
		if (exportseg->pfn_list[pfn_index + i] != PFN_INVALID) {
			return (RSMERR_MEM_ALREADY_BOUND);
		}
	}

	/*
	 * Set cmmu entries to valid if segment has been published.
	 */
	if (exportseg->state == memseg_published) {
		cmmu.entry_0.bit.valid = 1;
	} else {
		cmmu.entry_0.bit.valid = 0;
	}

	/*
	 * Find the right cmmugrp structure, tuple, and cmmu entry within
	 * the tuple (as indicated by cmmu_index) for <seg_offset>.
	 */
	get_start_cmmugrp(&cmmugrp, seg_offset, &cmmu_index, &cmmugrp_size);
	get_start_entry(cmmugrp, &tuple, &cmmutuples, &cmmu_index);

	used_in_group = 0;

	while (len > 0) {

		/*
		 * Get the pfn and size of the next page.
		 */
		if (startpp) {
			/*
			 * Get the pfn for next page in pagelist.  This is
			 * guaranteed to be real memory, as we have been
			 * given page structures.
			 */
			if (!pp) {
				err = RSMERR_NO_BACKING_MEM;
				goto bad_memory;
			}
			pfn = page_pptonum(pp);
			pgbytes = PAGESIZE;	/* same as bp_mapin */
			page_unlock(pp);
			pp = pp->p_next;
		} else {
			/*
			 * Get the pfn for the page backing <as, vaddr +
			 * cur_offset>.  Make sure this is real memory.
			 * Grab AS_LOCK to make sure as mappings don't
			 * change.
			 */

			AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
			pfn = hat_getpfnum(as->a_hat, vaddr + cur_offset);
			AS_LOCK_EXIT(as, &as->a_lock);

			if (pfn == PFN_INVALID) {
				err = RSMERR_NO_BACKING_MEM;
				goto bad_memory;
			}
			if (!pf_is_memory(pfn)) {
				err = RSMERR_NOT_MEM;
				goto bad_memory;
			}
			pgbytes = MMU_PAGESIZE;
		}

		DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT,
		    "mapping page with pfn 0x%lx size 0x%x\n",
		    pfn, pgbytes));

		ASSERT(pgbytes == MMU_PAGESIZE || pgbytes == MMU_PAGESIZE4M);
		ASSERT(pgbytes >= cmmugrp->pgbytes);

		pfn_8k = pfn;
		bytesleft = pgbytes;

		/*
		 * If we've already allocated all the entries from the
		 * current cmmugrp, move to the next one.
		 */
		if (used_in_group >= cmmugrp_size) {
			DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT,
				"set_lpa_fields used all in one group"
				" used_in_group = %lx, size = %lx\n",
				used_in_group, cmmugrp_size));

			get_next_cmmugrp(&cmmugrp, &cmmutuples, &cmmu_index,
					&cmmugrp_size, &tuple);

			used_in_group = 0;
		}

		while (bytesleft > 0) {

			/*
			 * Calculate the number of cmmu entries from this
			 * cmmugrp that will be used to map this page, and
			 * subtract covered bytes from bytesleft.
			 */
			get_num_entries(&bytesleft, &num_entries,
			    cmmugrp_size, cmmugrp->pgbytes);

			while (num_entries) {
				/*
				 * record lpa for this region of the page
				 */
				cmmu.entry_1.addr.lpa_page = pfn;
				wrsm_cmmu_update(network, &cmmu,
				    tuple->index + cmmu_index,
				    CMMU_UPDATE_LPA | CMMU_UPDATE_VALID);
				DPRINTF(DBG_EXPORT_EXTRA,
				    (CE_CONT, "set_lpa_fields "
				    "cmmu index %d pfn 0x%lx valid %ld\n",
				    tuple->index + cmmu_index,
				    cmmu.entry_1.addr.lpa_page,
				    cmmu.entry_0.bit.valid));

				/* get next CMMU entry */
				get_next_entry(cmmugrp->tuples, &tuple,
				    &cmmutuples, &cmmu_index);
				num_entries--;

				/*
				 * If cmmu entries are for small pages,
				 * get physaddr (pfn) for next 8k page.
				 */
				if (cmmugrp->pgbytes == MMU_PAGESIZE)
					pfn += MMU_PAGESIZE >> MMU_PAGESHIFT;
			}

			if (bytesleft == 0)
				break;

			get_next_cmmugrp(&cmmugrp, &cmmutuples, &cmmu_index,
			    &cmmugrp_size, &tuple);
			used_in_group = 0;
		}

		/*
		 * record the 8k-based pfns for this page in pfn_list
		 */
		for (i = 0; i < (pgbytes >> MMU_PAGESHIFT); i++) {
			exportseg->pfn_list[pfn_index + i] = pfn_8k;
			pfn_8k += MMU_PAGESIZE >> MMU_PAGESHIFT;
		}
		pfn_index += pgbytes >> MMU_PAGESHIFT;

		used_in_group += pgbytes;
		cur_offset += pgbytes;
		network->memseg->bytes_bound += pgbytes;
		len -= pgbytes;
		ASSERT(len >= 0);
	}
	return (WRSM_SUCCESS);


bad_memory:
	/*
	 * There was a problem with the backing memory.  Tear down
	 * previously set up stuff, and return error.
	 */
	pfn_index = seg_offset >> MMU_PAGESHIFT;
	for (i = 0; i < (cur_offset >> MMU_PAGESHIFT); i++) {
		exportseg->pfn_list[pfn_index + i] = PFN_INVALID;
	}
	(void) clear_lpa_fields(exportseg, seg_offset, cur_offset, B_FALSE);
	return (err);
}




/*
 * Allocate <num_entries> cmmu entries of <pgbytes> page size from the cmmu
 * allocator.  Create a cmmugrp entry to store info about these entries.
 */
static int
alloc_cmmu_tuples(exportseg_t *exportseg, int num_entries, off_t seg_offset,
    int pgbytes, cmmugrp_t **cmmugrpp, boolean_t sleep)
{
	wrsm_network_t *network = exportseg->network;
	int err = WRSM_SUCCESS;
	size_t cmmu_page_size;
	cmmugrp_t *cmmugrp;
	wrsm_cmmu_t cmmu;
	wrsm_cmmu_index_t index;
	boolean_t lg_page;
	int i, j;

	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "alloc_cmmu_tuples() - "
	    "num_entries %d seg_offset 0x%lx pgbytes 0x%x\n",
	    num_entries, seg_offset, pgbytes));

	cmmugrp = (cmmugrp_t *)kmem_zalloc(sizeof (cmmugrp_t),
		KM_SLEEP);
	cmmugrp->offset = seg_offset;
	cmmugrp->len = num_entries * pgbytes;
	cmmugrp->pgbytes = pgbytes;
	cmmu_page_size = (pgbytes == MMU_PAGESIZE) ?
	    CMMU_PAGE_SIZE_SMALL : CMMU_PAGE_SIZE_LARGE;
	lg_page = (pgbytes == MMU_PAGESIZE4M) ? B_TRUE : B_FALSE;


	if ((err = wrsm_cmmu_alloc(network, cmmu_page_size, num_entries,
	    &cmmugrp->tuples, &cmmugrp->num_tuples, sleep)) !=
	    WRSM_SUCCESS) {
		if (cmmu_page_size == CMMU_PAGE_SIZE_LARGE) {
			/*
			 * try allocating cmmu entries for small pages
			 */
			lg_page = B_FALSE;
			cmmugrp->pgbytes = MMU_PAGESIZE;
			cmmu_page_size = CMMU_PAGE_SIZE_SMALL;
			num_entries *= MMU_PAGESIZE4M >> MMU_PAGESHIFT;
			if ((err = wrsm_cmmu_alloc(network,
			    cmmu_page_size, num_entries,
			    &cmmugrp->tuples, &cmmugrp->num_tuples, sleep)) !=
			    WRSM_SUCCESS) {
				kmem_free(cmmugrp, sizeof (cmmugrp_t));
				/* return RSMPI complaint error code */
				return (RSMERR_INSUFFICIENT_RESOURCES);
			}
		} else {
			/* give up */
			kmem_free(cmmugrp, sizeof (cmmugrp_t));
			return (err);
		}
	}

	/*
	 * Update each CMMU entry to reflect how it is being used
	 */
	cmmu.entry_0.val = 0;
	cmmu.entry_0.bit.count_enable = B_FALSE;
	cmmu.entry_0.bit.large_page = lg_page;
	cmmu.entry_0.bit.user_err = B_FALSE;
	cmmu.entry_0.bit.writable = B_FALSE;
	cmmu.entry_0.bit.from_all = B_TRUE;
	cmmu.entry_0.bit.from_node = 255;
	cmmu.entry_0.bit.valid = B_FALSE;
	cmmu.entry_0.bit.type = CMMU_TYPE_CACHEABLE;

	cmmu.entry_1.val = 0;

	for (i = 0; i < cmmugrp->num_tuples; i++) {
		index = cmmugrp->tuples[i].index;
		DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT,
		    "alloc_cmmu_tuples() alloced tuples %d - %d\n",
		    index, index + cmmugrp->tuples[i].count - 1));
		for (j = 0; j < cmmugrp->tuples[i].count; j++) {
			wrsm_cmmu_update(network, &cmmu, index,
			    CMMU_UPDATE_ALL);
			index++;
		}
	}

	exportseg->total_tuples += cmmugrp->num_tuples;
	exportseg->num_cmmugrps++;
	*cmmugrpp = cmmugrp;

	return (WRSM_SUCCESS);
}




/*
 * Allocate enough cmmu entries for a segment of size <size>.  Allocate
 * large pages where possible. Set up mappings to any passed in memory.
 */
static int
alloc_seg_cmmu_entries(exportseg_t *exportseg, rsm_memory_local_t *memory,
    size_t size, boolean_t allow_lg_pages, boolean_t sleep)
{
	int pgbytes, opgbytes, num_entries, need_entries;
	off_t seg_offset;
	cmmugrp_t **cmmugrp_nextp;
	size_t nbytes = 0;
	pfn_t pfn;
	page_t *pp;
	page_t *startpp = NULL;
	struct buf *bp = NULL;
	struct as *as = NULL;
	off_t offset = 0;
	void *vaddr = NULL;
	/* LINTED: E_FUNC_SET_NOT_USED */
	int err;
#ifdef DEBUG
	pfn = 0;
#endif

	if (memory->ms_type == RSM_MEM_BUF) {
		bp = memory->ms_bp;

		DPRINTF(DBG_EXPORT, (CE_CONT, "alloc_seg_cmmu_entries() - "
		    "bp 0x%p size 0x%lx\n", (void *)bp, size));

		ASSERT(bp);
		ASSERT(SEMA_HELD(&bp->b_sem));

		nbytes = bp->b_bcount;

		if (bp->b_flags & B_PAGEIO) {
			if (!bp->b_pages) {
				return (RSMERR_NO_BACKING_MEM);
			} else {
				pp = startpp = bp->b_pages;
			}
		} else {
			vaddr = (void *)bp->b_un.b_addr;
			if (bp->b_flags & B_PHYS) {
				if (bp->b_proc == NULL ||
				    (as = bp->b_proc->p_as) == NULL)
					as = &kas;
			} else {
				as = &kas;
			}
		}

	} else {
		ASSERT(memory->ms_type == RSM_MEM_VADDR);

		as = memory->ms_as;
		if (as == NULL) {
			as = &kas;
		}
		vaddr = memory->ms_vaddr;
		nbytes = memory->ms_length;

		DPRINTF(DBG_EXPORT, (CE_CONT, "alloc_seg_cmmu_entries() - "
		    "as 0x%p vaddr 0x%p length 0x%lx size 0x%lx\n", (void *)as,
		    vaddr, nbytes, size));
	}

	if ((uint64_t)vaddr & (uint64_t)MMU_PAGEOFFSET) {
		/* vaddr must be propertly aligned */
		DPRINTF(DBG_EXPORT, (CE_CONT, "vaddr 0x%p not aligned\n",
		    (void *)vaddr));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (nbytes > size) {
		/* size range can't exceed segment size */
		DPRINTF(DBG_EXPORT, (CE_CONT, "nbytes %ld > size %ld\n",
		    nbytes, size));
		return (RSMERR_BAD_LENGTH);
	}

	if (nbytes & MMU_PAGEOFFSET) {
		/* size must be an aligned number of bytes */
		DPRINTF(DBG_EXPORT, (CE_CONT, "nbytes %ld not 64 byte round\n",
		    nbytes));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	size -= nbytes; /* size of region not backed by memory */
	pgbytes = opgbytes = MMU_PAGESIZE;
	num_entries = 0;
	seg_offset = 0;
	cmmugrp_nextp = &exportseg->cmmugrps;
	ASSERT(*cmmugrp_nextp == NULL);

	/*
	 * Use large page CMMU entries for all large physical pages if
	 * allowed and available.  We could try seeing if the small pages
	 * happen to be allocated consecutively, but the caller apparently
	 * didn't care enough to use large pages, so don't bother.
	 */

	while (nbytes > 0) {
		if (startpp) {
			if (!pp) {
				mseg_free_cmmus(exportseg);
				DPRINTF(DBG_EXPORT,
				    (CE_CONT, "invalid buf pp\n"));
				return (RSMERR_NO_BACKING_MEM);
			}

			pgbytes = PAGESIZE;	/* same as bp_mapin */
			pp = pp->p_next;

		} else {

			/*
			 * make sure the next region of the vaddr range
			 * points to valid physical memory.  Grab AS_LOCK
			 * to make sure as mappings don't change.
			 */

			AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
			pfn =  hat_getpfnum(as->a_hat, (caddr_t)vaddr +
			    offset);
			AS_LOCK_EXIT(as, &as->a_lock);

			if (pfn == PFN_INVALID) {
				/* not backed by anything! */
				mseg_free_cmmus(exportseg);
				DPRINTF(DBG_EXPORT, (CE_CONT, "vaddr 0x%p "
				    "not backed by memory\n",
				    (void *)((caddr_t)vaddr + offset)));
				return (RSMERR_NO_BACKING_MEM);
			}
			if (!pf_is_memory(pfn)) {
				/* tear down previously set up stuff */
				mseg_free_cmmus(exportseg);
				DPRINTF(DBG_EXPORT, (CE_CONT, "IO "
				    "pfn 0x%lx at vaddr 0x%p\n", pfn,
				    (void *)((caddr_t)vaddr + offset)));
				return (RSMERR_NOT_MEM);
			}
			pgbytes = MMU_PAGESIZE;
			offset += pgbytes;
		}

		ASSERT(pgbytes == MMU_PAGESIZE || pgbytes == MMU_PAGESIZE4M);

		if (pgbytes == MMU_PAGESIZE4M && !allow_lg_pages) {
			/*
			 * large pages not allowed: translate to small pages
			 */
			DPRINTF(DBG_EXPORT, (CE_CONT, "no large pages; convert "
			    "pages from size %d to %d (MMU_PAGESIZE)\n",
			    pgbytes, MMU_PAGESIZE));
			ASSERT((pgbytes & MMU_PAGEOFFSET) == 0);
			need_entries = pgbytes >> MMU_PAGESHIFT;
			pgbytes = MMU_PAGESIZE;
		} else {
			need_entries = 1;
		}

		nbytes -= pgbytes;

		if (pgbytes != opgbytes) {
			/*
			 * a different page size is being used
			 */
			if (num_entries != 0) {
				/*
				 * Allocate cmmu entries for the num_entries
				 * previous pages.
				 */
				if ((alloc_cmmu_tuples(exportseg,
				    num_entries, seg_offset, opgbytes,
				    cmmugrp_nextp, sleep)) != WRSM_SUCCESS) {
					mseg_free_cmmus(exportseg);
					DPRINTF(DBG_EXPORT, (CE_CONT,
					    "couldn't alloc cmmu tuples to "
					    "back memory\n"));
					return (RSMERR_INSUFFICIENT_RESOURCES);
				}
				cmmugrp_nextp = &((*cmmugrp_nextp)->next);

				/*
				 * record the physical addresses of this
				 * range of memory into the LPA fields in
				 * the cmmu entries
				 */
				err = set_lpa_fields(exportseg, seg_offset,
				    num_entries * opgbytes, as,
				    (caddr_t)vaddr + seg_offset, startpp);
				ASSERT(err == WRSM_SUCCESS);
				seg_offset += num_entries * opgbytes;

				if (startpp) {
					startpp = pp;
					ASSERT(startpp || nbytes == 0);
				}
				opgbytes = pgbytes;
				num_entries = 0;
			}
		}

		num_entries += need_entries;
	}

	ASSERT(nbytes == 0);


	/*
	 * allocate tuples for last set of physical pages
	 */

	if (num_entries != 0) {
		ASSERT(pgbytes == MMU_PAGESIZE || pgbytes == MMU_PAGESIZE4M);
		if (num_entries != 0) {
			if ((alloc_cmmu_tuples(exportseg, num_entries,
			    seg_offset, pgbytes, cmmugrp_nextp, sleep)) !=
			    WRSM_SUCCESS) {
				mseg_free_cmmus(exportseg);
				DPRINTF(DBG_EXPORT, (CE_CONT,
				    "couldn't alloc cmmu tuples for "
				    "last set of backing memory\n"));
				return (RSMERR_INSUFFICIENT_RESOURCES);
			}
			cmmugrp_nextp = &((*cmmugrp_nextp)->next);

			err = set_lpa_fields(exportseg, seg_offset,
			    num_entries * pgbytes, as,
			    (caddr_t)vaddr + seg_offset, startpp);
			ASSERT(err == WRSM_SUCCESS);
			seg_offset += num_entries * pgbytes;
		}
	}

	/*
	 * Allocate tuples for the end of the segment if some of it
	 * has no memory backing it. Allocate small pages for this
	 * part, as we don't know what memory will eventually back it.
	 */

	if (size != 0) {
		num_entries = size >> MMU_PAGESHIFT;
		ASSERT(num_entries != 0);
		if ((alloc_cmmu_tuples(exportseg, num_entries,
		    seg_offset, MMU_PAGESIZE, cmmugrp_nextp, sleep))
		    != WRSM_SUCCESS) {
			mseg_free_cmmus(exportseg);
			DPRINTF(DBG_EXPORT, (CE_CONT,
			    "couldn't alloc cmmu tuples for unbacked "
			    " memory\n"));
			return (RSMERR_INSUFFICIENT_RESOURCES);
		}
	}


	return (WRSM_SUCCESS);
}


/*
 * Parse the passed in access list, calculate new per node access
 * permissions (based on the old and new permissions), store the new
 * permissions, and apply the access permissions for an exported segment
 * to the appropriate cmmu entries.
 */
static int
apply_access_list(exportseg_t *exportseg,
    rsm_access_entry_t access_list[], uint_t access_list_length)
{
	rsm_addr_t addr;
	wrsm_network_t *network;
	cnodeid_t cnodeid;
	cnode_bitmask_t bitmask;
	rsm_permission_t perms = RSM_PERM_NONE;
	uint_t i;
	int j;
	boolean_t changed[WRSM_MAX_CNODES];
	boolean_t old_import_vals[WRSM_MAX_CNODES];
	rsm_permission_t old_perms_vals[WRSM_MAX_CNODES];

	DPRINTF(DBG_EXPORT, (CE_CONT, "apply_access_list()\n"));

	ASSERT(MUTEX_HELD(&exportseg->lock));

	WRSMSET_ZERO(bitmask);
	network = exportseg->network;

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		changed[i] = B_FALSE;
	}


	/*
	 * If no access list, assume default of all nodes, with a
	 * permission of RSM_PERM_RDWR.  If the access list's first entry
	 * specifies single hardware address of RSM_ACCESS_PUBLIC, apply
	 * the specified permission to all nodes.  Otherwise, parse the
	 * access list.
	 */

	if (access_list == NULL ||
	    access_list[0].ae_addr == RSM_ACCESS_PUBLIC) {
		perms = access_list ? access_list[0].ae_permission :
		    RSM_PERM_RDWR;

		if ((perms & ~RSM_PERM_RDWR) != 0) {
			return (RSMERR_BAD_ACL);
		}

		/* all nodes are allowed to import this segment */
		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			if (network->nodes[i]) {
				exportseg->nodes[i].allow_import = B_TRUE;
				exportseg->nodes[i].perms = perms;
				WRSMSET_ADD(bitmask, i);
			}
		}

	} else {
		for (i = 0; i < access_list_length; i++) {
			/*
			 * wrsm hardware addresses must be cnodeids.
			 * Only allowed bits in perms are RSM_PERM_READ
			 * and RSM_PERM_WRITE
			 */
			addr = access_list[i].ae_addr;
			if ((addr >= WRSM_MAX_CNODES) ||
			    !network->nodes[addr] ||
			    ((access_list[i].ae_permission &
			    ~RSM_PERM_RDWR) != 0)) {
				/*
				 * invalid hardware address or perms --
				 * reinstate old settings, then fail
				 */
				for (j = 0; j < i; j++) {
					if (changed[j]) {
						exportseg->nodes[j].
						    allow_import =
						    old_import_vals[j];
						exportseg->nodes[j].perms =
						    old_perms_vals[j];
					}
				}
				return (RSMERR_BAD_ACL);
			}
			cnodeid = access_list[i].ae_addr;
			WRSMSET_ADD(bitmask, cnodeid);

			changed[cnodeid] = B_TRUE;
			old_import_vals[cnodeid] =
			    exportseg->nodes[cnodeid].allow_import;
			old_perms_vals[cnodeid] =
			    exportseg->nodes[cnodeid].perms;
			exportseg->nodes[cnodeid].allow_import = B_TRUE;
			exportseg->nodes[cnodeid].perms =
			    access_list[i].ae_permission;

			/*
			 * make sure perms is set to the most permissive
			 * of each node's old and new permissions.
			 * perms starts out as RSM_PERM_NONE, and gets
			 * changed if the current node has greater
			 * permissions.
			 */
			switch (exportseg->nodes[cnodeid].perms) {
			    case RSM_PERM_RDWR:
			    case RSM_PERM_WRITE:
				perms = RSM_PERM_RDWR;
				break;
			    case RSM_PERM_READ:
				if (perms == RSM_PERM_NONE)
					perms = RSM_PERM_READ;
				break;
#ifdef DEBUG
			    default:
				ASSERT(exportseg->nodes[cnodeid].perms
				    == RSM_PERM_NONE);
				break;
#endif
			}
			switch (exportseg->nodes[cnodeid].actual_perms) {
			    case RSM_PERM_RDWR:
			    case RSM_PERM_WRITE:
				perms = RSM_PERM_RDWR;
				break;
			    case RSM_PERM_READ:
				if (perms == RSM_PERM_NONE)
					perms = RSM_PERM_READ;
				break;
#ifdef DEBUG
			    default:
				ASSERT(exportseg->nodes[cnodeid].actual_perms
				    == RSM_PERM_NONE);
				break;
#endif
			}
		}
	}

	/*
	 * Make sure the actual per node perms are the max permissions of
	 * previous actual perms and the newly installed perms.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		switch (exportseg->nodes[i].perms) {
		    case RSM_PERM_RDWR:
		    case RSM_PERM_WRITE:
			exportseg->nodes[i].actual_perms = RSM_PERM_RDWR;
			break;
		    case RSM_PERM_READ:
			if (exportseg->nodes[i].actual_perms == RSM_PERM_NONE)
				exportseg->nodes[i].actual_perms =
				    RSM_PERM_READ;
			break;
		}
		DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "cnode %d: allow_import %d "
		    "perms 0x%x actual perms 0x%x\n",
		    i,
		    exportseg->nodes[i].allow_import,
		    exportseg->nodes[i].perms,
		    exportseg->nodes[i].actual_perms));
	}

	if (!wrsm_hw_protection) {

		/*
		 * Set all CMMU entries to valid (if they have a valid
		 * lpa).  Set writeable to true if any node is allowed
		 * write permission, or if there were previous permissions
		 * that allowed writing.  (This handles the case of
		 * republish calling this function with stricter
		 * permissions.)
		 */
		/* LINTED: E_PRECEDENCE_CONFUSION */
		if ((perms == RSM_PERM_RDWR) || (perms == RSM_PERM_WRITE) ||
		    exportseg->writeable) {
			exportseg->writeable = B_TRUE;
			update_cmmu_fields(exportseg, 0, exportseg->size,
			    memseg_set_writeable);
		} else {
			exportseg->writeable = B_FALSE;
			update_cmmu_fields(exportseg, 0, exportseg->size,
			    memseg_unset_writeable);
		}
	}

	WRSMSET_COPY(bitmask, exportseg->import_bitmask);
	return (RSM_SUCCESS);
}



/*
 * Enable the small page interrupt cmmu entry for this exportseg.
 */
static void
enable_smallput_intr_page(exportseg_t *exportseg)
{
	wrsm_cmmu_t cmmu;
	wrsm_cmmu_index_t index;

	index = exportseg->small_put_intr.tuple->index;
	cmmu.entry_0.bit.valid = B_TRUE;
	wrsm_cmmu_update(exportseg->network, &cmmu, index, CMMU_UPDATE_VALID);
}



/*
 * Disable the small page interrupt cmmu entry for this exportseg.
 */
static void
disable_smallput_intr_page(exportseg_t *exportseg)
{
	wrsm_cmmu_t cmmu;
	wrsm_cmmu_index_t index;

	index = exportseg->small_put_intr.tuple->index;
	cmmu.entry_0.bit.valid = B_FALSE;
	wrsm_cmmu_update(exportseg->network, &cmmu, index,
	    CMMU_UPDATE_VALID | CMMU_UPDATE_FLUSH);

	/* make sure any in-process interrupts have completed */
	wrsm_intr_flush_recvq(exportseg->small_put_intr.recvq);
}




/*
 * Translate an exportseg's stored cmmu entry information into the format
 * needed for connection messages.
 */
static void
cmmutuple_to_ncslicetuple(wrsm_network_t *network, wrsm_cmmu_tuple_t *cmmutuple,
    import_ncslice_t *ncslicetuple, size_t seg_offset, size_t cmmu_page_size,
    cnodeid_t cnodeid)
{
	int i;
#ifdef DEBUG
	boolean_t found_ncslice = B_FALSE;
#endif
	ncslice_t ncslice;
	ncslicetuple->seg_offset = seg_offset;
	ncslice = cmmutuple->ncslice;
	/* set ncslice to the equivalent ncslice imported by this node */
	for (i = 0; i < WRSM_NODE_NCSLICES; i++) {
		if (network->exported_ncslices.id[i] == ncslice) {
#ifdef DEBUG
			found_ncslice = B_TRUE;
#endif
			ncslicetuple->ncslice = network->nodes[cnodeid]->
			    config->imported_ncslices.id[i];
			break;
		}
	}
#ifdef DEBUG
	ASSERT(found_ncslice);
#endif
	ncslicetuple->ncslice_offset = (off_t)cmmutuple->offset;
	ncslicetuple->len = cmmutuple->count * cmmu_page_size;
}

/*
 * Send requestor information about a published exported segment.
 */
void
wrsm_connect_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	cnodeid_t cnodeid = msg->header.source_cnode;
	connect_msg_t args;
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	connect_resp_t respargs;
	exportseg_t *exportseg;
	connect_info_t *connected;
	int connection = 0;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: connect_msg_evt() "
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

	respmsg->header.message_type = WRSM_MSG_SEGMENT_CONNECT_RESPONSE;

	/*
	 * does segment exist?
	 */
	exportseg = find_and_lock_exportseg(network, args.segid);
	if (exportseg == NULL) {
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	/*
	 * is segment published?
	 */
	if (exportseg->state != memseg_published) {
		mutex_exit(&exportseg->lock);
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	/*
	 * does requesting node have permission to connect to it?
	 */
	if (!WRSM_IN_SET(exportseg->import_bitmask, cnodeid)) {
		mutex_exit(&exportseg->lock);
		respargs.err = EACCES;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	if (exportseg->nodes[cnodeid].inuse != B_TRUE) {
		/*
		 * add to list of segments the remote node is importing
		 */
		exportseg->nodes[cnodeid].inuse = B_TRUE;
		connection = 1;
		mutex_enter(&node->memseg->lock);
		connected = kmem_zalloc(sizeof (connect_info_t), KM_SLEEP);
		connected->exportseg = exportseg;
		connected->next = node->memseg->connected;
		node->memseg->connected = connected;
		mutex_exit(&node->memseg->lock);
#ifdef DEBUG
	} else {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "unexpected connect request from node %d "
		    "for segment id %d\n", cnodeid, args.segid));
#endif
	}

	respargs.perms = exportseg->nodes[cnodeid].perms;
	respargs.size = exportseg->size;
	respargs.num_seg_tuples = exportseg->total_tuples;
	respargs.err = RSM_SUCCESS;
	mutex_exit(&exportseg->lock);

	/*
	 * Transport Layer tears down the session if there is a message
	 * delivery failure.
	 */
	bcopy(&respargs, &respmsg->body, sizeof (respargs));
	(void) wrsm_tl_rsp(network, msg, respmsg);


	mutex_enter(&network->lock);
	network->memseg->export_connected += connection;
	mutex_exit(&network->lock);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}


/*
 * Send requestor small put interrupt page mapping information for a
 * published exported segment.
 */
void
wrsm_smallputmap_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	cnodeid_t cnodeid = msg->header.source_cnode;
	smallputmap_msg_t args;
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	smallputmap_resp_t respargs;
	exportseg_t *exportseg;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: smallputmap_msg_evt() "
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

	respmsg->header.message_type = WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE;

	/*
	 * does segment exist?
	 */
	exportseg = find_and_lock_exportseg(network, args.segid);
	if (exportseg == NULL) {
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	respargs.err = RSM_SUCCESS;
	/*
	 * is segment published?
	 */
	if (exportseg->state != memseg_published) {
		respargs.err = ENOENT;
	}
	/*
	 * does requesting node have permission to connect to it?
	 */
	else if (!WRSM_IN_SET(exportseg->import_bitmask, cnodeid)) {
		respargs.err = EACCES;
	}
	/*
	 * 0 length segment -- no small put page to report
	 */
	else if (exportseg->size == 0) {
		respargs.err = EINVAL;
	}

	if (respargs.err != RSM_SUCCESS) {
		mutex_exit(&exportseg->lock);
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

#ifdef DEBUG
	if (exportseg->nodes[cnodeid].inuse != B_TRUE) {
		DPRINTF(DBG_WARN, (CE_WARN, "ctlr %d: smallputmap_msg_evt() "
		    "unexpected smallputmap request from node %d "
		    "for segment id %d\n", cnodeid, args.segid));
	}
#endif

	cmmutuple_to_ncslicetuple(network, exportseg->small_put_intr.tuple,
	    &respargs.small_put_tuple, 0, MMU_PAGESIZE, cnodeid);

	mutex_exit(&exportseg->lock);

	/*
	 * Transport Layer tears down the session if there is a message
	 * delivery failure.
	 */
	bcopy(&respargs, &respmsg->body, sizeof (respargs));
	(void) wrsm_tl_rsp(network, msg, respmsg);


	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}


/*
 * Send requestor barrier page mapping information for a published exported
 * segment.
 */
void
wrsm_barriermap_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	cnodeid_t cnodeid = msg->header.source_cnode;
	barriermap_msg_t args;
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	barriermap_resp_t respargs;
	exportseg_t *exportseg;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: barriermap_msg_evt() "
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

	respmsg->header.message_type = WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE;

	/*
	 * does segment exist?
	 */
	exportseg = find_and_lock_exportseg(network, args.segid);
	if (exportseg == NULL) {
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	respargs.err = RSM_SUCCESS;

	/*
	 * is segment published?
	 */
	if (exportseg->state != memseg_published) {
		respargs.err = ENOENT;
	}
	/*
	 * does requesting node have permission to connect to it?
	 */
	else if (!WRSM_IN_SET(exportseg->import_bitmask, cnodeid)) {
		respargs.err = EACCES;
	}
	/*
	 * 0 length segment -- no small put page to report
	 */
	else if (exportseg->size == 0) {
		respargs.err = EINVAL;
	}

	if (respargs.err != RSM_SUCCESS) {
		mutex_exit(&exportseg->lock);
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

#ifdef DEBUG
	if (exportseg->nodes[cnodeid].inuse != B_TRUE) {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "unexpected barriermap request from node %d "
		    "for segment id %d\n", cnodeid, args.segid));
	}
#endif

	cmmutuple_to_ncslicetuple(network, exportseg->barrier_page.tuple,
	    &respargs.barrier_tuple, 0, MMU_PAGESIZE, cnodeid);

	mutex_exit(&exportseg->lock);

	/*
	 * Transport Layer tears down the session if there is a message
	 * delivery failure.
	 */
	bcopy(&respargs, &respmsg->body, sizeof (respargs));
	(void) wrsm_tl_rsp(network, msg, respmsg);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}


/*
 * Send segment mapping information for a published exported segment.
 */
void
wrsm_segmap_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	segmap_msg_t args;
	cnodeid_t cnodeid = msg->header.source_cnode;
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	segmap_resp_t respargs;
	exportseg_t *exportseg;
	int i, j;
	cmmugrp_t *cmmugrp;
	uint64_t tuple_offset;
	int tuple_index;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: segmap_msg_evt() "
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

	respmsg->header.message_type = WRSM_MSG_SEGMENT_SEGMAP_RESPONSE;

	/*
	 * does segment exist?
	 */
	exportseg = find_and_lock_exportseg(network, args.segid);
	if (exportseg == NULL) {
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	/*
	 * is segment published?
	 */
	if (exportseg->state != memseg_published) {
		mutex_exit(&exportseg->lock);
		respargs.err = ENOENT;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}
	/*
	 * does requesting node have permission to connect to it?
	 */
	if (!WRSM_IN_SET(exportseg->import_bitmask, cnodeid)) {
		mutex_exit(&exportseg->lock);
		respargs.err = EACCES;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

#ifdef DEBUG
	if (exportseg->nodes[cnodeid].inuse != B_TRUE) {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "unexpected map request from node %d "
		    "for segment id %d\n", cnodeid, args.segid));
	}
#endif

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: segmap_msg_evt() "
	    "tuple_index %d\n", network->rsm_ctlr_id, args.tuple_index));

	tuple_index = args.tuple_index;
	if (tuple_index >= exportseg->total_tuples) {
		mutex_exit(&exportseg->lock);
		/* bad message */
		respargs.err = EINVAL;
		bcopy(&respargs, &respmsg->body, sizeof (respargs));
		(void) wrsm_tl_rsp(network, msg, respmsg);
		return;
	}

	/*
	 * find the cmmugrp containing the desired starting tuple
	 */
	i = 0;
	cmmugrp = exportseg->cmmugrps;
	while (i < tuple_index && ((i + cmmugrp->num_tuples) <= tuple_index)) {
		i += cmmugrp->num_tuples;
		cmmugrp = cmmugrp->next;
		ASSERT(cmmugrp);
	}

	/* calculate index within the cmmugrp */
	i = tuple_index - i;

	/*
	 * If this is not the first cmmu tuple in a cmmugrp, then
	 * compute its offset.
	 */
	tuple_offset = 0;
	if (i > 0) {
		for (j = 0; j < i; j++) {
			tuple_offset += (cmmugrp->tuples[j].count *
					cmmugrp->pgbytes);
		}
	}

	j = 0;

	/*
	 * copy as many tuples as possible into the response message
	 */
	while (j < MAP_MSG_TUPLES && tuple_index < exportseg->total_tuples) {

		cmmutuple_to_ncslicetuple(network, &(cmmugrp->tuples[i]),
		    &(respargs.tuples[j]),
		    cmmugrp->offset + tuple_offset,
		    cmmugrp->pgbytes, cnodeid);

		tuple_offset += (cmmugrp->tuples[i].count *
				cmmugrp->pgbytes);
		i++;
		j++;
		tuple_index++;

		if (tuple_index == exportseg->total_tuples)
			break;

		if (i == cmmugrp->num_tuples) {
			cmmugrp = cmmugrp->next;
			ASSERT(cmmugrp);
			i = 0;
			tuple_offset = 0;
		}
	}

	respargs.num_tuples = j;
	respargs.err = RSM_SUCCESS;

	mutex_exit(&exportseg->lock);

	/*
	 * Transport Layer tears down the session if there is a message
	 * delivery failure.
	 */
	bcopy(&respargs, &respmsg->body, sizeof (respargs));
	(void) wrsm_tl_rsp(network, msg, respmsg);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}



/*
 * Mark this exportseg as no longer imported by node sending this message.
 */
void
wrsm_disconnect_msg_evt(void *arg)
{
	wrsm_network_t *network = ((wrsm_memseg_evt_args_t *)arg)->network;
	wrsm_message_t *msg = &((wrsm_memseg_evt_args_t *)arg)->msg;
	disconnect_msg_t args;
	cnodeid_t cnodeid = msg->header.source_cnode;
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	exportseg_t *exportseg;
	connect_info_t **connpp, *connp;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: disconnect_msg_evt() "
	    "node %d\n", network->rsm_ctlr_id, cnodeid));

	if (node == NULL) {
		/* non-existent node */
		return;
	}

	if (wrsm_tl_rxhandler_sessionid(network, msg) == B_FALSE) {
		/* session must not be valid */
		return;
	}

	/*
	 * does segment exist?
	 */
	bcopy(&msg->body, &args, sizeof (args));
	exportseg = find_and_lock_exportseg(network, args.segid);
	if (exportseg == NULL) {
		/* ignore */
		DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: unexpected disconnect "
		    "from node %d for non-existent segment %d\n",
		    network->rsm_ctlr_id, node->config->cnodeid, args.segid));
		return;
	}

	if (exportseg->nodes[cnodeid].inuse == B_FALSE) {
		DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: unexpected disconnect "
		    "from disconnected node %d for segment %d\n",
		    network->rsm_ctlr_id, node->config->cnodeid, args.segid));
		mutex_exit(&exportseg->lock);
		return;
	}

	/*
	 * remove from list of segments the remote node is importing
	 */
	exportseg->nodes[cnodeid].inuse = B_FALSE;

	mutex_enter(&node->memseg->lock);
	for (connpp = &node->memseg->connected; *connpp != NULL;
	    connpp = &((*connpp)->next)) {
		if ((*connpp)->exportseg == exportseg) {
			connp = *connpp;
			*connpp = (*connpp)->next;
			kmem_free(connp, sizeof (*connp));
			break;
		}
	}
	mutex_exit(&node->memseg->lock);

	if (exportseg->wait_for_disconnects > 0) {
		DPRINTF(DBG_EXPORT, (CE_CONT, "disconnect_evt: "
		    "wait_for_disconnects %d\n",
		    exportseg->wait_for_disconnects));
		exportseg->wait_for_disconnects--;
	}

	mutex_exit(&exportseg->lock);

	mutex_enter(&network->lock);
	network->memseg->export_connected--;
	mutex_exit(&network->lock);

	/* We're done, deallocate our incoming args struct and the message */
	kmem_free(arg, sizeof (wrsm_memseg_evt_args_t));

}




/*
 * Send specified node a message indicating the the exported segment
 * is no longer published.  Record based on the response message whether
 * the node has released all connections to the segment.  Function
 * returns 1 if it received a disconnect response from the remote
 * node, otherwise it returns 0.
 */
static int
send_unpublish_msg(wrsm_node_t *node, exportseg_t *exportseg)
{
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	unpublish_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	wrsm_network_t *network = node->network;
	unpublish_resp_t recvargs;
	connect_info_t **connpp, *connp;
	int disconnect = 0;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: send_unpublish_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (unpublish_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_UNPUBLISH;
	args.segid = exportseg->segid;

	bcopy(&args, &msg->body, sizeof (args));
	if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
	    != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not
		 * delivered or response not received).  (Transport
		 * Layer tears down the session if there is a
		 * message delivery failure).
		 *
		 * Assume session teardown will remove all accesses
		 * to this segment.
		 */
		return (0);
	}

#ifdef DEBUG
	if (wrsm_export_memseg_debug & DBG_EXPORT_EXTRA)
		wrsm_tl_dump_message("UNPUBLISH_RESPONSE: ", recvmsg);
#endif
	if (recvmsg->header.message_type !=
	    WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE) {
		DPRINTF(DBG_EXPORT, (CE_WARN,
		    "send_unpublish_msg got invalid response\n"));
		return (0);
	}

	bcopy(&recvmsg->body, &recvargs, sizeof (recvargs));


	if (recvargs.status == WC_DISCONNECTED) {
		disconnect = 1;

		/*
		 * remove from list of segments the remote node is
		 * importing
		 */
		mutex_enter(&node->memseg->lock);
		for (connpp = &node->memseg->connected; *connpp != NULL;
		    connpp = &((*connpp)->next)) {
			if ((*connpp)->exportseg == exportseg) {
				connp = *connpp;
				*connpp = (*connpp)->next;
				kmem_free(connp, sizeof (*connp));
				break;
			}
		}
		mutex_exit(&node->memseg->lock);
	}

	return (disconnect);
}




/*
 * Send the specified node a message indicating new access permissions
 * for the exported segment.
 */
static void
send_access_msg(wrsm_node_t *node, rsm_memseg_id_t segid,
    rsm_permission_t perms)
{
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	access_msg_t args;
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	wrsm_network_t *network = node->network;

	DPRINTF(DBG_EXPORT, (CE_CONT, "ctlr %d: send_access_msg() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	/* LINTED */
	ASSERT(sizeof (access_msg_t) <= WRSM_MESSAGE_BODY_SIZE);

	msg->header.message_type = WRSM_MSG_SEGMENT_ACCESS;
	args.segid = segid;
	args.perms = perms;

	bcopy(&args, &msg->body, sizeof (args));
	if (wrsm_tl_rpc(network, node->config->cnodeid, msg, recvmsg)
	    != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not
		 * delivered or response not received).  (Transport
		 * Layer tears down the session if there is a
		 * message delivery failure).
		 *
		 * Assume session teardown will remove all accesses
		 * to this segment.
		 */
		return;
	}

#ifdef DEBUG
	if (wrsm_export_memseg_debug & DBG_EXPORT_EXTRA)
		wrsm_tl_dump_message("ACCESS_RESPONSE: ", recvmsg);
#endif
}




/*
 * The session to the specified node has been torn down.  Clean up
 * references by this node to any exported segments.
 */
boolean_t
exportseg_sess_teardown(wrsm_node_t *node)
{
	exportseg_t *exportseg;
	rsm_memseg_id_t segid;
	connect_info_t *connp;
	int disconnects = 0;
	wrsm_network_t *network = node->network;

	DPRINTF(DBG_EXPORT, (CE_CONT, "exportseg_sess_teardown"));

	/*
	 * it is presumed that at this point the node was removed from the
	 * cluster_members_bits registers in all wcis
	 */

	ASSERT(MUTEX_HELD(&node->memseg->lock));

	/*
	 * clean up exports to the remote node
	 */
	while (node->memseg->connected) {
		connp = node->memseg->connected;
		exportseg = connp->exportseg;
		segid = exportseg->segid;
		node->memseg->connected = node->memseg->connected->next;
		kmem_free(connp, sizeof (*connp));
		mutex_exit(&node->memseg->lock);
		/*
		 * Must release node->memseg->lock in order to take
		 * exportseg lock; meanwhile, exportseg could disappear, so
		 * use find_and_lock_exportseg to verify it's still around.
		 */
		exportseg = find_and_lock_exportseg(node->network, segid);
		if (exportseg) {
			if (exportseg->nodes[node->config->cnodeid].inuse) {
				exportseg->nodes[node->config->cnodeid].inuse =
				    B_FALSE;
				disconnects++;
				if (exportseg->wait_for_disconnects > 0) {
					exportseg->wait_for_disconnects--;
				}
			}
			mutex_exit(&exportseg->lock);
		}
		mutex_enter(&network->lock);
		network->memseg->export_connected -= disconnects;
		mutex_exit(&network->lock);
		disconnects = 0;
		mutex_enter(&node->memseg->lock);
	}


	return (B_TRUE);
}



/*
 * Allocate and set up cmmu entries for the segment.
 * The exportseg lock is not needed because segment is not yet visible to
 * other threads.
 */
static int
setup_segment_memory(exportseg_t *exportseg, int flags,
    rsm_memory_local_t *memory, boolean_t sleep)
{
	wrsm_network_t *network = exportseg->network;
	boolean_t allow_lg_pages = B_TRUE;
	int i;
	int err;

	DPRINTF(DBG_EXPORT, (CE_CONT, "setup segment memory\n"));

	exportseg->num_pages = exportseg->size >> MMU_PAGESHIFT;
	ASSERT(exportseg->num_pages != 0);
	exportseg->pfn_list = kmem_zalloc(
	    exportseg->num_pages * sizeof (pfn_t), KM_SLEEP);
	for (i = 0; i < exportseg->num_pages; i++) {
		exportseg->pfn_list[i] = PFN_INVALID;
	}


	/*
	 * Allocate CMMU entries for this segment.  We can't use 4 Meg
	 * entries if we don't export a 4 meg ncslice, if REBIND is
	 * permitted, or if there is no memory backing the segment.
	 *
	 * If backing memory was provided, calculate the physical address
	 * for each CMMU entry, and store it in the CMMU's LPA field.  Note:
	 * there is no guarantee that a buf struct will hang around, so can't
	 * just save a pointer to it.  Similarly, there is no guarantee
	 * that the particular address space mapping will remain the same
	 * (although it must be mapped somewhere and locked down).
	 *
	 * If we need the physical addresses for any reason (such as to
	 * create HW based per node entries), the LPA can be read from the
	 * CMMU entry or found in the pfn_list.  (The LPA field is
	 * RW.)
	 */

	if (!network->have_lg_page_ncslice ||
	    (flags & RSM_ALLOW_UNBIND_REBIND)) {
		allow_lg_pages = B_FALSE;
	}

	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "setup seg cmmu entries\n"));

	if (memory == NULL) {
		/* use small page CMMU entries */
		if ((alloc_cmmu_tuples(exportseg, exportseg->num_pages, 0,
		    MMU_PAGESIZE, &exportseg->cmmugrps, sleep)) !=
		    WRSM_SUCCESS) {
			kmem_free(exportseg->pfn_list,
			    exportseg->num_pages * sizeof (pfn_t));
			return (RSMERR_INSUFFICIENT_RESOURCES);
		}

	} else if (memory->ms_type == RSM_MEM_VADDR ||
	    memory->ms_type == RSM_MEM_BUF) {
		if ((err = alloc_seg_cmmu_entries(exportseg, memory,
		    exportseg->size, allow_lg_pages, sleep)) != WRSM_SUCCESS) {
			kmem_free(exportseg->pfn_list,
			    exportseg->num_pages * sizeof (pfn_t));
			return (err);
		}

	} else {
		kmem_free(exportseg->pfn_list,
		    exportseg->num_pages * sizeof (pfn_t));
		return (RSMERR_BAD_MSTYPE);
	}

	return (RSM_SUCCESS);
}

/*
 * Invalidate and remove cmmu entries for the segment.
 */
static void
teardown_segment_memory(exportseg_t *exportseg)
{
	/*
	 * Unbind all pages, free CMMU entries.
	 */
	(void) clear_lpa_fields(exportseg, 0, exportseg->size, B_FALSE);
	mseg_free_cmmus(exportseg);
	kmem_free(exportseg->pfn_list, exportseg->num_pages * sizeof (pfn_t));
}



/*
 * Allocate and set up cmmu entry for the smallput interrupt page.
 * The exportseg lock is not needed because segment is not yet visible to
 * other threads.
 */
static int
setup_smallput_interrupt(exportseg_t *exportseg, boolean_t sleep)
{
	wrsm_network_t *network = exportseg->network;
	unsigned num_tuples;
	int err;
	int flags;

	DPRINTF(DBG_EXPORT, (CE_CONT, "setup smallput interrupt\n"));

	/*
	 * Set up an interrupt page for small puts.  Allocate a CMMU entry,
	 * then create a receive queue.
	 */
	if ((err = wrsm_cmmu_alloc(network, CMMU_PAGE_SIZE_SMALL, 1,
	    &(exportseg->small_put_intr.tuple), &num_tuples, sleep)) !=
	    WRSM_SUCCESS) {
		ASSERT(err != ENOSPC);
		return (RSMERR_INSUFFICIENT_RESOURCES);

	}
	ASSERT(exportseg->small_put_intr.tuple->ncslice ==
	    network->nodes[network->cnodeid]->config->comm_ncslice);

	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "smallput interrupt: index %d\n",
	    exportseg->small_put_intr.tuple->index));


	/*
	 * wrsm_intr_create_recvq() sets up the cmmu entry - identified by
	 * the passed in cmmu index. Create the recvq with the invalid
	 * flag set, and sleep waiting for resources if the caller set
	 * the sleep flag.
	 */
	flags = WRSM_CREATE_RECVQ_INVALID;
	if (sleep) {
		flags |= WRSM_CREATE_RECVQ_SLEEP;
	}
	err = wrsm_intr_create_recvq(network,
	    WRSM_SMPUT_INTR_TYPE,
	    WRSM_SMPUT_PACKETRING_SIZE,
	    exportseg->small_put_intr.tuple->index,
	    &(exportseg->small_put_intr.recvq),
	    0, /* from_node - N/A for memsegs */
	    exportseg,
	    flags);
	if (err != WRSM_SUCCESS) {
		DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "smallput interrupt: "
		    "freeing index %d\n",
		    exportseg->small_put_intr.tuple->index));

		wrsm_cmmu_free(network, 1, exportseg->small_put_intr.tuple);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

	DPRINTF(DBG_EXPORT, (CE_CONT, "small put recvq 0x%p\n",
	    (void *)exportseg->small_put_intr.recvq));

	return (RSM_SUCCESS);
}

/*
 * Invalidate and remove cmmu entry for the smallput interrupt page.
 */
static void
teardown_smallput_interrupt(exportseg_t *exportseg)
{
	wrsm_network_t *network = exportseg->network;

	/*
	 * Release the small put interrupt page recvq
	 * and free the cmmu entry.
	 */
	wrsm_intr_destroy_recvq(network,
	    exportseg->small_put_intr.recvq);
	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "teardown_smallput interrupt: "
	    "freeing index %d\n",
	    exportseg->small_put_intr.tuple->index));
	wrsm_cmmu_free(network, 1, exportseg->small_put_intr.tuple);
}



/*
 * Allocate and set up cmmu entry for the barrier page.
 * The exportseg lock is not needed because segment is not yet visible to
 * other threads.
 */
static int
setup_barrier_page(exportseg_t *exportseg, boolean_t sleep)
{
	wrsm_network_t *network = exportseg->network;
	unsigned num_tuples;
	caddr_t aligned_vaddr;
	wrsm_cmmu_t cmmu;
	pfn_t pfn;
	/* LINTED: E_FUNC_SET_NOT_USED */
	int err;

	DPRINTF(DBG_EXPORT, (CE_CONT, "setup barrier page\n"));

	/*
	 * Set up a barrier page: allocate a page of memory, allocate a
	 * cmmu entry, and point the cmmu entry at the memory page.
	 */

	/*
	 * Need an aligned page, so allocate 2 pages.
	 */
	exportseg->barrier_page.vaddr = wrsm_alloc(MMU_PAGESIZE * 2, VM_SLEEP);
	bzero(exportseg->barrier_page.vaddr, (MMU_PAGESIZE * 2));

	if ((err = wrsm_cmmu_alloc(network, CMMU_PAGE_SIZE_SMALL, 1,
	    &(exportseg->barrier_page.tuple), &num_tuples, sleep)) !=
	    WRSM_SUCCESS) {
		ASSERT(err != ENOSPC);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}
	ASSERT(exportseg->barrier_page.tuple->ncslice ==
	    network->nodes[network->cnodeid]->config->comm_ncslice);

	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "setup_barrier interrupt: "
	    "index %d\n",
	    exportseg->barrier_page.tuple->index));

	cmmu.entry_0.val = 0;
	cmmu.entry_0.bit.count_enable = B_FALSE;
	cmmu.entry_0.bit.large_page = B_FALSE;
	cmmu.entry_0.bit.user_err = B_FALSE;
	cmmu.entry_0.bit.writable = B_TRUE;
	cmmu.entry_0.bit.from_all = B_TRUE;
	cmmu.entry_0.bit.from_node = 255;
	cmmu.entry_0.bit.valid = B_TRUE;
	cmmu.entry_0.bit.type = CMMU_TYPE_CACHEABLE;

	cmmu.entry_1.val = 0;
	aligned_vaddr = (caddr_t)
	    ((uint64_t)((caddr_t)exportseg->barrier_page.vaddr +
	    MMU_PAGEOFFSET) & (uint64_t)MMU_PAGEMASK);
	pfn = hat_getpfnum(kas.a_hat, aligned_vaddr);
	cmmu.entry_1.addr.lpa_page = pfn;

	DPRINTF(DBG_EXPORT, (CE_CONT, "setup barrier cmmu entry to "
	    "point to paddr 0x%lx (pfn 0x%lx)\n", va_to_pa(aligned_vaddr),
	    pfn));

	wrsm_cmmu_update(network, &cmmu, exportseg->barrier_page.tuple->index,
	    CMMU_UPDATE_ALL);

	return (RSM_SUCCESS);
}

/*
 * Invalidate and remove cmmu entry for the barrier page.
 */
static void
teardown_barrier_page(exportseg_t *exportseg)
{
	wrsm_network_t *network = exportseg->network;
	wrsm_cmmu_t cmmu;

	/*
	 * Invalidate and free barrier page cmmu entry, and free the
	 * barrier page memory.
	 */
	cmmu.entry_0.bit.valid = B_FALSE;
	wrsm_cmmu_update(network, &cmmu, exportseg->barrier_page.tuple->index,
	    CMMU_UPDATE_VALID);
	DPRINTF(DBG_EXPORT_EXTRA, (CE_CONT, "teardown_barrier interrupt: "
	    "freeing index %d\n",
	    exportseg->barrier_page.tuple->index));
	wrsm_cmmu_free(network, 1, exportseg->barrier_page.tuple);
	wrsm_free(exportseg->barrier_page.vaddr, MMU_PAGESIZE * 2);
}




/*
 * Free exportsegs when network is being removed.  Will only happen
 * if client does a release_controller without first releasing
 * exported segments.
 */
void
wrsm_free_exportsegs(wrsm_network_t *network)
{
	exportseg_t *exportseg;
	exportseg_t **exportsegp;
	int i;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsm_free_exportseg: ctlr %d\n",
	    network->rsm_ctlr_id));

	mutex_enter(&network->lock);
	if (network->memseg->export_count == 0) {
		mutex_exit(&network->lock);
		return;
	}

	mutex_enter(&all_exportsegs_lock);
	for (i = 0; i < WRSM_SEGID_HASH_SIZE; i++) {
		exportsegp = &(all_exportsegs_hash[i]);
		while (*exportsegp != NULL) {
			exportseg = *exportsegp;
			if (exportseg->network == network) {
				/*
				 * remove exportseg from all_exportsegs_hash
				 * and destroy it
				 */
				*exportsegp = exportseg->all_next;
				mutex_destroy(&exportseg->lock);
				if (exportseg->size > 0) {
					teardown_segment_memory(exportseg);
					teardown_smallput_interrupt(exportseg);
					teardown_barrier_page(exportseg);
				}
				kmem_free(exportseg, sizeof (exportseg_t));
				ASSERT(network->memseg->export_count > 0);
				network->memseg->export_count--;
			} else {
				exportsegp = &((*exportsegp)->all_next);
			}
		}
	}
	mutex_exit(&all_exportsegs_lock);
#ifdef DEBUG
	if (network->memseg->export_count > 0) {
		DPRINTF(DBG_WARN, (CE_WARN, "wrsm_free_exportseg: network "
		    "exportseg count %d after exportseg cleanup\n",
		    network->memseg->export_count));
	}
#endif
	mutex_exit(&network->lock);
}



/*
 *
 * RSMPI entry points
 *
 */


/* ARGSUSED */
int
wrsmrsm_seg_create(rsm_controller_handle_t controller,
    rsm_memseg_export_handle_t *memsegp,
    size_t size, uint_t flags, rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg)
{
	wrsm_network_t *network = (wrsm_network_t *)controller;
	exportseg_t *exportseg;
	int err;
	int i;
	int index;
	boolean_t sleep = B_FALSE;


	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_seg_create(ctlr %d)\n",
	    network->rsm_ctlr_id));

	if (callback != RSM_RESOURCE_SLEEP &&
	    callback != RSM_RESOURCE_DONTWAIT) {
		/* we don't support callbacks */
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if (callback == RSM_RESOURCE_SLEEP)
		sleep = B_TRUE;

	if ((size & MMU_PAGEOFFSET) != 0) {
		/* size must be full pages */
		DPRINTF(DBG_WARN, (CE_WARN, "seg_create: bad size 0x%lx\n",
		    size));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/*
	 * ddi_map() in sun4u's rootnex.c limits us to 4GB of total
	 * mappable space per segment.
	 */
	if (size > (uint64_t)UINT_MAX) {
		DPRINTF(DBG_WARN, (CE_WARN, "seg_create: bad size 0x%llx\n",
			size));
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

	exportseg = kmem_zalloc(sizeof (exportseg_t), KM_SLEEP);
	exportseg->network = network;
	exportseg->size = size;
	exportseg->state = memseg_unpublished;
	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_seg_create: exportseg 0x%p "
	    "(8k) size 0x%lx\n", (void *)exportseg, exportseg->size));

	if (exportseg->size > 0) {

		if ((err = setup_segment_memory(exportseg, flags, memory,
		    sleep)) != RSM_SUCCESS) {
			kmem_free(exportseg, sizeof (exportseg_t));
			return (err);
		}

		if ((err = setup_smallput_interrupt(exportseg, sleep))
		    != RSM_SUCCESS) {
			teardown_segment_memory(exportseg);
			kmem_free(exportseg, sizeof (exportseg_t));
			return (err);
		}

		if ((err = setup_barrier_page(exportseg, sleep))
		    != RSM_SUCCESS) {
			teardown_segment_memory(exportseg);
			teardown_smallput_interrupt(exportseg);
			kmem_free(exportseg, sizeof (exportseg_t));
			return (err);
		}
	}

	mutex_init(&exportseg->lock, NULL, MUTEX_DRIVER, NULL);
	exportseg->valid = B_TRUE;

	/* save flags */
	if (flags & RSM_ALLOW_UNBIND_REBIND) {
		exportseg->allow_rebind = B_TRUE;
	}

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		exportseg->nodes[i].perms = RSM_PERM_NONE;
		exportseg->nodes[i].actual_perms = RSM_PERM_NONE;
	}

	/*
	 * add exportseg to all_exportsegs_hash
	 */
	index = WRSM_PTR_HASH_FUNC(exportseg);
	mutex_enter(&network->lock);
	network->memseg->export_count++;
	mutex_exit(&network->lock);
	mutex_enter(&all_exportsegs_lock);
	exportseg->all_next = all_exportsegs_hash[index];
	all_exportsegs_hash[index] = exportseg;
	mutex_exit(&all_exportsegs_lock);


	*memsegp = (rsm_memseg_export_handle_t)exportseg;

	ASSERT(MUTEX_NOT_HELD(&exportseg->lock));
	return (RSM_SUCCESS);
}





int
wrsmrsm_seg_destroy(rsm_memseg_export_handle_t handle)
{
	exportseg_t *exportseg = (exportseg_t *)handle;
	exportseg_t **exportsegp;
	wrsm_network_t *network;
	boolean_t found_exportseg;
	int err;
	int index;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_seg_destroy(0x%p)\n",
	    (void *)exportseg));

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	/*
	 * make sure segment is not published
	 */
	if (exportseg->state != memseg_unpublished) {
		DPRINTF(DBG_EXPORT,
		    (CE_CONT, "seg_destroy - memseg 0x%p is published "
		    "with segid %d\n", (void *)exportseg, exportseg->segid));
		mutex_exit(&exportseg->lock);
		return (RSMERR_SEG_PUBLISHED);
	}

	network = exportseg->network;

	/*
	 * Remove exportseg from all_exportsegs_hash.  exportseg->lock
	 * can't be held prior to taking all_exportsegs_lock, so mark
	 * exportseg as invalid until it is actually removed from the hash.
	 * Searching for exportseg in the hash fails when exportseg->valid
	 * is B_FALSE.
	 */
	exportseg->valid = B_FALSE;
	mutex_exit(&exportseg->lock);

	index = WRSM_PTR_HASH_FUNC(exportseg);
	mutex_enter(&all_exportsegs_lock);
	found_exportseg = B_FALSE;
	for (exportsegp = &(all_exportsegs_hash[index]);
	    *exportsegp != NULL;
	    exportsegp = &((*exportsegp)->all_next)) {
		/* make sure no one else got here first */
		if ((*exportsegp == exportseg) &&
		    (exportseg->valid == B_FALSE)) {
			*exportsegp = exportseg->all_next;
			found_exportseg = B_TRUE;
			break;
		}
	}
	mutex_exit(&all_exportsegs_lock);

	if (found_exportseg) {

		mutex_enter(&network->lock);
		network->memseg->export_count--;
		mutex_exit(&network->lock);

		mutex_destroy(&exportseg->lock);

		if (exportseg->size > 0) {
			teardown_segment_memory(exportseg);
			teardown_smallput_interrupt(exportseg);
			teardown_barrier_page(exportseg);
		}

		kmem_free(exportseg, sizeof (exportseg_t));
	}

	return (RSM_SUCCESS);
}



/* ARGSUSED */
int
wrsmrsm_bind(rsm_memseg_export_handle_t memseg,
    off_t offset,
    rsm_memory_local_t *memory,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	size_t nbytes;
	struct buf *bp;
	page_t *startpp = NULL;
	struct as *as = NULL;
	void *vaddr = NULL;
	int err;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_bind(0x%p)\n",
	    (void *)exportseg));

	if (callback != RSM_RESOURCE_SLEEP &&
	    callback != RSM_RESOURCE_DONTWAIT) {
		/* we don't support callbacks */
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if (offset & (off_t)MMU_PAGEOFFSET) {
		/* can only bind starting at page boundaries */
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	if (memory->ms_type == RSM_MEM_BUF) {
		bp = memory->ms_bp;

		ASSERT(bp);
		ASSERT(SEMA_HELD(&bp->b_sem));

		nbytes = bp->b_bcount;

		if (bp->b_flags & B_PAGEIO) {
			if (!bp->b_pages) {
				mutex_exit(&exportseg->lock);
				return (RSMERR_NO_BACKING_MEM);
			} else {
				startpp = bp->b_pages;
			}
		} else {
			vaddr = (void *)bp->b_un.b_addr;
			if (bp->b_flags & B_PHYS) {
				if (bp->b_proc == NULL ||
				    (as = bp->b_proc->p_as) == NULL)
					as = &kas;
			} else {
				as = &kas;
			}
		}
	} else if (memory->ms_type == RSM_MEM_VADDR) {
		nbytes = memory->ms_length;
		as = memory->ms_as;
		vaddr = memory->ms_vaddr;
	} else {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MSTYPE);
	}

	if (nbytes + offset > exportseg->size) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (nbytes & MMU_PAGEOFFSET) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if ((uint64_t)vaddr & MMU_PAGEOFFSET) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (exportseg->size == 0) {
		/* don't touch cmmu entries if a 0 length segment */
		mutex_exit(&exportseg->lock);
		return (RSM_SUCCESS);
	}

	/*
	 * set up cmmu entries to point at the specified memory
	 */
	err = set_lpa_fields(exportseg, offset, nbytes, as, vaddr,
	    startpp);

	mutex_exit(&exportseg->lock);
	return (err);
}



int
wrsmrsm_unbind(rsm_memseg_export_handle_t memseg, off_t offset,
    size_t length)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	int err;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_unbind(0x%p)\n",
	    (void *)exportseg));

	if (offset & MMU_PAGEOFFSET) {
		/* can only unbind starting at page boundaries */
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (length & MMU_PAGEOFFSET) {
		/* can only unbind page aligned regions */
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	if (!exportseg->allow_rebind) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_UNBIND_REBIND_NOT_ALLOWED);
	}

	if (offset + length > exportseg->size) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (exportseg->size == 0) {
		/* don't touch cmmu entries if a 0 length segment */
		mutex_exit(&exportseg->lock);
		return (RSM_SUCCESS);
	}

	/*
	 * modify cmmu entries to no longer point to this memory
	 */
	err = clear_lpa_fields(exportseg, offset, length, B_TRUE);
	mutex_exit(&exportseg->lock);
	return (err);
}


/* ARGSUSED */
int
wrsmrsm_rebind(rsm_memseg_export_handle_t memseg, off_t offset,
    rsm_memory_local_t *memory, rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	size_t nbytes;
	struct buf *bp;
	page_t *startpp = NULL;
	struct as *as = NULL;
	void *vaddr = NULL;
	int err;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_rebind(0x%p)\n",
	    (void *)exportseg));

	if (callback != RSM_RESOURCE_SLEEP &&
	    callback != RSM_RESOURCE_DONTWAIT) {
		/* we don't support callbacks */
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if (offset & MMU_PAGEOFFSET) {
		/* can only rebind starting at page boundaries */
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	if (!exportseg->allow_rebind) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_UNBIND_REBIND_NOT_ALLOWED);
	}

	if (memory->ms_type == RSM_MEM_BUF) {
		bp = memory->ms_bp;

		ASSERT(bp);
		ASSERT(SEMA_HELD(&bp->b_sem));

		nbytes = bp->b_bcount;

		if (bp->b_flags & B_PAGEIO) {
			if (!bp->b_pages) {
				mutex_exit(&exportseg->lock);
				return (RSMERR_NO_BACKING_MEM);
			} else {
				startpp = bp->b_pages;
			}
		} else {
			vaddr = (void *)bp->b_un.b_addr;
			if (bp->b_flags & B_PHYS) {
				if (bp->b_proc == NULL ||
				    (as = bp->b_proc->p_as) == NULL)
					as = &kas;
			} else {
				as = &kas;
			}
		}

	} else if (memory->ms_type == RSM_MEM_VADDR) {
		nbytes = memory->ms_length;
		as = memory->ms_as;
		vaddr = memory->ms_vaddr;
	} else {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MSTYPE);
	}

	if (nbytes + offset > exportseg->size) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (nbytes & MMU_PAGEOFFSET) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if ((uint64_t)vaddr & MMU_PAGEOFFSET) {
		mutex_exit(&exportseg->lock);
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (exportseg->size == 0) {
		/* don't touch cmmu entries if a 0 length segment */
		mutex_exit(&exportseg->lock);
		return (RSM_SUCCESS);
	}

	/*
	 * modify cmmu entries to remove old mappings
	 */
	if ((err = clear_lpa_fields(exportseg, offset, nbytes, B_FALSE)) !=
	    WRSM_SUCCESS) {
		mutex_exit(&exportseg->lock);
		return (err);
	}

	/*
	 * modify cmmu entries to point to new memory
	 */
	err = set_lpa_fields(exportseg, offset, nbytes, as, vaddr,
	    startpp);

	mutex_exit(&exportseg->lock);
	return (err);
}


/* ARGSUSED */
int
wrsmrsm_publish(rsm_memseg_export_handle_t memseg,
    rsm_access_entry_t access_list[],
    uint_t access_list_length,
    rsm_memseg_id_t segid,
    rsm_resource_callback_t callback,
    rsm_resource_callback_arg_t callback_arg)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	int err;


	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_publish(0x%p)\n",
	    (void *)exportseg));

	if (callback != RSM_RESOURCE_SLEEP &&
	    callback != RSM_RESOURCE_DONTWAIT) {
		/* we don't support callbacks */
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	if ((err = exportseg_set_segid(exportseg, segid)) != RSM_SUCCESS) {
		if (err != RSMERR_BAD_SEG_HNDL) {
			mutex_exit(&exportseg->lock);
		}
		return (err);
	}


	if ((err = apply_access_list(exportseg, access_list,
	    access_list_length)) != RSM_SUCCESS) {
		mutex_exit(&exportseg->lock);
		exportseg_unset_segid(exportseg, segid);
		return (err);
	}

	if (exportseg->size > 0) {
		enable_smallput_intr_page(exportseg);
	}

	mutex_exit(&exportseg->lock);
	return (RSM_SUCCESS);
}



int
wrsmrsm_unpublish(rsm_memseg_export_handle_t memseg)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	rsm_memseg_id_t segid;
	wrsm_network_t *network;
	int err;
	int i;
	int disconnects = 0;
	int rcv_disconnect;
	int num_waiting;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_unpublish(0x%p)\n",
	    (void *)exportseg));

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}
	segid = exportseg->segid;

	if (exportseg->state == memseg_wait_for_disconnects) {
		/*
		 * segment was already unpublished, but wasn't able
		 * to complete cleanup.  Check whether cleanup has
		 * now completed.
		 */
		if (exportseg->wait_for_disconnects) {
			mutex_exit(&exportseg->lock);
			return (RSMERR_SEG_IN_USE);
		} else {
			mutex_exit(&exportseg->lock);
			exportseg_unset_segid(exportseg, segid);
			return (RSM_SUCCESS);
		}
	}

	if (exportseg->state != memseg_published) {
		/* segment is not published */
		mutex_exit(&exportseg->lock);
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	network = exportseg->network;

	/*
	 * Set state to reflect we're doing an unpublish.
	 *
	 * update state prior to releasing lock, so subsequent publish or
	 * republish calls fail.
	 *
	 * exportseg->wait_for_disconnects is used as a reference count
	 * for the export_seg.  The segment can't be freed until
	 * the count goes to zero.
	 *
	 * Note that the export segment lock is released prior
	 * to sending the RPC and thus the export seg state can change.
	 */
	exportseg->state = memseg_wait_for_disconnects;
	exportseg->wait_for_disconnects  = 0;

	/*
	 * Notify all importers that segment is being unpublished.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		exportseg->nodes[i].allow_import = B_FALSE;
		exportseg->nodes[i].perms = RSM_PERM_NONE;
		exportseg->nodes[i].actual_perms = RSM_PERM_NONE;

		if (exportseg->nodes[i].inuse) {
			exportseg->wait_for_disconnects++;

			mutex_exit(&exportseg->lock);
			rcv_disconnect = send_unpublish_msg(network->nodes[i],
				    exportseg);
			/*
			 * If a session teardown occurs while we are waiting
			 * for the reponse to the rpc,
			 * exportseg_sess_teardown(), while holding  exportseg
			 * lock, will decrement wait_for_disconnects,
			 * decrement network->memseg->export_connected,
			 * and clear inuse.
			 * So, if inuse is cleared, we don't want to
			 * do those actions again here.
			 */
			mutex_enter(&exportseg->lock);
			if (rcv_disconnect && exportseg->nodes[i].inuse) {
			    disconnects++;
			    exportseg->wait_for_disconnects--;
			    exportseg->nodes[i].inuse = B_FALSE;
			}
		}
	}

	/*
	 * disable ability to write to segment
	 */
	exportseg->writeable = B_FALSE;

	/* only need to update cmmu entries if size > 0 */
	if (exportseg->size != 0) {
		disable_smallput_intr_page(exportseg);
		update_cmmu_fields(exportseg, 0, exportseg->size,
		    memseg_unset_valid);
	}


	/*
	 * Kernel agent on importer doesn't always release mappings
	 * (doesn't call rsm_unmap) in a timely fashion.  So instead of
	 * waiting to complete the disconnect or tearing down the session,
	 * return RSMERR_SEG_IN_USE.
	 */
	num_waiting = exportseg->wait_for_disconnects;
	mutex_exit(&exportseg->lock);

	mutex_enter(&network->lock);
	network->memseg->export_connected -= disconnects;
	mutex_exit(&network->lock);

	if (num_waiting) {
		return (RSMERR_SEG_IN_USE);
	}

	exportseg_unset_segid(exportseg, segid);

	return (RSM_SUCCESS);
}




/* ARGSUSED */
int
wrsmrsm_republish(rsm_memseg_export_handle_t memseg,
    rsm_access_entry_t access_list[], uint_t access_list_length,
    rsm_resource_callback_t callback, rsm_resource_callback_arg_t callback_arg)
{
	exportseg_t *exportseg = (exportseg_t *)memseg;
	int err;
	int i;

	DPRINTF(DBG_EXPORT, (CE_CONT, "wrsmrsm_republish(0x%p)\n",
	    (void *)exportseg));

	if (callback != RSM_RESOURCE_SLEEP &&
	    callback != RSM_RESOURCE_DONTWAIT) {
		/* we don't support callbacks */
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if ((err = lock_exportseg(exportseg)) != RSM_SUCCESS) {
		return (err);
	}

	if (exportseg->state != memseg_published) {
		/* segment is not published */
		mutex_exit(&exportseg->lock);
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	/*
	 * apply new permissions
	 */
	if ((err = apply_access_list(exportseg, access_list,
	    access_list_length)) != RSM_SUCCESS) {
		mutex_exit(&exportseg->lock);
		return (err);
	}

	/*
	 * Notify current importers of permission changes.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (exportseg->nodes[i].inuse) {
			mutex_exit(&exportseg->lock);
			send_access_msg(exportseg->network->nodes[i],
			    exportseg->segid,
			    exportseg->nodes[i].perms);
			mutex_enter(&exportseg->lock);
		}
	}

	mutex_exit(&exportseg->lock);
	return (RSM_SUCCESS);
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * gnttab.c
 *
 * Granting foreign access to our memory reservation.
 *
 * Copyright (c) 2005-2006, Christopher Clark
 * Copyright (c) 2004-2005, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <sys/archsystm.h>
#ifdef XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#include <sys/mman.h>
#include <vm/hat.h>
#endif
#include <sys/hypervisor.h>
#include <sys/gnttab.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/condvar.h>
#include <sys/cpuvar.h>
#include <sys/taskq.h>
#include <sys/panic.h>
#include <sys/cmn_err.h>
#include <sys/promif.h>
#include <sys/cpu.h>
#include <sys/vmem.h>
#include <vm/hat_i86.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#ifndef XPV_HVM_DRIVER
#include <sys/bootinfo.h>
#include <sys/multiboot.h>
#include <vm/kboot_mmu.h>
#endif
#include <sys/bootvfs.h>
#include <sys/bootprops.h>
#include <vm/seg_kmem.h>
#include <sys/mman.h>

/* Globals */

static grant_ref_t **gnttab_list;
static uint_t nr_grant_frames;
static int gnttab_free_count;
static grant_ref_t gnttab_free_head;
static kmutex_t gnttab_list_lock;
static grant_entry_t *shared;
static struct gnttab_free_callback *gnttab_free_callback_list;

/* Macros */

#define	GT_PGADDR(i) ((uintptr_t)shared + ((i) << MMU_PAGESHIFT))
#define	VALID_GRANT_REF(r) ((r) < (nr_grant_frames * GREFS_PER_GRANT_FRAME))
#define	RPP (PAGESIZE / sizeof (grant_ref_t))
#define	GNTTAB_ENTRY(entry) (gnttab_list[(entry) / RPP][(entry) % RPP])
#define	CMPXCHG(t, c, n) atomic_cas_16((t), (c), (n))
/* External tools reserve first few grant table entries. */
#define	NR_RESERVED_ENTRIES 8
#define	GNTTAB_LIST_END 0xffffffff
#define	GREFS_PER_GRANT_FRAME (PAGESIZE / sizeof (grant_entry_t))

/* Implementation */

static uint_t
max_nr_grant_frames(void)
{
	struct gnttab_query_size query;
	int rc;

	query.dom = DOMID_SELF;

	rc = HYPERVISOR_grant_table_op(GNTTABOP_query_size, &query, 1);
	if ((rc < 0) || (query.status != GNTST_okay))
		return (4); /* Legacy max supported number of frames */

	ASSERT(query.max_nr_frames);
	return (query.max_nr_frames);
}

static void
do_free_callbacks(void)
{
	struct gnttab_free_callback *callback, *next;

	callback = gnttab_free_callback_list;
	gnttab_free_callback_list = NULL;

	while (callback != NULL) {
		next = callback->next;
		if (gnttab_free_count >= callback->count) {
			callback->next = NULL;
			callback->fn(callback->arg);
		} else {
			callback->next = gnttab_free_callback_list;
			gnttab_free_callback_list = callback;
		}
		callback = next;
	}
}

static void
check_free_callbacks(void)
{
	if (gnttab_free_callback_list)
		do_free_callbacks();
}

static int
grow_gnttab_list(uint_t more_frames)
{
	uint_t new_nr_grant_frames, extra_entries, i;
	uint_t nr_glist_frames, new_nr_glist_frames;

	ASSERT(MUTEX_HELD(&gnttab_list_lock));

	new_nr_grant_frames = nr_grant_frames + more_frames;
	extra_entries = more_frames * GREFS_PER_GRANT_FRAME;

	nr_glist_frames = (nr_grant_frames * GREFS_PER_GRANT_FRAME + RPP - 1)
	    / RPP;
	new_nr_glist_frames = (new_nr_grant_frames * GREFS_PER_GRANT_FRAME
	    + RPP - 1) / RPP;
	for (i = nr_glist_frames; i < new_nr_glist_frames; i++)
		gnttab_list[i] = kmem_alloc(PAGESIZE, KM_SLEEP);

	for (i = GREFS_PER_GRANT_FRAME * nr_grant_frames;
	    i < GREFS_PER_GRANT_FRAME * new_nr_grant_frames - 1; i++)
		GNTTAB_ENTRY(i) = i + 1;

	GNTTAB_ENTRY(i) = gnttab_free_head;
	gnttab_free_head = GREFS_PER_GRANT_FRAME * nr_grant_frames;
	gnttab_free_count += extra_entries;

	nr_grant_frames = new_nr_grant_frames;

	check_free_callbacks();

	return (0);
}

static int
gnttab_expand(uint_t req_entries)
{
	uint_t cur, extra;

	ASSERT(MUTEX_HELD(&gnttab_list_lock));

	cur = nr_grant_frames;
	extra = ((req_entries + (GREFS_PER_GRANT_FRAME - 1)) /
	    GREFS_PER_GRANT_FRAME);
	if (cur + extra > max_nr_grant_frames())
		return (-1);

	return (grow_gnttab_list(extra));
}

static int
get_free_entries(int count)
{
	int ref, rc;
	grant_ref_t head;

	mutex_enter(&gnttab_list_lock);
	if (gnttab_free_count < count &&
	    ((rc = gnttab_expand(count - gnttab_free_count)) < 0)) {
		mutex_exit(&gnttab_list_lock);
		return (rc);
	}
	ref = head = gnttab_free_head;
	gnttab_free_count -= count;
	while (count-- > 1)
		head = GNTTAB_ENTRY(head);
	gnttab_free_head = GNTTAB_ENTRY(head);
	GNTTAB_ENTRY(head) = GNTTAB_LIST_END;
	mutex_exit(&gnttab_list_lock);
	return (ref);
}

static void
put_free_entry(grant_ref_t ref)
{
	ASSERT(VALID_GRANT_REF(ref));

	mutex_enter(&gnttab_list_lock);
	GNTTAB_ENTRY(ref) = gnttab_free_head;
	gnttab_free_head = ref;
	gnttab_free_count++;
	check_free_callbacks();
	mutex_exit(&gnttab_list_lock);
}

/*
 * Public grant-issuing interface functions
 */

int
gnttab_grant_foreign_access(domid_t domid, gnttab_frame_t frame, int readonly)
{
	int ref;

	if ((ref = get_free_entries(1)) == -1)
		return (-1);

	ASSERT(VALID_GRANT_REF(ref));

	shared[ref].frame = frame;
	shared[ref].domid = domid;
	membar_producer();
	shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);

	return (ref);
}

void
gnttab_grant_foreign_access_ref(grant_ref_t ref, domid_t domid,
				gnttab_frame_t frame, int readonly)
{
	ASSERT(VALID_GRANT_REF(ref));

	shared[ref].frame = frame;
	shared[ref].domid = domid;
	membar_producer();
	shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
}


int
gnttab_query_foreign_access(grant_ref_t ref)
{
	uint16_t nflags;

	ASSERT(VALID_GRANT_REF(ref));

	nflags = shared[ref].flags;

	return (nflags & (GTF_reading|GTF_writing));
}

/* ARGSUSED */
int
gnttab_end_foreign_access_ref(grant_ref_t ref, int readonly)
{
	uint16_t flags, nflags;

	ASSERT(VALID_GRANT_REF(ref));

	nflags = shared[ref].flags;
	do {
		if ((flags = nflags) & (GTF_reading|GTF_writing)) {
			cmn_err(CE_WARN, "g.e. still in use!");
			return (0);
		}
	} while ((nflags = CMPXCHG(&shared[ref].flags, flags, 0)) != flags);

	return (1);
}

void
gnttab_end_foreign_access(grant_ref_t ref, int readonly, gnttab_frame_t page)
{
	ASSERT(VALID_GRANT_REF(ref));

	if (gnttab_end_foreign_access_ref(ref, readonly)) {
		put_free_entry(ref);
		/*
		 * XXPV - we don't support freeing a page here
		 */
		if (page != 0) {
			cmn_err(CE_WARN,
	"gnttab_end_foreign_access_ref: using unsupported free_page interface");
			/* free_page(page); */
		}
	} else {
		/*
		 * XXX This needs to be fixed so that the ref and page are
		 * placed on a list to be freed up later.
		 */
		cmn_err(CE_WARN, "leaking g.e. and page still in use!");
	}
}

int
gnttab_grant_foreign_transfer(domid_t domid, pfn_t pfn)
{
	int ref;

	if ((ref = get_free_entries(1)) == -1)
		return (-1);

	ASSERT(VALID_GRANT_REF(ref));

	gnttab_grant_foreign_transfer_ref(ref, domid, pfn);

	return (ref);
}

void
gnttab_grant_foreign_transfer_ref(grant_ref_t ref, domid_t domid, pfn_t pfn)
{
	ASSERT(VALID_GRANT_REF(ref));

	shared[ref].frame = pfn;
	shared[ref].domid = domid;
	membar_producer();
	shared[ref].flags = GTF_accept_transfer;
}

gnttab_frame_t
gnttab_end_foreign_transfer_ref(grant_ref_t ref)
{
	gnttab_frame_t frame;
	uint16_t flags;

	ASSERT(VALID_GRANT_REF(ref));

	/*
	 * If a transfer is not even yet started, try to reclaim the grant
	 * reference and return failure (== 0).
	 */
	while (!((flags = shared[ref].flags) & GTF_transfer_committed)) {
		if (CMPXCHG(&shared[ref].flags, flags, 0) == flags)
			return (0);
		(void) HYPERVISOR_yield();
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed)) {
		flags = shared[ref].flags;
		(void) HYPERVISOR_yield();
	}

	/* Read the frame number /after/ reading completion status. */
	membar_consumer();
	frame = shared[ref].frame;
	ASSERT(frame != 0);

	return (frame);
}

gnttab_frame_t
gnttab_end_foreign_transfer(grant_ref_t ref)
{
	gnttab_frame_t frame;

	ASSERT(VALID_GRANT_REF(ref));

	frame = gnttab_end_foreign_transfer_ref(ref);
	put_free_entry(ref);
	return (frame);
}

void
gnttab_free_grant_reference(grant_ref_t ref)
{
	ASSERT(VALID_GRANT_REF(ref));

	put_free_entry(ref);
}

void
gnttab_free_grant_references(grant_ref_t head)
{
	grant_ref_t ref;
	int count = 1;

	if (head == GNTTAB_LIST_END)
		return;
	mutex_enter(&gnttab_list_lock);
	ref = head;
	while (GNTTAB_ENTRY(ref) != GNTTAB_LIST_END) {
		ref = GNTTAB_ENTRY(ref);
		count++;
	}
	GNTTAB_ENTRY(ref) = gnttab_free_head;
	gnttab_free_head = head;
	gnttab_free_count += count;
	check_free_callbacks();
	mutex_exit(&gnttab_list_lock);
}

int
gnttab_alloc_grant_references(uint16_t count, grant_ref_t *head)
{
	int h = get_free_entries(count);

	if (h == -1)
		return (-1);

	*head = h;

	return (0);
}

int
gnttab_empty_grant_references(const grant_ref_t *private_head)
{
	return (*private_head == GNTTAB_LIST_END);
}

int
gnttab_claim_grant_reference(grant_ref_t *private_head)
{
	grant_ref_t g = *private_head;

	if (g == GNTTAB_LIST_END)
		return (-1);
	*private_head = GNTTAB_ENTRY(g);
	return (g);
}

void
gnttab_release_grant_reference(grant_ref_t *private_head, grant_ref_t release)
{
	ASSERT(VALID_GRANT_REF(release));

	GNTTAB_ENTRY(release) = *private_head;
	*private_head = release;
}

void
gnttab_request_free_callback(struct gnttab_free_callback *callback,
	void (*fn)(void *), void *arg, uint16_t count)
{
	mutex_enter(&gnttab_list_lock);
	if (callback->next)
		goto out;
	callback->fn = fn;
	callback->arg = arg;
	callback->count = count;
	callback->next = gnttab_free_callback_list;
	gnttab_free_callback_list = callback;
	check_free_callbacks();
out:
	mutex_exit(&gnttab_list_lock);
}

void
gnttab_cancel_free_callback(struct gnttab_free_callback *callback)
{
	struct gnttab_free_callback **pcb;

	mutex_enter(&gnttab_list_lock);
	for (pcb = &gnttab_free_callback_list; *pcb; pcb = &(*pcb)->next) {
		if (*pcb == callback) {
			*pcb = callback->next;
			break;
		}
	}
	mutex_exit(&gnttab_list_lock);
}

static gnttab_frame_t *
gnttab_setup(gnttab_setup_table_t *pset)
{
	gnttab_frame_t *frames;

	frames = kmem_alloc(pset->nr_frames * sizeof (gnttab_frame_t),
	    KM_SLEEP);

	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(pset->frame_list, frames);

	/*
	 * Take pset->nr_frames pages of grant table space from
	 * the hypervisor and map it
	 */
	if ((HYPERVISOR_grant_table_op(GNTTABOP_setup_table, pset, 1) != 0) ||
	    (pset->status != 0)) {
		cmn_err(CE_PANIC, "Grant Table setup failed");
	}

	return (frames);
}

#ifdef XPV_HVM_DRIVER
static void
gnttab_map(void)
{
	struct xen_add_to_physmap xatp;
	caddr_t va;
	pfn_t pfn;
	int i;

	va = (caddr_t)shared;
	for (i = 0; i < max_nr_grant_frames(); i++) {
		if ((pfn = hat_getpfnum(kas.a_hat, va)) == PFN_INVALID)
			cmn_err(CE_PANIC, "gnttab_map: Invalid pfn");

		xatp.domid = DOMID_SELF;
		xatp.idx = i;
		xatp.space = XENMAPSPACE_grant_table;
		xatp.gpfn = pfn;
		hat_unload(kas.a_hat, va, MMU_PAGESIZE, HAT_UNLOAD);
		/*
		 * This call replaces the existing machine page backing
		 * the given gpfn with the page from the allocated grant
		 * table at index idx. The existing machine page is
		 * returned to the free list.
		 */
		if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp) != 0)
			panic("Couldn't map grant table");
		hat_devload(kas.a_hat, va, MMU_PAGESIZE, pfn,
		    PROT_READ | PROT_WRITE | HAT_STORECACHING_OK,
		    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
		va += MMU_PAGESIZE;
	}
}
#endif /* XPV_HVM_DRIVER */

void
gnttab_init(void)
{
	gnttab_setup_table_t set;
	int i;
	uint_t nr_init_grefs, max_nr_glist_frames, nr_glist_frames;
	gnttab_frame_t *frames;

	/*
	 * gnttab_init() should only be invoked once.
	 */
	mutex_enter(&gnttab_list_lock);
	ASSERT(nr_grant_frames == 0);
	nr_grant_frames = 1;
	mutex_exit(&gnttab_list_lock);

	max_nr_glist_frames = (max_nr_grant_frames() *
	    GREFS_PER_GRANT_FRAME / RPP);

	set.dom = DOMID_SELF;
	set.nr_frames = max_nr_grant_frames();
	frames = gnttab_setup(&set);

#ifdef XPV_HVM_DRIVER
	shared = (grant_entry_t *)xen_alloc_pages(set.nr_frames);

	gnttab_map();
#else /* XPV_HVM_DRIVER */
	shared = vmem_xalloc(heap_arena, set.nr_frames * MMU_PAGESIZE,
	    MMU_PAGESIZE, 0, 0, 0, 0, VM_SLEEP);
	for (i = 0; i < set.nr_frames; i++) {
		hat_devload(kas.a_hat, (caddr_t)GT_PGADDR(i), PAGESIZE,
		    xen_assign_pfn(frames[i]),
		    PROT_READ | PROT_WRITE | HAT_STORECACHING_OK,
		    HAT_LOAD_LOCK);
	}
#endif

	gnttab_list = kmem_alloc(max_nr_glist_frames * sizeof (grant_ref_t *),
	    KM_SLEEP);

	nr_glist_frames = (nr_grant_frames * GREFS_PER_GRANT_FRAME + RPP - 1)
	    / RPP;
	for (i = 0; i < nr_glist_frames; i++) {
		gnttab_list[i] = kmem_alloc(PAGESIZE, KM_SLEEP);
	}

	kmem_free(frames, set.nr_frames * sizeof (gnttab_frame_t));

	nr_init_grefs = nr_grant_frames * GREFS_PER_GRANT_FRAME;

	for (i = NR_RESERVED_ENTRIES; i < nr_init_grefs - 1; i++)
		GNTTAB_ENTRY(i) = i + 1;

	GNTTAB_ENTRY(nr_init_grefs - 1) = GNTTAB_LIST_END;
	gnttab_free_count = nr_init_grefs - NR_RESERVED_ENTRIES;
	gnttab_free_head  = NR_RESERVED_ENTRIES;
}

void
gnttab_resume(void)
{
	gnttab_setup_table_t set;
	int i;
	gnttab_frame_t *frames;
	uint_t available_frames = max_nr_grant_frames();

	if (available_frames < nr_grant_frames) {
		cmn_err(CE_PANIC, "Hypervisor does not have enough grant "
		    "frames: required(%u), available(%u)", nr_grant_frames,
		    available_frames);
	}

#ifdef XPV_HVM_DRIVER
	gnttab_map();
#endif /* XPV_HVM_DRIVER */

	set.dom = DOMID_SELF;
	set.nr_frames = available_frames;
	frames = gnttab_setup(&set);

	for (i = 0; i < available_frames; i++) {
		(void) HYPERVISOR_update_va_mapping(GT_PGADDR(i),
		    FRAME_TO_MA(frames[i]) | PT_VALID | PT_WRITABLE,
		    UVMF_INVLPG | UVMF_ALL);
	}
	kmem_free(frames, set.nr_frames * sizeof (gnttab_frame_t));
}

void
gnttab_suspend(void)
{
	int i;

	/*
	 * clear grant table mappings before suspending
	 */
	for (i = 0; i < max_nr_grant_frames(); i++) {
		(void) HYPERVISOR_update_va_mapping(GT_PGADDR(i),
		    0, UVMF_INVLPG);
	}
}

/*
 * Local variables:
 *  c-file-style: "solaris"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */

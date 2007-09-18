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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * gnttab.c
 *
 * Granting foreign access to our memory reservation.
 *
 * Copyright (c) 2005, Christopher Clark
 * Copyright (c) 2004-2005, K A Fraser
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
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
#include <sys/bootinfo.h>
#include <sys/multiboot.h>
#include <sys/bootvfs.h>
#include <sys/bootprops.h>
#include <vm/kboot_mmu.h>
#include <vm/seg_kmem.h>

#define	cmpxchg(t, c, n) atomic_cas_16((t), (c), (n))

/* External tools reserve first few grant table entries. */
#define	NR_RESERVED_ENTRIES 8

#define	NR_GRANT_ENTRIES (NR_GRANT_FRAMES * \
	    MMU_PAGESIZE / sizeof (grant_entry_t))
#define	GNTTAB_LIST_END (NR_GRANT_ENTRIES + 1)
#define	VALID_GRANT_REF(r) ((r) < NR_GRANT_ENTRIES)

static grant_ref_t gnttab_list[NR_GRANT_ENTRIES];
static int gnttab_free_count;
static grant_ref_t gnttab_free_head;
static kmutex_t gnttab_list_lock;

static grant_entry_t *shared;
#define	GT_PGADDR(i) ((uintptr_t)shared + ((i) << PAGESHIFT))

static struct gnttab_free_callback *gnttab_free_callback_list = NULL;

static int
get_free_entries(int count)
{
	int ref;
	grant_ref_t head;

	mutex_enter(&gnttab_list_lock);
	if (gnttab_free_count < count) {
		mutex_exit(&gnttab_list_lock);
		return (-1);
	}
	ref = head = gnttab_free_head;
	gnttab_free_count -= count;
	while (count-- > 1)
		head = gnttab_list[head];
	gnttab_free_head = gnttab_list[head];
	gnttab_list[head] = GNTTAB_LIST_END;
	mutex_exit(&gnttab_list_lock);
	return (ref);
}

#define	get_free_entry() get_free_entries(1)

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

static void
put_free_entry(grant_ref_t ref)
{
	ASSERT(VALID_GRANT_REF(ref));

	mutex_enter(&gnttab_list_lock);
	gnttab_list[ref] = gnttab_free_head;
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

	if ((ref = get_free_entry()) == -1)
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
	} while ((nflags = cmpxchg(&shared[ref].flags, flags, 0)) != flags);

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
gnttab_grant_foreign_transfer(domid_t domid)
{
	int ref;

	if ((ref = get_free_entry()) == -1)
		return (-1);

	ASSERT(VALID_GRANT_REF(ref));

	shared[ref].frame = 0;
	shared[ref].domid = domid;
	membar_producer();
	shared[ref].flags = GTF_accept_transfer;

	return (ref);
}

void
gnttab_grant_foreign_transfer_ref(grant_ref_t ref, domid_t domid)
{
	ASSERT(VALID_GRANT_REF(ref));

	shared[ref].frame = 0;
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
		if (cmpxchg(&shared[ref].flags, flags, 0) == flags)
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
	while (gnttab_list[ref] != GNTTAB_LIST_END) {
		ref = gnttab_list[ref];
		count++;
	}
	gnttab_list[ref] = gnttab_free_head;
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
gnttab_claim_grant_reference(grant_ref_t *private_head)
{
	grant_ref_t g = *private_head;

	if (g == GNTTAB_LIST_END)
		return (-1);
	*private_head = gnttab_list[g];
	return (g);
}

void
gnttab_release_grant_reference(grant_ref_t *private_head, grant_ref_t release)
{
	ASSERT(VALID_GRANT_REF(release));

	gnttab_list[release] = *private_head;
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
gnttab_init(void)
{
	gnttab_setup_table_t set;
	gnttab_frame_t frames[NR_GRANT_FRAMES];
	int i;

	set.dom = DOMID_SELF;
	set.nr_frames = NR_GRANT_FRAMES;
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(set.frame_list, frames);

	/*
	 * Take 4 pages of grant table space from the hypervisor and map it
	 */
	if ((HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &set, 1) != 0) ||
	    (set.status != 0)) {
		cmn_err(CE_PANIC, "Grant Table setup failed");
	}

	shared = vmem_xalloc(heap_arena, NR_GRANT_FRAMES * MMU_PAGESIZE,
	    MMU_PAGESIZE, 0, 0, 0, 0, VM_SLEEP);

	for (i = 0; i < NR_GRANT_FRAMES; i++)
		kbm_map_ma(FRAME_TO_MA(frames[i]), GT_PGADDR(i), 0);

	for (i = NR_RESERVED_ENTRIES; i < NR_GRANT_ENTRIES; i++)
		gnttab_list[i] = i + 1;
	gnttab_free_count = NR_GRANT_ENTRIES - NR_RESERVED_ENTRIES;
	gnttab_free_head  = NR_RESERVED_ENTRIES;

	mutex_init(&gnttab_list_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
gnttab_resume(void)
{
	gnttab_setup_table_t set;
	gnttab_frame_t frames[NR_GRANT_FRAMES];
	int i;

	set.dom = DOMID_SELF;
	set.nr_frames = NR_GRANT_FRAMES;
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(set.frame_list, frames);

	/*
	 * Take NR_GRANT_FRAMES pages of grant table space from the
	 * hypervisor and map it
	 */
	if ((HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &set, 1) != 0) ||
	    (set.status != 0)) {
		cmn_err(CE_PANIC, "Grant Table setup failed");
	}

	for (i = 0; i < NR_GRANT_FRAMES; i++) {
		(void) HYPERVISOR_update_va_mapping(GT_PGADDR(i),
		    FRAME_TO_MA(frames[i]) | PT_VALID | PT_WRITABLE,
		    UVMF_INVLPG | UVMF_ALL);
	}
}

void
gnttab_suspend(void)
{
	int i;

	/*
	 * clear grant table mappings before suspending
	 */
	for (i = 0; i < NR_GRANT_FRAMES; i++) {
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

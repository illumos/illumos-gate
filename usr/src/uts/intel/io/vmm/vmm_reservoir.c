/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * VMM Memory Reservoir
 *
 *
 * In order to make the allocation of large (multi-GiB) chunks of memory
 * for bhyve VMs easier, we introduce the "VMM Reservoir", where system
 * operators can set aside a substantial portion of system memory exclusively
 * for VMs.  This memory is unavailable for general use by the rest of the
 * system.  Rather than having to scour the freelist, reap kmem caches, or put
 * pressure on the ARC, bhyve guest memory allocations can quickly determine if
 * there is adequate reservoir memory available.  Since the pages stored in the
 * reservoir are pre-zeroed, it can be immediately used when allocated to a
 * guest.  When the memory is returned to the reservoir, it is zeroed once more
 * to avoid leaking any sensitive data from that guest.
 *
 *
 * Transient Allocations
 *
 * While the explicit reservoir model may work well for some applications,
 * others may want a more traditional model, where pages for guest memory
 * objects are allocated on demand, rather than from a pool set aside from the
 * system.  In this case, the allocation can be made in "transient" mode, where
 * the memory is allocated normally, even if there is free capacity in the
 * reservoir.  When use of the transient allocation is complete (the guest is
 * halted and destroyed), the pages will be freed back to the system, rather
 * than added back to the reservoir.
 *
 * From an implementation standpoint, transient allocations follow the same
 * code paths as ones using the reservoir normally.  Those allocations have a
 * tag which marks them as transient, and used/free size tallies are maintained
 * separately for normal and transient operations.  When performing a transient
 * allocation, that amount of memory is immediately added to the reservoir ,
 * from which the allocation can be made.  When freeing a transient allocation,
 * a matching amount of memory is removed from the reservoir as part of the
 * operation.  This allows both allocation types to coexist without too much
 * additional machinery.
 *
 *
 * Administration
 *
 * Operators may attempt to alter the amount of memory allocated to the
 * reservoir via an ioctl against the vmmctl device.  The total amount of memory
 * in the reservoir (free, or allocated to VMs) is arbitrarily limited at this
 * time by `vmmr_total_limit`, which defaults to 80% of physmem.  This is done
 * to prevent the reservoir from inadvertently growing to a size where the
 * system has inadequate memory to make forward progress.  Shrinking the
 * reservoir is only possible when it contains free (not allocated by any guest
 * VMs) memory.
 *
 *
 * Page Tracking
 *
 * The reservoir currently uses vnode association to keep track of pages under
 * its control (either designated to the reservoir and free, or allocated to a
 * guest VM object).  This means using the existing VM system primitives for
 * page_t instances being associated with a given (vnode, offset) tuple.  It
 * means that spans of pages, either free or allocated, need only to store a
 * length (of the span) and an offset (into the vnode) in order to gain access
 * to all of the underlying pages associated with that span.  Associating the
 * pages against `kvps[KV_VVP]` (the VMM kernel vnode) means they will be
 * properly tracked as KAS pages, but be excluded from normal dumps (unless the
 * operator has chosen to dump all of RAM).
 */

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/machparam.h>
#include <sys/kmem.h>
#include <sys/stddef.h>
#include <sys/null.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/policy.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>
#include <sys/kstat.h>

#include <sys/vmm_reservoir.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>

#define	VMMR_TARGET_INACTIVE	SIZE_MAX

static kmutex_t vmmr_lock;

static size_t vmmr_free_sz;
static size_t vmmr_free_transient_sz;
static size_t vmmr_adding_sz;
static size_t vmmr_alloc_sz;
static size_t vmmr_alloc_transient_sz;
static size_t vmmr_empty_sz;

/*
 * Target size of the reservoir during active vmmr_set_target() operation.
 * It holds the sentinel value of VMMR_TARGET_INACTIVE when no resize is active.
 */
static size_t vmmr_target_sz;

static uintptr_t vmmr_empty_last;
/* Upper limit for the size (free + allocated) of the reservoir */
static size_t vmmr_total_limit;

/* VA range allocated from the VMM arena for the mappings */
static uintptr_t vmmr_va;
static uintptr_t vmmr_va_sz;

static kstat_t *vmmr_kstat;

/* Pair of AVL trees to store set of spans ordered by addr and size */
typedef struct vmmr_treepair {
	avl_tree_t by_addr;
	avl_tree_t by_size;
} vmmr_treepair_t;

/* Spans of free memory in the reservoir */
static vmmr_treepair_t vmmr_free_tp;

/* Spans of empty (not backed by memory) space in the reservoir */
static vmmr_treepair_t vmmr_empty_tp;

/* Regions of memory allocated from the reservoir */
static list_t vmmr_alloc_regions;

struct vmmr_span {
	uintptr_t	vs_addr;
	size_t		vs_size;
	avl_node_t	vs_by_addr;
	avl_node_t	vs_by_size;
	uintptr_t	vs_region_addr;
};
typedef struct vmmr_span vmmr_span_t;

struct vmmr_region {
	size_t		vr_size;
	avl_tree_t	vr_spans;
	list_node_t	vr_node;
	bool		vr_transient;
};

typedef struct vmmr_kstats {
	kstat_named_t	vmrks_bytes_free;
	kstat_named_t	vmrks_bytes_alloc;
	kstat_named_t	vmrks_bytes_transient;
	kstat_named_t	vmrks_bytes_limit;
} vmmr_kstats_t;


static int vmmr_add(size_t, bool);
static int vmmr_remove(size_t, bool);

static int
vmmr_cmp_addr(const void *a, const void *b)
{
	const vmmr_span_t *sa = a;
	const vmmr_span_t *sb = b;

	if (sa->vs_addr == sb->vs_addr) {
		return (0);
	} else if (sa->vs_addr < sb->vs_addr) {
		return (-1);
	} else {
		return (1);
	}
}

static int
vmmr_cmp_size(const void *a, const void *b)
{
	const vmmr_span_t *sa = a;
	const vmmr_span_t *sb = b;

	if (sa->vs_size == sb->vs_size) {
		/*
		 * Since discontiguous spans could have the same size in a
		 * by-size tree, differentiate them (as required by AVL) by
		 * address so they can safely coexist while remaining sorted.
		 */
		return (vmmr_cmp_addr(a, b));
	} else if (sa->vs_size < sb->vs_size) {
		return (-1);
	} else {
		return (1);
	}
}

static int
vmmr_cmp_region_addr(const void *a, const void *b)
{
	const vmmr_span_t *sa = a;
	const vmmr_span_t *sb = b;

	if (sa->vs_region_addr == sb->vs_region_addr) {
		return (0);
	} else if (sa->vs_region_addr < sb->vs_region_addr) {
		return (-1);
	} else {
		return (1);
	}
}

static void
vmmr_tp_init(vmmr_treepair_t *tree)
{
	avl_create(&tree->by_addr, vmmr_cmp_addr, sizeof (vmmr_span_t),
	    offsetof(vmmr_span_t, vs_by_addr));
	avl_create(&tree->by_size, vmmr_cmp_size, sizeof (vmmr_span_t),
	    offsetof(vmmr_span_t, vs_by_size));
}

static void
vmmr_tp_destroy(vmmr_treepair_t *tree)
{
	void *vcp = NULL;
	vmmr_span_t *span;

	while (avl_destroy_nodes(&tree->by_addr, &vcp) != NULL) {
		/* Freeing spans will be done when tearing down by-size tree */
	}
	while ((span = avl_destroy_nodes(&tree->by_size, &vcp)) != NULL) {
		kmem_free(span, sizeof (*span));
	}
	avl_destroy(&tree->by_addr);
	avl_destroy(&tree->by_size);
}

/*
 * Insert a vmmr_span_t into a treepair, concatenating if possible with adjacent
 * span(s).  Such concatenation could result in the `to_add` span being freed,
 * so the caller cannot use it after this returns.
 */
static void
vmmr_tp_insert_concat(vmmr_span_t *to_add, vmmr_treepair_t *tree)
{
	avl_tree_t *by_addr = &tree->by_addr;
	avl_tree_t *by_size = &tree->by_size;
	vmmr_span_t *node;
	avl_index_t where;

	/* This addr should not already exist in the treepair */
	node = avl_find(by_addr, to_add, &where);
	ASSERT3P(node, ==, NULL);

	node = avl_nearest(by_addr, where, AVL_BEFORE);
	if (node != NULL &&
	    (node->vs_addr + node->vs_size) == to_add->vs_addr) {
		/* concat with preceeding item */
		avl_remove(by_addr, node);
		avl_remove(by_size, node);
		node->vs_size += to_add->vs_size;
		kmem_free(to_add, sizeof (*to_add));

		/*
		 * Since this now-concatenated span could be adjacent one
		 * trailing it, fall through to perform that check.
		 */
		to_add = node;
	}

	node = avl_nearest(by_addr, where, AVL_AFTER);
	if (node != NULL &&
	    (to_add->vs_addr + to_add->vs_size) == node->vs_addr) {
		/* concat with trailing item */
		avl_remove(by_addr, node);
		avl_remove(by_size, node);
		node->vs_addr = to_add->vs_addr;
		node->vs_size += to_add->vs_size;
		avl_add(by_addr, node);
		avl_add(by_size, node);

		kmem_free(to_add, sizeof (*to_add));
		return;
	}

	/* simply insert */
	avl_add(by_addr, to_add);
	avl_add(by_size, to_add);
}

/*
 * Remove a vmmr_span_t from a treepair, splitting if necessary when a span of
 * the exact target size is not present, but a larger one is.  May return a span
 * with a size smaller than the target if splitting is not an option.
 */
static vmmr_span_t *
vmmr_tp_remove_split(size_t target_sz, vmmr_treepair_t *tree)
{
	avl_tree_t *by_addr = &tree->by_addr;
	avl_tree_t *by_size = &tree->by_size;
	vmmr_span_t *span;
	avl_index_t where;

	ASSERT3U(target_sz, !=, 0);
	ASSERT(!avl_is_empty(by_addr));
	ASSERT(!avl_is_empty(by_size));

	vmmr_span_t search = { .vs_size = target_sz };
	span = avl_find(by_size, &search, &where);
	if (span == NULL) {
		/* Try for a larger span (instead of exact match) */
		span = avl_nearest(by_size, where, AVL_AFTER);
		if (span == NULL) {
			/*
			 * Caller will need to collect several smaller spans in
			 * order to fulfill their request.
			 */
			span = avl_nearest(by_size, where, AVL_BEFORE);
			ASSERT3P(span, !=, NULL);
		}
	}

	if (span->vs_size <= target_sz) {
		avl_remove(by_size, span);
		avl_remove(by_addr, span);

		return (span);
	} else {
		/* Split off adequate chunk from larger span */
		uintptr_t start = span->vs_addr + span->vs_size - target_sz;

		avl_remove(by_size, span);
		span->vs_size -= target_sz;
		avl_add(by_size, span);

		vmmr_span_t *split_span =
		    kmem_zalloc(sizeof (vmmr_span_t), KM_SLEEP);
		split_span->vs_addr = start;
		split_span->vs_size = target_sz;

		return (split_span);
	}
}

static int
vmmr_kstat_update(struct kstat *ksp, int rw)
{
	vmmr_kstats_t *vkp = ksp->ks_data;

	mutex_enter(&vmmr_lock);
	vkp->vmrks_bytes_free.value.ui64 = vmmr_free_sz;
	vkp->vmrks_bytes_alloc.value.ui64 = vmmr_alloc_sz;
	/*
	 * In addition to the memory which is actually actually allocated to
	 * transient consumers, memory which is considered free-for-transient is
	 * also included in the sizing.
	 */
	vkp->vmrks_bytes_transient.value.ui64 =
	    vmmr_alloc_transient_sz + vmmr_free_transient_sz;
	vkp->vmrks_bytes_limit.value.ui64 = vmmr_total_limit;
	mutex_exit(&vmmr_lock);

	return (0);
}

int
vmmr_init()
{
	mutex_init(&vmmr_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * `vmm_total_limit` represents the absolute maximum size of the VMM
	 * memory reservoir.  It is meant to provide some measure of protection
	 * against an operator pushing the system into unrecoverable memory
	 * starvation through explicit or transient additions to the reservoir.
	 *
	 * There will be many situations where this limit would be inadequate to
	 * prevent kernel memory starvation in the face of certain operator
	 * actions.  It is a balance to be struck between safety and allowing
	 * large systems to reach high utilization.
	 *
	 * The value is based off of pages_pp_maximum: "Number of currently
	 * available pages that cannot be 'locked'".  It is sized as all of
	 * `physmem` less 120% of `pages_pp_maximum`.
	 */
	vmmr_total_limit =
	    (((physmem * 10)  - (pages_pp_maximum * 12)) * PAGESIZE) / 10;

	vmmr_empty_last = 0;
	vmmr_free_sz = 0;
	vmmr_alloc_sz = 0;
	vmmr_empty_sz = 0;
	vmmr_adding_sz = 0;
	vmmr_free_transient_sz = 0;
	vmmr_alloc_transient_sz = 0;
	vmmr_target_sz = VMMR_TARGET_INACTIVE;

	/*
	 * Attempt kstat allocation early, since it is the only part of
	 * reservoir initialization which is fallible.
	 */
	kstat_t *ksp = kstat_create_zone(VMM_MODULE_NAME, 0, "vmm_reservoir",
	    VMM_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (vmmr_kstats_t) / sizeof (kstat_named_t), 0, GLOBAL_ZONEID);
	if (ksp == NULL) {
		mutex_destroy(&vmmr_lock);
		return (ENOMEM);
	}

	vmmr_kstats_t *vkp = ksp->ks_data;

	kstat_named_init(&vkp->vmrks_bytes_free, "bytes_free",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vkp->vmrks_bytes_alloc, "bytes_alloc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vkp->vmrks_bytes_transient, "bytes_transient_alloc",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vkp->vmrks_bytes_limit, "bytes_limit",
	    KSTAT_DATA_UINT64);
	ksp->ks_private = NULL;
	ksp->ks_update = vmmr_kstat_update;
	vmmr_kstat = ksp;

	vmmr_tp_init(&vmmr_free_tp);
	vmmr_tp_init(&vmmr_empty_tp);

	list_create(&vmmr_alloc_regions, sizeof (vmmr_region_t),
	    offsetof(vmmr_region_t, vr_node));

	/* Grab a chunk of VA for the reservoir */
	vmmr_va_sz = physmem * PAGESIZE;
	vmmr_va = (uintptr_t)vmem_alloc(kvmm_arena, vmmr_va_sz, VM_SLEEP);

	kstat_install(vmmr_kstat);

	return (0);
}

void
vmmr_fini()
{
	mutex_enter(&vmmr_lock);
	VERIFY3U(vmmr_alloc_sz, ==, 0);
	VERIFY3U(vmmr_free_sz, ==, 0);
	VERIFY3U(vmmr_adding_sz, ==, 0);
	VERIFY3U(vmmr_alloc_transient_sz, ==, 0);
	VERIFY3U(vmmr_free_transient_sz, ==, 0);
	VERIFY(avl_is_empty(&vmmr_free_tp.by_addr));
	VERIFY(avl_is_empty(&vmmr_free_tp.by_size));
	VERIFY(list_is_empty(&vmmr_alloc_regions));

	kstat_delete(vmmr_kstat);
	vmmr_kstat = NULL;

	vmmr_tp_destroy(&vmmr_free_tp);
	vmmr_tp_destroy(&vmmr_empty_tp);
	list_destroy(&vmmr_alloc_regions);

	/* Release reservoir VA chunk */
	vmem_free(kvmm_arena, (void *)vmmr_va, vmmr_va_sz);
	vmmr_va = 0;
	vmmr_va_sz = 0;
	vmmr_total_limit = 0;
	vmmr_empty_last = 0;

	mutex_exit(&vmmr_lock);
	mutex_destroy(&vmmr_lock);
}

bool
vmmr_is_empty()
{
	mutex_enter(&vmmr_lock);
	bool res = (vmmr_alloc_sz == 0 && vmmr_alloc_transient_sz == 0 &&
	    vmmr_free_sz == 0 && vmmr_free_transient_sz == 0);
	mutex_exit(&vmmr_lock);
	return (res);
}

int
vmmr_alloc(size_t sz, bool transient, vmmr_region_t **resp)
{
	VERIFY3U(sz & PAGEOFFSET, ==, 0);

	if (!transient) {
		mutex_enter(&vmmr_lock);
		if (sz > vmmr_free_sz) {
			mutex_exit(&vmmr_lock);
			return (ENOSPC);
		}
	} else {
		int err;

		mutex_enter(&vmmr_lock);
		err = vmmr_add(sz, true);
		if (err != 0) {
			mutex_exit(&vmmr_lock);
			return (err);
		}
		VERIFY3U(vmmr_free_transient_sz, >=, sz);
	}

	vmmr_region_t *region;
	region = kmem_zalloc(sizeof (vmmr_region_t), KM_SLEEP);
	avl_create(&region->vr_spans, vmmr_cmp_region_addr,
	    sizeof (vmmr_span_t), offsetof(vmmr_span_t, vs_by_addr));
	region->vr_size = sz;

	size_t remain = sz;
	uintptr_t map_at = 0;
	while (remain > 0) {
		vmmr_span_t *span = vmmr_tp_remove_split(remain, &vmmr_free_tp);

		/*
		 * We have already ensured that adequate free memory is present
		 * in the reservoir for this allocation.
		 */
		VERIFY3P(span, !=, NULL);
		ASSERT3U(span->vs_size, <=, remain);

		span->vs_region_addr = map_at;
		avl_add(&region->vr_spans, span);
		map_at += span->vs_size;
		remain -= span->vs_size;
	}

	if (!transient) {
		vmmr_free_sz -= sz;
		vmmr_alloc_sz += sz;
	} else {
		vmmr_free_transient_sz -= sz;
		vmmr_alloc_transient_sz += sz;
		region->vr_transient = true;
	}
	list_insert_tail(&vmmr_alloc_regions, region);
	mutex_exit(&vmmr_lock);

	*resp = region;
	return (0);
}

void *
vmmr_region_mem_at(vmmr_region_t *region, uintptr_t off)
{
	/* just use KPM region for now */
	return (hat_kpm_pfn2va(vmmr_region_pfn_at(region, off)));
}

pfn_t
vmmr_region_pfn_at(vmmr_region_t *region, uintptr_t off)
{
	VERIFY3U(off & PAGEOFFSET, ==, 0);
	VERIFY3U(off, <, region->vr_size);

	vmmr_span_t search = {
		.vs_region_addr = off
	};
	avl_index_t where;
	vmmr_span_t *span = avl_find(&region->vr_spans, &search, &where);

	if (span == NULL) {
		span = avl_nearest(&region->vr_spans, where, AVL_BEFORE);
		ASSERT3P(span, !=, NULL);
	}
	uintptr_t span_off = off - span->vs_region_addr + span->vs_addr;
	page_t *pp = page_find(&kvps[KV_VVP], (u_offset_t)span_off);
	VERIFY(pp != NULL);
	return (pp->p_pagenum);
}

void
vmmr_free(vmmr_region_t *region)
{
	mutex_enter(&vmmr_lock);
	if (!region->vr_transient) {
		VERIFY3U(region->vr_size, <=, vmmr_alloc_sz);
	} else {
		VERIFY3U(region->vr_size, <=, vmmr_alloc_transient_sz);
	}
	list_remove(&vmmr_alloc_regions, region);
	mutex_exit(&vmmr_lock);

	/* Zero the contents (while not monopolizing vmmr_lock) */
	for (uintptr_t off = 0; off < region->vr_size; off += PAGESIZE) {
		bzero(vmmr_region_mem_at(region, off), PAGESIZE);
	}

	mutex_enter(&vmmr_lock);

	/* Put the contained span(s) back in the free pool */
	void *cookie = NULL;
	vmmr_span_t *span;
	while ((span = avl_destroy_nodes(&region->vr_spans, &cookie)) != NULL) {
		span->vs_region_addr = 0;
		vmmr_tp_insert_concat(span, &vmmr_free_tp);
	}
	avl_destroy(&region->vr_spans);
	if (!region->vr_transient) {
		vmmr_free_sz += region->vr_size;
		vmmr_alloc_sz -= region->vr_size;
	} else {
		vmmr_free_transient_sz += region->vr_size;
		vmmr_alloc_transient_sz -= region->vr_size;
	}

	if (region->vr_transient) {
		/*
		 * Since the transient capacity was previously allocated for
		 * this region, its removal should not fail.
		 */
		VERIFY0(vmmr_remove(region->vr_size, true));
	}
	kmem_free(region, sizeof (*region));
	mutex_exit(&vmmr_lock);
}

static void
vmmr_destroy_pages(vmmr_span_t *span)
{
	const uintptr_t end = span->vs_addr + span->vs_size;
	struct vnode *vp = &kvps[KV_VVP];
	for (uintptr_t pos = span->vs_addr; pos < end; pos += PAGESIZE) {
		page_t *pp;

		/* Page-free logic cribbed from segkmem_xfree(): */
		pp = page_find(vp, (u_offset_t)pos);
		VERIFY(pp != NULL);
		if (!page_tryupgrade(pp)) {
			/*
			 * Some other thread has a sharelock. Wait for
			 * it to drop the lock so we can free this page.
			 */
			page_unlock(pp);
			pp = page_lookup(vp, (u_offset_t)pos, SE_EXCL);
		}

		/*
		 * Clear p_lckcnt so page_destroy() doesn't update availrmem.
		 * That will be taken care of later via page_unresv().
		 */
		pp->p_lckcnt = 0;
		page_destroy(pp, 0);
	}
}

static int
vmmr_alloc_pages(const vmmr_span_t *span)
{
	struct seg kseg = {
		.s_as = &kas
	};
	struct vnode *vp = &kvps[KV_VVP];

	const uintptr_t end = span->vs_addr + span->vs_size;
	for (uintptr_t pos = span->vs_addr; pos < end; pos += PAGESIZE) {
		page_t *pp;

		pp = page_create_va(vp, (u_offset_t)pos, PAGESIZE,
		    PG_EXCL | PG_NORELOC, &kseg, (void *)(vmmr_va + pos));

		if (pp == NULL) {
			/* Destroy any already-created pages */
			if (pos != span->vs_addr) {
				vmmr_span_t destroy_span = {
					.vs_addr = span->vs_addr,
					.vs_size = pos - span->vs_addr,
				};

				vmmr_destroy_pages(&destroy_span);
			}
			return (ENOMEM);
		}

		/* mimic page state from segkmem */
		ASSERT(PAGE_EXCL(pp));
		page_io_unlock(pp);
		pp->p_lckcnt = 1;
		page_downgrade(pp);

		/* pre-zero the page */
		bzero(hat_kpm_pfn2va(pp->p_pagenum), PAGESIZE);
	}

	return (0);
}

static int
vmmr_resv_wait()
{
	if (delay_sig(hz >> 2) != 0) {
		/* bail due to interruption */
		return (0);
	}
	return (1);
}

static void
vmmr_remove_raw(size_t sz)
{
	VERIFY3U(sz & PAGEOFFSET, ==, 0);
	VERIFY(MUTEX_HELD(&vmmr_lock));

	size_t remain = sz;
	while (remain > 0) {
		vmmr_span_t *span = vmmr_tp_remove_split(remain, &vmmr_free_tp);

		/*
		 * The caller must ensure that at least `sz` amount is present
		 * in the free treepair.
		 */
		VERIFY3P(span, !=, NULL);
		ASSERT3U(span->vs_size, <=, remain);

		/* TODO: perhaps arrange to destroy pages outside the lock? */
		vmmr_destroy_pages(span);

		remain -= span->vs_size;
		vmmr_tp_insert_concat(span, &vmmr_empty_tp);
	}

	vmmr_empty_sz += sz;
}

/*
 * Add memory to vmm reservoir.  Memory may be marked for transient use, where
 * the addition is part of a transient allocation from the reservoir.  Otherwise
 * it is placed in the reservoir to be available for non-transient allocations.
 *
 * Expects vmmr_lock to be held when called, and will return with it held, but
 * will drop it during portions of the addition.
 */
static int
vmmr_add(size_t sz, bool transient)
{
	VERIFY3U(sz & PAGEOFFSET, ==, 0);
	VERIFY3U(sz, >, 0);
	VERIFY(MUTEX_HELD(&vmmr_lock));

	/*
	 * Make sure that the amount added is not going to breach the limits
	 * we've chosen
	 */
	const size_t current_total =
	    vmmr_alloc_sz + vmmr_free_sz + vmmr_adding_sz +
	    vmmr_alloc_transient_sz + vmmr_free_transient_sz;
	if ((current_total + sz) < current_total) {
		return (EOVERFLOW);
	}
	if ((current_total + sz) > vmmr_total_limit) {
		return (ENOSPC);
	}
	vmmr_adding_sz += sz;
	mutex_exit(&vmmr_lock);

	/* Wait for enough pages to become available */
	if (page_xresv(sz >> PAGESHIFT, KM_SLEEP, vmmr_resv_wait) == 0) {
		mutex_enter(&vmmr_lock);
		vmmr_adding_sz -= sz;
		return (EINTR);
	}

	mutex_enter(&vmmr_lock);
	size_t added = 0;
	size_t remain = sz;
	while (added < sz) {
		vmmr_span_t *span = NULL;

		if (vmmr_empty_sz > 0) {
			span = vmmr_tp_remove_split(remain, &vmmr_empty_tp);

			vmmr_empty_sz -= span->vs_size;
		} else {
			/*
			 * No empty space to fill with new pages, so just tack
			 * it on at the end instead.
			 */
			span = kmem_zalloc(sizeof (vmmr_span_t), KM_SLEEP);
			span->vs_addr = vmmr_empty_last;
			span->vs_size = remain;
			vmmr_empty_last += remain;
		}
		VERIFY3P(span, !=, NULL);


		/* Allocate the actual pages to back this span */
		mutex_exit(&vmmr_lock);
		int err = vmmr_alloc_pages(span);
		mutex_enter(&vmmr_lock);

		/*
		 * If an error is encountered during page allocation for the
		 * span, unwind any progress made by the addition request.
		 */
		if (err != 0) {
			/*
			 * Without pages allocated to this span, it is now
			 * tracked as empty.
			 */
			vmmr_empty_sz += span->vs_size;
			vmmr_tp_insert_concat(span, &vmmr_empty_tp);

			if (added != 0) {
				vmmr_remove_raw(added);
			}

			vmmr_adding_sz -= sz;

			page_unresv(sz >> PAGESHIFT);
			return (err);
		}

		/*
		 * The allocated-page-bearing span is placed in the "free"
		 * treepair now, but is not officially exposed for consumption
		 * until `vmm_free_sz` or `vmm_free_transient_sz` are updated.
		 *
		 * This allows us to unwind the allocation in case of a failure
		 * without the risk of the freshly added span(s) being snapped
		 * up by a consumer already.
		 */
		added += span->vs_size;
		remain -= span->vs_size;
		vmmr_tp_insert_concat(span, &vmmr_free_tp);
	}

	/* Make the added memory usable by exposing it to the size accounting */
	if (!transient) {
		vmmr_free_sz += added;
	} else {
		vmmr_free_transient_sz += added;
	}
	ASSERT3U(added, ==, sz);
	vmmr_adding_sz -= added;

	return (0);
}

/*
 * Remove memory from vmm reservoir.  Normally this will remove memory from the
 * reservoir which was available for non-transient allocations.  If the removal
 * is part of a vmmr_free() of a transient allocation, it will act on only that
 * transient region being freed, not the available memory in the reservoir.
 *
 * Expects vmmr_lock to be held when called, and will return with it held, but
 * may drop it during portions of the removal.
 */
static int
vmmr_remove(size_t sz, bool transient)
{
	VERIFY3U(sz & PAGEOFFSET, ==, 0);
	VERIFY(sz);
	VERIFY(MUTEX_HELD(&vmmr_lock));

	if ((!transient && sz > vmmr_free_sz) ||
	    (transient && sz > vmmr_free_transient_sz)) {
		return (ENOSPC);
	}

	vmmr_remove_raw(sz);

	if (!transient) {
		vmmr_free_sz -= sz;
	} else {
		vmmr_free_transient_sz -= sz;
	}
	page_unresv(sz >> PAGESHIFT);
	return (0);
}

static int
vmmr_set_target(size_t target_sz, size_t chunk_sz, size_t *resp)
{
	VERIFY(resp != NULL);

	mutex_enter(&vmmr_lock);

	size_t current_sz = vmmr_alloc_sz + vmmr_free_sz;

	/* Be sure to communicate current size in case of an early bail-out */
	*resp = current_sz;

	if ((target_sz & PAGEOFFSET) != 0 ||
	    (chunk_sz & PAGEOFFSET) != 0) {
		mutex_exit(&vmmr_lock);
		return (EINVAL);
	}
	/* Reject sentinel value */
	if (target_sz == VMMR_TARGET_INACTIVE) {
		mutex_exit(&vmmr_lock);
		return (EINVAL);
	}

	/* Already at target size */
	if (target_sz == current_sz) {
		mutex_exit(&vmmr_lock);
		return (0);
	}

	/* Reject racing requests size */
	if (vmmr_target_sz != VMMR_TARGET_INACTIVE) {
		mutex_exit(&vmmr_lock);
		return (EALREADY);
	}
	/* Record the target now to excluding a racing request */
	vmmr_target_sz = target_sz;

	int err = 0;
	do {
		/* Be sensitive to signal interruption */
		if (issig(JUSTLOOKING) != 0) {
			mutex_exit(&vmmr_lock);
			const bool sig_bail = issig(FORREAL) != 0;
			mutex_enter(&vmmr_lock);
			if (sig_bail) {
				err = EINTR;
				break;
			}
		}

		if (current_sz > target_sz) {
			/* Shrinking reservoir */

			size_t req_sz = current_sz - target_sz;
			if (chunk_sz != 0) {
				req_sz = MIN(req_sz, chunk_sz);
			}
			err = vmmr_remove(req_sz, false);
		} else {
			/* Growing reservoir */
			ASSERT(current_sz < target_sz);

			size_t req_sz = target_sz - current_sz;
			if (chunk_sz != 0) {
				req_sz = MIN(req_sz, chunk_sz);
			}
			err = vmmr_add(req_sz, false);
		}

		current_sz = vmmr_alloc_sz + vmmr_free_sz;
	} while (err == 0 && current_sz != target_sz);

	/* Clear the target now that we are done (success or not) */
	vmmr_target_sz = VMMR_TARGET_INACTIVE;
	mutex_exit(&vmmr_lock);
	*resp = current_sz;
	return (err);
}

int
vmmr_ioctl(int cmd, intptr_t arg, int md, cred_t *cr, int *rvalp)
{
	/*
	 * Since an LP64 datamodel is enforced by our caller (vmm_ioctl()), we
	 * do not need to duplicate such checks here.
	 */

	switch (cmd) {
	case VMM_RESV_QUERY: {
		struct vmm_resv_query res;
		void *datap = (void *)(uintptr_t)arg;

		/* For now, anyone with access to vmmctl device can query */
		mutex_enter(&vmmr_lock);
		res.vrq_free_sz = vmmr_free_sz;
		res.vrq_alloc_sz = vmmr_alloc_sz;
		res.vrq_alloc_transient_sz = vmmr_alloc_transient_sz;
		res.vrq_limit = vmmr_total_limit;
		mutex_exit(&vmmr_lock);
		if (ddi_copyout(&res, datap, sizeof (res), md) != 0) {
			return (EFAULT);
		}
		break;
	}
	case VMM_RESV_SET_TARGET: {
		if (secpolicy_sys_config(cr, B_FALSE) != 0) {
			return (EPERM);
		}

		struct vmm_resv_target tgt;
		void *datap = (void *)(uintptr_t)arg;

		if (ddi_copyin(datap, &tgt, sizeof (tgt), md) != 0) {
			return (EFAULT);
		}

		int err = vmmr_set_target(tgt.vrt_target_sz, tgt.vrt_chunk_sz,
		    &tgt.vrt_result_sz);

		/*
		 * Attempt to communicate the resultant size of the reservoir if
		 * setting it to the target was a success, or if we were
		 * interrupted (by a signal) while doing so.
		 */
		if (err == 0 || err == EINTR) {
			if (ddi_copyout(&tgt, datap, sizeof (tgt), md) != 0) {
				err = EFAULT;
			}
		}

		return (err);
	}
	default:
		return (ENOTTY);
	}
	return (0);
}

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
 * Special-purpose krtld allocators
 *
 * krtld can draw upon two sources of transient memory, both of which are
 * provided by boot, and both of which are unmapped early on in kernel
 * startup.  The first is temporary memory (kobj_tmp_*), which is available
 * only during the execution of kobj_init.  The only way to reclaim temporary
 * memory is via calls to kobj_tmp_free(), which will free *all* temporary
 * memory currently allocated.
 *
 * The second type of transient memory is scratch memory (kobj_bs_*).  Scratch
 * memory differes from transient memory in that it survives until the
 * conclusion of kobj_sync().  There is no way to reclaim scratch memory prior
 * to that point.
 */

#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/bootconf.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>

/*
 * Temporary memory
 *
 * Allocations over (pagesize - 16) bytes are satisfied by page allocations.
 * That is, the allocation size is rounded up to the next page, with full pages
 * used to satisfy the request.  Smaller allocations share pages.  When the
 * first small allocation is requested, an entire page is requested from the
 * booter, and the appropriate portion of that page is returned to the caller.
 * Subsequent small allocations are filled, when possible, from the same page.
 * If the requested allocation is larger than the available space on the current
 * page, a new page is requested for this and subsequent small alloctions.
 *
 * The small allocations page is laid out as follows:
 *
 *  ------------------------------------------------------------------
 *  | prev |  size  | buffer | 0xfeed |  size  | ... | 0xfeed | next |
 *  | page | 0xbeef |        |   face | 0xbeef |     |   face | page |
 *  ------------------------------------------------------------------
 *  0      4        8        n       n+4      n+8  pgsz-8   pgsz-4  pgsz
 */

#define	KOBJ_TMP_SIZE_GUARD	0xbeef
#define	KOBJ_TMP_ALIGN_PAD	0xdeadbeef
#define	KOBJ_TMP_REAR_GUARD	0xfeedface

typedef struct kobj_big_map {
	uint32_t bm_addr;
	uint32_t bm_size;
} kobj_big_map_t;

typedef struct kobj_tmp {
	caddr_t tmp_base;
	caddr_t tmp_page;
	caddr_t tmp_pageptr;
	kobj_big_map_t *tmp_bigmap;
	uint_t tmp_bigmapidx;
	size_t tmp_pageres;
	size_t tmp_used;
	size_t tmp_bigreq;
	size_t tmp_smallreq;
	size_t tmp_bigwaste;
	size_t tmp_smallpgwaste;
	size_t tmp_smallohwaste;
} kobj_tmp_t;

#define	KOBJ_TMP_SMALL_PAGE_SIZE		kobj_mmu_pagesize

/*
 * Beyond a certain point (when the size of the buffer plus the minimal overhead
 * used to track that buffer) gets larger than a page, we switch to page-based
 * allocations.
 */
#define	KOBJ_TMP_LARGE_ALLOC_THRESH	(kobj_mmu_pagesize - 16)

/*
 * Used to track large allocations.  Must be less than the large allocation
 * threshold, and greater than the number of large allocations.
 */
#define	KOBJ_TMP_LARGE_MAP_MAXENT	256

extern caddr_t _edata;

static kobj_tmp_t kobj_tmp;

static void
kobj_tmp_verify(void)
{
	caddr_t pg = kobj_tmp.tmp_base, lpg = NULL;

	while (pg != NULL) {
		uchar_t *cur = (uchar_t *)(pg + 4);
		size_t resid = KOBJ_TMP_SMALL_PAGE_SIZE - 8;
		size_t sz, asz;

		if (*(uint32_t *)pg != (uint32_t)(uintptr_t)lpg) {
			_kobj_printf(ops, "krtld temp mem corrupt: ");
			_kobj_printf(ops, "page %p ", pg);
			_kobj_printf(ops, "prev pointer %8x ", *(uint32_t *)pg);
			_kobj_printf(ops, "doesn't match prev page %p\n", lpg);
			BOP_ENTER_MON(ops);
		}

		while (resid > 0 && (sz = *(uint16_t *)cur) != 0) {
			uchar_t *buf;
			uint32_t guard;
			int i;

			if (sz + 8 > resid) {
				_kobj_printf(ops, "krtld temp mem corrupt: ");
				_kobj_printf(ops, "page %p, ", pg);
				_kobj_printf(ops, "size %lu + 8 bigger ", sz);
				_kobj_printf(ops, "than resid %lu ", resid);
				_kobj_printf(ops, "at %p\n", cur);
				BOP_ENTER_MON(ops);
			}
			asz = (sz + 7) / 8 * 8;

			cur += 2; /* skip size */

			if ((guard = *(uint16_t *)cur) != KOBJ_TMP_SIZE_GUARD) {
				_kobj_printf(ops, "krtld temp mem corrupt: ");
				_kobj_printf(ops, "page %p, ", pg);
				_kobj_printf(ops, "%lu-byte buf, size ", sz);
				_kobj_printf(ops, "guard %04x != ", guard);
				_kobj_printf(ops, "expected %04x ",
				    KOBJ_TMP_SIZE_GUARD);
				_kobj_printf(ops, "at %p\n", cur);
				BOP_ENTER_MON(ops);
			}

			cur += 2; /* skip size guard */

			buf = cur;
			cur += sz; /* skip allocated buffer */
			for (i = 0; (uintptr_t)cur % 8 != 0; i++, cur++) {
				const uint32_t pad = KOBJ_TMP_ALIGN_PAD;
				if ((*cur & 0xff) !=
				    ((uchar_t *)&pad)[i % 4]) {
					_kobj_printf(ops, "krtld temp mem "
					    "corrupt: ");
					_kobj_printf(ops, "page %p, ", pg);
					_kobj_printf(ops, "%lu-byte buf ", sz);
					_kobj_printf(ops, "at %p, ", buf);
					_kobj_printf(ops, "alignment pad "
					    "overwrite (is %02x, ",
					    (*cur & 0xff));
					_kobj_printf(ops, "expected %02x) ",
					    ((uchar_t *)&pad)[i % 4], cur);
					_kobj_printf(ops, "at %p\n", cur);
					BOP_ENTER_MON(ops);
				}
			}

			if ((guard = *(uint32_t *)cur) != KOBJ_TMP_REAR_GUARD) {
				_kobj_printf(ops, "krtld temp mem corrupt: ");
				_kobj_printf(ops, "page %p, ", pg);
				_kobj_printf(ops, "%lu-byte buf, ", sz);
				_kobj_printf(ops, "end guard %08x != ", guard);
				_kobj_printf(ops, "expected %08x ",
				    KOBJ_TMP_REAR_GUARD);
				_kobj_printf(ops, "at %p\n", cur);
				BOP_ENTER_MON(ops);
			}

			cur += 4; /* skip end guard */

			resid -= asz + 8;
		}

		lpg = pg;
		pg = (caddr_t)(uintptr_t)
		    *(uint32_t *)(pg + KOBJ_TMP_SMALL_PAGE_SIZE - 4);
	}
}

static void *
kobj_tmp_bigalloc(size_t sz)
{
	size_t act = roundup(sz, kobj_mmu_pagesize);
	void *buf;

	if ((buf = BOP_ALLOC(ops, (caddr_t)0, act, BO_NO_ALIGN)) == NULL) {
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_DEBUG) {
			_kobj_printf(ops, "krtld temp mem: failed bigalloc of "
			    "%u bytes -- falling back\n", act);
		}
#endif
		/*
		 * kobj_alloc doesn't guarantee page alignment, so we do the
		 * kobj_segbrk ourselves.
		 */
		if ((buf = kobj_segbrk(&_edata, sz, kobj_mmu_pagesize, 0)) ==
		    NULL) {
			_kobj_printf(ops, "krtld temp mem: failed segbrk for "
			    "bigalloc\n");
			BOP_ENTER_MON(ops);
		}

		return (buf);
	}

	kobj_tmp.tmp_used += act;
	kobj_tmp.tmp_bigreq += sz;
	kobj_tmp.tmp_bigwaste += act - sz;

	if (kobj_tmp.tmp_bigmap == NULL) {
		kobj_tmp.tmp_bigmap = kobj_tmp_alloc(KOBJ_TMP_LARGE_MAP_MAXENT *
		    sizeof (kobj_big_map_t));
		bzero(kobj_tmp.tmp_bigmap, KOBJ_TMP_LARGE_MAP_MAXENT *
		    sizeof (kobj_big_map_t));
		kobj_tmp.tmp_bigmapidx = 0;
	} else {
		if (++kobj_tmp.tmp_bigmapidx > KOBJ_TMP_LARGE_MAP_MAXENT) {
			_kobj_printf(ops, "krtld temp mem: exceeded number "
			    "of large allocations (%u allowed)\n",
			    KOBJ_TMP_LARGE_MAP_MAXENT);
			BOP_ENTER_MON(ops);
		}
	}

	kobj_tmp.tmp_bigmap[kobj_tmp.tmp_bigmapidx].bm_addr =
	    (uint32_t)(uintptr_t)buf;
	kobj_tmp.tmp_bigmap[kobj_tmp.tmp_bigmapidx].bm_size = sz;

	return (buf);
}

void *
kobj_tmp_alloc(size_t sz)
{
	size_t act = (sz + 7) / 8 * 8;
	size_t align = act - sz;
	caddr_t buf;
	int i;

	kobj_tmp_verify();

	/*
	 * Large requests are satisfied by returning an integral number of
	 * pages sufficient to cover the allocation.
	 */
	if (act > KOBJ_TMP_LARGE_ALLOC_THRESH)
		return (kobj_tmp_bigalloc(sz));

	/*
	 * If we don't have enough space in the current page (or if there isn't
	 * one), allocate a new page.  Attach the current and new pages, and
	 * adjust the various pointers and residual counter.
	 */
	if (kobj_tmp.tmp_page == NULL || kobj_tmp.tmp_pageres < act + 8) {
		caddr_t new;

		kobj_tmp.tmp_smallpgwaste += kobj_tmp.tmp_pageres;

		if ((new = BOP_ALLOC(ops, (caddr_t)0, KOBJ_TMP_SMALL_PAGE_SIZE,
		    BO_NO_ALIGN)) == NULL) {
#ifdef	KOBJ_DEBUG
			if (kobj_debug & D_DEBUG) {
				_kobj_printf(ops, "krtld temp mem: failed "
				    "alloc of %u bytes -- falling back\n", act);
			}
#endif
			return (kobj_alloc(sz, KM_SLEEP));
		}

		bzero(new, KOBJ_TMP_SMALL_PAGE_SIZE);
		kobj_tmp.tmp_used += KOBJ_TMP_SMALL_PAGE_SIZE;

		*(uint32_t *)new = (uint32_t)(uintptr_t)kobj_tmp.tmp_page;

		if (kobj_tmp.tmp_page != NULL) {
			*(uint32_t *)(kobj_tmp.tmp_page +
			    KOBJ_TMP_SMALL_PAGE_SIZE - 4) =
			    (uint32_t)(uintptr_t)new;
		}

		kobj_tmp.tmp_page = new;
		if (kobj_tmp.tmp_base == NULL)
			kobj_tmp.tmp_base = new;

		kobj_tmp.tmp_pageres = KOBJ_TMP_SMALL_PAGE_SIZE - 8;
		kobj_tmp.tmp_pageptr = kobj_tmp.tmp_page + 4;

		kobj_tmp.tmp_smallohwaste += 8;
	}

	/*
	 * Allocate the requested buffer.  Install the pre-buffer size/guard,
	 * and the post-buffer guard.  We also fill the alignment space with
	 * KOBJ_TMP_ALIGN_PAD to aid in overrun detection.
	 */
	*((uint16_t *)kobj_tmp.tmp_pageptr) = sz;
	kobj_tmp.tmp_pageptr += 2;
	*((uint16_t *)kobj_tmp.tmp_pageptr) = KOBJ_TMP_SIZE_GUARD;
	kobj_tmp.tmp_pageptr += 2;

	buf = kobj_tmp.tmp_pageptr;
	kobj_tmp.tmp_pageptr += act + 4;

	((uint32_t *)kobj_tmp.tmp_pageptr)[-1] = KOBJ_TMP_REAR_GUARD;
	kobj_tmp.tmp_pageres -= 4 + act + 4;

	for (i = 0; i < align; i++) {
		const uint32_t pad = KOBJ_TMP_ALIGN_PAD;
		buf[sz + i] = ((caddr_t)&pad)[i % 4];
	}

	kobj_tmp.tmp_smallohwaste += 8;
	kobj_tmp.tmp_smallreq += sz;

	return (buf);
}

void
kobj_tmp_free(void)
{
	caddr_t pg, npg;
	int i;

	kobj_tmp_verify();

	for (i = 0; i < kobj_tmp.tmp_bigmapidx; i++) {
		kobj_big_map_t *bm = &kobj_tmp.tmp_bigmap[i];

		if (bm->bm_addr == NULL)
			break;

		bzero((caddr_t)(uintptr_t)bm->bm_addr, bm->bm_size);
		BOP_FREE(ops, (caddr_t)(uintptr_t)bm->bm_addr, bm->bm_size);
	}

	for (pg = kobj_tmp.tmp_base; pg != NULL; pg = npg) {
		npg = (caddr_t)(uintptr_t)
		    *(uint32_t *)(pg + KOBJ_TMP_SMALL_PAGE_SIZE - 4);

		bzero(pg, KOBJ_TMP_SMALL_PAGE_SIZE);
		BOP_FREE(ops, pg, KOBJ_TMP_SMALL_PAGE_SIZE);
	}

	kobj_tmp.tmp_base = kobj_tmp.tmp_page = kobj_tmp.tmp_pageptr = NULL;
	kobj_tmp.tmp_bigmap = NULL;
	kobj_tmp.tmp_bigmapidx = 0;
}

/*
 * Scratch memory
 */

extern void *
kobj_bs_alloc(size_t sz)
{
	return (BOP_ALLOC(ops, (caddr_t)0, P2ROUNDUP(sz, kobj_mmu_pagesize),
	    BO_NO_ALIGN));
}

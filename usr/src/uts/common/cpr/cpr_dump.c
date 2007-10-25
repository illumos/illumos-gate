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
 * Fill in and write out the cpr state file
 *	1. Allocate and write headers, ELF and cpr dump header
 *	2. Allocate bitmaps according to phys_install
 *	3. Tag kernel pages into corresponding bitmap
 *	4. Write bitmaps to state file
 *	5. Write actual physical page data to state file
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/memlist.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/hat.h>
#include <sys/cpr.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/panic.h>
#include <sys/thread.h>
#include <sys/note.h>

/* Local defines and variables */
#define	BTOb(bytes)	((bytes) << 3)		/* Bytes to bits, log2(NBBY) */
#define	bTOB(bits)	((bits) >> 3)		/* bits to Bytes, log2(NBBY) */

#if defined(__sparc)
static uint_t cpr_pages_tobe_dumped;
static uint_t cpr_regular_pgs_dumped;
static int cpr_dump_regular_pages(vnode_t *);
static int cpr_count_upages(int, bitfunc_t);
static int cpr_compress_and_write(vnode_t *, uint_t, pfn_t, pgcnt_t);
#endif

int cpr_flush_write(vnode_t *);

int cpr_contig_pages(vnode_t *, int);

void cpr_clear_bitmaps();

extern size_t cpr_get_devsize(dev_t);
extern int i_cpr_dump_setup(vnode_t *);
extern int i_cpr_blockzero(char *, char **, int *, vnode_t *);
extern int cpr_test_mode;
int cpr_setbit(pfn_t, int);
int cpr_clrbit(pfn_t, int);

ctrm_t cpr_term;

char *cpr_buf, *cpr_buf_end;
int cpr_buf_blocks;		/* size of cpr_buf in blocks */
size_t cpr_buf_size;		/* size of cpr_buf in bytes */
size_t cpr_bitmap_size;
int cpr_nbitmaps;

char *cpr_pagedata;		/* page buffer for compression / tmp copy */
size_t cpr_pagedata_size;	/* page buffer size in bytes */

#if defined(__sparc)
static char *cpr_wptr;		/* keep track of where to write to next */
static int cpr_file_bn;		/* cpr state-file block offset */
static int cpr_disk_writes_ok;
static size_t cpr_dev_space = 0;
#endif

char cpr_pagecopy[CPR_MAXCONTIG * MMU_PAGESIZE];

#if defined(__sparc)
/*
 * On some platforms bcopy may modify the thread structure
 * during bcopy (eg, to prevent cpu migration).  If the
 * range we are currently writing out includes our own
 * thread structure then it will be snapshotted by bcopy
 * including those modified members - and the updates made
 * on exit from bcopy will no longer be seen when we later
 * restore the mid-bcopy kthread_t.  So if the range we
 * need to copy overlaps with our thread structure we will
 * use a simple byte copy.
 */
void
cprbcopy(void *from, void *to, size_t bytes)
{
	extern int curthreadremapped;
	caddr_t kthrend;

	kthrend = (caddr_t)curthread + sizeof (kthread_t) - 1;
	if (curthreadremapped || (kthrend >= (caddr_t)from &&
	    kthrend < (caddr_t)from + bytes + sizeof (kthread_t) - 1)) {
		caddr_t src = from, dst = to;

		while (bytes-- > 0)
			*dst++ = *src++;
	} else {
		bcopy(from, to, bytes);
	}
}

/*
 * Allocate pages for buffers used in writing out the statefile
 */
static int
cpr_alloc_bufs(void)
{
	char *allocerr = "Unable to allocate memory for cpr buffer";
	size_t size;

	/*
	 * set the cpr write buffer size to at least the historic
	 * size (128k) or large enough to store the both the early
	 * set of statefile structures (well under 0x800) plus the
	 * bitmaps, and roundup to the next pagesize.
	 */
	size = PAGE_ROUNDUP(dbtob(4) + cpr_bitmap_size);
	cpr_buf_size = MAX(size, CPRBUFSZ);
	cpr_buf_blocks = btodb(cpr_buf_size);
	cpr_buf = kmem_alloc(cpr_buf_size, KM_NOSLEEP);
	if (cpr_buf == NULL) {
		cpr_err(CE_WARN, allocerr);
		return (ENOMEM);
	}
	cpr_buf_end = cpr_buf + cpr_buf_size;

	cpr_pagedata_size = mmu_ptob(CPR_MAXCONTIG + 1);
	cpr_pagedata = kmem_alloc(cpr_pagedata_size, KM_NOSLEEP);
	if (cpr_pagedata == NULL) {
		kmem_free(cpr_buf, cpr_buf_size);
		cpr_buf = NULL;
		cpr_err(CE_WARN, allocerr);
		return (ENOMEM);
	}

	return (0);
}


/*
 * Set bitmap size in bytes based on phys_install.
 */
void
cpr_set_bitmap_size(void)
{
	struct memlist *pmem;
	size_t size = 0;

	memlist_read_lock();
	for (pmem = phys_install; pmem; pmem = pmem->next)
		size += pmem->size;
	memlist_read_unlock();
	cpr_bitmap_size = BITMAP_BYTES(size);
}


/*
 * CPR dump header contains the following information:
 *	1. header magic -- unique to cpr state file
 *	2. kernel return pc & ppn for resume
 *	3. current thread info
 *	4. debug level and test mode
 *	5. number of bitmaps allocated
 *	6. number of page records
 */
static int
cpr_write_header(vnode_t *vp)
{
	extern ushort_t cpr_mach_type;
	struct cpr_dump_desc cdump;
	pgcnt_t bitmap_pages;
	pgcnt_t kpages, vpages, upages;
	pgcnt_t cpr_count_kpages(int mapflag, bitfunc_t bitfunc);

	cdump.cdd_magic = (uint_t)CPR_DUMP_MAGIC;
	cdump.cdd_version = CPR_VERSION;
	cdump.cdd_machine = cpr_mach_type;
	cdump.cdd_debug = cpr_debug;
	cdump.cdd_test_mode = cpr_test_mode;
	cdump.cdd_bitmaprec = cpr_nbitmaps;

	cpr_clear_bitmaps();

	/*
	 * Remember how many pages we plan to save to statefile.
	 * This information will be used for sanity checks.
	 * Untag those pages that will not be saved to statefile.
	 */
	kpages = cpr_count_kpages(REGULAR_BITMAP, cpr_setbit);
	vpages = cpr_count_volatile_pages(REGULAR_BITMAP, cpr_clrbit);
	upages = cpr_count_upages(REGULAR_BITMAP, cpr_setbit);
	cdump.cdd_dumppgsize = kpages - vpages + upages;
	cpr_pages_tobe_dumped = cdump.cdd_dumppgsize;
	CPR_DEBUG(CPR_DEBUG7,
	    "\ncpr_write_header: kpages %ld - vpages %ld + upages %ld = %d\n",
	    kpages, vpages, upages, cdump.cdd_dumppgsize);

	/*
	 * Some pages contain volatile data (cpr_buf and storage area for
	 * sensitive kpages), which are no longer needed after the statefile
	 * is dumped to disk.  We have already untagged them from regular
	 * bitmaps.  Now tag them into the volatile bitmaps.  The pages in
	 * volatile bitmaps will be claimed during resume, and the resumed
	 * kernel will free them.
	 */
	(void) cpr_count_volatile_pages(VOLATILE_BITMAP, cpr_setbit);

	bitmap_pages = mmu_btopr(cpr_bitmap_size);

	/*
	 * Export accurate statefile size for statefile allocation retry.
	 * statefile_size = all the headers + total pages +
	 * number of pages used by the bitmaps.
	 * Roundup will be done in the file allocation code.
	 */
	STAT->cs_nocomp_statefsz = sizeof (cdd_t) + sizeof (cmd_t) +
	    (sizeof (cbd_t) * cdump.cdd_bitmaprec) +
	    (sizeof (cpd_t) * cdump.cdd_dumppgsize) +
	    mmu_ptob(cdump.cdd_dumppgsize + bitmap_pages);

	/*
	 * If the estimated statefile is not big enough,
	 * go retry now to save un-necessary operations.
	 */
	if (!(CPR->c_flags & C_COMPRESSING) &&
	    (STAT->cs_nocomp_statefsz > STAT->cs_est_statefsz)) {
		if (cpr_debug & (CPR_DEBUG1 | CPR_DEBUG7))
			prom_printf("cpr_write_header: "
			    "STAT->cs_nocomp_statefsz > "
			    "STAT->cs_est_statefsz\n");
		return (ENOSPC);
	}

	/* now write cpr dump descriptor */
	return (cpr_write(vp, (caddr_t)&cdump, sizeof (cdd_t)));
}


/*
 * CPR dump tail record contains the following information:
 *	1. header magic -- unique to cpr state file
 *	2. all misc info that needs to be passed to cprboot or resumed kernel
 */
static int
cpr_write_terminator(vnode_t *vp)
{
	cpr_term.magic = (uint_t)CPR_TERM_MAGIC;
	cpr_term.va = (cpr_ptr)&cpr_term;
	cpr_term.pfn = (cpr_ext)va_to_pfn(&cpr_term);

	/* count the last one (flush) */
	cpr_term.real_statef_size = STAT->cs_real_statefsz +
	    btod(cpr_wptr - cpr_buf) * DEV_BSIZE;

	CPR_DEBUG(CPR_DEBUG9, "cpr_dump: Real Statefile Size: %ld\n",
	    STAT->cs_real_statefsz);

	cpr_tod_get(&cpr_term.tm_shutdown);

	return (cpr_write(vp, (caddr_t)&cpr_term, sizeof (cpr_term)));
}

/*
 * Write bitmap descriptor array, followed by merged bitmaps.
 */
static int
cpr_write_bitmap(vnode_t *vp)
{
	char *rmap, *vmap, *dst, *tail;
	size_t size, bytes;
	cbd_t *dp;
	int err;

	dp = CPR->c_bmda;
	if (err = cpr_write(vp, (caddr_t)dp, cpr_nbitmaps * sizeof (*dp)))
		return (err);

	/*
	 * merge regular and volatile bitmaps into tmp space
	 * and write to disk
	 */
	for (; dp->cbd_size; dp++) {
		rmap = (char *)dp->cbd_reg_bitmap;
		vmap = (char *)dp->cbd_vlt_bitmap;
		for (size = dp->cbd_size; size; size -= bytes) {
			bytes = min(size, sizeof (cpr_pagecopy));
			tail = &cpr_pagecopy[bytes];
			for (dst = cpr_pagecopy; dst < tail; dst++)
				*dst = *rmap++ | *vmap++;
			if (err = cpr_write(vp, cpr_pagecopy, bytes))
				break;
		}
	}

	return (err);
}


static int
cpr_write_statefile(vnode_t *vp)
{
	uint_t error = 0;
	extern	int	i_cpr_check_pgs_dumped();
	void flush_windows(void);
	pgcnt_t spages;
	char *str;

	flush_windows();

	/*
	 * to get an accurate view of kas, we need to untag sensitive
	 * pages *before* dumping them because the disk driver makes
	 * allocations and changes kas along the way.  The remaining
	 * pages referenced in the bitmaps are dumped out later as
	 * regular kpages.
	 */
	str = "cpr_write_statefile:";
	spages = i_cpr_count_sensitive_kpages(REGULAR_BITMAP, cpr_clrbit);
	CPR_DEBUG(CPR_DEBUG7, "%s untag %ld sens pages\n", str, spages);

	/*
	 * now it's OK to call a driver that makes allocations
	 */
	cpr_disk_writes_ok = 1;

	/*
	 * now write out the clean sensitive kpages
	 * according to the sensitive descriptors
	 */
	error = i_cpr_dump_sensitive_kpages(vp);
	if (error) {
		CPR_DEBUG(CPR_DEBUG7,
		    "%s cpr_dump_sensitive_kpages() failed!\n", str);
		return (error);
	}

	/*
	 * cpr_dump_regular_pages() counts cpr_regular_pgs_dumped
	 */
	error = cpr_dump_regular_pages(vp);
	if (error) {
		CPR_DEBUG(CPR_DEBUG7,
		    "%s cpr_dump_regular_pages() failed!\n", str);
		return (error);
	}

	/*
	 * sanity check to verify the right number of pages were dumped
	 */
	error = i_cpr_check_pgs_dumped(cpr_pages_tobe_dumped,
	    cpr_regular_pgs_dumped);

	if (error) {
		prom_printf("\n%s page count mismatch!\n", str);
#ifdef DEBUG
		if (cpr_test_mode)
			debug_enter(NULL);
#endif
	}

	return (error);
}
#endif


/*
 * creates the CPR state file, the following sections are
 * written out in sequence:
 *    - writes the cpr dump header
 *    - writes the memory usage bitmaps
 *    - writes the platform dependent info
 *    - writes the remaining user pages
 *    - writes the kernel pages
 */
#if defined(__x86)
	_NOTE(ARGSUSED(0))
#endif
int
cpr_dump(vnode_t *vp)
{
#if defined(__sparc)
	int error;

	if (cpr_buf == NULL) {
		ASSERT(cpr_pagedata == NULL);
		if (error = cpr_alloc_bufs())
			return (error);
	}
	/* point to top of internal buffer */
	cpr_wptr = cpr_buf;

	/* initialize global variables used by the write operation */
	cpr_file_bn = cpr_statefile_offset();
	cpr_dev_space = 0;

	/* allocate bitmaps */
	if (CPR->c_bmda == NULL) {
		if (error = i_cpr_alloc_bitmaps()) {
			cpr_err(CE_WARN, "cannot allocate bitmaps");
			return (error);
		}
	}

	if (error = i_cpr_prom_pages(CPR_PROM_SAVE))
		return (error);

	if (error = i_cpr_dump_setup(vp))
		return (error);

	/*
	 * set internal cross checking; we dont want to call
	 * a disk driver that makes allocations until after
	 * sensitive pages are saved
	 */
	cpr_disk_writes_ok = 0;

	/*
	 * 1253112: heap corruption due to memory allocation when dumpping
	 *	    statefile.
	 * Theoretically on Sun4u only the kernel data nucleus, kvalloc and
	 * kvseg segments can be contaminated should memory allocations happen
	 * during sddump, which is not supposed to happen after the system
	 * is quiesced. Let's call the kernel pages that tend to be affected
	 * 'sensitive kpages' here. To avoid saving inconsistent pages, we
	 * will allocate some storage space to save the clean sensitive pages
	 * aside before statefile dumping takes place. Since there may not be
	 * much memory left at this stage, the sensitive pages will be
	 * compressed before they are saved into the storage area.
	 */
	if (error = i_cpr_save_sensitive_kpages()) {
		CPR_DEBUG(CPR_DEBUG7,
		    "cpr_dump: save_sensitive_kpages failed!\n");
		return (error);
	}

	/*
	 * since all cpr allocations are done (space for sensitive kpages,
	 * bitmaps, cpr_buf), kas is stable, and now we can accurately
	 * count regular and sensitive kpages.
	 */
	if (error = cpr_write_header(vp)) {
		CPR_DEBUG(CPR_DEBUG7,
		    "cpr_dump: cpr_write_header() failed!\n");
		return (error);
	}

	if (error = i_cpr_write_machdep(vp))
		return (error);

	if (error = i_cpr_blockzero(cpr_buf, &cpr_wptr, NULL, NULL))
		return (error);

	if (error = cpr_write_bitmap(vp))
		return (error);

	if (error = cpr_write_statefile(vp)) {
		CPR_DEBUG(CPR_DEBUG7,
		    "cpr_dump: cpr_write_statefile() failed!\n");
		return (error);
	}

	if (error = cpr_write_terminator(vp))
		return (error);

	if (error = cpr_flush_write(vp))
		return (error);

	if (error = i_cpr_blockzero(cpr_buf, &cpr_wptr, &cpr_file_bn, vp))
		return (error);
#endif

	return (0);
}


#if defined(__sparc)
/*
 * cpr_xwalk() is called many 100x with a range within kvseg or kvseg_reloc;
 * a page-count from each range is accumulated at arg->pages.
 */
static void
cpr_xwalk(void *arg, void *base, size_t size)
{
	struct cpr_walkinfo *cwip = arg;

	cwip->pages += cpr_count_pages(base, size,
	    cwip->mapflag, cwip->bitfunc, DBG_DONTSHOWRANGE);
	cwip->size += size;
	cwip->ranges++;
}

/*
 * cpr_walk() is called many 100x with a range within kvseg or kvseg_reloc;
 * a page-count from each range is accumulated at arg->pages.
 */
static void
cpr_walk(void *arg, void *base, size_t size)
{
	caddr_t addr = base;
	caddr_t addr_end = addr + size;

	/*
	 * If we are about to start walking the range of addresses we
	 * carved out of the kernel heap for the large page heap walk
	 * heap_lp_arena to find what segments are actually populated
	 */
	if (SEGKMEM_USE_LARGEPAGES &&
	    addr == heap_lp_base && addr_end == heap_lp_end &&
	    vmem_size(heap_lp_arena, VMEM_ALLOC) < size) {
		vmem_walk(heap_lp_arena, VMEM_ALLOC, cpr_xwalk, arg);
	} else {
		cpr_xwalk(arg, base, size);
	}
}


/*
 * faster scan of kvseg using vmem_walk() to visit
 * allocated ranges.
 */
pgcnt_t
cpr_scan_kvseg(int mapflag, bitfunc_t bitfunc, struct seg *seg)
{
	struct cpr_walkinfo cwinfo;

	bzero(&cwinfo, sizeof (cwinfo));
	cwinfo.mapflag = mapflag;
	cwinfo.bitfunc = bitfunc;

	vmem_walk(heap_arena, VMEM_ALLOC, cpr_walk, &cwinfo);

	if (cpr_debug & CPR_DEBUG7) {
		prom_printf("walked %d sub-ranges, total pages %ld\n",
		    cwinfo.ranges, mmu_btop(cwinfo.size));
		cpr_show_range(seg->s_base, seg->s_size,
		    mapflag, bitfunc, cwinfo.pages);
	}

	return (cwinfo.pages);
}


/*
 * cpr_walk_kpm() is called for every used area within the large
 * segkpm virtual address window. A page-count is accumulated at
 * arg->pages.
 */
static void
cpr_walk_kpm(void *arg, void *base, size_t size)
{
	struct cpr_walkinfo *cwip = arg;

	cwip->pages += cpr_count_pages(base, size,
	    cwip->mapflag, cwip->bitfunc, DBG_DONTSHOWRANGE);
	cwip->size += size;
	cwip->ranges++;
}


/*
 * faster scan of segkpm using hat_kpm_walk() to visit only used ranges.
 */
/*ARGSUSED*/
static pgcnt_t
cpr_scan_segkpm(int mapflag, bitfunc_t bitfunc, struct seg *seg)
{
	struct cpr_walkinfo cwinfo;

	if (kpm_enable == 0)
		return (0);

	bzero(&cwinfo, sizeof (cwinfo));
	cwinfo.mapflag = mapflag;
	cwinfo.bitfunc = bitfunc;
	hat_kpm_walk(cpr_walk_kpm, &cwinfo);

	if (cpr_debug & CPR_DEBUG7) {
		prom_printf("walked %d sub-ranges, total pages %ld\n",
		    cwinfo.ranges, mmu_btop(cwinfo.size));
		cpr_show_range(segkpm->s_base, segkpm->s_size,
		    mapflag, bitfunc, cwinfo.pages);
	}

	return (cwinfo.pages);
}


/*
 * Sparsely filled kernel segments are registered in kseg_table for
 * easier lookup. See also block comment for cpr_count_seg_pages.
 */

#define	KSEG_SEG_ADDR	0	/* address of struct seg */
#define	KSEG_PTR_ADDR	1	/* address of pointer to struct seg */

typedef struct {
	struct seg **st_seg;		/* segment pointer or segment address */
	pgcnt_t	(*st_fcn)(int, bitfunc_t, struct seg *); /* function to call */
	int	st_addrtype;		/* address type in st_seg */
} ksegtbl_entry_t;

ksegtbl_entry_t kseg_table[] = {
	{(struct seg **)&kvseg,		cpr_scan_kvseg,		KSEG_SEG_ADDR},
	{&segkpm,			cpr_scan_segkpm,	KSEG_PTR_ADDR},
	{NULL,				0,			0}
};


/*
 * Compare seg with each entry in kseg_table; when there is a match
 * return the entry pointer, otherwise return NULL.
 */
static ksegtbl_entry_t *
cpr_sparse_seg_check(struct seg *seg)
{
	ksegtbl_entry_t *ste = &kseg_table[0];
	struct seg *tseg;

	for (; ste->st_seg; ste++) {
		tseg = (ste->st_addrtype == KSEG_PTR_ADDR) ?
		    *ste->st_seg : (struct seg *)ste->st_seg;

		if (seg == tseg)
			return (ste);
	}

	return ((ksegtbl_entry_t *)NULL);
}


/*
 * Count pages within each kernel segment; call cpr_sparse_seg_check()
 * to find out whether a sparsely filled segment needs special
 * treatment (e.g. kvseg).
 * Todo: A "SEGOP_CPR" like SEGOP_DUMP should be introduced, the cpr
 *       module shouldn't need to know segment details like if it is
 *       sparsely filled or not (makes kseg_table obsolete).
 */
pgcnt_t
cpr_count_seg_pages(int mapflag, bitfunc_t bitfunc)
{
	struct seg *segp;
	pgcnt_t pages;
	ksegtbl_entry_t *ste;

	pages = 0;
	for (segp = AS_SEGFIRST(&kas); segp; segp = AS_SEGNEXT(&kas, segp)) {
		if (ste = cpr_sparse_seg_check(segp)) {
			pages += (ste->st_fcn)(mapflag, bitfunc, segp);
		} else {
			pages += cpr_count_pages(segp->s_base,
			    segp->s_size, mapflag, bitfunc, DBG_SHOWRANGE);
		}
	}

	return (pages);
}


/*
 * count kernel pages within kas and any special ranges
 */
pgcnt_t
cpr_count_kpages(int mapflag, bitfunc_t bitfunc)
{
	pgcnt_t kas_cnt;

	/*
	 * Some pages need to be taken care of differently.
	 * eg: panicbuf pages of sun4m are not in kas but they need
	 * to be saved.  On sun4u, the physical pages of panicbuf are
	 * allocated via prom_retain().
	 */
	kas_cnt = i_cpr_count_special_kpages(mapflag, bitfunc);
	kas_cnt += cpr_count_seg_pages(mapflag, bitfunc);

	CPR_DEBUG(CPR_DEBUG9, "cpr_count_kpages: kas_cnt=%ld\n", kas_cnt);
	CPR_DEBUG(CPR_DEBUG7, "\ncpr_count_kpages: %ld pages, 0x%lx bytes\n",
	    kas_cnt, mmu_ptob(kas_cnt));

	return (kas_cnt);
}


/*
 * Set a bit corresponding to the arg phys page number;
 * returns 0 when the ppn is valid and the corresponding
 * map bit was clear, otherwise returns 1.
 */
int
cpr_setbit(pfn_t ppn, int mapflag)
{
	char *bitmap;
	cbd_t *dp;
	pfn_t rel;
	int clr;

	for (dp = CPR->c_bmda; dp->cbd_size; dp++) {
		if (PPN_IN_RANGE(ppn, dp)) {
			bitmap = DESC_TO_MAP(dp, mapflag);
			rel = ppn - dp->cbd_spfn;
			if ((clr = isclr(bitmap, rel)) != 0)
				setbit(bitmap, rel);
			return (clr == 0);
		}
	}

	return (1);
}


/*
 * Clear a bit corresponding to the arg phys page number.
 */
int
cpr_clrbit(pfn_t ppn, int mapflag)
{
	char *bitmap;
	cbd_t *dp;
	pfn_t rel;
	int set;

	for (dp = CPR->c_bmda; dp->cbd_size; dp++) {
		if (PPN_IN_RANGE(ppn, dp)) {
			bitmap = DESC_TO_MAP(dp, mapflag);
			rel = ppn - dp->cbd_spfn;
			if ((set = isset(bitmap, rel)) != 0)
				clrbit(bitmap, rel);
			return (set == 0);
		}
	}

	return (1);
}


/* ARGSUSED */
int
cpr_nobit(pfn_t ppn, int mapflag)
{
	return (0);
}


/*
 * Lookup a bit corresponding to the arg phys page number.
 */
int
cpr_isset(pfn_t ppn, int mapflag)
{
	char *bitmap;
	cbd_t *dp;
	pfn_t rel;

	for (dp = CPR->c_bmda; dp->cbd_size; dp++) {
		if (PPN_IN_RANGE(ppn, dp)) {
			bitmap = DESC_TO_MAP(dp, mapflag);
			rel = ppn - dp->cbd_spfn;
			return (isset(bitmap, rel));
		}
	}

	return (0);
}


/*
 * Go thru all pages and pick up any page not caught during the invalidation
 * stage. This is also used to save pages with cow lock or phys page lock held
 * (none zero p_lckcnt or p_cowcnt)
 */
static	int
cpr_count_upages(int mapflag, bitfunc_t bitfunc)
{
	page_t *pp, *page0;
	pgcnt_t dcnt = 0, tcnt = 0;
	pfn_t pfn;

	page0 = pp = page_first();

	do {
#if defined(__sparc)
		extern struct vnode prom_ppages;
		if (pp->p_vnode == NULL || PP_ISKAS(pp) ||
		    pp->p_vnode == &prom_ppages ||
		    PP_ISFREE(pp) && PP_ISAGED(pp))
#else
		if (pp->p_vnode == NULL || PP_ISKAS(pp) ||
		    PP_ISFREE(pp) && PP_ISAGED(pp))
#endif /* __sparc */
			continue;

		pfn = page_pptonum(pp);
		if (pf_is_memory(pfn)) {
			tcnt++;
			if ((*bitfunc)(pfn, mapflag) == 0)
				dcnt++; /* dirty count */
		}
	} while ((pp = page_next(pp)) != page0);

	STAT->cs_upage2statef = dcnt;
	CPR_DEBUG(CPR_DEBUG9, "cpr_count_upages: dirty=%ld total=%ld\n",
	    dcnt, tcnt);
	CPR_DEBUG(CPR_DEBUG7, "cpr_count_upages: %ld pages, 0x%lx bytes\n",
	    dcnt, mmu_ptob(dcnt));

	return (dcnt);
}


/*
 * try compressing pages based on cflag,
 * and for DEBUG kernels, verify uncompressed data checksum;
 *
 * this routine replaces common code from
 * i_cpr_compress_and_save() and cpr_compress_and_write()
 */
char *
cpr_compress_pages(cpd_t *dp, pgcnt_t pages, int cflag)
{
	size_t nbytes, clen, len;
	uint32_t test_sum;
	char *datap;

	nbytes = mmu_ptob(pages);

	/*
	 * set length to the original uncompressed data size;
	 * always init cpd_flag to zero
	 */
	dp->cpd_length = nbytes;
	dp->cpd_flag = 0;

#ifdef	DEBUG
	/*
	 * Make a copy of the uncompressed data so we can checksum it.
	 * Compress that copy so the checksum works at the other end
	 */
	cprbcopy(CPR->c_mapping_area, cpr_pagecopy, nbytes);
	dp->cpd_usum = checksum32(cpr_pagecopy, nbytes);
	dp->cpd_flag |= CPD_USUM;
	datap = cpr_pagecopy;
#else
	datap = CPR->c_mapping_area;
	dp->cpd_usum = 0;
#endif

	/*
	 * try compressing the raw data to cpr_pagedata;
	 * if there was a size reduction: record the new length,
	 * flag the compression, and point to the compressed data.
	 */
	dp->cpd_csum = 0;
	if (cflag) {
		clen = compress(datap, cpr_pagedata, nbytes);
		if (clen < nbytes) {
			dp->cpd_flag |= CPD_COMPRESS;
			dp->cpd_length = clen;
			datap = cpr_pagedata;
#ifdef	DEBUG
			dp->cpd_csum = checksum32(datap, clen);
			dp->cpd_flag |= CPD_CSUM;

			/*
			 * decompress the data back to a scratch area
			 * and compare the new checksum with the original
			 * checksum to verify the compression.
			 */
			bzero(cpr_pagecopy, sizeof (cpr_pagecopy));
			len = decompress(datap, cpr_pagecopy,
			    clen, sizeof (cpr_pagecopy));
			test_sum = checksum32(cpr_pagecopy, len);
			ASSERT(test_sum == dp->cpd_usum);
#endif
		}
	}

	return (datap);
}


/*
 * 1. Prepare cpr page descriptor and write it to file
 * 2. Compress page data and write it out
 */
static int
cpr_compress_and_write(vnode_t *vp, uint_t va, pfn_t pfn, pgcnt_t npg)
{
	int error = 0;
	char *datap;
	cpd_t cpd;	/* cpr page descriptor */
	extern void i_cpr_mapin(caddr_t, uint_t, pfn_t);
	extern void i_cpr_mapout(caddr_t, uint_t);

	i_cpr_mapin(CPR->c_mapping_area, npg, pfn);

	CPR_DEBUG(CPR_DEBUG3, "mapped-in %ld pages, vaddr 0x%p, pfn 0x%lx\n",
	    npg, CPR->c_mapping_area, pfn);

	/*
	 * Fill cpr page descriptor.
	 */
	cpd.cpd_magic = (uint_t)CPR_PAGE_MAGIC;
	cpd.cpd_pfn = pfn;
	cpd.cpd_pages = npg;

	STAT->cs_dumped_statefsz += mmu_ptob(npg);

	datap = cpr_compress_pages(&cpd, npg, CPR->c_flags & C_COMPRESSING);

	/* Write cpr page descriptor */
	error = cpr_write(vp, (caddr_t)&cpd, sizeof (cpd_t));

	/* Write compressed page data */
	error = cpr_write(vp, (caddr_t)datap, cpd.cpd_length);

	/*
	 * Unmap the pages for tlb and vac flushing
	 */
	i_cpr_mapout(CPR->c_mapping_area, npg);

	if (error) {
		CPR_DEBUG(CPR_DEBUG1,
		    "cpr_compress_and_write: vp 0x%p va 0x%x ", vp, va);
		CPR_DEBUG(CPR_DEBUG1, "pfn 0x%lx blk %d err %d\n",
		    pfn, cpr_file_bn, error);
	} else {
		cpr_regular_pgs_dumped += npg;
	}

	return (error);
}


int
cpr_write(vnode_t *vp, caddr_t buffer, size_t size)
{
	caddr_t	fromp = buffer;
	size_t bytes, wbytes;
	int error;

	if (cpr_dev_space == 0) {
		if (vp->v_type == VBLK) {
			cpr_dev_space = cpr_get_devsize(vp->v_rdev);
			ASSERT(cpr_dev_space);
		} else
			cpr_dev_space = 1;	/* not used in this case */
	}

	/*
	 * break the write into multiple part if request is large,
	 * calculate count up to buf page boundary, then write it out.
	 * repeat until done.
	 */
	while (size) {
		bytes = MIN(size, cpr_buf_end - cpr_wptr);
		cprbcopy(fromp, cpr_wptr, bytes);
		cpr_wptr += bytes;
		fromp += bytes;
		size -= bytes;
		if (cpr_wptr < cpr_buf_end)
			return (0);	/* buffer not full yet */
		ASSERT(cpr_wptr == cpr_buf_end);

		wbytes = dbtob(cpr_file_bn + cpr_buf_blocks);
		if (vp->v_type == VBLK) {
			if (wbytes > cpr_dev_space)
				return (ENOSPC);
		} else {
			if (wbytes > VTOI(vp)->i_size)
				return (ENOSPC);
		}

		CPR_DEBUG(CPR_DEBUG3,
		    "cpr_write: frmp=%p wptr=%p cnt=%lx...",
		    fromp, cpr_wptr, bytes);
		/*
		 * cross check, this should not happen!
		 */
		if (cpr_disk_writes_ok == 0) {
			prom_printf("cpr_write: disk write too early!\n");
			return (EINVAL);
		}

		do_polled_io = 1;
		error = VOP_DUMP(vp, cpr_buf, cpr_file_bn, cpr_buf_blocks,
		    NULL);
		do_polled_io = 0;
		CPR_DEBUG(CPR_DEBUG3, "done\n");

		STAT->cs_real_statefsz += cpr_buf_size;

		if (error) {
			cpr_err(CE_WARN, "cpr_write error %d", error);
			return (error);
		}
		cpr_file_bn += cpr_buf_blocks;	/* Increment block count */
		cpr_wptr = cpr_buf;		/* back to top of buffer */
	}
	return (0);
}


int
cpr_flush_write(vnode_t *vp)
{
	int	nblk;
	int	error;

	/*
	 * Calculate remaining blocks in buffer, rounded up to nearest
	 * disk block
	 */
	nblk = btod(cpr_wptr - cpr_buf);

	do_polled_io = 1;
	error = VOP_DUMP(vp, (caddr_t)cpr_buf, cpr_file_bn, nblk, NULL);
	do_polled_io = 0;

	cpr_file_bn += nblk;
	if (error)
		CPR_DEBUG(CPR_DEBUG2, "cpr_flush_write: error (%d)\n",
		    error);
	return (error);
}

void
cpr_clear_bitmaps(void)
{
	cbd_t *dp;

	for (dp = CPR->c_bmda; dp->cbd_size; dp++) {
		bzero((void *)dp->cbd_reg_bitmap,
		    (size_t)dp->cbd_size * 2);
	}
	CPR_DEBUG(CPR_DEBUG7, "\ncleared reg and vlt bitmaps\n");
}

int
cpr_contig_pages(vnode_t *vp, int flag)
{
	int chunks = 0, error = 0;
	pgcnt_t i, j, totbit;
	pfn_t spfn;
	cbd_t *dp;
	uint_t	spin_cnt = 0;
	extern	int i_cpr_compress_and_save();

	for (dp = CPR->c_bmda; dp->cbd_size; dp++) {
		spfn = dp->cbd_spfn;
		totbit = BTOb(dp->cbd_size);
		i = 0; /* Beginning of bitmap */
		j = 0;
		while (i < totbit) {
			while ((j < CPR_MAXCONTIG) && ((j + i) < totbit)) {
				if (isset((char *)dp->cbd_reg_bitmap, j+i))
					j++;
				else /* not contiguous anymore */
					break;
			}

			if (j) {
				chunks++;
				if (flag == SAVE_TO_STORAGE) {
					error = i_cpr_compress_and_save(
					    chunks, spfn + i, j);
					if (error)
						return (error);
				} else if (flag == WRITE_TO_STATEFILE) {
					error = cpr_compress_and_write(vp, 0,
					    spfn + i, j);
					if (error)
						return (error);
					else {
						spin_cnt++;
						if ((spin_cnt & 0x5F) == 1)
							cpr_spinning_bar();
					}
				}
			}

			i += j;
			if (j != CPR_MAXCONTIG) {
				/* Stopped on a non-tagged page */
				i++;
			}

			j = 0;
		}
	}

	if (flag == STORAGE_DESC_ALLOC)
		return (chunks);
	else
		return (0);
}


void
cpr_show_range(caddr_t vaddr, size_t size,
    int mapflag, bitfunc_t bitfunc, pgcnt_t count)
{
	char *action, *bname;

	bname = (mapflag == REGULAR_BITMAP) ? "regular" : "volatile";
	if (bitfunc == cpr_setbit)
		action = "tag";
	else if (bitfunc == cpr_clrbit)
		action = "untag";
	else
		action = "none";
	prom_printf("range (0x%p, 0x%p), %s bitmap, %s %ld\n",
	    vaddr, vaddr + size, bname, action, count);
}


pgcnt_t
cpr_count_pages(caddr_t sva, size_t size,
    int mapflag, bitfunc_t bitfunc, int showrange)
{
	caddr_t	va, eva;
	pfn_t pfn;
	pgcnt_t count = 0;

	eva = sva + PAGE_ROUNDUP(size);
	for (va = sva; va < eva; va += MMU_PAGESIZE) {
		pfn = va_to_pfn(va);
		if (pfn != PFN_INVALID && pf_is_memory(pfn)) {
			if ((*bitfunc)(pfn, mapflag) == 0)
				count++;
		}
	}

	if ((cpr_debug & CPR_DEBUG7) && showrange == DBG_SHOWRANGE)
		cpr_show_range(sva, size, mapflag, bitfunc, count);

	return (count);
}


pgcnt_t
cpr_count_volatile_pages(int mapflag, bitfunc_t bitfunc)
{
	pgcnt_t count = 0;

	if (cpr_buf) {
		count += cpr_count_pages(cpr_buf, cpr_buf_size,
		    mapflag, bitfunc, DBG_SHOWRANGE);
	}
	if (cpr_pagedata) {
		count += cpr_count_pages(cpr_pagedata, cpr_pagedata_size,
		    mapflag, bitfunc, DBG_SHOWRANGE);
	}
	count += i_cpr_count_storage_pages(mapflag, bitfunc);

	CPR_DEBUG(CPR_DEBUG7, "cpr_count_vpages: %ld pages, 0x%lx bytes\n",
	    count, mmu_ptob(count));
	return (count);
}


static int
cpr_dump_regular_pages(vnode_t *vp)
{
	int error;

	cpr_regular_pgs_dumped = 0;
	error = cpr_contig_pages(vp, WRITE_TO_STATEFILE);
	if (!error)
		CPR_DEBUG(CPR_DEBUG7, "cpr_dump_regular_pages() done.\n");
	return (error);
}
#endif

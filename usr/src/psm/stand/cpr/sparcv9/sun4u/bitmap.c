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

#include <sys/types.h>
#include <sys/cpr.h>
#include <sys/fs/ufs_fs.h>
#include <sys/prom_plat.h>
#include "cprboot.h"


/*
 * max space for a copy of physavail data
 * prop size is usually 80 to 128 bytes
 */
#define	PA_BUFSIZE	1024

#define	CB_SETBIT	1
#define	CB_ISSET	2
#define	CB_ISCLR	3

/*
 * globals
 */
int cb_nbitmaps;

/*
 * file scope
 */
static arange_t *cb_physavail;
static char pabuf[PA_BUFSIZE];
static caddr_t high_virt;

static cbd_t cb_bmda[CPR_MAX_BMDESC];
static int tracking_init;


static int
cb_bitop(pfn_t ppn, int op)
{
	int rel, rval = 0;
	char *bitmap;
	cbd_t *dp;

	for (dp = cb_bmda; dp->cbd_size; dp++) {
		if (PPN_IN_RANGE(ppn, dp)) {
			bitmap = (char *)dp->cbd_reg_bitmap;
			rel = ppn - dp->cbd_spfn;
			if (op == CB_SETBIT)
				setbit(bitmap, rel);
			else if (op == CB_ISSET)
				rval = isset(bitmap, rel);
			else if (op == CB_ISCLR)
				rval = isclr(bitmap, rel);
			break;
		}
	}

	return (rval);
}


/*
 * count pages that are isolated from the kernel
 * within each available range
 */
static void
count_free_pages(void)
{
	arange_t *arp;
	pfn_t bitno;
	int cnt;

	for (arp = cb_physavail; arp->high; arp++) {
		cnt = 0;
		for (bitno = arp->low; bitno <= arp->high; bitno++) {
			if (cb_bitop(bitno, CB_ISCLR))
				cnt++;
		}
		arp->nfree = cnt;
	}
}


/*
 * scan the physavail list for a page
 * that doesn't clash with the kernel
 */
static pfn_t
search_phav_pages(void)
{
	static arange_t *arp;
	static pfn_t bitno;
	int rescan;

	if (arp == NULL) {
		count_free_pages();
		arp = cb_physavail;
		bitno = arp->low;
	}

	/*
	 * begin scanning from the previous position and if the scan
	 * reaches the end of the list, scan a second time from the top;
	 * nfree is checked to eliminate scanning overhead when most
	 * of the available space gets used up.  when a page is found,
	 * set a bit so the page wont be found by another scan.
	 */
	for (rescan = 0; rescan < 2; rescan++) {
		for (; arp->high; bitno = (++arp)->low) {
			if (arp->nfree == 0)
				continue;
			for (; bitno <= arp->high; bitno++) {
				if (cb_bitop(bitno, CB_ISCLR)) {
					(void) cb_bitop(bitno, CB_SETBIT);
					arp->nfree--;
					return (bitno++);
				}
			}
		}
		arp = cb_physavail;
		bitno = arp->low;
	}

	return (PFN_INVALID);
}


/*
 * scan statefile buffer pages for reusable tmp space
 */
static pfn_t
search_buf_pages(void)
{
	size_t coff, src_base;
	static size_t lboff;
	pfn_t ppn;

	if (tracking_init == 0)
		return (PFN_INVALID);

	/*
	 * when scanning the list of statefile buffer ppns, we know that
	 * all pages from lboff to the page boundary of buf_offset have
	 * already been restored; when the associated page bit is clear,
	 * that page is isolated from the kernel and we can reuse it for
	 * tmp space; otherwise, when SF_DIFF_PPN indicates a page had
	 * been moved, we know the page bit was previously clear and
	 * later set, and we can reuse the new page.
	 */
	src_base = sfile.buf_offset & MMU_PAGEMASK;
	while (lboff < src_base) {
		coff = lboff;
		lboff += MMU_PAGESIZE;
		ppn = SF_ORIG_PPN(coff);
		if (cb_bitop(ppn, CB_ISCLR)) {
			(void) cb_bitop(ppn, CB_SETBIT);
			SF_STAT_INC(recycle);
			return (ppn);
		} else if (SF_DIFF_PPN(coff)) {
			SF_STAT_INC(recycle);
			return (SF_BUF_PPN(coff));
		}
	}

	return (PFN_INVALID);
}


/*
 * scan physavail and statefile buffer page lists
 * for a page that doesn't clash with the kernel
 */
pfn_t
find_apage(void)
{
	pfn_t ppn;

	ppn = search_phav_pages();
	if (ppn != PFN_INVALID)
		return (ppn);
	ppn = search_buf_pages();
	if (ppn != PFN_INVALID)
		return (ppn);

	prom_printf("\n%s: ran out of available/free pages!\n%s\n",
	    prog, rsvp);
	cb_exit_to_mon();

	/* NOTREACHED */
	return (PFN_INVALID);
}


/*
 * reserve virt range, find available phys pages,
 * and map-in each phys starting at vaddr
 */
static caddr_t
map_free_phys(caddr_t vaddr, size_t size, char *name)
{
	int pages, ppn, err;
	physaddr_t phys;
	caddr_t virt;
	char *str;

	str = "map_free_phys";
	virt = prom_claim_virt(size, vaddr);
	CB_VPRINTF(("\n%s: claim vaddr 0x%p, size 0x%lx, ret 0x%p\n",
	    str, (void *)vaddr, size, (void *)virt));
	if (virt != vaddr) {
		prom_printf("\n%s: cant reserve (0x%p - 0x%p) for \"%s\"\n",
		    str, (void *)vaddr, (void *)(vaddr + size), name);
		return (virt);
	}

	for (pages = mmu_btop(size); pages--; virt += MMU_PAGESIZE) {
		/*
		 * map virt page to free phys
		 */
		ppn = find_apage();
		phys = PN_TO_ADDR(ppn);

		err = prom_map_phys(-1, MMU_PAGESIZE, virt, phys);
		if (err || verbose) {
			prom_printf("    map virt 0x%p, phys 0x%llx, "
			    "ppn 0x%x, ret %d\n", (void *)virt, phys, ppn, err);
		}
		if (err)
			return ((caddr_t)ERR);
	}

	return (vaddr);
}


/*
 * check bitmap desc and relocate bitmap data
 * to pages isolated from the kernel
 *
 * sets globals:
 *	high_virt
 */
int
cb_set_bitmap(void)
{
	size_t bmda_size, all_bitmap_size, alloc_size;
	caddr_t newvirt, src, dst, base;
	cbd_t *dp;
	char *str;

	str = "cb_set_bitmap";
	CB_VPRINTF((ent_fmt, str, entry));

	/*
	 * max is checked in the cpr module;
	 * this condition should never occur
	 */
	if (cb_nbitmaps > (CPR_MAX_BMDESC - 1)) {
		prom_printf("%s: too many bitmap descriptors %d, max %d\n",
		    str, cb_nbitmaps, (CPR_MAX_BMDESC - 1));
		return (ERR);
	}

	/*
	 * copy bitmap descriptors to aligned space, check magic numbers,
	 * and set the total size of all bitmaps
	 */
	bmda_size = cb_nbitmaps * sizeof (cbd_t);
	src = SF_DATA();
	bcopy(src, cb_bmda, bmda_size);
	base = src + bmda_size;
	all_bitmap_size = 0;
	for (dp = cb_bmda; dp < &cb_bmda[cb_nbitmaps]; dp++) {
		if (dp->cbd_magic != CPR_BITMAP_MAGIC) {
			prom_printf("%s: bad magic 0x%x, expect 0x%x\n",
			    str, dp->cbd_magic, CPR_BITMAP_MAGIC);
			return (ERR);
		}
		all_bitmap_size += dp->cbd_size;
		dp->cbd_reg_bitmap = (cpr_ptr)base;
		base += dp->cbd_size;
	}

	/*
	 * reserve new space for bitmaps
	 */
	alloc_size = PAGE_ROUNDUP(all_bitmap_size);
	if (verbose || CPR_DBG(7)) {
		prom_printf("%s: nbitmaps %d, bmda_size 0x%lx\n",
		    str, cb_nbitmaps, bmda_size);
		prom_printf("%s: all_bitmap_size 0x%lx, alloc_size 0x%lx\n",
		    str, all_bitmap_size, alloc_size);
	}
	high_virt = (caddr_t)CB_HIGH_VIRT;
	newvirt = map_free_phys(high_virt, alloc_size, "bitmaps");
	if (newvirt != high_virt)
		return (ERR);

	/*
	 * copy the bitmaps, clear any unused space trailing them,
	 * and set references into the new space
	 */
	base = src + bmda_size;
	dst = newvirt;
	bcopy(base, dst, all_bitmap_size);
	if (alloc_size > all_bitmap_size)
		bzero(dst + all_bitmap_size, alloc_size - all_bitmap_size);
	for (dp = cb_bmda; dp->cbd_size; dp++) {
		dp->cbd_reg_bitmap = (cpr_ptr)dst;
		dst += dp->cbd_size;
	}

	/* advance past all the bitmap data */
	SF_ADV(bmda_size + all_bitmap_size);
	high_virt += alloc_size;

	return (0);
}


/*
 * create a new stack for cprboot;
 * this stack is used to avoid clashes with kernel pages and
 * to avoid exceptions while remapping cprboot virt pages
 */
int
cb_get_newstack(void)
{
	caddr_t newstack;

	CB_VENTRY(cb_get_newstack);
	newstack = map_free_phys((caddr_t)CB_STACK_VIRT,
	    CB_STACK_SIZE, "new stack");
	if (newstack != (caddr_t)CB_STACK_VIRT)
		return (ERR);
	return (0);
}


/*
 * since kernel phys pages span most of the installed memory range,
 * some statefile buffer pages will likely clash with the kernel
 * and need to be moved before kernel pages are restored; a list
 * of buf phys page numbers is created here and later updated as
 * buf pages are moved
 *
 * sets globals:
 *	sfile.buf_map
 *	tracking_init
 */
int
cb_tracking_setup(void)
{
	pfn_t ppn, lppn;
	uint_t *imap;
	caddr_t newvirt;
	size_t size;
	int pages;

	CB_VENTRY(cb_tracking_setup);

	pages = mmu_btop(sfile.size);
	size = PAGE_ROUNDUP(pages * sizeof (*imap));
	newvirt = map_free_phys(high_virt, size, "buf tracking");
	if (newvirt != high_virt)
		return (ERR);
	sfile.buf_map = (uint_t *)newvirt;
	high_virt += size;

	/*
	 * create identity map of sfile.buf phys pages
	 */
	imap = sfile.buf_map;
	lppn = sfile.low_ppn + pages;
	for (ppn = sfile.low_ppn; ppn < lppn; ppn++, imap++)
		*imap = (uint_t)ppn;
	tracking_init = 1;

	return (0);
}


/*
 * get "available" prop from /memory node
 *
 * sets globals:
 *	cb_physavail
 */
int
cb_get_physavail(void)
{
	int len, glen, scnt, need, space;
	char *str, *pdev, *mem_prop;
	pnode_t mem_node;
	physaddr_t phys;
	pgcnt_t pages;
	arange_t *arp;
	pphav_t *pap;
	size_t size;
	pfn_t ppn;
	int err;

	str = "cb_get_physavail";
	CB_VPRINTF((ent_fmt, str, entry));

	/*
	 * first move cprboot pages off the physavail list
	 */
	size = PAGE_ROUNDUP((uintptr_t)_end) - (uintptr_t)_start;
	ppn = cpr_vatopfn((caddr_t)_start);
	phys = PN_TO_ADDR(ppn);
	err = prom_claim_phys(size, phys);
	CB_VPRINTF(("    text/data claim (0x%lx - 0x%lx) = %d\n",
	    ppn, ppn + mmu_btop(size) - 1, err));
	if (err)
		return (ERR);

	pdev = "/memory";
	mem_node = prom_finddevice(pdev);
	if (mem_node == OBP_BADNODE) {
		prom_printf("%s: cant find \"%s\" node\n", str, pdev);
		return (ERR);
	}
	mem_prop = "available";

	/*
	 * prop data is treated as a struct array;
	 * verify pabuf has enough room for the array
	 * in the original and converted forms
	 */
	len = prom_getproplen(mem_node, mem_prop);
	scnt = len / sizeof (*pap);
	need = len + (sizeof (*arp) * (scnt + 1));
	space = sizeof (pabuf);
	CB_VPRINTF(("    %s node 0x%x, len %d\n", pdev, mem_node, len));
	if (len == -1 || need > space) {
		prom_printf("\n%s: bad \"%s\" length %d, min %d, max %d\n",
		    str, mem_prop, len, need, space);
		return (ERR);
	}

	/*
	 * read-in prop data and clear trailing space
	 */
	glen = prom_getprop(mem_node, mem_prop, pabuf);
	if (glen != len) {
		prom_printf("\n%s: 0x%x,%s: expected len %d, got %d\n",
		    str, mem_node, mem_prop, len, glen);
		return (ERR);
	}
	bzero(&pabuf[len], space - len);

	/*
	 * convert the physavail list in place
	 * from (phys_base, phys_size) to (low_ppn, high_ppn)
	 */
	if (verbose)
		prom_printf("\nphysavail list:\n");
	cb_physavail = (arange_t *)pabuf;
	arp = cb_physavail + scnt - 1;
	pap = (pphav_t *)cb_physavail + scnt - 1;
	for (; scnt--; pap--, arp--) {
		pages = mmu_btop(pap->size);
		arp->low = ADDR_TO_PN(pap->base);
		arp->high = arp->low + pages - 1;
		if (verbose) {
			prom_printf("  %d: (0x%lx - 0x%lx),\tpages %ld\n",
			    (int)(arp - cb_physavail),
			    arp->low, arp->high, (arp->high - arp->low + 1));
		}
	}

	return (0);
}


/*
 * search for an available phys page,
 * copy the old phys page to the new one
 * and remap the virt page to the new phys
 */
static int
move_page(caddr_t vaddr, pfn_t oldppn)
{
	physaddr_t oldphys, newphys;
	pfn_t newppn;
	int err;

	newppn = find_apage();
	newphys = PN_TO_ADDR(newppn);
	oldphys = PN_TO_ADDR(oldppn);
	CB_VPRINTF(("    remap vaddr 0x%p, old 0x%lx/0x%llx,"
	    "	new 0x%lx/0x%llx\n",
	    (void *)vaddr, oldppn, oldphys, newppn, newphys));
	phys_xcopy(oldphys, newphys, MMU_PAGESIZE);
	err = prom_remap(MMU_PAGESIZE, vaddr, newphys);
	if (err)
		prom_printf("\nmove_page: remap error\n");
	return (err);
}


/*
 * physically relocate any text/data pages that clash
 * with the kernel; since we're already running on
 * a new stack, the original stack area is skipped
 */
int
cb_relocate(void)
{
	int is_ostk, is_clash, clash_cnt, ok_cnt;
	char *str, *desc, *skip_fmt;
	caddr_t ostk_low, ostk_high;
	caddr_t virt, saddr, eaddr;
	pfn_t ppn;

	str = "cb_relocate";
	CB_VPRINTF((ent_fmt, str, entry));

	ostk_low  = (caddr_t)&estack - CB_STACK_SIZE;
	ostk_high = (caddr_t)&estack - MMU_PAGESIZE;
	saddr = (caddr_t)_start;
	eaddr = (caddr_t)PAGE_ROUNDUP((uintptr_t)_end);

	install_remap();

	skip_fmt = "    skip  vaddr 0x%p, clash=%d, %s\n";
	clash_cnt = ok_cnt = 0;
	ppn = cpr_vatopfn(saddr);

	for (virt = saddr; virt < eaddr; virt += MMU_PAGESIZE, ppn++) {
		is_clash = (cb_bitop(ppn, CB_ISSET) != 0);
		if (is_clash)
			clash_cnt++;
		else
			ok_cnt++;

		is_ostk = (virt >= ostk_low && virt <= ostk_high);
		if (is_ostk)
			desc = "orig stack";
		else
			desc = "text/data";

		/*
		 * page logic:
		 *
		 * if (original stack page)
		 *	clash doesn't matter, just skip the page
		 * else (not original stack page)
		 * 	if (no clash)
		 *		setbit to avoid later alloc and overwrite
		 *	else (clash)
		 *		relocate phys page
		 */
		if (is_ostk) {
			CB_VPRINTF((skip_fmt, virt, is_clash, desc));
		} else if (is_clash == 0) {
			CB_VPRINTF((skip_fmt, virt, is_clash, desc));
			(void) cb_bitop(ppn, CB_SETBIT);
		} else if (move_page(virt, ppn))
			return (ERR);
	}
	CB_VPRINTF(("%s: total %d, clash %d, ok %d\n",
	    str, clash_cnt + ok_cnt, clash_cnt, ok_cnt));

	/*
	 * free original stack area for reuse
	 */
	ppn = cpr_vatopfn(ostk_low);
	prom_free_phys(CB_STACK_SIZE, PN_TO_ADDR(ppn));
	CB_VPRINTF(("%s: free old stack (0x%lx - 0x%lx)\n",
	    str, ppn, ppn + mmu_btop(CB_STACK_SIZE) - 1));

	return (0);
}

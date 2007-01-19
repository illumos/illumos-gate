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

#include <sys/types.h>
#include <sys/cpr.h>
#include <sys/ddi.h>
#include "cprboot.h"


/*
 * check if any cpd_t pages clash with the statefile buffer and shuffle
 * buf pages to free space; since kpages are saved in ascending order,
 * any buf pages preceding the current statefile buffer offset can be
 * written because those pages have already been read and restored
 */
static void
shuffle_pages(cpd_t *descp)
{
	pfn_t low_src_ppn, dst_ppn, tail_ppn, new_ppn;
	size_t dst_off;

	/*
	 * set the lowest source buf ppn for the (precede) comparison
	 * below; the ORIG macro is used for the case where the src buf
	 * page had already been moved - and would confuse the compare
	 */
	low_src_ppn = SF_ORIG_PPN(sfile.buf_offset);

	tail_ppn = descp->cpd_pfn + descp->cpd_pages;
	for (dst_ppn = descp->cpd_pfn; dst_ppn < tail_ppn; dst_ppn++) {
		/*
		 * if the dst page is outside the range of statefile
		 * buffer phys pages, it's OK to write that page;
		 * buf pages may have been moved outside the range,
		 * but only to locations isolated from any dst page
		 */
		if (dst_ppn < sfile.low_ppn || dst_ppn > sfile.high_ppn) {
			SF_STAT_INC(outside);
			continue;
		}

		/*
		 * the dst page is inside the range of buf ppns;
		 * dont need to move the buf page if the dst page
		 * precedes the lowest src buf page
		 */
		if (dst_ppn < low_src_ppn) {
			SF_STAT_INC(precede);
			continue;
		}

		/*
		 * the dst page clashes with the statefile buffer;
		 * move the buf page to a free location and update
		 * the buffer map
		 */
		new_ppn = find_apage();
		phys_xcopy(PN_TO_ADDR(dst_ppn), PN_TO_ADDR(new_ppn),
		    MMU_PAGESIZE);
		dst_off = mmu_ptob(dst_ppn - sfile.low_ppn);
		SF_BUF_PPN(dst_off) = new_ppn;
		SF_STAT_INC(move);
	}
}


/*
 * map-in source statefile buffer pages (read-only) at CB_SRC_VIRT;
 * sets the starting source vaddr with correct page offset
 */
static void
mapin_buf_pages(size_t datalen, caddr_t *srcp)
{
	int dtlb_index, pg_off;
	caddr_t vaddr, tail;
	size_t off, bytes;
	pfn_t src_ppn;

	dtlb_index = cb_dents - CB_MAX_KPAGES - 1;
	off = sfile.buf_offset;
	pg_off = off & MMU_PAGEOFFSET;
	bytes = PAGE_ROUNDUP(pg_off + datalen);
	vaddr = (caddr_t)CB_SRC_VIRT;
	*srcp = vaddr + pg_off;

	for (tail = vaddr + bytes; vaddr < tail; vaddr += MMU_PAGESIZE) {
		src_ppn = SF_BUF_PPN(off);
		cb_mapin(vaddr, src_ppn, TTE8K, 0, dtlb_index);
		dtlb_index--;
		off += MMU_PAGESIZE;
	}
}


/*
 * map-in destination kernel pages (read/write) at CB_DST_VIRT
 */
static void
mapin_dst_pages(cpd_t *descp)
{
	int dtlb_index, pages;
	caddr_t vaddr;
	pfn_t dst_ppn;

	dtlb_index = cb_dents - 1;
	vaddr = (caddr_t)CB_DST_VIRT;
	dst_ppn = descp->cpd_pfn;
	for (pages = 0; pages < descp->cpd_pages; pages++) {
		cb_mapin(vaddr, dst_ppn, TTE8K, TTE_HWWR_INT, dtlb_index);
		dtlb_index--;
		vaddr += MMU_PAGESIZE;
		dst_ppn++;
	}
}


/*
 * run a checksum on un/compressed data when flag is set
 */
static int
kdata_cksum(void *data, cpd_t *descp, uint_t flag)
{
	uint_t sum, expect;
	size_t len;

	if ((descp->cpd_flag & flag) == 0)
		return (0);
	else if (flag == CPD_CSUM) {
		expect = descp->cpd_csum;
		len = descp->cpd_length;
	} else {
		expect = descp->cpd_usum;
		len = mmu_ptob(descp->cpd_pages);
	}
	sum = checksum32(data, len);
	if (sum != expect) {
		prom_printf("\n%scompressed data checksum error, "
		    "expect 0x%x, got 0x%x\n", (flag == CPD_USUM) ? "un" : "",
		    expect, sum);
		return (ERR);
	}

	return (0);
}


/*
 * primary kpage restoration routine
 */
static int
restore_page_group(cpd_t *descp)
{
	caddr_t dst, datap;
	size_t size, len;
	caddr_t src;
	int raw;

#if defined(lint)
	(void) compress(0, 0, 0);
#endif

	/*
	 * move any source buf pages that clash with dst kernel pages;
	 * create tlb entries for the orig/new source buf pages and
	 * the dst kpages
	 */
	shuffle_pages(descp);
	mapin_buf_pages(descp->cpd_length, &src);
	mapin_dst_pages(descp);

	/*
	 * for compressed pages, run a checksum at the src vaddr and
	 * decompress to the mapped-in dst kpages; for uncompressed pages,
	 * just copy direct; uncompressed checksums are used for either
	 * uncompressed src data or decompressed result data
	 */
	dst = (caddr_t)CB_DST_VIRT;
	if (descp->cpd_flag & CPD_COMPRESS) {
		if (kdata_cksum(src, descp, CPD_CSUM))
			return (ERR);
		size = mmu_ptob(descp->cpd_pages);
		len = decompress(src, dst, descp->cpd_length, size);
		if (len != size) {
			prom_printf("\nbad decompressed len %lu, size %lu\n",
			    len, size);
			return (ERR);
		}
		raw = 0;
		datap = dst;
	} else {
		raw = 1;
		datap = src;
	}
	if (kdata_cksum(datap, descp, CPD_USUM))
		return (ERR);
	if (raw)
		bcopy(src, dst, descp->cpd_length);

	/*
	 * advance past the kdata for this cpd_t
	 */
	SF_ADV(descp->cpd_length);

	return (0);
}


/*
 * mapin part of the statefile buffer, copy to the virt destination,
 * and advance the statefile buffer offset.  this is used primarily
 * to copy thousands of tiny cpd_t into aligned struct space.
 */
static void
get_phys_data(void *vdst, size_t size)
{
	caddr_t src;

	mapin_buf_pages(size, &src);
	bcopy(src, vdst, size);
	SF_ADV(size);
}


/*
 * clear leftover locked dtlb entries
 */
static void
dtlb_cleanup(void)
{
	int dtlb_index;
	caddr_t vaddr;
	tte_t tte;

	CB_VENTRY(dtlb_cleanup);

	dtlb_index = cb_dents - CB_MAX_KPAGES - CB_MAX_BPAGES - 1;
	for (; dtlb_index < cb_dents; dtlb_index++) {
		get_dtlb_entry(dtlb_index, &vaddr, &tte);
		if (TTE_IS_LOCKED(&tte)) {
			tte.ll = 0;
			set_dtlb_entry(dtlb_index, (caddr_t)0, &tte);
			CB_VPRINTF(("    cleared dtlb entry %x\n", dtlb_index));
		}
	}
}


/*
 * before calling this routine, all cprboot phys pages
 * are isolated from kernel pages; now we can restore
 * kpages from the statefile buffer
 */
int
cb_restore_kpages(void)
{
	int npages, compressed, regular;
	cpd_t desc;
	char *str;

	str = "cb_restore_kpages";
	CB_VPRINTF((ent_fmt, str, entry));

	CPR_DEBUG(CPR_DEBUG1, "%s: restoring kpages... ", prog);
	npages = compressed = regular = 0;
	while (npages < sfile.kpages) {
		get_phys_data(&desc, sizeof (desc));
		if (desc.cpd_magic != CPR_PAGE_MAGIC) {
			prom_printf("\nbad page magic 0x%x, expect 0x%x\n",
			    desc.cpd_magic, CPR_PAGE_MAGIC);
			return (ERR);
		}
		if (restore_page_group(&desc))
			return (ERR);
		npages += desc.cpd_pages;

		if (desc.cpd_flag & CPD_COMPRESS)
			compressed += desc.cpd_pages;
		else
			regular += desc.cpd_pages;

		/*
		 * display a spin char for every 32 page groups
		 * (a full spin <= each MB restored)
		 */
		if ((sfile.ngroups++ & 0x1f) == 0)
			cb_spin();
	}
	CPR_DEBUG(CPR_DEBUG1, " \b\n");

	dtlb_cleanup();

	if (verbose) {
		prom_printf("\npage stats: total %d, outside %d, "
		    "move %d, precede %d\n", sfile.kpages, sfile.outside,
		    sfile.move, sfile.precede);
		prom_printf("page stats: ngroups %d, recycle %d\n",
		    sfile.ngroups, sfile.recycle);
	}

	CPR_DEBUG(CPR_DEBUG4,
	    "%s: total=%d, npages=%d, compressed=%d, regular=%d\n",
	    str, sfile.kpages, npages, compressed, regular);

	/*
	 * sanity check
	 */
	if (npages != sfile.kpages) {
		prom_printf("\n%s: page count mismatch, expect %d, got %d\n",
		    str, sfile.kpages, npages);
		return (ERR);
	}

	return (0);
}


/*
 * check and update the statefile terminator;
 * on exit there will be a leftover tlb entry,
 * but it will soon get replaced by restore_tlb()
 */
int
cb_terminator(void)
{
	ctrm_t cterm;

	CB_VENTRY(cb_terminator);
	get_phys_data(&cterm, sizeof (cterm));
	if (cterm.magic != CPR_TERM_MAGIC) {
		prom_printf("\nbad term magic 0x%x, expect 0x%x\n",
		    cterm.magic, CPR_TERM_MAGIC);
		return (ERR);
	}
	cterm.tm_cprboot_start.tv_sec = cb_msec / 1000;
	cb_mapin((caddr_t)CB_DST_VIRT, cterm.pfn,
	    TTE8K, TTE_HWWR_INT, cb_dents - 1);
	cpr_update_terminator(&cterm, (caddr_t)CB_DST_VIRT);
	return (0);
}

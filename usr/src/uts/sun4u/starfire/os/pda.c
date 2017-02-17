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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Starfire Post Descriptor Array (post2obp) management.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/vm.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/machsystm.h>
#include <sys/starfire.h>

#include <sys/cpu_sgnblk_defs.h>
#include <sys/pda.h>
#include <sys/cpu_sgn.h>

extern struct cpu	*SIGBCPU;
extern cpu_sgnblk_t	*cpu_sgnblkp[];

extern uint64_t		mc_get_mem_alignment();
extern uint64_t		mc_asr_to_pa(uint_t mcreg);

static post2obp_info_t	*cpu_p2o_mapin(int cpuid);
static void		cpu_p2o_mapout(int cpuid, post2obp_info_t *p2o);
static void		p2o_update_checksum(post2obp_info_t *p2o);
static uint_t		p2o_calc_checksum(post2obp_info_t *p2o);
static void		p2o_mem_sort(post2obp_info_t *p2o);
static void		p2o_mem_coalesce(post2obp_info_t *p2o);

typedef struct {
	post2obp_info_t	*p2o_ptr;
	int		p2o_cpuid;
} p2o_info_t;

/*
 * PDA management routines.  Should ultimately be made
 * accessible to other Starfire subsystems, but for
 * now we'll leave it here.
 */
pda_handle_t
pda_open()
{
	p2o_info_t	*pip;

	if (SIGBCPU == NULL) {
		cmn_err(CE_WARN, "pda_open: SIGBCPU is NULL");
		return (NULL);
	}

	pip = (p2o_info_t *)kmem_alloc(sizeof (p2o_info_t), KM_SLEEP);

	pip->p2o_cpuid = (int)SIGBCPU->cpu_id;
	pip->p2o_ptr = cpu_p2o_mapin(pip->p2o_cpuid);

	if (pip->p2o_ptr == NULL) {
		kmem_free((caddr_t)pip, sizeof (p2o_info_t));
		return ((pda_handle_t)NULL);
	} else {
		return ((pda_handle_t)pip);
	}
}

void
pda_close(pda_handle_t ph)
{
	p2o_info_t	*pip;

	if ((pip = (p2o_info_t *)ph) == NULL)
		return;

	cpu_p2o_mapout(pip->p2o_cpuid, pip->p2o_ptr);

	kmem_free((caddr_t)pip, sizeof (p2o_info_t));
}

int
pda_board_present(pda_handle_t ph, int boardnum)
{
	ushort_t	bda_board;
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;

	bda_board = p2o->p2o_bdinfo[boardnum].bda_board;

	if ((bda_board & BDAN_MASK) != BDAN_GOOD)
		return (0);
	else
		return (1);
}

void *
pda_get_board_info(pda_handle_t ph, int boardnum)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;

	return ((void *)&(p2o->p2o_bdinfo[boardnum]));
}

uint_t
pda_get_mem_size(pda_handle_t ph, int boardnum)
{
	int		c;
	pgcnt_t		npages;
	uint_t		asr;
	pfn_t		basepfn, endpfn;
	uint64_t	basepa, endpa;
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;

	if (boardnum == -1)
		return (p2o->p2o_memtotal.Memt_NumPages);

	asr = p2o->p2o_bdminfo[boardnum].bmda_adr;

	basepa = mc_asr_to_pa(asr);
	/*
	 * Put on MC alignment.
	 */
	endpa = mc_get_mem_alignment();
	basepa &= ~(endpa - 1);
	endpa += basepa;
	basepfn = (pfn_t)(basepa >> PAGESHIFT);
	endpfn = (pfn_t)(endpa >> PAGESHIFT);

	npages = 0;

	for (c = 0; c < p2o->p2o_memtotal.Memt_NumChunks; c++) {
		pfn_t	c_basepfn, c_endpfn;

		c_basepfn = (pfn_t)p2o->p2o_mchunks[c].Memc_StartAddress
		    >> (PAGESHIFT - BDA_PAGESHIFT);
		c_endpfn = (pfn_t)p2o->p2o_mchunks[c].Memc_Size
		    >> (PAGESHIFT - BDA_PAGESHIFT);
		c_endpfn += c_basepfn;

		if ((endpfn <= c_basepfn) || (basepfn >= c_endpfn))
			continue;

		c_basepfn = MAX(c_basepfn, basepfn);
		c_endpfn = MIN(c_endpfn, endpfn);
		ASSERT(c_basepfn <= c_endpfn);

		npages += c_endpfn - c_basepfn;
	}

	return (npages);
}

void
pda_mem_add_span(pda_handle_t ph, uint64_t basepa, uint64_t nbytes)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;
	int		c, nchunks;
	pfn_t		a_pfn, a_npgs;

	ASSERT(p2o);

	nchunks = p2o->p2o_memtotal.Memt_NumChunks;
	a_pfn = (pfn_t)(basepa >> BDA_PAGESHIFT);
	a_npgs = (pfn_t)(nbytes >> BDA_PAGESHIFT);

	for (c = 0; c < nchunks; c++) {
		int	cend;

		if (a_pfn <= p2o->p2o_mchunks[c].Memc_StartAddress) {
			for (cend = nchunks; cend > c; cend--)
				p2o->p2o_mchunks[cend] =
						p2o->p2o_mchunks[cend - 1];
			break;
		}
	}
	p2o->p2o_mchunks[c].Memc_StartAddress = a_pfn;
	p2o->p2o_mchunks[c].Memc_Size = a_npgs;
	nchunks++;

	p2o->p2o_memtotal.Memt_NumChunks = nchunks;
	p2o->p2o_memtotal.Memt_NumPages += a_npgs;

	p2o_mem_sort(p2o);
	p2o_mem_coalesce(p2o);
	p2o_update_checksum(p2o);
}

void
pda_mem_del_span(pda_handle_t ph, uint64_t basepa, uint64_t nbytes)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;
	int		c, o_nchunks, n_nchunks;
	pfn_t		d_pfn;
	pgcnt_t		d_npgs, npages;
	MemChunk_t	*mp, *endp;

	ASSERT(p2o);

	d_pfn = (pfn_t)(basepa >> BDA_PAGESHIFT);
	d_npgs = (pgcnt_t)(nbytes >> BDA_PAGESHIFT);
	n_nchunks = o_nchunks = p2o->p2o_memtotal.Memt_NumChunks;
	endp = &(p2o->p2o_mchunks[o_nchunks]);
	npages = 0;

	for (c = 0; c < o_nchunks; c++) {
		uint_t	p_pfn, p_npgs;

		p_pfn = p2o->p2o_mchunks[c].Memc_StartAddress;
		p_npgs = p2o->p2o_mchunks[c].Memc_Size;
		if (p_npgs == 0)
			continue;

		if (((d_pfn + d_npgs) <= p_pfn) ||
					(d_pfn >= (p_pfn + p_npgs))) {
			npages += p_npgs;
			continue;
		}

		if (d_pfn < p_pfn) {
			if ((d_pfn + d_npgs) >= (p_pfn + p_npgs)) {
				/*
				 * Entire chunk goes away.
				 */
				p_pfn = p_npgs = 0;
			} else {
				p_npgs -= d_pfn + d_npgs - p_pfn;
				p_pfn = d_pfn + d_npgs;
			}
		} else if (d_pfn == p_pfn) {
			if ((d_pfn + d_npgs) >= (p_pfn + p_npgs)) {
				p_pfn = p_npgs = 0;
			} else {
				p_npgs -= d_npgs;
				p_pfn += d_npgs;
			}
		} else {
			if ((d_pfn + d_npgs) >= (p_pfn + p_npgs)) {
				p_npgs = d_pfn - p_pfn;
				npages += p_npgs;
			} else {
				/*
				 * Ugh, got to split a
				 * memchunk, we're going to
				 * need an extra one.  It's
				 * gotten from the end.
				 */
				endp->Memc_StartAddress = d_pfn + d_npgs;
				endp->Memc_Size = (p_pfn + p_npgs)
							- (d_pfn + d_npgs);
				npages += endp->Memc_Size;
				endp++;
				n_nchunks++;
				p_npgs = d_pfn - p_pfn;
			}
		}

		p2o->p2o_mchunks[c].Memc_StartAddress = p_pfn;
		p2o->p2o_mchunks[c].Memc_Size = p_npgs;
		if (p_npgs == 0)
			n_nchunks--;
		npages += p_npgs;
	}
	p2o->p2o_memtotal.Memt_NumChunks = n_nchunks;
	p2o->p2o_memtotal.Memt_NumPages = npages;

	/*
	 * There is a possibility we created holes in the memchunk list
	 * due to memchunks that went away.  Before we can sort and
	 * coalesce we need to "pull up" the end of the memchunk list
	 * and get rid of any holes.
	 * endp = points to the last empty memchunk entry.
	 */
	for (mp = &(p2o->p2o_mchunks[0]); mp < endp; mp++) {
		register MemChunk_t	*mmp;

		if (mp->Memc_Size)
			continue;

		for (mmp = mp; mmp < endp; mmp++)
			*mmp = *(mmp + 1);
		mp--;
		endp--;
	}
	ASSERT(endp == &(p2o->p2o_mchunks[n_nchunks]));

	p2o_mem_sort(p2o);
	p2o_mem_coalesce(p2o);
	p2o_update_checksum(p2o);
}

/*
 * Synchonize all memory attributes (currently just MC ADRs [aka ASR])
 * with PDA representative values for the given board.  A board value
 * of (-1) indicates all boards.
 */
/*ARGSUSED*/
void
pda_mem_sync(pda_handle_t ph, int board, int unit)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;
	register int	b;

	for (b = 0; b < MAX_SYSBDS; b++) {
		if ((board != -1) && (board != b))
			continue;

		if (pda_board_present(ph, b)) {
			uint64_t	masr;
			uint_t		masr_value;

			masr = STARFIRE_MC_ASR_ADDR_BOARD(b);
			masr_value = ldphysio(masr);

			p2o->p2o_bdminfo[b].bmda_adr = masr_value;
		}

		if (board == b)
			break;
	}

	p2o_update_checksum(p2o);
}

void
pda_get_busmask(pda_handle_t ph, short *amask, short *dmask)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;

	if (amask)
		*amask = p2o ? p2o->p2o_abus_mask : 0;

	if (dmask)
		*dmask = p2o ? p2o->p2o_dbus_mask : 0;
}

int
pda_is_valid(pda_handle_t ph)
{
	post2obp_info_t	*p2o = ((p2o_info_t *)ph)->p2o_ptr;
	uint_t		csum;

	if (p2o == NULL)
		return (0);

	csum = p2o_calc_checksum(p2o);

	return (csum == p2o->p2o_csum);
}

/*
 * Post2obp support functions below here.  Internal to PDA module.
 *
 * p2o_update_checksum
 *
 * Calculate checksum for post2obp structure and insert it so
 * when POST reads it it'll be happy.
 */
static void
p2o_update_checksum(post2obp_info_t *p2o)
{
	uint_t	new_csum;

	ASSERT(p2o);

	new_csum = p2o_calc_checksum(p2o);
	p2o->p2o_csum = new_csum;
}

static uint_t
p2o_calc_checksum(post2obp_info_t *p2o)
{
	int	i, nchunks;
	uint_t	*csumptr;
	uint_t	p2o_size;
	uint_t	csum, o_csum;

	ASSERT(p2o != NULL);

	nchunks = p2o->p2o_memtotal.Memt_NumChunks;
	p2o_size = sizeof (post2obp_info_t)
		    + ((nchunks - VAR_ARRAY_LEN) * sizeof (MemChunk_t));
	p2o_size /= sizeof (uint_t);

	o_csum = p2o->p2o_csum;
	p2o->p2o_csum = 0;
	csum = 0;
	for (i = 0, csumptr = (uint_t *)p2o; i < p2o_size; i++)
		csum += *csumptr++;
	p2o->p2o_csum = o_csum;

	return (-csum);
}

/*
 * Sort the mchunk list in ascending order based on the
 * Memc_StartAddress field.
 *
 * disclosure: This is based on the qsort() library routine.
 */
static void
p2o_mem_sort(post2obp_info_t *p2o)
{
	MemChunk_t	*base;
	int		nchunks;
	uint_t		c1, c2;
	char		*min, *max;
	register char 	c, *i, *j, *lo, *hi;

	ASSERT(p2o != NULL);

	nchunks = p2o->p2o_memtotal.Memt_NumChunks;
	base = &p2o->p2o_mchunks[0];

	/* ala qsort() */
	max = (char *)base + nchunks * sizeof (MemChunk_t);
	hi  = max;
	for (j = lo = (char *)base; (lo += sizeof (MemChunk_t)) < hi; ) {
		c1 = ((MemChunk_t *)j)->Memc_StartAddress;
		c2 = ((MemChunk_t *)lo)->Memc_StartAddress;
		if (c1 > c2)
			j = lo;
	}
	if (j != (char *)base) {
		for (i = (char *)base,
		    hi = (char *)base + sizeof (MemChunk_t);
		    /* CSTYLED */
		    i < hi;) {
			c = *j;
			*j++ = *i;
			*i++ = c;
		}
	}
	for (min = (char *)base;
	    /* CSTYLED */
	    (hi = min += sizeof (MemChunk_t)) < max;) {
		do {
			hi -= sizeof (MemChunk_t);
			c1 = ((MemChunk_t *)hi)->Memc_StartAddress;
			c2 = ((MemChunk_t *)min)->Memc_StartAddress;
		} while (c1 > c2);
		if ((hi += sizeof (MemChunk_t)) != min) {
			for (lo = min + sizeof (MemChunk_t);
			    /* CSTYLED */
			    --lo >= min;) {
				c = *lo;
				for (i = j = lo;
				    (j -= sizeof (MemChunk_t)) >= hi;
				    i = j) {
					*i = *j;
				}
				*i = c;
			}
		}
	}
}

static void
p2o_mem_coalesce(post2obp_info_t *p2o)
{
	MemChunk_t	*mc;
	int		nchunks, new_nchunks;
	uint_t		addr, size, naddr, nsize;
	uint_t		npages;
	register int	i, cp, ncp;

	ASSERT(p2o != NULL);

	nchunks = new_nchunks = p2o->p2o_memtotal.Memt_NumChunks;
	mc = &p2o->p2o_mchunks[0];

	for (cp = i = 0; i < (nchunks-1); i++, cp = ncp) {
		ncp = cp + 1;
		addr = mc[cp].Memc_StartAddress;
		size = mc[cp].Memc_Size;
		naddr = mc[ncp].Memc_StartAddress;
		nsize = mc[ncp].Memc_Size;

		if ((addr + size) >= naddr) {
			uint_t	overlap;

			overlap = addr + size - naddr;
			/*
			 * if (nsize < overlap) then
			 * next entry fits within the current
			 * entry so no need to update size.
			 */
			if (nsize >= overlap) {
				size += nsize - overlap;
				mc[cp].Memc_Size = size;
			}
			bcopy((char *)&mc[ncp+1],
			    (char *)&mc[ncp],
			    (nchunks - ncp - 1) * sizeof (MemChunk_t));
			ncp = cp;
			new_nchunks--;
		}
	}

	npages = 0;
	for (i = 0; i < new_nchunks; i++)
		npages += p2o->p2o_mchunks[i].Memc_Size;

	p2o->p2o_memtotal.Memt_NumChunks = new_nchunks;
	p2o->p2o_memtotal.Memt_NumPages = npages;
}

/*
 * Mapin the the cpu's post2obp structure.
 */
static post2obp_info_t *
cpu_p2o_mapin(int cpuid)
{
	uint64_t	cpu_p2o_physaddr;
	uint32_t	cpu_p2o_offset;
	caddr_t		cvaddr;
	uint_t		num_pages;
	pfn_t		pfn;

	ASSERT(cpu_sgnblkp[cpuid] != NULL);
	/*
	 * Construct the physical base address of the bbsram
	 * in PSI space associated with this cpu in question.
	 */
	cpu_p2o_offset = (uint32_t)cpu_sgnblkp[cpuid]->sigb_postconfig;
	if (cpu_p2o_offset == 0) {
		cmn_err(CE_WARN,
			"cpu_p2o_mapin:%d: sigb_postconfig == NULL\n",
			cpuid);
		return (NULL);
	}
	cpu_p2o_physaddr = (STARFIRE_UPAID2UPS(cpuid) | STARFIRE_PSI_BASE) +
				(uint64_t)cpu_p2o_offset;
	cpu_p2o_offset = (uint32_t)(cpu_p2o_physaddr & MMU_PAGEOFFSET);
	cpu_p2o_physaddr -= (uint64_t)cpu_p2o_offset;

	/*
	 * cpu_p2o_physaddr = Beginning of page containing p2o.
	 * cpu_p2o_offset   = Offset within page where p2o starts.
	 */

	pfn = (pfn_t)(cpu_p2o_physaddr >> MMU_PAGESHIFT);

	num_pages = mmu_btopr(cpu_p2o_offset + sizeof (post2obp_info_t));

	/*
	 * Map in the post2obp structure.
	 */
	cvaddr = vmem_alloc(heap_arena, ptob(num_pages), VM_SLEEP);

	hat_devload(kas.a_hat, cvaddr, ptob(num_pages),
	    pfn, PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);

	return ((post2obp_info_t *)(cvaddr + (ulong_t)cpu_p2o_offset));
}

static void
cpu_p2o_mapout(int cpuid, post2obp_info_t *p2o)
{
	ulong_t		cvaddr, num_pages;
	uint32_t	cpu_p2o_offset;

	ASSERT(cpu_sgnblkp[cpuid] != NULL);

	cpu_p2o_offset = (uint32_t)cpu_sgnblkp[cpuid]->sigb_postconfig;
	if (cpu_p2o_offset == 0) {
		cmn_err(CE_WARN,
			"cpu_p2o_mapout:%d: sigb_postconfig == NULL\n",
			cpuid);
		return;
	}

	cpu_p2o_offset = (uint32_t)(((STARFIRE_UPAID2UPS(cpuid) |
					STARFIRE_PSI_BASE) +
					(uint64_t)cpu_p2o_offset) &
					MMU_PAGEOFFSET);

	num_pages = mmu_btopr(cpu_p2o_offset + sizeof (post2obp_info_t));

	cvaddr = (ulong_t)p2o - cpu_p2o_offset;
	if (cvaddr & MMU_PAGEOFFSET) {
		cmn_err(CE_WARN,
			"cpu_p2o_mapout:%d: cvaddr (0x%x) not on page "
			"boundary\n",
			cpuid, (uint_t)cvaddr);
		return;
	}

	hat_unload(kas.a_hat, (caddr_t)cvaddr, ptob(num_pages),
	    HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, (caddr_t)cvaddr, ptob(num_pages));
}

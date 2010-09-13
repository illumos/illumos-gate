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
 * Starfire Memory Controller specific routines.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/machsystm.h>

#include <sys/starfire.h>

struct mc_dimm_table {
	int	mc_type;
	int	mc_module_size;		/* module size in MB */
};

static struct mc_dimm_table dimmsize_table[] = {
	{ 4,	8 },
	{ 6,	8 },
	{ 11,	32 },
	{ 15,	128 },
	{ 0,	0 }
};

#define	MC_MB(mb) ((mb) * 1048576ull)

struct mc_seg_size {
	uint_t		seg_mask;
	uint64_t	seg_size;
};

struct mc_seg_size mc_seg_table[] = {
	{ 0x7f,	MC_MB(64)	},
	{ 0x7e,	MC_MB(128)	},
	{ 0x7c,	MC_MB(256)	},
	{ 0x78,	MC_MB(512)	},
	{ 0x70,	MC_MB(1024)	},
	{ 0x60,	MC_MB(2048)	},
	{ 0x40,	MC_MB(4096)	},
	{ 0,	0		}
};

/*
 * Alignment of memory between MC's.
 */
uint64_t
mc_get_mem_alignment()
{
	return (STARFIRE_MC_MEMBOARD_ALIGNMENT);
}

uint64_t
mc_get_asr_addr(pnode_t nodeid)
{
	int		rlen;
	uint64_t	psi_addr;
	struct sf_memunit_regspec	reg;

	rlen = prom_getproplen(nodeid, "reg");
	if (rlen != sizeof (struct sf_memunit_regspec))
		return ((uint64_t)-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return ((uint64_t)-1);

	psi_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	psi_addr |= (uint64_t)reg.regspec_addr_lo;

	return (STARFIRE_MC_ASR_ADDR(psi_addr));
}

uint64_t
mc_get_idle_addr(pnode_t nodeid)
{
	int		rlen;
	uint64_t	psi_addr;
	struct sf_memunit_regspec	reg;

	rlen = prom_getproplen(nodeid, "reg");
	if (rlen != sizeof (struct sf_memunit_regspec))
		return ((uint64_t)-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return ((uint64_t)-1);

	psi_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	psi_addr |= (uint64_t)reg.regspec_addr_lo;

	return (STARFIRE_MC_IDLE_ADDR(psi_addr));
}

int
mc_get_dimm_size(pnode_t nodeid)
{
	uint64_t	psi_addr;
	uint_t		dimmtype;
	int		i, rlen;
	struct sf_memunit_regspec	reg;

	rlen = prom_getproplen(nodeid, "reg");
	if (rlen != sizeof (struct sf_memunit_regspec))
		return (-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return (-1);

	psi_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	psi_addr |= (uint64_t)reg.regspec_addr_lo;
	psi_addr = STARFIRE_MC_DIMMTYPE_ADDR(psi_addr);

	if (psi_addr == (uint64_t)-1)
		return (-1);

	dimmtype = ldphysio(psi_addr);
	dimmtype &= STARFIRE_MC_DIMMSIZE_MASK;

	for (i = 0; dimmsize_table[i].mc_type != 0; i++)
		if (dimmsize_table[i].mc_type == dimmtype)
			break;

	return (dimmsize_table[i].mc_module_size);
}

uint64_t
mc_get_alignment_mask(pnode_t nodeid)
{
	uint64_t	psi_addr, seg_sz;
	uint_t		mcreg, seg_sz_mask;
	int		i, rlen;
	struct sf_memunit_regspec	reg;

	rlen = prom_getproplen(nodeid, "reg");
	if (rlen != sizeof (struct sf_memunit_regspec))
		return (-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return (-1);

	psi_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	psi_addr |= (uint64_t)reg.regspec_addr_lo;
	psi_addr = STARFIRE_MC_ASR_ADDR(psi_addr);

	if (psi_addr == (uint64_t)-1)
		return (-1);

	mcreg = ldphysio(psi_addr);
	seg_sz_mask = (mcreg & STARFIRE_MC_MASK_MASK) >> 8;

	for (i = 0; mc_seg_table[i].seg_size != 0; i++)
		if (mc_seg_table[i].seg_mask == seg_sz_mask)
			break;

	if (mc_seg_table[i].seg_size == 0)
		seg_sz = mc_get_mem_alignment();
	else
		seg_sz = mc_seg_table[i].seg_size;

#ifdef DEBUG
	printf("nodeid %x, mc asr addr %lx, val %x, seg_sz_mask %x, "
	    "seg_sz %lx\n", nodeid, psi_addr, mcreg, seg_sz_mask, seg_sz);
#endif /* DEBUG */

	return (seg_sz - 1);
}

int
mc_read_asr(pnode_t nodeid, uint_t *mcregp)
{
	uint64_t	psi_addr;

	*mcregp = 0;

	psi_addr = mc_get_asr_addr(nodeid);
	if (psi_addr == (uint64_t)-1)
		return (-1);

	*mcregp = ldphysio(psi_addr);

	return (0);
}

int
mc_write_asr(pnode_t nodeid, uint_t mcreg)
{
	uint_t		mcreg_rd;
	uint64_t	psi_addr;

	psi_addr = mc_get_asr_addr(nodeid);
	if (psi_addr == (uint64_t)-1)
		return (-1);

	stphysio(psi_addr, mcreg);

	mcreg_rd = ldphysio(psi_addr);
	ASSERT(mcreg_rd == mcreg);

	return ((mcreg_rd != mcreg) ? -1 : 0);
}

uint64_t
mc_asr_to_pa(uint_t mcreg)
{
	uint64_t	pa, masr, addrmask, lowbitmask;

	/*
	 * Remove memory present bit.
	 */
	masr = (uint64_t)(mcreg & ~STARFIRE_MC_MEM_PRESENT_MASK);
	/*
	 * Get mask for bits 32-26.
	 */
	lowbitmask = masr & (uint64_t)STARFIRE_MC_MASK_MASK;
	lowbitmask <<= STARFIRE_MC_MASK_SHIFT;
	addrmask = STARFIRE_MC_ADDR_HIBITS | lowbitmask;

	pa = (masr << STARFIRE_MC_BASE_SHIFT) & addrmask;

	return (pa);
}

uint_t
mc_pa_to_asr(uint_t masr, uint64_t pa)
{
	uint64_t	addrmask, lowbitmask;
	uint_t		base;

	/*
	 * Get mask for bits 32-26.
	 */
	lowbitmask = masr & (uint64_t)STARFIRE_MC_MASK_MASK;
	lowbitmask <<= STARFIRE_MC_MASK_SHIFT;
	addrmask = STARFIRE_MC_ADDR_HIBITS | lowbitmask;

	base  = (pa & addrmask) >> STARFIRE_MC_BASE_SHIFT;
	masr &= ~ STARFIRE_MC_MEM_BASEADDR_MASK;
	masr |= base & STARFIRE_MC_MEM_BASEADDR_MASK;

	ASSERT(mc_asr_to_pa(masr) == pa);

	return (masr);
}

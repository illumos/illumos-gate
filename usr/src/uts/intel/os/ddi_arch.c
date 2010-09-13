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
 * This file contains ddi functions common to intel architectures
 */

#include <sys/archsystm.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/cpu.h>

/*
 * DDI Mapping
 */

/*
 * i_ddi_bus_map:
 * Generic bus_map entry point, for byte addressable devices
 * conforming to the reg/range addressing model with no HAT layer
 * to be programmed at this level.
 */

int
i_ddi_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	struct regspec tmp_reg, *rp;
	ddi_map_req_t mr = *mp;		/* Get private copy of request */
	int error;

	mp = &mr;

	/*
	 * First, if given an rnumber, convert it to a regspec...
	 */

	if (mp->map_type == DDI_MT_RNUMBER)  {

		int rnumber = mp->map_obj.rnumber;
#ifdef	DDI_MAP_DEBUG
		static char *out_of_range =
		    "i_ddi_bus_map: Out of range rnumber <%d>, device <%s>";
#endif	/* DDI_MAP_DEBUG */

		rp = i_ddi_rnumber_to_regspec(rdip, rnumber);
		if (rp == (struct regspec *)0)  {
#ifdef	DDI_MAP_DEBUG
			cmn_err(CE_WARN, out_of_range, rnumber,
			    ddi_get_name(rdip));
#endif	/* DDI_MAP_DEBUG */
			return (DDI_ME_RNUMBER_RANGE);
		}

		/*
		 * Convert the given ddi_map_req_t from rnumber to regspec...
		 */

		mp->map_type = DDI_MT_REGSPEC;
		mp->map_obj.rp = rp;
	}

	/*
	 * Adjust offset and length correspnding to called values...
	 * XXX: A non-zero length means override the one in the regspec.
	 * XXX: (Regardless of what's in the parent's range)
	 */

	tmp_reg = *(mp->map_obj.rp);		/* Preserve underlying data */
	rp = mp->map_obj.rp = &tmp_reg;		/* Use tmp_reg in request */

#ifdef	DDI_MAP_DEBUG
	cmn_err(CE_CONT,
	    "i_ddi_bus_map: <%s,%s> <0x%x, 0x%x, 0x%d> "
	    "offset %d len %d handle 0x%x\n",
	    ddi_get_name(dip), ddi_get_name(rdip),
	    rp->regspec_bustype, rp->regspec_addr, rp->regspec_size,
	    offset, len, mp->map_handlep);
#endif	/* DDI_MAP_DEBUG */

	/*
	 * I/O or memory mapping
	 *
	 *	<bustype=0, addr=x, len=x>: memory
	 *	<bustype=1, addr=x, len=x>: i/o
	 *	<bustype>1, addr=0, len=x>: x86-compatibility i/o
	 */

	if (rp->regspec_bustype > 1 && rp->regspec_addr != 0) {
		cmn_err(CE_WARN, "<%s,%s>: invalid register spec"
		    " <0x%x, 0x%x, 0x%x>\n", ddi_get_name(dip),
		    ddi_get_name(rdip), rp->regspec_bustype,
		    rp->regspec_addr, rp->regspec_size);
		return (DDI_ME_INVAL);
	}

	if (rp->regspec_bustype > 1 && rp->regspec_addr == 0) {
		/*
		 * compatibility i/o mapping
		 */
		rp->regspec_bustype += (uint_t)offset;
	} else {
		/*
		 * Normal memory or i/o mapping
		 */
		rp->regspec_addr += (uint_t)offset;
	}

	if (len != 0)
		rp->regspec_size = (uint_t)len;

#ifdef	DDI_MAP_DEBUG
	cmn_err(CE_CONT,
	    "               <%s,%s> <0x%x, 0x%x, 0x%d> "
	    "offset %d len %d\n",
	    ddi_get_name(dip), ddi_get_name(rdip),
	    rp->regspec_bustype, rp->regspec_addr, rp->regspec_size,
	    offset, len);
#endif	/* DDI_MAP_DEBUG */

	/*
	 * If we had an MMU, this is where you'd program the MMU and hat layer.
	 * Since we're using the default function here, we do not have an MMU
	 * to program.
	 */

	/*
	 * Apply any parent ranges at this level, if applicable.
	 * (This is where nexus specific regspec translation takes place.
	 * Use of this function is implicit agreement that translation is
	 * provided via ddi_apply_range.)  Note that we assume that
	 * the request is within the parents limits.
	 */

#ifdef	DDI_MAP_DEBUG
	ddi_map_debug("applying range of parent <%s> to child <%s>...\n",
	    ddi_get_name(dip), ddi_get_name(rdip));
#endif	/* DDI_MAP_DEBUG */

	if ((error = i_ddi_apply_range(dip, rdip, mp->map_obj.rp)) != 0)
		return (error);

	/*
	 * Call my parents bus_map function with modified values...
	 */

	return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));
}

/*
 * Creating register mappings and handling interrupts:
 */

struct regspec *
i_ddi_rnumber_to_regspec(dev_info_t *dip, int rnumber)
{
	if (rnumber >= sparc_pd_getnreg(DEVI(dip)))
		return ((struct regspec *)0);

	return (sparc_pd_getreg(DEVI(dip), rnumber));
}

/*
 * Static function to determine if a reg prop is enclosed within
 * a given a range spec.  (For readability: only used by i_ddi_aply_range.).
 */
static int
reg_is_enclosed_in_range(struct regspec *rp, struct rangespec *rangep)
{
	if (rp->regspec_bustype != rangep->rng_cbustype)
		return (0);

	if (rp->regspec_addr < rangep->rng_coffset)
		return (0);

	if (rangep->rng_size == 0)
		return (1);	/* size is really 2**(bits_per_word) */

	if ((rp->regspec_addr + rp->regspec_size - 1) <=
	    (rangep->rng_coffset + rangep->rng_size - 1))
		return (1);

	return (0);
}

/*
 * i_ddi_apply_range:
 * Apply range of dp to struct regspec *rp, if applicable.
 * If there's any range defined, it gets applied.
 */

int
i_ddi_apply_range(dev_info_t *dp, dev_info_t *rdip, struct regspec *rp)
{
	int nrange, b;
	struct rangespec *rangep;
	static char *out_of_range =
	    "Out of range register specification from device node <%s>\n";

	nrange = sparc_pd_getnrng(dp);
	if (nrange == 0)  {
#ifdef	DDI_MAP_DEBUG
		ddi_map_debug("    No range.\n");
#endif	/* DDI_MAP_DEBUG */
		return (0);
	}

	/*
	 * Find a match, making sure the regspec is within the range
	 * of the parent, noting that a size of zero in a range spec
	 * really means a size of 2**(bitsperword).
	 */

	for (b = 0, rangep = sparc_pd_getrng(dp, 0); b < nrange; ++b, ++rangep)
		if (reg_is_enclosed_in_range(rp, rangep))
			break;		/* found a match */

	if (b == nrange)  {
		cmn_err(CE_WARN, out_of_range, ddi_get_name(rdip));
		return (DDI_ME_REGSPEC_RANGE);
	}

#ifdef	DDI_MAP_DEBUG
	ddi_map_debug("    Input:  %x.%x.%x\n", rp->regspec_bustype,
	    rp->regspec_addr, rp->regspec_size);
	ddi_map_debug("    Range:  %x.%x %x.%x %x\n",
	    rangep->rng_cbustype, rangep->rng_coffset,
	    rangep->rng_bustype, rangep->rng_offset, rangep->rng_size);
#endif	/* DDI_MAP_DEBUG */

	rp->regspec_bustype = rangep->rng_bustype;
	rp->regspec_addr += rangep->rng_offset - rangep->rng_coffset;

#ifdef	DDI_MAP_DEBUG
	ddi_map_debug("    Return: %x.%x.%x\n", rp->regspec_bustype,
	    rp->regspec_addr, rp->regspec_size);
#endif	/* DDI_MAP_DEBUG */

	return (0);
}

/*
 * i_ddi_map_fault: wrapper for bus_map_fault.
 */
int
i_ddi_map_fault(dev_info_t *dip, dev_info_t *rdip,
	struct hat *hat, struct seg *seg, caddr_t addr,
	struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock)
{
	dev_info_t *pdip;

	if (dip == NULL)
		return (DDI_FAILURE);

	pdip = (dev_info_t *)DEVI(dip)->devi_bus_map_fault;

	/* request appropriate parent to map fault */
	return ((*(DEVI(pdip)->devi_ops->devo_bus_ops->bus_map_fault))(pdip,
	    rdip, hat, seg, addr, dp, pfn, prot, lock));
}

/*
 * Return an integer in native machine format from an OBP 1275 integer
 * representation, which is big-endian, with no particular alignment
 * guarantees.  intp points to the OBP data, and n the number of bytes.
 *
 * Byte-swapping is needed on intel.
 */
int
impl_ddi_prop_int_from_prom(uchar_t *intp, int n)
{
	int	i = 0;

	ASSERT(n > 0 && n <= 4);

	intp += n;
	while (n-- > 0) {
		i = (i << 8) | *(--intp);
	}

	return (i);
}


int drv_usec_coarse_timing = 0;

/*
 * Time delay function called by drivers
 */
void
drv_usecwait(clock_t count)
{
	int tens = 0;
	extern int gethrtime_hires;

	if (gethrtime_hires) {
		hrtime_t start, end;
		hrtime_t waittime;

		if (drv_usec_coarse_timing) {
			/* revert to the wait time as before using tsc */
			/* in case there are callers depending on the */
			/* old behaviour */
			waittime = ((count > 10) ?
			    (((hrtime_t)count / 10) + 1) : 1) *
			    10 * (NANOSEC / MICROSEC);
		} else  {
			waittime = (hrtime_t)count * (NANOSEC / MICROSEC);
		}
		start = end =  gethrtime();
		while ((end - start) < waittime) {
			SMT_PAUSE();
			end = gethrtime();
		}
		return;

	}

	if (count > 10)
		tens = count/10;
	tens++;			/* roundup; wait at least 10 microseconds */
	while (tens > 0) {
		tenmicrosec();
		tens--;
	}
}

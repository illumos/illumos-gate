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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Given a unum including an offset calculate the associated system
 * address.  This may be different to when the original PA to unum
 * calculation took place if interleave etc has changed.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mc.h>

#include <mcamd_api.h>
#include <mcamd_err.h>

/*
 * The submitted unum must have the MC and DIMM numbers and an offset.
 * Any cs info it has will not be used - we will reconstruct cs info.
 * This is because cs is not in the topology used for diagnosis.
 */
int
mcamd_unumtopa(struct mcamd_hdl *hdl, mcamd_node_t *root, mc_unum_t *unump,
    uint64_t *pa)
{
	mcamd_node_t *mc, *dimm;
	uint64_t num, holesz;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa: chip %d "
	    "mc %d dimm %d offset 0x%llx\n", unump->unum_chip, unump->unum_mc,
	    unump->unum_dimms[0], unump->unum_offset);

	if (!MCAMD_RC_OFFSET_VALID(unump->unum_offset)) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa: offset "
		    "invalid\n");
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	/*
	 * Search current config for a MC number matching the chip in the
	 * unum.
	 */
	for (mc = mcamd_mc_next(hdl, root, NULL); mc != NULL;
	    mc = mcamd_mc_next(hdl, root, mc)) {
		if (!mcamd_get_numprops(hdl,
		    mc, MCAMD_PROP_NUM, &num,
		    mc, MCAMD_PROP_DRAMHOLE_SIZE, &holesz,
		    NULL)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mcamd_unumtopa: "
			    "failed to lookup num, dramhole for MC 0x%p\n", mc);
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}
		if (num == unump->unum_chip)
			break;
	}
	if (mc == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa; "
		    "no match for MC %d\n", unump->unum_chip);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	/*
	 * Search DIMMs of this MC.  We can match against the
	 * first dimm in the unum - if there is more than one they all
	 * share the same chip-selects anyway and the pa we will resolve
	 * to is not finer grained than the 128-bits of a dimm pair.
	 */
	for (dimm = mcamd_dimm_next(hdl, mc, NULL); dimm != NULL;
	    dimm = mcamd_dimm_next(hdl, mc, dimm)) {
		if (!mcamd_get_numprop(hdl, dimm, MCAMD_PROP_NUM, &num)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mcamd_unumtopa: "
			    "failed to lookup num for dimm 0xx%p\n",
			    dimm);
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}
		if (num == unump->unum_dimms[0])
			break;
	}
	if (dimm == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa; "
		    "no match for dimm %d cs %d on MC %d\n",
		    unump->unum_dimms[0], unump->unum_cs, unump->unum_chip);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa: matched "
	    "mc 0x%p dimm 0x%p; resolving offset 0x%llx\n",
	    mc, dimm, unump->unum_offset);

	if (mc_offset_to_pa(hdl, mc, dimm, unump->unum_offset, pa) < 0) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa: "
		    "mc_offset_to_pa failed: %s\n", mcamd_errmsg(hdl));
		return (-1);	/* errno already set */
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_unumtopa: "
	    "mc_offset_to_pa succeeded and returned pa=0x%llx: %\n",
	    *pa);

	/*
	 * If this MC has a dram address hole just below 4GB then we must
	 * hoist all address from the hole start upwards by the hole size
	 */
	if (holesz != 0) {
		if (*pa >= 0x100000000 - holesz)
			*pa += holesz;
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_untopa: hoist "
		    "above dram hole of size 0x%llx to get pa=0x%llx",
		    holesz, *pa);
	}

	return (0);
}

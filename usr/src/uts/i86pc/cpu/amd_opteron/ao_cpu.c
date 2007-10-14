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
#include <sys/pghw.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/fm/protocol.h>
#include <sys/x86_archext.h>
#include <sys/pci_cfgspace.h>

#include "ao.h"

/*
 * AMD Opteron CPU Subroutines
 *
 * The following two tunables are used to determine the scrubbing rates for
 * the D$ and L2$.  The values range from 0x00-0x16 as described in BKDG
 * Scrub Control Register.  A value of zero disables the scrubber.  Values
 * above zero indicate rates in descending order.
 *
 * The current default values are used on several Sun systems.  In the future
 * this code should assign values dynamically based on cache sizing.  If you
 * tune these values manually be aware of the following architectural issue:
 * At present, Opteron can only survive certain kinds of multi-bit errors if
 * they are detected by the scrubbers.  Therefore in general we want these
 * values tuned as high as possible without impacting workload performance.
 */
uint32_t ao_scrub_rate_dcache = 8;	/* 64B every 5.12 us */
uint32_t ao_scrub_rate_l2cache = 9;	/* 64B every 10.2 us */

enum {
	AO_SCRUB_BIOSDEFAULT,		/* retain system default values */
	AO_SCRUB_FIXED,			/* assign ao_scrub_rate_* values */
	AO_SCRUB_MAX			/* assign max of system and tunables */
} ao_scrub_policy = AO_SCRUB_MAX;

void
ao_pcicfg_write(uint_t chipid, uint_t func, uint_t reg, uint32_t val)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	cmi_pci_putl(0, chipid + 24, func, reg, 0, val);
}

uint32_t
ao_pcicfg_read(uint_t chipid, uint_t func, uint_t reg)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	return (cmi_pci_getl(0, chipid + 24, func, reg, 0, 0));
}


/*
 * Return the maximum scrubbing rate between r1 and r2, where r2 is extracted
 * from the specified 'cfg' register value using 'mask' and 'shift'.  If a
 * value is zero, scrubbing is off so return the opposite value.  Otherwise
 * the maximum rate is the smallest non-zero value of the two values.
 */
static uint32_t
ao_scrubber_max(uint32_t r1, uint32_t r2)
{
	if (r1 != 0 && r2 != 0)
		return (MIN(r1, r2));

	return (r1 ? r1 : r2);
}

/*
 * Enable the chip-specific hardware scrubbers for the D$ and L2$.  We set
 * the scrubber rate based on a set of tunables defined at the top of the file.
 */
void
ao_chip_scrubber_enable(cmi_hdl_t hdl, ao_ms_data_t *ao)
{
	chipid_t chipid = cmi_hdl_chipid(hdl);
	union mcreg_scrubctl scrubctl;

	ao->ao_ms_shared->aos_bcfg_scrubctl = MCREG_VAL32(&scrubctl) =
	    ao_pcicfg_read(chipid, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBCTL);

	if (ao_scrub_policy == AO_SCRUB_BIOSDEFAULT)
		return;

	if (ao_scrub_rate_dcache > AMD_NB_SCRUBCTL_RATE_MAX) {
		cmn_err(CE_WARN, "ao_scrub_rate_dcache is too large; "
		    "resetting to 0x%x\n", AMD_NB_SCRUBCTL_RATE_MAX);
		ao_scrub_rate_dcache = AMD_NB_SCRUBCTL_RATE_MAX;
	}

	if (ao_scrub_rate_l2cache > AMD_NB_SCRUBCTL_RATE_MAX) {
		cmn_err(CE_WARN, "ao_scrub_rate_l2cache is too large; "
		    "resetting to 0x%x\n", AMD_NB_SCRUBCTL_RATE_MAX);
		ao_scrub_rate_l2cache = AMD_NB_SCRUBCTL_RATE_MAX;
	}

	switch (ao_scrub_policy) {
	case AO_SCRUB_FIXED:
		/* Use the system values checked above */
		break;

	default:
		cmn_err(CE_WARN, "Unknown ao_scrub_policy value %d - "
		    "using default policy of AO_SCRUB_MAX", ao_scrub_policy);
		/*FALLTHRU*/

	case AO_SCRUB_MAX:
		ao_scrub_rate_dcache =
		    ao_scrubber_max(ao_scrub_rate_dcache,
		    MCREG_FIELD_CMN(&scrubctl, DcacheScrub));

		ao_scrub_rate_l2cache =
		    ao_scrubber_max(ao_scrub_rate_l2cache,
		    MCREG_FIELD_CMN(&scrubctl, L2Scrub));
		break;
	}

	MCREG_FIELD_CMN(&scrubctl, DcacheScrub) = ao_scrub_rate_dcache;
	MCREG_FIELD_CMN(&scrubctl, L2Scrub) = ao_scrub_rate_l2cache;

	ao_pcicfg_write(chipid, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBCTL,
	    MCREG_VAL32(&scrubctl));
}

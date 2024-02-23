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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Implementation of the various igc functionality that is required by the core
 * code.
 */

#include "igc.h"

/*
 * Set to 1 if you want the igc core logic actually written out. Otherwise this
 * serves as a DTrace point.
 */
uint32_t igc_core_debug = 0;

void
igc_core_log(struct igc_hw *hw, const char *fmt, ...)
{
	igc_t *igc = hw->back;

	if (igc_core_debug != 0) {
		va_list ap;

		va_start(ap, fmt);
		vdev_err(igc->igc_dip, CE_WARN, fmt, ap);
		va_end(ap);
	}
}

uint32_t
IGC_READ_REG(struct igc_hw *hw, uint32_t reg)
{
	igc_t *igc = hw->back;

	return (igc_read32(igc, reg));
}

void
IGC_WRITE_REG(struct igc_hw *hw, uint32_t reg, uint32_t val)
{
	igc_t *igc = hw->back;

	igc_write32(igc, reg, val);
}

void
IGC_WRITE_REG_ARRAY(struct igc_hw *hw, uint32_t reg, uint32_t offset,
    uint32_t val)
{
	igc_t *igc = hw->back;

	ASSERT3U(reg, <, igc->igc_regs_size);
	ASSERT3U(offset + reg, <=, igc->igc_regs_size);
	igc_write32(igc, reg + offset, val);
}

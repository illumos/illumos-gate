/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2017, Joyent, Inc.
 */

#include "ixgbe_sw.h"

uint16_t
ixgbe_read_pci_cfg(struct ixgbe_hw *hw, uint32_t reg)
{
	return (pci_config_get16(OS_DEP(hw)->cfg_handle, reg));
}

void
ixgbe_write_pci_cfg(struct ixgbe_hw *hw, uint32_t reg, uint32_t val)
{
	pci_config_put16(OS_DEP(hw)->cfg_handle, reg, val);
}

/*
 * This is our last line of defense against a hardware device that has decided
 * to somehow disappear without our knowledge of it. To try and deal with this,
 * we'll read the status register and see if it returns all 1s, indicating an
 * invalid read. Note the status register is defined to have bits in all current
 * revisions that are hardwired to zero.
 */
boolean_t
ixgbe_removed(struct ixgbe_hw *hw)
{
	uint32_t val;

	val = IXGBE_READ_REG(hw, IXGBE_STATUS);
	if (val == PCI_EINVAL32) {
		ixgbe_t *ixgbe = OS_DEP(hw)->ixgbe;

		ixgbe_error(ixgbe, "failed to read status register: device "
		    "may be gone");
		if (ixgbe->ixgbe_ks != NULL) {
			ixgbe_stat_t *s = ixgbe->ixgbe_ks->ks_data;
			s->dev_gone.value.ui64++;
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

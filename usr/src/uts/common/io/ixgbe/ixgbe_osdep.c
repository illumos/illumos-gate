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
 */

#include "ixgbe_osdep.h"
#include "ixgbe_api.h"

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

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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <sys/pci.h>

#include "unm_nic.h"
#include "unm_nic_hw.h"
#include "nic_cmn.h"
#include "nic_phan_reg.h"

static void
unm_nic_isr_other(struct unm_adapter_s *adapter)
{
	u32 portno = adapter->portnum;
	u32 val, linkup, qg_linksup = adapter->ahw.linkup;

	UNM_READ_LOCK(&adapter->adapter_lock);
	adapter->unm_nic_hw_read_wx(adapter, CRB_XG_STATE, &val, 4);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	linkup = 1 & (val >> adapter->physical_port);
	adapter->ahw.linkup = linkup;

	if (linkup != qg_linksup) {
		cmn_err(CE_WARN, "%s: PORT %d link %s\n", unm_nic_driver_name,
		    portno, ((linkup == 0) ? "down" : "up"));
		mac_link_update(adapter->mach, linkup);
		if (linkup)
			unm_nic_set_link_parameters(adapter);
	}
}

void
unm_nic_handle_phy_intr(struct unm_adapter_s *adapter)
{
	uint32_t	val, val1, linkupval;

	switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
			if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
				unm_nic_isr_other(adapter);
				break;
			}
		/* FALLTHROUGH */

		case UNM_NIC_XGBE:
			/* WINDOW = 1 */
		UNM_READ_LOCK(&adapter->adapter_lock);
		if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
			adapter->unm_nic_hw_read_wx(adapter, CRB_XG_STATE_P3,
			    &val, 4);
			val1 = XG_LINK_STATE_P3(adapter->ahw.pci_func, val);
			linkupval = XG_LINK_UP_P3;
		} else {
			adapter->unm_nic_hw_read_wx(adapter, CRB_XG_STATE,
			    &val, 4);
			val >>= (adapter->portnum * 8);
			val1 = val & 0xff;
			linkupval = XG_LINK_UP;
		}
		UNM_READ_UNLOCK(&adapter->adapter_lock);

		if (adapter->ahw.linkup && (val1 != linkupval)) {
			if (verbmsg != 0)
				cmn_err(CE_NOTE, "%s%d: NIC Link is down\n",
				    adapter->name, adapter->portnum);
			mac_link_update(adapter->mach, LINK_STATE_DOWN);
			adapter->ahw.linkup = 0;
		} else if ((adapter->ahw.linkup == 0) && (val1 == linkupval)) {
			if (verbmsg != 0)
				cmn_err(CE_NOTE, "%s%d: NIC Link is up\n",
				    adapter->name, adapter->portnum);
			mac_link_update(adapter->mach, LINK_STATE_UP);
			adapter->ahw.linkup = 1;

			if (adapter->ahw.board_type == UNM_NIC_GBE)
				unm_nic_set_link_parameters(adapter);
		}

		break;

		default:
		DPRINTF(0, (CE_WARN, "%s%d ISR: Unknown board type\n",
		    unm_nic_driver_name, adapter->portnum));
	}
}

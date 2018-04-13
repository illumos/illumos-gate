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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 RackTop Systems.
 */
/*
 * Silicon Image 3XXX controller specific processing
 *
 * This file may be expanded to take advantage of Silicon Image
 * additional features (if applicable to specific controller model):
 * 1. Virtual DMA operation
 * 2. Concurrent all-channel DMA
 * 3. Large Block Transfers
 * 4. Watchdog Timer
 * 5. Power Management
 * 6. Hot Plug Support
 */

#include "ata_common.h"
#include "sil3xxx.h"
#include <sys/pci.h>

int fifocntctl[] = {FIFO_CNTCTL_0, FIFO_CNTCTL_1, FIFO_CNTCTL_2, FIFO_CNTCTL_3};
int sfiscfg[] = {SFISCFG_0, SFISCFG_1, SFISCFG_2, SFISCFG_3};

/*
 * Controller specific initialization
 */
/* ARGSUSED */
uint_t
sil3xxx_init_controller(dev_info_t *dip, ushort_t vendor_id, ushort_t device_id)
{
	ddi_acc_handle_t  pci_conf_handle; /* pci config space handle */
	uint8_t cache_lnsz, frrc = 0;
	uint32_t fifo_cnt_ctl;
	int ports, i;

#ifdef	ATA_DEBUG
	ushort_t sfiscfg_val __unused;
#endif

	/*
	 * Sil3114, Sil3512, Sil3112
	 * We want to perform this initialization only once per entire
	 * pciide controller (all channels)
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "sil3xxx-initialized")) {
		return (TRUE);
	}

	if (pci_config_setup(ddi_get_parent(dip), &pci_conf_handle) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "sil3xxx_init_controller: Can't do pci_config_setup\n");
		return (FALSE);
	}

	/*
	 * Sil3114/3512/3112 incorrectly change between MR and back to
	 * MRM for same transaction, which violates the PCI spec and can
	 * lead to incorrect data reads.  The workaround
	 * is to set bits 2:0 in the FIFO count and control register so
	 * that its value, a multiple of 32 bytes starting at 32, not 0,
	 * is greater or equal to the cacheline size, a multiple of 4
	 * bytes.  This will prevent any reads until the FIFO free space
	 * is greater than a cacheline size, ensuring only MRM is issued.
	 */

	cache_lnsz = pci_config_get8(pci_conf_handle, PCI_CONF_CACHE_LINESZ);

	/*
	 * The cache line is specified in 32-bit words, so multiply by 4
	 * to get bytes.  Then divide by 32 bytes, the granularity of the
	 * FIFO control bits 2:0.  Add 1 if there is any remainder to
	 * account for a partial 32-byte block, then subtract 1 since for
	 * FIFO controls bits 2:0, 0 corresponds to 32, 1 corresponds to
	 * 64, and so on.  The calculation is expanded for clarity.
	 */
	if (cache_lnsz != 0) {
		frrc = (cache_lnsz * 4 / 32) +
		    (((cache_lnsz * 4) % 32) ? 1 : 0) - 1;
	}

	if (device_id == SIL3114_DEVICE_ID) {
		ports = 4;
	} else {
		ports = 2;
	}

	/*
	 * The following BAR5 registers are accessed via an indirect register
	 * in the PCI configuration space rather than mapping BAR5.
	 */
	for (i = 0; i < ports; i++) {
		GET_BAR5_INDIRECT(pci_conf_handle, fifocntctl[i],
		    fifo_cnt_ctl);
		fifo_cnt_ctl = (fifo_cnt_ctl & ~0x7) | (frrc & 0x7);
		PUT_BAR5_INDIRECT(pci_conf_handle, fifocntctl[i],
		    fifo_cnt_ctl);
		/*
		 * Correct default setting for FIS0cfg
		 */
#ifdef	ATA_DEBUG
		GET_BAR5_INDIRECT(pci_conf_handle, sfiscfg[i],
		    sfiscfg_val);
		ADBG_WARN(("sil3xxx_init_controller: old val SFISCfg "
		    "ch%d: %x\n", i, sfiscfg_val));
#endif
		PUT_BAR5_INDIRECT(pci_conf_handle, sfiscfg[i],
		    SFISCFG_ERRATA);
#ifdef	ATA_DEBUG
		GET_BAR5_INDIRECT(pci_conf_handle, sfiscfg[i],
		    sfiscfg_val);
		ADBG_WARN(("sil3xxx_init_controller: new val SFISCfg "
		    "ch%d: %x\n", i, sfiscfg_val));
#endif
	}

	/* Now tear down the pci config setup */
	pci_config_teardown(&pci_conf_handle);

	/* Create property indicating that initialization was done */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ddi_get_parent(dip),
	    "sil3xxx-initialized", 1);

	return (TRUE);
}

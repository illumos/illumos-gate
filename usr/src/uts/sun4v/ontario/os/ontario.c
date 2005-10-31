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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>

#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <sys/promif.h>
#include <sys/bootconf.h>

/*
 * Definitions for accessing the pci config space of the isa node
 * of Southbridge.
 */
#define	ONTARIO_ISA_PATHNAME	"/pci@7c0/pci@0/pci@1/pci@0/isa@2"
#define	ONTARIO_IDE_PATHNAME	"/pci@7c0/pci@0/pci@1/pci@0/ide@8"

/*
 * Handle for isa pci space
 */
static ddi_acc_handle_t isa_handle;

/*
 * Platform power management drivers list - empty by default
 */
char *platform_module_list[] = {
	(char *)0
};


/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}

void
load_platform_drivers(void)
{
	dev_info_t 		*dip;		/* dip of the isa driver */
	pnode_t 		nodeid;

	/*
	 * Install ISA driver. This is required for the southbridge IDE
	 * workaround - to reset the IDE channel during IDE bus reset.
	 * Panic the system in case ISA driver could not be loaded or
	 * any problem in accessing its pci config space. Since the register
	 * to reset the channel for IDE is in ISA config space!.
	 */

	nodeid = prom_finddevice(ONTARIO_IDE_PATHNAME);
	if (nodeid == OBP_BADNODE) {
		return;
	}
	dip = e_ddi_hold_devi_by_path(ONTARIO_ISA_PATHNAME, 0);
	if (dip == NULL) {
		cmn_err(CE_PANIC, "Could not install the isa driver\n");
		return;
	}

	if (pci_config_setup(dip, &isa_handle) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "Could not get the config space of isa\n");
		return;
	}
}

/*
 * This routine provides a workaround for a bug in the SB chip which
 * can cause data corruption. Will be invoked from the IDE HBA driver for
 * Acer SouthBridge at the time of IDE bus reset.
 */
/*ARGSUSED*/
int
plat_ide_chipreset(dev_info_t *dip, int chno)
{
	uint8_t	val;
	int	ret = DDI_SUCCESS;

	if (isa_handle == NULL) {
		return (DDI_FAILURE);
	}

	val = pci_config_get8(isa_handle, 0x58);
	/*
	 * The dip passed as the argument is not used here.
	 * This will be needed for platforms which have multiple on-board SB,
	 * The dip passed will be used to match the corresponding ISA node.
	 */
	switch (chno) {
	case 0:
		/*
		 * First disable the primary channel then re-enable it.
		 * As per ALI no wait should be required in between have
		 * given 1ms delay in between to be on safer side.
		 * bit 2 of register 0x58 when 0 disable the channel 0.
		 * bit 2 of register 0x58 when 1 enables the channel 0.
		 */
		pci_config_put8(isa_handle, 0x58, val & 0xFB);
		drv_usecwait(1000);
		pci_config_put8(isa_handle, 0x58, val);
		break;
	case 1:
		/*
		 * bit 3 of register 0x58 when 0 disable the channel 1.
		 * bit 3 of register 0x58 when 1 enables the channel 1.
		 */
		pci_config_put8(isa_handle, 0x58, val & 0xF7);
		drv_usecwait(1000);
		pci_config_put8(isa_handle, 0x58, val);
		break;
	default:
		/*
		 * Unknown channel number passed. Return failure.
		 */
		ret = DDI_FAILURE;
	}

	return (ret);
}

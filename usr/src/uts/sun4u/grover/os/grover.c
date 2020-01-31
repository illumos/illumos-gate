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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi.h>

#include <sys/platform_module.h>
#include <sys/errno.h>

void
startup_platform(void)
{
}

int
set_platform_tsb_spares()
{
	return (0);
}

void
set_platform_defaults(void)
{
}


/*
 * Definitions for accessing the pci config space of the isa node
 * of Southbridge.
 */
#define	GROVER_ISA_PATHNAME	"/pci@1f,0/isa@7"
ddi_acc_handle_t	grover_isa_handle;	/* handle for isa pci space */

void
load_platform_drivers(void)
{
	dev_info_t		*dip;		/* dip of the isa driver */


	if (i_ddi_attach_hw_nodes("power") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"power\" driver.");

	/*
	 * It is OK to return error because 'us' driver is not available
	 * in all clusters (e.g. missing in Core cluster).
	 */
	(void) i_ddi_attach_hw_nodes("us");

	if (i_ddi_attach_hw_nodes("grbeep") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"beep\" driver.");

	/*
	 * Install Isa driver. This is required for the southbridge IDE
	 * workaround - to reset the IDE channel during IDE bus reset.
	 * Panic the system in case ISA driver could not be loaded or
	 * any problem in accessing its pci config space. Since the register
	 * to reset the channel for IDE is in ISA config space!.
	 */

	dip = e_ddi_hold_devi_by_path(GROVER_ISA_PATHNAME, 0);
	if (dip == NULL) {
		cmn_err(CE_PANIC, "Could not install the isa driver\n");
	}

	if (pci_config_setup(dip, &grover_isa_handle) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "Could not get the config space of isa\n");
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

	val = pci_config_get8(grover_isa_handle, 0x58);
	/*
	 * The dip passed as the argument is not used for grover.
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
			pci_config_put8(grover_isa_handle, 0x58, val & 0xFB);
			drv_usecwait(1000);
			pci_config_put8(grover_isa_handle, 0x58, val);
			break;
		case 1:
			/*
			 * bit 3 of register 0x58 when 0 disable the channel 1.
			 * bit 3 of register 0x58 when 1 enables the channel 1.
			 */
			pci_config_put8(grover_isa_handle, 0x58, val & 0xF7);
			drv_usecwait(1000);
			pci_config_put8(grover_isa_handle, 0x58, val);
			break;
		default:
			/*
			 * Unknown channel number passed. Return failure.
			 */
			ret = DDI_FAILURE;
	}

	return (ret);
}



/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*ARGSUSED*/
void
plat_freelist_process(int mnode)
{
}

char *platform_module_list[] = {
	"grppm",
	(char *)0
};

/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}

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
#include <sys/platform_module.h>
#include <sys/errno.h>

/*
 * 1535D+ IDE Interface Control Register Index
 */
#define	IDEIC_RINDEX	(0x58)

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

void
startup_platform(void)
{
}

int
set_platform_tsb_spares(void)
{
	return (0);
}

void
set_platform_defaults(void)
{
}

/*
 * Definitions for accessing the pci config space of the ISA node
 * of Southbridge.
 */
#define	TACO_ISA_PATHNAME	"/pci@1e,600000/isa@7"
static ddi_acc_handle_t isa_handle;		/* handle for ISA pci space */


void
load_platform_drivers(void)
{
	dev_info_t 		*dip;		/* dip of the ISA driver */

	/*
	 * Install power driver which handles the power button.
	 */
	if (i_ddi_attach_hw_nodes("power") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"power\" driver.");
	(void) ddi_hold_driver(ddi_name_to_major("power"));

	/*
	 * It is OK to return error because 'us' driver is not available
	 * in all clusters (e.g. missing in Core cluster).
	 */
	(void) i_ddi_attach_hw_nodes("us");

	if (i_ddi_attach_hw_nodes("grbeep") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"beep\" driver.");


	/*
	 * mc-us3i must stay loaded for plat_get_mem_unum()
	 */
	if (i_ddi_attach_hw_nodes("mc-us3i") != DDI_SUCCESS)
		cmn_err(CE_WARN, "mc-us3i driver failed to install");
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3i"));

	/*
	 * Install ISA driver. This is required for the southbridge IDE
	 * workaround - to reset the IDE channel during IDE bus reset.
	 * Panic the system in case ISA driver could not be loaded or
	 * any problem in accessing its pci config space. Since the register
	 * to reset the channel for IDE is in ISA config space!.
	 */

	dip = e_ddi_hold_devi_by_path(TACO_ISA_PATHNAME, 0);
	if (dip == NULL) {
		cmn_err(CE_PANIC, "Could not install the ISA driver\n");
		return;
	}

	if (pci_config_setup(dip, &isa_handle) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "Could not get the config space of ISA\n");
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

	val = pci_config_get8(isa_handle, IDEIC_RINDEX);
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
			pci_config_put8(isa_handle, IDEIC_RINDEX, val & 0xFB);
			drv_usecwait(1000);
			pci_config_put8(isa_handle, IDEIC_RINDEX, val);
			break;
		case 1:
			/*
			 * bit 3 of register 0x58 when 0 disable the channel 1.
			 * bit 3 of register 0x58 when 1 enables the channel 1.
			 */
			pci_config_put8(isa_handle, IDEIC_RINDEX, val & 0xF7);
			drv_usecwait(1000);
			pci_config_put8(isa_handle, IDEIC_RINDEX, val);
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
	"m1535ppm",
	"jbusppm",
	"ics951601",
	"ppm",
	(char *)0
};

/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}

/*ARGSUSED*/
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	if (flt_in_memory && (p2get_mem_unum != NULL))
		return (p2get_mem_unum(synd_code, P2ALIGN(flt_addr, 8),
			buf, buflen, lenp));
	else
		return (ENOTSUP);
}

/*ARGSUSED*/
int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	if (snprintf(buf, buflen, "MB") >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

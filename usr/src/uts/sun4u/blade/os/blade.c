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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi.h>

#include <sys/platform_module.h>
#include <sys/modctl.h>
#include <sys/lom_priv.h>
#include <sys/errno.h>
#include <sys/utsname.h>

#define	TOD_DRIVER_NAME	"todblade"
#define	BSC_DRV		SUNW_KERN_BSCV_MODULENAME
#define	BSC_DRV_FUNC	SUNW_KERN_BSCV_IDI_FN


/* local functions */
static void cpu_sgn_update(ushort_t, uchar_t, uchar_t, int);

/* Globals */
void (*bsc_drv_func_ptr)(struct bscv_idi_info *) = NULL;


void
startup_platform(void)
{
	extern char	*tod_module_name;
	extern int	watchdog_available;
	extern int	watchdog_enable;
	extern int	disable_watchdog_on_exit;

	/* Set appropriate tod module for blade */
	tod_module_name = TOD_DRIVER_NAME;

	/* Set watchdog default configuration */
	watchdog_available = 1;
	watchdog_enable = 1;
	disable_watchdog_on_exit = 1;
}

int
set_platform_tsb_spares()
{
	return (0);
}

void
set_platform_defaults(void)
{
	/* Set the CPU signature function pointer */
	cpu_sgn_func = cpu_sgn_update;
}

/*
 * Definitions for accessing the pci config space of the isa node
 * of Southbridge.
 */
#define	PLATFORM_ISA_PATHNAME	"/pci@1f,0/isa@7"
#define	PLATFORM_ISA_PATHNAME_WITH_SIMBA	"/pci@1f,0/pci@1,1/isa@7"
static ddi_acc_handle_t platform_isa_handle;	/* handle for isa pci space */

void
load_platform_drivers(void)
{
	extern int		watchdog_available;
	extern int		watchdog_enable;
	dev_info_t 		*dip;		/* dip of the isa driver */
	int			simba_present = 0;
	dev_info_t		*root_child_node;
	major_t	major;

	if (ddi_install_driver("power") != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to install \"power\" driver.");

	/*
	 * Install Isa driver. This is required for the southbridge IDE
	 * workaround - to reset the IDE channel during IDE bus reset.
	 * Panic the system in case ISA driver could not be loaded or
	 * any problem in accessing its pci config space. Since the register
	 * to reset the channel for IDE is in ISA config space!.
	 */
	root_child_node = ddi_get_child(ddi_root_node());

	while (root_child_node != NULL) {
		if (strcmp(ddi_node_name(root_child_node), "pci") == 0) {
			root_child_node = ddi_get_child(root_child_node);
			if (strcmp(ddi_node_name(root_child_node), "pci") == 0)
				simba_present = 1;
			break;
		}
		root_child_node = ddi_get_next_sibling(root_child_node);
	}

	if (simba_present)
		dip = e_ddi_hold_devi_by_path(PLATFORM_ISA_PATHNAME_WITH_SIMBA,
		    0);
	else
		dip = e_ddi_hold_devi_by_path(PLATFORM_ISA_PATHNAME, 0);

	if (dip == NULL) {
		cmn_err(CE_PANIC, "Could not install the isa driver\n");
		return;
	}

	if (pci_config_setup(dip, &platform_isa_handle) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "Could not get the config space of isa\n");
		return;
	}

	/*
	 * Load the blade support chip driver.
	 *
	 */

	if (((major = ddi_name_to_major(BSC_DRV)) == -1) ||
		(ddi_hold_installed_driver(major) == NULL)) {
		cmn_err(CE_WARN, "%s: failed to load", BSC_DRV);
	} else {

		bsc_drv_func_ptr = (void (*)(struct bscv_idi_info *))
		    modgetsymvalue(BSC_DRV_FUNC, 0);

		if (bsc_drv_func_ptr == NULL) {
			cmn_err(CE_WARN, "load_platform_defaults: %s()"
			" not found; signatures will not be updated\n",
			BSC_DRV_FUNC);
			watchdog_available = 0;
			if (watchdog_enable) {
				cmn_err(CE_WARN, "load_platform_defaults: %s()"
			" not found; BSC OS watchdog service not available\n",
				BSC_DRV_FUNC);
			}
		}
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

	if (platform_isa_handle == NULL)
		return (DDI_FAILURE);

	val = pci_config_get8(platform_isa_handle, 0x58);
	/*
	 * The dip passed as the argument is not used for platform.
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
			pci_config_put8(platform_isa_handle, 0x58, val & 0xFB);
			drv_usecwait(1000);
			pci_config_put8(platform_isa_handle, 0x58, val);
			break;
		case 1:
			/*
			 * bit 3 of register 0x58 when 0 disable the channel 1.
			 * bit 3 of register 0x58 when 1 enables the channel 1.
			 */
			pci_config_put8(platform_isa_handle, 0x58, val & 0xF7);
			drv_usecwait(1000);
			pci_config_put8(platform_isa_handle, 0x58, val);
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
	(char *)0
};

/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}

/*
 * Our nodename has been set, pass it along to the BSC.
 */
void
plat_nodename_set(void)
{
	struct bscv_idi_info bscv_info;

	bscv_info.type = BSCV_IDI_NODENAME;
	bscv_info.data = utsname.nodename;
	bscv_info.size = strlen(utsname.nodename);

	if (bsc_drv_func_ptr != NULL)
		(bsc_drv_func_ptr)(&bscv_info);
}

/*
 * Send an updated CPU signature to the BSC.
 */

static void
cpu_sgn_update(ushort_t sig, uchar_t state, uchar_t sub_state, int cpuid)
{
	struct bscv_idi_info bscv_info;
	bscv_sig_t sc;

	sc.sig_info.signature = CPU_SIG_BLD(sig, state, sub_state);
	sc.cpu = cpuid;

	bscv_info.type = BSCV_IDI_SIG;
	bscv_info.data = &sc;
	bscv_info.size = sizeof (sc);


	if (bsc_drv_func_ptr != NULL)
		(*bsc_drv_func_ptr)(&bscv_info);
}

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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/platform_module.h>
#include <sys/errno.h>

/*
 * This platmod is used by both SUNW,Sun-Fire-280R (a.k.a littleneck) and
 * SUNW,Netra-T4 (a.k.a. lw2plus) platforms.
 */

#define	LITTLENECK_NVRAM_PATH	"/pci@8,700000/ebus@5/i2c@1,2e/nvram@0,a0"
#define	LW2PLUS_NVRAM_PATH	"/pci@8,700000/ebus@5/i2c@1,30/nvram@0,e0"

static dev_info_t *shared_pcf8584_dip = NULL;
static kmutex_t lneck_pcf8584_mutex;

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

void
startup_platform(void)
{
	mutex_init(&lneck_pcf8584_mutex, NULL, MUTEX_ADAPTIVE, NULL);
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

void
load_platform_drivers(void)
{
	char		**drv;
	dev_info_t	*nvram_dip;
	static char	*boot_time_drivers[] = {
		"todds1287",
		"pcf8574",
		"mc-us3",
		NULL
	};

	for (drv = boot_time_drivers; *drv; drv++) {
		if (i_ddi_attach_hw_nodes(*drv) != DDI_SUCCESS)
			cmn_err(CE_WARN, "Failed to install \"%s\" driver.",
			    *drv);
	}

	/* hold modules for keyswitch polling and plat_get_mem_unum() */
	(void) ddi_hold_driver(ddi_name_to_major("pcf8574"));
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3"));

	/*
	 * For littleneck we figure out which pcf8584 dip is shared with
	 * OBP for the nvram device, so the lock can be acquired.
	 * If this fails see if we're running on a Netra 20.
	 * The Netra 20 nvram node is the SCC and is also shared by
	 * Solaris and OBP.
	 */

	nvram_dip = e_ddi_hold_devi_by_path(LITTLENECK_NVRAM_PATH, 0);

	if (nvram_dip == NULL)
		nvram_dip = e_ddi_hold_devi_by_path(LW2PLUS_NVRAM_PATH, 0);
	if (nvram_dip == NULL)
		cmn_err(CE_WARN, "Failed to hold pcf8584");
	else {
		shared_pcf8584_dip = ddi_get_parent(nvram_dip);

		ndi_hold_devi(shared_pcf8584_dip);
		ndi_rele_devi(nvram_dip);
	}
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

/*
 * No platform drivers on this platform
 */
char *platform_module_list[] = {
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

int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	if (snprintf(buf, buflen, "Slot %d", cpuid) >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * Littleneck's BBC pcf8584 controller is used by both OBP and the OS's i2c
 * drivers.  The 'eeprom' command executes OBP code to handle property requests.
 * If eeprom didn't do this, or if the controllers were partitioned so that all
 * devices on a given controller were driven by either OBP or the OS, this
 * wouldn't be necessary.
 *
 * Note that getprop doesn't have the same issue as it reads from cached
 * memory in OBP.
 */

/*
 * Common locking enter code
 */
void
plat_setprop_enter(void)
{
	mutex_enter(&lneck_pcf8584_mutex);
}

/*
 * Common locking exit code
 */
void
plat_setprop_exit(void)
{
	mutex_exit(&lneck_pcf8584_mutex);
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_enter(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_pcf8584_dip) {
		plat_setprop_enter();
	}
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_exit(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_pcf8584_dip) {
		plat_setprop_exit();
	}
}

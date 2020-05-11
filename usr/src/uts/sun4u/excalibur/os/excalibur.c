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
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/conf.h>

#include <sys/platform_module.h>
#include <sys/errno.h>

#include <sys/sunldi.h>
#include <sys/file.h>

#define	SHARED_PCF8584_PATH "/pci@8,700000/ebus@5/i2c@1,2e/nvram@0,a0"
static dev_info_t *shared_pcf8584_dip;
static kmutex_t excal_pcf8584_mutex;

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

/*
 * Excalibur fan information
 */
typedef struct xcalfan_info {
	char		*pathname;
	int8_t		val8;
	ldi_handle_t	lh;
} xcalfan_info_t;

static xcalfan_info_t xcalfans[] = {
	{"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:2", 63, NULL},
	{"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:0", 63, NULL},
	{"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:4", 31, NULL}
};

#define	NFANS	(sizeof (xcalfans) / sizeof (xcalfans[0]))

void
startup_platform(void)
{
	mutex_init(&excal_pcf8584_mutex, NULL, MUTEX_ADAPTIVE, NULL);
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
	ldi_ident_t	li;
	dev_info_t	*dip;
	char		**drv;
	int		i, err;

	static char *boot_time_drivers[] = {
		"todds1287",
		"us",
		"mc-us3",
		"bbc_beep",
		"max1617",
		"tda8444",
		"seeprom",
		NULL
	};

	for (drv = boot_time_drivers; *drv; drv++) {
		if ((i_ddi_attach_hw_nodes(*drv) != DDI_SUCCESS) &&
		    (strcmp(*drv, "us") != 0))
			/*
			 * It is OK if 'us' driver doesn't load. It's
			 * not available in Core cluster.
			 */
			cmn_err(CE_WARN, "Failed to install \"%s\" driver.",
			    *drv);
	}

	/*
	 * mc-us3 must stay loaded for plat_get_mem_unum()
	 */
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3"));

	/*
	 * Figure out which pcf8584_dip is shared with OBP for the nvram
	 * device, so the lock can be acquired.
	 *
	 * This should really be done elsewhere, like startup_platform, but
	 * that runs before the devinfo tree is setup with configure().
	 * So it is here until there is a better place.
	 */
	dip = e_ddi_hold_devi_by_path(SHARED_PCF8584_PATH, 0);

	ASSERT(dip != NULL);
	shared_pcf8584_dip = ddi_get_parent(dip);

	ndi_hold_devi(shared_pcf8584_dip);
	ndi_rele_devi(dip);

	li = ldi_ident_from_anon();
	for (i = 0; i < NFANS; ++i) {
		err = ldi_open_by_name(xcalfans[i].pathname,
		    FWRITE, kcred, &xcalfans[i].lh, li);

		if (err != 0) {
			cmn_err(CE_WARN, "plat_fan_blast: "
			    "Failed to get fan device handle for %s",
			    xcalfans[i].pathname);
			continue;
		}
	}
	ldi_ident_release(li);
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
	"schppm",	/* must attach before xcalppm */
	"xcalppm",
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
 * Unfortunately, excal's BBC pcf8584 controller is used by both OBP
 * and the OS's i2c drivers.  The 'eeprom' command executes
 * OBP code to handle property requests.  If eeprom didn't do this, or if the
 * controllers were partitioned so that all devices on a given controller were
 * driven by either OBP or the OS, this wouldn't be necessary.
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
	mutex_enter(&excal_pcf8584_mutex);
}

/*
 * Common locking exit code
 */
void
plat_setprop_exit(void)
{
	mutex_exit(&excal_pcf8584_mutex);
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_enter(dev_info_t *dip)
{
	if (dip == shared_pcf8584_dip) {
		plat_setprop_enter();
	}
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_exit(dev_info_t *dip)
{
	if (dip == shared_pcf8584_dip) {
		plat_setprop_exit();
	}
}

/*
 * Set platform fans to maximum speed
 */
void
plat_fan_blast(void)
{
	struct uio	uio;
	struct iovec	iov;
	int8_t		fv;
	int		err;
	int		i;

	for (i = 0; i < NFANS; ++i) {
		fv = xcalfans[i].val8;
		bzero(&uio, sizeof (uio));
		bzero(&iov, sizeof (iov));
		iov.iov_base = &fv;
		iov.iov_len = sizeof (fv);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_loffset = 0;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_resid = sizeof (fv);

		err = ldi_write(xcalfans[i].lh, &uio, kcred);
		if (err != 0) {
			if (err == EAGAIN) {
				cmn_err(CE_WARN, "!plat_fan_blast: Cannot "
				    "write %d to %s now, try again later.",
				    xcalfans[i].val8, xcalfans[i].pathname);
			} else {
				cmn_err(CE_WARN, "plat_fan_blast: "
				    "Error %d while writing %d to %s.", err,
				    xcalfans[i].val8, xcalfans[i].pathname);
			}
		}
	}
}

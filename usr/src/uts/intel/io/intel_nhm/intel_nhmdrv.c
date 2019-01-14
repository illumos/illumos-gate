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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/mc_intel.h>
#include <sys/mc.h>
#include <sys/fm/protocol.h>
#include "nhm_log.h"
#include "intel_nhm.h"

int max_bus_number = 0xff;

nvlist_t *inhm_mc_nvl[MAX_CPU_NODES];
krwlock_t inhm_mc_lock;

char *inhm_mc_snapshot[MAX_CPU_NODES];
uint_t nhm_config_gen;
uint_t inhm_mc_snapshotgen;
size_t inhm_mc_snapshotsz[MAX_CPU_NODES];
static dev_info_t *inhm_dip;
int nhm_allow_detach = 0;

extern int nhm_patrol_scrub;
extern int nhm_demand_scrub;
extern int nhm_no_smbios;
extern int nhm_smbios_serial;
extern int nhm_smbios_manufacturer;
extern int nhm_smbios_part_number;
extern int nhm_smbios_version;
extern int nhm_smbios_label;

extern void inhm_create_nvl(int);
extern char *inhm_mc_name(void);
extern void init_dimms(void);
extern void nhm_smbios();

static void
inhm_mc_snapshot_destroy()
{
	int i;

	ASSERT(RW_LOCK_HELD(&inhm_mc_lock));

	for (i = 0; i < MAX_CPU_NODES; i++) {
		if (inhm_mc_snapshot[i] == NULL)
			continue;

		kmem_free(inhm_mc_snapshot[i], inhm_mc_snapshotsz[i]);
		inhm_mc_snapshot[i] = NULL;
		inhm_mc_snapshotsz[i] = 0;
	}
	inhm_mc_snapshotgen++;
}

static int
inhm_mc_snapshot_update()
{
	int i;
	int rt = 0;

	ASSERT(RW_LOCK_HELD(&inhm_mc_lock));

	for (i = 0; i < MAX_CPU_NODES; i++) {
		if (inhm_mc_snapshot[i] != NULL)
			continue;

		if (nvlist_pack(inhm_mc_nvl[i], &inhm_mc_snapshot[i],
		    &inhm_mc_snapshotsz[i], NV_ENCODE_XDR, KM_SLEEP) != 0)
			rt = -1;
	}

	return (rt);
}

/*ARGSUSED*/
static int
inhm_mc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int rc = 0;
	int chip;
	mc_snapshot_info_t mcs;

	if (cmd != MC_IOC_SNAPSHOT_INFO && cmd != MC_IOC_SNAPSHOT)
		return (EINVAL);

	rw_enter(&inhm_mc_lock, RW_READER);
	chip = getminor(dev) % MAX_CPU_NODES;
	if (inhm_mc_nvl[chip] == NULL ||
	    inhm_mc_snapshotgen != nhm_config_gen) {
		if (!rw_tryupgrade(&inhm_mc_lock)) {
			rw_exit(&inhm_mc_lock);
			return (EAGAIN);
		}
		if (inhm_mc_nvl[chip])
			inhm_mc_snapshot_destroy();
		inhm_create_nvl(chip);
		nhm_config_gen = inhm_mc_snapshotgen;
		(void) inhm_mc_snapshot_update();
	}
	switch (cmd) {
	case MC_IOC_SNAPSHOT_INFO:
		mcs.mcs_size = (uint32_t)inhm_mc_snapshotsz[chip];
		mcs.mcs_gen = inhm_mc_snapshotgen;

		if (ddi_copyout(&mcs, (void *)arg, sizeof (mc_snapshot_info_t),
		    mode) < 0)
			rc = EFAULT;
		break;
	case MC_IOC_SNAPSHOT:
		if (ddi_copyout(inhm_mc_snapshot[chip], (void *)arg,
		    inhm_mc_snapshotsz[chip], mode) < 0)
			rc = EFAULT;
		break;
	}
	rw_exit(&inhm_mc_lock);
	return (rc);
}

/*ARGSUSED*/
static int
inhm_mc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	if ((infocmd != DDI_INFO_DEVT2DEVINFO &&
	    infocmd != DDI_INFO_DEVT2INSTANCE) || inhm_dip == NULL) {
		*result = NULL;
		return (DDI_FAILURE);
	}
	if (infocmd == DDI_INFO_DEVT2DEVINFO)
		*result = inhm_dip;
	else
		*result = (void *)(uintptr_t)ddi_get_instance(inhm_dip);
	return (0);
}

static int
inhm_mc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int i;
	char buf[64];

	if (cmd == DDI_RESUME) {
		nhm_dev_reinit();
		nhm_scrubber_enable();
		nhm_smbios();
		return (DDI_SUCCESS);
	}
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (inhm_dip == NULL) {
		inhm_dip = dip;
		nhm_pci_cfg_setup(dip);
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    inhm_mc_name());
		if (nhm_dev_init()) {
			nhm_pci_cfg_free();
			inhm_dip = NULL;
			return (DDI_FAILURE);
		}
		ddi_set_name_addr(dip, "1");
		for (i = 0; i < MAX_CPU_NODES; i++) {
			(void) snprintf(buf, sizeof (buf), "mc-intel-%d", i);
			if (ddi_create_minor_node(dip, buf, S_IFCHR,
			    i, "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "failed to create minor node"
				    " for memory controller %d\n", i);
			}
		}
		cmi_hdl_walk(inhm_mc_register, NULL, NULL, NULL);
		nhm_patrol_scrub = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "patrol-scrub", 0);
		nhm_demand_scrub = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "demand-scrub", 0);
		nhm_no_smbios = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "no-smbios", 0);
		nhm_smbios_serial = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "smbios-dimm-serial", 1);
		nhm_smbios_manufacturer = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "smbios-dimm-manufacturer", 1);
		nhm_smbios_part_number = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "smbios-dimm-part-number", 1);
		nhm_smbios_version = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "smbios-dimme-version", 1);
		nhm_smbios_label = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "smbios-dimm-label", 1);
		nhm_scrubber_enable();
		nhm_smbios();
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
inhm_mc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (nhm_allow_detach && cmd == DDI_DETACH && dip == inhm_dip) {
		rw_enter(&inhm_mc_lock, RW_WRITER);
		inhm_mc_snapshot_destroy();
		rw_exit(&inhm_mc_lock);
		inhm_dip = NULL;
		return (DDI_SUCCESS);
	} else if (cmd == DDI_SUSPEND || cmd == DDI_PM_SUSPEND) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
inhm_mc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	rw_enter(&inhm_mc_lock, RW_READER);
	if (getminor(*devp) >= MAX_CPU_NODES) {
		rw_exit(&inhm_mc_lock);
		return (EINVAL);
	}
	rw_exit(&inhm_mc_lock);

	return (0);
}

/*ARGSUSED*/
static int
inhm_mc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}


static struct cb_ops inhm_mc_cb_ops = {
	inhm_mc_open,
	inhm_mc_close,
	nodev,		/* not a block driver */
	nodev,		/* no print routine */
	nodev,		/* no dump routine */
	nodev,		/* no read routine */
	nodev,		/* no write routine */
	inhm_mc_ioctl,
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver */
	D_NEW | D_MP,	/* safe for multi-thread/multi-processor */
};

static struct dev_ops inhm_mc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	inhm_mc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	inhm_mc_attach,		/* devo_attach */
	inhm_mc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&inhm_mc_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Intel QuickPath Memory Controller Hub Module",
	&inhm_mc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int err;

	err = nhm_init();
	if (err == 0 && (err = mod_install(&modlinkage)) == 0) {
		rw_init(&inhm_mc_lock, NULL, RW_DRIVER, NULL);
		init_dimms();
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		nhm_unload();
		rw_destroy(&inhm_mc_lock);
	}

	return (err);
}

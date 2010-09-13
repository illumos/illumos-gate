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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/synch.h>
#include <sys/fipe.h>

/* Configurable through /etc/system. */
int			fipe_allow_attach = 1;
int 			fipe_allow_detach = 1;

static kmutex_t		fipe_drv_lock;
static dev_info_t	*fipe_drv_dip;

/*
 * PCI device ID for supported hardware.
 * For memory controller devices in Intel 5000/7300 series chipset, PCI vendor
 * id and PCI device id is read only, PCI subvendor id and PCI subsystem id is
 * write-once. So we could only rely on PCI vendor id and PCI device id here.
 * For all PCI functions (0,1,2,3) in device 0x10 on bus 0, they will have the
 * same PCI (vendor_id, device_id, subvendor_id, subsystem_id, class_id).
 * We only need to access PCI device (0, 0x10, 1), all other PCI functions will
 * be filtered out by unit address.
 */
static struct fipe_pci_id {
	uint16_t		venid;
	uint16_t		devid;
	uint16_t		subvenid;
	uint16_t		subsysid;
	char			*unitaddr;
} fipe_mc_pciids[] = {
	{ 0x8086, 0x25f0, 0xffff, 0xffff, "10,1" },	/* Intel 5000P/V/X/Z */
	{ 0x8086, 0x360c, 0xffff, 0xffff, "10,1" }	/* Intel 7300 NB */
};

/*ARGSUSED*/
static int
fipe_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR) {
		cmn_err(CE_NOTE, "!fipe: invalid otyp %d in open.", otyp);
		return (EINVAL);
	}

	return (0);
}

/*ARGSUSED*/
static int
fipe_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
fipe_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int rc = 0;
	fipe_pm_policy_t policy;

	/* First check permission. */
	if (secpolicy_power_mgmt(credp) != 0) {
		return (EPERM);
	}

	switch (cmd) {
	case FIPE_IOCTL_START:
		if ((mode & FWRITE) == 0) {
			rc = EBADF;
		} else {
			mutex_enter(&fipe_drv_lock);
			rc = fipe_start();
			mutex_exit(&fipe_drv_lock);
			rc =  (rc == 0) ? 0 : ENXIO;
		}
		break;

	case FIPE_IOCTL_STOP:
		if ((mode & FWRITE) == 0) {
			rc = EBADF;
		} else {
			mutex_enter(&fipe_drv_lock);
			rc = fipe_stop();
			mutex_exit(&fipe_drv_lock);
			rc =  (rc == 0) ? 0 : ENXIO;
		}
		break;

	case FIPE_IOCTL_GET_PMPOLICY:
		if ((mode & FREAD) == 0) {
			rc = EBADF;
		} else {
			mutex_enter(&fipe_drv_lock);
			policy = fipe_get_pmpolicy();
			mutex_exit(&fipe_drv_lock);
			rc = ddi_copyout(&policy, (void *)arg,
			    sizeof (policy), mode);
			rc = (rc >= 0) ? 0 : EFAULT;
		}
		break;

	case FIPE_IOCTL_SET_PMPOLICY:
		if ((mode & FWRITE) == 0) {
			rc = EBADF;
		} else {
			mutex_enter(&fipe_drv_lock);
			rc = fipe_set_pmpolicy((fipe_pm_policy_t)arg);
			mutex_exit(&fipe_drv_lock);
			rc =  (rc == 0) ? 0 : ENXIO;
		}
		break;

	default:
		cmn_err(CE_NOTE, "!fipe: unknown ioctl command %d.", cmd);
		rc = ENOTSUP;
		break;
	}

	return (rc);
}

/*ARGSUSED*/
static int
fipe_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (fipe_drv_dip != NULL) {
			*result = fipe_drv_dip;
			return (DDI_SUCCESS);
		} else {
			*result = NULL;
			return (DDI_FAILURE);
		}

	case DDI_INFO_DEVT2INSTANCE:
		if (fipe_drv_dip != NULL) {
			*result = (void *)(uintptr_t)
			    ddi_get_instance(fipe_drv_dip);
			return (DDI_SUCCESS);
		} else {
			*result = NULL;
			return (DDI_FAILURE);
		}

	default:
		*result = NULL;
		return (DDI_FAILURE);
	}
}

/* Validate whether it's supported hardware. */
static int
fipe_validate_dip(dev_info_t *dip)
{
	int i, rc = -1;
	char *unitaddr;
	struct fipe_pci_id *ip;
	ddi_acc_handle_t handle;
	uint16_t venid, devid, subvenid, subsysid;

	/* Get device unit address, it's "devid,funcid" in hexadecimal. */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "unit-address", &unitaddr) != DDI_PROP_SUCCESS) {
		cmn_err(CE_CONT, "?fipe: failed to get deivce unit address.");
		return (-1);
	}
	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "?fipe: failed to setup pcicfg handler.");
		ddi_prop_free(unitaddr);
		return (-1);
	}
	venid = pci_config_get16(handle, PCI_CONF_VENID);
	devid = pci_config_get16(handle, PCI_CONF_DEVID);
	subvenid = pci_config_get16(handle, PCI_CONF_SUBVENID);
	subsysid = pci_config_get16(handle, PCI_CONF_SUBSYSID);

	/* Validate device. */
	for (rc = -1, i = 0, ip = &fipe_mc_pciids[0];
	    i < sizeof (fipe_mc_pciids) / sizeof (fipe_mc_pciids[0]);
	    i++, ip++) {
		if ((ip->venid == 0xffffu || ip->venid == venid) &&
		    (ip->devid == 0xffffu || ip->devid == devid) &&
		    (ip->subvenid == 0xffffu || ip->subvenid == subvenid) &&
		    (ip->subsysid == 0xffffu || ip->subsysid == subsysid) &&
		    (ip->unitaddr == NULL ||
		    strcmp(ip->unitaddr, unitaddr) == 0)) {
			rc = 0;
			break;
		}
	}

	pci_config_teardown(&handle);
	ddi_prop_free(unitaddr);

	return (rc);
}

static int
fipe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char *ptr;
	int ignore = 0, rc = DDI_FAILURE;

	mutex_enter(&fipe_drv_lock);
	switch (cmd) {
	case DDI_ATTACH:
		/* Check whether it has been disabled by user. */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
		    "disable_fipe_pm", &ptr) == DDI_SUCCESS) {
			if (strcasecmp(ptr, "true") == 0 ||
			    strcasecmp(ptr, "yes") == 0) {
				fipe_allow_attach = 0;
			}
			ddi_prop_free(ptr);
		}
		if (fipe_allow_attach == 0) {
			cmn_err(CE_WARN,
			    "fipe: driver has been disabled by user.");
			ignore = 1;
			break;
		}

		/* Filter out unwanted PCI functions. */
		if ((ignore = fipe_validate_dip(dip)) != 0) {
			break;
		/* There should be only one MC device in system. */
		} else if (fipe_drv_dip != NULL) {
			cmn_err(CE_NOTE,
			    "!fipe: more than one hardware instances found.");
			break;
		}
		fipe_drv_dip = dip;

		/* Initialize and start power management subsystem. */
		if (fipe_init(fipe_drv_dip) != 0) {
			fipe_drv_dip = NULL;
			break;
		} else if (fipe_start() != 0) {
			(void) fipe_fini();
			fipe_drv_dip = NULL;
			break;
		}

		/* Ignore error from creating minor node. */
		if (ddi_create_minor_node(dip, "fipe", S_IFCHR, 0,
		    "ddi_mem_pm", 0) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "?fipe: failed to create device minor node.\n");
		}

		rc = DDI_SUCCESS;
		break;

	case DDI_RESUME:
		if (fipe_resume() == 0) {
			rc = DDI_SUCCESS;
		}
		break;

	default:
		break;
	}
	mutex_exit(&fipe_drv_lock);

	if (ignore == 0 && rc != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!fipe: failed to attach or resume device.");
	}

	return (rc);
}

/*ARGSUSED*/
static int
fipe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int rc = DDI_FAILURE;

	mutex_enter(&fipe_drv_lock);
	switch (cmd) {
	case DDI_DETACH:
		if (fipe_allow_detach == 0 || dip != fipe_drv_dip) {
			break;
		}
		if (fipe_stop() != 0) {
			break;
		} else if (fipe_fini() != 0) {
			(void) fipe_start();
			break;
		}
		ddi_remove_minor_node(dip, NULL);
		fipe_drv_dip = NULL;
		rc = DDI_SUCCESS;
		break;

	case DDI_SUSPEND:
		if (fipe_suspend() == 0) {
			rc = DDI_SUCCESS;
		}
		break;

	default:
		break;
	}
	mutex_exit(&fipe_drv_lock);

	if (rc != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "!fipe: failed to detach or suspend device.");
	}

	return (rc);
}

static int
fipe_quiesce(dev_info_t *dip)
{
	if (dip != fipe_drv_dip) {
		return (DDI_SUCCESS);
	}
	/* Quiesce hardware by stopping power management subsystem. */
	if (fipe_suspend() != 0) {
		cmn_err(CE_NOTE, "!fipe: failed to quiesce device.");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static struct cb_ops fipe_cb_ops = {
	fipe_open,
	fipe_close,
	nodev,		/* not a block driver */
	nodev,		/* no print routine */
	nodev,		/* no dump routine */
	nodev,		/* no read routine */
	nodev,		/* no write routine */
	fipe_ioctl,
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver */
	D_NEW | D_MP,	/* safe for multi-thread/multi-processor */
};

static struct dev_ops fipe_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	fipe_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	fipe_attach,		/* devo_attach */
	fipe_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&fipe_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	&fipe_quiesce,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Intel 5000/7300 memory controller driver",
	&fipe_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	fipe_drv_dip = NULL;
	mutex_init(&fipe_drv_lock, NULL, MUTEX_DRIVER, NULL);

	return (mod_install(&modlinkage));
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
		mutex_destroy(&fipe_drv_lock);
		fipe_drv_dip = NULL;
	}

	return (err);
}

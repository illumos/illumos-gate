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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>

#include <sys/ioat.h>

static int ioat_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int ioat_close(dev_t devp, int flag, int otyp, cred_t *cred);
static int ioat_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int ioat_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int ioat_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int ioat_quiesce(dev_info_t *dip);

static 	struct cb_ops ioat_cb_ops = {
	ioat_open,		/* cb_open */
	ioat_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	ioat_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_NEW | D_MP | D_64BIT | D_DEVMAP,	/* cb_flag */
	CB_REV
};

static struct dev_ops ioat_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ioat_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ioat_attach,		/* devo_attach */
	ioat_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ioat_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ioat_quiesce,		/* devo_quiesce */
};

static struct modldrv ioat_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"ioat driver",		/* Name of the module. */
	&ioat_dev_ops,		/* driver ops */
};

static struct modlinkage ioat_modlinkage = {
	MODREV_1,
	(void *) &ioat_modldrv,
	NULL
};


void *ioat_statep;

static int ioat_chip_init(ioat_state_t *state);
static void ioat_chip_fini(ioat_state_t *state);
static int ioat_drv_init(ioat_state_t *state);
static void ioat_drv_fini(ioat_state_t *state);
static uint_t ioat_isr(caddr_t parm);
static void ioat_intr_enable(ioat_state_t *state);
static void ioat_intr_disable(ioat_state_t *state);
void ioat_detach_finish(ioat_state_t *state);


ddi_device_acc_attr_t ioat_acc_attr = {
	DDI_DEVICE_ATTR_V0,		/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,		/* devacc_attr_endian_flags */
	DDI_STORECACHING_OK_ACC,	/* devacc_attr_dataorder */
	DDI_DEFAULT_ACC			/* devacc_attr_access */
};

/* dcopy callback interface */
dcopy_device_cb_t ioat_cb = {
	DCOPY_DEVICECB_V0,
	0,		/* reserved */
	ioat_channel_alloc,
	ioat_channel_free,
	ioat_cmd_alloc,
	ioat_cmd_free,
	ioat_cmd_post,
	ioat_cmd_poll,
	ioat_unregister_complete
};

/*
 * _init()
 */
int
_init(void)
{
	int e;

	e = ddi_soft_state_init(&ioat_statep, sizeof (ioat_state_t), 1);
	if (e != 0) {
		return (e);
	}

	e = mod_install(&ioat_modlinkage);
	if (e != 0) {
		ddi_soft_state_fini(&ioat_statep);
		return (e);
	}

	return (0);
}

/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ioat_modlinkage, modinfop));
}

/*
 * _fini()
 */
int
_fini(void)
{
	int e;

	e = mod_remove(&ioat_modlinkage);
	if (e != 0) {
		return (e);
	}

	ddi_soft_state_fini(&ioat_statep);

	return (0);
}

/*
 * ioat_attach()
 */
static int
ioat_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ioat_state_t *state;
	int instance;
	int e;


	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		state = ddi_get_soft_state(ioat_statep, instance);
		if (state == NULL) {
			return (DDI_FAILURE);
		}
		e = ioat_channel_resume(state);
		if (e != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		ioat_intr_enable(state);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	e = ddi_soft_state_zalloc(ioat_statep, instance);
	if (e != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	state = ddi_get_soft_state(ioat_statep, instance);
	if (state == NULL) {
		goto attachfail_get_soft_state;
	}

	state->is_dip = dip;
	state->is_instance = instance;

	/* setup the registers, save away some device info */
	e = ioat_chip_init(state);
	if (e != DDI_SUCCESS) {
		goto attachfail_chip_init;
	}

	/* initialize driver state, must be after chip init */
	e = ioat_drv_init(state);
	if (e != DDI_SUCCESS) {
		goto attachfail_drv_init;
	}

	/* create the minor node (for the ioctl) */
	e = ddi_create_minor_node(dip, "ioat", S_IFCHR, instance, DDI_PSEUDO,
	    0);
	if (e != DDI_SUCCESS) {
		goto attachfail_minor_node;
	}

	/* Enable device interrupts */
	ioat_intr_enable(state);

	/* Report that driver was loaded */
	ddi_report_dev(dip);

	/* register with dcopy */
	e = dcopy_device_register(state, &state->is_deviceinfo,
	    &state->is_device_handle);
	if (e != DCOPY_SUCCESS) {
		goto attachfail_register;
	}

	return (DDI_SUCCESS);

attachfail_register:
	ioat_intr_disable(state);
	ddi_remove_minor_node(dip, NULL);
attachfail_minor_node:
	ioat_drv_fini(state);
attachfail_drv_init:
	ioat_chip_fini(state);
attachfail_chip_init:
attachfail_get_soft_state:
	(void) ddi_soft_state_free(ioat_statep, instance);

	return (DDI_FAILURE);
}

/*
 * ioat_detach()
 */
static int
ioat_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ioat_state_t *state;
	int instance;
	int e;


	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(ioat_statep, instance);
	if (state == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		ioat_channel_suspend(state);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 * try to unregister from dcopy.  Since this driver doesn't follow the
	 * traditional parent/child model, we may still be in use so we can't
	 * detach yet.
	 */
	e = dcopy_device_unregister(&state->is_device_handle);
	if (e != DCOPY_SUCCESS) {
		if (e == DCOPY_PENDING) {
			cmn_err(CE_NOTE, "device busy, performing asynchronous"
			    " detach\n");
		}
		return (DDI_FAILURE);
	}

	ioat_detach_finish(state);

	return (DDI_SUCCESS);
}

/*
 * ioat_getinfo()
 */
/*ARGSUSED*/
static int
ioat_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	ioat_state_t *state;
	int instance;
	dev_t dev;
	int e;


	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		state = ddi_get_soft_state(ioat_statep, instance);
		if (state == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *)state->is_dip;
		e = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		e = DDI_SUCCESS;
		break;

	default:
		e = DDI_FAILURE;
		break;
	}

	return (e);
}


/*
 * ioat_open()
 */
/*ARGSUSED*/
static int
ioat_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	ioat_state_t *state;
	int instance;

	instance = getminor(*devp);
	state = ddi_get_soft_state(ioat_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	return (0);
}


/*
 * ioat_close()
 */
/*ARGSUSED*/
static int
ioat_close(dev_t devp, int flag, int otyp, cred_t *cred)
{
	return (0);
}


/*
 * ioat_chip_init()
 */
static int
ioat_chip_init(ioat_state_t *state)
{
	ddi_device_acc_attr_t attr;
	int e;


	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	e =  ddi_regs_map_setup(state->is_dip, 1, (caddr_t *)&state->is_genregs,
	    0, 0, &attr, &state->is_reg_handle);
	if (e != DDI_SUCCESS) {
		goto chipinitfail_regsmap;
	}

	/* save away ioat chip info */
	state->is_num_channels = (uint_t)ddi_get8(state->is_reg_handle,
	    &state->is_genregs[IOAT_CHANCNT]);

	/*
	 * If we get a bogus value, something is wrong with the H/W, fail to
	 * attach.
	 */
	if (state->is_num_channels == 0) {
		goto chipinitfail_numchan;
	}

	state->is_maxxfer = (uint_t)ddi_get8(state->is_reg_handle,
	    &state->is_genregs[IOAT_XFERCAP]);
	state->is_chanoff = (uintptr_t)ddi_get16(state->is_reg_handle,
	    (uint16_t *)&state->is_genregs[IOAT_PERPORT_OFF]);
	state->is_cbver = (uint_t)ddi_get8(state->is_reg_handle,
	    &state->is_genregs[IOAT_CBVER]);
	state->is_intrdelay = (uint_t)ddi_get16(state->is_reg_handle,
	    (uint16_t *)&state->is_genregs[IOAT_INTRDELAY]);
	state->is_status = (uint_t)ddi_get16(state->is_reg_handle,
	    (uint16_t *)&state->is_genregs[IOAT_CSSTATUS]);
	state->is_capabilities = (uint_t)ddi_get32(state->is_reg_handle,
	    (uint32_t *)&state->is_genregs[IOAT_DMACAPABILITY]);

	if (state->is_cbver & 0x10) {
		state->is_ver = IOAT_CBv1;
	} else if (state->is_cbver & 0x20) {
		state->is_ver = IOAT_CBv2;
	} else {
		goto chipinitfail_version;
	}

	return (DDI_SUCCESS);

chipinitfail_version:
chipinitfail_numchan:
	ddi_regs_map_free(&state->is_reg_handle);
chipinitfail_regsmap:
	return (DDI_FAILURE);
}


/*
 * ioat_chip_fini()
 */
static void
ioat_chip_fini(ioat_state_t *state)
{
	ddi_regs_map_free(&state->is_reg_handle);
}


/*
 * ioat_drv_init()
 */
static int
ioat_drv_init(ioat_state_t *state)
{
	ddi_acc_handle_t handle;
	int e;


	mutex_init(&state->is_mutex, NULL, MUTEX_DRIVER, NULL);

	state->is_deviceinfo.di_dip = state->is_dip;
	state->is_deviceinfo.di_num_dma = state->is_num_channels;
	state->is_deviceinfo.di_maxxfer = state->is_maxxfer;
	state->is_deviceinfo.di_capabilities = state->is_capabilities;
	state->is_deviceinfo.di_cb = &ioat_cb;

	e = pci_config_setup(state->is_dip, &handle);
	if (e != DDI_SUCCESS) {
		goto drvinitfail_config_setup;
	}

	/* read in Vendor ID */
	state->is_deviceinfo.di_id = (uint64_t)pci_config_get16(handle, 0);
	state->is_deviceinfo.di_id = state->is_deviceinfo.di_id << 16;

	/* read in Device ID */
	state->is_deviceinfo.di_id |= (uint64_t)pci_config_get16(handle, 2);
	state->is_deviceinfo.di_id = state->is_deviceinfo.di_id << 32;

	/* Add in chipset version */
	state->is_deviceinfo.di_id |= (uint64_t)state->is_cbver;
	pci_config_teardown(&handle);

	e = ddi_intr_hilevel(state->is_dip, 0);
	if (e != 0) {
		cmn_err(CE_WARN, "hilevel interrupt not supported\n");
		goto drvinitfail_hilevel;
	}

	/* we don't support MSIs for v2 yet */
	e = ddi_add_intr(state->is_dip, 0, NULL, NULL, ioat_isr,
	    (caddr_t)state);
	if (e != DDI_SUCCESS) {
		goto drvinitfail_add_intr;
	}

	e = ddi_get_iblock_cookie(state->is_dip, 0, &state->is_iblock_cookie);
	if (e != DDI_SUCCESS) {
		goto drvinitfail_iblock_cookie;
	}

	e = ioat_channel_init(state);
	if (e != DDI_SUCCESS) {
		goto drvinitfail_channel_init;
	}

	return (DDI_SUCCESS);

drvinitfail_channel_init:
drvinitfail_iblock_cookie:
	ddi_remove_intr(state->is_dip, 0, state->is_iblock_cookie);
drvinitfail_add_intr:
drvinitfail_hilevel:
drvinitfail_config_setup:
	mutex_destroy(&state->is_mutex);

	return (DDI_FAILURE);
}


/*
 * ioat_drv_fini()
 */
static void
ioat_drv_fini(ioat_state_t *state)
{
	ioat_channel_fini(state);
	ddi_remove_intr(state->is_dip, 0, state->is_iblock_cookie);
	mutex_destroy(&state->is_mutex);
}


/*
 * ioat_unregister_complete()
 */
void
ioat_unregister_complete(void *device_private, int status)
{
	ioat_state_t *state;


	state = device_private;

	if (status != DCOPY_SUCCESS) {
		cmn_err(CE_WARN, "asynchronous detach aborted\n");
		return;
	}

	cmn_err(CE_CONT, "detach completing\n");
	ioat_detach_finish(state);
}


/*
 * ioat_detach_finish()
 */
void
ioat_detach_finish(ioat_state_t *state)
{
	ioat_intr_disable(state);
	ddi_remove_minor_node(state->is_dip, NULL);
	ioat_drv_fini(state);
	ioat_chip_fini(state);
	(void) ddi_soft_state_free(ioat_statep, state->is_instance);
}


/*
 * ioat_intr_enable()
 */
static void
ioat_intr_enable(ioat_state_t *state)
{
	uint32_t intr_status;


	/* Clear any pending interrupts */
	intr_status = ddi_get32(state->is_reg_handle,
	    (uint32_t *)&state->is_genregs[IOAT_ATTNSTATUS]);
	if (intr_status != 0) {
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&state->is_genregs[IOAT_ATTNSTATUS],
		    intr_status);
	}

	/* Enable interrupts on the device */
	ddi_put8(state->is_reg_handle, &state->is_genregs[IOAT_INTRCTL],
	    IOAT_INTRCTL_MASTER_EN);
}


/*
 * ioat_intr_disable()
 */
static void
ioat_intr_disable(ioat_state_t *state)
{
	/*
	 * disable interrupts on the device. A read of the interrupt control
	 * register clears the enable bit.
	 */
	(void) ddi_get8(state->is_reg_handle,
	    &state->is_genregs[IOAT_INTRCTL]);
}


/*
 * ioat_isr()
 */
static uint_t
ioat_isr(caddr_t parm)
{
	uint32_t intr_status;
	ioat_state_t *state;
	uint8_t intrctrl;
	uint32_t chan;
	uint_t r;
	int i;

	state = (ioat_state_t *)parm;

	intrctrl = ddi_get8(state->is_reg_handle,
	    &state->is_genregs[IOAT_INTRCTL]);
	/* master interrupt enable should always be set */
	ASSERT(intrctrl & IOAT_INTRCTL_MASTER_EN);

	/* If the interrupt status bit isn't set, it's not ours */
	if (!(intrctrl & IOAT_INTRCTL_INTR_STAT)) {
		/* re-set master interrupt enable (since it clears on read) */
		ddi_put8(state->is_reg_handle,
		    &state->is_genregs[IOAT_INTRCTL], intrctrl);
		return (DDI_INTR_UNCLAIMED);
	}

	/* see which channels generated the interrupt */
	intr_status = ddi_get32(state->is_reg_handle,
	    (uint32_t *)&state->is_genregs[IOAT_ATTNSTATUS]);

	/* call the intr handler for the channels */
	r = DDI_INTR_UNCLAIMED;
	chan = 1;
	for (i = 0; i < state->is_num_channels; i++) {
		if (intr_status & chan) {
			ioat_channel_intr(&state->is_channel[i]);
			r = DDI_INTR_CLAIMED;
		}
		chan = chan << 1;
	}

	/*
	 * if interrupt status bit was set, there should have been an
	 * attention status bit set too.
	 */
	ASSERT(r == DDI_INTR_CLAIMED);

	/* re-set master interrupt enable (since it clears on read) */
	ddi_put8(state->is_reg_handle, &state->is_genregs[IOAT_INTRCTL],
	    intrctrl);

	return (r);
}

static int
ioat_quiesce(dev_info_t *dip)
{
	ioat_state_t *state;
	int instance;

	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(ioat_statep, instance);
	if (state == NULL) {
		return (DDI_FAILURE);
	}

	ioat_intr_disable(state);
	ioat_channel_quiesce(state);

	return (DDI_SUCCESS);
}

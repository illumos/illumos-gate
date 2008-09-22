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


/*
 * i2bsc.c is the nexus driver i2c traffic against devices hidden behind the
 * Blade Support Chip (BSC).  It supports both interrupt and polled
 * mode operation, but defaults to interrupt.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/platform_module.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/log.h>
#include <sys/debug.h>
#include <sys/note.h>

#include <sys/bscbus.h>
#include <sys/lom_ebuscodes.h>

#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/misc/i2c_svc_impl.h>
#include <sys/i2c/nexus/i2bsc_impl.h>

/*
 * static function declarations
 */
static void i2bsc_resume(dev_info_t *dip);
static void i2bsc_suspend(dev_info_t *dip);
static int i2bsc_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
static  void i2bsc_acquire(i2bsc_t *, dev_info_t *dip,
	i2c_transfer_t *tp);
static  void i2bsc_release(i2bsc_t *);
static int i2bsc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int i2bsc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int i2bsc_open(dev_t *devp, int flag, int otyp,
    cred_t *cred_p);
static int i2bsc_close(dev_t dev, int flag, int otyp,
    cred_t *cred_p);
static int i2bsc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int i2bsc_initchild(dev_info_t *dip, dev_info_t *cdip);
static int i2bsc_uninitchild(dev_info_t *dip, dev_info_t *cdip);
static int i2bsc_setup_regs(i2bsc_t *);
static void i2bsc_start_session(i2bsc_t *);
static void i2bsc_fail_session(i2bsc_t *);
static int i2bsc_end_session(i2bsc_t *);
static void i2bsc_free_regs(i2bsc_t *);
static int i2bsc_reportdev(dev_info_t *dip, dev_info_t *rdip);
int i2bsc_transfer(dev_info_t *dip, i2c_transfer_t *tp);
static void i2bsc_trace(i2bsc_t *, char, const char *,
    const char *, ...);
static int i2bsc_notify_max_transfer_size(i2bsc_t *);
static int i2bsc_discover_capability(i2bsc_t *);
static void i2bsc_put8(i2bsc_t *, uint8_t, uint8_t, uint8_t);
static uint8_t i2bsc_get8(i2bsc_t *, uint8_t, uint8_t);
static int i2bsc_safe_upload(i2bsc_t *, i2c_transfer_t *);
static boolean_t i2bsc_is_firmware_broken(i2bsc_t *);

static struct bus_ops i2bsc_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	NULL,				/* bus_map_fault */
	ddi_no_dma_map,			/* bus_dma_map */
	ddi_no_dma_allochdl,		/* bus_dma_allochdl */
	ddi_no_dma_freehdl,		/* bus_dma_freehdl */
	ddi_no_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_no_dma_unbindhdl,		/* bus_unbindhdl */
	ddi_no_dma_flush,		/* bus_dma_flush */
	ddi_no_dma_win,			/* bus_dma_win */
	ddi_no_dma_mctl,		/* bus_dma_ctl */
	i2bsc_bus_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_eventcall */
	NULL,				/* bus_post_event */
	0,				/* bus_intr_ctl */
	0,				/* bus_config		*/
	0,				/* bus_unconfig		*/
	0,				/* bus_fm_init		*/
	0,				/* bus_fm_fini		*/
	0,				/* bus_fm_access_enter	*/
	0,				/* bus_fm_access_exit	*/
	0,				/* bus_power		*/
	i_ddi_intr_ops			/* bus_intr_op		*/

};

struct cb_ops i2bsc_cb_ops = {
	i2bsc_open,		/* open */
	i2bsc_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	i2bsc_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_MP | D_NEW		/* Driver compatibility flag */
};

static struct dev_ops i2bsc_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	i2bsc_attach,
	i2bsc_detach,
	nodev,
	&i2bsc_cb_ops,
	&i2bsc_busops,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

#ifdef DEBUG
#define	I2BSC_VERSION_STRING "i2bsc driver - Debug"
#else
#define	I2BSC_VERSION_STRING "i2bsc driver"
#endif

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	I2BSC_VERSION_STRING,	/* Name of the module. */
	&i2bsc_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * i2bsc soft state
 */
static void	*i2bsc_state;

i2c_nexus_reg_t i2bsc_regvec = {
	I2C_NEXUS_REV,
	i2bsc_transfer,
};

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&i2bsc_state, sizeof (i2bsc_t),
	    I2BSC_INITIAL_SOFT_SPACE);
	if (status != 0) {
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&i2bsc_state);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&i2bsc_state);
	}

	return (status);
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
i2bsc_dodetach(dev_info_t *dip)
{
	i2bsc_t *i2c;
	int instance = ddi_get_instance(dip);

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);

	if ((i2c->i2bsc_attachflags & IMUTEX) != 0) {
		mutex_destroy(&i2c->i2bsc_imutex);
		cv_destroy(&i2c->i2bsc_icv);
	}
	if ((i2c->i2bsc_attachflags & SETUP_REGS) != 0) {
		i2bsc_free_regs(i2c);
	}
	if ((i2c->i2bsc_attachflags & NEXUS_REGISTER) != 0) {
		i2c_nexus_unregister(dip);
	}
	if ((i2c->i2bsc_attachflags & MINOR_NODE) != 0) {
		ddi_remove_minor_node(dip, NULL);
	}

	ddi_soft_state_free(i2bsc_state, instance);
}

static int
i2bsc_doattach(dev_info_t *dip)
{
	i2bsc_t *i2c;
	int instance = ddi_get_instance(dip);

	/*
	 * Allocate soft state structure.
	 */
	if (ddi_soft_state_zalloc(i2bsc_state, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);

	i2c->majornum = ddi_driver_major(dip);
	i2c->minornum = instance;
	i2c->i2bsc_dip = dip;
	i2c->debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "debug", 0);

	(void) snprintf(i2c->i2bsc_name, sizeof (i2c->i2bsc_name),
	    "%s_%d", ddi_node_name(dip), instance);

	if (i2bsc_setup_regs(i2c) != DDI_SUCCESS) {
		goto bad;
	}

	i2c->i2bsc_attachflags |= SETUP_REGS;

	mutex_init(&i2c->i2bsc_imutex, NULL, MUTEX_DRIVER,
	    (void *) 0);
	cv_init(&i2c->i2bsc_icv, NULL, CV_DRIVER, NULL);
	i2c->i2bsc_attachflags |= IMUTEX;

	i2c_nexus_register(dip, &i2bsc_regvec);
	i2c->i2bsc_attachflags |= NEXUS_REGISTER;

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed",
		    i2c->i2bsc_name);
		goto bad;
	}

	i2c->i2bsc_attachflags |= MINOR_NODE;

	/*
	 * Now actually start talking to the microcontroller.  The first
	 * thing to check is whether the firmware is broken.
	 */
	if (i2bsc_is_firmware_broken(i2c)) {
		cmn_err(CE_WARN, "Underlying BSC hardware not communicating;"
		    " shutting down my i2c services");
		goto bad;
	}

	i2c->i2bsc_attachflags |= FIRMWARE_ALIVE;

	/*
	 * Now see if the BSC chip supports the i2c service we rely upon.
	 */
	(void) i2bsc_discover_capability(i2c);

	if (i2bsc_notify_max_transfer_size(i2c) == DDI_SUCCESS)
		i2c->i2bsc_attachflags |= TRANSFER_SZ;

	i2bsc_trace(i2c, 'A', "i2bsc_doattach", "attachflags %d",
	    i2c->i2bsc_attachflags);

	return (DDI_SUCCESS);

bad:
	i2bsc_dodetach(dip);

	return (DDI_FAILURE);
}

static int
i2bsc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_ATTACH:
		return (i2bsc_doattach(dip));

		case DDI_RESUME:
		i2bsc_resume(dip);
		return (DDI_SUCCESS);

		default:
		return (DDI_FAILURE);
	}
}

static int
i2bsc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		i2bsc_dodetach(dip);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		i2bsc_suspend(dip);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
i2bsc_open(dev_t  *devp,  int  flag,  int  otyp,  cred_t *cred_p)
{
	int instance;
	i2bsc_t *i2c;

	/*
	 * Make sure the open is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);
	if (i2c == NULL)
		return (ENXIO);

	/*
	 * Enforce exclusive access
	 */
	mutex_enter(&i2c->i2bsc_imutex);
	if (i2c->i2bsc_open) {
		mutex_exit(&i2c->i2bsc_imutex);
		return (EBUSY);
	} else
		i2c->i2bsc_open = 1;

	mutex_exit(&i2c->i2bsc_imutex);

	return (0);
}

/*ARGSUSED*/
static int
i2bsc_close(dev_t  dev,  int  flag,  int  otyp,  cred_t *cred_p)
{
	int instance;
	i2bsc_t *i2c;

	/*
	 * Make sure the close is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(dev);
	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);
	if (i2c == NULL)
		return (ENXIO);

	mutex_enter(&i2c->i2bsc_imutex);
	i2c->i2bsc_open = 0;
	mutex_exit(&i2c->i2bsc_imutex);

	return (0);
}

/*ARGSUSED*/
static int
i2bsc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	i2bsc_t *i2c;
	dev_info_t *self;
	dev_info_t *child;
	struct devctl_iocdata *dcp;
	int rv;

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, getminor(dev));

	if (i2c == NULL)
		return (ENXIO);

	self = (dev_info_t *)i2c->i2bsc_dip;

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS) {
		return (EFAULT);
	}

	switch (cmd) {
		case DEVCTL_BUS_DEV_CREATE:
		rv = ndi_dc_devi_create(dcp, self, 0, NULL);
		break;

		case DEVCTL_DEVICE_REMOVE:
		if (ndi_dc_getname(dcp) == NULL ||
		    ndi_dc_getaddr(dcp) == NULL) {
			rv = EINVAL;
			break;
		}

		/*
		 * lookup and hold child device
		 */
		child = ndi_devi_find(self,
		    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));
		if (child == NULL) {
			rv = ENXIO;
			break;
		}

		if ((rv = ndi_devi_offline(child, NDI_DEVI_REMOVE)) !=
		    NDI_SUCCESS) {
			rv = (rv == NDI_BUSY) ? EBUSY : EIO;
		}

		break;

		default:
		rv = ENOTSUP;
	}

	ndi_dc_freehdl(dcp);

	return (rv);
}

static int
i2bsc_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result)
{
	i2bsc_t	*i2c;
	int instance = ddi_get_instance(dip);

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);

	i2bsc_trace(i2c, 'A', "i2bsc_bus_ctl", "dip/rdip,op/arg"
	    " %p/%p,%d/%p", dip, rdip, (int)op, arg);

	switch (op) {
		case DDI_CTLOPS_INITCHILD:
		return (i2bsc_initchild(dip, (dev_info_t *)arg));

		case DDI_CTLOPS_UNINITCHILD:
		return (i2bsc_uninitchild(dip, (dev_info_t *)arg));

		case DDI_CTLOPS_REPORTDEV:
		return (i2bsc_reportdev(dip, rdip));

		case DDI_CTLOPS_DMAPMAPC:
		case DDI_CTLOPS_POKE:
		case DDI_CTLOPS_PEEK:
		case DDI_CTLOPS_IOMIN:
		case DDI_CTLOPS_REPORTINT:
		case DDI_CTLOPS_SIDDEV:
		case DDI_CTLOPS_SLAVEONLY:
		case DDI_CTLOPS_AFFINITY:
		case DDI_CTLOPS_PTOB:
		case DDI_CTLOPS_BTOP:
		case DDI_CTLOPS_BTOPR:
		case DDI_CTLOPS_DVMAPAGESIZE:
		return (DDI_FAILURE);

		default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}

/*
 * i2bsc_suspend() is called before the system suspends.  Existing
 * transfer in progress or waiting will complete, but new transfers are
 * effectively blocked by "acquiring" the bus.
 */
static void
i2bsc_suspend(dev_info_t *dip)
{
	i2bsc_t *i2c;
	int instance;

	instance = ddi_get_instance(dip);
	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);

	i2bsc_acquire(i2c, NULL, NULL);
}

/*
 * i2bsc_resume() is called when the system resumes from CPR.  It releases
 * the hold that was placed on the i2c bus, which allows any real
 * transfers to continue.
 */
static void
i2bsc_resume(dev_info_t *dip)
{
	i2bsc_t *i2c;
	int instance;

	instance = ddi_get_instance(dip);
	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, instance);

	i2bsc_release(i2c);
}

/*
 * i2bsc_acquire() is called by a thread wishing to "own" the I2C bus.
 * It should not be held across multiple transfers.
 */
static void
i2bsc_acquire(i2bsc_t *i2c, dev_info_t *dip, i2c_transfer_t *tp)
{
	mutex_enter(&i2c->i2bsc_imutex);
	while (i2c->i2bsc_busy) {
		cv_wait(&i2c->i2bsc_icv, &i2c->i2bsc_imutex);
	}
	i2c->i2bsc_busy = 1;
	i2c->i2bsc_cur_tran = tp;
	i2c->i2bsc_cur_dip = dip;
	mutex_exit(&i2c->i2bsc_imutex);
}

/*
 * i2bsc_release() is called to release a hold made by i2bsc_acquire().
 */
static void
i2bsc_release(i2bsc_t *i2c)
{
	mutex_enter(&i2c->i2bsc_imutex);
	i2c->i2bsc_busy = 0;
	i2c->i2bsc_cur_tran = NULL;
	cv_signal(&i2c->i2bsc_icv);
	mutex_exit(&i2c->i2bsc_imutex);
}

static int
i2bsc_initchild(dev_info_t *dip, dev_info_t *cdip)
{
	i2bsc_t *i2c;
	int32_t address_cells;
	int len;
	int32_t regs[3];
	int err;
	i2bsc_ppvt_t *ppvt;
	char name[30];

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, ddi_get_instance(dip));

	i2bsc_trace(i2c, 'A', "i2bsc_initchild", "dip/cdip %p/%p", dip, cdip);

	ppvt = kmem_alloc(sizeof (i2bsc_ppvt_t), KM_SLEEP);

	len = sizeof (address_cells);

	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_CANSLEEP, "#address-cells",
	    (caddr_t)&address_cells, &len);
	if (err != DDI_PROP_SUCCESS || len != sizeof (address_cells)) {
		return (DDI_FAILURE);
	}

	len = sizeof (regs);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)regs, &len);
	if (err != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (address_cells == 1) {
		ppvt->i2bsc_ppvt_bus = I2BSC_DEFAULT_BUS;
		ppvt->i2bsc_ppvt_addr = regs[0];
		(void) sprintf(name, "%x", regs[0]);
		i2bsc_trace(i2c, 'A', "i2bsc_initchild", "#address-cells = 1"
		    " regs[0] = %d", regs[0]);
	} else if (address_cells == 2) {
		ppvt->i2bsc_ppvt_bus = regs[0];
		ppvt->i2bsc_ppvt_addr = regs[1];
		(void) sprintf(name, "%x,%x", regs[0], regs[1]);
		i2bsc_trace(i2c, 'A', "i2bsc_initchild", "#address-cells = 2"
		    " regs[0] = %d, regs[1] = %d", regs[0], regs[1]);
	} else {
		return (DDI_FAILURE);
	}

	/*
	 * Attach the parent's private data structure to the child's devinfo
	 * node, and store the child's address on the nexus in the child's
	 * devinfo node.
	 */
	ddi_set_parent_data(cdip, ppvt);
	ddi_set_name_addr(cdip, name);

	i2bsc_trace(i2c, 'A', "i2bsc_initchild", "success(%s)",
	    ddi_node_name(cdip));

	return (DDI_SUCCESS);
}

static int
i2bsc_uninitchild(dev_info_t *dip, dev_info_t *cdip)
{
	i2bsc_t *i2c;
	i2bsc_ppvt_t *ppvt;

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state, ddi_get_instance(dip));

	i2bsc_trace(i2c, 'D', "i2bsc_uninitchild", "dip/cdip %p/%p", dip, cdip);

	ppvt = ddi_get_parent_data(cdip);
	kmem_free(ppvt, sizeof (i2bsc_ppvt_t));

	ddi_set_parent_data(cdip, NULL);
	ddi_set_name_addr(cdip, NULL);

	i2bsc_trace(i2c, 'D', "i2bsc_uninitchild", "success(%s)",
	    ddi_node_name(cdip));

	return (DDI_SUCCESS);
}

/*
 * i2bsc_setup_regs() is called to map in registers specific to
 * the i2bsc.
 */
static int
i2bsc_setup_regs(i2bsc_t *i2c)
{
	int nregs;

	i2c->bscbus_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	i2c->bscbus_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	i2c->bscbus_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_dev_nregs(i2c->i2bsc_dip, &nregs) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (nregs < 1) {
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(i2c->i2bsc_dip, 0,
	    (caddr_t *)&i2c->bscbus_regs, 0, 0, &i2c->bscbus_attr,
	    &i2c->bscbus_handle) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * i2bsc_free_regs() frees any registers previously
 * allocated.
 */
static void
i2bsc_free_regs(i2bsc_t *i2c)
{
	if (i2c->bscbus_regs != NULL) {
		ddi_regs_map_free(&i2c->bscbus_handle);
	}
}

/*ARGSUSED*/
static int
i2bsc_reportdev(dev_info_t *dip, dev_info_t *rdip)
{
	if (rdip == (dev_info_t *)0)
		return (DDI_FAILURE);

	cmn_err(CE_CONT, "?i2bsc-device: %s@%s, %s%d\n",
	    ddi_node_name(rdip), ddi_get_name_addr(rdip), ddi_driver_name(rdip),
	    ddi_get_instance(rdip));

	return (DDI_SUCCESS);
}

/*
 * I/O Functions
 *
 * i2bsc_{put,get}8_once are wrapper functions to ddi_{get,put}8.
 * i2bsc_{put,get}8 are equivalent functions but with retry code.
 * i2bsc_bscbus_state determines underlying bus error status.
 * i2bsc_clear_acc_fault clears the underlying bus error status.
 *
 * I/O Flags
 *
 * bscbus_fault	   -	Error register in underlying bus for last IO operation.
 * session_failure - 	Set by any failed IO command.  This is a sticky flag
 * 			reset explicitly using i2bsc_start_session
 *
 * Session Management
 *
 * i2bsc_{start,end}_session need to be used to detect an error across multiple
 * gets/puts rather than having to test for an error on each get/put.
 */

static int i2bsc_bscbus_state(i2bsc_t *i2c)
{
	uint32_t retval;

	retval = ddi_get32(i2c->bscbus_handle,
	    (uint32_t *)I2BSC_NEXUS_ADDR(i2c, EBUS_CMD_SPACE_GENERIC,
	    LOMBUS_FAULT_REG));
	i2c->bscbus_fault = retval;

	return ((retval == 0) ? DDI_SUCCESS : DDI_FAILURE);
}

static void i2bsc_clear_acc_fault(i2bsc_t *i2c)
{
	i2bsc_trace(i2c, '@', "i2bsc_clear_acc_fault", "clearing acc fault");
	ddi_put32(i2c->bscbus_handle,
	    (uint32_t *)I2BSC_NEXUS_ADDR(i2c, EBUS_CMD_SPACE_GENERIC,
	    LOMBUS_FAULT_REG), 0);
}

static void
i2bsc_start_session(i2bsc_t *i2c)
{
	i2bsc_trace(i2c, 'S', "i2bsc_start_session", "session started");
	i2c->bscbus_session_failure = 0;
}

static void
i2bsc_fail_session(i2bsc_t *i2c)
{
	i2bsc_trace(i2c, 'S', "i2bsc_fail_session", "session failed");
	i2c->bscbus_session_failure = 1;
}

static int
i2bsc_end_session(i2bsc_t *i2c)
{
	/*
	 * The ONLY way to get the session status is to end the session.
	 * If clients of the session interface ever wanted the status mid-way
	 * then they are really working with multiple contigious sessions.
	 */
	i2bsc_trace(i2c, 'S', "i2bsc_end_session", "session ended with %d",
	    i2c->bscbus_session_failure);
	return ((i2c->bscbus_session_failure) ? DDI_FAILURE : DDI_SUCCESS);
}

static boolean_t
i2bsc_is_firmware_broken(i2bsc_t *i2c)
{
	int i;
	int niterations = I2BSC_SHORT_RETRY_LIMIT;

	i2bsc_trace(i2c, 'A', "i2bsc_is_firmware_broken", "called");

	for (i = 0; i < niterations; i++) {
		(void) ddi_get8(i2c->bscbus_handle,
		    I2BSC_NEXUS_ADDR(i2c, EBUS_CMD_SPACE_I2C,
		    EBUS_IDX12_RESULT));
		if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS) {
			i2bsc_clear_acc_fault(i2c);
			continue;
		} else {
			/*
			 * Firmware communication succeeded.
			 */
			i2bsc_trace(i2c, 'A', "i2bsc_is_firmware_broken",
			    "firmware communications okay");
			return (B_FALSE);
		}
	}

	/*
	 * Firmware is not communicative.  Some possible causes :
	 *	Broken hardware
	 *	BSC held in reset
	 *	Corrupt BSC image
	 *	OBP incompatiblity preventing drivers loading properly
	 */
	i2bsc_trace(i2c, 'A', "i2bsc_is_firmware_broken", "%d read fails",
	    niterations);
	return (B_TRUE);
}

static void
i2bsc_put8(i2bsc_t *i2c, uint8_t space, uint8_t index, uint8_t value)
{
	int retryable = I2BSC_RETRY_LIMIT;

	i2bsc_trace(i2c, '@', "i2bsc_put8", "(space,index)<-val (%d,%d)<-%d",
	    space, index, value);

	i2bsc_clear_acc_fault(i2c);

	/*
	 * If a session failure has already occurred, reduce the level of
	 * retries to a minimum.  This is a optimization of the failure
	 * recovery strategy.
	 */
	if (i2c->bscbus_session_failure)
		retryable = 1;

	while (retryable--) {
		ddi_put8(i2c->bscbus_handle,
		    I2BSC_NEXUS_ADDR(i2c, space, index), value);
		if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS) {
			i2bsc_clear_acc_fault(i2c);
		} else
			break;
	}

	if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS)
		i2bsc_fail_session(i2c);

	i2bsc_trace(i2c, '@', "i2bsc_put8", "tried %d time(s)",
	    I2BSC_RETRY_LIMIT - retryable);
}

static uint8_t
i2bsc_get8(i2bsc_t *i2c, uint8_t space, uint8_t index)
{
	uint8_t value;
	int retryable = I2BSC_RETRY_LIMIT;

	i2bsc_clear_acc_fault(i2c);

	/*
	 * If a session failure has already occurred, reduce the level of
	 * retries to a minimum.  This is a optimization of the failure
	 * recovery strategy.
	 */
	if (i2c->bscbus_session_failure)
		retryable = 1;

	while (retryable--) {
		value = ddi_get8(i2c->bscbus_handle,
		    I2BSC_NEXUS_ADDR(i2c, space, index));
		if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS) {
			i2bsc_clear_acc_fault(i2c);
		} else
			break;
	}

	if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS)
		i2bsc_fail_session(i2c);

	i2bsc_trace(i2c, '@', "i2bsc_get8", "tried %d time(s)",
	    I2BSC_RETRY_LIMIT - retryable);

	i2bsc_trace(i2c, '@', "i2bsc_get8", "(space,index)->val (%d,%d)->%d",
	    space, index, value);
	return (value);
}

static void
i2bsc_put8_once(i2bsc_t *i2c, uint8_t space, uint8_t index, uint8_t value)
{
	i2bsc_trace(i2c, '@', "i2bsc_put8_once",
	    "(space,index)<-val (%d,%d)<-%d", space, index, value);

	i2bsc_clear_acc_fault(i2c);

	ddi_put8(i2c->bscbus_handle,
	    I2BSC_NEXUS_ADDR(i2c, space, index), value);

	if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS)
		i2bsc_fail_session(i2c);
}

static uint8_t
i2bsc_get8_once(i2bsc_t *i2c, uint8_t space, uint8_t index)
{
	uint8_t value;

	i2bsc_clear_acc_fault(i2c);

	value = ddi_get8(i2c->bscbus_handle,
	    I2BSC_NEXUS_ADDR(i2c, space, index));

	if (i2bsc_bscbus_state(i2c) != DDI_SUCCESS)
		i2bsc_fail_session(i2c);

	i2bsc_trace(i2c, '@', "i2bsc_get8_once",
	    "(space,index)->val (%d,%d)->%d", space, index, value);

	return (value);
}

static int
i2bsc_notify_max_transfer_size(i2bsc_t *i2c)
{
	/*
	 * If the underlying hardware does not support the i2c service and
	 * we are not running in fake_mode, then we cannot set the
	 * MAX_TRANSFER_SZ.
	 */
	if (i2c->i2c_proxy_support == 0)
		return (DDI_FAILURE);

	i2bsc_start_session(i2c);

	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_MAX_TRANSFER_SZ,
	    I2BSC_MAX_TRANSFER_SZ);

	if (i2bsc_end_session(i2c) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * Discover if the microcontroller implements the I2C Proxy Service this
 * driver requires.  If it does not, i2c transactions will abort with
 * I2C_FAILURE, unless fake_mode is being used.
 */
static int
i2bsc_discover_capability(i2bsc_t *i2c)
{
	i2bsc_start_session(i2c);

	i2c->i2c_proxy_support = i2bsc_get8(i2c, EBUS_CMD_SPACE_GENERIC,
	    EBUS_IDX_CAP0);
	i2c->i2c_proxy_support &= EBUS_CAP0_I2C_PROXY;

	if (i2bsc_end_session(i2c) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
i2bsc_upload_preamble(i2bsc_t *i2c, i2c_transfer_t *tp)
{
	i2bsc_ppvt_t *ppvt;
	int wr_rd;

	ppvt = ddi_get_parent_data(i2c->i2bsc_cur_dip);

	/* Get a lock on the i2c devices owned by the microcontroller */
	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_TRANSACTION_LOCK, 1);
	if (!i2bsc_get8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_TRANSACTION_LOCK)) {
		/*
		 * i2c client driver must timeout retry, NOT this nexus
		 */
		tp->i2c_result = I2C_INCOMPLETE;
		i2bsc_trace(i2c, 'U', "i2bsc_upload_preamble",
		    "Couldn't get transaction lock");
		return (tp->i2c_result);
	}

	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_BUS_ADDRESS,
	    ppvt->i2bsc_ppvt_bus);

	/*
	 * The Solaris architecture for I2C uses 10-bit I2C addresses where
	 * bit-0 is zero (the read/write bit).  The microcontroller uses 7 bit
	 * I2C addresses (read/write bit excluded).  Hence we need to convert
	 * the address by bit-shifting.
	 */
	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_CLIENT_ADDRESS,
	    ppvt->i2bsc_ppvt_addr >> 1);

	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_TRANSFER_TYPE,
	    tp->i2c_flags);

	/*
	 * We have only one register used for data input and output.  When
	 * a WR_RD is issued, this means we want to do a Random-Access-Read.
	 * First a series of bytes are written which define the address to
	 * read from.  In hardware this sets an address pointer.  Then a series
	 * of bytes are read.  The read/write boundary tells you how many
	 * bytes are to be written before reads will be issued.
	 */
	if (tp->i2c_flags == I2C_WR_RD)
		wr_rd = tp->i2c_wlen;
	else
		wr_rd = 0;

	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_WR_RD_BOUNDARY, wr_rd);

	return (I2C_SUCCESS);
}

/*
 * Function	i2bsc_upload
 *
 * Description	This function runs the i2c transfer protocol down to the
 *		microcontroller.  Its goal is to be as reliable as possible.
 *		This is achieved by making all the state-less aspects
 *		re-tryable.  For stateful aspects, we take care to ensure the
 *		counters are decremented only when data transfer has been
 *		successful.
 */
static int
i2bsc_upload(i2bsc_t *i2c, i2c_transfer_t *tp)
{
	int quota = I2BSC_MAX_TRANSFER_SZ;
	uint8_t res;
	int residual;

	/*
	 * Total amount of data outstanding
	 */
	residual = tp->i2c_w_resid + tp->i2c_r_resid;

	/*
	 * Anything in this session *could* be re-tried without side-effects.
	 * Therefore, error exit codes are I2C_INCOMPLETE rather than
	 * I2C_FAILURE.
	 */
	i2bsc_start_session(i2c);
	if (i2bsc_upload_preamble(i2c, tp) != I2C_SUCCESS)
		return (I2C_INCOMPLETE);
	if (i2bsc_end_session(i2c) != DDI_SUCCESS)
		return (I2C_INCOMPLETE);

	/* The writes done here are not retryable */
	while (tp->i2c_w_resid && quota) {
		i2bsc_put8_once(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_DATA_INOUT,
		    tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid]);
		if (i2bsc_bscbus_state(i2c) == DDI_SUCCESS) {
			tp->i2c_w_resid--;
			quota--;
			residual--;
		} else {
			i2bsc_trace(i2c, 'T', "i2bsc_upload", "write failed");
			return (tp->i2c_result = I2C_INCOMPLETE);
		}
	}

	/* The reads done here are not retryable */
	while (tp->i2c_r_resid && quota) {
		tp->i2c_rbuf[tp->i2c_rlen - tp->i2c_r_resid] =
		    i2bsc_get8_once(i2c, EBUS_CMD_SPACE_I2C,
		    EBUS_IDX12_DATA_INOUT);
		if (i2bsc_bscbus_state(i2c) == DDI_SUCCESS) {
			tp->i2c_r_resid--;
			quota--;
			residual--;
		} else {
			i2bsc_trace(i2c, 'T', "i2bsc_upload", "read failed");
			return (tp->i2c_result = I2C_INCOMPLETE);
		}
	}

	i2bsc_start_session(i2c);

	/*
	 * A possible future enhancement would be to allow early breakout of the
	 * loops seen above.  In such circumstances, "residual" would be non-
	 * zero.  This may be useful if we want to support the interruption of
	 * transfer part way through an i2c_transfer_t.
	 */
	i2bsc_put8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_RESIDUAL_DATA, residual);
	res = i2bsc_get8(i2c, EBUS_CMD_SPACE_I2C, EBUS_IDX12_RESULT);
	if (i2bsc_end_session(i2c) != DDI_SUCCESS)
		return (tp->i2c_result = I2C_INCOMPLETE);

	switch (res) {
		case EBUS_I2C_SUCCESS:
		tp->i2c_result = I2C_SUCCESS;
		break;
		case EBUS_I2C_FAILURE:
		/*
		 * This is rare but possible.  A retry may still fix this
		 * so lets allow that by returning I2C_INCOMPLETE.
		 * "hifTxRing still contains 1 bytes" is reported by the
		 * microcontroller when this return value is seen.
		 */
		i2bsc_trace(i2c, 'T', "i2bsc_upload", "EBUS_I2C_FAILURE"
		    " but returning I2C_INCOMPLETE for possible re-try");
		tp->i2c_result = I2C_INCOMPLETE;
		break;
		case EBUS_I2C_INCOMPLETE:
		tp->i2c_result = I2C_INCOMPLETE;
		break;
		default:
		tp->i2c_result = I2C_FAILURE;
	}

	return (tp->i2c_result);
}

/*
 * Function	i2bsc_safe_upload
 *
 * Description	This function is called "safe"-upload because it attempts to
 *		do transaction re-tries for cases where state is not spoiled
 *		by a transaction-level retry.
 */
static int
i2bsc_safe_upload(i2bsc_t *i2c, i2c_transfer_t *tp)
{
	int retryable = I2BSC_RETRY_LIMIT;
	int result;

	i2bsc_trace(i2c, 'T', "i2bsc_safe_upload", "Transaction %s",
	    (tp->i2c_flags == I2C_WR_RD) ? "retryable" : "single-shot");

	/*
	 * The only re-tryable transaction type is I2C_WR_RD.  If we don't
	 * have this we can only use session-based recovery offered by
	 * i2bsc_upload.
	 */
	if (tp->i2c_flags != I2C_WR_RD)
		return (i2bsc_upload(i2c, tp));

	while (retryable--) {
		result = i2bsc_upload(i2c, tp);
		if (result == I2C_INCOMPLETE) {
			/* Have another go */
			tp->i2c_r_resid = tp->i2c_rlen;
			tp->i2c_w_resid = tp->i2c_wlen;
			tp->i2c_result = I2C_SUCCESS;
			i2bsc_trace(i2c, 'T', "i2bsc_safe_upload",
			    "Retried (%d)", I2BSC_RETRY_LIMIT - retryable);
			continue;
		} else {
			i2bsc_trace(i2c, 'T', "i2bsc_safe_upload",
			    "Exiting while loop on result %d", result);
			return (result);
		}
	}

	i2bsc_trace(i2c, 'T', "i2bsc_safe_upload", "Exiting on %d", result);
	return (result);
}

/*
 * Function	i2bsc_transfer
 *
 * Description	This is the entry-point that clients use via the Solaris i2c
 *		framework.  It kicks off the servicing of i2c transfer requests.
 */
int
i2bsc_transfer(dev_info_t *dip, i2c_transfer_t *tp)
{
	i2bsc_t *i2c;

	i2c = (i2bsc_t *)ddi_get_soft_state(i2bsc_state,
	    ddi_get_instance(ddi_get_parent(dip)));

	i2bsc_acquire(i2c, dip, tp);

	tp->i2c_r_resid = tp->i2c_rlen;
	tp->i2c_w_resid = tp->i2c_wlen;
	tp->i2c_result = I2C_SUCCESS;

	i2bsc_trace(i2c, 'T', "i2bsc_transfer", "Transaction i2c_version/flags"
	    " %d/%d", tp->i2c_version, tp->i2c_flags);
	i2bsc_trace(i2c, 'T', "i2bsc_transfer", "Transaction buffer rlen/wlen"
	    " %d/%d", tp->i2c_rlen, tp->i2c_wlen);
	i2bsc_trace(i2c, 'T', "i2bsc_transfer", "Transaction ptrs wbuf/rbuf"
	    " %p/%p", tp->i2c_wbuf, tp->i2c_rbuf);

	if (i2c->i2c_proxy_support)
		(void) i2bsc_safe_upload(i2c, tp);
	else
		tp->i2c_result = I2C_FAILURE;

	i2bsc_trace(i2c, 'T', "i2bsc_transfer", "Residual writes/reads"
	    " %d/%d", tp->i2c_w_resid, tp->i2c_r_resid);
	i2bsc_trace(i2c, 'T', "i2bsc_transfer", "i2c_result"
	    " %d", tp->i2c_result);

	i2bsc_release(i2c);

	return (tp->i2c_result);
}

/*
 *  General utility routines ...
 */

#ifdef DEBUG

static void
i2bsc_trace(i2bsc_t *ssp, char code, const char *caller,
	const char *fmt, ...)
{
	char buf[256];
	char *p;
	va_list va;

	if (ssp->debug & (1 << (code-'@'))) {
		p = buf;
		(void) snprintf(p, sizeof (buf) - (p - buf),
		    "%s/%s: ", ssp->i2bsc_name, caller);
		p += strlen(p);

		va_start(va, fmt);
		(void) vsnprintf(p, sizeof (buf) - (p - buf), fmt, va);
		va_end(va);

		buf[sizeof (buf) - 1] = '\0';
		(void) strlog(ssp->majornum, ssp->minornum, code, SL_TRACE,
		    buf);
	}
}

#else /* DEBUG */

_NOTE(ARGSUSED(0))
static void
i2bsc_trace(i2bsc_t *ssp, char code, const char *caller,
	const char *fmt, ...)
{
}

#endif /* DEBUG */

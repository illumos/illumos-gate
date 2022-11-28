/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/id_space.h>
#include <sys/stat.h>

#include <sys/vmm_drv.h>
#include <sys/vmm_drv_test.h>

#define	VDT_CTL_NAME	"vmm_drv_test"
#define	VDT_CTL_MINOR	0

static dev_info_t	*vdt_dip;
static void		*vdt_state;
static id_space_t	*vdt_minors;

typedef struct vdt_soft_state {
	kmutex_t	vss_lock;
	vmm_hold_t	*vss_hold;
} vdt_soft_state_t;


static int
vdt_open(dev_t *devp, int flag, int otype, cred_t *cr)
{
	id_t minor;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}
	if (getminor(*devp) != VDT_CTL_MINOR) {
		return (ENXIO);
	}

	minor = id_alloc_nosleep(vdt_minors);
	if (minor == -1) {
		return (EBUSY);
	}
	if (ddi_soft_state_zalloc(vdt_state, minor) != DDI_SUCCESS) {
		id_free(vdt_minors, minor);
		return (ENOMEM);
	}

	vdt_soft_state_t *ss;
	ss = ddi_get_soft_state(vdt_state, minor);
	mutex_init(&ss->vss_lock, NULL, MUTEX_DEFAULT, NULL);
	*devp = makedevice(getmajor(*devp), minor);

	return (0);
}

static int
vdt_close(dev_t dev, int flag, int otype, cred_t *cr)
{
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	id_t minor = getminor(dev);
	vdt_soft_state_t *ss = ddi_get_soft_state(vdt_state, minor);
	if (ss == NULL) {
		return (ENXIO);
	}

	if (ss->vss_hold != NULL) {
		vmm_drv_rele(ss->vss_hold);
		ss->vss_hold = NULL;
	}
	mutex_destroy(&ss->vss_lock);
	ddi_soft_state_free(vdt_state, minor);
	id_free(vdt_minors, minor);

	return (0);
}

static int
vdt_ioc_hold(vdt_soft_state_t *ss, cred_t *cr, int vmm_fd)
{
	mutex_enter(&ss->vss_lock);
	if (ss->vss_hold != NULL) {
		mutex_exit(&ss->vss_lock);
		return (EEXIST);
	}

	file_t *fp = getf(vmm_fd);
	if (fp == NULL) {
		mutex_exit(&ss->vss_lock);
		return (EBADF);
	}

	int err = vmm_drv_hold(fp, cr, &ss->vss_hold);
	releasef(vmm_fd);
	mutex_exit(&ss->vss_lock);
	return (err);
}

static int
vdt_ioc_rele(vdt_soft_state_t *ss)
{
	mutex_enter(&ss->vss_lock);
	if (ss->vss_hold == NULL) {
		mutex_exit(&ss->vss_lock);
		return (ENODEV);
	}

	vmm_drv_rele(ss->vss_hold);
	ss->vss_hold = NULL;
	mutex_exit(&ss->vss_lock);
	return (0);
}

static int
vdt_ioctl(dev_t dev, int cmd, intptr_t data, int md, cred_t *cr, int *rv)
{
	vdt_soft_state_t *ss = ddi_get_soft_state(vdt_state, getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	int err = 0;
	*rv = 0;
	switch (cmd) {
	case VDT_IOC_HOLD:
		err = vdt_ioc_hold(ss, cr, (int)data);
		break;
	case VDT_IOC_RELE:
		err = vdt_ioc_rele(ss);
		break;
	default:
		err = ENOTTY;
		break;
	}

	return (err);
}

static int
vdt_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)vdt_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
vdt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (vdt_dip != NULL) {
		return (DDI_FAILURE);
	}

	/* Create "control" node from which other instances are spawned */
	if (ddi_create_minor_node(dip, VDT_CTL_NAME, S_IFCHR, VDT_CTL_MINOR,
	    DDI_PSEUDO, 0) != 0) {
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);
	vdt_dip = dip;
	return (DDI_SUCCESS);
}

static int
vdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(vdt_dip, NULL);
	vdt_dip = NULL;

	return (DDI_SUCCESS);
}

static struct cb_ops vdt_cb_ops = {
	.cb_open	= vdt_open,
	.cb_close	= vdt_close,
	.cb_strategy	= nodev,
	.cb_print	= nodev,
	.cb_dump	= nodev,
	.cb_read	= nodev,
	.cb_write	= nodev,
	.cb_ioctl	= vdt_ioctl,
	.cb_devmap	= nodev,
	.cb_mmap	= nodev,
	.cb_segmap	= nodev,
	.cb_chpoll	= nochpoll,
	.cb_prop_op	= ddi_prop_op,

	.cb_str		= NULL,

	.cb_flag	= D_NEW | D_MP | D_DEVMAP,
	.cb_rev		= CB_REV,
	.cb_aread	= nodev,
	.cb_awrite	= nodev,
};

static struct dev_ops vdt_ops = {
	.devo_rev	= DEVO_REV,
	.devo_refcnt	= 0,

	.devo_getinfo	= vdt_info,
	.devo_identify	= nulldev,
	.devo_probe	= nulldev,
	.devo_attach	= vdt_attach,
	.devo_detach	= vdt_detach,
	.devo_reset	= nodev,
	.devo_cb_ops	= &vdt_cb_ops,

	.devo_bus_ops	= NULL,
	.devo_power	= ddi_power,
	.devo_quiesce	= ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	&mod_driverops,
	"bhyve vmm drv test",
	&vdt_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int err;

	vdt_minors = id_space_create("vmm_drv_test_minors",
	    VDT_CTL_MINOR + 1, MAXMIN32);

	err = ddi_soft_state_init(&vdt_state, sizeof (vdt_soft_state_t), 0);
	if (err != 0) {
		return (err);
	}

	err = mod_install(&modlinkage);
	if (err != 0) {
		ddi_soft_state_fini(&vdt_state);
	}

	return (0);
}

int
_fini(void)
{
	int err = mod_remove(&modlinkage);
	if (err != 0) {
		return (err);
	}

	ddi_soft_state_fini(&vdt_state);

	id_space_destroy(vdt_minors);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

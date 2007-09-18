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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * xdf.c - Xen Virtual Block Device Driver
 * TODO:
 *	- support alternate block size (currently only DEV_BSIZE supported)
 *	- revalidate geometry for removable devices
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "xdf.h"

#define	FLUSH_DISKCACHE	0x1
#define	WRITE_BARRIER	0x2
#define	DEFAULT_FLUSH_BLOCK	156 /* block to write to cause a cache flush */
#define	USE_WRITE_BARRIER(vdp)				\
	((vdp)->xdf_feature_barrier && !(vdp)->xdf_flush_supported)
#define	USE_FLUSH_DISKCACHE(vdp)			\
	((vdp)->xdf_feature_barrier && (vdp)->xdf_flush_supported)
#define	IS_WRITE_BARRIER(vdp, bp)			\
	(!IS_READ(bp) && USE_WRITE_BARRIER(vdp) &&	\
	((bp)->b_un.b_addr == (vdp)->xdf_cache_flush_block))
#define	IS_FLUSH_DISKCACHE(bp)				\
	(!IS_READ(bp) && USE_FLUSH_DISKCACHE(vdp) && ((bp)->b_bcount == 0))

static void *vbd_ss;
static kmem_cache_t *xdf_vreq_cache;
static kmem_cache_t *xdf_gs_cache;
static int xdf_maxphys = XB_MAXPHYS;
int xdfdebug = 0;
extern int do_polled_io;
diskaddr_t xdf_flush_block = DEFAULT_FLUSH_BLOCK;
int	xdf_barrier_flush_disable = 0;

/*
 * dev_ops and cb_ops entrypoints
 */
static int xdf_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int xdf_attach(dev_info_t *, ddi_attach_cmd_t);
static int xdf_detach(dev_info_t *, ddi_detach_cmd_t);
static int xdf_reset(dev_info_t *, ddi_reset_cmd_t);
static int xdf_open(dev_t *, int, int, cred_t *);
static int xdf_close(dev_t, int, int, struct cred *);
static int xdf_strategy(struct buf *);
static int xdf_read(dev_t, struct uio *, cred_t *);
static int xdf_aread(dev_t, struct aio_req *, cred_t *);
static int xdf_write(dev_t, struct uio *, cred_t *);
static int xdf_awrite(dev_t, struct aio_req *, cred_t *);
static int xdf_dump(dev_t, caddr_t, daddr_t, int);
static int xdf_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static uint_t xdf_intr(caddr_t);
static int xdf_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
    caddr_t, int *);

/*
 * misc private functions
 */
static int xdf_suspend(dev_info_t *);
static int xdf_resume(dev_info_t *);
static int xdf_start_connect(xdf_t *);
static int xdf_start_disconnect(xdf_t *);
static int xdf_post_connect(xdf_t *);
static void xdf_post_disconnect(xdf_t *);
static void xdf_oe_change(dev_info_t *, ddi_eventcookie_t, void *, void *);
static void xdf_iostart(xdf_t *);
static void xdf_iofini(xdf_t *, uint64_t, int);
static int xdf_prepare_rreq(xdf_t *, struct buf *, blkif_request_t *);
static int xdf_drain_io(xdf_t *);
static boolean_t xdf_isopen(xdf_t *, int);
static int xdf_check_state_transition(xdf_t *, XenbusState);
static int xdf_connect(xdf_t *, boolean_t);
static int xdf_dmacallback(caddr_t);
static void xdf_timeout_handler(void *);
static uint_t xdf_iorestart(caddr_t);
static v_req_t *vreq_get(xdf_t *, buf_t *);
static void vreq_free(xdf_t *, v_req_t *);
static int vreq_setup(xdf_t *, v_req_t *);
static ge_slot_t *gs_get(xdf_t *, int);
static void gs_free(xdf_t *, ge_slot_t *);
static grant_ref_t gs_grant(ge_slot_t *, mfn_t);
static void unexpectedie(xdf_t *);
static void xdfmin(struct buf *);

static 	struct cb_ops xdf_cbops = {
	xdf_open,
	xdf_close,
	xdf_strategy,
	nodev,
	xdf_dump,
	xdf_read,
	xdf_write,
	xdf_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	xdf_prop_op,
	NULL,
	D_MP | D_NEW | D_64BIT,
	CB_REV,
	xdf_aread,
	xdf_awrite
};

struct dev_ops xdf_devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xdf_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xdf_attach,		/* devo_attach */
	xdf_detach,		/* devo_detach */
	xdf_reset,		/* devo_reset */
	&xdf_cbops,		/* devo_cb_ops */
	(struct bus_ops *)NULL	/* devo_bus_ops */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"virtual block driver %I%",	/* short description */
	&xdf_devops		/* driver specific ops */
};

static struct modlinkage xdf_modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * I/O buffer DMA attributes
 * Make sure: one DMA window contains BLKIF_MAX_SEGMENTS_PER_REQUEST at most
 */
static ddi_dma_attr_t xb_dma_attr = {
	DMA_ATTR_V0,
	(uint64_t)0,			/* lowest address */
	(uint64_t)0xffffffffffffffff,	/* highest usable address */
	(uint64_t)0xffffff,		/* DMA counter limit max */
	(uint64_t)XB_BSIZE,		/* alignment in bytes */
	XB_BSIZE - 1,			/* bitmap of burst sizes */
	XB_BSIZE,			/* min transfer */
	(uint64_t)XB_MAX_XFER, 		/* maximum transfer */
	(uint64_t)PAGEOFFSET,		/* 1 page segment length  */
	BLKIF_MAX_SEGMENTS_PER_REQUEST,	/* maximum number of segments */
	XB_BSIZE,			/* granularity */
	0,				/* flags (reserved) */
};

static ddi_device_acc_attr_t xc_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/* callbacks from commmon label */

static int xdf_lb_rdwr(dev_info_t *, uchar_t, void *, diskaddr_t, size_t,
	void *);
static int xdf_lb_getinfo(dev_info_t *, int, void *, void *);

static cmlb_tg_ops_t xdf_lb_ops = {
	TG_DK_OPS_VERSION_1,
	xdf_lb_rdwr,
	xdf_lb_getinfo
};

int
_init(void)
{
	int rc;

	if ((rc = ddi_soft_state_init(&vbd_ss, sizeof (xdf_t), 0)) == 0) {
		xdf_vreq_cache = kmem_cache_create("xdf_vreq_cache",
		    sizeof (v_req_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
		ASSERT(xdf_vreq_cache != NULL);
		xdf_gs_cache = kmem_cache_create("xdf_gs_cache",
		    sizeof (ge_slot_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
		ASSERT(xdf_gs_cache != NULL);
		if ((rc = mod_install(&xdf_modlinkage)) != 0) {
			kmem_cache_destroy(xdf_vreq_cache);
			kmem_cache_destroy(xdf_gs_cache);
			ddi_soft_state_fini(&vbd_ss);
		}
	}

	return (rc);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&xdf_modlinkage)) != 0)
		return (err);

	kmem_cache_destroy(xdf_vreq_cache);
	kmem_cache_destroy(xdf_gs_cache);
	ddi_soft_state_fini(&vbd_ss);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xdf_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
xdf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **rp)
{
	int instance;
	xdf_t *vbdp;

	instance = XDF_INST(getminor((dev_t)arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((vbdp = ddi_get_soft_state(vbd_ss, instance)) == NULL) {
			*rp = NULL;
			return (DDI_FAILURE);
		}
		*rp = vbdp->xdf_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*rp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
xdf_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
	char *name, caddr_t valuep, int *lengthp)
{
	int instance = ddi_get_instance(dip);
	xdf_t *vdp;
	diskaddr_t p_blkcnt;

	/*
	 * xdf dynamic properties are device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op.
	 */
	vdp = ddi_get_soft_state(vbd_ss, instance);

	if ((dev == DDI_DEV_T_ANY) || (vdp == NULL))
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));

	/* do cv_wait until connected or failed */
	mutex_enter(&vdp->xdf_dev_lk);
	if (xdf_connect(vdp, B_TRUE) != XD_READY) {
		mutex_exit(&vdp->xdf_dev_lk);
		goto out;
	}
	mutex_exit(&vdp->xdf_dev_lk);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, XDF_PART(getminor(dev)), &p_blkcnt,
	    NULL, NULL, NULL, NULL) == 0)
		return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, (uint64_t)p_blkcnt));

out:
	return (ddi_prop_op(dev, dip, prop_op, mod_flags, name, valuep,
	    lengthp));
}

static int
xdf_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	xdf_t *vdp;
	ddi_iblock_cookie_t ibc;
	ddi_iblock_cookie_t softibc;
	int instance;

	xdfdebug = ddi_prop_get_int(DDI_DEV_T_ANY, devi, DDI_PROP_NOTPROM,
	    "xdfdebug", 0);

	switch (cmd) {
		case DDI_ATTACH:
			break;

		case DDI_RESUME:
			return (xdf_resume(devi));

		default:
			return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);
	if (ddi_soft_state_zalloc(vbd_ss, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	DPRINTF(DDI_DBG, ("xdf%d: attaching\n", instance));
	vdp = ddi_get_soft_state(vbd_ss, instance);
	vdp->xdf_dip = devi;
	if (ddi_get_iblock_cookie(devi, 0, &ibc) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: failed to get iblock cookie",
		    ddi_get_name_addr(devi));
		goto errout1;
	}

	mutex_init(&vdp->xdf_dev_lk, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&vdp->xdf_cb_lk, NULL, MUTEX_DRIVER, (void *)ibc);
	cv_init(&vdp->xdf_dev_cv, NULL, CV_DEFAULT, NULL);
	ddi_set_driver_private(devi, vdp);

	if (ddi_get_soft_iblock_cookie(devi, DDI_SOFTINT_LOW, &softibc)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: failed to get softintr iblock cookie",
		    ddi_get_name_addr(devi));
		goto errout2;
	}
	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &vdp->xdf_softintr_id,
	    &softibc, NULL, xdf_iorestart, (caddr_t)vdp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: failed to add softintr",
		    ddi_get_name_addr(devi));
		goto errout2;
	}

	/*
	 * create kstat for iostat(1M)
	 */
	if ((vdp->xdf_xdev_iostat = kstat_create("xdf", instance, NULL, "disk",
	    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT)) != NULL) {
		vdp->xdf_xdev_iostat->ks_lock = &vdp->xdf_dev_lk;
		kstat_install(vdp->xdf_xdev_iostat);
	} else {
		cmn_err(CE_WARN, "xdf@%s: failed to create kstat",
		    ddi_get_name_addr(devi));
		goto errout3;
	}

	/*
	 * driver handles kernel-issued IOCTLs
	 */
	if (ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: cannot create DDI_KERNEL_IOCTL prop",
		    ddi_get_name_addr(devi));
		goto errout4;
	}

	/*
	 * create default device minor nodes: non-removable disk
	 * we will adjust minor nodes after we are connected w/ backend
	 */
	cmlb_alloc_handle(&vdp->xdf_vd_lbl);
	if (cmlb_attach(devi, &xdf_lb_ops, DTYPE_DIRECT, 0, 1, DDI_NT_BLOCK,
	    CMLB_FAKE_LABEL_ONE_PARTITION, vdp->xdf_vd_lbl, NULL) != 0) {
		cmn_err(CE_WARN, "xdf@%s: default cmlb attach failed",
		    ddi_get_name_addr(devi));
		goto errout5;
	}

	/*
	 * We ship with cache-enabled disks
	 */
	vdp->xdf_wce = 1;

	mutex_enter(&vdp->xdf_cb_lk);

	/* Watch backend XenbusState change */
	if (xvdi_add_event_handler(devi, XS_OE_STATE,
	    xdf_oe_change) != DDI_SUCCESS) {
		mutex_exit(&vdp->xdf_cb_lk);
		goto errout6;
	}

	if (xdf_start_connect(vdp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: start connection failed",
		    ddi_get_name_addr(devi));
		(void) xdf_start_disconnect(vdp);
		mutex_exit(&vdp->xdf_cb_lk);
		goto errout7;
	}

	mutex_exit(&vdp->xdf_cb_lk);

	list_create(&vdp->xdf_vreq_act, sizeof (v_req_t),
	    offsetof(v_req_t, v_link));
	list_create(&vdp->xdf_gs_act, sizeof (ge_slot_t),
	    offsetof(ge_slot_t, link));

	ddi_report_dev(devi);
	DPRINTF(DDI_DBG, ("xdf%d: attached\n", instance));

	return (DDI_SUCCESS);

errout7:
	xvdi_remove_event_handler(devi, XS_OE_STATE);
errout6:
	cmlb_detach(vdp->xdf_vd_lbl, NULL);
errout5:
	cmlb_free_handle(&vdp->xdf_vd_lbl);
	ddi_prop_remove_all(devi);
errout4:
	kstat_delete(vdp->xdf_xdev_iostat);
errout3:
	ddi_remove_softintr(vdp->xdf_softintr_id);
errout2:
	ddi_set_driver_private(devi, NULL);
	cv_destroy(&vdp->xdf_dev_cv);
	mutex_destroy(&vdp->xdf_cb_lk);
	mutex_destroy(&vdp->xdf_dev_lk);
errout1:
	cmn_err(CE_WARN, "xdf@%s: attach failed", ddi_get_name_addr(devi));
	ddi_soft_state_free(vbd_ss, instance);
	return (DDI_FAILURE);
}

static int
xdf_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	xdf_t *vdp;
	int instance;

	switch (cmd) {

	case DDI_PM_SUSPEND:
		break;

	case DDI_SUSPEND:
		return (xdf_suspend(devi));

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);
	DPRINTF(DDI_DBG, ("xdf%d: detaching\n", instance));
	vdp = ddi_get_soft_state(vbd_ss, instance);

	if (vdp == NULL)
		return (DDI_FAILURE);

	mutex_enter(&vdp->xdf_dev_lk);
	if (xdf_isopen(vdp, -1)) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (DDI_FAILURE);
	}

	if (vdp->xdf_status != XD_CLOSED) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (DDI_FAILURE);
	}

	ASSERT(!ISDMACBON(vdp));
	mutex_exit(&vdp->xdf_dev_lk);

	if (vdp->xdf_timeout_id != 0)
		(void) untimeout(vdp->xdf_timeout_id);

	xvdi_remove_event_handler(devi, XS_OE_STATE);

	/* we'll support backend running in domU later */
#ifdef	DOMU_BACKEND
	(void) xvdi_post_event(devi, XEN_HP_REMOVE);
#endif

	list_destroy(&vdp->xdf_vreq_act);
	list_destroy(&vdp->xdf_gs_act);
	ddi_prop_remove_all(devi);
	kstat_delete(vdp->xdf_xdev_iostat);
	ddi_remove_softintr(vdp->xdf_softintr_id);
	ddi_set_driver_private(devi, NULL);
	cv_destroy(&vdp->xdf_dev_cv);
	mutex_destroy(&vdp->xdf_cb_lk);
	mutex_destroy(&vdp->xdf_dev_lk);
	if (vdp->xdf_cache_flush_block != NULL)
		kmem_free(vdp->xdf_flush_mem, 2 * DEV_BSIZE);
	ddi_soft_state_free(vbd_ss, instance);
	return (DDI_SUCCESS);
}

static int
xdf_suspend(dev_info_t *devi)
{
	xdf_t *vdp;
	int instance;

	instance = ddi_get_instance(devi);

	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_suspend: xdf#%d\n", instance);

	if ((vdp = ddi_get_soft_state(vbd_ss, instance)) == NULL)
		return (DDI_FAILURE);

	xvdi_suspend(devi);

	/* stop further I/O requests */
	mutex_enter(&vdp->xdf_cb_lk);
	mutex_enter(&vdp->xdf_dev_lk);
	vdp->xdf_status = XD_SUSPEND;
	mutex_exit(&vdp->xdf_dev_lk);
	mutex_exit(&vdp->xdf_cb_lk);

	/* make sure no more I/O responses left in the ring buffer */
	(void) ddi_remove_intr(devi, 0, NULL);
	(void) xdf_drain_io(vdp);

	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_suspend: SUCCESS\n");

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
xdf_resume(dev_info_t *devi)
{
	xdf_t *vdp;
	int instance;

	instance = ddi_get_instance(devi);
	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_resume: xdf%d\n", instance);

	if ((vdp = ddi_get_soft_state(vbd_ss, instance)) == NULL)
		return (DDI_FAILURE);

	mutex_enter(&vdp->xdf_cb_lk);

	if (xvdi_resume(devi) != DDI_SUCCESS) {
		mutex_exit(&vdp->xdf_cb_lk);
		return (DDI_FAILURE);
	}

	mutex_enter(&vdp->xdf_dev_lk);
	ASSERT(vdp->xdf_status == XD_SUSPEND);
	vdp->xdf_status = XD_UNKNOWN;
	mutex_exit(&vdp->xdf_dev_lk);

	if (xdf_start_connect(vdp) != DDI_SUCCESS) {
		mutex_exit(&vdp->xdf_cb_lk);
		return (DDI_FAILURE);
	}

	mutex_exit(&vdp->xdf_cb_lk);

	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_resume: done\n");
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
xdf_reset(dev_info_t *devi, ddi_reset_cmd_t cmd)
{
	xdf_t *vdp;
	int instance;

	instance = ddi_get_instance(devi);
	DPRINTF(DDI_DBG, ("xdf%d: resetting\n", instance));
	if ((vdp = ddi_get_soft_state(vbd_ss, instance)) == NULL)
		return (DDI_FAILURE);

	/*
	 * wait for any outstanding I/O to complete
	 */
	(void) xdf_drain_io(vdp);

	DPRINTF(DDI_DBG, ("xdf%d: reset complete\n", instance));
	return (DDI_SUCCESS);
}

static int
xdf_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t	minor;
	xdf_t	*vdp;
	int part;
	ulong_t parbit;
	diskaddr_t p_blkct = 0;
	boolean_t firstopen;

	minor = getminor(*devp);
	if ((vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))) == NULL)
		return (ENXIO);

	DPRINTF(DDI_DBG, ("xdf%d: opening\n", XDF_INST(minor)));

	/* do cv_wait until connected or failed */
	mutex_enter(&vdp->xdf_dev_lk);
	if (xdf_connect(vdp, B_TRUE) != XD_READY) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (ENXIO);
	}

	if ((flag & FWRITE) && XD_IS_RO(vdp)) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (EROFS);
	}

	part = XDF_PART(minor);
	parbit = 1 << part;
	if (vdp->xdf_vd_exclopen & parbit) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (EBUSY);
	}

	/* are we the first one to open this node? */
	firstopen = !xdf_isopen(vdp, -1);

	if ((flag & FEXCL) && !firstopen) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (EBUSY);
	}

	if (otyp == OTYP_LYR)
		vdp->xdf_vd_lyropen[part]++;

	vdp->xdf_vd_open[otyp] |= parbit;

	if (flag & FEXCL)
		vdp->xdf_vd_exclopen |= parbit;

	mutex_exit(&vdp->xdf_dev_lk);

	/* force a re-validation */
	if (firstopen)
		cmlb_invalidate(vdp->xdf_vd_lbl, NULL);

	/*
	 * check size
	 * ignore CD/DVD which contains a zero-sized s0
	 */
	if (!(flag & (FNDELAY | FNONBLOCK)) && !XD_IS_CD(vdp) &&
	    ((cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkct,
	    NULL, NULL, NULL, NULL) != 0) || (p_blkct == 0))) {
		(void) xdf_close(*devp, flag, otyp, credp);
		return (ENXIO);
	}

	return (0);
}

/*ARGSUSED*/
static int
xdf_close(dev_t dev, int flag, int otyp, struct cred *credp)
{
	minor_t	minor;
	xdf_t	*vdp;
	int part;
	ulong_t parbit;

	minor = getminor(dev);
	if ((vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))) == NULL)
		return (ENXIO);

	mutex_enter(&vdp->xdf_dev_lk);
	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part)) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (ENXIO);
	}
	parbit = 1 << part;

	if (otyp == OTYP_LYR) {
		if (vdp->xdf_vd_lyropen[part] != 0)
			vdp->xdf_vd_lyropen[part]--;
		if (vdp->xdf_vd_lyropen[part] == 0)
			vdp->xdf_vd_open[OTYP_LYR] &= ~parbit;
	} else {
		vdp->xdf_vd_open[otyp] &= ~parbit;
	}
	vdp->xdf_vd_exclopen &= ~parbit;

	mutex_exit(&vdp->xdf_dev_lk);
	return (0);
}

static int
xdf_strategy(struct buf *bp)
{
	xdf_t	*vdp;
	minor_t minor;
	diskaddr_t p_blkct, p_blkst;
	ulong_t nblks;
	int part;

	minor = getminor(bp->b_edev);
	part = XDF_PART(minor);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))) ||
	    !xdf_isopen(vdp, part) ||
	    cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkct,
	    &p_blkst, NULL, NULL, NULL)) {
		bioerror(bp, ENXIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	if (!IS_READ(bp) && XD_IS_RO(vdp)) {
		bioerror(bp, EROFS);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	/*
	 * starting beyond partition
	 */
	if (bp->b_blkno > p_blkct) {
		DPRINTF(IO_DBG, ("xdf: block %lld exceeds VBD size %"PRIu64,
		    (longlong_t)bp->b_blkno, (uint64_t)p_blkct));
		bioerror(bp, EINVAL);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	/* Legacy: don't set error flag at this case */
	if (bp->b_blkno == p_blkct) {
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	/*
	 * adjust for partial transfer
	 */
	nblks = bp->b_bcount >> XB_BSHIFT;
	if ((bp->b_blkno + nblks) > p_blkct) {
		bp->b_resid = ((bp->b_blkno + nblks) - p_blkct) << XB_BSHIFT;
		bp->b_bcount -= bp->b_resid;
	}


	DPRINTF(IO_DBG, ("xdf: strategy blk %lld len %lu\n",
	    (longlong_t)bp->b_blkno, (ulong_t)bp->b_bcount));

	mutex_enter(&vdp->xdf_dev_lk);
	kstat_waitq_enter(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));
	if (vdp->xdf_f_act == NULL) {
		vdp->xdf_f_act = vdp->xdf_l_act = bp;
	} else {
		vdp->xdf_l_act->av_forw = bp;
		vdp->xdf_l_act = bp;
	}
	bp->av_forw = NULL;
	bp->av_back = NULL; /* not tagged with a v_req */
	bp->b_private = (void *)(uintptr_t)p_blkst;
	mutex_exit(&vdp->xdf_dev_lk);
	xdf_iostart(vdp);
	if (do_polled_io)
		(void) xdf_drain_io(vdp);
	return (0);
}

/*ARGSUSED*/
static int
xdf_read(dev_t dev, struct uio *uiop, cred_t *credp)
{

	xdf_t	*vdp;
	minor_t minor;
	diskaddr_t p_blkcnt;
	int part;

	minor = getminor(dev);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))))
		return (ENXIO);

	DPRINTF(IO_DBG, ("xdf: read offset 0x%"PRIx64"\n",
	    (int64_t)uiop->uio_offset));

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkcnt,
	    NULL, NULL, NULL, NULL))
		return (ENXIO);

	if (U_INVAL(uiop))
		return (EINVAL);

	return (physio(xdf_strategy, NULL, dev, B_READ, xdfmin, uiop));
}

/*ARGSUSED*/
static int
xdf_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	xdf_t *vdp;
	minor_t minor;
	diskaddr_t p_blkcnt;
	int part;

	minor = getminor(dev);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))))
		return (ENXIO);

	DPRINTF(IO_DBG, ("xdf: write offset 0x%"PRIx64"\n",
	    (int64_t)uiop->uio_offset));

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkcnt,
	    NULL, NULL, NULL, NULL))
		return (ENXIO);

	if (uiop->uio_loffset >= XB_DTOB(p_blkcnt))
		return (ENOSPC);

	if (U_INVAL(uiop))
		return (EINVAL);

	return (physio(xdf_strategy, NULL, dev, B_WRITE, minphys, uiop));
}

/*ARGSUSED*/
static int
xdf_aread(dev_t dev, struct aio_req *aiop, cred_t *credp)
{
	xdf_t	*vdp;
	minor_t minor;
	struct uio *uiop = aiop->aio_uio;
	diskaddr_t p_blkcnt;
	int part;

	minor = getminor(dev);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))))
		return (ENXIO);

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkcnt,
	    NULL, NULL, NULL, NULL))
		return (ENXIO);

	if (uiop->uio_loffset >= XB_DTOB(p_blkcnt))
		return (ENOSPC);

	if (U_INVAL(uiop))
		return (EINVAL);

	return (aphysio(xdf_strategy, anocancel, dev, B_READ, minphys, aiop));
}

/*ARGSUSED*/
static int
xdf_awrite(dev_t dev, struct aio_req *aiop, cred_t *credp)
{
	xdf_t *vdp;
	minor_t minor;
	struct uio *uiop = aiop->aio_uio;
	diskaddr_t p_blkcnt;
	int part;

	minor = getminor(dev);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))))
		return (ENXIO);

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkcnt,
	    NULL, NULL, NULL, NULL))
		return (ENXIO);

	if (uiop->uio_loffset >= XB_DTOB(p_blkcnt))
		return (ENOSPC);

	if (U_INVAL(uiop))
		return (EINVAL);

	return (aphysio(xdf_strategy, anocancel, dev, B_WRITE, minphys, aiop));
}

static int
xdf_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	struct buf dumpbuf, *dbp;
	xdf_t	*vdp;
	minor_t minor;
	int err = 0;
	int part;
	diskaddr_t p_blkcnt, p_blkst;

	minor = getminor(dev);
	if (!(vdp = ddi_get_soft_state(vbd_ss, XDF_INST(minor))))
		return (ENXIO);

	DPRINTF(IO_DBG, ("xdf: dump addr (0x%p) blk (%ld) nblks (%d)\n",
	    addr, blkno, nblk));

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	if (cmlb_partinfo(vdp->xdf_vd_lbl, part, &p_blkcnt, &p_blkst,
	    NULL, NULL, NULL))
		return (ENXIO);

	if ((blkno + nblk) > p_blkcnt) {
		cmn_err(CE_WARN, "xdf: block %ld exceeds VBD size %"PRIu64,
		    blkno + nblk, (uint64_t)vdp->xdf_xdev_nblocks);
		return (EINVAL);
	}

	dbp = &dumpbuf;
	bioinit(dbp);
	dbp->b_flags = B_BUSY;
	dbp->b_un.b_addr = addr;
	dbp->b_bcount	= nblk << DEV_BSHIFT;
	dbp->b_resid = 0;
	dbp->b_blkno = blkno;
	dbp->b_edev = dev;
	dbp->b_private = (void *)(uintptr_t)p_blkst;

	mutex_enter(&vdp->xdf_dev_lk);
	kstat_waitq_enter(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));
	if (vdp->xdf_f_act == NULL) {
		vdp->xdf_f_act = vdp->xdf_l_act = dbp;
	} else {
		vdp->xdf_l_act->av_forw = dbp;
		vdp->xdf_l_act = dbp;
	}
	dbp->av_forw = NULL;
	dbp->av_back = NULL;
	mutex_exit(&vdp->xdf_dev_lk);
	xdf_iostart(vdp);
	err = xdf_drain_io(vdp);
	biofini(dbp);
	return (err);
}

/*ARGSUSED*/
static int
xdf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int instance;
	xdf_t	*vdp;
	minor_t minor;
	int part;

	minor = getminor(dev);
	instance = XDF_INST(minor);

	if ((vdp = ddi_get_soft_state(vbd_ss, instance)) == NULL)
		return (ENXIO);

	DPRINTF(IOCTL_DBG, ("xdf%d:ioctl: cmd %d (0x%x)\n",
	    instance, cmd, cmd));

	part = XDF_PART(minor);
	if (!xdf_isopen(vdp, part))
		return (ENXIO);

	switch (cmd) {
	case DKIOCGMEDIAINFO: {
		struct dk_minfo	media_info;

		media_info.dki_lbsize = DEV_BSIZE;
		media_info.dki_capacity = vdp->xdf_xdev_nblocks;
		media_info.dki_media_type = DK_FIXED_DISK;

		if (ddi_copyout(&media_info, (void *)arg,
		    sizeof (struct dk_minfo), mode)) {
			return (EFAULT);
		} else {
			return (0);
		}
	}

	case DKIOCINFO: {
		struct dk_cinfo info;

		/* controller information */
		if (XD_IS_CD(vdp))
			info.dki_ctype = DKC_CDROM;
		else
			info.dki_ctype = DKC_VBD;

		info.dki_cnum = 0;
		(void) strncpy((char *)(&info.dki_cname), "xdf", 8);

		/* unit information */
		info.dki_unit = ddi_get_instance(vdp->xdf_dip);
		(void) strncpy((char *)(&info.dki_dname), "xdf", 8);
		info.dki_flags = DKI_FMTVOL;
		info.dki_partition = part;
		info.dki_maxtransfer = maxphys / DEV_BSIZE;
		info.dki_addr = 0;
		info.dki_space = 0;
		info.dki_prio = 0;
		info.dki_vec = 0;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), mode))
			return (EFAULT);
		else
			return (0);
	}

	case DKIOCSTATE: {
		enum dkio_state	dkstate = DKIO_INSERTED;
		if (ddi_copyout(&dkstate, (void *)arg, sizeof (dkstate),
		    mode) != 0)
			return (EFAULT);
		return (0);
	}

	/*
	 * is media removable?
	 */
	case DKIOCREMOVABLE: {
		int i = XD_IS_RM(vdp) ? 1 : 0;
		if (ddi_copyout(&i, (caddr_t)arg, sizeof (int), mode))
			return (EFAULT);
		return (0);
	}

	case DKIOCG_PHYGEOM:
	case DKIOCG_VIRTGEOM:
	case DKIOCGGEOM:
	case DKIOCSGEOM:
	case DKIOCGAPART:
	case DKIOCGVTOC:
	case DKIOCSVTOC:
	case DKIOCPARTINFO:
	case DKIOCGETEFI:
	case DKIOCSETEFI:
	case DKIOCPARTITION: {
		int rc;

		rc = cmlb_ioctl(vdp->xdf_vd_lbl, dev, cmd, arg, mode, credp,
		    rvalp, NULL);
		return (rc);
	}

	case DKIOCGETWCE:
		if (ddi_copyout(&vdp->xdf_wce, (void *)arg,
		    sizeof (vdp->xdf_wce), mode))
			return (EFAULT);
		return (0);
	case DKIOCSETWCE:
		if (ddi_copyin((void *)arg, &vdp->xdf_wce,
		    sizeof (vdp->xdf_wce), mode))
			return (EFAULT);
		return (0);
	case DKIOCFLUSHWRITECACHE: {
		int rc;
		struct dk_callback *dkc = (struct dk_callback *)arg;

		if (vdp->xdf_flush_supported) {
			rc = xdf_lb_rdwr(vdp->xdf_dip, TG_WRITE,
			    NULL, 0, 0, (void *)dev);
		} else {
			if (xdf_barrier_flush_disable)
				return (ENOTTY);
			rc = xdf_lb_rdwr(vdp->xdf_dip, TG_WRITE,
			    vdp->xdf_cache_flush_block, xdf_flush_block,
			    DEV_BSIZE, (void *)dev);
		}
		if ((mode & FKIOCTL) && (dkc != NULL) &&
		    (dkc->dkc_callback != NULL)) {
			(*dkc->dkc_callback)(dkc->dkc_cookie, rc);
			/* need to return 0 after calling callback */
			rc = 0;
		}
		return (rc);
	}

	default:
		return (ENOTTY);
	}
}

/*
 * xdf interrupt handler
 */
static uint_t
xdf_intr(caddr_t arg)
{
	xdf_t *vdp = (xdf_t *)arg;
	xendev_ring_t *xbr;
	blkif_response_t *resp;
	int bioerr = 0;
	uint64_t id;
	extern int do_polled_io;
	uint8_t op;
	uint16_t status;
	ddi_acc_handle_t acchdl;

	mutex_enter(&vdp->xdf_dev_lk);

	if ((xbr = vdp->xdf_xb_ring) == NULL) {
		mutex_exit(&vdp->xdf_dev_lk);
		return (DDI_INTR_UNCLAIMED);
	}

	acchdl = vdp->xdf_xb_ring_hdl;

	/*
	 * complete all requests which have a response
	 */
	while (resp = xvdi_ring_get_response(xbr)) {
		id = ddi_get64(acchdl, &resp->id);
		op = ddi_get8(acchdl, &resp->operation);
		status = ddi_get16(acchdl, (uint16_t *)&resp->status);
		DPRINTF(INTR_DBG, ("resp: op %d id %"PRIu64" status %d\n",
		    op, id, status));

		/*
		 * XXPV - close connection to the backend and restart
		 */
		if (status != BLKIF_RSP_OKAY) {
			DPRINTF(IO_DBG, ("xdf@%s: I/O error while %s",
			    ddi_get_name_addr(vdp->xdf_dip),
			    (op == BLKIF_OP_READ) ? "reading" : "writing"));
			bioerr = EIO;
		}

		xdf_iofini(vdp, id, bioerr);
	}

	mutex_exit(&vdp->xdf_dev_lk);

	if (!do_polled_io)
		xdf_iostart(vdp);

	return (DDI_INTR_CLAIMED);
}

int xdf_fbrewrites;	/* how many times was our flush block rewritten */

/*
 * Snarf new data if our flush block was re-written
 */
static void
check_fbwrite(xdf_t *vdp, buf_t *bp, daddr_t blkno)
{
	int nblks;
	boolean_t mapin;

	if (IS_WRITE_BARRIER(vdp, bp))
		return; /* write was a flush write */

	mapin = B_FALSE;
	nblks = bp->b_bcount >> DEV_BSHIFT;
	if (xdf_flush_block >= blkno && xdf_flush_block < (blkno + nblks)) {
		xdf_fbrewrites++;
		if (bp->b_flags & (B_PAGEIO | B_PHYS)) {
			mapin = B_TRUE;
			bp_mapin(bp);
		}
		bcopy(bp->b_un.b_addr +
		    ((xdf_flush_block - blkno) << DEV_BSHIFT),
		    vdp->xdf_cache_flush_block, DEV_BSIZE);
		if (mapin)
			bp_mapout(bp);
	}
}

static void
xdf_iofini(xdf_t *vdp, uint64_t id, int bioerr)
{
	ge_slot_t *gs = (ge_slot_t *)(uintptr_t)id;
	v_req_t *vreq = gs->vreq;
	buf_t *bp = vreq->v_buf;

	gs_free(vdp, gs);
	if (bioerr)
		bioerror(bp, bioerr);
	vreq->v_nslots--;
	if (vreq->v_nslots != 0)
		return;

	XDF_UPDATE_IO_STAT(vdp, bp);
	kstat_runq_exit(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));

	if (IS_ERROR(bp))
		bp->b_resid = bp->b_bcount;

	vreq_free(vdp, vreq);
	biodone(bp);
}

/*
 * return value of xdf_prepare_rreq()
 * used in xdf_iostart()
 */
#define	XF_PARTIAL	0 /* rreq is full, not all I/O in buf transferred */
#define	XF_COMP		1 /* no more I/O left in buf */

static void
xdf_iostart(xdf_t *vdp)
{
	xendev_ring_t *xbr;
	struct buf *bp;
	blkif_request_t *rreq;
	int retval;
	int rreqready = 0;

	xbr = vdp->xdf_xb_ring;

	/*
	 * populate the ring request(s)
	 *
	 * loop until there is no buf to transfer or no free slot
	 * available in I/O ring
	 */
	for (;;) {
		mutex_enter(&vdp->xdf_dev_lk);

		if (vdp->xdf_status != XD_READY)
			break;

		/* active buf queue empty? */
		if ((bp = vdp->xdf_f_act) == NULL)
			break;

		/* try to grab a vreq for this bp */
		if ((BP2VREQ(bp) == NULL) && (vreq_get(vdp, bp) == NULL))
				break;
		/* alloc DMA/GTE resources */
		if (vreq_setup(vdp, BP2VREQ(bp)) != DDI_SUCCESS)
			break;

		/* get next blkif_request in the ring */
		if ((rreq = xvdi_ring_get_request(xbr)) == NULL)
			break;
		bzero(rreq, sizeof (blkif_request_t));

		/* populate blkif_request with this buf */
		rreqready++;
		retval = xdf_prepare_rreq(vdp, bp, rreq);
		if (retval == XF_COMP) {
			/* finish this bp, switch to next one */
			kstat_waitq_to_runq(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));
			vdp->xdf_f_act = bp->av_forw;
			bp->av_forw = NULL;
		}

		mutex_exit(&vdp->xdf_dev_lk);
	}

	/*
	 * Send the request(s) to the backend
	 */
	if (rreqready) {
		if (xvdi_ring_push_request(xbr)) {
			DPRINTF(IO_DBG, ("xdf_iostart: "
			    "sent request(s) to backend\n"));
			xvdi_notify_oe(vdp->xdf_dip);
		}
	}

	mutex_exit(&vdp->xdf_dev_lk);
}

/*
 * populate a single blkif_request_t w/ a buf
 */
static int
xdf_prepare_rreq(xdf_t *vdp, struct buf *bp, blkif_request_t *rreq)
{
	int		rval;
	grant_ref_t	gr;
	uint8_t		fsect, lsect;
	size_t		bcnt;
	paddr_t		dma_addr;
	off_t		blk_off;
	dev_info_t	*dip = vdp->xdf_dip;
	blkif_vdev_t	vdev = xvdi_get_vdevnum(dip);
	v_req_t		*vreq = BP2VREQ(bp);
	uint64_t	blkno = vreq->v_blkno;
	uint_t		ndmacs = vreq->v_ndmacs;
	ddi_acc_handle_t acchdl = vdp->xdf_xb_ring_hdl;
	int		seg = 0;
	int		isread = IS_READ(bp);

	if (isread)
		ddi_put8(acchdl, &rreq->operation, BLKIF_OP_READ);
	else {
		switch (vreq->v_flush_diskcache) {
		case FLUSH_DISKCACHE:
			ddi_put8(acchdl, &rreq->operation,
			    BLKIF_OP_FLUSH_DISKCACHE);
			ddi_put16(acchdl, &rreq->handle, vdev);
			ddi_put64(acchdl, &rreq->id,
			    (uint64_t)(uintptr_t)(vreq->v_gs));
			ddi_put8(acchdl, &rreq->nr_segments, 0);
			return (XF_COMP);
		case WRITE_BARRIER:
			ddi_put8(acchdl, &rreq->operation,
			    BLKIF_OP_WRITE_BARRIER);
			break;
		default:
			if (!vdp->xdf_wce)
				ddi_put8(acchdl, &rreq->operation,
				    BLKIF_OP_WRITE_BARRIER);
			else
				ddi_put8(acchdl, &rreq->operation,
				    BLKIF_OP_WRITE);
			break;
		}
	}

	ddi_put16(acchdl, &rreq->handle, vdev);
	ddi_put64(acchdl, &rreq->sector_number, blkno);
	ddi_put64(acchdl, &rreq->id, (uint64_t)(uintptr_t)(vreq->v_gs));

	/*
	 * loop until all segments are populated or no more dma cookie in buf
	 */
	for (;;) {
	/*
	 * Each segment of a blkif request can transfer up to
	 * one 4K page of data.
	 */
		bcnt = vreq->v_dmac.dmac_size;
		ASSERT(bcnt <= PAGESIZE);
		ASSERT((bcnt % XB_BSIZE) == 0);
		dma_addr = vreq->v_dmac.dmac_laddress;
		blk_off = (uint_t)((paddr_t)XB_SEGOFFSET & dma_addr);
		ASSERT((blk_off & XB_BMASK) == 0);
		fsect = blk_off >> XB_BSHIFT;
		lsect = fsect + (bcnt >> XB_BSHIFT) - 1;
		ASSERT(fsect < XB_MAX_SEGLEN / XB_BSIZE &&
		    lsect < XB_MAX_SEGLEN / XB_BSIZE);
		DPRINTF(IO_DBG, ("  ""seg%d: dmacS %lu blk_off %ld\n",
		    seg, vreq->v_dmac.dmac_size, blk_off));
		gr = gs_grant(vreq->v_gs, PATOMA(dma_addr) >> PAGESHIFT);
		ddi_put32(acchdl, &rreq->seg[seg].gref, gr);
		ddi_put8(acchdl, &rreq->seg[seg].first_sect, fsect);
		ddi_put8(acchdl, &rreq->seg[seg].last_sect, lsect);
		DPRINTF(IO_DBG, ("  ""seg%d: fs %d ls %d gr %d dma 0x%"PRIx64
		    "\n", seg, fsect, lsect, gr, dma_addr));

		blkno += (bcnt >> XB_BSHIFT);
		seg++;
		ASSERT(seg <= BLKIF_MAX_SEGMENTS_PER_REQUEST);
		if (--ndmacs) {
			ddi_dma_nextcookie(vreq->v_dmahdl, &vreq->v_dmac);
			continue;
		}

		vreq->v_status = VREQ_DMAWIN_DONE;
		vreq->v_blkno = blkno;
		if (vreq->v_dmaw + 1 == vreq->v_ndmaws)
			/* last win */
			rval = XF_COMP;
		else
			rval = XF_PARTIAL;
		break;
	}
	ddi_put8(acchdl,  &rreq->nr_segments, seg);
	DPRINTF(IO_DBG, ("xdf_prepare_rreq: request id=%"PRIx64" ready\n",
	    rreq->id));

	return (rval);
}

#define	XDF_QSEC	50000	/* .005 second */
#define	XDF_POLLCNT	12	/* loop for 12 times before time out */

static int
xdf_drain_io(xdf_t *vdp)
{
	int pollc, rval;
	xendev_ring_t *xbr;

	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_drain_io: start\n");

	mutex_enter(&vdp->xdf_dev_lk);

	if ((vdp->xdf_status != XD_READY) && (vdp->xdf_status != XD_SUSPEND))
		goto out;

	rval = 0;
	xbr = vdp->xdf_xb_ring;
	ASSERT(xbr != NULL);

	for (pollc = 0; pollc < XDF_POLLCNT; pollc++) {
		if (xvdi_ring_has_unconsumed_responses(xbr)) {
			mutex_exit(&vdp->xdf_dev_lk);
			(void) xdf_intr((caddr_t)vdp);
			mutex_enter(&vdp->xdf_dev_lk);
		}
		if (!xvdi_ring_has_incomp_request(xbr))
			goto out;

		(void) HYPERVISOR_yield();
		/*
		 * file-backed devices can be slow
		 */
		drv_usecwait(XDF_QSEC << pollc);
	}
	cmn_err(CE_WARN, "xdf_polled_io: timeout");
	rval = EIO;
out:
	mutex_exit(&vdp->xdf_dev_lk);
	if (xdfdebug & SUSRES_DBG)
		xen_printf("xdf_drain_io: end, err=%d\n", rval);
	return (rval);
}

/* ARGSUSED5 */
static int
xdf_lb_rdwr(dev_info_t *devi, uchar_t cmd, void *bufp,
    diskaddr_t start, size_t reqlen, void *tg_cookie)
{
	xdf_t *vdp;
	struct buf *bp;
	int err = 0;

	vdp = ddi_get_soft_state(vbd_ss, ddi_get_instance(devi));
	if (vdp == NULL)
		return (ENXIO);

	if ((start + (reqlen >> DEV_BSHIFT)) > vdp->xdf_xdev_nblocks)
		return (EINVAL);

	bp = getrbuf(KM_SLEEP);
	if (cmd == TG_READ)
		bp->b_flags = B_BUSY | B_READ;
	else
		bp->b_flags = B_BUSY | B_WRITE;
	bp->b_un.b_addr = bufp;
	bp->b_bcount = reqlen;
	bp->b_resid = 0;
	bp->b_blkno = start;
	bp->av_forw = NULL;
	bp->av_back = NULL;
	bp->b_edev = DDI_DEV_T_NONE; /* don't have dev_t */

	mutex_enter(&vdp->xdf_dev_lk);
	kstat_waitq_enter(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));
	if (vdp->xdf_f_act == NULL) {
		vdp->xdf_f_act = vdp->xdf_l_act = bp;
	} else {
		vdp->xdf_l_act->av_forw = bp;
		vdp->xdf_l_act = bp;
	}
	mutex_exit(&vdp->xdf_dev_lk);
	xdf_iostart(vdp);
	err = biowait(bp);

	ASSERT(bp->b_flags & B_DONE);

	freerbuf(bp);
	return (err);
}

/*
 * synthetic geometry
 */
#define	XDF_NSECTS	256
#define	XDF_NHEADS	16

static int
xdf_lb_getcap(dev_info_t *devi, diskaddr_t *capp)
{
	xdf_t *vdp;

	vdp = ddi_get_soft_state(vbd_ss, ddi_get_instance(devi));

	if (vdp == NULL)
		return (ENXIO);

	mutex_enter(&vdp->xdf_dev_lk);
	*capp = vdp->xdf_xdev_nblocks;
	DPRINTF(LBL_DBG, ("capacity %llu\n", *capp));
	mutex_exit(&vdp->xdf_dev_lk);
	return (0);
}

static int
xdf_lb_getpgeom(dev_info_t *devi, cmlb_geom_t *geomp)
{
	xdf_t *vdp;
	uint_t ncyl;
	uint_t spc = XDF_NHEADS * XDF_NSECTS;

	vdp = ddi_get_soft_state(vbd_ss, ddi_get_instance(devi));

	if (vdp == NULL)
		return (ENXIO);

	ncyl = vdp->xdf_xdev_nblocks / spc;

	geomp->g_ncyl = ncyl == 0 ? 1 : ncyl;
	geomp->g_acyl = 0;
	geomp->g_nhead = XDF_NHEADS;
	geomp->g_secsize = XB_BSIZE;
	geomp->g_nsect = XDF_NSECTS;
	geomp->g_intrlv = 0;
	geomp->g_rpm = 7200;
	geomp->g_capacity = vdp->xdf_xdev_nblocks;
	return (0);
}

/*
 * No real HBA, no geometry available from it
 */
/*ARGSUSED*/
static int
xdf_lb_getvgeom(dev_info_t *devi, cmlb_geom_t *geomp)
{
	return (EINVAL);
}

static int
xdf_lb_getattribute(dev_info_t *devi, tg_attribute_t *tgattributep)
{
	xdf_t *vdp;

	if (!(vdp = ddi_get_soft_state(vbd_ss, ddi_get_instance(devi))))
		return (ENXIO);

	if (XD_IS_RO(vdp))
		tgattributep->media_is_writable = 0;
	else
		tgattributep->media_is_writable = 1;
	return (0);
}

/* ARGSUSED3 */
static int
xdf_lb_getinfo(dev_info_t *devi, int cmd, void *arg, void *tg_cookie)
{
	switch (cmd) {
	case TG_GETPHYGEOM:
		return (xdf_lb_getpgeom(devi, (cmlb_geom_t *)arg));
	case TG_GETVIRTGEOM:
		return (xdf_lb_getvgeom(devi, (cmlb_geom_t *)arg));
	case TG_GETCAPACITY:
		return (xdf_lb_getcap(devi, (diskaddr_t *)arg));
	case TG_GETBLOCKSIZE:
		*(uint32_t *)arg = XB_BSIZE;
		return (0);
	case TG_GETATTR:
		return (xdf_lb_getattribute(devi, (tg_attribute_t *)arg));
	default:
		return (ENOTTY);
	}
}

/*
 * Kick-off connect process
 * Status should be XD_UNKNOWN or XD_CLOSED
 * On success, status will be changed to XD_INIT
 * On error, status won't be changed
 */
static int
xdf_start_connect(xdf_t *vdp)
{
	char *xsnode;
	grant_ref_t gref;
	xenbus_transaction_t xbt;
	int rv;
	dev_info_t *dip = vdp->xdf_dip;

	if ((vdp->xdf_peer = xvdi_get_oeid(dip)) == (domid_t)-1)
		goto errout;

	if (xvdi_alloc_evtchn(dip) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: failed to alloc event channel",
		    ddi_get_name_addr(dip));
		goto errout;
	}
	if (ddi_add_intr(dip, 0, NULL, NULL, xdf_intr, (caddr_t)vdp) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf_start_connect: xdf@%s: "
		    "failed to add intr handler", ddi_get_name_addr(dip));
		goto errout1;
	}

	if (xvdi_alloc_ring(dip, BLKIF_RING_SIZE,
	    sizeof (union blkif_sring_entry), &gref, &vdp->xdf_xb_ring) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdf@%s: failed to alloc comm ring",
		    ddi_get_name_addr(dip));
		goto errout2;
	}
	vdp->xdf_xb_ring_hdl = vdp->xdf_xb_ring->xr_acc_hdl; /* ugly!! */

	/*
	 * Write into xenstore the info needed by backend
	 */
	if ((xsnode = xvdi_get_xsname(dip)) == NULL) {
		cmn_err(CE_WARN, "xdf@%s: "
		    "failed to get xenstore node path",
		    ddi_get_name_addr(dip));
		goto fail_trans;
	}
trans_retry:
	if (xenbus_transaction_start(&xbt)) {
		cmn_err(CE_WARN, "xdf@%s: failed to start transaction",
		    ddi_get_name_addr(dip));
		xvdi_fatal_error(dip, EIO, "transaction start");
		goto fail_trans;
	}

	if (rv = xenbus_printf(xbt, xsnode, "ring-ref", "%u", gref)) {
		cmn_err(CE_WARN, "xdf@%s: failed to write ring-ref",
		    ddi_get_name_addr(dip));
		xvdi_fatal_error(dip, rv, "writing ring-ref");
		goto abort_trans;
	}

	if (rv = xenbus_printf(xbt, xsnode, "event-channel", "%u",
	    xvdi_get_evtchn(dip))) {
		cmn_err(CE_WARN, "xdf@%s: failed to write event-channel",
		    ddi_get_name_addr(dip));
		xvdi_fatal_error(dip, rv, "writing event-channel");
		goto abort_trans;
	}

	if ((rv = xvdi_switch_state(dip, xbt, XenbusStateInitialised)) > 0) {
		cmn_err(CE_WARN, "xdf@%s: "
		    "failed to switch state to XenbusStateInitialised",
		    ddi_get_name_addr(dip));
		xvdi_fatal_error(dip, rv, "writing state");
		goto abort_trans;
	}

	/* kick-off connect process */
	if (rv = xenbus_transaction_end(xbt, 0)) {
		if (rv == EAGAIN)
			goto trans_retry;
		cmn_err(CE_WARN, "xdf@%s: failed to end transaction",
		    ddi_get_name_addr(dip));
		xvdi_fatal_error(dip, rv, "completing transaction");
		goto fail_trans;
	}

	ASSERT(mutex_owned(&vdp->xdf_cb_lk));
	mutex_enter(&vdp->xdf_dev_lk);
	vdp->xdf_status = XD_INIT;
	mutex_exit(&vdp->xdf_dev_lk);

	return (DDI_SUCCESS);

abort_trans:
	(void) xenbus_transaction_end(xbt, 1);
fail_trans:
	xvdi_free_ring(vdp->xdf_xb_ring);
errout2:
	(void) ddi_remove_intr(vdp->xdf_dip, 0, NULL);
errout1:
	xvdi_free_evtchn(dip);
errout:
	cmn_err(CE_WARN, "xdf@%s: fail to kick-off connecting",
	    ddi_get_name_addr(dip));
	return (DDI_FAILURE);
}

/*
 * Kick-off disconnect process
 * Status won't be changed
 */
static int
xdf_start_disconnect(xdf_t *vdp)
{
	if (xvdi_switch_state(vdp->xdf_dip, XBT_NULL, XenbusStateClosed) > 0) {
		cmn_err(CE_WARN, "xdf@%s: fail to kick-off disconnecting",
		    ddi_get_name_addr(vdp->xdf_dip));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
xdf_get_flush_block(xdf_t *vdp)
{
	/*
	 * Get a DEV_BSIZE aligned bufer
	 */
	vdp->xdf_flush_mem = kmem_alloc(DEV_BSIZE * 2, KM_SLEEP);
	vdp->xdf_cache_flush_block =
	    (char *)P2ROUNDUP((uintptr_t)(vdp->xdf_flush_mem), DEV_BSIZE);
	if (xdf_lb_rdwr(vdp->xdf_dip, TG_READ, vdp->xdf_cache_flush_block,
	    xdf_flush_block, DEV_BSIZE, NULL) != 0)
		return (DDI_FAILURE);
	return (DDI_SUCCESS);
}

/*
 * Finish other initialization after we've connected to backend
 * Status should be XD_INIT before calling this routine
 * On success, status should be changed to XD_READY
 * On error, status should stay XD_INIT
 */
static int
xdf_post_connect(xdf_t *vdp)
{
	int rv;
	uint_t len;
	char *type;
	char *barrier;
	dev_info_t *devi = vdp->xdf_dip;

	/*
	 * Determine if feature barrier is supported by backend
	 */
	if (xenbus_read(XBT_NULL, xvdi_get_oename(devi),
	    "feature-barrier", (void **)&barrier, &len) == 0) {
		vdp->xdf_feature_barrier = 1;
		kmem_free(barrier, len);
	} else {
		cmn_err(CE_NOTE, "xdf@%s: failed to read feature-barrier",
		    ddi_get_name_addr(vdp->xdf_dip));
		vdp->xdf_feature_barrier = 0;
	}

	/* probe backend */
	if (rv = xenbus_gather(XBT_NULL, xvdi_get_oename(devi),
	    "sectors", "%"SCNu64, &vdp->xdf_xdev_nblocks,
	    "info", "%u", &vdp->xdf_xdev_info, NULL)) {
		cmn_err(CE_WARN, "xdf_post_connect: xdf@%s: "
		    "cannot read backend info", ddi_get_name_addr(devi));
		xvdi_fatal_error(devi, rv, "reading backend info");
		return (DDI_FAILURE);
	}

	/* fix disk type */
	if (xenbus_read(XBT_NULL, xvdi_get_xsname(devi), "device-type",
	    (void **)&type, &len) != 0) {
		cmn_err(CE_WARN, "xdf_post_connect: xdf@%s: "
		    "cannot read device-type", ddi_get_name_addr(devi));
		xvdi_fatal_error(devi, rv, "reading device-type");
		return (DDI_FAILURE);
	}
	if (strcmp(type, "cdrom") == 0)
		vdp->xdf_xdev_info |= VDISK_CDROM;
	kmem_free(type, len);

	/*
	 * We've created all the minor nodes via cmlb_attach() using default
	 * value in xdf_attach() to make it possbile to block in xdf_open(),
	 * in case there's anyone (say, booting thread) ever trying to open
	 * it before connected to backend. We will refresh all those minor
	 * nodes w/ latest info we've got now when we are almost connected.
	 *
	 * Don't do this when xdf is already opened by someone (could happen
	 * during resume), for that cmlb_attach() will invalid the label info
	 * and confuse those who has already opened the node, which is bad.
	 */
	if (!xdf_isopen(vdp, -1) && (XD_IS_CD(vdp) || XD_IS_RM(vdp))) {
		/* re-init cmlb w/ latest info we got from backend */
		if (cmlb_attach(devi, &xdf_lb_ops,
		    XD_IS_CD(vdp) ? DTYPE_RODIRECT : DTYPE_DIRECT,
		    XD_IS_RM(vdp), 1, DDI_NT_BLOCK,
		    CMLB_FAKE_LABEL_ONE_PARTITION,
		    vdp->xdf_vd_lbl, NULL) != 0) {
			cmn_err(CE_WARN, "xdf@%s: cmlb attach failed",
			    ddi_get_name_addr(devi));
			return (DDI_FAILURE);
		}
	}

	/* mark vbd is ready for I/O */
	ASSERT(mutex_owned(&vdp->xdf_cb_lk));
	mutex_enter(&vdp->xdf_dev_lk);
	vdp->xdf_status = XD_READY;
	mutex_exit(&vdp->xdf_dev_lk);
	/*
	 * If backend has feature-barrier, see if it supports disk
	 * cache flush op.
	 */
	vdp->xdf_flush_supported = 0;
	if (vdp->xdf_feature_barrier) {
		/*
		 * Pretend we already know flush is supported so probe
		 * will attempt the correct op.
		 */
		vdp->xdf_flush_supported = 1;
		if (xdf_lb_rdwr(vdp->xdf_dip, TG_WRITE, NULL, 0, 0, 0) == 0) {
			vdp->xdf_flush_supported = 1;
		} else {
			vdp->xdf_flush_supported = 0;
			/*
			 * If the other end does not support the cache flush op
			 * then we must use a barrier-write to force disk
			 * cache flushing.  Barrier writes require that a data
			 * block actually be written.
			 * Cache a block to barrier-write when we are
			 * asked to perform a flush.
			 * XXX - would it be better to just copy 1 block
			 * (512 bytes) from whatever write we did last
			 * and rewrite that block?
			 */
			if (xdf_get_flush_block(vdp) != DDI_SUCCESS)
				return (DDI_FAILURE);
		}
	}

	cmn_err(CE_CONT, "?xdf@%s: %"PRIu64" blocks", ddi_get_name_addr(devi),
	    (uint64_t)vdp->xdf_xdev_nblocks);

	return (DDI_SUCCESS);
}

/*
 * Finish other uninitialization after we've disconnected from backend
 * when status is XD_CLOSING or XD_INIT. After returns, status is XD_CLOSED
 */
static void
xdf_post_disconnect(xdf_t *vdp)
{
	(void) ddi_remove_intr(vdp->xdf_dip, 0, NULL);
	xvdi_free_evtchn(vdp->xdf_dip);
	xvdi_free_ring(vdp->xdf_xb_ring);
	vdp->xdf_xb_ring = NULL;
	vdp->xdf_xb_ring_hdl = NULL;
	vdp->xdf_peer = (domid_t)-1;

	ASSERT(mutex_owned(&vdp->xdf_cb_lk));
	mutex_enter(&vdp->xdf_dev_lk);
	vdp->xdf_status = XD_CLOSED;
	mutex_exit(&vdp->xdf_dev_lk);
}

/*ARGSUSED*/
static void
xdf_oe_change(dev_info_t *dip, ddi_eventcookie_t id, void *arg, void *impl_data)
{
	XenbusState new_state = *(XenbusState *)impl_data;
	xdf_t *vdp = (xdf_t *)ddi_get_driver_private(dip);
	boolean_t unexpect_die = B_FALSE;
	int status;

	DPRINTF(DDI_DBG, ("xdf@%s: otherend state change to %d!\n",
	    ddi_get_name_addr(dip), new_state));

	mutex_enter(&vdp->xdf_cb_lk);

	if (xdf_check_state_transition(vdp, new_state) == DDI_FAILURE) {
		mutex_exit(&vdp->xdf_cb_lk);
		return;
	}

	switch (new_state) {
	case XenbusStateInitialising:
		ASSERT(vdp->xdf_status == XD_CLOSED);
		/*
		 * backend recovered from a previous failure,
		 * kick-off connect process again
		 */
		if (xdf_start_connect(vdp) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "xdf@%s:"
			    " failed to start reconnecting to backend",
			    ddi_get_name_addr(dip));
		}
		break;
	case XenbusStateConnected:
		ASSERT(vdp->xdf_status == XD_INIT);
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateConnected);
		/* finish final init after connect */
		if (xdf_post_connect(vdp) != DDI_SUCCESS)
			(void) xdf_start_disconnect(vdp);
		break;
	case XenbusStateClosing:
		if (vdp->xdf_status == XD_READY) {
			mutex_enter(&vdp->xdf_dev_lk);
			if (xdf_isopen(vdp, -1)) {
				cmn_err(CE_NOTE, "xdf@%s: hot-unplug failed, "
				    "still in use", ddi_get_name_addr(dip));
				mutex_exit(&vdp->xdf_dev_lk);
				break;
			} else {
				vdp->xdf_status = XD_CLOSING;
			}
			mutex_exit(&vdp->xdf_dev_lk);
		}
		(void) xdf_start_disconnect(vdp);
		break;
	case XenbusStateClosed:
		/* first check if BE closed unexpectedly */
		mutex_enter(&vdp->xdf_dev_lk);
		if (xdf_isopen(vdp, -1)) {
			unexpect_die = B_TRUE;
			unexpectedie(vdp);
			cmn_err(CE_WARN, "xdf@%s: backend closed, "
			    "reconnecting...", ddi_get_name_addr(dip));
		}
		mutex_exit(&vdp->xdf_dev_lk);

		if (vdp->xdf_status == XD_READY) {
			mutex_enter(&vdp->xdf_dev_lk);
			vdp->xdf_status = XD_CLOSING;
			mutex_exit(&vdp->xdf_dev_lk);

#ifdef	DOMU_BACKEND
			(void) xvdi_post_event(dip, XEN_HP_REMOVE);
#endif

			xdf_post_disconnect(vdp);
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
		} else if ((vdp->xdf_status == XD_INIT) ||
		    (vdp->xdf_status == XD_CLOSING)) {
			xdf_post_disconnect(vdp);
		} else {
			mutex_enter(&vdp->xdf_dev_lk);
			vdp->xdf_status = XD_CLOSED;
			mutex_exit(&vdp->xdf_dev_lk);
		}
	}

	/* notify anybody waiting for oe state change */
	mutex_enter(&vdp->xdf_dev_lk);
	cv_broadcast(&vdp->xdf_dev_cv);
	mutex_exit(&vdp->xdf_dev_lk);

	status = vdp->xdf_status;
	mutex_exit(&vdp->xdf_cb_lk);

	if (status == XD_READY) {
		xdf_iostart(vdp);
	} else if ((status == XD_CLOSED) && !unexpect_die) {
		/* interface is closed successfully, remove all minor nodes */
		cmlb_detach(vdp->xdf_vd_lbl, NULL);
		cmlb_free_handle(&vdp->xdf_vd_lbl);
	}
}

/* check if partition is open, -1 - check all partitions on the disk */
static boolean_t
xdf_isopen(xdf_t *vdp, int partition)
{
	int i;
	ulong_t parbit;
	boolean_t rval = B_FALSE;

	if (partition == -1)
		parbit = (ulong_t)-1;
	else
		parbit = 1 << partition;

	for (i = 0; i < OTYPCNT; i++) {
		if (vdp->xdf_vd_open[i] & parbit)
			rval = B_TRUE;
	}

	return (rval);
}

/*
 * Xdf_check_state_transition will check the XenbusState change to see
 * if the change is a valid transition or not.
 * The new state is written by backend domain, or by running xenstore-write
 * to change it manually in dom0
 */
static int
xdf_check_state_transition(xdf_t *vdp, XenbusState oestate)
{
	int status;
	int stcheck;
#define	STOK	0 /* need further process */
#define	STNOP	1 /* no action need taking */
#define	STBUG	2 /* unexpected state change, could be a bug */

	status = vdp->xdf_status;
	stcheck = STOK;

	switch (status) {
	case XD_UNKNOWN:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateConnected))
			stcheck = STBUG;
		else if ((oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised))
			stcheck = STNOP;
		break;
	case XD_INIT:
		if (oestate == XenbusStateUnknown)
			stcheck = STBUG;
		else if ((oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised))
			stcheck = STNOP;
		break;
	case XD_READY:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised))
			stcheck = STBUG;
		else if (oestate == XenbusStateConnected)
			stcheck = STNOP;
		break;
	case XD_CLOSING:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised)		||
		    (oestate == XenbusStateConnected))
			stcheck = STBUG;
		else if (oestate == XenbusStateClosing)
			stcheck = STNOP;
		break;
	case XD_CLOSED:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateConnected))
			stcheck = STBUG;
		else if ((oestate == XenbusStateInitWait)	||
		    (oestate == XenbusStateInitialised)		||
		    (oestate == XenbusStateClosing)		||
		    (oestate == XenbusStateClosed))
			stcheck = STNOP;
		break;
	case XD_SUSPEND:
	default:
			stcheck = STBUG;
	}

	if (stcheck == STOK)
		return (DDI_SUCCESS);

	if (stcheck == STBUG)
		cmn_err(CE_NOTE, "xdf@%s: unexpected otherend "
		    "state change to %d!, when status is %d",
		    ddi_get_name_addr(vdp->xdf_dip), oestate, status);

	return (DDI_FAILURE);
}

static int
xdf_connect(xdf_t *vdp, boolean_t wait)
{
	ASSERT(mutex_owned(&vdp->xdf_dev_lk));
	while (vdp->xdf_status != XD_READY) {
		if (!wait || (vdp->xdf_status > XD_READY))
			break;

		if (cv_wait_sig(&vdp->xdf_dev_cv, &vdp->xdf_dev_lk) == 0)
			break;
	}

	return (vdp->xdf_status);
}

/*
 * callback func when DMA/GTE resources is available
 *
 * Note: we only register one callback function to grant table subsystem
 * since we only have one 'struct gnttab_free_callback' in xdf_t.
 */
static int
xdf_dmacallback(caddr_t arg)
{
	xdf_t *vdp = (xdf_t *)arg;
	ASSERT(vdp != NULL);

	DPRINTF(DMA_DBG, ("xdf@%s: DMA callback started\n",
	    ddi_get_name_addr(vdp->xdf_dip)));

	ddi_trigger_softintr(vdp->xdf_softintr_id);
	return (DDI_DMA_CALLBACK_DONE);
}

static uint_t
xdf_iorestart(caddr_t arg)
{
	xdf_t *vdp = (xdf_t *)arg;

	ASSERT(vdp != NULL);

	mutex_enter(&vdp->xdf_dev_lk);
	ASSERT(ISDMACBON(vdp));
	SETDMACBOFF(vdp);
	mutex_exit(&vdp->xdf_dev_lk);

	xdf_iostart(vdp);

	return (DDI_INTR_CLAIMED);
}

static void
xdf_timeout_handler(void *arg)
{
	xdf_t *vdp = arg;

	mutex_enter(&vdp->xdf_dev_lk);
	vdp->xdf_timeout_id = 0;
	mutex_exit(&vdp->xdf_dev_lk);

	/* new timeout thread could be re-scheduled */
	xdf_iostart(vdp);
}

/*
 * Alloc a vreq for this bp
 * bp->av_back contains the pointer to the vreq upon return
 */
static v_req_t *
vreq_get(xdf_t *vdp, buf_t *bp)
{
	v_req_t *vreq = NULL;

	ASSERT(BP2VREQ(bp) == NULL);

	vreq = kmem_cache_alloc(xdf_vreq_cache, KM_NOSLEEP);
	if (vreq == NULL) {
		if (vdp->xdf_timeout_id == 0)
			/* restart I/O after one second */
			vdp->xdf_timeout_id =
			    timeout(xdf_timeout_handler, vdp, hz);
		return (NULL);
	}
	bzero(vreq, sizeof (v_req_t));

	list_insert_head(&vdp->xdf_vreq_act, (void *)vreq);
	bp->av_back = (buf_t *)vreq;
	vreq->v_buf = bp;
	vreq->v_status = VREQ_INIT;
	/* init of other fields in vreq is up to the caller */

	return (vreq);
}

static void
vreq_free(xdf_t *vdp, v_req_t *vreq)
{
	buf_t *bp = vreq->v_buf;

	list_remove(&vdp->xdf_vreq_act, (void *)vreq);

	switch (vreq->v_status) {
	case VREQ_DMAWIN_DONE:
	case VREQ_GS_ALLOCED:
	case VREQ_DMABUF_BOUND:
		(void) ddi_dma_unbind_handle(vreq->v_dmahdl);
		/*FALLTHRU*/
	case VREQ_DMAMEM_ALLOCED:
		if (!ALIGNED_XFER(bp)) {
			ASSERT(vreq->v_abuf != NULL);
			if (!IS_ERROR(bp) && IS_READ(bp))
				bcopy(vreq->v_abuf, bp->b_un.b_addr,
				    bp->b_bcount);
			ddi_dma_mem_free(&vreq->v_align);
		}
		/*FALLTHRU*/
	case VREQ_MEMDMAHDL_ALLOCED:
		if (!ALIGNED_XFER(bp))
			ddi_dma_free_handle(&vreq->v_memdmahdl);
		/*FALLTHRU*/
	case VREQ_DMAHDL_ALLOCED:
		ddi_dma_free_handle(&vreq->v_dmahdl);
		break;
	default:
		break;
	}
	vreq->v_buf->av_back = NULL;
	kmem_cache_free(xdf_vreq_cache, vreq);
}

/*
 * Initalize the DMA and grant table resources for the buf
 */
static int
vreq_setup(xdf_t *vdp, v_req_t *vreq)
{
	int rc;
	ddi_dma_attr_t dmaattr;
	uint_t ndcs, ndws;
	ddi_dma_handle_t dh;
	ddi_dma_handle_t mdh;
	ddi_dma_cookie_t dc;
	ddi_acc_handle_t abh;
	caddr_t	aba;
	ge_slot_t *gs;
	size_t bufsz;
	off_t off;
	size_t sz;
	buf_t *bp = vreq->v_buf;
	int dma_flags = (IS_READ(bp) ? DDI_DMA_READ : DDI_DMA_WRITE) |
	    DDI_DMA_STREAMING | DDI_DMA_PARTIAL;

	switch (vreq->v_status) {
	case VREQ_INIT:
		if (IS_FLUSH_DISKCACHE(bp)) {
			if ((gs = gs_get(vdp, IS_READ(bp))) == NULL) {
				DPRINTF(DMA_DBG, (
				    "xdf@%s: get ge_slotfailed\n",
				    ddi_get_name_addr(vdp->xdf_dip)));
				return (DDI_FAILURE);
			}
			vreq->v_blkno = 0;
			vreq->v_nslots = 1;
			vreq->v_gs = gs;
			vreq->v_flush_diskcache = FLUSH_DISKCACHE;
			gs->vreq = vreq;
			return (DDI_SUCCESS);
		}

		if (IS_WRITE_BARRIER(vdp, bp))
			vreq->v_flush_diskcache = WRITE_BARRIER;
		vreq->v_blkno = bp->b_blkno +
		    (diskaddr_t)(uintptr_t)bp->b_private;
		bp->b_private = NULL;
		/* See if we wrote new data to our flush block */
		if (!IS_READ(bp) && USE_WRITE_BARRIER(vdp))
			check_fbwrite(vdp, bp, vreq->v_blkno);
		vreq->v_status = VREQ_INIT_DONE;
		/*FALLTHRU*/

	case VREQ_INIT_DONE:
		/*
		 * alloc DMA handle
		 */
		rc = ddi_dma_alloc_handle(vdp->xdf_dip, &xb_dma_attr,
		    xdf_dmacallback, (caddr_t)vdp, &dh);
		if (rc != DDI_SUCCESS) {
			SETDMACBON(vdp);
			DPRINTF(DMA_DBG, ("xdf@%s: DMA handle alloc failed\n",
			    ddi_get_name_addr(vdp->xdf_dip)));
			return (DDI_FAILURE);
		}

		vreq->v_dmahdl = dh;
		vreq->v_status = VREQ_DMAHDL_ALLOCED;
		/*FALLTHRU*/

	case VREQ_DMAHDL_ALLOCED:
		/*
		 * alloc dma handle for 512-byte aligned buf
		 */
		if (!ALIGNED_XFER(bp)) {
			/*
			 * XXPV: we need to temporarily enlarge the seg
			 * boundary and s/g length to work round CR6381968
			 */
			dmaattr = xb_dma_attr;
			dmaattr.dma_attr_seg = (uint64_t)-1;
			dmaattr.dma_attr_sgllen = INT_MAX;
			rc = ddi_dma_alloc_handle(vdp->xdf_dip, &dmaattr,
			    xdf_dmacallback, (caddr_t)vdp, &mdh);
			if (rc != DDI_SUCCESS) {
				SETDMACBON(vdp);
				DPRINTF(DMA_DBG, ("xdf@%s: unaligned buf DMA"
				    "handle alloc failed\n",
				    ddi_get_name_addr(vdp->xdf_dip)));
				return (DDI_FAILURE);
			}
			vreq->v_memdmahdl = mdh;
			vreq->v_status = VREQ_MEMDMAHDL_ALLOCED;
		}
		/*FALLTHRU*/

	case VREQ_MEMDMAHDL_ALLOCED:
		/*
		 * alloc 512-byte aligned buf
		 */
		if (!ALIGNED_XFER(bp)) {
			if (bp->b_flags & (B_PAGEIO | B_PHYS))
				bp_mapin(bp);

			rc = ddi_dma_mem_alloc(vreq->v_memdmahdl,
			    roundup(bp->b_bcount, XB_BSIZE), &xc_acc_attr,
			    DDI_DMA_STREAMING, xdf_dmacallback, (caddr_t)vdp,
			    &aba, &bufsz, &abh);
			if (rc != DDI_SUCCESS) {
				SETDMACBON(vdp);
				DPRINTF(DMA_DBG, (
				    "xdf@%s: DMA mem allocation failed\n",
				    ddi_get_name_addr(vdp->xdf_dip)));
				return (DDI_FAILURE);
			}

			vreq->v_abuf = aba;
			vreq->v_align = abh;
			vreq->v_status = VREQ_DMAMEM_ALLOCED;

			ASSERT(bufsz >= bp->b_bcount);
			if (!IS_READ(bp))
				bcopy(bp->b_un.b_addr, vreq->v_abuf,
				    bp->b_bcount);
		}
		/*FALLTHRU*/

	case VREQ_DMAMEM_ALLOCED:
		/*
		 * dma bind
		 */
		if (ALIGNED_XFER(bp)) {
			rc = ddi_dma_buf_bind_handle(vreq->v_dmahdl, bp,
			    dma_flags, xdf_dmacallback, (caddr_t)vdp,
			    &dc, &ndcs);
		} else {
			rc = ddi_dma_addr_bind_handle(vreq->v_dmahdl,
			    NULL, vreq->v_abuf, bp->b_bcount, dma_flags,
			    xdf_dmacallback, (caddr_t)vdp, &dc, &ndcs);
		}
		if (rc == DDI_DMA_MAPPED || rc == DDI_DMA_PARTIAL_MAP) {
			/* get num of dma windows */
			if (rc == DDI_DMA_PARTIAL_MAP) {
				rc = ddi_dma_numwin(vreq->v_dmahdl, &ndws);
				ASSERT(rc == DDI_SUCCESS);
			} else {
				ndws = 1;
			}
		} else {
			SETDMACBON(vdp);
			DPRINTF(DMA_DBG, ("xdf@%s: DMA bind failed\n",
			    ddi_get_name_addr(vdp->xdf_dip)));
			return (DDI_FAILURE);
		}

		vreq->v_dmac = dc;
		vreq->v_dmaw = 0;
		vreq->v_ndmacs = ndcs;
		vreq->v_ndmaws = ndws;
		vreq->v_nslots = ndws;
		vreq->v_status = VREQ_DMABUF_BOUND;
		/*FALLTHRU*/

	case VREQ_DMABUF_BOUND:
		/*
		 * get ge_slot, callback is set upon failure from gs_get(),
		 * if not set previously
		 */
		if ((gs = gs_get(vdp, IS_READ(bp))) == NULL) {
			DPRINTF(DMA_DBG, ("xdf@%s: get ge_slot failed\n",
			    ddi_get_name_addr(vdp->xdf_dip)));
			return (DDI_FAILURE);
		}

		vreq->v_gs = gs;
		gs->vreq = vreq;
		vreq->v_status = VREQ_GS_ALLOCED;
		break;

	case VREQ_GS_ALLOCED:
		/* nothing need to be done */
		break;

	case VREQ_DMAWIN_DONE:
		/*
		 * move to the next dma window
		 */
		ASSERT((vreq->v_dmaw + 1) < vreq->v_ndmaws);

		/* get a ge_slot for this DMA window */
		if ((gs = gs_get(vdp, IS_READ(bp))) == NULL) {
			DPRINTF(DMA_DBG, ("xdf@%s: get ge_slot failed\n",
			    ddi_get_name_addr(vdp->xdf_dip)));
			return (DDI_FAILURE);
		}

		vreq->v_gs = gs;
		gs->vreq = vreq;
		vreq->v_dmaw++;
		rc = ddi_dma_getwin(vreq->v_dmahdl, vreq->v_dmaw, &off, &sz,
		    &vreq->v_dmac, &vreq->v_ndmacs);
		ASSERT(rc == DDI_SUCCESS);
		vreq->v_status = VREQ_GS_ALLOCED;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static ge_slot_t *
gs_get(xdf_t *vdp, int isread)
{
	grant_ref_t gh;
	ge_slot_t *gs;

	/* try to alloc GTEs needed in this slot, first */
	if (gnttab_alloc_grant_references(
	    BLKIF_MAX_SEGMENTS_PER_REQUEST, &gh) == -1) {
		if (vdp->xdf_gnt_callback.next == NULL) {
			SETDMACBON(vdp);
			gnttab_request_free_callback(
			    &vdp->xdf_gnt_callback,
			    (void (*)(void *))xdf_dmacallback,
			    (void *)vdp,
			    BLKIF_MAX_SEGMENTS_PER_REQUEST);
		}
		return (NULL);
	}

	gs = kmem_cache_alloc(xdf_gs_cache, KM_NOSLEEP);
	if (gs == NULL) {
		gnttab_free_grant_references(gh);
		if (vdp->xdf_timeout_id == 0)
			/* restart I/O after one second */
			vdp->xdf_timeout_id =
			    timeout(xdf_timeout_handler, vdp, hz);
		return (NULL);
	}

	/* init gs_slot */
	list_insert_head(&vdp->xdf_gs_act, (void *)gs);
	gs->oeid = vdp->xdf_peer;
	gs->isread = isread;
	gs->ghead = gh;
	gs->ngrefs = 0;

	return (gs);
}

static void
gs_free(xdf_t *vdp, ge_slot_t *gs)
{
	int i;
	grant_ref_t *gp = gs->ge;
	int ngrefs = gs->ngrefs;
	boolean_t isread = gs->isread;

	list_remove(&vdp->xdf_gs_act, (void *)gs);

	/* release all grant table entry resources used in this slot */
	for (i = 0; i < ngrefs; i++, gp++)
		gnttab_end_foreign_access(*gp, !isread, 0);
	gnttab_free_grant_references(gs->ghead);

	kmem_cache_free(xdf_gs_cache, (void *)gs);
}

static grant_ref_t
gs_grant(ge_slot_t *gs, mfn_t mfn)
{
	grant_ref_t gr = gnttab_claim_grant_reference(&gs->ghead);

	ASSERT(gr != -1);
	ASSERT(gs->ngrefs < BLKIF_MAX_SEGMENTS_PER_REQUEST);
	gs->ge[gs->ngrefs++] = gr;
	gnttab_grant_foreign_access_ref(gr, gs->oeid, mfn, !gs->isread);

	return (gr);
}

static void
unexpectedie(xdf_t *vdp)
{
	/* clean up I/Os in ring that have responses */
	if (xvdi_ring_has_unconsumed_responses(vdp->xdf_xb_ring)) {
		mutex_exit(&vdp->xdf_dev_lk);
		(void) xdf_intr((caddr_t)vdp);
		mutex_enter(&vdp->xdf_dev_lk);
	}

	/* free up all grant table entries */
	while (!list_is_empty(&vdp->xdf_gs_act))
		gs_free(vdp, list_head(&vdp->xdf_gs_act));

	/*
	 * move bp back to active list orderly
	 * vreq_busy is updated in vreq_free()
	 */
	while (!list_is_empty(&vdp->xdf_vreq_act)) {
		v_req_t *vreq = list_head(&vdp->xdf_vreq_act);
		buf_t *bp = vreq->v_buf;

		bp->av_back = NULL;
		bp->b_resid = bp->b_bcount;
		if (vdp->xdf_f_act == NULL) {
			vdp->xdf_f_act = vdp->xdf_l_act = bp;
		} else {
			/* move to the head of list */
			bp->av_forw = vdp->xdf_f_act;
			vdp->xdf_f_act = bp;
		}
		kstat_runq_back_to_waitq(KSTAT_IO_PTR(vdp->xdf_xdev_iostat));
		vreq_free(vdp, vreq);
	}
}

static void
xdfmin(struct buf *bp)
{
	if (bp->b_bcount > xdf_maxphys)
		bp->b_bcount = xdf_maxphys;
}

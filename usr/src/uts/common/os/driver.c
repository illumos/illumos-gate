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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/debug.h>
#include <sys/tnf_probe.h>

/* Don't #include <sys/ddi.h> - it #undef's getmajor() */

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunpm.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/esunddi.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>
#include <sys/epm.h>
#include <sys/dacf.h>
#include <sys/sunmdi.h>
#include <sys/instance.h>
#include <sys/sdt.h>

static void i_attach_ctlop(dev_info_t *, ddi_attach_cmd_t, ddi_pre_post_t, int);
static void i_detach_ctlop(dev_info_t *, ddi_detach_cmd_t, ddi_pre_post_t, int);

/* decide what to do when a double dev_lclose is detected */
#ifdef	DEBUG
int		dev_lclose_ce = CE_PANIC;
#else	/* DEBUG */
int		dev_lclose_ce = CE_WARN;
#endif	/* DEBUG */

/*
 * Configuration-related entry points for nexus and leaf drivers
 */
int
devi_identify(dev_info_t *devi)
{
	struct dev_ops *ops;
	int (*fn)(dev_info_t *);

	if ((ops = ddi_get_driver(devi)) == NULL ||
	    (fn = ops->devo_identify) == NULL)
		return (-1);

	return ((*fn)(devi));
}

int
devi_probe(dev_info_t *devi)
{
	int rv, probe_failed;
	pm_ppm_cookie_t ppm_cookie;
	struct dev_ops *ops;
	int (*fn)(dev_info_t *);

	ops = ddi_get_driver(devi);
	ASSERT(ops);

	pm_pre_probe(devi, &ppm_cookie);

	/*
	 * probe(9E) in 2.0 implies that you can get
	 * away with not writing one of these .. so we
	 * pretend we're 'nulldev' if we don't find one (sigh).
	 */
	if ((fn = ops->devo_probe) == NULL) {
		if (ddi_dev_is_sid(devi) == DDI_SUCCESS)
			rv = DDI_PROBE_DONTCARE;
		else
			rv = DDI_PROBE_FAILURE;
	} else
		rv = (*fn)(devi);

	switch (rv) {
	case DDI_PROBE_DONTCARE:
	case DDI_PROBE_SUCCESS:
		probe_failed = 0;
		break;
	default:
		probe_failed = 1;
		break;
	}
	pm_post_probe(&ppm_cookie, rv, probe_failed);

	return (rv);
}


/*
 * devi_attach()
 * 	attach a device instance to the system if the driver supplies an
 * 	attach(9E) entrypoint.
 */
int
devi_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct dev_ops *ops;
	int error;
	int (*fn)(dev_info_t *, ddi_attach_cmd_t);
	pm_ppm_cookie_t pc;

	if ((error = mdi_pre_attach(devi, cmd)) != DDI_SUCCESS) {
		return (error);
	}

	pm_pre_attach(devi, &pc, cmd);

	if ((cmd == DDI_RESUME || cmd == DDI_PM_RESUME) &&
	    e_ddi_parental_suspend_resume(devi)) {
		error = e_ddi_resume(devi, cmd);
		goto done;
	}
	ops = ddi_get_driver(devi);
	ASSERT(ops);
	if ((fn = ops->devo_attach) == NULL) {
		error = DDI_FAILURE;
		goto done;
	}

	/*
	 * Call the driver's attach(9e) entrypoint
	 */
	i_attach_ctlop(devi, cmd, DDI_PRE, 0);
	error = (*fn)(devi, cmd);
	i_attach_ctlop(devi, cmd, DDI_POST, error);

done:
	pm_post_attach(&pc, error);
	mdi_post_attach(devi, cmd, error);

	return (error);
}

/*
 * devi_detach()
 * 	detach a device instance from the system if the driver supplies a
 * 	detach(9E) entrypoint.
 */
int
devi_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	struct dev_ops *ops;
	int error;
	int (*fn)(dev_info_t *, ddi_detach_cmd_t);
	pm_ppm_cookie_t pc;

	ASSERT(cmd == DDI_SUSPEND || cmd == DDI_PM_SUSPEND ||
	    cmd == DDI_DETACH);

	if ((cmd == DDI_SUSPEND || cmd == DDI_PM_SUSPEND) &&
	    e_ddi_parental_suspend_resume(devi)) {
		return (e_ddi_suspend(devi, cmd));
	}
	ops = ddi_get_driver(devi);
	ASSERT(ops);
	if ((fn = ops->devo_detach) == NULL)
		return (DDI_FAILURE);

	if ((error = mdi_pre_detach(devi, cmd)) != DDI_SUCCESS) {
		return (error);
	}
	i_detach_ctlop(devi, cmd, DDI_PRE, 0);
	pm_pre_detach(devi, cmd, &pc);

	/*
	 * Call the driver's detach routine
	 */
	error = (*fn)(devi, cmd);

	pm_post_detach(&pc, error);
	i_detach_ctlop(devi, cmd, DDI_POST, error);
	mdi_post_detach(devi, cmd, error);

	return (error);
}

static void
i_attach_ctlop(dev_info_t *devi, ddi_attach_cmd_t cmd, ddi_pre_post_t w,
    int ret)
{
	int error;
	struct attachspec as;
	dev_info_t *pdip = ddi_get_parent(devi);

	as.cmd = cmd;
	as.when = w;
	as.pdip = pdip;
	as.result = ret;
	(void) ddi_ctlops(devi, devi, DDI_CTLOPS_ATTACH, &as, &error);
}

static void
i_detach_ctlop(dev_info_t *devi, ddi_detach_cmd_t cmd, ddi_pre_post_t w,
    int ret)
{
	int error;
	struct detachspec ds;
	dev_info_t *pdip = ddi_get_parent(devi);

	ds.cmd = cmd;
	ds.when = w;
	ds.pdip = pdip;
	ds.result = ret;
	(void) ddi_ctlops(devi, devi, DDI_CTLOPS_DETACH, &ds, &error);
}

/*
 * This entry point not defined by Solaris 2.0 DDI/DKI, so
 * its inclusion here is somewhat moot.
 */
int
devi_reset(dev_info_t *devi, ddi_reset_cmd_t cmd)
{
	struct dev_ops *ops;
	int (*fn)(dev_info_t *, ddi_reset_cmd_t);

	if ((ops = ddi_get_driver(devi)) == NULL ||
	    (fn = ops->devo_reset) == NULL)
		return (DDI_FAILURE);

	return ((*fn)(devi, cmd));
}

int
devi_quiesce(dev_info_t *devi)
{
	struct dev_ops *ops;
	int (*fn)(dev_info_t *);

	if (((ops = ddi_get_driver(devi)) == NULL) ||
	    (ops->devo_rev < 4) || ((fn = ops->devo_quiesce) == NULL))
		return (DDI_FAILURE);

	return ((*fn)(devi));
}

/*
 * Leaf driver entry points. The following [cb]dev_* functions are *not* part
 * of the DDI, please use functions defined in <sys/sunldi.h> and driver_lyr.c.
 */
int
dev_open(dev_t *devp, int flag, int type, struct cred *cred)
{
	struct cb_ops   *cb;

	cb = devopsp[getmajor(*devp)]->devo_cb_ops;
	return ((*cb->cb_open)(devp, flag, type, cred));
}

int
dev_close(dev_t dev, int flag, int type, struct cred *cred)
{
	struct cb_ops   *cb;

	cb = (devopsp[getmajor(dev)])->devo_cb_ops;
	return ((*cb->cb_close)(dev, flag, type, cred));
}

/*
 * New Leaf driver open entry point.  We make a vnode and go through specfs
 * in order to obtain open close exclusions guarantees.  Note that we drop
 * OTYP_LYR if it was specified - we are going through specfs and it provides
 * last close semantics (FKLYR is provided to open(9E)).  Also, since
 * spec_open will drive attach via e_ddi_hold_devi_by_dev for a makespecvp
 * vnode with no SDIP_SET on the common snode, the dev_lopen caller no longer
 * needs to call ddi_hold_installed_driver.
 */
int
dev_lopen(dev_t *devp, int flag, int otype, struct cred *cred)
{
	struct vnode	*vp;
	int		error;
	struct vnode	*cvp;

	vp = makespecvp(*devp, (otype == OTYP_BLK) ? VBLK : VCHR);
	error = VOP_OPEN(&vp, flag | FKLYR, cred, NULL);
	if (error == 0) {
		/* Pick up the (possibly) new dev_t value. */
		*devp = vp->v_rdev;

		/*
		 * Place extra hold on the common vnode, which contains the
		 * open count, so that it is not destroyed by the VN_RELE of
		 * the shadow makespecvp vnode below.
		 */
		cvp = STOV(VTOCS(vp));
		VN_HOLD(cvp);
	}

	/* release the shadow makespecvp vnode. */
	VN_RELE(vp);
	return (error);
}

/*
 * Leaf driver close entry point.  We make a vnode and go through specfs in
 * order to obtain open close exclusions guarantees.  Note that we drop
 * OTYP_LYR if it was specified - we are going through specfs and it provides
 * last close semantics (FLKYR is provided to close(9E)).
 */
int
dev_lclose(dev_t dev, int flag, int otype, struct cred *cred)
{
	struct vnode	*vp;
	int		error;
	struct vnode	*cvp;
	char		*funcname;
	ulong_t		offset;

	vp = makespecvp(dev, (otype == OTYP_BLK) ? VBLK : VCHR);
	error = VOP_CLOSE(vp, flag | FKLYR, 1, (offset_t)0, cred, NULL);

	/*
	 * Release the extra dev_lopen hold on the common vnode. We inline a
	 * VN_RELE(cvp) call so that we can detect more dev_lclose calls than
	 * dev_lopen calls without panic. See vn_rele.  If our inline of
	 * vn_rele called VOP_INACTIVE(cvp, CRED(), ...) we would panic on the
	 * "release the makespecvp vnode" VN_RELE(vp) that follows  - so
	 * instead we diagnose this situation.  Note that the driver has
	 * still seen a double close(9E), but that would have occurred with
	 * the old dev_close implementation too.
	 */
	cvp = STOV(VTOCS(vp));
	mutex_enter(&cvp->v_lock);
	switch (cvp->v_count) {
	default:
		VN_RELE_LOCKED(cvp);
		break;

	case 0:
		VTOS(vp)->s_commonvp = NULL;	/* avoid panic */
		/*FALLTHROUGH*/
	case 1:
		/*
		 * The following message indicates a serious problem in the
		 * identified driver, the driver should be fixed. If obtaining
		 * a panic dump is needed to diagnose the driver problem then
		 * adding "set dev_lclose_ce=3" to /etc/system will cause a
		 * panic when this occurs.
		 */
		funcname = modgetsymname((uintptr_t)caller(), &offset);
		cmn_err(dev_lclose_ce, "dev_lclose: extra close of dev_t 0x%lx "
		    "from %s`%s()", dev, mod_containing_pc(caller()),
		    funcname ? funcname : "unknown...");
		break;
	}
	mutex_exit(&cvp->v_lock);

	/* release the makespecvp vnode. */
	VN_RELE(vp);
	return (error);
}

/*
 * Returns -1 or the instance number of the given dev_t as
 * interpreted by the device driver.  The code may load the driver
 * but it does not attach any instances.
 *
 * Instance is supposed to be a int but drivers have assumed that
 * the pointer was a pointer to "void *" instead of a pointer to
 * "int *" so we now explicitly pass a pointer to "void *" and then
 * cast the result to an int when returning the value.
 */
int
dev_to_instance(dev_t dev)
{
	major_t		major = getmajor(dev);
	struct dev_ops	*ops;
	void		*vinstance;
	int		error;

	/* verify that the driver is loaded */
	if ((ops = mod_hold_dev_by_major(major)) == NULL)
		return (-1);
	ASSERT(CB_DRV_INSTALLED(ops));

	/* verify that it supports the getinfo(9E) entry point */
	if (ops->devo_getinfo == NULL) {
		mod_rele_dev_by_major(major);
		return (-1);
	}

	/* ask the driver to extract the instance number from the devt */
	error = (*ops->devo_getinfo)(NULL, DDI_INFO_DEVT2INSTANCE,
	    (void *)dev, &vinstance);

	/* release the driver */
	mod_rele_dev_by_major(major);

	if (error != DDI_SUCCESS)
		return (-1);

	return ((int)(uintptr_t)vinstance);
}

static void
bdev_strategy_tnf_probe(struct buf *bp)
{
	/* Kernel probe */
	TNF_PROBE_5(strategy, "io blockio", /* CSTYLED */,
	    tnf_device, device, bp->b_edev,
	    tnf_diskaddr, block, bp->b_lblkno,
	    tnf_size, size, bp->b_bcount,
	    tnf_opaque, buf, bp,
	    tnf_bioflags, flags, bp->b_flags);
}

int
bdev_strategy(struct buf *bp)
{
	struct dev_ops *ops;

	ops = devopsp[getmajor(bp->b_edev)];

	/*
	 * Before we hit the io:::start probe, we need to fill in the b_dip
	 * field of the buf structure.  This should be -- for the most part --
	 * incredibly cheap.  If you're in this code looking to bum cycles,
	 * there is almost certainly bigger game further down the I/O path...
	 */
	(void) ops->devo_getinfo(NULL, DDI_INFO_DEVT2DEVINFO,
	    (void *)bp->b_edev, (void **)&bp->b_dip);

	DTRACE_IO1(start, struct buf *, bp);
	bp->b_flags |= B_STARTED;

	/*
	 * Call the TNF probe here instead of the inline code
	 * to force our compiler to use the tail call optimization.
	 */
	bdev_strategy_tnf_probe(bp);

	return (ops->devo_cb_ops->cb_strategy(bp));
}

int
bdev_print(dev_t dev, caddr_t str)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_print)(dev, str));
}

/*
 * Return number of DEV_BSIZE byte blocks.
 */
int
bdev_size(dev_t dev)
{
	uint_t		nblocks;
	uint_t		blksize;

	if ((nblocks = e_ddi_getprop(dev, VBLK, "nblocks",
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, -1)) == -1)
		return (-1);

	/* Get blksize, default to DEV_BSIZE */
	if ((blksize = e_ddi_getprop(dev, VBLK, "blksize",
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, -1)) == -1)
		blksize = e_ddi_getprop(DDI_DEV_T_ANY, VBLK, "device-blksize",
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, DEV_BSIZE);

	if (blksize >= DEV_BSIZE)
		return (nblocks * (blksize / DEV_BSIZE));
	else
		return (nblocks / (DEV_BSIZE / blksize));
}

/*
 * Same for 64-bit Nblocks property
 */
uint64_t
bdev_Size(dev_t dev)
{
	uint64_t	nblocks;
	uint_t		blksize;

	if ((nblocks = e_ddi_getprop_int64(dev, VBLK, "Nblocks",
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, -1)) == -1)
		return (-1);

	/* Get blksize, default to DEV_BSIZE */
	if ((blksize = e_ddi_getprop(dev, VBLK, "blksize",
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, -1)) == -1)
		blksize = e_ddi_getprop(DDI_DEV_T_ANY, VBLK, "device-blksize",
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, DEV_BSIZE);

	if (blksize >= DEV_BSIZE)
		return (nblocks * (blksize / DEV_BSIZE));
	else
		return (nblocks / (DEV_BSIZE / blksize));
}

int
bdev_dump(dev_t dev, caddr_t addr, daddr_t blkno, int blkcnt)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_dump)(dev, addr, blkno, blkcnt));
}

int
cdev_read(dev_t dev, struct uio *uiop, struct cred *cred)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_read)(dev, uiop, cred));
}

int
cdev_write(dev_t dev, struct uio *uiop, struct cred *cred)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_write)(dev, uiop, cred));
}

int
cdev_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, struct cred *cred,
    int *rvalp)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_ioctl)(dev, cmd, arg, mode, cred, rvalp));
}

int
cdev_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t mode)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_devmap)(dev, dhp, off, len, maplen, mode));
}

int
cdev_mmap(int (*mapfunc)(dev_t, off_t, int), dev_t dev, off_t off, int prot)
{
	return ((*mapfunc)(dev, off, prot));
}

int
cdev_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, cred_t *credp)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_segmap)(dev, off, as, addrp,
	    len, prot, maxprot, flags, credp));
}

int
cdev_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **pollhdrp)
{
	struct cb_ops	*cb;

	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	return ((*cb->cb_chpoll)(dev, events, anyyet, reventsp, pollhdrp));
}

/*
 * A 'size' property can be provided by a VCHR device.
 *
 * Since it's defined as zero for STREAMS devices, so we avoid the
 * overhead of looking it up.  Note also that we don't force an
 * unused driver into memory simply to ask about it's size.  We also
 * don't bother to ask it its size unless it's already been attached
 * (the attach routine is the earliest place the property will be created)
 *
 * XXX	In an ideal world, we'd call this at VOP_GETATTR() time.
 */
int
cdev_size(dev_t dev)
{
	major_t maj;
	struct devnames *dnp;

	if ((maj = getmajor(dev)) >= devcnt)
		return (0);

	dnp = &(devnamesp[maj]);
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (devopsp[maj] && devopsp[maj]->devo_cb_ops &&
	    !devopsp[maj]->devo_cb_ops->cb_str) {
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (e_ddi_getprop(dev, VCHR, "size",
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, 0));
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);
	return (0);
}

/*
 * same for 64-bit Size property
 */
uint64_t
cdev_Size(dev_t dev)
{
	major_t maj;
	struct devnames *dnp;

	if ((maj = getmajor(dev)) >= devcnt)
		return (0);

	dnp = &(devnamesp[maj]);
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (devopsp[maj] && devopsp[maj]->devo_cb_ops &&
	    !devopsp[maj]->devo_cb_ops->cb_str) {
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (e_ddi_getprop_int64(dev, VCHR, "Size",
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, 0));
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);
	return (0);
}

/*
 * XXX	This routine is poorly named, because block devices can and do
 *	have properties (see bdev_size() above).
 *
 * XXX	fix the comment in devops.h that claims that cb_prop_op
 *	is character-only.
 */
int
cdev_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	struct cb_ops	*cb;

	if ((cb = devopsp[DEVI(dip)->devi_major]->devo_cb_ops) == NULL)
		return (DDI_PROP_NOT_FOUND);

	return ((*cb->cb_prop_op)(dev, dip, prop_op, mod_flags,
	    name, valuep, lengthp));
}

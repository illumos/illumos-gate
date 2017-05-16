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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/dkio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/open.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/policy.h>
#include <sys/devpolicy.h>

#include <sys/proc.h>
#include <sys/user.h>
#include <sys/session.h>
#include <sys/vmsystm.h>
#include <sys/vtrace.h>
#include <sys/pathname.h>

#include <sys/fs/snode.h>

#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_dev.h>
#include <vm/seg_vn.h>

#include <fs/fs_subr.h>

#include <sys/esunddi.h>
#include <sys/autoconf.h>
#include <sys/sunndi.h>
#include <sys/contract/device_impl.h>


static int spec_open(struct vnode **, int, struct cred *, caller_context_t *);
static int spec_close(struct vnode *, int, int, offset_t, struct cred *,
	caller_context_t *);
static int spec_read(struct vnode *, struct uio *, int, struct cred *,
	caller_context_t *);
static int spec_write(struct vnode *, struct uio *, int, struct cred *,
	caller_context_t *);
static int spec_ioctl(struct vnode *, int, intptr_t, int, struct cred *, int *,
	caller_context_t *);
static int spec_getattr(struct vnode *, struct vattr *, int, struct cred *,
	caller_context_t *);
static int spec_setattr(struct vnode *, struct vattr *, int, struct cred *,
	caller_context_t *);
static int spec_access(struct vnode *, int, int, struct cred *,
	caller_context_t *);
static int spec_create(struct vnode *, char *, vattr_t *, enum vcexcl, int,
	struct vnode **, struct cred *, int, caller_context_t *, vsecattr_t *);
static int spec_fsync(struct vnode *, int, struct cred *, caller_context_t *);
static void spec_inactive(struct vnode *, struct cred *, caller_context_t *);
static int spec_fid(struct vnode *, struct fid *, caller_context_t *);
static int spec_seek(struct vnode *, offset_t, offset_t *, caller_context_t *);
static int spec_frlock(struct vnode *, int, struct flock64 *, int, offset_t,
	struct flk_callback *, struct cred *, caller_context_t *);
static int spec_realvp(struct vnode *, struct vnode **, caller_context_t *);

static int spec_getpage(struct vnode *, offset_t, size_t, uint_t *, page_t **,
	size_t, struct seg *, caddr_t, enum seg_rw, struct cred *,
	caller_context_t *);
static int spec_putapage(struct vnode *, page_t *, u_offset_t *, size_t *, int,
	struct cred *);
static struct buf *spec_startio(struct vnode *, page_t *, u_offset_t, size_t,
	int);
static int spec_getapage(struct vnode *, u_offset_t, size_t, uint_t *,
	page_t **, size_t, struct seg *, caddr_t, enum seg_rw, struct cred *);
static int spec_map(struct vnode *, offset_t, struct as *, caddr_t *, size_t,
	uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static int spec_addmap(struct vnode *, offset_t, struct as *, caddr_t, size_t,
	uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static int spec_delmap(struct vnode *, offset_t, struct as *, caddr_t, size_t,
	uint_t, uint_t, uint_t, struct cred *, caller_context_t *);

static int spec_poll(struct vnode *, short, int, short *, struct pollhead **,
	caller_context_t *);
static int spec_dump(struct vnode *, caddr_t, offset_t, offset_t,
    caller_context_t *);
static int spec_pageio(struct vnode *, page_t *, u_offset_t, size_t, int,
    cred_t *, caller_context_t *);

static int spec_getsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
	caller_context_t *);
static int spec_setsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
	caller_context_t *);
static int spec_pathconf(struct	vnode *, int, ulong_t *, struct cred *,
	caller_context_t *);

#define	SN_HOLD(csp)	{ \
	mutex_enter(&csp->s_lock); \
	csp->s_count++; \
	mutex_exit(&csp->s_lock); \
}

#define	SN_RELE(csp)	{ \
	mutex_enter(&csp->s_lock); \
	csp->s_count--; \
	ASSERT((csp->s_count > 0) || (csp->s_vnode->v_stream == NULL)); \
	mutex_exit(&csp->s_lock); \
}

#define	S_ISFENCED(sp)	((VTOS((sp)->s_commonvp))->s_flag & SFENCED)

struct vnodeops *spec_vnodeops;

/*
 * *PLEASE NOTE*: If you add new entry points to specfs, do
 * not forget to add support for fencing. A fenced snode
 * is indicated by the SFENCED flag in the common snode.
 * If a snode is fenced, determine if your entry point is
 * a configuration operation (Example: open), a detection
 * operation (Example: gettattr), an I/O operation (Example: ioctl())
 * or an unconfiguration operation (Example: close). If it is
 * a configuration or detection operation, fail the operation
 * for a fenced snode with an ENXIO or EIO as appropriate. If
 * it is any other operation, let it through.
 */

const fs_operation_def_t spec_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = spec_open },
	VOPNAME_CLOSE,		{ .vop_close = spec_close },
	VOPNAME_READ,		{ .vop_read = spec_read },
	VOPNAME_WRITE,		{ .vop_write = spec_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = spec_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = spec_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = spec_setattr },
	VOPNAME_ACCESS,		{ .vop_access = spec_access },
	VOPNAME_CREATE,		{ .vop_create = spec_create },
	VOPNAME_FSYNC,		{ .vop_fsync = spec_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = spec_inactive },
	VOPNAME_FID,		{ .vop_fid = spec_fid },
	VOPNAME_SEEK,		{ .vop_seek = spec_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = spec_pathconf },
	VOPNAME_FRLOCK,		{ .vop_frlock = spec_frlock },
	VOPNAME_REALVP,		{ .vop_realvp = spec_realvp },
	VOPNAME_GETPAGE,	{ .vop_getpage = spec_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = spec_putpage },
	VOPNAME_MAP,		{ .vop_map = spec_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = spec_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = spec_delmap },
	VOPNAME_POLL,		{ .vop_poll = spec_poll },
	VOPNAME_DUMP,		{ .vop_dump = spec_dump },
	VOPNAME_PAGEIO,		{ .vop_pageio = spec_pageio },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = spec_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = spec_getsecattr },
	NULL,			NULL
};

/*
 * Return address of spec_vnodeops
 */
struct vnodeops *
spec_getvnodeops(void)
{
	return (spec_vnodeops);
}

extern vnode_t *rconsvp;

/*
 * Acquire the serial lock on the common snode.
 */
#define	LOCK_CSP(csp)			(void) spec_lockcsp(csp, 0, 1, 0)
#define	LOCKHOLD_CSP_SIG(csp)		spec_lockcsp(csp, 1, 1, 1)
#define	SYNCHOLD_CSP_SIG(csp, intr)	spec_lockcsp(csp, intr, 0, 1)

typedef enum {
	LOOP,
	INTR,
	SUCCESS
} slock_ret_t;

/*
 * Synchronize with active SLOCKED snode, optionally checking for a signal and
 * optionally returning with SLOCKED set and SN_HOLD done.  The 'intr'
 * argument determines if the thread is interruptible by a signal while
 * waiting, the function returns INTR if interrupted while there is another
 * thread closing this snonde and LOOP if interrupted otherwise.
 * When SUCCESS is returned the 'hold' argument determines if the open
 * count (SN_HOLD) has been incremented and the 'setlock' argument
 * determines if the function returns with SLOCKED set.
 */
static slock_ret_t
spec_lockcsp(struct snode *csp, int intr, int setlock, int hold)
{
	slock_ret_t ret = SUCCESS;
	mutex_enter(&csp->s_lock);
	while (csp->s_flag & SLOCKED) {
		csp->s_flag |= SWANT;
		if (intr) {
			if (!cv_wait_sig(&csp->s_cv, &csp->s_lock)) {
				if (csp->s_flag & SCLOSING)
					ret = INTR;
				else
					ret = LOOP;
				mutex_exit(&csp->s_lock);
				return (ret);		/* interrupted */
			}
		} else {
			cv_wait(&csp->s_cv, &csp->s_lock);
		}
	}
	if (setlock)
		csp->s_flag |= SLOCKED;
	if (hold)
		csp->s_count++;		/* one more open reference : SN_HOLD */
	mutex_exit(&csp->s_lock);
	return (ret);			/* serialized/locked */
}

/*
 * Unlock the serial lock on the common snode
 */
#define	UNLOCK_CSP_LOCK_HELD(csp)			\
	ASSERT(mutex_owned(&csp->s_lock));		\
	if (csp->s_flag & SWANT)			\
		cv_broadcast(&csp->s_cv);		\
	csp->s_flag &= ~(SWANT|SLOCKED);

#define	UNLOCK_CSP(csp)					\
	mutex_enter(&csp->s_lock);			\
	UNLOCK_CSP_LOCK_HELD(csp);			\
	mutex_exit(&csp->s_lock);

/*
 * compute/return the size of the device
 */
#define	SPEC_SIZE(csp)	\
	(((csp)->s_flag & SSIZEVALID) ? (csp)->s_size : spec_size(csp))

/*
 * Compute and return the size.  If the size in the common snode is valid then
 * return it.  If not valid then get the size from the driver and set size in
 * the common snode.  If the device has not been attached then we don't ask for
 * an update from the driver- for non-streams SSIZEVALID stays unset until the
 * device is attached. A stat of a mknod outside /devices (non-devfs) may
 * report UNKNOWN_SIZE because the device may not be attached yet (SDIPSET not
 * established in mknod until open time). An stat in /devices will report the
 * size correctly.  Specfs should always call SPEC_SIZE instead of referring
 * directly to s_size to initialize/retrieve the size of a device.
 *
 * XXX There is an inconsistency between block and raw - "unknown" is
 * UNKNOWN_SIZE for VBLK and 0 for VCHR(raw).
 */
static u_offset_t
spec_size(struct snode *csp)
{
	struct vnode	*cvp = STOV(csp);
	u_offset_t	size;
	int		plen;
	uint32_t	size32;
	dev_t		dev;
	dev_info_t	*devi;
	major_t		maj;
	uint_t		blksize;
	int		blkshift;

	ASSERT((csp)->s_commonvp == cvp);	/* must be common node */

	/* return cached value */
	mutex_enter(&csp->s_lock);
	if (csp->s_flag & SSIZEVALID) {
		mutex_exit(&csp->s_lock);
		return (csp->s_size);
	}

	/* VOP_GETATTR of mknod has not had devcnt restriction applied */
	dev = cvp->v_rdev;
	maj = getmajor(dev);
	if (maj >= devcnt) {
		/* return non-cached UNKNOWN_SIZE */
		mutex_exit(&csp->s_lock);
		return ((cvp->v_type == VCHR) ? 0 : UNKNOWN_SIZE);
	}

	/* establish cached zero size for streams */
	if (STREAMSTAB(maj)) {
		csp->s_size = 0;
		csp->s_flag |= SSIZEVALID;
		mutex_exit(&csp->s_lock);
		return (0);
	}

	/*
	 * Return non-cached UNKNOWN_SIZE if not open.
	 *
	 * NB: This check is bogus, calling prop_op(9E) should be gated by
	 * attach, not open. Not having this check however opens up a new
	 * context under which a driver's prop_op(9E) could be called. Calling
	 * prop_op(9E) in this new context has been shown to expose latent
	 * driver bugs (insufficient NULL pointer checks that lead to panic).
	 * We are keeping this open check for now to avoid these panics.
	 */
	if (csp->s_count == 0) {
		mutex_exit(&csp->s_lock);
		return ((cvp->v_type == VCHR) ? 0 : UNKNOWN_SIZE);
	}

	/* Return non-cached UNKNOWN_SIZE if not attached. */
	if (((csp->s_flag & SDIPSET) == 0) || (csp->s_dip == NULL) ||
	    !i_ddi_devi_attached(csp->s_dip)) {
		mutex_exit(&csp->s_lock);
		return ((cvp->v_type == VCHR) ? 0 : UNKNOWN_SIZE);
	}

	devi = csp->s_dip;

	/*
	 * Established cached size obtained from the attached driver. Since we
	 * know the devinfo node, for efficiency we use cdev_prop_op directly
	 * instead of [cb]dev_[Ss]size.
	 */
	if (cvp->v_type == VCHR) {
		size = 0;
		plen = sizeof (size);
		if (cdev_prop_op(dev, devi, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS |
		    DDI_PROP_CONSUMER_TYPED, "Size", (caddr_t)&size,
		    &plen) != DDI_PROP_SUCCESS) {
			plen = sizeof (size32);
			if (cdev_prop_op(dev, devi, PROP_LEN_AND_VAL_BUF,
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    "size", (caddr_t)&size32, &plen) ==
			    DDI_PROP_SUCCESS)
				size = size32;
		}
	} else {
		size = UNKNOWN_SIZE;
		plen = sizeof (size);
		if (cdev_prop_op(dev, devi, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS |
		    DDI_PROP_CONSUMER_TYPED, "Nblocks", (caddr_t)&size,
		    &plen) != DDI_PROP_SUCCESS) {
			plen = sizeof (size32);
			if (cdev_prop_op(dev, devi, PROP_LEN_AND_VAL_BUF,
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    "nblocks", (caddr_t)&size32, &plen) ==
			    DDI_PROP_SUCCESS)
				size = size32;
		}

		if (size != UNKNOWN_SIZE) {
			blksize = DEV_BSIZE;		/* default */
			plen = sizeof (blksize);

			/* try to get dev_t specific "blksize" */
			if (cdev_prop_op(dev, devi, PROP_LEN_AND_VAL_BUF,
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    "blksize", (caddr_t)&blksize, &plen) !=
			    DDI_PROP_SUCCESS) {
				/*
				 * Try for dev_info node "device-blksize".
				 * If this fails then blksize will still be
				 * DEV_BSIZE default value.
				 */
				(void) cdev_prop_op(DDI_DEV_T_ANY, devi,
				    PROP_LEN_AND_VAL_BUF,
				    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
				    "device-blksize", (caddr_t)&blksize, &plen);
			}

			/* blksize must be a power of two */
			ASSERT(BIT_ONLYONESET(blksize));
			blkshift = highbit(blksize) - 1;

			/* convert from block size to byte size */
			if (size < (MAXOFFSET_T >> blkshift))
				size = size << blkshift;
			else
				size = UNKNOWN_SIZE;
		}
	}

	csp->s_size = size;
	csp->s_flag |= SSIZEVALID;

	mutex_exit(&csp->s_lock);
	return (size);
}

/*
 * This function deal with vnode substitution in the case of
 * device cloning.
 */
static int
spec_clone(struct vnode **vpp, dev_t newdev, int vtype, struct stdata *stp)
{
	dev_t		dev = (*vpp)->v_rdev;
	major_t		maj = getmajor(dev);
	major_t 	newmaj = getmajor(newdev);
	int		sysclone = (maj == clone_major);
	int		qassociate_used = 0;
	struct snode	*oldsp, *oldcsp;
	struct snode	*newsp, *newcsp;
	struct vnode	*newvp, *newcvp;
	dev_info_t	*dip;
	queue_t		*dq;

	ASSERT(dev != newdev);

	/*
	 * Check for cloning across different drivers.
	 * We only support this under the system provided clone driver
	 */
	if ((maj != newmaj) && !sysclone) {
		cmn_err(CE_NOTE,
		    "unsupported clone open maj = %u, newmaj = %u",
		    maj, newmaj);
		return (ENXIO);
	}

	/* old */
	oldsp = VTOS(*vpp);
	oldcsp = VTOS(oldsp->s_commonvp);

	/* new */
	newvp = makespecvp(newdev, vtype);
	ASSERT(newvp != NULL);
	newsp = VTOS(newvp);
	newcvp = newsp->s_commonvp;
	newcsp = VTOS(newcvp);

	/*
	 * Clones inherit fsid, realvp, and dip.
	 * XXX realvp inherit is not occurring, does fstat of clone work?
	 */
	newsp->s_fsid = oldsp->s_fsid;
	if (sysclone) {
		newsp->s_flag |= SCLONE;
		dip = NULL;
	} else {
		newsp->s_flag |= SSELFCLONE;
		dip = oldcsp->s_dip;
	}

	/*
	 * If we cloned to an opened newdev that already has called
	 * spec_assoc_vp_with_devi (SDIPSET set) then the association is
	 * already established.
	 */
	if (!(newcsp->s_flag & SDIPSET)) {
		/*
		 * Establish s_dip association for newdev.
		 *
		 * If we trusted the getinfo(9E) DDI_INFO_DEVT2INSTANCE
		 * implementation of all cloning drivers  (SCLONE and SELFCLONE)
		 * we would always use e_ddi_hold_devi_by_dev().  We know that
		 * many drivers have had (still have?) problems with
		 * DDI_INFO_DEVT2INSTANCE, so we try to minimize reliance by
		 * detecting drivers that use QASSOCIATE (by looking down the
		 * stream) and setting their s_dip association to NULL.
		 */
		qassociate_used = 0;
		if (stp) {
			for (dq = stp->sd_wrq; dq; dq = dq->q_next) {
				if (_RD(dq)->q_flag & _QASSOCIATED) {
					qassociate_used = 1;
					dip = NULL;
					break;
				}
			}
		}

		if (dip || qassociate_used) {
			spec_assoc_vp_with_devi(newvp, dip);
		} else {
			/* derive association from newdev */
			dip = e_ddi_hold_devi_by_dev(newdev, 0);
			spec_assoc_vp_with_devi(newvp, dip);
			if (dip)
				ddi_release_devi(dip);
		}
	}

	SN_HOLD(newcsp);

	/* deal with stream stuff */
	if (stp != NULL) {
		LOCK_CSP(newcsp);	/* synchronize stream open/close */
		mutex_enter(&newcsp->s_lock);
		newcvp->v_stream = newvp->v_stream = stp;
		stp->sd_vnode = newcvp;
		stp->sd_strtab = STREAMSTAB(newmaj);
		mutex_exit(&newcsp->s_lock);
		UNLOCK_CSP(newcsp);
	}

	/* substitute the vnode */
	SN_RELE(oldcsp);
	VN_RELE(*vpp);
	*vpp = newvp;

	return (0);
}

static int
spec_open(struct vnode **vpp, int flag, struct cred *cr, caller_context_t *cc)
{
	major_t maj;
	dev_t dev, newdev;
	struct vnode *vp, *cvp;
	struct snode *sp, *csp;
	struct stdata *stp;
	dev_info_t *dip;
	int error, type;
	contract_t *ct = NULL;
	int open_returns_eintr;
	slock_ret_t spec_locksp_ret;


	flag &= ~FCREAT;		/* paranoia */

	vp = *vpp;
	sp = VTOS(vp);
	ASSERT((vp->v_type == VCHR) || (vp->v_type == VBLK));
	if ((vp->v_type != VCHR) && (vp->v_type != VBLK))
		return (ENXIO);

	/*
	 * If the VFS_NODEVICES bit was set for the mount,
	 * do not allow opens of special devices.
	 */
	if (sp->s_realvp && (sp->s_realvp->v_vfsp->vfs_flag & VFS_NODEVICES))
		return (ENXIO);

	newdev = dev = vp->v_rdev;

	/*
	 * If we are opening a node that has not had spec_assoc_vp_with_devi
	 * called against it (mknod outside /devices or a non-dacf makespecvp
	 * node) then SDIPSET will not be set. In this case we call an
	 * interface which will reconstruct the path and lookup (drive attach)
	 * through devfs (e_ddi_hold_devi_by_dev -> e_ddi_hold_devi_by_path ->
	 * devfs_lookupname).  For support of broken drivers that don't call
	 * ddi_create_minor_node for all minor nodes in their instance space,
	 * we call interfaces that operates at the directory/devinfo
	 * (major/instance) level instead of to the leaf/minor node level.
	 * After finding and attaching the dip we associate it with the
	 * common specfs vnode (s_dip), which sets SDIPSET.  A DL_DETACH_REQ
	 * to style-2 stream driver may set s_dip to NULL with SDIPSET set.
	 *
	 * NOTE: Although e_ddi_hold_devi_by_dev takes a dev_t argument, its
	 * implementation operates at the major/instance level since it only
	 * need to return a dip.
	 */
	cvp = sp->s_commonvp;
	csp = VTOS(cvp);
	if (!(csp->s_flag & SDIPSET)) {
		/* try to attach, return error if we fail */
		if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
			return (ENXIO);

		/* associate dip with the common snode s_dip */
		spec_assoc_vp_with_devi(vp, dip);
		ddi_release_devi(dip);	/* from e_ddi_hold_devi_by_dev */
	}

	/* check if device fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

#ifdef  DEBUG
	/* verify attach/open exclusion guarantee */
	dip = csp->s_dip;
	ASSERT((dip == NULL) || i_ddi_devi_attached(dip));
#endif  /* DEBUG */

	if ((error = secpolicy_spec_open(cr, vp, flag)) != 0)
		return (error);

	/* Verify existance of open(9E) implementation. */
	maj = getmajor(dev);
	if ((maj >= devcnt) ||
	    (devopsp[maj]->devo_cb_ops == NULL) ||
	    (devopsp[maj]->devo_cb_ops->cb_open == NULL))
		return (ENXIO);

	/*
	 * split STREAMS vs. non-STREAMS
	 *
	 * If the device is a dual-personality device, then we might want
	 * to allow for a regular OTYP_BLK open.  If however it's strictly
	 * a pure STREAMS device, the cb_open entry point will be
	 * nodev() which returns ENXIO.  This does make this failure path
	 * somewhat longer, but such attempts to use OTYP_BLK with STREAMS
	 * devices should be exceedingly rare.  (Most of the time they will
	 * be due to programmer error.)
	 */
	if ((vp->v_type == VCHR) && (STREAMSTAB(maj)))
		goto streams_open;

not_streams:
	/*
	 * Wait for in progress last close to complete. This guarantees
	 * to the driver writer that we will never be in the drivers
	 * open and close on the same (dev_t, otype) at the same time.
	 * Open count already incremented (SN_HOLD) on non-zero return.
	 * The wait is interruptible by a signal if the driver sets the
	 * D_OPEN_RETURNS_EINTR cb_ops(9S) cb_flag or sets the
	 * ddi-open-returns-eintr(9P) property in its driver.conf.
	 */
	if ((devopsp[maj]->devo_cb_ops->cb_flag & D_OPEN_RETURNS_EINTR) ||
	    (devnamesp[maj].dn_flags & DN_OPEN_RETURNS_EINTR))
		open_returns_eintr = 1;
	else
		open_returns_eintr = 0;
	while ((spec_locksp_ret = SYNCHOLD_CSP_SIG(csp, open_returns_eintr)) !=
	    SUCCESS) {
		if (spec_locksp_ret == INTR)
			return (EINTR);
	}

	/* non streams open */
	type = (vp->v_type == VBLK ? OTYP_BLK : OTYP_CHR);
	error = dev_open(&newdev, flag, type, cr);

	/* deal with clone case */
	if (error == 0 && dev != newdev) {
		error = spec_clone(vpp, newdev, vp->v_type, NULL);
		/*
		 * bail on clone failure, further processing
		 * results in undefined behaviors.
		 */
		if (error != 0)
			return (error);
		sp = VTOS(*vpp);
		csp = VTOS(sp->s_commonvp);
	}

	/*
	 * create contracts only for userland opens
	 * Successful open and cloning is done at this point.
	 */
	if (error == 0 && !(flag & FKLYR)) {
		int spec_type;
		spec_type = (STOV(csp)->v_type == VCHR) ? S_IFCHR : S_IFBLK;
		if (contract_device_open(newdev, spec_type, NULL) != 0) {
			error = EIO;
		}
	}

	if (error == 0) {
		sp->s_size = SPEC_SIZE(csp);

		if ((csp->s_flag & SNEEDCLOSE) == 0) {
			int nmaj = getmajor(newdev);
			mutex_enter(&csp->s_lock);
			/* successful open needs a close later */
			csp->s_flag |= SNEEDCLOSE;

			/*
			 * Invalidate possible cached "unknown" size
			 * established by a VOP_GETATTR while open was in
			 * progress, and the driver might fail prop_op(9E).
			 */
			if (((cvp->v_type == VCHR) && (csp->s_size == 0)) ||
			    ((cvp->v_type == VBLK) &&
			    (csp->s_size == UNKNOWN_SIZE)))
				csp->s_flag &= ~SSIZEVALID;

			if (devopsp[nmaj]->devo_cb_ops->cb_flag & D_64BIT)
				csp->s_flag |= SLOFFSET;
			if (devopsp[nmaj]->devo_cb_ops->cb_flag & D_U64BIT)
				csp->s_flag |= SLOFFSET | SANYOFFSET;
			mutex_exit(&csp->s_lock);
		}
		return (0);
	}

	/*
	 * Open failed. If we missed a close operation because
	 * we were trying to get the device open and it is the
	 * last in progress open that is failing then call close.
	 *
	 * NOTE: Only non-streams open has this race condition.
	 */
	mutex_enter(&csp->s_lock);
	csp->s_count--;			/* decrement open count : SN_RELE */
	if ((csp->s_count == 0) &&	/* no outstanding open */
	    (csp->s_mapcnt == 0) &&	/* no mapping */
	    (csp->s_flag & SNEEDCLOSE)) { /* need a close */
		csp->s_flag &= ~(SNEEDCLOSE | SSIZEVALID);

		/* See comment in spec_close() */
		if (csp->s_flag & (SCLONE | SSELFCLONE))
			csp->s_flag &= ~SDIPSET;

		csp->s_flag |= SCLOSING;
		mutex_exit(&csp->s_lock);

		ASSERT(*vpp != NULL);
		(void) device_close(*vpp, flag, cr);

		mutex_enter(&csp->s_lock);
		csp->s_flag &= ~SCLOSING;
		mutex_exit(&csp->s_lock);
	} else {
		mutex_exit(&csp->s_lock);
	}
	return (error);

streams_open:
	/*
	 * Lock common snode to prevent any new clone opens on this
	 * stream while one is in progress. This is necessary since
	 * the stream currently associated with the clone device will
	 * not be part of it after the clone open completes. Unfortunately
	 * we don't know in advance if this is a clone
	 * device so we have to lock all opens.
	 *
	 * If we fail, it's because of an interrupt - EINTR return is an
	 * expected aspect of opening a stream so we don't need to check
	 * D_OPEN_RETURNS_EINTR. Open count already incremented (SN_HOLD)
	 * on non-zero return.
	 */
	if (LOCKHOLD_CSP_SIG(csp) != SUCCESS)
		return (EINTR);

	error = stropen(cvp, &newdev, flag, cr);
	stp = cvp->v_stream;

	/* deal with the clone case */
	if ((error == 0) && (dev != newdev)) {
		vp->v_stream = cvp->v_stream = NULL;
		UNLOCK_CSP(csp);
		error = spec_clone(vpp, newdev, vp->v_type, stp);
		/*
		 * bail on clone failure, further processing
		 * results in undefined behaviors.
		 */
		if (error != 0)
			return (error);
		sp = VTOS(*vpp);
		csp = VTOS(sp->s_commonvp);
	} else if (error == 0) {
		vp->v_stream = stp;
		UNLOCK_CSP(csp);
	}

	/*
	 * create contracts only for userland opens
	 * Successful open and cloning is done at this point.
	 */
	if (error == 0 && !(flag & FKLYR)) {
		/* STREAM is of type S_IFCHR */
		if (contract_device_open(newdev, S_IFCHR, &ct) != 0) {
			UNLOCK_CSP(csp);
			(void) spec_close(vp, flag, 1, 0, cr, cc);
			return (EIO);
		}
	}

	if (error == 0) {
		/* STREAMS devices don't have a size */
		sp->s_size = csp->s_size = 0;

		if (!(stp->sd_flag & STRISTTY) || (flag & FNOCTTY))
			return (0);

		/* try to allocate it as a controlling terminal */
		if (strctty(stp) != EINTR)
			return (0);

		/* strctty() was interrupted by a signal */
		if (ct) {
			/* we only create contracts for userland opens */
			ASSERT(ttoproc(curthread));
			(void) contract_abandon(ct, ttoproc(curthread), 0);
		}
		(void) spec_close(vp, flag, 1, 0, cr, cc);
		return (EINTR);
	}

	/*
	 * Deal with stropen failure.
	 *
	 * sd_flag in the stream head cannot change since the
	 * common snode is locked before the call to stropen().
	 */
	if ((stp != NULL) && (stp->sd_flag & STREOPENFAIL)) {
		/*
		 * Open failed part way through.
		 */
		mutex_enter(&stp->sd_lock);
		stp->sd_flag &= ~STREOPENFAIL;
		mutex_exit(&stp->sd_lock);

		UNLOCK_CSP(csp);
		(void) spec_close(vp, flag, 1, 0, cr, cc);
	} else {
		UNLOCK_CSP(csp);
		SN_RELE(csp);
	}

	/*
	 * Resolution for STREAMS vs. regular character device: If the
	 * STREAMS open(9e) returns ENOSTR, then try an ordinary device
	 * open instead.
	 */
	if (error == ENOSTR) {
		goto not_streams;
	}
	return (error);
}

/*ARGSUSED2*/
static int
spec_close(
	struct vnode	*vp,
	int		flag,
	int		count,
	offset_t	offset,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct vnode *cvp;
	struct snode *sp, *csp;
	enum vtype type;
	dev_t dev;
	int error = 0;
	int sysclone;

	if (!(flag & FKLYR)) {
		/* this only applies to closes of devices from userland */
		cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
		cleanshares(vp, ttoproc(curthread)->p_pid);
		if (vp->v_stream)
			strclean(vp);
	}
	if (count > 1)
		return (0);

	/* we allow close to succeed even if device is fenced off */
	sp = VTOS(vp);
	cvp = sp->s_commonvp;

	dev = sp->s_dev;
	type = vp->v_type;

	ASSERT(type == VCHR || type == VBLK);

	/*
	 * Prevent close/close and close/open races by serializing closes
	 * on this common snode. Clone opens are held up until after
	 * we have closed this device so the streams linkage is maintained
	 */
	csp = VTOS(cvp);

	LOCK_CSP(csp);
	mutex_enter(&csp->s_lock);

	csp->s_count--;			/* one fewer open reference : SN_RELE */
	sysclone = sp->s_flag & SCLONE;

	/*
	 * Invalidate size on each close.
	 *
	 * XXX We do this on each close because we don't have interfaces that
	 * allow a driver to invalidate the size.  Since clearing this on each
	 * close this causes property overhead we skip /dev/null and
	 * /dev/zero to avoid degrading kenbus performance.
	 */
	if (getmajor(dev) != mm_major)
		csp->s_flag &= ~SSIZEVALID;

	/*
	 * Only call the close routine when the last open reference through
	 * any [s, v]node goes away.  This can be checked by looking at
	 * s_count on the common vnode.
	 */
	if ((csp->s_count == 0) && (csp->s_mapcnt == 0)) {
		/* we don't need a close */
		csp->s_flag &= ~(SNEEDCLOSE | SSIZEVALID);

		/*
		 * A cloning driver may open-clone to the same dev_t that we
		 * are closing before spec_inactive destroys the common snode.
		 * If this occurs the s_dip association needs to be reevaluated.
		 * We clear SDIPSET to force reevaluation in this case.  When
		 * reevaluation occurs (by spec_clone after open), if the
		 * devinfo association has changed then the old association
		 * will be released as the new association is established by
		 * spec_assoc_vp_with_devi().
		 */
		if (csp->s_flag & (SCLONE | SSELFCLONE))
			csp->s_flag &= ~SDIPSET;

		csp->s_flag |= SCLOSING;
		mutex_exit(&csp->s_lock);
		error = device_close(vp, flag, cr);

		/*
		 * Decrement the devops held in clnopen()
		 */
		if (sysclone) {
			ddi_rele_driver(getmajor(dev));
		}
		mutex_enter(&csp->s_lock);
		csp->s_flag &= ~SCLOSING;
	}

	UNLOCK_CSP_LOCK_HELD(csp);
	mutex_exit(&csp->s_lock);

	return (error);
}

/*ARGSUSED2*/
static int
spec_read(
	struct vnode	*vp,
	struct uio	*uiop,
	int		ioflag,
	struct cred	*cr,
	caller_context_t *ct)
{
	int error;
	struct snode *sp = VTOS(vp);
	dev_t dev = sp->s_dev;
	size_t n;
	ulong_t on;
	u_offset_t bdevsize;
	offset_t maxoff;
	offset_t off;
	struct vnode *blkvp;

	ASSERT(vp->v_type == VCHR || vp->v_type == VBLK);

	if (vp->v_stream) {
		ASSERT(vp->v_type == VCHR);
		smark(sp, SACC);
		return (strread(vp, uiop, cr));
	}

	if (uiop->uio_resid == 0)
		return (0);

	/*
	 * Plain old character devices that set D_U64BIT can have
	 * unrestricted offsets.
	 */
	maxoff = spec_maxoffset(vp);
	ASSERT(maxoff != -1 || vp->v_type == VCHR);

	if (maxoff != -1 && (uiop->uio_loffset < 0 ||
	    uiop->uio_loffset + uiop->uio_resid > maxoff))
		return (EINVAL);

	if (vp->v_type == VCHR) {
		smark(sp, SACC);
		ASSERT(vp->v_stream == NULL);
		return (cdev_read(dev, uiop, cr));
	}

	/*
	 * Block device.
	 */
	error = 0;
	blkvp = sp->s_commonvp;
	bdevsize = SPEC_SIZE(VTOS(blkvp));

	do {
		caddr_t base;
		offset_t diff;

		off = uiop->uio_loffset & (offset_t)MAXBMASK;
		on = (size_t)(uiop->uio_loffset & MAXBOFFSET);
		n = (size_t)MIN(MAXBSIZE - on, uiop->uio_resid);
		diff = bdevsize - uiop->uio_loffset;

		if (diff <= 0)
			break;
		if (diff < n)
			n = (size_t)diff;

		if (vpm_enable) {
			error = vpm_data_copy(blkvp, (u_offset_t)(off + on),
			    n, uiop, 1, NULL, 0, S_READ);
		} else {
			base = segmap_getmapflt(segkmap, blkvp,
			    (u_offset_t)(off + on), n, 1, S_READ);

			error = uiomove(base + on, n, UIO_READ, uiop);
		}
		if (!error) {
			int flags = 0;
			/*
			 * If we read a whole block, we won't need this
			 * buffer again soon.
			 */
			if (n + on == MAXBSIZE)
				flags = SM_DONTNEED | SM_FREE;
			if (vpm_enable) {
				error = vpm_sync_pages(blkvp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(blkvp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
			if (bdevsize == UNKNOWN_SIZE) {
				error = 0;
				break;
			}
		}
	} while (error == 0 && uiop->uio_resid > 0 && n != 0);

	return (error);
}

/*ARGSUSED*/
static int
spec_write(
	struct vnode *vp,
	struct uio *uiop,
	int ioflag,
	struct cred *cr,
	caller_context_t *ct)
{
	int error;
	struct snode *sp = VTOS(vp);
	dev_t dev = sp->s_dev;
	size_t n;
	ulong_t on;
	u_offset_t bdevsize;
	offset_t maxoff;
	offset_t off;
	struct vnode *blkvp;

	ASSERT(vp->v_type == VCHR || vp->v_type == VBLK);

	if (vp->v_stream) {
		ASSERT(vp->v_type == VCHR);
		smark(sp, SUPD);
		return (strwrite(vp, uiop, cr));
	}

	/*
	 * Plain old character devices that set D_U64BIT can have
	 * unrestricted offsets.
	 */
	maxoff = spec_maxoffset(vp);
	ASSERT(maxoff != -1 || vp->v_type == VCHR);

	if (maxoff != -1 && (uiop->uio_loffset < 0 ||
	    uiop->uio_loffset + uiop->uio_resid > maxoff))
		return (EINVAL);

	if (vp->v_type == VCHR) {
		smark(sp, SUPD);
		ASSERT(vp->v_stream == NULL);
		return (cdev_write(dev, uiop, cr));
	}

	if (uiop->uio_resid == 0)
		return (0);

	error = 0;
	blkvp = sp->s_commonvp;
	bdevsize = SPEC_SIZE(VTOS(blkvp));

	do {
		int pagecreate;
		int newpage;
		caddr_t base;
		offset_t diff;

		off = uiop->uio_loffset & (offset_t)MAXBMASK;
		on = (ulong_t)(uiop->uio_loffset & MAXBOFFSET);
		n = (size_t)MIN(MAXBSIZE - on, uiop->uio_resid);
		pagecreate = 0;

		diff = bdevsize - uiop->uio_loffset;
		if (diff <= 0) {
			error = ENXIO;
			break;
		}
		if (diff < n)
			n = (size_t)diff;

		/*
		 * Check to see if we can skip reading in the page
		 * and just allocate the memory.  We can do this
		 * if we are going to rewrite the entire mapping
		 * or if we are going to write to end of the device
		 * from the beginning of the mapping.
		 */
		if (n == MAXBSIZE || (on == 0 && (off + n) == bdevsize))
			pagecreate = 1;

		newpage = 0;

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)n, uiop);

		if (vpm_enable) {
			error = vpm_data_copy(blkvp, (u_offset_t)(off + on),
			    n, uiop, !pagecreate, NULL, 0, S_WRITE);
		} else {
			base = segmap_getmapflt(segkmap, blkvp,
			    (u_offset_t)(off + on), n, !pagecreate, S_WRITE);

			/*
			 * segmap_pagecreate() returns 1 if it calls
			 * page_create_va() to allocate any pages.
			 */

			if (pagecreate)
				newpage = segmap_pagecreate(segkmap, base + on,
				    n, 0);

			error = uiomove(base + on, n, UIO_WRITE, uiop);
		}

		if (!vpm_enable && pagecreate &&
		    uiop->uio_loffset <
		    P2ROUNDUP_TYPED(off + on + n, PAGESIZE, offset_t)) {
			/*
			 * We created pages w/o initializing them completely,
			 * thus we need to zero the part that wasn't set up.
			 * This can happen if we write to the end of the device
			 * or if we had some sort of error during the uiomove.
			 */
			long nzero;
			offset_t nmoved;

			nmoved = (uiop->uio_loffset - (off + on));
			if (nmoved < 0 || nmoved > n) {
				panic("spec_write: nmoved bogus");
				/*NOTREACHED*/
			}
			nzero = (long)P2ROUNDUP(on + n, PAGESIZE) -
			    (on + nmoved);
			if (nzero < 0 || (on + nmoved + nzero > MAXBSIZE)) {
				panic("spec_write: nzero bogus");
				/*NOTREACHED*/
			}
			(void) kzero(base + on + nmoved, (size_t)nzero);
		}

		/*
		 * Unlock the pages which have been allocated by
		 * page_create_va() in segmap_pagecreate().
		 */
		if (!vpm_enable && newpage)
			segmap_pageunlock(segkmap, base + on,
			    (size_t)n, S_WRITE);

		if (error == 0) {
			int flags = 0;

			/*
			 * Force write back for synchronous write cases.
			 */
			if (ioflag & (FSYNC|FDSYNC))
				flags = SM_WRITE;
			else if (n + on == MAXBSIZE || IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write and
				 * mark the buffer to indicate that
				 * it won't be needed again soon.
				 * Push swap files here, since it
				 * won't happen anywhere else.
				 */
				flags = SM_WRITE | SM_ASYNC | SM_DONTNEED;
			}
			smark(sp, SUPD|SCHG);
			if (vpm_enable) {
				error = vpm_sync_pages(blkvp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(blkvp, off, n, SM_INVAL);
			} else {
				(void) segmap_release(segkmap, base, SM_INVAL);
			}
		}

	} while (error == 0 && uiop->uio_resid > 0 && n != 0);

	return (error);
}

/*ARGSUSED6*/
static int
spec_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode, struct cred *cr,
    int *rvalp, caller_context_t *ct)
{
	struct snode *sp;
	dev_t dev;
	int error;

	if (vp->v_type != VCHR)
		return (ENOTTY);

	/*
	 * allow ioctls() to go through even for fenced snodes, as they
	 * may include unconfiguration operation - for example popping of
	 * streams modules.
	 */

	sp = VTOS(vp);
	dev = sp->s_dev;
	if (vp->v_stream) {
		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
	} else {
		error = cdev_ioctl(dev, cmd, arg, mode, cr, rvalp);
	}
	return (error);
}

static int
spec_getattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	int error;
	struct snode *sp;
	struct vnode *realvp;

	/* With ATTR_COMM we will not get attributes from realvp */
	if (flags & ATTR_COMM) {
		sp = VTOS(vp);
		vp = sp->s_commonvp;
	}
	sp = VTOS(vp);

	/* we want stat() to fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	realvp = sp->s_realvp;

	if (realvp == NULL) {
		static int snode_shift	= 0;

		/*
		 * Calculate the amount of bitshift to a snode pointer which
		 * will still keep it unique.  See below.
		 */
		if (snode_shift == 0)
			snode_shift = highbit(sizeof (struct snode));
		ASSERT(snode_shift > 0);

		/*
		 * No real vnode behind this one.  Fill in the fields
		 * from the snode.
		 *
		 * This code should be refined to return only the
		 * attributes asked for instead of all of them.
		 */
		vap->va_type = vp->v_type;
		vap->va_mode = 0;
		vap->va_uid = vap->va_gid = 0;
		vap->va_fsid = sp->s_fsid;

		/*
		 * If the va_nodeid is > MAX_USHORT, then i386 stats might
		 * fail. So we shift down the snode pointer to try and get
		 * the most uniqueness into 16-bits.
		 */
		vap->va_nodeid = ((ino64_t)(uintptr_t)sp >> snode_shift) &
		    0xFFFF;
		vap->va_nlink = 0;
		vap->va_rdev = sp->s_dev;

		/*
		 * va_nblocks is the number of 512 byte blocks used to store
		 * the mknod for the device, not the number of blocks on the
		 * device itself.  This is typically zero since the mknod is
		 * represented directly in the inode itself.
		 */
		vap->va_nblocks = 0;
	} else {
		error = VOP_GETATTR(realvp, vap, flags, cr, ct);
		if (error != 0)
			return (error);
	}

	/* set the size from the snode */
	vap->va_size = SPEC_SIZE(VTOS(sp->s_commonvp));
	vap->va_blksize = MAXBSIZE;

	mutex_enter(&sp->s_lock);
	vap->va_atime.tv_sec = sp->s_atime;
	vap->va_mtime.tv_sec = sp->s_mtime;
	vap->va_ctime.tv_sec = sp->s_ctime;
	mutex_exit(&sp->s_lock);

	vap->va_atime.tv_nsec = 0;
	vap->va_mtime.tv_nsec = 0;
	vap->va_ctime.tv_nsec = 0;
	vap->va_seq = 0;

	return (0);
}

static int
spec_setattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	struct vnode *realvp;
	int error;

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	if (vp->v_type == VCHR && vp->v_stream && (vap->va_mask & AT_SIZE)) {
		/*
		 * 1135080:	O_TRUNC should have no effect on
		 *		named pipes and terminal devices.
		 */
		ASSERT(vap->va_mask == AT_SIZE);
		return (0);
	}

	if ((realvp = sp->s_realvp) == NULL)
		error = 0;	/* no real vnode to update */
	else
		error = VOP_SETATTR(realvp, vap, flags, cr, ct);
	if (error == 0) {
		/*
		 * If times were changed, update snode.
		 */
		mutex_enter(&sp->s_lock);
		if (vap->va_mask & AT_ATIME)
			sp->s_atime = vap->va_atime.tv_sec;
		if (vap->va_mask & AT_MTIME) {
			sp->s_mtime = vap->va_mtime.tv_sec;
			sp->s_ctime = gethrestime_sec();
		}
		mutex_exit(&sp->s_lock);
	}
	return (error);
}

static int
spec_access(
	struct vnode *vp,
	int mode,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct vnode *realvp;
	struct snode *sp = VTOS(vp);

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	if ((realvp = sp->s_realvp) != NULL)
		return (VOP_ACCESS(realvp, mode, flags, cr, ct));
	else
		return (0);	/* Allow all access. */
}

/*
 * This can be called if creat or an open with O_CREAT is done on the root
 * of a lofs mount where the mounted entity is a special file.
 */
/*ARGSUSED*/
static int
spec_create(
	struct vnode *dvp,
	char *name,
	vattr_t *vap,
	enum vcexcl excl,
	int mode,
	struct vnode **vpp,
	struct cred *cr,
	int flag,
	caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int error;
	struct snode *sp = VTOS(dvp);

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	ASSERT(dvp && (dvp->v_flag & VROOT) && *name == '\0');
	if (excl == NONEXCL) {
		if (mode && (error = spec_access(dvp, mode, 0, cr, ct)))
			return (error);
		VN_HOLD(dvp);
		return (0);
	}
	return (EEXIST);
}

/*
 * In order to sync out the snode times without multi-client problems,
 * make sure the times written out are never earlier than the times
 * already set in the vnode.
 */
static int
spec_fsync(
	struct vnode *vp,
	int syncflag,
	struct cred *cr,
	caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	struct vnode *realvp;
	struct vnode *cvp;
	struct vattr va, vatmp;

	/* allow syncing even if device is fenced off */

	/* If times didn't change, don't flush anything. */
	mutex_enter(&sp->s_lock);
	if ((sp->s_flag & (SACC|SUPD|SCHG)) == 0 && vp->v_type != VBLK) {
		mutex_exit(&sp->s_lock);
		return (0);
	}
	sp->s_flag &= ~(SACC|SUPD|SCHG);
	mutex_exit(&sp->s_lock);
	cvp = sp->s_commonvp;
	realvp = sp->s_realvp;

	if (vp->v_type == VBLK && cvp != vp && vn_has_cached_data(cvp) &&
	    (cvp->v_flag & VISSWAP) == 0)
		(void) VOP_PUTPAGE(cvp, (offset_t)0, 0, 0, cr, ct);

	/*
	 * For devices that support it, force write cache to stable storage.
	 * We don't need the lock to check s_flags since we can treat
	 * SNOFLUSH as a hint.
	 */
	if ((vp->v_type == VBLK || vp->v_type == VCHR) &&
	    !(sp->s_flag & SNOFLUSH)) {
		int rval, rc;
		struct dk_callback spec_callback;

		spec_callback.dkc_flag = FLUSH_VOLATILE;
		spec_callback.dkc_callback = NULL;

		/* synchronous flush on volatile cache */
		rc = cdev_ioctl(vp->v_rdev, DKIOCFLUSHWRITECACHE,
		    (intptr_t)&spec_callback, FNATIVE|FKIOCTL, cr, &rval);

		if (rc == ENOTSUP || rc == ENOTTY) {
			mutex_enter(&sp->s_lock);
			sp->s_flag |= SNOFLUSH;
			mutex_exit(&sp->s_lock);
		}
	}

	/*
	 * If no real vnode to update, don't flush anything.
	 */
	if (realvp == NULL)
		return (0);

	vatmp.va_mask = AT_ATIME|AT_MTIME;
	if (VOP_GETATTR(realvp, &vatmp, 0, cr, ct) == 0) {

		mutex_enter(&sp->s_lock);
		if (vatmp.va_atime.tv_sec > sp->s_atime)
			va.va_atime = vatmp.va_atime;
		else {
			va.va_atime.tv_sec = sp->s_atime;
			va.va_atime.tv_nsec = 0;
		}
		if (vatmp.va_mtime.tv_sec > sp->s_mtime)
			va.va_mtime = vatmp.va_mtime;
		else {
			va.va_mtime.tv_sec = sp->s_mtime;
			va.va_mtime.tv_nsec = 0;
		}
		mutex_exit(&sp->s_lock);

		va.va_mask = AT_ATIME|AT_MTIME;
		(void) VOP_SETATTR(realvp, &va, 0, cr, ct);
	}
	(void) VOP_FSYNC(realvp, syncflag, cr, ct);
	return (0);
}

/*ARGSUSED*/
static void
spec_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	struct vnode *cvp;
	struct vnode *rvp;

	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1) {
		panic("spec_inactive: Bad v_count");
		/*NOTREACHED*/
	}
	mutex_enter(&stable_lock);

	mutex_enter(&vp->v_lock);
	VN_RELE_LOCKED(vp);
	if (vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&stable_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	sdelete(sp);
	mutex_exit(&stable_lock);

	/* We are the sole owner of sp now */
	cvp = sp->s_commonvp;
	rvp = sp->s_realvp;

	if (rvp) {
		/*
		 * If the snode times changed, then update the times
		 * associated with the "realvp".
		 */
		if ((sp->s_flag & (SACC|SUPD|SCHG)) != 0) {

			struct vattr va, vatmp;

			mutex_enter(&sp->s_lock);
			sp->s_flag &= ~(SACC|SUPD|SCHG);
			mutex_exit(&sp->s_lock);
			vatmp.va_mask = AT_ATIME|AT_MTIME;
			/*
			 * The user may not own the device, but we
			 * want to update the attributes anyway.
			 */
			if (VOP_GETATTR(rvp, &vatmp, 0, kcred, ct) == 0) {
				if (vatmp.va_atime.tv_sec > sp->s_atime)
					va.va_atime = vatmp.va_atime;
				else {
					va.va_atime.tv_sec = sp->s_atime;
					va.va_atime.tv_nsec = 0;
				}
				if (vatmp.va_mtime.tv_sec > sp->s_mtime)
					va.va_mtime = vatmp.va_mtime;
				else {
					va.va_mtime.tv_sec = sp->s_mtime;
					va.va_mtime.tv_nsec = 0;
				}

				va.va_mask = AT_ATIME|AT_MTIME;
				(void) VOP_SETATTR(rvp, &va, 0, kcred, ct);
			}
		}
	}
	ASSERT(!vn_has_cached_data(vp));
	vn_invalid(vp);

	/* if we are sharing another file systems vfs, release it */
	if (vp->v_vfsp && (vp->v_vfsp != &spec_vfs))
		VFS_RELE(vp->v_vfsp);

	/* if we have a realvp, release the realvp */
	if (rvp)
		VN_RELE(rvp);

	/* if we have a common, release the common */
	if (cvp && (cvp != vp)) {
		VN_RELE(cvp);
#ifdef DEBUG
	} else if (cvp) {
		/*
		 * if this is the last reference to a common vnode, any
		 * associated stream had better have been closed
		 */
		ASSERT(cvp == vp);
		ASSERT(cvp->v_stream == NULL);
#endif /* DEBUG */
	}

	/*
	 * if we have a hold on a devinfo node (established by
	 * spec_assoc_vp_with_devi), release the hold
	 */
	if (sp->s_dip)
		ddi_release_devi(sp->s_dip);

	/*
	 * If we have an associated device policy, release it.
	 */
	if (sp->s_plcy != NULL)
		dpfree(sp->s_plcy);

	/*
	 * If all holds on the devinfo node are through specfs/devfs
	 * and we just destroyed the last specfs node associated with the
	 * device, then the devinfo node reference count should now be
	 * zero.  We can't check this because there may be other holds
	 * on the node from non file system sources: ddi_hold_devi_by_instance
	 * for example.
	 */
	kmem_cache_free(snode_cache, sp);
}

static int
spec_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct vnode *realvp;
	struct snode *sp = VTOS(vp);

	if ((realvp = sp->s_realvp) != NULL)
		return (VOP_FID(realvp, fidp, ct));
	else
		return (EINVAL);
}

/*ARGSUSED1*/
static int
spec_seek(
	struct vnode *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	offset_t maxoff = spec_maxoffset(vp);

	if (maxoff == -1 || *noffp <= maxoff)
		return (0);
	else
		return (EINVAL);
}

static int
spec_frlock(
	struct vnode *vp,
	int		cmd,
	struct flock64	*bfp,
	int		flag,
	offset_t	offset,
	struct flk_callback *flk_cbp,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	struct snode *csp;

	csp = VTOS(sp->s_commonvp);
	/*
	 * If file is being mapped, disallow frlock.
	 */
	if (csp->s_mapcnt > 0)
		return (EAGAIN);

	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

static int
spec_realvp(struct vnode *vp, struct vnode **vpp, caller_context_t *ct)
{
	struct vnode *rvp;

	if ((rvp = VTOS(vp)->s_realvp) != NULL) {
		vp = rvp;
		if (VOP_REALVP(vp, &rvp, ct) == 0)
			vp = rvp;
	}

	*vpp = vp;
	return (0);
}

/*
 * Return all the pages from [off..off + len] in block
 * or character device.
 */
/*ARGSUSED*/
static int
spec_getpage(
	struct vnode	*vp,
	offset_t	off,
	size_t		len,
	uint_t		*protp,
	page_t		*pl[],
	size_t		plsz,
	struct seg	*seg,
	caddr_t		addr,
	enum seg_rw	rw,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	int err;

	ASSERT(sp->s_commonvp == vp);

	/*
	 * XXX	Given the above assertion, this might not do
	 *	what is wanted here.
	 */
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);
	TRACE_4(TR_FAC_SPECFS, TR_SPECFS_GETPAGE,
	    "specfs getpage:vp %p off %llx len %ld snode %p",
	    vp, off, len, sp);

	switch (vp->v_type) {
	case VBLK:
		if (protp != NULL)
			*protp = PROT_ALL;

		if (((u_offset_t)off + len) > (SPEC_SIZE(sp) + PAGEOFFSET))
			return (EFAULT);	/* beyond EOF */

		err = pvn_getpages(spec_getapage, vp, (u_offset_t)off, len,
		    protp, pl, plsz, seg, addr, rw, cr);
		break;

	case VCHR:
		cmn_err(CE_NOTE, "spec_getpage called for character device. "
		    "Check any non-ON consolidation drivers");
		err = 0;
		pl[0] = (page_t *)0;
		break;

	default:
		panic("spec_getpage: bad v_type 0x%x", vp->v_type);
		/*NOTREACHED*/
	}

	return (err);
}

extern int klustsize;	/* set in machdep.c */

int spec_ra = 1;
int spec_lostpage;	/* number of times we lost original page */

/*ARGSUSED2*/
static int
spec_getapage(
	struct vnode *vp,
	u_offset_t	off,
	size_t		len,
	uint_t		*protp,
	page_t		*pl[],
	size_t		plsz,
	struct seg	*seg,
	caddr_t		addr,
	enum seg_rw	rw,
	struct cred	*cr)
{
	struct snode *sp;
	struct buf *bp;
	page_t *pp, *pp2;
	u_offset_t io_off1, io_off2;
	size_t io_len1;
	size_t io_len2;
	size_t blksz;
	u_offset_t blkoff;
	int dora, err;
	page_t *pagefound;
	uint_t xlen;
	size_t adj_klustsize;
	u_offset_t size;
	u_offset_t tmpoff;

	sp = VTOS(vp);
	TRACE_3(TR_FAC_SPECFS, TR_SPECFS_GETAPAGE,
	    "specfs getapage:vp %p off %llx snode %p", vp, off, sp);
reread:

	err = 0;
	bp = NULL;
	pp = NULL;
	pp2 = NULL;

	if (pl != NULL)
		pl[0] = NULL;

	size = SPEC_SIZE(VTOS(sp->s_commonvp));

	if (spec_ra && sp->s_nextr == off)
		dora = 1;
	else
		dora = 0;

	if (size == UNKNOWN_SIZE) {
		dora = 0;
		adj_klustsize = PAGESIZE;
	} else {
		adj_klustsize = dora ? klustsize : PAGESIZE;
	}

again:
	if ((pagefound = page_exists(vp, off)) == NULL) {
		if (rw == S_CREATE) {
			/*
			 * We're allocating a swap slot and it's
			 * associated page was not found, so allocate
			 * and return it.
			 */
			if ((pp = page_create_va(vp, off,
			    PAGESIZE, PG_WAIT, seg, addr)) == NULL) {
				panic("spec_getapage: page_create");
				/*NOTREACHED*/
			}
			io_len1 = PAGESIZE;
			sp->s_nextr = off + PAGESIZE;
		} else {
			/*
			 * Need to really do disk I/O to get the page(s).
			 */
			blkoff = (off / adj_klustsize) * adj_klustsize;
			if (size == UNKNOWN_SIZE) {
				blksz = PAGESIZE;
			} else {
				if (blkoff + adj_klustsize <= size)
					blksz = adj_klustsize;
				else
					blksz =
					    MIN(size - blkoff, adj_klustsize);
			}

			pp = pvn_read_kluster(vp, off, seg, addr, &tmpoff,
			    &io_len1, blkoff, blksz, 0);
			io_off1 = tmpoff;
			/*
			 * Make sure the page didn't sneek into the
			 * cache while we blocked in pvn_read_kluster.
			 */
			if (pp == NULL)
				goto again;

			/*
			 * Zero part of page which we are not
			 * going to be reading from disk now.
			 */
			xlen = (uint_t)(io_len1 & PAGEOFFSET);
			if (xlen != 0)
				pagezero(pp->p_prev, xlen, PAGESIZE - xlen);

			bp = spec_startio(vp, pp, io_off1, io_len1,
			    pl == NULL ? (B_ASYNC | B_READ) : B_READ);
			sp->s_nextr = io_off1 + io_len1;
		}
	}

	if (dora && rw != S_CREATE) {
		u_offset_t off2;
		caddr_t addr2;

		off2 = ((off / adj_klustsize) + 1) * adj_klustsize;
		addr2 = addr + (off2 - off);

		pp2 = NULL;
		/*
		 * If we are past EOF then don't bother trying
		 * with read-ahead.
		 */
		if (off2 >= size)
			pp2 = NULL;
		else {
			if (off2 + adj_klustsize <= size)
				blksz = adj_klustsize;
			else
				blksz = MIN(size - off2, adj_klustsize);

			pp2 = pvn_read_kluster(vp, off2, seg, addr2, &tmpoff,
			    &io_len2, off2, blksz, 1);
			io_off2 = tmpoff;
		}

		if (pp2 != NULL) {
			/*
			 * Zero part of page which we are not
			 * going to be reading from disk now.
			 */
			xlen = (uint_t)(io_len2 & PAGEOFFSET);
			if (xlen != 0)
				pagezero(pp2->p_prev, xlen, PAGESIZE - xlen);

			(void) spec_startio(vp, pp2, io_off2, io_len2,
			    B_READ | B_ASYNC);
		}
	}

	if (pl == NULL)
		return (err);

	if (bp != NULL) {
		err = biowait(bp);
		pageio_done(bp);

		if (err) {
			if (pp != NULL)
				pvn_read_done(pp, B_ERROR);
			return (err);
		}
	}

	if (pagefound) {
		se_t se = (rw == S_CREATE ? SE_EXCL : SE_SHARED);
		/*
		 * Page exists in the cache, acquire the appropriate
		 * lock.  If this fails, start all over again.
		 */

		if ((pp = page_lookup(vp, off, se)) == NULL) {
			spec_lostpage++;
			goto reread;
		}
		pl[0] = pp;
		pl[1] = NULL;

		sp->s_nextr = off + PAGESIZE;
		return (0);
	}

	if (pp != NULL)
		pvn_plist_init(pp, pl, plsz, off, io_len1, rw);
	return (0);
}

/*
 * Flags are composed of {B_INVAL, B_DIRTY B_FREE, B_DONTNEED, B_FORCE}.
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 & off == 0 (entire vp list),
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 */
/*ARGSUSED5*/
int
spec_putpage(
	struct vnode *vp,
	offset_t	off,
	size_t		len,
	int		flags,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct snode *sp = VTOS(vp);
	struct vnode *cvp;
	page_t *pp;
	u_offset_t io_off;
	size_t io_len = 0;	/* for lint */
	int err = 0;
	u_offset_t size;
	u_offset_t tmpoff;

	ASSERT(vp->v_count != 0);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	cvp = sp->s_commonvp;
	size = SPEC_SIZE(VTOS(cvp));

	if (!vn_has_cached_data(vp) || off >= size)
		return (0);

	ASSERT(vp->v_type == VBLK && cvp == vp);
	TRACE_4(TR_FAC_SPECFS, TR_SPECFS_PUTPAGE,
	    "specfs putpage:vp %p off %llx len %ld snode %p",
	    vp, off, len, sp);

	if (len == 0) {
		/*
		 * Search the entire vp list for pages >= off.
		 */
		err = pvn_vplist_dirty(vp, off, spec_putapage,
		    flags, cr);
	} else {
		u_offset_t eoff;

		/*
		 * Loop over all offsets in the range [off...off + len]
		 * looking for pages to deal with.  We set limits so
		 * that we kluster to klustsize boundaries.
		 */
		eoff = off + len;
		for (io_off = off; io_off < eoff && io_off < size;
		    io_off += io_len) {
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || pvn_getdirty(pp, flags) == 0)
				io_len = PAGESIZE;
			else {
				err = spec_putapage(vp, pp, &tmpoff, &io_len,
				    flags, cr);
				io_off = tmpoff;
				if (err != 0)
					break;
				/*
				 * "io_off" and "io_len" are returned as
				 * the range of pages we actually wrote.
				 * This allows us to skip ahead more quickly
				 * since several pages may've been dealt
				 * with by this iteration of the loop.
				 */
			}
		}
	}
	return (err);
}


/*
 * Write out a single page, possibly klustering adjacent
 * dirty pages.
 */
/*ARGSUSED5*/
static int
spec_putapage(
	struct vnode	*vp,
	page_t		*pp,
	u_offset_t	*offp,		/* return value */
	size_t		*lenp,		/* return value */
	int		flags,
	struct cred	*cr)
{
	struct snode *sp = VTOS(vp);
	u_offset_t io_off;
	size_t io_len;
	size_t blksz;
	u_offset_t blkoff;
	int err = 0;
	struct buf *bp;
	u_offset_t size;
	size_t adj_klustsize;
	u_offset_t tmpoff;

	/*
	 * Destroy read ahead value since we are really going to write.
	 */
	sp->s_nextr = 0;
	size = SPEC_SIZE(VTOS(sp->s_commonvp));

	adj_klustsize = klustsize;

	blkoff = (pp->p_offset / adj_klustsize) * adj_klustsize;

	if (blkoff + adj_klustsize <= size)
		blksz = adj_klustsize;
	else
		blksz = size - blkoff;

	/*
	 * Find a kluster that fits in one contiguous chunk.
	 */
	pp = pvn_write_kluster(vp, pp, &tmpoff, &io_len, blkoff,
	    blksz, flags);
	io_off = tmpoff;

	/*
	 * Check for page length rounding problems
	 * XXX - Is this necessary?
	 */
	if (io_off + io_len > size) {
		ASSERT((io_off + io_len) - size < PAGESIZE);
		io_len = size - io_off;
	}

	bp = spec_startio(vp, pp, io_off, io_len, B_WRITE | flags);

	/*
	 * Wait for i/o to complete if the request is not B_ASYNC.
	 */
	if ((flags & B_ASYNC) == 0) {
		err = biowait(bp);
		pageio_done(bp);
		pvn_write_done(pp, ((err) ? B_ERROR : 0) | B_WRITE | flags);
	}

	if (offp)
		*offp = io_off;
	if (lenp)
		*lenp = io_len;
	TRACE_4(TR_FAC_SPECFS, TR_SPECFS_PUTAPAGE,
	    "specfs putapage:vp %p offp %p snode %p err %d",
	    vp, offp, sp, err);
	return (err);
}

/*
 * Flags are composed of {B_ASYNC, B_INVAL, B_FREE, B_DONTNEED}
 */
static struct buf *
spec_startio(
	struct vnode *vp,
	page_t		*pp,
	u_offset_t	io_off,
	size_t		io_len,
	int		flags)
{
	struct buf *bp;

	bp = pageio_setup(pp, io_len, vp, flags);

	bp->b_edev = vp->v_rdev;
	bp->b_dev = cmpdev(vp->v_rdev);
	bp->b_blkno = btodt(io_off);
	bp->b_un.b_addr = (caddr_t)0;

	(void) bdev_strategy(bp);

	if (flags & B_READ)
		lwp_stat_update(LWP_STAT_INBLK, 1);
	else
		lwp_stat_update(LWP_STAT_OUBLK, 1);

	return (bp);
}

static int
spec_poll(
	struct vnode	*vp,
	short		events,
	int		anyyet,
	short		*reventsp,
	struct pollhead **phpp,
	caller_context_t *ct)
{
	dev_t dev;
	int error;

	if (vp->v_type == VBLK)
		error = fs_poll(vp, events, anyyet, reventsp, phpp, ct);
	else {
		ASSERT(vp->v_type == VCHR);
		dev = vp->v_rdev;
		if (vp->v_stream) {
			ASSERT(vp->v_stream != NULL);
			error = strpoll(vp->v_stream, events, anyyet,
			    reventsp, phpp);
		} else if (devopsp[getmajor(dev)]->devo_cb_ops->cb_chpoll) {
			error = cdev_poll(dev, events, anyyet, reventsp, phpp);
		} else {
			error = fs_poll(vp, events, anyyet, reventsp, phpp, ct);
		}
	}
	return (error);
}

/*
 * This routine is called through the cdevsw[] table to handle
 * traditional mmap'able devices that support a d_mmap function.
 */
/*ARGSUSED8*/
int
spec_segmap(
	dev_t dev,
	off_t off,
	struct as *as,
	caddr_t *addrp,
	off_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	struct cred *cred)
{
	struct segdev_crargs dev_a;
	int (*mapfunc)(dev_t dev, off_t off, int prot);
	size_t i;
	int	error;

	if ((mapfunc = devopsp[getmajor(dev)]->devo_cb_ops->cb_mmap) == nodev)
		return (ENODEV);
	TRACE_4(TR_FAC_SPECFS, TR_SPECFS_SEGMAP,
	    "specfs segmap:dev %x as %p len %lx prot %x",
	    dev, as, len, prot);

	/*
	 * Character devices that support the d_mmap
	 * interface can only be mmap'ed shared.
	 */
	if ((flags & MAP_TYPE) != MAP_SHARED)
		return (EINVAL);

	/*
	 * Check to ensure that the entire range is
	 * legal and we are not trying to map in
	 * more than the device will let us.
	 */
	for (i = 0; i < len; i += PAGESIZE) {
		if (cdev_mmap(mapfunc, dev, off + i, maxprot) == -1)
			return (ENXIO);
	}

	as_rangelock(as);
	/* Pick an address w/o worrying about any vac alignment constraints. */
	error = choose_addr(as, addrp, len, off, ADDR_NOVACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	dev_a.mapfunc = mapfunc;
	dev_a.dev = dev;
	dev_a.offset = off;
	dev_a.prot = (uchar_t)prot;
	dev_a.maxprot = (uchar_t)maxprot;
	dev_a.hat_flags = 0;
	dev_a.hat_attr = 0;
	dev_a.devmap_data = NULL;

	error = as_map(as, *addrp, len, segdev_create, &dev_a);
	as_rangeunlock(as);
	return (error);
}

int
spec_char_map(
	dev_t dev,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred)
{
	int error = 0;
	major_t maj = getmajor(dev);
	int map_flag;
	int (*segmap)(dev_t, off_t, struct as *,
	    caddr_t *, off_t, uint_t, uint_t, uint_t, cred_t *);
	int (*devmap)(dev_t, devmap_cookie_t, offset_t,
	    size_t, size_t *, uint_t);
	int (*mmap)(dev_t dev, off_t off, int prot);

	/*
	 * Character device: let the device driver
	 * pick the appropriate segment driver.
	 *
	 * 4.x compat.: allow 'NULL' cb_segmap => spec_segmap
	 * Kindness: allow 'nulldev' cb_segmap => spec_segmap
	 */
	segmap = devopsp[maj]->devo_cb_ops->cb_segmap;
	if (segmap == NULL || segmap == nulldev || segmap == nodev) {
		mmap = devopsp[maj]->devo_cb_ops->cb_mmap;
		map_flag = devopsp[maj]->devo_cb_ops->cb_flag;

		/*
		 * Use old mmap framework if the driver has both mmap
		 * and devmap entry points.  This is to prevent the
		 * system from calling invalid devmap entry point
		 * for some drivers that might have put garbage in the
		 * devmap entry point.
		 */
		if ((map_flag & D_DEVMAP) || mmap == NULL ||
		    mmap == nulldev || mmap == nodev) {
			devmap = devopsp[maj]->devo_cb_ops->cb_devmap;

			/*
			 * If driver provides devmap entry point in
			 * cb_ops but not xx_segmap(9E), call
			 * devmap_setup with default settings
			 * (NULL) for callback_ops and driver
			 * callback private data
			 */
			if (devmap == nodev || devmap == NULL ||
			    devmap == nulldev)
				return (ENODEV);

			error = devmap_setup(dev, off, as, addrp,
			    len, prot, maxprot, flags, cred);

			return (error);
		} else
			segmap = spec_segmap;
	} else
		segmap = cdev_segmap;

	return ((*segmap)(dev, (off_t)off, as, addrp, len, prot,
	    maxprot, flags, cred));
}

/*ARGSUSED9*/
static int
spec_map(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	int error = 0;
	struct snode *sp = VTOS(vp);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/* fail map with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	/*
	 * If file is locked, fail mapping attempt.
	 */
	if (vn_has_flocks(vp))
		return (EAGAIN);

	if (vp->v_type == VCHR) {
		return (spec_char_map(vp->v_rdev, off, as, addrp, len, prot,
		    maxprot, flags, cred));
	} else if (vp->v_type == VBLK) {
		struct segvn_crargs vn_a;
		struct vnode *cvp;
		struct snode *sp;

		/*
		 * Block device, use segvn mapping to the underlying commonvp
		 * for pages.
		 */
		if (off > spec_maxoffset(vp))
			return (ENXIO);

		sp = VTOS(vp);
		cvp = sp->s_commonvp;
		ASSERT(cvp != NULL);

		if (off < 0 || ((offset_t)(off + len) < 0))
			return (ENXIO);

		as_rangelock(as);
		error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
		if (error != 0) {
			as_rangeunlock(as);
			return (error);
		}

		vn_a.vp = cvp;
		vn_a.offset = off;
		vn_a.type = flags & MAP_TYPE;
		vn_a.prot = (uchar_t)prot;
		vn_a.maxprot = (uchar_t)maxprot;
		vn_a.flags = flags & ~MAP_TYPE;
		vn_a.cred = cred;
		vn_a.amp = NULL;
		vn_a.szc = 0;
		vn_a.lgrp_mem_policy_flags = 0;

		error = as_map(as, *addrp, len, segvn_create, &vn_a);
		as_rangeunlock(as);
	} else
		return (ENODEV);

	return (error);
}

/*ARGSUSED1*/
static int
spec_addmap(
	struct vnode *vp,	/* the common vnode */
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,		/* how many bytes to add */
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	int error = 0;
	struct snode *csp = VTOS(vp);
	ulong_t npages;

	ASSERT(vp != NULL && VTOS(vp)->s_commonvp == vp);

	/*
	 * XXX	Given the above assertion, this might not
	 *	be a particularly sensible thing to test.
	 */
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/* fail with EIO if the device is fenced off */
	if (S_ISFENCED(csp))
		return (EIO);

	npages = btopr(len);
	LOCK_CSP(csp);
	csp->s_mapcnt += npages;

	UNLOCK_CSP(csp);
	return (error);
}

/*ARGSUSED1*/
static int
spec_delmap(
	struct vnode *vp,	/* the common vnode */
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,		/* how many bytes to take away */
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct snode *csp = VTOS(vp);
	ulong_t npages;
	long mcnt;

	/* segdev passes us the common vp */

	ASSERT(vp != NULL && VTOS(vp)->s_commonvp == vp);

	/* allow delmap to succeed even if device fenced off */

	/*
	 * XXX	Given the above assertion, this might not
	 *	be a particularly sensible thing to test..
	 */
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	npages = btopr(len);

	LOCK_CSP(csp);
	mutex_enter(&csp->s_lock);
	mcnt = (csp->s_mapcnt -= npages);

	if (mcnt == 0) {
		/*
		 * Call the close routine when the last reference of any
		 * kind through any [s, v]node goes away.  The s_dip hold
		 * on the devinfo node is released when the vnode is
		 * destroyed.
		 */
		if (csp->s_count == 0) {
			csp->s_flag &= ~(SNEEDCLOSE | SSIZEVALID);

			/* See comment in spec_close() */
			if (csp->s_flag & (SCLONE | SSELFCLONE))
				csp->s_flag &= ~SDIPSET;

			mutex_exit(&csp->s_lock);

			(void) device_close(vp, 0, cred);
		} else
			mutex_exit(&csp->s_lock);

		mutex_enter(&csp->s_lock);
	}
	ASSERT(mcnt >= 0);

	UNLOCK_CSP_LOCK_HELD(csp);
	mutex_exit(&csp->s_lock);

	return (0);
}

/*ARGSUSED4*/
static int
spec_dump(
	struct vnode *vp,
	caddr_t addr,
	offset_t bn,
	offset_t count,
	caller_context_t *ct)
{
	/* allow dump to succeed even if device fenced off */

	ASSERT(vp->v_type == VBLK);
	return (bdev_dump(vp->v_rdev, addr, (daddr_t)bn, (int)count));
}


/*
 * Do i/o on the given page list from/to vp, io_off for io_len.
 * Flags are composed of:
 * 	{B_ASYNC, B_INVAL, B_FREE, B_DONTNEED, B_READ, B_WRITE}
 * If B_ASYNC is not set i/o is waited for.
 */
/*ARGSUSED5*/
static int
spec_pageio(
	struct vnode *vp,
	page_t	*pp,
	u_offset_t io_off,
	size_t	io_len,
	int	flags,
	cred_t	*cr,
	caller_context_t *ct)
{
	struct buf *bp = NULL;
	int err = 0;

	if (pp == NULL)
		return (EINVAL);

	bp = spec_startio(vp, pp, io_off, io_len, flags);

	/*
	 * Wait for i/o to complete if the request is not B_ASYNC.
	 */
	if ((flags & B_ASYNC) == 0) {
		err = biowait(bp);
		pageio_done(bp);
	}
	return (err);
}

/*
 * Set ACL on underlying vnode if one exists, or return ENOSYS otherwise.
 */
int
spec_setsecattr(
	struct vnode *vp,
	vsecattr_t *vsap,
	int flag,
	struct cred *cr,
	caller_context_t *ct)
{
	struct vnode *realvp;
	struct snode *sp = VTOS(vp);
	int error;

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	/*
	 * The acl(2) system calls VOP_RWLOCK on the file before setting an
	 * ACL, but since specfs does not serialize reads and writes, this
	 * VOP does not do anything.  However, some backing file systems may
	 * expect the lock to be held before setting an ACL, so it is taken
	 * here privately to avoid serializing specfs reads and writes.
	 */
	if ((realvp = sp->s_realvp) != NULL) {
		(void) VOP_RWLOCK(realvp, V_WRITELOCK_TRUE, ct);
		error = VOP_SETSECATTR(realvp, vsap, flag, cr, ct);
		(void) VOP_RWUNLOCK(realvp, V_WRITELOCK_TRUE, ct);
		return (error);
	} else
		return (fs_nosys());
}

/*
 * Get ACL from underlying vnode if one exists, or fabricate it from
 * the permissions returned by spec_getattr() otherwise.
 */
int
spec_getsecattr(
	struct vnode *vp,
	vsecattr_t *vsap,
	int flag,
	struct cred *cr,
	caller_context_t *ct)
{
	struct vnode *realvp;
	struct snode *sp = VTOS(vp);

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	if ((realvp = sp->s_realvp) != NULL)
		return (VOP_GETSECATTR(realvp, vsap, flag, cr, ct));
	else
		return (fs_fab_acl(vp, vsap, flag, cr, ct));
}

int
spec_pathconf(
	vnode_t *vp,
	int cmd,
	ulong_t *valp,
	cred_t *cr,
	caller_context_t *ct)
{
	vnode_t *realvp;
	struct snode *sp = VTOS(vp);

	/* fail with ENXIO if the device is fenced off */
	if (S_ISFENCED(sp))
		return (ENXIO);

	if ((realvp = sp->s_realvp) != NULL)
		return (VOP_PATHCONF(realvp, cmd, valp, cr, ct));
	else
		return (fs_pathconf(vp, cmd, valp, cr, ct));
}

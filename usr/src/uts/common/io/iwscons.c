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
 * workstation console redirecting driver
 *
 * Redirects all I/O through a given device instance to the device designated
 * as the current target, as given by the vnode associated with the first
 * entry in the list of redirections for the given device instance.  The
 * implementation assumes that this vnode denotes a STREAMS device; this is
 * perhaps a bug.
 *
 * Supports the SRIOCSREDIR ioctl for designating a new redirection target.
 * The new target is added to the front of a list of potentially active
 * designees.  Should the device at the front of this list be closed, the new
 * front entry assumes active duty.  (Stated differently, redirection targets
 * stack, except that it's possible for entries in the interior of the stack
 * to go away.)
 *
 * Supports the SRIOCISREDIR ioctl for inquiring whether the descriptor given
 * as argument is the current front of the redirection list associated with
 * the descriptor on which the ioctl was issued.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/open.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/strredir.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/sunldi.h>
#include <sys/consdev.h>
#include <sys/fs/snode.h>

/*
 * Global data
 */
static dev_info_t	*iwscn_dip;

/*
 * We record the list of redirections as a linked list of iwscn_list_t
 * structures.  We need to keep track of the target's vp, so that
 * we can vector reads, writes, etc. off to the current designee.
 */
typedef struct _iwscn_list {
	struct _iwscn_list	*wl_next;	/* next entry */
	vnode_t			*wl_vp;		/* target's vnode */
	int			wl_ref_cnt;	/* operation in progress */
	boolean_t		wl_is_console;	/* is the real console */
} iwscn_list_t;
static iwscn_list_t	*iwscn_list;

/*
 * iwscn_list_lock serializes modifications to the global iwscn_list list.
 *
 * iwscn_list_cv is used when freeing an entry from iwscn_list to allow
 * the caller to wait till the wl_ref_cnt field is zero.
 *
 * iwscn_redirect_lock is used to serialize redirection requests.  This
 * is required to ensure that all active redirection streams have
 * the redirection streams module (redirmod) pushed on them.
 *
 * If both iwscn_redirect_lock and iwscn_list_lock must be held then
 * iwscn_redirect_lock must be acquired first.
 */
static kcondvar_t	iwscn_list_cv;
static kmutex_t		iwscn_list_lock;
static kmutex_t		iwscn_redirect_lock;

/*
 * Routines for managing iwscn_list
 */
static vnode_t *
str_vp(vnode_t *vp)
{
	/*
	 * Here we switch to using the vnode that is linked
	 * to from the stream queue.  (In the case of device
	 * streams this will correspond to the common vnode
	 * for the device.)  The reason we use this vnode
	 * is that when wcmclose() calls srpop(), this is the
	 * only vnode that it has access to.
	 */
	ASSERT(vp->v_stream != NULL);
	return (vp->v_stream->sd_vnode);
}

/*
 * Interrupt any operations that may be outstanding against this vnode.
 * optionally, wait for them to complete.
 */
static void
srinterrupt(iwscn_list_t *lp, boolean_t wait)
{
	ASSERT(MUTEX_HELD(&iwscn_list_lock));

	while (lp->wl_ref_cnt != 0) {
		strsetrerror(lp->wl_vp, EINTR, 0, NULL);
		strsetwerror(lp->wl_vp, EINTR, 0, NULL);
		if (!wait)
			break;
		cv_wait(&iwscn_list_cv, &iwscn_list_lock);
	}
}

/*
 * Remove vp from the redirection list rooted at iwscn_list, should it
 * be there. Return a pointer to the removed entry.
 */
static iwscn_list_t *
srrm(vnode_t *vp)
{
	iwscn_list_t	*lp, **lpp;

	ASSERT(MUTEX_HELD(&iwscn_list_lock));

	/* Get the stream vnode */
	vp = str_vp(vp);
	ASSERT(vp);

	/* Look for this vnode on the redirection list */
	for (lpp = &iwscn_list; (lp = *lpp) != NULL; lpp = &lp->wl_next) {
		if (lp->wl_vp == vp)
			break;
	}
	if (lp != NULL)
		/* Found it, remove this entry from the redirection list */
		*lpp = lp->wl_next;

	return (lp);
}

/*
 * Push vp onto the redirection list.
 * If it's already there move it to the front position.
 */
static void
srpush(vnode_t *vp, boolean_t is_console)
{
	iwscn_list_t	*lp;

	ASSERT(MUTEX_HELD(&iwscn_list_lock));

	/* Get the stream vnode */
	vp = str_vp(vp);
	ASSERT(vp);

	/* Check if it's already on the redirection list */
	if ((lp = srrm(vp)) == NULL) {
		lp = kmem_zalloc(sizeof (*lp), KM_SLEEP);
		lp->wl_vp = vp;
		lp->wl_is_console = is_console;
	}
	/*
	 * Note that if this vnode was already somewhere on the redirection
	 * list then we removed it above and are now bumping it up to the
	 * front of the redirection list.
	 */
	lp->wl_next = iwscn_list;
	iwscn_list = lp;
}

/*
 * This vnode is no longer a valid redirection target. Terminate any current
 * operations. If closing, wait for them to complete, then free the entry.
 * If called because a hangup has occurred, just deprecate the entry to ensure
 * it won't become the target again.
 */
void
srpop(vnode_t *vp, boolean_t close)
{
	iwscn_list_t	*tlp;		/* This target's entry */
	iwscn_list_t	*lp, **lpp;

	mutex_enter(&iwscn_list_lock);

	/*
	 * Ensure no further operations are directed at the target
	 * by removing it from the redirection list.
	 */
	if ((tlp = srrm(vp)) == NULL) {
		/* vnode wasn't in the list */
		mutex_exit(&iwscn_list_lock);
		return;
	}
	/*
	 * Terminate any current operations.
	 * If we're closing, wait until they complete.
	 */
	srinterrupt(tlp, close);

	if (close) {
		/* We're finished with this target */
		kmem_free(tlp, sizeof (*tlp));
	} else {
		/*
		 * Deprecate the entry. There's no need for a flag to indicate
		 * this state, it just needs to be moved to the back of the list
		 * behind the underlying console device. Since the underlying
		 * device anchors the list and is never removed, this entry can
		 * never return to the front again to become the target.
		 */
		for (lpp = &iwscn_list; (lp = *lpp) != NULL; )
			lpp = &lp->wl_next;
		tlp->wl_next = NULL;
		*lpp = tlp;
	}
	mutex_exit(&iwscn_list_lock);
}

/* Get a hold on the current target */
static iwscn_list_t *
srhold()
{
	iwscn_list_t	*lp;

	mutex_enter(&iwscn_list_lock);
	ASSERT(iwscn_list != NULL);
	lp = iwscn_list;
	ASSERT(lp->wl_ref_cnt >= 0);
	lp->wl_ref_cnt++;
	mutex_exit(&iwscn_list_lock);

	return (lp);
}

/* Release a hold on an entry from the redirection list */
static void
srrele(iwscn_list_t *lp)
{
	ASSERT(lp != NULL);
	mutex_enter(&iwscn_list_lock);
	ASSERT(lp->wl_ref_cnt > 0);
	lp->wl_ref_cnt--;
	cv_broadcast(&iwscn_list_cv);
	mutex_exit(&iwscn_list_lock);
}

static int
iwscnread(dev_t dev, uio_t *uio, cred_t *cred)
{
	iwscn_list_t	*lp;
	int		error;

	ASSERT(getminor(dev) == 0);

	lp = srhold();
	error = strread(lp->wl_vp, uio, cred);
	srrele(lp);

	return (error);
}

static int
iwscnwrite(dev_t dev, uio_t *uio, cred_t *cred)
{
	iwscn_list_t	*lp;
	int		error;

	ASSERT(getminor(dev) == 0);

	lp = srhold();
	error = strwrite(lp->wl_vp, uio, cred);
	srrele(lp);

	return (error);
}

static int
iwscnpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	iwscn_list_t	*lp;
	int		error;

	ASSERT(getminor(dev) == 0);

	lp = srhold();
	error = VOP_POLL(lp->wl_vp, events, anyyet, reventsp, phpp, NULL);
	srrele(lp);

	return (error);
}

static int
iwscnioctl(dev_t dev, int cmd, intptr_t arg, int flag,
    cred_t *cred, int *rvalp)
{
	iwscn_list_t	*lp;
	file_t		*f;
	char		modname[FMNAMESZ + 1] = " ";
	int		error = 0;

	ASSERT(getminor(dev) == 0);

	switch (cmd) {
	case SRIOCSREDIR:
		/* Serialize all pushes of the redirection module */
		mutex_enter(&iwscn_redirect_lock);

		/*
		 * Find the vnode corresponding to the file descriptor
		 * argument and verify that it names a stream.
		 */
		if ((f = getf((int)arg)) == NULL) {
			mutex_exit(&iwscn_redirect_lock);
			return (EBADF);
		}
		if (f->f_vnode->v_stream == NULL) {
			releasef((int)arg);
			mutex_exit(&iwscn_redirect_lock);
			return (ENOSTR);
		}

		/*
		 * If the user is trying to redirect console output
		 * back to the underlying console via SRIOCSREDIR
		 * then they are evil and we'll stop them here.
		 */
		if (str_vp(f->f_vnode) == str_vp(rwsconsvp)) {
			releasef((int)arg);
			mutex_exit(&iwscn_redirect_lock);
			return (EINVAL);
		}

		/*
		 * Check if this stream already has the redirection
		 * module pushed onto it.  I_LOOK returns an error
		 * if there are no modules pushed onto the stream.
		 */
		(void) strioctl(f->f_vnode, I_LOOK, (intptr_t)modname,
		    FKIOCTL, K_TO_K, cred, rvalp);
		if (strcmp(modname, STRREDIR_MOD) != 0) {

			/*
			 * Push a new instance of the redirecting module onto
			 * the stream, so that its close routine can notify
			 * us when the overall stream is closed.  (In turn,
			 * we'll then remove it from the redirection list.)
			 */
			error = strioctl(f->f_vnode, I_PUSH,
			    (intptr_t)STRREDIR_MOD, FKIOCTL, K_TO_K,
			    cred, rvalp);

			if (error != 0) {
				releasef((int)arg);
				mutex_exit(&iwscn_redirect_lock);
				return (error);
			}
		}

		/* Push it onto the redirection stack */
		mutex_enter(&iwscn_list_lock);
		srpush(f->f_vnode, B_FALSE);
		mutex_exit(&iwscn_list_lock);

		releasef((int)arg);
		mutex_exit(&iwscn_redirect_lock);
		return (0);

	case SRIOCISREDIR:
		/*
		 * Find the vnode corresponding to the file descriptor
		 * argument and verify that it names a stream.
		 */
		if ((f = getf((int)arg)) == NULL) {
			return (EBADF);
		}
		if (f->f_vnode->v_stream == NULL) {
			releasef((int)arg);
			return (ENOSTR);
		}

		lp = srhold();
		*rvalp = (str_vp(f->f_vnode) == lp->wl_vp);
		srrele(lp);
		releasef((int)arg);
		return (0);

	case I_POP:
		/*
		 * We need to serialize I_POP operations with
		 * SRIOCSREDIR operations so we don't accidently
		 * remove the redirection module from a stream.
		 */
		mutex_enter(&iwscn_redirect_lock);
		lp = srhold();

		/*
		 * Here we need to protect against process that might
		 * try to pop off the redirection module from the
		 * redirected stream.  Popping other modules is allowed.
		 *
		 * It's ok to hold iwscn_list_lock while doing the
		 * I_LOOK since it's such a simple operation.
		 */
		(void) strioctl(lp->wl_vp, I_LOOK, (intptr_t)modname,
		    FKIOCTL, K_TO_K, cred, rvalp);

		if (strcmp(STRREDIR_MOD, modname) == 0) {
			srrele(lp);
			mutex_exit(&iwscn_redirect_lock);
			return (EINVAL);
		}

		/* Process the ioctl normally */
		error = VOP_IOCTL(lp->wl_vp, cmd, arg, flag, cred, rvalp, NULL);

		srrele(lp);
		mutex_exit(&iwscn_redirect_lock);
		return (error);
	}

	/* Process the ioctl normally */
	lp = srhold();
	error = VOP_IOCTL(lp->wl_vp, cmd, arg, flag, cred, rvalp, NULL);
	srrele(lp);
	return (error);
}

/* ARGSUSED */
static int
iwscnopen(dev_t *devp, int flag, int state, cred_t *cred)
{
	iwscn_list_t	*lp;
	vnode_t		*vp = rwsconsvp;

	if (state != OTYP_CHR)
		return (ENXIO);

	if (getminor(*devp) != 0)
		return (ENXIO);

	/*
	 * You can't really open us until the console subsystem
	 * has been configured.
	 */
	if (rwsconsvp == NULL)
		return (ENXIO);

	/*
	 * Check if this is the first open of this device or if
	 * there is currently no redirection going on.  (Ie, we're
	 * sending output to underlying console device.)
	 */
	mutex_enter(&iwscn_list_lock);
	if ((iwscn_list == NULL) || (iwscn_list->wl_vp == str_vp(vp))) {
		int		error = 0;

		/* Don't hold the list lock across an VOP_OPEN */
		mutex_exit(&iwscn_list_lock);

		/*
		 * There is currently no redirection going on.
		 * pass this open request onto the console driver
		 */
		error = VOP_OPEN(&vp, flag, cred, NULL);
		if (error != 0)
			return (error);

		/* Re-acquire the list lock */
		mutex_enter(&iwscn_list_lock);

		if (iwscn_list == NULL) {
			/* Save this vnode on the redirection list */
			srpush(vp, B_TRUE);
		} else {
			/*
			 * In this case there must already be a copy of
			 * this vnode on the list, so we can free up this one.
			 */
			(void) VOP_CLOSE(vp, flag, 1, (offset_t)0, cred, NULL);
		}
	}

	/*
	 * XXX This is an ugly legacy hack that has been around
	 * forever.  This code is here because this driver (the
	 * iwscn driver) is a character driver layered over a
	 * streams driver.
	 *
	 * Normally streams recieve notification whenever a process
	 * closes its last reference to that stream so that it can
	 * clean up any signal handling related configuration.  (Ie,
	 * when a stream is configured to deliver a signal to a
	 * process upon certain events.)  This is a feature supported
	 * by the streams framework.
	 *
	 * But character/block drivers don't recieve this type
	 * of notification.  A character/block driver's close routine
	 * is only invoked upon the last close of the device.  This
	 * is an artifact of the multiple open/single close driver
	 * model currently supported by solaris.
	 *
	 * So a problem occurs when a character driver layers itself
	 * on top of a streams driver.  Since this driver doesn't always
	 * receive a close notification when a process closes its
	 * last reference to it, this driver can't tell the stream
	 * it's layered upon to clean up any signal handling
	 * configuration for that process.
	 *
	 * So here we hack around that by manually cleaning up the
	 * signal handling list upon each open.  It doesn't guarantee
	 * that the signaling handling data stored in the stream will
	 * always be up to date, but it'll be more up to date than
	 * it would be if we didn't do this.
	 *
	 * The real way to solve this problem would be to change
	 * the device framework from an multiple open/single close
	 * model to a multiple open/multiple close model.  Then
	 * character/block drivers could pass on close requests
	 * to streams layered underneath.
	 */
	str_cn_clean(VTOS(rwsconsvp)->s_commonvp);
	for (lp = iwscn_list; lp != NULL; lp = lp->wl_next) {
		ASSERT(lp->wl_vp->v_stream != NULL);
		str_cn_clean(lp->wl_vp);
	}

	mutex_exit(&iwscn_list_lock);
	return (0);
}

/* ARGSUSED */
static int
iwscnclose(dev_t dev, int flag, int state, cred_t *cred)
{
	iwscn_list_t	*lp;

	ASSERT(getminor(dev) == 0);

	if (state != OTYP_CHR)
		return (ENXIO);

	mutex_enter(&iwscn_list_lock);
	/*
	 * Remove each entry from the redirection list, terminate any
	 * current operations, wait for them to finish, then free the entry.
	 */
	while (iwscn_list != NULL) {
		lp = srrm(iwscn_list->wl_vp);
		ASSERT(lp != NULL);
		srinterrupt(lp, B_TRUE);

		if (lp->wl_is_console == B_TRUE)
			/* Close the underlying console device. */
			(void) VOP_CLOSE(lp->wl_vp, 0, 1, (offset_t)0, kcred,
			    NULL);

		kmem_free(lp, sizeof (*lp));
	}
	mutex_exit(&iwscn_list_lock);
	return (0);
}

/*ARGSUSED*/
static int
iwscnattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/*
	 * This is a pseudo device so there will never be more than
	 * one instance attached at a time
	 */
	ASSERT(iwscn_dip == NULL);

	if (ddi_create_minor_node(devi, "iwscn", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	iwscn_dip = devi;
	mutex_init(&iwscn_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&iwscn_redirect_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&iwscn_list_cv, NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
iwscninfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (iwscn_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)iwscn_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

struct cb_ops	iwscn_cb_ops = {
	iwscnopen,		/* open */
	iwscnclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	iwscnread,		/* read */
	iwscnwrite,		/* write */
	iwscnioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	iwscnpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP			/* Driver compatibility flag */
};

struct dev_ops	iwscn_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	iwscninfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	iwscnattach,		/* attach */
	nodev,			/* detach */
	nodev,			/* reset */
	&iwscn_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Workstation Redirection driver",
	&iwscn_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

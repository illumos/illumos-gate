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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Redirecting driver; used to handle workstation console redirection.
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
 *
 * Every open instance of this driver corresponds to an instance of the
 * underlying client driver.  If the redirection stack would otherwise become
 * empty, this device (designated by the wd_vp field of the wcd_data
 * structure) is implicitly opened and added to the front of the list.  Thus,
 * there's always an active device for handling i/o through an open instance
 * of this driver.
 *
 * XXX: Names -- many of the names in this driver and its companion STREAMS
 *	module still reflect its origins as the workstation console
 *	redirection driver.  Ultimately, they should be changed to reflect the
 *	fact that this driver is potentially a general purpose redirection
 *	driver.  In the meantime, the driver is still specialized to have a
 *	single client -- the workstation console driver -- and its file name
 *	remains iwscons.c to reflect that specialization.
 *
 *	Proposed change: "iwscn" becomes either "dr" (for "streams redirecting
 *	driver") or "srm" (for "streams redirecting module"), as appropriate.
 *
 * XXX:	Add mechanism for notifying a redirectee that it's no longer the
 *	current redirectee?  (This in contrast to the current facility for
 *	letting it ask.)
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

static int	iwscninfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	iwscnattach(dev_info_t *, ddi_attach_cmd_t);
static int	iwscnopen(dev_t *, int, int, cred_t *);
static int	iwscnclose(dev_t, int, int, cred_t *);
static int	iwscnread(dev_t, struct uio *, cred_t *);
static int	iwscnwrite(dev_t, struct uio *, cred_t *);
static int	iwscnioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	iwscnpoll(dev_t, short, int, short *, struct pollhead **);

/*
 * Private copy of devinfo pointer; iwscninfo uses it.
 */
static dev_info_t	*iwscn_dip;

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
	nodev, 			/* segmap */
	iwscnpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW|D_MP		/* Driver compatibility flag */
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
	NULL			/* bus operations */
};

static krwlock_t	iwscn_lock; /* lock proecting almost everything here */

/*
 * A read/write lock was used to serialize reads,writes/opens,closes.
 * Sometime the open would hang due to a pending read.  The new lock
 * iwscn_open_lock and the read lock are held in open to assure a single
 * instance, while letting concurrent reads/writes to proceed.
 */
static kmutex_t 	iwscn_open_lock; /* Serializes opens  */

/*
 * These next two fields, protected by iwscn_lock, pass the data to wcmopen()
 * from the ioctl SRIOCSREDIR.  wcmopen() uses the data only if the thread
 * matches.  This keeps other threads from interfering.
 */
extern kthread_id_t	iwscn_thread;	/* thread that is allowed to */
					/* push redirm */
extern wcm_data_t	*iwscn_wcm_data;  /* allocated data for redirm */

/*
 * Forward declarations of private routines.
 */
static int		srreset(wcd_data_t *, int, cred_t *);
static wcrlist_t	*srrm(wcrlist_t **, vnode_t *, int);
static wcd_data_t	*srilookup(minor_t);
static wcd_data_t	*srialloc(minor_t);
static void		sridealloc(wcd_data_t *);
static wcrlist_t	*srpush(wcrlist_t **, vnode_t *);

/*
 * The head of the list of open instances.
 */
static wcd_data_t	*wcddata;

/*
 * Currently, the only client of this driver is the workstation console
 * driver.  Thus, we can get away with hard-wiring a reference to it here.
 *
 * To handle multiple clients, the driver must be revised as follows.
 * 1)	Add a registration routine that clients can call to announce
 *	themselves to this driver.  The routine should take as arguments the
 *	major device number of the corresponding instantiation of the
 *	redirecting driver and a pointer to its dedvnops ops vector.
 * 2)	Maintain a list (or perhaps hash array) or registered clients,
 *	recording for each the srvnops ops vector and a pointer to the list
 *	of open instances for that client.
 * 3)	Modify the driver entry points to use their dev argument to look up
 *	the proper instantiation, get the list of open instances, and then use
 *	that as they currently use the open instance list.
 * 4)	To allow clients to unload themselves, we probably need an unregister
 *	routine.  This routine would have to cope with active open instances.
 */
extern srvnops_t	wscons_srvnops;

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Workstation Redirection driver 'iwscn' 1.42",
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

/*
 * DDI glue routines.
 */

/*ARGSUSED*/
static int
iwscnattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	static char	been_here;

	if (!been_here) {
		been_here = 1;
		rw_init(&iwscn_lock, NULL, RW_DEFAULT, NULL);
	}
	if (ddi_create_minor_node(devi, "iwscn", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	iwscn_dip = devi;
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


/* ARGSUSED */
static int
iwscnopen(
	dev_t	*devp,
	int	flag,
	int	state,		/* should be OTYP_CHR */
	cred_t	*cred)
{
	minor_t		unit = getminor(*devp);
	wcd_data_t	*wd;
	int		err = 0;
	struct wcrlist	*wwd;

	if (state != OTYP_CHR)
		return (ENXIO);
	rw_enter(&iwscn_lock, RW_READER);
	mutex_enter(&iwscn_open_lock);
	if ((wd = srilookup(unit)) == NULL) {
		vnode_t	*vp;

		/*
		 * First open for this instance; get a state structure for it.
		 */
		wd = srialloc(unit);

		/*
		 * Call the client driver to obtain a held vnode for the
		 * underlying "real" device instance.
		 *
		 * XXX:	There's wired in knowledge of the client driver here.
		 */
		err = wscons_srvnops.svn_get(unit, &vp);
		if (err != 0) {
			sridealloc(wd);
			mutex_exit(&iwscn_open_lock);
			rw_exit(&iwscn_lock);
			return (err);
		}
		wd->wd_vp = vp;
	}

	/*
	 * Reinitalize the list if necessary.
	 *
	 * XXX:	Is it possible for the list to empty completely while this
	 *	instance is still open?  If not, this if should be coalesced
	 *	with the previous one.
	 */
	if (wd->wd_list == NULL) {
		wcrlist_t	*e = srpush(&wd->wd_list, wd->wd_vp);

		/*
		 * There's no corresponding redirecting module instance for
		 * the underlying device.
		 */
		e->wl_data = NULL;
	}

	err = srreset(wd, flag, cred);
	/*
	 *  XXX cleanup the sig list.  Hook for console driver.
	 */
	for (wwd = wd->wd_list; wwd != NULL; wwd = wwd->wl_next) {
		ASSERT(wwd->wl_vp->v_stream != NULL);
		str_cn_clean(wwd->wl_vp);
	}
	mutex_exit(&iwscn_open_lock);
	rw_exit(&iwscn_lock);
	return (err);
}

/* ARGSUSED */
static int
iwscnclose(
	dev_t	dev,
	int	flag,
	int	state,		/* should be OTYP_CHR */
	cred_t	*cred)
{
	wcd_data_t	*wd;
	int		err = 0;

	if (state != OTYP_CHR)
		return (ENXIO);
	rw_enter(&iwscn_lock, RW_WRITER);
	wd = srilookup(getminor(dev));
	/*
	 * Remove all outstanding redirections for this instance.
	 */
	while (wd->wd_list != NULL)
		(void) srrm(&wd->wd_list, wd->wd_list->wl_vp, 1);

	/*
	 * Since this is the _last_ close, it's our last chance to close the
	 * underlying device.  (Note that if someone else has the underlying
	 * workstation console device open, we won't get here, since
	 * spec_close will see s_count > 1.)
	 */
	while ((wd->wd_wsconsopen != 0) && (!err)) {
		err = VOP_CLOSE(wd->wd_vp, flag, 1, (offset_t)0, cred);
		if (!err)
			wd->wd_wsconsopen--;
	}
	if (!err)
		wd->wd_vp->v_stream = NULL;

	/*
	 * We don't need the vnode that the client driver gave us any more.
	 *
	 * XXX:	There's wired in knowledge of the client driver here.
	 */
	wscons_srvnops.svn_rele(wd->wd_unit, wd->wd_vp);
	sridealloc(wd);

	rw_exit(&iwscn_lock);
	return (err);
}

static int
iwscnread(dev_t dev, uio_t *uio, cred_t *cred)
{
	wcd_data_t	*wd;
	int 		error;
	vnode_t		*vp;

	rw_enter(&iwscn_lock, RW_READER);
	wd = srilookup(getminor(dev));
	/*
	 * We don't need to hold iwscn_lock while waiting for the read to
	 * complete, but the vnode must not be destroyed.
	 */
	vp = wd->wd_list->wl_vp;
	VN_HOLD(vp);
	rw_exit(&iwscn_lock);
	error = strread(vp, uio, cred);
	VN_RELE(vp);
	return (error);
}

static int
iwscnwrite(dev_t dev, uio_t *uio, cred_t *cred)
{
	wcd_data_t	*wd;
	int error;

	rw_enter(&iwscn_lock, RW_READER);
	wd = srilookup(getminor(dev));
	error = strwrite(wd->wd_list->wl_vp, uio, cred);
	rw_exit(&iwscn_lock);
	return (error);
}

static int
iwscnioctl(dev_t dev, int cmd, intptr_t arg, int flag,
    cred_t *cred, int *rvalp)
{
	wcd_data_t *wd;
	int err = 0;
	file_t *f;

	switch (cmd) {
	case SRIOCSREDIR: {
		wcrlist_t	*wlp;
		wcm_data_t	*mdp;

		if (!rw_tryenter(&iwscn_lock, RW_WRITER)) {
			return (EBUSY);
		}
		wd = srilookup(getminor(dev));
		/*
		 * Find the vnode corresponding to the file descriptor
		 * argument and verify that it names a stream.
		 */
		if ((f = getf((int)arg)) == NULL) {
			err = EBADF;
			break;
		}
		if (f->f_vnode->v_stream == NULL) {
			err = ENOSTR;
			releasef((int)arg);
			break;
		}
		/*
		 * allocate the private data for redirmod, and pass it through
		 * a global to wcmopen().  This is all protected by iwscn_lock.
		 */
		mdp = kmem_alloc(sizeof (*mdp), KM_SLEEP);
		iwscn_wcm_data = mdp;
		iwscn_thread = curthread;

		/*
		 * Push a new instance of the redirecting module onto the
		 * stream, so that its close routine can notify us when the
		 * overall stream is closed.  (In turn, we'll then remove it
		 * from the redirection list.)
		 */
		if ((err = VOP_IOCTL(f->f_vnode, I_PUSH, (intptr_t)"redirmod",
		    (FREAD | FKIOCTL), cred, rvalp)) != 0) {
			iwscn_thread = NULL;
			kmem_free(mdp, sizeof (*mdp));
			releasef((int)arg);
			break;
		}
		iwscn_thread = NULL;	/* clear authorization for wcmopen() */

		/*
		 * Push it onto the redirection stack.
		 */
		wlp = srpush(&wd->wd_list, f->f_vnode);
		/*
		 * Fill in the redirecting module instance's private data with
		 * information to let it get to our redirection list when its
		 * close routine is called.  Cross-link it with the
		 * redirection list entry.
		 */
		mdp->wm_wd = wd;
		mdp->wm_entry = wlp;
		wlp->wl_data = mdp;
		releasef((int)arg);

		break;
	    }

	case SRIOCISREDIR:
		rw_enter(&iwscn_lock, RW_READER);
		wd = srilookup(getminor(dev));
		if ((f = getf((int)arg)) == NULL) {
			err = EBADF;
			break;
		}
		/*
		 * Return value is 1 if the argument descriptor is the current
		 * redirection target, and 0 otherwise.
		 */
		*rvalp = (f->f_vnode == wd->wd_list->wl_vp) ? 1 : 0;
		releasef((int)arg);
		break;

	case I_POP: {
		/*
		 * XXX - This is a big kludge the handles a deadlock case
		 * when we are trying to pop off the redirection
		 * module.  Since this should only happen on a close
		 * of the device, and since it hangs the system, just
		 * do not allow a pop of the redirection module to happen.
		 * Popping other modules is allowed.
		 */
		struct stdata	*stp;
		char modname[FMNAMESZ + 1] = " ";

		rw_enter(&iwscn_lock, RW_READER);
		wd = srilookup(getminor(dev));
		(void) strioctl(wd->wd_list->wl_vp, I_LOOK, (intptr_t)modname,
		    flag, K_TO_K, cred, rvalp);
		if (strcmp("redirmod", modname) == 0) {
			if ((f = getf((int)arg)) == NULL) {
				err = EBADF;
				break;
			}
			if ((stp = f->f_vnode->v_stream) == NULL) {
				err = ENOSTR;
				releasef((int)arg);
				break;
			}
			if (!(stp->sd_flag & STRCLOSE)) {
				releasef((int)arg);
				rw_exit(&iwscn_lock);
				cmn_err(CE_WARN, "Popping of redirection "
				    "module not allowed");
				return (EINVAL);
			}

			releasef((int)arg);
		}

		/* Process ioctl normally */
		err = strioctl(wd->wd_list->wl_vp, cmd, arg, flag, U_TO_K,
		    cred, rvalp);
		break;
	}

	default:
		rw_enter(&iwscn_lock, RW_READER);
		wd = srilookup(getminor(dev));
		err = strioctl(wd->wd_list->wl_vp, cmd, arg, flag, U_TO_K,
			cred, rvalp);
		break;
	}

	rw_exit(&iwscn_lock);
	return (err);
}

static int
iwscnpoll(
	dev_t			dev,
	short			events,
	int			anyyet,
	short			*reventsp,
	struct pollhead		**phpp)
{
	wcd_data_t	*wd;
	int	error;

	rw_enter(&iwscn_lock, RW_READER);
	wd = srilookup(getminor(dev));
	error = strpoll(wd->wd_list->wl_vp->v_stream, events, anyyet,
		    reventsp, phpp);
	rw_exit(&iwscn_lock);
	return (error);
}


/*
 * Auxiliary routines.
 */

/*
 * Additional public interfaces.
 */

/*
 * Reset the current workstation console designee to the device denoted by the
 * wl_vp field of the first entry in the redirection list.  Called from
 * iwscnopen and from the SRIOCSREDIR case of iwscnioctl, in both cases after
 * the target vp has been set to its new value.
 */
static int
srreset(wcd_data_t *wd, int flag, cred_t *cred)
{
	wcrlist_t	*wlp;
	int		err = 0;

	ASSERT(RW_WRITE_HELD(&iwscn_lock) || MUTEX_HELD(&iwscn_open_lock));
	wlp = wd->wd_list;		/* first entry */

	/*
	 * If we're reverting back to the workstation console, make sure it's
	 * open.
	 */
	if (wlp != NULL && wlp->wl_vp == wd->wd_vp) {
		vnode_t	*vp = wd->wd_vp;	/* underlying device's vp */

		err = VOP_OPEN(&vp, flag, cred);
		/*
		 * The underlying driver is not allowed to have cloned itself
		 * for this open.
		 */
		if (vp != wd->wd_vp) {
			panic("srreset: Illegal clone");
			/*NOTREACHED*/
		}
		if (!err)
			wd->wd_wsconsopen++;
	}
	return (err);
}

/*
 * Remove vp from the redirection list rooted at *rwlp, should it be there.
 * If zap is nonzero, deallocate the entry and remove dangling references to
 * the it from the corresponding redirecting module instance's wcm_data
 * structure.
 *
 * If the entry doesn't exist upon completion, return NULL; otherwise return a
 * pointer to it.
 */
static wcrlist_t *
srrm(wcrlist_t **rwlp, vnode_t *vp, int zap)
{
	wcrlist_t	**delwlp;
	wcrlist_t	*wlp;
	wcm_data_t	*mdp;

	ASSERT(RW_WRITE_HELD(&iwscn_lock) || MUTEX_HELD(&iwscn_open_lock));
	for (delwlp = rwlp; (wlp = *delwlp) != NULL; delwlp = &wlp->wl_next)
		if (wlp->wl_vp == vp)
			break;
	if (wlp == NULL)
		return (NULL);
	*delwlp = wlp->wl_next;

	if (zap == 0)
		return (wlp);

	if (wlp->wl_vp == vp)
		VN_RELE(vp);
	/*
	 * Make sure there are no dangling references leading to the entry
	 * from the corresponding redirecting module instance.
	 */
	if ((mdp = wlp->wl_data) != NULL) {
		mdp->wm_wd = NULL;
		mdp->wm_entry = NULL;
	}

	kmem_free(wlp, sizeof (*wlp));
	return (NULL);
}

/*
 * srpop - remove redirection because the target stream is being closed.
 * Called from wcmclose().
 */
void
srpop(wcm_data_t *mdp, int flag, cred_t *cred)
{
	wcd_data_t	*ddp;

	rw_enter(&iwscn_lock, RW_WRITER);
	if ((ddp = mdp->wm_wd) != NULL) {
		ASSERT(mdp->wm_entry != NULL);
		(void) srrm(&ddp->wd_list, mdp->wm_entry->wl_vp, 1);
		(void) srreset(ddp, flag, cred);
	}
	rw_exit(&iwscn_lock);
}

/*
 * Routines for allocating, deallocating, and finding wcd_data structures.
 *
 * For a given instantiation of the driver, its open instance structures are
 * linked together into a list, on the assumption that there will never be
 * enough open instances to make search efficiency a serious concern.
 */

/*
 * Look up the instance structure denoted by unit.
 */
static wcd_data_t *
srilookup(minor_t unit)
{
	wcd_data_t	*wd = wcddata;

	ASSERT(RW_LOCK_HELD(&iwscn_lock));
	for (; wd != NULL && wd->wd_unit != unit; wd = wd->wd_next)
		continue;

	return (wd);
}

/*
 * Allocate a wcd_data structure for the instance denoted by unit, link it in
 * place, and return a pointer to it.  If it's already allocated, simply
 * return a pointer to it.
 */
static wcd_data_t *
srialloc(minor_t unit)
{
	wcd_data_t	*wdp;
	wcd_data_t	**wdpp;

	ASSERT(MUTEX_HELD(&iwscn_open_lock));
	for (wdpp = &wcddata; (wdp = *wdpp) != NULL; wdpp = &wdp->wd_next) {
		if (unit < wdp->wd_unit)
			break;
		if (unit == wdp->wd_unit) {
			/* Already allocated and in place. */
			return (wdp);
		}
	}
	/*
	 * wdpp now points to the proper insertion point for unit's
	 * per-instance structure.
	 */
	wdp = kmem_zalloc(sizeof (*wdp), KM_SLEEP);
	wdp->wd_unit = unit;
	wdp->wd_next = *wdpp;
	*wdpp = wdp;

	return (wdp);
}

/*
 * Deallocate the wcd_data structure denoted by wd and unlink it from the
 * list of open instances.
 */
static void
sridealloc(wcd_data_t *wd)
{
	wcd_data_t	*wdp;
	wcd_data_t	**wdpp;

	ASSERT(RW_WRITE_HELD(&iwscn_lock) || MUTEX_HELD(&iwscn_open_lock));
	for (wdpp = &wcddata; (wdp = *wdpp) != NULL; wdpp = &wdp->wd_next)
		if (wd == wdp)
			break;
	if (wdp == NULL) {
		/*
		 * Not there.  This should probably be a panic.
		 */
		return;
	}
	*wdpp = wdp->wd_next;
	kmem_free(wdp, sizeof (*wdp));
}


/*
 * Push vp onto the redirection list rooted at *wlpp.  If it's already there,
 * move it to the front position.  Return a pointer to its list entry.
 *
 * N.B.: It is the caller's responsibility to initialize all fields in the
 * entry other than the wl_next and wl_vp fields.
 */
static wcrlist_t *
srpush(wcrlist_t **wlpp, vnode_t *vp)
{
	wcrlist_t	*nwlp;

	ASSERT(RW_WRITE_HELD(&iwscn_lock) || MUTEX_HELD(&iwscn_open_lock));
	if ((nwlp = srrm(wlpp, vp, 0)) == NULL) {
		nwlp = kmem_zalloc(sizeof (*nwlp), KM_SLEEP);
		nwlp->wl_vp = vp;
		/*
		 * The hold will prevent underlying device from closing
		 * while this vnode is still on the redirection list.
		 */
		VN_HOLD(vp);
	}
	nwlp->wl_next = *wlpp;
	*wlpp = nwlp;

	return (nwlp);
}

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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * vol: the volume management driver
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/poll.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/cpu.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/fdio.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/fdio.h>
#include <sys/vol.h>
#include <sys/session.h>
#include <sys/systm.h>
#include <sys/debug.h>

/*
 * NOTE:
 *
 * there was originally code in this module that would attempt to
 * enqueue IO requests in a local queue if the reason for an IO
 * failure was because the requested media was not present.  there
 * was a kernel thread that would run automatically when the requested
 * media was inserted and would attempt to restart the queued IO's once
 * the media was present.  the code that enqueued the IO's had been
 * ifdef'ed out for some time (since around version 1.27) due to some
 * problems experienced with the sparc floppy driver.  finally, the
 * rest of the code, including the kernel thread itself was removed,
 * because it wasn't really being used and was wasting resources.  the
 * code was removed as of version 1.67.  if you're interested in seeing
 * it, please retrieve that version.
 */

/* names */
#define	VOLLONGNAME	"Volume Management Driver, %I%"
#define	VOLNBUFPROP	"nbuf"			/* number of bufs property */


static char	*vold_root = NULL;		/* location of vol root */
static size_t	vold_root_len = 0;
#define	VOL_ROOT_DEFAULT	"/vol"		/* default vold_root */
#define	VOL_ROOT_DEFAULT_LEN	(strlen(VOL_ROOT_DEFAULT)) /* it's length */


/*
 * debug stuff
 */

#ifndef	VOLDEBUG
#define	VOLDEBUG	0
#endif

int		voldebug = VOLDEBUG;

#define	DPRINTF		if (voldebug > 0) printf
#define	DPRINTF2	if (voldebug > 1) printf
#define	DPRINTF3	if (voldebug > 2) printf
#define	DPRINTF4	if (voldebug > 3) printf


/*
 * keep kvioc_queue and kvioc_event in sync.  It is important that
 * kve_next and kve_prev are in the same order and relative position
 * in the respective structures.
 */
struct kvioc_queue {
	struct kvioc_event *kve_next;
	struct kvioc_event *kve_prev;
};

struct kvioc_event {
	struct kvioc_event *kve_next;
	struct kvioc_event *kve_prev;
	struct vioc_event   kve_event;
};

/*
 * Data required to interface ioctls between vold.
 */
struct vol_ioctl {
	kmutex_t	mutex;
	kcondvar_t	cv;		/* cond to wait for ioctl resp */
	kcondvar_t	s_cv;		/* cond to serialize the ioctl */
	kcondvar_t	close_cv;	/* cond to wait for unref */
	uintptr_t	argp;		/* value passed to vold ioctl */
	uintptr_t	rptr;		/* return pointer from vold */
	int		rval;		/* return value from vold */
	int		nwait;		/* # of threads waiting */
	char		active;		/* set while waiting for a resp */
	char		closing;	/* set while closing unit 0 */
	char		closewait;	/* set while waiting for shutdown */
};

/*
 * private device info -- controlling device "volctl"
 */
static struct volctl {
	dev_info_t	*ctl_dip;	/* dev info */
	struct buf	*ctl_bhead;	/* bufs to use for strategy */
	uint_t		ctl_evcnt;	/* count of events on queue */
	uint_t		ctl_maxunit;	/* largest unit # we've seen */
	uint_t		ctl_open;	/* control port open flag */
	int		ctl_daemon_pid;	/* pid of daemon at work */
	struct kvioc_queue ctl_events;	/* queue of events for vold */
	struct kvioc_event *ctl_evend;	/* pointer to end of queue */
	ksema_t		ctl_bsema;	/* semaphore for vol_bhead */
	kmutex_t	ctl_bmutex;	/* mutex for vol_bhead */
	kmutex_t	ctl_muxmutex;	/* mutex for voltab */
	kmutex_t	ctl_evmutex;	/* mutex for events */
	kmutex_t	ctl_volrmutex;	/* mutex for vold_root */
	struct vol_ioctl ctl_insert;
	struct vol_ioctl ctl_inuse;
	struct vol_ioctl ctl_symname;
	struct vol_ioctl ctl_symdev;
	uint_t		ctl_closing;	/* device being closed */
} volctl;

static struct pollhead vol_pollhead;

/*
 * private device info, per active minor node.
 */
struct vol_tab {
	dev_t		vol_dev;	/* stacked device */
	struct dev_ops	*vol_devops;	/* stacked dev_ops */
	uint_t		vol_bocnt; 	/* open count, block  */
	uint_t		vol_cocnt; 	/* open count, character  */
	uint_t		vol_locnt;	/* open count, layered */
	uint_t		vol_flags;	/* miscellaneous flags */
	int		vol_cancel;	/* cancel flag */
	int		vol_unit;	/* minor number of this struct */
	int		vol_mtype;	/* type of media (for checking) */
	uint64_t	vol_id;		/* id of the volume */
	char		*vol_path;	/* path of mapped device */
	size_t		vol_pathlen;	/* length of above path */
	kcondvar_t	vol_incv;	/* insertion condvar */
	struct vol_ioctl vol_eject;
	struct vol_ioctl vol_attr;
	kmutex_t	vol_rwlck_mutex; /* mutex for rw lock */
	kcondvar_t	vol_rwlck_cv;	/* cv for reader/writer lock */
	uint_t		vol_nreader;	/* number of readers */
	uint_t		vol_lckwaiter;	/* number of lock waiter */
	uint_t		vol_refcnt;	/* number of references */
	kcondvar_t	vol_rele_cv;	/* cv waiting for release */
	char		vol_relewait;	/* release waiting flag */
	char		vol_locked;	/* lock flag 1:READ 2:WRITE locked */
};

#define	VOL_TAB_UNLOCKED	0
#define	VOL_TAB_RD_LOCKED	1
#define	VOL_TAB_WR_LOCKED	2

static void  *voltab;		/* dynamic voltab */

/* vol_flags */
#define	ST_OPEN		0x0001		/* device is open */
#define	ST_EXCL		0x0002		/* device is open exclusively */
#define	ST_ENXIO	0x0004		/* return enxio till close */
#define	ST_CHKMEDIA	0x0008		/* device should be checked b4 i/o */
#define	ST_RDONLY	0x0010		/* volume is read-only */

/* vol_mtype */
#define	MT_FLOPPY	0x0001		/* floppy that supports FDGETCHANGE */

/* flags to the vol_gettab function */
#define	VGT_NOWAIT	0x01
#define	VGT_WAITSIG	0x02
#define	VGT_NEW		0x04
#define	VGT_OPEN	0x08
#define	VGT_CLOSE	0x10
#define	VGT_NDELAY	0x20

/* local functions */
static void 		vol_enqueue(enum vie_event type, void *data);
static int		vol_done(struct buf *bp);
static void		vol_cleanup(void);
static void		vol_unmap(struct vol_tab *);
static void		vol_checkwrite(struct vol_tab *tp,
				struct uio *uiop, int unit);
#ifdef _SYSCALL32_IMPL
static int		vol_event32(struct vioc_event32 *e32p,
				struct vioc_event *e);
#endif
static struct vol_tab 	*vol_gettab(int unit,
				uint_t flags, int *error);
static int		vol_checkmedia(struct vol_tab *tp, int *found_media);
static int		vol_checkmedia_machdep(struct vol_tab *tp);

static void		vol_release_driver(struct vol_tab *tp);
static int		vol_daemon_check(void);

static void		vol_ioctl_init(struct vol_ioctl *vic);
static void		vol_ioctl_fini(struct vol_ioctl *vic);
static int		vol_ioctl_enter(struct vol_ioctl *vic);
static int		vol_ioctl_wait(struct vol_ioctl *vic,
				int *rvalp, void *);
static void		vol_ioctl_exit(struct vol_ioctl *vic);
static void		vol_ioctl_fail(struct vol_ioctl *vic);
static void		vol_ioctl_enable(struct vol_ioctl *vic);
static int		vold_ioctl_enter(struct vol_ioctl *vic, void *rptrp);
static void		vold_ioctl_respond(struct vol_ioctl *vic,
				int rval, void *rptr);
static void		vold_ioctl_exit(struct vol_ioctl *vic);

static void		vol_tab_init(struct vol_tab *tp);
static void		vol_tab_fini(struct vol_tab *tp);
static void		vol_tab_rlock(struct vol_tab *tp);
static int		vol_tab_rlock_sig(struct vol_tab *tp);
static void		vol_tab_rwlock_upgrade(struct vol_tab *tp);
static int		vol_tab_rwlock_upgrade_sig(struct vol_tab *tp);
static void		vol_tab_unlock(struct vol_tab *tp);
static void		vol_tab_rele(struct vol_tab *tp);
static void		vol_tab_unlock_and_rele(struct vol_tab *tp);
static void		vol_tab_rele_wait(struct vol_tab *tp);

/* defaults */
#define	DEFAULT_NBUF	20	/* default number of bufs to allocate */
#define	DEFAULT_MAXUNIT	100	/* default number of minor units to alloc */

/* devsw ops */
static int	volopen(dev_t *devp, int flag, int otyp, cred_t *credp);
static int	volclose(dev_t dev, int flag, int otyp, cred_t *credp);
static int	volstrategy(struct buf *bp);
static int	volread(dev_t dev, struct uio *uiop, cred_t *credp);
static int	volwrite(dev_t dev, struct uio *uiop, cred_t *credp);
static int	volprop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
			int flags, char *name, caddr_t valuep, int *lengthp);
static int	volioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);
static int	volpoll(dev_t dev, short events, int anyyet,
			short *reventsp, struct pollhead **phpp);

static struct cb_ops	vol_cb_ops = {
	volopen,		/* open */
	volclose,		/* close */
	volstrategy,		/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	volread,		/* read */
	volwrite,		/* write */
	volioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	volpoll,		/* poll */
	volprop_op,		/* prop_op */
	(struct streamtab *)0,	/* streamtab */
	D_NEW | D_MP | D_64BIT,	/* flags */
};

static int	volattach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	voldetach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	volinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
			void **result);

static struct dev_ops	vol_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	volinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	volattach,		/* attach */
	voldetach,		/* detach */
	nulldev,		/* reset */
	&vol_cb_ops,		/* cb_ops */
	(struct bus_ops *)0,	/* bus_ops */
};

extern struct mod_ops	mod_pseudodrvops;
extern struct mod_ops	mod_driverops;

extern int	ddi_create_internal_pathname(dev_info_t *dip, char *name,
		    int spec_type, minor_t minor_num);

static struct modldrv	vol_driver_info = {
	&mod_driverops,		/* modops */
	VOLLONGNAME,		/* name */
	&vol_ops,		/* dev_ops */
};

static struct modlinkage vol_linkage = {
	MODREV_1,			/* rev */
	{				/* linkage */
		&vol_driver_info,
		NULL,
		NULL,
		NULL,
	},
};

static kmutex_t	floppy_chk_mutex;

/*
 * Virtual driver loader entry points
 */

int
_init(void)
{
	int ret;

	DPRINTF("vol: _init\n");

	/*
	 * The ddi_soft_state code automatically grows the array
	 * when more is asked for.  DEFAULT_MAXUNIT is
	 * just a reasonable lower bound.
	 */
	ret = ddi_soft_state_init(&voltab, sizeof (struct vol_tab),
	    DEFAULT_MAXUNIT);
	if (ret != 0) {
		cmn_err(CE_CONT, "vol: _init, could not init soft state");
		return (-1);
	}

	ret = mod_install(&vol_linkage);
	if (ret != 0)
		ddi_soft_state_fini(&voltab);

	return (ret);
}


int
_fini(void)
{
	int ret;

	DPRINTF("vol: _fini\n");
	ret = mod_remove(&vol_linkage);
	if (ret != 0)
		return (ret);

	ddi_soft_state_fini(&voltab);
	return (0);
}


int
_info(struct modinfo *modinfop)
{
	DPRINTF("vol: _info: modinfop %p\n", (void *)modinfop);
	return (mod_info(&vol_linkage, modinfop));
}


/*
 * Driver administration entry points
 */
static int
volattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct vol_tab	*tp;
	int		unit;
	int		length;
	int		nbuf;
	int		i;
	int		err = DDI_SUCCESS;

	DPRINTF("vol: attach: %d: dip %p cmd 0x%x\n",
	    ddi_get_instance(dip), (void *)dip, (int)cmd);

	unit = ddi_get_instance(dip);

	/* check unit */
	if (unit != 0)
		return (ENXIO);

	/* check command */
	if (cmd != DDI_ATTACH) {
		cmn_err(CE_CONT, "vol: attach: %d: unknown cmd %d\n",
		    unit, cmd);
		return (DDI_FAILURE);
	}

	if (volctl.ctl_dip != NULL) {
		cmn_err(CE_CONT,
		    "vol: attach: %d: already attached\n", unit);
		return (DDI_FAILURE);
	}

	/* clear device entry, initialize locks, and save dev info */
	bzero(&volctl, sizeof (volctl));
	volctl.ctl_dip = dip;

	/* get number of buffers, must use DDI_DEV_T_ANY */
	length = sizeof (nbuf);
	if ((err = ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    0, VOLNBUFPROP, (caddr_t)&nbuf, &length)) != DDI_SUCCESS) {
		DPRINTF("vol: couldn't get nbuf prop, using default %d\n",
		    DEFAULT_NBUF);
		nbuf = DEFAULT_NBUF;
		err = 0;	/* no biggie */
	}

	DPRINTF2("vol: attach: %d: nbuf %d\n", ddi_get_instance(dip), nbuf);

	sema_init(&volctl.ctl_bsema, 0, NULL, SEMA_DRIVER, NULL);

	/* allocate buffers to stack with */
	volctl.ctl_bhead = NULL;
	for (i = 0; (i < nbuf); ++i) {
		struct buf	*bp;

		if ((bp = getrbuf(KM_NOSLEEP)) == NULL) {
			cmn_err(CE_CONT,
			    "vol: attach: %d: could not allocate buf\n", unit);
			err = ENOMEM;
			goto out;
		}
		bp->b_chain = volctl.ctl_bhead;
		volctl.ctl_bhead = bp;
		sema_v(&volctl.ctl_bsema);
	}

	/* create minor node for /dev/volctl */
	if ((err = ddi_create_minor_node(dip, VOLCTLNAME, S_IFCHR,
	    0, DDI_PSEUDO, 0)) != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "vol: attach: %d: ddi_create_minor_node '%s' failed\n",
		    unit, VOLCTLNAME);
		goto out;
	}

	/*
	 * build our 'tp' for unit 0.  makes things look better below
	 */
	(void) ddi_soft_state_zalloc(voltab, 0);
	if ((tp = (struct vol_tab *)ddi_get_soft_state(voltab, 0)) == NULL) {
		cmn_err(CE_CONT, "vol: attach, could not get soft state");
		err = DDI_FAILURE;
		goto out;
	}

	/* build the mapping */
	tp->vol_dev = NODEV;
	tp->vol_devops = NULL;

	/* initialize my linked list */
	volctl.ctl_events.kve_next =
	    (struct kvioc_event *)&volctl.ctl_events;
	volctl.ctl_evcnt = 0;
	volctl.ctl_evend = NULL;

out:
	/* cleanup or return success */
	if (err != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		while (volctl.ctl_bhead != NULL) {
			struct buf	*bp;

			bp = volctl.ctl_bhead;
			volctl.ctl_bhead = bp->b_chain;
			freerbuf(bp);
		}
		sema_destroy(&volctl.ctl_bsema);
		bzero(&volctl, sizeof (volctl));
		return (err);
	}

	mutex_init(&volctl.ctl_bmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&volctl.ctl_muxmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&volctl.ctl_evmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&volctl.ctl_volrmutex, NULL, MUTEX_DRIVER, NULL);
	vol_ioctl_init(&volctl.ctl_insert);
	vol_ioctl_init(&volctl.ctl_inuse);
	vol_ioctl_init(&volctl.ctl_symname);
	vol_ioctl_init(&volctl.ctl_symdev);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}


static int
voldetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		unit;
	int		stat;

	DPRINTF("vol: detach: %d: dip %p cmd %d\n", ddi_get_instance(dip),
	    (void *)dip, (int)cmd);

	/* get and check unit */
	if ((unit = ddi_get_instance(dip)) != 0)
		return (ENXIO);

	switch (cmd) {
		/* cleanup and detach */
	case DDI_DETACH:
		/*
		 * if the daemon has us open, say no without looking
		 * any further.
		 */
		if (volctl.ctl_open != 0)
			return (DDI_FAILURE);
		/*
		 * Free various data structures that have been allocated
		 * behind our back.
		 */
		ddi_soft_state_free(voltab, 0);

		/*
		 * Return our bufs to the world.
		 */
		while (volctl.ctl_bhead != NULL) {
			struct buf	*bp;

			bp = volctl.ctl_bhead;
			volctl.ctl_bhead = bp->b_chain;
			freerbuf(bp);
		}

		/*
		 * Get rid of our various locks.
		 */
		sema_destroy(&volctl.ctl_bsema);
		mutex_destroy(&volctl.ctl_bmutex);
		mutex_destroy(&volctl.ctl_muxmutex);
		mutex_destroy(&volctl.ctl_evmutex);
		mutex_destroy(&volctl.ctl_volrmutex);
		vol_ioctl_fini(&volctl.ctl_insert);
		vol_ioctl_fini(&volctl.ctl_inuse);
		vol_ioctl_fini(&volctl.ctl_symname);
		vol_ioctl_fini(&volctl.ctl_symdev);

		/*
		 * A nice fresh volctl, for the next attach.
		 */
		bzero(&volctl, sizeof (volctl));

		stat = DDI_SUCCESS;
		break;

	default:
		cmn_err(CE_CONT, "vol: detach: %d: unknown cmd %d\n",
		    unit, cmd);
		stat = DDI_FAILURE;
		break;
	}
	return (stat);
}


/* ARGSUSED */
static int
volinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t		dev = (dev_t)arg;
	int		unit = getminor(dev);
	int		err = DDI_FAILURE;

	DPRINTF("vol: info: dip %p cmd %d arg %p (%u.%u) result %p\n",
	    (void *)dip, (int)cmd, arg, getmajor(dev), unit, (void *)result);

	/* process command */
	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;		/* only instance zero */
		err = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2DEVINFO:
		if (volctl.ctl_dip) {
			*result = (void *)volctl.ctl_dip;
			err = DDI_SUCCESS;
		}
		break;

	default:
		cmn_err(CE_CONT, "vol: info: %d: unknown cmd %d\n",
		    unit, cmd);
		break;
	}

	return (err);
}


/*
 * Common entry points
 */

/* ARGSUSED3 */
static int
volopen(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int		unit;
	struct vol_tab	*tp;
	int		err = 0;
	uint_t		gflags;

	DPRINTF("vol: open: devp %p (%u.%u) flag %x otyp %x credp %p\n",
	    (void *)devp, (int)getmajor(*devp), (int)getminor(*devp),
	    flag, otyp, (void *)credp);

	unit = getminor(*devp);
	gflags = VGT_NEW | VGT_WAITSIG;

	/* implement non-blocking open */
	if (flag & FNDELAY)
		gflags |= VGT_NDELAY;

	if (unit == 0) {
		if (otyp != OTYP_CHR)
			return (EINVAL);
		gflags |= VGT_OPEN;
	}

	/* get our vol structure for this unit */
	if ((tp = vol_gettab(unit, gflags, &err)) == NULL) {
		DPRINTF("vol: open: gettab on unit %d, err %d\n", unit, err);
		if (err == EAGAIN)
			err = EIO;		/* convert to usable errno */
		return (err);
	}

	/*
	 * wrlock upgrade creates a race where other threads can
	 * modify flags while unlocking the rlock.
	 * We need write lock before testing all the flags.
	 */
	if (vol_tab_rwlock_upgrade_sig(tp)) {
		/* we've lost the lock */
		vol_tab_rele(tp);
		return (EINTR);
	}

	/* check for opening read-only with write flag set */
	if ((flag & FWRITE) && (tp->vol_flags & ST_RDONLY)) {
		vol_tab_unlock_and_rele(tp);
		return (EROFS);
	}

	/* implement exclusive use */
	if (((flag & FEXCL) && (tp->vol_flags & ST_OPEN)) ||
	    (tp->vol_flags & ST_EXCL)) {
		vol_tab_unlock_and_rele(tp);
		return (EBUSY);
	}

	if (unit == 0 && (tp->vol_flags & ST_OPEN) == 0)
		volctl.ctl_open = 1;

	if (flag & FEXCL)
		tp->vol_flags |= ST_EXCL;

	/* count and flag open */
	if (otyp == OTYP_BLK) {
		tp->vol_bocnt = 1;	/* user block device open */
	} else if (otyp == OTYP_CHR) {
		tp->vol_cocnt = 1;	/* user character device */
	} else {
		tp->vol_locnt++;	/* kernel open */
	}

	tp->vol_flags |= ST_OPEN;

	/* release lock, and return */
	vol_tab_unlock_and_rele(tp);
	return (0);
}


/* ARGSUSED3 */
static int
volclose(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		unit;
	struct vol_tab	*tp;
	int		err;

	DPRINTF("vol: close: dev %u.%u flag %x otyp %x credp %p\n",
	    (int)getmajor(dev), (int)getminor(dev), flag, otyp, (void *)credp);

	unit = getminor(dev);

	if ((tp = vol_gettab(unit, VGT_NOWAIT, &err)) == NULL) {
		/* unit 0 has already been closed */
		return (0);
	}

	vol_tab_rwlock_upgrade(tp);

	if (otyp == OTYP_BLK) {
		tp->vol_bocnt = 0;	/* block opens */
	} else if (otyp == OTYP_CHR) {
		tp->vol_cocnt = 0;	/* character opens */
	} else {
		tp->vol_locnt--;	/* kernel opens */
	}

	if ((tp->vol_bocnt == 0) && (tp->vol_cocnt == 0) &&
	    (tp->vol_locnt == 0)) {
		tp->vol_flags &= ~(ST_OPEN|ST_EXCL);
		/*
		 * ST_ENXIO should be cleared on the last close.
		 * Otherwise, there is no way to reset the flags
		 * other than killing the vold.
		 */
		tp->vol_flags &= ~ST_ENXIO;
	}

	/*
	 * If we've closed the device clean up after ourselves
	 */
	if (((tp->vol_flags & ST_OPEN) == 0) && (unit != 0)) {
#ifdef	NOT_NEEDED
		/*
		 * unmapping here means that every close unmaps so every open
		 * will have to remap
		 */
		(void) mutex_enter(&volctl.ctl_muxmutex);
		vol_unmap(tp);
		/* "tp" is invalid after vol_unmap!!! */
		(void) mutex_exit(&volctl.ctl_muxmutex);
#endif
		vol_enqueue(VIE_CLOSE, (void *)&unit);
	}

	if (unit == 0) {
		/* vold is no longer responding */
		volctl.ctl_daemon_pid = 0;

		/* closing unit 0 by vold. clean up all vol_tabs */
		vol_cleanup();

		/*
		 * we've grabbed write lock for vol_tab unit#0, so no race
		 * between open to drop the ctl_open.
		 */
		volctl.ctl_open = 0;
	}

	/* release lock */
	vol_tab_unlock_and_rele(tp);

	/* done */
	return (0);
}


static int
volstrategy(struct buf *bp)
{
	int		unit;
	struct vol_tab	*tp;
	struct buf	*mybp;
	int		err = 0;

	DPRINTF2("vol: strategy: bp %p dev %u.%u off %lu len %ld\n",
	    (void *)bp, getmajor(bp->b_edev), getminor(bp->b_edev),
	    (unsigned long)dbtob(bp->b_blkno), bp->b_bcount);

	unit = getminor(bp->b_edev);
	if (unit == 0) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	if ((tp = vol_gettab(unit, VGT_WAITSIG, &err)) == NULL) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, err);
		biodone(bp);
		DPRINTF("vol: strategy: gettab error %d\n", err);
		return (0);
	}

	if ((tp->vol_flags & ST_OPEN) == 0) {
		/* it's not even open */
		bp->b_resid = bp->b_bcount;
		bioerror(bp, ENXIO);
		vol_tab_unlock_and_rele(tp);
		biodone(bp);
		DPRINTF("vol: strategy: device not even open (ENXIO)\n");
		return (0);
	}

	/* allocate new buffer */
	sema_p(&volctl.ctl_bsema);
	mutex_enter(&volctl.ctl_bmutex);

	if (volctl.ctl_bhead == NULL) {
		panic("vol: strategy: bhead == NULL");
		/*NOTREACHED*/
	}

	mybp = volctl.ctl_bhead;
	volctl.ctl_bhead = mybp->b_chain;
	mutex_exit(&volctl.ctl_bmutex);

	/* setup buffer */
	ASSERT(tp->vol_dev != NODEV);
	*mybp = *bp;		/* structure copy */
	mybp->b_forw = mybp->b_back = mybp;
	mybp->av_forw = mybp->av_back = NULL;
	mybp->b_dev = cmpdev(tp->vol_dev);
	mybp->b_iodone = vol_done;
	mybp->b_edev = tp->vol_dev;
	mybp->b_chain = bp;	/* squirrel away old buf for vol_done */
	sema_init(&mybp->b_io, 0, NULL, SEMA_DRIVER, NULL);
	sema_init(&mybp->b_sem, 0, NULL, SEMA_DRIVER, NULL);

	if (tp->vol_flags & ST_CHKMEDIA) {
		err = vol_checkmedia(tp, NULL);
		if (err) {
			if (err == EINTR)
				vol_tab_rele(tp);
			else
				vol_tab_unlock_and_rele(tp);

			/* free buffer */
			mutex_enter(&volctl.ctl_bmutex);
			mybp->b_chain = volctl.ctl_bhead;
			volctl.ctl_bhead = mybp;
			mutex_exit(&volctl.ctl_bmutex);

			/* release semaphore */
			sema_v(&volctl.ctl_bsema);

			bp->b_resid = bp->b_bcount;
			bioerror(bp, err);
			biodone(bp);
			DPRINTF("vol: strategy: precheck failed, error %d\n",
			    err);
			return (0);
		}
	}

	/* release lock, pass request on to stacked driver */
	vol_tab_unlock_and_rele(tp);

	/* pass request on to stacked driver */
	return (bdev_strategy(mybp));
}


static int
vol_done(struct buf *mybp)
{
	struct buf		*bp = mybp->b_chain;

	DPRINTF2("vol: done: mybp %p bp %p dev %u.%u off %lu len %ld\n",
	    (void *)mybp, (void *)bp, getmajor(bp->b_edev),
	    getminor(bp->b_edev), (unsigned long)dbtob(bp->b_blkno),
	    bp->b_bcount);

	/*
	 * See NOTE comment at beginning of this module about code that
	 * used to queue failed IO requests.
	 */
	if (mybp->b_error) {
		DPRINTF("vol: error %d from device (should retry)\n",
		    mybp->b_error);
	}

	/* copy status */
	bp->b_flags = mybp->b_flags;
	bp->b_un = mybp->b_un;
	bp->b_resid = mybp->b_resid;
	bp->b_error = mybp->b_error;

	/* free buffer */
	mutex_enter(&volctl.ctl_bmutex);
	mybp->b_chain = volctl.ctl_bhead;
	volctl.ctl_bhead = mybp;
	mutex_exit(&volctl.ctl_bmutex);

	/* release semaphore */
	sema_v(&volctl.ctl_bsema);

	/* continue on with biodone() */
	biodone(bp);
	return (0);
}


/* ARGSUSED */
static int
volread(dev_t dev, struct uio *uiop, cred_t *credp)
{
	struct vol_tab	*tp;
	int		unit;
	int		err = 0;
	int		err1;
	int		found_media;

	DPRINTF2("vol: read: dev %u.%u uiop %p credp %p\n",
	    getmajor(dev), getminor(dev), (void *)uiop,
	    (void *)credp);

	unit = getminor(dev);
	if (unit == 0) {
		return (ENXIO);
	}

	if ((tp = vol_gettab(unit, VGT_WAITSIG, &err)) == NULL) {
		DPRINTF("vol: read: gettab on unit %d, err %d\n", unit, err);
		if (err == EAGAIN) {
			err = EIO;		/* convert to usable errno */
		}
		return (err);
	}

	if ((tp->vol_flags & ST_OPEN) == 0) {
		err = ENXIO;
		goto out;
	}

	if (tp->vol_flags & ST_CHKMEDIA) {
		err = vol_checkmedia(tp, NULL);
		if (err) {
			if (err == EINTR) {
				vol_tab_rele(tp);
				return (EINTR);
			}
			goto out;
		}
	}

	for (;;) {
		/* read data */
		if (tp->vol_dev == NODEV) {
			DPRINTF("vol: read: no device\n");
			err = ENXIO;
			goto out;
		}

		err = cdev_read(tp->vol_dev, uiop, kcred);

		if (err && tp->vol_flags & ST_CHKMEDIA) {
			err1 = vol_checkmedia(tp, &found_media);
			if (err1 == EINTR) {
				vol_tab_rele(tp);
				return (EINTR);
			}
			/*
			 * if we got an error and media was actually
			 * in the drive, just return the error.
			 */
			if (found_media) {
				break;
			}

			/*
			 * probably a cancel on the i/o.
			 */
			if (err1) {
				err = err1;
				break;
			}
		} else {
			break;
		}
	}

	/* release lock, return success */
out:
	vol_tab_unlock_and_rele(tp);
	return (err);
}


/* ARGSUSED */
static int
volwrite(dev_t dev, struct uio *uiop, cred_t *credp)
{
	struct vol_tab	*tp;
	int		unit;
	int		err = 0;
	int		err1;
	int		found_media;

	DPRINTF2("vol: write: dev %u.%u uiop %p credp %p\n",
	    getmajor(dev), getminor(dev), (void *)uiop,
	    (void *)credp);

	unit = getminor(dev);
	if (unit == 0) {
		return (ENXIO);
	}

	if ((tp = vol_gettab(unit, VGT_WAITSIG, &err)) == NULL) {
		DPRINTF("vol: write: gettab on unit %d, err %d\n", unit, err);
		if (err == EAGAIN) {
			err = EIO;		/* convert to usable errno */
		}
		return (err);
	}

	if ((tp->vol_flags & ST_OPEN) == 0) {
		err = ENXIO;
		goto out;
	}

	vol_checkwrite(tp, uiop, unit);

	if (tp->vol_flags & ST_CHKMEDIA) {
		err = vol_checkmedia(tp, NULL);
		if (err) {
			if (err == EINTR) {
				vol_tab_rele(tp);
				return (EINTR);
			}
			goto out;
		}
	}

	for (;;) {
		/* write data */
		if (tp->vol_dev == NODEV) {
			DPRINTF("vol: write: no device");
			err = ENXIO;
			goto out;
		}

		err = cdev_write(tp->vol_dev, uiop, kcred);

		if (err && tp->vol_flags & ST_CHKMEDIA) {
			err1 = vol_checkmedia(tp, &found_media);
			if (err1 == EINTR) {
				vol_tab_rele(tp);
				return (EINTR);
			}
			/*
			 * if we got an error and media was actually
			 * in the drive, just return the error.
			 */
			if (found_media) {
				break;
			}

			/*
			 * probably a cancel on the i/o.
			 */
			if (err1) {
				err = err1;
				break;
			}
		} else {
			break;
		}
	}

	/* release lock, return err */
out:
	vol_tab_unlock_and_rele(tp);
	return (err);
}


/*
 * Check the write to see if we are writing over the label
 * on this unit.  If we are, let the daemon know.
 */
static void
vol_checkwrite(struct vol_tab *tp, struct uio *uiop, int unit)
{
	/*
	 * XXX: this is VERY incomplete.
	 * This only works with a full label write of the Sun label.
	 */
	if (uiop->uio_loffset == 0) {
		vol_enqueue(VIE_NEWLABEL, (void *)&unit);
		/*
		 * We now need to invalidate the blocks that
		 * are cached for both the device we point at.
		 * Odds are good that the label was written
		 * through the raw device, and we don't want to
		 * read stale stuff.
		 */
		binval(tp->vol_dev);		/* XXX: not DDI compliant */
	}
}


static int
volprop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		unit;
	struct vol_tab	*tp;
	dev_info_t	*stackdip;
	int		err = 0;

	DPRINTF2("vol: prop_op: dev %u.%u dip %p prop_op %d flags %x\n",
	    getmajor(dev), getminor(dev), (void *)dip, (int)prop_op,
	    flags);
	DPRINTF2("     name '%s' valuep %p lengthp %p\n",
	    name, (void *)valuep, (void *)lengthp);

	/* send our props on to ddi_prop_op */
	if (strcmp(name, "instance") == 0 ||
	    strcmp(name, VOLNBUFPROP) == 0) {
		err = ddi_prop_op(dev, dip, prop_op, flags,
		    name, valuep, lengthp);
		return (err);
	}

	unit = getminor(dev);
	if (unit == 0) {
		return (DDI_PROP_NOT_FOUND);
	}

	if ((tp = vol_gettab(unit, VGT_NOWAIT, &err)) == NULL) {
		DPRINTF("vol: prop_op: gettab on unit %d, err %d\n", unit,
		    err);
		return (DDI_PROP_NOT_FOUND);
	}

	if (err) {
		err = DDI_PROP_NOT_FOUND;
		goto out;
	}

	/* get stacked dev info */
	ASSERT(tp->vol_devops != NULL);
	if ((err = (*(tp->vol_devops->devo_getinfo))(NULL,
	    DDI_INFO_DEVT2DEVINFO, (void *)tp->vol_dev, (void *)&stackdip))
	    != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "vol: prop_op: %d: could not get child dev info err %d\n",
		    unit, err);
		err = DDI_PROP_NOT_FOUND;
		goto out;
	}

	/* pass request on to stacked driver */
	err = cdev_prop_op(tp->vol_dev, stackdip, prop_op, flags,
	    name, valuep, lengthp);

	if (err) {
		DPRINTF("vol: cdev_prop_op: err = %d\n", err);
	}

	/* release lock, return err */
out:
	vol_tab_unlock_and_rele(tp);
	return (err);
}


/* ARGSUSED */
static int
volioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp)
{
	int		unit, tunit;
	struct vol_tab	*tp;
	int		err = 0;
	dev_t		udev;

	DPRINTF("volioctl: dev=%u.%u cmd=%x arg=%lx mode=%x\n",
	    getmajor(dev), getminor(dev), cmd, arg, mode);

	unit = getminor(dev);
	if (unit == 0) {
		/* commands from vold */
		switch (cmd) {

		/*
		 * The daemon will call this if it's using the driver.
		 */
		case VOLIOCDAEMON: {
			pid_t pid = (pid_t)arg;

			if (drv_priv(credp) != 0) {
				err = EPERM;
				break;
			}
			mutex_enter(&volctl.ctl_muxmutex);
			if (volctl.ctl_daemon_pid == 0) {
				volctl.ctl_daemon_pid = pid;
			} else {
				if (vol_daemon_check() == 0) {
					/* i'm vold who can change pid */
					volctl.ctl_daemon_pid = pid;
				} else {
					/* already a daemon running! */
					err = EBUSY;
				}
			}
			mutex_exit(&volctl.ctl_muxmutex);
#ifdef VOL_CLEANUP_BY_DAEMON
			if (volctl.ctl_daemon_pid == 0) {
				/* no daemon. clean up */
				vol_cleanup();
			}
#endif
			break;
		}

		/*
		 * Establish a mapping between a unit (minor number)
		 * and a lower level driver (dev_t).
		 */
		case VOLIOCMAP: {
			STRUCT_DECL(vioc_map, vim);
			struct dev_ops *devp;
			char	*path;
			uint_t	pathlen;

			if ((err = vol_daemon_check()) != 0)
				break;

			STRUCT_INIT(vim, mode & FMODELS);
			if (ddi_copyin((void *)arg, STRUCT_BUF(vim),
			    STRUCT_SIZE(vim), mode) != 0) {
				DPRINTF("vol: map:copyin broke\n");
				err = EFAULT;
				break;
			}
			/* don't allow mapping for unit 0 */
			if ((tunit = STRUCT_FGET(vim, vim_unit)) == 0) {
				err = EINVAL;
				break;
			}
			/* pathname cannot be longer than MAXPATHLEN */
			pathlen = STRUCT_FGET(vim, vim_pathlen);
			if (pathlen >= MAXPATHLEN) {
				err = ENAMETOOLONG;
				break;
			}
			path = NULL;
			if (pathlen != 0) {
				path = kmem_alloc(pathlen + 1, KM_SLEEP);
				if (ddi_copyin(STRUCT_FGETP(vim, vim_path),
				    path, pathlen, mode)) {
					kmem_free(path, pathlen + 1);
					err = EFAULT;
					break;
				}
				path[pathlen] = '\0';
			}

			/* copyins complete, get vol_tab */
			tp = vol_gettab(tunit, VGT_NOWAIT|VGT_NEW, &err);
			if (tp == NULL) {
				DPRINTF("vol: map:null on vol %u, err %d\n",
				    (uint_t)tunit, err);
				if (path != NULL)
					kmem_free(path, pathlen + 1);
				break;
			}
			err = 0;

			if ((mode & FMODELS) == FNATIVE)
				udev = STRUCT_FGET(vim, vim_dev);
			else
				udev = expldev(STRUCT_FGET(vim, vim_dev));

			/* ready to grab the driver */
			if (udev != NODEV) {
				devp = ddi_hold_driver(getmajor(udev));
				if (devp == NULL) {
					DPRINTF("vol: map:hold_inst broke\n");
					vol_tab_unlock_and_rele(tp);
					if (path != NULL)
						kmem_free(path, pathlen + 1);
					err = ENODEV;
					break;
				}
				DPRINTF3("vol: ioctl: holding driver %u\n",
				    getmajor(udev));
			}

			/* changing vol_tab, needs wlock(no interrupt) */
			vol_tab_rwlock_upgrade(tp);

			/* release old driver if it's been held */
			vol_release_driver(tp);

			tp->vol_path = path;
			tp->vol_pathlen = pathlen;
			tp->vol_id = STRUCT_FGET(vim, vim_id);

			if (STRUCT_FGET(vim, vim_flags) & VIM_FLOPPY) {
				tp->vol_flags |= ST_CHKMEDIA;
				tp->vol_mtype = MT_FLOPPY;
			} else {
				/* clear data (in case of previous use) */
				tp->vol_flags &= ~ST_CHKMEDIA;
				tp->vol_mtype = 0;
			}
			/* is this a read-only volume? */
			if (STRUCT_FGET(vim, vim_flags) & VIM_RDONLY) {
				tp->vol_flags |= ST_RDONLY;
			}

			mutex_enter(&volctl.ctl_muxmutex);
			/*
			 * if vim.vim_dev == NODEV, it means that the daemon
			 * is unblocking a "nodelay" request.
			 */
			if (udev != NODEV) {
				/* build the mapping */
				tp->vol_dev = udev;
				tp->vol_devops = devp;
				/* clear any pending cancel */
				tp->vol_cancel = FALSE;
			}
			cv_broadcast(&tp->vol_incv);
			vol_tab_unlock(tp);
			mutex_exit(&volctl.ctl_muxmutex);
			vol_tab_rele(tp);
			break;
		}

		/*
		 * Break a mapping established with the above
		 * map ioctl.
		 */
		case VOLIOCUNMAP: {
			if ((err = vol_daemon_check()) != 0)
				break;
			if (ddi_copyin((caddr_t)arg, &tunit,
			    sizeof (tunit), mode) != 0) {
				DPRINTF("vol: unmap:copyin broke\n");
				err = EFAULT;
				break;
			}
			if (tunit == 0) {
				err = EINVAL;
				break;
			}
			if ((tp = vol_gettab(tunit, VGT_NOWAIT, &err)) == NULL)
				break;
			vol_tab_rwlock_upgrade(tp);
			vol_release_driver(tp);
			vol_tab_unlock_and_rele(tp);
			break;
		}

		/*
		 * Get an event.  This is used by calling this
		 * ioctl until it returns EWOULDBLOCK.  poll(2)
		 * is the mechanism for waiting around for an
		 * event to happen.
		 */
		case VOLIOCEVENT: {
			struct kvioc_event *kve = NULL;

			if ((err = vol_daemon_check()) != 0)
				break;
			mutex_enter(&volctl.ctl_evmutex);
			if (volctl.ctl_evcnt) {
				kve = volctl.ctl_events.kve_next;
				volctl.ctl_evcnt--;
				if (volctl.ctl_evcnt == 0)
					volctl.ctl_evend = NULL;
				remque(kve);
			}
			mutex_exit(&volctl.ctl_evmutex);
			if (kve == NULL) {
				err = EWOULDBLOCK;
				break;
			}
			if ((mode & FMODELS) == FNATIVE) {
				if (ddi_copyout(&kve->kve_event, (caddr_t)arg,
				    sizeof (kve->kve_event), mode) != 0) {
					err = EFAULT;
				}
			}
#ifdef _SYSCALL32_IMPL
			else {
				struct vioc_event32 e32;

				err = vol_event32(&e32, &kve->kve_event);
				if (err == 0) {
					if (ddi_copyout(&e32, (caddr_t)arg,
					    sizeof (e32), mode) != 0) {
						err = EFAULT;
					}
				}
			}
#endif /* _SYSCALL32_IMPL */
			if (err != 0 && err != EOVERFLOW) {
				/* add it back on err */
				mutex_enter(&volctl.ctl_evmutex);
				insque(kve, &volctl.ctl_events);
				volctl.ctl_evcnt++;
				mutex_exit(&volctl.ctl_evmutex);
				DPRINTF("vol: event: copyout %d\n", err);
				break;
			}
			kmem_free(kve, sizeof (*kve));
			break;
		}


		/*
		 * Deliver status (eject or don't eject) to a pending
		 * eject ioctl.  That ioctl will then send down the
		 * eject to the device (or not).
		 */
		case VOLIOCEJECT: {
			STRUCT_DECL(vioc_eject, viej);
			enum eject_state status;

			if ((err = vol_daemon_check()) != 0)
				break;
			STRUCT_INIT(viej, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(viej),
			    STRUCT_SIZE(viej), mode) != 0) {
				DPRINTF("VOLIOCEJECT: copyin error\n");
				err = EFAULT;
				break;
			}
			if ((tunit = STRUCT_FGET(viej, viej_unit)) == 0) {
				err = EINVAL;
				break;
			}
			tp = vol_gettab(tunit, VGT_NOWAIT, &err);
			if (tp == NULL) {
				DPRINTF("VOLIOCEJECT: gettab error\n");
				break;
			}
			status = STRUCT_FGET(viej, viej_state);
			if (status != VEJ_YES &&
			    status != VEJ_NO &&
			    status != VEJ_YESSTOP) {
				vol_tab_unlock_and_rele(tp);
				err = EINVAL;
				break;
			}
			if ((err = vold_ioctl_enter(&tp->vol_eject,
			    NULL)) != 0) {
				vol_tab_unlock_and_rele(tp);
				break;
			}
			vold_ioctl_respond(&tp->vol_eject, status, NULL);
			vold_ioctl_exit(&tp->vol_eject);
			vol_tab_unlock_and_rele(tp);
			break;
		}

		/* Daemon response to setattr from user */
		case VOLIOCDSATTR: {
			STRUCT_DECL(vioc_dattr, vda);
			int	attr_err;
			struct ve_attr *attr_ptr;

			if ((err = vol_daemon_check()) != 0)
				break;
			STRUCT_INIT(vda, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vda),
			    STRUCT_SIZE(vda), mode) != 0) {
				err = EFAULT;
				break;
			}
			if ((tunit = STRUCT_FGET(vda, vda_unit)) == 0) {
				err = EINVAL;
				break;
			}
			if ((attr_err = STRUCT_FGET(vda, vda_errno)) < 0) {
				err = EINVAL;
				break;
			}
			tp = vol_gettab(tunit, VGT_NOWAIT, &err);
			if (tp == NULL)
				break;
			if ((err = vold_ioctl_enter(&tp->vol_attr,
			    &attr_ptr)) != 0) {
				vol_tab_unlock_and_rele(tp);
				break;
			}
			if (attr_ptr == NULL || attr_ptr->viea_unit != tunit) {
				/* shouldn't happen, but just in case */
				err = EAGAIN;
			} else {
				vold_ioctl_respond(&tp->vol_attr,
				    attr_err, attr_ptr);
			}
			vold_ioctl_exit(&tp->vol_attr);
			vol_tab_unlock_and_rele(tp);
			break;
		}
		/* Daemon response to getattr from user */
		case VOLIOCDGATTR: {
			STRUCT_DECL(vioc_dattr, vda);
			int	attr_err;
			struct	ve_attr *attr_ptr = NULL;

			if ((err = vol_daemon_check()) != 0)
				break;
			STRUCT_INIT(vda, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vda),
			    STRUCT_SIZE(vda), mode) != 0) {
				err = EFAULT;
				break;
			}
			if ((tunit = STRUCT_FGET(vda, vda_unit)) == 0) {
				err = EINVAL;
				break;
			}
			if ((attr_err = STRUCT_FGET(vda, vda_errno)) < 0) {
				err = EINVAL;
				break;
			}
			tp = vol_gettab(tunit, VGT_NOWAIT, &err);
			if (tp == NULL)
				break;
			if ((err = vold_ioctl_enter(&tp->vol_attr,
			    &attr_ptr)) != 0) {
				vol_tab_unlock_and_rele(tp);
				break;
			}
			if (attr_err == 0 && attr_ptr != NULL) {
				char	*vstr;
				int	len;

				vstr = STRUCT_FGETP(vda, vda_value);
				/* put end mark so that strlen never overrun */
				vstr[MAX_ATTR_LEN -1] = '\0';
				len = strlen(vstr);
				bcopy(vstr, attr_ptr->viea_value, len);
				attr_ptr->viea_value[len] = '\0';
			}
			vold_ioctl_respond(&tp->vol_attr, attr_err, attr_ptr);
			vold_ioctl_exit(&tp->vol_attr);
			vol_tab_unlock_and_rele(tp);
			break;
		}

		/* Daemon response to insert from user */
		case VOLIOCDCHECK:
			if ((err = vol_daemon_check()) != 0)
				break;
			if ((int)arg < 0) {
				err = EINVAL;
				break;
			}
			if ((err = vold_ioctl_enter(&volctl.ctl_insert,
			    NULL)) != 0)
				break;
			vold_ioctl_respond(&volctl.ctl_insert, (int)arg, NULL);
			vold_ioctl_exit(&volctl.ctl_insert);
			break;

		/* Daemon response to inuse from user */
		case VOLIOCDINUSE:
			if ((err = vol_daemon_check()) != 0)
				break;
			if ((int)arg < 0) {
				err = EINVAL;
				break;
			}
			if ((err = vold_ioctl_enter(&volctl.ctl_inuse,
			    NULL)) != 0)
				break;
			vold_ioctl_respond(&volctl.ctl_inuse, (int)arg, NULL);
			vold_ioctl_exit(&volctl.ctl_inuse);
			break;

		/* Daemon response to inuse from user */
		case VOLIOCFLAGS: {
			STRUCT_DECL(vioc_flags, vfl);

			if ((err = vol_daemon_check()) != 0)
				break;
			STRUCT_INIT(vfl, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vfl),
			    STRUCT_SIZE(vfl), mode) != 0) {
				err = EFAULT;
				break;
			}
			if ((tunit = STRUCT_FGET(vfl, vfl_unit)) == 0) {
				err = EINVAL;
				break;
			}
			tp = vol_gettab(tunit, VGT_NOWAIT, &err);
			if (tp == NULL)
				break;
			/* if we had an ENXIO error, then that's okay */
			if (err == ENXIO || err == ENODEV) {
				DPRINTF(
				"volioctl: clearing gettab ENXIO or ENODEV\n");
				err = 0;
			}

			/*
			 * vol_gettab() returns the vol_tab struct pointed
			 * to by tp locked in reader mode -- but, to
			 * change something in that struct, we need to
			 * lock it in writer mode
			 */
			vol_tab_rwlock_upgrade(tp);

			/* set or clear the ST_ENXIO flag */
			if (STRUCT_FGET(vfl, vfl_flags) & VFL_ENXIO) {
				tp->vol_flags |= ST_ENXIO;
#ifdef	DEBUG_ENXIO
				(void) printf(
	"volioctl: VOLIOCFLAGS(ST_ENXIO), unit %d (flags=0x%x, tp=%p)\n",
				    tunit, tp->vol_flags, (void *)tp);
#endif
			} else {
				tp->vol_flags &= ~ST_ENXIO;
#ifdef	DEBUG_ENXIO
				(void) printf(
	"volioctl: VOLIOCFLAGS(0), unit %d (flags=0x%x, tp=%p)\n",
				    tunit, tp->vol_flags, (void *)tp);
#endif
			}
			DPRINTF(
			    "vol: volioctl: %s ST_ENXIO flag for unit %u\n",
			    (STRUCT_FGET(vfl, vfl_flags) & VFL_ENXIO) ?
			    "set" : "cleared", tunit);

			vol_tab_unlock_and_rele(tp);
			break;
		}

		/* daemon response to symname request from user */
		case VOLIOCDSYMNAME: {
			STRUCT_DECL(vol_str, vstr);
			char	*symname;
			size_t	symname_len;

			if ((err = vol_daemon_check()) != 0)
				break;
			/* get the string struct */
			STRUCT_INIT(vstr, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vstr),
			    STRUCT_SIZE(vstr), mode) != 0) {
				err = EFAULT;
				break;
			}
			symname_len = STRUCT_FGET(vstr, data_len);
			if (symname_len > VOL_SYMNAME_LEN) {
				err = EINVAL;
				break;
			}
			/* if any string to get then get it */
			if (symname_len != 0) {
				/* allocate some memory for string */
				symname = kmem_alloc(symname_len + 1, KM_SLEEP);
				/* grab the string */
				if (ddi_copyin(STRUCT_FGETP(vstr, data),
				    symname, symname_len, mode) != 0) {
					kmem_free(symname, symname_len + 1);
					err = EFAULT;
					break;
				}
				symname[symname_len] = '\0';
			} else {
				symname = NULL;
			}
			if ((err = vold_ioctl_enter(&volctl.ctl_symname,
			    NULL)) != 0) {
				if (symname != NULL)
					kmem_free(symname, symname_len + 1);
				break;
			}
			/* signal waiter that we have the info */
			vold_ioctl_respond(&volctl.ctl_symname,
			    symname_len, symname);
			vold_ioctl_exit(&volctl.ctl_symname);
			break;
		}

		/* daemon response to symdev request from user */
		case VOLIOCDSYMDEV: {
			STRUCT_DECL(vol_str, vstr);
			char	*symdev;
			size_t	symdev_len;

			if ((err = vol_daemon_check()) != 0)
				break;
			/* get the string */
			STRUCT_INIT(vstr, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vstr),
			    STRUCT_SIZE(vstr), mode) != 0) {
				err = EFAULT;
				break;
			}
			symdev_len = STRUCT_FGET(vstr, data_len);
			if (symdev_len >= VOL_SYMDEV_LEN) {
				err = EINVAL;
				break;
			}
			if (symdev_len != 0) {
				/* get memory for string */
				symdev = kmem_alloc(symdev_len + 1, KM_SLEEP);
				/* now get the dev string */
				if (ddi_copyin(STRUCT_FGETP(vstr, data),
				    symdev, symdev_len, mode) != 0) {
					kmem_free(symdev, symdev_len + 1);
					err = EFAULT;
					break;
				}
				symdev[symdev_len] = '\0';
			} else {
				symdev = NULL;
			}
			/* lock data struct */
			if ((err = vold_ioctl_enter(&volctl.ctl_symdev,
			    NULL)) != 0) {
				if (symdev != NULL)
					kmem_free(symdev, symdev_len + 1);
				break;
			}
			/* signal waiter that we have the info */
			vold_ioctl_respond(&volctl.ctl_symdev,
			    symdev_len, symdev);
			vold_ioctl_exit(&volctl.ctl_symdev);
			break;
		}

		/*
		 * Begin: ioctls that joe random program can issue to
		 * the volctl device.
		 */

		/*
		 * Tell volume daemon to check for new media and wait
		 * for it to tell us if anything was there.
		 */
		case VOLIOCCHECK: {
			dev_t	dev;
			int	rval;
			/*
			 * If there's no daemon, we already know the answer.
			 */
			if (volctl.ctl_daemon_pid == 0) {
				err = ENXIO;
				break;
			}
			if ((err = vol_ioctl_enter(&volctl.ctl_insert)) != 0)
				break;
			if ((mode & FMODELS) == FNATIVE)
				dev = (dev_t)arg;
			else
				dev = expldev((dev32_t)arg);
			vol_enqueue(VIE_CHECK, (void *)&dev);
			err = vol_ioctl_wait(&volctl.ctl_insert, &rval, NULL);
			if (err == 0)
				err = rval;
			vol_ioctl_exit(&volctl.ctl_insert);
			break;
		}

		/*
		 * ask the volume daemon if it is running (dev_t ==
		 * this dev_t), or if it's controlling a particular
		 * device (any dev_t).
		 */
		case VOLIOCINUSE: {
			dev_t	dev;
			int	rval;
			/*
			 * If there's no daemon, we already know the answer.
			 */
			if (volctl.ctl_daemon_pid == 0) {
				err = ENXIO;
				break;
			}
			if ((err = vol_ioctl_enter(&volctl.ctl_inuse)) != 0)
				break;
			if ((mode & FMODELS) == FNATIVE)
				dev = (dev_t)arg;
			else
				dev = expldev((dev32_t)arg);
			vol_enqueue(VIE_INUSE, (void *)&dev);
			err = vol_ioctl_wait(&volctl.ctl_inuse, &rval, NULL);
			if (err == 0)
				err = rval;
			vol_ioctl_exit(&volctl.ctl_inuse);
			break;
		}

		/* Cancel initiated from the daemon */
		case VOLIOCCANCEL: {
			if ((err = vol_daemon_check()) != 0)
				break;
			if (ddi_copyin((caddr_t)arg, &tunit,
			    sizeof (tunit), mode) != 0) {
				DPRINTF("vol: cancel:copyin broke\n");
				err = EFAULT;
				break;
			}
			if (tunit == 0) {
				err = EINVAL;
				break;
			}
			tp = vol_gettab(tunit, VGT_NOWAIT, &err);
			if (tp == NULL)
				break;
			if (err == ENXIO || err == ENODEV)
				err = 0;
			/*
			 * need wrlock as we are changing vol_cancel.
			 */
			vol_tab_rwlock_upgrade(tp);
			mutex_enter(&volctl.ctl_muxmutex);
			DPRINTF("vol: doing cancel on %u\n", tunit);
			tp->vol_cancel = TRUE;
			cv_broadcast(&tp->vol_incv);
			vol_tab_unlock(tp);
			mutex_exit(&volctl.ctl_muxmutex);
			vol_tab_rele(tp);
			break;
		}

		/* set the volmgt root dir (defaults to "/vol") */
		case VOLIOCDROOT: {
			STRUCT_DECL(vol_str, vstr);
			char	*rptr;
			size_t	rlen;

			if ((err = vol_daemon_check()) != 0)
				break;

			mutex_enter(&volctl.ctl_volrmutex);
			/* can't set if already set */
			if (vold_root != NULL) {
				/* error */
				mutex_exit(&volctl.ctl_volrmutex);
				err = EAGAIN;
				break;
			}
			mutex_exit(&volctl.ctl_volrmutex);

			STRUCT_INIT(vstr, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vstr),
			    STRUCT_SIZE(vstr), mode) != 0) {
				err = EFAULT;
				break;
			}
			rlen = STRUCT_FGET(vstr, data_len);
			if (rlen == 0 || rlen >= MAXPATHLEN) {
				err = EINVAL;
				break;
			}
			rptr = kmem_alloc(rlen + 1, KM_SLEEP);
			if (ddi_copyin(STRUCT_FGETP(vstr, data),
			    rptr, rlen, mode) != 0) {
				kmem_free(rptr, rlen + 1);
				err = EFAULT;
				break;
			}
			rptr[rlen] = '\0';

			mutex_enter(&volctl.ctl_volrmutex);
			if (vold_root != NULL) {
				/* someone has set the root */
				kmem_free(rptr, rlen + 1);
				err = EAGAIN;
			} else {
				vold_root = rptr;
				vold_root_len = rlen;
			}
			mutex_exit(&volctl.ctl_volrmutex);
			break;
		}

		/* return where the vol root is */
		case VOLIOCROOT: {
			STRUCT_DECL(vol_str, vd);
			char	path[64], *rptr;

			mutex_enter(&volctl.ctl_volrmutex);
			/* if no root set then punt */
			if (vold_root == NULL) {
				/* allocate a default vol root */
				vold_root = kmem_alloc(VOL_ROOT_DEFAULT_LEN + 1,
				    KM_SLEEP);
				vold_root_len = VOL_ROOT_DEFAULT_LEN;
				(void) strcpy(vold_root, VOL_ROOT_DEFAULT);
			}
			if (vold_root_len >= sizeof (path))
				rptr = kmem_alloc(vold_root_len + 1, KM_SLEEP);
			else
				rptr = path;
			(void) bcopy(vold_root, rptr, vold_root_len + 1);
			mutex_exit(&volctl.ctl_volrmutex);

			/*
			 * copy in struct to know buf size at target
			 * for vold_root
			 */
			STRUCT_INIT(vd, get_udatamodel());
			if (ddi_copyin((caddr_t)arg, STRUCT_BUF(vd),
			    STRUCT_SIZE(vd), mode) != 0) {
				err = EFAULT;
				goto rootout;
			}
			/* check if our str len is out of range */
			if ((vold_root_len + 1) > STRUCT_FGET(vd, data_len)) {
				err = EINVAL;
				goto rootout;
			}
			/* all is ok, send back the vold_root */
			if (ddi_copyout(rptr, STRUCT_FGETP(vd, data),
			    vold_root_len + 1, mode) != 0) {
				err = EFAULT;
			}
rootout:
			if (rptr != path)
				kmem_free(rptr, vold_root_len + 1);
			break;
		}

		/* find a symname given a dev */
		case VOLIOCSYMNAME: {
			STRUCT_DECL(vioc_symname, sn);
			dev_t	dev;
			char	*symname = NULL;
			int	symname_len = 0;

			/* if there's no daemon then we can't check */
			if (volctl.ctl_daemon_pid == 0) {
				err = ENXIO;
				break;
			}
			/* get the struct */
			STRUCT_INIT(sn, get_udatamodel());
			if (ddi_copyin((void *)arg, STRUCT_BUF(sn),
			    STRUCT_SIZE(sn), mode)) {
				err = EFAULT;
				break;
			}
			/* lock out others */
			if ((err = vol_ioctl_enter(&volctl.ctl_symname)) != 0)
				break;
			/* tell the daemon that we want a symname */
			if ((mode & FMODELS) == FNATIVE)
				dev = STRUCT_FGET(sn, sn_dev);
			else
				dev = expldev(STRUCT_FGET(sn, sn_dev));
			vol_enqueue(VIE_SYMNAME, (void *)&dev);
			err = vol_ioctl_wait(&volctl.ctl_symname,
			    &symname_len, &symname);

			/* return result (if not interrupted) */
			if (err == 0) {
				/* is there enough room for the result ? */
				if (symname_len >=
				    STRUCT_FGET(sn, sn_pathlen)) {
					DPRINTF(
				"volctl: no room for symname result\n");
					err = EINVAL;
				} else if (symname_len == 0 ||
				    symname == NULL) {
					DPRINTF(
					"volctl: no symname to copy out\n");
					err = ENOENT;
				} else {
					if (ddi_copyout(symname,
					    STRUCT_FGETP(sn, sn_symname),
					    symname_len + 1, mode) != 0) {
						err = EFAULT;
					}
				}
			}
			/*
			 * vol_ioctl_wait() may have failed, but vold
			 * may have allocated symname.
			 */
			if (symname_len != 0 && symname != NULL)
				kmem_free(symname, symname_len + 1);
			/* release lock */
			vol_ioctl_exit(&volctl.ctl_symname);
			break;
		}

		/* find a dev path given a symname */
		case VOLIOCSYMDEV: {
			STRUCT_DECL(vioc_symdev, sd);
			struct ve_symdev	vesd;
			char	*symdev = NULL;
			int	symdev_len = 0;
			size_t	symname_len;

			/* if there's no daemon then we can't check */
			if (volctl.ctl_daemon_pid == 0) {
				err = ENXIO;
				break;
			}
			/* get the struct */
			STRUCT_INIT(sd, get_udatamodel());
			if (ddi_copyin((void *)arg, STRUCT_BUF(sd),
			    STRUCT_SIZE(sd), mode)) {
				err = EFAULT;
				break;
			}
			/* see if user is providing a length too long */
			symname_len = STRUCT_FGET(sd, sd_symnamelen);
			if (symname_len == 0 || symname_len > VOL_SYMNAME_LEN) {
				err = EINVAL;
				break;
			}

			/* don't copyout garbage */
			bzero(&vesd, sizeof (vesd));

			/* get the symname */
			if (ddi_copyin(STRUCT_FGETP(sd, sd_symname),
			    vesd.vied_symname, symname_len, mode) != 0) {
				err = EFAULT;
				break;
			}
			vesd.vied_symname[symname_len] = '\0';

			/* lock out others */
			if ((err = vol_ioctl_enter(&volctl.ctl_symdev)) != 0)
				break;

			/* tell the daemon that we want a symdev */
			vol_enqueue(VIE_SYMDEV, (void *)&vesd);

			/* wait for daemon to reply */
			err = vol_ioctl_wait(&volctl.ctl_symdev,
			    &symdev_len, &symdev);

			/* return result (if not interrupted) */
			if (err == 0) {
				/* is there enough room for the result ? */
				if (symdev_len >= STRUCT_FGET(sd, sd_pathlen)) {
					DPRINTF(
				"volctl: no room for symdev result\n");
					err = EINVAL;
				} else if (symdev_len == 0 ||
				    symdev == NULL) {
					DPRINTF(
					    "volctl: no symdev to copy out\n");
					err = ENOENT;
				} else {
					if (ddi_copyout(symdev,
					    STRUCT_FGETP(sd, sd_symdevname),
					    symdev_len + 1, mode) != 0) {
						err = EFAULT;
					}
				}
			}
			/* free room */
			if (symdev_len != 0 && symdev != NULL)
				kmem_free(symdev, symdev_len + 1);
			/* release lock */
			vol_ioctl_exit(&volctl.ctl_symdev);
			break;
		}

		/*
		 * Create minor name for unit
		 */
		case VOLIOCCMINOR: {
			char	mname_chr[16];
			char	mname_blk[16];

			if ((err = vol_daemon_check()) != 0)
				break;

			if ((tunit = (minor_t)arg) == 0) {
				err = EINVAL;
				break;
			}
			ASSERT(volctl.ctl_dip);
			(void) snprintf(mname_blk, sizeof (mname_blk),
			    VOLUNITNAME_BLK, (int)tunit);
			(void) snprintf(mname_chr, sizeof (mname_chr),
			    VOLUNITNAME_CHR, tunit);

			if (ddi_create_internal_pathname(volctl.ctl_dip,
			    mname_blk, S_IFBLK, tunit) != DDI_SUCCESS)
				err = ENODEV;
			else if (ddi_create_internal_pathname(volctl.ctl_dip,
			    mname_chr, S_IFCHR, tunit) != DDI_SUCCESS) {
				err = ENODEV;
				ddi_remove_minor_node(volctl.ctl_dip,
				    mname_blk);
			}
			break;
		}

		/*
		 * Remove minor name for unit
		 */
		case VOLIOCRMINOR: {
			char	mname[16];

			if ((err = vol_daemon_check()) != 0)
				break;

			if ((tunit = (minor_t)arg) == 0) {
				err = EINVAL;
				break;
			}
			ASSERT(volctl.ctl_dip);
			(void) snprintf(mname, sizeof (mname),
			    VOLUNITNAME_BLK, (int)tunit);
			ddi_remove_minor_node(volctl.ctl_dip, mname);

			(void) snprintf(mname, sizeof (mname),
			    VOLUNITNAME_CHR, (int)tunit);
			ddi_remove_minor_node(volctl.ctl_dip, mname);
			break;
		}

		default:
			err = ENOTTY;
			break;
		}

		if ((err != 0) && (err != EWOULDBLOCK)) {
			DPRINTF("vol: ioctl: err=%d (cmd=%x)\n", err, cmd);
		}

		return (err);
		/*NOTREACHED*/
	}

	/*
	 * This set of ioctls are available to be executed without
	 * having the unit available. vol_gettab() can be interrupted
	 * by signal.
	 */
	tp = vol_gettab(unit, VGT_NDELAY|VGT_NOWAIT|VGT_WAITSIG, &err);
	if (tp == NULL)
		return (err);
	err = 0;

	switch (cmd) {
	case VOLIOCINFO: {
		/*
		 * Gather information about the unit.  This is specific to
		 * volume management.
		 *
		 * XXX: we should just return an error if the amount of space
		 * the user has allocated for our return value is too small,
		 * but instead we just truncate and return ... ??
		 */
		STRUCT_DECL(vioc_info, info);

		STRUCT_INIT(info, get_udatamodel());
		if (ddi_copyin((caddr_t)arg, STRUCT_BUF(info),
		    STRUCT_SIZE(info), mode) != 0) {
			vol_tab_unlock_and_rele(tp);
			return (EFAULT);
		}
		STRUCT_FSET(info, vii_inuse, tp->vol_bocnt + tp->vol_cocnt +
		    tp->vol_locnt);
		STRUCT_FSET(info, vii_id, tp->vol_id);

		if (ddi_copyout(STRUCT_BUF(info), (caddr_t)arg,
		    STRUCT_SIZE(info), mode) != 0) {
			err = EFAULT;
		}
		if (err == 0 &&
		    STRUCT_FGETP(info, vii_devpath) != NULL &&
		    STRUCT_FGET(info, vii_pathlen) != 0 &&
		    tp->vol_path != NULL) {
			if (ddi_copyout(tp->vol_path, STRUCT_FGETP(info,
			    vii_devpath), min(STRUCT_FGET(info, vii_pathlen),
			    tp->vol_pathlen) + 1, mode) != 0) {
				err = EFAULT;
			}
		}
		vol_tab_unlock_and_rele(tp);
		return (err);
	}

	/*
	 * Cancel i/o pending (i.e. waiting in vol_gettab) on
	 * a device.  Cancel will persist until the last close.
	 */
	case VOLIOCCANCEL:
		if (vol_tab_rwlock_upgrade_sig(tp)) {
			vol_tab_rele(tp);
			err = EINTR;
			break;
		}
		mutex_enter(&volctl.ctl_muxmutex);
		DPRINTF("vol: doing cancel on %d\n", unit);
		tp->vol_cancel = TRUE;
		cv_broadcast(&tp->vol_incv);
		vol_tab_unlock(tp);
		mutex_exit(&volctl.ctl_muxmutex);
		vol_tab_rele(tp);
		vol_enqueue(VIE_CANCEL, (void *)&unit);
		return (0);

	case VOLIOCSATTR: {
		STRUCT_DECL(vioc_sattr, sa);
		int	attr_err;
		size_t	len;
		struct ve_attr vea, *attr_ptr;

		if (volctl.ctl_daemon_pid == 0) {
			err = ENXIO;
			goto sattr_err;
		}
		STRUCT_INIT(sa, get_udatamodel());
		if (ddi_copyin((caddr_t)arg, STRUCT_BUF(sa), STRUCT_SIZE(sa),
		    mode) != 0) {
			err = EFAULT;
			goto sattr_err;
		}

		/* zero out, otherwise, copyout kernel stack */
		bzero(&vea, sizeof (vea));

		len = STRUCT_FGET(sa, sa_attr_len);
		if (len > MAX_ATTR_LEN) {
			err = EINVAL;
			goto sattr_err;
		}
		if (ddi_copyin(STRUCT_FGETP(sa, sa_attr),
		    vea.viea_attr, len, mode) != 0) {
			err = EFAULT;
			goto sattr_err;
		}
		vea.viea_attr[len] = '\0';

		len = STRUCT_FGET(sa, sa_value_len);
		if (len > MAX_ATTR_LEN) {
			err = EINVAL;
			goto sattr_err;
		}
		if (ddi_copyin(STRUCT_FGETP(sa, sa_value),
		    vea.viea_value, len, mode) != 0) {
			err = EFAULT;
			goto sattr_err;
		}
		vea.viea_value[len] = '\0';

		vea.viea_unit = unit;

		/*
		 * We need to release lock. Otherwise we fall into
		 * deadlock if VOLIOCMAP/UNMAP was acquiring WRITE lock.
		 * We are safe here; still tp is hold by refcnt, and
		 * also vol_attr is not used until we call vol_ioctl_exit().
		 */
		vol_tab_unlock(tp);

		if ((err = vol_ioctl_enter(&tp->vol_attr)) != 0) {
			vol_tab_rele(tp);
			return (err);
		}
		vol_enqueue(VIE_SETATTR, &vea);
		attr_ptr = &vea;
		err = vol_ioctl_wait(&tp->vol_attr, &attr_err, &attr_ptr);
		if (err == 0) {
			err = attr_err;
			/* check response */
			if (attr_ptr != &vea)
				err = EINVAL;
		}
		vol_ioctl_exit(&tp->vol_attr);
		vol_tab_rele(tp);
		return (err);
sattr_err:
		vol_tab_unlock_and_rele(tp);
		return (err);
	}

	case VOLIOCGATTR: {
		STRUCT_DECL(vioc_gattr, ga);
		int	attr_err;
		size_t	len;
		struct ve_attr vea, *attr_ptr;

		if (volctl.ctl_daemon_pid == 0) {
			err = ENXIO;
			goto gattr_dun;
		}
		STRUCT_INIT(ga, get_udatamodel());
		if (ddi_copyin((caddr_t)arg, STRUCT_BUF(ga), STRUCT_SIZE(ga),
		    mode) != 0) {
			err = EFAULT;
			goto gattr_dun;
		}

		bzero(&vea, sizeof (vea));

		len = STRUCT_FGET(ga, ga_attr_len);
		if (len > MAX_ATTR_LEN) {
			err = EINVAL;
			goto gattr_dun;
		}
		if (ddi_copyin(STRUCT_FGETP(ga, ga_attr),
		    vea.viea_attr, len, mode) != 0) {
			err = EFAULT;
			goto gattr_dun;
		}
		vea.viea_attr[len] = '\0';

		vea.viea_unit = unit;

		/*
		 * do unlock, othewise deadlock.
		 */
		vol_tab_unlock(tp);

		if ((err = vol_ioctl_enter(&tp->vol_attr)) != 0) {
			vol_tab_rele(tp);
			return (err);
		}
		vol_enqueue(VIE_GETATTR, &vea);
		attr_ptr = &vea;
		err = vol_ioctl_wait(&tp->vol_attr, &attr_err, &attr_ptr);
		if (err == 0) {
			err = attr_err;
			if (attr_ptr != &vea)
				err = EINVAL;
		}
		vol_ioctl_exit(&tp->vol_attr);
		if (err == 0 &&
		    (strlen(vea.viea_value) + 1) >
		    STRUCT_FGET(ga, ga_val_len)) {
			err = EINVAL;
		}
		if (err == 0) {
			if (ddi_copyout(vea.viea_value,
			    STRUCT_FGETP(ga, ga_value),
			    strlen(vea.viea_value) + 1, mode) != 0) {
				err = EFAULT;
			}
		}
		vol_tab_rele(tp);
		return (err);
gattr_dun:
		vol_tab_unlock_and_rele(tp);
		return (err);
	}

	case VOLIOCREMOUNT:	/* the medium has a new partition structure */
		vol_enqueue(VIE_REMOUNT, (void *)&unit);
		vol_tab_unlock_and_rele(tp);
		/* may return ENODEV, even though event was queued ?? */
		return (err);
	case CDROMEJECT:
	case FDEJECT:
	case DKIOCEJECT:
		if (tp->vol_devops == NULL) {
			vol_tab_unlock_and_rele(tp);
			return (EAGAIN);
		}
		vol_tab_unlock_and_rele(tp);
		break;

	default:
		vol_tab_unlock_and_rele(tp);
		break;
	}

	/*
	 * This is the part that passes ioctls on to the lower
	 * level devices.  Some of these may have to be trapped
	 * and remapped.
	 */
	if ((tp = vol_gettab(unit, VGT_WAITSIG, &err)) == NULL) {
		DPRINTF("vol: ioctl (to pass on): gettab on unit %d, err %d\n",
		    unit, err);
		return (err);
	}

	/*
	 * this is almost certainly the ENXIO case for that special
	 * flag we set.
	 */
	if (err)
		goto out;

	if (!(tp->vol_flags & ST_OPEN)) {
		err = ENXIO;
		goto out;
	}

	switch (cmd) {
	/*
	 * Here's where we watch for the eject ioctls.  Here, we enqueue
	 * a message for the daemon and wait around to hear the results.
	 */
	case CDROMEJECT:
	case FDEJECT:
	case DKIOCEJECT: {
		dev_t savedev = tp->vol_dev;
		struct ve_eject	vej;
		int	status;

		if (volctl.ctl_daemon_pid == 0) {
			vol_tab_unlock_and_rele(tp);
			return (ENXIO);
		}

		vej.viej_unit = unit;
		vej.viej_force = 0;

		vol_tab_unlock(tp);

		if ((err = vol_ioctl_enter(&tp->vol_eject)) != 0) {
			vol_tab_rele(tp);
			return (err);
		}
		/* ask daemon for permission to eject */
		vol_enqueue(VIE_EJECT, (void *)&vej);
		err = vol_ioctl_wait(&tp->vol_eject, &status, NULL);
		if (err == 0) {
			if (status == VEJ_NO)
				err = EBUSY;
		}
		vol_ioctl_exit(&tp->vol_eject);
		if (err != 0) {
			/* ioctl is either signalled or rejected by vold */
			vol_tab_rele(tp);
			return (err);
		}

		ASSERT(savedev != NODEV);
		err = cdev_ioctl(savedev, cmd, arg,
		    (mode & FMODELS) | FREAD, credp, rvalp);
		/*
		 * clean out the block device.
		 */
		binval(savedev);	/* XXX: not DDI compliant */

		vol_tab_rele(tp);
		return (err);
	}

	/*
	 * The following ioctls cause volume management to
	 * reread the label after last close.  The assumption is
	 * that these are only used during "format" operations
	 * and labels and stuff get written with these.
	 */
	case DKIOCSVTOC:	/* set vtoc */
	case DKIOCSGEOM:	/* set geometry */
	case DKIOCSAPART:	/* set partitions */
	case FDRAW:		/* "raw" command to floppy */
		vol_enqueue(VIE_NEWLABEL, (void *)&unit);
		/* FALL THROUGH */
	default:
		/*
		 * Pass the ioctl on down.
		 */
		if (tp->vol_dev == NODEV) {
			err = EIO;

			DPRINTF("vol: tp->vol_dev = NODEV\n");
			DPRINTF("vol: ioctl: dev %u.%u cmd %x arg %lx "
			    "mode %x credp %p rvalp %p\n",
			    getmajor(dev), getminor(dev),
			    cmd, arg, mode, (void *)credp, (void *)rvalp);
			break;
		}
		err = cdev_ioctl(tp->vol_dev, cmd, arg,
		    mode & ~FWRITE, credp, rvalp);
		break;
	}
	/* release lock, return err */
out:
	vol_tab_unlock_and_rele(tp);
	return (err);
}


static int
volpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	int		unit;
	struct vol_tab 	*tp;
	int		err = 0;

	DPRINTF4(
	    "vol: poll: dev %u.%u events 0x%x anyyet 0x%x revents 0x%x\n",
	    getmajor(dev), getminor(dev), (int)events, anyyet,
	    (int)*reventsp);

	unit = getminor(dev);
	if (unit == 0) {
		if (volctl.ctl_open == 0 || volctl.ctl_daemon_pid == 0) {
			*reventsp |= POLLNVAL;
			return (EINVAL);
		}
		if (events & POLLRDNORM) {
			DPRINTF4("vol: poll: got a POLLRDNORM\n");
			mutex_enter(&volctl.ctl_evmutex);
			if (volctl.ctl_evcnt) {
				DPRINTF3("vol: poll: we have data\n");
				*reventsp |= POLLRDNORM;
				mutex_exit(&volctl.ctl_evmutex);
				return (0);
			}
			mutex_exit(&volctl.ctl_evmutex);
		}
		if (!anyyet) {
			*phpp = &vol_pollhead;
			*reventsp = 0;
		}
		return (0);
	}

	if ((tp = vol_gettab(unit, VGT_WAITSIG, &err)) == NULL) {
		*reventsp |= POLLERR;
		return (err);
	}

	if ((tp->vol_flags & ST_OPEN) == 0) {
		*reventsp |= POLLERR;
		err = ENXIO;
		goto out;
	}
	ASSERT(tp->vol_dev != NODEV);
	err = cdev_poll(tp->vol_dev, events, anyyet, reventsp, phpp);

out:
	vol_tab_unlock_and_rele(tp);
	return (err);
}


static void
vol_enqueue(enum vie_event type, void *data)
{
	struct kvioc_event 	*kvie;
	cred_t			*c;
	proc_t			*p;
	uid_t			uid;
	gid_t			gid;
	dev_t			ctty;


	kvie = kmem_alloc(sizeof (*kvie), KM_SLEEP);
	kvie->kve_event.vie_type = type;

	/* build our user friendly slop.  Probably not DDI compliant */
	if (drv_getparm(UCRED, &c) != 0) {
		DPRINTF("vol: vol_enqueue: couldn't get ucred\n");
		uid = -1;
		gid = -1;
	} else {
		uid = crgetuid(c);
		gid = crgetgid(c);
	}

	if (drv_getparm(UPROCP, &p) != 0) {
		DPRINTF("vol: vol_enqueue: couldn't get uprocp\n");
		ctty = NODEV;
	} else {
		ctty = cttydev(p);
	}

	DPRINTF2("vol: vol_enqueue: uid=%d, gid=%d, ctty=0x%lx\n", uid,
	    gid, ctty);

	switch (type) {
	case VIE_MISSING:
		kvie->kve_event.vie_missing = *(struct ve_missing *)data;
		kvie->kve_event.vie_missing.viem_user = uid;
		kvie->kve_event.vie_missing.viem_tty = ctty;
		break;
	case VIE_INSERT:
		kvie->kve_event.vie_insert.viei_dev = *(dev_t *)data;
		break;
	case VIE_CHECK:
		kvie->kve_event.vie_check.viec_dev = *(dev_t *)data;
		break;
	case VIE_INUSE:
		kvie->kve_event.vie_inuse.vieu_dev = *(dev_t *)data;
		break;
	case VIE_EJECT:
		kvie->kve_event.vie_eject = *(struct ve_eject *)data;
		kvie->kve_event.vie_eject.viej_user = uid;
		kvie->kve_event.vie_eject.viej_tty = ctty;
		break;
	case VIE_DEVERR:
		kvie->kve_event.vie_error = *(struct ve_error *)data;
		break;
	case VIE_CLOSE:
		kvie->kve_event.vie_close.viecl_unit = *(minor_t *)data;
		break;
	case VIE_REMOVED:
		kvie->kve_event.vie_rm.virm_unit = *(minor_t *)data;
		break;
	case VIE_CANCEL:
		kvie->kve_event.vie_cancel.viec_unit = *(minor_t *)data;
		break;
	case VIE_NEWLABEL:
		kvie->kve_event.vie_newlabel.vien_unit = *(minor_t *)data;
		break;
	case VIE_GETATTR:
	case VIE_SETATTR:
		kvie->kve_event.vie_attr = *(struct ve_attr *)data;
		kvie->kve_event.vie_attr.viea_uid = uid;
		kvie->kve_event.vie_attr.viea_gid = gid;
		break;
	case VIE_SYMNAME:
		kvie->kve_event.vie_symname.vies_dev = *(dev_t *)data;
		break;
	case VIE_SYMDEV:
		kvie->kve_event.vie_symdev = *(struct ve_symdev *)data;
		break;
	case VIE_REMOUNT:
		kvie->kve_event.vie_remount.vier_unit = *(minor_t *)data;
		break;
	default:
		cmn_err(CE_WARN, "vol_enqueue: bad type %d", type);
		kmem_free(kvie, sizeof (*kvie));
		return;
	}

	mutex_enter(&volctl.ctl_evmutex);
	if (volctl.ctl_evend) {
		insque(kvie, volctl.ctl_evend);
	} else {
		insque(kvie, &volctl.ctl_events);
	}
	volctl.ctl_evend = kvie;
	volctl.ctl_evcnt++;
	mutex_exit(&volctl.ctl_evmutex);
	pollwakeup(&vol_pollhead, POLLRDNORM);
}

#ifdef _SYSCALL32_IMPL
static int
vol_event32(struct vioc_event32 *e32, struct vioc_event *e)
{
	int err = 0;

	bzero(e32, sizeof (*e32));

#define	E2E32(x) e32->x = e->x

	E2E32(vie_type);
	switch (e->vie_type) {
	case VIE_MISSING:
		E2E32(vie_missing.viem_unit);
		E2E32(vie_missing.viem_ndelay);
		E2E32(vie_missing.viem_user);
		if (!cmpldev(&(e32->vie_missing.viem_tty),
		    e->vie_missing.viem_tty))
			err = EOVERFLOW;
		break;
	case VIE_EJECT:
		E2E32(vie_eject.viej_unit);
		E2E32(vie_eject.viej_user);
		if (!cmpldev(&(e32->vie_eject.viej_tty),
		    e->vie_eject.viej_tty))
			err = EOVERFLOW;
		E2E32(vie_eject.viej_force);
		break;
	case VIE_DEVERR:
		if (!cmpldev(&(e32->vie_error.viee_dev),
		    e->vie_error.viee_dev))
			err = EOVERFLOW;
		E2E32(vie_error.viee_errno);
		break;
	case VIE_CLOSE:
		E2E32(vie_close.viecl_unit);
		break;
	case VIE_CANCEL:
		E2E32(vie_cancel.viec_unit);
		break;
	case VIE_NEWLABEL:
		E2E32(vie_newlabel.vien_unit);
		break;
	case VIE_INSERT:
		if (!cmpldev(&(e32->vie_insert.viei_dev),
		    e->vie_insert.viei_dev))
			err = EOVERFLOW;
		break;
	case VIE_SETATTR:
	case VIE_GETATTR:
		E2E32(vie_attr.viea_unit);
		/* copy all the data including the null terminate */
		bcopy(e->vie_attr.viea_attr, e32->vie_attr.viea_attr,
		    MAX_ATTR_LEN + 1);
		bcopy(e->vie_attr.viea_value, e32->vie_attr.viea_value,
		    MAX_ATTR_LEN + 1);
		E2E32(vie_attr.viea_uid);
		E2E32(vie_attr.viea_gid);
		break;
	case VIE_INUSE:
		if (!cmpldev(&(e32->vie_inuse.vieu_dev),
		    e->vie_inuse.vieu_dev))
			err = EOVERFLOW;
		break;
	case VIE_CHECK:
		if (!cmpldev(&(e32->vie_check.viec_dev),
		    e->vie_check.viec_dev))
			err = EOVERFLOW;
		break;
	case VIE_REMOVED:
		E2E32(vie_rm.virm_unit);
		break;
	case VIE_SYMNAME:
		if (!cmpldev(&(e32->vie_symname.vies_dev),
		    e->vie_symname.vies_dev))
			err = EOVERFLOW;
		break;
	case VIE_SYMDEV:
		bcopy(e->vie_symdev.vied_symname, e32->vie_symdev.vied_symname,
		    VOL_SYMNAME_LEN + 1);
		break;
	case VIE_REMOUNT:
		E2E32(vie_remount.vier_unit);
		break;
	}
	return (err);
}
#endif /* _SYSCALL32_IMPL */

/*
 * vol_gettab() returns a vol_tab_t * for the unit.  If the unit
 * isn't mapped, we tell vold about it and wait around until
 * a mapping occurs
 *
 * upon successful completion, the vol_tab for which the pointer is
 * returned has the read/write lock held as a reader
 */
static struct vol_tab *
vol_gettab(int unit, uint_t flags, int *err)
{
	struct vol_tab		*tp;
	int			rv;
	struct ve_missing	ve;

	*err = 0;

	mutex_enter(&volctl.ctl_muxmutex);

	/*
	 * If unit#0 has not opened, VGT_OPEN can be used to forcibly
	 * grab the vol_tab. Similarly, if unit#0 was closing, VGT_CLOSE
	 * can be used.
	 */
	if ((volctl.ctl_open == 0 && (flags & VGT_OPEN) == 0) ||
	    (volctl.ctl_closing && (flags & VGT_CLOSE) == 0)) {
		mutex_exit(&volctl.ctl_muxmutex);
		*err = ENXIO;
		DPRINTF("vol: gettab: ctl unit not open (ENXIO)!\n");
		return (NULL);
	}

	ASSERT(unit >= 0);
	if (unit < 0) {
		mutex_exit(&volctl.ctl_muxmutex);
		*err = ENOTTY;
		DPRINTF("vol: vol_gettab: negative unit number!\n");
		return (NULL);
	}

	tp = (struct vol_tab *)ddi_get_soft_state(voltab, unit);
	if (tp == NULL) {
		/* this unit not yet created */
		if (flags & VGT_NEW) {
			/* the "create" flag is set, so create it */
			*err = ddi_soft_state_zalloc(voltab, unit);
			if (*err) {
				DPRINTF("vol: zalloc broke vol %d\n", unit);
				*err = ENODEV;
				mutex_exit(&volctl.ctl_muxmutex);
				goto out;
			}
			tp = (struct vol_tab *)
				ddi_get_soft_state(voltab, unit);
			if (tp == NULL) {
				DPRINTF("vol: soft state was null!\n");
				*err = ENOTTY;
				mutex_exit(&volctl.ctl_muxmutex);
				goto out;
			}
			vol_tab_init(tp);
			tp->vol_unit = unit;
		} else {
			/* didn't build a new one and we don't have one */
			DPRINTF("vol: vol_gettab: ENODEV\n");
			*err = ENODEV;
			mutex_exit(&volctl.ctl_muxmutex);
			goto out;
		}
	}
	tp->vol_refcnt++;

	/* now we know the unit exists */

	/* keep track of the largest unit number we've seen */
	if (unit > volctl.ctl_maxunit) {
		volctl.ctl_maxunit = unit;
	}

	mutex_exit(&volctl.ctl_muxmutex);

	if (flags & VGT_WAITSIG) {
		if (vol_tab_rlock_sig(tp)) {
			vol_tab_rele(tp);
			*err = EINTR;
			return (NULL);
		}
	} else {
		vol_tab_rlock(tp);
	}

	/* check for ops already gotten, or for /dev/volctl */
	if ((tp->vol_devops != NULL) || (unit == 0)) {
		/* got it! */
		goto out;
	}

	/* no vol_devops yet (and unit not /dev/volctl) */

	if (flags & VGT_NOWAIT) {
		/* no ops, and they don't want to wait */
		DPRINTF("vol: vol_gettab: no mapping for %d, no waiting\n",
		    unit);
		*err = ENODEV;
		goto out;
	}

	/* no vol_devops yet, but caller is willing to wait */

#ifdef	DEBUG_ENXIO
	if (tp->vol_flags & ST_ENXIO) {
		DPRINTF("vol_gettab: no mapping for %d: doing ENXIO\n", unit);
	} else {
		DPRINTF("vol_gettab: no mapping for %d: it's MISSING "
		    "(flags=0x%x, tp=%p)\n", unit, tp->vol_flags, (void *)tp);
	}
#endif
	if (tp->vol_flags & ST_ENXIO) {
		/*
		 * It's been unmapped, but the requested behavior is to
		 * return ENXIO rather than waiting around.  The enxio
		 * behavior is cleared on close.
		 */
		DPRINTF("vol: vol_gettab: no mapping for %d, doing ENXIO\n",
		    unit);
		vol_tab_unlock_and_rele(tp);
		tp = NULL;
		*err = ENXIO;
		goto out;
	}

	/*
	 * there isn't a mapping -- enqueue a missing message to the
	 * daemon and wait around until it appears
	 */
	ve.viem_unit = unit;
	ve.viem_ndelay = (flags & VGT_NDELAY) ? TRUE : FALSE;

	/*
	 * hang around until a unit appears or we're cancelled.
	 */
	while (tp->vol_devops == NULL) {
		if (tp->vol_cancel) {
			break;		/* a volcancel has been done */
		}
		/*
		 * Due to the lock ordering between rwlock and muxmutex, we
		 * need to release muxmuex prior to releasing rlock after
		 * cv_wait is complete. Between those two calls, corresponding
		 * node can be unmapped. As a result, we will go into
		 * cv_wait() again without posting VIE_MISSING, and thus
		 * cv_wait sleeps forever. Therefore, we need to post
		 * VIE_MISSING every time before we go into cv_wait().
		 */
		DPRINTF("vol: vol_gettab: enqueing missing event, unit %d "
		    "(ndelay=%d)\n", unit, ve.viem_ndelay);
		vol_enqueue(VIE_MISSING, (void *)&ve);

		/*
		 * We need to ensure that the thread is sleeping in the
		 * cond when it's signalled. If muxmutex was acquired after
		 * the vol_tab_unlock() below, it creates a race with
		 * VOLIOCMAP which would cause loss of signal. Therefore
		 * muxmutex should be held here before releasing rlock.
		 */
		mutex_enter(&volctl.ctl_muxmutex);

		/* release rlock so that VOLIOCMAP can update devops */
		vol_tab_unlock(tp);

		/* wait right here */
		if (flags & VGT_WAITSIG) {
			rv = cv_wait_sig(&tp->vol_incv, &volctl.ctl_muxmutex);
			if (rv == 0) {
				DPRINTF("vol: vol_gettab: eintr -> cnx\n");
				/*
				 * found pending signal. We don't cancel
				 * the request here, otherwise next open
				 * would fail with ENXIO until vold creates
				 * a new mapping, also media can be ejected
				 * by a Ctrl-C.
				 */
				mutex_exit(&volctl.ctl_muxmutex);
				vol_tab_rele(tp);
				*err = EINTR;
				tp = NULL;
				break;
			}
		} else {
			/* can't be interrupted by a signal */
			cv_wait(&tp->vol_incv, &volctl.ctl_muxmutex);
		}

		/* we may have signalled from close(). */
		if (volctl.ctl_daemon_pid == 0) {
			mutex_exit(&volctl.ctl_muxmutex);
			vol_tab_rele(tp);
			*err = ENXIO;
			tp = NULL;
			break;
		}

		/*
		 * muxmutex is no longer necessary. It should be released
		 * before acquiring rlock, so that thread running VOLIOCMAP
		 * etc won't deadlock.
		 */
		mutex_exit(&volctl.ctl_muxmutex);

		/* here, node can be unmapped again. see comments above */

		/* rlock again as we will test vol_devops */
		if (flags & VGT_WAITSIG) {
			if (vol_tab_rlock_sig(tp)) {
				vol_tab_rele(tp);
				*err = EINTR;
				tp = NULL;
				break;
			}
		} else {
			vol_tab_rlock(tp);
		}

		DPRINTF2("vol: vol_gettab: insert cv wakeup rcvd\n");

		if ((flags & VGT_NDELAY) && (tp->vol_dev == NODEV))
			break;
	}
out:
	/*
	 * If the device is "cancelled", don't return the tp unless
	 * the caller really wants it (nowait and ndelay).
	 */
	if ((tp != NULL) && tp->vol_cancel && !(flags & VGT_NOWAIT) &&
	    !(flags & VGT_NDELAY)) {
		DPRINTF("vol: vol_gettab: cancel (flags 0x%x)\n", flags);
		*err = EIO;
		vol_tab_unlock_and_rele(tp);
		tp = NULL;
	}
	if (*err != 0) {
		DPRINTF("vol: vol_gettab: err=%d unit=%d, tp=%p\n",
		    *err, unit, (void *)tp);
	}
	return (tp);
}


/*
 * Unmap *tp.  Removes it from the ddi_soft_state list.
 */
static void
vol_unmap(struct vol_tab *tp)
{
	char	mname[16];

	ASSERT(MUTEX_HELD(&volctl.ctl_muxmutex));
	ASSERT(volctl.ctl_dip);

	/* wait until everyone is done with it */
	vol_tab_rele_wait(tp);

	/* release underlying driver */
	vol_release_driver(tp);

	/* get rid of the thing */
	vol_tab_fini(tp);

	/* remove minor node */
	(void) snprintf(mname, sizeof (mname), VOLUNITNAME_BLK, tp->vol_unit);
	ddi_remove_minor_node(volctl.ctl_dip, mname);

	(void) snprintf(mname, sizeof (mname), VOLUNITNAME_CHR, tp->vol_unit);
	ddi_remove_minor_node(volctl.ctl_dip, mname);

	/* done */
	ddi_soft_state_free(voltab, tp->vol_unit);
}


/*
 * This is called when the volume daemon closes its connection.
 * It cleans out our mux.
 */
static void
vol_cleanup(void)
{
	int		i;
	int		err;
	struct vol_tab	*tp;
	struct kvioc_event *kve;

	DPRINTF("vol_cleanup: entering (daemon dead?)\n");

	/*
	 * We need to grab muxmutex to make sure that all threads
	 * opening unit>0 are aware of closing, and ctl_muxunit will
	 * never be changed.
	 */
	mutex_enter(&volctl.ctl_muxmutex);
	volctl.ctl_closing = 1;
	mutex_exit(&volctl.ctl_muxmutex);

	for (i = 1; i < (volctl.ctl_maxunit + 1); i++) {

		tp = vol_gettab(i, VGT_NOWAIT|VGT_CLOSE, &err);
		if (tp == NULL)
			continue;

		DPRINTF("vol_cleanup: unit %d\n", i);

		vol_ioctl_fail(&tp->vol_attr);
		/* cancel pending eject requests */
		vol_ioctl_fail(&tp->vol_eject);

		/*
		 * acquire muxmutex, to make sure that all the threads
		 * are aware of ctl_closing flag, and running threads have
		 * either failed or already acquired rlock in vol_gettab().
		 * write lock is required as we will touch vol_cancel.
		 */
		vol_tab_rwlock_upgrade(tp);
		mutex_enter(&volctl.ctl_muxmutex);

		/* send a "cancel" for pending missing events */
		tp->vol_cancel = TRUE;
		cv_broadcast(&tp->vol_incv);

		vol_unmap(tp);
		/* tp is no longer valid after a vol_umnap() */

		mutex_exit(&volctl.ctl_muxmutex);
	}

	DPRINTF("vol: vol_cleanup: cleared from 0 to %d\n",
	    volctl.ctl_maxunit);

	volctl.ctl_maxunit = 0;

	/*
	 * handle threads waiting for replies from the daemon
	 */
	vol_ioctl_fail(&volctl.ctl_inuse);
	vol_ioctl_fail(&volctl.ctl_insert);
	vol_ioctl_fail(&volctl.ctl_symname);
	vol_ioctl_fail(&volctl.ctl_symdev);

	/*
	 * Free up anything lurking on the event queue.
	 */
	mutex_enter(&volctl.ctl_evmutex);
	while (volctl.ctl_evcnt != 0) {
		kve = volctl.ctl_events.kve_next;
		volctl.ctl_evcnt--;
		remque(kve);
		kmem_free(kve, sizeof (*kve));
	}
	volctl.ctl_evend = NULL;
	mutex_exit(&volctl.ctl_evmutex);

	/* wake up threads if sleeping in poll() */
	pollwakeup(&vol_pollhead, POLLERR);

	/*
	 * release memory only needed while the daemon is running
	 */
	mutex_enter(&volctl.ctl_volrmutex);
	if (vold_root != NULL) {
		kmem_free(vold_root, vold_root_len + 1);
		vold_root = NULL;
		vold_root_len = 0;
	}
	mutex_exit(&volctl.ctl_volrmutex);

	/* re-enable the ioctls */
	vol_ioctl_enable(&volctl.ctl_inuse);
	vol_ioctl_enable(&volctl.ctl_insert);
	vol_ioctl_enable(&volctl.ctl_symname);
	vol_ioctl_enable(&volctl.ctl_symdev);

	volctl.ctl_closing = 0;
}


/*
 * Check the floppy drive to see if there's a floppy still in the
 * drive.  If there isn't this function will block until the floppy
 * is either back in the drive or the i/o is cancelled.  If found_media
 * is supplied the status will be returned through it.
 */
static int
vol_checkmedia(struct vol_tab *tp, int *found_media)
{
	int 		err = 0;
	int		badnews = 0;
	struct vol_tab	*tp0;

	DPRINTF2("vol: checkmedia\n");

	/* do the grotty stuff to get the answer */
	badnews = vol_checkmedia_machdep(tp);

	/* check to see if there's no media in the drive */
	if (badnews) {
		/* there's no media in the drive */

		if (found_media) {
			*found_media = FALSE;	/* return result */
		}

		if (vol_tab_rwlock_upgrade_sig(tp))
			return (EINTR);

		/* unmap the device */
		vol_release_driver(tp);
		vol_tab_unlock(tp);

		vol_enqueue(VIE_REMOVED, (void *)&tp->vol_unit);

		/* get the mapping for this device, waiting if needed */
		DPRINTF("vol: checkmedia: calling gettab\n");
		tp0 = vol_gettab(tp->vol_unit, VGT_WAITSIG, &err);
		if (tp0 == NULL && err == EINTR)
			return (EINTR);
		if (tp0 != NULL)
			vol_tab_unlock_and_rele(tp0);

		if (vol_tab_rlock_sig(tp))
			return (EINTR);

		DPRINTF("vol: checkmedia: gettab has returned\n");
	} else {
		/* there is media in the drive */

		if (found_media) {
			*found_media = TRUE;	/* return results */
		}
	}
	/* all done */
	return (err);
}


/*
 * return the bad news: media there (0) or not (1).
 */
static int
vol_checkmedia_machdep(struct vol_tab *tp)
{
	int	err;
	int	fl_rval = 0;	/* bitmap word: all bits clear initially */


	switch (tp->vol_mtype) {
	case MT_FLOPPY:
		/* check for a floppy disk in the drive */

		/* ensure we have a dev to do the ioctl on */
		if (tp->vol_dev == NODEV) {
			/* it's been unmapped (so probably not there) */
			DPRINTF("vol: checkmedia: volume unmapped\n");
			return (1);
		}

		/*
		 * XXX this mutex make sure that we're only doing one of
		 * XXX these ioctl's at a time.  this avoids a deadlock
		 * XXX in the floppy driver.
		 */
		mutex_enter(&floppy_chk_mutex);
		err = cdev_ioctl(tp->vol_dev, FDGETCHANGE,
		    (intptr_t)&fl_rval, FNATIVE | FKIOCTL, kcred, NULL);
		mutex_exit(&floppy_chk_mutex);

		if (err != 0) {
			DPRINTF("vol: checkmedia: FDGETCHANGE failed %d\n",
			    err);
			/* if we got an error, assume the worst */
			return (1);
		}

		/* is media present ?? */
		if (fl_rval & FDGC_CURRENT) {
			DPRINTF("vol: checkmedia: no media! (fl_rval = 0x%x)\n",
			    fl_rval);
			return (1);	/* no media in the drive */
		}

		return (0);		/* media in the drive */

	default:
		DPRINTF("vol: checkmedia: bad mtype %d\n", tp->vol_mtype);
		return (1);
	}
	/*NOTREACHED*/
}

/*
 * Release the driver and cleanup unnecessary stuff in vol_tab.
 */
static void
vol_release_driver(struct vol_tab *tp)
{
	if (tp->vol_dev != NODEV && tp->vol_devops != NULL) {
		ddi_rele_driver(getmajor(tp->vol_dev));
		DPRINTF3("vol: released driver %u\n", getmajor(tp->vol_dev));
	}
	tp->vol_dev = NODEV;
	tp->vol_devops = NULL;
	/* drop media related flags */
	tp->vol_flags &= ~(ST_CHKMEDIA|ST_RDONLY);
	if (tp->vol_path != NULL)
		kmem_free(tp->vol_path, tp->vol_pathlen + 1);
	tp->vol_path = NULL;
	tp->vol_pathlen = 0;
}

/*
 * return 0 if you are vold.
 */
static int
vol_daemon_check(void)
{
	pid_t pid;

	if (volctl.ctl_daemon_pid == 0)
		return (ENXIO);
	(void) drv_getparm(PPID, &pid);
	if (volctl.ctl_daemon_pid != pid)
		return (EPERM);
	else
		return (0);
}

/*
 * client side functions can be used to interface ioctls to vold.
 * vold is responding for the ioctls by using vold_xx functions.
 *
 * vol_ioctl_init()
 * vol_ioctl_fini()
 *	initialize/destroy mutex, condvar etc.
 *
 * vol_ioctl_enter()
 *	serialize ioctl request to make sure only one thread
 *	is reqeusting a response from vold for particular uni/ioctl.
 *
 * vol_ioctl_wait()
 * 	set argument in argp which will be used by by vold ioctl, and
 *	wait for vold's response. value/ptr from vold are also returned
 * 	via rval/rptr arguments.
 *
 * vol_ioctl_exit()
 *	exit from critical section and let the next thread go into
 *	the ioctl.
 *
 * vol_ioctl_fail()
 *	wakes up threads either waiting for entering ioctl or waiting
 *	for a response from vold. This will make those ioctls fail.
 */
static void
vol_ioctl_init(struct vol_ioctl *vic)
{
	mutex_init(&vic->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vic->cv, NULL, CV_DRIVER, NULL);
	cv_init(&vic->s_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vic->close_cv, NULL, CV_DRIVER, NULL);
	vic->nwait = 0;
	vic->active = 0;
	vic->closing = 0;
}

static void
vol_ioctl_fini(struct vol_ioctl *vic)
{
	mutex_destroy(&vic->mutex);
	cv_destroy(&vic->cv);
	cv_destroy(&vic->s_cv);
	cv_destroy(&vic->close_cv);
}

static int
vol_ioctl_enter(struct vol_ioctl *vic)
{
	int r;

	mutex_enter(&vic->mutex);
	if (vic->closing) {
		mutex_exit(&vic->mutex);
		return (ENXIO);
	}
	while (vic->active) {
		vic->nwait++;
		r = cv_wait_sig(&vic->s_cv, &vic->mutex);
		vic->nwait--;
		if (vic->closing) {
			if (vic->closewait && vic->nwait == 0) {
				/* I'm the last */
				cv_signal(&vic->close_cv);
			}
			mutex_exit(&vic->mutex);
			if (r == 0)
				return (EINTR);
			else
				return (ENXIO);
		}
		if (r == 0) {
			/* signal pending */
			mutex_exit(&vic->mutex);
			return (EINTR);
		}
	}
	vic->active = 1;
	return (0);
}

static int
vol_ioctl_wait(struct vol_ioctl *vic, int *rvalp, void *rptrp)
{
	int err = 0;

	vic->rval = -1;
	vic->rptr = NULL;	/* clear return pointer in case of error */
	if (rptrp != NULL)
		vic->argp = *(uintptr_t *)rptrp;
	while (vic->rval == -1) {
		if (cv_wait_sig(&vic->cv, &vic->mutex) == 0) {
			/* we are interrupted */
			vic->rval = 0;
			err = EINTR;
			break;
		}
	}
	if (vic->closing || volctl.ctl_daemon_pid == 0) {
		/* the daemon is dying, or has already died */
		err = ENXIO;
	}
	/* return data from vold */
	if (rptrp != NULL)
		*(uintptr_t *)rptrp = vic->rptr; /* set return pointer */
	*rvalp = vic->rval;
	return (err);
}

static void
vol_ioctl_exit(struct vol_ioctl *vic)
{
	vic->active = 0;
	if (vic->nwait != 0) {
		cv_broadcast(&vic->s_cv);
	} else if (vic->closewait) {
		/*
		 * I'm the last one. wake up the thread sleeping
		 * in vol_ioctl_fail.
		 */
		cv_signal(&vic->close_cv);
	}
	mutex_exit(&vic->mutex);
}

static void
vol_ioctl_fail(struct vol_ioctl *vic)
{

	mutex_enter(&vic->mutex);
	if (vic->active) {
		/*
		 * client is waiting for response.
		 * vold may or may not have responded to the request.
		 * If vold has already responded, rval has been set.
		 * We don't reset rval in such case. If vold has not
		 * yet responded, we set rval to pull thread out from
		 * loop in ioctl_wait. vold will see vic->closing, so
		 * it never reset rval again.
		 */
		if (vic->rval == -1) {
			vic->rval = 0;
			vic->rptr = NULL;
		}
	}
	vic->closing = 1;
	vic->closewait = 0;
	if (vic->nwait)
		cv_broadcast(&vic->s_cv);
	if (vic->active)
		cv_broadcast(&vic->cv);
	/*
	 * If ioctl is active, or someone is waiting for ioctl.
	 */
	while (vic->active || vic->nwait > 0) {
		vic->closewait = 1;
		cv_wait(&vic->close_cv, &vic->mutex);
		vic->closewait = 0;
	}
	mutex_exit(&vic->mutex);
}

static void
vol_ioctl_enable(struct vol_ioctl *vic)
{
	mutex_enter(&vic->mutex);
	vic->closing = 0;
	mutex_exit(&vic->mutex);
}

/*
 * vold side ioctl functions to interface with client side.
 *
 * vold_ioctl_enter()
 *	double check to see if there is a request and vold can
 *	respond. Retrieve data passed by vol_ioctl_wait().
 *
 * vold_ioctl_respond()
 *	set return values, and signal thread waiting for a
 *	response.
 *
 * vold_ioctl_exit()
 *	just exit. release lock.
 */

static int
vold_ioctl_enter(struct vol_ioctl *vic, void *rptrp)
{
	mutex_enter(&vic->mutex);
	if (vic->closing) {
		/* should not happen, but */
		mutex_exit(&vic->mutex);
		return (ENXIO);
	}
	if (!vic->active) {
		mutex_exit(&vic->mutex);
		return (EAGAIN);
	}
	if (rptrp != NULL)
		*(uintptr_t *)rptrp = vic->argp;
	return (0);
}

static void
vold_ioctl_respond(struct vol_ioctl *vic, int rval, void *rptr)
{
	ASSERT(rval != -1);
	vic->rval = rval;
	vic->rptr = (uintptr_t)rptr;
	cv_signal(&vic->cv);
}

static void
vold_ioctl_exit(struct vol_ioctl *vic)
{
	mutex_exit(&vic->mutex);
}

/*
 * vol_tab lock/unlock functions. It used to be reader/writer lock,
 * but need vol specific version which could prevent deadlock and race
 * condition mainly created by lock upgrade sequence.
 *
 * vol_tab_init(), vol_tab_fini()
 *	initialize/destroy the mutex/condvars.
 *
 * vol_tab_rlock_unlocked()
 * vol_tab_rlock()/vol_tab_rlock_sig()
 *	acquire reader lock. If write locked, just sleep. If read locked,
 * 	increment reader count. If not yet read/write locked, set lock word,
 *	and set reader count to 1.
 *
 * vol_tab_unlock()/vol_tab_unlock_unlocked()
 *	release lock. If read locked, decrement reader count. If reader
 *	count becomes 0, clear lock word. If write locked, just clear lock
 *	flag. If anyone waiting for lock, wake up the threads sleeping
 *	in either rlock or upgrade.
 *
 * vol_tab_rwlock_upgrade()
 *	upgrades the acquired reader lock to writer lock.
 *	If there is no other thread holding rlock, then straight upgrade
 *	to write lock. If no, unlock the read lock, and wait until lock
 *	is released.
 *
 * vol_tab_rele()
 *	decrement the reference count. reference count is incremented
 *	in vol_gettab(). If thread calling close() is waiting for
 *	vol_tab to be released(no reference), wake up the thread.
 *
 * vol_tab_unlock_and_rele()
 *	release lock, and decrement the reference count.
 *
 * vol_tab_rele_wait()
 *	waiting until no other thread has referece to the vol_tab.
 */

static void
vol_tab_init(struct vol_tab *tp)
{
	vol_ioctl_init(&tp->vol_eject);
	vol_ioctl_init(&tp->vol_attr);
	mutex_init(&tp->vol_rwlck_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tp->vol_incv, NULL, CV_DRIVER, NULL);
	cv_init(&tp->vol_rwlck_cv, NULL, CV_DRIVER, NULL);
	cv_init(&tp->vol_rele_cv, NULL, CV_DRIVER, NULL);
}

static void
vol_tab_fini(struct vol_tab *tp)
{
	vol_ioctl_fini(&tp->vol_eject);
	vol_ioctl_fini(&tp->vol_attr);
	mutex_destroy(&tp->vol_rwlck_mutex);
	cv_destroy(&tp->vol_incv);
	cv_destroy(&tp->vol_rwlck_cv);
	cv_destroy(&tp->vol_rele_cv);
}

static int
vol_tab_rlock_unlocked(struct vol_tab *tp, boolean_t waitsig)
{
	ASSERT(!MUTEX_HELD(&volctl.ctl_muxmutex));
	/* wait until wlock is released */
	while (tp->vol_locked == VOL_TAB_WR_LOCKED) {
		tp->vol_lckwaiter++;
		if (waitsig) {
			if (cv_wait_sig(&tp->vol_rwlck_cv,
			    &tp->vol_rwlck_mutex) == 0) {
				tp->vol_lckwaiter--;
				return (EINTR);
			}
		} else {
			cv_wait(&tp->vol_rwlck_cv, &tp->vol_rwlck_mutex);
		}
		tp->vol_lckwaiter--;
	}
	tp->vol_locked = VOL_TAB_RD_LOCKED;
	tp->vol_nreader++;
	return (0);
}

static void
vol_tab_rlock(struct vol_tab *tp)
{
	mutex_enter(&tp->vol_rwlck_mutex);
	(void) vol_tab_rlock_unlocked(tp, B_FALSE);
	mutex_exit(&tp->vol_rwlck_mutex);
}

static int
vol_tab_rlock_sig(struct vol_tab *tp)
{
	int r;

	mutex_enter(&tp->vol_rwlck_mutex);
	r = vol_tab_rlock_unlocked(tp, B_TRUE);
	mutex_exit(&tp->vol_rwlck_mutex);
	return (r);
}

static void
vol_tab_unlock_unlocked(struct vol_tab *tp)
{
	ASSERT(tp->vol_locked != VOL_TAB_UNLOCKED);

	if (tp->vol_locked == VOL_TAB_RD_LOCKED) {
		ASSERT(tp->vol_nreader != 0);
		if (--tp->vol_nreader == 0) {
			tp->vol_locked = VOL_TAB_UNLOCKED;
		}
	} else if (tp->vol_locked == VOL_TAB_WR_LOCKED) {
		tp->vol_locked = VOL_TAB_UNLOCKED;
	}
	if (tp->vol_locked == VOL_TAB_UNLOCKED && tp->vol_lckwaiter != 0) {
		cv_broadcast(&tp->vol_rwlck_cv);
	}
}

static void
vol_tab_unlock(struct vol_tab *tp)
{
	mutex_enter(&tp->vol_rwlck_mutex);
	vol_tab_unlock_unlocked(tp);
	mutex_exit(&tp->vol_rwlck_mutex);
}

static int
vol_tab_rwlock_upgrade_unlocked(struct vol_tab *tp, boolean_t waitsig)
{
	ASSERT(!MUTEX_HELD(&volctl.ctl_muxmutex));
	ASSERT(tp->vol_locked == VOL_TAB_RD_LOCKED && tp->vol_nreader > 0);

	if (tp->vol_nreader == 1) {
		tp->vol_nreader = 0;
		tp->vol_locked = VOL_TAB_WR_LOCKED;
		return (0);
	}
	vol_tab_unlock_unlocked(tp);	/* release READ lock */
	while (tp->vol_locked != VOL_TAB_UNLOCKED) {
		tp->vol_lckwaiter++;
		if (waitsig) {
			if (cv_wait_sig(&tp->vol_rwlck_cv,
			    &tp->vol_rwlck_mutex) == 0) {
				tp->vol_lckwaiter--;
				return (EINTR);
			}
		} else {
			cv_wait(&tp->vol_rwlck_cv, &tp->vol_rwlck_mutex);
		}
		tp->vol_lckwaiter--;
	}
	ASSERT(tp->vol_nreader == 0);
	tp->vol_locked = VOL_TAB_WR_LOCKED;
	return (0);
}

static void
vol_tab_rwlock_upgrade(struct vol_tab *tp)
{
	mutex_enter(&tp->vol_rwlck_mutex);
	(void) vol_tab_rwlock_upgrade_unlocked(tp, B_FALSE);
	mutex_exit(&tp->vol_rwlck_mutex);
}

static int
vol_tab_rwlock_upgrade_sig(struct vol_tab *tp)
{
	int r;

	mutex_enter(&tp->vol_rwlck_mutex);
	r = vol_tab_rwlock_upgrade_unlocked(tp, B_TRUE);
	mutex_exit(&tp->vol_rwlck_mutex);
	return (r);
}

static void
vol_tab_rele(struct vol_tab *tp)
{
	mutex_enter(&volctl.ctl_muxmutex);
	ASSERT(tp->vol_refcnt != 0);
	tp->vol_refcnt--;
	if (tp->vol_relewait && tp->vol_refcnt == 0) {
		/* I'm the last */
		cv_broadcast(&tp->vol_rele_cv);
	}
	mutex_exit(&volctl.ctl_muxmutex);
}

static void
vol_tab_unlock_and_rele(struct vol_tab *tp)
{
	ASSERT(!MUTEX_HELD(&volctl.ctl_muxmutex));
	vol_tab_unlock(tp);
	vol_tab_rele(tp);
}

static void
vol_tab_rele_wait(struct vol_tab *tp)
{
	ASSERT(MUTEX_HELD(&volctl.ctl_muxmutex));
	vol_tab_unlock(tp);
	tp->vol_refcnt--;
	while (tp->vol_refcnt > 0) {
		tp->vol_relewait = 1;
		cv_wait(&tp->vol_rele_cv, &volctl.ctl_muxmutex);
		tp->vol_relewait = 0;
	}
}

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
 * voltestdrv: test driver for Volume Management
 */


#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/buf.h>
#include	<sys/conf.h>
#include	<sys/proc.h>
#include	<sys/user.h>
#include	<sys/cred.h>
#include	<sys/file.h>
#include	<sys/open.h>
#include	<sys/poll.h>
#include	<sys/errno.h>
#include	<sys/ioccom.h>
#include	<sys/cmn_err.h>
#include	<sys/kmem.h>
#include	<sys/uio.h>
#include	<sys/modctl.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/cdio.h>
#include	<sys/fdio.h>
#include	<rpc/types.h>
#include	<sys/systm.h>

#include	"voltestdrv.h"


/* names */

#define	VTNODENAME	"voltestdrv"		/* driver name */
#define	VTLONGNAME	"Volume Management Test Driver, %I%"
						/* long driver name */
#define	VTNUNITS	"nunits"
#define	VTRWLOCK	"vt_rwlock"

/*
 * debug stuff
 */
#define	VTDEBUG		0	/* default debug level */

#define	VT_TABLE_KM_SFX	0	/* not used */
#define	VT_LABEL_TM_SFX 1	/* set label: too much memory requested */
#define	VT_LABEL_KM_SFX	2	/* not used */
#define	VT_NAME_TM_SFX	3	/* set name: too much memory requested */
#define	VT_NAME_KM_SFX	4	/* not used */
#define	VT_VTOC_KM_SFX	5	/* not used */
#define	VT_TOCE_TM_SFX	6	/* set vtoc entries: too much mem requested */
#define	VT_TOCE_KM_SFX	7	/* not used */
#define	VT_COUNTERS	8

static	int	vtdebug = VTDEBUG;

/*
 * set reasonable limit for certain ioctls
 * (label_cdrom reads 64k plus some slop)
 */
static	size_t	vt_too_much = 70 * 1024;

static	size_t	vt_mem_counters[VT_COUNTERS];

#define	DPRINTF		if (vtdebug > 0) printf
#define	DPRINTF2	if (vtdebug > 1) printf
#define	DPRINTF3	if (vtdebug > 2) printf
#define	DPRINTF4	if (vtdebug > 3) printf

/*
 * private device info
 */
static struct vt_tab {
	krwlock_t	vt_rwlock;	/* rdrs/writer lock for this struct */
	dev_info_t	*vt_dip;	/* dev info */
	uint_t		vt_flags;	/* per-device flags */
	char		*vt_name;	/* "label" for this dev */
	uint_t		vt_namelen;	/* length of vt_name */
	uint_t		vt_tag;		/* magic cookie */
	bool_t		vt_inserted;	/* state flag */
	int		vt_label_errno;	/* error for reads of label */
	size_t		vt_error_length; /* bytes to provide before error */
	size_t		vt_lablen;	/* length of label */
	char		*vt_label;	/* fake label */
	int		vt_ocnt[OTYPCNT]; /* open counts */
	struct vt_vtoc	*vt_toc;	/* table of contents */
	struct vt_hdrinfo vt_tochdrinfo; /* cdrom toc header info */
	int		vt_entry_errno;	/* error for cdrom toc entry */
	unsigned char	vt_error_track;	/* track to get error */
	size_t		vt_entry_count;	/* number of cdrom toc entries */
	struct cdrom_tocentry *vt_toc_entries; /* cdrom toc entries */
	kmutex_t	vt_lab_mx;	/* for vt_label and vt_lablen */
};

static struct vt_tab *vttab = NULL;

static int	vt_nunits = 0;	/* number of units driver is config'd for */

#define	VT_LABEL_MUTEX	"vt_lab_mx"


/* for vt_flags */
#define	ST_OPEN		0x1
#define	ST_EXCL		0x2


/*
 * keep kvt_queue and kvt_event in sync.  It is important that
 * kve_next and kve_prev are in the same order and relative position
 * in the resepctive structures.
 */
struct kvt_queue {
	struct kvt_event	*kve_next;
	struct kvt_event	*kve_prev;
};

struct kvt_event {
	struct kvt_event	*kve_next;
	struct kvt_event	*kve_prev;
	struct vt_status	kve_event;
};

static kmutex_t		vt_evmutex;	/* mutex for the event queue */

static unsigned int	vt_evcnt;	/* number of events on the list */
static struct kvt_queue vt_events;	/* list of events */
static struct pollhead	vt_pollhead;

static void 	vt_enqueue(enum vt_evtype, void *);


/*
 * insertion event variables
 */

static kmutex_t		vtnm_mut;
static kcondvar_t	vtnm_read_cv;
static kcondvar_t	vtnm_write_cv;

static minor_t		vtnm_dev;


static int	vtopen(dev_t *, int, int, cred_t *);
static int	vtclose(dev_t, int, int, cred_t *);
static int	vtstrategy(struct buf *);
static int	vtread(dev_t, struct uio *, cred_t *);
static int	vtwrite(dev_t, struct uio *, cred_t *p);
static int	vtprop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	vtioctl(dev_t, int, int, int, cred_t *, int *);
static int	vtpoll(dev_t, short, int, short *, struct pollhead **);



static struct cb_ops	vt_cb_ops = {
	vtopen,			/* open */
	vtclose,		/* close */
	vtstrategy,		/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	vtread,			/* read */
	vtwrite,		/* write */
	vtioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	vtpoll,			/* poll */
	vtprop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP,		/* flags */
};


static int	vtinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
#if SOLARIS2 < 10
static int	vtidentify(dev_info_t *);
#endif
static int	vtattach(dev_info_t *, ddi_attach_cmd_t);
static int	vtdetach(dev_info_t *, ddi_detach_cmd_t);


static struct dev_ops	vt_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	vtinfo,			/* info */
#if SOLARIS2 >= 10
	nulldev,
#else
	vtidentify,		/* identify */
#endif
	nulldev,		/* probe */
	vtattach,		/* attach */
	vtdetach,		/* detach */
	nulldev,		/* reset */
	&vt_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
};

extern struct mod_ops	mod_pseudodrvops;
extern struct mod_ops	mod_driverops;

static struct modldrv	vt_driver_info = {
	&mod_driverops,		/* modops */
	VTLONGNAME,		/* name */
	&vt_ops,		/* dev_ops */
};

static struct modlinkage vt_linkage = {
	MODREV_1,			/* rev */
	&vt_driver_info,
	NULL
};



#define	VTBUFSIZE	128
#define	VTMAXNAMLEN	80


/*
 * Virtual driver loader entry points
 */

int
_init(void)
{
	DPRINTF("vt: _init\n");
	return (mod_install(&vt_linkage));
}


int
_fini(void)
{
	DPRINTF("vt: _fini\n");

	/* nope, no open devices, detach. */
	return (mod_remove(&vt_linkage));
}


int
_info(struct modinfo *modinfop)
{
	DPRINTF("vt: _info: modinfop %x\n", (int)modinfop);
	return (mod_info(&vt_linkage, modinfop));
}


/*
 * Driver administration entry points
 */

#if SOLARIS2 < 10
static int
vtidentify(dev_info_t *dip)
{
	DPRINTF("vt: identify: dip %x\n", (int)dip);

	if (strcmp(ddi_get_name(dip), VTNODENAME) == 0) {
		return (DDI_IDENTIFIED);
	}
	return (DDI_NOT_IDENTIFIED);
}
#endif


static int
vtattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			unit = ddi_get_instance(dip);
	struct vt_tab		*tp = NULL;
	int			length;
	char			namebuf[40], *nm;
	int			nunits;
	int			i;
	int			error;


	DPRINTF("vt: attach: %d: dip %x cmd %d\n", unit, (int)dip, (int)cmd);

	/* check unit */
	if (unit != 0) {
		return (ENXIO);
	}

	/* check command */
	if (cmd != DDI_ATTACH) {
		cmn_err(CE_CONT, "vt: attach: %d: unknown cmd %d\n",
		    unit, cmd);
		return (DDI_FAILURE);
	}
	if (vttab != NULL) {
		cmn_err(CE_CONT,
		    "vt: attach: %d: already attached\n", unit);
		return (DDI_FAILURE);
	}

	for (i = 0; i < VT_COUNTERS; i++) {
		vt_mem_counters[i] = 0;
	}

	/* get number of units, must use DDI_DEV_T_ANY */
	length = sizeof (nunits);
	if ((error = ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    0, VTNUNITS, (caddr_t)&nunits, &length)) != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "vt: attach: %d: could not get nunits prop, error %d\n",
		    unit, error);
		goto out;
	}

	vt_nunits = nunits;

	/* create the vttab array */
	vttab = (struct vt_tab *)kmem_alloc(sizeof (struct vt_tab) * nunits,
	    KM_SLEEP);
	bzero((caddr_t)vttab, sizeof (struct vt_tab) * nunits);

	/* init each unit */
	for (unit = 0; unit < nunits; unit++) {

		tp = &vttab[unit];

		/* initialize locks, and save dev info */
		rw_init(&tp->vt_rwlock, VTRWLOCK, RW_DEFAULT, NULL);
		mutex_init(&tp->vt_lab_mx, VT_LABEL_MUTEX, MUTEX_DRIVER, NULL);
		tp->vt_dip = dip;

		/* create minor nodes */
		if (unit == 0) {
			nm = VTCTLNAME;
		} else {
			nm =  sprintf(namebuf, "%d", unit);
		}

		if ((error = ddi_create_minor_node(dip, nm, S_IFCHR, unit,
		    DDI_PSEUDO, 0)) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
		"vt: attach: %d: ddi_create_minor_node '%s' failed\n",
				unit, nm);
			goto out;
		}
	}

	vt_events.kve_next = (struct kvt_event *)&vt_events;

	/* cleanup or return success */
out:
	if (error != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		if (tp != NULL) {
			bzero((caddr_t)tp, sizeof (*tp));
		}
	} else {
		ddi_report_dev(dip);
	}
	return (error);
}


static int
vtdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		unit = ddi_get_instance(dip);
	struct vt_tab	*tp;
	int		i, j;

	DPRINTF("vt: detach: %d: dip %x cmd %d\n", unit, (int)dip, (int)cmd);

	/* check unit */
	if (unit != 0) {
		return (ENXIO);
	}

	/* process command */
	switch (cmd) {

	/* cleanup and detach */
	case DDI_DETACH:
	/* Check to see if there are any open devices. */
	for (i = 0; (i < vt_nunits); ++i) {
		tp = &vttab[i];
		for (j = 0; j < OTYPCNT; j++) {
			if (tp->vt_ocnt[j] != 0) {
				DPRINTF(
					"vt: _fini: unit/type %d/%d ocnt=%d\n",
					i, j, tp->vt_ocnt[j]);
					return (DDI_FAILURE);
			}
		}
	}
		for (i = 0; i < vt_nunits; i++) {
			tp = &vttab[i];
			rw_destroy(&tp->vt_rwlock);
			mutex_destroy(&tp->vt_lab_mx);
			if (tp->vt_label != NULL) {
				kmem_free(tp->vt_label, tp->vt_lablen);
				/* clean up -- just in case */
				tp->vt_label = NULL;
				tp->vt_lablen = 0;
			}
			if (tp->vt_name != NULL) {
				kmem_free(tp->vt_name, tp->vt_namelen);
				tp->vt_name = NULL;
				tp->vt_namelen = 0;
			}
			if (tp->vt_toc != NULL) {
				kmem_free(tp->vt_toc, sizeof (struct vt_vtoc));
				tp->vt_toc = NULL;
			}
			if (tp->vt_toc_entries != NULL) {
				kmem_free(tp->vt_toc_entries,
				    tp->vt_entry_count *
				    sizeof (struct cdrom_tocentry));
				tp->vt_toc_entries = NULL;
				tp->vt_entry_count = 0;
			}
		}
		kmem_free(vttab, sizeof (struct vt_tab) * vt_nunits);
		vttab = NULL;
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_CONT, "vt: detach: %d: unknown cmd %d\n",
		    unit, cmd);
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
vtinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int		unit = getminor((dev_t)arg);
	struct vt_tab	*tp;
	int		error = DDI_SUCCESS;


	DPRINTF3("vt: info: dip %x cmd %d arg %x (%d.%d) result %x\n",
	    (int)dip, (int)cmd, (int)arg, (int)getmajor((dev_t)arg),
	    unit, (int)result);

	/* check unit, grab lock */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}
	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_READER);

	/* process command */
	switch (cmd) {

	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)tp->vt_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)unit;
		break;

	default:
		cmn_err(CE_CONT, "vt: info: %d: unknown cmd %d\n",
		    unit, cmd);
		error = DDI_FAILURE;
		break;
	}

	/* release lock, return success */
	rw_exit(&tp->vt_rwlock);
	return (error);
}


/*
 * Common entry points
 */

/* ARGSUSED3 */
static int
vtopen(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int		unit = getminor(*devp);
	struct vt_tab	*tp;
	int		error = 0;


	DPRINTF("vt: open: devp %x (%d.%d) flag %x otyp %x credp %x\n",
	    (int)devp, (int)getmajor(*devp), unit, flag, otyp, (int)credp);

	/* check unit, grab lock */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}
	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_READER);

	/* check type and flags */
	if ((otyp < 0) || (otyp >= OTYPCNT) || (otyp == OTYP_SWP)) {
		error = EINVAL;
		goto out;
	}

	if (((flag & FEXCL) && (tp->vt_flags & ST_OPEN)) ||
	    (tp->vt_flags & ST_EXCL)) {
		error = EBUSY;
		goto out;
	}

	rw_exit(&tp->vt_rwlock);
	/* window */
	rw_enter(&tp->vt_rwlock, RW_WRITER);

	/* count and flag open */
	tp->vt_ocnt[otyp]++;

	tp->vt_flags |= ST_OPEN;
	if (flag & FEXCL) {
		tp->vt_flags |= ST_EXCL;
	}

	/* release lock, return success */
out:
	rw_exit(&tp->vt_rwlock);
	return (error);
}


/* ARGSUSED3 */
static int
vtclose(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		unit = getminor(dev);
	struct vt_tab	*tp;
	int		i;


	DPRINTF("vt: close: dev %d.%d flag %x otyp %x credp %x\n",
	    (int)getmajor(dev), unit, flag, otyp, (int)credp);

	/* check unit, grab lock */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}

	/* check type and flags */
	if ((otyp < 0) || (otyp >= OTYPCNT)) {
		return (EINVAL);
	}

	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_WRITER);

	/* count and flag closed */
	if (otyp == OTYP_LYR) {
		tp->vt_ocnt[otyp]--;
	} else {
		tp->vt_ocnt[otyp] = 0;
	}
	tp->vt_flags &= ~ST_OPEN;

	for (i = 0; i < OTYPCNT; i++) {
		if (tp->vt_ocnt[i] != 0) {
			tp->vt_flags |= ST_OPEN;
		}
	}

	if (!(tp->vt_flags & ST_OPEN)) {
		tp->vt_flags &= ~ST_EXCL;
	}

	rw_exit(&tp->vt_rwlock);

	if (unit == 0) {
		/* clear out any waiters */
		mutex_enter(&vtnm_mut);
		vtnm_dev = NODEV;
		cv_signal(&vtnm_read_cv);
		cv_signal(&vtnm_write_cv);
		mutex_exit(&vtnm_mut);
	}

	return (0);
}


static int
vtstrategy(struct buf *bp)
{
	DPRINTF("vt: strategy: bp %x dev %d.%d off %lu len %d\n",
	    (int)bp, (int)getmajor(bp->b_edev), (int)getminor(bp->b_edev),
	    dbtob(bp->b_blkno), bp->b_bcount);

	/* we really should update the various things ... */
	return (ENXIO);
}


/* ARGSUSED */
static int
vtread(dev_t dev, struct uio *uiop, cred_t *credp)
{
	static long	bytes_to_move(struct vt_tab *, struct uio *, int *);
	long		byte_count;
	int		unit = getminor(dev);
	struct vt_tab	*tp;
	int		error = 0;
	int		buf[VTBUFSIZE];
	size_t		buf_size = sizeof (buf);
	int		i;
	long		name_label_len;



	DPRINTF("vt: read: dev %d.%d uiop %x credp %x\n",
	    (int)getmajor(dev), unit, (int)uiop, (int)credp);

	/* check unit */
	if ((unit < 0) || (unit >= vt_nunits)) {
		error = ENXIO;
		goto out;
	}

	/* ensure unit is open */
	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_READER);
	if (!(tp->vt_flags & ST_OPEN)) {
		error = ENXIO;
		rw_exit(&tp->vt_rwlock);
		goto out;
	}

	/* transfer data */

	mutex_enter(&tp->vt_lab_mx);

	/* transfer the label (or our name if no label) */
	if (tp->vt_label != NULL) {

		/* we have a fake label -- return that */

		DPRINTF2("vt: read: reading fake label\n");

		while ((uiop->uio_resid != 0) &&
		    (uiop->uio_offset < tp->vt_lablen)) {

			/* figure out how many bytes to copy */
			byte_count = bytes_to_move(tp, uiop, &error);
			if (error != 0) {
				DPRINTF2("vt: generating read error %d\n",
				    error);
				break;
			}

			DPRINTF2("vt: read: returning %ld bytes\n", byte_count);

			/* copy label to user */
			if ((error = uiomove(
			    (caddr_t)tp->vt_label + uiop->uio_offset,
			    byte_count, UIO_READ, uiop)) != 0) {
				DPRINTF2("vt: label read error %d\n", error);
				break;
			}
		}

	} else {

		/* we don't have a fake label -- return our name */

		/* get length of our name (to be returned to caller) */
		name_label_len = tp->vt_namelen - 1;

		DPRINTF2("vt: read: returning name/label \"%s\" (%ld bytes)\n",
		    tp->vt_name, name_label_len);

		while ((uiop->uio_resid != 0) &&
		    (uiop->uio_offset < name_label_len)) {

			/* copy fake label to user */
			error = uiomove((caddr_t)tp->vt_name,
			    min(name_label_len, uiop->uio_resid), UIO_READ,
			    uiop);
			if (error != 0) {
				DPRINTF2("vt: name/label read error %d\n",
				    error);
				break;
			}
		}
	}

	mutex_exit(&tp->vt_lab_mx);
	rw_exit(&tp->vt_rwlock);

	/* if there's still work to do ... */
	if (uiop->uio_resid != 0) {

		DPRINTF2("vt: read: %d bytes left\n", uiop->uio_resid);

		/* fill a buf with user-specified tag */
		rw_enter(&tp->vt_rwlock, RW_READER);
		for (i = 0; i < VTBUFSIZE; i++) {
			buf[i] = tp->vt_tag;
		}
		rw_exit(&tp->vt_rwlock);

#ifdef	DEBUG
		DPRINTF2("vt: read: %d words (%d bytes) set to 0x%x\n",
			VTBUFSIZE, VTBUFSIZE * sizeof (int), tp->vt_tag);
#endif

		/* send the rest of the data to the user */
		while (uiop->uio_resid != 0) {

			/* figure out how many bytes to xfer to caller */
			rw_enter(&tp->vt_rwlock, RW_READER);
			mutex_enter(&tp->vt_lab_mx);
			byte_count = bytes_to_move(tp, uiop, &error);
			mutex_exit(&tp->vt_lab_mx);
			rw_exit(&tp->vt_rwlock);

			if (error != 0) {
				DPRINTF2("vt: generating read error %d\n",
				    error);
				break;
			}

			DPRINTF2("vt: read: returning %lu bytes\n",
			    min(buf_size, byte_count));

			/* copy tag data to user */
			error = uiomove((caddr_t)buf,
			    min(buf_size, byte_count), UIO_READ, uiop);
			if (error != 0) {
				DPRINTF2("vt: data read error %d\n", error);
				break;
			}
		}
	}

	/* return status */
out:
#ifdef	DEBUG
	DPRINTF2("vt: read: returning %d\n", error);
#endif
	return (error);
}


/* ARGSUSED */
static int
vtwrite(dev_t dev, struct uio *uiop, cred_t *credp)
{
	/*
	 * simulate writes by taking each block "written" and enqueueing
	 * it "up" to vold (though /dev/voltestdrv, into dev_test.so.1)
	 */
	int			unit = getminor(dev);
	struct vt_tab		*tp;
	int			error = 0;
	int			buf[VTBUFSIZE];
	int			n;
	int			i;
	struct ve_wrterr	vwe;



	DPRINTF("vt: write: dev %d.%d uiop %x credp %x\n",
	    (int)getmajor(dev), unit, (int)uiop, (int)credp);

	/* check unit */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}
	/* ensure unit is open (locking struct to check) */
	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_READER);
	if (!(tp->vt_flags & ST_OPEN)) {
		error = ENXIO;
		rw_exit(&tp->vt_rwlock);
		goto out;
	}
	rw_exit(&tp->vt_rwlock);

	/* get the data from the user and see if it's good stuff */
	while (uiop->uio_resid != 0) {

		n = min(VTBUFSIZE * sizeof (int), uiop->uio_resid);

		if ((error = uiomove((caddr_t)buf, n, UIO_WRITE, uiop)) != 0) {
			break;
		}

		for (i = 0; i < (n / sizeof (int)); i++) {

			rw_enter(&tp->vt_rwlock, RW_READER);
			if (buf[i] != tp->vt_tag) {
				vwe.vwe_unit = unit;
				rw_exit(&tp->vt_rwlock);
				vwe.vwe_want = tp->vt_tag;
				vwe.vwe_got = buf[i];
				vt_enqueue(VSE_WRTERR, (void *)&vwe);
			} else {
				rw_exit(&tp->vt_rwlock);
			}
		}
	}

	/* return results */
out:
	return (error);
}


static int
vtprop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		unit = ddi_get_instance(dip);
	struct vt_tab	*tp;
	int		error = 0;


	DPRINTF3("vt: prop_op: dev %d.%d dip %x prop_op %d flags %x\n",
	    (int)getmajor(dev), (int)getminor(dev), (int)dip, (int)prop_op,
	    flags);
	DPRINTF3("     name '%s' valuep %x lengthp %x\n",
	    name, (int)valuep, (int)lengthp);

	/* check unit, must use dip as dev could be a wildcard, grab lock */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}
	tp = &vttab[unit];
	rw_enter(&tp->vt_rwlock, RW_READER);

	/* send our props on to ddi_prop_op */
	if ((strcmp(name, "name") == 0) || (strcmp(name, "parent") == 0)) {
		error = ddi_prop_op(dev, dip, prop_op, flags,
		    name, valuep, lengthp);
		goto out;
	}

	/* release lock, return error */
out:
	rw_exit(&tp->vt_rwlock);
	return (error);
}



/* ARGSUSED */
static int
vtioctl(dev_t dev, int cmd, int arg, int mode, cred_t *credp, int *rvalp)
{
	int		unit = getminor(dev);
	struct vt_tab	*tp, *vtp;
	int		error = 0;
	char		buf[VTMAXNAMLEN];
	size_t		length;


	DPRINTF(
	    "vt: ioctl: dev %d.%d cmd %x arg %x mode %x\n",
	    (int)getmajor(dev), unit, cmd, arg, mode);

	/* check unit, grab lock */
	if ((unit < 0) || (unit >= vt_nunits)) {
		return (ENXIO);
	}

	tp = &vttab[unit];

	rw_enter(&tp->vt_rwlock, RW_READER);

	if (!(tp->vt_flags & ST_OPEN)) {
		error = ENXIO;
		rw_exit(&tp->vt_rwlock);
		goto out;
	}

	rw_exit(&tp->vt_rwlock);

	if (unit == 0) {

		/*
		 * unit-0 ioctls: these are meta-ioctls, used to talk
		 * to the test driver itself
		 */

		switch (cmd) {

		case VTIOCLABEL:
		case VTIOCLABEL_OLD:
		{
			struct vt_lab	vtl;
			char		*lab;

			DPRINTF2("vt: entering VTIOCLABEL\n");

			if ((error = copyin((caddr_t)arg, (caddr_t)&vtl,
			    sizeof (struct vt_lab))) != 0) {
				goto out;
			}

			if ((vtl.vtl_len > 0) && (vtl.vtl_label != NULL)) {

				DPRINTF2("vt: label length is %d\n",
				    vtl.vtl_len);

				if (vtl.vtl_len > vt_too_much) {
					DPRINTF2(
				"vt: VTIOCLABEL too much memory error.\n");
					vt_mem_counters[VT_LABEL_TM_SFX]++;
					error = ENOMEM;
					goto out;
				}
				lab = (char *)kmem_alloc(vtl.vtl_len,
				    KM_SLEEP);
				if ((error = copyin((caddr_t)vtl.vtl_label,
				    lab, vtl.vtl_len)) != 0) {
					kmem_free(lab, vtl.vtl_len);
					goto out;
				}
			} else {
				lab = NULL;
				vtl.vtl_len = 0;
			}
			vtp = &vttab[vtl.vtl_unit];
			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			mutex_enter(&tp->vt_lab_mx);
			if (vtp->vt_label != NULL) {
				kmem_free(vtp->vt_label, vtp->vt_lablen);
			}
			vtp->vt_label_errno = vtl.vtl_errno;
			vtp->vt_error_length = vtl.vtl_readlen;
			vtp->vt_lablen = vtl.vtl_len;
			vtp->vt_label = lab;
			mutex_exit(&tp->vt_lab_mx);
			rw_exit(&vtp->vt_rwlock);
			break;
		}

		case VTIOCNAME:
		case VTIOCNAME_OLD:
		{
			struct vt_name	vtn;
			int		unit;

			if ((error = copyin((caddr_t)arg, (caddr_t)&vtn,
			    sizeof (struct vt_name))) != 0) {
				goto out;
			}
			unit = vtn.vtn_unit;
			if ((error = copyinstr(vtn.vtn_name, buf, VTMAXNAMLEN,
			    &length)) != 0) {
				goto out;
			}

			DPRINTF2("vt: VTIOCNAME: unit %d: %s (len %d)\n",
			    unit, buf, length-1);

			if (unit == 0) {
				DPRINTF("vt: unit 0 is bogus!\n");
				error = EINVAL;
				goto out;
			}

			vtp = &vttab[unit];

			rw_enter(&vtp->vt_rwlock, RW_READER);

			if (vtp->vt_inserted != FALSE) {
				rw_exit(&vtp->vt_rwlock);
				error = EBUSY;
				goto out;
			}
			rw_exit(&vtp->vt_rwlock);
			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			if (vtp->vt_name != NULL) {
				kmem_free(vtp->vt_name, vtp->vt_namelen);
			}
			if (length > vt_too_much) {
				rw_exit(&vtp->vt_rwlock);
				DPRINTF2(
				    "vt: VTIOCNAME too much memory error.\n");
				vt_mem_counters[VT_NAME_TM_SFX]++;
				error = ENOMEM;
				goto out;
			}
			vtp->vt_namelen = length;	/* counting null */
			vtp->vt_name = (char *)kmem_alloc(vtp->vt_namelen,
			    KM_SLEEP);
			strcpy(vtp->vt_name, buf);
			vtp->vt_inserted = TRUE;
			vtp->vt_tag = unit;	/* default tag */
			rw_exit(&vtp->vt_rwlock);

			mutex_enter(&vtnm_mut);
			while (vtnm_dev != 0) {
				if (cv_wait_sig(&vtnm_write_cv,
				    &vtnm_mut) == 0) {
					error = EINTR;
					break;
				}
				if (vtnm_dev == NODEV) {
					error = EINTR;
					break;
				}
			}
			if (error == 0) {
				/*
				 * pass info to waiting event thread (if any)
				 */
				vtnm_dev = unit;
				cv_signal(&vtnm_read_cv);
			}
			mutex_exit(&vtnm_mut);
			break;
		}

		case VTIOCTAG:
		case VTIOCTAG_OLD:
		{
			struct vt_tag vtt;

			if ((error = copyin((caddr_t)arg, (caddr_t)&vtt,
			    sizeof (struct vt_tag))) != 0) {
				goto out;
			}

			vtp = &vttab[vtt.vtt_unit];

			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			vtp->vt_tag = vtt.vtt_tag;
			rw_exit(&vtp->vt_rwlock);

			DPRINTF2("vt: VTIOCTAG: unit %lu tag set to 0x%x\n",
			    vtt.vtt_unit, vtt.vtt_tag);

			break;
		}

		case VTIOCEVENT:
		case VTKIOCEVENT:
		case VTIOCEVENT_OLD:
		case VTKIOCEVENT_OLD:
		{
			struct vt_event vte;

			DPRINTF2("vt: entering VTIOCEVENT\n");
			mutex_enter(&vtnm_mut);
			while (vtnm_dev == 0) {
				if (cv_wait_sig(&vtnm_read_cv,
				    &vtnm_mut) == 0) {
					break;
				}
			}
			if ((vtnm_dev == NODEV) || (vtnm_dev == 0)) {
				error = EINTR;
			}

			vte.vte_dev = vtnm_dev;
			vtnm_dev = 0;
			cv_signal(&vtnm_write_cv);
			mutex_exit(&vtnm_mut);
			if (error != 0) {
				break;
			}
			DPRINTF2("vt: got an event, co to 0x%x\n", arg);

			if (cmd == VTKIOCEVENT) {
				bcopy((caddr_t)&vte, (caddr_t)arg,
				    sizeof (struct vt_event));
			} else {
				error = copyout((caddr_t)&vte, (caddr_t)arg,
				    sizeof (struct vt_event));
			}
			break;
		}

		case VTIOCSVTOC:
		case VTIOCSVTOC_OLD:
		{
			struct vt_vtdes	toc_des;
			struct vt_vtoc	*toc;

			DPRINTF2("vt: entered VTIOCSVTOC\n");
			if ((error = copyin((caddr_t)arg, (caddr_t)&toc_des,
			    sizeof (struct vt_vtdes))) != 0) {
				goto out;
			}
			toc = (struct vt_vtoc *)kmem_alloc(
			    sizeof (struct vt_vtoc), KM_SLEEP);
			DPRINTF2("vt: have memory for struct vt_vtoc.\n");
			*toc = toc_des.vtvd_vtoc;
			vtp = &vttab[toc_des.vtvd_unit];
			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			if (vtp->vt_toc != NULL) {
				DPRINTF2("vt: freeing previous vt_vtoc.\n");
				kmem_free(vtp->vt_toc,
				    sizeof (struct vt_vtoc));
			}
			vtp->vt_toc = toc;
			rw_exit(&vtp->vt_rwlock);
			DPRINTF2("vt: leaving VTIOCSVTOC");
			break;
		}

		case VTIOCSTOCHDR:
		case VTIOCSTOCHDR_OLD:
		{
			struct vt_tochdr	header_data;

			DPRINTF2("vt: entered VTIOCSTOCHDR\n");
			if ((error = copyin((caddr_t)arg,
			    (caddr_t)&header_data,
			    sizeof (struct vt_tochdr))) != 0) {
				goto out;
			}
			DPRINTF2("vt: VTIOCSTOCHDR copyin succeeded\n");
			vtp = &vttab[header_data.vtt_unit];
			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			vtp->vt_tochdrinfo = header_data.vtt_toc;
			rw_exit(&vtp->vt_rwlock);
			DPRINTF2("vt: leaving VTIOCSTOCHDR\n");
			break;
		}

		case VTIOCSTOCENTRIES:
		case VTIOCSTOCENTRIES_OLD:
		{
			struct vt_tedes		entry_des;
			struct cdrom_tocentry	*entries = NULL;

			DPRINTF2("vt: entered VTIOCSTOCENTRIES\n");
			if ((error = copyin((caddr_t)arg, (caddr_t)&entry_des,
			    sizeof (struct vt_tedes))) != 0) {
				goto out;
			}
			if (entry_des.vttd_count > 0) {

				DPRINTF2("vt: length of toc entries=%x\n",
				    sizeof (struct cdrom_tocentry) *
				    entry_des.vttd_count);

				if ((sizeof (struct cdrom_tocentry) *
				    entry_des.vttd_count) > vt_too_much) {
					DPRINTF2(
		"vt: VTIOCSTOCENTRIES too much memory error.  %d entries.\n",
					    entry_des.vttd_count);
					vt_mem_counters[VT_TOCE_TM_SFX]++;
					error = ENOMEM;
					goto out;
				}
				entries = (struct cdrom_tocentry *)kmem_alloc(
				    sizeof (struct cdrom_tocentry) *
				    entry_des.vttd_count, KM_SLEEP);

				DPRINTF2(
			"vt: have memory for struct cdrom_tocentry.\n");

				if ((error = copyin(
				    (caddr_t)entry_des.vttd_entries,
				    (caddr_t)entries,
				    sizeof (struct cdrom_tocentry) *
				    entry_des.vttd_count)) != 0) {
					goto out;
				}
			}
			vtp = &vttab[entry_des.vttd_unit];
			rw_enter(&vtp->vt_rwlock, RW_WRITER);
			if (vtp->vt_toc_entries != NULL) {
				DPRINTF2(
				    "vt: freeing previous vt_toc_entries\n");
				kmem_free(vtp->vt_toc_entries,
				    vtp->vt_entry_count *
				    sizeof (struct cdrom_tocentry));
			}
			vtp->vt_entry_errno = entry_des.vttd_errno;
			vtp->vt_error_track = entry_des.vttd_err_track;
			vtp->vt_entry_count = entry_des.vttd_count;
			vtp->vt_toc_entries = entries;
			rw_exit(&vtp->vt_rwlock);
			DPRINTF2("vt: leaving VTIOCSTOCENTRIES\n");
			break;
		}

		case VTIOCUNITS:
		case VTIOCUNITS_OLD:
			error = copyout((caddr_t)&vt_nunits, (caddr_t)arg,
			    sizeof (uint_t));
			break;

		/*
		 * Get an event.  This is used by calling this
		 * ioctl until it returns EWOULDBLOCK.  poll(2)
		 * is the mechanism for waiting around for an
		 * event to happen.
		 */
		case VTIOCSTATUS:
		case VTIOCSTATUS_OLD:
		{
			struct kvt_event *kve = NULL;

			DPRINTF2("vt: entering VTIOCSTATUS\n");
			mutex_enter(&vt_evmutex);
			if (vt_evcnt != 0) {
				kve = vt_events.kve_next;
				vt_evcnt--;
				remque(kve);
			}
			mutex_exit(&vt_evmutex);
			if (kve != NULL) {
				error = copyout((caddr_t)&kve->kve_event,
				    (caddr_t)arg, sizeof (struct vt_status));
				if (error != 0) {
					/* add it back on error */
					mutex_enter(&vt_evmutex);
					insque(kve, &vt_events);
					vt_evcnt++;
					mutex_exit(&vt_evmutex);
					DPRINTF("event: copyout %d\n", error);
					break;
				}

				kmem_free(kve, sizeof (struct kvt_event));
			} else {
				error = EWOULDBLOCK;
			}
			break;
		}

		default:
			error = ENOTTY;
			goto out;
		}

	} else {

		/*
		 * non-unit-0 ioctls -- in general, we're emulating a device
		 * with these ioctls, since all non-unit-0 units are
		 * test devices
		 */

		switch (cmd) {

		case CDROMEJECT:
		case FDEJECT:
		case DKIOCEJECT:
			/* mark our unit as ejected */
			rw_enter(&tp->vt_rwlock, RW_WRITER);
			tp->vt_inserted = FALSE;
			rw_exit(&tp->vt_rwlock);
			break;

		case CDROMREADTOCHDR:
		{
			struct cdrom_tochdr header;

			DPRINTF2("vt: CDROMREADTOCHDR entered on unit %d\n",
			    unit);
			rw_enter(&tp->vt_rwlock, RW_READER);
			if ((error = tp->vt_tochdrinfo.vttoc_errno) == 0) {
				header = tp->vt_tochdrinfo.vttoc_hdr;
			}
			rw_exit(&tp->vt_rwlock);

			if (error == 0) {
				DPRINTF2("vt: copying out cdrom_tochdr\n");
				error = copyout((caddr_t)&header,
				    (caddr_t)arg,
				    sizeof (struct cdrom_tochdr));
				if (error != 0) {
					DPRINTF2(
				"vt: copy out cdrom_tochdr error %d\n",
					    error);
				}
			}
			break;
		}

		case CDROMREADTOCENTRY:
		{
			struct cdrom_tocentry	entry;
			unsigned char		track;
			int			entry_number;

			DPRINTF2("vt: CDROMREADTOCENTRY entered on unit %d\n",
			    unit);

			/* copy in the toc entry to get desired track. */
			error = copyin((caddr_t)arg, (caddr_t)&entry,
			    sizeof (struct cdrom_tocentry));
			if (error != 0) {
				break;
			}
			track = entry.cdte_track;
			rw_enter(&tp->vt_rwlock, RW_READER);
			if (tp->vt_toc_entries == NULL) {
				error = ENXIO;
			}
			if (track == CDROM_LEADOUT) {
				entry_number = tp->vt_entry_count - 1;
			} else {
				entry_number = track -
				    tp->vt_tochdrinfo.vttoc_hdr.cdth_trk0;
			}

			if (tp->vt_entry_errno != 0) {
				/*
				 * Simulate errors:
				 * If errno < 0, simulate an error all
				 * tracks using the absolute value for the
				 * error.  If errno > 0, then only simulate
				 * an error on vt_error_track
				 */
				error = tp->vt_entry_errno;
				if (error < 0) {
					error = -error;
				} else {
					if (track != tp->vt_error_track) {
						error = 0;
					}
				}
			}
			if ((entry_number >= 0) && (error == 0)) {
				entry = *(tp->vt_toc_entries + entry_number);
			}
			rw_exit(&tp->vt_rwlock);
			if (error != 0) {
				DPRINTF2(
			"vt: no toc entry for track %d on unit %d\n",
				    track, unit);
				break;
			}
			if (entry_number >= 0) {
				if (track == entry.cdte_track) {
					error = copyout((caddr_t)&entry,
					    (caddr_t)arg,
					    sizeof (struct cdrom_tocentry));
				} else {
					error = ENXIO;
				}
			}
			if (error == 0) {
				DPRINTF2(
			"vt: toc entry for track %d returned for unit %d\n",
				    track, unit);
			}
			DPRINTF2("vt: leaving CDROMREADTOCENTRY for unit %d\n",
			    unit);
			break;
		}

		case DKIOCGVTOC:
		{
			struct vt_vtoc	toc_info;

			DPRINTF2("vt: DKIOCGVTOC entered on unit %d\n", unit);
			rw_enter(&tp->vt_rwlock, RW_READER);
			if (tp->vt_toc == NULL) {
				error = ENXIO;
			} else {
				toc_info = *(tp->vt_toc);
			}
			rw_exit(&tp->vt_rwlock);
			if (error != 0) {
				DPRINTF2("vt: no VTOC available for unit %d\n",
				    unit);
				break;
			}
			if ((error = toc_info.vtvt_errno) == 0) {
				error = copyout((caddr_t)&toc_info.vtvt_vtoc,
				    (caddr_t)arg, sizeof (toc_info.vtvt_vtoc));
				if (error != 0) {
					DPRINTF2("vt: DKIOCGVTOC copyout %d\n",
					    error);
				}
			}
			break;
		}

		case DKIOCSVTOC:
			/*
			 * do not allow setting the VTOC
			 */
			DPRINTF2("vt: DKIOCGVTOC entered on unit %d\n", unit);
			error = EINVAL;
			break;

		default:
			/* XXX: hey, we'll take anything, but should we? */
			DPRINTF2("vt: skipping unknown cmd 0x%x\n", cmd);
			break;
		}

	}

out:
	return (error);
}


vtpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	int		unit = getminor(dev);


	DPRINTF4(
	    "vt: poll: dev %d.%d events 0x%x anyyet 0x%x reventsp 0x%x\n",
	    (int)getmajor(dev), unit, (int)events, anyyet,
	    (int)*reventsp);

	if (unit == 0) {
		if (events & POLLRDNORM) {
			DPRINTF4("vt: poll: got a POLLIN\n");
			mutex_enter(&vt_evmutex);
			if (vt_evcnt != 0) {
				DPRINTF3("vt: poll: we have data\n");
				*reventsp |= POLLIN;
				mutex_exit(&vt_evmutex);
				return (0);
			}
			mutex_exit(&vt_evmutex);
		}
		if (!anyyet) {
			*phpp = &vt_pollhead;
			*reventsp = 0;
		}
		return (0);
	}

	return (ENXIO);
}


static void
vt_enqueue(enum vt_evtype type, void *data)
{
	struct kvt_event 	*kvie;


	kvie = (struct kvt_event *)kmem_alloc(sizeof (struct kvt_event),
	    KM_SLEEP);
	kvie->kve_event.vte_type = type;

	switch (type) {
	case VSE_WRTERR:
		kvie->kve_event.vse_wrterr = *(struct ve_wrterr *)data;
		break;

	default:
		cmn_err(CE_WARN, "vt_enqueue: bad type %d\n", type);
		kmem_free(kvie, sizeof (struct kvt_event));
		return;
	}

	mutex_enter(&vt_evmutex);
	insque(kvie, &vt_events);
	vt_evcnt++;
	mutex_exit(&vt_evmutex);
	pollwakeup(&vt_pollhead, POLLRDNORM);
}


/*
 * called from vtread() to determine how many bytes to copy out
 *
 * assume tp struct is locked in reader mode
 */
static long
bytes_to_move(struct vt_tab *tp, struct uio *uiop, int *error)
{
	long	bytes;


	*error = 0;

	if ((tp->vt_label != NULL) && (uiop->uio_offset < tp->vt_lablen)) {

		/* We are in the label area */

		/*
		 * how many bytes to transfer = number of bytes left to
		 *  xfer for this read, or bytes left in label, which ever
		 *  is smaller
		 */
		bytes = min(uiop->uio_resid,
		    (tp->vt_lablen - uiop->uio_offset));

	} else {

		/* either there's no label, or we're past the label */

		/* bytes to xfer = bytes left to xfer for this read */
		bytes = uiop->uio_resid;
	}

	/* check for an error being requested (iff we have a label) */
	if ((tp->vt_label != NULL) && (tp->vt_label_errno != 0)) {
		/*
		 * it is possible to have an error because this
		 * read may go beyond the designated error point
		 */
		if ((uiop->uio_offset + bytes) > tp->vt_error_length) {
			/*
			 * an error has been requested for a certain
			 * length, and we've reached that length
			 */
			*error = tp->vt_label_errno;
			bytes = tp->vt_error_length - uiop->uio_offset;
			if (bytes < 0) {
				bytes = 0;
			}
		}
	}

	return (bytes);
}

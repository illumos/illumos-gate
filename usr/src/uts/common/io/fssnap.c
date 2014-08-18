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


#include <sys/debug.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/filio.h>
#include <sys/stat.h> /* needed for S_IFBLK and S_IFCHR */
#include <sys/kstat.h>

#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/priv_names.h>

#include <sys/fssnap.h>
#include <sys/fssnap_if.h>

/*
 * This module implements the file system snapshot code, which provides a
 * point-in-time image of a file system for the purposes of online backup.
 * There are essentially two parts to this project: the driver half and the
 * file system half.  The driver half is a pseudo device driver called
 * "fssnap" that represents the snapshot.  Each snapshot is assigned a
 * number that corresponds to the minor number of the device, and a control
 * device with a high minor number is used to initiate snapshot creation and
 * deletion.  For all practical purposes the driver half acts like a
 * read-only disk device whose contents are exactly the same as the master
 * file system at the time the snapshot was created.
 *
 * The file system half provides interfaces necessary for performing the
 * file system dependent operations required to create and delete snapshots
 * and a special driver strategy routine that must always be used by the file
 * system for snapshots to work correctly.
 *
 * When a snapshot is to be created, the user utility will send an ioctl to
 * the control device of the driver half specifying the file system to be
 * snapshotted, the file descriptor of a backing-store file which is used to
 * hold old data before it is overwritten, and other snapshot parameters.
 * This ioctl is passed on to the file system specified in the original
 * ioctl request.  The file system is expected to be able to flush
 * everything out to make the file system consistent and lock it to ensure
 * no changes occur while the snapshot is being created.  It then calls
 * fssnap_create() to create state for a new snapshot, from which an opaque
 * handle is returned with the snapshot locked.  Next, the file system must
 * populate the "candidate bitmap", which tells the snapshot code which
 * "chunks" should be considered for copy-on-write (a chunk is the unit of
 * granularity used for copy-on-write, which is independent of the device
 * and file system block sizes).  This is typically done by scanning the
 * file system allocation bitmaps to determine which chunks contain
 * allocated blocks in the file system at the time the snapshot was created.
 * If a chunk has no allocated blocks, it does not need to be copied before
 * being written to.  Once the candidate bitmap is populated with
 * fssnap_set_candidate(), the file system calls fssnap_create_done() to
 * complete the snapshot creation and unlock the snapshot.  The file system
 * may now be unlocked and modifications to it resumed.
 *
 * Once a snapshot is created, the file system must perform all writes
 * through a special strategy routine, fssnap_strategy().  This strategy
 * routine determines whether the chunks contained by the write must be
 * copied before being overwritten by consulting the candidate bitmap
 * described above, and the "hastrans bitmap" which tells it whether the chunk
 * has been copied already or not.  If the chunk is a candidate but has not
 * been copied, it reads the old data in and adds it to a queue.  The
 * old data can then be overwritten with the new data.  An asynchronous
 * task queue is dispatched for each old chunk read in which writes the old
 * data to the backing file specified at snapshot creation time.  The
 * backing file is a sparse file the same size as the file system that
 * contains the old data at the offset that data originally had in the
 * file system.  If the queue containing in-memory chunks gets too large,
 * writes to the file system may be throttled by a semaphore until the
 * task queues have a chance to push some of the chunks to the backing file.
 *
 * With the candidate bitmap, the hastrans bitmap, the data on the master
 * file system, and the old data in memory and in the backing file, the
 * snapshot pseudo-driver can piece together the original file system
 * information to satisfy read requests.  If the requested chunk is not a
 * candidate, it returns a zeroed buffer.  If the chunk is a candidate but
 * has not been copied it reads it from the master file system.  If it is a
 * candidate and has been copied, it either copies the data from the
 * in-memory queue or it reads it in from the backing file.  The result is
 * a replication of the original file system that can be backed up, mounted,
 * or manipulated by other file system utilities that work on a read-only
 * device.
 *
 * This module is divided into three roughly logical sections:
 *
 *     - The snapshot driver, which is a character/block driver
 *       representing the snapshot itself.  These routines are
 *       prefixed with "snap_".
 *
 *     - The library routines that are defined in fssnap_if.h that
 *       are used by file systems that use this snapshot implementation.
 *       These functions are prefixed with "fssnap_" and are called through
 *       a function vector from the file system.
 *
 *     - The helper routines used by the snapshot driver and the fssnap
 *       library routines for managing the translation table and other
 *       useful functions.  These routines are all static and are
 *       prefixed with either "fssnap_" or "transtbl_" if they
 *       are specifically used for translation table activities.
 */

static dev_info_t		*fssnap_dip = NULL;
static struct snapshot_id	*snapshot = NULL;
static struct snapshot_id	snap_ctl;
static int			num_snapshots = 0;
static kmutex_t			snapshot_mutex;
static char			snapname[] = SNAP_NAME;

/* "tunable" parameters */
static int		fssnap_taskq_nthreads = FSSNAP_TASKQ_THREADS;
static uint_t		fssnap_max_mem_chunks = FSSNAP_MAX_MEM_CHUNKS;
static int		fssnap_taskq_maxtasks = FSSNAP_TASKQ_MAXTASKS;

/* static function prototypes */

/* snapshot driver */
static int snap_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int snap_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int snap_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int snap_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int snap_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int snap_strategy(struct buf *bp);
static int snap_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int snap_print(dev_t dev, char *str);
static int snap_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);
static int snap_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);
static int snap_getchunk(struct snapshot_id *sidp, chunknumber_t chunk,
    int offset, int len, char *buffer);


/* fssnap interface implementations (see fssnap_if.h) */
static void fssnap_strategy_impl(void *, struct buf *);
static void *fssnap_create_impl(chunknumber_t, uint_t, u_offset_t,
    struct vnode *, int, struct vnode **, char *, u_offset_t);
static void fssnap_set_candidate_impl(void *, chunknumber_t);
static int fssnap_is_candidate_impl(void *, u_offset_t);
static int fssnap_create_done_impl(void *);
static int fssnap_delete_impl(void *);

/* fssnap interface support routines */
static int  fssnap_translate(struct snapshot_id **, struct buf *);
static void fssnap_write_taskq(void *);
static void fssnap_create_kstats(snapshot_id_t *, int, const char *,
    const char *);
static int  fssnap_update_kstat_num(kstat_t *, int);
static void fssnap_delete_kstats(struct cow_info *);

/* translation table prototypes */
static cow_map_node_t *transtbl_add(cow_map_t *, chunknumber_t, caddr_t);
static cow_map_node_t *transtbl_get(cow_map_t *, chunknumber_t);
static void transtbl_delete(cow_map_t *, cow_map_node_t *);
static void transtbl_free(cow_map_t *);

static kstat_t *fssnap_highwater_kstat;

/* ************************************************************************ */

/* Device and Module Structures */

static struct cb_ops snap_cb_ops = {
	snap_open,
	snap_close,
	snap_strategy,
	snap_print,
	nodev,		/* no snap_dump */
	snap_read,
	nodev,		/* no snap_write */
	snap_ioctl,
	nodev,		/* no snap_devmap */
	nodev,		/* no snap_mmap   */
	nodev,		/* no snap_segmap */
	nochpoll,
	snap_prop_op,
	NULL,		/* streamtab */
	D_64BIT | D_NEW | D_MP, /* driver compatibility */
	CB_REV,
	nodev,		/* async I/O read entry point */
	nodev		/* async I/O write entry point */
};

static struct dev_ops snap_ops = {
	DEVO_REV,
	0,			/* ref count */
	snap_getinfo,
	nulldev,		/* snap_identify obsolete */
	nulldev,		/* no snap_probe */
	snap_attach,
	snap_detach,
	nodev,			/* no snap_reset */
	&snap_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,		/* no snap_power() */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops, /* Type of module. This is a driver */
	"snapshot driver", 	/* Name of the module */
	&snap_ops,
};

static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

static void *statep;

int
_init(void)
{
	int	error;
	kstat_t	*ksp;
	kstat_named_t	*ksdata;

	error = ddi_soft_state_init(&statep, sizeof (struct snapshot_id *), 1);
	if (error) {
		cmn_err(CE_WARN, "_init: failed to init ddi_soft_state.");
		return (error);
	}

	error = mod_install(&ml);

	if (error) {
		cmn_err(CE_WARN, "_init: failed to mod_install.");
		ddi_soft_state_fini(&statep);
		return (error);
	}

	/*
	 * Fill in the snapshot operations vector for file systems
	 * (defined in fssnap_if.c)
	 */

	snapops.fssnap_create = fssnap_create_impl;
	snapops.fssnap_set_candidate = fssnap_set_candidate_impl;
	snapops.fssnap_is_candidate = fssnap_is_candidate_impl;
	snapops.fssnap_create_done = fssnap_create_done_impl;
	snapops.fssnap_delete = fssnap_delete_impl;
	snapops.fssnap_strategy = fssnap_strategy_impl;

	mutex_init(&snapshot_mutex, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Initialize the fssnap highwater kstat
	 */
	ksp = kstat_create(snapname, 0, FSSNAP_KSTAT_HIGHWATER, "misc",
	    KSTAT_TYPE_NAMED, 1, 0);
	if (ksp != NULL) {
		ksdata = (kstat_named_t *)ksp->ks_data;
		kstat_named_init(ksdata, FSSNAP_KSTAT_HIGHWATER,
		    KSTAT_DATA_UINT32);
		ksdata->value.ui32 = 0;
		kstat_install(ksp);
	} else {
		cmn_err(CE_WARN, "_init: failed to create highwater kstat.");
	}
	fssnap_highwater_kstat = ksp;

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&ml);
	if (error)
		return (error);
	ddi_soft_state_fini(&statep);

	/*
	 * delete the fssnap highwater kstat
	 */
	kstat_delete(fssnap_highwater_kstat);

	mutex_destroy(&snapshot_mutex);

	/* Clear out the file system operations vector */
	snapops.fssnap_create = NULL;
	snapops.fssnap_set_candidate = NULL;
	snapops.fssnap_create_done = NULL;
	snapops.fssnap_delete = NULL;
	snapops.fssnap_strategy = NULL;

	return (0);
}

/* ************************************************************************ */

/*
 * Snapshot Driver Routines
 *
 * This section implements the snapshot character and block drivers.  The
 * device will appear to be a consistent read-only file system to
 * applications that wish to back it up or mount it.  The snapshot driver
 * communicates with the file system through the translation table, which
 * tells the snapshot driver where to find the data necessary to piece
 * together the frozen file system.  The data may either be on the master
 * device (no translation exists), in memory (a translation exists but has
 * not been flushed to the backing store), or in the backing store file.
 * The read request may require the snapshot driver to retrieve data from
 * several different places and piece it together to look like a single
 * contiguous read.
 *
 * The device minor number corresponds to the snapshot number in the list of
 * snapshot identifiers.  The soft state for each minor number is simply a
 * pointer to the snapshot id, which holds all of the snapshot state.  One
 * minor number is designated as the control device.  All snapshot create
 * and delete requests go through the control device to ensure this module
 * is properly loaded and attached before the file system starts calling
 * routines defined here.
 */


/*
 * snap_getinfo() - snapshot driver getinfo(9E) routine
 *
 */
/*ARGSUSED*/
static int
snap_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = fssnap_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;	/* we only have one instance */
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * snap_attach() - snapshot driver attach(9E) routine
 *
 *    sets up snapshot control device and control state.  The control state
 *    is a pointer to an "anonymous" snapshot_id for tracking opens and closes
 */
static int
snap_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			error;

	switch (cmd) {
	case DDI_ATTACH:
		/* create the control device */
		error = ddi_create_priv_minor_node(dip, SNAP_CTL_NODE, S_IFCHR,
		    SNAP_CTL_MINOR, DDI_PSEUDO, PRIVONLY_DEV,
		    PRIV_SYS_CONFIG, PRIV_SYS_CONFIG, 0666);
		if (error == DDI_FAILURE) {
			return (DDI_FAILURE);
		}

		rw_init(&snap_ctl.sid_rwlock, NULL, RW_DEFAULT, NULL);
		rw_enter(&snap_ctl.sid_rwlock, RW_WRITER);
		fssnap_dip = dip;
		snap_ctl.sid_snapnumber = SNAP_CTL_MINOR;
		/* the control sid is not linked into the snapshot list */
		snap_ctl.sid_next = NULL;
		snap_ctl.sid_cowinfo = NULL;
		snap_ctl.sid_flags = 0;
		rw_exit(&snap_ctl.sid_rwlock);
		ddi_report_dev(dip);

		return (DDI_SUCCESS);
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * snap_detach() - snapshot driver detach(9E) routine
 *
 *    destroys snapshot control device and control state.  If any snapshots
 *    are active (ie. num_snapshots != 0), the device will refuse to detach.
 */
static int
snap_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct snapshot_id *sidp, *sidnextp;

	switch (cmd) {
	case DDI_DETACH:
		/* do not detach if the device is active */
		mutex_enter(&snapshot_mutex);
		if ((num_snapshots != 0) ||
		    ((snap_ctl.sid_flags & SID_CHAR_BUSY) != 0)) {
			mutex_exit(&snapshot_mutex);
			return (DDI_FAILURE);
		}

		/* free up the snapshot list */
		for (sidp = snapshot; sidp != NULL; sidp = sidnextp) {
			ASSERT(SID_AVAILABLE(sidp) &&
			    !RW_LOCK_HELD(&sidp->sid_rwlock));
			sidnextp = sidp->sid_next;
			rw_destroy(&sidp->sid_rwlock);
			kmem_free(sidp, sizeof (struct snapshot_id));
		}
		snapshot = NULL;

		/* delete the control device */
		ddi_remove_minor_node(dip, SNAP_CTL_NODE);
		fssnap_dip = NULL;

		ASSERT((snap_ctl.sid_flags & SID_CHAR_BUSY) == 0);
		rw_destroy(&snap_ctl.sid_rwlock);
		mutex_exit(&snapshot_mutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * snap_open() - snapshot driver open(9E) routine
 *
 *     marks the snapshot id as busy so it will not be recycled when deleted
 *     until the snapshot is closed.
 */
/* ARGSUSED */
static int
snap_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	minor_t	minor;
	struct snapshot_id **sidpp, *sidp;

	/* snapshots are read-only */
	if (flag & FWRITE)
		return (EROFS);

	minor = getminor(*devp);

	if (minor == SNAP_CTL_MINOR) {
		/* control device must be opened exclusively */
		if (((flag & FEXCL) != FEXCL) || (otyp != OTYP_CHR))
			return (EINVAL);

		rw_enter(&snap_ctl.sid_rwlock, RW_WRITER);
		if ((snap_ctl.sid_flags & SID_CHAR_BUSY) != 0) {
			rw_exit(&snap_ctl.sid_rwlock);
			return (EBUSY);
		}

		snap_ctl.sid_flags |= SID_CHAR_BUSY;
		rw_exit(&snap_ctl.sid_rwlock);

		return (0);
	}

	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL)
		return (ENXIO);
	sidp = *sidpp;
	rw_enter(&sidp->sid_rwlock, RW_WRITER);

	if ((flag & FEXCL) && SID_BUSY(sidp)) {
		rw_exit(&sidp->sid_rwlock);
		return (EAGAIN);
	}

	ASSERT(sidpp != NULL && sidp != NULL);
	/* check to see if this snapshot has been killed on us */
	if (SID_INACTIVE(sidp)) {
		cmn_err(CE_WARN, "snap_open: snapshot %d does not exist.",
		    minor);
		rw_exit(&sidp->sid_rwlock);
		return (ENXIO);
	}

	switch (otyp) {
	case OTYP_CHR:
		sidp->sid_flags |= SID_CHAR_BUSY;
		break;
	case OTYP_BLK:
		sidp->sid_flags |= SID_BLOCK_BUSY;
		break;
	default:
		rw_exit(&sidp->sid_rwlock);
		return (EINVAL);
	}

	rw_exit(&sidp->sid_rwlock);

	/*
	 * at this point if a valid snapshot was found then it has
	 * been marked busy and we can use it.
	 */
	return (0);
}

/*
 * snap_close() - snapshot driver close(9E) routine
 *
 *    unsets the busy bits in the snapshot id.  If the snapshot has been
 *    deleted while the snapshot device was open, the close call will clean
 *    up the remaining state information.
 */
/* ARGSUSED */
static int
snap_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	struct snapshot_id	**sidpp, *sidp;
	minor_t			minor;
	char			name[20];

	minor = getminor(dev);

	/* if this is the control device, close it and return */
	if (minor == SNAP_CTL_MINOR) {
		rw_enter(&snap_ctl.sid_rwlock, RW_WRITER);
		snap_ctl.sid_flags &= ~(SID_CHAR_BUSY);
		rw_exit(&snap_ctl.sid_rwlock);
		return (0);
	}

	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL) {
		cmn_err(CE_WARN, "snap_close: could not find state for "
		    "snapshot %d.", minor);
		return (ENXIO);
	}
	sidp = *sidpp;
	mutex_enter(&snapshot_mutex);
	rw_enter(&sidp->sid_rwlock, RW_WRITER);

	/* Mark the snapshot as not being busy anymore */
	switch (otyp) {
	case OTYP_CHR:
		sidp->sid_flags &= ~(SID_CHAR_BUSY);
		break;
	case OTYP_BLK:
		sidp->sid_flags &= ~(SID_BLOCK_BUSY);
		break;
	default:
		mutex_exit(&snapshot_mutex);
		rw_exit(&sidp->sid_rwlock);
		return (EINVAL);
	}

	if (SID_AVAILABLE(sidp)) {
		/*
		 * if this is the last close on a snapshot that has been
		 * deleted, then free up the soft state.  The snapdelete
		 * ioctl does not free this when the device is in use so
		 * we do it here after the last reference goes away.
		 */

		/* remove the device nodes */
		ASSERT(fssnap_dip != NULL);
		(void) snprintf(name, sizeof (name), "%d",
		    sidp->sid_snapnumber);
		ddi_remove_minor_node(fssnap_dip, name);
		(void) snprintf(name, sizeof (name), "%d,raw",
		    sidp->sid_snapnumber);
		ddi_remove_minor_node(fssnap_dip, name);

		/* delete the state structure */
		ddi_soft_state_free(statep, sidp->sid_snapnumber);
		num_snapshots--;
	}

	mutex_exit(&snapshot_mutex);
	rw_exit(&sidp->sid_rwlock);

	return (0);
}

/*
 * snap_read() - snapshot driver read(9E) routine
 *
 *    reads data from the snapshot by calling snap_strategy() through physio()
 */
/* ARGSUSED */
static int
snap_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	minor_t		minor;
	struct snapshot_id **sidpp;

	minor = getminor(dev);
	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL) {
		cmn_err(CE_WARN,
		    "snap_read: could not find state for snapshot %d.", minor);
		return (ENXIO);
	}
	return (physio(snap_strategy, NULL, dev, B_READ, minphys, uiop));
}

/*
 * snap_strategy() - snapshot driver strategy(9E) routine
 *
 *    cycles through each chunk in the requested buffer and calls
 *    snap_getchunk() on each chunk to retrieve it from the appropriate
 *    place.  Once all of the parts are put together the requested buffer
 *    is returned.  The snapshot driver is read-only, so a write is invalid.
 */
static int
snap_strategy(struct buf *bp)
{
	struct snapshot_id **sidpp, *sidp;
	minor_t		minor;
	chunknumber_t	chunk;
	int		off, len;
	u_longlong_t	reqptr;
	int		error = 0;
	size_t		chunksz;
	caddr_t		buf;

	/* snapshot device is read-only */
	if (bp->b_flags & B_WRITE) {
		bioerror(bp, EROFS);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	minor = getminor(bp->b_edev);
	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL) {
		cmn_err(CE_WARN,
		    "snap_strategy: could not find state for snapshot %d.",
		    minor);
		bioerror(bp, ENXIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}
	sidp = *sidpp;
	ASSERT(sidp);
	rw_enter(&sidp->sid_rwlock, RW_READER);

	if (SID_INACTIVE(sidp)) {
		bioerror(bp, ENXIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		rw_exit(&sidp->sid_rwlock);
		return (0);
	}

	if (bp->b_flags & (B_PAGEIO|B_PHYS))
		bp_mapin(bp);

	bp->b_resid = bp->b_bcount;
	ASSERT(bp->b_un.b_addr);
	buf = bp->b_un.b_addr;

	chunksz = sidp->sid_cowinfo->cow_map.cmap_chunksz;

	/* reqptr is the current DEV_BSIZE offset into the device */
	/* chunk is the chunk containing reqptr */
	/* len is the length of the request (in the current chunk) in bytes */
	/* off is the byte offset into the current chunk */
	reqptr = bp->b_lblkno;
	while (bp->b_resid > 0) {
		chunk = dbtocowchunk(&sidp->sid_cowinfo->cow_map, reqptr);
		off = (reqptr % (chunksz >> DEV_BSHIFT)) << DEV_BSHIFT;
		len = min(chunksz - off, bp->b_resid);
		ASSERT((off + len) <= chunksz);

		if ((error = snap_getchunk(sidp, chunk, off, len, buf)) != 0) {
			/*
			 * EINVAL means the user tried to go out of range.
			 * Anything else means it's likely that we're
			 * confused.
			 */
			if (error != EINVAL) {
				cmn_err(CE_WARN, "snap_strategy: error "
				    "calling snap_getchunk, chunk = %llu, "
				    "offset = %d, len = %d, resid = %lu, "
				    "error = %d.",
				    chunk, off, len, bp->b_resid, error);
			}
			bioerror(bp, error);
			biodone(bp);
			rw_exit(&sidp->sid_rwlock);
			return (0);
		}
		bp->b_resid -= len;
		reqptr += (len >> DEV_BSHIFT);
		buf += len;
	}

	ASSERT(bp->b_resid == 0);
	biodone(bp);

	rw_exit(&sidp->sid_rwlock);
	return (0);
}

/*
 * snap_getchunk() - helper function for snap_strategy()
 *
 *    gets the requested data from the appropriate place and fills in the
 *    buffer.  chunk is the chunk number of the request, offset is the
 *    offset into that chunk and must be less than the chunk size.  len is
 *    the length of the request starting at offset, and must not exceed a
 *    chunk boundary.  buffer is the address to copy the data to.  len
 *    bytes are copied into the buffer starting at the location specified.
 *
 *    A chunk is located according to the following algorithm:
 *        - If the chunk does not have a translation or is not a candidate
 *          for translation, it is read straight from the master device.
 *        - If the chunk does have a translation, then it is either on
 *          disk or in memory:
 *            o If it is in memory the requested data is simply copied out
 *              of the in-memory buffer.
 *            o If it is in the backing store, it is read from there.
 *
 *    This function does the real work of the snapshot driver.
 */
static int
snap_getchunk(struct snapshot_id *sidp, chunknumber_t chunk, int offset,
    int len, char *buffer)
{
	cow_map_t	*cmap = &sidp->sid_cowinfo->cow_map;
	cow_map_node_t	*cmn;
	struct buf	*snapbuf;
	int		error = 0;
	char		*newbuffer;
	int		newlen = 0;
	int		partial = 0;

	ASSERT(RW_READ_HELD(&sidp->sid_rwlock));
	ASSERT(offset + len <= cmap->cmap_chunksz);

	/*
	 * Check if the chunk number is out of range and if so bail out
	 */
	if (chunk >= (cmap->cmap_bmsize * NBBY)) {
		return (EINVAL);
	}

	/*
	 * If the chunk is not a candidate for translation, then the chunk
	 * was not allocated when the snapshot was taken.  Since it does
	 * not contain data associated with this snapshot, just return a
	 * zero buffer instead.
	 */
	if (isclr(cmap->cmap_candidate, chunk)) {
		bzero(buffer, len);
		return (0);
	}

	/*
	 * if the chunk is a candidate for translation but a
	 * translation does not exist, then read through to the
	 * original file system.  The rwlock is held until the read
	 * completes if it hasn't been translated to make sure the
	 * file system does not translate the block before we
	 * access it. If it has already been translated we don't
	 * need the lock, because the translation will never go away.
	 */
	rw_enter(&cmap->cmap_rwlock, RW_READER);
	if (isclr(cmap->cmap_hastrans, chunk)) {
		snapbuf = getrbuf(KM_SLEEP);
		/*
		 * Reading into the buffer saves having to do a copy,
		 * but gets tricky if the request size is not a
		 * multiple of DEV_BSIZE.  However, we are filling the
		 * buffer left to right, so future reads will write
		 * over any extra data we might have read.
		 */

		partial = len % DEV_BSIZE;

		snapbuf->b_bcount = len;
		snapbuf->b_lblkno = lbtodb(chunk * cmap->cmap_chunksz + offset);
		snapbuf->b_un.b_addr = buffer;

		snapbuf->b_iodone = NULL;
		snapbuf->b_proc = NULL;		/* i.e. the kernel */
		snapbuf->b_flags = B_READ | B_BUSY;
		snapbuf->b_edev = sidp->sid_fvp->v_vfsp->vfs_dev;

		if (partial) {
			/*
			 * Partial block read in progress.
			 * This is bad as modules further down the line
			 * assume buf's are exact multiples of DEV_BSIZE
			 * and we end up with fewer, or zero, bytes read.
			 * To get round this we need to round up to the
			 * nearest full block read and then return only
			 * len bytes.
			 */
			newlen = (len - partial) + DEV_BSIZE;
			newbuffer = kmem_alloc(newlen, KM_SLEEP);

			snapbuf->b_bcount = newlen;
			snapbuf->b_un.b_addr = newbuffer;
		}

		(void) bdev_strategy(snapbuf);
		(void) biowait(snapbuf);

		error = geterror(snapbuf);

		if (partial) {
			/*
			 * Partial block read. Now we need to bcopy the
			 * correct number of bytes back into the
			 * supplied buffer, and tidy up our temp
			 * buffer.
			 */
			bcopy(newbuffer, buffer, len);
			kmem_free(newbuffer, newlen);
		}

		freerbuf(snapbuf);
		rw_exit(&cmap->cmap_rwlock);

		return (error);
	}

	/*
	 * finally, if the chunk is a candidate for translation and it
	 * has been translated, then we clone the chunk of the buffer
	 * that was copied aside by the file system.
	 * The cmap_rwlock does not need to be held after we know the
	 * data has already been copied. Once a chunk has been copied
	 * to the backing file, it is stable read only data.
	 */
	cmn = transtbl_get(cmap, chunk);

	/* check whether the data is in memory or in the backing file */
	if (cmn != NULL) {
		ASSERT(cmn->cmn_buf);
		/* already in memory */
		bcopy(cmn->cmn_buf + offset, buffer, len);
		rw_exit(&cmap->cmap_rwlock);
	} else {
		ssize_t resid = len;
		int	bf_index;
		/*
		 * can cause deadlock with writer if we don't drop the
		 * cmap_rwlock before trying to get the backing store file
		 * vnode rwlock.
		 */
		rw_exit(&cmap->cmap_rwlock);

		bf_index = chunk / cmap->cmap_chunksperbf;

		/* read buffer from backing file */
		error = vn_rdwr(UIO_READ,
		    (sidp->sid_cowinfo->cow_backfile_array)[bf_index],
		    buffer, len, ((chunk % cmap->cmap_chunksperbf) *
		    cmap->cmap_chunksz) + offset, UIO_SYSSPACE, 0,
		    RLIM64_INFINITY, kcred, &resid);
	}

	return (error);
}

/*
 * snap_print() - snapshot driver print(9E) routine
 *
 *    prints the device identification string.
 */
static int
snap_print(dev_t dev, char *str)
{
	struct snapshot_id **sidpp;
	minor_t		minor;

	minor = getminor(dev);
	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL) {
		cmn_err(CE_WARN,
		    "snap_print: could not find state for snapshot %d.", minor);
		return (ENXIO);
	}

	cmn_err(CE_NOTE, "snap_print: snapshot %d: %s",  minor, str);

	return (0);
}

/*
 * snap_prop_op() - snapshot driver prop_op(9E) routine
 *
 *    get 32-bit and 64-bit values for size (character driver) and nblocks
 *    (block driver).
 */
static int
snap_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		minor;
	struct snapshot_id **sidpp;
	dev_t		mdev;
	dev_info_t	*mdip;
	int		error;

	minor = getminor(dev);

	/*
	 * If this is the control device just check for .conf properties,
	 * if the wildcard DDI_DEV_T_ANY was passed in via the dev_t
	 * just fall back to the defaults.
	 */
	if ((minor == SNAP_CTL_MINOR) || (dev == DDI_DEV_T_ANY))
		return (ddi_prop_op(dev, dip, prop_op, flags, name,
		    valuep, lengthp));

	/* check to see if there is a master device plumbed */
	sidpp = ddi_get_soft_state(statep, minor);
	if (sidpp == NULL || *sidpp == NULL) {
		cmn_err(CE_WARN,
		    "snap_prop_op: could not find state for "
		    "snapshot %d.", minor);
		return (DDI_PROP_NOT_FOUND);
	}

	if (((*sidpp)->sid_fvp == NULL) || ((*sidpp)->sid_fvp->v_vfsp == NULL))
		return (ddi_prop_op(dev, dip, prop_op, flags, name,
		    valuep, lengthp));

	/* hold master device and pass operation down */
	mdev = (*sidpp)->sid_fvp->v_vfsp->vfs_dev;
	if (mdip = e_ddi_hold_devi_by_dev(mdev, 0)) {

		/* get size information from the master device. */
		error = cdev_prop_op(mdev, mdip,
		    prop_op, flags, name, valuep, lengthp);
		ddi_release_devi(mdip);
		if (error == DDI_PROP_SUCCESS)
			return (error);
	}

	/* master device did not service the request, try framework */
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));

}

/*
 * snap_ioctl() - snapshot driver ioctl(9E) routine
 *
 *    only applies to the control device.  The control device accepts two
 *    ioctl requests: create a snapshot or delete a snapshot.  In either
 *    case, the vnode for the requested file system is extracted, and the
 *    request is passed on to the file system via the same ioctl.  The file
 *    system is responsible for doing the things necessary for creating or
 *    destroying a snapshot, including any file system specific operations
 *    that must be performed as well as setting up and deleting the snapshot
 *    state through the fssnap interfaces.
 */
static int
snap_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
int *rvalp)
{
	minor_t	minor;
	int error = 0;

	minor = getminor(dev);

	if (minor != SNAP_CTL_MINOR) {
		return (EINVAL);
	}

	switch (cmd) {
	case _FIOSNAPSHOTCREATE:
	{
		struct fiosnapcreate	fc;
		struct file		*fp;
		struct vnode		*vp;

		if (ddi_copyin((void *)arg, &fc, sizeof (fc), mode))
			return (EFAULT);

		/* get vnode for file system mount point */
		if ((fp = getf(fc.rootfiledesc)) == NULL)
			return (EBADF);

		ASSERT(fp->f_vnode);
		vp = fp->f_vnode;
		VN_HOLD(vp);
		releasef(fc.rootfiledesc);

		/* pass ioctl request to file system */
		error = VOP_IOCTL(vp, cmd, arg, 0, credp, rvalp, NULL);
		VN_RELE(vp);
		break;
	}
	case _FIOSNAPSHOTCREATE_MULTI:
	{
		struct fiosnapcreate_multi	fc;
		struct file		*fp;
		struct vnode		*vp;

		if (ddi_copyin((void *)arg, &fc, sizeof (fc), mode))
			return (EFAULT);

		/* get vnode for file system mount point */
		if ((fp = getf(fc.rootfiledesc)) == NULL)
			return (EBADF);

		ASSERT(fp->f_vnode);
		vp = fp->f_vnode;
		VN_HOLD(vp);
		releasef(fc.rootfiledesc);

		/* pass ioctl request to file system */
		error = VOP_IOCTL(vp, cmd, arg, 0, credp, rvalp, NULL);
		VN_RELE(vp);
		break;
	}
	case _FIOSNAPSHOTDELETE:
	{
		major_t			major;
		struct fiosnapdelete	fc;
		snapshot_id_t		*sidp = NULL;
		snapshot_id_t		*sidnextp = NULL;
		struct file		*fp = NULL;
		struct vnode		*vp = NULL;
		struct vfs 		*vfsp = NULL;
		vfsops_t		*vfsops = EIO_vfsops;

		if (ddi_copyin((void *)arg, &fc, sizeof (fc), mode))
			return (EFAULT);

		/* get vnode for file system mount point */
		if ((fp = getf(fc.rootfiledesc)) == NULL)
			return (EBADF);

		ASSERT(fp->f_vnode);
		vp = fp->f_vnode;
		VN_HOLD(vp);
		releasef(fc.rootfiledesc);
		/*
		 * Test for two formats of delete and set correct minor/vp:
		 * pseudo device:
		 * fssnap -d [/dev/fssnap/x]
		 * or
		 * mount point:
		 * fssnap -d [/mntpt]
		 * Note that minor is verified to be equal to SNAP_CTL_MINOR
		 * at this point which is an invalid minor number.
		 */
		ASSERT(fssnap_dip != NULL);
		major = ddi_driver_major(fssnap_dip);
		mutex_enter(&snapshot_mutex);
		for (sidp = snapshot; sidp != NULL; sidp = sidnextp) {
			rw_enter(&sidp->sid_rwlock, RW_READER);
			sidnextp = sidp->sid_next;
			/* pseudo device: */
			if (major == getmajor(vp->v_rdev)) {
				minor = getminor(vp->v_rdev);
				if (sidp->sid_snapnumber == (uint_t)minor &&
				    sidp->sid_fvp) {
					VN_RELE(vp);
					vp = sidp->sid_fvp;
					VN_HOLD(vp);
					rw_exit(&sidp->sid_rwlock);
					break;
				}
			/* Mount point: */
			} else {
				if (sidp->sid_fvp == vp) {
					minor = sidp->sid_snapnumber;
					rw_exit(&sidp->sid_rwlock);
					break;
				}
			}
			rw_exit(&sidp->sid_rwlock);
		}
		mutex_exit(&snapshot_mutex);
		/* Verify minor got set correctly above */
		if (minor == SNAP_CTL_MINOR) {
			VN_RELE(vp);
			return (EINVAL);
		}
		dev = makedevice(major, minor);
		/*
		 * Create dummy vfs entry
		 * to use as a locking semaphore across the IOCTL
		 * for mount in progress cases...
		 */
		vfsp = vfs_alloc(KM_SLEEP);
		VFS_INIT(vfsp, vfsops, NULL);
		VFS_HOLD(vfsp);
		vfs_addmip(dev, vfsp);
		if ((vfs_devmounting(dev, vfsp)) ||
		    (vfs_devismounted(dev))) {
			vfs_delmip(vfsp);
			VFS_RELE(vfsp);
			VN_RELE(vp);
			return (EBUSY);
		}
		/*
		 * Nobody mounted but do not release mount in progress lock
		 * until IOCTL complete to prohibit a mount sneaking
		 * in
		 */
		error = VOP_IOCTL(vp, cmd, arg, 0, credp, rvalp, NULL);
		vfs_delmip(vfsp);
		VFS_RELE(vfsp);
		VN_RELE(vp);
		break;
	}
	default:
		cmn_err(CE_WARN, "snap_ioctl: Invalid ioctl cmd %d, minor %d.",
		    cmd, minor);
		return (EINVAL);
	}

	return (error);
}


/* ************************************************************************ */

/*
 * Translation Table Routines
 *
 *    These support routines implement a simple doubly linked list
 *    to keep track of chunks that are currently in memory.  The maximum
 *    size of the list is determined by the fssnap_max_mem_chunks variable.
 *    The cmap_rwlock is used to protect the linkage of the list.
 */

/*
 * transtbl_add() - add a node to the translation table
 *
 *    allocates a new node and points it at the buffer passed in.  The node
 *    is added to the beginning of the doubly linked list and the head of
 *    the list is moved.  The cmap_rwlock must be held as a writer through
 *    this operation.
 */
static cow_map_node_t *
transtbl_add(cow_map_t *cmap, chunknumber_t chunk, caddr_t buf)
{
	cow_map_node_t	*cmnode;

	ASSERT(RW_WRITE_HELD(&cmap->cmap_rwlock));

	cmnode = kmem_alloc(sizeof (cow_map_node_t), KM_SLEEP);

	/*
	 * insert new translations at the beginning so cmn_table is always
	 * the first node.
	 */
	cmnode->cmn_chunk = chunk;
	cmnode->cmn_buf = buf;
	cmnode->cmn_prev = NULL;
	cmnode->cmn_next = cmap->cmap_table;
	if (cmnode->cmn_next)
		cmnode->cmn_next->cmn_prev = cmnode;
	cmap->cmap_table = cmnode;

	return (cmnode);
}

/*
 * transtbl_get() - look up a node in the translation table
 *
 *    called by the snapshot driver to find data that has been translated.
 *    The lookup is done by the chunk number, and the node is returned.
 *    If the node was not found, NULL is returned.
 */
static cow_map_node_t *
transtbl_get(cow_map_t *cmap, chunknumber_t chunk)
{
	cow_map_node_t *cmn;

	ASSERT(RW_READ_HELD(&cmap->cmap_rwlock));
	ASSERT(cmap);

	/* search the translation table */
	for (cmn = cmap->cmap_table; cmn != NULL; cmn = cmn->cmn_next) {
		if (cmn->cmn_chunk == chunk)
			return (cmn);
	}

	/* not found */
	return (NULL);
}

/*
 * transtbl_delete() - delete a node from the translation table
 *
 *    called when a node's data has been written out to disk.  The
 *    cmap_rwlock must be held as a writer for this operation.  If the node
 *    being deleted is the head of the list, then the head is moved to the
 *    next node.  Both the node's data and the node itself are freed.
 */
static void
transtbl_delete(cow_map_t *cmap, cow_map_node_t *cmn)
{
	ASSERT(RW_WRITE_HELD(&cmap->cmap_rwlock));
	ASSERT(cmn);
	ASSERT(cmap->cmap_table);

	/* if the head of the list is being deleted, then move the head up */
	if (cmap->cmap_table == cmn) {
		ASSERT(cmn->cmn_prev == NULL);
		cmap->cmap_table = cmn->cmn_next;
	}


	/* make previous node's next pointer skip over current node */
	if (cmn->cmn_prev != NULL) {
		ASSERT(cmn->cmn_prev->cmn_next == cmn);
		cmn->cmn_prev->cmn_next = cmn->cmn_next;
	}

	/* make next node's previous pointer skip over current node */
	if (cmn->cmn_next != NULL) {
		ASSERT(cmn->cmn_next->cmn_prev == cmn);
		cmn->cmn_next->cmn_prev = cmn->cmn_prev;
	}

	/* free the data and the node */
	ASSERT(cmn->cmn_buf);
	kmem_free(cmn->cmn_buf, cmap->cmap_chunksz);
	kmem_free(cmn, sizeof (cow_map_node_t));
}

/*
 * transtbl_free() - free the entire translation table
 *
 *    called when the snapshot is deleted.  This frees all of the nodes in
 *    the translation table (but not the bitmaps).
 */
static void
transtbl_free(cow_map_t *cmap)
{
	cow_map_node_t	*curnode;
	cow_map_node_t	*tempnode;

	for (curnode = cmap->cmap_table; curnode != NULL; curnode = tempnode) {
		tempnode = curnode->cmn_next;

		kmem_free(curnode->cmn_buf, cmap->cmap_chunksz);
		kmem_free(curnode, sizeof (cow_map_node_t));
	}
}


/* ************************************************************************ */

/*
 * Interface Implementation Routines
 *
 * The following functions implement snapshot interface routines that are
 * called by the file system to create, delete, and use a snapshot.  The
 * interfaces are defined in fssnap_if.c and are filled in by this driver
 * when it is loaded.  This technique allows the file system to depend on
 * the interface module without having to load the full implementation and
 * snapshot device drivers.
 */

/*
 * fssnap_strategy_impl() - strategy routine called by the file system
 *
 *    called by the file system to handle copy-on-write when necessary.  All
 *    reads and writes that the file system performs should go through this
 *    function.  If the file system calls the underlying device's strategy
 *    routine without going through fssnap_strategy() (eg. by calling
 *    bdev_strategy()), the snapshot may not be consistent.
 *
 *    This function starts by doing significant sanity checking to insure
 *    the snapshot was not deleted out from under it or deleted and then
 *    recreated.  To do this, it checks the actual pointer passed into it
 *    (ie. the handle held by the file system).  NOTE that the parameter is
 *    a POINTER TO A POINTER to the snapshot id.  Once the snapshot id is
 *    locked, it knows things are ok and that this snapshot is really for
 *    this file system.
 *
 *    If the request is a write, fssnap_translate() is called to determine
 *    whether a copy-on-write is required.  If it is a read, the read is
 *    simply passed on to the underlying device.
 */
static void
fssnap_strategy_impl(void *snapshot_id, buf_t *bp)
{
	struct snapshot_id **sidpp;
	struct snapshot_id *sidp;
	int error;

	/* read requests are always passed through */
	if (bp->b_flags & B_READ) {
		(void) bdev_strategy(bp);
		return;
	}

	/*
	 * Because we were not able to take the snapshot read lock BEFORE
	 * checking for a snapshot back in the file system, things may have
	 * drastically changed out from under us.  For instance, the snapshot
	 * may have been deleted, deleted and recreated, or worse yet, deleted
	 * for this file system but now the snapshot number is in use by another
	 * file system.
	 *
	 * Having a pointer to the file system's snapshot id pointer allows us
	 * to sanity check most of this, though it assumes the file system is
	 * keeping track of a pointer to the snapshot_id somewhere.
	 */
	sidpp = (struct snapshot_id **)snapshot_id;
	sidp = *sidpp;

	/*
	 * if this file system's snapshot was disabled, just pass the
	 * request through.
	 */
	if (sidp == NULL) {
		(void) bdev_strategy(bp);
		return;
	}

	/*
	 * Once we have the reader lock the snapshot will not magically go
	 * away.  But things may have changed on us before this so double check.
	 */
	rw_enter(&sidp->sid_rwlock, RW_READER);

	/*
	 * if an error was founds somewhere the DELETE flag will be
	 * set to indicate the snapshot should be deleted and no new
	 * translations should occur.
	 */
	if (sidp->sid_flags & SID_DELETE) {
		rw_exit(&sidp->sid_rwlock);
		(void) fssnap_delete_impl(sidpp);
		(void) bdev_strategy(bp);
		return;
	}

	/*
	 * If the file system is no longer pointing to the snapshot we were
	 * called with, then it should not attempt to translate this buffer as
	 * it may be going to a snapshot for a different file system.
	 * Even if the file system snapshot pointer is still the same, the
	 * snapshot may have been disabled before we got the reader lock.
	 */
	if (sidp != *sidpp || SID_INACTIVE(sidp)) {
		rw_exit(&sidp->sid_rwlock);
		(void) bdev_strategy(bp);
		return;
	}

	/*
	 * At this point we're sure the snapshot will not go away while the
	 * reader lock is held, and we are reasonably certain that we are
	 * writing to the correct snapshot.
	 */
	if ((error = fssnap_translate(sidpp, bp)) != 0) {
		/*
		 * fssnap_translate can release the reader lock if it
		 * has to wait for a semaphore.  In this case it is possible
		 * for the snapshot to be deleted in this time frame.  If this
		 * happens just sent the buf thru to the filesystems device.
		 */
		if (sidp != *sidpp || SID_INACTIVE(sidp)) {
			rw_exit(&sidp->sid_rwlock);
			(void) bdev_strategy(bp);
			return;
		}
		bioerror(bp, error);
		biodone(bp);
	}
	rw_exit(&sidp->sid_rwlock);
}

/*
 * fssnap_translate() - helper function for fssnap_strategy()
 *
 *    performs the actual copy-on-write for write requests, if required.
 *    This function does the real work of the file system side of things.
 *
 *    It first checks the candidate bitmap to quickly determine whether any
 *    action is necessary.  If the candidate bitmap indicates the chunk was
 *    allocated when the snapshot was created, then it checks to see whether
 *    a translation already exists.  If a translation already exists then no
 *    action is required.  If the chunk is a candidate for copy-on-write,
 *    and a translation does not already exist, then the chunk is read in
 *    and a node is added to the translation table.
 *
 *    Once all of the chunks in the request range have been copied (if they
 *    needed to be), then the original request can be satisfied and the old
 *    data can be overwritten.
 */
static int
fssnap_translate(struct snapshot_id **sidpp, struct buf *wbp)
{
	snapshot_id_t	*sidp = *sidpp;
	struct buf	*oldbp;	/* buffer to store old data in */
	struct cow_info	*cowp = sidp->sid_cowinfo;
	cow_map_t	*cmap = &cowp->cow_map;
	cow_map_node_t	*cmn;
	chunknumber_t	cowchunk, startchunk, endchunk;
	int		error;
	int	throttle_write = 0;

	/* make sure the snapshot is active */
	ASSERT(RW_READ_HELD(&sidp->sid_rwlock));

	startchunk = dbtocowchunk(cmap, wbp->b_lblkno);
	endchunk   = dbtocowchunk(cmap, wbp->b_lblkno +
	    ((wbp->b_bcount-1) >> DEV_BSHIFT));

	/*
	 * Do not throttle the writes of the fssnap taskq thread and
	 * the log roll (trans_roll) thread. Furthermore the writes to
	 * the on-disk log are also not subject to throttling.
	 * The fssnap_write_taskq thread's write can block on the throttling
	 * semaphore which leads to self-deadlock as this same thread
	 * releases the throttling semaphore after completing the IO.
	 * If the trans_roll thread's write is throttled then we can deadlock
	 * because the fssnap_taskq_thread which releases the throttling
	 * semaphore can block waiting for log space which can only be
	 * released by the trans_roll thread.
	 */

	throttle_write = !(taskq_member(cowp->cow_taskq, curthread) ||
	    tsd_get(bypass_snapshot_throttle_key));

	/*
	 * Iterate through all chunks covered by this write and perform the
	 * copy-aside if necessary.  Once all chunks have been safely
	 * stowed away, the new data may be written in a single sweep.
	 *
	 * For each chunk in the range, the following sequence is performed:
	 *	- Is the chunk a candidate for translation?
	 *		o If not, then no translation is necessary, continue
	 *	- If it is a candidate, then does it already have a translation?
	 *		o If so, then no translation is necessary, continue
	 *	- If it is a candidate, but does not yet have a translation,
	 *	  then read the old data and schedule an asynchronous taskq
	 *	  to write the old data to the backing file.
	 *
	 * Once this has been performed over the entire range of chunks, then
	 * it is safe to overwrite the data that is there.
	 *
	 * Note that no lock is required to check the candidate bitmap because
	 * it never changes once the snapshot is created.  The reader lock is
	 * taken to check the hastrans bitmap since it may change.  If it
	 * turns out a copy is required, then the lock is upgraded to a
	 * writer, and the bitmap is re-checked as it may have changed while
	 * the lock was released.  Finally, the write lock is held while
	 * reading the old data to make sure it is not translated out from
	 * under us.
	 *
	 * This locking mechanism should be sufficient to handle multiple
	 * threads writing to overlapping chunks simultaneously.
	 */
	for (cowchunk = startchunk; cowchunk <= endchunk; cowchunk++) {
		/*
		 * If the cowchunk is outside of the range of our
		 * candidate maps, then simply break out of the
		 * loop and pass the I/O through to bdev_strategy.
		 * This would occur if the file system has grown
		 * larger since the snapshot was taken.
		 */
		if (cowchunk >= (cmap->cmap_bmsize * NBBY))
			break;

		/*
		 * If no disk blocks were allocated in this chunk when the
		 * snapshot was created then no copy-on-write will be
		 * required.  Since this bitmap is read-only no locks are
		 * necessary.
		 */
		if (isclr(cmap->cmap_candidate, cowchunk)) {
			continue;
		}

		/*
		 * If a translation already exists, the data can be written
		 * through since the old data has already been saved off.
		 */
		if (isset(cmap->cmap_hastrans, cowchunk)) {
			continue;
		}


		/*
		 * Throttle translations if there are too many outstanding
		 * chunks in memory.  The semaphore is sema_v'd by the taskq.
		 *
		 * You can't keep the sid_rwlock if you would go to sleep.
		 * This will result in deadlock when someone tries to delete
		 * the snapshot (wants the sid_rwlock as a writer, but can't
		 * get it).
		 */
		if (throttle_write) {
			if (sema_tryp(&cmap->cmap_throttle_sem) == 0) {
				rw_exit(&sidp->sid_rwlock);
				atomic_inc_32(&cmap->cmap_waiters);
				sema_p(&cmap->cmap_throttle_sem);
				atomic_dec_32(&cmap->cmap_waiters);
				rw_enter(&sidp->sid_rwlock, RW_READER);

			/*
			 * Now since we released the sid_rwlock the state may
			 * have transitioned underneath us. so check that again.
			 */
				if (sidp != *sidpp || SID_INACTIVE(sidp)) {
					sema_v(&cmap->cmap_throttle_sem);
					return (ENXIO);
				}
			}
		}

		/*
		 * Acquire the lock as a writer and check to see if a
		 * translation has been added in the meantime.
		 */
		rw_enter(&cmap->cmap_rwlock, RW_WRITER);
		if (isset(cmap->cmap_hastrans, cowchunk)) {
			if (throttle_write)
				sema_v(&cmap->cmap_throttle_sem);
			rw_exit(&cmap->cmap_rwlock);
			continue; /* go to the next chunk */
		}

		/*
		 * read a full chunk of data from the requested offset rounded
		 * down to the nearest chunk size.
		 */
		oldbp = getrbuf(KM_SLEEP);
		oldbp->b_lblkno = cowchunktodb(cmap, cowchunk);
		oldbp->b_edev = wbp->b_edev;
		oldbp->b_bcount = cmap->cmap_chunksz;
		oldbp->b_bufsize = cmap->cmap_chunksz;
		oldbp->b_iodone = NULL;
		oldbp->b_proc = NULL;
		oldbp->b_flags = B_READ;
		oldbp->b_un.b_addr = kmem_alloc(cmap->cmap_chunksz, KM_SLEEP);

		(void) bdev_strategy(oldbp);
		(void) biowait(oldbp);

		/*
		 * It's ok to bail in the middle of translating the range
		 * because the extra copy-asides will not hurt anything
		 * (except by using extra space in the backing store).
		 */
		if ((error = geterror(oldbp)) != 0) {
			cmn_err(CE_WARN, "fssnap_translate: error reading "
			    "old data for snapshot %d, chunk %llu, disk block "
			    "%lld, size %lu, error %d.", sidp->sid_snapnumber,
			    cowchunk, oldbp->b_lblkno, oldbp->b_bcount, error);
			kmem_free(oldbp->b_un.b_addr, cmap->cmap_chunksz);
			freerbuf(oldbp);
			rw_exit(&cmap->cmap_rwlock);
			if (throttle_write)
				sema_v(&cmap->cmap_throttle_sem);
			return (error);
		}

		/*
		 * add the node to the translation table and save a reference
		 * to pass to the taskq for writing out to the backing file
		 */
		cmn = transtbl_add(cmap, cowchunk, oldbp->b_un.b_addr);
		freerbuf(oldbp);

		/*
		 * Add a reference to the snapshot id so the lower level
		 * processing (ie. the taskq) can get back to the state
		 * information.
		 */
		cmn->cmn_sid = sidp;
		cmn->release_sem = throttle_write;
		setbit(cmap->cmap_hastrans, cowchunk);

		rw_exit(&cmap->cmap_rwlock);

		/*
		 * schedule the asynchronous write to the backing file
		 */
		if (cowp->cow_backfile_array != NULL)
			(void) taskq_dispatch(cowp->cow_taskq,
			    fssnap_write_taskq, cmn, TQ_SLEEP);
	}

	/*
	 * Write new data in place of the old data.  At this point all of the
	 * chunks touched by this write have been copied aside and so the new
	 * data can be written out all at once.
	 */
	(void) bdev_strategy(wbp);

	return (0);
}

/*
 * fssnap_write_taskq() - write in-memory translations to the backing file
 *
 *    writes in-memory translations to the backing file asynchronously.  A
 *    task is dispatched each time a new translation is created.  The task
 *    writes the data to the backing file and removes it from the memory
 *    list. The throttling semaphore is released only if the particular
 *    translation was throttled in fssnap_translate.
 */
static void
fssnap_write_taskq(void *arg)
{
	cow_map_node_t	*cmn = (cow_map_node_t *)arg;
	snapshot_id_t	*sidp = cmn->cmn_sid;
	cow_info_t	*cowp = sidp->sid_cowinfo;
	cow_map_t	*cmap = &cowp->cow_map;
	int		error;
	int		bf_index;
	int		release_sem = cmn->release_sem;

	/*
	 * The sid_rwlock does not need to be held here because the taskqs
	 * are destroyed explicitly by fssnap_delete (with the sid_rwlock
	 * held as a writer).  taskq_destroy() will flush all of the tasks
	 * out before fssnap_delete frees up all of the structures.
	 */

	/* if the snapshot was disabled from under us, drop the request. */
	rw_enter(&sidp->sid_rwlock, RW_READER);
	if (SID_INACTIVE(sidp)) {
		rw_exit(&sidp->sid_rwlock);
		if (release_sem)
			sema_v(&cmap->cmap_throttle_sem);
		return;
	}
	rw_exit(&sidp->sid_rwlock);

	atomic_inc_64((uint64_t *)&cmap->cmap_nchunks);

	if ((cmap->cmap_maxsize != 0) &&
	    ((cmap->cmap_nchunks * cmap->cmap_chunksz) > cmap->cmap_maxsize)) {
		cmn_err(CE_WARN, "fssnap_write_taskq: snapshot %d (%s) has "
		    "reached the maximum backing file size specified (%llu "
		    "bytes) and will be deleted.", sidp->sid_snapnumber,
		    (char *)cowp->cow_kstat_mntpt->ks_data,
		    cmap->cmap_maxsize);
		if (release_sem)
			sema_v(&cmap->cmap_throttle_sem);
		atomic_or_uint(&sidp->sid_flags, SID_DELETE);
		return;
	}

	/* perform the write */
	bf_index = cmn->cmn_chunk / cmap->cmap_chunksperbf;

	if (error = vn_rdwr(UIO_WRITE, (cowp->cow_backfile_array)[bf_index],
	    cmn->cmn_buf, cmap->cmap_chunksz,
	    (cmn->cmn_chunk % cmap->cmap_chunksperbf) * cmap->cmap_chunksz,
	    UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, (ssize_t *)NULL)) {
		cmn_err(CE_WARN, "fssnap_write_taskq: error writing to "
		    "backing file.  DELETING SNAPSHOT %d, backing file path "
		    "%s, offset %llu bytes, error %d.", sidp->sid_snapnumber,
		    (char *)cowp->cow_kstat_bfname->ks_data,
		    cmn->cmn_chunk * cmap->cmap_chunksz, error);
		if (release_sem)
			sema_v(&cmap->cmap_throttle_sem);
		atomic_or_uint(&sidp->sid_flags, SID_DELETE);
		return;
	}

	/*
	 * now remove the node and buffer from memory
	 */
	rw_enter(&cmap->cmap_rwlock, RW_WRITER);
	transtbl_delete(cmap, cmn);
	rw_exit(&cmap->cmap_rwlock);

	/* Allow more translations */
	if (release_sem)
		sema_v(&cmap->cmap_throttle_sem);

}

/*
 * fssnap_create_impl() - called from the file system to create a new snapshot
 *
 *    allocates and initializes the structures needed for a new snapshot.
 *    This is called by the file system when it receives an ioctl request to
 *    create a new snapshot.  An unused snapshot identifier is either found
 *    or created, and eventually returned as the opaque handle the file
 *    system will use to identify this snapshot.  The snapshot number
 *    associated with the snapshot identifier is the same as the minor
 *    number for the snapshot device that is used to access that snapshot.
 *
 *    The snapshot can not be used until the candidate bitmap is populated
 *    by the file system (see fssnap_set_candidate_impl()), and the file
 *    system finishes the setup process by calling fssnap_create_done().
 *    Nearly all of the snapshot locks are held for the duration of the
 *    create, and are not released until fssnap_create_done is called().
 */
static void *
fssnap_create_impl(chunknumber_t nchunks, uint_t chunksz, u_offset_t maxsize,
    struct vnode *fsvp, int backfilecount, struct vnode **bfvpp, char *backpath,
    u_offset_t max_backfile_size)
{
	refstr_t *mountpoint;
	char taskqname[50];
	struct cow_info *cowp;
	struct cow_map	*cmap;
	struct snapshot_id *sidp;
	int lastsnap;

	/*
	 * Sanity check the parameters we care about
	 * (we don't care about the informational parameters)
	 */
	if ((nchunks == 0) ||
	    ((chunksz % DEV_BSIZE) != 0) ||
	    (bfvpp == NULL)) {
		return (NULL);
	}

	/*
	 * Look for unused snapshot identifiers.  Snapshot ids are never
	 * freed, but deleted snapshot ids will be recycled as needed.
	 */
	mutex_enter(&snapshot_mutex);

findagain:
	lastsnap = 0;
	for (sidp = snapshot; sidp != NULL; sidp = sidp->sid_next) {
		if (sidp->sid_snapnumber > lastsnap)
			lastsnap = sidp->sid_snapnumber;

		/*
		 * The sid_rwlock is taken as a reader initially so that
		 * activity on each snapshot is not stalled while searching
		 * for a free snapshot id.
		 */
		rw_enter(&sidp->sid_rwlock, RW_READER);

		/*
		 * If the snapshot has been deleted and nobody is using the
		 * snapshot device than we can reuse this snapshot_id.  If
		 * the snapshot is marked to be deleted (SID_DELETE), then
		 * it hasn't been deleted yet so don't reuse it.
		 */
		if (SID_AVAILABLE(sidp))
			break; /* This spot is unused, so take it */
		rw_exit(&sidp->sid_rwlock);
	}

	/*
	 * add a new snapshot identifier if there are no deleted
	 * entries.  Since it doesn't matter what order the entries
	 * are in we can just add it to the beginning of the list.
	 */
	if (sidp) {
		if (rw_tryupgrade(&sidp->sid_rwlock) == 0) {
			/* someone else grabbed it as a writer, try again */
			rw_exit(&sidp->sid_rwlock);
			goto findagain;
		}
	} else {
		/* Create a new node if we didn't find an unused one */
		sidp = kmem_alloc(sizeof (struct snapshot_id), KM_SLEEP);
		rw_init(&sidp->sid_rwlock, NULL, RW_DEFAULT, NULL);
		rw_enter(&sidp->sid_rwlock, RW_WRITER);
		sidp->sid_snapnumber = (snapshot == NULL) ? 0 : lastsnap + 1;
		sidp->sid_cowinfo = NULL;
		sidp->sid_flags = 0;
		sidp->sid_next = snapshot;
		snapshot = sidp;
	}

	ASSERT(RW_WRITE_HELD(&sidp->sid_rwlock));
	ASSERT(sidp->sid_cowinfo == NULL);
	ASSERT(sidp->sid_snapnumber <= (lastsnap + 1));

	sidp->sid_flags |= SID_CREATING;
	/* The root vnode is held until snap_delete_impl() is called */
	VN_HOLD(fsvp);
	sidp->sid_fvp = fsvp;
	num_snapshots++;

	/* allocate and initialize structures */

	cowp = kmem_zalloc(sizeof (struct cow_info), KM_SLEEP);

	cowp->cow_backfile_array = bfvpp;
	cowp->cow_backcount = backfilecount;
	cowp->cow_backfile_sz = max_backfile_size;

	/*
	 * Initialize task queues for this snapshot.  Only a small number
	 * of threads are required because they will be serialized on the
	 * backing file's reader/writer lock anyway.
	 */
	(void) snprintf(taskqname, sizeof (taskqname), "%s_taskq_%d", snapname,
	    sidp->sid_snapnumber);
	cowp->cow_taskq = taskq_create(taskqname, fssnap_taskq_nthreads,
	    minclsyspri, 1,  fssnap_taskq_maxtasks, 0);

	/* don't allow tasks to start until after everything is ready */
	taskq_suspend(cowp->cow_taskq);

	/* initialize translation table */
	cmap = &cowp->cow_map;
	rw_init(&cmap->cmap_rwlock, NULL, RW_DEFAULT, NULL);
	rw_enter(&cmap->cmap_rwlock, RW_WRITER);

	sema_init(&cmap->cmap_throttle_sem, fssnap_max_mem_chunks, NULL,
	    SEMA_DEFAULT, NULL);

	cmap->cmap_chunksz = chunksz;
	cmap->cmap_maxsize = maxsize;
	cmap->cmap_chunksperbf = max_backfile_size / chunksz;

	/*
	 * allocate one bit per chunk for the bitmaps, round up
	 */
	cmap->cmap_bmsize = (nchunks + (NBBY - 1)) / NBBY;
	cmap->cmap_hastrans  = kmem_zalloc(cmap->cmap_bmsize, KM_SLEEP);
	cmap->cmap_candidate = kmem_zalloc(cmap->cmap_bmsize, KM_SLEEP);

	sidp->sid_cowinfo = cowp;

	/* initialize kstats for this snapshot */
	mountpoint = vfs_getmntpoint(fsvp->v_vfsp);
	fssnap_create_kstats(sidp, sidp->sid_snapnumber,
	    refstr_value(mountpoint), backpath);
	refstr_rele(mountpoint);

	mutex_exit(&snapshot_mutex);

	/*
	 * return with snapshot id rwlock held as a writer until
	 * fssnap_create_done is called
	 */
	return (sidp);
}

/*
 * fssnap_set_candidate_impl() - mark a chunk as a candidate for copy-on-write
 *
 *    sets a bit in the candidate bitmap that indicates that a chunk is a
 *    candidate for copy-on-write.  Typically, chunks that are allocated on
 *    the file system at the time the snapshot is taken are candidates,
 *    while chunks that have no allocated data do not need to be copied.
 *    Chunks containing metadata must be marked as candidates as well.
 */
static void
fssnap_set_candidate_impl(void *snapshot_id, chunknumber_t chunknumber)
{
	struct snapshot_id	*sid = snapshot_id;
	struct cow_info *cowp = sid->sid_cowinfo;
	struct cow_map	*cmap = &cowp->cow_map;

	/* simple bitmap operation for now */
	ASSERT(chunknumber < (cmap->cmap_bmsize * NBBY));
	setbit(cmap->cmap_candidate, chunknumber);
}

/*
 * fssnap_is_candidate_impl() - check whether a chunk is a candidate
 *
 *    returns 0 if the chunk is not a candidate and 1 if the chunk is a
 *    candidate.  This can be used by the file system to change behavior for
 *    chunks that might induce a copy-on-write.  The offset is specified in
 *    bytes since the chunk size may not be known by the file system.
 */
static int
fssnap_is_candidate_impl(void *snapshot_id, u_offset_t off)
{
	struct snapshot_id	*sid = snapshot_id;
	struct cow_info *cowp = sid->sid_cowinfo;
	struct cow_map	*cmap = &cowp->cow_map;
	ulong_t chunknumber = off / cmap->cmap_chunksz;

	/* simple bitmap operation for now */
	ASSERT(chunknumber < (cmap->cmap_bmsize * NBBY));
	return (isset(cmap->cmap_candidate, chunknumber));
}

/*
 * fssnap_create_done_impl() - complete the snapshot setup process
 *
 *    called when the file system is done populating the candidate bitmap
 *    and it is ready to start using the snapshot.  This routine releases
 *    the snapshot locks, allows taskq tasks to start processing, and
 *    creates the device minor nodes associated with the snapshot.
 */
static int
fssnap_create_done_impl(void *snapshot_id)
{
	struct snapshot_id	**sidpp, *sidp = snapshot_id;
	struct cow_info		*cowp;
	struct cow_map		*cmap;
	int			snapnumber = -1;
	char			name[20];

	/* sid rwlock and cmap rwlock should be taken from fssnap_create */
	ASSERT(sidp);
	ASSERT(RW_WRITE_HELD(&sidp->sid_rwlock));
	ASSERT(sidp->sid_cowinfo);

	cowp = sidp->sid_cowinfo;
	cmap = &cowp->cow_map;

	ASSERT(RW_WRITE_HELD(&cmap->cmap_rwlock));

	sidp->sid_flags &= ~(SID_CREATING | SID_DISABLED);
	snapnumber = sidp->sid_snapnumber;

	/* allocate state structure and find new snapshot id */
	if (ddi_soft_state_zalloc(statep, snapnumber) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "snap_ioctl: create: could not allocate "
		    "state for snapshot %d.", snapnumber);
		snapnumber = -1;
		goto out;
	}

	sidpp = ddi_get_soft_state(statep, snapnumber);
	*sidpp = sidp;

	/* create minor node based on snapshot number */
	ASSERT(fssnap_dip != NULL);
	(void) snprintf(name, sizeof (name), "%d", snapnumber);
	if (ddi_create_minor_node(fssnap_dip, name, S_IFBLK,
	    snapnumber, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "snap_ioctl: could not create "
		    "block minor node for snapshot %d.", snapnumber);
		snapnumber = -1;
		goto out;
	}

	(void) snprintf(name, sizeof (name), "%d,raw", snapnumber);
	if (ddi_create_minor_node(fssnap_dip, name, S_IFCHR,
	    snapnumber, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "snap_ioctl: could not create "
		    "character minor node for snapshot %d.", snapnumber);
		snapnumber = -1;
	}

out:
	rw_exit(&sidp->sid_rwlock);
	rw_exit(&cmap->cmap_rwlock);

	/* let the taskq threads start processing */
	taskq_resume(cowp->cow_taskq);

	return (snapnumber);
}

/*
 * fssnap_delete_impl() - delete a snapshot
 *
 *    used when a snapshot is no longer needed.  This is called by the file
 *    system when it receives an ioctl request to delete a snapshot.  It is
 *    also called internally when error conditions such as disk full, errors
 *    writing to the backing file, or backing file maxsize exceeded occur.
 *    If the snapshot device is busy when the delete request is received,
 *    all state will be deleted except for the soft state and device files
 *    associated with the snapshot; they will be deleted when the snapshot
 *    device is closed.
 *
 *    NOTE this function takes a POINTER TO A POINTER to the snapshot id,
 *    and expects to be able to set the handle held by the file system to
 *    NULL.  This depends on the file system checking that variable for NULL
 *    before calling fssnap_strategy().
 */
static int
fssnap_delete_impl(void *snapshot_id)
{
	struct snapshot_id	**sidpp = (struct snapshot_id **)snapshot_id;
	struct snapshot_id	*sidp;
	struct snapshot_id	**statesidpp;
	struct cow_info		*cowp;
	struct cow_map		*cmap;
	char			name[20];
	int			snapnumber = -1;
	vnode_t			**vpp;

	/*
	 * sidp is guaranteed to be valid if sidpp is valid because
	 * the snapshot list is append-only.
	 */
	if (sidpp == NULL) {
		return (-1);
	}

	sidp = *sidpp;
	rw_enter(&sidp->sid_rwlock, RW_WRITER);

	ASSERT(RW_WRITE_HELD(&sidp->sid_rwlock));

	/*
	 * double check that the snapshot is still valid for THIS file system
	 */
	if (*sidpp == NULL) {
		rw_exit(&sidp->sid_rwlock);
		return (-1);
	}

	/*
	 * Now we know the snapshot is still valid and will not go away
	 * because we have the write lock.  Once the state is transitioned
	 * to "disabling", the sid_rwlock can be released.  Any pending I/O
	 * waiting for the lock as a reader will check for this state and
	 * abort without touching data that may be getting freed.
	 */
	sidp->sid_flags |= SID_DISABLING;
	if (sidp->sid_flags & SID_DELETE) {
		cmn_err(CE_WARN, "Snapshot %d automatically deleted.",
		    sidp->sid_snapnumber);
		sidp->sid_flags &= ~(SID_DELETE);
	}


	/*
	 * This is pointing into file system specific data!  The assumption is
	 * that fssnap_strategy() gets called from the file system based on
	 * whether this reference to the snapshot_id is NULL or not.  So
	 * setting this to NULL should disable snapshots for the file system.
	 */
	*sidpp = NULL;

	/* remove cowinfo */
	cowp = sidp->sid_cowinfo;
	if (cowp == NULL) {
		rw_exit(&sidp->sid_rwlock);
		return (-1);
	}
	rw_exit(&sidp->sid_rwlock);

	/* destroy task queues first so they don't reference freed data. */
	if (cowp->cow_taskq) {
		taskq_destroy(cowp->cow_taskq);
		cowp->cow_taskq = NULL;
	}

	if (cowp->cow_backfile_array != NULL) {
		for (vpp = cowp->cow_backfile_array; *vpp; vpp++)
			VN_RELE(*vpp);
		kmem_free(cowp->cow_backfile_array,
		    (cowp->cow_backcount + 1) * sizeof (vnode_t *));
		cowp->cow_backfile_array = NULL;
	}

	sidp->sid_cowinfo = NULL;

	/* remove cmap */
	cmap = &cowp->cow_map;
	ASSERT(cmap);

	if (cmap->cmap_candidate)
		kmem_free(cmap->cmap_candidate, cmap->cmap_bmsize);

	if (cmap->cmap_hastrans)
		kmem_free(cmap->cmap_hastrans, cmap->cmap_bmsize);

	if (cmap->cmap_table)
		transtbl_free(&cowp->cow_map);

	rw_destroy(&cmap->cmap_rwlock);

	while (cmap->cmap_waiters) {
		sema_p(&cmap->cmap_throttle_sem);
		sema_v(&cmap->cmap_throttle_sem);
	}
	sema_destroy(&cmap->cmap_throttle_sem);

	/* remove kstats */
	fssnap_delete_kstats(cowp);

	kmem_free(cowp, sizeof (struct cow_info));

	statesidpp = ddi_get_soft_state(statep, sidp->sid_snapnumber);
	if (statesidpp == NULL || *statesidpp == NULL) {
		cmn_err(CE_WARN,
		    "fssnap_delete_impl: could not find state for snapshot %d.",
		    sidp->sid_snapnumber);
	}
	ASSERT(*statesidpp == sidp);

	/*
	 * Leave the node in the list marked DISABLED so it can be reused
	 * and avoid many race conditions.  Return the snapshot number
	 * that was deleted.
	 */
	mutex_enter(&snapshot_mutex);
	rw_enter(&sidp->sid_rwlock, RW_WRITER);
	sidp->sid_flags &= ~(SID_DISABLING);
	sidp->sid_flags |= SID_DISABLED;
	VN_RELE(sidp->sid_fvp);
	sidp->sid_fvp = NULL;
	snapnumber = sidp->sid_snapnumber;

	/*
	 * If the snapshot is not busy, free the device info now.  Otherwise
	 * the device nodes are freed in snap_close() when the device is
	 * closed.  The sid will not be reused until the device is not busy.
	 */
	if (SID_AVAILABLE(sidp)) {
		/* remove the device nodes */
		ASSERT(fssnap_dip != NULL);
		(void) snprintf(name, sizeof (name), "%d",
		    sidp->sid_snapnumber);
		ddi_remove_minor_node(fssnap_dip, name);
		(void) snprintf(name, sizeof (name), "%d,raw",
		    sidp->sid_snapnumber);
		ddi_remove_minor_node(fssnap_dip, name);

		/* delete the state structure */
		ddi_soft_state_free(statep, sidp->sid_snapnumber);
		num_snapshots--;
	}

	mutex_exit(&snapshot_mutex);
	rw_exit(&sidp->sid_rwlock);

	return (snapnumber);
}

/*
 * fssnap_create_kstats() - allocate and initialize snapshot kstats
 *
 */
static void
fssnap_create_kstats(snapshot_id_t *sidp, int snapnum,
    const char *mountpoint, const char *backfilename)
{
	kstat_t *num, *mntpoint, *bfname;
	kstat_named_t *hw;
	struct cow_info *cowp = sidp->sid_cowinfo;
	struct cow_kstat_num *stats;

	/* update the high water mark */
	if (fssnap_highwater_kstat == NULL) {
		cmn_err(CE_WARN, "fssnap_create_kstats: failed to lookup "
		    "high water mark kstat.");
		return;
	}

	hw = (kstat_named_t *)fssnap_highwater_kstat->ks_data;
	if (hw->value.ui32 < snapnum)
		hw->value.ui32 = snapnum;

	/* initialize the mount point kstat */
	kstat_delete_byname(snapname, snapnum, FSSNAP_KSTAT_MNTPT);

	if (mountpoint != NULL) {
		mntpoint = kstat_create(snapname, snapnum, FSSNAP_KSTAT_MNTPT,
		    "misc", KSTAT_TYPE_RAW, strlen(mountpoint) + 1, 0);
		if (mntpoint == NULL) {
			cowp->cow_kstat_mntpt = NULL;
			cmn_err(CE_WARN, "fssnap_create_kstats: failed to "
			    "create mount point kstat");
		} else {
			(void) strncpy(mntpoint->ks_data, mountpoint,
			    strlen(mountpoint));
			cowp->cow_kstat_mntpt = mntpoint;
			kstat_install(mntpoint);
		}
	} else {
		cowp->cow_kstat_mntpt = NULL;
		cmn_err(CE_WARN, "fssnap_create_kstats: mount point not "
		    "specified.");
	}

	/* initialize the backing file kstat */
	kstat_delete_byname(snapname, snapnum, FSSNAP_KSTAT_BFNAME);

	if (backfilename == NULL) {
		cowp->cow_kstat_bfname = NULL;
	} else {
		bfname = kstat_create(snapname, snapnum, FSSNAP_KSTAT_BFNAME,
		    "misc", KSTAT_TYPE_RAW, strlen(backfilename) + 1, 0);
		if (bfname != NULL) {
			(void) strncpy(bfname->ks_data, backfilename,
			    strlen(backfilename));
			cowp->cow_kstat_bfname = bfname;
			kstat_install(bfname);
		} else {
			cowp->cow_kstat_bfname = NULL;
			cmn_err(CE_WARN, "fssnap_create_kstats: failed to "
			    "create backing file name kstat");
		}
	}

	/* initialize numeric kstats */
	kstat_delete_byname(snapname, snapnum, FSSNAP_KSTAT_NUM);

	num = kstat_create(snapname, snapnum, FSSNAP_KSTAT_NUM,
	    "misc", KSTAT_TYPE_NAMED,
	    sizeof (struct cow_kstat_num) / sizeof (kstat_named_t),
	    0);
	if (num == NULL) {
		cmn_err(CE_WARN, "fssnap_create_kstats: failed to create "
		    "numeric kstats");
		cowp->cow_kstat_num = NULL;
		return;
	}

	cowp->cow_kstat_num = num;
	stats = num->ks_data;
	num->ks_update = fssnap_update_kstat_num;
	num->ks_private = sidp;

	kstat_named_init(&stats->ckn_state, FSSNAP_KSTAT_NUM_STATE,
	    KSTAT_DATA_INT32);
	kstat_named_init(&stats->ckn_bfsize, FSSNAP_KSTAT_NUM_BFSIZE,
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->ckn_maxsize, FSSNAP_KSTAT_NUM_MAXSIZE,
	    KSTAT_DATA_UINT64);
	kstat_named_init(&stats->ckn_createtime, FSSNAP_KSTAT_NUM_CREATETIME,
	    KSTAT_DATA_LONG);
	kstat_named_init(&stats->ckn_chunksize, FSSNAP_KSTAT_NUM_CHUNKSIZE,
	    KSTAT_DATA_UINT32);

	/* initialize the static kstats */
	stats->ckn_chunksize.value.ui32 = cowp->cow_map.cmap_chunksz;
	stats->ckn_maxsize.value.ui64 = cowp->cow_map.cmap_maxsize;
	stats->ckn_createtime.value.l = gethrestime_sec();

	kstat_install(num);
}

/*
 * fssnap_update_kstat_num() - update a numerical snapshot kstat value
 *
 */
int
fssnap_update_kstat_num(kstat_t *ksp, int rw)
{
	snapshot_id_t *sidp = (snapshot_id_t *)ksp->ks_private;
	struct cow_info *cowp = sidp->sid_cowinfo;
	struct cow_kstat_num *stats = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/* state */
	if (sidp->sid_flags & SID_CREATING)
		stats->ckn_state.value.i32 = COWSTATE_CREATING;
	else if (SID_INACTIVE(sidp))
		stats->ckn_state.value.i32 = COWSTATE_DISABLED;
	else if (SID_BUSY(sidp))
		stats->ckn_state.value.i32 = COWSTATE_ACTIVE;
	else
		stats->ckn_state.value.i32 = COWSTATE_IDLE;

	/* bfsize */
	stats->ckn_bfsize.value.ui64 = cowp->cow_map.cmap_nchunks *
	    cowp->cow_map.cmap_chunksz;

	return (0);
}

/*
 * fssnap_delete_kstats() - deallocate snapshot kstats
 *
 */
void
fssnap_delete_kstats(struct cow_info *cowp)
{
	if (cowp->cow_kstat_num != NULL) {
		kstat_delete(cowp->cow_kstat_num);
		cowp->cow_kstat_num = NULL;
	}
	if (cowp->cow_kstat_mntpt != NULL) {
		kstat_delete(cowp->cow_kstat_mntpt);
		cowp->cow_kstat_mntpt = NULL;
	}
	if (cowp->cow_kstat_bfname != NULL) {
		kstat_delete(cowp->cow_kstat_bfname);
		cowp->cow_kstat_bfname = NULL;
	}
}

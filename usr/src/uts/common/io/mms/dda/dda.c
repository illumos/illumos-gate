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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Driver for Disk Archiving (dda)
 *
 * DDA emulates the st tape driver BSD mode for MMS disk archiving.
 *
 * A limited number of MTIO operations are implemented by DDA.
 *
 * USCSI commands are not implemented by DDA.
 *
 * Tape drive operations such as load, capacity and read block limits
 * are DDA ioctl commands.
 *
 * DDA media is implemented as a cartridge directory containing three
 * files: metadata, index and data.
 *
 * The metadata file contains cartridge information such as version,
 * capacity, stripe alignment, directio alignment, and the write
 * protect tab.
 *
 * The index file contains index records which describes the media format.
 * An index record contains the data file offset, number of consective
 * same size records and the number of consective filemarks. The data file
 * offset is adjusted for stripe and directio alignment. Stripe alignment
 * occurs at bot and when data follows a filemark. Directio alignment is
 * checked for at bot and the data alignment occurs when the data length
 * is modulus the sector size. An index record that contains updated
 * information is written when a filemark or position change occurs. The
 * index record file is in big endian.
 *
 * The data file contains user data along with holes for stripe and
 * directio alignment.
 *
 */

#include <sys/devops.h>			/* used by dev_ops */
#include <sys/conf.h>			/* used by dev_ops and cb_ops */
#include <sys/modctl.h> 		/* used by modlinkage, modldrv, */
					/* _init, _info, and _fini */
#include <sys/types.h>  		/* used by open, close, read, write, */
					/* prop_op, and ddi_prop_op */
#include <sys/file.h>			/* used by open, close */
#include <sys/errno.h>  		/* used by open, close, read, write */
#include <sys/open.h>			/* used by open, close, read, write */
#include <sys/cred.h>			/* used by open, close, read */
#include <sys/uio.h>			/* used by read */
#include <sys/stat.h>			/* defines S_IFCHR used by */
					/* ddi_create_minor_node */
#include <sys/cmn_err.h>		/* used by all entry points for */
					/* this driver */
#include <sys/ddi.h>			/* used by all entry points for */
					/* this driver also used by cb_ops, */
					/* ddi_get_instance, and ddi_prop_op */
#include <sys/sunddi.h> 		/* used by all entry points for */
					/* this driver also used by cb_ops, */
					/* ddi_create_minor_node, */
					/* ddi_get_instance, and ddi_prop_op */
#include <sys/scsi/impl/uscsi.h>	/* uscsi commands */
#include <sys/ioctl.h>
#include <sys/mtio.h>			/* tape io */
#include <sys/scsi/targets/stdef.h>
#include <sys/fs/ufs_inode.h>
#include <sys/vfs.h>
#include <limits.h>
#include <sys/sdt.h>
#include <sys/flock.h>	/* non-blocking file lock */
#include <nfs/lm.h>
#include "dda.h"

/* vnode mode is read, write, large files, allow symlinks */
#define	DDA_VNODE_MODE FREAD|FWRITE|FOFFMAX

/* maximum block size */
#define	DDA_MAX_REC_SIZE	262144	/* maximum media block size */

/* early warning capacity - space */
#define	DDA_EARLY_WARN		98	/* media early warning percentage */

/* block number unknown */
#define	DDA_BLKNO_UNKNOWN	1000000000

/* file name unknown */
#define	DDA_UNKNOWN_FNAME	"?"

/* operation flags and macros */
#define	DDA_FLAG_TRUNC		0x1	/* write truncate */
#define	DDA_FLAG_FM_FWD_PEND	0x2	/* file mark forward pending */
#define	DDA_FLAG_FM_NOSKIP	0x4	/* fsr set fm forward pending */
#define	DDA_FLAG_FM_NEEDED	0x8	/* file mark needed */
#define	DDA_FLAG_EOT_EIO	0x10	/* read return code for eot */
#define	DDA_FLAG_EW		0x20	/* alternating ew write failure */
#define	DDA_FLAG_INDEX		0x40	/* index record needs file write */

#define	DDA_GET_TRUNC(x)	(x->dda_flags & DDA_FLAG_TRUNC)
#define	DDA_GET_FM_FWD_PEND(x)	(x->dda_flags & DDA_FLAG_FM_FWD_PEND)
#define	DDA_GET_FM_NOSKIP(x)	(x->dda_flags & DDA_FLAG_FM_NOSKIP)
#define	DDA_GET_FM_NEEDED(x)	(x->dda_flags & DDA_FLAG_FM_NEEDED)
#define	DDA_GET_EOT_EIO(x)	(x->dda_flags & DDA_FLAG_EOT_EIO)
#define	DDA_GET_EW(x)		(x->dda_flags & DDA_FLAG_EW)
#define	DDA_GET_INDEX(x)	(x->dda_flags & DDA_FLAG_INDEX)

#define	DDA_SET_TRUNC(x)	(x->dda_flags |= DDA_FLAG_TRUNC)
#define	DDA_SET_FM_FWD_PEND(x)	(x->dda_flags |= DDA_FLAG_FM_FWD_PEND)
#define	DDA_SET_FM_NOSKIP(x)	(x->dda_flags |= DDA_FLAG_FM_NOSKIP)
#define	DDA_SET_FM_NEEDED(x)	(x->dda_flags |= DDA_FLAG_FM_NEEDED)
#define	DDA_SET_EOT_EIO(x)	(x->dda_flags |= DDA_FLAG_EOT_EIO)
#define	DDA_SET_EW(x)		(x->dda_flags |= DDA_FLAG_EW)
#define	DDA_SET_INDEX(x)	(x->dda_flags |= DDA_FLAG_INDEX)

#define	DDA_CLR_TRUNC(x)	(x->dda_flags &= ~DDA_FLAG_TRUNC)
#define	DDA_CLR_FM_FWD_PEND(x)	(x->dda_flags &= ~(DDA_FLAG_FM_FWD_PEND | \
						    DDA_FLAG_FM_NOSKIP))
#define	DDA_CLR_FM_NOSKIP(x)	(x->dda_flags &= ~DDA_FLAG_FM_NOSKIP)
#define	DDA_CLR_FM_NEEDED(x)	(x->dda_flags &= ~DDA_FLAG_FM_NEEDED)
#define	DDA_CLR_EOT_EIO(x)	(x->dda_flags &= ~DDA_FLAG_EOT_EIO)
#define	DDA_CLR_EW(x)		(x->dda_flags &= ~DDA_FLAG_EW)
#define	DDA_CLR_INDEX(x)	(x->dda_flags &= ~DDA_FLAG_INDEX)

/* metadata flag */
#define	DDA_GET_WPROTECT(x)	(x->dda_metadata.dda_flags & DDA_FLAG_WPROTECT)

/* read only tape */
#define	DDA_GET_READ_ONLY(x)	((x->dda_read_only || \
				    DDA_GET_WPROTECT(x)) ? 1 : 0)

/* alignment macros */
#define	DDA_OFF_ALIGNED(off, sz)	(off & (int64_t)(sz - 1))
#define	DDA_LEN_ALIGNED(len, sz)	((size_t)len & (sz - 1))

/* index record calculations */
#define	DDA_IS_BOT(x)		(x->dda_index_offset == 0 && \
				    x->dda_pos == 0 ? 1 : 0)
#define	DDA_IS_BLANK(x)		(x->dda_index_offset == 0 && \
				    DDA_INDEX_COUNT(x) == 0 ? 1 : 0)
#define	DDA_IS_FM(x)		(DDA_IS_BLANK(x) ? 0 : \
				    x->dda_index.dda_fmcount && \
				    x->dda_pos >= x->dda_index. \
				    dda_blkcount && \
				    x->dda_pos <= DDA_INDEX_COUNT(x) ? 1 : 0)
#define	DDA_LBA(x)		(x->dda_index.dda_lba + x->dda_pos)
#define	DDA_INDEX_COUNT(x)	(x->dda_index.dda_blkcount + \
				    x->dda_index.dda_fmcount)

#ifdef	DEBUG
#define	DDA_DEBUG(y) y
#else
#define	DDA_DEBUG(y)
#endif

#define	DDA_DEBUG1(x) DDA_DEBUG(DTRACE_PROBE1 x)
#define	DDA_DEBUG2(x) DDA_DEBUG(DTRACE_PROBE2 x)
#define	DDA_DEBUG3(x) DDA_DEBUG(DTRACE_PROBE3 x)
#define	DDA_DEBUG4(x) DDA_DEBUG(DTRACE_PROBE4 x)

/* index record state */
typedef struct dda_istate {
	dda_index_t	dda_index;
	off64_t		dda_index_offset;
	int64_t		dda_pos;
	uint32_t	dda_flags;
} dda_istate_t;

/* driver operations */
static int dda_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int dda_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int dda_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int dda_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int dda_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int dda_read(dev_t dev, struct uio *uio, cred_t *credp);
static int dda_write(dev_t dev, struct uio *uio, cred_t *credp);
static int dda_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);

/* tape operations */
static int dda_tape_op(dda_t *dda, struct mtlop *mtop);
static int dda_tape_load(dda_t *dda, char *path);
static int dda_tape_unload(dda_t *dda);
static int dda_tape_rewind(dda_t *dda);
static int dda_tape_write(dda_t *dda, struct uio *uio);
static int dda_tape_read(dda_t *dda, struct uio *uio);
static int dda_tape_wfm(dda_t *dda, int count);
static int dda_tape_eom(dda_t *dda);
static int dda_tape_fsf(dda_t *dda, int count);
static int dda_tape_bsf(dda_t *dda, int count);
static int dda_tape_fsr(dda_t *dda, int count);
static int dda_tape_bsr(dda_t *dda, int count);
static int dda_tape_locate(dda_t *dda, int64_t position);
static int dda_tape_erase(dda_t *dda);

/* support routines */
static void dda_gen_serial_num(dda_t *dda);
static void dda_set_unloaded(dda_t *dda);
static int64_t dda_get_fileno(dda_t *dda);
static int dda_get_blkno(dda_t *dda, int64_t *blkno);
static int dda_write_truncate(dda_t *dda);

/* index record write, read, generate, save and restore */
static int dda_write_index(dda_t *dda);
static int dda_read_index(dda_t *dda);
static void dda_gen_next_index(dda_t *dda, int32_t blksize);
static void dda_save_istate(dda_t *dda, dda_istate_t *istate);
static void dda_restore_istate(dda_t *dda, dda_istate_t *istate);

/* stripe and directio alignment */
static off64_t dda_stripe_align(dda_t *dda);
static off64_t dda_data_offset(dda_t *dda);
static int dda_sector_align(dda_t *dda);

/* space */
static int dda_tape_capacity(dda_t *dda, int64_t *space);
static int dda_ew_eom(dda_t *dda, int32_t count, int64_t *avail, int *ew);

/* search */
static int dda_locate_compare(dda_t *dda, int64_t lba);
static int dda_fsf_compare(dda_t *dda, int64_t fileno);
static int dda_bsf_compare(dda_t *dda, int64_t fileno);
static int dda_bsearch(dda_t *dda,
    int64_t key,
    int (*compare)(dda_t *, int64_t),
    int *found);

/* vnode operations */
static int dda_vn_open(dda_t *dda, struct vnode **vpp, char *fname);
static int dda_vn_close(dda_t *dda, struct vnode **vpp);
static int dda_vn_lock(dda_t *dda, struct vnode *vp, short lock);
static int dda_vn_read(dda_t *dda, struct vnode *vp, void *buf, int len,
    off64_t offset);
static int dda_vn_write(dda_t *dda, struct vnode *vp, void *buf, int len,
    off64_t offset);
static int dda_vn_truncate(dda_t *dda, struct vnode *vp, off64_t offset);
static int dda_vn_sync(dda_t *dda, struct vnode *vp);
static int dda_vn_size(dda_t *dda, struct vnode *vp, off64_t *fsize);
static char *dda_vn_get_fname(dda_t *dda, struct vnode *vp);
static void dda_vn_error_skey(dda_t *dda, int err);

/* cb_ops structure */
static struct cb_ops dda_cb_ops = {
	dda_open,
	dda_close,
	nodev,			/* no strategy - nodev returns ENXIO */
	nodev,			/* no print */
	nodev,			/* no dump */
	dda_read,
	dda_write,
	dda_ioctl,
	nodev,			/* no devmap */
	nodev,			/* no mmap */
	nodev,			/* no segmap */
	nochpoll,		/* returns ENXIO for non-pollable devices */
	ddi_prop_op,
	NULL,			/* streamtab struct; if not NULL, all above */
	/* fields are ignored */
	D_NEW | D_MP,		/* compatibility flags: see conf.h */
	CB_REV,			/* cb_ops revision number */
	nodev,			/* no aread */
	nodev			/* no awrite */
};

/* dev_ops structure */
static struct dev_ops dda_dev_ops = {
	DEVO_REV,
	0,			/* reference count */
	dda_getinfo,
	nulldev,		/* no identify - nulldev returns 0 */
	nulldev,		/* no probe */
	dda_attach,
	dda_detach,
	nodev,			/* no reset - nodev returns ENXIO */
	&dda_cb_ops,
	(struct bus_ops *)NULL,
	nodev			/* no power */
};

/* modldrv structure */
#define	DDA_LINKINFO "driver for disk archiving"
static char dda_linkinfo[100];
static struct modldrv dda_md = {
	&mod_driverops,
	dda_linkinfo,
	&dda_dev_ops
};

/* modlinkage structure */
static struct modlinkage dda_ml = {
	MODREV_1,
	&dda_md,
	NULL
};

/* dev_info structure, one instance per dda device */
static void *dda_state;
extern char hw_serial[];

/* Loadable module configuration entry points */

/*
 * _init
 *
 * Parameters:
 *	None
 *
 * Globals:
 *	- dda_state:	Uninitialized list of DDA drives.
 *	- dda_linkinfo:	DDA description string.
 *	- dda_ml:	DDA module linkage structure.
 *
 * Initialize list of emulated tape drives.
 * Create driver description reported to user.
 * Export driver specification to the kernel.
 *
 * Return Values:
 *	0 : success
 *	non-zero : failure
 *
 */
int
_init(void)
{
	int	rc;

	if ((rc = ddi_soft_state_init(&dda_state, sizeof (dda_t), 0)) != 0) {
		cmn_err(CE_WARN, "_init: soft state init error %d", rc);
		return (rc);
	}
	(void) snprintf(dda_linkinfo, sizeof (dda_linkinfo), "%s %d.%d",
	    DDA_LINKINFO, DDA_MAJOR_VERSION, DDA_MINOR_VERSION);
	if ((rc = mod_install(&dda_ml)) != 0) {
		cmn_err(CE_WARN, "_init: mod install error %d", rc);
		ddi_soft_state_fini(&dda_state);
	}
	return (rc);
}

/*
 * _info
 *
 * Parameters:
 *	- modinfop:	Opaque module information structure.
 *
 * Globals:
 *	- dda_ml:       DDA module linkage structure.
 *
 * Report DDA module information.
 *
 * Return Values:
 *      non-zero : success
 *      0 : failure
 *
 */
int
_info(struct modinfo *modinfop)
{
	int	rc;

	if ((rc = mod_info(&dda_ml, modinfop)) == 0) {
		cmn_err(CE_WARN, "_info: mod info error %d", rc);
	}
	return (rc);
}

/*
 * _fini
 *
 * Parameters:
 *	- none
 *
 * Globals:
 *	- dda_ml:       DDA module linkage structure.
 *	- dda_state:	DDA drive list.
 *
 * Prepare to unload the DDA driver from the kernel.
 * Release DDA drive list to the system.
 *
 * Return Values:
 *      0 : success
 *      non-zero : failure
 *
 */
int
_fini(void)
{
	int	rc;

	if ((rc = mod_remove(&dda_ml)) != 0) {
		return (rc);
	}
	ddi_soft_state_fini(&dda_state);
	return (rc);
}

/* Device configuration entry points */

/*
 * dda_attach
 *
 * Parameters:
 *	- dip:		Device information structure.
 *	- cmd:		Attach command.
 *
 * Globals:
 *	- dda_state:	Pointer to list of DDA drives.
 *
 * Create and initialize one DDA tape drive for each dda.conf instance.
 * Create BSD no-rewind tape drive minor node.
 * Assign generated serial number to the drive.
 * Initialize exclusive drive access mutex.
 * Set drive state to unload.
 *
 * Return Values:
 *      DDI_SUCCESS : success
 *      DDI_FAILURE : failure
 *
 */
static int
dda_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	dda_t		*dda;

	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(dda_state, instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%d attach soft state alloc failed",
			    instance);
			return (DDI_FAILURE);
		}

		if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
			ddi_soft_state_free(dda_state, instance);
			cmn_err(CE_WARN, "%d attach get soft state failed",
			    instance);
			return (DDI_FAILURE);
		}
		dda->dda_inst = -1;

		if (ddi_create_minor_node(dip, "bn", S_IFCHR,
		    instance, DDI_PSEUDO, 0) != DDI_SUCCESS) {
			ddi_soft_state_free(dda_state, instance);
			cmn_err(CE_WARN, "%d attach create minor node failed",
			    instance);
			return (DDI_FAILURE);
		}

		dda->dda_dip = dip;
		dda->dda_inst = instance;
		dda_gen_serial_num(dda);
		mutex_init(&dda->dda_mutex, NULL, MUTEX_DRIVER, NULL);
		dda_set_unloaded(dda);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * dda_detach
 *
 * Parameters:
 *	- dip:		Device information structure.
 *	- cmd:		Detach command.
 *
 * Globals:
 *	- dda_state:	Pointer to list of DDA drives.
 *
 * Get drive instance from the list of drives.
 * If media is loaded in the drive then unload the media.
 * Remove minor device node.
 * Release exclusive access mutex.
 * Release memory.
 *
 * Return Values:
 *      DDI_SUCCESS : success
 *      DDI_FAILURE : failure
 *
 */
static int
dda_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance = ddi_get_instance(dip);
	dda_t	*dda;

	switch (cmd) {
	case DDI_DETACH:
		if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
			cmn_err(CE_WARN, "%d detach get soft state failed",
			    instance);
			return (DDI_FAILURE);
		}
		if (dda->dda_loaded) {
			dda->dda_cred = kcred;
			(void) dda_tape_unload(dda);
		}
		ddi_remove_minor_node(dip, "bn");
		mutex_destroy(&dda->dda_mutex);
		ddi_soft_state_free(dda_state, instance);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * dda_getinfo
 *
 * Parameters:
 *	- dip:		Device information structure.
 *	- cmd:		Information command.
 *	- arg:		Device structure.
 *	- resultp:	Pointer for information requested.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Return drive instance information to the kernel.
 *
 * Return Values:
 *      DDI_SUCCESS : success
 *      DDI_FAILURE : failure
 *
 */
/*ARGSUSED*/
static int
dda_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	int	instance = getminor((dev_t)arg);
	dda_t	*dda;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((dda = ddi_get_soft_state(dda_state,
		    instance)) == NULL) {
			cmn_err(CE_WARN, "%d getinfo get soft state failed",
			    instance);
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = dda->dda_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	default:
		*resultp = NULL;
		return (DDI_FAILURE);
	}
}

/* Main entry points */

/*
 * dda_open
 *
 * Parameters:
 *	- devp:		Device structure.
 *	- flag:		Device open mode.
 *	- otyp:		Character or block device open.
 *	- credp:	User credentials.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Verify character device open.
 * Get drive structure.
 * Lock drive to ensure sequential access.
 * If drive is already in-use then unlock drive and return busy.
 * If drive is not loaded then prevent read only or write non-blocking
 * access to the drive.
 * Save open process pid as the test for drive in-use.
 * Set read only mode.
 * Unlock drive.
 *
 * Return Values:
 *      DDI_SUCCESS : success
 *      DDI_FAILURE : failure
 *
 */
static int
dda_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	instance = getminor(*devp);
	dda_t	*dda;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}
	if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
		return (ENXIO);
	}
	mutex_enter(&dda->dda_mutex);
	if (dda->dda_pid) {
		/*
		 * The real tape driver does not allow a drive to be
		 * opened multiple times.
		 */
		mutex_exit(&dda->dda_mutex);
		return (EBUSY);
	}
	if (!dda->dda_loaded) {
		/*
		 * The real tape driver does not allow an unloaded tape
		 * drive to be opened in read only or blocking mode.
		 */
		if ((flag & FWRITE) == 0 ||
		    ((flag & FWRITE) == FWRITE &&
		    (flag & (FNDELAY | FNONBLOCK)) == 0)) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
	}

	/* user credentials */
	dda->dda_cred = credp;

	/* set open flag */
	dda->dda_pid = ddi_get_pid();

	/* get read only mode */
	dda->dda_read_only = (flag & FWRITE) ? 0 : 1;
	DDA_DEBUG2((dda_pid,
	    int, dda->dda_inst,
	    pid_t, dda->dda_pid));
	mutex_exit(&dda->dda_mutex);
	return (0);
}

/*
 * dda_open
 *
 * Parameters:
 *	- devp:		Device structure.
 *	- flag:		Device open mode.
 *	- otyp:		Character or block device open.
 *	- credp:	User credentials.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Verify character device close.
 * Get drive structure.
 * Lock drive to ensure sequential access.
 * Append filemark if loaded and needed.
 * Unlock drive.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	instance = getminor(dev);
	dda_t	*dda;
	int	err = 0;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}
	if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
		return (ENXIO);
	}
	mutex_enter(&dda->dda_mutex);
	dda->dda_cred = credp;
	DDA_DEBUG2((dda_pid,
	    int, dda->dda_inst,
	    pid_t, dda->dda_pid));
	if (DDA_GET_FM_FWD_PEND(dda)) {
		DDA_CLR_FM_FWD_PEND(dda);
		DDA_CLR_FM_NEEDED(dda);
	}
	if ((flag & FWRITE) &&
	    DDA_GET_FM_NEEDED(dda) &&
	    DDA_GET_READ_ONLY(dda) == 0) {
		err = dda_tape_wfm(dda, 1);
	} else {
		dda->dda_resid = 0;
	}
	dda->dda_pid = 0;
	/* only reset record size at bot for bsb no rewind */
	if (DDA_IS_BOT(dda)) {
		dda->dda_rec_size = 0;
		dda->dda_ili = 0;
	}
	mutex_exit(&dda->dda_mutex);
	return (err);
}

/*
 * dda_read
 *
 * Parameters:
 *	- dev:		Device structure.
 *	- uio:		Vector I/O operations.
 *	- credp:	User credentials.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Get drive structure.
 * Lock drive to ensure sequential access.
 * Call tape read function.
 * Unlock drive.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	int	instance = getminor(dev);
	dda_t	*dda;
	int	err;

	if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
		return (ENXIO);
	}
	mutex_enter(&dda->dda_mutex);
	dda->dda_cred = credp;
	err = dda_tape_read(dda, uio);
	mutex_exit(&dda->dda_mutex);
	return (err);
}

/*
 * dda_write
 *
 * Parameters:
 *	- dev:		Device structure.
 *	- uio:		Vector I/O operations.
 *	- credp:	User credentials.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Get drive structure.
 * Lock drive to ensure sequential access.
 * Call tape write function.
 * Unlock drive.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	int	instance = getminor(dev);
	dda_t	*dda;
	int	err;

	if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
		return (ENXIO);
	}
	mutex_enter(&dda->dda_mutex);
	dda->dda_cred = credp;
	err = dda_tape_write(dda, uio);
	mutex_exit(&dda->dda_mutex);
	return (err);
}

/*
 * dda_ioctl
 *
 * Parameters:
 *	- dev:		Device structure.
 *	- cmd:		DDA or MTIO command.
 *	- flag:		User data model.
 *	- credp:	User credentials.
 *	- rvalp:	Return error number.
 *
 * Globals:
 *	- dda_state:	List of DDA emulated tape drives.
 *
 * Interface to execute DDA commands and selected MTIO commands.
 *
 * The DDA commands perform operations normally handled by a real tape
 * drive such as load, capacity, write protect tab, read block limits,
 * loaded cartridge pcl.
 *
 * MTIO commands support unload, motion, write filemark, erase, drive status,
 * drive type, record size, and setting incorrect length indicator.
 *
 * Get drive structure.
 * Determine command to execute.
 * Lock drive to ensure sequential access.
 * Call function to emulate MTIO functionality.
 * Unlock drive.
 *
 * Return Values:
 *	Cartridge write protect command:
 *	0 : read only
 *	-1 : read write
 *
 *	All other commands:
 *      0 : success
 *      errno : failure
 *
 * Note:
 *	DDA emulates BSD no-rewind behavior.
 *
 */
/*ARGSUSED5*/
static int
dda_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp, int *rvalp)
{
	int	instance = getminor(dev);
	dda_t	*dda;
	int	tmp;
	char	*path;
	int	err = 0;


	if ((dda = ddi_get_soft_state(dda_state, instance)) == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case DDA_CMD_LOAD: {
		path = kmem_alloc(PATH_MAX, KM_SLEEP);
		if (ddi_copyin((void *)arg, path, PATH_MAX, flag)) {
			err = EFAULT;
		} else {
			mutex_enter(&dda->dda_mutex);
			dda->dda_cred = credp;
			err = dda_tape_load(dda, path);
			mutex_exit(&dda->dda_mutex);
		}
		kmem_free(path, PATH_MAX);
		return (err);
	}
	case DDA_CMD_NAME: {
		mutex_enter(&dda->dda_mutex);
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		path = kmem_alloc(PATH_MAX, KM_SLEEP);
		(void) snprintf(path, PATH_MAX, "%s", dda->dda_path);
		mutex_exit(&dda->dda_mutex);
		if (ddi_copyout(path, (void *)arg, PATH_MAX, flag)) {
			err = EFAULT;
		}
		kmem_free(path, PATH_MAX);
		return (err);
	}
	case DDA_CMD_CAPACITY: {
		dda_capacity_t		capacity;

		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		dda->dda_resid = 0;
		capacity.dda_capacity = dda->dda_metadata.dda_capacity;
		if (err = dda_tape_capacity(dda, &capacity.dda_space)) {
			mutex_exit(&dda->dda_mutex);
			return (err);
		}
		mutex_exit(&dda->dda_mutex);
		if (ddi_copyout(&capacity, (void *)arg,
		    sizeof (dda_capacity_t), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DDA_CMD_WPROTECT: {
		mutex_enter(&dda->dda_mutex);
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		dda->dda_resid = 0;
		if (DDA_GET_WPROTECT(dda) != 0) {
			mutex_exit(&dda->dda_mutex);
			/* write protect tab on */
			return (0);
		}
		mutex_exit(&dda->dda_mutex);
		/* write protect tab off */
		return (-1);
	}
	case DDA_CMD_BLKLMT: {
		dda_blklmt_t	blklmt;

		blklmt.dda_blkmax = DDA_MAX_REC_SIZE;
		blklmt.dda_blkmin = 1;

		mutex_enter(&dda->dda_mutex);
		dda->dda_resid = 0;
		mutex_exit(&dda->dda_mutex);

		if (ddi_copyout(&blklmt, (void *)arg,
		    sizeof (dda_blklmt_t), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case DDA_CMD_SERIAL: {
		dda_serial_t	serial;

		mutex_enter(&dda->dda_mutex);
		dda->dda_resid = 0;
		(void) snprintf(serial, sizeof (dda_serial_t), "%s",
		    dda->dda_serial);
		mutex_exit(&dda->dda_mutex);
		if (ddi_copyout(serial, (void *)arg,
		    sizeof (dda_serial_t), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case USCSICMD: {
		return (ENOTTY);
	}
	case MTIOCGETPOS: {
		tapepos_t	pos;
		int64_t		blkno;

		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		dda->dda_resid = 0;

		bzero(&pos, sizeof (tapepos_t));
		pos.lgclblkno = DDA_LBA(dda);
		pos.fileno = dda_get_fileno(dda);
		(void) dda_get_blkno(dda, &blkno);
		pos.blkno = (UINT32_MAX & blkno);
		pos.pmode = logical;

		mutex_exit(&dda->dda_mutex);
		if (ddi_copyout(&pos, (void *)arg,
		    sizeof (tapepos_t), flag)) {
			return (EFAULT);
		}
		return (0);
	}
	case MTIOCRESTPOS: {
		tapepos_t	pos;

		if (ddi_copyin((void *)arg, &pos,
		    sizeof (tapepos_t), flag)) {
			return (EFAULT);
		}
		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		if (pos.pmode != logical) {
			mutex_exit(&dda->dda_mutex);
			return (EINVAL);
		}
		err = dda_tape_locate(dda, pos.lgclblkno);
		mutex_exit(&dda->dda_mutex);
		return (err);
	}
	case MTIOCLTOP: {
		struct	mtlop	local;
		int	rval;

		if (ddi_copyin((void *)arg, &local, sizeof (local), flag)) {
			return (EFAULT);
		}

		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		rval = dda_tape_op(dda, &local);
		mutex_exit(&dda->dda_mutex);

		if (ddi_copyout(&local, (void *)arg, sizeof (local), flag)) {
			rval = EFAULT;
		}
		return (rval);
	}
	case MTIOCTOP: {
#ifdef _MULTI_DATAMODEL
		/*
		 * For use when a 32 bit app makes a call into a
		 * 64 bit ioctl
		 */
		struct mtop32   mtop_32_for_64;
#endif /* _MULTI_DATAMODEL */
		struct mtop passed;
		struct mtlop local;
		int rval = 0;

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)arg, &mtop_32_for_64,
			    sizeof (struct mtop32), flag)) {
				return (EFAULT);
			}
			local.mt_op = mtop_32_for_64.mt_op;
			local.mt_count =  (int64_t)mtop_32_for_64.mt_count;
			break;

		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &passed,
			    sizeof (passed), flag)) {
				return (EFAULT);
			}
			local.mt_op = passed.mt_op;
			/* prevent sign extension */
			local.mt_count = (UINT32_MAX & passed.mt_count);
			break;
		}

#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &passed, sizeof (passed), flag)) {
			return (EFAULT);
		}
		local.mt_op = passed.mt_op;
		/* prevent sign extension */
		local.mt_count = (UINT32_MAX & passed.mt_count);
#endif /* _MULTI_DATAMODEL */

		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		rval = dda_tape_op(dda, &local);
		mutex_exit(&dda->dda_mutex);

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (((uint64_t)local.mt_count) > UINT32_MAX) {
				rval = ERANGE;
				break;
			}
			/*
			 * Convert 64 bit back to 32 bit before doing
			 * copyout. This is what the ILP32 app expects.
			 */
			mtop_32_for_64.mt_op = local.mt_op;
			mtop_32_for_64.mt_count = (daddr32_t)local.mt_count;

			if (ddi_copyout(&mtop_32_for_64, (void *)arg,
			    sizeof (struct mtop32), flag)) {
				rval = EFAULT;
			}
			break;

		case DDI_MODEL_NONE:
			passed.mt_count = local.mt_count;
			passed.mt_op = local.mt_op;
			if (ddi_copyout(&passed, (void *)arg,
			    sizeof (passed), flag)) {
				rval = EFAULT;
			}
			break;
		}
#else /* ! _MULTI_DATAMODE */
		if (((uint64_t)local.mt_count) > UINT32_MAX) {
			rval = ERANGE;
		} else {
			passed.mt_op = local.mt_op;
			passed.mt_count = (daddr32_t)local.mt_count;
			if (ddi_copyout(&passed, (void *)arg,
			    sizeof (passed), flag)) {
				rval = EFAULT;
			}
		}
#endif /* _MULTI_DATAMODE */
		return (rval);
	}
	case MTIOCGET: {
#ifdef	_MULTI_DATAMODEL
		struct mtget32	mtg_local32;
		struct mtget32	*mtget_32 = &mtg_local32;
#endif	/* _MULTI_DATAMODEL */
		struct mtget mtg_local;
		struct mtget *mtget = &mtg_local;

		bzero(mtget, sizeof (struct mtget));
		mutex_enter(&dda->dda_mutex);
		dda->dda_cred = credp;
		if (!dda->dda_loaded) {
			mtget->mt_erreg = KEY_NOT_READY;
			mtget->mt_resid = 0;
			mtget->mt_fileno = -1;
			mtget->mt_blkno = 0;
		} else {
			mtget->mt_erreg = dda->dda_status;
			mtget->mt_resid = dda->dda_resid;
			mtget->mt_fileno = dda_get_fileno(dda);
			mtget->mt_blkno = dda->dda_blkno;
		}
		mtget->mt_type = MT_ISOTHER;
		mtget->mt_flags = MTF_SCSI /* | MTF_ASF */;
		mtget->mt_bf = 1;

		dda->dda_status = 0;
		dda->dda_resid = 0;
		tmp = sizeof (struct mtget);

		DDA_CLR_FM_NEEDED(dda);
		DDA_DEBUG3((dda_cmd_status,
		    int, dda->dda_inst,
		    short, mtget->mt_erreg,
		    int32_t, mtget->mt_resid));
		mutex_exit(&dda->dda_mutex);

#ifdef	_MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			mtget_32->mt_erreg =	mtget->mt_erreg;
			mtget_32->mt_resid =	mtget->mt_resid;
			mtget_32->mt_dsreg =	mtget->mt_dsreg;
			mtget_32->mt_fileno =	(daddr32_t)mtget->mt_fileno;
			mtget_32->mt_blkno =	(daddr32_t)mtget->mt_blkno;
			mtget_32->mt_type =	mtget->mt_type;
			mtget_32->mt_flags =	mtget->mt_flags;
			mtget_32->mt_bf =	mtget->mt_bf;

			if (ddi_copyout(mtget_32, (void *)arg,
			    sizeof (struct mtget32), flag)) {
				return (EFAULT);
			}
			break;
		case DDI_MODEL_NONE:
			if (ddi_copyout(mtget, (void *)arg, tmp, flag)) {
				return (EFAULT);
			}
			break;
		}
#else	/* ! _MULTI_DATAMODE */
		if (ddi_copyout(mtget, (void *)arg, tmp, flag)) {
			return (EFAULT);
		}
#endif	/* _MULTI_DATAMODE */

		return (0);
	}
	case MTIOCGETDRIVETYPE: {
#ifdef	_MULTI_DATAMODEL
		struct mtdrivetype_request32	mtdtrq32;
#endif	/* _MULTI_DATAMODEL */
		struct mtdrivetype_request mtdtrq;
		struct mtdrivetype mtdrtyp;
		struct mtdrivetype *mtdt = &mtdrtyp;

#ifdef	_MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			if (ddi_copyin((void *)arg, &mtdtrq32,
			    sizeof (struct mtdrivetype_request32), flag)) {
				return (EFAULT);
			}
			mtdtrq.size = mtdtrq32.size;
			mtdtrq.mtdtp =
			    (struct  mtdrivetype *)(uintptr_t)mtdtrq32.mtdtp;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &mtdtrq,
			    sizeof (struct mtdrivetype_request), flag)) {
				return (EFAULT);
			}
			break;
		}
#else	/* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &mtdtrq,
		    sizeof (struct mtdrivetype_request), flag)) {
			return (EFAULT);
		}
#endif	/* _MULTI_DATAMODEL */

		if (mtdtrq.size < 0) {
			return (EINVAL);
		}
		bzero(mtdt, sizeof (struct mtdrivetype));
		(void) strncpy(mtdt->name, DDA_ST_NAME, ST_NAMESIZE);
		(void) strncpy(mtdt->vid, DDA_VID, VIDPIDLEN);
		mtdt->type = MT_ISOTHER;
		mtdt->bsize = 0;
		mtdt->options = ST_VARIABLE |
		    ST_READ_IGNORE_ILI |
		    ST_BSF |
		    ST_BSR |
		    ST_KNOWS_EOD |
		    ST_UNLOADABLE |
		    ST_NO_RESERVE_RELEASE;
		tmp = sizeof (struct mtdrivetype);
		if (mtdtrq.size < tmp)
			tmp = mtdtrq.size;
		if (ddi_copyout(mtdt, mtdtrq.mtdtp, tmp, flag)) {
			return (EFAULT);
		}
		mutex_enter(&dda->dda_mutex);
		DDA_CLR_FM_NEEDED(dda);
		mutex_exit(&dda->dda_mutex);
		return (0);
	}
	case MTIOCREADIGNOREILI: {
		int	set_ili;

		if (ddi_copyin((void *)arg, &set_ili,
		    sizeof (set_ili), flag)) {
			return (EFAULT);
		}

		mutex_enter(&dda->dda_mutex);
		if (!dda->dda_loaded) {
			mutex_exit(&dda->dda_mutex);
			return (EIO);
		}
		if (dda->dda_rec_size) {
			mutex_exit(&dda->dda_mutex);
			return (ENOTTY);
		}
		if (set_ili != 0 && set_ili != 1) {
			mutex_exit(&dda->dda_mutex);
			return (EINVAL);
		}
		dda->dda_ili = set_ili;
		DDA_DEBUG2((dda_cmd_ili,
		    int, dda->dda_inst,
		    int, dda->dda_ili));
		DDA_CLR_FM_NEEDED(dda);
		mutex_exit(&dda->dda_mutex);
		return (0);
	}

	} /* switch end */

	return (ENOTTY);
}

/* tape operations */

/*
 * dda_tape_op
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- mtop:		Magnetic tape operation structure.
 *
 * Perform the MTIO command by calling the appropriate DDA function.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_tape_op(dda_t *dda, struct mtlop *mtop)
{
	int	err;

	switch (mtop->mt_op) {
	case MTTELL:
		if (!dda->dda_loaded) {
			return (EIO);
		}
		mtop->mt_count = DDA_LBA(dda);
		return (0);
	case MTSEEK: {
		int64_t	lba;

		if (!dda->dda_loaded) {
			return (EIO);
		}
		if (err = dda_tape_locate(dda, mtop->mt_count)) {
			lba = DDA_LBA(dda);
		}
		if (err && mtop->mt_count != lba) {
			/* turn seek into tell command */
			mtop->mt_op = MTTELL;
			mtop->mt_count = lba;
		}
		return (err);
	}
	case MTWEOF:
		if (mtop->mt_count < 0) {
			return (EINVAL);
		}
		err = dda_tape_wfm(dda, mtop->mt_count);
		return (err);
	case MTFSF:
		err = dda_tape_fsf(dda, mtop->mt_count);
		return (err);
	case MTBSF:
		err = dda_tape_bsf(dda, mtop->mt_count);
		return (err);
	case MTFSR:
		err = dda_tape_fsr(dda, mtop->mt_count);
		return (err);
	case MTBSR:
		err = dda_tape_bsr(dda, mtop->mt_count);
		return (err);
	case MTRETEN:
	case MTREW:
		err = dda_tape_rewind(dda);
		return (err);
	case MTNOP:
		DDA_DEBUG3((dda_cmd_nop,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda),
		    int64_t, dda_get_fileno(dda)));
		return (0);
	case MTERASE:
		err = dda_tape_erase(dda);
		return (err);
	case MTEOM:
		err = dda_tape_eom(dda);
		return (err);
	case MTOFFL:
		err = dda_tape_unload(dda);
		return (err);
	case MTSRSZ:
		if (mtop->mt_count < 0) {
			return (EINVAL);
		}
		if (mtop->mt_count > DDA_MAX_REC_SIZE) {
			return (EINVAL);
		}
		if (!dda->dda_loaded) {
			return (EIO);
		}
		dda->dda_rec_size = mtop->mt_count;

		if (dda->dda_rec_size) {
			dda->dda_ili = 0;
		}

		DDA_DEBUG3((dda_cmd_srsz,
		    int, dda->dda_inst,
		    int32_t, dda->dda_rec_size,
		    int, dda->dda_ili));
		DDA_CLR_FM_NEEDED(dda);
		return (0);
	case MTGRSZ:
		if (!dda->dda_loaded) {
			return (EIO);
		}
		mtop->mt_count = dda->dda_rec_size;
		DDA_DEBUG3((dda_cmd_grsz,
		    int, dda->dda_inst,
		    int32_t, dda->dda_rec_size,
		    int, dda->dda_ili));
		return (0);
	}
	return (ENOTTY);
}

/*
 * dda_tape_load
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- path:		DDA media directory.
 *
 * If the drive is already loaded and the path is different then
 * reject the load command and return.
 * If the drive is already loaded and the path is the same then
 * accept the load command and return.
 * If not loaded open the DDA media files.
 * If write protect tab is set read only.
 * Calculate data file offset to early warning.
 * Set unit attention status.
 * Set truncate need flag since the media is at BOT.
 * DDA media is now loaded and ready for access.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_tape_load(dda_t *dda, char *path)
{
	char		*fname;
	int		err;
	short		status;


	dda->dda_status = 0;
	dda->dda_resid = 0;
	if (dda->dda_loaded) {
		if (strcmp(dda->dda_path, path) != 0) {
			cmn_err(CE_CONT,
			    "%d loaded already %s",
			    dda->dda_inst, dda->dda_path);

			DDA_DEBUG2((dda_cmd_loaded_already,
			    int, dda->dda_inst,
			    char *, dda->dda_path));

			dda->dda_status = KEY_ILLEGAL_REQUEST;
			return (EIO);
		}
		cmn_err(CE_CONT,
		    "%d load resume %s",
		    dda->dda_inst, dda->dda_path);

		DDA_DEBUG2((dda_cmd_load_resume,
		    int, dda->dda_inst,
		    char *, dda->dda_path));

		return (0);
	}

	fname = kmem_alloc(PATH_MAX, KM_SLEEP);

	/* reset media data, the drive data is not reset */
	bzero(dda, offsetof(dda_t, dda_inst));
	(void) snprintf(dda->dda_path, PATH_MAX, "%s", path);

	(void) snprintf(fname, PATH_MAX, "%s/%s", dda->dda_path,
	    DDA_METADATA_FNAME);
	if (err = dda_vn_open(dda, &dda->dda_metadata_vp, fname)) {
		goto load_error;
	}
	if (err = dda_vn_lock(dda, dda->dda_metadata_vp, F_WRLCK)) {
		goto load_error;
	}
	if (err = dda_vn_read(dda, dda->dda_metadata_vp, &dda->dda_metadata,
	    sizeof (dda_metadata_t), 0)) {
		goto load_error;
	}
	DDA_BE_METADATA(dda->dda_metadata, dda->dda_metadata);

	(void) snprintf(fname, PATH_MAX, "%s/%s", dda->dda_path,
	    DDA_INDEX_FNAME);
	if (err = dda_vn_open(dda, &dda->dda_index_vp, fname)) {
		goto load_error;
	}
	if (err = dda_vn_size(dda, dda->dda_index_vp, &dda->dda_index_fsize)) {
		goto load_error;
	}
	if (err = dda_read_index(dda)) {
		goto load_error;
	}

	(void) snprintf(fname, PATH_MAX, "%s/%s", dda->dda_path,
	    DDA_DATA_FNAME);
	if (err = dda_vn_open(dda, &dda->dda_data_vp, fname)) {
		goto load_error;
	}
	if (err = dda_vn_size(dda, dda->dda_data_vp, &dda->dda_data_fsize)) {
		goto load_error;
	}

	/* non-floating point early warning to eom percentage calculation */
	dda->dda_early_warn =
	    (dda->dda_metadata.dda_capacity / 100) * DDA_EARLY_WARN;
	if (dda->dda_early_warn < DDA_MAX_REC_SIZE) {
		dda->dda_early_warn = DDA_MAX_REC_SIZE;
		if (dda->dda_early_warn > dda->dda_metadata.dda_capacity) {
			dda->dda_early_warn = dda->dda_metadata.dda_capacity;
		}
	}

	/* set media loaded */
	dda->dda_status = KEY_UNIT_ATTENTION;
	dda->dda_loaded = 1;
	DDA_SET_TRUNC(dda);

	cmn_err(CE_CONT, "%d loaded %s",
	    dda->dda_inst, dda->dda_path);

	DDA_DEBUG2((dda_cmd_load,
	    int, dda->dda_inst,
	    char *, path));

	kmem_free(fname, PATH_MAX);
	return (0);

load_error:
	cmn_err(CE_WARN, "%d load %s error %d",
	    dda->dda_inst, dda->dda_path, err);

	DDA_DEBUG3((dda_cmd_load_err,
	    int, dda->dda_inst,
	    char *, path,
	    int, err));

	/* cleanup */
	status = dda->dda_status;
	if (dda->dda_index_vp) {
		(void) dda_vn_close(dda, &dda->dda_index_vp);
	}
	if (dda->dda_data_vp) {
		(void) dda_vn_close(dda, &dda->dda_data_vp);
	}
	if (dda->dda_metadata_vp) {
		(void) dda_vn_lock(dda, dda->dda_metadata_vp, F_UNLCK);
		(void) dda_vn_close(dda, &dda->dda_metadata_vp);
	}
	dda_set_unloaded(dda);
	dda->dda_status = status;
	kmem_free(fname, PATH_MAX);
	return (err);
}

/*
 * dda_tape_unload
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Write filemark if needed to emulate st bsd mode.
 * Unload media from the drive.
 * Report first error encounter.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_tape_unload(dda_t *dda)
{
	int	rc;
	int	err = 0;
	short	status;


	/*
	 * Close all files, report first error
	 */

	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (err = dda_write_index(dda)) {
		status = dda->dda_status;
	}

	if (DDA_GET_FM_NEEDED(dda)) {
		if (rc = dda_tape_wfm(dda, 1)) {
			if (err == 0) {
				err = rc;
				status = dda->dda_status;
			}
		}
	}

	if (rc = dda_vn_close(dda, &dda->dda_index_vp)) {
		if (err == 0) {
			err = rc;
			status = dda->dda_status;
		}
	}

	if (rc = dda_vn_close(dda, &dda->dda_data_vp)) {
		if (err == 0) {
			err = rc;
			status = dda->dda_status;
		}
	}

	(void) dda_vn_lock(dda, dda->dda_metadata_vp, F_UNLCK);
	if (rc = dda_vn_close(dda, &dda->dda_metadata_vp)) {
		if (err == 0) {
			err = rc;
			status = dda->dda_status;
		}
	}

	dda->dda_status = status;

	if (err == 0) {
		cmn_err(CE_CONT, "%d unloaded %s",
		    dda->dda_inst, dda->dda_path);

		DDA_DEBUG2((dda_cmd_unload,
		    int, dda->dda_inst,
		    char *, dda->dda_path));
	} else {
		cmn_err(CE_WARN, "%d unloaded %s with error %d",
		    dda->dda_inst, dda->dda_path, err);

		DDA_DEBUG3((dda_cmd_unload_err,
		    int, dda->dda_inst,
		    char *, dda->dda_path,
		    int, err));
	}

	dda_set_unloaded(dda);
	return (err);
}

/* support routines */

/*
 * dda_gen_serial_num
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Globals:
 *	- hw_serial:	Hostid.
 *
 * Generate DDA unit serial number from the computer hostid and drive
 * instance number.
 *
 * Return Values:
 *      None
 *
 */
static void
dda_gen_serial_num(dda_t *dda)
{
	char		sn[100];
	int		len;
	int		off;
	char		*hostid_p = &hw_serial[0];
	int		hostid_i;

	/*
	 * Generate unit serial number:
	 *	zeros, hostid, instance number
	 */
	hostid_i = stoi(&hostid_p);
	len = snprintf(sn, sizeof (sn),
	    "%016x%x%x", 0, hostid_i, dda->dda_inst);

	/*
	 * Use least significant part of generated serial number
	 */
	if ((off = len - sizeof (dda_serial_t) + 1) < 0) {
		off = 0;
	}
	bcopy(&sn[off], dda->dda_serial, sizeof (dda_serial_t));
}

/*
 * dda_set_unloaded
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Set DDA drive unloaded.
 * Zero DDA media structure members.
 * Set fileno to -1 for status.
 *
 * Return Values:
 *      None
 *
 */
static void
dda_set_unloaded(dda_t *dda)
{
	bzero(dda, offsetof(dda_t, dda_inst));
	dda->dda_index.dda_fileno = -1;
	dda->dda_loaded = 0;
}

/*
 * dda_get_fileno
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Get DDA media fileno based on st bsd behavior.
 *
 * Return Values:
 *	fileno : filemark number
 *
 */
static int64_t
dda_get_fileno(dda_t *dda)
{
	int64_t	fileno;

	fileno = dda->dda_index.dda_fileno;
	if (dda->dda_pos > dda->dda_index.dda_blkcount) {
		fileno += (dda->dda_pos - dda->dda_index.dda_blkcount);
	}

	if (DDA_GET_FM_FWD_PEND(dda)) {
		if (DDA_GET_FM_NOSKIP(dda)) {
			fileno--;
		}
	}

	return (fileno);
}

/*
 * dda_get_blkno
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Get DDA media blkno.
 * If positioned at filemark then the blkno is 0.
 * Otherwise backup until bot or filemark is encountered.
 *
 * Return Values:
 *	fileno : filemark number
 *
 */
static int
dda_get_blkno(dda_t *dda, int64_t *blkno)
{
	dda_istate_t	istate;
	int		err = 0;

	if (dda->dda_pos > dda->dda_index.dda_blkcount) {
		*blkno = 0;
		return (0);
	}
	dda_save_istate(dda, &istate);
	*blkno = dda->dda_pos;
	dda->dda_index_offset -= sizeof (dda_index_t);
	while (dda->dda_index_offset >= 0) {
		if (err = dda_read_index(dda)) {
			break;
		}
		if (dda->dda_index.dda_fmcount) {
			break;
		}
		*blkno += dda->dda_index.dda_blkcount;
		dda->dda_index_offset -= sizeof (dda_index_t);
	}
	dda_restore_istate(dda, &istate);
	return (err);
}

/*
 * dda_write_truncate
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Truncate DDA media at the current position.
 * If at bot then align data file offset for directio.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_write_truncate(dda_t *dda)
{
	int	err;

	dda->dda_flags = 0;

	if (DDA_IS_BOT(dda)) {
		bzero(&dda->dda_index, sizeof (dda_index_t));
		DDA_SET_INDEX(dda);
	}

	if (dda->dda_pos != DDA_INDEX_COUNT(dda)) {
		DDA_SET_INDEX(dda);
		if (dda->dda_pos <= dda->dda_index.dda_blkcount) {
			dda->dda_index.dda_fmcount = 0;
			dda->dda_index.dda_blkcount = dda->dda_pos;
		} else {
			dda->dda_index.dda_fmcount =
			    dda->dda_pos - dda->dda_index.dda_blkcount;
		}

		if (DDA_INDEX_COUNT(dda) == 0) {
			dda->dda_index_offset -= sizeof (dda_index_t);
			if (dda->dda_index_offset < 0) {
				bzero(&dda->dda_index, sizeof (dda_index_t));
				dda->dda_index_offset = 0;
				dda->dda_pos = 0;
			} else {
				if (err = dda_read_index(dda)) {
					return (err);
				}
				dda->dda_pos = DDA_INDEX_COUNT(dda);
			}
		}
	}

	if (err = dda_write_index(dda)) {
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (err);
	}

	dda->dda_index_fsize = dda->dda_index_offset + sizeof (dda_index_t);
	if (err = dda_vn_truncate(dda, dda->dda_index_vp,
	    dda->dda_index_fsize)) {
		return (err);
	}

	dda->dda_data_fsize = dda_data_offset(dda);
	if (err = dda_vn_truncate(dda, dda->dda_data_vp,
	    dda->dda_data_fsize)) {
		return (err);
	}

	if (DDA_IS_BOT(dda)) {
		if (err = dda_sector_align(dda)) {
			return (err);
		}
		dda->dda_index.dda_offset += dda_stripe_align(dda);
	}

	return (0);
}

/*
 * dda_tape_erase
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Erase DDA media from the current position.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_erase(dda_t *dda)
{
	int	err;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (DDA_GET_READ_ONLY(dda)) {
		dda->dda_status = KEY_WRITE_PROTECT;
		return (EACCES);
	}

	/*
	 * Erase from current logical position
	 */
	DDA_DEBUG2((dda_cmd_erase,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda)));

	if (err = dda_write_truncate(dda)) {
		DDA_DEBUG2((dda_cmd_erase_err,
		    int, dda->dda_inst,
		    int, err));
	}
	return (err);
}

/*
 * dda_sync
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Flush DDA media files to disk.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_sync(dda_t *dda)
{
	int	err;
	int	rc;
	short	status;

	/*
	 * Sync all files, report first error
	 */

	err = dda_vn_sync(dda, dda->dda_index_vp);
	status = dda->dda_status;

	if (rc = dda_vn_sync(dda, dda->dda_data_vp)) {
		if (err == 0) {
			status = dda->dda_status;
			err = rc;
		}
	}

	if (rc = dda_vn_sync(dda, dda->dda_metadata_vp)) {
		if (err == 0) {
			status = dda->dda_status;
			err = rc;
		}
	}

	dda->dda_status = status;
	return (err);
}

/*
 * dda_tape_wfm
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Number of filemarks to write.
 *
 * If zero filemarks then flush media to disk and return.
 * Truncate DDA media if needed.
 * If at physical end of media and no filemarks can be
 * written then set status and return.
 * Write the number of filemarks requested.
 * Update position on media.
 * Set residual for the number of filemarks not written.
 * Flush DDA media to disk.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 * Note:
 *	A filemark is counted as 1 byte of used tape space.
 */
static int
dda_tape_wfm(dda_t *dda, int count)
{
	int	err;
	int64_t	avail;
	int	ew;

	if (!dda->dda_loaded) {
		return (EIO);
	}
	dda->dda_status = 0;
	dda->dda_resid = count;

	if (DDA_GET_READ_ONLY(dda)) {
		dda->dda_status = KEY_WRITE_PROTECT;
		return (EACCES);
	}

	DDA_DEBUG3((dda_cmd_wfm,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int, count));

	if (count == 0) {
		if (err = dda_write_index(dda)) {
			return (err);
		}
		err = dda_sync(dda);
		return (err);
	}

	if (DDA_GET_TRUNC(dda) && (err = dda_write_truncate(dda))) {
		return (err);
	}

	if (err = dda_ew_eom(dda, count, &avail, &ew)) {
		return (err);
	}

	if (avail == 0) {
		/*
		 * Physical end of media.
		 */
		DDA_DEBUG2((dda_cmd_wfm_eom,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda)));
		dda->dda_status = SUN_KEY_EOT;
		return (EIO);
	}

	DDA_SET_INDEX(dda);
	dda->dda_index.dda_fmcount += avail;
	if (err = dda_write_index(dda)) {
		dda->dda_index.dda_fmcount -= avail;
		return (err);
	}

	dda->dda_resid -= avail;
	dda->dda_pos += avail;
	dda->dda_blkno = 0;

	if (err = dda_sync(dda)) {
		return (err);
	}

	DDA_CLR_FM_NEEDED(dda);

	return (0);
}

/*
 * dda_tape_write
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- uio:		Vector I/O operations.
 *
 * DDA write supports all write lengths allowed by the kernel.
 *
 * A variable length write may span two index records when the
 * length is not modulus max record size.
 *
 * A fixed length write requires the data length to be a multiple
 * the record size.
 *
 * If read only media then set write protect status and return.
 * If zero length write then return.
 * Calculate number of blocks to write based on the record size.
 * Truncate media if needed.
 * Get early warning and physical end of media.
 * Adjust length to write in blocks based on tape space remaining.
 * If positioned past early warning then alternating write failures
 * occur.
 * Get data file offset.
 * Write the data to the data file.
 * If write error then set status and return errno.
 * If write returns residual then adjust counts and truncate
 * incomplete blocks.
 * Update index record with new media position.
 * If write crosses into early warning then set status.
 * Write complete.
 *
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_write(dda_t *dda, struct uio *uio)
{
	int		err;
	int32_t		len;
	int32_t		total;
	int32_t		blksize;
	int32_t		blkcount;
	int64_t		avail;
	int		ew;
	int		rc;
	off64_t		data_offset;
	int32_t		blks;
	int64_t		offset;
	dda_istate_t	istate;
	int32_t		partial = 0;

	if (!dda->dda_loaded) {
		return (EIO);
	}
	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (DDA_GET_READ_ONLY(dda)) {
		dda->dda_status = KEY_WRITE_PROTECT;
		dda->dda_resid = uio->uio_resid;
		return (EACCES);
	}

	if ((total = uio->uio_resid) == 0) {
		if (err = dda_write_index(dda)) {
			return (err);
		}
		return (0);
	}
	len = total;

	dda_save_istate(dda, &istate);

	if (dda->dda_rec_size == 0) {
		/* variable block(s) */
		if (len > DDA_MAX_REC_SIZE) {
			/* write may span this index record and next */
			blksize = DDA_MAX_REC_SIZE;
			blkcount = len / DDA_MAX_REC_SIZE;
			partial = len - (blksize * blkcount);
		} else {
			/* single block write */
			blksize = len;
			blkcount = 1;
		}
		dda->dda_resid = len;
	} else {
		/* fixed block(s) */
		if ((len % dda->dda_rec_size) != 0) {
			return (EINVAL);
		}
		blksize = dda->dda_rec_size;
		blkcount = (len / dda->dda_rec_size);
		dda->dda_resid = blkcount;
	}

	DDA_DEBUG4((dda_cmd_write,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int32_t, uio->uio_resid,
	    int32_t, blkcount));

	if (DDA_GET_TRUNC(dda) && (err = dda_write_truncate(dda))) {
		return (err);
	}

	if (err = dda_ew_eom(dda, len, &avail, &ew)) {
		return (err);
	}

	if (ew) {
		/*
		 * Logical end of media, alternating
		 * zero byte writes after early warning.
		 */
		DDA_DEBUG2((dda_cmd_write_ew,
		    int, dda->dda_inst,
		    int, DDA_GET_EW(dda)));
		if (DDA_GET_EW(dda)) {
			DDA_CLR_EW(dda);
			dda->dda_status = SUN_KEY_EOT;
			if (avail < blksize) {
				/*
				 * Physical end of media hit.
				 */
				return (EIO);
			}
			return (0);
		}

		/*
		 * Next early warning write is zero bytes.
		 */
		DDA_SET_EW(dda);
	}

	if (avail < len) {
		/* at least one block */
		if (avail < blksize) {
			/*
			 * Physical end of media hit.
			 */
			DDA_DEBUG2((dda_cmd_write_eom,
			    int, dda->dda_inst,
			    int64_t, DDA_LBA(dda)));
			dda->dda_status = SUN_KEY_EOT;
			return (EIO);
		}

		/* adjust counts */
		blkcount = avail / blksize;
		len = blkcount * blksize;
		if (dda->dda_rec_size == 0) {
			partial = 0;
			dda->dda_resid = (total - len);
		} else {
			dda->dda_resid = (total - len) / blksize;
		}
	}

	if (dda->dda_pos > dda->dda_index.dda_blkcount &&
	    dda->dda_index.dda_fmcount) {
		dda_gen_next_index(dda, blksize);
		dda->dda_index.dda_offset += dda_stripe_align(dda);
	}

	if (blksize != dda->dda_index.dda_blksize) {
		if (DDA_IS_BOT(dda)) {
			dda->dda_index.dda_blksize = blksize;
		} else {
			if (err = dda_write_index(dda)) {
				goto write_error;
			}
			dda_gen_next_index(dda, blksize);
		}
	}

	/* write data */
	data_offset = dda_data_offset(dda);
	uio->uio_loffset = data_offset;
	uio->uio_resid = len;
	(void) VOP_RWLOCK(dda->dda_data_vp, V_WRITELOCK_TRUE, NULL);
	err = VOP_WRITE(dda->dda_data_vp, uio, 0, dda->dda_cred, NULL);
	VOP_RWUNLOCK(dda->dda_data_vp, V_WRITELOCK_TRUE, NULL);

	if (err) {
		DDA_DEBUG4((dda_cmd_write_vn_err,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda),
		    off64_t, data_offset,
		    int, err));
		dda_vn_error_skey(dda, err);
		goto write_error;
	}

	if (uio->uio_resid) {
		if (dda->dda_rec_size == 0) {
			partial = 0;
		}

		/* remove blocks from data */

		blks = uio->uio_resid / blksize;
		if (uio->uio_resid - (blks * blksize)) {
			blks++;
		}
		blkcount -= blks;
		if (blkcount == 0) {
			goto write_error;
		}

		len = blkcount * blksize;
		offset = data_offset + len;

		if (err = dda_vn_truncate(dda, dda->dda_data_vp, offset)) {
			goto write_error;
		}
	}

	/* update index record block count */
	DDA_SET_INDEX(dda);
	dda->dda_index.dda_blkcount += blkcount;
	dda->dda_pos += blkcount;
	dda->dda_blkno += blkcount;

	if (partial) {
		if (err = dda_write_index(dda)) {
			goto write_error;
		}
		dda_save_istate(dda, &istate);
		dda_gen_next_index(dda, partial);

		/* update new index record with block */
		DDA_SET_INDEX(dda);
		dda->dda_index.dda_blkcount = 1;
		dda->dda_pos++;
		dda->dda_blkno++;
	}

	if (total == len) {
		dda->dda_resid = 0;
	} else {
		uio->uio_resid = total - len;
		if (dda->dda_rec_size == 0) {
			dda->dda_resid = (total - len);
		} else {
			dda->dda_resid = (total - len) / blksize;
		}

		DDA_DEBUG4((dda_cmd_write_done,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda),
		    int32_t, blkcount,
		    int32_t, uio->uio_resid));
	}

	if (ew) {
		DDA_DEBUG2((dda_cmd_write_ew,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda)));
		dda->dda_status = SUN_KEY_EOT;
	}

	DDA_SET_FM_NEEDED(dda);

	dda->dda_data_fsize += total - uio->uio_resid;

	return (err);

write_error:
	/* no blocks written */
	uio->uio_resid = total;
	if (dda->dda_rec_size == 0) {
		dda->dda_resid = total;
	} else {
		dda->dda_resid = total / blksize;
	}
	dda_restore_istate(dda, &istate);
	if (DDA_IS_BOT(dda)) {
		dda->dda_index.dda_blksize = 0;
	}
	DDA_SET_TRUNC(dda);
	if (rc = dda_write_truncate(dda)) {
		if (err == 0) {
			err = rc;
		}
	}
	DDA_DEBUG3((dda_cmd_write_err,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int, err));
	if (err) {
		/* original error */
		return (err);
	}
	return (EIO);
}

/*
 * dda_tape_read
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- uio:		Vector I/O operations.
 *
 * DDA read supports all read lengths allowed by the kernel.
 *
 * A variable length read may span two index records.
 *
 * The DDA variable length read supports the ILI (incorrect length
 * indicator).
 *
 * A fixed length read requires the data length to be a multiple of
 * the record size.
 *
 * If zero length read then return.
 * Calculate the number of blocks to read based on the
 * record size.
 * Get early warning and physical end of media.
 * Adjust length (blocks) to read based on tape space remaining.
 * Read the data from the data file.
 * If read error occurred then set status and return.
 * If read returns residual then adjust counts.
 * Update the index record with new media position.
 * Read complete.
 *
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
int
dda_tape_read(dda_t *dda, struct uio *uio)
{
	int32_t		len;
	int32_t		total;
	int32_t		blksize;
	int32_t		blkcount;
	int		err;
	off64_t		fsize;
	dda_istate_t	istate;
	off64_t		data_offset;
	int		overflow = 0;
	int		noskip;
	int		partial = 0;
	off64_t		offset;
	dda_index_t	index;

	if (!dda->dda_loaded) {
		return (EIO);
	}
	dda->dda_status = 0;
	dda->dda_resid = 0;
	DDA_SET_TRUNC(dda);
	DDA_CLR_FM_NEEDED(dda);
	DDA_CLR_EW(dda);

	if ((total = uio->uio_resid) == 0) {
		if (err = dda_write_index(dda)) {
			return (err);
		}
		return (0);
	}
	len = total;

	dda_save_istate(dda, &istate);

	if (dda->dda_rec_size == 0) {
		/* variable */
		if (len > DDA_MAX_REC_SIZE) {
			/* read may span this index record and next */
			blksize = DDA_MAX_REC_SIZE;
			blkcount = len / DDA_MAX_REC_SIZE;
			if (len - (blksize * blkcount)) {
				/* actual partial blksize determined below */
				partial = 1;
			}
		} else {
			/* single block read */
			blksize = len;
			blkcount = 1;
		}
		dda->dda_resid = len;
	} else {
		/* fixed */
		if (dda->dda_ili) {
			cmn_err(CE_WARN, "%d Incorrect Length Indicator Set",
			    dda->dda_inst);
			return (EINVAL);
		}
		if ((len % dda->dda_rec_size) != 0) {
			cmn_err(CE_WARN, "%d read: not modulo %d block size",
			    dda->dda_inst, dda->dda_rec_size);
			return (EINVAL);
		}
		blksize = dda->dda_rec_size;
		blkcount = (len / dda->dda_rec_size);
		dda->dda_resid = blkcount;
	}

	if (err = dda_write_index(dda)) {
		return (err);
	}

	DDA_DEBUG4((dda_cmd_read,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int32_t, uio->uio_resid,
	    int32_t, blkcount));

	if (DDA_GET_FM_FWD_PEND(dda)) {
		noskip = DDA_GET_FM_NOSKIP(dda);
		DDA_CLR_FM_FWD_PEND(dda);
		if (noskip) {
			DDA_DEBUG1((dda_cmd_read_ffpns,
			    int, dda->dda_inst));

			dda->dda_status = SUN_KEY_EOF;
			dda->dda_blkno = 0;
			return (0);
		}

		DDA_DEBUG1((dda_cmd_read_ffpc,
		    int, dda->dda_inst));
	}

	fsize = dda->dda_index_fsize - sizeof (dda_index_t);

	if (dda->dda_pos >= DDA_INDEX_COUNT(dda)) {
		dda->dda_index_offset += sizeof (dda_index_t);
		if (dda->dda_index_offset > fsize) {

			DDA_DEBUG3((dda_cmd_read_eot,
			    int, dda->dda_inst,
			    int64_t, DDA_LBA(dda),
			    int, DDA_GET_EOT_EIO(dda)));

			dda->dda_index_offset -= sizeof (dda_index_t);
			dda->dda_status = SUN_KEY_EOT;
			if (DDA_GET_EOT_EIO(dda) == 0) {
				DDA_SET_EOT_EIO(dda);
				dda->dda_resid = len;
				return (EIO);
			}
			return (0);
		}
		if (err = dda_read_index(dda)) {
			dda_restore_istate(dda, &istate);
			return (err);
		}
	}

	DDA_CLR_EOT_EIO(dda);

	if (DDA_IS_FM(dda)) {
		DDA_DEBUG2((dda_cmd_read_fm,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda)));

		DDA_SET_FM_FWD_PEND(dda);
		dda->dda_pos++;
		dda->dda_status = SUN_KEY_EOF;
		dda->dda_blkno = 0;
		return (0);
	}

	if (blksize != dda->dda_index.dda_blksize) {
		if (blksize < dda->dda_index.dda_blksize) {
			len = blksize;
			if (dda->dda_ili == 0) {
				overflow = 1;
			}
		} else {
			len = dda->dda_index.dda_blksize;
		}
		blkcount = 1;
		blksize = len;
		partial = 0;

		DDA_DEBUG4((dda_cmd_read_blksz,
		    int, dda->dda_inst,
		    int64_t, blksize,
		    int64_t, blkcount,
		    int, overflow));
	}

	if (dda->dda_pos + blkcount + partial > dda->dda_index.dda_blkcount) {
		if (partial) {
			/* get partial from next index record */
			offset = dda->dda_index_offset + sizeof (dda_index_t);
			if (offset > fsize) {
				partial = 0;
			} else if (dda_vn_read(dda, dda->dda_index_vp,
			    &index, sizeof (dda_index_t), offset)) {
				partial = 0;
			} else {
				DDA_BE_INDEX(index, index);
				if (index.dda_blkcount == 0) {
					partial = 0;
				}
			}
		}

		blkcount = dda->dda_index.dda_blkcount - dda->dda_pos;
		if (blkcount == 0) {
			if (dda->dda_rec_size == 0) {
				dda->dda_resid = total;
			} else {
				dda->dda_resid = total / blksize;
			}
			DDA_DEBUG1((dda_cmd_read_noblks,
			    int, dda->dda_inst));
			return (0);
		}

		len = blkcount * blksize;

		if (partial) {
			len += index.dda_blksize;
		}

		DDA_DEBUG4((dda_cmd_read_numblks,
		    int, dda->dda_inst,
		    int32_t, len,
		    int32_t, blksize,
		    int32_t, blkcount));

	} else if (partial) {
		/* current index record contains partial */
		len += dda->dda_index.dda_blksize;
	}

	if (len > total) {
		len = total;
		if (dda->dda_ili == 0) {
			overflow = 1;
		}
	}

	DDA_DEBUG2((dda_cmd_read_partial,
	    int, dda->dda_inst,
	    int32_t, partial));

	data_offset = dda_data_offset(dda);
	uio->uio_loffset = data_offset;
	uio->uio_resid = len;
	(void) VOP_RWLOCK(dda->dda_data_vp, V_WRITELOCK_FALSE, NULL);
	err = VOP_READ(dda->dda_data_vp, uio, 0, dda->dda_cred, NULL);
	VOP_RWUNLOCK(dda->dda_data_vp, V_WRITELOCK_FALSE, NULL);

	if (err) {
		DDA_DEBUG4((dda_cmd_read_vn_err,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda),
		    off64_t, data_offset,
		    int, err));

		dda_restore_istate(dda, &istate);
		uio->uio_resid = total;
		dda_vn_error_skey(dda, err);
		if (dda->dda_rec_size == 0) {
			dda->dda_resid = total;
		} else {
			dda->dda_resid = total / blksize;
		}
		return (err);
	}

	if (uio->uio_resid) {
		DDA_DEBUG2((dda_cmd_read_resid,
		    int, dda->dda_inst,
		    int32_t, uio->uio_resid));

		uio->uio_resid = total;
		if (dda->dda_rec_size == 0) {
			dda->dda_resid = total;
		} else {
			dda->dda_resid = total / blksize;
		}
		dda_restore_istate(dda, &istate);
		return (EIO);
	}

	dda->dda_pos += blkcount;

	if (total == len) {
		dda->dda_blkno += blkcount;
		dda->dda_resid = 0;
	} else {
		uio->uio_resid = total - len;
		if (dda->dda_rec_size == 0) {
			dda->dda_resid = uio->uio_resid;
		} else {
			dda->dda_resid = uio->uio_resid / blksize;
		}
		dda->dda_blkno += uio->uio_resid / blksize;
	}

	if (partial) {
		dda->dda_pos = 1;
		dda->dda_blkno++;
		dda->dda_index = index;
		dda->dda_index_offset += sizeof (dda_index_t);
	}

	DDA_DEBUG3((dda_cmd_read_short,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int32_t, dda->dda_resid));

	if (overflow) {
		DDA_DEBUG2((dda_cmd_read_overflow,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda)));
		dda->dda_resid = 0;
		err = ENOMEM;
	}

	return (err);
}

/*
 * dda_tape_locate
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- position:	Locate to LBA.
 *
 * Locate to LBA requested.
 *
 * Return Values:
 *	0 : success
 *	errno : failure, positioned at bot or eom
 *
 */
static int
dda_tape_locate(dda_t *dda, off64_t position)
{
	int		err;
	int		found;
	int64_t		lba;
	dda_istate_t	istate;
	int		rc;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	dda->dda_blkno = 0;
	dda->dda_resid = 0;
	dda->dda_flags = 0;
	DDA_SET_TRUNC(dda);
	lba = DDA_LBA(dda);

	DDA_DEBUG3((dda_cmd_locate,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    off64_t, position));

	dda_save_istate(dda, &istate);
	if (err = dda_bsearch(dda, position, dda_locate_compare, &found)) {
		DDA_DEBUG2((dda_cmd_locate_err,
		    int, dda->dda_inst,
		    int, err));
		dda_restore_istate(dda, &istate);
		return (err);
	}

	if (!found) {
		/*
		 * Locate unsuccessful,
		 * position based on direction of search
		 */
		if (position < lba) {
			if (err = dda_tape_rewind(dda)) {
				return (err);
			}
			dda->dda_status = SUN_KEY_BOT;
			dda->dda_resid = 0;
		} else {
			if (err = dda_tape_eom(dda)) {
				return (err);
			}
			dda->dda_status = KEY_BLANK_CHECK;
			dda->dda_resid = 0;
		}
		err = EIO;
	}
	if (rc = dda_get_blkno(dda, &dda->dda_blkno)) {
		err = rc;
	}

	DDA_DEBUG4((dda_cmd_locate_done,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int64_t, dda->dda_blkno));

	return (err);
}

/*
 * dda_tape_fsr
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Number of records to forward space.
 *
 * Forward space records the requested count.
 * Set truncate needed for write that may follow.
 * Clear filemark forward pending.
 * Clear alternating write success at early warning.
 * If filemark is hit during fsr then cross the filemark but report
 * logical position in front of the filemark to the user.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_fsr(dda_t *dda, int count)
{
	int		err;
	off64_t		fsize;
	dda_istate_t	istate;
	int		fm;
	int64_t		blks;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = count;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	DDA_SET_TRUNC(dda);
	DDA_CLR_FM_NEEDED(dda);
	DDA_CLR_EW(dda);

	DDA_DEBUG4((dda_cmd_fsr,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int, count));

	fsize = dda->dda_index_fsize - sizeof (dda_index_t);

	while (dda->dda_resid) {
		dda_save_istate(dda, &istate);

		if (DDA_GET_FM_FWD_PEND(dda)) {
			dda->dda_status = SUN_KEY_EOF;
			return (EIO);
		}

		if (dda->dda_pos >= DDA_INDEX_COUNT(dda)) {
			dda->dda_index_offset += sizeof (dda_index_t);
			if (dda->dda_index_offset > fsize) {
				dda_restore_istate(dda, &istate);
				dda->dda_status = KEY_BLANK_CHECK;
				err = EIO;
				break;
			}
			if (err = dda_read_index(dda)) {
				dda_restore_istate(dda, &istate);
				DDA_DEBUG2((dda_cmd_fsr_err,
				    int, dda->dda_inst,
				    int, err));
				return (err);
			}
		}

		DDA_DEBUG4((dda_cmd_fsr_where,
		    int, dda->dda_inst,
		    int64_t, dda->dda_pos,
		    int64_t, dda->dda_index.dda_blkcount,
		    int64_t, dda->dda_index.dda_fmcount));

		fm = DDA_IS_FM(dda);
		if (fm) {
			blks = 1;
		} else {
			blks = dda->dda_index.dda_blkcount - dda->dda_pos;
			if (dda->dda_resid <= blks) {
				blks = dda->dda_resid;
			}
		}

		DDA_DEBUG2((dda_cmd_fsr_blks,
		    int, dda->dda_inst,
		    int64_t, blks));

		dda->dda_pos += blks;
		dda->dda_blkno += blks;

		if (fm) {
			DDA_DEBUG1((dda_cmd_fsr_fm,
			    int, dda->dda_inst));
			DDA_SET_FM_FWD_PEND(dda);
			DDA_SET_FM_NOSKIP(dda);
			dda->dda_blkno--;
			dda->dda_status = SUN_KEY_EOF;
			err = EIO;
			break;
		}

		dda->dda_resid -= blks;
	}

	DDA_DEBUG4((dda_cmd_fsr_done,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int32_t, dda->dda_resid));

	return (err);
}

/*
 * dda_tape_bsr
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Number of records to backward space.
 *
 * Backspace records the requested count.
 * Set truncate needed for write that may follow.
 * Clear filemark forward pending.
 * Clear alternating write success at early warning.
 * If filemark is hit during bsr then do not cross the filemark.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_bsr(dda_t *dda, int count)
{
	int		err = 0;
	dda_istate_t	istate;
	int64_t		blks;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = count;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	DDA_SET_TRUNC(dda);
	DDA_CLR_FM_NEEDED(dda);
	DDA_CLR_EW(dda);

	DDA_DEBUG4((dda_cmd_bsr,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int, count));

	while (dda->dda_resid) {
		dda_save_istate(dda, &istate);

		if (DDA_GET_FM_FWD_PEND(dda)) {
			DDA_CLR_FM_FWD_PEND(dda);
			dda->dda_pos--;
		}

		if (dda->dda_pos <= 0) {
			dda->dda_index_offset -= sizeof (dda_index_t);
			if (dda->dda_index_offset < 0) {
				dda_restore_istate(dda, &istate);
				dda->dda_status = SUN_KEY_BOT;
				err = EIO;
				break;
			}
			if (err = dda_read_index(dda)) {
				dda_restore_istate(dda, &istate);
				DDA_DEBUG2((dda_cmd_bsr_err,
				    int, dda->dda_inst,
				    int, err));
				return (err);
			}
			dda->dda_pos = DDA_INDEX_COUNT(dda);
		}

		DDA_DEBUG4((dda_cmd_bsr_where,
		    int, dda->dda_inst,
		    int64_t, dda->dda_pos,
		    int64_t, dda->dda_index.dda_blkcount,
		    int64_t, dda->dda_index.dda_fmcount));

		blks = 0;
		if (dda->dda_pos <= dda->dda_index.dda_blkcount) {
			blks = dda->dda_pos;
			if (dda->dda_resid <= blks) {
				blks = dda->dda_resid;
			}
		}

		DDA_DEBUG2((dda_cmd_bsr_blks,
		    int, dda->dda_inst,
		    int64_t, blks));

		dda->dda_pos -= blks;
		dda->dda_blkno -= blks;

		if (DDA_IS_FM(dda)) {
			DDA_DEBUG3((dda_cmd_bsr_fm,
			    int, dda->dda_inst,
			    int64_t, DDA_LBA(dda),
			    int64_t, dda_get_fileno(dda)));

			dda->dda_blkno = 0;
			dda->dda_status = SUN_KEY_EOF;
			err = EIO;
			break;
		}

		dda->dda_resid -= blks;
	}

	DDA_DEBUG4((dda_cmd_bsr_done,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int32_t, dda->dda_resid));

	return (err);
}

/*
 * dda_tape_fsf
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Number of filemarks to forward space.
 *
 * Forward space filemarks.
 * Set truncate needed for write that may follow.
 * Clear filemark forward pending.
 * Clear alternating write success at early warning.
 * If filemark forward pending then decrement the count.
 * Binary search to the filemark.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_fsf(dda_t *dda, int count)
{
	int		err;
	int		found;
	dda_istate_t	istate;
	int64_t		fileno;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = count;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	dda->dda_blkno = 0;
	DDA_SET_TRUNC(dda);
	DDA_CLR_FM_NEEDED(dda);
	DDA_CLR_EOT_EIO(dda);
	DDA_CLR_EW(dda);

	DDA_DEBUG4((dda_cmd_fsf,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int, count));

	if (DDA_GET_FM_FWD_PEND(dda)) {
		DDA_CLR_FM_FWD_PEND(dda);
		count--;

		DDA_DEBUG4((dda_cmd_fsf_pend,
		    int, dda->dda_inst,
		    int64_t, DDA_LBA(dda),
		    int64_t, dda_get_fileno(dda),
		    int, count));
	}

	dda_save_istate(dda, &istate);
	fileno = dda_get_fileno(dda) + count;

	if (fileno == 0) {
		err = dda_tape_rewind(dda);
		goto fsf_done;
	}

	if (err = dda_bsearch(dda, fileno, dda_fsf_compare, &found)) {
		DDA_DEBUG2((dda_cmd_fsf_err,
		    int, dda->dda_inst,
		    int, err));
		dda_restore_istate(dda, &istate);
		return (err);
	}

	if (found) {
		/*
		 * Forward space file successful
		 */
		dda->dda_resid = 0;
	} else {
		/*
		 * Forward space file unsuccessful,
		 * position based on direction of search
		 */
		if (count < 0) {
			if (err = dda_tape_rewind(dda)) {
				return (err);
			}
			dda->dda_status = SUN_KEY_BOT;
			dda->dda_resid = dda_get_fileno(dda) - fileno;
		} else {
			if (err = dda_tape_eom(dda)) {
				return (err);
			}
			if (err = dda_get_blkno(dda, &dda->dda_blkno)) {
				return (err);
			}
			dda->dda_status = KEY_BLANK_CHECK;
			dda->dda_resid = fileno - dda_get_fileno(dda);
		}
		err = EIO;
	}

fsf_done:
	DDA_DEBUG4((dda_cmd_fsf_done,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int32_t, dda->dda_resid));

	return (err);
}

/*
 * dda_tape_bsf
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Number of filemarks to backward space.
 *
 * Backward space filemarks.
 * Zero flags.
 * Set truncate needed for write that may follow.
 * Binary search to filemark.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_bsf(dda_t *dda, int count)
{
	int		err;
	int		found;
	dda_istate_t	istate;
	int64_t		fileno;
	int		rc;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = count;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	dda->dda_flags = 0;
	dda->dda_blkno = DDA_BLKNO_UNKNOWN;
	DDA_SET_TRUNC(dda);
	fileno = dda_get_fileno(dda) - count;

	DDA_DEBUG4((dda_cmd_bsf,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int, count));

	dda_save_istate(dda, &istate);
	if (err = dda_bsearch(dda, fileno, dda_bsf_compare, &found)) {
		DDA_DEBUG2((dda_cmd_bsf_err,
		    int, dda->dda_inst,
		    int, err));
		dda_restore_istate(dda, &istate);
		return (err);
	}

	if (found) {
		/*
		 * Backward space file successful
		 */
		dda->dda_resid = 0;
	} else {
		/*
		 * Backward space file unsuccessful,
		 * position based on direction of search
		 */
		if (count < 0) {
			if (err = dda_tape_eom(dda)) {
				return (err);
			}
			if (rc = dda_get_blkno(dda, &dda->dda_blkno)) {
				err = rc;
			}
			dda->dda_status = KEY_BLANK_CHECK;
			dda->dda_resid = fileno - dda_get_fileno(dda);
		} else {
			if (err = dda_tape_rewind(dda)) {
				return (err);
			}
			dda->dda_status = SUN_KEY_BOT;
			dda->dda_resid = dda_get_fileno(dda) - fileno;
		}
		err = EIO;
	}

	DDA_DEBUG4((dda_cmd_bsf_done,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int32_t, dda->dda_resid));

	return (err);
}

/*
 * dda_tape_eom
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Position to end of media.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_eom(dda_t *dda)
{
	off64_t	fsize;
	int	err;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	dda->dda_flags = 0;
	dda->dda_blkno = 0;

	fsize = dda->dda_index_fsize - sizeof (dda_index_t);
	if (fsize < 0) {
		DDA_DEBUG2((dda_cmd_eom_err,
		    int, dda->dda_inst,
		    int, err));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}
	if (dda->dda_index_offset != fsize) {
		dda->dda_index_offset = fsize;
		if (err = dda_read_index(dda)) {
			DDA_DEBUG2((dda_cmd_eom_err,
			    int, dda->dda_inst,
			    int, err));
			return (err);
		}
	}
	dda->dda_pos = DDA_INDEX_COUNT(dda);

	DDA_DEBUG4((dda_cmd_eom,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    int64_t, dda_get_fileno(dda),
	    int64_t, dda->dda_blkno));

	return (0);
}

/*
 * dda_tape_rewind
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Position to beginning of media.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_rewind(dda_t *dda)
{
	int	err = 0;


	if (!dda->dda_loaded) {
		return (EIO);
	}

	dda->dda_status = 0;
	dda->dda_resid = 0;

	if (err = dda_write_index(dda)) {
		return (err);
	}

	if (DDA_GET_FM_NEEDED(dda)) {
		if (err = dda_tape_wfm(dda, 1)) {
			return (err);
		}
	}

	dda->dda_flags = 0;
	dda->dda_blkno = 0;
	DDA_SET_TRUNC(dda);

	dda->dda_index_offset = 0;
	if (err = dda_read_index(dda)) {
		DDA_DEBUG2((dda_cmd_rewind_err,
		    int, dda->dda_inst,
		    int, err));
		return (err);
	}

	DDA_DEBUG2((dda_cmd_rewind,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda)));

	return (0);
}

/* index operations */

/*
 * dda_write_index
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Write an index record at the index file position.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_write_index(dda_t *dda)
{
	int		err;
	dda_index_t	index;

	if (DDA_GET_INDEX(dda)) {
		DDA_CLR_INDEX(dda);
		DDA_BE_INDEX(dda->dda_index, index);
		if (err = dda_vn_write(dda, dda->dda_index_vp, &index,
		    sizeof (dda_index_t), dda->dda_index_offset)) {
			return (err);
		}
		dda->dda_index_fsize = dda->dda_index_offset +
		    sizeof (dda_index_t);

		DDA_DEBUG4((dda_write_index,
		    int, dda->dda_inst,
		    int64_t, dda->dda_index.dda_lba,
		    int64_t, dda->dda_index.dda_fileno,
		    off64_t, dda->dda_index_offset));
	}
	return (0);
}

/*
 * dda_read_index
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Read an index record from the index file position.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_read_index(dda_t *dda)
{
	int		err;
	dda_index_t	index;

	DDA_CLR_INDEX(dda);
	dda->dda_pos = 0;
	if (err = dda_vn_read(dda, dda->dda_index_vp, &index,
	    sizeof (dda_index_t), dda->dda_index_offset)) {
		return (err);
	}
	DDA_BE_INDEX(index, dda->dda_index);

	DDA_DEBUG4((dda_read_index,
	    int, dda->dda_inst,
	    int64_t, dda->dda_index.dda_lba,
	    int64_t, dda->dda_index.dda_fileno,
	    off64_t, dda->dda_index_offset));

	return (0);
}

/*
 * dda_gen_next_index
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- blksize:	Record size for index record.
 *
 * Generate the next index record with starting positions from the
 * end of previous index record.
 * Function is called after a change in record size or when data
 * follows a filemark.
 *
 * Return Values:
 *	None
 *
 */
static void
dda_gen_next_index(dda_t *dda, int32_t blksize)
{
	DDA_CLR_INDEX(dda);
	dda->dda_index.dda_offset = dda_data_offset(dda);
	dda->dda_index.dda_lba += DDA_INDEX_COUNT(dda);
	dda->dda_index.dda_fileno += dda->dda_index.dda_fmcount;
	dda->dda_index.dda_fmcount = 0;
	dda->dda_index.dda_blkcount = 0;
	dda->dda_index.dda_blksize = blksize;
	dda->dda_index_offset += sizeof (dda_index_t);
	dda->dda_pos = 0;

	DDA_DEBUG3((dda_gen_next_index,
	    int, dda->dda_inst,
	    int64_t, dda->dda_index.dda_lba,
	    int64_t, dda->dda_index.dda_fileno));

}

/*
 * dda_save_istate
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- istate:	Index record and index file offset.
 *
 * Save current index record and position.
 *
 * Return Values:
 *	None
 *
 */
static void
dda_save_istate(dda_t *dda, dda_istate_t *istate)
{
	istate->dda_index_offset = dda->dda_index_offset;
	istate->dda_index = dda->dda_index;
	istate->dda_pos = dda->dda_pos;
	istate->dda_flags = dda->dda_flags;
}

/*
 * dda_restore_istate
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- istate:	Index record and index file offset.
 *
 * Restore saved index record and position.
 *
 * Return Values:
 *	None
 *
 */
static void
dda_restore_istate(dda_t *dda, dda_istate_t *istate)
{
	dda->dda_index_offset = istate->dda_index_offset;
	dda->dda_index = istate->dda_index;
	dda->dda_pos = istate->dda_pos;
	if (istate->dda_flags & DDA_FLAG_INDEX) {
		DDA_SET_INDEX(dda);
	}
}

/* alignment */

/*
 * dda_stripe_align
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Align data file offset following after a filemark.
 *
 * Return Values:
 *	Aligned data file offset.
 *
 */
static off64_t
dda_stripe_align(dda_t *dda)
{
	off64_t	amount = 0;

	DDA_DEBUG1((dda_stripe_align_enter,
	    int, dda->dda_inst));

	/*
	 * Called at bot write or when write data follows a file mark.
	 */
	if (dda->dda_metadata.dda_stripe > 0) {
		/*
		 * Start tape file on stripe boundary
		 */
		amount = dda->dda_index.dda_offset %
		    dda->dda_metadata.dda_stripe;

		DDA_DEBUG3((dda_stripe_align_amount,
		    int, dda->dda_inst,
		    int32_t, dda->dda_metadata.dda_stripe,
		    off64_t, amount));

		if (amount) {
			/*
			 * Stripe adjustment needed.
			 */
			amount = dda->dda_metadata.dda_stripe - amount;

			DDA_DEBUG3((dda_stripe_align,
			    int, dda->dda_inst,
			    int32_t, dda->dda_metadata.dda_stripe,
			    off64_t, amount));
		}
	}
	return (amount);
}

/*
 * dda_data_offset
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * Align data file offset for the index record.
 * If directio is enable then the alignment is calculated.
 *
 * Return Values:
 *	Aligned data file offset.
 *
 */
static off64_t
dda_data_offset(dda_t *dda)
{
	off64_t	offset;
	off64_t	amount;
	int32_t	sector = dda->dda_metadata.dda_sector;

	offset = dda->dda_index.dda_offset;

	DDA_DEBUG2((dda_data_offset_start,
	    int, dda->dda_inst,
	    off64_t, offset));

	if (dda->dda_pos <= dda->dda_index.dda_blkcount) {

		offset += (dda->dda_pos * dda->dda_index.dda_blksize);

		DDA_DEBUG2((dda_data_offset_le,
		    int, dda->dda_inst,
		    off64_t, offset));

	} else {

		offset += (dda->dda_index.dda_blkcount *
		    dda->dda_index.dda_blksize);

		DDA_DEBUG2((dda_data_offset_gt,
		    int, dda->dda_inst,
		    off64_t, offset));

	}

	if (DDA_LEN_ALIGNED(dda->dda_index.dda_blksize, sector) == 0) {

		if (dda->dda_metadata.dda_sector) {

			/* fs supports directio */

			amount = DDA_OFF_ALIGNED(offset, sector);

			if (amount) {

				/* bytes needed for sector alignment */

				amount = sector - amount;
			}

			offset += amount;

			DDA_DEBUG3((dda_data_offset_align,
			    int, dda->dda_inst,
			    off64_t, offset,
			    off64_t, amount));
		}
	}

	DDA_DEBUG3((dda_data_offset,
	    int, dda->dda_inst,
	    int64_t, DDA_LBA(dda),
	    off64_t, offset));

	return (offset);
}

/*
 * dda_sector_align
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *
 * If filesystem is capable of directio then update metadata file with
 * sector size.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_sector_align(dda_t *dda)
{
	struct inode	*ip;
	int32_t		sector;
	int		err;
	dda_metadata_t	metadata;

	/*
	 * Set sector alignment at bot then use to eom.
	 */
	if (dda->dda_data_vp == NULL) {
		DDA_DEBUG1((dda_sec_align_vn_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	sector = dda->dda_metadata.dda_sector;

	/* ufs directio flag */
	ip = VTOI(dda->dda_data_vp);
	if (ip->i_flag & IDIRECTIO) {

		/*
		 * Directio on, do sector alignment.
		 */
		dda->dda_metadata.dda_sector = DEV_BSIZE;
	} else {

		/*
		 * Directio off, don't do sector alignment.
		 */
		dda->dda_metadata.dda_sector = 0;
	}

	if (dda->dda_metadata.dda_sector == sector) {

		/*
		 * Metadata already contains sector alignment.
		 */
		return (0);
	}

	/*
	 * Save sector alignment change.
	 */
	DDA_BE_METADATA(dda->dda_metadata, metadata);
	if (err = dda_vn_write(dda, dda->dda_metadata_vp, &metadata,
	    sizeof (dda_metadata_t), 0)) {
		DDA_DEBUG2((dda_sec_align_err,
		    int, dda->dda_inst,
		    int, err));
		return (err);
	}

	DDA_DEBUG3((dda_sec_align,
	    int, dda->dda_inst,
	    int32_t, sector,
	    int32_t, dda->dda_metadata.dda_sector));

	return (0);
}

/* space */

/*
 * dda_tape_capacity
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- space:	Amount of space remaining to eom.
 *
 * The amount of available space remaining to eom is from the last
 * data or fm on tape to phyical eom. The position on media does not
 * change the space remaining calculation. Filemarks count as 1 byte
 * of used capacity. The size of the three media files (metadata,
 * index, and data) are also subtracted from the capacity.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_tape_capacity(dda_t *dda, int64_t *space)
{
	int		err;
	dda_index_t	last_index;
	off64_t 	last_index_offset;
	off64_t		last_index_fileno;
	off64_t		last_index_fmcount;


	/* get offset of last index file record */
	last_index_offset = dda->dda_index_fsize - sizeof (dda_index_t);
	if (last_index_offset < 0) {
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	/* get total number of filemarks on tape */
	if (dda->dda_index_offset >= last_index_offset) {
		/* current or next index record is the last index record */
		last_index_fileno = dda->dda_index.dda_fileno;
		last_index_fmcount = dda->dda_index.dda_fmcount;
	} else {
		/* read last index record */
		if (err = dda_vn_read(dda, dda->dda_index_vp, &last_index,
		    sizeof (dda_index_t), last_index_offset)) {
			return (err);
		}
		DDA_BE_INDEX(last_index, last_index);
		last_index_fileno = last_index.dda_fileno;
		last_index_fmcount = last_index.dda_fmcount;
	}

	*space = dda->dda_metadata.dda_capacity - /* max cart size minus */
	    dda->dda_data_fsize -		  /* data file size */
	    sizeof (dda_metadata_t) -		  /* metadata file size */
	    dda->dda_index_fsize -		  /* index file size */
	    last_index_fileno -			  /* total num of prev fms */
	    last_index_fmcount;			  /* remaining number of fms */

	if (*space < 0) {
		*space = 0;
	}

	DDA_DEBUG3((dda_capacity,
	    int, dda->dda_inst,
	    int64_t, dda->dda_metadata.dda_capacity,
	    int64_t, *space));

	return (0);
}

/*
 * dda_ew_eom
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- count:	Bytes to write.
 *	- avail:	Bytes available on media.
 *	- ew:		Early warning.
 *
 * On return avail contains the number of bytes that can be written
 * to the media. The ew flag is set if the write is past early warning.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_ew_eom(dda_t *dda, int32_t count, int64_t *avail, int *ew)
{
	int64_t	space;
	int	err;
	int64_t	used;

	if (err = dda_tape_capacity(dda, &space)) {
		return (err);
	}

	used = dda->dda_metadata.dda_capacity - space;

	if (used + count >= dda->dda_early_warn) {
		*ew = 1;
	} else {
		*ew = 0;
	}
	if (used + count > dda->dda_metadata.dda_capacity) {
		*avail = space;
	} else {
		*avail = count;
	}

	DDA_DEBUG4((dda_ew_eom,
	    int, dda->dda_inst,
	    int32_t, count,
	    int64_t, *avail,
	    int, *ew));

	return (0);
}

/* search */

/*
 * dda_locate_compare
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- lba:		Locate to LBA.
 *
 * Locate LBA binary search compare function.
 *
 * Return Values:
 *	0 : found
 *	1 : forward
 *	-1 : backward
 *
 */
static int
dda_locate_compare(dda_t *dda, int64_t lba)
{
	int64_t	last;

	last = dda->dda_index.dda_lba + DDA_INDEX_COUNT(dda);

	if (lba >= dda->dda_index.dda_lba && lba <= last) {

		dda->dda_pos = lba - dda->dda_index.dda_lba;

		return (0);
	}

	if (lba < dda->dda_index.dda_lba) {
		return (-1);
	}

	return (1);
}

/*
 * dda_fsf_compare
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- fileno:	Locate file number.
 *
 * Forward space file binary search compare function.
 *
 * Return Values:
 *	0 : found
 *	1 : forward
 *	-1 : backward
 *
 */
static int
dda_fsf_compare(dda_t *dda, int64_t fileno)
{
	int64_t	last;

	if (dda->dda_index.dda_fmcount) {

		last = dda->dda_index.dda_fileno + dda->dda_index.dda_fmcount;

		if (fileno > dda->dda_index.dda_fileno && fileno <= last) {

			dda->dda_pos = dda->dda_index.dda_blkcount +
			    fileno - dda->dda_index.dda_fileno;

			return (0);
		}
	}

	if (fileno <= dda->dda_index.dda_fileno) {
		return (-1);
	}

	return (1);
}

/*
 * dda_bsf_compare
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- fileno:	Locate file number.
 *
 * Backward space file binary search compare function.
 *
 * Return Values:
 *	0 : found
 *	1 : forward
 *	-1 : backward
 *
 */
static int
dda_bsf_compare(dda_t *dda, int64_t fileno)
{
	int64_t	last;

	if (dda->dda_index.dda_fmcount) {

		last = dda->dda_index.dda_fileno + dda->dda_index.dda_fmcount;

		if (fileno >= dda->dda_index.dda_fileno && fileno < last) {

			dda->dda_pos = dda->dda_index.dda_blkcount +
			    fileno - dda->dda_index.dda_fileno;

			return (0);
		}
	}

	if (fileno < dda->dda_index.dda_fileno) {
		return (-1);
	}

	return (1);
}

/*
 * dda_bsearch
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- key:		LBA or file number.
 *	- compare:	Binary search comparison function.
 *	- found:	Search successful.
 *
 * Binary search index file records for LBA or fileno.
 *
 * Return Values:
 *	0 : success
 *	errno : fs failure
 *
 */
static int
dda_bsearch(dda_t *dda,
    int64_t key,
    int (*compare)(dda_t *, int64_t),
    int *found)
{
	int	err;
	int	res;
	off64_t	nel, width, base, two_width, last;

	/*
	 * Index file binary search for lba or fileno
	 */

	DDA_DEBUG2((dda_bsearch,
	    int, dda->dda_inst,
	    int64_t, key));

	*found = 0;

	/* bsearch(3C) */
	width = sizeof (dda_index_t);
	two_width = width + width;

	base = 0;
	nel = dda->dda_index_fsize / sizeof (dda_index_t);
	last = base + width * (nel - 1);

	while (last >= base) {

		dda->dda_index_offset =
		    base + width * ((last - base) / two_width);

		if (err = dda_read_index(dda)) {
			return (err);
		}

		res = compare(dda, key);

		if (res == 0) {
			*found = 1;
			return (0);
		}

		if (res < 0) {
			last = dda->dda_index_offset - width;
		} else {
			base = dda->dda_index_offset + width;
		}
	}

	return (0);
}

/* vnode operations */

/*
 * dda_vn_open
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vpp:		Pointer to a vnode file pointer.
 *	- fname:	Filename to open.
 *
 * Open a dda media file from the kernel.
 * Ensure the dda user has permission to open the file.
 * On error convert the file open error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_open(dda_t *dda, struct vnode **vpp, char *fname)
{
	int		err;

	if (err = vn_open(fname, UIO_SYSSPACE, DDA_VNODE_MODE, 0, vpp, 0, 0)) {
		DDA_DEBUG3((dda_vn_open_err,
		    int, dda->dda_inst,
		    char *, fname,
		    int, err));
		*vpp = NULL;
		dda_vn_error_skey(dda, err);
		return (err);
	}

	err = VOP_ACCESS(*vpp, DDA_VNODE_MODE, 0, dda->dda_cred, NULL);
	if (err) {
		DDA_DEBUG3((dda_vn_open_access,
		    int, dda->dda_inst,
		    char *, fname,
		    int, err));
		(void) VOP_CLOSE(*vpp, DDA_VNODE_MODE, 1, (offset_t)0,
		    dda->dda_cred, NULL);
		VN_RELE(*vpp);
		*vpp = NULL;
		dda_vn_error_skey(dda, err);
	}
	return (err);
}

/*
 * dda_vn_close
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vpp:		Pointer to a vnode file pointer.
 *
 * Close dda media file from the kernel.
 * On error convert the file close error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_close(dda_t *dda, struct vnode **vpp)
{
	int		err;

	if (*vpp == NULL) {
		DDA_DEBUG1((dda_vn_close_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	err = VOP_CLOSE(*vpp, DDA_VNODE_MODE, 1, (offset_t)0,
	    dda->dda_cred, NULL);
	if (err) {
		DDA_DEBUG3((dda_vn_close_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, *vpp),
		    int, err));
		dda_vn_error_skey(dda, err);
	}
	VN_RELE(*vpp);
	*vpp = NULL;
	return (err);
}

/*
 * dda_vn_lock
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode pointer to open file.
 *	- cmd:		File lock or unlock command.
 *
 * Set or unset a file lock on the entire file.
 * The file lock is held by the driver while the media is loaded.
 *
 * Return Values:
 *      0 : success
 *      errno : failure
 *
 */
static int
dda_vn_lock(dda_t *dda, struct vnode *vp, short cmd)
{
	flock64_t	flk;
	int		err;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_lock_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	/* lock or unlock entire file */
	bzero(&flk, sizeof (flock64_t));
	flk.l_type = cmd;

	/* non-blocking file lock */
	err = VOP_FRLOCK(vp, F_SETLK, &flk, FREAD | FWRITE,
	    0, NULL, dda->dda_cred, NULL);

	if (cmd == F_UNLCK && vn_has_flocks(vp)) {
		cleanlocks(vp, IGN_PID, 0);
	}

	if (err) {
		DDA_DEBUG4((dda_vn_lock_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    int, cmd,
		    int, err));
		dda_vn_error_skey(dda, err);
	}

	return (err);
}

/*
 * dda_vn_read
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *	- buf:		File read buffer.
 *	- len:		Length of read buffer.
 *	- offset:	File offset to begin reading from.
 *
 * From the kernel read the requested buffer length from the file.
 * On error convert the file read error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_read(dda_t *dda, struct vnode *vp, void *buf, int len, off64_t offset)
{
	int		err;
	struct iovec	iov;
	struct uio	uio;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_read_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	iov.iov_base = (caddr_t)buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = offset;
	uio.uio_resid = len;
	uio.uio_fmode = FREAD;
	uio.uio_llimit = MAXOFFSET_T;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	err = VOP_READ(vp, &uio, 0, dda->dda_cred, NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);

	if (err) {
		DDA_DEBUG4((dda_vn_read_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    off64_t, offset,
		    int, err));
		dda_vn_error_skey(dda, err);
		return (err);
	}

	if (uio.uio_resid != 0) {
		DDA_DEBUG4((dda_vn_read_resid,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    off64_t, offset,
		    int32_t, uio.uio_resid));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}
	return (0);
}

/*
 * dda_vn_write
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *	- buf:		File write buffer.
 *	- len:		Length of write buffer.
 *	- offset:	File offset to begin writing.
 *
 * From the kernel write the requested buffer length to the file.
 * On error convert the file write error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_write(dda_t *dda, struct vnode *vp, void *buf, int len, off64_t offset)
{
	int		err;
	struct iovec	iov;
	struct uio	uio;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_write_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	iov.iov_base = (caddr_t)buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = offset;
	uio.uio_resid = len;
	uio.uio_fmode = FWRITE;
	uio.uio_llimit = MAXOFFSET_T;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	err = VOP_WRITE(vp, &uio, FWRITE|FTRUNC, dda->dda_cred, NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

	if (err) {
		DDA_DEBUG4((dda_vn_write_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    off64_t, offset,
		    int, err));
		dda_vn_error_skey(dda, err);
		return (err);
	}

	if (uio.uio_resid != 0) {
		DDA_DEBUG4((dda_vn_write_resid,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    off64_t, offset,
		    int32_t, uio.uio_resid));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}
	return (0);
}

/*
 * dda_vn_truncate
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *	- offset:	Truncate file at offset.
 *
 * Truncate the file.
 * On error convert the file truncate error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_truncate(dda_t *dda, struct vnode *vp, off64_t offset)
{
	int		err;
	struct vattr	vattr;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_truncate_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	vattr.va_size = offset;
	vattr.va_mask = AT_SIZE;
	err = VOP_SETATTR(vp, &vattr, 0, dda->dda_cred, NULL);
	if (err) {
		DDA_DEBUG4((dda_vn_truncate_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    off64_t, offset,
		    int, err));
		dda_vn_error_skey(dda, err);
	}
	return (err);
}

/*
 * dda_vn_sync
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *
 * Flush file to disk.
 * On error convert the file flush error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_sync(dda_t *dda, struct vnode *vp)
{
	int		err;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_sync_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	err = VOP_FSYNC(vp, FSYNC, dda->dda_cred, NULL);
	if (err) {
		DDA_DEBUG3((dda_vn_sync_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    int, err));
		dda_vn_error_skey(dda, err);
	}
	return (err);
}

/*
 * dda_vn_size
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *	- fsize:	File size.
 *
 * Get dda media file size.
 * On error convert the file size error into a sense key.
 *
 * Return Values:
 *	0 : success
 *	errno : failure
 *
 */
static int
dda_vn_size(dda_t *dda, struct vnode *vp, off64_t *fsize)
{
	int		err;
	struct vattr	vattr;

	if (vp == NULL) {
		DDA_DEBUG1((dda_vn_size_null,
		    int, dda->dda_inst));
		dda->dda_status = KEY_MEDIUM_ERROR;
		return (EIO);
	}

	vattr.va_mask = AT_SIZE;
	err = VOP_GETATTR(vp, &vattr, 0, dda->dda_cred, NULL);
	if (err) {
		DDA_DEBUG3((dda_vn_size_err,
		    int, dda->dda_inst,
		    char *, dda_vn_get_fname(dda, vp),
		    int, err));
		dda_vn_error_skey(dda, err);
	} else {
		*fsize = (off64_t)vattr.va_size;
	}
	return (err);
}

/*
 * dda_vn_get_fname
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- vp:		Vnode file pointer.
 *
 * Get dda media filename from the vnode pointer for tracing.
 *
 * Return Values:
 *	filename
 *
 */
static char *
dda_vn_get_fname(dda_t *dda, struct vnode *vp)
{
	char	*fname;

	if (vp == dda->dda_metadata_vp) {
		fname = DDA_METADATA_FNAME;
	} else if (vp == dda->dda_index_vp) {
		fname = DDA_INDEX_FNAME;
	} else if (vp == dda->dda_data_vp) {
		fname = DDA_DATA_FNAME;
	} else {
		fname = DDA_UNKNOWN_FNAME;
	}
	return (fname);
}

/*
 * dda_vn_error_skey
 *
 * Parameters:
 *	- dda:		DDA tape drive.
 *	- int:		errno
 *
 * Convert filesystem or kernel errno into tape drive sense key.
 *
 * Return Values:
 *	None
 *
 */
static void
dda_vn_error_skey(dda_t *dda, int err)
{
	switch (err) {
	case 0:		/* no error */
		dda->dda_status = KEY_NO_SENSE;
		break;
	case EINVAL:	/* invalid arg */
		dda->dda_status = KEY_ILLEGAL_REQUEST;
		break;
	case EFBIG:	/* file too large */
	case ENOSPC:	/* no space */
		dda->dda_status = SUN_KEY_EOT;
		break;
	case EACCES:	/* permission denied */
	case EROFS:	/* read only fs */
		dda->dda_status = KEY_WRITE_PROTECT;
		break;
	case EISDIR:	/* is directory */
	case ENOENT:	/* no such file or directory */
		dda->dda_status = KEY_MEDIUM_ERROR;
		break;
	/* ESTALE: stale nfs file handle */
	/* EMFILE: too many open files */
	/* EMLINK: too many links */
	/* EAGAIN: resource temporarily unavailable */
	/* ENOMEM: not enough core */
	/* ENOLCK: no record locks available */
	default:
		dda->dda_status = KEY_RECOVERABLE_ERROR;
		break;
	}
}

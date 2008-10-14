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

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#ifndef DS_DDICT
#include <sys/vnode.h>
#endif
#include <sys/cmn_err.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/uio.h>
#ifndef DS_DDICT
#include <sys/pathname.h>	/* for lookupname */
#endif
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

#include <ns/solaris/nsc_thread.h>
#ifdef DS_DDICT
#include "../contract.h"
#endif
#include "../nsctl.h"
#include "nskernd.h"


typedef struct raw_maj {
	struct raw_maj	*next;
	major_t		major;
	struct dev_ops	*devops;
	strategy_fn_t	strategy;
	int		(*open)(dev_t *, int, int, cred_t *);
	int		(*close)(dev_t, int, int, cred_t *);
	int		(*ioctl)(dev_t, int, intptr_t, int, cred_t *, int *);
} raw_maj_t;

typedef struct raw_dev {
	ldi_handle_t	lh;		/* Solaris layered driver handle */
	struct vnode	*vp;		/* vnode of device */
	uint64_t	size;		/* size of device in blocks */
	raw_maj_t	*major;		/* pointer to major structure */
	char		*path;		/* pathname -- kmem_alloc'd */
	int		plen;		/* length of kmem_alloc for pathname */
	dev_t		rdev;		/* device number */
	char		in_use;		/* flag */
	int		partition;	/* partition number */
} raw_dev_t;

static int fd_hwm = 0;	/* first never used entry in _nsc_raw_files */

static raw_dev_t *_nsc_raw_files;
static raw_maj_t *_nsc_raw_majors;

kmutex_t _nsc_raw_lock;

int _nsc_raw_flags = 0;				/* required by nsctl */
static int _nsc_raw_maxdevs;			/* local copy */

static int _raw_strategy(struct buf *);		/* forward decl */

static dev_t
ldi_get_dev_t_from_path(char *path)
{
	vnode_t	*vp;
	dev_t rdev;

	/* Validate parameters */
	if (path == NULL)
		return (NULL);

	/* Lookup path */
	vp = NULL;
	if (lookupname(path, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp))
		return (NULL);

	/* Validate resulting vnode */
	if ((vp) && (vp->v_type == VCHR))
		rdev = vp->v_rdev;
	else
		rdev = (dev_t)NULL;

	/* Release vnode */
	if (vp)
		VN_RELE(vp);

	return (rdev);
}

int
_nsc_init_raw(int maxdevs)
{
	_nsc_raw_files =
	    kmem_zalloc(sizeof (*_nsc_raw_files) * maxdevs, KM_SLEEP);
	if (!_nsc_raw_files)
		return (ENOMEM);

	_nsc_raw_maxdevs = maxdevs;
	_nsc_raw_majors = NULL;

	mutex_init(&_nsc_raw_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}


void
_nsc_deinit_raw(void)
{
	raw_maj_t *maj = _nsc_raw_majors;
	raw_maj_t *next;

	/*  Free the memory allocated for strategy pointers */
	while (maj != NULL) {
		next = maj->next;
		kmem_free(maj, sizeof (*maj));
		maj = next;
	}

	mutex_destroy(&_nsc_raw_lock);
	kmem_free(_nsc_raw_files, sizeof (*_nsc_raw_files) * _nsc_raw_maxdevs);
	_nsc_raw_files = NULL;
	_nsc_raw_maxdevs = 0;
}


/* must be called with the _nsc_raw_lock held */
static raw_maj_t *
_raw_get_maj_info(major_t umaj)
{
	raw_maj_t *maj = _nsc_raw_majors;

	ASSERT(MUTEX_HELD(&_nsc_raw_lock));

	/*  Walk through the linked list */
	while (maj != NULL) {
		if (maj->major == umaj) {
			/* Found major number */
			break;
		}
		maj = maj->next;
	}

	if (maj == NULL) {
		struct dev_ops *ops = NULL;
#ifdef DEBUG
		const int maxtry = 5;
		int try = maxtry;
#endif

		/*
		 * The earlier ldi_open call has locked the driver
		 * for this major number into memory, so just index into
		 * the devopsp array to get the dev_ops pointer which
		 * must be valid.
		 */

		ops = devopsp[umaj];

		if (ops == NULL || ops->devo_cb_ops == NULL) {
			cmn_err(CE_WARN,
			    "nskern: cannot find dev_ops for major %d", umaj);

			return (NULL);
		}

#ifdef DEBUG
		cmn_err(CE_NOTE,
			"nsc_raw: held driver (%d) after %d attempts",
			umaj, (maxtry - try));
#endif /* DEBUG */

		maj = kmem_zalloc(sizeof (raw_maj_t), KM_NOSLEEP);
		if (!maj) {
			return (NULL);
		}

		maj->strategy = ops->devo_cb_ops->cb_strategy;
		maj->ioctl = ops->devo_cb_ops->cb_ioctl;
		maj->close = ops->devo_cb_ops->cb_close;
		maj->open = ops->devo_cb_ops->cb_open;
		maj->major = umaj;
		maj->devops = ops;

		if (maj->strategy == NULL ||
		    maj->strategy == nodev ||
		    maj->strategy == nulldev) {
			cmn_err(CE_WARN,
			    "nskern: no strategy function for "
			    "disk driver (major %d)",
			    umaj);
			kmem_free(maj, sizeof (*maj));
			return (NULL);
		}

		maj->next = _nsc_raw_majors;
		_nsc_raw_majors = maj;
	}

	return (maj);
}


/*
 * nsc_get_strategy returns the strategy function associated with
 * the major number umaj.  NULL is returned if no strategy is found.
 */
strategy_fn_t
nsc_get_strategy(major_t umaj)
{
	raw_maj_t *maj;
	strategy_fn_t strategy = NULL;

	mutex_enter(&_nsc_raw_lock);

	for (maj = _nsc_raw_majors; maj != NULL; maj = maj->next) {
		if (maj->major == umaj) {
			/* Found major number */
			strategy = maj->strategy;
			break;
		}
	}

	mutex_exit(&_nsc_raw_lock);

	return (strategy);
}


void *
nsc_get_devops(major_t umaj)
{
	raw_maj_t *maj;
	void *devops = NULL;

	mutex_enter(&_nsc_raw_lock);

	for (maj = _nsc_raw_majors; maj != NULL; maj = maj->next) {
		if (maj->major == umaj) {
			devops = maj->devops;
			break;
		}
	}

	mutex_exit(&_nsc_raw_lock);

	return (devops);
}


/*
 * _raw_open
 *
 * Multiple opens, single close.
 */

/* ARGSUSED */
static int
_raw_open(char *path, int flag, blind_t *cdp, void *iodev)
{
	struct cred *cred;
	raw_dev_t *cdi = NULL;
	char *spath;
	dev_t rdev;
	int rc, cd, the_cd;
	int plen;
	ldi_ident_t	li;

	if (proc_nskernd == NULL) {
		cmn_err(CE_WARN, "nskern: no nskernd daemon running!");
		return (ENXIO);
	}

	if (_nsc_raw_maxdevs == 0) {
		cmn_err(CE_WARN, "nskern: _raw_open() before _nsc_init_raw()!");
		return (ENXIO);
	}

	plen = strlen(path) + 1;
	spath = kmem_alloc(plen, KM_SLEEP);
	if (spath == NULL) {
		cmn_err(CE_WARN,
		    "nskern: unable to alloc memory in _raw_open()");
		return (ENOMEM);
	}

	(void) strcpy(spath, path);

	/*
	 * Lookup the vnode to extract the dev_t info,
	 * then release the vnode.
	 */
	if ((rdev = ldi_get_dev_t_from_path(path)) == 0) {
		kmem_free(spath, plen);
		return (ENXIO);
	}

	/*
	 * See if this device is already opened
	 */

	the_cd = -1;

	mutex_enter(&_nsc_raw_lock);

	for (cd = 0, cdi = _nsc_raw_files; cd < fd_hwm; cd++, cdi++) {
		if (rdev == cdi->rdev) {
			the_cd = cd;
			break;
		} else if (the_cd == -1 && !cdi->in_use)
			the_cd = cd;
	}

	if (the_cd == -1) {
		if (fd_hwm < _nsc_raw_maxdevs)
			the_cd = fd_hwm++;
		else {
			mutex_exit(&_nsc_raw_lock);
			cmn_err(CE_WARN, "_raw_open: too many open devices");
			kmem_free(spath, plen);
			return (EIO);
		}
	}

	cdi = &_nsc_raw_files[the_cd];
	if (cdi->in_use) {
		/* already set up - just return */
		mutex_exit(&_nsc_raw_lock);
		*cdp = (blind_t)cdi->rdev;
		kmem_free(spath, plen);
		return (0);
	}

	cdi->partition = -1;
	cdi->size = (uint64_t)0;
	cdi->rdev = rdev;
	cdi->path = spath;
	cdi->plen = plen;

	cred = ddi_get_cred();

	/*
	 * Layered driver
	 *
	 * We use xxx_open_by_dev() since this guarantees that a
	 * specfs vnode is created and used, not a standard filesystem
	 * vnode. This is necessary since in a cluster PXFS will block
	 * vnode operations during switchovers, so we have to use the
	 * underlying specfs vnode not the PXFS vnode.
	 *
	 */

	if ((rc = ldi_ident_from_dev(cdi->rdev, &li)) == 0) {
		rc = ldi_open_by_dev(&cdi->rdev,
		    OTYP_BLK, FREAD|FWRITE, cred, &cdi->lh, li);
	}
	if (rc != 0) {
		cdi->lh = NULL;
		goto failed;
	}

	/*
	 * grab the major_t related information
	 */

	cdi->major = _raw_get_maj_info(getmajor(rdev));
	if (cdi->major == NULL) {
		/* Out of memory */
		cmn_err(CE_WARN,
		    "_raw_open: cannot alloc major number structure");

		rc = ENOMEM;
		goto failed;
	}

	*cdp = (blind_t)cdi->rdev;
	cdi->in_use++;

	mutex_exit(&_nsc_raw_lock);

	return (rc);

failed:

	if (cdi->lh)
		(void) ldi_close(cdi->lh, FWRITE|FREAD, cred);

	bzero(cdi, sizeof (*cdi));

	mutex_exit(&_nsc_raw_lock);

	kmem_free(spath, plen);
	return (rc);
}


static int
__raw_get_cd(dev_t fd)
{
	int cd;

	if (_nsc_raw_maxdevs != 0) {
		for (cd = 0; cd < fd_hwm; cd++) {
			if (fd == _nsc_raw_files[cd].rdev)
				return (cd);
		}
	}

	return (-1);
}


/*
 * _raw_close
 *
 * Multiple opens, single close.
 */

static int
_raw_close(dev_t fd)
{
	struct cred *cred;
	raw_dev_t *cdi;
	int rc;
	int cd;

	mutex_enter(&_nsc_raw_lock);

	if ((cd = __raw_get_cd(fd)) == -1 || !_nsc_raw_files[cd].in_use) {
		mutex_exit(&_nsc_raw_lock);
		return (EIO);
	}

	cdi = &_nsc_raw_files[cd];

	cred = ddi_get_cred();

	rc = ldi_close(cdi->lh, FREAD|FWRITE, cred);
	if (rc != 0) {
		mutex_exit(&_nsc_raw_lock);
		return (rc);
	}

	kmem_free(cdi->path, cdi->plen);

	bzero(cdi, sizeof (*cdi));

	mutex_exit(&_nsc_raw_lock);

	return (0);
}


/* ARGSUSED */
static int
_raw_uread(dev_t fd, uio_t *uiop, cred_t *crp)
{
	return (physio(_raw_strategy, 0, fd, B_READ, minphys, uiop));
}


/* ARGSUSED */
static int
_raw_uwrite(dev_t fd, uio_t *uiop, cred_t *crp)
{
	return (physio(_raw_strategy, 0, fd, B_WRITE, minphys, uiop));
}


static int
_raw_strategy(struct buf *bp)
{
	int cd = __raw_get_cd(bp->b_edev);

	if (cd == -1 || _nsc_raw_files[cd].major == NULL) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (NULL);
	}

	return ((*_nsc_raw_files[cd].major->strategy)(bp));
}


static int
_raw_partsize(dev_t fd, nsc_size_t *rvalp)
{
	int cd;

	if ((cd = __raw_get_cd(fd)) == -1 || !_nsc_raw_files[cd].in_use)
		return (EIO);

	*rvalp = (nsc_size_t)_nsc_raw_files[cd].size;
	return (0);
}


/*
 * Return largest i/o size.
 */

static nsc_size_t nsc_rawmaxfbas = 0;
/* ARGSUSED */
static int
_raw_maxfbas(dev_t dev, int flag, nsc_size_t *ptr)
{
	struct buf *bp;
	if (flag == NSC_CACHEBLK)
		*ptr = 1;
	else {
		if (nsc_rawmaxfbas == 0) {
			bp = getrbuf(KM_SLEEP);
			bp->b_bcount = 4096 * 512;
			minphys(bp);
			nsc_rawmaxfbas = FBA_NUM(bp->b_bcount);
			freerbuf(bp);
		}
		*ptr = nsc_rawmaxfbas;
	}
	return (0);
}


/*
 * Control device or system.
 */

/* ARGSUSED */
static int
_raw_control(dev_t dev, int cmd, int *ptr)
{
#ifdef DEBUG
	cmn_err(CE_WARN, "unrecognised nsc_control: %x", cmd);
#endif
	return (EINVAL);	/* no control commands understood */
}


static int
_raw_get_bsize(dev_t dev, uint64_t *bsizep, int *partitionp)
{
#ifdef DKIOCPARTITION
	struct partition64 *p64 = NULL;
#endif
	struct dk_cinfo *dki_info = NULL;
	struct dev_ops *ops;
	struct cred *cred;
	struct vtoc *vtoc = NULL;
	dev_info_t *dip;
	raw_dev_t *cdi;
	int rc, cd;
	int flags;
	int rval;

	*partitionp = -1;
	*bsizep = 0;

	if ((cd = __raw_get_cd(dev)) == -1 || !_nsc_raw_files[cd].in_use)
		return (-1);

	cdi = &_nsc_raw_files[cd];
	ops = cdi->major->devops;

	if (ops == NULL) {
		return (-1);
	}

	rc = (*ops->devo_getinfo)(NULL, DDI_INFO_DEVT2DEVINFO,
	    (void *)dev, (void **)&dip);

	if (rc != DDI_SUCCESS || dip == NULL) {
		return (-1);
	}

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, DDI_KERNEL_IOCTL)) {
		return (-1);
	}

	cred = ddi_get_cred();

	flags = FKIOCTL | FREAD | FWRITE | DATAMODEL_NATIVE;

	dki_info = kmem_alloc(sizeof (*dki_info), KM_SLEEP);

	/* DKIOCINFO */
	rc = (*cdi->major->ioctl)(dev, DKIOCINFO,
	    (intptr_t)dki_info, flags, cred, &rval);

	if (rc != 0) {
		goto out;
	}

	/* return partition number */
	*partitionp = (int)dki_info->dki_partition;

	vtoc = kmem_alloc(sizeof (*vtoc), KM_SLEEP);

	/* DKIOCGVTOC */
	rc = (*cdi->major->ioctl)(dev, DKIOCGVTOC,
	    (intptr_t)vtoc, flags, cred, &rval);

	if (rc) {
		/* DKIOCGVTOC failed, but there might be an EFI label */
		rc = -1;

#ifdef DKIOCPARTITION
		/* do we have an EFI partition table? */
		p64 = kmem_alloc(sizeof (*p64), KM_SLEEP);
		p64->p_partno = (uint_t)*partitionp;

		/* DKIOCPARTITION */
		rc = (*cdi->major->ioctl)(dev, DKIOCPARTITION,
		    (intptr_t)p64, flags, cred, &rval);

		if (rc == 0) {
			/* found EFI, return size */
			*bsizep = (uint64_t)p64->p_size;
		} else {
			/* both DKIOCGVTOC and DKIOCPARTITION failed - error */
			rc = -1;
		}
#endif

		goto out;
	}

	if ((vtoc->v_sanity != VTOC_SANE) ||
	    (vtoc->v_version != V_VERSION && vtoc->v_version != 0) ||
	    (dki_info->dki_partition > V_NUMPAR)) {
		rc = -1;
		goto out;
	}

	*bsizep = (uint64_t)vtoc->v_part[(int)dki_info->dki_partition].p_size;
	rc = 0;

out:
	if (dki_info) {
		kmem_free(dki_info, sizeof (*dki_info));
	}

	if (vtoc) {
		kmem_free(vtoc, sizeof (*vtoc));
	}

#ifdef DKIOCPARTITION
	if (p64) {
		kmem_free(p64, sizeof (*p64));
	}
#endif

	return (rc);
}


/*
 * Ugly, ugly, ugly.
 *
 * Some volume managers (Veritas) don't support layered ioctls
 * (no FKIOCTL support, no DDI_KERNEL_IOCTL property defined) AND
 * do not support the properties for bdev_Size()/bdev_size().
 *
 * If the underlying driver has specified DDI_KERNEL_IOCTL, then we use
 * the FKIOCTL technique.  Otherwise ...
 *
 * The only reliable way to get the partition size, is to bounce the
 * command through user land (nskernd).
 *
 * Then, SunCluster PXFS blocks access at the vnode level to device
 * nodes during failover / switchover, so a read_vtoc() function call
 * from user land deadlocks.  So, we end up coming back into the kernel
 * to go directly to the underlying device driver - that's what
 * nskern_bsize() is doing below.
 *
 * There has to be a better way ...
 */

static int
_raw_init_dev(dev_t fd, uint64_t *sizep, int *partitionp)
{
	struct nskernd *nsk;
	int rc, cd;

	if ((cd = __raw_get_cd(fd)) == -1 || !_nsc_raw_files[cd].in_use)
		return (EIO);

	/* try the in-kernel way */

	rc = _raw_get_bsize(fd, sizep, partitionp);
	if (rc == 0) {
		return (0);
	}

	/* fallback to the the slow way */

	nsk = kmem_zalloc(sizeof (*nsk), KM_SLEEP);
	nsk->command = NSKERND_BSIZE;
	nsk->data1 = (uint64_t)0;
	nsk->data2 = (uint64_t)fd;
	(void) strncpy(nsk->char1, _nsc_raw_files[cd].path, NSC_MAXPATH);

	rc = nskernd_get(nsk);
	if (rc == 0) {
		*partitionp = (int)nsk->data2;
		*sizep = nsk->data1;
	}

	kmem_free(nsk, sizeof (*nsk));
	return (rc < 0 ? EIO : 0);
}


static int
_raw_attach_io(dev_t fd)
{
	int cd;

	if ((cd = __raw_get_cd(fd)) == -1 || !_nsc_raw_files[cd].in_use)
		return (EIO);

	return (_raw_init_dev(fd, &_nsc_raw_files[cd].size,
	    &_nsc_raw_files[cd].partition));
}


/*
 * See the comment above _raw_init_dev().
 */

int
nskern_bsize(struct nscioc_bsize *bsize, int *rvp)
{
	struct cred *cred;
	raw_dev_t *cdi;
	int errno = 0;
	int flag;
	int cd;

	*rvp = 0;

	if (bsize == NULL || rvp == NULL)
		return (EINVAL);

	cd = __raw_get_cd(bsize->raw_fd);
	if (cd == -1 || !_nsc_raw_files[cd].in_use)
		return (EIO);

	cdi = &_nsc_raw_files[cd];
	cred = ddi_get_cred();

	/*
	 * ddi_mmap_get_model() returns the model for this user thread
	 * which is what we want - get_udatamodel() is not public.
	 */

	flag = FREAD | FWRITE | ddi_mmap_get_model();

	if (bsize->efi == 0) {
		/* DKIOCINFO */
		errno = (*cdi->major->ioctl)(bsize->raw_fd,
		    DKIOCINFO, (intptr_t)bsize->dki_info, flag, cred, rvp);

		if (errno) {
			return (errno);
		}

		/* DKIOCGVTOC */
		errno = (*cdi->major->ioctl)(bsize->raw_fd,
		    DKIOCGVTOC, (intptr_t)bsize->vtoc, flag, cred, rvp);

		if (errno) {
			return (errno);
		}
	} else {
#ifdef DKIOCPARTITION
		/* do we have an EFI partition table? */
		errno = (*cdi->major->ioctl)(bsize->raw_fd,
		    DKIOCPARTITION, (intptr_t)bsize->p64, flag, cred, rvp);

		if (errno) {
			return (errno);
		}
#endif
	}

	return (0);
}


/*
 * Private function for sv to use.
 */
int
nskern_partition(dev_t fd, int *partitionp)
{
	uint64_t size;
	int cd, rc;

	if ((cd = __raw_get_cd(fd)) == -1 || !_nsc_raw_files[cd].in_use)
		return (EIO);

	if ((*partitionp = _nsc_raw_files[cd].partition) != -1) {
		return (0);
	}

	rc = _raw_init_dev(fd, &size, partitionp);
	if (rc != 0 || *partitionp < 0) {
		return (EIO);
	}

	return (0);
}


nsc_def_t _nsc_raw_def[] = {
	"Open",		(uintptr_t)_raw_open,		0,
	"Close",	(uintptr_t)_raw_close,		0,
	"Attach",	(uintptr_t)_raw_attach_io,	0,
	"UserRead",	(uintptr_t)_raw_uread,		0,
	"UserWrite",	(uintptr_t)_raw_uwrite,		0,
	"PartSize",	(uintptr_t)_raw_partsize,	0,
	"MaxFbas",	(uintptr_t)_raw_maxfbas,	0,
	"Control",	(uintptr_t)_raw_control,	0,
	"Provide",	NSC_DEVICE,			0,
	0,		0,				0
};

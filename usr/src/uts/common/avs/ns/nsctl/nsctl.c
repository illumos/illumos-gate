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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsc_gen.h>
#include <sys/nsctl/nsc_ioctl.h>
#include <sys/nsctl/nsc_power.h>
#include <sys/nsctl/nsc_mem.h>
#include "../nsctl.h"

#include <sys/nsctl/nsvers.h>

#ifdef DS_DDICT
#include "../contract.h"
#endif

extern void nscsetup();
extern int _nsc_init_raw(int);
extern void _nsc_deinit_raw();
extern void _nsc_init_start();
extern void _nsc_init_os(), _nsc_deinit_os();
extern void _nsc_init_dev(), _nsc_init_mem();
extern void _nsc_init_gen(), _nsc_init_rmlock();
extern void _nsc_init_resv(), _nsc_deinit_resv();
extern void _nsc_init_frz(), _nsc_deinit_frz();
extern void _nsc_init_ncio(), _nsc_deinit_ncio();
extern void _nsc_deinit_mem(), _nsc_deinit_rmlock();
extern void _nsc_deinit_dev();

extern int _nsc_frz_start(char *, int *);
extern int _nsc_frz_stop(char *, int *);
extern int _nsc_frz_isfrozen(char *, int *);

extern nsc_mem_t *_nsc_local_mem;
extern nsc_rmhdr_t *_nsc_rmhdr_ptr;
extern nsc_def_t _nsc_raw_def[];
extern int _nsc_raw_flags;

int nsc_devflag = D_MP;

int _nsc_init_done = 0;

kmutex_t _nsc_drv_lock;
nsc_io_t *_nsc_file_io;
nsc_io_t *_nsc_vchr_io;
nsc_io_t *_nsc_raw_io;

nsc_fd_t **_nsc_minor_fd;
kmutex_t **_nsc_minor_slp;


/* Maximum number of devices - tunable in nsctl.conf */
static int _nsc_max_devices;

/* Internal version of _nsc_max_devices */
int _nsc_maxdev;

extern void _nsc_global_setup(void);

static int nsc_load(), nsc_unload();
static void nscteardown();

/*
 * Solaris specific driver module interface code.
 */

extern int nscopen(dev_t *, int, int, cred_t *);
extern int nscioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int nscclose(dev_t, int, int, cred_t *);
extern int nscread(dev_t, uio_t *, cred_t *);
extern int nscwrite(dev_t, uio_t *, cred_t *);

static dev_info_t *nsctl_dip;		/* Single DIP for driver */

static int _nsctl_print(dev_t, char *);

static	struct	cb_ops nsctl_cb_ops = {
	nscopen,		/* open */
	nscclose,	/* close */
	nodev,		/* not a block driver, strategy not an entry point */
	_nsctl_print,	/* no print routine */
	nodev,		/* no dump routine */
	nscread,		/* read */
	nscwrite,	/* write */
	(int (*)()) nscioctl,	/* ioctl */
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver, no cb_str routine */
	D_NEW | D_MP | D_64BIT,	/* safe for multi-thread/multi-processor */
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
};

static int _nsctl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int _nsctl_attach(dev_info_t *, ddi_attach_cmd_t);
static int _nsctl_detach(dev_info_t *, ddi_detach_cmd_t);

static	struct	dev_ops nsctl_ops = {
	DEVO_REV,			/* Driver build version */
	0,				/* device reference count */
	_nsctl_getinfo,
	nulldev,			/* Identify */
	nulldev,			/* Probe */
	_nsctl_attach,
	_nsctl_detach,
	nodev,				/* Reset */
	&nsctl_cb_ops,
	(struct bus_ops *)0
};

static struct modldrv nsctl_ldrv = {
	&mod_driverops,
	"nws:Control:" ISS_VERSION_STR,
	&nsctl_ops
};

static	struct modlinkage nsctl_modlinkage = {
	MODREV_1,
	&nsctl_ldrv,
	NULL
};

/*
 * Solaris module load time code
 */

int nsc_min_nodeid;
int nsc_max_nodeid;

int
_init(void)
{
	int err;

	err = nsc_load();

	if (!err)
		err = mod_install(&nsctl_modlinkage);

	if (err) {
		(void) nsc_unload();
		cmn_err(CE_NOTE, "!nsctl_init: err %d", err);
	}

	return (err);

}

/*
 * Solaris module unload time code
 */

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&nsctl_modlinkage)) == 0) {
		err = nsc_unload();
	}
	return (err);
}

/*
 * Solaris module info code
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&nsctl_modlinkage, modinfop));
}

/*
 * Attach an instance of the device. This happens before an open
 * can succeed.
 */
static int
_nsctl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rc;

	if (cmd == DDI_ATTACH) {
		nsctl_dip = dip;

		/* Announce presence of the device */
		ddi_report_dev(dip);

		/*
		 * Get the node parameters now that we can look up.
		 */
		nsc_min_nodeid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "nsc_min_nodeid", 0);

		nsc_max_nodeid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "nsc_max_nodeid", 5);

		_nsc_max_devices = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "nsc_max_devices", 128);

		_nsc_maxdev = _nsc_max_devices;
		nscsetup();

		/*
		 * Init raw requires the _nsc_max_devices value and so
		 * cannot be done before the nsc_max_devices property has
		 * been read which can only be done after the module is
		 * attached and we have a dip.
		 */

		if ((rc = _nsc_init_raw(_nsc_max_devices)) != 0) {
			cmn_err(CE_WARN,
			    "!nsctl: unable to initialize raw io provider: %d",
			    rc);
			return (DDI_FAILURE);
		}

		/*
		 * Init rest of soft state structure
		 */

		rc = ddi_create_minor_node(dip, "c,nsctl", S_IFCHR, 0,
		    DDI_PSEUDO, 0);
		if (rc != DDI_SUCCESS) {
			/* free anything we allocated here */
			cmn_err(CE_WARN,
			    "!_nsctl_attach: ddi_create_minor_node failed %d",
			    rc);
			return (DDI_FAILURE);
		}

		/* Announce presence of the device */
		ddi_report_dev(dip);

		/* mark the device as attached, opens may proceed */
		return (DDI_SUCCESS);
	} else
		return (DDI_FAILURE);
}

static int
_nsctl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_DETACH) {
		nscteardown();
		_nsc_deinit_raw();

		ddi_remove_minor_node(dip, NULL);
		nsctl_dip = NULL;

		return (DDI_SUCCESS);
	}
	else
		return (DDI_FAILURE);
}


/* ARGSUSED */
static int
_nsctl_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t dev;
	int rc;

	switch (cmd) {
		case DDI_INFO_DEVT2INSTANCE:
			/* The "instance" number is the minor number */
			dev = (dev_t)arg;
			*result = (void *)(unsigned long)getminor(dev);
			rc = DDI_SUCCESS;
			break;

		case DDI_INFO_DEVT2DEVINFO:
			*result = nsctl_dip;
			rc = DDI_SUCCESS;
			break;

		default:
			rc = DDI_FAILURE;
			break;
	}

	return (rc);
}


/* ARGSUSED */
static int
_nsctl_print(dev_t dev, char *s)
{
	cmn_err(CE_WARN, "!nsctl:%s", s);
	return (0);
}


void
nsc_init()
{
	if (_nsc_init_done)
		return;

	_nsc_init_start();
	_nsc_init_gen();
	_nsc_init_svc();
	_nsc_init_mem();
	_nsc_init_dev();
	_nsc_init_rmlock();
	_nsc_init_resv();
	_nsc_init_os();
	(void) _nsc_init_power();

	/*
	 * When using mc, nscsetup is done through mc callback to global_init.
	 */
	nscsetup();

	mutex_init(&_nsc_drv_lock, NULL, MUTEX_DRIVER, NULL);

	_nsc_raw_io = nsc_register_io("raw",
	    NSC_RAW_ID | _nsc_raw_flags, _nsc_raw_def);

	if (!_nsc_raw_io)
		cmn_err(CE_WARN, "!_nsc_init: register io failed - raw");

	_nsc_init_ncio();
	_nsc_init_frz();

	_nsc_init_done = 1;
}


/*
 * Called after the mc refresh is complete (SEG_INIT callbacks have
 * been received) and module _attach() is done.  Only does any real
 * work when all of the above conditions have been met.
 */
void
nscsetup()
{
	if (nsc_max_devices() == 0 || _nsc_minor_fd != NULL)
		return;

	_nsc_minor_fd = nsc_kmem_zalloc(sizeof (nsc_fd_t *)*_nsc_maxdev,
	    0, _nsc_local_mem);

	if (!_nsc_minor_fd) {
		cmn_err(CE_WARN, "!nscsetup - alloc failed");
		return;
	}

	_nsc_minor_slp = nsc_kmem_zalloc(sizeof (kmutex_t *)*_nsc_maxdev,
	    0, _nsc_local_mem);

	if (!_nsc_minor_slp)  {
		cmn_err(CE_WARN, "!nscsetup - alloc failed");
		nsc_kmem_free(_nsc_minor_fd, sizeof (nsc_fd_t *) * _nsc_maxdev);
		_nsc_minor_fd = (nsc_fd_t **)NULL;
	}
}

static void
nscteardown()
{
	int i;

	if (_nsc_minor_fd == NULL)
		return;

#ifdef DEBUG
	/* Check all devices were closed.  Index 0 is the prototype dev. */
	for (i = 1; i < _nsc_maxdev; i++) {
		ASSERT(_nsc_minor_slp[i] == NULL);
		ASSERT(_nsc_minor_fd[i] == NULL);
	}
#endif /* DEBUG */

	nsc_kmem_free(_nsc_minor_fd, sizeof (nsc_fd_t *) * _nsc_maxdev);
	nsc_kmem_free(_nsc_minor_slp, sizeof (kmutex_t *) * _nsc_maxdev);

	_nsc_minor_fd = (nsc_fd_t **)NULL;
	_nsc_minor_slp = (kmutex_t **)NULL;
}

int
nsc_load()
{
	nsc_init();
	return (0);
}


int
nsc_unload()
{
	if (!_nsc_init_done) {
		return (0);
	}

	nscteardown();

	(void) _nsc_deinit_power();
	_nsc_deinit_resv();
	_nsc_deinit_mem();
	_nsc_deinit_rmlock();
	_nsc_deinit_svc();
	_nsc_deinit_frz();
	_nsc_deinit_ncio();

	if (_nsc_vchr_io)
		(void) nsc_unregister_io(_nsc_vchr_io, 0);

	if (_nsc_file_io)
		(void) nsc_unregister_io(_nsc_file_io, 0);

	_nsc_vchr_io = NULL;
	_nsc_file_io = NULL;

	if (_nsc_raw_io)
		(void) nsc_unregister_io(_nsc_raw_io, 0);

	_nsc_raw_io = NULL;

	_nsc_deinit_dev();
	_nsc_deinit_os();

	_nsc_init_done = 0;
	return (0);
}


/* ARGSUSED */

int
nscopen(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	kmutex_t *slp;
	int i, error;

	if (error = drv_priv(crp))
		return (error);

	if (!_nsc_minor_fd || !_nsc_minor_slp)
		return (ENXIO);

	if (getminor(*devp) != 0)
		return (ENXIO);

	slp = nsc_kmem_alloc(sizeof (kmutex_t), 0, _nsc_local_mem);
	mutex_init(slp, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&_nsc_drv_lock);

	for (i = 1; i < _nsc_maxdev; i++) {
		if (_nsc_minor_slp[i] == NULL) {
			_nsc_minor_slp[i] = slp;
			break;
		}
	}

	mutex_exit(&_nsc_drv_lock);

	if (i >= _nsc_maxdev) {
		mutex_destroy(slp);
		nsc_kmem_free(slp, sizeof (kmutex_t));
		return (EAGAIN);
	}

	*devp = makedevice(getmajor(*devp), i);

	return (0);
}


int
_nscopen(dev_t dev, intptr_t arg, int mode, int *rvp)
{
	minor_t mindev = getminor(dev);
	struct nscioc_open *op;
	nsc_fd_t *fd;
	int rc;

	op = nsc_kmem_alloc(sizeof (*op), KM_SLEEP, _nsc_local_mem);
	if (op == NULL) {
		return (ENOMEM);
	}

	if (ddi_copyin((void *)arg, op, sizeof (*op), mode) < 0) {
		nsc_kmem_free(op, sizeof (*op));
		return (EFAULT);
	}

	mutex_enter(_nsc_minor_slp[mindev]);

	if (_nsc_minor_fd[mindev]) {
		mutex_exit(_nsc_minor_slp[mindev]);
		nsc_kmem_free(op, sizeof (*op));
		return (EBUSY);
	}

	op->path[sizeof (op->path)-1] = 0;

	fd = nsc_open(op->path, (op->flag & NSC_TYPES), 0, 0, &rc);

	if (fd == NULL) {
		mutex_exit(_nsc_minor_slp[mindev]);
		nsc_kmem_free(op, sizeof (*op));
		return (rc);
	}

	mode |= (op->mode - FOPEN);

	if (mode & (FWRITE|FEXCL)) {
		if ((rc = nsc_reserve(fd, NSC_PCATCH)) != 0) {
			mutex_exit(_nsc_minor_slp[mindev]);
			(void) nsc_close(fd);
			nsc_kmem_free(op, sizeof (*op));
			return (rc);
		}
	}

	*rvp = 0;
	_nsc_minor_fd[mindev] = fd;

	mutex_exit(_nsc_minor_slp[mindev]);
	nsc_kmem_free(op, sizeof (*op));
	return (0);
}


/* ARGSUSED */

int
nscclose(dev_t dev, int flag, int otyp, cred_t *crp)
{
	minor_t mindev = getminor(dev);
	kmutex_t *slp;
	nsc_fd_t *fd;

	if (!_nsc_minor_fd || !_nsc_minor_slp)
		return (0);

	if ((slp = _nsc_minor_slp[mindev]) == 0)
		return (0);

	if ((fd = _nsc_minor_fd[mindev]) != NULL)
		(void) nsc_close(fd);

	_nsc_minor_fd[mindev] = NULL;
	_nsc_minor_slp[mindev] = NULL;

	mutex_destroy(slp);
	nsc_kmem_free(slp, sizeof (kmutex_t));
	return (0);
}


/* ARGSUSED */

int
nscread(dev_t dev, uio_t *uiop, cred_t *crp)
{
	minor_t mindev = getminor(dev);
	int rc, resv;
	nsc_fd_t *fd;

	if ((fd = _nsc_minor_fd[mindev]) == 0)
		return (EIO);

	mutex_enter(_nsc_minor_slp[mindev]);

	resv = (nsc_held(fd) == 0);

	if (resv && (rc = nsc_reserve(fd, NSC_PCATCH)) != 0) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (rc);
	}

	rc = nsc_uread(fd, uiop, crp);

	if (resv)
		nsc_release(fd);

	mutex_exit(_nsc_minor_slp[mindev]);
	return (rc);
}


/* ARGSUSED */

int
nscwrite(dev_t dev, uio_t *uiop, cred_t *crp)
{
	minor_t mindev = getminor(dev);
	int rc, resv;
	nsc_fd_t *fd;

	if ((fd = _nsc_minor_fd[mindev]) == 0)
		return (EIO);

	mutex_enter(_nsc_minor_slp[mindev]);

	resv = (nsc_held(fd) == 0);

	if (resv && (rc = nsc_reserve(fd, NSC_PCATCH)) != 0) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (rc);
	}

	rc = nsc_uwrite(fd, uiop, crp);

	if (resv)
		nsc_release(fd);

	mutex_exit(_nsc_minor_slp[mindev]);
	return (rc);
}


int
_nscreserve(dev_t dev, int *rvp)
{
	minor_t mindev = getminor(dev);
	nsc_fd_t *fd;
	int rc;

	if ((fd = _nsc_minor_fd[mindev]) == 0)
		return (EIO);

	mutex_enter(_nsc_minor_slp[mindev]);

	if (nsc_held(fd)) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (EBUSY);
	}

	if ((rc = nsc_reserve(fd, NSC_PCATCH)) != 0) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (rc);
	}

	*rvp = 0;

	mutex_exit(_nsc_minor_slp[mindev]);
	return (0);
}


int
_nscrelease(dev_t dev, int *rvp)
{
	minor_t mindev = getminor(dev);
	nsc_fd_t *fd;

	if ((fd = _nsc_minor_fd[mindev]) == 0)
		return (EIO);

	mutex_enter(_nsc_minor_slp[mindev]);

	if (!nsc_held(fd)) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (EINVAL);
	}

	nsc_release(fd);

	*rvp = 0;

	mutex_exit(_nsc_minor_slp[mindev]);
	return (0);
}


int
_nscpartsize(dev_t dev, intptr_t arg, int mode)
{
	struct nscioc_partsize partsize;
	minor_t mindev = getminor(dev);
	nsc_size_t size;
	int rc, resv;
	nsc_fd_t *fd;

	if ((fd = _nsc_minor_fd[mindev]) == 0)
		return (EIO);

	mutex_enter(_nsc_minor_slp[mindev]);

	resv = (nsc_held(fd) == 0);

	if (resv && (rc = nsc_reserve(fd, NSC_PCATCH)) != 0) {
		mutex_exit(_nsc_minor_slp[mindev]);
		return (rc);
	}

	rc = nsc_partsize(fd, &size);
	partsize.partsize = (uint64_t)size;

	if (resv)
		nsc_release(fd);

	mutex_exit(_nsc_minor_slp[mindev]);

	if (ddi_copyout((void *)&partsize, (void *)arg,
	    sizeof (partsize), mode) < 0) {
		return (EFAULT);
	}

	return (rc);
}


/* ARGSUSED */

int
nscioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp, int *rvp)
{
	struct nscioc_bsize *bsize = NULL;
	char *path = NULL;
	int rc = 0;

	*rvp = 0;

	switch (cmd) {
	case NSCIOC_OPEN:
		rc = _nscopen(dev, arg, mode, rvp);
		break;

	case NSCIOC_RESERVE:
		rc = _nscreserve(dev, rvp);
		break;

	case NSCIOC_RELEASE:
		rc = _nscrelease(dev, rvp);
		break;

	case NSCIOC_PARTSIZE:
		rc = _nscpartsize(dev, arg, mode);
		break;

	case NSCIOC_FREEZE:
		path = nsc_kmem_alloc(NSC_MAXPATH, KM_SLEEP, _nsc_local_mem);
		if (path == NULL) {
			rc = ENOMEM;
			break;
		}
		if (ddi_copyin((void *)arg, path, NSC_MAXPATH, mode) < 0)
			rc = EFAULT;
		else {
			path[NSC_MAXPATH-1] = 0;
			rc = _nsc_frz_start(path, rvp);
		}
		break;

	case NSCIOC_UNFREEZE:
		path = nsc_kmem_alloc(NSC_MAXPATH, KM_SLEEP, _nsc_local_mem);
		if (path == NULL) {
			rc = ENOMEM;
			break;
		}
		if (ddi_copyin((void *)arg, path, NSC_MAXPATH, mode) < 0)
			rc = EFAULT;
		else {
			path[NSC_MAXPATH-1] = 0;
			rc = _nsc_frz_stop(path, rvp);
		}
		break;

	case NSCIOC_ISFROZEN:
		path = nsc_kmem_alloc(NSC_MAXPATH, KM_SLEEP, _nsc_local_mem);
		if (path == NULL) {
			rc = ENOMEM;
			break;
		}
		if (ddi_copyin((void *)arg, path, NSC_MAXPATH, mode) < 0)
			rc = EFAULT;
		else {
			path[NSC_MAXPATH-1] = 0;
			rc = _nsc_frz_isfrozen(path, rvp);
		}
		break;

#ifdef ENABLE_POWER_MSG
	case NSCIOC_POWERMSG:
		rc = _nsc_power((void *)arg, rvp);
		break;
#endif

	case NSCIOC_NSKERND:
		rc = nskernd_command(arg, mode, rvp);
		break;

	/* return sizes of global memory segments */
	case NSCIOC_GLOBAL_SIZES:
		if (!_nsc_init_done) {
			rc = EINVAL;
			break;
		}

		rc = _nsc_get_global_sizes((void *)arg, rvp);

		break;

	/* return contents of global segments */
	case NSCIOC_GLOBAL_DATA:
		if (!_nsc_init_done) {
			rc = EINVAL;
			break;
		}

		rc = _nsc_get_global_data((void *)arg, rvp);
		break;

	/*
	 * nvmem systems:
	 * clear the hdr dirty bit to prevent loading from nvme on reboot
	 */
	case NSCIOC_NVMEM_CLEANF:
		rc = _nsc_clear_dirty(1);	/* dont be nice about it */
		break;
	case NSCIOC_NVMEM_CLEAN:
		rc = _nsc_clear_dirty(0);
		break;

	case NSCIOC_BSIZE:
		bsize = nsc_kmem_alloc(sizeof (*bsize), KM_SLEEP,
		    _nsc_local_mem);
		if (bsize == NULL) {
			rc = ENOMEM;
			break;
		}

		if (ddi_copyin((void *)arg, bsize, sizeof (*bsize), mode) < 0) {
			rc = EFAULT;
			break;
		}

		rc = nskern_bsize(bsize, rvp);
		if (rc == 0) {
			if (ddi_copyout(bsize, (void *)arg,
			    sizeof (*bsize), mode) < 0) {
				rc = EFAULT;
				break;
			}
		}

		break;

	default:
		return (ENOTTY);
	}

	if (bsize != NULL) {
		nsc_kmem_free(bsize, sizeof (*bsize));
		bsize = NULL;
	}
	if (path != NULL) {
		nsc_kmem_free(path, NSC_MAXPATH);
		path = NULL;
	}
	return (rc);
}


int
nsc_max_devices(void)
{
	return (_nsc_max_devices);
}


/*
 * Used by _nsc_global_setup() in case nvram is dirty and has saved a different
 * value for nsc_max_devices. We need to use the saved value, not the new
 * one configured by the user.
 */
void
_nsc_set_max_devices(int maxdev)
{
	_nsc_max_devices = maxdev;
	_nsc_maxdev = _nsc_max_devices;
}

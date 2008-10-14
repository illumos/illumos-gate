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
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/ddi.h>

#include <sys/ncall/ncall.h>

#define	__NSC_GEN__
#include "nsc_dev.h"

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include "../nsctl.h"

#define	NSC_DEVMIN	"DevMin"
#define	NSC_DEVMAJ	"DevMaj"

#define	_I(x)	(((long)(&((nsc_io_t *)0)->x))/sizeof (long))
#define	_F(x)	(((long)(&((nsc_fd_t *)0)->x))/sizeof (long))


nsc_def_t _nsc_io_def[] = {
	"Open",		(uintptr_t)nsc_null,	_I(open),
	"Close",	(uintptr_t)nsc_null,	_I(close),
	"Attach",	(uintptr_t)nsc_null,	_I(attach),
	"Detach",	(uintptr_t)nsc_null,	_I(detach),
	"Flush",	(uintptr_t)nsc_null,	_I(flush),
	"Provide",	0,		_I(provide),
	0,		0,		0
};

nsc_def_t _nsc_fd_def[] = {
	"Pinned",	(uintptr_t)nsc_null,	_F(sf_pinned),
	"Unpinned",	(uintptr_t)nsc_null,	_F(sf_unpinned),
	"Attach",	(uintptr_t)nsc_null,	_F(sf_attach),
	"Detach",	(uintptr_t)nsc_null,	_F(sf_detach),
	"Flush",	(uintptr_t)nsc_null,	_F(sf_flush),
	0,		0,		0
};

kmutex_t _nsc_io_lock;
kmutex_t _nsc_devval_lock;

nsc_io_t *_nsc_io_top = NULL;
nsc_io_t *_nsc_null_io = NULL;
nsc_dev_t *_nsc_dev_top = NULL;
nsc_dev_t *_nsc_dev_pend = NULL;
nsc_path_t *_nsc_path_top = NULL;
nsc_devval_t *_nsc_devval_top = NULL;

extern nsc_def_t _nsc_disk_def[];
extern nsc_def_t _nsc_cache_def[];

extern nsc_mem_t *_nsc_local_mem;
extern nsc_rmmap_t *_nsc_global_map;

static clock_t _nsc_io_lbolt;

static nsc_io_t *_nsc_find_io(char *, int, int *);
nsc_io_t *_nsc_reserve_io(char *, int);
static nsc_io_t *_nsc_alloc_io(int, char *, int);

static int _nsc_open_fn(nsc_fd_t *, int);
static int _nsc_close_fn(nsc_fd_t *);
static int _nsc_alloc_fd(char *, int, int, nsc_fd_t **);
static int _nsc_alloc_iodev(nsc_dev_t *, int, nsc_iodev_t **);
static int _nsc_alloc_dev(char *, nsc_dev_t **);
static int _nsc_reopen_io(char *, int);
static int _nsc_reopen_dev(nsc_dev_t *, int);
static int _nsc_relock_dev(nsc_dev_t *, nsc_fd_t *, nsc_iodev_t *);
static int _nsc_reopen_fd(nsc_fd_t *, int);
static int _nsc_decode_io(nsc_def_t *, nsc_io_t *);

void _nsc_release_io(nsc_io_t *);
static void _nsc_free_fd(nsc_fd_t *);
static void _nsc_free_iodev(nsc_iodev_t *);
static void _nsc_free_dev(nsc_dev_t *);
static void _nsc_free_io(nsc_io_t *);
static void _nsc_relink_fd(nsc_fd_t *, nsc_fd_t **, nsc_fd_t **, nsc_iodev_t *);

static int _nsc_setval(nsc_dev_t *, char *, char *, int, int);
static void r_nsc_setval(ncall_t *, int *);
static void r_nsc_setval_all(ncall_t *, int *);

extern void _nsc_add_disk(nsc_io_t *);
extern void _nsc_add_cache(nsc_io_t *);


/*
 * void
 * _nsc_init_dev (void)
 *	Initialise device subsystem.
 *
 * Calling/Exit State:
 *	Called at driver initialisation time to allocate necessary
 *	data structures.
 */
void
_nsc_init_dev()
{
	mutex_init(&_nsc_io_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_nsc_devval_lock, NULL, MUTEX_DRIVER, NULL);

	_nsc_null_io = nsc_register_io("null", NSC_NULL, (nsc_def_t *)0);

	if (!_nsc_null_io)
		cmn_err(CE_PANIC, "nsctl: nsc_init_dev");

	ncall_register_svc(NSC_SETVAL_ALL, r_nsc_setval_all);
	ncall_register_svc(NSC_SETVAL, r_nsc_setval);
}


void
_nsc_deinit_dev()
{
	nsc_devval_t *dv;
	nsc_val_t *vp;

	mutex_enter(&_nsc_devval_lock);

	while ((dv = _nsc_devval_top) != NULL) {
		while ((vp = dv->dv_values) != NULL) {
			dv->dv_values = vp->sv_next;
			nsc_kmem_free(vp, sizeof (*vp));
		}

		_nsc_devval_top = dv->dv_next;
		nsc_kmem_free(dv, sizeof (*dv));
	}

	mutex_exit(&_nsc_devval_lock);

	ncall_unregister_svc(NSC_SETVAL_ALL);
	ncall_unregister_svc(NSC_SETVAL);

	mutex_destroy(&_nsc_devval_lock);
	mutex_destroy(&_nsc_io_lock);
}


/*
 * nsc_io_t *
 * nsc_register_io (char *name, int type, nsc_def_t *def)
 *	Register an I/O module.
 *
 * Calling/Exit State:
 *	Returns a token for use in future calls to nsc_unregister_io.
 *	The ID and flags for the module are specified by 'type' and
 *	the appropriate entry points are defined using 'def'. If
 *	registration fails NULL is returned.
 *
 * Description:
 *	Registers an I/O module for use by subsequent calls to
 *	nsc_open.
 */
nsc_io_t *
nsc_register_io(name, type, def)
char *name;
int type;
nsc_def_t *def;
{
	nsc_io_t *io, *tp;
	int rc, id, flag;
	nsc_io_t **iop;

	id = (type & NSC_TYPES);
	flag = (type & ~NSC_TYPES);

	if ((!(id & NSC_ID) || (id & ~NSC_IDS)) &&
			(id != NSC_NULL || _nsc_null_io))
		return (NULL);

	if (!(io = _nsc_alloc_io(id, name, flag)))
		return (NULL);

	rc = _nsc_decode_io(def, io);

	if (!rc && id != NSC_NULL) {
		_nsc_free_io(io);
		return (NULL);
	}

	mutex_enter(&_nsc_io_lock);

	for (tp = _nsc_io_top; tp; tp = tp->next) {
		if (strcmp(tp->name, name) == 0 || tp->id == id) {
			mutex_exit(&_nsc_io_lock);
			_nsc_free_io(io);
			return (NULL);
		}
	}

	for (iop = &_nsc_io_top; *iop; iop = &(*iop)->next)
		if (id >= (*iop)->id)
			break;

	io->next = (*iop);
	(*iop) = io;

	_nsc_io_lbolt = nsc_lbolt();

	while ((rc = _nsc_reopen_io(NULL, 0)) != 0)
		if (rc != ERESTART)
			break;

	mutex_exit(&_nsc_io_lock);
	return (io);
}


/*
 * static int
 * _nsc_decode_io (nsc_def_t *def, nsc_io_t *io)
 *	Decode I/O module definition.
 *
 * Calling/Exit State:
 *	Returns TRUE if the definition contains an adequate
 *	description of an I/O module.
 *
 * Description:
 *	Decode the definition of an I/O module and supply
 *	translation routines where possible for operations
 *	that are not defined.
 */
static int
_nsc_decode_io(def, io)
nsc_def_t *def;
nsc_io_t *io;
{
	nsc_decode_param(def, _nsc_io_def, (long *)io);
	nsc_decode_param(def, _nsc_disk_def, (long *)io);
	nsc_decode_param(def, _nsc_cache_def, (long *)io);

	_nsc_add_disk(io);
	_nsc_add_cache(io);

	return (1);
}


/*
 * int
 * nsc_unregister_io (nsc_io_t *io, int flag)
 *	Un-register an I/O module.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise returns an error code.
 *
 * Description:
 *	The specified I/O module is un-registered if possible.
 *	All open file descriptors using the module will be closed
 *	in preparation for a subsequent re-open.
 *
 *	If NSC_PCATCH is specified and a signal is received,
 *	the unregister will be terminated and EINTR returned.
 */
int
nsc_unregister_io(nsc_io_t *io, int flag)
{
	nsc_path_t *sp;
	nsc_io_t *xio;
	int rc = 0;

	if (io == _nsc_null_io)
		return (EINVAL);

	mutex_enter(&_nsc_io_lock);

	for (xio = _nsc_io_top; xio; xio = xio->next)
		if (xio == io)
			break;

	if (!xio || io->pend) {
		mutex_exit(&_nsc_io_lock);
		return (xio ? EALREADY : 0);
	}

	io->pend = 1;
lp:
	for (sp = _nsc_path_top; sp; sp = sp->sp_next)
		if (sp->sp_io == io) {
			mutex_exit(&_nsc_io_lock);

			if ((rc = nsc_unregister_path(sp, flag)) != 0) {
				io->pend = 0;
				return (rc);
			}

			mutex_enter(&_nsc_io_lock);
			goto lp;
		}

	_nsc_io_lbolt = nsc_lbolt();

	while (io->refcnt && !rc) {
		while ((rc = _nsc_reopen_io(NULL, flag)) != 0)
			if (rc != ERESTART)
				break;

		if (rc || !io->refcnt)
			break;

		if (!cv_wait_sig(&io->cv, &_nsc_io_lock))
			rc = EINTR;
	}

	/*
	 * We have tried to get rid of all the IO provider's clients.
	 * If there are still anonymous buffers outstanding, then fail
	 * the unregister.
	 */

	if (!rc && io->abufcnt > 0)
		rc = EUSERS;

	if (rc)
		io->pend = 0;

	mutex_exit(&_nsc_io_lock);

	if (!rc)
		_nsc_free_io(io);

	return (rc);
}


/*
 * nsc_path_t *
 * nsc_register_path (char *path, int type, nsc_io_t *io)
 *	Register interest in pathname.
 *
 * Calling/Exit State:
 *	Returns a token for use in future calls to
 *	nsc_unregister_path. The 'path' argument can contain
 *	wild characters. If registration fails NULL is returned.
 *	May not be called for io providers that support NSC_ANON.
 *
 * Description:
 *	Registers an interest in any pathnames matching 'path'
 *	which are opened with the specified type.
 */
nsc_path_t *
nsc_register_path(char *path, int type, nsc_io_t *io)
{
	nsc_path_t *sp, **spp;
	int rc;

	if ((type & NSC_IDS) || !io || (io->provide & NSC_ANON) ||
	    !(sp = nsc_kmem_zalloc(sizeof (*sp), KM_SLEEP, _nsc_local_mem)))
		return (NULL);

	sp->sp_path = nsc_strdup(path);
	sp->sp_type = type;
	sp->sp_io = io;

	mutex_enter(&_nsc_io_lock);

	for (spp = &_nsc_path_top; *spp; spp = &(*spp)->sp_next)
		if (io->id >= (*spp)->sp_io->id)
			break;

	sp->sp_next = (*spp);
	(*spp) = sp;

	_nsc_io_lbolt = nsc_lbolt();

	while ((rc = _nsc_reopen_io(path, 0)) != 0)
		if (rc != ERESTART)
			break;

	mutex_exit(&_nsc_io_lock);
	return (sp);
}


/*
 * int
 * nsc_unregister_path (nsc_path_t *sp, int flag)
 *	Un-register interest in pathname.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise returns an error code.
 *
 * Description:
 *	Interest in the specified pathname is un-registered
 *	if possible. All appropriate file descriptors will be
 *	closed in preparation for a subsequent re-open.
 *
 *	If NSC_PCATCH is specified and a signal is received,
 *	the unregister will be terminated and EINTR returned.
 */
int
nsc_unregister_path(sp, flag)
nsc_path_t *sp;
int flag;
{
	nsc_path_t *xsp, **spp;
	int rc;

	mutex_enter(&_nsc_io_lock);

	for (xsp = _nsc_path_top; xsp; xsp = xsp->sp_next)
		if (xsp == sp)
			break;

	if (!xsp || sp->sp_pend) {
		mutex_exit(&_nsc_io_lock);
		return (xsp ? EALREADY : 0);
	}

	sp->sp_pend = 1;
	_nsc_io_lbolt = nsc_lbolt();

	while ((rc = _nsc_reopen_io(sp->sp_path, flag)) != 0)
		if (rc != ERESTART) {
			sp->sp_pend = 0;
			mutex_exit(&_nsc_io_lock);
			return (rc);
		}

	for (spp = &_nsc_path_top; *spp; spp = &(*spp)->sp_next)
		if (*spp == sp)
			break;

	if (*spp)
		(*spp) = sp->sp_next;

	mutex_exit(&_nsc_io_lock);

	nsc_strfree(sp->sp_path);
	nsc_kmem_free(sp, sizeof (*sp));
	return (0);
}


/*
 * static int
 * _nsc_reopen_io (char *path, int flag)
 *	Force re-open of all file descriptors.
 *
 * Calling/Exit State:
 *	The _nsc_io_lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the force succeeds without releasing
 *	_nsc_io_lock, otherwise returns an error code.
 *
 * Description:
 *	A re-open is forced for all file descriptors as
 *	appropriate. For performance reasons available
 *	devices are re-opened before those that would block.
 */
static int
_nsc_reopen_io(path, flag)
char *path;
int flag;
{
	nsc_dev_t *dp, *dev;
	int rc, errno = 0;
	int try, run;

	for (run = 1, try = (NSC_TRY | NSC_DEFER); run--; try = 0) {
		for (dev = _nsc_dev_top; dev; dev = dev->nsc_next) {
			if (path && !nsc_strmatch(dev->nsc_path, path))
				continue;

			if (!(rc = _nsc_reopen_dev(dev, flag | try)))
				continue;

			for (dp = _nsc_dev_top; dp; dp = dp->nsc_next)
				if (dp == dev)
					break;

			if (!dp)
				return (ERESTART);

			if (try && !(flag & NSC_TRY))
				run = 1;
			if (!run && errno != ERESTART)
				errno = rc;
		}
	}

	return (errno);
}


/*
 * static int
 * _nsc_reopen_dev (nsc_dev_t *dev, int flag)
 *	Force re-open of entire device.
 *
 * Calling/Exit State:
 *	The _nsc_io_lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the force succeeds without releasing
 *	_nsc_io_lock, otherwise returns an error code.
 *
 * Description:
 *	A re-open is forced for all file descriptors for the
 *	device as appropriate.
 */
static int
_nsc_reopen_dev(dev, flag)
nsc_dev_t *dev;
int flag;
{
	int rc, errno = 0;
	nsc_iodev_t *iodev;
	int try, run;
	nsc_fd_t *fd;

	mutex_enter(&dev->nsc_lock);

	for (run = 1, try = (NSC_TRY | NSC_DEFER); run--; try = 0)
		for (iodev = dev->nsc_list; iodev; iodev = iodev->si_next) {
			for (fd = iodev->si_open; fd; fd = fd->sf_next) {
				if (!(rc = _nsc_reopen_fd(fd, flag | try)))
					continue;

				if (rc == -ERESTART)
					return (ERESTART);

				if (!_nsc_relock_dev(dev, fd, iodev))
					return (ERESTART);

				if (try && !(flag & NSC_TRY))
					run = 1;
				if (!run && errno != ERESTART)
					errno = rc;
			}
		}

	for (run = 1, try = (NSC_TRY | NSC_DEFER); run--; try = 0)
		for (fd = dev->nsc_close; fd; fd = fd->sf_next) {
			if (!(rc = _nsc_reopen_fd(fd, flag | try)))
				continue;

			if (rc == -ERESTART)
				return (ERESTART);

			if (!_nsc_relock_dev(dev, fd, NULL))
				return (ERESTART);

			if (try && !(flag & NSC_TRY))
				run = 1;
			if (!run && errno != ERESTART)
				errno = rc;
		}

	mutex_exit(&dev->nsc_lock);
	return (errno);
}


/*
 * static int
 * _nsc_relock_dev (nsc_dev_t *dev, nsc_fd_t *fd, nsc_iodev_t *iodev)
 *	Relock device structure if possible.
 *
 * Calling/Exit State:
 *	The _nsc_io_lock must be held across calls to
 *	this function.
 *
 *	Checks whether the file descriptor is still part
 *	of the specified device and I/O device. If so the
 *	device lock is taken. Otherwise FALSE is returned.
 */
static int
_nsc_relock_dev(nsc_dev_t *dev, nsc_fd_t *fd, nsc_iodev_t *iodev)
{
	nsc_fd_t *fp = NULL;
	nsc_iodev_t *iop;
	nsc_dev_t *dp;

	for (dp = _nsc_dev_top; dp; dp = dp->nsc_next)
		if (dp == dev)
			break;

	if (!dp)
		return (0);

	mutex_enter(&dev->nsc_lock);

	if (iodev)
		for (iop = dev->nsc_list; iop; iop = iop->si_next)
			if (iop == iodev)
				break;

	if (!iodev || iop) {
		fp = (iodev) ? iodev->si_open : dev->nsc_close;

		for (; fp; fp = fp->sf_next)
			if (fp == fd)
				break;
	}

	if (!fp) {
		mutex_exit(&dev->nsc_lock);
		return (0);
	}

	return (1);
}


/*
 * static int
 * _nsc_reopen_fd (nsc_fd_t *dev, int flag)
 *	Force re-open of file descriptor.
 *
 * Calling/Exit State:
 *	Both _nsc_io_lock and the device lock must be held
 *	across calls to this function.
 *
 *	Returns 0 if the force succeeds without releasing
 *	any locks, otherwise returns an error code. If an
 *	error code is returned the device lock is released.
 *
 * Description:
 *	If appropriate the file descriptor is closed in order
 *	to force a subsequent open using the currently available
 *	resources.
 */
static int
_nsc_reopen_fd(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	nsc_iodev_t *iodev = fd->sf_iodev;
	int changed = 0;
	int rc;

	if (!fd->sf_pend && !iodev)
		return (0);

	if (fd->sf_pend == _NSC_OPEN)
		if (fd->sf_lbolt - _nsc_io_lbolt > 0)
			return (0);

	if (iodev &&
	    (iodev->si_io ==
		_nsc_find_io(dev->nsc_path, fd->sf_type, &changed)) &&
	    !changed)
		return (0);

	if (iodev)
		fd->sf_reopen = 1;

	mutex_exit(&_nsc_io_lock);

	dev->nsc_reopen = 1;

	rc = _nsc_close_fd(fd, flag);

	dev->nsc_reopen = 0;

	if (rc == EAGAIN && (flag & NSC_DEFER) && fd->sf_reopen)
		dev->nsc_drop = 1;

	mutex_exit(&dev->nsc_lock);

	if (rc == -ERESTART)
		delay(2);	/* allow other threads cpu time */

	mutex_enter(&_nsc_io_lock);
	return (rc ? rc : ERESTART);
}


/*
 * nsc_fd_t *
 * nsc_open (char *path, int type, nsc_def_t *def, blind_t arg, int *sts)
 *	Open file descriptor for pathname.
 *
 * Calling/Exit State:
 *	Returns file descriptor if open succeeds, otherwise
 *	returns 0 and puts error code in the location pointed
 *	to by sts.
 *
 * Description:
 *	Open the specified pathname using an appropriate access
 *	method.
 */
nsc_fd_t *
nsc_open(path, type, def, arg, sts)
char *path;
int type;
nsc_def_t *def;
blind_t arg;
int *sts;
{
	int flag, rc;
	nsc_fd_t *fd;

	flag = (type & ~NSC_TYPES);
	type &= NSC_TYPES;

	if ((flag & NSC_READ) == 0)
		flag |= NSC_RDWR;

	if ((rc = _nsc_alloc_fd(path, type, flag, &fd)) != 0) {
		if (sts)
			*sts = rc;
		return (NULL);
	}

	fd->sf_arg = arg;
	fd->sf_aio = _nsc_null_io;

	nsc_decode_param(def, _nsc_fd_def, (long *)fd);

	mutex_enter(&fd->sf_dev->nsc_lock);

	while ((rc = _nsc_open_fd(fd, flag)) != 0)
		if (rc != ERESTART)
			break;

	mutex_exit(&fd->sf_dev->nsc_lock);

	if (rc) {
		_nsc_free_fd(fd);
		if (sts)
			*sts = rc;
		return (NULL);
	}

	return (fd);
}


/*
 * int
 * _nsc_open_fd (nsc_fd_t *fd, int flag)
 *	Open file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the open succeeds, otherwise
 *	returns an error code.
 *
 * Description:
 *	Open the specified file descriptor.
 */
int
_nsc_open_fd(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	int rc;

	if (fd->sf_pend)
		return (_nsc_wait_dev(dev, flag));

	if (fd->sf_iodev)
		return (0);
	if (flag & NSC_NOBLOCK)
		return (EAGAIN);

	fd->sf_pend = _NSC_OPEN;
	fd->sf_lbolt = nsc_lbolt();

	mutex_exit(&dev->nsc_lock);

	rc = _nsc_open_fn(fd, flag);

	mutex_enter(&dev->nsc_lock);
	fd->sf_pend = 0;

	if (!rc)
		fd->sf_iodev->si_pend = 0;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	return (rc ? rc : ERESTART);
}


/*
 * static int
 * _nsc_open_fn (nsc_fd_t *fd, int flag)
 *	Allocate I/O device and open file descriptor.
 *
 * Calling/Exit State:
 *	No locks may be held across this function.
 *
 *	If the open succeeds an I/O device will be
 *	attached to the file descriptor, marked as
 *	pending and 0 returned. Otherwise, returns
 *	an error code.
 *
 * Description:
 *	Allocate an I/O device and open the specified
 *	file descriptor.
 */
static int
_nsc_open_fn(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	nsc_iodev_t *iodev;
	int rc;

	if ((rc = _nsc_alloc_iodev(dev, fd->sf_type, &iodev)) != 0)
		return (rc);

	mutex_enter(&dev->nsc_lock);

	if (iodev->si_pend) {
		rc = _nsc_wait_dev(dev, flag);
		mutex_exit(&dev->nsc_lock);
		_nsc_free_iodev(iodev);
		return (rc);
	}

	iodev->si_pend = _NSC_OPEN;
	mutex_exit(&dev->nsc_lock);

	rc = (*iodev->si_io->open)(dev->nsc_path,
			(fd->sf_flag & ~NSC_RDWR), &fd->sf_cd, iodev);

	if (rc) {
		iodev->si_pend = 0;
		_nsc_free_iodev(iodev);
		return (rc);
	}

	/* save away the DevMaj and DevMin values */
	if (iodev->si_io->id == NSC_RAW_ID) {
		rc = _nsc_setval(dev, NULL, NSC_DEVMAJ,
		    (int)getmajor((dev_t)fd->sf_cd), FALSE);
#ifdef DEBUG
		if (rc != 1) {
			cmn_err(CE_NOTE, "nsctl: could not set DevMaj (%s:%x)",
			    dev->nsc_path, (int)getmajor((dev_t)fd->sf_cd));
		}
#endif

		rc = _nsc_setval(dev, NULL, NSC_DEVMIN,
		    (int)getminor((dev_t)fd->sf_cd), FALSE);
#ifdef DEBUG
		if (rc != 1) {
			cmn_err(CE_NOTE, "nsctl: could not set DevMin (%s:%x)",
			    dev->nsc_path, (int)getminor((dev_t)fd->sf_cd));
		}
#endif
	}

	fd->sf_iodev = iodev;
	_nsc_relink_fd(fd, &dev->nsc_close, &iodev->si_open, iodev);

	return (0);
}


/*
 * int
 * nsc_close (nsc_fd_t *fd)
 *	Close file descriptor for pathname.
 *
 * Calling/Exit State:
 *	Returns 0 if close succeeds, otherwise returns error
 *	code.
 *
 * Description:
 *	Close the specified file descriptor. It is assumed
 *	that all other users of this file descriptor have
 *	finished. Any reserve will be discarded before the
 *	close is performed.
 */
int
nsc_close(fd)
nsc_fd_t *fd;
{
	int rc;

	if (!fd)
		return (0);

	while (fd->sf_reserve)
		nsc_release(fd);

	mutex_enter(&fd->sf_dev->nsc_lock);

	fd->sf_owner = NULL;

	while ((rc = _nsc_close_fd(fd, 0)) != 0)
		if (rc != ERESTART)
			break;

	nsc_decode_param(_nsc_fd_def, _nsc_fd_def, (long *)fd);

	mutex_exit(&fd->sf_dev->nsc_lock);

	if (!rc)
		_nsc_free_fd(fd);
	return (rc);
}


/*
 * int
 * _nsc_close_fd (nsc_fd_t *fd, int flag)
 *	Close file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the close succeeds, otherwise
 *	returns an error code.
 *
 * Description:
 *	Close the specified file descriptor.
 */
int
_nsc_close_fd(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	nsc_iodev_t *iodev;
	int rc;

	if (fd->sf_pend) {
		if (fd->sf_pend == _NSC_CLOSE && dev->nsc_reopen != 0)
			return (-ERESTART);

		return (_nsc_wait_dev(dev, flag));
	}

	flag |= NSC_RDWR;
	iodev = fd->sf_iodev;

	if (!iodev)
		return (0);

	if ((rc = _nsc_detach_fd(fd, flag)) != 0)
		return (rc);

	if (iodev->si_pend)
		return (_nsc_wait_dev(dev, flag));

	if (iodev->si_open == fd && !fd->sf_next) {
		if ((rc = _nsc_detach_iodev(iodev, NULL, flag)) != 0)
			return (rc);

		if (dev->nsc_list == iodev && !iodev->si_next)
			if ((rc = _nsc_detach_dev(dev, NULL, flag)) != 0)
				return (rc);
	}

	if (flag & NSC_NOBLOCK)
		return (EAGAIN);

	fd->sf_pend = _NSC_CLOSE;
	iodev->si_pend = _NSC_CLOSE;
	mutex_exit(&dev->nsc_lock);

	rc = _nsc_close_fn(fd);

	mutex_enter(&dev->nsc_lock);
	fd->sf_pend = 0;

	fd->sf_reopen = 0;
	if (rc)
		iodev->si_pend = 0;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	return (rc ? rc : ERESTART);
}


/*
 * static int
 * _nsc_close_fn (nsc_fd_t *fd)
 *	Close file descriptor and free I/O device.
 *
 * Calling/Exit State:
 *	No locks may be held across this function.
 *
 *	Returns 0 if the close succeeds, otherwise
 *	returns an error code.
 *
 *	If the close succeeds the I/O device will be
 *	detached from the file descriptor, released
 *	and 0 returned. Otherwise, returns an error
 *	code.
 *
 * Description:
 *	Close the specified file descriptor and free
 *	the I/O device.
 */
static int
_nsc_close_fn(fd)
nsc_fd_t *fd;
{
	nsc_iodev_t *iodev = fd->sf_iodev;
	nsc_dev_t *dev = fd->sf_dev;
	int last, rc;

	last = (iodev->si_open == fd && !fd->sf_next);

	if (last || (iodev->si_io->flag & NSC_REFCNT))
		if ((rc = (*iodev->si_io->close)(fd->sf_cd)) != 0)
			return (rc);

	fd->sf_iodev = NULL;
	_nsc_relink_fd(fd, &iodev->si_open, &dev->nsc_close, iodev);

	iodev->si_pend = 0;
	_nsc_free_iodev(iodev);

	return (0);
}


/*
 * void
 * nsc_set_owner (nsc_fd_t *fd, nsc_iodev_t *iodev)
 *	Set owner associated with file descriptor.
 *
 * Calling/Exit State:
 *	Sets the owner field in the file descriptor.
 */
void
nsc_set_owner(nsc_fd_t *fd, nsc_iodev_t *iodev)
{
	if (fd) {
		mutex_enter(&fd->sf_dev->nsc_lock);
		fd->sf_owner = iodev;
		mutex_exit(&fd->sf_dev->nsc_lock);
	}
}


/*
 * char *
 * nsc_pathname (nsc_fd_t *fd)
 *	Pathname associated with file descriptor.
 *
 * Calling/Exit State:
 *	Returns a pointer to the pathname associated
 *	with the given file descriptor.
 */
char *
nsc_pathname(fd)
nsc_fd_t *fd;
{
	return ((fd) ? (fd->sf_dev->nsc_path) : 0);
}


/*
 * int
 * nsc_fdpathcmp(nsc_fd_t *fd, uint64_t phash, char *path)
 *	Compare fd to pathname and hash
 *
 * Calling/Exit State:
 *	Returns comparison value like strcmp(3C).
 *
 * Description:
 *	Does an optimised comparison of the pathname and associated hash
 *	value (as returned from nsc_strhash()) against the pathname of
 *	the filedescriptor, fd.
 */
int
nsc_fdpathcmp(nsc_fd_t *fd, uint64_t phash, char *path)
{
	int rc = -1;

	if (fd != NULL && fd->sf_dev->nsc_phash == phash)
		rc = strcmp(fd->sf_dev->nsc_path, path);

	return (rc);
}


static int
_nsc_setval(nsc_dev_t *dev, char *path, char *name, int val, int do_ncall)
{
	nsc_devval_t *dv;
	nsc_rval_t *rval;
	ncall_t *ncall;
	nsc_val_t *vp;
	uint64_t phash;
	char *pp;
	int rc;

	ASSERT(dev != NULL || path != NULL);
#ifdef DEBUG
	if (dev != NULL && path != NULL) {
		ASSERT(strcmp(dev->nsc_path, path) == 0);
	}
#endif

	pp = (dev != NULL) ? dev->nsc_path : path;

	if (strlen(name) >= NSC_SETVAL_MAX) {
#ifdef DEBUG
		cmn_err(CE_WARN, "nsc_setval: max name size (%d) exceeded (%d)",
		    NSC_SETVAL_MAX-1, (int)strlen(name));
#endif
		return (0);
	}

	phash = nsc_strhash(pp);

	mutex_enter(&_nsc_devval_lock);

	if (dev != NULL)
		dv = dev->nsc_values;
	else {
		for (dv = _nsc_devval_top; dv != NULL; dv = dv->dv_next) {
			if (phash == dv->dv_phash &&
			    strcmp(pp, dv->dv_path) == 0)
				/* found dv for device */
				break;
		}
	}

	if (dv == NULL) {
		dv = nsc_kmem_zalloc(sizeof (*dv), KM_SLEEP, _nsc_local_mem);
		if (dv == NULL) {
			mutex_exit(&_nsc_devval_lock);
			return (0);
		}

		(void) strncpy(dv->dv_path, pp, sizeof (dv->dv_path));
		dv->dv_phash = phash;

		dv->dv_next = _nsc_devval_top;
		_nsc_devval_top = dv;
		if (dev != NULL)
			dev->nsc_values = dv;
	}

	for (vp = dv->dv_values; vp; vp = vp->sv_next) {
		if (strcmp(vp->sv_name, name) == 0) {
			vp->sv_value = val;
			break;
		}
	}

	if (vp == NULL) {
		vp = nsc_kmem_zalloc(sizeof (*vp), KM_SLEEP, _nsc_local_mem);
		if (vp != NULL) {
			(void) strncpy(vp->sv_name, name, sizeof (vp->sv_name));
			vp->sv_value = val;
			vp->sv_next = dv->dv_values;
			dv->dv_values = vp;
		}
	}

	mutex_exit(&_nsc_devval_lock);

	/*
	 * phoenix: ncall the new value to the other node now.
	 */

	if (vp && do_ncall) {
		/* CONSTCOND */
		ASSERT(sizeof (nsc_rval_t) <= NCALL_DATA_SZ);

		rval = nsc_kmem_zalloc(sizeof (*rval), KM_SLEEP,
		    _nsc_local_mem);
		if (rval == NULL) {
			goto out;
		}

		rc = ncall_alloc(ncall_mirror(ncall_self()), 0, 0, &ncall);
		if (rc == 0) {
			(void) strncpy(rval->path, pp, sizeof (rval->path));
			(void) strncpy(rval->name, name, sizeof (rval->name));
			rval->value = val;

			rc = ncall_put_data(ncall, rval, sizeof (*rval));
			if (rc == 0) {
				/*
				 * Send synchronously and read a reply
				 * so that we know that the remote
				 * setval has completed before this
				 * function returns and hence whilst
				 * the device is still reserved on this
				 * node.
				 */
				if (ncall_send(ncall, 0, NSC_SETVAL) == 0)
					(void) ncall_read_reply(ncall, 1, &rc);
			}

			ncall_free(ncall);
		}

		nsc_kmem_free(rval, sizeof (*rval));
	}

out:
	return (vp ? 1 : 0);
}


/* ARGSUSED */

static void
r_nsc_setval(ncall_t *ncall, int *ap)
{
	nsc_rval_t *rval;
	int rc;

	rval = nsc_kmem_zalloc(sizeof (*rval), KM_SLEEP, _nsc_local_mem);
	if (rval == NULL) {
		ncall_reply(ncall, ENOMEM);
		return;
	}

	rc = ncall_get_data(ncall, rval, sizeof (*rval));
	if (rc != 0) {
		ncall_reply(ncall, EFAULT);
		return;
	}

	if (_nsc_setval(NULL, rval->path, rval->name, rval->value, FALSE))
		rc = 0;
	else
		rc = ENOMEM;

	ncall_reply(ncall, rc);
	nsc_kmem_free(rval, sizeof (*rval));
}


/* ARGSUSED */

static void
r_nsc_setval_all(ncall_t *ncall, int *ap)
{
	nsc_rval_t *in = NULL, *out = NULL;
	nsc_devval_t *dv;
	nsc_val_t *vp;
	ncall_t *np;
	uint64_t phash;
	int rc;

	/* CONSTCOND */
	ASSERT(sizeof (nsc_rval_t) <= NCALL_DATA_SZ);

	in = nsc_kmem_zalloc(sizeof (*in), KM_SLEEP, _nsc_local_mem);
	out = nsc_kmem_zalloc(sizeof (*out), KM_SLEEP, _nsc_local_mem);
	if (in == NULL || out == NULL) {
		if (in != NULL) {
			nsc_kmem_free(in, sizeof (*in));
			in = NULL;
		}
		if (out != NULL) {
			nsc_kmem_free(out, sizeof (*out));
			out = NULL;
		}
		ncall_reply(ncall, ENOMEM);
	}

	rc = ncall_get_data(ncall, in, sizeof (*in));
	if (rc != 0) {
		ncall_reply(ncall, EFAULT);
		return;
	}

	phash = nsc_strhash(in->path);

	(void) strncpy(out->path, in->path, sizeof (out->path));

	rc = ncall_alloc(ncall_mirror(ncall_self()), 0, 0, &np);
	if (rc != 0) {
		ncall_reply(ncall, ENOMEM);
		return;
	}

	mutex_enter(&_nsc_devval_lock);

	for (dv = _nsc_devval_top; dv; dv = dv->dv_next) {
		if (dv->dv_phash == phash &&
		    strcmp(dv->dv_path, in->path) == 0)
			break;
	}

	if (dv) {
		for (vp = dv->dv_values; vp; vp = vp->sv_next) {
			if (strcmp(vp->sv_name, NSC_DEVMIN) == 0 ||
			    strcmp(vp->sv_name, NSC_DEVMAJ) == 0) {
				/* ignore the implicit DevMin/DevMaj values */
				continue;
			}

			(void) strncpy(out->name, vp->sv_name,
			    sizeof (out->name));
			out->value = vp->sv_value;

			rc = ncall_put_data(np, out, sizeof (*out));
			if (rc == 0) {
				/*
				 * Send synchronously and read a reply
				 * so that we know that the remote
				 * setval has completed before this
				 * function returns.
				 */
				if (ncall_send(np, 0, NSC_SETVAL) == 0)
					(void) ncall_read_reply(np, 1, &rc);
			}

			ncall_reset(np);
		}

		ncall_free(np);
		rc = 0;
	} else {
		rc = ENODEV;
	}

	mutex_exit(&_nsc_devval_lock);

	ncall_reply(ncall, rc);

	nsc_kmem_free(out, sizeof (*out));
	nsc_kmem_free(in, sizeof (*in));
}


/*
 * int
 * nsc_setval (nsc_fd_t *fd, char *name, int val)
 *	Set value for device.
 *
 * Calling/Exit State:
 *	Returns 1 if the value has been set, otherwise 0.
 *	Must be called with the fd reserved.
 *
 * Description:
 *	Sets the specified global variable for the device
 *	to the value provided.
 */
int
nsc_setval(nsc_fd_t *fd, char *name, int val)
{
	if (!fd)
		return (0);

	if (!nsc_held(fd))
		return (0);

	return (_nsc_setval(fd->sf_dev, NULL, name, val, TRUE));
}


/*
 * int
 * nsc_getval (nsc_fd_t *fd, char *name, int *vp)
 *	Get value from device.
 *
 * Calling/Exit State:
 *	Returns 1 if the value has been found, otherwise 0.
 *	Must be called with the fd reserved, except for "DevMaj" / "DevMin".
 *
 * Description:
 *	Finds the value of the specified device variable for
 *	the device and returns it in the location pointed to
 *	by vp.
 */
int
nsc_getval(nsc_fd_t *fd, char *name, int *vp)
{
	nsc_devval_t *dv;
	nsc_val_t *val;

	if (!fd)
		return (0);

	/*
	 * Don't check for nsc_held() for the device number values
	 * since these are magically created and cannot change when
	 * the fd is not reserved.
	 */

	if (strcmp(name, NSC_DEVMAJ) != 0 &&
	    strcmp(name, NSC_DEVMIN) != 0 &&
	    !nsc_held(fd))
		return (0);

	mutex_enter(&_nsc_devval_lock);

	dv = fd->sf_dev->nsc_values;
	val = NULL;

	if (dv != NULL) {
		for (val = dv->dv_values; val; val = val->sv_next) {
			if (strcmp(val->sv_name, name) == 0) {
				*vp = val->sv_value;
				break;
			}
		}
	}

	mutex_exit(&_nsc_devval_lock);

	return (val ? 1 : 0);
}


/*
 * char *
 * nsc_shared (nsc_fd_t *fd)
 *	Device is currently shared.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to this
 *	this function.
 *
 *	Returns an indication of whether the device accessed
 *	by the file descriptor is currently referenced by more
 *	than one user.
 *
 *	This is only intended for use in performance critical
 *	situations.
 */
int
nsc_shared(fd)
nsc_fd_t *fd;
{
	nsc_iodev_t *iodev;
	int cnt = 0;

	if (!fd)
		return (0);
	if (!fd->sf_iodev)
		return (1);

	for (iodev = fd->sf_dev->nsc_list; iodev; iodev = iodev->si_next)
		for (fd = iodev->si_open; fd; fd = fd->sf_next)
			if (!fd->sf_owner && cnt++)
				return (1);

	return (0);
}


/*
 * kmutex_t *
 * nsc_lock_addr (nsc_fd_t *fd)
 *	Address of device lock.
 *
 * Calling/Exit State:
 *	Returns a pointer to the spin lock associated with the
 *	device.
 *
 * Description:
 *	This is only intended for use in performance critical
 *	situations in conjunction with nsc_reserve_lk.
 */
kmutex_t *
nsc_lock_addr(fd)
nsc_fd_t *fd;
{
	return (&fd->sf_dev->nsc_lock);
}


/*
 * int
 * _nsc_call_io (long f, blind_t a, blind_t b, blind_t c)
 *	Call information function.
 *
 * Calling/Exit State:
 *	Returns result from function or 0 if not available.
 *	f represents the offset into the I/O structure at which
 *	the required function can be found and a, b, c are the
 *	desired arguments.
 *
 * Description:
 *	Calls the requested function for the first available
 *	cache interface.
 */
int
_nsc_call_io(long f, blind_t a, blind_t b, blind_t c)
{
	nsc_io_t *io;
	int (*fn)();
	int rc;

	io = _nsc_reserve_io(NULL, NSC_SDBC_ID);
	if (!io)
		io = _nsc_reserve_io(NULL, NSC_NULL);

	fn = (blindfn_t)(((long *)io)[f]);
	rc = (*fn)(a, b, c);

	_nsc_release_io(io);
	return (rc);
}


/*
 * nsc_io_t *
 * _nsc_reserve_io (char *, int type)
 *	Reserve I/O module.
 *
 * Calling/Exit State:
 *	Returns address of I/O structure matching specified
 *	type, or NULL.
 *
 * Description:
 *	Searches for an appropriate I/O module and increments
 *	the reference count to prevent it being unregistered.
 */
nsc_io_t *
_nsc_reserve_io(path, type)
char *path;
int type;
{
	nsc_io_t *io;

	mutex_enter(&_nsc_io_lock);

	if ((io = _nsc_find_io(path, type, NULL)) != 0)
		io->refcnt++;

	mutex_exit(&_nsc_io_lock);
	return (io);
}


/*
 * static nsc_io_t *
 * _nsc_find_io (char *path, int type, int *changed)
 *	Find I/O module.
 *
 * Calling/Exit State:
 *	The _nsc_io_lock must be held across calls to
 *	this function.
 *
 *	Returns address of I/O structure matching specified
 *	type, or NULL.
 *
 *	'changed' will be set to non-zero if there is a pending
 *	nsc_path_t that matches the criteria for the requested type.
 *	This allows nsctl to distinguish between multiple
 *	nsc_register_path's done by the same I/O provider.
 *
 * Description:
 *	Searches for an appropriate I/O module.
 *
 *	1.  If <type> is a single module id find the specified I/O
 *	    module by module id.
 *
 *	2.  Find the highest module that provides any of the I/O types
 *	    included in <type>, taking into account any modules
 *	    registered via the nsc_register_path() interface if <path>
 *	    is non-NULL.
 *
 *	3.  Find an I/O module following the rules in (2), but whose
 *	    module id is less than the id OR'd into <type>.
 *
 *	If no module is found by the above algorithms and NSC_NULL was
 *	included in <type>, return the _nsc_null_io module. Otherwise
 *	return NULL.
 */
static nsc_io_t *
_nsc_find_io(char *path, int type, int *changed)
{
	nsc_path_t *sp = NULL;
	nsc_path_t *pp = NULL;
	nsc_io_t *io;

	type &= NSC_TYPES;

	if (path) {
		for (sp = _nsc_path_top; sp; sp = sp->sp_next) {
			if ((type & NSC_ID) &&
			    sp->sp_io->id >= (type & NSC_IDS))
				continue;

			if (sp->sp_pend || (type & sp->sp_type) == 0)
				continue;

			if (nsc_strmatch(path, sp->sp_path))
				break;
		}

		if (sp) {
			/* look for matching pending paths */
			for (pp = _nsc_path_top; pp; pp = pp->sp_next) {
				if (pp->sp_pend &&
				    (type & pp->sp_type) &&
				    nsc_strmatch(path, pp->sp_path)) {
					break;
				}
			}
		}
	}

	for (io = _nsc_io_top; io; io = io->next) {
		if (io->pend)
			continue;

		if (type & NSC_ID) {
			if ((type & ~NSC_IDS) == 0) {
				if (io->id == type)
					break;
				continue;
			}

			if (io->id >= (type & NSC_IDS))
				continue;
		}

		if (io->provide & type)
			break;
	}

	if (pp && (!io || pp->sp_io->id >= io->id)) {
		/*
		 * Mark this as a path change.
		 */
		if (changed) {
			*changed = 1;
		}
	}

	if (sp && (!io || sp->sp_io->id >= io->id))
		io = sp->sp_io;

	if (!io && !(type & NSC_NULL))
		return (NULL);

	if (!io)
		io = _nsc_null_io;

	return (io);
}


/*
 * void
 * _nsc_release_io (nsc_io_t *)
 *	Release I/O module.
 *
 * Description:
 *	Releases reference to I/O structure and wakes up
 *	anybody waiting on it.
 */
void
_nsc_release_io(io)
nsc_io_t *io;
{
	mutex_enter(&_nsc_io_lock);

	io->refcnt--;
	cv_broadcast(&io->cv);

	mutex_exit(&_nsc_io_lock);
}


/*
 * static int
 * _nsc_alloc_fd (char *path, int type, int flag, nsc_fd_t **fdp)
 *	Allocate file descriptor structure.
 *
 * Calling/Exit State:
 *	Stores address of file descriptor through fdp and
 *	returns 0 on success, otherwise returns error code.
 *
 * Description:
 *	A new file descriptor is allocated and linked in to
 *	the file descriptor chain which is protected by the
 *	device lock.
 *
 *	On return the file descriptor must contain all the
 *	information necessary to perform an open. Details
 *	specific to user callbacks are not required yet.
 */
static int
_nsc_alloc_fd(path, type, flag, fdp)
char *path;
int type, flag;
nsc_fd_t **fdp;
{
	nsc_dev_t *dev;
	nsc_fd_t *fd;
	int rc;

	if (!(fd = (nsc_fd_t *)nsc_kmem_zalloc(
				sizeof (*fd), KM_SLEEP, _nsc_local_mem)))
		return (ENOMEM);

	if ((rc = _nsc_alloc_dev(path, &dev)) != 0) {
		nsc_kmem_free(fd, sizeof (*fd));
		return (rc);
	}

	mutex_enter(&dev->nsc_lock);

	fd->sf_type = type;
	fd->sf_flag = flag;
	fd->sf_dev = dev;
	fd->sf_next = dev->nsc_close;
	dev->nsc_close = fd;

	mutex_exit(&dev->nsc_lock);

	*fdp = fd;
	return (0);
}


/*
 * static int
 * _nsc_free_fd (nsc_fd_t *)
 *	Free file descriptor.
 *
 * Description:
 *	The file descriptor is removed from the chain and free'd
 *	once pending activity has completed.
 */
static void
_nsc_free_fd(fd)
nsc_fd_t *fd;
{
	nsc_dev_t *dev = fd->sf_dev;
	nsc_fd_t **fdp;

	if (!fd)
		return;

	mutex_enter(&dev->nsc_lock);

	for (fdp = &dev->nsc_close; *fdp; fdp = &(*fdp)->sf_next)
		if (*fdp == fd) {
			*fdp = fd->sf_next;
			break;
		}

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	while (fd->sf_pend)
		(void) _nsc_wait_dev(dev, 0);

	mutex_exit(&dev->nsc_lock);

	_nsc_free_dev(dev);

	nsc_kmem_free(fd, sizeof (*fd));
}


/*
 * static void
 * _nsc_relink_fd (nsc_fd_t *fd, nsc_fd_t **from,
 *				nsc_fd_t **to, nsc_iodev_t *iodev)
 *	Relink file descriptor.
 *
 * Description:
 *	Remove the file descriptor from the 'from' chain and
 *	add it to the 'to' chain. The busy flag in iodev is
 *	used to prevent modifications to the chain whilst a
 *	callback is in progress.
 */
static void
_nsc_relink_fd(nsc_fd_t *fd, nsc_fd_t **from, nsc_fd_t **to, nsc_iodev_t *iodev)
{
	nsc_dev_t *dev = fd->sf_dev;
	nsc_fd_t **fdp;

	mutex_enter(&dev->nsc_lock);

	while (iodev->si_busy)
		(void) _nsc_wait_dev(dev, 0);

	for (fdp = from; *fdp; fdp = &(*fdp)->sf_next)
		if (*fdp == fd) {
			*fdp = fd->sf_next;
			break;
		}

	fd->sf_next = (*to);
	(*to) = fd;

	mutex_exit(&dev->nsc_lock);
}


/*
 * static int
 * _nsc_alloc_iodev (nsc_dev_t *dev, int type, nsc_iodev_t **iodevp)
 *	Allocate I/O device structure.
 *
 * Calling/Exit State:
 *	Stores address of I/O device structure through iodevp
 *	and returns 0 on success, otherwise returns error code.
 *
 * Description:
 *	If an entry for the I/O device already exists increment
 *	the reference count and return the address, otherwise
 *	allocate a new structure.
 *
 *	A new structure is allocated before scanning the chain
 *	to avoid calling the memory allocator with a spin lock
 *	held. If an entry is found the new structure is free'd.
 *
 *	The I/O device chain is protected by the device lock.
 */
static int
_nsc_alloc_iodev(dev, type, iodevp)
nsc_dev_t *dev;
int type;
nsc_iodev_t **iodevp;
{
	nsc_iodev_t *iodev, *ip;
	nsc_io_t *io;

	if (!(iodev = (nsc_iodev_t *)nsc_kmem_zalloc(
				sizeof (*iodev), KM_SLEEP, _nsc_local_mem)))
		return (ENOMEM);

	mutex_init(&iodev->si_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&iodev->si_cv, NULL, CV_DRIVER, NULL);

	if (!(io = _nsc_reserve_io(dev->nsc_path, type))) {
		mutex_destroy(&iodev->si_lock);
		cv_destroy(&iodev->si_cv);
		nsc_kmem_free(iodev, sizeof (*iodev));
		return (ENXIO);
	}

	iodev->si_refcnt++;
	iodev->si_io = io;
	iodev->si_dev = dev;

	mutex_enter(&_nsc_io_lock);
	dev->nsc_refcnt++;
	mutex_exit(&_nsc_io_lock);

	mutex_enter(&dev->nsc_lock);

	for (ip = dev->nsc_list; ip; ip = ip->si_next)
		if (ip->si_io == io) {
			ip->si_refcnt++;
			break;
		}

	if (!ip) {
		iodev->si_next = dev->nsc_list;
		dev->nsc_list = iodev;
	}

	mutex_exit(&dev->nsc_lock);

	if (ip) {
		_nsc_free_iodev(iodev);
		iodev = ip;
	}

	*iodevp = iodev;
	return (0);
}


/*
 * static int
 * _nsc_free_iodev (nsc_iodev_t *iodev)
 *	Free I/O device structure.
 *
 * Description:
 *	Decrements the reference count of a previously allocated
 *	I/O device structure. If this is the last reference it
 *	is removed from the device chain and free'd once pending
 *	activity has completed.
 */
static void
_nsc_free_iodev(nsc_iodev_t *iodev)
{
	nsc_iodev_t **ipp;
	nsc_dev_t *dev;

	if (!iodev)
		return;

	dev = iodev->si_dev;

	mutex_enter(&dev->nsc_lock);

	if (--iodev->si_refcnt > 0) {
		mutex_exit(&dev->nsc_lock);
		return;
	}

	for (ipp = &dev->nsc_list; *ipp; ipp = &(*ipp)->si_next)
		if (*ipp == iodev) {
			*ipp = iodev->si_next;
			break;
		}

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	while (iodev->si_pend || iodev->si_rpend || iodev->si_busy)
		(void) _nsc_wait_dev(dev, 0);

	mutex_exit(&dev->nsc_lock);

	_nsc_release_io(iodev->si_io);
	_nsc_free_dev(dev);

	mutex_destroy(&iodev->si_lock);
	cv_destroy(&iodev->si_cv);

	nsc_kmem_free(iodev, sizeof (*iodev));
}


/*
 * static int
 * _nsc_alloc_dev (char *path, nsc_dev_t **devp)
 *	Allocate device structure.
 *
 * Calling/Exit State:
 *	Stores address of device structure through devp
 *	and returns 0 on success, otherwise returns error
 *	code.
 *
 * Description:
 *	If an entry for the device already exists increment
 *	the reference count and return the address, otherwise
 *	allocate a new structure.
 *
 *	A new structure is allocated before scanning the device
 *	chain to avoid calling the memory allocator with a spin
 *	lock held. If the device is found the new structure is
 *	free'd.
 *
 *	The device chain is protected by _nsc_io_lock.
 */
static int
_nsc_alloc_dev(char *path, nsc_dev_t **devp)
{
	nsc_dev_t *dev, *dp, **ddp;
	nsc_devval_t *dv;
	nsc_rval_t *rval;
	ncall_t *ncall;
	int rc;

	if (!(dev = (nsc_dev_t *)nsc_kmem_zalloc(
	    sizeof (*dev), KM_SLEEP, _nsc_local_mem)))
		return (ENOMEM);

	dev->nsc_refcnt++;

	mutex_init(&dev->nsc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dev->nsc_cv, NULL, CV_DRIVER, NULL);

	dev->nsc_phash = nsc_strhash(path);
	dev->nsc_path = nsc_strdup(path);

	mutex_enter(&_nsc_io_lock);

	dev->nsc_next = _nsc_dev_pend;
	_nsc_dev_pend = dev;

	mutex_exit(&_nsc_io_lock);

	mutex_enter(&_nsc_io_lock);

	for (dp = _nsc_dev_top; dp; dp = dp->nsc_next)
		if (dp->nsc_phash == dev->nsc_phash &&
		    strcmp(dp->nsc_path, dev->nsc_path) == 0) {
			dp->nsc_refcnt++;
			break;
		}

	if (!dp) {
		for (ddp = &_nsc_dev_pend; *ddp; ddp = &(*ddp)->nsc_next)
			if (*ddp == dev) {
				*ddp = dev->nsc_next;
				break;
			}

		dev->nsc_next = _nsc_dev_top;
		_nsc_dev_top = dev;
	}

	mutex_exit(&_nsc_io_lock);

	if (dp) {
		_nsc_free_dev(dev);
		dev = dp;
	}

	/*
	 * Try and find the device/values header for this device
	 * and link it back to the device structure.
	 */

	mutex_enter(&_nsc_devval_lock);

	if (dev->nsc_values == NULL) {
		for (dv = _nsc_devval_top; dv; dv = dv->dv_next) {
			if (dv->dv_phash == dev->nsc_phash &&
			    strcmp(dv->dv_path, dev->nsc_path) == 0) {
				dev->nsc_values = dv;
				break;
			}
		}
	}

	mutex_exit(&_nsc_devval_lock);

	/*
	 * Refresh the device/values from the other node
	 */

	rval = nsc_kmem_zalloc(sizeof (*rval), KM_SLEEP, _nsc_local_mem);
	if (rval == NULL) {
		goto out;
	}

	rc = ncall_alloc(ncall_mirror(ncall_self()), 0, 0, &ncall);
	if (rc == 0) {
		(void) strncpy(rval->path, path, sizeof (rval->path));

		rc = ncall_put_data(ncall, rval, sizeof (*rval));
		if (rc == 0) {
			/*
			 * Send synchronously and read a reply
			 * so that we know that the updates
			 * have completed before this
			 * function returns.
			 */
			if (ncall_send(ncall, 0, NSC_SETVAL_ALL) == 0)
				(void) ncall_read_reply(ncall, 1, &rc);
		}

		ncall_free(ncall);
	}

	nsc_kmem_free(rval, sizeof (*rval));

out:
	*devp = dev;
	return (0);
}


/*
 * static void
 * _nsc_free_dev (nsc_dev_t *dev)
 *	Free device structure.
 *
 * Description:
 *	Decrements the reference count of a previously allocated
 *	device structure. If this is the last reference it is
 *	removed from the device chain and free'd once pending
 *	activity has completed.
 *
 *	Whilst waiting for pending activity to cease the device is
 *	relinked onto the pending chain.
 */
static void
_nsc_free_dev(dev)
nsc_dev_t *dev;
{
	nsc_dev_t **ddp;

	if (!dev)
		return;

	mutex_enter(&_nsc_io_lock);

	if (--dev->nsc_refcnt > 0) {
		mutex_exit(&_nsc_io_lock);
		return;
	}

	for (ddp = &_nsc_dev_top; *ddp; ddp = &(*ddp)->nsc_next)
		if (*ddp == dev) {
			*ddp = dev->nsc_next;
			dev->nsc_next = _nsc_dev_pend;
			_nsc_dev_pend = dev;
			break;
		}

	mutex_exit(&_nsc_io_lock);

	mutex_enter(&dev->nsc_lock);

	while (dev->nsc_pend || dev->nsc_rpend || dev->nsc_wait) {
		cv_wait(&dev->nsc_cv, &dev->nsc_lock);
	}

	mutex_exit(&dev->nsc_lock);

	mutex_enter(&_nsc_io_lock);

	for (ddp = &_nsc_dev_pend; *ddp; ddp = &(*ddp)->nsc_next)
		if (*ddp == dev) {
			*ddp = dev->nsc_next;
			break;
		}

	mutex_exit(&_nsc_io_lock);

	mutex_destroy(&dev->nsc_lock);
	cv_destroy(&dev->nsc_cv);
	nsc_strfree(dev->nsc_path);

	nsc_kmem_free(dev, sizeof (*dev));
}


/*
 * static nsc_io_t *
 * _nsc_alloc_io (int id, char *name, int flag)
 *	Allocate an I/O structure.
 *
 * Calling/Exit State:
 *	Returns the address of the I/O structure, or NULL.
 */
static nsc_io_t *
_nsc_alloc_io(id, name, flag)
int id;
char *name;
int flag;
{
	nsc_io_t *io;

	if (!(io = (nsc_io_t *)nsc_kmem_zalloc(
			sizeof (*io), KM_NOSLEEP, _nsc_local_mem)))
		return (NULL);

	cv_init(&io->cv, NULL, CV_DRIVER, NULL);

	io->id = id;
	io->name = name;
	io->flag = flag;

	return (io);
}


/*
 * static void
 * _nsc_free_io (int id, char *name, int flag)
 *	Free an I/O structure.
 *
 * Calling/Exit State:
 *	Free the I/O structure and remove it from the chain.
 */
static void
_nsc_free_io(io)
nsc_io_t *io;
{
	nsc_io_t **iop;

	mutex_enter(&_nsc_io_lock);

	for (iop = &_nsc_io_top; *iop; iop = &(*iop)->next)
		if (*iop == io)
			break;

	if (*iop)
		(*iop) = io->next;

	mutex_exit(&_nsc_io_lock);

	cv_destroy(&io->cv);
	nsc_kmem_free(io, sizeof (*io));
}

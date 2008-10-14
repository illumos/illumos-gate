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
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include <sys/ncall/ncall.h>
#include "nsc_dev.h"
#include "../nsctl.h"
#ifdef DS_DDICT
#include "../contract.h"
#endif


static int _nsc_attach_fd(nsc_fd_t *, int);
static int _nsc_detach_owner(nsc_fd_t *, int);
static int _nsc_fd_fn(nsc_fd_t *, int (*)(), int, int);
static int _nsc_attach_iodev(nsc_iodev_t *, int);
static int _nsc_attach_dev(nsc_dev_t *, int);
static int _nsc_call_dev(nsc_dev_t *, blindfn_t, blind_t,
    int *, int *, int, int, nsc_iodev_t *);


/*
 * void
 * _nsc_init_resv (void)
 *	Initialise reserve mechanism.
 *
 * Calling/Exit State:
 *	Called at initialisation time to allocate necessary
 *	data structures.
 */
void
_nsc_init_resv()
{
}


/*
 * void
 * _nsc_deinit_resv (void)
 *	De-initialise reserve mechanism.
 *
 * Calling/Exit State:
 *	Called at unload time to de-allocate resources.
 */
void
_nsc_deinit_resv()
{
}


/*
 * int
 * nsc_attach (nsc_fd_t *fd, int flag)
 *	Force attach of file descriptor.
 *
 * Calling/Exit State:
 *	Returns 0 if the attach succeeds, otherwise
 *	returns an error code.
 *
 * Description:
 *	Tries to attach the file descriptor by reserving
 *	and then releasing it. This is intended purely as
 *	a performance aid since there is no guarantee that
 *	the file descriptor will remain attached upon
 *	return.
 */
int
nsc_attach(fd, flag)
nsc_fd_t *fd;
int flag;
{
	int rc;

	rc = nsc_reserve(fd, flag);

	if (rc == 0)
		nsc_release(fd);

	return (rc);
}


/*
 * int
 * nsc_reserve (nsc_fd_t *fd, int flag)
 *	Reserve file descriptor.
 *
 * Calling/Exit State:
 *	Returns 0 if the reserve succeeds, otherwise
 *	returns an error code.
 *
 * Description:
 *	Reserves the file descriptor for either NSC_READ or
 *	NSC_WRITE access. If neither is specified the mode
 *	with which the file was opened will be used. Trying
 *	to reserve a read only file in write mode will cause
 *	EACCES to be returned.
 *
 *	If NSC_NOBLOCK is specifed and the reserve cannot be
 *	completed immediately, EAGAIN will be returned.
 *
 *	If NSC_NOWAIT is set and the device is busy, EAGAIN
 *	will be returned.
 *
 *	If NSC_TRY is set and the device is already reserved
 *	EAGAIN will be returned.
 *
 *	If NSC_PCATCH is specified and a signal is received,
 *	the reserve will be terminated and EINTR returned.
 *
 *	If NSC_MULTI is set then multiple reserves of the
 *	same type are permitted for the file descriptor.
 */
int
nsc_reserve(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	int rc, rw;

	if ((flag & NSC_READ) == 0)
		flag |= (fd->sf_flag & NSC_RDWR);

	rw = (flag & NSC_RDWR);
	if ((fd->sf_flag & rw) != rw)
		return (EACCES);

	mutex_enter(&dev->nsc_lock);

	while ((rc = _nsc_attach_fd(fd, flag)) != 0)
		if (rc != ERESTART)
			break;

	if (!rc && !fd->sf_reserve++) {
		fd->sf_aio = fd->sf_iodev->si_io;
		fd->sf_mode = (flag & NSC_MULTI);
	}

	mutex_exit(&dev->nsc_lock);
	return (rc);
}


/*
 * int
 * nsc_reserve_lk (nsc_fd_t *fd)
 *	Reserve locked file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Must be preceeded by a successful call to nsc_avail.
 *
 * Description:
 *	Reserves the file descriptor using the mode specified
 *	when the file was opened. This is only intended for
 *	use in performance critical situations.
 */
void
nsc_reserve_lk(fd)
nsc_fd_t *fd;
{
	fd->sf_reserve = 1;
	fd->sf_aio = fd->sf_iodev->si_io;
}


/*
 * int
 * nsc_avail (nsc_fd_t *fd)
 *	Test if file descriptor is available.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns true if the file descriptor is available to
 *	be reserved using the mode specified when the file
 *	was opened.
 *
 * Description:
 *	This is only intended for use in performance critical
 *	situations in conjunction with nsc_reserve_lk.
 */
int
nsc_avail(fd)
nsc_fd_t *fd;
{
	int rw;

	if (!fd || fd->sf_pend || fd->sf_reserve || fd->sf_reopen)
		return (0);

	if ((fd->sf_avail & _NSC_ATTACH) == 0)
		return (0);
	if ((fd->sf_avail & _NSC_PINNED) == 0)
		return (0);

	rw = (fd->sf_flag & NSC_RDWR);

	return ((fd->sf_avail & rw) == rw);
}


/*
 * int
 * nsc_held (nsc_fd_t *fd)
 *	Test if file descriptor is reserved.
 *
 * Calling/Exit State:
 *	Returns true if the file descriptor is currently
 *	reserved.
 */
int
nsc_held(fd)
nsc_fd_t *fd;
{
	return ((fd) ? fd->sf_reserve : 1);
}


/*
 * int
 * nsc_waiting (nsc_fd_t *fd)
 *	Test if another client is waiting for this device.
 *
 * Calling/Exit State:
 *	Must be called with the file descriptor reserved.
 *	Returns true if another thread is waiting to reserve this device.
 *
 * Description:
 *	This is only intended for use in performance critical
 *	situations and inherently returns historical information.
 */
int
nsc_waiting(nsc_fd_t *fd)
{
	nsc_dev_t *dev;

	if (!fd || !nsc_held(fd))
		return (FALSE);

	dev = fd->sf_dev;

	return (dev->nsc_wait || dev->nsc_refcnt <= 0);
}


/*
 * int
 * nsc_release_lk (nsc_fd_t *fd)
 *	Release locked file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns true if another node is waiting for the
 *	device and a call to nsc_detach should be made.
 *
 * Description:
 *	Releases the file descriptor. This is only intended
 *	for use in performance critical situations in
 *	conjunction with nsc_reserve_lk.
 */
int
nsc_release_lk(fd)
nsc_fd_t *fd;
{
	nsc_dev_t *dev = fd->sf_dev;

	fd->sf_reserve = 0;
	fd->sf_aio = _nsc_null_io;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	return (dev->nsc_drop > 0);
}


/*
 * int
 * nsc_release (nsc_fd_t *fd)
 *	Release file descriptor.
 *
 * Description:
 *	Releases the file descriptor. If another node
 *	is waiting for the device it will be completely
 *	detached before returning.
 */
void
nsc_release(fd)
nsc_fd_t *fd;
{
	nsc_dev_t *dev = fd->sf_dev;
	int rc;

	mutex_enter(&dev->nsc_lock);

	if (!fd->sf_reserve || --fd->sf_reserve) {
		mutex_exit(&dev->nsc_lock);
		return;
	}

	fd->sf_aio = _nsc_null_io;
	fd->sf_mode = 0;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	while (dev->nsc_drop > 0) {
		rc = _nsc_detach_dev(dev, NULL, NSC_RDWR);
		if (!rc || rc != ERESTART)
			break;
	}

	mutex_exit(&dev->nsc_lock);
}


/*
 * int
 * nsc_detach (nsc_fd_t *fd, int flag)
 *	Detach device from node.
 *
 * Calling/Exit State:
 *	Returns 0 if the reserve succeeds, otherwise
 *	returns an error code.
 *
 * Description:
 *	Detaches the device from the current node. If flag
 *	specifies read access then flush is called in preference
 *	to detach.
 *
 *	If NSC_NOBLOCK is specifed and the detach cannot be
 *	completed immediately, EAGAIN will be returned.
 *
 *	If NSC_TRY is set and the device is reserved, EAGAIN
 *	will be returned.
 *
 *	If NSC_NOWAIT is set and the device is busy, EAGAIN
 *	will be returned.
 *
 *	If NSC_PCATCH is specified and a signal is received,
 *	the reserve will be terminated and EINTR returned.
 *
 *	If NSC_DEFER is set and the device is reserved, then
 *	the detach will be done on release.
 */
int
nsc_detach(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev;
	int rc;

	if (!fd)
		return (0);

	dev = fd->sf_dev;

	if (flag & NSC_DEFER)
		flag |= NSC_TRY;
	if ((flag & NSC_READ) == 0)
		flag |= NSC_RDWR;

	mutex_enter(&dev->nsc_lock);

	while ((rc = _nsc_detach_dev(dev, NULL, flag)) != 0)
		if (rc != ERESTART)
			break;

	if (rc == EAGAIN && (flag & NSC_DEFER))
		dev->nsc_drop = 1;

	mutex_exit(&dev->nsc_lock);
	return (rc);
}


/*
 * static int
 * _nsc_attach_fd (nsc_fd_t *fd, int flag)
 *	Attach file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the attach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Attach the specified file descriptor. Other file
 *	descriptors for the same I/O device will be flushed
 *	or detached first as necessary.
 */
static int
_nsc_attach_fd(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	int rw = (flag & NSC_RDWR);
	nsc_iodev_t *iodev;
	int rc, av;

	if (fd->sf_pend)
		return (_nsc_wait_dev(dev, flag));

	if (fd->sf_reopen)
		if ((rc = _nsc_close_fd(fd, flag)) != 0)
			return (rc);

	if (!fd->sf_iodev)
		if ((rc = _nsc_open_fd(fd, flag)) != 0)
			return (rc);

	iodev = fd->sf_iodev;

	if ((flag & fd->sf_mode & NSC_MULTI) && fd->sf_reserve)
		if ((fd->sf_avail & rw) == rw && !iodev->si_rpend)
			if (dev->nsc_drop == 0)
				return (0);

	if (fd->sf_reserve) {
		if (flag & NSC_TRY)
			return (EAGAIN);
		return (_nsc_wait_dev(dev, flag));
	}

	if (fd->sf_avail & _NSC_ATTACH)
		if (fd->sf_avail & _NSC_PINNED)
			if ((fd->sf_avail & rw) == rw)
				return (0);

	if (iodev->si_rpend && !fd->sf_avail)
		return (_nsc_wait_dev(dev, flag));

	if ((rc = _nsc_detach_iodev(iodev, fd, flag)) != 0 ||
	    (rc = _nsc_attach_iodev(iodev, flag)) != 0)
		return (rc);

	if (!fd->sf_avail) {
		fd->sf_avail = rw;
		return (_nsc_fd_fn(fd, fd->sf_attach, _NSC_ATTACH, flag));
	}

	if ((fd->sf_avail & _NSC_PINNED) == 0) {
		av = (fd->sf_avail | _NSC_PINNED);

		return _nsc_call_dev(dev, iodev->si_io->getpin,
			fd->sf_cd, &fd->sf_avail, &fd->sf_pend, av, flag, NULL);
	}

	fd->sf_avail |= rw;
	return (0);
}


/*
 * int
 * _nsc_detach_fd (nsc_fd_t *fd, int flag)
 *	Detach file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the detach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Detach the specified file descriptor. If flag
 *	specifies read access then flush is called in
 *	preference to detach.
 */
int
_nsc_detach_fd(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *dev = fd->sf_dev;
	int rc;

	if (fd->sf_pend == _NSC_CLOSE)
		return (0);

	if (fd->sf_pend)
		return (_nsc_wait_dev(dev, flag));

	if (fd->sf_flush == nsc_null)
		flag |= NSC_RDWR;

	if ((fd->sf_avail & NSC_RDWR) == 0)
		if (!fd->sf_avail || !(flag & NSC_WRITE))
			return (0);

	if (fd->sf_reserve && fd->sf_owner)
		if ((rc = _nsc_detach_owner(fd, flag)) != 0)
			return (rc);

	if (fd->sf_reserve) {
		if (flag & NSC_TRY)
			return (EAGAIN);
		return (_nsc_wait_dev(dev, flag));
	}

	if (flag & NSC_WRITE) {
		if (fd->sf_iodev->si_busy)
			return (_nsc_wait_dev(dev, flag));

		return (_nsc_fd_fn(fd, fd->sf_detach, 0, flag));
	}

	return (_nsc_fd_fn(fd, fd->sf_flush, (fd->sf_avail & ~NSC_RDWR), flag));
}


/*
 * static int
 * _nsc_detach_owner (nsc_fd_t *fd, int flag)
 *	Detach owner of file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the detach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Detach the owner of the specified file descriptor.
 *	Wherever possible this is done without releasing
 *	the current device lock.
 */
static int
_nsc_detach_owner(fd, flag)
nsc_fd_t *fd;
int flag;
{
	nsc_dev_t *newdev = fd->sf_owner->si_dev;
	nsc_dev_t *dev = fd->sf_dev;
	int try;
	int rc;

	if (newdev == dev) {
		if ((rc = _nsc_detach_iodev(fd->sf_owner, NULL, flag)) == 0)
			fd->sf_owner = NULL;
		return (rc);
	}

	if ((try = mutex_tryenter(&newdev->nsc_lock)) != 0)
		if (!_nsc_detach_iodev(fd->sf_owner, NULL,
					(flag | NSC_NOBLOCK))) {
			mutex_exit(&newdev->nsc_lock);
			return (0);
		}

	if (flag & NSC_NOBLOCK) {
		if (try != 0)
			mutex_exit(&newdev->nsc_lock);
		return (EAGAIN);
	}

	fd->sf_pend = _NSC_OWNER;
	mutex_exit(&dev->nsc_lock);

	if (try == 0)
		mutex_enter(&newdev->nsc_lock);

	rc = _nsc_detach_iodev(fd->sf_owner, NULL, flag);
	fd->sf_owner = NULL;

	mutex_exit(&newdev->nsc_lock);

	mutex_enter(&dev->nsc_lock);
	fd->sf_pend = 0;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	return (rc ? rc : ERESTART);
}


/*
 * static int
 * _nsc_fd_fn (nsc_fd_t *fd, int (*fn)(), int a, int flag)
 *	Call function to attach/detach file descriptor.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns an error code if the operation failed,
 *	otherwise returns ERESTART to indicate that the
 *	device state has changed.
 *
 * Description:
 *	Sets up the active I/O module and calls the
 *	specified function.
 */
static int
_nsc_fd_fn(nsc_fd_t *fd, int (*fn)(), int a, int flag)
{
	int rc;

	fd->sf_aio = fd->sf_iodev->si_io;

	rc = _nsc_call_dev(fd->sf_dev, fn, fd->sf_arg,
				&fd->sf_avail, &fd->sf_pend, a, flag, NULL);

	fd->sf_aio = _nsc_null_io;
	return (rc);
}


/*
 * static int
 * _nsc_attach_iodev (nsc_iodev_t *iodev, int flag)
 *	Attach I/O device.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the attach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Attach the specified I/O device. Other I/O devices
 *	for the same device will be flushed or detached first
 *	as necessary.
 *
 *	It is assumed that any valid cache descriptor for
 *	this device can be used to attach the I/O device.
 */
static int
_nsc_attach_iodev(iodev, flag)
nsc_iodev_t *iodev;
int flag;
{
	nsc_dev_t *dev = iodev->si_dev;
	nsc_io_t *io = iodev->si_io;
	int rc, rw;

	rw = (flag & NSC_RDWR);

	if (iodev->si_pend)
		return (_nsc_wait_dev(dev, flag));

	if (iodev->si_avail & _NSC_ATTACH)
		if ((iodev->si_avail & rw) == rw)
			return (0);

	if ((io->flag & NSC_FILTER) == 0) {
		if (dev->nsc_rpend && !iodev->si_avail)
			return (_nsc_wait_dev(dev, flag));

		if ((rc = _nsc_detach_dev(dev, iodev, flag)) != 0 ||
		    (rc = _nsc_attach_dev(dev, flag)) != 0)
			return (rc);
	}

	if (!iodev->si_avail) {
		iodev->si_avail = rw;

		if (!iodev->si_open) {
			cmn_err(CE_PANIC,
			    "nsctl: _nsc_attach_iodev: %p no fds",
			    (void *)iodev);
		}

		return (_nsc_call_dev(dev, io->attach, iodev->si_open->sf_cd,
		    &iodev->si_avail, &iodev->si_pend, _NSC_ATTACH,
		    flag, iodev));
	}

	iodev->si_avail |= rw;
	return (0);
}


/*
 * int
 * _nsc_detach_iodev (nsc_iodev_t *iodev, nsc_fd_t *keep, int flag)
 *	Detach I/O device.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the detach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Detach the specified I/O device except for file
 *	descriptor keep. If flag specifies read access then
 *	flush is called in preference to detach.
 *
 *	It is assumed that any valid cache descriptor for
 *	this device can be used to detach the I/O device.
 */
int
_nsc_detach_iodev(nsc_iodev_t *iodev, nsc_fd_t *keep, int flag)
{
	nsc_dev_t *dev = iodev->si_dev;
	nsc_io_t *io = iodev->si_io;
	int (*fn)(), av, rc;
	nsc_fd_t *fd;

	if (iodev->si_pend == _NSC_CLOSE)
		return (0);

	if (iodev->si_pend)
		return (_nsc_wait_dev(dev, flag));

	if (!keep && io->flush == nsc_null)
		flag |= NSC_RDWR;

	if ((iodev->si_avail & NSC_RDWR) == 0)
		if (!iodev->si_avail || !(flag & NSC_WRITE))
			return (0);

	iodev->si_rpend++;

	for (fd = iodev->si_open; fd; fd = fd->sf_next) {
		if (fd == keep)
			continue;

		if ((rc = _nsc_detach_fd(fd, flag)) != 0) {
			_nsc_wake_dev(dev, &iodev->si_rpend);
			return (rc);
		}
	}

	_nsc_wake_dev(dev, &iodev->si_rpend);

	if (keep)
		return (0);

	if (!iodev->si_open) {
		cmn_err(CE_PANIC,
		    "nsctl: _nsc_detach_iodev: %p no fds", (void *)iodev);
	}

	fn = (flag & NSC_WRITE) ? io->detach : io->flush;
	av = (flag & NSC_WRITE) ? 0 : (iodev->si_avail & ~NSC_RDWR);

	return (_nsc_call_dev(dev, fn, iodev->si_open->sf_cd,
	    &iodev->si_avail, &iodev->si_pend, av, flag, iodev));
}


/*
 * static int
 * _nsc_attach_dev (nsc_dev_t *dev, int flag)
 *	Attach device to node.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the attach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Attach the device to the current node.
 */
static int
_nsc_attach_dev(dev, flag)
nsc_dev_t *dev;
int flag;
{
	if (dev->nsc_pend) {
		if (flag & NSC_TRY)
			return (EAGAIN);
		return (_nsc_wait_dev(dev, flag));
	}

	return (0);
}


/*
 * int
 * _nsc_detach_dev (nsc_dev_t *dev, nsc_iodev_t *keep, int flag)
 *	Detach device.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 *	Returns 0 if the detach succeeds without releasing
 *	the device lock, otherwise returns an error code.
 *
 * Description:
 *	Detach the device except for I/O descriptor keep.
 *	If flag specifies read access then flush is called
 *	in preference to detach. If appropriate the device
 *	will be released for use by another node.
 *
 *	All I/O devices are detached regardless of the
 *	current owner as a sanity check.
 */
int
_nsc_detach_dev(nsc_dev_t *dev, nsc_iodev_t *keep, int flag)
{
	nsc_iodev_t *iodev;
	int rc = 0;

	if (dev->nsc_pend) {
		if (flag & NSC_TRY)
			return (EAGAIN);
		return (_nsc_wait_dev(dev, flag));
	}

	dev->nsc_rpend++;

	for (iodev = dev->nsc_list; iodev; iodev = iodev->si_next) {
		if (iodev == keep)
			continue;
		if (iodev->si_io->flag & NSC_FILTER)
			continue;

		if ((rc = _nsc_detach_iodev(iodev, NULL, flag)) != 0)
			break;
	}

	_nsc_wake_dev(dev, &dev->nsc_rpend);

	if (keep || !(flag & NSC_WRITE))
		return (rc);
	if (rc == EAGAIN || rc == ERESTART)
		return (rc);

	dev->nsc_drop = 0;

	return (rc);
}


/*
 * static int
 * _nsc_call_dev (nsc_dev_t *dev, blindfn_t fn, blind_t arg,
 *    *int *ap, int *pp, int a, int flag, nsc_iodev_t *iodev)
 *	Call attach/detach function.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to this
 *	this function.
 *
 *	Returns an error code if the operation failed,
 *	otherwise returns ERESTART to indicate that the
 *	device state has changed.
 *
 *	The flags pointed to by ap are updated to reflect
 *	availability based upon argument a. The pending
 *	flag pointed to by pp is set whilst the operation
 *	is in progress.
 *
 * Description:
 *	Marks the device busy, temporarily releases the
 *	device lock and calls the specified function with
 *	the given argument.
 *
 *	If a detach is being performed then clear _NSC_ATTACH
 *	first to prevent pinned data callbacks. If the detach
 *	fails then clear _NSC_PINNED and indicate that a flush
 *	is required by setting NSC_READ.
 */
static int
_nsc_call_dev(nsc_dev_t *dev, blindfn_t fn, blind_t arg, int *ap, int *pp,
		int a, int flag, nsc_iodev_t *iodev)
{
	int rc = 0, v = *ap;

	if (flag & NSC_NOBLOCK)
		if (fn != nsc_null)
			return (EAGAIN);

	if (!a && v)
		*ap = (v & ~_NSC_ATTACH) | NSC_READ;

	if (fn != nsc_null) {
		*pp = (a) ? a : _NSC_DETACH;
		mutex_exit(&dev->nsc_lock);

		rc = (*fn)(arg, iodev);

		mutex_enter(&dev->nsc_lock);
		*pp = 0;
	}

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	if (rc) {
		if (!a && v)
			a = (v & ~_NSC_PINNED) | NSC_READ;
		else if (v & _NSC_ATTACH)
			a = v;
		else
			a = 0;
	}

	*ap = a;
	return (rc ? rc : ERESTART);
}


/*
 * int
 * _nsc_wait_dev (nsc_dev_t *dev, int flag)
 *	Wait for device state to change.
 *
 * Calling/Exit State:
 *	Must be called with the device lock held.
 *	Returns EAGAIN if NSC_NOBLOCK or NSC_NOWAIT is set,
 *	or EINTR if the wait was interrupted, otherwise
 *	returns ERESTART to indicate that the device state
 *	has changed.
 *
 * Description:
 *	Waits for the device state to change before resuming.
 *
 * Remarks:
 *	If the reference count on the device has dropped to
 *	zero then cv_broadcast is called to wakeup _nsc_free_dev.
 */
int
_nsc_wait_dev(dev, flag)
nsc_dev_t *dev;
int flag;
{
	int rc = 1;

	if (flag & (NSC_NOBLOCK | NSC_NOWAIT))
		return (EAGAIN);

	dev->nsc_wait++;

	if (flag & NSC_PCATCH)
		rc = cv_wait_sig(&dev->nsc_cv, &dev->nsc_lock);
	else
		cv_wait(&dev->nsc_cv, &dev->nsc_lock);

	dev->nsc_wait--;

	if (dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);

	return ((rc == 0) ? EINTR : ERESTART);
}


/*
 * void
 * _nsc_wake_dev (nsc_dev_t *dev, int *valp)
 *	Decrement value and wakeup device.
 *
 * Calling/Exit State:
 *	The device lock must be held across calls to
 *	this function.
 *
 * Description:
 *	Decrements the indicated value and if appropriate
 *	wakes up anybody waiting on the device.
 */
void
_nsc_wake_dev(dev, valp)
nsc_dev_t *dev;
int *valp;
{
	if (--(*valp))
		return;

	if (dev->nsc_wait || dev->nsc_refcnt <= 0)
		cv_broadcast(&dev->nsc_cv);
}

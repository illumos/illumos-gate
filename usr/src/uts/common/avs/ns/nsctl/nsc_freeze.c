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
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include "nsc_dev.h"
#include "../nsctl.h"

/*
 * (Un)Freeze Module
 *
 * This module provides a means to 'freeze' a device and ensure
 * that no SP software has an open reference to that device.  Later
 * the device can be 'unfrozen' and the SP software can resume
 * normal operations.
 *
 * This module is required because it is possible to place a virtual
 * volume driver (RAID-0, 1 or 5) into a state whereby it needs to be
 * disabled for corrective action.  The (un)freeze facility provides a
 * method of doing this without downtime.
 *
 * A device that is frozen should be frozen on all nodes.  It is the
 * responsibility of the management software or the user to perform
 * the freeze and unfreeze on the required nodes.
 */

extern nsc_mem_t *_nsc_local_mem;

typedef struct _nsc_frz_s {
	struct _nsc_frz_s	*next;
	nsc_path_t		*token;
	char			path[NSC_MAXPATH];
} _nsc_frz_t;


extern int _nsc_frz_stop(char *, int *);		/* forward decl */

static _nsc_frz_t *_nsc_frz_top;
static nsc_def_t _nsc_frz_def[];
static kmutex_t _nsc_frz_sleep;
static nsc_io_t *_nsc_frz_io;


void
_nsc_init_frz(void)
{
	mutex_init(&_nsc_frz_sleep, NULL, MUTEX_DRIVER, NULL);

	_nsc_frz_io = nsc_register_io("frz",
			NSC_FREEZE_ID | NSC_FILTER, _nsc_frz_def);

	if (!_nsc_frz_io)
		cmn_err(CE_WARN, "nsctl: _nsc_init_frz: register failed");
}


void
_nsc_deinit_frz(void)
{
	if (_nsc_frz_io)
		(void) nsc_unregister_io(_nsc_frz_io, 0);

	_nsc_frz_io = NULL;

	mutex_destroy(&_nsc_frz_sleep);
}


/*
 * int _nsc_frz_start(char *path, int *rvp)
 *	Freeze a device
 *
 * Calling/Exit State:
 *	Must be called from a context that can block.
 *	Returns 0 for success, or one of the following error codes:
 *		EINVAL   - invalid 'path' argument
 *		ENOMEM   - failed to allocate memory
 *		EALREADY - 'path' is already frozen
 *
 * Description:
 *	Registers 'path' to be accessed through the NSC_FREEZE_ID
 *	io module, and forces any open file descriptors for 'path'
 *	to be re-opened as appropriate.
 */
int
_nsc_frz_start(path, rvp)
char *path;
int *rvp;
{
	_nsc_frz_t *frz, *xfrz;
	int rc;

	*rvp = 0;

	if (strlen(path) >= NSC_MAXPATH)
		return (EINVAL);

	frz = nsc_kmem_zalloc(sizeof (*frz), KM_SLEEP, _nsc_local_mem);
	if (!frz)
		return (ENOMEM);

	(void) strcpy(frz->path, path);

	mutex_enter(&_nsc_frz_sleep);

	for (xfrz = _nsc_frz_top; xfrz; xfrz = xfrz->next)
		if (strcmp(frz->path, xfrz->path) == 0)
			break;

	if (!xfrz) {
		frz->next = _nsc_frz_top;
		_nsc_frz_top = frz;
	}

	mutex_exit(&_nsc_frz_sleep);

	if (xfrz) {
		nsc_kmem_free(frz, sizeof (*frz));
		return (EALREADY);
	}

	frz->token = nsc_register_path(path, NSC_DEVICE, _nsc_frz_io);

	if (!frz->token) {
		(void) _nsc_frz_stop(path, &rc);
		return (EINVAL);
	}

	return (0);
}


/*
 * int _nsc_frz_stop(char *path, int *rvp)
 *	Unfreeze a device
 *
 * Calling/Exit State:
 *	Must be called from a context that can block.
 *	Returns 0 or an error code.
 *
 * Description:
 *	Removes the path registration for the NSC_FREEZE_ID io module
 *	and forces any re-opens as appropriate.
 */
int
_nsc_frz_stop(path, rvp)
char *path;
int *rvp;
{
	_nsc_frz_t **xfrz, *frz = NULL;
	int rc = 0;

	*rvp = 0;

	mutex_enter(&_nsc_frz_sleep);

	for (xfrz = &_nsc_frz_top; *xfrz; xfrz = &(*xfrz)->next)
		if (strcmp(path, (*xfrz)->path) == 0) {
			frz = *xfrz;
			break;
		}

	if (!frz) {
		mutex_exit(&_nsc_frz_sleep);
		return (EINVAL);
	}

	if (frz->token)
		rc = nsc_unregister_path(frz->token, NSC_PCATCH);

	if (rc) {
		mutex_exit(&_nsc_frz_sleep);
		return (rc);
	}

	(*xfrz) = frz->next;

	mutex_exit(&_nsc_frz_sleep);

	nsc_kmem_free(frz, sizeof (*frz));

	return (0);
}


/*
 * int _nsc_frz_isfrozen(char *path, int *rvp)
 *	Tests whether a device is frozen.
 *
 * Calling/Exit State:
 *	Returns 0 or EINVAL.
 *	Sets *rvp to 1 if the device was not frozen, and 0 otherwise.
 *	This function returns historical information.
 */
int
_nsc_frz_isfrozen(path, rvp)
char *path;
int *rvp;
{
	_nsc_frz_t *frz;

	*rvp = 1;

	if (! _nsc_frz_io)
		return (EINVAL);

	mutex_enter(&_nsc_frz_sleep);

	for (frz = _nsc_frz_top; frz; frz = frz->next)
		if (strcmp(frz->path, path) == 0) {
			*rvp = 0;
			break;
		}

	mutex_exit(&_nsc_frz_sleep);

	return (0);
}


/*
 * static int
 * _nsc_frz_open(char *path, int flag, blind_t *cdp)
 *	Dummy open function.
 *
 * Description:
 *	This is the "Open" function for the I/O module.
 *	It is just a dummy.
 */

/* ARGSUSED */

static int
_nsc_frz_open(path, flag, cdp)
char *path;
int flag;
blind_t *cdp;
{
	*cdp = 0;
	return (0);
}


/*
 * static int
 * _nsc_frz_close()
 *	Dummy close function.
 *
 * Description:
 *	This is the "Close" function for the I/O module.
 *	It is just a dummy.
 */
static int
_nsc_frz_close() { return (0); }


/*
 * static int
 * _nsc_frz_attach()
 *	Attach a device to this i/o module.
 *
 * Calling/Exit State:
 *	Returns EACCES in all cricumstances.
 *
 * Description:
 *	This function is called by the nsctl module when it wishes
 *	to attach the device to this I/O module (ie. as part of
 *	nsc_reserve() processing).  This function unconditionally
 *	returns an error which forces the nsc_reserve() to fail, and
 *	so no access to possible to the underlying device.
 */
static int
_nsc_frz_attach() { return (EACCES); }


static nsc_def_t _nsc_frz_def[] = {
	"Open",		(uintptr_t)_nsc_frz_open,		0,
	"Close",	(uintptr_t)_nsc_frz_close,		0,
	"Attach",	(uintptr_t)_nsc_frz_attach,		0,
	"Provide",	0,				0,
	0,		0,				0
};

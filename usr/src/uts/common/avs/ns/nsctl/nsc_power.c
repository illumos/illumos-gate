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
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>

#define	__NSC_GEN__
#include "nsc_dev.h"
#include "nsc_ioctl.h"
#include "nsc_power.h"
#include "../nsctl.h"

extern nsc_mem_t *_nsc_local_mem;
static  int null_power(void);


typedef struct _nsc_power_s {
	struct _nsc_power_s *next;	/* chain */
	char *name;			/* module name */
	void (*pw_power_lost)(int);	/* callback power lost(rideout) */
	void (*pw_power_ok)(void);	/* callback power ok */
	void (*pw_power_down)(void);
				/* callback power down (shutdown imminent) */
} _nsc_power_t;

#define	_P(x)	(((long)(&((_nsc_power_t *)0)->x))/sizeof (long))

static nsc_def_t _nsc_power_def[] = {
	"Power_Lost",	(uintptr_t)null_power,	_P(pw_power_lost),
	"Power_OK",	(uintptr_t)null_power,	_P(pw_power_ok),
	"Power_Down",	(uintptr_t)null_power,	_P(pw_power_down),
	0,		0,			0,
};

static _nsc_power_t *_power_clients;
static kmutex_t _power_mutex;


static int null_power(void)
/*
 * init null_power - dummy power routine for clients that choose not
 * to implement all the power hooks.
 *
 */
{
	return (0);
}

/*
 * int
 * _nsc_power
 *	Call registered clients of the generic power ioctls.
 *
 * Calling/Exit State:
 *	Calls all the registered clients with a message describing the
 *      current state of the power for the system.
 */
int
_nsc_power(blind_t argp, int *rvp)
{
	nsc_power_ctl_t opc;
	_nsc_power_t *pp;

	*rvp = 0;
	if (copyin((void *) argp, &opc, sizeof (nsc_power_ctl_t)))
		return (EFAULT);
	mutex_enter(&_power_mutex);

	pp = _power_clients;
	while (pp) {
		switch ((nsc_power_ops_t)opc.msg) {

	case Power_OK:
			(*pp->pw_power_ok)();
			break;

	case Power_Down:
			(*pp->pw_power_down)();
			break;

	case Power_Lost:
			(*pp->pw_power_lost)(opc.arg1);
			break;

	default:
			mutex_exit(&_power_mutex);
			return (EINVAL);
		}

		pp = pp->next;
	}
	mutex_exit(&_power_mutex);
	return (0);
}

/*
 * int
 * _nsc_init_power (void)
 *	Initialise power ioctl subsystem.
 *
 * Calling/Exit State:
 *	Called at driver initialisation time to allocate necessary
 *	data structures.
 */
int
_nsc_init_power(void)
{
	mutex_init(&_power_mutex, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

/*
 * int
 * _nsc_deinit_power (void)
 *	Initialise power ioctl subsystem.
 *
 * Calling/Exit State:
 *	Called at driver initialisation time to allocate necessary
 *	data structures.
 */
int
_nsc_deinit_power(void)
{
	_nsc_power_t *pp, *npp;

	mutex_enter(&_power_mutex);
	pp = _power_clients;
	while (pp) {
		npp = pp->next;
		nsc_kmem_free(pp, sizeof (_nsc_power_t));
		pp = npp;
	}
	_power_clients = NULL;
	mutex_exit(&_power_mutex);
	mutex_destroy(&_power_mutex);
	return (0);
}

/*
 * blind_t
 * nsc_register_power (char *name, nsc_def_t *def)
 *	Register an power ioctl client.
 *
 * Calling/Exit State:
 *	Returns a token for use in future calls to nsc_unregister_power.
 *      If a client with the same name is already registered then NULL
 *      is return to indicate failure.
 *	If registration fails NULL is returned.
 *
 * Description:
 *	Registers an power ioctl client for notifications during subsequent
 *      ioctl from UPS/PCU management.
 */
blind_t
nsc_register_power(char *name, nsc_def_t *def)
{
	_nsc_power_t *entry, *pp;


	entry = nsc_kmem_alloc(sizeof (_nsc_power_t), 0, _nsc_local_mem);

	if (entry == NULL)
		return (NULL);
	nsc_decode_param(def, _nsc_power_def, (long *)entry);

	mutex_enter(&_power_mutex);

	for (pp = _power_clients; pp; pp = pp->next) {
		if (strcmp(pp->name, name) == 0) {
			mutex_exit(&_power_mutex);
			nsc_kmem_free(entry, sizeof (_nsc_power_t));
			return (NULL);
		}
	}
	entry->name = name;

	entry->next = _power_clients;
	_power_clients = entry;
	mutex_exit(&_power_mutex);
	return ((blind_t)entry);
}

/*
 * int
 * nsc_unregister_power (blind_t powerp)
 *	Un-register a power ioctl client.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise returns an error code.
 *
 * Description:
 *	The specified power ioctl client is un-registered if possible.
 *      Zero is returned on success otherwise an error code.
 */
int
nsc_unregister_power(blind_t powerp)
{
	_nsc_power_t **xpp, *entry;

	entry = (_nsc_power_t *)powerp;
	if (entry == NULL)
		return (EINVAL);

	mutex_enter(&_power_mutex);

	for (xpp = &_power_clients; *xpp; xpp = &(*xpp)->next)
		if (*xpp == entry)
			break;

	if (*xpp == NULL) {
		mutex_exit(&_power_mutex);
		return (EALREADY);
	}
	*xpp = entry->next;
	mutex_exit(&_power_mutex);
	nsc_kmem_free(entry, sizeof (_nsc_power_t));

	return (0);
}

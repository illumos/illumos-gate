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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "synonyms.h"
#include <sys/types.h>
#include <sys/procset.h>
#include <sys/priocntl.h>
#include <stdarg.h>
#include <errno.h>

/*
 * The declarations of __priocntlset() and __priocntl() were in prior releases
 * in <sys/priocntl.h>.  They are used to define PC_VERSION at compile time,
 * based on the contents of the header file.  This behavior is now changed.
 * Old binaries call __priocntl() and __priocntlset() instead of priocntl()
 * and priocntlset().  New binaries call priocntl() and priocntlset().
 */

/*
 * defined in priocntlset.s
 */
extern long __priocntlset(int, procset_t *, int, caddr_t, ...);

static int pc_vaargs2parms(va_list valist, pc_vaparms_t *vp);

long
__priocntl(int pc_version, idtype_t idtype, id_t id, int cmd, caddr_t arg)
{
	procset_t	procset;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);

	return (__priocntlset(pc_version, &procset, cmd, arg, 0));
}

/*
 * Internally to libc, we call this function rather than priocntl()
 * when the cmd is not PC_GETXPARMS or PC_SETXPARMS.  We do this
 * for the sake of calling common code in various places.  One of
 * these places is in spawn() and spawnp(), where we must not call
 * any function that is exported from libc while in the child of vfork().
 */
long
_private_priocntl(idtype_t idtype, id_t id, int cmd, void *arg)
{
	extern long _private__priocntlset(int, procset_t *, int, caddr_t, ...);
	procset_t procset;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);
	return (_private__priocntlset(PC_VERSION, &procset, cmd, arg, 0));
}


/*VARARGS3*/
long
priocntl(idtype_t idtype, id_t id, int cmd, ...)
{
	procset_t	procset;
	va_list		valist;
	pc_vaparms_t	varparms;
	caddr_t		arg;
	int		error;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);

	va_start(valist, cmd);
	arg = va_arg(valist, caddr_t);

	if (cmd != PC_GETXPARMS && cmd != PC_SETXPARMS) {
		va_end(valist);
		return (__priocntlset(PC_VERSION, &procset, cmd, arg, 0));
	}

	error = pc_vaargs2parms(valist, &varparms);
	va_end(valist);

	if (error) {
		errno = error;
		return (-1);
	}

	return (__priocntlset(PC_VERSION, &procset, cmd, arg, &varparms));
}


/*VARARGS2*/
long
priocntlset(procset_t *procsetp, int cmd, ...)
{
	va_list		valist;
	pc_vaparms_t	varparms;
	caddr_t		arg;
	int		error;

	va_start(valist, cmd);
	arg = va_arg(valist, caddr_t);

	if (cmd != PC_GETXPARMS && cmd != PC_SETXPARMS) {
		va_end(valist);
		return (__priocntlset(PC_VERSION, procsetp, cmd, arg, 0));
	}

	error = pc_vaargs2parms(valist, &varparms);
	va_end(valist);

	if (error) {
		errno = error;
		return (-1);
	}

	return (__priocntlset(PC_VERSION, procsetp, cmd, arg, &varparms));
}


static int
pc_vaargs2parms(va_list valist, pc_vaparms_t *vp)
{
	pc_vaparm_t	*vpp = &vp->pc_parms[0];
	int		key;

	for (vp->pc_vaparmscnt = 0;
	    (key = va_arg(valist, int)) != PC_KY_NULL; vpp++) {
		if (++vp->pc_vaparmscnt > PC_VAPARMCNT)
			return (EINVAL);

		vpp->pc_key = key;
		vpp->pc_parm = va_arg(valist, uintptr_t);
	}

	return (0);
}

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

#pragma weak _getacct = getacct
#pragma weak _putacct = putacct
#pragma weak _wracct = wracct

#include "lint.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/procset.h>

size_t
getacct(idtype_t idtype, id_t id, void *buf, size_t bufsize)
{
	sysret_t rval;
	int error;

	error = __systemcall(&rval, SYS_exacctsys,
	    0, idtype, id, buf, bufsize, 0);
	if (error)
		(void) __set_errno(error);
	return ((size_t)rval.sys_rval1);
}

int
putacct(idtype_t idtype, id_t id, void *buf, size_t bufsize, int flags)
{
	return (syscall(SYS_exacctsys, 1, idtype, id, buf, bufsize, flags));
}

int
wracct(idtype_t idtype, id_t id, int flags)
{
	return (syscall(SYS_exacctsys, 2, idtype, id, NULL, 0, flags));
}

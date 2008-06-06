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

#pragma weak _setppriv = setppriv
#pragma weak _getppriv = getppriv
#pragma weak _setpflags = setpflags
#pragma weak _getpflags = getpflags

#include "lint.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include "priv_private.h"
#include <priv.h>

int
setppriv(priv_op_t op, priv_ptype_t type, const priv_set_t *pset)
{
	priv_data_t *d;
	int set;

	LOADPRIVDATA(d);

	set = priv_getsetbyname(type);

	return (syscall(SYS_privsys, PRIVSYS_SETPPRIV, op, set, (void *)pset,
	    d->pd_setsize));
}

int
getppriv(priv_ptype_t type, priv_set_t *pset)
{
	priv_data_t *d;
	int set;

	LOADPRIVDATA(d);

	set = priv_getsetbyname(type);

	return (syscall(SYS_privsys, PRIVSYS_GETPPRIV, 0, set, (void *)pset,
	    d->pd_setsize));
}

int
getprivinfo(priv_impl_info_t *buf, size_t bufsize)
{
	return (syscall(SYS_privsys, PRIVSYS_GETIMPLINFO, 0, 0, (void *)buf,
	    bufsize));
}

int
setpflags(uint_t flag, uint_t val)
{
	return (syscall(SYS_privsys, PRIVSYS_SETPFLAGS, (priv_op_t)flag,
	    (priv_ptype_t)(uintptr_t)val, 0, 0));
}

uint_t
getpflags(uint_t flag)
{
	return (syscall(SYS_privsys, PRIVSYS_GETPFLAGS, flag, 0, 0, 0));
}

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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/lx_types.h>
#include <unistd.h>

/*
 * The lx brand cannot support the setfs[ug]id16/setfs[ug]id calls as that
 * would require significant rework of Solaris' privilege mechanisms, so
 * instead return the current effective [ug]id.
 *
 * In Linux, fsids track effective IDs, so returning the effective IDs works
 * as a substitute; returning the current value also denotes failure of the
 * call if the caller had specified something different.  We don't need to
 * worry about setting error codes because the Linux calls don't set any.
 */
/*ARGSUSED*/
long
lx_setfsuid16(uintptr_t fsuid16)
{
	return ((int)LX_UID32_TO_UID16(geteuid()));
}

/*ARGSUSED*/
long
lx_setfsgid16(uintptr_t fsgid16)
{
	return ((int)LX_GID32_TO_GID16(getegid()));
}

/*ARGSUSED*/
long
lx_setfsuid(uintptr_t fsuid)
{
	return (geteuid());
}

/*ARGSUSED*/
long
lx_setfsgid(uintptr_t fsgid)
{
	return (getegid());
}

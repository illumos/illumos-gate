/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * We've cleverly designed things such that an #include of <sys/stat.h>
 * on Intel brings in stat_impl.h, which defines *static* copies of
 * the stat, lstat, and fstat functions, all of which call _xstat.  It
 * also triggers the generation of a static copy of mknod, which calls
 * _xmknod.
 */

#include <sys/stat.h>
#include <errno.h>

/*ARGSUSED*/
int
_fxstat(const int ver, int fd, struct stat *st)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
_xstat(const int ver, const char *path, struct stat *st)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
_lxstat(const int ver, const char *path, struct stat *st)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
_xmknod(const int ver, const char *path, mode_t mode, dev_t dev)
{
	return (EINVAL);
}

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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak fchownat = _fchownat
#pragma weak renameat = _renameat
#pragma weak futimesat = _futimesat
#pragma weak unlinkat = _unlinkat

#include "synonyms.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>

int
fchownat(int fd, const char *name, uid_t uid, gid_t gid, int flags)
{
	return (syscall(SYS_fsat, 4, fd, name, uid, gid, flags));
}

int
unlinkat(int fd, const char *name, int flags)
{
	return (syscall(SYS_fsat, 5, fd, name, flags));
}

int
futimesat(int fd, const char *name, const struct timeval *tv)
{
	return (syscall(SYS_fsat, 6, fd, name, tv));
}

int
renameat(int fromfd, const char *fromname, int tofd, const char *toname)
{
	return (syscall(SYS_fsat, 7, fromfd, fromname, tofd, toname));
}

int
__openattrdirat(int fd, const char *name)
{
	return (syscall(SYS_fsat, 9, fd, name));
}

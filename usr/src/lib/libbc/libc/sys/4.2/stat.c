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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "chkpath.h"
#include <sys/stat.h>

extern int errno;

int stat(path, buf)
char *path;
struct stat *buf;
{
	return(bc_stat(path, buf));
}


int bc_stat(path, buf)
char *path;
struct stat *buf;
{
	if ((path == (char*)-1) || (path == (char*)0)) {
		errno = EFAULT;
		return (-1);
	}
	if ((buf == (struct stat*)0) || (buf == (struct stat*)-1)) {
		errno = EFAULT;
		return (-1);
	}
	return(stat_com(0, path, buf));
}


int lstat(path, buf)
char *path;
struct stat *buf;
{
	return(bc_lstat(path, buf));
}

int bc_lstat(path, buf)
char *path;
struct stat *buf;
{
	CHKNULL(path);
	return(stat_com(1, path, buf));
}


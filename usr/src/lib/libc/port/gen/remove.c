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
#include <sys/stat.h>
#include <unistd.h>
#include "libc.h"

int
remove(const char *filename)
{
	struct stat64	statb;

	/*
	 * If filename is not a directory, call unlink(filename)
	 * Otherwise, call rmdir(filename)
	 */

	if (lstat64(filename, &statb) != 0)
		return (-1);
	if ((statb.st_mode & S_IFMT) != S_IFDIR)
		return (unlink(filename));
	return (rmdir(filename));
}

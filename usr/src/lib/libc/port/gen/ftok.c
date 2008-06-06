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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _ftok = ftok

#include "lint.h"
#include "libc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/nvpair.h>
#include <fcntl.h>
#include <attr.h>

key_t
ftok(const char *path, int id)
{
	struct stat64 st;
	nvlist_t *nvp;
	uint32_t devpiece;
	int error;

	if (stat64(path, &st) < 0)
		return ((key_t)-1);

	/*
	 * if getattrat works then extract the FSID from the nvlist
	 * otherwise, just fall back and use the value from the stat data
	 */
	if ((error = getattrat(AT_FDCWD, XATTR_VIEW_READONLY,
	    path, &nvp)) == 0) {
		uint64_t value;

		if ((error = libc_nvlist_lookup_uint64(nvp,
		    A_FSID, &value)) == 0)
			devpiece = value & 0xfff;
		libc_nvlist_free(nvp);
	}

	if (error)
		devpiece = st.st_dev & 0xfff;

	return ((key_t)((key_t)id << 24 | devpiece << 12 |
	    ((uint32_t)st.st_ino & 0x0fff)));
}

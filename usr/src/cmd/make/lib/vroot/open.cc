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
 * Copyright 1993 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern int open(const char *path, int oflag, ...);

#include <vroot/vroot.h>
#include <vroot/args.h>

static int	open_thunk(char *path)
{
	vroot_result= open(path, vroot_args.open.flags, vroot_args.open.mode);
	return(vroot_result >= 0);
}

int	open_vroot(char *path, int flags, int mode, pathpt vroot_path, pathpt vroot_vroot)
{
	vroot_args.open.flags= flags;
	vroot_args.open.mode= mode;
	translate_with_thunk(path, open_thunk, vroot_path, vroot_vroot,
				((flags & (O_CREAT|O_APPEND)) != 0) ? rw_write : rw_read);
	return(vroot_result);
}

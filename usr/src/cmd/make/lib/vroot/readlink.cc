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


#include <unistd.h>

extern int readlink(const char *path, void *buf, size_t bufsiz);

#include <vroot/vroot.h>
#include <vroot/args.h>

static int	readlink_thunk(char *path)
{
	vroot_result= readlink(path, vroot_args.readlink.buffer, vroot_args.readlink.buffer_size);
	return(vroot_result >= 0);
}

int	readlink_vroot(char *path, char *buffer, int buffer_size, pathpt vroot_path, pathpt vroot_vroot)
{
	vroot_args.readlink.buffer= buffer;
	vroot_args.readlink.buffer_size= buffer_size;
	translate_with_thunk(path, readlink_thunk, vroot_path, vroot_vroot, rw_read);
	return(vroot_result);
}

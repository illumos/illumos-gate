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
 * Copyright 1999 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _ARGS_H_
#define _ARGS_H_

#include <sys/syscall.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

typedef enum { rw_read, rw_write} rwt, *rwpt;

extern	void	translate_with_thunk(register char *filename, int (*thunk) (char *), pathpt path_vector, pathpt vroot_vector, rwt rw);

union Args {
	struct { int mode;} access;
	struct { int mode;} chmod;
	struct { int user; int group;} chown;
	struct { int mode;} creat;
	struct { char **argv; char **environ;} execve;
	struct { struct stat *buffer;} lstat;
	struct { int mode;} mkdir;
	struct { char *name; int mode;} mount;
	struct { int flags; int mode;} open;
	struct { char *buffer; int buffer_size;} readlink;
	struct { struct stat *buffer;} stat;
	struct { int length;} truncate;
	struct { struct timeval *time;} utimes;
};

extern	union Args	vroot_args;
extern	int		vroot_result;

#endif

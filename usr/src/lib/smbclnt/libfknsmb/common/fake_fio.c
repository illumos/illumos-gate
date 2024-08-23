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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent Inc.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved */

/*
 * The kTLI "shim"  in fake_ktli.c uses file_getf(), file_releasef() to
 * get a file_t pointer, and uses the (private) file_getfd() to access
 * the socket file descriptor behind that file_t (which is actually a
 * fake_file_t created here).  These correspond to getf/releasef that
 * are normally found in os/fio.c but renamed to avoid accidental use.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/debug.h>
#include <sys/kmem.h>

#include "fake_fio.h"

typedef struct fake_file {
	struct file ff_file;
	int	ff_fd;
} fake_file_t;

#define	FAKEFDS	256

kmutex_t ftlock;
fake_file_t *ftab[FAKEFDS];

file_t *
file_getf(int fd)
{
	fake_file_t *fp;

	if (fd < 0 || fd >= FAKEFDS)
		return (NULL);

	mutex_enter(&ftlock);
	if ((fp = ftab[fd]) != NULL) {
		fp->ff_file.f_count++;
		mutex_exit(&ftlock);
		return (&fp->ff_file);
	}

	fp = kmem_zalloc(sizeof (*fp), KM_SLEEP);
	fp->ff_fd = fd;
	fp->ff_file.f_count = 1;

	ftab[fd] = fp;
	mutex_exit(&ftlock);

	return (&fp->ff_file);
}

void
file_releasef(int fd)
{
	fake_file_t *fp;

	mutex_enter(&ftlock);
	if ((fp = ftab[fd]) == NULL) {
		mutex_exit(&ftlock);
		return;
	}
	fp->ff_file.f_count--;
	if (fp->ff_file.f_count > 0) {
		mutex_exit(&ftlock);
		return;
	}
	ftab[fd] = NULL;
	mutex_exit(&ftlock);

	kmem_free(fp, sizeof (*fp));
}

int
file_getfd(file_t *fp)
{
	fake_file_t *ffp = (fake_file_t *)fp;
	int fd = ffp->ff_fd;

	VERIFY(fd >= 0 && fd < FAKEFDS);
	ASSERT(ffp == ftab[fd]);

	return (fd);
}

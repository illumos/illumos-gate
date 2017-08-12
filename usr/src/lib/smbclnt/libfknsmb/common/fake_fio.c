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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved */

/*
 * The kTLI "shim" over in ./fake_ktli.c uses getf(), releasef() to
 * represent an open socket FD in "fake" vnode_t and file_t objects.
 * This implements minimal getf()/releasef() shims for that purpose.
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

#define	FAKEFDS	256

kmutex_t ftlock;
file_t *ftab[FAKEFDS];

file_t *
getf(int fd)
{
	file_t *fp;
	vnode_t *vp;

	if (fd >= FAKEFDS)
		return (NULL);

	mutex_enter(&ftlock);
	if ((fp = ftab[fd]) != NULL) {
		fp->f_count++;
		mutex_exit(&ftlock);
		return (fp);
	}

	fp = kmem_zalloc(sizeof (*fp), KM_SLEEP);
	vp = kmem_zalloc(sizeof (*vp), KM_SLEEP);
	vp->v_fd = fd;
	fp->f_vnode = vp;
	fp->f_count = 1;
	ftab[fd] = fp;

	mutex_exit(&ftlock);

	return (fp);
}

void
releasef(int fd)
{
	file_t *fp;
	vnode_t *vp;

	mutex_enter(&ftlock);
	if ((fp = ftab[fd]) == NULL) {
		mutex_exit(&ftlock);
		return;
	}
	fp->f_count--;
	if (fp->f_count > 0) {
		mutex_exit(&ftlock);
		return;
	}
	ftab[fd] = NULL;
	mutex_exit(&ftlock);

	vp = fp->f_vnode;
	kmem_free(vp, sizeof (*vp));
	kmem_free(fp, sizeof (*fp));
}

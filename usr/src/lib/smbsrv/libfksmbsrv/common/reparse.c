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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/nvpair.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <fs/fs_subr.h>
#include <fs/fs_reparse.h>


/*
 * support functions for reparse point
 * copied from uts/common/fs/fs_subr.c
 */

/*
 * reparse_vnode_parse
 *
 * Read the symlink data of a reparse point specified by the vnode
 * and return the reparse data as name-value pair in the nvlist.
 */
int
reparse_vnode_parse(vnode_t *vp, nvlist_t *nvl)
{
	int err;
	char *lkdata;
	struct uio uio;
	struct iovec iov;

	if (vp == NULL || nvl == NULL)
		return (EINVAL);

	lkdata = kmem_alloc(MAXREPARSELEN, KM_SLEEP);

	/*
	 * Set up io vector to read sym link data
	 */
	iov.iov_base = lkdata;
	iov.iov_len = MAXREPARSELEN;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = (offset_t)0;
	uio.uio_resid = MAXREPARSELEN;

	if ((err = VOP_READLINK(vp, &uio, zone_kcred(), NULL)) == 0) {
		*(lkdata + MAXREPARSELEN - uio.uio_resid) = '\0';
		err = reparse_parse(lkdata, nvl);
	}
	kmem_free(lkdata, MAXREPARSELEN);	/* done with lkdata */

	return (err);
}

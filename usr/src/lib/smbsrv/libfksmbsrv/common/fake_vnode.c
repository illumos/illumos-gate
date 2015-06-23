/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/t_lock.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/pathname.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>

#include <sys/acl.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>

/*
 * Are vp1 and vp2 the same vnode?
 */
int
vn_compare(vnode_t *vp1, vnode_t *vp2)
{
	vnode_t *realvp;

	if (vp1 != NULL && VOP_REALVP(vp1, &realvp, NULL) == 0)
		vp1 = realvp;
	if (vp2 != NULL && VOP_REALVP(vp2, &realvp, NULL) == 0)
		vp2 = realvp;
	return (VN_CMP(vp1, vp2));
}

/* ARGSUSED */
vfs_t *
vn_mountedvfs(vnode_t *vp)
{
	return (NULL);
}

void
xva_init(xvattr_t *xvap)
{
	bzero(xvap, sizeof (xvattr_t));
	xvap->xva_mapsize = XVA_MAPSIZE;
	xvap->xva_magic = XVA_MAGIC;
	xvap->xva_vattr.va_mask = AT_XVATTR;
	xvap->xva_rtnattrmapp = &(xvap->xva_rtnattrmap)[0];
}

/*
 * If AT_XVATTR is set, returns a pointer to the embedded xoptattr_t
 * structure.  Otherwise, returns NULL.
 */
xoptattr_t *
xva_getxoptattr(xvattr_t *xvap)
{
	xoptattr_t *xoap = NULL;
	if (xvap->xva_vattr.va_mask & AT_XVATTR)
		xoap = &xvap->xva_xoptattrs;
	return (xoap);
}

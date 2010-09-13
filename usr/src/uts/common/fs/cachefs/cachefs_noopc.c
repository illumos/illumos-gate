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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>

#include <sys/fs/cachefs_fs.h>

/*ARGSUSED*/
static int
c_nop_init_cached_object(fscache_t *fscp, cnode_t *cp, vattr_t *vap,
    cred_t *cr)
{
	int error;
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(cr != NULL);
	ASSERT(MUTEX_HELD(&cp->c_statelock));

	/* NFSv4 always sets strict consistency */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* if attributes not passed in then get them */
	if (vap == NULL) {
		/* if not connected then cannot get attrs */
		if ((fscp->fs_cdconnected != CFS_CD_CONNECTED) ||
		    (fscp->fs_backvfsp == NULL))
			return (ETIMEDOUT);

		/* get backvp if necessary */
		if (cp->c_backvp == NULL) {
			error = cachefs_getbackvp(fscp, cp);
			if (error)
				return (error);
		}

		/* get the attributes */
		cp->c_attr.va_mask = AT_ALL;
		ASSERT(cp->c_backvp != NULL);
		error = VOP_GETATTR(cp->c_backvp, &cp->c_attr, 0, cr, NULL);
		if (error)
			return (error);
	} else {
		/* copy passed in attributes into the cnode */
		cp->c_attr = *vap;
	}

	cp->c_size = cp->c_attr.va_size;
	mdp->md_consttype = CFS_FS_CONST_NOCONST;
	cp->c_flags |= CN_UPDATED;
	return (0);
}

/*ARGSUSED*/
static int
c_nop_check_cached_object(struct fscache *fscp, struct cnode *cp,
	int verify_what, cred_t *cr)
{
	struct vattr attrs;
	int fail = 0, backhit = 0;
	int error = 0;
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(cr);
	ASSERT(MUTEX_HELD(&cp->c_statelock));

	/* nothing to do if not connected */
	if ((fscp->fs_cdconnected != CFS_CD_CONNECTED) ||
	    (fscp->fs_backvfsp == NULL))
		goto out;

	/* done if do not have to check */
	if (((verify_what & C_BACK_CHECK) == 0) &&
	    ((mdp->md_flags & MD_NEEDATTRS) == 0))
		goto out;

	/* get backvp if necessary */
	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if (error)
			goto out;
	}

	/* get the file attributes from the back fs */
	attrs.va_mask = AT_ALL;
	error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
	backhit = 1;
	if (error)
		goto out;

	cp->c_attr = attrs;
	if (attrs.va_size > cp->c_size)
		cp->c_size = attrs.va_size;
	mdp->md_flags &= ~MD_NEEDATTRS;
	cachefs_cnode_setlocalstats(cp);
	cp->c_flags |= CN_UPDATED;

out:
	if (backhit != 0) {
		if (fail != 0)
			fscp->fs_stats.st_fails++;
		else
			fscp->fs_stats.st_passes++;
	}

	return (error);
}

static void
c_nop_modify_cached_object(struct fscache *fscp, struct cnode *cp, cred_t *cr)
{
	struct vattr attrs;
	int	error;
	nlink_t	nlink;
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(fscp->fs_cdconnected == CFS_CD_CONNECTED);
	ASSERT(fscp->fs_backvfsp);

	fscp->fs_stats.st_modifies++;

	/* from now on, make sure we're using the server's idea of time */
	mdp->md_flags &= ~(MD_LOCALCTIME | MD_LOCALMTIME);
	mdp->md_flags |= MD_NEEDATTRS;

	/* if in write-around mode, make sure file is nocached */
	if (CFS_ISFS_WRITE_AROUND(fscp)) {
		if ((cp->c_flags & CN_NOCACHE) == 0)
			cachefs_nocache(cp);
	}

	/* get the new attributes so we don't wait forever to get them */
	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if (error)
			return;
	}
	attrs.va_mask = AT_ALL;
	error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
	if (error)
		return;
	nlink = cp->c_attr.va_nlink;
	cp->c_attr = attrs;
	cp->c_attr.va_nlink = nlink;
	if ((attrs.va_size > cp->c_size) || !vn_has_cached_data(CTOV(cp)))
		cp->c_size = attrs.va_size;
	mdp->md_flags &= ~MD_NEEDATTRS;
	cachefs_cnode_setlocalstats(cp);
	cp->c_flags |= CN_UPDATED;
}

/*ARGSUSED*/
static void
c_nop_invalidate_cached_object(struct fscache *fscp, struct cnode *cp,
	cred_t *cr)
{
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	mdp->md_flags |= MD_NEEDATTRS;
	cp->c_flags |= CN_UPDATED;
}

/*ARGSUSED*/
static void
c_nop_convert_cached_object(struct fscache *fscp, struct cnode *cp,
	cred_t *cr)
{
	cachefs_metadata_t *mdp = &cp->c_metadata;
	mdp->md_flags |= MD_NEEDATTRS;
	mdp->md_consttype = CFS_FS_CONST_NOCONST;
	cp->c_flags |= CN_UPDATED;
}

struct cachefsops nopcfsops = {
	c_nop_init_cached_object,
	c_nop_check_cached_object,
	c_nop_modify_cached_object,
	c_nop_invalidate_cached_object,
	c_nop_convert_cached_object
};

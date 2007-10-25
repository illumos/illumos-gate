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
#include <netinet/in.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/fs/cachefs_fs.h>

#define	C_CACHE_VALID(SAVED_MTIME, NEW_MTIME)   \
	((SAVED_MTIME.tv_sec == NEW_MTIME.tv_sec) && \
		(SAVED_MTIME.tv_nsec == NEW_MTIME.tv_nsec))

static time_t cachefs_gettime_cached_object(struct fscache *fscp,
    struct cnode *cp, time_t mtime);

static int
c_strict_init_cached_object(fscache_t *fscp, cnode_t *cp, vattr_t *vap,
    cred_t *cr)
{
	int error;
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(cr);
	ASSERT(MUTEX_HELD(&cp->c_statelock));

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
		error = VOP_GETATTR(cp->c_backvp, &cp->c_attr, 0, cr, NULL);
		if (error)
			return (error);
	} else {
		/* copy passed in attributes into the cnode */
		cp->c_attr = *vap;
	}

	/*
	 * Expire time is based on the number of seconds since
	 * the last change.
	 * (i.e. files that changed recently are likely to change soon)
	 */
	mdp->md_x_time.tv_nsec = 0;
	mdp->md_x_time.tv_sec = cachefs_gettime_cached_object(fscp, cp,
		cp->c_attr.va_mtime.tv_sec);
	mdp->md_consttype = CFS_FS_CONST_STRICT;
	cp->c_size = cp->c_attr.va_size;
	cp->c_flags |= CN_UPDATED;

	return (0);
}

static int
c_strict_check_cached_object(struct fscache *fscp, struct cnode *cp,
	int verify_what, cred_t *cr)
{
	struct vattr attrs;
	int error = 0;
	int fail = 0, backhit = 0;
	cachefs_metadata_t *mdp = &cp->c_metadata;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VOPS)
		printf("c_strict_check_cached_object: ENTER cp %p\n",
		    (void *)cp);
#endif

	ASSERT(cr);
	ASSERT(MUTEX_HELD(&cp->c_statelock));

	if ((fscp->fs_cdconnected != CFS_CD_CONNECTED) ||
	    (fscp->fs_backvfsp == NULL))
		goto out;

	/*
	 * If backfs is NFSv4, do a getattr to update link count,
	 * all other attributes are not used, and the backfs is
	 * called on a getattr request.
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		backhit = 1;
		attrs.va_mask = AT_ALL;
		error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
		if (error)
			goto out;
		cp->c_attr = attrs;
		goto out;
	}

	/* done if do not have to check and time has not expired */
	if (((verify_what & C_BACK_CHECK) == 0) &&
	    (gethrestime_sec() < mdp->md_x_time.tv_sec) &&
	    ((mdp->md_flags & MD_NEEDATTRS) == 0))
		goto out;

	/* get backvp if necessary */
	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if (error)
			goto out;
	}

	/*
	 * If the cnode is being populated, and we're not the populating
	 * thread, then block until the pop thread completes.  If we are the
	 * pop thread, then we may come in here, but not to nuke the directory
	 * cnode at a critical juncture.
	 */
again:
	while ((cp->c_flags & CN_ASYNC_POP_WORKING) &&
	    (cp->c_popthrp != curthread)) {
		cv_wait(&cp->c_popcv, &cp->c_statelock);

		/*
		 * recheck backvp and connectivity - if backvp now null,
		 * something bad happened, so don't bother trying to 'get' it
		 */
		if ((cp->c_backvp == NULL) ||
			(fscp->fs_cdconnected != CFS_CD_CONNECTED) ||
			(fscp->fs_backvfsp == NULL)) {
			if (cp->c_flags | CN_STALE) {
				cp->c_flags |= CN_NOCACHE;
				error = ESTALE;
			}
			goto out;
		}
	}

	/* get the file attributes from the back fs */
	attrs.va_mask = AT_ALL;
	error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
	backhit = 1;
	if (error)
		goto out;

	/* if the mtime or size of the file has changed */
	if ((!C_CACHE_VALID(mdp->md_vattr.va_mtime, attrs.va_mtime) ||
	    (cp->c_size != attrs.va_size)) &&
	    ((mdp->md_flags & MD_NEEDATTRS) == 0)) {
		fail = 1;
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_INVALIDATE)
			printf("c_strict_check: invalidating %llu\n",
			    (u_longlong_t)cp->c_id.cid_fileno);
#endif
		if (vn_has_cached_data(CTOV(cp))) {
			mutex_exit(&cp->c_statelock);
			error = cachefs_putpage_common(CTOV(cp),
			    (offset_t)0, 0, B_INVAL, cr);
			mutex_enter(&cp->c_statelock);
			if (CFS_TIMEOUT(fscp, error))
				goto out;
			error = 0;
			/*
			 * if an async pop started while the lock was
			 * dropped, go back and try again
			 */
			if ((cp->c_flags & CN_ASYNC_POP_WORKING) &&
			    (cp->c_popthrp != curthread))
				goto again;
		}
		/*
		 * We should properly handle the CN_NOCACHE flag here.
		 * In fact, we should remember that cachefs_inval_object()
		 * forcibly sets/unsets the flag, so we should keep a
		 * state of the flag over the call.
		 */
		if ((cp->c_flags & CN_NOCACHE) == 0)
			cachefs_inval_object(cp);
		else {
			cachefs_inval_object(cp);
			cp->c_flags |= CN_NOCACHE;
		}
		if ((CTOV(cp))->v_type == VREG) {
			attrs.va_mask = AT_ALL;
			error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
			if (error)
				goto out;
		}
		if (!vn_has_cached_data(CTOV(cp))) {
			cp->c_size = attrs.va_size;
		}
#ifdef CFSDEBUG
		else {
			CFS_DEBUG(CFSDEBUG_VOPS)
				printf("c_strict_check: v_pages not null\n");
		}
#endif
	}

	/* toss cached acl info if ctime changed */
	if (!C_CACHE_VALID(mdp->md_vattr.va_ctime, attrs.va_ctime)) {
		cachefs_purgeacl(cp);
	}

	cp->c_attr = attrs;
	if (attrs.va_size > cp->c_size)
		cp->c_size = attrs.va_size;
	mdp->md_x_time.tv_sec =
	    cachefs_gettime_cached_object(fscp, cp, attrs.va_mtime.tv_sec);
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

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VOPS)
		printf("c_strict_check_cached_object: EXIT expires %lx\n",
			(long)mdp->md_x_time.tv_sec);
#endif
	return (error);
}

static void
c_strict_modify_cached_object(struct fscache *fscp, struct cnode *cp,
	cred_t *cr)
{
	struct vattr attrs;
	int error = 0;
	nlink_t nlink;
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(fscp->fs_cdconnected == CFS_CD_CONNECTED);
	ASSERT(fscp->fs_backvfsp);

	/*
	 * Don't do a getattr if NFSv4, which maintains
	 * its attributes (and link count) by doing a call
	 * to CFSOP_CHECK_COBJECT() during vnode operations.
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp))
		goto out;

	fscp->fs_stats.st_modifies++;

	/* from now on, make sure we're using the server's idea of time */
	mdp->md_flags &= ~(MD_LOCALCTIME | MD_LOCALMTIME);
	mdp->md_flags |= MD_NEEDATTRS;

	/* if in write-around mode, make sure file is nocached */
	if (CFS_ISFS_WRITE_AROUND(fscp)) {
		if ((cp->c_flags & CN_NOCACHE) == 0)
			cachefs_nocache(cp);

		/*
		 * If a directory, then defer getting the new attributes
		 * until requested.  Might be a little bit faster this way.
		 */
		if (CTOV(cp)->v_type == VDIR)
			goto out;
	}

	/* get the new mtime so the next call to check_cobject does not fail */
	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if (error) {
			mdp->md_vattr.va_mtime.tv_sec = 0;
			goto out;
		}
	}

	attrs.va_mask = AT_ALL;
	ASSERT(cp->c_backvp != NULL);
	error = VOP_GETATTR(cp->c_backvp, &attrs, 0, cr, NULL);
	if (error) {
		mdp->md_vattr.va_mtime.tv_sec = 0;
		goto out;
	}

	mdp->md_x_time.tv_sec =
	    cachefs_gettime_cached_object(fscp, cp, attrs.va_mtime.tv_sec);
	nlink = cp->c_attr.va_nlink;
	cp->c_attr = attrs;
	cp->c_attr.va_nlink = nlink;
	if ((attrs.va_size > cp->c_size) || !vn_has_cached_data(CTOV(cp)))
		cp->c_size = attrs.va_size;
	mdp->md_flags &= ~MD_NEEDATTRS;
	cachefs_cnode_setlocalstats(cp);
out:
	cp->c_flags |= CN_UPDATED;
}

/*ARGSUSED*/
static void
c_strict_invalidate_cached_object(struct fscache *fscp, struct cnode *cp,
	cred_t *cr)
{
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	mdp->md_vattr.va_mtime.tv_sec = 0;
	mdp->md_flags |= MD_NEEDATTRS;
	cp->c_flags |= CN_UPDATED;
}

/*ARGSUSED*/
static void
c_strict_convert_cached_object(struct fscache *fscp, struct cnode *cp,
	cred_t *cr)
{
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	mdp->md_flags |= MD_NEEDATTRS;
	mdp->md_consttype = CFS_FS_CONST_STRICT;
	cp->c_flags |= CN_UPDATED;
}

/*
 * Returns the tod in secs when the consistency of the object should
 * be checked.
 */
static time_t
cachefs_gettime_cached_object(struct fscache *fscp, struct cnode *cp,
	time_t mtime)
{
	time_t xsec;
	time_t acmin, acmax;
	time_t now;

	/*
	 * Expire time is based on the number of seconds since the last change
	 * (i.e. files that changed recently are likely to change soon),
	 */
	if ((CTOV(cp))->v_type == VDIR) {
		acmin = fscp->fs_acdirmin;
		acmax = fscp->fs_acdirmax;
	} else {
		acmin = fscp->fs_acregmin;
		acmax = fscp->fs_acregmax;
	}

	now = gethrestime_sec();
	xsec = now - mtime;
	xsec = MAX(xsec, acmin);
	xsec = MIN(xsec, acmax);
	xsec += now;
	return (xsec);
}

struct cachefsops strictcfsops = {
	c_strict_init_cached_object,
	c_strict_check_cached_object,
	c_strict_modify_cached_object,
	c_strict_invalidate_cached_object,
	c_strict_convert_cached_object
};

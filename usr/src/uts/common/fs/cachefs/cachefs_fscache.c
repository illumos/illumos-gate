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
#include <sys/file.h>
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
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/fbuf.h>
#include <rpc/types.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>

/* external references */
extern struct cachefsops nopcfsops, strictcfsops, codcfsops;

/* forward references */
int fscdir_create(cachefscache_t *cachep, char *namep, fscache_t *fscp);
int fscdir_find(cachefscache_t *cachep, ino64_t fsid, fscache_t *fscp);
static int fscache_info_sync(fscache_t *fscp);

struct kmem_cache *cachefs_fscache_cache = NULL;

/*
 * ------------------------------------------------------------------
 *
 *		fscache_create
 *
 * Description:
 *	Creates a fscache object.
 * Arguments:
 *	cachep		cache to create fscache object for
 * Returns:
 *	Returns a fscache object.
 * Preconditions:
 *	precond(cachep)
 */

fscache_t *
fscache_create(cachefscache_t *cachep)
{
	fscache_t *fscp;

	/* create and initialize the fscache object */
	fscp = kmem_cache_alloc(cachefs_fscache_cache, KM_SLEEP);

	bzero(fscp, sizeof (*fscp));

	mutex_init(&fscp->fs_fslock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&fscp->fs_idlelock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&fscp->fs_dlock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&fscp->fs_cdlock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&fscp->fs_cdwaitcv, NULL, CV_DEFAULT, NULL);

	fscp->fs_cache = cachep;
	fscp->fs_info.fi_mntflags = CFS_WRITE_AROUND;
	fscp->fs_info.fi_popsize = DEF_POP_SIZE;
	fscp->fs_info.fi_fgsize = DEF_FILEGRP_SIZE;
	fscp->fs_cfsops = &nopcfsops;
	fscp->fs_consttype = CFS_FS_CONST_NOCONST;
	fscp->fs_acregmin = 30;
	fscp->fs_acregmax = 30;
	fscp->fs_acdirmin = 30;
	fscp->fs_acdirmax = 30;
	fscp->fs_cdconnected = CFS_CD_CONNECTED;
	fscp->fs_mntpt = NULL;
	fscp->fs_hostname = NULL;
	fscp->fs_backfsname = NULL;
	cachefs_workq_init(&fscp->fs_workq);
	return (fscp);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_destroy
 *
 * Description:
 *	Destroys the fscache object.
 * Arguments:
 *	fscp	the fscache object to destroy
 * Returns:
 * Preconditions:
 *	precond(fscp)
 *	precond(fs_ref == 0)
 */

void
fscache_destroy(fscache_t *fscp)
{
	size_t strl;

	ASSERT(fscp->fs_ref == 0);

	(void) fscache_info_sync(fscp);

	if (fscp->fs_mntpt) {
		strl = strlen(fscp->fs_mntpt);
		if (strl != 0)
			kmem_free(fscp->fs_mntpt, strl + 1);
	}
	if (fscp->fs_hostname) {
		strl = strlen(fscp->fs_hostname);
		if (strl != 0)
			kmem_free(fscp->fs_hostname, strl + 1);
	}
	if (fscp->fs_backfsname) {
		strl = strlen(fscp->fs_backfsname);
		if (strl != 0)
			kmem_free(fscp->fs_backfsname, strl + 1);
	}

	/* drop the inum translation table */
	if (fscp->fs_inum_size > 0)
		cachefs_kmem_free(fscp->fs_inum_trans,
		    fscp->fs_inum_size * sizeof (cachefs_inum_trans_t));

	/* drop references to the fscache directory */
	if (fscp->fs_fscdirvp)
		VN_RELE(fscp->fs_fscdirvp);
	if (fscp->fs_fsattrdir)
		VN_RELE(fscp->fs_fsattrdir);
	if (fscp->fs_infovp)
		VN_RELE(fscp->fs_infovp);

	/* drop logging references */
	cachefs_dlog_teardown(fscp);

	mutex_destroy(&fscp->fs_fslock);
	mutex_destroy(&fscp->fs_idlelock);
	mutex_destroy(&fscp->fs_dlock);
	mutex_destroy(&fscp->fs_cdlock);
	cv_destroy(&fscp->fs_cdwaitcv);

	kmem_cache_free(cachefs_fscache_cache, fscp);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_setup
 *
 * Description:
 *	Activates a fscache by associating the fscache object
 *	with on disk data.
 *	If the fscache directory of the specified fsid exists then
 *	it will be used.
 *	Otherwise a new fscache directory will be created using namep
 *	and optp with fsid being ignored.  However if namep or optp
 *	are not NULL or the cache is in NOFILL then this routine fails.
 * Arguments:
 *	fscp	the fscache object to activate
 *	fsid	unique identifier for the cache
 *	namep	name of the cache
 *	optp	options for the cache
 * Returns:
 *	Returns 0 for success, !0 on failure.
 * Preconditions:
 *	precond(fscp)
 *	precond(the cache must not be in NOCACHE mode)
 *	precond(the cache must not alread by active)
 */

static int
fscache_setup(fscache_t *fscp, ino64_t fsid, char *namep,
    struct cachefsoptions *optp, ino64_t backfileno, int setflags)
{
	int error;
	cachefscache_t *cachep = fscp->fs_cache;

	ASSERT((cachep->c_flags & CACHE_NOCACHE) == 0);

	/* see if the fscache directory already exists */
	error =	fscdir_find(cachep, fsid, fscp);
	if (error) {
		/* return error if cannot create the directory */
		if ((namep == NULL) || (optp == NULL) ||
		    (cachep->c_flags & CACHE_NOFILL)) {
			return (error);
		}
		if (backfileno == 0)
			return (EAGAIN);

		/* remember the root back fileno for disconnected mounts */
		fscp->fs_info.fi_root = backfileno;

		/* copy options into the fscache */
		fscp->fs_info.fi_mntflags = optp->opt_flags;
		fscp->fs_info.fi_popsize = optp->opt_popsize;
		fscp->fs_info.fi_fgsize = optp->opt_fgsize;
		fscp->fs_flags |= CFS_FS_DIRTYINFO;

		/* create the directory */
		error = fscdir_create(cachep, namep, fscp);
		if (error) {
			if (error == ENOSPC)
				cmn_err(CE_WARN,
				    "CacheFS: not enough space to create %s",
				    namep);
			else
				cmn_err(CE_WARN,
				    "CacheFS: error %d creating %s",
				    error, namep);
			return (error);
		}
	} else if (optp) {
		/* compare the options to make sure they are compatible */
		error = fscache_compare_options(fscp, optp);
		if (error) {
			cmn_err(CE_WARN,
				"CacheFS: mount failed, options do not match.");
			return (error);
		}

		/* copy options into the fscache */
		fscp->fs_info.fi_mntflags = optp->opt_flags;
		fscp->fs_info.fi_popsize = optp->opt_popsize;
		fscp->fs_info.fi_fgsize = optp->opt_fgsize;
		fscp->fs_flags |= CFS_FS_DIRTYINFO;

		/*
		 * The fileid of the root of the filesystem can change
		 * in NFSv4, so make sure we update the fi_root
		 * with the new filenumber.
		 */
		if (CFS_ISFS_BACKFS_NFSV4(fscp) &&
		    fscp->fs_info.fi_root != backfileno) {
			fscp->fs_info.fi_root = backfileno;
		}
	}

	if (setflags) {
		mutex_enter(&fscp->fs_fslock);
		fscp->fs_flags |= CFS_FS_READ;
		if ((cachep->c_flags & CACHE_NOFILL) == 0)
			fscp->fs_flags |= CFS_FS_WRITE;
		mutex_exit(&fscp->fs_fslock);
	}

	return (0);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_activate
 *
 * Description:
 *	A wrapper routine for fscache_setup, telling it to setup the
 *	fscache for general use.
 *
 */
int
fscache_activate(fscache_t *fscp, ino64_t fsid, char *namep,
    struct cachefsoptions *optp, ino64_t backfileno)
{
	return (fscache_setup(fscp, fsid, namep, optp, backfileno, 1));
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_enable
 *
 * Description:
 *	A wrapper routine for fscache_setup, telling it to create a
 *	fscache that can be used during remount.  In this case the
 *	fscache flags that allow general use are not yet turned on.
 *	A later call to fscache_activate_rw will set the flags.
 *
 */
int
fscache_enable(fscache_t *fscp, ino64_t fsid, char *namep,
    struct cachefsoptions *optp, ino64_t backfileno)
{
	return (fscache_setup(fscp, fsid, namep, optp, backfileno, 0));
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_activate_rw
 *
 * Description:
 *	Makes the fscache both readable and writable.
 * Arguments:
 *	fscp		fscache object
 * Returns:
 * Preconditions:
 *	precond(fscp)
 */

void
fscache_activate_rw(fscache_t *fscp)
{
	mutex_enter(&fscp->fs_fslock);
	fscp->fs_flags |= (CFS_FS_WRITE|CFS_FS_READ);
	mutex_exit(&fscp->fs_fslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_hold
 *
 * Description:
 *	Increments the reference count on the fscache object
 * Arguments:
 *	fscp		fscache object to incriment reference count on
 * Returns:
 * Preconditions:
 *	precond(fscp)
 */

void
fscache_hold(fscache_t *fscp)
{
	mutex_enter(&fscp->fs_fslock);
	fscp->fs_ref++;
	ASSERT(fscp->fs_ref > 0);
	mutex_exit(&fscp->fs_fslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_rele
 *
 * Description:
 *	Decriments the reference count on the fscache object
 * Arguments:
 *	fscp		fscache object to decriment reference count on
 * Returns:
 * Preconditions:
 *	precond(fscp)
 */

void
fscache_rele(fscache_t *fscp)
{
	mutex_enter(&fscp->fs_fslock);
	ASSERT(fscp->fs_ref > 0);
	fscp->fs_ref--;
	mutex_exit(&fscp->fs_fslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_cnodecnt
 *
 * Description:
 *	Changes the count of number of cnodes on this fscache
 *	by the specified amount.
 * Arguments:
 *	fscp		fscache object to to modify count on
 *	cnt		amount to adjust by
 * Returns:
 *	Returns new count of number of cnodes.
 * Preconditions:
 *	precond(fscp)
 */

int
fscache_cnodecnt(fscache_t *fscp, int cnt)
{
	int xx;

	mutex_enter(&fscp->fs_fslock);
	fscp->fs_cnodecnt += cnt;
	ASSERT(fscp->fs_cnodecnt >= 0);
	xx = fscp->fs_cnodecnt;
	mutex_exit(&fscp->fs_fslock);
	return (xx);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_mounted
 *
 * Description:
 *	Called to indicate the the fscache is mounted.
 * Arguments:
 *	fscp		fscache object
 *	cfsvfsp		cachefs vfsp
 *	backvfsp	vfsp of back file system
 * Returns:
 *	Returns 0 for success, -1 if the cache is already mounted.
 * Preconditions:
 *	precond(fscp)
 */

int
fscache_mounted(fscache_t *fscp, struct vfs *cfsvfsp, struct vfs *backvfsp)
{
	int error = 0;

	mutex_enter(&fscp->fs_fslock);
	if (fscp->fs_flags & CFS_FS_MOUNTED) {
		error = -1;
		goto out;
	}

	fscp->fs_backvfsp = backvfsp;
	fscp->fs_cfsvfsp = cfsvfsp;
	gethrestime(&fscp->fs_cod_time);
	fscp->fs_flags |= CFS_FS_MOUNTED;

	if (CFS_ISFS_SNR(fscp)) {
		/*
		 * If there is a dlog file present, then we assume the cache
		 * was left in disconnected mode.
		 * Also if the back file system was not mounted we also
		 * start off in disconnected mode.
		 */
		error = cachefs_dlog_setup(fscp, 0);
		if (!error || (backvfsp == NULL)) {
			mutex_enter(&fscp->fs_cdlock);
			fscp->fs_cdconnected = CFS_CD_DISCONNECTED;
			fscp->fs_cdtransition = 0;
			cv_broadcast(&fscp->fs_cdwaitcv);
			mutex_exit(&fscp->fs_cdlock);
		}

		/* invalidate any local fileno mappings */
		fscp->fs_info.fi_resetfileno++;
		fscp->fs_flags |= CFS_FS_DIRTYINFO;

		/* if connected, invalidate any local time mappings */
		if (backvfsp)
			fscp->fs_info.fi_resettimes++;
	}

		error = 0;

	/* set up the consistency mode */
	if (fscp->fs_info.fi_mntflags & CFS_NOCONST_MODE) {
		fscp->fs_cfsops = &nopcfsops;
		fscp->fs_consttype = CFS_FS_CONST_NOCONST;
	} else if (fscp->fs_info.fi_mntflags & CFS_CODCONST_MODE) {
		fscp->fs_cfsops = &codcfsops;
		fscp->fs_consttype = CFS_FS_CONST_CODCONST;
	} else {
		fscp->fs_cfsops = &strictcfsops;
		fscp->fs_consttype = CFS_FS_CONST_STRICT;
	}

out:
	mutex_exit(&fscp->fs_fslock);
	(void) fscache_info_sync(fscp);
	return (error);
}

/*
 * Compares fscache state with new mount options
 * to make sure compatible.
 * Returns ESRCH if not compatible or 0 for success.
 */
int
fscache_compare_options(fscache_t *fscp, struct cachefsoptions *optp)
{
	if ((fscp->fs_info.fi_popsize == optp->opt_popsize) &&
	    (fscp->fs_info.fi_fgsize == optp->opt_fgsize)) {
		return (0);
	} else {
		return (ESRCH);
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_sync
 *
 * Description:
 *	Syncs any data for this fscache to the front file system.
 * Arguments:
 *	fscp	fscache to sync
 * Returns:
 * Preconditions:
 *	precond(fscp)
 */

void
fscache_sync(struct fscache *fscp)
{
	struct filegrp *fgp;
	int xx;

	(void) fscache_info_sync(fscp);

	/* sync the cnodes */
	cachefs_cnode_traverse(fscp, cachefs_cnode_sync);

	mutex_enter(&fscp->fs_fslock);

	/* sync the attrcache files */
	for (xx = 0; xx < CFS_FS_FGP_BUCKET_SIZE; xx++) {
		for (fgp = fscp->fs_filegrp[xx]; fgp != NULL;
			fgp = fgp->fg_next) {
			(void) filegrp_sync(fgp);
		}
	}

	/* garbage collect any unused file groups */
	filegrp_list_gc(fscp);

	mutex_exit(&fscp->fs_fslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_acset
 *
 * Description:
 *	Sets the ac timeout values for the fscache.
 * Arguments:
 *	fscp	fscache object
 * Returns:
 * Preconditions:
 *	precond(fscp)
 */

void
fscache_acset(fscache_t *fscp,
	uint_t acregmin, uint_t acregmax, uint_t acdirmin, uint_t acdirmax)
{
	mutex_enter(&fscp->fs_fslock);
	if (acregmin > acregmax)
		acregmin = acregmax;
	if (acdirmin > acdirmax)
		acdirmin = acdirmax;
	if (acregmin != 0)
		fscp->fs_acregmin = acregmin;
	if (acregmax != 0)
		fscp->fs_acregmax = acregmax;
	if (acdirmin != 0)
		fscp->fs_acdirmin = acdirmin;
	if (acdirmax != 0)
		fscp->fs_acdirmax = acdirmax;
	mutex_exit(&fscp->fs_fslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_list_find
 *
 * Description:
 *	Finds the desired fscache structure on a cache's
 *	file system list.
 * Arguments:
 *	cachep	holds the list of fscache objects to search
 *	fsid	the numeric identifier of the fscache
 * Returns:
 *	Returns an fscache object on success or NULL on failure.
 * Preconditions:
 *	precond(cachep)
 *	precond(the fslistlock must be held)
 */

fscache_t *
fscache_list_find(cachefscache_t *cachep, ino64_t fsid)
{
	fscache_t *fscp = cachep->c_fslist;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));

	while (fscp != NULL) {
		if (fscp->fs_cfsid == fsid) {
			ASSERT(fscp->fs_cache == cachep);
			break;
		}
		fscp = fscp->fs_next;
	}

	return (fscp);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_list_add
 *
 * Description:
 *	Adds the specified fscache object to the list on
 *	the specified cachep.
 * Arguments:
 *	cachep	holds the list of fscache objects
 *	fscp	fscache object to add to list
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(fscp)
 *	precond(fscp cannot already be on a list)
 *	precond(the fslistlock must be held)
 */

void
fscache_list_add(cachefscache_t *cachep, fscache_t *fscp)
{
	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));

	fscp->fs_next = cachep->c_fslist;
	cachep->c_fslist = fscp;
	cachep->c_refcnt++;
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_list_remove
 *
 * Description:
 *	Removes the specified fscache object from the list
 *	on the specified cachep.
 * Arguments:
 *	cachep	holds the list of fscache objects
 *	fscp	fscache object to remove from list
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(fscp)
 *	precond(the fslistlock must be held)
 */

void
fscache_list_remove(cachefscache_t *cachep, fscache_t *fscp)
{
	struct fscache **pfscp = &cachep->c_fslist;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));

	while (*pfscp != NULL) {
		if (fscp == *pfscp) {
			*pfscp = fscp->fs_next;
			cachep->c_refcnt--;
			break;
		}
		pfscp = &(*pfscp)->fs_next;
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_list_gc
 *
 * Description:
 *	Traverses the list of fscache objects on the cachep
 *	list and destroys any that are not mounted and
 *	that are not referenced.
 * Arguments:
 *	cachep	holds the list of fscache objects
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(the fslistlock must be held)
 */

void
fscache_list_gc(cachefscache_t *cachep)
{
	struct fscache *next, *fscp;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));

	for (fscp = cachep->c_fslist; fscp != NULL; fscp = next) {
		next = fscp->fs_next;
		mutex_enter(&fscp->fs_fslock);
		if (((fscp->fs_flags & CFS_FS_MOUNTED) == 0) &&
		    (fscp->fs_ref == 0)) {
			mutex_exit(&fscp->fs_fslock);
			fscache_list_remove(cachep, fscp);
			fscache_destroy(fscp);
		} else {
			mutex_exit(&fscp->fs_fslock);
		}
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_list_mounted
 *
 * Description:
 *	Returns the number of fscache objects that are mounted.
 * Arguments:
 *	cachep	holds the list of fscache objects
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(the fslistlock must be held)
 */

int
fscache_list_mounted(cachefscache_t *cachep)
{
	struct fscache *fscp;
	int count;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));

	count = 0;
	for (fscp = cachep->c_fslist; fscp != NULL; fscp = fscp->fs_next) {
		mutex_enter(&fscp->fs_fslock);
		if (fscp->fs_flags & CFS_FS_MOUNTED)
			count++;
		mutex_exit(&fscp->fs_fslock);
	}

	return (count);
}

/*
 * Creates the fs cache directory.
 * The directory name is the ascii version of the fsid.
 * Also makes a symlink to the directory using the specified name.
 */
int
fscdir_create(cachefscache_t *cachep, char *namep, fscache_t *fscp)
{
	int error;
	vnode_t *fscdirvp = NULL;
	vnode_t *infovp = NULL;
	vnode_t *attrvp = NULL;
	struct vattr *attrp = (struct vattr *)NULL;
	char name[CFS_FRONTFILE_NAME_SIZE];
	int files;
	int blocks = 0;
	cfs_cid_t cid;
	ino64_t fsid;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));
	ASSERT(fscp->fs_infovp == NULL);
	ASSERT(fscp->fs_fscdirvp == NULL);
	ASSERT(fscp->fs_fsattrdir == NULL);

	/* directory, symlink and options file + attrcache dir */
	files = 0;
	while (files < 4) {
		error = cachefs_allocfile(cachep);
		if (error)
			goto out;
		files++;
	}
	error = cachefs_allocblocks(cachep, 4, CACHEFS_RL_NONE);
	if (error)
		goto out;
	blocks = 4;

	attrp = cachefs_kmem_alloc(sizeof (struct vattr), KM_SLEEP);
	attrp->va_mode = S_IFDIR | 0777;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VDIR;
	attrp->va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	error = VOP_MKDIR(cachep->c_dirvp, namep, attrp, &fscdirvp, kcred,
	    NULL, 0, NULL);
	if (error) {
		cmn_err(CE_WARN, "Can't create fs cache directory");
		goto out;
	}

	/*
	 * Created the directory. Get the fileno. That'll be the cachefs_fsid.
	 */
	attrp->va_mask = AT_NODEID;
	error = VOP_GETATTR(fscdirvp, attrp, 0, kcred, NULL);
	if (error) {
		goto out;
	}
	fsid = attrp->va_nodeid;
	attrp->va_mode = S_IFREG | 0666;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VREG;
	attrp->va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	error = VOP_CREATE(fscdirvp, CACHEFS_FSINFO, attrp, EXCL,
			0600, &infovp, kcred, 0, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "Can't create fs option file");
		goto out;
	}
	attrp->va_size = MAXBSIZE;
	attrp->va_mask = AT_SIZE;
	error = VOP_SETATTR(infovp, attrp, 0, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "Can't set size of fsinfo file");
		goto out;
	}

	/* write out the info file */
	fscp->fs_flags |= CFS_FS_DIRTYINFO;
	error = fscache_info_sync(fscp);
	if (error)
		goto out;

	/*
	 * Install the symlink from cachefs_fsid -> directory.
	 */
	cid.cid_flags = 0;
	cid.cid_fileno = fsid;
	make_ascii_name(&cid, name);
	error = VOP_RENAME(cachep->c_dirvp, namep, cachep->c_dirvp,
		name, kcred, NULL, 0);
	if (error) {
		cmn_err(CE_WARN, "Can't rename cache directory");
		goto out;
	}
	attrp->va_mask = AT_MODE | AT_TYPE;
	attrp->va_mode = 0777;
	attrp->va_type = VLNK;
	error = VOP_SYMLINK(cachep->c_dirvp, namep, attrp, name, kcred, NULL,
	    0);
	if (error) {
		cmn_err(CE_WARN, "Can't create cache directory symlink");
		goto out;
	}

	/*
	 * Finally, make the attrcache directory
	 */
	attrp->va_mode = S_IFDIR | 0777;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VDIR;
	attrp->va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	error = VOP_MKDIR(fscdirvp, ATTRCACHE_NAME, attrp, &attrvp, kcred, NULL,
	    0, NULL);
	if (error) {
		cmn_err(CE_WARN, "Can't create attrcache dir for fscache");
		goto out;
	}

	mutex_enter(&fscp->fs_fslock);
	fscp->fs_cfsid = fsid;
	fscp->fs_fscdirvp = fscdirvp;
	fscp->fs_fsattrdir = attrvp;
	fscp->fs_infovp = infovp;
	mutex_exit(&fscp->fs_fslock);

out:

	if (error) {
		while (files-- > 0)
			cachefs_freefile(cachep);
		if (fscdirvp)
			VN_RELE(fscdirvp);
		if (blocks)
			cachefs_freeblocks(cachep, blocks, CACHEFS_RL_NONE);
		if (attrvp)
			VN_RELE(attrvp);
		if (infovp)
			VN_RELE(infovp);
	}
	if (attrp)
		cachefs_kmem_free(attrp, sizeof (struct vattr));
	return (error);
}

/*
 * Tries to find the fscache directory indicated by fsid.
 */
int
fscdir_find(cachefscache_t *cachep, ino64_t fsid, fscache_t *fscp)
{
	int error;
	vnode_t *infovp = NULL;
	vnode_t *fscdirvp = NULL;
	vnode_t *attrvp = NULL;
	char dirname[CFS_FRONTFILE_NAME_SIZE];
	cfs_cid_t cid;
	cachefs_fsinfo_t fsinfo;
	caddr_t addr;

	ASSERT(MUTEX_HELD(&cachep->c_fslistlock));
	ASSERT(fscp->fs_infovp == NULL);
	ASSERT(fscp->fs_fscdirvp == NULL);
	ASSERT(fscp->fs_fsattrdir == NULL);

	/* convert the fsid value to the name of the directory */
	cid.cid_flags = 0;
	cid.cid_fileno = fsid;
	make_ascii_name(&cid, dirname);

	/* try to find the directory */
	error = VOP_LOOKUP(cachep->c_dirvp, dirname, &fscdirvp, NULL,
			0, NULL, kcred, NULL, NULL, NULL);
	if (error)
		goto out;

	/* this better be a directory or we are hosed */
	if (fscdirvp->v_type != VDIR) {
		cmn_err(CE_WARN, "cachefs: fscdir_find_a: cache corruption"
			" run fsck, %s", dirname);
		error = ENOTDIR;
		goto out;
	}

	/* try to find the info file */
	error = VOP_LOOKUP(fscdirvp, CACHEFS_FSINFO, &infovp,
	    NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: fscdir_find_b: cache corruption"
			" run fsck, %s", dirname);
		goto out;
	}

	/* read in info struct */
	addr = segmap_getmapflt(segkmap, infovp, (offset_t)0,
				MAXBSIZE, 1, S_READ);

	/*LINTED alignment okay*/
	fsinfo = *(cachefs_fsinfo_t *)addr;
	error =  segmap_release(segkmap, addr, 0);
	if (error) {
		cmn_err(CE_WARN, "cachefs: fscdir_find_c: cache corruption"
			" run fsck, %s", dirname);
		goto out;
	}

	/* try to find the attrcache directory */
	error = VOP_LOOKUP(fscdirvp, ATTRCACHE_NAME,
	    &attrvp, NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: fscdir_find_d: cache corruption"
			" run fsck, %s", dirname);
		goto out;
	}

	mutex_enter(&fscp->fs_fslock);
	fscp->fs_info = fsinfo;
	fscp->fs_cfsid = fsid;
	fscp->fs_fscdirvp = fscdirvp;
	fscp->fs_fsattrdir = attrvp;
	fscp->fs_infovp = infovp;
	mutex_exit(&fscp->fs_fslock);

out:
	if (error) {
		if (infovp)
			VN_RELE(infovp);
		if (fscdirvp)
			VN_RELE(fscdirvp);
	}
	return (error);
}

/*
 * fscache_info_sync
 * Writes out the fs_info data if necessary.
 */
static int
fscache_info_sync(fscache_t *fscp)
{
	caddr_t addr;
	int error = 0;

	mutex_enter(&fscp->fs_fslock);

	if (fscp->fs_cache->c_flags & CACHE_NOFILL) {
		error = EROFS;
		goto out;
	}

	/* if the data is dirty and we have the file vnode */
	if ((fscp->fs_flags & CFS_FS_DIRTYINFO) && fscp->fs_infovp) {
		addr = segmap_getmapflt(segkmap, fscp->fs_infovp, 0,
					MAXBSIZE, 1, S_WRITE);

		/*LINTED alignment okay*/
		*(cachefs_fsinfo_t *)addr = fscp->fs_info;
		error = segmap_release(segkmap, addr, SM_WRITE);

		if (error) {
			cmn_err(CE_WARN,
			    "cachefs: Can not write to info file.");
		} else {
			fscp->fs_flags &= ~CFS_FS_DIRTYINFO;
		}
	}

out:

	mutex_exit(&fscp->fs_fslock);

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		fscache_name_to_fsid
 *
 * Description:
 *	Takes the name of a cache and determines it corresponding
 *	fsid.
 * Arguments:
 *	cachep	cache object to find name of fs cache in
 *	namep	the name of the fs cache
 *	fsidp	set to the fsid if found
 * Returns:
 *	Returns 0 on success, !0 on error.
 * Preconditions:
 *	precond(cachep)
 *	precond(namep)
 *	precond(fsidp)
 */

int
fscache_name_to_fsid(cachefscache_t *cachep, char *namep, ino64_t *fsidp)
{
	int error;
	char dirname[CFS_FRONTFILE_NAME_SIZE];
	vnode_t *linkvp = NULL;
	struct uio uio;
	struct iovec iov;
	ino64_t nodeid;
	char *pd;
	int xx;
	int c;

	/* get the vnode of the name */
	error = VOP_LOOKUP(cachep->c_dirvp, namep, &linkvp, NULL, 0, NULL,
		kcred, NULL, NULL, NULL);
	if (error)
		goto out;

	/* the vnode had better be a link */
	if (linkvp->v_type != VLNK) {
		error = EINVAL;
		goto out;
	}

	/* read the contents of the link */
	iov.iov_len = CFS_FRONTFILE_NAME_SIZE;
	iov.iov_base = dirname;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = iov.iov_len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = 0;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	error = VOP_READLINK(linkvp, &uio, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: Can't read filesystem cache link");
		goto out;
	}

	/* convert the contents of the link to a ino64_t */
	nodeid = 0;
	pd = dirname;
	for (xx = 0; xx < (CFS_FRONTFILE_NAME_SIZE - 2); xx++) {
		nodeid <<= 4;
		c = *pd++;
		if (c <= '9')
			c -= '0';
		else if (c <= 'F')
			c = c - 'A' + 10;
		else
			c = c - 'a' + 10;
		nodeid += c;
	}
	*fsidp = nodeid;
out:
	if (linkvp)
		VN_RELE(linkvp);

	return (error);
}


/*
 * Suspends the thread until access to the cache is granted.
 * If !SOFT then
 *	waitconnected == 1 means wait until connected
 *	waitconnected == 0 means wait until connected or disconnected
 * else then
 *	wait until connected or disconnected
 * writing is set to 1 if writing, 0 if reading
 * Returns 0, EINTR, or ETIMEDOUT.
 */
int
cachefs_cd_access(fscache_t *fscp, int waitconnected, int writing)
{
	int nosig;
	int error = 0;
	cachefscache_t *cachep;
	int waithappens = 0;
	pid_t pid;

	mutex_enter(&fscp->fs_cdlock);

#ifdef CFS_CD_DEBUG
	ASSERT((curthread->t_flag & T_CD_HELD) == 0);
#endif

	for (;;) {
		/* if we have to wait */
		if (waithappens ||
		    (waitconnected &&
		    (fscp->fs_cdconnected != CFS_CD_CONNECTED))) {

			/* do not make soft mounts wait until connected */
			if ((waithappens == 0) && CFS_ISFS_SOFT(fscp)) {
				error = ETIMEDOUT;
				break;
			}

			/* wait for a wakeup or a signal */
			nosig = cv_wait_sig(&fscp->fs_cdwaitcv,
			    &fscp->fs_cdlock);

			/* if we got a signal */
			if (nosig == 0) {
				error = EINTR;
				break;
			}

			if (waitconnected &&
			    (fscp->fs_cdconnected == CFS_CD_CONNECTED))
				waitconnected = 0;

			/* try again to get access */
			waithappens = 0;
			continue;
		}

		/* if transitioning modes */
		if (fscp->fs_cdtransition) {
			waithappens = 1;
			continue;
		}

		/* if rolling the log */
		if (fscp->fs_cdconnected == CFS_CD_RECONNECTING) {
			pid = ttoproc(curthread)->p_pid;
			cachep = fscp->fs_cache;

			/* if writing or not the cachefsd */
			if (writing ||
			    ((fscp->fs_cddaemonid != pid) &&
			    (cachep->c_rootdaemonid != pid))) {
				waithappens = 1;
				continue;
			}
		}

		/* if the daemon is not running */
		if (fscp->fs_cddaemonid == 0) {
			/* if writing and not connected */
			if (writing &&
			    (fscp->fs_cdconnected != CFS_CD_CONNECTED)) {
				waithappens = 1;
				continue;
			}
		}

		/*
		 * Verify don't set wait for NFSv4 (doesn't support
		 * disconnected behavior).
		 */
		ASSERT(!CFS_ISFS_BACKFS_NFSV4(fscp) ||
				(waithappens == 0 && waitconnected == 0));

		ASSERT(fscp->fs_cdrefcnt >= 0);
		fscp->fs_cdrefcnt++;
#ifdef CFS_CD_DEBUG
		curthread->t_flag |= T_CD_HELD;
#endif
		break;
	}
	mutex_exit(&fscp->fs_cdlock);

	return (error);
}

/*
 * Call to check if can have access after a cache miss has occurred.
 * Only read access is allowed, do not call this routine if want
 * to write.
 * Returns 1 if yes, 0 if no.
 */
int
cachefs_cd_access_miss(fscache_t *fscp)
{
	cachefscache_t *cachep;
	pid_t pid;

#ifdef CFS_CD_DEBUG
	ASSERT(curthread->t_flag & T_CD_HELD);
#endif

	/* should not get called if connected */
	ASSERT(fscp->fs_cdconnected != CFS_CD_CONNECTED);

	/* if no back file system, then no */
	if (fscp->fs_backvfsp == NULL)
		return (0);

	/* if daemon is not running, then yes */
	if (fscp->fs_cddaemonid == 0) {
		return (1);
	}

	pid = ttoproc(curthread)->p_pid;
	cachep = fscp->fs_cache;

	/* if daemon is running, only daemon is allowed to have access */
	if ((fscp->fs_cddaemonid != pid) &&
	    (cachep->c_rootdaemonid != pid)) {
		return (0);
	}

	return (1);
}

/*
 * Releases an access to the file system.
 */
void
cachefs_cd_release(fscache_t *fscp)
{
	mutex_enter(&fscp->fs_cdlock);

#ifdef CFS_CD_DEBUG
	ASSERT(curthread->t_flag & T_CD_HELD);
	curthread->t_flag &= ~T_CD_HELD;
#endif
	/* decriment hold on file system */
	fscp->fs_cdrefcnt--;
	ASSERT(fscp->fs_cdrefcnt >= 0);

	/* Verify no connected state transitions for NFSv4 */
	ASSERT(!CFS_ISFS_BACKFS_NFSV4(fscp) || fscp->fs_cdtransition == 0);

	/* wake up cachefsd */
	if ((fscp->fs_cdrefcnt == 0) && fscp->fs_cdtransition)
		cv_broadcast(&fscp->fs_cdwaitcv);

	mutex_exit(&fscp->fs_cdlock);
}

/*
 * Called when a network timeout error has occurred.
 * If connected, switches state to disconnected.
 */
void
cachefs_cd_timedout(fscache_t *fscp)
{
	int state;

	/* nothing to do if not snr or not connected */
	if (!CFS_ISFS_SNR(fscp) || (fscp->fs_cdconnected != CFS_CD_CONNECTED))
		return;

#ifdef CFS_CD_DEBUG
	ASSERT((curthread->t_flag & T_CD_HELD) == 0);
#endif

	/* Verify no state changes done for NFSv4 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	state = CFS_FS_DISCONNECTED;
	(void) cachefs_io_stateset(fscp->fs_rootvp, &state, NULL);
}

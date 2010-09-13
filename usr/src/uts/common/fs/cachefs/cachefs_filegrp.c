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
#include <sys/file.h>
#include <sys/stat.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>

struct kmem_cache *cachefs_filegrp_cache = NULL;

#if (defined(_SYSCALL32_IMPL) || defined(_LP64))

#define	CACHEFS_ALLOC_CFS_METADATA(p, inp)				\
	p = cachefs_kmem_zalloc(sizeof (struct cfs_cachefs_metadata), KM_SLEEP)

#define	CACHEFS_FREE_CFS_METADATA(p)					\
	cachefs_kmem_free(p, sizeof (struct cfs_cachefs_metadata))

/* CACHEFS_COPY_COMMON_METADATA_FIELDS - common code for the metadata copy */
#define	CACHEFS_COPY_COMMON_METADATA_FIELDS(inmdp, outmdp)		\
	(outmdp)->md_aclclass = (inmdp)->md_aclclass;			\
	CACHEFS_FID_COPY(&(inmdp)->md_cookie, &(outmdp)->md_cookie);	\
	(outmdp)->md_flags = (inmdp)->md_flags;				\
	(outmdp)->md_rlno = (inmdp)->md_rlno;				\
	(outmdp)->md_rltype = (inmdp)->md_rltype;			\
	(outmdp)->md_consttype = (inmdp)->md_consttype;			\
	CACHEFS_FID_COPY(&(inmdp)->md_fid, &(outmdp)->md_fid);		\
	(outmdp)->md_frontblks = (inmdp)->md_frontblks;			\
	(outmdp)->md_gen = (inmdp)->md_gen;				\
	(outmdp)->md_parent = (inmdp)->md_parent;			\
	(outmdp)->md_resettimes = (inmdp)->md_resettimes;		\
	(outmdp)->md_localfileno = (inmdp)->md_localfileno;		\
	(outmdp)->md_resetfileno = (inmdp)->md_resetfileno;		\
	(outmdp)->md_seq = (inmdp)->md_seq;				\
	(outmdp)->md_allocents = (inmdp)->md_allocents;			\
	bcopy(&(inmdp)->md_allocinfo, &(outmdp)->md_allocinfo,		\
	    MIN(sizeof (inmdp)->md_allocinfo, sizeof (outmdp)->md_allocinfo))

#define	CACHEFS_COPY_METADATA_TO_CFS_METADATA(inmdp, outmdp, error)	\
	CACHEFS_VATTR_TO_CFS_VATTR_COPY(&(inmdp)->md_vattr,		\
		&(outmdp)->md_vattr, error);				\
	CACHEFS_TS_TO_CFS_TS_COPY(&(inmdp)->md_timestamp,		\
		&(outmdp)->md_timestamp, error);			\
	CACHEFS_TS_TO_CFS_TS_COPY(&(inmdp)->md_x_time,			\
		&(outmdp)->md_x_time, error);				\
	CACHEFS_TS_TO_CFS_TS_COPY(&(inmdp)->md_localmtime,		\
		&(outmdp)->md_localmtime, error);			\
	CACHEFS_TS_TO_CFS_TS_COPY(&(inmdp)->md_localctime,		\
		&(outmdp)->md_localctime, error);			\
	CACHEFS_COPY_COMMON_METADATA_FIELDS(inmdp, outmdp)

#define	CACHEFS_COPY_CFS_METADATA_TO_METADATA(inmdp, outmdp)		\
	CACHEFS_CFS_VATTR_TO_VATTR_COPY(&(inmdp)->md_vattr,		\
		&(outmdp)->md_vattr);					\
	CACHEFS_CFS_TS_TO_TS_COPY(&(inmdp)->md_timestamp,		\
		&(outmdp)->md_timestamp);				\
	CACHEFS_CFS_TS_TO_TS_COPY(&(inmdp)->md_x_time,			\
		&(outmdp)->md_x_time);					\
	CACHEFS_CFS_TS_TO_TS_COPY(&(inmdp)->md_localmtime,		\
		&(outmdp)->md_localmtime);				\
	CACHEFS_CFS_TS_TO_TS_COPY(&(inmdp)->md_localctime,		\
		&(outmdp)->md_localctime);				\
	CACHEFS_COPY_COMMON_METADATA_FIELDS(inmdp, outmdp)

#else /* not (_SYSCALL32_IMPL || _LP64) */

#define	CACHEFS_ALLOC_CFS_METADATA(p, inp)				\
	p = (cfs_cachefs_metadata_t *)(inp)

#define	CACHEFS_FREE_CFS_METADATA(p)

#define	CACHEFS_COPY_METADATA_TO_CFS_METADATA(inmdp, outmdp, error)

#define	CACHEFS_COPY_CFS_METADATA_TO_METADATA(inmdp, outmdp)

#endif /* _SYSCALL32_IMPL || _LP64 */

/* forward references */
int filegrp_write_space(vnode_t *vp, offset_t offset, ssize_t cnt);
int filegrpattr_find(struct filegrp *fgp);
int filegrpattr_create(struct filegrp *fgp);

int
/*ARGSUSED*/
filegrp_cache_create(void *voidp, void *cdrarg, int kmflags)
{
	filegrp_t *fgp = (filegrp_t *)voidp;

	mutex_init(&fgp->fg_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&fgp->fg_cnodelock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

void
/*ARGSUSED*/
filegrp_cache_destroy(void *voidp, void *cdrarg)
{
	filegrp_t *fgp = (filegrp_t *)voidp;

	mutex_destroy(&fgp->fg_mutex);
	mutex_destroy(&fgp->fg_cnodelock);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_create
 *
 * Description:
 *	Creates a filegrp object for the specified fscache.
 *	The CFS_FG_ALLOC_{ATTR, FILE} bits will be set in fg_flags
 *	if the cache is in NOCACHE and NOFILL mode or if
 *	the directory does not exist yet.
 *	The filegrp object maintains a reference to the specified
 *	fscache.
 * Arguments:
 *	fscp	fscache to create the file group in
 *	cidp	start cid for the file group
 * Returns:
 *	Returns the created filegrp object.
 * Preconditions:
 *	precond(fscp)
 *	precond(cidp)
 *	precond(fscp->fs_info.fi_fgsize > 0)
 */
#define	Bugid_1249206_notfixed
#ifdef Bugid_1249206_notfixed
int bugid_1249206 = 0;
#endif
filegrp_t *
filegrp_create(struct fscache *fscp, cfs_cid_t *cidp)
{
	filegrp_t *fgp;
	int fgsize;
	int flags;
	ino64_t nfgsize;

	fgsize = fscp->fs_info.fi_fgsize;

	fgp = (filegrp_t *)
	    kmem_cache_alloc(cachefs_filegrp_cache, KM_SLEEP);

	fgp->fg_flags = CFS_FG_ALLOC_ATTR | CFS_FG_ALLOC_FILE;
	fgp->fg_count = 0;
	fgp->fg_id = *cidp;
#ifdef Bugid_1249206_notfixed
	if (bugid_1249206)
		cmn_err(CE_CONT, "fg_id assigned value is %" PRId64 "\n",
		    fgp->fg_id.cid_fileno);
#endif
	nfgsize = (fgp->fg_id.cid_fileno / (ino64_t)fgsize);
	fgp->fg_id.cid_fileno = (ino64_t)(nfgsize * (ino64_t)fgsize);
#ifdef Bugid_1249206_notfixed
	if (bugid_1249206) {
		cmn_err(CE_CONT,
		    "cid_fileno for fscp %p fgp %p is %" PRId64 "\n",
		    (void *)fscp, (void *)fgp,
		    fgp->fg_id.cid_fileno);
		cmn_err(CE_CONT,
		    "sent fileno is %" PRId64 " fgsize %d nfgsize %" PRId64
		    "\n", cidp->cid_fileno, fgsize, nfgsize);
	}
#endif
	fgp->fg_fscp = fscp;
	fgp->fg_cnodelist = NULL;
	fgp->fg_next = NULL;
	fgp->fg_dirvp = NULL;
	fgp->fg_attrvp = NULL;
	fgp->fg_header = NULL;
	fgp->fg_offsets = NULL;
	fgp->fg_alloclist = NULL;

	fgp->fg_headersize = (uint_t)sizeof (struct attrcache_header) +
	    (fgsize * (uint_t)sizeof (struct attrcache_index)) +
	    ((fgsize + 7) >> 3);

	fgp->fg_filesize = fgp->fg_headersize +
	    (fgsize * (uint_t)sizeof (struct cfs_cachefs_metadata));

	flags = fscp->fs_flags;
	if (flags & CFS_FS_READ) {
		fgp->fg_flags |= CFS_FG_READ;
		if (flags & CFS_FS_WRITE) {
			fgp->fg_flags |= CFS_FG_WRITE;
		}
	}

	if (fgp->fg_flags & CFS_FG_READ) {
		/* find the attrcache file and frontfile directory */
		(void) filegrpattr_find(fgp);

		/*
		 * XXX: we can tell from the file count in the attrcache
		 * whether we can expect to find a front file dir or
		 * not.  If not, we can save the lookup here...
		 */
		(void) filegrpdir_find(fgp);
	}

	return (fgp);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_destroy
 *
 * Description:
 *	Destroys the filegrp object and releases any kernel
 *	resource associated with it.
 *	Additionally if the on disk file group directory does
 *	not contain any front files it is removed.
 * Arguments:
 *	fgp	filegrp object to destroy
 * Returns:
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(fgp->fg_count == 0)
 *	precond(fgp->fg_next == NULL)
 */

void
filegrp_destroy(filegrp_t *fgp)
{
	struct fscache *fscp = fgp->fg_fscp;
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;
	int error;

	ASSERT(fgp->fg_count == 0);
	ASSERT(fgp->fg_next == NULL);

	if (fgp->fg_attrvp) {
		if (fgp->fg_flags & CFS_FG_UPDATED) {
			error = filegrp_sync(fgp);
			if (error)
				cmn_err(CE_WARN,
				    "cachefs: UFS error on cache, "
				    "run fsck %d", error);
		}
		VN_RELE(fgp->fg_attrvp);
	}
	if (fgp->fg_header) {
		/*
		 * If there are no attrcache entries in use and
		 * if we can modify the cache.
		 */
		if ((fgp->fg_header->ach_count == 0) &&
		    (fgp->fg_flags & CFS_FG_WRITE)) {
			ASSERT(fgp->fg_header->ach_nffs == 0);

			/* remove attrcache file from the rl list */
			ASSERT(fgp->fg_header->ach_rl_current ==
			    CACHEFS_RL_GC);
#ifdef CFSDEBUG
			cachefs_rlent_verify(fscp->fs_cache, CACHEFS_RL_GC,
			    fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */

			/*
			 * XXX sam: since we're blowing away the
			 * attrcache file, i guess i don't need to set
			 * ach_rl_current to CACHEFS_RL_NONE and
			 * sync the attrcache file, right?
			 *
			 * fgp->fg_header->ach_rl_current = CACHEFS_RL_NONE;
			 * fgp->fg_flags |= CFS_FG_UPDATED;
			 */

			/* remove the attrcache file */
			make_ascii_name(&fgp->fg_id, name);
			fname = name;
			error = VOP_REMOVE(fscp->fs_fsattrdir, fname, kcred,
			    NULL, 0);
			if (error) {
				cmn_err(CE_WARN,
				    "cachefs: error in cache, run fsck");
			} else {
				cachefs_freefile(fscp->fs_cache);
				cachefs_freeblocks(fscp->fs_cache,
				    fgp->fg_header->ach_nblks, CACHEFS_RL_GC);
				cachefs_rlent_moveto(fscp->fs_cache,
				    CACHEFS_RL_FREE, fgp->fg_header->ach_rlno,
				    0);
			}
		}
		cachefs_kmem_free(fgp->fg_header, fgp->fg_headersize);
	}
	if (fgp->fg_dirvp) {
		VN_RELE(fgp->fg_dirvp);
	}
	kmem_cache_free(cachefs_filegrp_cache, fgp);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_allocattr
 *
 * Description:
 *	Tries to find the attrcache file for the given filegroup.
 *	If the file does not yet exist it is created.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

int
filegrp_allocattr(filegrp_t *fgp)
{
	int error = 0;

	mutex_enter(&fgp->fg_mutex);

	/* if we do not yet have the attrcache file */
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		/* fail if we tried to create it but failed previously */
		if (fgp->fg_flags & CFS_FG_NOCACHE) {
			error = ENOENT;
			goto out;
		}

		/* fail if we cannot read from the cache */
		if ((fgp->fg_flags & CFS_FG_READ) == 0) {
			error = ENOENT;
			goto out;
		}

		/* try to find the attrcache file in the cache */
		error = filegrpattr_find(fgp);
		if (error == ENOENT) {
			/* fail if we cannot create the attrcache file */
			if ((fgp->fg_flags & CFS_FG_WRITE) == 0) {
				error = ENOENT;
				goto out;
			}

			/* try to create the attrcache file */
			error = filegrpattr_create(fgp);
		}
	}
out:
	mutex_exit(&fgp->fg_mutex);

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_hold
 *
 * Description:
 *	Increments the number of references to this filegrp object.
 * Arguments:
 *	fgp	filegrp object to reference
 * Returns:
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

void
filegrp_hold(filegrp_t *fgp)
{
	mutex_enter(&fgp->fg_mutex);

	fgp->fg_count++;

	/* remove attrcache file from the rl list if necessary */
	if ((fgp->fg_flags & CFS_FG_WRITE) &&
	    (fgp->fg_header != NULL) &&
	    (fgp->fg_header->ach_rl_current == CACHEFS_RL_GC)) {
#ifdef CFSDEBUG
		cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_GC, fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
		cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ATTRFILE, fgp->fg_header->ach_rlno,
		    fgp->fg_header->ach_nblks);
		fgp->fg_header->ach_rl_current = CACHEFS_RL_ATTRFILE;
		fgp->fg_flags |= CFS_FG_UPDATED;
	}

	mutex_exit(&fgp->fg_mutex);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_rele
 *
 * Description:
 *	Decrements the number of references to this filegrp object.
 * Arguments:
 *	fgp	filegrp object to dereference
 * Returns:
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(number of references to filegrp is > 0)
 */

void
filegrp_rele(filegrp_t *fgp)
{
	mutex_enter(&fgp->fg_mutex);
	ASSERT(fgp->fg_count > 0);

	/* move attrcache file to the rl list if necessary */
	if (((fgp->fg_flags & CFS_FG_ALLOC_ATTR) == 0) &&
	    (fgp->fg_flags & CFS_FG_WRITE) &&
	    (fgp->fg_header->ach_rl_current != CACHEFS_RL_GC) &&
	    (fgp->fg_count == 1) &&
	    (fgp->fg_header->ach_nffs == 0)) {
#ifdef CFSDEBUG
		cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ATTRFILE, fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
		cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_GC, fgp->fg_header->ach_rlno,
		    fgp->fg_header->ach_nblks);
		fgp->fg_header->ach_rl_current = CACHEFS_RL_GC;
		fgp->fg_flags |= CFS_FG_UPDATED;
	}

	fgp->fg_count--;

	mutex_exit(&fgp->fg_mutex);

}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_ffhold
 *
 * Description:
 *	Increments the count of the number of front files for
 *	this filegrp by one.
 * Arguments:
 *	fgp	filegrp object to reference
 * Returns:
 *	Returns 0 for success or a non-zero errno.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(number of references to filegrp is > 0)
 *	precond(filegrp is writable)
 */

int
filegrp_ffhold(filegrp_t *fgp)
{
	int error = 0;

	cachefs_cache_dirty(fgp->fg_fscp->fs_cache, 1);

	mutex_enter(&fgp->fg_mutex);
	ASSERT(fgp->fg_flags & CFS_FG_WRITE);
	ASSERT(fgp->fg_count > 0);

	/* if the filegrp is no good, bail out with warning */
	if (fgp->fg_flags & CFS_FG_NOCACHE) {
		error = EINVAL;
		goto out;
	}

	/* if we do not have the directory vp yet */
	if (fgp->fg_flags & CFS_FG_ALLOC_FILE) {

		/* create the directory if necessary */
		if (fgp->fg_header->ach_nffs == 0) {
			error = filegrpdir_create(fgp);
			if (error)
				goto out;
		}

		/* else find the directory */
		else {
			error = filegrpdir_find(fgp);
			if (error) {
#ifdef CFSDEBUG
				CFS_DEBUG(CFSDEBUG_FILEGRP)
					printf("ffhold: no dir, errno %d, "
					    "fileno %llx\n",
				error, (u_longlong_t)fgp->fg_id.cid_fileno);
#endif
				goto out;
			}
		}
	}
	ASSERT(fgp->fg_dirvp);

#ifdef CFSDEBUG
	if (fgp->fg_header->ach_nffs == 0) {
		ASSERT(fgp->fg_header->ach_rl_current == CACHEFS_RL_ATTRFILE);
		cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ATTRFILE, fgp->fg_header->ach_rlno);

		/*
		 * XXX sam: this used to remove from the active list,
		 * and put on `NONE'.  now, we're on
		 * CACHEFS_RL_ATTRFILE if either count or nffs is
		 * nonzero; CACHEFS_RL_GC otherwise.  since we just
		 * asserted that we're not on CACHEFS_RL_GC, there's
		 * nothing more to do.  right?
		 */
	}
#endif /* CFSDEBUG */

	fgp->fg_header->ach_nffs++;
	fgp->fg_flags |= CFS_FG_UPDATED;
	ASSERT(fgp->fg_header->ach_nffs <= fgp->fg_header->ach_count);

out:
	mutex_exit(&fgp->fg_mutex);

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_ffrele
 *
 * Description:
 *	Decrements the count of the number of front files for
 *	this filegrp by one.
 * Arguments:
 *	fgp	filegrp object to dereference
 * Returns:
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(filegrp is writable)
 *	precond(number of references to filegrp is > 0)
 *	precond(number of front file references is > 0)
 */

void
filegrp_ffrele(filegrp_t *fgp)
{
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;
	struct fscache *fscp = fgp->fg_fscp;
	int error = 0;

	/* if the filegrp is corrupt, bail out with warning */
	if (fgp->fg_flags & CFS_FG_NOCACHE) {
		return;
	}

	cachefs_cache_dirty(fgp->fg_fscp->fs_cache, 1);

	mutex_enter(&fgp->fg_mutex);
	ASSERT(fgp->fg_flags & CFS_FG_WRITE);
	ASSERT((fgp->fg_flags & CFS_FG_ALLOC_FILE) == 0);
	ASSERT(fgp->fg_dirvp != NULL);
	ASSERT(fgp->fg_count > 0);
	ASSERT(fgp->fg_header->ach_nffs > 0);
	ASSERT(fgp->fg_header->ach_nffs <= fgp->fg_header->ach_count);

	fgp->fg_header->ach_nffs--;
	fgp->fg_flags |= CFS_FG_UPDATED;

	if (fgp->fg_header->ach_nffs == 0) {
		make_ascii_name(&fgp->fg_id, name);
		fname = name;
		error = VOP_RMDIR(fscp->fs_fscdirvp, fname,
		    fscp->fs_fscdirvp, kcred, NULL, 0);
		if (error == 0) {
			cachefs_freefile(fscp->fs_cache);
			cachefs_freeblocks(fscp->fs_cache, 1,
			    fgp->fg_header->ach_rl_current);
			VN_RELE(fgp->fg_dirvp);
			fgp->fg_dirvp = NULL;
			fgp->fg_flags |= CFS_FG_ALLOC_FILE;
		} else {
			fgp->fg_flags |= CFS_FG_NOCACHE;
			cmn_err(CE_WARN, "cachefs_ffrele:"
			    " frontfs cache error %d, run fsck", error);
		}

		/*
		 * XXX sam: this used to move from `NONE' to
		 * `CACHEFS_RL_ACTIVE'.  now, we're on
		 * CACHEFS_RL_ATTRFILE if count and/or nffs is
		 * nonzero, and CACHEFS_RL_GC otherwise.  since we
		 * just asserted that count > 0, there's nothing to
		 * do.  right?
		 */
#ifdef CFSDEBUG
		cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ATTRFILE, fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
	}
	mutex_exit(&fgp->fg_mutex);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_sync
 *
 * Description:
 *	Writes the file group's attrcache header to the attrcache
 *	file if necessary and syncs it.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

int
filegrp_sync(filegrp_t *fgp)
{
	int error = 0;

	mutex_enter(&fgp->fg_mutex);

	if (((fgp->fg_flags & CFS_FG_UPDATED) == 0) ||
	    (fgp->fg_flags & CFS_FG_ALLOC_ATTR) ||
		CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp)) {
		mutex_exit(&fgp->fg_mutex);
		return (0);
	}

	ASSERT(fgp->fg_header->ach_nffs <= fgp->fg_header->ach_count);

	error = vn_rdwr(UIO_WRITE, fgp->fg_attrvp, (caddr_t)fgp->fg_header,
	    fgp->fg_headersize, 0LL, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY,
	    kcred, NULL);

	if (error == 0)
		error = VOP_FSYNC(fgp->fg_attrvp, FSYNC, kcred, NULL);

	if (error == 0)
		fgp->fg_flags &= ~CFS_FG_UPDATED;

	mutex_exit(&fgp->fg_mutex);

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_read_metadata
 *
 * Description:
 *	Reads the metadata for the specified file from the attrcache
 *	file belonging to the filegrp object.  Note that the md_rltype
 *	field may be incorrect if (cachep->c_flags & CACHE_CHECK_RLTYPE);
 *	in this case, if you care about md_rltype, you should double-check
 *	if rl_type is CACHEFS_RL_ACTIVE; cachefs_move_active_to_rl may have
 *	moved it without telling us.
 * Arguments:
 *	fgp	filegrp object
 *	cidp	the file to search for
 *	mdp	set to the metadata for the fileno
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(mdp)
 *	precond(slotp)
 */

int
filegrp_read_metadata(filegrp_t *fgp, cfs_cid_t *cidp,
    struct cachefs_metadata *mdp)
{
	int slot;
	int error;
	int index;
	struct cfs_cachefs_metadata	*tmpmdp;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	mutex_enter(&fgp->fg_mutex);
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}

	slot = filegrp_cid_to_slot(fgp, cidp);
	if (slot == 0) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}


	/* see if metadata was ever written */
	index = (int)(cidp->cid_fileno - fgp->fg_id.cid_fileno);
	if (fgp->fg_offsets[index].ach_written == 0) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}

	CACHEFS_ALLOC_CFS_METADATA(tmpmdp, mdp);

	error = vn_rdwr(UIO_READ, fgp->fg_attrvp,
	    (caddr_t)tmpmdp, sizeof (struct cfs_cachefs_metadata),
	    (offset_t)slot,
	    UIO_SYSSPACE, 0, (long long)0, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN,
		    "cachefs_read_metadata:"
		    " frontfs cache error %d, run fsck", error);
	}
	CACHEFS_COPY_CFS_METADATA_TO_METADATA(tmpmdp, mdp);
	CACHEFS_FREE_CFS_METADATA(tmpmdp);

	mutex_exit(&fgp->fg_mutex);
	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_create_metadata
 *
 * Description:
 *	Allocates a slot for the specified fileno.
 * Arguments:
 *	fgp	filegrp object
 *	cidp	the file to allocate a slot for
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

int
filegrp_create_metadata(filegrp_t *fgp, struct cachefs_metadata *md,
    cfs_cid_t *cidp)
{
	struct fscache *fscp = fgp->fg_fscp;
	cachefscache_t *cachep = fscp->fs_cache;
	int slot;
	int bitno;
	uchar_t mask;
	int last;
	int xx;
	int index;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	cachefs_cache_dirty(cachep, 1);

	mutex_enter(&fgp->fg_mutex);

	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}

	slot = filegrp_cid_to_slot(fgp, cidp);
	if (slot) {
		mutex_exit(&fgp->fg_mutex);
		return (0);
	}

	index = (int)(cidp->cid_fileno - fgp->fg_id.cid_fileno);

	ASSERT(index < fgp->fg_fscp->fs_info.fi_fgsize);

	last = (((fgp->fg_fscp->fs_info.fi_fgsize + 7) & ~(7)) / 8);
	for (xx = 0; xx < last; xx++) {
		if (fgp->fg_alloclist[xx] != (uchar_t)0xff) {
			for (mask = 1, bitno = 0; bitno < 8; bitno++) {
				if ((mask & fgp->fg_alloclist[xx]) == 0) {
					slot = (xx * 8) + bitno;
					goto found;
				}
				mask <<= 1;
			}
		}
	}
found:
	if (xx == last) {
		cmn_err(CE_WARN, "cachefs: attrcache error, run fsck");
		mutex_exit(&fgp->fg_mutex);
		return (ENOMEM);
	}

	slot = (slot * (int)sizeof (struct cfs_cachefs_metadata)) +
		fgp->fg_headersize;

	ASSERT(fgp->fg_header->ach_nffs <= fgp->fg_header->ach_count);
	fgp->fg_header->ach_count++;
	fgp->fg_offsets[index].ach_offset = slot;
	fgp->fg_offsets[index].ach_written = 0;
	fgp->fg_alloclist[xx] |= mask;
	fgp->fg_flags |= CFS_FG_UPDATED;

	mutex_exit(&fgp->fg_mutex);

	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_MDCREATE))
		cachefs_log_mdcreate(cachep, 0,
		    fscp->fs_cfsvfsp, &md->md_cookie, cidp->cid_fileno,
		    fgp->fg_header->ach_count);

	return (0);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_write_metadata
 *
 * Description:
 *	Writes metadata to the slot held by file.
 * Arguments:
 *	fgp	filegrp object
 *	cidp	the file to write the metadata for
 *	mdp	the metadata to write
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(mdp)
 */
int
filegrp_write_metadata(filegrp_t *fgp, cfs_cid_t *cidp,
    struct cachefs_metadata *mdp)
{
	int error = 0;
	int slot;
	blkcnt64_t nblks;
	int index;
	struct fscache *fscp = fgp->fg_fscp;
	struct cfs_cachefs_metadata	*tmpmdp;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	cachefs_cache_dirty(fscp->fs_cache, 1);
	mutex_enter(&fgp->fg_mutex);

	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		error = ENOENT;
		goto out;
	}

	slot = filegrp_cid_to_slot(fgp, cidp);
	if (slot == 0) {
		error = ENOENT;
		goto out;
	}

	/* allocate blocks for the data if necessary */
	nblks = slot + sizeof (struct cfs_cachefs_metadata);
	nblks = (nblks + MAXBSIZE - 1) / MAXBSIZE;
	nblks -= fgp->fg_header->ach_nblks;
	if (nblks > 0) {
		error = cachefs_allocblocks(fscp->fs_cache, nblks,
		    fgp->fg_header->ach_rl_current);
		if (error)
			goto out;
		error = filegrp_write_space(fgp->fg_attrvp,
			(offset_t)fgp->fg_header->ach_nblks * MAXBSIZE,
			nblks * MAXBSIZE);
		if (error) {
			cachefs_freeblocks(fscp->fs_cache, nblks,
			    fgp->fg_header->ach_rl_current);
			goto out;
		}
	} else
		nblks = 0;

	CACHEFS_ALLOC_CFS_METADATA(tmpmdp, mdp);
	CACHEFS_COPY_METADATA_TO_CFS_METADATA(mdp, tmpmdp, error);
	/* write the metadata */
	if (!error)
		error = vn_rdwr(UIO_WRITE, fgp->fg_attrvp, (caddr_t)tmpmdp,
			sizeof (struct cfs_cachefs_metadata), (offset_t)slot,
			UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY, kcred, NULL);

	CACHEFS_FREE_CFS_METADATA(tmpmdp);

	if (error) {
		if (error == EOVERFLOW) {
			cmn_err(CE_WARN, "cachefs_write_metadata:"
			    " time/dev overflow error %d", error);
		} else if (error != ENOSPC) {
			cmn_err(CE_WARN,
			    "cachefs: UFS write error %d, run fsck",
			    error);
		}
		cachefs_freeblocks(fscp->fs_cache, nblks,
		    fgp->fg_header->ach_rl_current);
		goto out;
	}

	/* mark metadata as having been written */
	index = (int)(cidp->cid_fileno - fgp->fg_id.cid_fileno);
	fgp->fg_offsets[index].ach_written = 1;

	/* update number of blocks used by the attrcache file */
	fgp->fg_header->ach_nblks += nblks;

	/* force sync to be done eventually */
	fgp->fg_flags |= CFS_FG_UPDATED;

out:
	mutex_exit(&fgp->fg_mutex);
	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_destroy_metadata
 *
 * Description:
 *	Destroys the metadata associated with the specified file.
 * Arguments:
 *	fgp	filegrp object
 *	cidp	the file to destroy the metadata for
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

int
filegrp_destroy_metadata(filegrp_t *fgp, cfs_cid_t *cidp)
{
	int i;
	int bitno;
	uchar_t mask = 1;

	int slot;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	cachefs_cache_dirty(fgp->fg_fscp->fs_cache, 1);
	mutex_enter(&fgp->fg_mutex);

	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}

	slot = filegrp_cid_to_slot(fgp, cidp);
	if (slot == 0) {
		mutex_exit(&fgp->fg_mutex);
		return (ENOENT);
	}

	i = (int)(cidp->cid_fileno - fgp->fg_id.cid_fileno);
	fgp->fg_offsets[i].ach_offset = 0;
	fgp->fg_offsets[i].ach_written = 0;
	i = (slot - fgp->fg_headersize) /
		(int)sizeof (struct cfs_cachefs_metadata);
	bitno = i & 7;
	i = i >> 3;
	mask <<= bitno;
	if (fgp->fg_alloclist[i] & mask)
		fgp->fg_alloclist[i] &= ~mask;
	else
		cmn_err(CE_WARN,
		    "filegrp_destroy_metadata:"
		    " fileno %" PRId64 " slot %d-%d fgp %p not allocated",
		    cidp->cid_fileno, i, bitno, (void *)fgp);

	fgp->fg_header->ach_count--;
	ASSERT(fgp->fg_header->ach_nffs <= fgp->fg_header->ach_count);
	fgp->fg_flags |= CFS_FG_UPDATED;
	mutex_exit(&fgp->fg_mutex);

	return (0);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_find
 *
 * Description:
 *	Looks for the filegrp that owns the specified file
 *	on the fscp filegrp lists.
 *	The fscp->fs_fslock must be held while this routine is called.
 *	By convention the filegrp object returned may be used as
 *	long as the fs_fslock is held.  To use the filegrp after
 *	dropping fs_fslock, call filegrp_hold.
 * Arguments:
 *	fscp	fscache object
 *	cidp	the file to search on
 * Returns:
 *	Returns the filegrp object if found, NULL if not.
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 */

filegrp_t *
filegrp_list_find(struct fscache *fscp, cfs_cid_t *cidp)
{
	int fgsize = fscp->fs_info.fi_fgsize;
	struct filegrp *fgp;
	ino64_t fxx;
	int findex;
	ino64_t fileno;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	/* get fileno of filegrp */
	fxx = (ino64_t)(cidp->cid_fileno / fgsize);
	fileno = fxx * fgsize;

	/* hash into array of file groups */
	findex = (int)(fxx & (CFS_FS_FGP_BUCKET_SIZE - 1));

	/* search set of file groups for this hash bucket */
	for (fgp = fscp->fs_filegrp[findex];
	    fgp != NULL;
	    fgp = fgp->fg_next) {
		if ((fgp->fg_id.cid_fileno == fileno) &&
		    (fgp->fg_id.cid_flags == cidp->cid_flags))
			break;
	}

	return (fgp);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_add
 *
 * Description:
 *	Adds the filegrp to the list of filegrps in the fscp.
 *	The fscp->fs_fslock must be held while this routine is called.
 * Arguments:
 *	fscp	fscache object
 *	fgp	filegrp object
 * Returns:
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 *	precond(fgp is a valid filegrp object)
 *	precond(fgp is not already on a list of filegrps)
 */

void
filegrp_list_add(struct fscache *fscp, filegrp_t *fgp)
{
	int findex;
	int fgsize = fscp->fs_info.fi_fgsize;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));
	ASSERT(fgp->fg_next == NULL);

	/* hash into array of file groups */
	findex = (int)((fgp->fg_id.cid_fileno / fgsize) &
	    (CFS_FS_FGP_BUCKET_SIZE - 1));

	fgp->fg_next = fscp->fs_filegrp[findex];
	fscp->fs_filegrp[findex] = fgp;
	fscp->fs_ref++;
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_remove
 *
 * Description:
 *	Removes the filegrp from the list of filegrps in the fscp.
 *	The fscp->fs_fslock must be held while this routine is called.
 * Arguments:
 *	fscp	fscache object
 *	fgp	filegrp object
 * Returns:
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 *	precond(fgp is a valid filegrp object)
 *	precond(fgp is on the list of filegrps in fscp)
 */

void
filegrp_list_remove(struct fscache *fscp, filegrp_t *fgp)
{
	struct filegrp *fp;
	struct filegrp **pfgp;
	int found = 0;
	int findex;
	int fgsize = fscp->fs_info.fi_fgsize;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	/* hash into array of file groups */
	findex = (int)((fgp->fg_id.cid_fileno / fgsize) &
	    (CFS_FS_FGP_BUCKET_SIZE - 1));
	fp = fscp->fs_filegrp[findex];
	pfgp = &fscp->fs_filegrp[findex];

	while (fp != NULL) {
		if (fp == fgp) {
			*pfgp = fp->fg_next;
			fp->fg_next = NULL;
			found++;
			break;
		}
		pfgp = &fp->fg_next;
		fp = fp->fg_next;
	}
	ASSERT(found);
	fscp->fs_ref--;
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_gc
 *
 * Description:
 *	Traverses the filegrp lists and throws away any filegrps that are
 *	not in use.
 *	The fscp->fs_fslock must be held while this routine is called.
 * Arguments:
 *	fscp	fscache object
 * Returns:
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 */

void
filegrp_list_gc(struct fscache *fscp)
{
	struct filegrp *next, *fgp;
	int xx;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	for (xx = 0; xx < CFS_FS_FGP_BUCKET_SIZE; xx++) {
		for (fgp = fscp->fs_filegrp[xx]; fgp != NULL; fgp = next) {
			next = fgp->fg_next;
			mutex_enter(&fgp->fg_mutex);
			if (fgp->fg_count > 0) {
				mutex_exit(&fgp->fg_mutex);
				continue;
			}
			mutex_exit(&fgp->fg_mutex);
			filegrp_list_remove(fscp, fgp);
			filegrp_destroy(fgp);
		}
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_setup
 *
 * Description:
 *	Perform initialization actions on the given filegrp.
 *	The fgp->fg_mutex must be held while this routine is called.
 * Arguments:
 *	fgp	filegrp object
 *	flags	flags to be OR'ed into the fgp flags field
 *	dorl	indicates whether filegrp should be removed from rl or not
 * Returns:
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */
static void
filegrp_setup(struct filegrp *fgp, int flags, int dorl)
{
	ASSERT(MUTEX_HELD(&fgp->fg_mutex));

	/* turn on the specified flags */
	if (flags)
		fgp->fg_flags |= flags;

	/* if the attrcache file exists, find it */
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR)
		(void) filegrpattr_find(fgp);

	/* if the attrcache directory exists, find it */
	if (((fgp->fg_flags & CFS_FG_ALLOC_ATTR) == 0) &&
	    (fgp->fg_flags & CFS_FG_ALLOC_FILE) &&
	    (fgp->fg_header->ach_nffs > 0)) {
		(void) filegrpdir_find(fgp);
	}

	/* move from gc list to attrfile list if necessary */
	if ((dorl != 0) &&
	    ((fgp->fg_flags & CFS_FG_ALLOC_ATTR) == 0) &&
	    (fgp->fg_header->ach_rl_current == CACHEFS_RL_GC)) {
		ASSERT(fgp->fg_header->ach_nffs == 0);
		if (fgp->fg_count > 0) {
#ifdef CFSDEBUG
			cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
			    CACHEFS_RL_GC, fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
			cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
			    CACHEFS_RL_ATTRFILE, fgp->fg_header->ach_rlno,
			    fgp->fg_header->ach_nblks);
			fgp->fg_header->ach_rl_current = CACHEFS_RL_ATTRFILE;
			fgp->fg_flags |= CFS_FG_UPDATED;
		}
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_enable_caching_ro
 *
 * Description:
 *	Traverses the filegrp lists and enables the
 *	use of the cache read-only.
 *	The fscp->fs_fslock must be held while this routine is called.
 * Arguments:
 *	fscp	fscache object
 * Returns:
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 */

void
filegrp_list_enable_caching_ro(struct fscache *fscp)
{
	struct filegrp *fgp;
	int xx;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	for (xx = 0; xx < CFS_FS_FGP_BUCKET_SIZE; xx++) {
		for (fgp = fscp->fs_filegrp[xx]; fgp != NULL;
		    fgp = fgp->fg_next) {
			mutex_enter(&fgp->fg_mutex);
			filegrp_setup(fgp, 0, 0);
			mutex_exit(&fgp->fg_mutex);
		}
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_list_enable_caching_rw
 *
 * Description:
 *	Traverses the filegrp lists and enables the
 *	use of the cache read-write.
 *	The fscp->fs_fslock must be held while this routine is called.
 * Arguments:
 *	fscp	fscache object
 * Returns:
 * Preconditions:
 *	precond(fscp is a valid fscache object)
 *	precond(all filegrps must be in the read-only state)
 */

void
filegrp_list_enable_caching_rw(struct fscache *fscp)
{
	struct filegrp *fgp;
	int xx;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	for (xx = 0; xx < CFS_FS_FGP_BUCKET_SIZE; xx++) {
		for (fgp = fscp->fs_filegrp[xx]; fgp != NULL;
		    fgp = fgp->fg_next) {
			mutex_enter(&fgp->fg_mutex);
			filegrp_setup(fgp, CFS_FG_READ|CFS_FG_WRITE, 1);
			mutex_exit(&fgp->fg_mutex);
		}
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrpdir_find
 *
 * Description:
 *	Tries to find the filegrp frontfile directory in the cache.
 *	If found CFS_FG_ALLOC_FILE is turned off.
 *	This routine should not be called if CFS_FG_ALLOC_FILE is
 *	already off.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 */

int
filegrpdir_find(filegrp_t *fgp)
{
	int error;
	vnode_t *dirvp;
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;
	struct fscache *fscp = fgp->fg_fscp;

	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR)
		return (ENOENT);
	ASSERT(fgp->fg_flags & CFS_FG_ALLOC_FILE);

	make_ascii_name(&fgp->fg_id, name);
	fname = name;
	error = VOP_LOOKUP(fscp->fs_fscdirvp, fname, &dirvp, NULL,
			0, NULL, kcred, NULL, NULL, NULL);
	if (error == 0) {
		fgp->fg_dirvp = dirvp;
		fgp->fg_flags &= ~CFS_FG_ALLOC_FILE;
#ifdef CFSDEBUG
		if (fgp->fg_header->ach_nffs == 0) {
			CFS_DEBUG(CFSDEBUG_FILEGRP)
				printf("filegrpdir_find: "
				    "%s found but no front files\n", fname);
		}
#endif
	}
#ifdef CFSDEBUG
	else if (fgp->fg_header->ach_nffs != 0) {
		CFS_DEBUG(CFSDEBUG_FILEGRP)
			printf("filegrpdir_find: "
				"%s NOT found but %d front files\n",
				fname, fgp->fg_header->ach_nffs);
	}
#endif
	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrparttr_find
 *
 * Description:
 *	Tries to find the attrcache file for the given filegrp.
 *	If found the header information is read in and
 *	CFS_FG_ALLOC_ATTR is turned off.
 *	This routine should not be called if CFS_FG_ALLOC_ATTR is
 *	already off.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(fgp is readable)
 */

int
filegrpattr_find(struct filegrp *fgp)
{
	int error = 0;
	struct fscache *fscp = fgp->fg_fscp;
	cachefscache_t *cachep = fscp->fs_cache;
	vnode_t *attrvp;
	struct attrcache_header *ahp;
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;

	if (fgp->fg_flags & CFS_FG_NOCACHE)
		return (ENOENT);

	ASSERT(fgp->fg_flags & CFS_FG_ALLOC_ATTR);
	make_ascii_name(&fgp->fg_id, name);
	fname = name;
	error = VOP_LOOKUP(fscp->fs_fsattrdir, fname,
	    &attrvp, NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error) {
		return (error);
	}
	ahp = (struct attrcache_header *)cachefs_kmem_zalloc(
	    fgp->fg_headersize, KM_SLEEP);

	error = vn_rdwr(UIO_READ, attrvp, (caddr_t)ahp,
				fgp->fg_headersize, 0LL, UIO_SYSSPACE,
			0, (rlim64_t)RLIM_INFINITY, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: Read attrcache error %d, run fsck",
		    error);
		cachefs_kmem_free(ahp, fgp->fg_headersize);
		fgp->fg_flags |= CFS_FG_NOCACHE;
		VN_RELE(attrvp);
	} else {
		ASSERT(ahp->ach_nffs <= ahp->ach_count);
		fgp->fg_attrvp = attrvp;
		fgp->fg_header = ahp;
		fgp->fg_offsets = (struct attrcache_index *)(ahp + 1);
		fgp->fg_alloclist = ((uchar_t *)fgp->fg_offsets) +
			(fscp->fs_info.fi_fgsize *
			sizeof (struct attrcache_index));
		fgp->fg_flags &= ~CFS_FG_ALLOC_ATTR;

		if ((cachep->c_flags & CACHE_CHECK_RLTYPE) &&
		    (ahp->ach_rl_current == CACHEFS_RL_ATTRFILE)) {
			rl_entry_t *rlp, rl;

			mutex_enter(&cachep->c_contentslock);
			error = cachefs_rl_entry_get(cachep, ahp->ach_rlno,
									&rlp);
			if (error) {
				mutex_exit(&cachep->c_contentslock);
				cachefs_kmem_free(ahp, fgp->fg_headersize);
				fgp->fg_flags |= CFS_FG_NOCACHE;
				VN_RELE(attrvp);
				return (error);
			}

			rl = *rlp;
			mutex_exit(&cachep->c_contentslock);

			if (rl.rl_current != ahp->ach_rl_current) {
				ahp->ach_rl_current = rl.rl_current;
				fgp->fg_flags |= CFS_FG_UPDATED;
			}
		}

		/* if the attr file is on the rl */
		if (fgp->fg_header->ach_rl_current == CACHEFS_RL_GC) {
#ifdef CFSDEBUG
			if (fgp->fg_flags & CFS_FG_WRITE)
				cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
				    CACHEFS_RL_GC,
				    fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
			if ((fgp->fg_count > 0) &&
			    (fgp->fg_flags & CFS_FG_WRITE)) {
				/* remove from rl, put on active */
				cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
				    CACHEFS_RL_ATTRFILE,
				    fgp->fg_header->ach_rlno,
				    fgp->fg_header->ach_nblks);
				fgp->fg_header->ach_rl_current =
				    CACHEFS_RL_ATTRFILE;
				fgp->fg_flags |= CFS_FG_UPDATED;
			}
		} else {
			ASSERT(fgp->fg_header->ach_rl_current ==
			    CACHEFS_RL_ATTRFILE);
#ifdef CFSDEBUG
			if (fgp->fg_flags & CFS_FG_WRITE)
				cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
				    CACHEFS_RL_ATTRFILE,
				    fgp->fg_header->ach_rlno);
#endif /* CFSDEBUG */
		}
	}

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrpdir_create
 *
 * Description:
 *	Creates the filegrp directory in the cache.
 *	If created CFS_FG_ALLOC_FILE is turned off.
 *	This routine should not be called if CFS_FG_ALLOC_FILE is
 *	already off.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(filegrp is writeable)
 */

int
filegrpdir_create(filegrp_t *fgp)
{
	int error;
	vnode_t *dirvp = NULL;
	struct vattr *attrp = NULL;
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;
	struct fscache *fscp = fgp->fg_fscp;

	ASSERT(fgp->fg_flags & CFS_FG_WRITE);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
	ASSERT(MUTEX_HELD(&fgp->fg_mutex));

	if (fgp->fg_flags & (CFS_FG_ALLOC_ATTR | CFS_FG_NOCACHE))
		return (ENOENT);

	/* allocate a 1 block file for the directory */
	error = cachefs_allocfile(fscp->fs_cache);
	if (error) {
		return (error);
	}
	error = cachefs_allocblocks(fscp->fs_cache, 1,
	    fgp->fg_header->ach_rl_current);
	if (error) {
		cachefs_freefile(fscp->fs_cache);
		return (error);
	}

	/*
	 * Construct a name for this file group directory and then do a mkdir
	 */
	make_ascii_name(&fgp->fg_id, name);
	fname = name;
	attrp = (struct vattr *)cachefs_kmem_alloc(sizeof (struct vattr),
			KM_SLEEP);
	attrp->va_mode = S_IFDIR | 0777;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VDIR;
	attrp->va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	error = VOP_MKDIR(fscp->fs_fscdirvp, fname, attrp, &dirvp, kcred, NULL,
	    0, NULL);
	if (error) {
		fgp->fg_flags |= CFS_FG_NOCACHE;
		cachefs_freefile(fscp->fs_cache);
		cachefs_freeblocks(fscp->fs_cache, 1,
		    fgp->fg_header->ach_rl_current);
	} else {
		fgp->fg_dirvp = dirvp;
		fgp->fg_flags &= ~CFS_FG_ALLOC_FILE;
	}

	if (attrp)
		cachefs_kmem_free(attrp, sizeof (*attrp));

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrpattr_create
 *
 * Description:
 *	Creates the attrcache file for the given filegrp.
 *	If created CFS_FG_ALLOC_ATTR is turned off.
 *	This routine should not be called if CFS_FG_ALLOC_ATTR is
 *	already off.
 * Arguments:
 *	fgp	filegrp object
 * Returns:
 *	Returns 0 on success, an errno value on failure.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(filegrp is writable)
 */

int
filegrpattr_create(struct filegrp *fgp)
{
	int error;
	vnode_t *attrvp = NULL;
	struct attrcache_header *ahp = NULL;
	int nblks = 0;
	int gotrlent = 0;
	struct vattr *attrp = NULL;
	char name[CFS_FRONTFILE_NAME_SIZE];
	char *fname;
	struct fscache *fscp = fgp->fg_fscp;
	rl_entry_t rl_ent;

	ASSERT(fgp->fg_flags & CFS_FG_WRITE);

	if (fgp->fg_flags & CFS_FG_NOCACHE)
		return (ENOENT);

	cachefs_cache_dirty(fscp->fs_cache, 1);

	/* allocate a file for the attrcache */
	error = cachefs_allocfile(fscp->fs_cache);
	if (error) {
		goto out;
	}

	make_ascii_name(&fgp->fg_id, name);
	fname = name;
	attrp = cachefs_kmem_alloc(sizeof (struct vattr), KM_SLEEP);
	attrp->va_mode = S_IFREG | 0666;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VREG;
	attrp->va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	error = VOP_CREATE(fscp->fs_fsattrdir, fname, attrp, EXCL, 0666,
			&attrvp, kcred, 0, NULL, NULL);
	if (error) {
		cachefs_freefile(fscp->fs_cache);
		goto out;
	}

	/* alloc blocks for the attrcache header */
	nblks = (fgp->fg_headersize + MAXBSIZE - 1) / MAXBSIZE;
	error = cachefs_allocblocks(fscp->fs_cache, nblks, CACHEFS_RL_NONE);
	if (error) {
		nblks = 0;
		goto out;
	}

	/* Construct an attrcache header */
	ahp = cachefs_kmem_zalloc(fgp->fg_headersize, KM_SLEEP);

	/* write out the header to allocate space on ufs */
	error = vn_rdwr(UIO_WRITE, attrvp, (caddr_t)ahp,
	fgp->fg_headersize, 0LL, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY,
		kcred, NULL);
	if (error)
		goto out;
	error = filegrp_write_space(attrvp, (offset_t)fgp->fg_headersize,
		(nblks * MAXBSIZE) - fgp->fg_headersize);
	if (error)
		goto out;
	error = VOP_FSYNC(attrvp, FSYNC, kcred, NULL);
	if (error)
		goto out;

	/* allocate an rl entry and mark it as an attrcache entry */
	rl_ent.rl_fileno = fgp->fg_id.cid_fileno;
	rl_ent.rl_local = (fgp->fg_id.cid_flags & CFS_CID_LOCAL) ? 1 : 0;
	rl_ent.rl_fsid = fscp->fs_cfsid;
	rl_ent.rl_attrc = 1;
	error = cachefs_rl_alloc(fscp->fs_cache, &rl_ent, &ahp->ach_rlno);
	if (error)
		goto out;
	gotrlent = 1;
	if (fgp->fg_count == 0) {
		/* put on the gc */
		cachefs_rlent_moveto(fgp->fg_fscp->fs_cache, CACHEFS_RL_GC,
		    ahp->ach_rlno, nblks);
		ahp->ach_rl_current = CACHEFS_RL_GC;
	} else {
		/* put on attrfile list */
		cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ATTRFILE, ahp->ach_rlno, nblks);
		ahp->ach_rl_current = CACHEFS_RL_ATTRFILE;
	}

out:
	if (error) {
		fgp->fg_flags |= CFS_FG_NOCACHE;
		if (attrvp) {
			VN_RELE(attrvp);
			(void) VOP_REMOVE(fscp->fs_fsattrdir, fname, kcred,
			    NULL, 0);
			cachefs_freefile(fscp->fs_cache);
		}
		if (nblks)
			cachefs_freeblocks(fscp->fs_cache, nblks,
			    CACHEFS_RL_NONE);
		if (gotrlent)
			cachefs_rlent_moveto(fscp->fs_cache,
			    CACHEFS_RL_FREE, ahp->ach_rlno, 0);
		if (ahp)
			cachefs_kmem_free(ahp, fgp->fg_headersize);
	} else {
		fgp->fg_attrvp = attrvp;
		fgp->fg_header = ahp;
		fgp->fg_offsets = (struct attrcache_index *)(ahp + 1);
		fgp->fg_alloclist = ((uchar_t *)fgp->fg_offsets) +
			(fscp->fs_info.fi_fgsize *
			sizeof (struct attrcache_index));
		ahp->ach_count = 0;
		ahp->ach_nffs = 0;
		ahp->ach_nblks = nblks;
		fgp->fg_flags &= ~CFS_FG_ALLOC_ATTR;
		fgp->fg_flags |= CFS_FG_UPDATED;
	}

	if (attrp)
		cachefs_kmem_free(attrp, sizeof (*attrp));

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		filegrp_cid_to_slot
 *
 * Description:
 *	Takes a file and returns the offset to the metadata
 *	slot for the specified filegrp.
 * Arguments:
 *	fgp	filegrp object
 *	cidp	file to map to an offset
 * Returns:
 *	Returns the offset or 0 if the slot is not allocated yet
 *	or it is invalid.
 * Preconditions:
 *	precond(fgp is a valid filegrp object)
 *	precond(fgp is not ALLOC_PENDING or NOCACHE)
 */

int
filegrp_cid_to_slot(filegrp_t *fgp, cfs_cid_t *cidp)
{
	int xx;
	int slot;
	int index;

	index = (int)(cidp->cid_fileno - fgp->fg_id.cid_fileno);

	if (index > fgp->fg_fscp->fs_info.fi_fgsize) {
		cmn_err(CE_WARN, "cachefs: attrcache error, run fsck");
		return (0);
	}

	slot = fgp->fg_offsets[index].ach_offset;
	if (slot == 0)
		return (0);

	xx = fgp->fg_filesize - (int)sizeof (struct cfs_cachefs_metadata);
	if ((slot < fgp->fg_headersize) || (xx < slot)) {
		cmn_err(CE_WARN, "cachefs: attrcache error, run fsck");
		return (0);
	}

	return (slot);
}

/*
 *
 *		filegrp_write_space
 *
 * Description:
 *	Writes garbage data to the specified file starting
 *	at the specified location for the specified number of bytes.
 *	slot for the specified filegrp.
 * Arguments:
 *	vp	vnode to write to
 *	offset	offset to write at
 *	cnt	number of bytes to write
 * Returns:
 *	Returns 0 for success or on error the result of the
 *	last vn_rdwr call.
 * Preconditions:
 *	precond(vp)
 */

int
filegrp_write_space(vnode_t *vp, offset_t offset, ssize_t cnt)
{
	char *bufp;
	int xx;
	int error = 0;

	bufp = (char *)cachefs_kmem_zalloc(MAXBSIZE, KM_SLEEP);
	while (cnt > 0) {
		if (cnt > MAXBSIZE)
			xx = MAXBSIZE;
		else
			xx = (int)cnt;
		error = vn_rdwr(UIO_WRITE, vp, (caddr_t)bufp,
		xx, offset, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY,
			kcred, NULL);
		if (error)
			break;
		offset += xx;
		cnt -= xx;
	}
	cachefs_kmem_free(bufp, MAXBSIZE);
	return (error);
}

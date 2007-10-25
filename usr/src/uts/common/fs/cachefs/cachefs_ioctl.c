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
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/tiuser.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/fbuf.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/mount.h>
#include <sys/dnlc.h>
#include <sys/stat.h>
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
#include <sys/fs/cachefs_dir.h>
#include <sys/fs/cachefs_dlog.h>
#include "fs/fs_subr.h"

void cachefs_addhash(struct cnode *);


/*
 * Local functions
 */
static void sync_metadata(cnode_t *);
static void drop_backvp(cnode_t *);
static void allow_pendrm(cnode_t *cp);
static int cachefs_unpack_common(vnode_t *vp);
static int cachefs_unpackall_list(cachefscache_t *cachep,
    enum cachefs_rl_type type);
static void cachefs_modified_fix(fscache_t *fscp);
static void cachefs_iosetneedattrs(fscache_t *fscp, cfs_cid_t *cidp);

#if (defined(_SYSCALL32_IMPL) || defined(_LP64))

#define	CACHEFS_DECL(type, handle)					\
	type	handle

#define	CACHEFS_TMPPTR_SET(in_addr, tmp_addr, tmp_ptr, type)		\
	tmp_ptr = (type *)(tmp_addr)

#define	CACHEFS_FID_COPYOUT(in_fidp, out_fidp)				\
	CACHEFS_FID_COPY((fid_t *)(in_fidp), (cfs_fid_t *)(out_fidp))

#define	CACHEFS_FID_COPYIN(in_fidp, out_fidp)				\
	CACHEFS_FID_COPY((cfs_fid_t *)(in_fidp), (fid_t *)(out_fidp))

#define	CACHEFS_VATTR_COPYOUT(in_vattrp, out_vattrp, error)		\
	if (!error) {							\
		CACHEFS_VATTR_TO_CFS_VATTR_COPY((vattr_t *)(in_vattrp),	\
			(cfs_vattr_t *)(out_vattrp), error);		\
	}

#define	CACHEFS_VATTR_COPYIN(in_vattrp, out_vattrp)			\
	CACHEFS_CFS_VATTR_TO_VATTR_COPY((cfs_vattr_t *)(in_vattrp),	\
			(vattr_t *)(out_vattrp))

#else /* not _SYSCALL32_IMPL || _LP64 */

#define	CACHEFS_DECL(type, handle)

#define	CACHEFS_TMPPTR_SET(in_addr, tmp_addr, tmp_ptr, type)		\
	tmp_ptr = (type *)(in_addr)

#define	CACHEFS_FID_COPYOUT(in_fidp, out_fidp)

#define	CACHEFS_FID_COPYIN(in_fidp, out_fidp)

#define	CACHEFS_VATTR_COPYOUT(in_vattrp, out_vattrp, error)

#define	CACHEFS_VATTR_COPYIN(in_vattrp, out_vattrp)

#endif	/* _SYSCALL32_IMPL || _LP64 */

/*
 * Conjure up a credential from the partial credential stored in
 * a file.  This is bogus and cachefs should really be fixed, but
 * this maintains maximum compatibility.
 * dl_cred *cr points to a basic credential followed directly by a buffer that
 * takes a number of groups.
 */

static cred_t *
conj_cred(dl_cred_t *cr)
{
	cred_t *newcr = crget();

	(void) crsetresuid(newcr, cr->cr_ruid, cr->cr_uid, cr->cr_suid);
	(void) crsetresgid(newcr, cr->cr_rgid, cr->cr_gid, cr->cr_sgid);

	(void) crsetgroups(newcr, MIN(NGROUPS_MAX_DEFAULT, cr->cr_ngroups),
		cr->cr_groups);

	return (newcr);
}
/*
 * Pack a file in the cache
 *	dvp is the directory the file resides in.
 *	name is the name of the file.
 *	Returns 0 or an error if could not perform the operation.
 */
int
cachefs_pack(struct vnode *dvp, char *name, cred_t *cr)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(dvp));
	int error = 0;
	int connected = 0;
	vnode_t *vp;

	/*
	 * Return if NFSv4 is the backfs (no caching).
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		goto out;
	}

	for (;;) {
		/* get access to the file system */
		error = cachefs_cd_access(fscp, connected, 0);
		if (error)
			break;

		/* lookup the file name */
		error = cachefs_lookup_common(dvp, name, &vp, NULL, 0, NULL,
		    cr);
		if (error == 0) {
			error = cachefs_pack_common(vp, cr);
			VN_RELE(vp);
		}
		if (CFS_TIMEOUT(fscp, error)) {
			if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
				cachefs_cd_release(fscp);
				cachefs_cd_timedout(fscp);
				connected = 0;
				continue;
			} else {
				cachefs_cd_release(fscp);
				connected = 1;
				continue;
			}
		}
		cachefs_cd_release(fscp);
		break;
	}

out:
	return (error);
}
/*
 * Packs the file belonging to the passed in vnode.
 */
int
cachefs_pack_common(vnode_t *vp, cred_t *cr)
{
	cnode_t *cp = VTOC(vp);
	fscache_t *fscp = C_TO_FSCACHE(cp);
	int error = 0;
	offset_t off;
	caddr_t buf;
	int buflen;
	rl_entry_t rl_ent;
	u_offset_t cnode_size;

	rw_enter(&cp->c_rwlock, RW_WRITER);
	mutex_enter(&cp->c_statelock);

	/* done if cannot write to cache */
	if ((cp->c_filegrp->fg_flags & CFS_FG_WRITE) == 0) {
		error = EROFS;
		goto out;
	}

	/* done if not usable */
	if (cp->c_flags & (CN_STALE | CN_DESTROY)) {
		error = ESTALE;
		goto out;
	}

	/* make sure up to date */
	error = CFSOP_CHECK_COBJECT(fscp, cp, C_BACK_CHECK, cr);
	if (error)
		goto out;

	/* make it cachable */
	cp->c_flags &= ~CN_NOCACHE;

	/* get a metadata slot if we do not have one yet */
	if (cp->c_flags & CN_ALLOC_PENDING) {
		if (cp->c_filegrp->fg_flags & CFS_FG_ALLOC_ATTR) {
			(void) filegrp_allocattr(cp->c_filegrp);
		}
		error = filegrp_create_metadata(cp->c_filegrp,
		    &cp->c_metadata, &cp->c_id);
		if (error)
			goto out;
		cp->c_flags &= ~CN_ALLOC_PENDING;
		cp->c_flags |= CN_UPDATED;
	}

	/* cache the ACL if necessary */
	if (((fscp->fs_info.fi_mntflags & CFS_NOACL) == 0) &&
	    (cachefs_vtype_aclok(vp)) &&
	    ((cp->c_metadata.md_flags & MD_ACL) == 0)) {
		error = cachefs_cacheacl(cp, NULL);
		if (error != 0)
			goto out;
	}

	/* directory */
	if (vp->v_type == VDIR) {
		if (cp->c_metadata.md_flags & MD_POPULATED)
			goto out;

		if (error = cachefs_dir_fill(cp, cr))
			goto out;
	}

	/* regular file */
	else if (vp->v_type == VREG) {
		if (cp->c_metadata.md_flags & MD_POPULATED)
			goto out;

		if (cp->c_backvp == NULL) {
			error = cachefs_getbackvp(fscp, cp);
			if (error)
				goto out;
		}
		if (cp->c_frontvp == NULL) {
			error = cachefs_getfrontfile(cp);
			if (error)
				goto out;
		}
		/* populate the file */
		off = (offset_t)0;
		cnode_size = cp->c_attr.va_size;
		while (off < cnode_size) {
			if (!cachefs_check_allocmap(cp, off)) {
				u_offset_t popoff;
				size_t popsize;

				cachefs_cluster_allocmap(off, &popoff,
				    &popsize, (size_t)DEF_POP_SIZE, cp);
				if (popsize != 0) {
					error = cachefs_populate(cp, popoff,
					    popsize, cp->c_frontvp,
					    cp->c_backvp, cp->c_size, cr);
					if (error)
						goto out;
					else
						cp->c_flags |= (CN_UPDATED |
						    CN_NEED_FRONT_SYNC |
						    CN_POPULATION_PENDING);
					popsize = popsize - (off - popoff);
				}
			}
			off += PAGESIZE;
		}
	}

	/* symbolic link */
	else if (vp->v_type == VLNK) {
		if (cp->c_metadata.md_flags & (MD_POPULATED | MD_FASTSYMLNK))
			goto out;

		/* get the sym link contents from the back fs */
		error = cachefs_readlink_back(cp, cr, &buf, &buflen);
		if (error)
			goto out;

		/* try to cache the sym link */
		error = cachefs_stuffsymlink(cp, buf, buflen);
		cachefs_kmem_free(buf, MAXPATHLEN);
	}

	/* assume that all other types fit in the attributes */

out:
	/* get the rl slot if needed */
	if ((error == 0) && (cp->c_metadata.md_rlno == 0)) {
		rl_ent.rl_fileno = cp->c_id.cid_fileno;
		rl_ent.rl_local = (cp->c_id.cid_flags & CFS_CID_LOCAL) ? 1 : 0;
		rl_ent.rl_fsid = fscp->fs_cfsid;
		rl_ent.rl_attrc = 0;
		cp->c_metadata.md_rltype = CACHEFS_RL_NONE;
		error = cachefs_rl_alloc(fscp->fs_cache, &rl_ent,
		    &cp->c_metadata.md_rlno);
		if (error == 0)
			error = filegrp_ffhold(cp->c_filegrp);
	}

	/* mark the file as packed */
	if (error == 0) {
		/* modified takes precedence over packed */
		if (cp->c_metadata.md_rltype != CACHEFS_RL_MODIFIED) {
			cachefs_rlent_moveto(fscp->fs_cache,
			    CACHEFS_RL_PACKED, cp->c_metadata.md_rlno,
			    cp->c_metadata.md_frontblks);
			cp->c_metadata.md_rltype = CACHEFS_RL_PACKED;
		}
		cp->c_metadata.md_flags |= MD_PACKED;
		cp->c_flags |= CN_UPDATED;
	}

	mutex_exit(&cp->c_statelock);
	rw_exit(&cp->c_rwlock);

	return (error);
}

/*
 * Unpack a file from the cache
 *	dvp is the directory the file resides in.
 *	name is the name of the file.
 *	Returns 0 or an error if could not perform the operation.
 */
int
cachefs_unpack(struct vnode *dvp, char *name, cred_t *cr)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(dvp));
	int error = 0;
	int connected = 0;
	vnode_t *vp;

	/* Return error if NFSv4 is the backfs (no caching) */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		goto out;
	}

	for (;;) {
		/* get access to the file system */
		error = cachefs_cd_access(fscp, connected, 0);
		if (error)
			break;

		/* lookup the file name */
		error = cachefs_lookup_common(dvp, name, &vp, NULL, 0, NULL,
		    cr);
		if (error == 0) {
			error = cachefs_unpack_common(vp);
			VN_RELE(vp);
		}
		if (CFS_TIMEOUT(fscp, error)) {
			if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
				cachefs_cd_release(fscp);
				cachefs_cd_timedout(fscp);
				connected = 0;
				continue;
			} else {
				cachefs_cd_release(fscp);
				connected = 1;
				continue;
			}
		}
		cachefs_cd_release(fscp);
		break;
	}
out:
	return (error);
}

/*
 * Unpacks the file belonging to the passed in vnode.
 */
static int
cachefs_unpack_common(vnode_t *vp)
{
	cnode_t *cp = VTOC(vp);
	fscache_t *fscp = C_TO_FSCACHE(cp);
	int error = 0;

	mutex_enter(&cp->c_statelock);

	/* nothing to do if not packed */
	if ((cp->c_metadata.md_flags & MD_PACKED) == 0)
		goto out;

	/* nothing to do if cannot modify cache */
	if ((cp->c_filegrp->fg_flags & CFS_FG_WRITE) == 0) {
		error = EROFS;
		goto out;
	}

	/* mark file as no longer packed */
	ASSERT(cp->c_metadata.md_rlno);
	cp->c_metadata.md_flags &= ~MD_PACKED;
	cp->c_flags |= CN_UPDATED;

	/* done if file has been modified */
	if (cp->c_metadata.md_rltype == CACHEFS_RL_MODIFIED)
		goto out;

	/* if there is no front file */
	if ((cp->c_metadata.md_flags & MD_FILE) == 0) {
		/* nuke front file resources */
		filegrp_ffrele(cp->c_filegrp);
		cachefs_rlent_moveto(fscp->fs_cache,
		    CACHEFS_RL_FREE, cp->c_metadata.md_rlno, 0);
		cp->c_metadata.md_rlno = 0;
		cp->c_metadata.md_rltype = CACHEFS_RL_NONE;
	}

	/* else move the front file to the active list */
	else {
		cachefs_rlent_moveto(fscp->fs_cache,
		    CACHEFS_RL_ACTIVE, cp->c_metadata.md_rlno,
		    cp->c_metadata.md_frontblks);
		cp->c_metadata.md_rltype = CACHEFS_RL_ACTIVE;
	}

out:
	mutex_exit(&cp->c_statelock);
	return (error);
}

/*
 * Returns packing information on a file.
 *	dvp is the directory the file resides in.
 *	name is the name of the file.
 *	*statusp is set to the status of the file
 *	Returns 0 or an error if could not perform the operation.
 */
int
cachefs_packinfo(struct vnode *dvp, char *name, int *statusp, cred_t *cr)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(dvp));
	struct vnode *vp;
	struct cnode *cp;
	int error;
	int connected = 0;

	*statusp = 0;

	/*
	 * Return if NFSv4 is the backfs (no caching).
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		goto out;
	}

	for (;;) {
		/* get access to the file system */
		error = cachefs_cd_access(fscp, connected, 0);
		if (error)
			break;

		/* lookup the file name */
		error = cachefs_lookup_common(dvp, name, &vp, NULL, 0, NULL,
		    cr);
		if (CFS_TIMEOUT(fscp, error)) {
			if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
				cachefs_cd_release(fscp);
				cachefs_cd_timedout(fscp);
				connected = 0;
				continue;
			} else {
				cachefs_cd_release(fscp);
				connected = 1;
				continue;
			}
		}
		if (error)
			break;
		cp = VTOC(vp);

		mutex_enter(&cp->c_statelock);
		if (cp->c_metadata.md_flags & MD_PACKED)
			*statusp |= CACHEFS_PACKED_FILE;
		if (cp->c_metadata.md_flags & (MD_POPULATED | MD_FASTSYMLNK))
			*statusp |= CACHEFS_PACKED_DATA;
		else if ((vp->v_type != VREG) &&
		    (vp->v_type != VDIR) &&
		    (vp->v_type != VLNK))
			*statusp |= CACHEFS_PACKED_DATA;
		else if (cp->c_size == 0)
			*statusp |= CACHEFS_PACKED_DATA;
		if (cp->c_flags & CN_NOCACHE)
			*statusp |= CACHEFS_PACKED_NOCACHE;
		mutex_exit(&cp->c_statelock);

		VN_RELE(vp);
		cachefs_cd_release(fscp);
		break;
	}

out:
	return (error);
}

/*
 * Finds all packed files in the cache and unpacks them.
 */
int
cachefs_unpackall(vnode_t *vp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	cachefscache_t *cachep = fscp->fs_cache;
	int error;

	/*
	 * Return if NFSv4 is the backfs (no caching).
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		goto out;
	}

	error = cachefs_unpackall_list(cachep, CACHEFS_RL_PACKED);
	if (error)
		goto out;
	error = cachefs_unpackall_list(cachep, CACHEFS_RL_PACKED_PENDING);
out:
	return (error);
}

/*
 * Finds all packed files on the specified list and unpacks them.
 */
static int
cachefs_unpackall_list(cachefscache_t *cachep, enum cachefs_rl_type type)
{
	fscache_t *fscp = NULL;
	cnode_t *cp;
	int error = 0;
	rl_entry_t rl_ent;
	cfs_cid_t cid;

	rl_ent.rl_current = type;
	for (;;) {
		/* get the next entry on the specified resource list */
		error = cachefs_rlent_data(cachep, &rl_ent, NULL);
		if (error) {
			error = 0;
			break;
		}

		/* if the fscp we have does not match */
		if ((fscp == NULL) || (fscp->fs_cfsid != rl_ent.rl_fsid)) {
			if (fscp) {
				cachefs_cd_release(fscp);
				fscache_rele(fscp);
				fscp = NULL;
			}

			/* get the file system cache object for this fsid */
			mutex_enter(&cachep->c_fslistlock);
			fscp = fscache_list_find(cachep, rl_ent.rl_fsid);
			if (fscp == NULL) {
				fscp = fscache_create(cachep);
				error = fscache_activate(fscp, rl_ent.rl_fsid,
				    NULL, NULL, 0);
				if (error) {
					cmn_err(CE_WARN,
					    "cachefs: cache error, run fsck\n");
					fscache_destroy(fscp);
					fscp = NULL;
					mutex_exit(&cachep->c_fslistlock);
					break;
				}
				fscache_list_add(cachep, fscp);
			}
			fscache_hold(fscp);
			mutex_exit(&cachep->c_fslistlock);

			/* get access to the file system */
			error = cachefs_cd_access(fscp, 0, 0);
			if (error) {
				fscache_rele(fscp);
				fscp = NULL;
				break;
			}
		}

		/* get the cnode for the file */
		cid.cid_fileno = rl_ent.rl_fileno;
		cid.cid_flags = rl_ent.rl_local ? CFS_CID_LOCAL : 0;
		error = cachefs_cnode_make(&cid, fscp,
		    NULL, NULL, NULL, kcred, 0, &cp);
		if (error) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_IOCTL)
				printf("cachefs: cul: could not find %llu\n",
				    (u_longlong_t)cid.cid_fileno);
			delay(5*hz);
#endif
			continue;
		}

		/* unpack the file */
		(void) cachefs_unpack_common(CTOV(cp));
		VN_RELE(CTOV(cp));
	}

	/* free up allocated resources */
	if (fscp) {
		cachefs_cd_release(fscp);
		fscache_rele(fscp);
	}
	return (error);
}

/*
 * Identifies this process as the cachefsd.
 * Stays this way until close is done.
 */
int
/*ARGSUSED*/
cachefs_io_daemonid(vnode_t *vp, void *dinp, void *doutp)
{
	int error = 0;

	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	cachefscache_t *cachep = fscp->fs_cache;

	mutex_enter(&fscp->fs_cdlock);

	/* can only do this on the root of the file system */
	if (vp != fscp->fs_rootvp)
		error = ENOENT;

	/* else if there already is a daemon running */
	else if (fscp->fs_cddaemonid)
		error = EBUSY;

	/* else use the pid to identify the daemon */
	else {
		fscp->fs_cddaemonid = ttoproc(curthread)->p_pid;
		cv_broadcast(&fscp->fs_cdwaitcv);
	}

	mutex_exit(&fscp->fs_cdlock);

	if (error == 0) {
		/* the daemon that takes care of root is special */
		if (fscp->fs_flags & CFS_FS_ROOTFS) {
			mutex_enter(&cachep->c_contentslock);
			ASSERT(cachep->c_rootdaemonid == 0);
			cachep->c_rootdaemonid = fscp->fs_cddaemonid;
			mutex_exit(&cachep->c_contentslock);
		}
	}
	return (error);
}

/*
 * Returns the current state in doutp
 */
int
/*ARGSUSED*/
cachefs_io_stateget(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	int *statep = (int *)doutp;
	int state;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	mutex_enter(&fscp->fs_cdlock);
	switch (fscp->fs_cdconnected) {
	case CFS_CD_CONNECTED:
		state = CFS_FS_CONNECTED;
		break;
	case CFS_CD_DISCONNECTED:
		state = CFS_FS_DISCONNECTED;
		break;
	case CFS_CD_RECONNECTING:
		state = CFS_FS_RECONNECTING;
		break;
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&fscp->fs_cdlock);

	*statep = state;
	return (0);
}

/*
 * Sets the state of the file system.
 */
int
/*ARGSUSED*/
cachefs_io_stateset(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	int nosig = 1;
	int state = *(int *)dinp;

	/*
	 * State should not be changeable and always be connected if
	 * NFSv4 is in use.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* wait until the file system is quiet */
	mutex_enter(&fscp->fs_cdlock);
	if (fscp->fs_cdtransition == 1) {
		/* if someone is already changing the state */
		mutex_exit(&fscp->fs_cdlock);
		return (0);
	}
	fscp->fs_cdtransition = 1;
	while (nosig && (fscp->fs_cdrefcnt != 0)) {
		nosig = cv_wait_sig(&fscp->fs_cdwaitcv, &fscp->fs_cdlock);
	}
	if (!nosig) {
		fscp->fs_cdtransition = 0;
		cv_broadcast(&fscp->fs_cdwaitcv);
		mutex_exit(&fscp->fs_cdlock);
		return (EINTR);
	}
	mutex_exit(&fscp->fs_cdlock);

	switch (state) {
	case CFS_FS_CONNECTED:
		/* done if already in this state */
		if (fscp->fs_cdconnected == CFS_CD_CONNECTED)
			break;

		mutex_enter(&fscp->fs_cdlock);
		fscp->fs_cdconnected = CFS_CD_CONNECTED;
		mutex_exit(&fscp->fs_cdlock);

		/* fix up modified files */
		cachefs_modified_fix(fscp);

#if 0
		if (fscp->fs_hostname != NULL)
			printf("\ncachefs:server          - %s",
			    fscp->fs_hostname);
		if (fscp->fs_mntpt != NULL)
			printf("\ncachefs:mount point     - %s",
			    fscp->fs_mntpt);
		if (fscp->fs_backfsname != NULL)
			printf("\ncachefs:back filesystem - %s",
			    fscp->fs_backfsname);
		printf("\nok\n");
#else
		if (fscp->fs_hostname && fscp->fs_backfsname)
			printf("cachefs: %s:%s ok\n",
			    fscp->fs_hostname, fscp->fs_backfsname);
		else
			printf("cachefs: server ok\n");
#endif

		/* allow deletion of renamed open files to proceed */
		cachefs_cnode_traverse(fscp, allow_pendrm);
		break;

	case CFS_FS_DISCONNECTED:
		/* done if already in this state */
		if (fscp->fs_cdconnected == CFS_CD_DISCONNECTED)
			break;

		/* drop all back vps */
		cachefs_cnode_traverse(fscp, drop_backvp);


		mutex_enter(&fscp->fs_cdlock);
		fscp->fs_cdconnected = CFS_CD_DISCONNECTED;
		mutex_exit(&fscp->fs_cdlock);

#if 0
		if (fscp->fs_hostname != NULL)
			printf("\ncachefs:server          - %s",
			    fscp->fs_hostname);
		if (fscp->fs_mntpt != NULL)
			printf("\ncachefs:mount point     - %s",
			    fscp->fs_mntpt);
		if (fscp->fs_backfsname != NULL)
			printf("\ncachefs:back filesystem - %s",
			    fscp->fs_backfsname);
		printf("\nnot responding still trying\n");
#else
		if (fscp->fs_hostname && fscp->fs_backfsname)
			printf("cachefs: %s:%s not responding still trying\n",
			    fscp->fs_hostname, fscp->fs_backfsname);
		else
			printf("cachefs: server not responding still trying\n");
#endif
		break;

	case CFS_FS_RECONNECTING:
		/* done if already in this state */
		if (fscp->fs_cdconnected == CFS_CD_RECONNECTING)
			break;

		/*
		 * Before we enter disconnected state we sync all metadata,
		 * this allows us to read metadata directly in subsequent
		 * calls so we don't need to allocate cnodes when
		 * we just need metadata information.
		 */
		/* XXX bob: need to eliminate this */
		cachefs_cnode_traverse(fscp, sync_metadata);

		mutex_enter(&fscp->fs_cdlock);
		fscp->fs_cdconnected = CFS_CD_RECONNECTING;
		mutex_exit(&fscp->fs_cdlock);

		/* no longer need dlog active */
		cachefs_dlog_teardown(fscp);
		break;

	default:
		error = ENOTTY;
		break;
	}

	mutex_enter(&fscp->fs_cdlock);
	fscp->fs_cdtransition = 0;
	cv_broadcast(&fscp->fs_cdwaitcv);
	mutex_exit(&fscp->fs_cdlock);
	return (error);
}

/*
 * Blocks until the file system switches
 * out of the connected state.
 */
int
/*ARGSUSED*/
cachefs_io_xwait(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	int nosig = 1;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not used when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	mutex_enter(&fscp->fs_cdlock);
	while (nosig &&
	    (fscp->fs_cdconnected == CFS_CD_CONNECTED)) {
		nosig = cv_wait_sig(&fscp->fs_cdwaitcv, &fscp->fs_cdlock);
	}
	mutex_exit(&fscp->fs_cdlock);
	if (!nosig)
		return (EINTR);

	return (0);
}

#define	RL_HEAD(cachep, type) \
	(&(cachep->c_rlinfo.rl_items[CACHEFS_RL_INDEX(type)]))

/*
 * Returns some statistics about the cache.
 */
#define	CFS_STAT_FACTOR		(MAXBSIZE / 1024)
int
/*ARGSUSED*/
cachefs_io_getstats(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	cachefscache_t *cachep = fscp->fs_cache;
	struct statvfs64 sb;
	fsblkcnt64_t avail = 0;
	fsblkcnt64_t blocks;
	int error;
	cachefsio_getstats_t *gsp = (cachefsio_getstats_t *)doutp;

	/* determine number of blocks available to the cache */
	error = VFS_STATVFS(cachep->c_dirvp->v_vfsp, &sb);
	if (error == 0) {
		blocks = (fsblkcnt64_t)(cachep->c_label.cl_maxblks -
		    cachep->c_usage.cu_blksused);
		if ((longlong_t)blocks < (longlong_t)0)
			blocks = (fsblkcnt64_t)0;
		avail = (sb.f_bfree * sb.f_frsize) / MAXBSIZE;
		if (blocks < avail)
			avail = blocks;
	}

	gsp->gs_total = cachep->c_usage.cu_blksused * CFS_STAT_FACTOR;
	gsp->gs_gc = RL_HEAD(cachep, CACHEFS_RL_GC)->rli_blkcnt *
		CFS_STAT_FACTOR;
	gsp->gs_active = RL_HEAD(cachep, CACHEFS_RL_ACTIVE)->rli_blkcnt *
		CFS_STAT_FACTOR;
	gsp->gs_packed = RL_HEAD(cachep, CACHEFS_RL_PACKED)->rli_blkcnt *
		CFS_STAT_FACTOR;
	gsp->gs_free = (long)(avail * CFS_STAT_FACTOR);
	gsp->gs_gctime = cachep->c_rlinfo.rl_gctime;
	return (0);
}

/*
 * This looks to see if the specified file exists in the cache.
 * 	0 is returned if it exists
 *	ENOENT is returned if it doesn't exist.
 */
int
/*ARGSUSED*/
cachefs_io_exists(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	cnode_t *cp = NULL;
	int error;
	cfs_cid_t *cidp = (cfs_cid_t *)dinp;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* find the cnode of the file */
	error = cachefs_cnode_make(cidp, fscp,
	    NULL, NULL, NULL, kcred, 0, &cp);
	if (error)
		return (ENOENT);

	if ((cp->c_flags & (CN_DESTROY | CN_NOCACHE)) ||
	    !(cp->c_metadata.md_flags & (MD_POPULATED | MD_FASTSYMLNK)))
		error = ENOENT;

	VN_RELE(CTOV(cp));
	return	(error);

}

/*
 * Moves the specified file to the lost+found directory for the
 * cached file system.
 * Invalidates cached data and attributes.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_lostfound(vnode_t *vp, void *dinp, void *doutp)
{
	int error;
	cnode_t *cp = NULL;
	fscache_t *fscp;
	cachefscache_t *cachep;
	cachefsio_lostfound_arg_t *lfp;
	cachefsio_lostfound_return_t *rp;

	lfp = (cachefsio_lostfound_arg_t *)dinp;
	rp = (cachefsio_lostfound_return_t *)doutp;

	fscp = C_TO_FSCACHE(VTOC(vp));
	cachep = fscp->fs_cache;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* find the cnode of the file */
	error = cachefs_cnode_make(&lfp->lf_cid, fscp,
	    NULL, NULL, NULL, kcred, 0, &cp);
	if (error) {
		error = ENOENT;
		goto out;
	}

	mutex_enter(&cp->c_statelock);

	/* must be regular file and modified */
	if ((cp->c_attr.va_type != VREG) ||
	    (cp->c_metadata.md_rltype != CACHEFS_RL_MODIFIED)) {
		mutex_exit(&cp->c_statelock);
		error = EINVAL;
		goto out;
	}

	/* move to lost+found */
	error = cachefs_cnode_lostfound(cp, lfp->lf_name);
	mutex_exit(&cp->c_statelock);

	if (error == 0)
		(void) strcpy(rp->lf_name, lfp->lf_name);
out:
	if (cp)
		VN_RELE(CTOV(cp));

	return (error);
}

/*
 * Given a cid, returns info about the file in the cache.
 */
int
cachefs_io_getinfo(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	struct cnode *dcp = NULL;
	struct cnode *cp = NULL;
	struct vattr va;
	u_offset_t blockoff = 0;
	struct fbuf *fbp;
	int offset = 0;
	int error = 0;
	cfs_cid_t *fcidp;
	cachefsio_getinfo_t *infop;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	fcidp = (cfs_cid_t *)dinp;
	infop = (cachefsio_getinfo_t *)doutp;

	/* find the cnode of the file */
	error = cachefs_cnode_make(fcidp, fscp, NULL, NULL, NULL,
	    kcred, 0, &cp);
	if (error) {
		error = ENOENT;
		goto out;
	}

	infop->gi_cid = *fcidp;
	infop->gi_modified = (cp->c_metadata.md_rltype == CACHEFS_RL_MODIFIED);
	CACHEFS_VATTR_TO_CFS_VATTR_COPY(&cp->c_attr, &infop->gi_attr, error);
	infop->gi_pcid = cp->c_metadata.md_parent;
	infop->gi_name[0] = '\0';
	infop->gi_seq = cp->c_metadata.md_seq;
	if (error || (cp->c_metadata.md_parent.cid_fileno == 0))
		goto out;

	/* try to get the cnode of the parent dir */
	error = cachefs_cnode_make(&cp->c_metadata.md_parent, fscp,
	    NULL, NULL, NULL, kcred, 0, &dcp);
	if (error) {
		error = 0;
		goto out;
	}

	/* make sure a directory and populated */
	if ((((dcp->c_flags & CN_ASYNC_POPULATE) == 0) ||
	    ((dcp->c_metadata.md_flags & MD_POPULATED) == 0)) &&
	    (CTOV(dcp)->v_type == VDIR)) {
		error = 0;
		goto out;
	}

	/* get the front file */
	if (dcp->c_frontvp == NULL) {
		mutex_enter(&dcp->c_statelock);
		error = cachefs_getfrontfile(dcp);
		mutex_exit(&dcp->c_statelock);
		if (error) {
			error = 0;
			goto out;
		}

		/* make sure frontvp is still populated */
		if ((dcp->c_metadata.md_flags & MD_POPULATED) == 0) {
			error = 0;
			goto out;
		}
	}

	/* Get the length of the directory */
	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(dcp->c_frontvp, &va, 0, kcred, NULL);
	if (error) {
		error = 0;
		goto out;
	}

	/* XXX bob: change this to use cachfs_dir_read */
	/* We have found the parent, now we open the dir and look for file */
	while (blockoff < va.va_size) {
		offset = 0;
		error = fbread(dcp->c_frontvp, (offset_t)blockoff, MAXBSIZE,
						S_OTHER, &fbp);
		if (error)
			goto out;
		while (offset < MAXBSIZE && (blockoff + offset) < va.va_size) {
			struct c_dirent	*dep;
			dep = (struct c_dirent *)((uintptr_t)fbp->fb_addr +
									offset);
			if ((dep->d_flag & CDE_VALID) &&
			    (bcmp(&dep->d_id, &infop->gi_cid,
			    sizeof (cfs_cid_t)) == 0)) {
				/* found the name */
				(void) strcpy(infop->gi_name, dep->d_name);
				fbrelse(fbp, S_OTHER);
				goto out;
			}
			offset += dep->d_length;
		}
		fbrelse(fbp, S_OTHER);
		fbp = NULL;
		blockoff += MAXBSIZE;

	}
out:
	if (cp)
		VN_RELE(CTOV(cp));
	if (dcp)
		VN_RELE(CTOV(dcp));
	return (error);
}

/*
 * Given a file number, this functions returns the fid
 * for the back file system.
 * Returns ENOENT if file does not exist.
 * Returns ENOMSG if fid is not valid, ie: local file.
 */
int
cachefs_io_cidtofid(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	cnode_t *cp = NULL;
	int error;
	cfs_cid_t *cidp = (cfs_cid_t *)dinp;
	cfs_fid_t *fidp = (cfs_fid_t *)doutp;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* get the cnode for the file */
	error = cachefs_cnode_make(cidp, fscp, NULL, NULL, NULL, kcred, 0, &cp);
	if (error)
		goto out;

	/* if local file, fid is a local fid and is not valid */
	if (cp->c_id.cid_flags & CFS_CID_LOCAL) {
		error = ENOMSG;
		goto out;
	}

	/* copy out the fid */
	CACHEFS_FID_COPY(&cp->c_cookie, fidp);

out:
	if (cp)
		VN_RELE(CTOV(cp));
	return	(error);
}

/*
 * This performs a getattr on the back file system given
 * a fid that is passed in.
 *
 * The backfid is in gafid->cg_backfid, the creds to use for
 * this operation are in gafid->cg_cred.  The attributes are
 * returned in gafid->cg_attr
 *
 * the error returned is 0 if successful, nozero if not
 */
int
cachefs_io_getattrfid(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*backvp = NULL;
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	cred_t	*cr;
	cachefsio_getattrfid_t *gafid;
	fid_t	*tmpfidp;
	vattr_t *tmpvap;
	cfs_vattr_t *attrp;
	CACHEFS_DECL(fid_t, tmpfid);
	CACHEFS_DECL(vattr_t, va);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	gafid = (cachefsio_getattrfid_t *)dinp;
	attrp = (cfs_vattr_t *)doutp;

	/* Get a vnode for the back file */
	CACHEFS_TMPPTR_SET(&gafid->cg_backfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&gafid->cg_backfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &backvp, tmpfidp);
	if (error)
		return (error);

	cr = conj_cred(&gafid->cg_cred);
	CACHEFS_TMPPTR_SET(attrp, &va, tmpvap, vattr_t);
	tmpvap->va_mask = AT_ALL;
	error = VOP_GETATTR(backvp, tmpvap, 0, cr, NULL);
	CACHEFS_VATTR_COPYOUT(tmpvap, attrp, error);
	crfree(cr);

	/* VFS_VGET performs a VN_HOLD on the vp */
	VN_RELE(backvp);

	return (error);
}


/*
 * This performs a getattr on the back file system.  Instead of
 * passing the fid to perform the gettr on we are given the
 * parent directory fid and a name.
 */
int
cachefs_io_getattrname(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*pbackvp = NULL;
	vnode_t	*cbackvp = NULL;
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	cred_t	*cr;
	fid_t	*tmpfidp;
	vattr_t	*tmpvap;
	cachefsio_getattrname_arg_t *gap;
	cachefsio_getattrname_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);
	CACHEFS_DECL(vattr_t, va);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	gap = (cachefsio_getattrname_arg_t *)dinp;
	retp = (cachefsio_getattrname_return_t *)doutp;

	/* Get a vnode for the parent directory */
	CACHEFS_TMPPTR_SET(&gap->cg_dir, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&gap->cg_dir, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &pbackvp, tmpfidp);
	if (error)
		return (error);

	/* lookup the file name */
	cr = conj_cred(&gap->cg_cred);
	error = VOP_LOOKUP(pbackvp, gap->cg_name, &cbackvp,
	    (struct pathname *)NULL, 0, (vnode_t *)NULL, cr, NULL, NULL, NULL);
	if (error) {
		crfree(cr);
		VN_RELE(pbackvp);
		return (error);
	}

	CACHEFS_TMPPTR_SET(&retp->cg_attr, &va, tmpvap, vattr_t);
	tmpvap->va_mask = AT_ALL;
	error = VOP_GETATTR(cbackvp, tmpvap, 0, cr, NULL);
	CACHEFS_VATTR_COPYOUT(tmpvap, &retp->cg_attr, error);
	if (!error) {
		CACHEFS_TMPPTR_SET(&retp->cg_fid, &tmpfid, tmpfidp, fid_t);
		tmpfidp->fid_len = MAXFIDSZ;
		error = VOP_FID(cbackvp, tmpfidp, NULL);
		CACHEFS_FID_COPYOUT(tmpfidp, &retp->cg_fid);
	}

	crfree(cr);
	VN_RELE(cbackvp);
	VN_RELE(pbackvp);
	return (error);
}

/*
 * This will return the fid of the root of this mount point.
 */
int
/*ARGSUSED*/
cachefs_io_rootfid(vnode_t *vp, void *dinp, void *doutp)
{
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	cfs_fid_t *rootfid = (cfs_fid_t *)doutp;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	CACHEFS_FID_COPY(&VTOC(fscp->fs_rootvp)->c_metadata.md_cookie, rootfid);
	return (0);
}

/*
 * Pushes the data associated with a file back to the file server.
 */
int
cachefs_io_pushback(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t *backvp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	caddr_t	buffer = NULL;
	int error = 0;
	cnode_t	*cp;
	size_t amt;
	u_offset_t size;
	vattr_t	va;
	offset_t off;
	cred_t *cr = NULL;
	fid_t	*tmpfidp;
	cachefsio_pushback_arg_t *pbp;
	cachefsio_pushback_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	pbp = (cachefsio_pushback_arg_t *)dinp;
	retp = (cachefsio_pushback_return_t *)doutp;

	cr = conj_cred(&pbp->pb_cred);

	/* get the backvp to push to */
	CACHEFS_TMPPTR_SET(&pbp->pb_fid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&pbp->pb_fid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &backvp, tmpfidp);
	if (error) {
		backvp = NULL;
		goto out;
	}

	/* Get the cnode for the file we are to push back */
	error = cachefs_cnode_make(&pbp->pb_cid, fscp,
	    NULL, NULL, NULL, cr, 0, &cp);
	if (error) {
		goto out;
	}

	/* must be a regular file */
	if (cp->c_attr.va_type != VREG) {
		error = EINVAL;
		goto out;
	}

	mutex_enter(&cp->c_statelock);

	/* get the front file */
	if (cp->c_frontvp == NULL) {
		error = cachefs_getfrontfile(cp);
		if (error) {
			mutex_exit(&cp->c_statelock);
			goto out;
		}
	}

	/* better be populated */
	if ((cp->c_metadata.md_flags & MD_POPULATED) == 0) {
		mutex_exit(&cp->c_statelock);
		error = EINVAL;
		goto out;
	}

	/* do open so NFS gets correct creds on writes */
	error = VOP_OPEN(&backvp, FWRITE, cr, NULL);
	if (error) {
		mutex_exit(&cp->c_statelock);
		goto out;
	}

	buffer = cachefs_kmem_alloc(MAXBSIZE, KM_SLEEP);

	/* Read the data from the cache and write it to the server */
	/* XXX why not use segmapio? */
	off = 0;
	for (size = cp->c_size; size != 0; size -= amt) {
		if (size > MAXBSIZE)
			amt = MAXBSIZE;
		else
			amt = size;

		/* read a block of data from the front file */
		error = vn_rdwr(UIO_READ, cp->c_frontvp, buffer,
			amt, off, UIO_SYSSPACE, 0, RLIM_INFINITY, cr, 0);
		if (error) {
			mutex_exit(&cp->c_statelock);
			goto out;
		}

		/* write the block of data to the back file */
		error = vn_rdwr(UIO_WRITE, backvp, buffer, amt, off,
			UIO_SYSSPACE, 0, RLIM_INFINITY, cr, 0);
		if (error) {
			mutex_exit(&cp->c_statelock);
			goto out;
		}
		off += amt;
	}

	error = VOP_FSYNC(backvp, FSYNC, cr, NULL);
	if (error == 0)
		error = VOP_CLOSE(backvp, FWRITE, 1, (offset_t)0, cr, NULL);
	if (error) {
		mutex_exit(&cp->c_statelock);
		goto out;
	}

	cp->c_metadata.md_flags |= MD_PUSHDONE;
	cp->c_metadata.md_flags &= ~MD_PUTPAGE;
	cp->c_metadata.md_flags |= MD_NEEDATTRS;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);

	/*
	 * if we have successfully stored the data, we need the
	 * new ctime and mtimes.
	 */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(backvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->pb_ctime, error);
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_mtime, &retp->pb_mtime, error);

out:
	if (buffer)
		cachefs_kmem_free(buffer, MAXBSIZE);
	if (cp)
		VN_RELE(CTOV(cp));
	if (backvp)
		VN_RELE(backvp);
	if (cr)
		crfree(cr);
	return (error);
}

/*
 * Create a file on the back file system.
 */
int
cachefs_io_create(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	vnode_t	*cvp = NULL;
	cnode_t *cp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	vattr_t	va, *tmpvap;
	int error = 0;
	cred_t *cr = NULL;
	fid_t	*tmpfidp;
	cachefsio_create_arg_t *crp;
	cachefsio_create_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	crp = (cachefsio_create_arg_t *)dinp;
	retp = (cachefsio_create_return_t *)doutp;

	/* get a vnode for the parent directory  */
	CACHEFS_TMPPTR_SET(&crp->cr_backfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&crp->cr_backfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, tmpfidp);
	if (error)
		goto out;

	cr = conj_cred(&crp->cr_cred);

	/* do the create */
	CACHEFS_TMPPTR_SET(&crp->cr_va, &va, tmpvap, vattr_t);
	CACHEFS_VATTR_COPYIN(&crp->cr_va, tmpvap);
	error = VOP_CREATE(dvp, crp->cr_name, tmpvap,
	    crp->cr_exclusive, crp->cr_mode, &cvp, cr, 0, NULL, NULL);
	if (error)
		goto out;

	/* get the fid of the file */
	CACHEFS_TMPPTR_SET(&retp->cr_newfid, &tmpfid, tmpfidp, fid_t);
	tmpfidp->fid_len = MAXFIDSZ;
	error = VOP_FID(cvp, tmpfidp, NULL);
	if (error)
		goto out;
	CACHEFS_FID_COPYOUT(tmpfidp, &retp->cr_newfid);

	/* get attributes for the file */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->cr_ctime, error);
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_mtime, &retp->cr_mtime, error);
	if (error)
		goto out;

	/* update the cnode for this file with the new info */
	error = cachefs_cnode_make(&crp->cr_cid, fscp,
	    NULL, NULL, NULL, cr, 0, &cp);
	if (error) {
		error = 0;
		goto out;
	}

	mutex_enter(&cp->c_statelock);
	ASSERT(cp->c_id.cid_flags & CFS_CID_LOCAL);
	cp->c_attr.va_nodeid = va.va_nodeid;
	cp->c_metadata.md_flags |= MD_CREATEDONE;
	cp->c_metadata.md_flags |= MD_NEEDATTRS;
	cp->c_metadata.md_cookie = *tmpfidp;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);

out:
	if (cr)
		crfree(cr);
	if (dvp)
		VN_RELE(dvp);
	if (cvp)
		VN_RELE(cvp);
	if (cp)
		VN_RELE(CTOV(cp));
	return (error);
}

/*
 * Remove a file on the back file system.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_remove(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	vnode_t	*cvp;
	cred_t *cr = NULL;
	vattr_t	va;
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	int error;
	fid_t child_fid, *child_fidp;
	cachefsio_remove_t *rmp = (cachefsio_remove_t *)dinp;
	cfs_timestruc_t *ctimep = (cfs_timestruc_t *)doutp;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* Get a vnode for the directory */
	CACHEFS_TMPPTR_SET(&rmp->rm_fid, &child_fid, child_fidp, fid_t);
	CACHEFS_FID_COPYIN(&rmp->rm_fid, child_fidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, child_fidp);
	if (error) {
		dvp = NULL;
		goto out;
	}

	cr = conj_cred(&rmp->rm_cred);

	/* if the caller wants the ctime after the remove */
	if (ctimep) {
		error = VOP_LOOKUP(dvp, rmp->rm_name, &cvp, NULL, 0, NULL, cr,
			NULL, NULL, NULL);
		if (error == 0) {
			child_fid.fid_len = MAXFIDSZ;
			error = VOP_FID(cvp, &child_fid, NULL);
			VN_RELE(cvp);
		}
		if (error)
			goto out;
	}

	/* do the remove */
	error = VOP_REMOVE(dvp, rmp->rm_name, cr, NULL, 0);
	if (error)
		goto out;

	/* get the new ctime if requested */
	if (ctimep) {
		error = VFS_VGET(fscp->fs_backvfsp, &cvp, &child_fid);
		if (error == 0) {
			va.va_mask = AT_ALL;
			error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
			if (error == 0) {
				CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime,
					ctimep, error);
			}
			VN_RELE(cvp);
		}
		cachefs_iosetneedattrs(fscp, &rmp->rm_cid);
	}

out:
	if (cr)
		crfree(cr);
	if (dvp)
		VN_RELE(dvp);
	return (error);
}

/*
 * Perform a link on the back file system.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_link(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	vnode_t	*lvp = NULL;
	vattr_t	va;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	cred_t *cr = NULL;
	fid_t *tmpfidp;
	cachefsio_link_t *linkp = (cachefsio_link_t *)dinp;
	cfs_timestruc_t *ctimep = (cfs_timestruc_t *)doutp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* Get a vnode parent directory */
	CACHEFS_TMPPTR_SET(&linkp->ln_dirfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&linkp->ln_dirfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, tmpfidp);
	if (error) {
		dvp = NULL;
		goto out;
	}

	/* Get a vnode file to link to */
	CACHEFS_TMPPTR_SET(&linkp->ln_filefid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&linkp->ln_filefid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &lvp, tmpfidp);
	if (error) {
		lvp = NULL;
		goto out;
	}

	cr = conj_cred(&linkp->ln_cred);

	/* do the link */
	error = VOP_LINK(dvp, lvp, linkp->ln_name, cr, NULL, 0);
	if (error)
		goto out;

	/* get the ctime */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(lvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, ctimep, error);
	if (error)
		goto out;

	cachefs_iosetneedattrs(fscp, &linkp->ln_cid);
out:
	if (cr)
		crfree(cr);
	if (dvp)
		VN_RELE(dvp);
	if (lvp)
		VN_RELE(lvp);
	return (error);
}

/*
 * Rename the file on the back file system.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_rename(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*odvp = NULL;
	vnode_t	*ndvp = NULL;
	cred_t *cr = NULL;
	vnode_t	*cvp = NULL;
	vattr_t va;
	fscache_t  *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	fid_t child_fid, *child_fidp;
	cachefsio_rename_arg_t *rnp;
	cachefsio_rename_return_t *retp;

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	rnp = (cachefsio_rename_arg_t *)dinp;
	retp = (cachefsio_rename_return_t *)doutp;

	/* Get vnode of old parent directory */
	CACHEFS_TMPPTR_SET(&rnp->rn_olddir, &child_fid, child_fidp, fid_t);
	CACHEFS_FID_COPYIN(&rnp->rn_olddir, child_fidp);
	error = VFS_VGET(fscp->fs_backvfsp, &odvp, child_fidp);
	if (error) {
		odvp = NULL;
		goto out;
	}

	/* Get vnode of new parent directory */
	CACHEFS_TMPPTR_SET(&rnp->rn_newdir, &child_fid, child_fidp, fid_t);
	CACHEFS_FID_COPYIN(&rnp->rn_newdir, child_fidp);
	error = VFS_VGET(fscp->fs_backvfsp, &ndvp, child_fidp);
	if (error) {
		ndvp = NULL;
		goto out;
	}

	cr = conj_cred(&rnp->rn_cred);

	/* if the caller wants the ctime of the target after deletion */
	if (rnp->rn_del_getctime) {
		error = VOP_LOOKUP(ndvp, rnp->rn_newname, &cvp, NULL, 0,
		    NULL, cr, NULL, NULL, NULL);
		if (error) {
			cvp = NULL; /* paranoia */
			goto out;
		}

		child_fid.fid_len = MAXFIDSZ;
		error = VOP_FID(cvp, &child_fid, NULL);
		if (error)
			goto out;
		VN_RELE(cvp);
		cvp = NULL;
	}

	/* do the rename */
	error = VOP_RENAME(odvp, rnp->rn_oldname, ndvp, rnp->rn_newname, cr,
		NULL, 0);
	if (error)
		goto out;

	/* get the new ctime on the renamed file */
	error = VOP_LOOKUP(ndvp, rnp->rn_newname, &cvp, NULL, 0, NULL, cr,
		NULL, NULL, NULL);
	if (error)
		goto out;

	va.va_mask = AT_ALL;
	error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->rn_ctime, error);
	VN_RELE(cvp);
	cvp = NULL;
	if (error)
		goto out;

	cachefs_iosetneedattrs(fscp, &rnp->rn_cid);

	/* get the new ctime if requested of the deleted target */
	if (rnp->rn_del_getctime) {
		error = VFS_VGET(fscp->fs_backvfsp, &cvp, &child_fid);
		if (error) {
			cvp = NULL;
			goto out;
		}
		va.va_mask = AT_ALL;
		error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
		if (error)
			goto out;
		CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->rn_del_ctime,
			error);
		VN_RELE(cvp);
		cvp = NULL;
		if (error)
			goto out;
		cachefs_iosetneedattrs(fscp, &rnp->rn_del_cid);
	}

out:
	if (cr)
		crfree(cr);
	if (cvp)
		VN_RELE(cvp);
	if (odvp)
		VN_RELE(odvp);
	if (ndvp)
		VN_RELE(ndvp);
	return (error);
}

/*
 * Make a directory on the backfs.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_mkdir(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	vnode_t	*cvp = NULL;
	cnode_t *cp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	int error = 0;
	cred_t *cr = NULL;
	fid_t	*tmpfidp;
	vattr_t va, *tmpvap;
	cachefsio_mkdir_t *mdirp = (cachefsio_mkdir_t *)dinp;
	cfs_fid_t *fidp = (cfs_fid_t *)doutp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* Get vnode of parent directory */
	CACHEFS_TMPPTR_SET(&mdirp->md_dirfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&mdirp->md_dirfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, tmpfidp);
	if (error) {
		dvp = NULL;
		goto out;
	}

	cr = conj_cred(&mdirp->md_cred);

	/* make the directory */
	CACHEFS_TMPPTR_SET(&mdirp->md_vattr, &va, tmpvap, vattr_t);
	CACHEFS_VATTR_COPYIN(&mdirp->md_vattr, tmpvap);
	error = VOP_MKDIR(dvp, mdirp->md_name, tmpvap, &cvp, cr, NULL, 0, NULL);
	if (error) {
		if (error != EEXIST)
			goto out;

		/* if the directory already exists, then use it */
		error = VOP_LOOKUP(dvp, mdirp->md_name, &cvp,
		    NULL, 0, NULL, cr, NULL, NULL, NULL);
		if (error) {
			cvp = NULL;
			goto out;
		}
		if (cvp->v_type != VDIR) {
			error = EINVAL;
			goto out;
		}
	}

	/* get the fid of the directory */
	CACHEFS_TMPPTR_SET(fidp, &tmpfid, tmpfidp, fid_t);
	tmpfidp->fid_len = MAXFIDSZ;
	error = VOP_FID(cvp, tmpfidp, NULL);
	if (error)
		goto out;
	CACHEFS_FID_COPYOUT(tmpfidp, fidp);

	/* get attributes of the directory */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
	if (error)
		goto out;

	/* update the cnode for this dir with the new fid */
	error = cachefs_cnode_make(&mdirp->md_cid, fscp,
	    NULL, NULL, NULL, cr, 0, &cp);
	if (error) {
		error = 0;
		goto out;
	}
	mutex_enter(&cp->c_statelock);
	ASSERT(cp->c_id.cid_flags & CFS_CID_LOCAL);
	cp->c_metadata.md_cookie = *tmpfidp;
	cp->c_metadata.md_flags |= MD_CREATEDONE;
	cp->c_metadata.md_flags |= MD_NEEDATTRS;
	cp->c_attr.va_nodeid = va.va_nodeid;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);
out:
	if (cr)
		crfree(cr);
	if (dvp)
		VN_RELE(dvp);
	if (cvp)
		VN_RELE(cvp);
	if (cp)
		VN_RELE(CTOV(cp));
	return (error);
}

/*
 * Perform a rmdir on the back file system.
 * Returns 0 or an error if could not perform operation.
 */
int
/*ARGSUSED*/
cachefs_io_rmdir(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	int error;
	cred_t *cr;
	fid_t	*tmpfidp;
	cachefsio_rmdir_t *rdp = (cachefsio_rmdir_t *)dinp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/* Get a vnode for the back file */
	CACHEFS_TMPPTR_SET(&rdp->rd_dirfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&rdp->rd_dirfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, tmpfidp);
	if (error) {
		dvp = NULL;
		return (error);
	}

	cr = conj_cred(&rdp->rd_cred);
	error = VOP_RMDIR(dvp, rdp->rd_name, dvp, cr, NULL, 0);
	crfree(cr);

	VN_RELE(dvp);
	return (error);
}

/*
 * create a symlink on the back file system
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_symlink(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*dvp = NULL;
	vnode_t	*svp = NULL;
	cnode_t *cp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	fid_t	*tmpfidp;
	vattr_t	va, *tmpvap;
	int error = 0;
	cred_t *cr = NULL;
	cachefsio_symlink_arg_t *symp;
	cachefsio_symlink_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	symp = (cachefsio_symlink_arg_t *)dinp;
	retp = (cachefsio_symlink_return_t *)doutp;

	/* get a vnode for the back directory */
	CACHEFS_TMPPTR_SET(&symp->sy_dirfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&symp->sy_dirfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &dvp, tmpfidp);
	if (error) {
		dvp = NULL;
		goto out;
	}

	cr = conj_cred(&symp->sy_cred);

	/* create the symlink */
	CACHEFS_TMPPTR_SET(&symp->sy_vattr, &va, tmpvap, vattr_t);
	CACHEFS_VATTR_COPYIN(&symp->sy_vattr, tmpvap);
	error = VOP_SYMLINK(dvp, symp->sy_name, tmpvap,
	    symp->sy_link, cr, NULL, 0);
	if (error)
		goto out;

	/* get the vnode for the symlink */
	error = VOP_LOOKUP(dvp, symp->sy_name, &svp, NULL, 0, NULL, cr,
		NULL, NULL, NULL);
	if (error)
		goto out;

	/* get the attributes of the symlink */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(svp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->sy_ctime, error);
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_mtime, &retp->sy_mtime, error);
	if (error)
		goto out;

	/* get the fid */
	CACHEFS_TMPPTR_SET(&retp->sy_newfid, &tmpfid, tmpfidp, fid_t);
	tmpfidp->fid_len = MAXFIDSZ;
	error = VOP_FID(svp, tmpfidp, NULL);
	if (error)
		goto out;
	CACHEFS_FID_COPYOUT(tmpfidp, &retp->sy_newfid);

	/* update the cnode for this file with the new info */
	error = cachefs_cnode_make(&symp->sy_cid, fscp,
	    NULL, NULL, NULL, cr, 0, &cp);
	if (error) {
		error = 0;
		goto out;
	}
	mutex_enter(&cp->c_statelock);
	ASSERT(cp->c_id.cid_flags & CFS_CID_LOCAL);
	cp->c_metadata.md_cookie = *tmpfidp;
	cp->c_metadata.md_flags |= MD_CREATEDONE;
	cp->c_metadata.md_flags |= MD_NEEDATTRS;
	cp->c_attr.va_nodeid = va.va_nodeid;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);

out:
	if (cr)
		crfree(cr);
	if (dvp)
		VN_RELE(dvp);
	if (svp)
		VN_RELE(svp);
	if (cp)
		VN_RELE(CTOV(cp));
	return (error);
}

/*
 * Perform setattr on the back file system.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_io_setattr(vnode_t *vp, void *dinp, void *doutp)
{
	vnode_t	*cvp = NULL;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	fid_t	*tmpfidp;
	vattr_t	va, *tmpvap;
	int error = 0;
	cred_t *cr = NULL;
	cachefsio_setattr_arg_t *sap;
	cachefsio_setattr_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	sap = (cachefsio_setattr_arg_t *)dinp;
	retp = (cachefsio_setattr_return_t *)doutp;

	/* get a vnode for the back directory */
	CACHEFS_TMPPTR_SET(&sap->sa_backfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&sap->sa_backfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &cvp, tmpfidp);
	if (error) {
		cvp = NULL;
		goto out;
	}

	cr = conj_cred(&sap->sa_cred);

	/* perform the setattr */
	CACHEFS_TMPPTR_SET(&sap->sa_vattr, &va, tmpvap, vattr_t);
	CACHEFS_VATTR_COPYIN(&sap->sa_vattr, tmpvap);
	error = VOP_SETATTR(cvp, tmpvap, 0, cr, NULL);
	if (error)
		goto out;

	/* get the new ctime and mtime */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(cvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->sa_ctime, error);
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_mtime, &retp->sa_mtime, error);
	if (error)
		goto out;

	cachefs_iosetneedattrs(fscp, &sap->sa_cid);
out:
	if (cr)
		crfree(cr);
	if (cvp)
		VN_RELE(cvp);
	return (error);
}

int
cachefs_io_setsecattr(vnode_t *vp, void *dinp, void *doutp)
{
	int error = 0;
	fscache_t *fscp = C_TO_FSCACHE(VTOC(vp));
	vnode_t *tvp = NULL;
	vsecattr_t vsec;
	vattr_t va;
	cred_t *cr = NULL;
	fid_t	*tmpfidp;
	cachefsio_setsecattr_arg_t *ssap;
	cachefsio_setsecattr_return_t *retp;
	CACHEFS_DECL(fid_t, tmpfid);

	/*
	 * Only called in support of disconnectable operation, so assert
	 * that this is not called when NFSv4 is the backfilesytem.
	 */
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	ssap = (cachefsio_setsecattr_arg_t *)dinp;
	retp = (cachefsio_setsecattr_return_t *)doutp;

	/* get vnode of back file to do VOP_SETSECATTR to */
	CACHEFS_TMPPTR_SET(&ssap->sc_backfid, &tmpfid, tmpfidp, fid_t);
	CACHEFS_FID_COPYIN(&ssap->sc_backfid, tmpfidp);
	error = VFS_VGET(fscp->fs_backvfsp, &tvp, tmpfidp);
	if (error != 0) {
		tvp = NULL;
		goto out;
	}

	/* get the creds */
	cr = conj_cred(&ssap->sc_cred);

	/* form the vsecattr_t */
	vsec.vsa_mask = ssap->sc_mask;
	vsec.vsa_aclcnt = ssap->sc_aclcnt;
	vsec.vsa_dfaclcnt = ssap->sc_dfaclcnt;
	vsec.vsa_aclentp = ssap->sc_acl;
	vsec.vsa_dfaclentp = ssap->sc_acl + ssap->sc_aclcnt;

	/* set the ACL */
	(void) VOP_RWLOCK(tvp, V_WRITELOCK_TRUE, NULL);
	error = VOP_SETSECATTR(tvp, &vsec, 0, cr, NULL);
	VOP_RWUNLOCK(tvp, V_WRITELOCK_TRUE, NULL);
	if (error != 0)
		goto out;

	/* get the new ctime and mtime */
	va.va_mask = AT_ALL;
	error = VOP_GETATTR(tvp, &va, 0, cr, NULL);
	if (error)
		goto out;
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_ctime, &retp->sc_ctime, error);
	CACHEFS_TS_TO_CFS_TS_COPY(&va.va_mtime, &retp->sc_mtime, error);
	if (error)
		goto out;

	cachefs_iosetneedattrs(fscp, &ssap->sc_cid);
out:

	if (cr != NULL)
		crfree(cr);
	if (tvp != NULL)
		VN_RELE(tvp);

	return (error);
}

static void
sync_metadata(cnode_t *cp)
{
	if (cp->c_flags & (CN_STALE | CN_DESTROY))
		return;
	(void) cachefs_sync_metadata(cp);
}

static void
drop_backvp(cnode_t *cp)
{
	if (cp->c_backvp) {
		mutex_enter(&cp->c_statelock);
		if (cp->c_backvp) {
			/* dump any pages, may be a dirty one */
			(void) VOP_PUTPAGE(cp->c_backvp, (offset_t)0, 0,
			    B_INVAL | B_TRUNC, kcred, NULL);
		}
		mutex_exit(&cp->c_statelock);
	}
}

static void
allow_pendrm(cnode_t *cp)
{
	if (cp->c_flags & CN_PENDRM) {
		mutex_enter(&cp->c_statelock);
		if (cp->c_flags & CN_PENDRM) {
			cp->c_flags &= ~CN_PENDRM;
			VN_RELE(CTOV(cp));
		}
		mutex_exit(&cp->c_statelock);
	}
}

static void
cachefs_modified_fix(fscache_t *fscp)
{
	cnode_t *cp;
	int error = 0;
	rl_entry_t rl_ent;
	cfs_cid_t cid;
	cachefscache_t *cachep = fscp->fs_cache;
	enum cachefs_rl_type type;
	cachefs_metadata_t *mdp;
	int timedout = 0;
	struct vattr va;

	/* XXX just return if fs is in error ro mode */

	/* lock out other users of the MF list */
	mutex_enter(&cachep->c_mflock);

	/* move the modified entries for this file system to the MF list */
	cachefs_move_modified_to_mf(cachep, fscp);

	rl_ent.rl_current = CACHEFS_RL_MF;
	for (;;) {
		/* get the next entry on the MF list */
		error = cachefs_rlent_data(cachep, &rl_ent, NULL);
		if (error) {
			error = 0;
			break;
		}
		ASSERT(fscp->fs_cfsid == rl_ent.rl_fsid);

		/* get the cnode for the file */
		cid.cid_fileno = rl_ent.rl_fileno;
		cid.cid_flags = rl_ent.rl_local ? CFS_CID_LOCAL : 0;
		error = cachefs_cnode_make(&cid, fscp,
		    NULL, NULL, NULL, kcred, 0, &cp);
		if (error) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_IOCTL)
				printf("cachefs: mf: could not find %llu\n",
				    (u_longlong_t)cid.cid_fileno);
			delay(5*hz);
#endif
			/* XXX this will loop forever, maybe put fs in */
			/*   ro mode */
			continue;
		}

		mutex_enter(&cp->c_statelock);

		mdp = &cp->c_metadata;

		/* if a regular file that has not been pushed */
		if ((cp->c_attr.va_type == VREG) &&
		    (((mdp->md_flags & (MD_PUSHDONE | MD_PUTPAGE)) ==
		    MD_PUTPAGE))) {
			/* move the file to lost+found */
			error = cachefs_cnode_lostfound(cp, NULL);
			if (error) {
				/* XXX put fs in ro mode */
				/* XXX need to drain MF list */
				panic("lostfound failed %d", error);
			}
			mutex_exit(&cp->c_statelock);
			VN_RELE(CTOV(cp));
			continue;
		}

		/* if a local file */
		if (cp->c_id.cid_flags & CFS_CID_LOCAL) {
			/* if the file was not created */
			if ((cp->c_metadata.md_flags & MD_CREATEDONE) == 0) {
				/* do not allow cnode to be used */
				cachefs_cnode_stale(cp);
				mutex_exit(&cp->c_statelock);
				VN_RELE(CTOV(cp));
				continue;
			}

			/* save the local fileno for later getattrs */
			mdp->md_localfileno = cp->c_id.cid_fileno;
			mutex_exit(&cp->c_statelock);

			/* register the mapping from old to new fileno */
			mutex_enter(&fscp->fs_fslock);
			cachefs_inum_register(fscp, cp->c_attr.va_nodeid,
			    mdp->md_localfileno);
			cachefs_inum_register(fscp, mdp->md_localfileno, 0);
			mutex_exit(&fscp->fs_fslock);

			/* move to new location in the cache */
			cachefs_cnode_move(cp);
			mutex_enter(&cp->c_statelock);
		}

		/* else if a modified file that needs to have its mode fixed */
		else if ((cp->c_metadata.md_flags & MD_FILE) &&
		    (cp->c_attr.va_type == VREG)) {

			if (cp->c_frontvp == NULL)
				(void) cachefs_getfrontfile(cp);
			if (cp->c_frontvp) {
				/* mark file as no longer modified */
				va.va_mode = 0666;
				va.va_mask = AT_MODE;
				error = VOP_SETATTR(cp->c_frontvp, &va,
				    0, kcred, NULL);
				if (error) {
					cmn_err(CE_WARN,
					    "Cannot change ff mode.\n");
				}
			}
		}


		/* if there is a rl entry, put it on the correct list */
		if (mdp->md_rlno) {
			if (mdp->md_flags & MD_PACKED) {
				if ((mdp->md_flags & MD_POPULATED) ||
				    ((mdp->md_flags & MD_FILE) == 0))
					type = CACHEFS_RL_PACKED;
				else
					type = CACHEFS_RL_PACKED_PENDING;
				cachefs_rlent_moveto(fscp->fs_cache, type,
				    mdp->md_rlno, mdp->md_frontblks);
				mdp->md_rltype = type;
			} else if (mdp->md_flags & MD_FILE) {
				type = CACHEFS_RL_ACTIVE;
				cachefs_rlent_moveto(fscp->fs_cache, type,
				    mdp->md_rlno, mdp->md_frontblks);
				mdp->md_rltype = type;
			} else {
				type = CACHEFS_RL_FREE;
				cachefs_rlent_moveto(fscp->fs_cache, type,
				    mdp->md_rlno, 0);
				filegrp_ffrele(cp->c_filegrp);
				mdp->md_rlno = 0;
				mdp->md_rltype = CACHEFS_RL_NONE;
			}
		}
		mdp->md_flags &= ~(MD_CREATEDONE | MD_PUTPAGE |
		    MD_PUSHDONE | MD_MAPPING);

		/* if a directory, populate it */
		if (CTOV(cp)->v_type == VDIR) {
			/* XXX hack for now */
			mdp->md_flags |= MD_INVALREADDIR;
			dnlc_purge_vp(CTOV(cp));

			mdp->md_flags |= MD_NEEDATTRS;
		}

		if (!timedout) {
			error = CFSOP_CHECK_COBJECT(fscp, cp, 0, kcred);
			if (CFS_TIMEOUT(fscp, error))
				timedout = 1;
			else if ((error == 0) &&
			    ((fscp->fs_info.fi_mntflags & CFS_NOACL) == 0)) {
				if (cachefs_vtype_aclok(CTOV(cp)) &&
				    ((cp->c_flags & CN_NOCACHE) == 0))
					(void) cachefs_cacheacl(cp, NULL);
			}
		}

		cp->c_flags |= CN_UPDATED;
		mutex_exit(&cp->c_statelock);
		VN_RELE(CTOV(cp));
	}
	mutex_exit(&cachep->c_mflock);
}

void
cachefs_inum_register(fscache_t *fscp, ino64_t real, ino64_t fake)
{
	cachefs_inum_trans_t *tbl;
	int toff, thop;
	int i;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	/*
	 * first, see if an empty slot exists.
	 */

	for (i = 0; i < fscp->fs_inum_size; i++)
		if (fscp->fs_inum_trans[i].cit_real == 0)
			break;

	/*
	 * if there are no empty slots, try to grow the table.
	 */

	if (i >= fscp->fs_inum_size) {
		cachefs_inum_trans_t *oldtbl;
		int oldsize, newsize = 0;

		/*
		 * try to fetch a new table size that's bigger than
		 * our current size
		 */

		for (i = 0; cachefs_hash_sizes[i] != 0; i++)
			if (cachefs_hash_sizes[i] > fscp->fs_inum_size) {
				newsize = cachefs_hash_sizes[i];
				break;
			}

		/*
		 * if we're out of larger twin-primes, give up.  thus,
		 * the inode numbers in some directory entries might
		 * change at reconnect, and disagree with what stat()
		 * says.  this isn't worth panicing over, but it does
		 * merit a warning message.
		 */
		if (newsize == 0) {
			/* only print hash table warning once */
			if ((fscp->fs_flags & CFS_FS_HASHPRINT) == 0) {
				cmn_err(CE_WARN,
				    "cachefs: inode hash table full\n");
				fscp->fs_flags |= CFS_FS_HASHPRINT;
			}
			return;
		}

		/* set up this fscp with a new hash table */

		oldtbl = fscp->fs_inum_trans;
		oldsize = fscp->fs_inum_size;
		fscp->fs_inum_size = newsize;
		fscp->fs_inum_trans = (cachefs_inum_trans_t *)
		    cachefs_kmem_zalloc(sizeof (cachefs_inum_trans_t) * newsize,
			KM_SLEEP);

		/*
		 * re-insert all of the old values.  this will never
		 * go more than one level into recursion-land.
		 */

		for (i = 0; i < oldsize; i++) {
			tbl = oldtbl + i;
			if (tbl->cit_real != 0) {
				cachefs_inum_register(fscp, tbl->cit_real,
				    tbl->cit_fake);
			} else {
				ASSERT(0);
			}
		}

		if (oldsize > 0)
			cachefs_kmem_free(oldtbl, oldsize *
			    sizeof (cachefs_inum_trans_t));
	}

	/*
	 * compute values for the hash table.  see ken rosen's
	 * `elementary number theory and its applications' for one
	 * description of double hashing.
	 */

	toff = (int)(real % fscp->fs_inum_size);
	thop = (int)(real % (fscp->fs_inum_size - 2)) + 1;

	/*
	 * since we know the hash table isn't full when we get here,
	 * this loop shouldn't terminate except via the `break'.
	 */

	for (i = 0; i < fscp->fs_inum_size; i++) {
		tbl = fscp->fs_inum_trans + toff;
		if ((tbl->cit_real == 0) || (tbl->cit_real == real)) {
			tbl->cit_real = real;
			tbl->cit_fake = fake;
			break;
		}

		toff += thop;
		toff %= fscp->fs_inum_size;
	}
	ASSERT(i < fscp->fs_inum_size);
}

/*
 * given an inode number, map it to the inode number that should be
 * put in a directory entry before its copied out.
 *
 * don't call this function unless there is a fscp->fs_inum_trans
 * table that has real entries in it!
 */

ino64_t
cachefs_inum_real2fake(fscache_t *fscp, ino64_t real)
{
	cachefs_inum_trans_t *tbl;
	ino64_t rc = real;
	int toff, thop;
	int i;

	ASSERT(fscp->fs_inum_size > 0);
	ASSERT(MUTEX_HELD(&fscp->fs_fslock));

	toff = (int)(real % fscp->fs_inum_size);
	thop = (int)(real % (fscp->fs_inum_size - 2)) + 1;

	for (i = 0; i < fscp->fs_inum_size; i++) {
		tbl = fscp->fs_inum_trans + toff;

		if (tbl->cit_real == 0) {
			break;
		} else if (tbl->cit_real == real) {
			rc = tbl->cit_fake;
			break;
		}

		toff += thop;
		toff %= fscp->fs_inum_size;
	}

	return (rc);
}

/*
 * Passed a cid, finds the cnode and sets the MD_NEEDATTRS bit
 * in the metadata.
 */
static void
cachefs_iosetneedattrs(fscache_t *fscp, cfs_cid_t *cidp)
{
	int error;
	cnode_t *cp;

	error = cachefs_cnode_make(cidp, fscp,
	    NULL, NULL, NULL, kcred, 0, &cp);
	if (error)
		return;

	mutex_enter(&cp->c_statelock);
	cp->c_metadata.md_flags |= MD_NEEDATTRS;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);

	VN_RELE(CTOV(cp));
}

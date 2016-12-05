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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/fs/hyprlofs.h>
#include <sys/fs/hyprlofs_info.h>
#include <sys/mman.h>
#include <vm/pvn.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

static int hyprlofs_add_entry(vnode_t *, char *, char *, cred_t *,
		caller_context_t *);
static int hyprlofs_rm_entry(vnode_t *, char *, cred_t *, caller_context_t *,
		int);
static int hyprlofs_rm_all(vnode_t *, cred_t *, caller_context_t *, int);
static int hyprlofs_remove(vnode_t *, char *, cred_t *, caller_context_t *,
		int);
static int hyprlofs_get_all(vnode_t *, intptr_t, cred_t *, caller_context_t *,
		int);

/*
 * This is a somewhat arbitrary upper limit on the number of entries we can
 * pass in on a single add/rm ioctl call.  This is only used to validate that
 * the input list looks sane.
 */
#define	MAX_IOCTL_PARAMS	100000

static int
hyprlofs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t *rvp;
	int error;

	rvp = REALVP(*vpp);

	if (VTOHLN(*vpp)->hln_looped == 0)
		return (0);

	/*
	 * looped back, pass through to real vnode. Need to hold new reference
	 * to vp since VOP_OPEN() may decide to release it.
	 */
	VN_HOLD(rvp);
	error = VOP_OPEN(&rvp, flag, cr, ct);
	ASSERT(rvp->v_count > 1);
	VN_RELE(rvp);

	return (error);
}

static int
hyprlofs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	if (VTOHLN(vp)->hln_looped == 0) {
		cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
		cleanshares(vp, ttoproc(curthread)->p_pid);
		return (0);
	}

	return (VOP_CLOSE(REALVP(vp), flag, count, offset, cr, ct));
}

static int
hyprlofs_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	if (vp->v_type == VDIR)
		return (EISDIR);
	return (VOP_READ(REALVP(vp), uiop, ioflag, cr, ct));
}

static int
hyprlofs_write(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	/* We don't support writing to non-regular files */
	if (vp->v_type != VREG)
		return (EINVAL);

	if (vn_is_readonly(vp))
		return (EROFS);

	return (VOP_WRITE(REALVP(vp), uiop, ioflag, cr, ct));
}

/* ARGSUSED */
static int
hyprlofs_ioctl(vnode_t *vp, int cmd, intptr_t data, int flag,
    cred_t *cr, int *rvalp, caller_context_t *ct)
{
	uint_t len, cnt;
	int i, error;
	model_t model;
	char path[MAXPATHLEN];
	char nm[MAXPATHLEN];

	/* We only support the hyprlofs ioctls on the root vnode */
	if (!(vp->v_flag & VROOT))
		return (ENOTTY);

	/*
	 * Check if managing hyprlofs is allowed.
	 */
	if (secpolicy_hyprlofs_control(cr) != 0)
		return (EPERM);

	if (cmd == HYPRLOFS_ADD_ENTRIES || cmd == HYPRLOFS_RM_ENTRIES) {
		model = get_udatamodel();

		if (model == DATAMODEL_NATIVE) {
			hyprlofs_entries_t ebuf;
			hyprlofs_entry_t *e;

			if (copyin((void *)data, &ebuf, sizeof (ebuf)))
				return (EFAULT);
			cnt = ebuf.hle_len;
			if (cnt > MAX_IOCTL_PARAMS)
				return (EINVAL);
			len = sizeof (hyprlofs_entry_t) * cnt;

			e = kmem_alloc(len, KM_SLEEP);
			if (copyin((void *)(ebuf.hle_entries), e, len)) {
				kmem_free(e, len);
				return (EFAULT);
			}

			for (i = 0; i < cnt; i++) {
				if (e[i].hle_nlen == 0 ||
				    e[i].hle_nlen >= sizeof (nm))
					return (EINVAL);

				if (copyin(e[i].hle_name, nm, e[i].hle_nlen)
				    != 0) {
					kmem_free(e, len);
					return (EFAULT);
				}
				nm[e[i].hle_nlen] = '\0';

				if (cmd == HYPRLOFS_ADD_ENTRIES) {
					if (e[i].hle_plen == 0 ||
					    e[i].hle_plen >= sizeof (path))
						return (EINVAL);

					if (copyin(e[i].hle_path, path,
					    e[i].hle_plen) != 0) {
						kmem_free(e, len);
						return (EFAULT);
					}
					path[e[i].hle_plen] = '\0';

					if ((error = hyprlofs_add_entry(vp,
					    path, nm, cr, ct)) != 0) {
						kmem_free(e, len);
						return (error);
					}
				} else {
					if ((error = hyprlofs_rm_entry(vp, nm,
					    cr, ct, flag)) != 0) {
						kmem_free(e, len);
						return (error);
					}
				}
			}

			kmem_free(e, len);
			return (0);

		} else {
			hyprlofs_entries32_t ebuf32;
			hyprlofs_entry32_t *e32;

			if (copyin((void *)data, &ebuf32, sizeof (ebuf32)))
				return (EFAULT);

			cnt = ebuf32.hle_len;
			if (cnt > MAX_IOCTL_PARAMS)
				return (EINVAL);
			len = sizeof (hyprlofs_entry32_t) * cnt;

			e32 = kmem_alloc(len, KM_SLEEP);
			if (copyin((void *)(unsigned long)(ebuf32.hle_entries),
			    e32, len)) {
				kmem_free(e32, len);
				return (EFAULT);
			}

			for (i = 0; i < cnt; i++) {
				if (e32[i].hle_nlen == 0 ||
				    e32[i].hle_nlen >= sizeof (nm))
					return (EINVAL);

				if (copyin((void *)(unsigned long)
				    e32[i].hle_name, nm,
				    e32[i].hle_nlen) != 0) {
					kmem_free(e32, len);
					return (EFAULT);
				}
				nm[e32[i].hle_nlen] = '\0';

				if (cmd == HYPRLOFS_ADD_ENTRIES) {
					if (e32[i].hle_plen == 0 ||
					    e32[i].hle_plen >= sizeof (path))
						return (EINVAL);

					if (copyin((void *)(unsigned long)
					    e32[i].hle_path, path,
					    e32[i].hle_plen) != 0) {
						kmem_free(e32, len);
						return (EFAULT);
					}
					path[e32[i].hle_plen] = '\0';

					if ((error = hyprlofs_add_entry(vp,
					    path, nm, cr, ct)) != 0) {
						kmem_free(e32, len);
						return (error);
					}
				} else {
					if ((error = hyprlofs_rm_entry(vp, nm,
					    cr, ct, flag)) != 0) {
						kmem_free(e32, len);
						return (error);
					}
				}
			}

			kmem_free(e32, len);
			return (0);
		}
	}

	if (cmd == HYPRLOFS_RM_ALL) {
		return (hyprlofs_rm_all(vp, cr, ct, flag));
	}

	if (cmd == HYPRLOFS_GET_ENTRIES) {
		return (hyprlofs_get_all(vp, data, cr, ct, flag));
	}

	return (ENOTTY);
}

static int
hyprlofs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	hlnode_t *tp = (hlnode_t *)VTOHLN(vp);
	vattr_t tmp_va;

	if (tp->hln_looped == 1) {
		int error;

		if ((error = VOP_GETATTR(REALVP(vp), &tmp_va, flags, cr,
		    ct)) != 0)
			return (error);
	}

	mutex_enter(&tp->hln_tlock);
	vap->va_type = vp->v_type;
	vap->va_mode = tp->hln_mode & MODEMASK;
	vap->va_uid = tp->hln_uid;
	vap->va_gid = tp->hln_gid;
	vap->va_fsid = tp->hln_fsid;
	vap->va_nodeid = (ino64_t)tp->hln_nodeid;
	vap->va_nlink = tp->hln_nlink;
	vap->va_size = (u_offset_t)tp->hln_size;
	vap->va_atime = tp->hln_atime;
	vap->va_mtime = tp->hln_mtime;
	vap->va_ctime = tp->hln_ctime;
	vap->va_blksize = PAGESIZE;
	vap->va_rdev = tp->hln_rdev;
	vap->va_seq = tp->hln_seq;

	if (tp->hln_looped == 1) {
		vap->va_nblocks = tmp_va.va_nblocks;
	} else {
		vap->va_nblocks =
		    (fsblkcnt64_t)btodb(ptob(btopr(vap->va_size)));
	}
	mutex_exit(&tp->hln_tlock);
	return (0);
}

/*ARGSUSED4*/
static int
hyprlofs_setattr(vnode_t *vp, vattr_t *vap, int flags,
    cred_t *cr, caller_context_t *ct)
{
	hlnode_t *tp = (hlnode_t *)VTOHLN(vp);
	int error = 0;
	vattr_t *get;
	long mask;

	/*
	 * Cannot set these attributes
	 */
	if ((vap->va_mask & AT_NOSET) || (vap->va_mask & AT_XVATTR))
		return (EINVAL);

	mutex_enter(&tp->hln_tlock);

	get = &tp->hln_attr;
	/*
	 * Change file access modes. Must be owner or have sufficient
	 * privileges.
	 */
	error = secpolicy_vnode_setattr(cr, vp, vap, get, flags,
	    hyprlofs_taccess, tp);

	if (error)
		goto out;

	mask = vap->va_mask;

	if (mask & AT_MODE) {
		get->va_mode &= S_IFMT;
		get->va_mode |= vap->va_mode & ~S_IFMT;
	}

	if (mask & AT_UID)
		get->va_uid = vap->va_uid;
	if (mask & AT_GID)
		get->va_gid = vap->va_gid;
	if (mask & AT_ATIME)
		get->va_atime = vap->va_atime;
	if (mask & AT_MTIME)
		get->va_mtime = vap->va_mtime;

	if (mask & (AT_UID | AT_GID | AT_MODE | AT_MTIME))
		gethrestime(&tp->hln_ctime);

out:
	mutex_exit(&tp->hln_tlock);
	return (error);
}

static int
hyprlofs_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	hlnode_t *tp = (hlnode_t *)VTOHLN(vp);
	int error;

	if (mode & VWRITE) {
		if (vp->v_type == VREG && vn_is_readonly(vp))
			return (EROFS);
	}
	if (VTOHLN(vp)->hln_looped == 1)
		return (VOP_ACCESS(REALVP(vp), mode, flags, cr, ct));

	mutex_enter(&tp->hln_tlock);
	error = hyprlofs_taccess(tp, mode, cr);
	mutex_exit(&tp->hln_tlock);
	return (error);
}

/* ARGSUSED3 */
static int
hyprlofs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	hlnode_t *tp = (hlnode_t *)VTOHLN(dvp);
	hlnode_t *ntp = NULL;
	int error;

	if (VTOHLN(dvp)->hln_looped == 1)
		return (VOP_LOOKUP(REALVP(dvp), nm, vpp, pnp, flags, rdir,
		    cr, ct, direntflags, realpnp));

	if (flags & LOOKUP_XATTR)
		return (EINVAL);

	/* Null component name is a synonym for directory being searched. */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}
	ASSERT(tp);

	if ((error = hyprlofs_dirlookup(tp, nm, &ntp, cr)) == 0) {
		ASSERT(ntp);
		*vpp = HLNTOV(ntp);
	}
	return (error);
}

/*
 * Create the loopback from the hyprlofs vnode to the real vnode.
 */
static int
hyprlofs_loopback(vnode_t *dvp, vnode_t *rvp, char *nm, vattr_t *vap,
    int mode, cred_t *cr, caller_context_t *ct)
{
	hlnode_t *parent;
	hlfsmount_t *tm;
	int error;
	hlnode_t *oldtp;
	vnode_t *vp;

	parent = (hlnode_t *)VTOHLN(dvp);
	tm = (hlfsmount_t *)VTOHLM(dvp);
	error = 0;
	oldtp = NULL;

	if (vap->va_type == VREG && (vap->va_mode & VSVTX)) {
		/* we don't support the sticky bit */
		vap->va_mode &= ~VSVTX;
	} else if (vap->va_type == VNON) {
		return (EINVAL);
	}

	/* Null component name is a synonym for directory being searched. */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		oldtp = parent;
	} else {
		error = hyprlofs_dirlookup(parent, nm, &oldtp, cr);
	}

	if (error == 0) {	/* name found */
		ASSERT(oldtp);

		rw_enter(&oldtp->hln_rwlock, RW_WRITER);

		/*
		 * if create/read-only an existing directory, allow it
		 */
		if ((oldtp->hln_type == VDIR) && (mode & VWRITE))
			error = EISDIR;
		else {
			error = hyprlofs_taccess(oldtp, mode, cr);
		}

		if (error) {
			rw_exit(&oldtp->hln_rwlock);
			hlnode_rele(oldtp);
			return (error);
		}

		vp = HLNTOV(oldtp);
		rw_exit(&oldtp->hln_rwlock);

		if (vp->v_type == VREG) {
			hlnode_rele(oldtp);
			return (EEXIST);
		}

		vnevent_create(vp, ct);
		return (0);
	}

	if (error != ENOENT)
		return (error);

	rw_enter(&parent->hln_rwlock, RW_WRITER);
	error = hyprlofs_direnter(tm, parent, nm, DE_CREATE, rvp, vap, NULL,
	    cr);
	rw_exit(&parent->hln_rwlock);

	return (error);
}

/*
 * Create an in-memory directory based on the add-entry ioctl name.
 * If the dir exists, return EEXIST but still also return node in vpp.
 */
static int
hyprlofs_mkdir(vnode_t *dvp, char *nm, vattr_t *va, vnode_t **vpp, cred_t *cr)
{
	hlnode_t *parent = (hlnode_t *)VTOHLN(dvp);
	hlnode_t *self = NULL;
	hlfsmount_t *tm = (hlfsmount_t *)VTOHLM(dvp);
	int error;

	/*
	 * Might be dangling directory.  Catch it here, because a ENOENT return
	 * from hyprlofs_dirlookup() is a valid return.
	 */
	if (parent->hln_nlink == 0)
		return (ENOENT);

	error = hyprlofs_dirlookup(parent, nm, &self, cr);
	if (error == 0) {
		ASSERT(self);
		hlnode_rele(self);
		/* We can't loop in under a looped in directory */
		if (self->hln_looped)
			return (EACCES);
		*vpp = HLNTOV(self);
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	rw_enter(&parent->hln_rwlock, RW_WRITER);
	error = hyprlofs_direnter(tm, parent, nm, DE_MKDIR, (vnode_t *)NULL,
	    va, &self, cr);
	rw_exit(&parent->hln_rwlock);

	if (error == 0 || error == EEXIST) {
		hlnode_rele(self);
		*vpp = HLNTOV(self);
	}

	return (error);
}

/*
 * Loop in a file or directory into the namespace.
 */
static int
hyprlofs_add_entry(vnode_t *vp, char *fspath, char *fsname,
    cred_t *cr, caller_context_t *ct)
{
	int error;
	char *p, *pnm;
	vnode_t *realvp, *dvp;
	vattr_t va;

	/*
	 * Get vnode for the real file/dir. We'll have a hold on realvp which
	 * we won't vn_rele until hyprlofs_inactive.
	 */
	if ((error = lookupname(fspath, UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &realvp)) != 0)
		return (error);

	/* no devices allowed */
	if (IS_DEVVP(realvp)) {
		VN_RELE(realvp);
		return (ENODEV);
	}

	/*
	 * realvp may be an AUTOFS node, in which case we perform a VOP_ACCESS
	 * to trigger the mount of the intended filesystem. This causes a
	 * loopback mount of the intended filesystem instead of the AUTOFS
	 * filesystem.
	 */
	if ((error = VOP_ACCESS(realvp, 0, 0, cr, NULL)) != 0) {
		VN_RELE(realvp);
		return (error);
	}

	/*
	 * We're interested in the top most filesystem. This is specially
	 * important when fspath is a trigger AUTOFS node, since we're really
	 * interested in mounting the filesystem AUTOFS mounted as result of
	 * the VOP_ACCESS() call not the AUTOFS node itself.
	 */
	if (vn_mountedvfs(realvp) != NULL) {
		if ((error = traverse(&realvp)) != 0) {
			VN_RELE(realvp);
			return (error);
		}
	}

	va.va_type = VNON;
	/*
	 * If the target name is a path, make sure we have all of the
	 * intermediate directories, creating them if necessary.
	 */
	dvp = vp;
	pnm = p = fsname;

	/* path cannot be absolute */
	if (*p == '/') {
		VN_RELE(realvp);
		return (EINVAL);
	}

	for (p = strchr(pnm, '/'); p != NULL; p = strchr(pnm, '/')) {
		if (va.va_type == VNON)
			/* use the top-level dir as the template va for mkdir */
			if ((error = VOP_GETATTR(vp, &va, 0, cr, NULL)) != 0) {
				VN_RELE(realvp);
				return (error);
			}

		*p = '\0';

		/* Path component cannot be empty or relative */
		if (pnm[0] == '\0' ||
		    (pnm[0] == '.' && pnm[1] == '.' && pnm[2] == '\0')) {
			VN_RELE(realvp);
			return (EINVAL);
		}

		if ((error = hyprlofs_mkdir(dvp, pnm, &va, &dvp, cr)) != 0 &&
		    error != EEXIST) {
			VN_RELE(realvp);
			return (error);
		}

		*p = '/';
		pnm = p + 1;
	}

	/* The file name is required */
	if (pnm[0] == '\0') {
		VN_RELE(realvp);
		return (EINVAL);
	}

	/* Now use the real file's va as the template va */
	if ((error = VOP_GETATTR(realvp, &va, 0, cr, NULL)) != 0) {
		VN_RELE(realvp);
		return (error);
	}

	/* Make the vnode */
	error = hyprlofs_loopback(dvp, realvp, pnm, &va, va.va_mode, cr, ct);
	if (error != 0)
		VN_RELE(realvp);
	return (error);
}

/*
 * Remove a looped in file from the namespace.
 */
static int
hyprlofs_rm_entry(vnode_t *dvp, char *fsname, cred_t *cr, caller_context_t *ct,
    int flags)
{
	int error;
	char *p, *pnm;
	hlnode_t *parent;
	hlnode_t *fndtp;

	pnm = p = fsname;

	/* path cannot be absolute */
	if (*p == '/')
		return (EINVAL);

	/*
	 * If the target name is a path, get the containing dir and simple
	 * file name.
	 */
	parent = (hlnode_t *)VTOHLN(dvp);
	for (p = strchr(pnm, '/'); p != NULL; p = strchr(pnm, '/')) {
		*p = '\0';

		/* Path component cannot be empty or relative */
		if (pnm[0] == '\0' ||
		    (pnm[0] == '.' && pnm[1] == '.' && pnm[2] == '\0'))
			return (EINVAL);

		if ((error = hyprlofs_dirlookup(parent, pnm, &fndtp, cr)) != 0)
			return (error);

		dvp = HLNTOV(fndtp);
		parent = fndtp;
		pnm = p + 1;
	}

	/* The file name is required */
	if (pnm[0] == '\0')
		return (EINVAL);

	/* Remove the entry from the parent dir */
	return (hyprlofs_remove(dvp, pnm, cr, ct, flags));
}

/*
 * Remove all looped in files from the namespace.
 */
static int
hyprlofs_rm_all(vnode_t *dvp, cred_t *cr, caller_context_t *ct,
    int flags)
{
	int error = 0;
	hlnode_t *hp = (hlnode_t *)VTOHLN(dvp);
	hldirent_t *hdp;

	hlnode_hold(hp);

	/*
	 * There's a window here where someone could have removed
	 * all the entries in the directory after we put a hold on the
	 * vnode but before we grabbed the rwlock.  Just return.
	 */
	if (hp->hln_dir == NULL) {
		if (hp->hln_nlink) {
			panic("empty directory 0x%p", (void *)hp);
			/*NOTREACHED*/
		}
		goto done;
	}

	hdp = hp->hln_dir;
	while (hdp) {
		hlnode_t *fndhp;

		if (strcmp(hdp->hld_name, ".") == 0 ||
		    strcmp(hdp->hld_name, "..") == 0) {
			hdp = hdp->hld_next;
			continue;
		}

		/* This holds the fndhp vnode */
		error = hyprlofs_dirlookup(hp, hdp->hld_name, &fndhp, cr);
		if (error != 0)
			goto done;
		hlnode_rele(fndhp);

		if (fndhp->hln_looped == 0) {
			/* recursively remove contents of this subdir */
			if (fndhp->hln_type == VDIR) {
				vnode_t *tvp = HLNTOV(fndhp);

				error = hyprlofs_rm_all(tvp, cr, ct, flags);
				if (error != 0)
					goto done;
			}
		}

		/* remove the entry */
		error = hyprlofs_remove(dvp, hdp->hld_name, cr, ct, flags);
		if (error != 0)
			goto done;

		hdp = hp->hln_dir;
	}

done:
	hlnode_rele(hp);
	return (error);
}

/*
 * Get a list of all looped in files in the namespace.
 */
static int
hyprlofs_get_all_entries(vnode_t *dvp, hyprlofs_curr_entry_t *hcp,
    char *prefix, uint_t *pcnt, uint_t n_max,
    cred_t *cr, caller_context_t *ct, int flags)
{
	int error = 0;
	int too_big = 0;
	uint_t cnt;
	uint_t len;
	hlnode_t *hp = (hlnode_t *)VTOHLN(dvp);
	hldirent_t *hdp;
	char *path;

	cnt = *pcnt;
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	hlnode_hold(hp);

	/*
	 * There's a window here where someone could have removed
	 * all the entries in the directory after we put a hold on the
	 * vnode but before we grabbed the rwlock.  Just return.
	 */
	if (hp->hln_dir == NULL) {
		if (hp->hln_nlink) {
			panic("empty directory 0x%p", (void *)hp);
			/*NOTREACHED*/
		}
		goto done;
	}

	hdp = hp->hln_dir;
	while (hdp) {
		hlnode_t *fndhp;
		vnode_t *tvp;

		if (strcmp(hdp->hld_name, ".") == 0 ||
		    strcmp(hdp->hld_name, "..") == 0) {
			hdp = hdp->hld_next;
			continue;
		}

		/* This holds the fndhp vnode */
		error = hyprlofs_dirlookup(hp, hdp->hld_name, &fndhp, cr);
		if (error != 0)
			goto done;
		hlnode_rele(fndhp);

		if (fndhp->hln_looped == 0) {
			/* recursively get contents of this subdir */
			VERIFY(fndhp->hln_type == VDIR);
			tvp = HLNTOV(fndhp);

			if (*prefix == '\0')
				(void) strlcpy(path, hdp->hld_name, MAXPATHLEN);
			else
				(void) snprintf(path, MAXPATHLEN, "%s/%s",
				    prefix, hdp->hld_name);

			error = hyprlofs_get_all_entries(tvp, hcp, path,
			    &cnt, n_max, cr, ct, flags);

			if (error == E2BIG) {
				too_big = 1;
				error = 0;
			}
			if (error != 0)
				goto done;
		} else {
			if (cnt < n_max) {
				char *p;

				if (*prefix == '\0')
					(void) strlcpy(path, hdp->hld_name,
					    MAXPATHLEN);
				else
					(void) snprintf(path, MAXPATHLEN,
					    "%s/%s", prefix, hdp->hld_name);

				len = strlen(path);
				ASSERT(len <= MAXPATHLEN);
				if (copyout(path, (void *)(hcp[cnt].hce_name),
				    len)) {
					error = EFAULT;
					goto done;
				}

				tvp = REALVP(HLNTOV(fndhp));
				if (tvp->v_path == vn_vpath_empty) {
					p = "<unknown>";
				} else {
					p = tvp->v_path;
				}
				len = strlen(p);
				ASSERT(len <= MAXPATHLEN);
				if (copyout(p, (void *)(hcp[cnt].hce_path),
				    len)) {
					error = EFAULT;
					goto done;
				}
			}

			cnt++;
			if (cnt > n_max)
				too_big = 1;
		}

		hdp = hdp->hld_next;
	}

done:
	hlnode_rele(hp);
	kmem_free(path, MAXPATHLEN);

	*pcnt = cnt;
	if (error == 0 && too_big == 1)
		error = E2BIG;

	return (error);
}

/*
 * Return a list of all looped in files in the namespace.
 */
static int
hyprlofs_get_all(vnode_t *dvp, intptr_t data, cred_t *cr, caller_context_t *ct,
    int flags)
{
	uint_t limit, cnt;
	int error;
	model_t model;
	hyprlofs_curr_entry_t *e;

	model = get_udatamodel();

	if (model == DATAMODEL_NATIVE) {
		hyprlofs_curr_entries_t ebuf;

		if (copyin((void *)data, &ebuf, sizeof (ebuf)))
			return (EFAULT);
		limit = ebuf.hce_cnt;
		e = ebuf.hce_entries;
		if (limit > MAX_IOCTL_PARAMS)
			return (EINVAL);

	} else {
		hyprlofs_curr_entries32_t ebuf32;

		if (copyin((void *)data, &ebuf32, sizeof (ebuf32)))
			return (EFAULT);

		limit = ebuf32.hce_cnt;
		e = (hyprlofs_curr_entry_t *)(unsigned long)
		    (ebuf32.hce_entries);
		if (limit > MAX_IOCTL_PARAMS)
			return (EINVAL);
	}

	cnt = 0;
	error = hyprlofs_get_all_entries(dvp, e, "", &cnt, limit, cr, ct,
	    flags);

	if (error == 0 || error == E2BIG) {
		if (model == DATAMODEL_NATIVE) {
			hyprlofs_curr_entries_t ebuf;

			ebuf.hce_cnt = cnt;
			if (copyout(&ebuf, (void *)data, sizeof (ebuf)))
				return (EFAULT);

		} else {
			hyprlofs_curr_entries32_t ebuf32;

			ebuf32.hce_cnt = cnt;
			if (copyout(&ebuf32, (void *)data, sizeof (ebuf32)))
				return (EFAULT);
		}
	}

	return (error);
}

/* ARGSUSED3 */
static int
hyprlofs_remove(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct,
    int flags)
{
	hlnode_t *parent = (hlnode_t *)VTOHLN(dvp);
	int error;
	hlnode_t *hp = NULL;

	/* This holds the hp vnode */
	error = hyprlofs_dirlookup(parent, nm, &hp, cr);
	if (error)
		return (error);

	ASSERT(hp);
	rw_enter(&parent->hln_rwlock, RW_WRITER);
	rw_enter(&hp->hln_rwlock, RW_WRITER);

	error = hyprlofs_dirdelete(parent, hp, nm, DR_REMOVE, cr);

	rw_exit(&hp->hln_rwlock);
	rw_exit(&parent->hln_rwlock);
	vnevent_remove(HLNTOV(hp), dvp, nm, ct);

	/*
	 * We've now dropped the dir link so by rele-ing our vnode we should
	 * clean up in hyprlofs_inactive.
	 */
	hlnode_rele(hp);

	return (error);
}

/* ARGSUSED4 */
static int
hyprlofs_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
    caller_context_t *ct, int flags)
{
	hlnode_t *parent = (hlnode_t *)VTOHLN(dvp);
	hlnode_t *self = NULL;
	vnode_t *vp;
	int error = 0;

	/* Return error if removing . or .. */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* Should be ENOTEMPTY */
	error = hyprlofs_dirlookup(parent, nm, &self, cr);
	if (error)
		return (error);

	rw_enter(&parent->hln_rwlock, RW_WRITER);
	rw_enter(&self->hln_rwlock, RW_WRITER);

	vp = HLNTOV(self);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto done1;
	}
	if (self->hln_type != VDIR) {
		error = ENOTDIR;
		goto done1;
	}

	/*
	 * When a dir is looped in, we only remove the in-memory dir, not the
	 * backing dir.
	 */
	if (self->hln_looped == 0) {
		mutex_enter(&self->hln_tlock);
		if (self->hln_nlink > 2) {
			mutex_exit(&self->hln_tlock);
			error = EEXIST;
			goto done1;
		}
		mutex_exit(&self->hln_tlock);

		if (vn_vfswlock(vp)) {
			error = EBUSY;
			goto done1;
		}
		if (vn_mountedvfs(vp) != NULL) {
			error = EBUSY;
			goto done;
		}

		/*
		 * Check for an empty directory, i.e. only includes entries for
		 * "." and ".."
		 */
		if (self->hln_dirents > 2) {
			error = EEXIST;		/* SIGH should be ENOTEMPTY */
			/*
			 * Update atime because checking hln_dirents is
			 * equivalent to reading the directory
			 */
			gethrestime(&self->hln_atime);
			goto done;
		}

		error = hyprlofs_dirdelete(parent, self, nm, DR_RMDIR, cr);
	} else {
		error = hyprlofs_dirdelete(parent, self, nm, DR_REMOVE, cr);
	}

done:
	if (self->hln_looped == 0)
		vn_vfsunlock(vp);
done1:
	rw_exit(&self->hln_rwlock);
	rw_exit(&parent->hln_rwlock);
	vnevent_rmdir(HLNTOV(self), dvp, nm, ct);

	/*
	 * We've now dropped the dir link so by rele-ing our vnode we should
	 * clean up in hyprlofs_inactive.
	 */
	hlnode_rele(self);

	return (error);
}

static int
hyprlofs_readdir(vnode_t *vp, struct uio *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	hlnode_t *hp = (hlnode_t *)VTOHLN(vp);
	hldirent_t *hdp;
	int error = 0;
	size_t namelen;
	struct dirent64 *dp;
	ulong_t offset;
	ulong_t total_bytes_wanted;
	ulong_t outcount = 0;
	ulong_t bufsize;
	size_t reclen;
	caddr_t outbuf;

	if (VTOHLN(vp)->hln_looped == 1)
		return (VOP_READDIR(REALVP(vp), uiop, cr, eofp, ct, flags));

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}
	/* assuming syscall has already called hln_rwlock */
	ASSERT(RW_READ_HELD(&hp->hln_rwlock));

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * There's a window here where someone could have removed
	 * all the entries in the directory after we put a hold on the
	 * vnode but before we grabbed the rwlock.  Just return.
	 */
	if (hp->hln_dir == NULL) {
		if (hp->hln_nlink) {
			panic("empty directory 0x%p", (void *)hp);
			/*NOTREACHED*/
		}
		return (0);
	}

	/* Get space for multiple dir entries */
	total_bytes_wanted = uiop->uio_iov->iov_len;
	bufsize = total_bytes_wanted + sizeof (struct dirent64);
	outbuf = kmem_alloc(bufsize, KM_SLEEP);

	dp = (struct dirent64 *)((uintptr_t)outbuf);

	offset = 0;
	hdp = hp->hln_dir;
	while (hdp) {
		namelen = strlen(hdp->hld_name);	/* no +1 needed */
		offset = hdp->hld_offset;
		if (offset >= uiop->uio_offset) {
			reclen = DIRENT64_RECLEN(namelen);
			if (outcount + reclen > total_bytes_wanted) {
				if (!outcount)
					/* Buffer too small for any entries. */
					error = EINVAL;
				break;
			}
			ASSERT(hdp->hld_hlnode != NULL);

			/* zero out uninitialized bytes */
			(void) strncpy(dp->d_name, hdp->hld_name,
			    DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)hdp->hld_hlnode->hln_nodeid;
			dp->d_off = (offset_t)hdp->hld_offset + 1;
			dp = (struct dirent64 *)
			    ((uintptr_t)dp + dp->d_reclen);
			outcount += reclen;
			ASSERT(outcount <= bufsize);
		}
		hdp = hdp->hld_next;
	}

	if (!error)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		/*
		 * If we reached the end of the list our offset should now be
		 * just past the end.
		 */
		if (!hdp) {
			offset += 1;
			if (eofp)
				*eofp = 1;
		} else if (eofp)
			*eofp = 0;
		uiop->uio_offset = offset;
	}
	gethrestime(&hp->hln_atime);
	kmem_free(outbuf, bufsize);
	return (error);
}

static int
hyprlofs_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	if (VTOHLN(vp)->hln_looped == 1)
		return (VOP_FSYNC(REALVP(vp), syncflag, cr, ct));
	return (0);
}

/* ARGSUSED */
static void
hyprlofs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	hlnode_t *hp = (hlnode_t *)VTOHLN(vp);
	hlfsmount_t *hm = (hlfsmount_t *)VFSTOHLM(vp->v_vfsp);

	rw_enter(&hp->hln_rwlock, RW_WRITER);

	mutex_enter(&hp->hln_tlock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's nothing to do except drop our hold.
	 */
	if (vp->v_count > 1 || hp->hln_nlink != 0) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&hp->hln_tlock);
		rw_exit(&hp->hln_rwlock);
		return;
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&hp->hln_tlock);

	/* release hold on the real vnode now */
	if (hp->hln_looped == 1 && hp->hln_realvp != NULL)
		VN_RELE(hp->hln_realvp);

	/* Here's our chance to send invalid event while we're between locks */
	vn_invalid(HLNTOV(hp));

	mutex_enter(&hm->hlm_contents);
	if (hp->hln_forw == NULL)
		hm->hlm_rootnode->hln_back = hp->hln_back;
	else
		hp->hln_forw->hln_back = hp->hln_back;
	hp->hln_back->hln_forw = hp->hln_forw;
	mutex_exit(&hm->hlm_contents);
	rw_exit(&hp->hln_rwlock);
	rw_destroy(&hp->hln_rwlock);
	mutex_destroy(&hp->hln_tlock);
	vn_free(HLNTOV(hp));
	kmem_free(hp, sizeof (hlnode_t));
}

static int
hyprlofs_fid(vnode_t *vp, struct fid *fidp, caller_context_t *ct)
{
	hlnode_t *hp = (hlnode_t *)VTOHLN(vp);
	hlfid_t *hfid;

	if (VTOHLN(vp)->hln_looped == 1)
		return (VOP_FID(REALVP(vp), fidp, ct));

	if (fidp->fid_len < (sizeof (hlfid_t) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (hlfid_t) - sizeof (ushort_t);
		return (ENOSPC);
	}

	hfid = (hlfid_t *)fidp;
	bzero(hfid, sizeof (hlfid_t));
	hfid->hlfid_len = (int)sizeof (hlfid_t) - sizeof (ushort_t);

	hfid->hlfid_ino = hp->hln_nodeid;
	hfid->hlfid_gen = hp->hln_gen;

	return (0);
}

static int
hyprlofs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr, enum seg_rw rw,
    cred_t *cr, caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_GETPAGE(REALVP(vp), off, len, protp, pl, plsz, seg, addr,
	    rw, cr, ct));
}

int
hyprlofs_putpage(vnode_t *vp, offset_t off, size_t len, int flags,
    cred_t *cr, caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_PUTPAGE(REALVP(vp), off, len, flags, cr, ct));
}

static int
hyprlofs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_MAP(REALVP(vp), off, as, addrp, len, prot, maxprot, flags,
	    cr, ct));
}

static int
hyprlofs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_ADDMAP(REALVP(vp), off, as, addr, len, prot, maxprot,
	    flags, cr, ct));
}

static int
hyprlofs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_DELMAP(REALVP(vp), off, as, addr, len, prot, maxprot,
	    flags, cr, ct));
}

static int
hyprlofs_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	/* return EACCES to be consistent with mmap */
	if (VTOHLN(vp)->hln_looped != 1)
		return (EACCES);
	return (VOP_SPACE(REALVP(vp), cmd, bfp, flag, offset, cr, ct));
}

static int
hyprlofs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	if (VTOHLN(vp)->hln_looped == 0)
		return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);

	return (VOP_SEEK(REALVP(vp), ooff, noffp, ct));
}

static int
hyprlofs_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	hlnode_t *hp = VTOHLN(vp);

	if (hp->hln_looped == 1)
		return (VOP_RWLOCK(REALVP(vp), write_lock, ct));

	if (write_lock) {
		rw_enter(&hp->hln_rwlock, RW_WRITER);
	} else {
		rw_enter(&hp->hln_rwlock, RW_READER);
	}
	return (write_lock);
}

static void
hyprlofs_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	hlnode_t *hp = VTOHLN(vp);

	if (hp->hln_looped == 1) {
		VOP_RWUNLOCK(REALVP(vp), write_lock, ct);
		return;
	}

	rw_exit(&hp->hln_rwlock);
}

static int
hyprlofs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	int error;

	if (VTOHLN(vp)->hln_looped == 1)
		return (VOP_PATHCONF(REALVP(vp), cmd, valp, cr, ct));

	switch (cmd) {
	case _PC_XATTR_ENABLED:
	case _PC_XATTR_EXISTS:
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		error = EINVAL;
		break;
	case _PC_TIMESTAMP_RESOLUTION:
		/* nanosecond timestamp resolution */
		*valp = 1L;
		error = 0;
		break;
	default:
		error = fs_pathconf(vp, cmd, valp, cr, ct);
	}
	return (error);
}


struct vnodeops *hyprlofs_vnodeops;

const fs_operation_def_t hyprlofs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = hyprlofs_open },
	VOPNAME_CLOSE,		{ .vop_close = hyprlofs_close },
	VOPNAME_READ,		{ .vop_read = hyprlofs_read },
	VOPNAME_WRITE,		{ .vop_write = hyprlofs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = hyprlofs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = hyprlofs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = hyprlofs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = hyprlofs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = hyprlofs_lookup },
	VOPNAME_CREATE,		{ .error = fs_error },
	VOPNAME_REMOVE,		{ .vop_remove = hyprlofs_remove },
	VOPNAME_LINK,		{ .error = fs_error },
	VOPNAME_RENAME,		{ .error = fs_error },
	VOPNAME_MKDIR,		{ .error = fs_error },
	VOPNAME_RMDIR,		{ .vop_rmdir = hyprlofs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = hyprlofs_readdir },
	VOPNAME_SYMLINK,	{ .error = fs_error },
	VOPNAME_READLINK,	{ .error = fs_error },
	VOPNAME_FSYNC,		{ .vop_fsync = hyprlofs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = hyprlofs_inactive },
	VOPNAME_FID,		{ .vop_fid = hyprlofs_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = hyprlofs_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = hyprlofs_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = hyprlofs_seek },
	VOPNAME_SPACE,		{ .vop_space = hyprlofs_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = hyprlofs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = hyprlofs_putpage },
	VOPNAME_MAP,		{ .vop_map = hyprlofs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = hyprlofs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = hyprlofs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = hyprlofs_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

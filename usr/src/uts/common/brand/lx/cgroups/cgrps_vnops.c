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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
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
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <vm/seg_vn.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/vm.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>
#include <sys/sdt.h>

#include "cgrps.h"

/* ARGSUSED1 */
static int
cgrp_open(struct vnode **vpp, int flag, struct cred *cred, caller_context_t *ct)
{
	/*
	 * swapon to a cgrp file is not supported so access is denied on open
	 * if VISSWAP is set.
	 */
	if ((*vpp)->v_flag & VISSWAP)
		return (EINVAL);
	return (0);
}

/* ARGSUSED1 */
static int
cgrp_close(struct vnode *vp, int flag, int count, offset_t offset,
    struct cred *cred, caller_context_t *ct)
{
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*
 * cgrp_wr does the real work of write requests for cgroups.
 */
static int
cgrp_wr(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio, struct cred *cr,
    caller_context_t *ct)
{
	struct vnode *vp;
	int error = 0;
	rlim64_t limit = uio->uio_llimit;

	vp = CGNTOV(cn);
	ASSERT(vp->v_type == VREG);

	ASSERT(RW_WRITE_HELD(&cn->cgn_contents));
	ASSERT(RW_WRITE_HELD(&cn->cgn_rwlock));

	if (uio->uio_loffset < 0)
		return (EINVAL);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	if (uio->uio_loffset >= MAXOFF_T)
		return (EFBIG);

	if (uio->uio_resid == 0)
		return (0);

	if (limit > MAXOFF_T)
		limit = MAXOFF_T;

	/* XXX implement pseudo file write for subsystem and type */
	DTRACE_PROBE2(cgrp__wr, int, cgm->cg_ssid, int, cn->cgn_type);

	return (error);
}

/*
 * cgrp_rd does the real work of read requests for cgroups.
 */
static int
cgrp_rd(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio, caller_context_t *ct)
{
	struct vnode *vp;
	int error = 0;

	vp = CGNTOV(cn);

	ASSERT(RW_LOCK_HELD(&cn->cgn_contents));

	ASSERT(cn->cgn_type != CG_CGROUP_DIR);

	if (uio->uio_loffset >= MAXOFF_T)
		return (0);
	if (uio->uio_loffset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);

	/* XXX implement pseudo file read for subsystem and type */
	DTRACE_PROBE2(cgrp__rd, int, cgm->cg_ssid, int, cn->cgn_type);

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_read(struct vnode *vp, struct uio *uiop, int ioflag, cred_t *cred,
    struct caller_context *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VTOCGM(vp);
	int error;

	/*
	 * We don't support reading non-regular files
	 */
	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);
	/*
	 * cgrp_rwlock should have already been called from layers above
	 */
	ASSERT(RW_READ_HELD(&cn->cgn_rwlock));

	rw_enter(&cn->cgn_contents, RW_READER);

	error = cgrp_rd(cgm, cn, uiop, ct);

	rw_exit(&cn->cgn_contents);

	return (error);
}

static int
cgrp_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
    struct caller_context *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VTOCGM(vp);
	int error;

	/*
	 * We don't support writing to non-regular files
	 */
	if (vp->v_type != VREG)
		return (EINVAL);

	/* cgrp_rwlock should have already been called from layers above */
	ASSERT(RW_WRITE_HELD(&cn->cgn_rwlock));

	rw_enter(&cn->cgn_contents, RW_WRITER);

	if (ioflag & FAPPEND) {
		/* In append mode start at end of file. */
		uiop->uio_loffset = cn->cgn_size;
	}

	error = cgrp_wr(cgm, cn, uiop, cred, ct);

	rw_exit(&cn->cgn_contents);

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_getattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	struct vattr va;
	int attrs = 1;

	mutex_enter(&cn->cgn_tlock);
	if (attrs == 0) {
		cn->cgn_uid = va.va_uid;
		cn->cgn_gid = va.va_gid;
	}
	vap->va_type = vp->v_type;
	vap->va_mode = cn->cgn_mode & MODEMASK;
	vap->va_uid = cn->cgn_uid;
	vap->va_gid = cn->cgn_gid;
	vap->va_fsid = cn->cgn_fsid;
	vap->va_nodeid = (ino64_t)cn->cgn_nodeid;
	vap->va_nlink = cn->cgn_nlink;
	vap->va_size = (u_offset_t)cn->cgn_size;
	vap->va_atime = cn->cgn_atime;
	vap->va_mtime = cn->cgn_mtime;
	vap->va_ctime = cn->cgn_ctime;
	vap->va_blksize = PAGESIZE;
	vap->va_rdev = cn->cgn_rdev;
	vap->va_seq = cn->cgn_seq;

	vap->va_nblocks = (fsblkcnt64_t)btodb(ptob(btopr(vap->va_size)));
	mutex_exit(&cn->cgn_tlock);
	return (0);
}

/*ARGSUSED4*/
static int
cgrp_setattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	int error = 0;
	struct vattr *get;
	long mask;

	/*
	 * Cannot set these attributes
	 */
	if ((vap->va_mask & AT_NOSET) || (vap->va_mask & AT_XVATTR) ||
	    (vap->va_mode & (S_ISUID | S_ISGID)) || (vap->va_mask & AT_SIZE))
		return (EINVAL);

	mutex_enter(&cn->cgn_tlock);

	get = &cn->cgn_attr;
	/*
	 * Change file access modes. Must be owner or have sufficient
	 * privileges.
	 */
	error = secpolicy_vnode_setattr(cred, vp, vap, get, flags, cgrp_taccess,
	    cn);

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
		gethrestime(&cn->cgn_ctime);

out:
	mutex_exit(&cn->cgn_tlock);
	return (error);
}

/* ARGSUSED2 */
static int
cgrp_access(struct vnode *vp, int mode, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	int error;

	mutex_enter(&cn->cgn_tlock);
	error = cgrp_taccess(cn, mode, cred);
	mutex_exit(&cn->cgn_tlock);
	return (error);
}

/* ARGSUSED3 */
static int
cgrp_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(dvp);
	cgrp_node_t *ncn = NULL;
	int error;

	/* disallow extended attrs */
	if (flags & LOOKUP_XATTR)
		return (EINVAL);

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}
	ASSERT(cn);

	error = cgrp_dirlookup(cn, nm, &ncn, cred);

	if (error == 0) {
		ASSERT(ncn);
		*vpp = CGNTOV(ncn);
	}

	return (error);
}

/*ARGSUSED7*/
static int
cgrp_create(struct vnode *dvp, char *nm, struct vattr *vap,
    enum vcexcl exclusive, int mode, struct vnode **vpp, struct cred *cred,
    int flag, caller_context_t *ct, vsecattr_t *vsecp)
{
	/*
	 * cgroups doesn't allow creation of additional, non-subsystem specific
	 * files in a dir
	 */
	return (EPERM);
}

/* ARGSUSED3 */
static int
cgrp_remove(struct vnode *dvp, char *nm, struct cred *cred,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *parent = (cgrp_node_t *)VTOCGN(dvp);
	int error;
	cgrp_node_t *cn = NULL;

	/*
	 * Removal of subsystem-specific files is not allowed but we need
	 * to return the correct error if they try to remove a non-existent
	 * file.
	 */

	error = cgrp_dirlookup(parent, nm, &cn, cred);
	if (error)
		return (error);

	ASSERT(cn);
	cgnode_rele(cn);
	return (EPERM);
}

/* ARGSUSED4 */
static int
cgrp_link(struct vnode *dvp, struct vnode *srcvp, char *cnm, struct cred *cred,
    caller_context_t *ct, int flags)
{
	/* cgroups doesn't support hard links */
	return (EPERM);
}

/*
 * Rename of subsystem-specific files is not allowed but we can rename
 * directories (i.e. sub-groups). We cannot mv subdirs from one group to
 * another so the src and dest vnode must be the same.
 */
/* ARGSUSED5 */
static int
cgrp_rename(
	struct vnode *odvp,	/* source parent vnode */
	char *onm,		/* source name */
	struct vnode *ndvp,	/* destination parent vnode */
	char *nnm,		/* destination name */
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	cgrp_node_t *fromparent;
	cgrp_node_t *toparent;
	cgrp_node_t *fromcn = NULL;	/* source cgrp_node */
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VTOCGM(odvp);
	int error, err;

	fromparent = (cgrp_node_t *)VTOCGN(odvp);
	toparent = (cgrp_node_t *)VTOCGN(ndvp);

	if (fromparent != toparent)
		return (EIO);

	/* discourage additional use of toparent */
	toparent = NULL;

	mutex_enter(&cgm->cg_renamelck);

	/*
	 * Look up cgrp_node of file we're supposed to rename.
	 */
	error = cgrp_dirlookup(fromparent, onm, &fromcn, cred);
	if (error) {
		mutex_exit(&cgm->cg_renamelck);
		return (error);
	}

	if (fromcn->cgn_type != CG_CGROUP_DIR) {
		error = EPERM;
		goto done;
	}

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.
	 */
	if (((error = cgrp_taccess(fromparent, VWRITE, cred)) != 0))
		goto done;

	/*
	 * Check for renaming to or from '.' or '..' or that
	 * fromcn == fromparent
	 */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0'))) ||
	    (fromparent == fromcn)) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Link source to new target
	 */
	rw_enter(&fromparent->cgn_rwlock, RW_WRITER);
	error = cgrp_direnter(cgm, fromparent, nnm, DE_RENAME,
	    fromcn, (struct vattr *)NULL,
	    (cgrp_node_t **)NULL, cred, ct);
	rw_exit(&fromparent->cgn_rwlock);

	if (error)
		goto done;

	/*
	 * Unlink from source.
	 */
	rw_enter(&fromparent->cgn_rwlock, RW_WRITER);
	rw_enter(&fromcn->cgn_rwlock, RW_WRITER);

	error = err = cgrp_dirdelete(fromparent, fromcn, onm, DR_RENAME, cred);

	/*
	 * The following handles the case where our source cgrp_node was
	 * removed before we got to it.
	 */
	if (error == ENOENT)
		error = 0;

	rw_exit(&fromcn->cgn_rwlock);
	rw_exit(&fromparent->cgn_rwlock);

	if (err == 0) {
		vnevent_rename_src(CGNTOV(fromcn), odvp, onm, ct);
		vnevent_rename_dest_dir(ndvp, CGNTOV(fromcn), nnm, ct);
	}

done:
	cgnode_rele(fromcn);
	mutex_exit(&cgm->cg_renamelck);

	return (error);
}

/* ARGSUSED5 */
static int
cgrp_mkdir(struct vnode *dvp, char *nm, struct vattr *va, struct vnode **vpp,
    struct cred *cred, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	cgrp_node_t *parent = (cgrp_node_t *)VTOCGN(dvp);
	cgrp_node_t *self = NULL;
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VTOCGM(dvp);
	int error;

	/*
	 * Might be dangling directory.  Catch it here, because a ENOENT
	 * return from cgrp_dirlookup() is an "ok return".
	 */
	if (parent->cgn_nlink == 0)
		return (ENOENT);

	error = cgrp_dirlookup(parent, nm, &self, cred);
	if (error == 0) {
		ASSERT(self != NULL);
		cgnode_rele(self);
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	rw_enter(&parent->cgn_rwlock, RW_WRITER);
	error = cgrp_direnter(cgm, parent, nm, DE_MKDIR, (cgrp_node_t *)NULL,
	    va, &self, cred, ct);
	if (error) {
		rw_exit(&parent->cgn_rwlock);
		if (self != NULL)
			cgnode_rele(self);
		return (error);
	}
	rw_exit(&parent->cgn_rwlock);
	*vpp = CGNTOV(self);
	return (0);
}

/* ARGSUSED4 */
static int
cgrp_rmdir(struct vnode *dvp, char *nm, struct vnode *cdir, struct cred *cred,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *parent = (cgrp_node_t *)VTOCGN(dvp);
	cgrp_mnt_t *cgm;
	cgrp_node_t *self = NULL;
	struct vnode *vp;
	int error = 0;

	/*
	 * Return error when removing . and ..
	 */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* Should be ENOTEMPTY */
	error = cgrp_dirlookup(parent, nm, &self, cred);
	if (error)
		return (error);

	rw_enter(&parent->cgn_rwlock, RW_WRITER);
	rw_enter(&self->cgn_rwlock, RW_WRITER);

	vp = CGNTOV(self);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto done1;
	}
	if (self->cgn_type != CG_CGROUP_DIR) {
		error = ENOTDIR;
		goto done1;
	}

	cgm = (cgrp_mnt_t *)VFSTOCGM(self->cgn_vnode->v_vfsp);

	mutex_enter(&self->cgn_tlock);
	/* Check for the existence of any sub-cgroup directories */
	if (self->cgn_nlink > 2) {
		mutex_exit(&self->cgn_tlock);
		error = EEXIST;
		goto done1;
	}
	mutex_exit(&self->cgn_tlock);

	if (vn_vfswlock(vp)) {
		error = EBUSY;
		goto done1;
	}
	if (vn_mountedvfs(vp) != NULL) {
		error = EBUSY;
		goto done;
	}

	/*
	 * Confirm directory only includes entries for ".", ".." and the
	 * fixed pseudo file entries.
	 */
	if (self->cgn_dirents > (cgrp_num_pseudo_ents(cgm->cg_ssid) + 2)) {
		error = EEXIST;		/* should be ENOTEMPTY */
		/*
		 * Update atime because checking cn_dirents is logically
		 * equivalent to reading the directory
		 */
		gethrestime(&self->cgn_atime);
		goto done;
	}

	error = cgrp_dirdelete(parent, self, nm, DR_RMDIR, cred);
done:
	vn_vfsunlock(vp);
done1:
	rw_exit(&self->cgn_rwlock);
	rw_exit(&parent->cgn_rwlock);
	vnevent_rmdir(CGNTOV(self), dvp, nm, ct);
	cgnode_rele(self);

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_readdir(struct vnode *vp, struct uio *uiop, struct cred *cred, int *eofp,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	cgrp_dirent_t *cdp;
	int error = 0;
	size_t namelen;
	struct dirent64 *dp;
	ulong_t offset;
	ulong_t total_bytes_wanted;
	long outcount = 0;
	long bufsize;
	int reclen;
	caddr_t outbuf;

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}
	/*
	 * assuming system call has already called cgrp_rwlock
	 */
	ASSERT(RW_READ_HELD(&cn->cgn_rwlock));

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if (cn->cgn_dir == NULL) {
		VERIFY(cn->cgn_nlink == 0);
		return (0);
	}

	/*
	 * Get space for multiple directory entries
	 */
	total_bytes_wanted = uiop->uio_iov->iov_len;
	bufsize = total_bytes_wanted + sizeof (struct dirent64);
	outbuf = kmem_alloc(bufsize, KM_SLEEP);

	dp = (struct dirent64 *)outbuf;

	offset = 0;
	cdp = cn->cgn_dir;
	while (cdp) {
		namelen = strlen(cdp->cgd_name);	/* no +1 needed */
		offset = cdp->cgd_offset;
		if (offset >= uiop->uio_offset) {
			reclen = (int)DIRENT64_RECLEN(namelen);
			if (outcount + reclen > total_bytes_wanted) {
				if (!outcount) {
					/* Buffer too small for any entries. */
					error = EINVAL;
				}
				break;
			}
			ASSERT(cdp->cgd_cgrp_node != NULL);

			/* use strncpy(9f) to zero out uninitialized bytes */

			(void) strncpy(dp->d_name, cdp->cgd_name,
			    DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)cdp->cgd_cgrp_node->cgn_nodeid;
			dp->d_off = (offset_t)cdp->cgd_offset + 1;
			dp = (struct dirent64 *)((uintptr_t)dp + dp->d_reclen);
			outcount += reclen;
			ASSERT(outcount <= bufsize);
		}
		cdp = cdp->cgd_next;
	}

	if (!error)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		/*
		 * If we reached the end of the list our offset should now be
		 * just past the end.
		 */
		if (!cdp) {
			offset += 1;
			if (eofp)
				*eofp = 1;
		} else if (eofp)
			*eofp = 0;
		uiop->uio_offset = offset;
	}
	gethrestime(&cn->cgn_atime);
	kmem_free(outbuf, bufsize);
	return (error);
}

/* ARGSUSED5 */
static int
cgrp_symlink(struct vnode *dvp, char *lnm, struct vattr *cva, char *cnm,
    struct cred *cred, caller_context_t *ct, int flags)
{
	/* cgroups doesn't support symlinks */
	return (EPERM);
}

/* ARGSUSED */
static void
cgrp_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	cgrp_node_t *cn = (cgrp_node_t *)VTOCGN(vp);
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vp->v_vfsp);

	rw_enter(&cn->cgn_rwlock, RW_WRITER);
	mutex_enter(&cn->cgn_tlock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's little to do -- just drop our hold.
	 */
	if (vp->v_count > 1 || cn->cgn_nlink != 0) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&cn->cgn_tlock);
		rw_exit(&cn->cgn_rwlock);
		return;
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&cn->cgn_tlock);
	/* Here's our chance to send invalid event while we're between locks */
	vn_invalid(CGNTOV(cn));

	mutex_enter(&cgm->cg_contents);
	if (cn->cgn_forw == NULL)
		cgm->cg_rootnode->cgn_back = cn->cgn_back;
	else
		cn->cgn_forw->cgn_back = cn->cgn_back;
	cn->cgn_back->cgn_forw = cn->cgn_forw;
	mutex_exit(&cgm->cg_contents);

	rw_exit(&cn->cgn_rwlock);
	rw_destroy(&cn->cgn_rwlock);
	mutex_destroy(&cn->cgn_tlock);
	vn_free(CGNTOV(cn));
	kmem_free(cn, sizeof (cgrp_node_t));
}

/* ARGSUSED */
static int
cgrp_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED2 */
static int
cgrp_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	cgrp_node_t *cn = VTOCGN(vp);

	if (write_lock) {
		rw_enter(&cn->cgn_rwlock, RW_WRITER);
	} else {
		rw_enter(&cn->cgn_rwlock, RW_READER);
	}
	return (write_lock);
}

/* ARGSUSED1 */
static void
cgrp_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	cgrp_node_t *cn = VTOCGN(vp);

	rw_exit(&cn->cgn_rwlock);
}

static int
cgrp_pathconf(struct vnode *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	int error;

	switch (cmd) {
	case _PC_XATTR_EXISTS:
		if (vp->v_vfsp->vfs_flag & VFS_XATTR) {
			*valp = 0;	/* assume no attributes */
			error = 0;	/* okay to ask */
		} else {
			error = EINVAL;
		}
		break;
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
		    (vp->v_type == VREG || vp->v_type == VDIR);
		error = 0;
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


struct vnodeops *cgrp_vnodeops;

const fs_operation_def_t cgrp_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = cgrp_open },
	VOPNAME_CLOSE,		{ .vop_close = cgrp_close },
	VOPNAME_READ,		{ .vop_read = cgrp_read },
	VOPNAME_WRITE,		{ .vop_write = cgrp_write },
	VOPNAME_GETATTR,	{ .vop_getattr = cgrp_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = cgrp_setattr },
	VOPNAME_ACCESS,		{ .vop_access = cgrp_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = cgrp_lookup },
	VOPNAME_CREATE,		{ .vop_create = cgrp_create },
	VOPNAME_REMOVE,		{ .vop_remove = cgrp_remove },
	VOPNAME_LINK,		{ .vop_link = cgrp_link },
	VOPNAME_RENAME,		{ .vop_rename = cgrp_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = cgrp_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = cgrp_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = cgrp_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = cgrp_symlink },
	VOPNAME_INACTIVE,	{ .vop_inactive = cgrp_inactive },
	VOPNAME_RWLOCK,		{ .vop_rwlock = cgrp_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = cgrp_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = cgrp_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = cgrp_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

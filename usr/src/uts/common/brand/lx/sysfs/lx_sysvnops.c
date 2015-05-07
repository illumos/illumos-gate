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

/*
 * lx_sysfs -- a Linux-compatible /sys for the LX brand
 */

#include <vm/seg_vn.h>
#include <sys/sdt.h>
#include <sys/strlog.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/lx_brand.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/pool_pset.h>
#include <sys/pset.h>
#include <sys/zone.h>
#include <sys/pghw.h>
#include <sys/vfs_opreg.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/lx_misc.h>
#include <sys/brand.h>
#include <sys/cred_impl.h>
#include <sys/tihdr.h>

#include "lx_sysfs.h"

/*
 * Pointer to the vnode ops vector for this fs.
 * This is instantiated in lxsys_init() in lx_sysvfsops.c
 */
vnodeops_t *lxsys_vnodeops;

static int lxsys_open(vnode_t **, int, cred_t *, caller_context_t *);
static int lxsys_close(vnode_t *, int, int, offset_t, cred_t *,
    caller_context_t *);
static int lxsys_read(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
static int lxsys_getattr(vnode_t *, vattr_t *, int, cred_t *,
    caller_context_t *);
static int lxsys_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int lxsys_lookup(vnode_t *, char *, vnode_t **,
    pathname_t *, int, vnode_t *, cred_t *, caller_context_t *, int *,
    pathname_t *);
static int lxsys_readdir(vnode_t *, uio_t *, cred_t *, int *,
    caller_context_t *, int);
static int lxsys_readlink(vnode_t *, uio_t *, cred_t *, caller_context_t *);
static int lxsys_cmp(vnode_t *, vnode_t *, caller_context_t *);
static int lxsys_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int lxsys_sync(void);
static void lxsys_inactive(vnode_t *, cred_t *, caller_context_t *);

static vnode_t *lxsys_lookup_sysdir(vnode_t *, char *);
static vnode_t *lxsys_lookup_fsdir(vnode_t *, char *);
static vnode_t *lxsys_lookup_fs_cgroupdir(vnode_t *, char *);

static int lxsys_readdir_sysdir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_fsdir(lxsys_node_t *, uio_t *, int *);
static int lxsys_readdir_fs_cgroupdir(lxsys_node_t *, uio_t *, int *);

/*
 * The lx /sys vnode operations vector
 */
const fs_operation_def_t lxsys_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lxsys_open },
	VOPNAME_CLOSE,		{ .vop_close = lxsys_close },
	VOPNAME_READ,		{ .vop_read = lxsys_read },
	VOPNAME_GETATTR,	{ .vop_getattr = lxsys_getattr },
	VOPNAME_ACCESS,		{ .vop_access = lxsys_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = lxsys_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = lxsys_readdir },
	VOPNAME_READLINK,	{ .vop_readlink = lxsys_readlink },
	VOPNAME_FSYNC,		{ .error = lxsys_sync },
	VOPNAME_SEEK,		{ .error = lxsys_sync },
	VOPNAME_INACTIVE,	{ .vop_inactive = lxsys_inactive },
	VOPNAME_CMP,		{ .vop_cmp = lxsys_cmp },
	VOPNAME_REALVP,		{ .vop_realvp = lxsys_realvp },
	NULL,			NULL
};


/*
 * file contents of an lx /sys directory.
 */
static lxsys_dirent_t sysdir[] = {
	{ LXSYS_FSDIR,		"fs" }
};

#define	SYSDIRFILES	(sizeof (sysdir) / sizeof (sysdir[0]))

/*
 * contents of lx /sys/fs directory
 */
static lxsys_dirent_t fsdir[] = {
	{ LXSYS_FS_CGROUPDIR,	"cgroup" }
};

#define	FSDIRFILES	(sizeof (fsdir) / sizeof (fsdir[0]))

/*
 * contents of lx /sys/fs/cgroup directory
 */
static lxsys_dirent_t cgroupdir[] = {
};

#define	CGROUPDIRFILES	0

/*
 * lxsys_open(): Vnode operation for VOP_OPEN()
 */
static int
lxsys_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t		*vp = *vpp;
	lxsys_node_t	*lxsnp = VTOLXS(vp);
	vnode_t		*rvp;
	int		error = 0;

	/*
	 * We only allow reading in this file system
	 */
	if (flag & FWRITE)
		return (EROFS);

	/*
	 * If we are opening an underlying file only allow regular files,
	 * reject the open for anything else.
	 * Just do it if we are opening the current or root directory.
	 */
	if (lxsnp->lxsys_realvp != NULL) {
		rvp = lxsnp->lxsys_realvp;

		/*
		 * Need to hold rvp since VOP_OPEN() may release it.
		 */
		VN_HOLD(rvp);
		error = VOP_OPEN(&rvp, flag, cr, ct);
		if (error) {
			VN_RELE(rvp);
		} else {
			*vpp = rvp;
			VN_RELE(vp);
		}
	}

	return (error);
}


/*
 * lxsys_close(): Vnode operation for VOP_CLOSE()
 */
/* ARGSUSED */
static int
lxsys_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/*
 * Array of lookup functions, indexed by lx /sys file type.
 */
static vnode_t *(*lxsys_lookup_function[LXSYS_NFILES])() = {
	lxsys_lookup_sysdir,		/* /sys			*/
	lxsys_lookup_fsdir,		/* /sys/fs		*/
	lxsys_lookup_fs_cgroupdir,	/* /sys/fs/cgroup	*/
};

/*
 * Array of readdir functions, indexed by /sys file type.
 */
static int (*lxsys_readdir_function[LXSYS_NFILES])() = {
	lxsys_readdir_sysdir,		/* /sys			*/
	lxsys_readdir_fsdir,		/* /sys/fs		*/
	lxsys_readdir_fs_cgroupdir,	/* /sys/fs/cgroup	*/
};


/*
 * lxsys_read(): Vnode operation for VOP_READ()
 * All we currently have in this fs are directories.
 */
/* ARGSUSED */
static int
lxsys_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	lxsys_node_t *lxsnp = VTOLXS(vp);
	lxsys_nodetype_t type = lxsnp->lxsys_type;

	ASSERT(type < LXSYS_NFILES);
	return (EISDIR);
}

/*
 * lxsys_getattr(): Vnode operation for VOP_GETATTR()
 */
static int
lxsys_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	register lxsys_node_t *lxsnp = VTOLXS(vp);
	int error;

	/*
	 * Return attributes of underlying vnode if ATTR_REAL
	 *
	 * but keep fd files with the symlink permissions
	 */
	if (lxsnp->lxsys_realvp != NULL && (flags & ATTR_REAL)) {
		vnode_t *rvp = lxsnp->lxsys_realvp;

		/*
		 * limit attribute information to owner or root
		 */
		if ((error = VOP_ACCESS(rvp, 0, 0, cr, ct)) != 0) {
			return (error);
		}

		/*
		 * now its attributes
		 */
		if ((error = VOP_GETATTR(rvp, vap, flags, cr, ct)) != 0) {
			return (error);
		}

		return (0);
	}

	/* Default attributes, that may be overridden below */
	bzero(vap, sizeof (*vap));
	vap->va_atime = vap->va_mtime = vap->va_ctime = lxsnp->lxsys_time;
	vap->va_nlink = 1;
	vap->va_type = vp->v_type;
	vap->va_mode = lxsnp->lxsys_mode;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_blksize = DEV_BSIZE;
	vap->va_uid = lxsnp->lxsys_uid;
	vap->va_gid = lxsnp->lxsys_gid;
	vap->va_nodeid = lxsnp->lxsys_ino;

	vap->va_nblocks = (fsblkcnt64_t)btod(vap->va_size);
	return (0);
}

/*
 * lxsys_access(): Vnode operation for VOP_ACCESS()
 */
static int
lxsys_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	lxsys_node_t *lxsnp = VTOLXS(vp);
	int shift = 0;

	/*
	 * Although our lx sysfs is basically a read only file system, Linux
	 * expects it to be writable so we can't just error if (mode & VWRITE).
	 */

	if (lxsnp->lxsys_realvp != NULL) {
		/*
		 * For these we use the underlying vnode's accessibility.
		 */
		return (VOP_ACCESS(lxsnp->lxsys_realvp, mode, flags, cr, ct));
	}

	/* If user is root allow access regardless of permission bits */
	if (secpolicy_proc_access(cr) == 0)
		return (0);

	/*
	 * Access check is based on only one of owner, group, public.  If not
	 * owner, then check group.  If not a member of the group, then check
	 * public access.
	 */
	if (crgetuid(cr) != lxsnp->lxsys_uid) {
		shift += 3;
		if (!groupmember((uid_t)lxsnp->lxsys_gid, cr))
			shift += 3;
	}

	mode &= ~(lxsnp->lxsys_mode << shift);

	if (mode == 0)
		return (0);

	return (EACCES);
}

/*
 * lxsys_lookup(): Vnode operation for VOP_LOOKUP()
 */
/* ARGSUSED */
static int
lxsys_lookup(vnode_t *dp, char *comp, vnode_t **vpp, pathname_t *pathp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	lxsys_node_t *lxsnp = VTOLXS(dp);
	lxsys_nodetype_t type = lxsnp->lxsys_type;
	int error;

	ASSERT(dp->v_type == VDIR);
	ASSERT(type < LXSYS_NFILES);

	/*
	 * restrict lookup permission to owner or root
	 */
	if ((error = lxsys_access(dp, VEXEC, 0, cr, ct)) != 0) {
		return (error);
	}

	/*
	 * Just return the parent vnode if that's where we are trying to go.
	 */
	if (strcmp(comp, "..") == 0) {
		VN_HOLD(lxsnp->lxsys_parent);
		*vpp = lxsnp->lxsys_parent;
		return (0);
	}

	/*
	 * Special handling for directory searches.  Note: null component name
	 * denotes that the current directory is being searched.
	 */
	if ((dp->v_type == VDIR) && (*comp == '\0' || strcmp(comp, ".") == 0)) {
		VN_HOLD(dp);
		*vpp = dp;
		return (0);
	}

	*vpp = (lxsys_lookup_function[type](dp, comp));
	return ((*vpp == NULL) ? ENOENT : 0);
}

/*
 * Do a sequential search on the given directory table
 */
static vnode_t *
lxsys_lookup_common(vnode_t *dp, char *comp, proc_t *p,
    lxsys_dirent_t *dirtab, int dirtablen)
{
	lxsys_node_t *lxsnp;
	int count;

	for (count = 0; count < dirtablen; count++) {
		if (strcmp(dirtab[count].d_name, comp) == 0) {
			lxsnp = lxsys_getnode(dp, dirtab[count].d_type, p);
			dp = LXSTOV(lxsnp);
			ASSERT(dp != NULL);
			return (dp);
		}
	}
	return (NULL);
}

static vnode_t *
lxsys_lookup_sysdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXS(dp)->lxsys_type == LXSYS_SYSDIR);
	return (lxsys_lookup_common(dp, comp, NULL, sysdir, SYSDIRFILES));
}

static vnode_t *
lxsys_lookup_fsdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXS(dp)->lxsys_type == LXSYS_FSDIR);
	return (lxsys_lookup_common(dp, comp, NULL, fsdir, FSDIRFILES));
}

static vnode_t *
lxsys_lookup_fs_cgroupdir(vnode_t *dp, char *comp)
{
	ASSERT(VTOLXS(dp)->lxsys_type == LXSYS_FS_CGROUPDIR);
	return (lxsys_lookup_common(dp, comp, NULL, cgroupdir, CGROUPDIRFILES));
}

/*
 * lxsys_readdir(): Vnode operation for VOP_READDIR()
 */
/* ARGSUSED */
static int
lxsys_readdir(vnode_t *dp, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	lxsys_node_t *lxsnp = VTOLXS(dp);
	lxsys_nodetype_t type = lxsnp->lxsys_type;
	ssize_t uresid;
	off_t uoffset;
	int error;

	ASSERT(dp->v_type == VDIR);
	ASSERT(type < LXSYS_NFILES);

	/*
	 * restrict readdir permission to owner or root
	 */
	if ((error = lxsys_access(dp, VREAD, 0, cr, ct)) != 0)
		return (error);

	uoffset = uiop->uio_offset;
	uresid = uiop->uio_resid;

	/* can't do negative reads */
	if (uoffset < 0 || uresid <= 0)
		return (EINVAL);

	/* can't read directory entries that don't exist! */
	if (uoffset % LXSYS_SDSIZE)
		return (ENOENT);

	return (lxsys_readdir_function[lxsnp->lxsys_type](lxsnp, uiop, eofp));
}

/*
 * This has the common logic for returning directory entries
 */
static int
lxsys_readdir_common(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp,
    lxsys_dirent_t *dirtab, int dirtablen)
{
	/* bp holds one dirent64 structure */
	longlong_t bp[DIRENT64_RECLEN(LXSNSIZ) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	ssize_t oresid;	/* save a copy for testing later */
	ssize_t uresid;

	oresid = uiop->uio_resid;

	/* clear out the dirent buffer */
	bzero(bp, sizeof (bp));

	/*
	 * Satisfy user request
	 */
	while ((uresid = uiop->uio_resid) > 0) {
		int dirindex;
		off_t uoffset;
		int reclen;
		int error;

		uoffset = uiop->uio_offset;
		dirindex  = (uoffset / LXSYS_SDSIZE) - 2;

		if (uoffset == 0) {

			dirent->d_ino = lxsnp->lxsys_ino;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);

		} else if (uoffset == LXSYS_SDSIZE) {

			dirent->d_ino = lxsys_parentinode(lxsnp);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);

		} else if (dirindex < dirtablen) {
			int slen = strlen(dirtab[dirindex].d_name);

			dirent->d_ino = lxsys_inode(dirtab[dirindex].d_type);

			ASSERT(slen < LXSNSIZ);
			(void) strcpy(dirent->d_name, dirtab[dirindex].d_name);
			reclen = DIRENT64_RECLEN(slen);

		} else {
			/* Run out of table entries */
			if (eofp) {
				*eofp = 1;
			}
			return (0);
		}

		dirent->d_off = (off64_t)(uoffset + LXSYS_SDSIZE);
		dirent->d_reclen = (ushort_t)reclen;

		/*
		 * if the size of the data to transfer is greater
		 * that that requested then we can't do it this transfer.
		 */
		if (reclen > uresid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uresid == oresid) {
				return (EINVAL);
			}
			break;
		}

		/*
		 * uiomove() updates both uiop->uio_resid and uiop->uio_offset
		 * by the same amount.  But we want uiop->uio_offset to change
		 * in increments of LXSYS_SDSIZE, which is different from the
		 * number of bytes being returned to the user.  So we set
		 * uiop->uio_offset separately, ignoring what uiomove() does.
		 */
		if ((error = uiomove((caddr_t)dirent, reclen, UIO_READ,
		    uiop)) != 0)
			return (error);

		uiop->uio_offset = uoffset + LXSYS_SDSIZE;
	}

	/* Have run out of space, but could have just done last table entry */
	if (eofp) {
		*eofp = (uiop->uio_offset >= ((dirtablen+2) * LXSYS_SDSIZE)) ?
		    1 : 0;
	}
	return (0);
}

static int
lxsys_readdir_sysdir(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxsnp->lxsys_type == LXSYS_SYSDIR);
	return (lxsys_readdir_common(lxsnp, uiop, eofp, sysdir, SYSDIRFILES));
}

static int
lxsys_readdir_fsdir(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxsnp->lxsys_type == LXSYS_FSDIR);
	return (lxsys_readdir_common(lxsnp, uiop, eofp, fsdir, FSDIRFILES));
}

static int
lxsys_readdir_fs_cgroupdir(lxsys_node_t *lxsnp, uio_t *uiop, int *eofp)
{
	ASSERT(lxsnp->lxsys_type == LXSYS_FS_CGROUPDIR);
	return (lxsys_readdir_common(lxsnp, uiop, eofp, cgroupdir,
	    CGROUPDIRFILES));
}

/*
 * lxsys_readlink(): Vnode operation for VOP_READLINK()
 */
/* ARGSUSED */
static int
lxsys_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	return (EINVAL);
}


/*
 * lxsys_inactive(): Vnode operation for VOP_INACTIVE()
 * Vnode is no longer referenced, deallocate the file
 * and all its resources.
 */
/* ARGSUSED */
static void
lxsys_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	lxsys_freenode(VTOLXS(vp));
}

/*
 * lxsys_sync(): Vnode operation for VOP_SYNC()
 */
static int
lxsys_sync()
{
	/*
	 * Nothing to sync but this function must never fail
	 */
	return (0);
}

/*
 * lxsys_cmp(): Vnode operation for VOP_CMP()
 */
static int
lxsys_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	vnode_t *rvp;

	while (vn_matchops(vp1, lxsys_vnodeops) &&
	    (rvp = VTOLXS(vp1)->lxsys_realvp) != NULL) {
		vp1 = rvp;
	}

	while (vn_matchops(vp2, lxsys_vnodeops) &&
	    (rvp = VTOLXS(vp2)->lxsys_realvp) != NULL) {
		vp2 = rvp;
	}

	if (vn_matchops(vp1, lxsys_vnodeops) ||
	    vn_matchops(vp2, lxsys_vnodeops))
		return (vp1 == vp2);
	return (VOP_CMP(vp1, vp2, ct));
}

/*
 * lxsys_realvp(): Vnode operation for VOP_REALVP()
 */
static int
lxsys_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	vnode_t *rvp;

	if ((rvp = VTOLXS(vp)->lxsys_realvp) != NULL) {
		vp = rvp;
		if (VOP_REALVP(vp, &rvp, ct) == 0)
			vp = rvp;
	}

	*vpp = vp;
	return (0);
}

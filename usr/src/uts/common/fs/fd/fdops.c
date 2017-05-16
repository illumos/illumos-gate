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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All rights reserved.  	*/


#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/user.h>
#include <sys/t_lock.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>
#include <sys/atomic.h>
#include <sys/mkdev.h>

#define	round(r)	(((r)+sizeof (int)-1)&(~(sizeof (int)-1)))
#define	fdtoi(n)	((n)+100)

#define	FDDIRSIZE 14
struct fddirect {
	short	d_ino;
	char	d_name[FDDIRSIZE];
};

#define	FDROOTINO	2
#define	FDSDSIZE	sizeof (struct fddirect)
#define	FDNSIZE		10

static int		fdfstype = 0;
static major_t		fdfsmaj;
static minor_t		fdfsmin;
static major_t		fdrmaj;
static kmutex_t		fd_minor_lock;

static int fdget(vnode_t *, char *, vnode_t **);

/* ARGSUSED */
static int
fdopen(vnode_t **vpp, int mode, cred_t *cr, caller_context_t *ct)
{
	if ((*vpp)->v_type != VDIR) {
		mutex_enter(&(*vpp)->v_lock);
		(*vpp)->v_flag |= VDUP;
		mutex_exit(&(*vpp)->v_lock);
	}
	return (0);
}

/* ARGSUSED */
static int
fdclose(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
fdread(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr, caller_context_t *ct)
{
	static struct fddirect dotbuf[] = {
		{ FDROOTINO, "."  },
		{ FDROOTINO, ".." }
	};
	struct fddirect dirbuf;
	int i, n;
	int minfd, maxfd, modoff, error = 0;
	int nentries;
	rctl_qty_t fdno_ctl;
	int endoff;

	if (vp->v_type != VDIR)
		return (ENOSYS);

	mutex_enter(&curproc->p_lock);
	fdno_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_NOFILE],
	    curproc->p_rctls, curproc);
	nentries = MIN(P_FINFO(curproc)->fi_nfiles, (int)fdno_ctl);
	mutex_exit(&curproc->p_lock);

	endoff = (nentries + 2) * FDSDSIZE;

	/*
	 * Fake up ".", "..", and the /dev/fd directory entries.
	 */
	if (uiop->uio_loffset < (offset_t)0 ||
	    uiop->uio_loffset >= (offset_t)endoff ||
	    uiop->uio_resid <= 0)
		return (0);
	ASSERT(uiop->uio_loffset <= MAXOFF_T);
	if (uiop->uio_offset < 2*FDSDSIZE) {
		error = uiomove((caddr_t)dotbuf + uiop->uio_offset,
		    MIN(uiop->uio_resid, 2*FDSDSIZE - uiop->uio_offset),
		    UIO_READ, uiop);
		if (uiop->uio_resid <= 0 || error)
			return (error);
	}
	minfd = (uiop->uio_offset - 2*FDSDSIZE)/FDSDSIZE;
	maxfd = (uiop->uio_offset + uiop->uio_resid - 1)/FDSDSIZE;
	modoff = uiop->uio_offset % FDSDSIZE;

	for (i = 0; i < FDDIRSIZE; i++)
		dirbuf.d_name[i] = '\0';
	for (i = minfd; i < MIN(maxfd, nentries); i++) {
		n = i;
		dirbuf.d_ino = fdtoi(n);
		numtos((ulong_t)n, dirbuf.d_name);
		error = uiomove((caddr_t)&dirbuf + modoff,
		    MIN(uiop->uio_resid, FDSDSIZE - modoff),
		    UIO_READ, uiop);
		if (uiop->uio_resid <= 0 || error)
			return (error);
		modoff = 0;
	}

	return (error);
}

/* ARGSUSED */
static int
fdgetattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	vfs_t *vfsp = vp->v_vfsp;
	timestruc_t now;

	if (vp->v_type == VDIR) {
		vap->va_nlink = 2;
		vap->va_size = (u_offset_t)
		    ((P_FINFO(curproc)->fi_nfiles + 2) * FDSDSIZE);
		vap->va_mode = 0555;
		vap->va_nodeid = (ino64_t)FDROOTINO;
	} else {
		vap->va_nlink = 1;
		vap->va_size = (u_offset_t)0;
		vap->va_mode = 0666;
		vap->va_nodeid = (ino64_t)fdtoi(getminor(vp->v_rdev));
	}
	vap->va_type = vp->v_type;
	vap->va_rdev = vp->v_rdev;
	vap->va_blksize = vfsp->vfs_bsize;
	vap->va_nblocks = (fsblkcnt64_t)0;
	gethrestime(&now);
	vap->va_atime = vap->va_mtime = vap->va_ctime = now;
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_fsid = vfsp->vfs_dev;
	vap->va_seq = 0;
	return (0);
}

/* ARGSUSED */
static int
fdaccess(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
fdlookup(vnode_t *dp, char *comp, vnode_t **vpp, pathname_t *pnp, int flags,
    vnode_t *rdir, cred_t *cr, caller_context_t *ct, int *direntflags,
    pathname_t *realpnp)
{
	if (comp[0] == 0 || strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
		VN_HOLD(dp);
		*vpp = dp;
		return (0);
	}
	return (fdget(dp, comp, vpp));
}

/* ARGSUSED */
static int
fdcreate(vnode_t *dvp, char *comp, vattr_t *vap, enum vcexcl excl, int mode,
    vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
    vsecattr_t *vsecp)
{
	return (fdget(dvp, comp, vpp));
}

/* ARGSUSED */
static int
fdreaddir(vnode_t *vp, uio_t *uiop, cred_t *cr, int *eofp, caller_context_t *ct,
    int flags)
{
	/* bp holds one dirent structure */
	u_offset_t bp[DIRENT64_RECLEN(FDNSIZE) / sizeof (u_offset_t)];
	struct dirent64 *dirent = (struct dirent64 *)bp;
	int reclen, nentries;
	rctl_qty_t fdno_ctl;
	int  n;
	int oresid;
	off_t off;

	if (uiop->uio_offset < 0 || uiop->uio_resid <= 0 ||
	    (uiop->uio_offset % FDSDSIZE) != 0)
		return (ENOENT);

	ASSERT(uiop->uio_loffset <= MAXOFF_T);
	oresid = uiop->uio_resid;
	bzero(bp, sizeof (bp));

	mutex_enter(&curproc->p_lock);
	fdno_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_NOFILE],
	    curproc->p_rctls, curproc);
	nentries = MIN(P_FINFO(curproc)->fi_nfiles, (int)fdno_ctl);
	mutex_exit(&curproc->p_lock);

	while (uiop->uio_resid > 0) {
		if ((off = uiop->uio_offset) == 0) {	/* "." */
			dirent->d_ino = (ino64_t)FDROOTINO;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);
		} else if (off == FDSDSIZE) {		/* ".." */
			dirent->d_ino = (ino64_t)FDROOTINO;
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);
		} else {
			/*
			 * Return entries corresponding to the allowable
			 * number of file descriptors for this process.
			 */
			if ((n = (off-2*FDSDSIZE)/FDSDSIZE) >= nentries)
				break;
			dirent->d_ino = (ino64_t)fdtoi(n);
			numtos((ulong_t)n, dirent->d_name);
			reclen = DIRENT64_RECLEN(strlen(dirent->d_name));
		}
		dirent->d_off = (offset_t)(uiop->uio_offset + FDSDSIZE);
		dirent->d_reclen = (ushort_t)reclen;

		if (reclen > uiop->uio_resid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uiop->uio_resid == oresid)
				return (EINVAL);
			break;
		}
		/*
		 * uiomove() updates both resid and offset by the same
		 * amount.  But we want offset to change in increments
		 * of FDSDSIZE, which is different from the number of bytes
		 * being returned to the user.  So we set uio_offset
		 * separately, ignoring what uiomove() does.
		 */
		if (uiomove((caddr_t)dirent, reclen, UIO_READ, uiop))
			return (EFAULT);
		uiop->uio_offset = off + FDSDSIZE;
	}
	if (eofp)
		*eofp = ((uiop->uio_offset-2*FDSDSIZE)/FDSDSIZE >= nentries);
	return (0);
}

/* ARGSUSED */
static void
fdinactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);
	VN_RELE_LOCKED(vp);
	if (vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);
	vn_invalid(vp);
	vn_free(vp);
}

static struct vnodeops *fd_vnodeops;

static const fs_operation_def_t fd_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = fdopen },
	VOPNAME_CLOSE,		{ .vop_close = fdclose },
	VOPNAME_READ,		{ .vop_read = fdread },
	VOPNAME_GETATTR,	{ .vop_getattr = fdgetattr },
	VOPNAME_ACCESS,		{ .vop_access = fdaccess },
	VOPNAME_LOOKUP,		{ .vop_lookup = fdlookup },
	VOPNAME_CREATE,		{ .vop_create = fdcreate },
	VOPNAME_READDIR,	{ .vop_readdir = fdreaddir },
	VOPNAME_INACTIVE,	{ .vop_inactive = fdinactive },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_POLL,		{ .error = fs_error },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};

static int
fdget(struct vnode *dvp, char *comp, struct vnode **vpp)
{
	int n = 0;
	struct vnode *vp;

	while (*comp) {
		if (*comp < '0' || *comp > '9')
			return (ENOENT);
		n = 10 * n + *comp++ - '0';
	}
	vp = vn_alloc(KM_SLEEP);
	vp->v_type = VCHR;
	vp->v_vfsp = dvp->v_vfsp;
	vn_setops(vp, fd_vnodeops);
	vp->v_data = NULL;
	vp->v_flag = VNOMAP;
	vp->v_rdev = makedevice(fdrmaj, n);
	vn_exists(vp);
	*vpp = vp;
	return (0);
}

/*
 * fdfs is mounted on /dev/fd, however, there are two interesting
 * possibilities - two threads racing to do the same mount (protected
 * by vfs locking), and two threads mounting fdfs in different places.
 */
/*ARGSUSED*/
static int
fdmount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	struct vnode *vp;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Having the resource be anything but "fd" doesn't make sense
	 */
	vfs_setresource(vfsp, "fd", 0);

	vp = vn_alloc(KM_SLEEP);
	vp->v_vfsp = vfsp;
	vn_setops(vp, fd_vnodeops);
	vp->v_type = VDIR;
	vp->v_data = NULL;
	vp->v_flag |= VROOT;
	vfsp->vfs_fstype = fdfstype;
	vfsp->vfs_data = (char *)vp;
	mutex_enter(&fd_minor_lock);
	do {
		fdfsmin = (fdfsmin + 1) & L_MAXMIN32;
		vfsp->vfs_dev = makedevice(fdfsmaj, fdfsmin);
	} while (vfs_devismounted(vfsp->vfs_dev));
	mutex_exit(&fd_minor_lock);
	vfs_make_fsid(&vfsp->vfs_fsid, vfsp->vfs_dev, fdfstype);
	vfsp->vfs_bsize = 1024;
	return (0);
}

/* ARGSUSED */
static int
fdunmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	vnode_t *rvp;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	rvp = (vnode_t *)vfsp->vfs_data;
	if (rvp->v_count > 1)
		return (EBUSY);

	VN_RELE(rvp);
	return (0);
}

/* ARGSUSED */
static int
fdroot(vfs_t *vfsp, vnode_t **vpp)
{
	vnode_t *vp = (vnode_t *)vfsp->vfs_data;

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

/*
 * No locking required because I held the root vnode before calling this
 * function so the vfs won't disappear on me.  To be more explicit:
 * fdvrootp->v_count will be greater than 1 so fdunmount will just return.
 */
static int
fdstatvfs(struct vfs *vfsp, struct statvfs64 *sp)
{
	dev32_t d32;
	rctl_qty_t fdno_ctl;

	mutex_enter(&curproc->p_lock);
	fdno_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_NOFILE],
	    curproc->p_rctls, curproc);
	mutex_exit(&curproc->p_lock);

	bzero(sp, sizeof (*sp));
	sp->f_bsize = 1024;
	sp->f_frsize = 1024;
	sp->f_blocks = (fsblkcnt64_t)0;
	sp->f_bfree = (fsblkcnt64_t)0;
	sp->f_bavail = (fsblkcnt64_t)0;
	sp->f_files = (fsfilcnt64_t)
	    (MIN(P_FINFO(curproc)->fi_nfiles, fdno_ctl + 2));
	sp->f_ffree = (fsfilcnt64_t)0;
	sp->f_favail = (fsfilcnt64_t)0;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strcpy(sp->f_basetype, vfssw[fdfstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = FDNSIZE;
	(void) strcpy(sp->f_fstr, "/dev/fd");
	(void) strcpy(&sp->f_fstr[8], "/dev/fd");
	return (0);
}

int
fdinit(int fstype, char *name)
{
	static const fs_operation_def_t fd_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = fdmount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = fdunmount },
		VFSNAME_ROOT, 		{ .vfs_root = fdroot },
		VFSNAME_STATVFS,	{ .vfs_statvfs = fdstatvfs },
		NULL,			NULL
	};
	int error;

	fdfstype = fstype;
	ASSERT(fdfstype != 0);

	/*
	 * Associate VFS ops vector with this fstype.
	 */
	error = vfs_setfsops(fstype, fd_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "fdinit: bad vnode ops template");
		return (error);
	}

	error = vn_make_ops(name, fd_vnodeops_template, &fd_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "fdinit: bad vnode ops template");
		return (error);
	}

	/*
	 * Assign unique "device" numbers (reported by stat(2)).
	 */
	fdfsmaj = getudev();
	fdrmaj = getudev();
	if (fdfsmaj == (major_t)-1 || fdrmaj == (major_t)-1) {
		cmn_err(CE_WARN, "fdinit: can't get unique device numbers");
		if (fdfsmaj == (major_t)-1)
			fdfsmaj = 0;
		if (fdrmaj == (major_t)-1)
			fdrmaj = 0;
	}
	mutex_init(&fd_minor_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*
 * FDFS Mount options table
 */
static char *rw_cancel[] = { MNTOPT_RO, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name		cancel option	default arg	flags
 */
	{ MNTOPT_RW,		rw_cancel,	NULL,		MO_DEFAULT,
		(void *)MNTOPT_NOINTR },
	{ MNTOPT_IGNORE,	NULL,		NULL,		0,
		(void *)0 },
};

static mntopts_t fdfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"fd",
	fdinit,
	VSW_HASPROTO | VSW_ZMOUNT,
	&fdfs_mntopts
};

static struct modlfs modlfs = {
	&mod_fsops,
	"filesystem for fd",
	&vfw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlfs,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fbuf.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/policy.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/page.h>
#include <sys/swap.h>

#include <fs/fs_subr.h>

#include <sys/fs/udf_volume.h>
#include <sys/fs/udf_inode.h>

static int32_t udf_open(struct vnode **,
	int32_t, struct cred *, caller_context_t *);
static int32_t udf_close(struct vnode *,
	int32_t, int32_t, offset_t, struct cred *, caller_context_t *);
static int32_t udf_read(struct vnode *,
	struct uio *, int32_t, struct cred *, caller_context_t *);
static int32_t udf_write(struct vnode *,
	struct uio *, int32_t, struct cred *, caller_context_t *);
static int32_t udf_ioctl(struct vnode *,
	int32_t, intptr_t, int32_t, struct cred *, int32_t *,
	caller_context_t *);
static int32_t udf_getattr(struct vnode *,
	struct vattr *, int32_t, struct cred *, caller_context_t *);
static int32_t udf_setattr(struct vnode *,
	struct vattr *, int32_t, struct cred *, caller_context_t *);
static int32_t udf_access(struct vnode *,
	int32_t, int32_t, struct cred *, caller_context_t *);
static int32_t udf_lookup(struct vnode *,
	char *, struct vnode **, struct pathname *,
	int32_t, struct vnode *, struct cred *,
	caller_context_t *, int *, pathname_t *);
static int32_t udf_create(struct vnode *,
	char *, struct vattr *, enum vcexcl,
	int32_t, struct vnode **, struct cred *, int32_t,
	caller_context_t *, vsecattr_t *);
static int32_t udf_remove(struct vnode *,
	char *, struct cred *, caller_context_t *, int);
static int32_t udf_link(struct vnode *,
	struct vnode *, char *, struct cred *, caller_context_t *, int);
static int32_t udf_rename(struct vnode *,
	char *, struct vnode *, char *, struct cred *, caller_context_t *, int);
static int32_t udf_mkdir(struct vnode *,
	char *, struct vattr *, struct vnode **, struct cred *,
	caller_context_t *, int, vsecattr_t *);
static int32_t udf_rmdir(struct vnode *,
	char *, struct vnode *, struct cred *, caller_context_t *, int);
static int32_t udf_readdir(struct vnode *,
	struct uio *, struct cred *, int32_t *, caller_context_t *, int);
static int32_t udf_symlink(struct vnode *,
	char *, struct vattr *, char *, struct cred *, caller_context_t *, int);
static int32_t udf_readlink(struct vnode *,
	struct uio *, struct cred *, caller_context_t *);
static int32_t udf_fsync(struct vnode *,
	int32_t, struct cred *, caller_context_t *);
static void udf_inactive(struct vnode *,
	struct cred *, caller_context_t *);
static int32_t udf_fid(struct vnode *, struct fid *, caller_context_t *);
static int udf_rwlock(struct vnode *, int32_t, caller_context_t *);
static void udf_rwunlock(struct vnode *, int32_t, caller_context_t *);
static int32_t udf_seek(struct vnode *, offset_t, offset_t *,
	caller_context_t *);
static int32_t udf_frlock(struct vnode *, int32_t,
	struct flock64 *, int32_t, offset_t, struct flk_callback *, cred_t *,
	caller_context_t *);
static int32_t udf_space(struct vnode *, int32_t,
	struct flock64 *, int32_t, offset_t, cred_t *, caller_context_t *);
static int32_t udf_getpage(struct vnode *, offset_t,
	size_t, uint32_t *, struct page **, size_t,
	struct seg *, caddr_t, enum seg_rw, struct cred *, caller_context_t *);
static int32_t udf_putpage(struct vnode *, offset_t,
	size_t, int32_t, struct cred *, caller_context_t *);
static int32_t udf_map(struct vnode *, offset_t, struct as *,
	caddr_t *, size_t, uint8_t, uint8_t, uint32_t, struct cred *,
	caller_context_t *);
static int32_t udf_addmap(struct vnode *, offset_t, struct as *,
	caddr_t, size_t, uint8_t, uint8_t, uint32_t, struct cred *,
	caller_context_t *);
static int32_t udf_delmap(struct vnode *, offset_t, struct as *,
	caddr_t, size_t, uint32_t, uint32_t, uint32_t, struct cred *,
	caller_context_t *);
static int32_t udf_l_pathconf(struct vnode *, int32_t,
	ulong_t *, struct cred *, caller_context_t *);
static int32_t udf_pageio(struct vnode *, struct page *,
	u_offset_t, size_t, int32_t, struct cred *, caller_context_t *);

int32_t ud_getpage_miss(struct vnode *, u_offset_t,
	size_t, struct seg *, caddr_t, page_t *pl[],
	size_t, enum seg_rw, int32_t);
void ud_getpage_ra(struct vnode *, u_offset_t, struct seg *, caddr_t);
int32_t ud_putpages(struct vnode *, offset_t, size_t, int32_t, struct cred *);
int32_t ud_page_fill(struct ud_inode *, page_t *,
	u_offset_t, uint32_t, u_offset_t *);
int32_t ud_iodone(struct buf *);
int32_t ud_rdip(struct ud_inode *, struct uio *, int32_t, cred_t *);
int32_t ud_wrip(struct ud_inode *, struct uio *, int32_t, cred_t *);
int32_t ud_multi_strat(struct ud_inode *, page_t *, struct buf *, u_offset_t);
int32_t ud_slave_done(struct buf *);

/*
 * Structures to control multiple IO operations to get or put pages
 * that are backed by discontiguous blocks. The master struct is
 * a dummy that holds the original bp from pageio_setup. The
 * slave struct holds the working bp's to do the actual IO. Once
 * all the slave IOs complete. The master is processed as if a single
 * IO op has completed.
 */
uint32_t master_index = 0;
typedef struct mio_master {
	kmutex_t	mm_mutex;	/* protect the fields below */
	int32_t		mm_size;
	buf_t		*mm_bp;		/* original bp */
	int32_t		mm_resid;	/* bytes remaining to transfer */
	int32_t		mm_error;	/* accumulated error from slaves */
	int32_t		mm_index;	/* XXX debugging */
} mio_master_t;

typedef struct mio_slave {
	buf_t		ms_buf;		/* working buffer for this IO chunk */
	mio_master_t	*ms_ptr;	/* pointer to master */
} mio_slave_t;

struct vnodeops *udf_vnodeops;

const fs_operation_def_t udf_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = udf_open },
	VOPNAME_CLOSE,		{ .vop_close = udf_close },
	VOPNAME_READ,		{ .vop_read = udf_read },
	VOPNAME_WRITE,		{ .vop_write = udf_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = udf_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = udf_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = udf_setattr },
	VOPNAME_ACCESS,		{ .vop_access = udf_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = udf_lookup },
	VOPNAME_CREATE,		{ .vop_create = udf_create },
	VOPNAME_REMOVE,		{ .vop_remove = udf_remove },
	VOPNAME_LINK,		{ .vop_link = udf_link },
	VOPNAME_RENAME,		{ .vop_rename = udf_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = udf_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = udf_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = udf_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = udf_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = udf_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = udf_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = udf_inactive },
	VOPNAME_FID,		{ .vop_fid = udf_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = udf_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = udf_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = udf_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = udf_frlock },
	VOPNAME_SPACE,		{ .vop_space = udf_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = udf_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = udf_putpage },
	VOPNAME_MAP,		{ .vop_map = udf_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = udf_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = udf_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = udf_l_pathconf },
	VOPNAME_PAGEIO,		{ .vop_pageio = udf_pageio },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/* ARGSUSED */
static int32_t
udf_open(
	struct vnode **vpp,
	int32_t flag,
	struct cred *cr,
	caller_context_t *ct)
{
	ud_printf("udf_open\n");

	return (0);
}

/* ARGSUSED */
static int32_t
udf_close(
	struct vnode *vp,
	int32_t flag,
	int32_t count,
	offset_t offset,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_close\n");

	ITIMES(ip);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	/*
	 * Push partially filled cluster at last close.
	 * ``last close'' is approximated because the dnlc
	 * may have a hold on the vnode.
	 */
	if (vp->v_count <= 2 && vp->v_type != VBAD) {
		struct ud_inode *ip = VTOI(vp);
		if (ip->i_delaylen) {
			(void) ud_putpages(vp, ip->i_delayoff, ip->i_delaylen,
			    B_ASYNC | B_FREE, cr);
			ip->i_delaylen = 0;
		}
	}

	return (0);
}

/* ARGSUSED */
static int32_t
udf_read(
	struct vnode *vp,
	struct uio *uiop,
	int32_t ioflag,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);
	int32_t error;

	ud_printf("udf_read\n");

#ifdef	__lock_lint
	rw_enter(&ip->i_rwlock, RW_READER);
#endif

	ASSERT(RW_READ_HELD(&ip->i_rwlock));

	if (MANDLOCK(vp, ip->i_char)) {
		/*
		 * udf_getattr ends up being called by chklock
		 */
		error = chklock(vp, FREAD, uiop->uio_loffset,
		    uiop->uio_resid, uiop->uio_fmode, ct);
		if (error) {
			goto end;
		}
	}

	rw_enter(&ip->i_contents, RW_READER);
	error = ud_rdip(ip, uiop, ioflag, cr);
	rw_exit(&ip->i_contents);

end:
#ifdef	__lock_lint
	rw_exit(&ip->i_rwlock);
#endif

	return (error);
}


int32_t ud_WRITES = 1;
int32_t ud_HW = 96 * 1024;
int32_t ud_LW = 64 * 1024;
int32_t ud_throttles = 0;

/* ARGSUSED */
static int32_t
udf_write(
	struct vnode *vp,
	struct uio *uiop,
	int32_t ioflag,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);
	int32_t error = 0;

	ud_printf("udf_write\n");

#ifdef	__lock_lint
	rw_enter(&ip->i_rwlock, RW_WRITER);
#endif

	ASSERT(RW_WRITE_HELD(&ip->i_rwlock));

	if (MANDLOCK(vp, ip->i_char)) {
		/*
		 * ud_getattr ends up being called by chklock
		 */
		error = chklock(vp, FWRITE, uiop->uio_loffset,
		    uiop->uio_resid, uiop->uio_fmode, ct);
		if (error) {
			goto end;
		}
	}
	/*
	 * Throttle writes.
	 */
	mutex_enter(&ip->i_tlock);
	if (ud_WRITES && (ip->i_writes > ud_HW)) {
		while (ip->i_writes > ud_HW) {
			ud_throttles++;
			cv_wait(&ip->i_wrcv, &ip->i_tlock);
		}
	}
	mutex_exit(&ip->i_tlock);

	/*
	 * Write to the file
	 */
	rw_enter(&ip->i_contents, RW_WRITER);
	if ((ioflag & FAPPEND) != 0 && (ip->i_type == VREG)) {
		/*
		 * In append mode start at end of file.
		 */
		uiop->uio_loffset = ip->i_size;
	}
	error = ud_wrip(ip, uiop, ioflag, cr);
	rw_exit(&ip->i_contents);

end:
#ifdef	__lock_lint
	rw_exit(&ip->i_rwlock);
#endif

	return (error);
}

/* ARGSUSED */
static int32_t
udf_ioctl(
	struct vnode *vp,
	int32_t cmd,
	intptr_t arg,
	int32_t flag,
	struct cred *cr,
	int32_t *rvalp,
	caller_context_t *ct)
{
	return (ENOTTY);
}

/* ARGSUSED */
static int32_t
udf_getattr(
	struct vnode *vp,
	struct vattr *vap,
	int32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_getattr\n");

	if (vap->va_mask == AT_SIZE) {
		/*
		 * for performance, if only the size is requested don't bother
		 * with anything else.
		 */
		vap->va_size = ip->i_size;
		return (0);
	}

	rw_enter(&ip->i_contents, RW_READER);

	vap->va_type = vp->v_type;
	vap->va_mode = UD2VA_PERM(ip->i_perm) | ip->i_char;

	vap->va_uid = ip->i_uid;
	vap->va_gid = ip->i_gid;
	vap->va_fsid = ip->i_dev;
	vap->va_nodeid = ip->i_icb_lbano;
	vap->va_nlink = ip->i_nlink;
	vap->va_size = ip->i_size;
	vap->va_seq = ip->i_seq;
	if (vp->v_type == VCHR || vp->v_type == VBLK) {
		vap->va_rdev = ip->i_rdev;
	} else {
		vap->va_rdev = 0;
	}

	mutex_enter(&ip->i_tlock);
	ITIMES_NOLOCK(ip);	/* mark correct time in inode */
	vap->va_atime.tv_sec = (time_t)ip->i_atime.tv_sec;
	vap->va_atime.tv_nsec = ip->i_atime.tv_nsec;
	vap->va_mtime.tv_sec = (time_t)ip->i_mtime.tv_sec;
	vap->va_mtime.tv_nsec = ip->i_mtime.tv_nsec;
	vap->va_ctime.tv_sec = (time_t)ip->i_ctime.tv_sec;
	vap->va_ctime.tv_nsec = ip->i_ctime.tv_nsec;
	mutex_exit(&ip->i_tlock);

	switch (ip->i_type) {
		case VBLK:
			vap->va_blksize = MAXBSIZE;
			break;
		case VCHR:
			vap->va_blksize = MAXBSIZE;
			break;
		default:
			vap->va_blksize = ip->i_udf->udf_lbsize;
			break;
	}
	vap->va_nblocks = ip->i_lbr << ip->i_udf->udf_l2d_shift;

	rw_exit(&ip->i_contents);

	return (0);
}

static int
ud_iaccess_vmode(void *ip, int mode, struct cred *cr)
{
	return (ud_iaccess(ip, UD_UPERM2DPERM(mode), cr, 0));
}

/*ARGSUSED4*/
static int32_t
udf_setattr(
	struct vnode *vp,
	struct vattr *vap,
	int32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	int32_t error = 0;
	uint32_t mask = vap->va_mask;
	struct ud_inode *ip;
	timestruc_t now;
	struct vattr ovap;

	ud_printf("udf_setattr\n");

	ip = VTOI(vp);

	/*
	 * not updates allowed to 4096 files
	 */
	if (ip->i_astrat == STRAT_TYPE4096) {
		return (EINVAL);
	}

	/*
	 * Cannot set these attributes
	 */
	if (mask & AT_NOSET) {
		return (EINVAL);
	}

	rw_enter(&ip->i_rwlock, RW_WRITER);
	rw_enter(&ip->i_contents, RW_WRITER);

	ovap.va_uid = ip->i_uid;
	ovap.va_mode = UD2VA_PERM(ip->i_perm) | ip->i_char;
	error = secpolicy_vnode_setattr(cr, vp, vap, &ovap, flags,
	    ud_iaccess_vmode, ip);
	if (error)
		goto update_inode;

	mask = vap->va_mask;
	/*
	 * Change file access modes.
	 */
	if (mask & AT_MODE) {
		ip->i_perm = VA2UD_PERM(vap->va_mode);
		ip->i_char = vap->va_mode & (VSUID | VSGID | VSVTX);
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= ICHG;
		mutex_exit(&ip->i_tlock);
	}
	if (mask & (AT_UID|AT_GID)) {
		if (mask & AT_UID) {
			ip->i_uid = vap->va_uid;
		}
		if (mask & AT_GID) {
			ip->i_gid = vap->va_gid;
		}
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= ICHG;
		mutex_exit(&ip->i_tlock);
	}
	/*
	 * Truncate file.  Must have write permission and not be a directory.
	 */
	if (mask & AT_SIZE) {
		if (vp->v_type == VDIR) {
			error = EISDIR;
			goto update_inode;
		}
		if (error = ud_iaccess(ip, IWRITE, cr, 0)) {
			goto update_inode;
		}
		if (vap->va_size > MAXOFFSET_T) {
			error = EFBIG;
			goto update_inode;
		}
		if (error = ud_itrunc(ip, vap->va_size, 0, cr)) {
			goto update_inode;
		}

		if (vap->va_size == 0)
			vnevent_truncate(vp, ct);
	}
	/*
	 * Change file access or modified times.
	 */
	if (mask & (AT_ATIME|AT_MTIME)) {
		mutex_enter(&ip->i_tlock);
		if (mask & AT_ATIME) {
			ip->i_atime.tv_sec = vap->va_atime.tv_sec;
			ip->i_atime.tv_nsec = vap->va_atime.tv_nsec;
			ip->i_flag &= ~IACC;
		}
		if (mask & AT_MTIME) {
			ip->i_mtime.tv_sec = vap->va_mtime.tv_sec;
			ip->i_mtime.tv_nsec = vap->va_mtime.tv_nsec;
			gethrestime(&now);
			ip->i_ctime.tv_sec = now.tv_sec;
			ip->i_ctime.tv_nsec = now.tv_nsec;
			ip->i_flag &= ~(IUPD|ICHG);
			ip->i_flag |= IMODTIME;
		}
		ip->i_flag |= IMOD;
		mutex_exit(&ip->i_tlock);
	}

update_inode:
	if (curthread->t_flag & T_DONTPEND) {
		ud_iupdat(ip, 1);
	} else {
		ITIMES_NOLOCK(ip);
	}
	rw_exit(&ip->i_contents);
	rw_exit(&ip->i_rwlock);

	return (error);
}

/* ARGSUSED */
static int32_t
udf_access(
	struct vnode *vp,
	int32_t mode,
	int32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_access\n");

	if (ip->i_udf == NULL) {
		return (EIO);
	}

	return (ud_iaccess(ip, UD_UPERM2DPERM(mode), cr, 1));
}

int32_t udfs_stickyhack = 1;

/* ARGSUSED */
static int32_t
udf_lookup(
	struct vnode *dvp,
	char *nm,
	struct vnode **vpp,
	struct pathname *pnp,
	int32_t flags,
	struct vnode *rdir,
	struct cred *cr,
	caller_context_t *ct,
	int *direntflags,
	pathname_t *realpnp)
{
	int32_t error;
	struct vnode *vp;
	struct ud_inode *ip, *xip;

	ud_printf("udf_lookup\n");
	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		error = 0;
		goto out;
	}

	/*
	 * Fast path: Check the directory name lookup cache.
	 */
	ip = VTOI(dvp);
	if (vp = dnlc_lookup(dvp, nm)) {
		/*
		 * Check accessibility of directory.
		 */
		if ((error = ud_iaccess(ip, IEXEC, cr, 1)) != 0) {
			VN_RELE(vp);
		}
		xip = VTOI(vp);
	} else {
		error = ud_dirlook(ip, nm, &xip, cr, 1);
		ITIMES(ip);
	}

	if (error == 0) {
		ip = xip;
		*vpp = ITOV(ip);
		if ((ip->i_type != VDIR) &&
		    (ip->i_char & ISVTX) &&
		    ((ip->i_perm & IEXEC) == 0) &&
		    udfs_stickyhack) {
			mutex_enter(&(*vpp)->v_lock);
			(*vpp)->v_flag |= VISSWAP;
			mutex_exit(&(*vpp)->v_lock);
		}
		ITIMES(ip);
		/*
		 * If vnode is a device return special vnode instead.
		 */
		if (IS_DEVVP(*vpp)) {
			struct vnode *newvp;
			newvp = specvp(*vpp, (*vpp)->v_rdev,
			    (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (newvp == NULL) {
				error = ENOSYS;
			} else {
				*vpp = newvp;
			}
		}
	}
out:
	return (error);
}

/* ARGSUSED */
static int32_t
udf_create(
	struct vnode *dvp,
	char *name,
	struct vattr *vap,
	enum vcexcl excl,
	int32_t mode,
	struct vnode **vpp,
	struct cred *cr,
	int32_t flag,
	caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int32_t error;
	struct ud_inode *ip = VTOI(dvp), *xip;

	ud_printf("udf_create\n");

	if ((vap->va_mode & VSVTX) && secpolicy_vnode_stky_modify(cr) != 0)
		vap->va_mode &= ~VSVTX;

	if (*name == '\0') {
		/*
		 * Null component name refers to the directory itself.
		 */
		VN_HOLD(dvp);
		ITIMES(ip);
		error = EEXIST;
	} else {
		xip = NULL;
		rw_enter(&ip->i_rwlock, RW_WRITER);
		error = ud_direnter(ip, name, DE_CREATE,
		    (struct ud_inode *)0, (struct ud_inode *)0,
		    vap, &xip, cr, ct);
		rw_exit(&ip->i_rwlock);
		ITIMES(ip);
		ip = xip;
	}
#ifdef	__lock_lint
	rw_enter(&ip->i_contents, RW_WRITER);
#else
	if (ip != NULL) {
		rw_enter(&ip->i_contents, RW_WRITER);
	}
#endif

	/*
	 * If the file already exists and this is a non-exclusive create,
	 * check permissions and allow access for non-directories.
	 * Read-only create of an existing directory is also allowed.
	 * We fail an exclusive create of anything which already exists.
	 */
	if (error == EEXIST) {
		if (excl == NONEXCL) {
			if ((ip->i_type == VDIR) && (mode & VWRITE)) {
				error = EISDIR;
			} else if (mode) {
				error = ud_iaccess(ip,
				    UD_UPERM2DPERM(mode), cr, 0);
			} else {
				error = 0;
			}
		}
		if (error) {
			rw_exit(&ip->i_contents);
			VN_RELE(ITOV(ip));
			goto out;
		} else if ((ip->i_type == VREG) &&
		    (vap->va_mask & AT_SIZE) && vap->va_size == 0) {
			/*
			 * Truncate regular files, if requested by caller.
			 * Grab i_rwlock to make sure no one else is
			 * currently writing to the file (we promised
			 * bmap we would do this).
			 * Must get the locks in the correct order.
			 */
			if (ip->i_size == 0) {
				ip->i_flag |= ICHG | IUPD;
			} else {
				rw_exit(&ip->i_contents);
				rw_enter(&ip->i_rwlock, RW_WRITER);
				rw_enter(&ip->i_contents, RW_WRITER);
				(void) ud_itrunc(ip, 0, 0, cr);
				rw_exit(&ip->i_rwlock);
			}
			vnevent_create(ITOV(ip), ct);
		}
	}

	if (error == 0) {
		*vpp = ITOV(ip);
		ITIMES(ip);
	}
#ifdef	__lock_lint
	rw_exit(&ip->i_contents);
#else
	if (ip != NULL) {
		rw_exit(&ip->i_contents);
	}
#endif
	if (error) {
		goto out;
	}

	/*
	 * If vnode is a device return special vnode instead.
	 */
	if (!error && IS_DEVVP(*vpp)) {
		struct vnode *newvp;

		newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
		VN_RELE(*vpp);
		if (newvp == NULL) {
			error = ENOSYS;
			goto out;
		}
		*vpp = newvp;
	}
out:
	return (error);
}

/* ARGSUSED */
static int32_t
udf_remove(
	struct vnode *vp,
	char *nm,
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	int32_t error;
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_remove\n");

	rw_enter(&ip->i_rwlock, RW_WRITER);
	error = ud_dirremove(ip, nm,
	    (struct ud_inode *)0, (struct vnode *)0, DR_REMOVE, cr, ct);
	rw_exit(&ip->i_rwlock);
	ITIMES(ip);

	return (error);
}

/* ARGSUSED */
static int32_t
udf_link(
	struct vnode *tdvp,
	struct vnode *svp,
	char *tnm,
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	int32_t error;
	struct vnode *realvp;
	struct ud_inode *sip;
	struct ud_inode *tdp;

	ud_printf("udf_link\n");
	if (VOP_REALVP(svp, &realvp, ct) == 0) {
		svp = realvp;
	}

	/*
	 * Do not allow links to directories
	 */
	if (svp->v_type == VDIR) {
		return (EPERM);
	}

	sip = VTOI(svp);

	if (sip->i_uid != crgetuid(cr) && secpolicy_basic_link(cr) != 0)
		return (EPERM);

	tdp = VTOI(tdvp);

	rw_enter(&tdp->i_rwlock, RW_WRITER);
	error = ud_direnter(tdp, tnm, DE_LINK, (struct ud_inode *)0,
	    sip, (struct vattr *)0, (struct ud_inode **)0, cr, ct);
	rw_exit(&tdp->i_rwlock);
	ITIMES(sip);
	ITIMES(tdp);

	if (error == 0) {
		vnevent_link(svp, ct);
	}

	return (error);
}

/* ARGSUSED */
static int32_t
udf_rename(
	struct vnode *sdvp,
	char *snm,
	struct vnode *tdvp,
	char *tnm,
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	int32_t error = 0;
	struct udf_vfs *udf_vfsp;
	struct ud_inode *sip;		/* source inode */
	struct ud_inode *tip;		/* target inode */
	struct ud_inode *sdp, *tdp;	/* source and target parent inode */
	struct vnode *realvp;

	ud_printf("udf_rename\n");

	if (VOP_REALVP(tdvp, &realvp, ct) == 0) {
		tdvp = realvp;
	}

	sdp = VTOI(sdvp);
	tdp = VTOI(tdvp);

	udf_vfsp = sdp->i_udf;

	mutex_enter(&udf_vfsp->udf_rename_lck);
	/*
	 * Look up inode of file we're supposed to rename.
	 */
	if (error = ud_dirlook(sdp, snm, &sip, cr, 0)) {
		mutex_exit(&udf_vfsp->udf_rename_lck);
		return (error);
	}
	/*
	 * be sure this is not a directory with another file system mounted
	 * over it.  If it is just give up the locks, and return with
	 * EBUSY
	 */
	if (vn_mountedvfs(ITOV(sip)) != NULL) {
		error = EBUSY;
		goto errout;
	}
	/*
	 * Make sure we can delete the source entry.  This requires
	 * write permission on the containing directory.  If that
	 * directory is "sticky" it further requires (except for
	 * privileged users) that the user own the directory or the
	 * source entry, or else have permission to write the source
	 * entry.
	 */
	rw_enter(&sdp->i_contents, RW_READER);
	rw_enter(&sip->i_contents, RW_READER);
	if ((error = ud_iaccess(sdp, IWRITE, cr, 0)) != 0 ||
	    (error = ud_sticky_remove_access(sdp, sip, cr)) != 0) {
		rw_exit(&sip->i_contents);
		rw_exit(&sdp->i_contents);
		ITIMES(sip);
		goto errout;
	}

	/*
	 * Check for renaming '.' or '..' or alias of '.'
	 */
	if ((strcmp(snm, ".") == 0) ||
	    (strcmp(snm, "..") == 0) ||
	    (sdp == sip)) {
		error = EINVAL;
		rw_exit(&sip->i_contents);
		rw_exit(&sdp->i_contents);
		goto errout;
	}

	rw_exit(&sip->i_contents);
	rw_exit(&sdp->i_contents);

	if (ud_dirlook(tdp, tnm, &tip, cr, 0) == 0) {
		vnevent_pre_rename_dest(ITOV(tip), tdvp, tnm, ct);
		VN_RELE(ITOV(tip));
	}

	/* Notify the target dir. if not the same as the source dir. */
	if (sdvp != tdvp)
		vnevent_pre_rename_dest_dir(tdvp, ITOV(sip), tnm, ct);

	vnevent_pre_rename_src(ITOV(sip), sdvp, snm, ct);

	/*
	 * Link source to the target.
	 */
	rw_enter(&tdp->i_rwlock, RW_WRITER);
	if (error = ud_direnter(tdp, tnm, DE_RENAME, sdp, sip,
	    (struct vattr *)0, (struct ud_inode **)0, cr, ct)) {
		/*
		 * ESAME isn't really an error; it indicates that the
		 * operation should not be done because the source and target
		 * are the same file, but that no error should be reported.
		 */
		if (error == ESAME) {
			error = 0;
		}
		rw_exit(&tdp->i_rwlock);
		goto errout;
	}
	rw_exit(&tdp->i_rwlock);

	rw_enter(&sdp->i_rwlock, RW_WRITER);
	/*
	 * Unlink the source.
	 * Remove the source entry.  ud_dirremove() checks that the entry
	 * still reflects sip, and returns an error if it doesn't.
	 * If the entry has changed just forget about it.  Release
	 * the source inode.
	 */
	if ((error = ud_dirremove(sdp, snm, sip, (struct vnode *)0,
	    DR_RENAME, cr, ct)) == ENOENT) {
		error = 0;
	}
	rw_exit(&sdp->i_rwlock);

	if (error == 0) {
		vnevent_rename_src(ITOV(sip), sdvp, snm, ct);
		/*
		 * vnevent_rename_dest and vnevent_rename_dest_dir are called
		 * in ud_direnter().
		 */
	}

errout:
	ITIMES(sdp);
	ITIMES(tdp);
	VN_RELE(ITOV(sip));
	mutex_exit(&udf_vfsp->udf_rename_lck);

	return (error);
}

/* ARGSUSED */
static int32_t
udf_mkdir(
	struct vnode *dvp,
	char *dirname,
	struct vattr *vap,
	struct vnode **vpp,
	struct cred *cr,
	caller_context_t *ct,
	int flags,
	vsecattr_t *vsecp)
{
	int32_t error;
	struct ud_inode *ip;
	struct ud_inode *xip;

	ASSERT((vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));

	ud_printf("udf_mkdir\n");

	ip = VTOI(dvp);
	rw_enter(&ip->i_rwlock, RW_WRITER);
	error = ud_direnter(ip, dirname, DE_MKDIR,
	    (struct ud_inode *)0, (struct ud_inode *)0, vap, &xip, cr, ct);
	rw_exit(&ip->i_rwlock);
	ITIMES(ip);
	if (error == 0) {
		ip = xip;
		*vpp = ITOV(ip);
		ITIMES(ip);
	} else if (error == EEXIST) {
		ITIMES(xip);
		VN_RELE(ITOV(xip));
	}

	return (error);
}

/* ARGSUSED */
static int32_t
udf_rmdir(
	struct vnode *vp,
	char *nm,
	struct vnode *cdir,
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	int32_t error;
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_rmdir\n");

	rw_enter(&ip->i_rwlock, RW_WRITER);
	error = ud_dirremove(ip, nm, (struct ud_inode *)0, cdir, DR_RMDIR,
	    cr, ct);
	rw_exit(&ip->i_rwlock);
	ITIMES(ip);

	return (error);
}

/* ARGSUSED */
static int32_t
udf_readdir(
	struct vnode *vp,
	struct uio *uiop,
	struct cred *cr,
	int32_t *eofp,
	caller_context_t *ct,
	int flags)
{
	struct ud_inode *ip;
	struct dirent64 *nd;
	struct udf_vfs *udf_vfsp;
	int32_t error = 0, len, outcount = 0;
	uint32_t dirsiz, offset;
	uint32_t bufsize, ndlen, dummy;
	caddr_t outbuf;
	caddr_t outb, end_outb;
	struct iovec *iovp;

	uint8_t *dname;
	int32_t length;

	uint8_t *buf = NULL;

	struct fbuf *fbp = NULL;
	struct file_id *fid;
	uint8_t *name;


	ud_printf("udf_readdir\n");

	ip = VTOI(vp);
	udf_vfsp = ip->i_udf;

	dirsiz = ip->i_size;
	if ((uiop->uio_offset >= dirsiz) ||
	    (ip->i_nlink <= 0)) {
		if (eofp) {
			*eofp = 1;
		}
		return (0);
	}

	offset = uiop->uio_offset;
	iovp = uiop->uio_iov;
	bufsize = iovp->iov_len;

	outb = outbuf = (char *)kmem_alloc((uint32_t)bufsize, KM_SLEEP);
	end_outb = outb + bufsize;
	nd = (struct dirent64 *)outbuf;

	dname = (uint8_t *)kmem_zalloc(1024, KM_SLEEP);
	buf = (uint8_t *)kmem_zalloc(udf_vfsp->udf_lbsize, KM_SLEEP);

	if (offset == 0) {
		len = DIRENT64_RECLEN(1);
		if (((caddr_t)nd + len) >= end_outb) {
			error = EINVAL;
			goto end;
		}
		nd->d_ino = ip->i_icb_lbano;
		nd->d_reclen = (uint16_t)len;
		nd->d_off = 0x10;
		nd->d_name[0] = '.';
		bzero(&nd->d_name[1], DIRENT64_NAMELEN(len) - 1);
		nd = (struct dirent64 *)((char *)nd + nd->d_reclen);
		outcount++;
	} else if (offset == 0x10) {
		offset = 0;
	}

	while (offset < dirsiz) {
		error = ud_get_next_fid(ip, &fbp,
		    offset, &fid, &name, buf);
		if (error != 0) {
			break;
		}

		if ((fid->fid_flags & FID_DELETED) == 0) {
			if (fid->fid_flags & FID_PARENT) {

				len = DIRENT64_RECLEN(2);
				if (((caddr_t)nd + len) >= end_outb) {
					error = EINVAL;
					break;
				}

				nd->d_ino = ip->i_icb_lbano;
				nd->d_reclen = (uint16_t)len;
				nd->d_off = offset + FID_LEN(fid);
				nd->d_name[0] = '.';
				nd->d_name[1] = '.';
				bzero(&nd->d_name[2],
				    DIRENT64_NAMELEN(len) - 2);
				nd = (struct dirent64 *)
				    ((char *)nd + nd->d_reclen);
			} else {
				if ((error = ud_uncompress(fid->fid_idlen,
				    &length, name, dname)) != 0) {
					break;
				}
				if (length == 0) {
					offset += FID_LEN(fid);
					continue;
				}
				len = DIRENT64_RECLEN(length);
				if (((caddr_t)nd + len) >= end_outb) {
					if (!outcount) {
						error = EINVAL;
					}
					break;
				}
				(void) strncpy(nd->d_name,
				    (caddr_t)dname, length);
				bzero(&nd->d_name[length],
				    DIRENT64_NAMELEN(len) - length);
				nd->d_ino = ud_xlate_to_daddr(udf_vfsp,
				    SWAP_16(fid->fid_icb.lad_ext_prn),
				    SWAP_32(fid->fid_icb.lad_ext_loc), 1,
				    &dummy);
				nd->d_reclen = (uint16_t)len;
				nd->d_off = offset + FID_LEN(fid);
				nd = (struct dirent64 *)
				    ((char *)nd + nd->d_reclen);
			}
			outcount++;
		}

		offset += FID_LEN(fid);
	}

end:
	if (fbp != NULL) {
		fbrelse(fbp, S_OTHER);
	}
	ndlen = ((char *)nd - outbuf);
	/*
	 * In case of error do not call uiomove.
	 * Return the error to the caller.
	 */
	if ((error == 0) && (ndlen != 0)) {
		error = uiomove(outbuf, (long)ndlen, UIO_READ, uiop);
		uiop->uio_offset = offset;
	}
	kmem_free((caddr_t)buf, udf_vfsp->udf_lbsize);
	kmem_free((caddr_t)dname, 1024);
	kmem_free(outbuf, (uint32_t)bufsize);
	if (eofp && error == 0) {
		*eofp = (uiop->uio_offset >= dirsiz);
	}
	return (error);
}

/* ARGSUSED */
static int32_t
udf_symlink(
	struct vnode *dvp,
	char *linkname,
	struct vattr *vap,
	char *target,
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	int32_t error = 0, outlen;
	uint32_t ioflag = 0;
	struct ud_inode *ip, *dip = VTOI(dvp);

	struct path_comp *pc;
	int8_t *dname = NULL, *uname = NULL, *sp;

	ud_printf("udf_symlink\n");

	ip = (struct ud_inode *)0;
	vap->va_type = VLNK;
	vap->va_rdev = 0;

	rw_enter(&dip->i_rwlock, RW_WRITER);
	error = ud_direnter(dip, linkname, DE_CREATE,
	    (struct ud_inode *)0, (struct ud_inode *)0, vap, &ip, cr, ct);
	rw_exit(&dip->i_rwlock);
	if (error == 0) {
		dname = kmem_zalloc(1024, KM_SLEEP);
		uname = kmem_zalloc(PAGESIZE, KM_SLEEP);

		pc = (struct path_comp *)uname;
		/*
		 * If the first character in target is "/"
		 * then skip it and create entry for it
		 */
		if (*target == '/') {
			pc->pc_type = 2;
			pc->pc_len = 0;
			pc = (struct path_comp *)(((char *)pc) + 4);
			while (*target == '/') {
				target++;
			}
		}

		while (*target != NULL) {
			sp = target;
			while ((*target != '/') && (*target != '\0')) {
				target ++;
			}
			/*
			 * We got the next component of the
			 * path name. Create path_comp of
			 * appropriate type
			 */
			if (((target - sp) == 1) && (*sp == '.')) {
				/*
				 * Dot entry.
				 */
				pc->pc_type = 4;
				pc = (struct path_comp *)(((char *)pc) + 4);
			} else if (((target - sp) == 2) &&
			    (*sp == '.') && ((*(sp + 1)) == '.')) {
				/*
				 * DotDot entry.
				 */
				pc->pc_type = 3;
				pc = (struct path_comp *)(((char *)pc) + 4);
			} else {
				/*
				 * convert the user given name
				 * into appropriate form to be put
				 * on the media
				 */
				outlen = 1024;	/* set to size of dname */
				if (error = ud_compress(target - sp, &outlen,
				    (uint8_t *)sp, (uint8_t *)dname)) {
					break;
				}
				pc->pc_type = 5;
				/* LINTED */
				pc->pc_len = outlen;
				dname[outlen] = '\0';
				(void) strcpy((char *)pc->pc_id, dname);
				pc = (struct path_comp *)
				    (((char *)pc) + 4 + outlen);
			}
			while (*target == '/') {
				target++;
			}
			if (*target == NULL) {
				break;
			}
		}

		rw_enter(&ip->i_contents, RW_WRITER);
		if (error == 0) {
			ioflag = FWRITE;
			if (curthread->t_flag & T_DONTPEND) {
				ioflag |= FDSYNC;
			}
			error = ud_rdwri(UIO_WRITE, ioflag, ip,
			    uname, ((int8_t *)pc) - uname,
			    (offset_t)0, UIO_SYSSPACE, (int32_t *)0, cr);
		}
		if (error) {
			ud_idrop(ip);
			rw_exit(&ip->i_contents);
			rw_enter(&dip->i_rwlock, RW_WRITER);
			(void) ud_dirremove(dip, linkname, (struct ud_inode *)0,
			    (struct vnode *)0, DR_REMOVE, cr, ct);
			rw_exit(&dip->i_rwlock);
			goto update_inode;
		}
		rw_exit(&ip->i_contents);
	}

	if ((error == 0) || (error == EEXIST)) {
		VN_RELE(ITOV(ip));
	}

update_inode:
	ITIMES(VTOI(dvp));
	if (uname != NULL) {
		kmem_free(uname, PAGESIZE);
	}
	if (dname != NULL) {
		kmem_free(dname, 1024);
	}

	return (error);
}

/* ARGSUSED */
static int32_t
udf_readlink(
	struct vnode *vp,
	struct uio *uiop,
	struct cred *cr,
	caller_context_t *ct)
{
	int32_t error = 0, off, id_len, size, len;
	int8_t *dname = NULL, *uname = NULL;
	struct ud_inode *ip;
	struct fbuf *fbp = NULL;
	struct path_comp *pc;

	ud_printf("udf_readlink\n");

	if (vp->v_type != VLNK) {
		return (EINVAL);
	}

	ip = VTOI(vp);
	size = ip->i_size;
	if (size > PAGESIZE) {
		return (EIO);
	}

	if (size == 0) {
		return (0);
	}

	dname = kmem_zalloc(1024, KM_SLEEP);
	uname = kmem_zalloc(PAGESIZE, KM_SLEEP);

	rw_enter(&ip->i_contents, RW_READER);

	if ((error = fbread(vp, 0, size, S_READ, &fbp)) != 0) {
		goto end;
	}

	off = 0;

	while (off < size) {
		pc = (struct path_comp *)(fbp->fb_addr + off);
		switch (pc->pc_type) {
			case 1 :
				(void) strcpy(uname, ip->i_udf->udf_fsmnt);
				(void) strcat(uname, "/");
				break;
			case 2 :
				if (pc->pc_len != 0) {
					goto end;
				}
				uname[0] = '/';
				uname[1] = '\0';
				break;
			case 3 :
				(void) strcat(uname, "../");
				break;
			case 4 :
				(void) strcat(uname, "./");
				break;
			case 5 :
				if ((error = ud_uncompress(pc->pc_len, &id_len,
				    pc->pc_id, (uint8_t *)dname)) != 0) {
					break;
				}
				dname[id_len] = '\0';
				(void) strcat(uname, dname);
				(void) strcat(uname, "/");
				break;
			default :
				error = EINVAL;
				goto end;
		}
		off += 4 + pc->pc_len;
	}
	len = strlen(uname) - 1;
	if (uname[len] == '/') {
		if (len == 0) {
			/*
			 * special case link to /
			 */
			len = 1;
		} else {
			uname[len] = '\0';
		}
	}

	error = uiomove(uname, len, UIO_READ, uiop);

	ITIMES(ip);

end:
	if (fbp != NULL) {
		fbrelse(fbp, S_OTHER);
	}
	rw_exit(&ip->i_contents);
	if (uname != NULL) {
		kmem_free(uname, PAGESIZE);
	}
	if (dname != NULL) {
		kmem_free(dname, 1024);
	}
	return (error);
}

/* ARGSUSED */
static int32_t
udf_fsync(
	struct vnode *vp,
	int32_t syncflag,
	struct cred *cr,
	caller_context_t *ct)
{
	int32_t error = 0;
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_fsync\n");

	rw_enter(&ip->i_contents, RW_WRITER);
	if (!(IS_SWAPVP(vp))) {
		error = ud_syncip(ip, 0, I_SYNC); /* Do synchronous writes */
	}
	if (error == 0) {
		error = ud_sync_indir(ip);
	}
	ITIMES(ip);		/* XXX: is this necessary ??? */
	rw_exit(&ip->i_contents);

	return (error);
}

/* ARGSUSED */
static void
udf_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	ud_printf("udf_iinactive\n");

	ud_iinactive(VTOI(vp), cr);
}

/* ARGSUSED */
static int32_t
udf_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct udf_fid *udfidp;
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_fid\n");

	if (fidp->fid_len < (sizeof (struct udf_fid) - sizeof (uint16_t))) {
		fidp->fid_len = sizeof (struct udf_fid) - sizeof (uint16_t);
		return (ENOSPC);
	}

	udfidp = (struct udf_fid *)fidp;
	bzero((char *)udfidp, sizeof (struct udf_fid));
	rw_enter(&ip->i_contents, RW_READER);
	udfidp->udfid_len = sizeof (struct udf_fid) - sizeof (uint16_t);
	udfidp->udfid_uinq_lo = ip->i_uniqid & 0xffffffff;
	udfidp->udfid_prn = ip->i_icb_prn;
	udfidp->udfid_icb_lbn = ip->i_icb_block;
	rw_exit(&ip->i_contents);

	return (0);
}

/* ARGSUSED2 */
static int
udf_rwlock(struct vnode *vp, int32_t write_lock, caller_context_t *ctp)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_rwlock\n");

	if (write_lock) {
		rw_enter(&ip->i_rwlock, RW_WRITER);
	} else {
		rw_enter(&ip->i_rwlock, RW_READER);
	}
#ifdef	__lock_lint
	rw_exit(&ip->i_rwlock);
#endif
	return (write_lock);
}

/* ARGSUSED */
static void
udf_rwunlock(struct vnode *vp, int32_t write_lock, caller_context_t *ctp)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_rwunlock\n");

#ifdef	__lock_lint
	rw_enter(&ip->i_rwlock, RW_WRITER);
#endif

	rw_exit(&ip->i_rwlock);

}

/* ARGSUSED */
static int32_t
udf_seek(struct vnode *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

static int32_t
udf_frlock(
	struct vnode *vp,
	int32_t cmd,
	struct flock64 *bfp,
	int32_t flag,
	offset_t offset,
	struct flk_callback *flk_cbp,
	cred_t *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_frlock\n");

	/*
	 * If file is being mapped, disallow frlock.
	 * XXX I am not holding tlock while checking i_mapcnt because the
	 * current locking strategy drops all locks before calling fs_frlock.
	 * So, mapcnt could change before we enter fs_frlock making is
	 * meaningless to have held tlock in the first place.
	 */
	if ((ip->i_mapcnt > 0) &&
	    (MANDLOCK(vp, ip->i_char))) {
		return (EAGAIN);
	}

	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

/*ARGSUSED6*/
static int32_t
udf_space(
	struct vnode *vp,
	int32_t cmd,
	struct flock64 *bfp,
	int32_t flag,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	int32_t error = 0;

	ud_printf("udf_space\n");

	if (cmd != F_FREESP) {
		error =  EINVAL;
	} else if ((error = convoff(vp, bfp, 0, offset)) == 0) {
		error = ud_freesp(vp, bfp, flag, cr);

		if (error == 0 && bfp->l_start == 0)
			vnevent_truncate(vp, ct);
	}

	return (error);
}

/* ARGSUSED */
static int32_t
udf_getpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	uint32_t *protp,
	struct page **plarr,
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);
	int32_t error, has_holes, beyond_eof, seqmode, dolock;
	int32_t pgsize = PAGESIZE;
	struct udf_vfs *udf_vfsp = ip->i_udf;
	page_t **pl;
	u_offset_t pgoff, eoff, uoff;
	krw_t rwtype;
	caddr_t pgaddr;

	ud_printf("udf_getpage\n");

	uoff = (u_offset_t)off; /* type conversion */
	if (protp) {
		*protp = PROT_ALL;
	}
	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}
	seqmode = ip->i_nextr == uoff && rw != S_CREATE;

	rwtype = RW_READER;
	dolock = (rw_owner(&ip->i_contents) != curthread);
retrylock:
#ifdef	__lock_lint
	rw_enter(&ip->i_contents, rwtype);
#else
	if (dolock) {
		rw_enter(&ip->i_contents, rwtype);
	}
#endif

	/*
	 * We may be getting called as a side effect of a bmap using
	 * fbread() when the blocks might be being allocated and the
	 * size has not yet been up'ed.  In this case we want to be
	 * able to return zero pages if we get back UDF_HOLE from
	 * calling bmap for a non write case here.  We also might have
	 * to read some frags from the disk into a page if we are
	 * extending the number of frags for a given lbn in bmap().
	 */
	beyond_eof = uoff + len > ip->i_size + PAGEOFFSET;
	if (beyond_eof && seg != segkmap) {
#ifdef	__lock_lint
		rw_exit(&ip->i_contents);
#else
		if (dolock) {
			rw_exit(&ip->i_contents);
		}
#endif
		return (EFAULT);
	}

	/*
	 * Must hold i_contents lock throughout the call to pvn_getpages
	 * since locked pages are returned from each call to ud_getapage.
	 * Must *not* return locked pages and then try for contents lock
	 * due to lock ordering requirements (inode > page)
	 */

	has_holes = ud_bmap_has_holes(ip);

	if ((rw == S_WRITE || rw == S_CREATE) && (has_holes || beyond_eof)) {
		int32_t	blk_size, count;
		u_offset_t offset;

		/*
		 * We must acquire the RW_WRITER lock in order to
		 * call bmap_write().
		 */
		if (dolock && rwtype == RW_READER) {
			rwtype = RW_WRITER;

			if (!rw_tryupgrade(&ip->i_contents)) {

				rw_exit(&ip->i_contents);

				goto retrylock;
			}
		}

		/*
		 * May be allocating disk blocks for holes here as
		 * a result of mmap faults. write(2) does the bmap_write
		 * in rdip/wrip, not here. We are not dealing with frags
		 * in this case.
		 */
		offset = uoff;
		while ((offset < uoff + len) &&
		    (offset < ip->i_size)) {
			/*
			 * the variable "bnp" is to simplify the expression for
			 * the compiler; * just passing in &bn to bmap_write
			 * causes a compiler "loop"
			 */

			blk_size = udf_vfsp->udf_lbsize;
			if ((offset + blk_size) > ip->i_size) {
				count = ip->i_size - offset;
			} else {
				count = blk_size;
			}
			error = ud_bmap_write(ip, offset, count, 0, cr);
			if (error) {
				goto update_inode;
			}
			offset += count; /* XXX - make this contig */
		}
	}

	/*
	 * Can be a reader from now on.
	 */
#ifdef	__lock_lint
	if (rwtype == RW_WRITER) {
		rw_downgrade(&ip->i_contents);
	}
#else
	if (dolock && rwtype == RW_WRITER) {
		rw_downgrade(&ip->i_contents);
	}
#endif

	/*
	 * We remove PROT_WRITE in cases when the file has UDF holes
	 * because we don't  want to call bmap_read() to check each
	 * page if it is backed with a disk block.
	 */
	if (protp && has_holes && rw != S_WRITE && rw != S_CREATE) {
		*protp &= ~PROT_WRITE;
	}

	error = 0;

	/*
	 * The loop looks up pages in the range <off, off + len).
	 * For each page, we first check if we should initiate an asynchronous
	 * read ahead before we call page_lookup (we may sleep in page_lookup
	 * for a previously initiated disk read).
	 */
	eoff = (uoff + len);
	for (pgoff = uoff, pgaddr = addr, pl = plarr;
	    pgoff < eoff; /* empty */) {
		page_t	*pp;
		u_offset_t	nextrio;
		se_t	se;

		se = ((rw == S_CREATE) ? SE_EXCL : SE_SHARED);

		/*
		 * Handle async getpage (faultahead)
		 */
		if (plarr == NULL) {
			ip->i_nextrio = pgoff;
			ud_getpage_ra(vp, pgoff, seg, pgaddr);
			pgoff += pgsize;
			pgaddr += pgsize;
			continue;
		}

		/*
		 * Check if we should initiate read ahead of next cluster.
		 * We call page_exists only when we need to confirm that
		 * we have the current page before we initiate the read ahead.
		 */
		nextrio = ip->i_nextrio;
		if (seqmode &&
		    pgoff + RD_CLUSTSZ(ip) >= nextrio && pgoff <= nextrio &&
		    nextrio < ip->i_size && page_exists(vp, pgoff))
			ud_getpage_ra(vp, pgoff, seg, pgaddr);

		if ((pp = page_lookup(vp, pgoff, se)) != NULL) {

			/*
			 * We found the page in the page cache.
			 */
			*pl++ = pp;
			pgoff += pgsize;
			pgaddr += pgsize;
			len -= pgsize;
			plsz -= pgsize;
		} else  {

			/*
			 * We have to create the page, or read it from disk.
			 */
			if (error = ud_getpage_miss(vp, pgoff, len,
			    seg, pgaddr, pl, plsz, rw, seqmode)) {
				goto error_out;
			}

			while (*pl != NULL) {
				pl++;
				pgoff += pgsize;
				pgaddr += pgsize;
				len -= pgsize;
				plsz -= pgsize;
			}
		}
	}

	/*
	 * Return pages up to plsz if they are in the page cache.
	 * We cannot return pages if there is a chance that they are
	 * backed with a UDF hole and rw is S_WRITE or S_CREATE.
	 */
	if (plarr && !(has_holes && (rw == S_WRITE || rw == S_CREATE))) {

		ASSERT((protp == NULL) ||
		    !(has_holes && (*protp & PROT_WRITE)));

		eoff = pgoff + plsz;
		while (pgoff < eoff) {
			page_t		*pp;

			if ((pp = page_lookup_nowait(vp, pgoff,
			    SE_SHARED)) == NULL)
				break;

			*pl++ = pp;
			pgoff += pgsize;
			plsz -= pgsize;
		}
	}

	if (plarr)
		*pl = NULL;			/* Terminate page list */
	ip->i_nextr = pgoff;

error_out:
	if (error && plarr) {
		/*
		 * Release any pages we have locked.
		 */
		while (pl > &plarr[0])
			page_unlock(*--pl);

		plarr[0] = NULL;
	}

update_inode:
#ifdef	__lock_lint
	rw_exit(&ip->i_contents);
#else
	if (dolock) {
		rw_exit(&ip->i_contents);
	}
#endif

	/*
	 * If the inode is not already marked for IACC (in rwip() for read)
	 * and the inode is not marked for no access time update (in rwip()
	 * for write) then update the inode access time and mod time now.
	 */
	mutex_enter(&ip->i_tlock);
	if ((ip->i_flag & (IACC | INOACC)) == 0) {
		if ((rw != S_OTHER) && (ip->i_type != VDIR)) {
			ip->i_flag |= IACC;
		}
		if (rw == S_WRITE) {
			ip->i_flag |= IUPD;
		}
		ITIMES_NOLOCK(ip);
	}
	mutex_exit(&ip->i_tlock);

	return (error);
}

int32_t ud_delay = 1;

/* ARGSUSED */
static int32_t
udf_putpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	int32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip;
	int32_t error = 0;

	ud_printf("udf_putpage\n");

	ip = VTOI(vp);
#ifdef	__lock_lint
	rw_enter(&ip->i_contents, RW_WRITER);
#endif

	if (vp->v_count == 0) {
		cmn_err(CE_WARN, "ud_putpage : bad v_count");
		error = EINVAL;
		goto out;
	}

	if (vp->v_flag & VNOMAP) {
		error = ENOSYS;
		goto out;
	}

	if (flags & B_ASYNC) {
		if (ud_delay && len &&
		    (flags & ~(B_ASYNC|B_DONTNEED|B_FREE)) == 0) {
			mutex_enter(&ip->i_tlock);

			/*
			 * If nobody stalled, start a new cluster.
			 */
			if (ip->i_delaylen == 0) {
				ip->i_delayoff = off;
				ip->i_delaylen = len;
				mutex_exit(&ip->i_tlock);
				goto out;
			}

			/*
			 * If we have a full cluster or they are not contig,
			 * then push last cluster and start over.
			 */
			if (ip->i_delaylen >= WR_CLUSTSZ(ip) ||
			    ip->i_delayoff + ip->i_delaylen != off) {
				u_offset_t doff;
				size_t dlen;

				doff = ip->i_delayoff;
				dlen = ip->i_delaylen;
				ip->i_delayoff = off;
				ip->i_delaylen = len;
				mutex_exit(&ip->i_tlock);
				error = ud_putpages(vp, doff, dlen, flags, cr);
				/* LMXXX - flags are new val, not old */
				goto out;
			}

			/*
			 * There is something there, it's not full, and
			 * it is contig.
			 */
			ip->i_delaylen += len;
			mutex_exit(&ip->i_tlock);
			goto out;
		}

		/*
		 * Must have weird flags or we are not clustering.
		 */
	}

	error = ud_putpages(vp, off, len, flags, cr);

out:
#ifdef	__lock_lint
	rw_exit(&ip->i_contents);
#endif
	return (error);
}

/* ARGSUSED */
static int32_t
udf_map(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uint8_t prot,
	uint8_t maxprot,
	uint32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	int32_t error = 0;

	ud_printf("udf_map\n");

	if (vp->v_flag & VNOMAP) {
		error = ENOSYS;
		goto end;
	}

	if ((off < (offset_t)0) ||
	    ((off + len) < (offset_t)0)) {
		error = EINVAL;
		goto end;
	}

	if (vp->v_type != VREG) {
		error = ENODEV;
		goto end;
	}

	/*
	 * If file is being locked, disallow mapping.
	 */
	if (vn_has_mandatory_locks(vp, VTOI(vp)->i_char)) {
		error = EAGAIN;
		goto end;
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto end;
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, (caddr_t)&vn_a);
	as_rangeunlock(as);

end:
	return (error);
}

/* ARGSUSED */
static int32_t
udf_addmap(struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint8_t prot,
	uint8_t maxprot,
	uint32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_addmap\n");

	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}

	mutex_enter(&ip->i_tlock);
	ip->i_mapcnt += btopr(len);
	mutex_exit(&ip->i_tlock);

	return (0);
}

/* ARGSUSED */
static int32_t
udf_delmap(
	struct vnode *vp, offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint32_t prot,
	uint32_t maxprot,
	uint32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct ud_inode *ip = VTOI(vp);

	ud_printf("udf_delmap\n");

	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}

	mutex_enter(&ip->i_tlock);
	ip->i_mapcnt -= btopr(len); 	/* Count released mappings */
	ASSERT(ip->i_mapcnt >= 0);
	mutex_exit(&ip->i_tlock);

	return (0);
}

/* ARGSUSED */
static int32_t
udf_l_pathconf(
	struct vnode *vp,
	int32_t cmd,
	ulong_t *valp,
	struct cred *cr,
	caller_context_t *ct)
{
	int32_t error = 0;

	ud_printf("udf_l_pathconf\n");

	if (cmd == _PC_FILESIZEBITS) {
		/*
		 * udf supports 64 bits as file size
		 * but there are several other restrictions
		 * it only supports 32-bit block numbers and
		 * daddr32_t is only and int32_t so taking these
		 * into account we can stay just as where ufs is
		 */
		*valp = 41;
	} else if (cmd == _PC_TIMESTAMP_RESOLUTION) {
		/* nanosecond timestamp resolution */
		*valp = 1L;
	} else {
		error = fs_pathconf(vp, cmd, valp, cr, ct);
	}

	return (error);
}

uint32_t ud_pageio_reads = 0, ud_pageio_writes = 0;
#ifndef	__lint
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", ud_pageio_reads))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", ud_pageio_writes))
#endif
/*
 * Assumption is that there will not be a pageio request
 * to a enbedded file
 */
/* ARGSUSED */
static int32_t
udf_pageio(
	struct vnode *vp,
	struct page *pp,
	u_offset_t io_off,
	size_t io_len,
	int32_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	daddr_t bn;
	struct buf *bp;
	struct ud_inode *ip = VTOI(vp);
	int32_t dolock, error = 0, contig, multi_io;
	size_t done_len = 0, cur_len = 0;
	page_t *npp = NULL, *opp = NULL, *cpp = pp;

	if (pp == NULL) {
		return (EINVAL);
	}

	dolock = (rw_owner(&ip->i_contents) != curthread);

	/*
	 * We need a better check.  Ideally, we would use another
	 * vnodeops so that hlocked and forcibly unmounted file
	 * systems would return EIO where appropriate and w/o the
	 * need for these checks.
	 */
	if (ip->i_udf == NULL) {
		return (EIO);
	}

#ifdef	__lock_lint
	rw_enter(&ip->i_contents, RW_READER);
#else
	if (dolock) {
		rw_enter(&ip->i_contents, RW_READER);
	}
#endif

	/*
	 * Break the io request into chunks, one for each contiguous
	 * stretch of disk blocks in the target file.
	 */
	while (done_len < io_len) {
		ASSERT(cpp);
		bp = NULL;
		contig = 0;
		if (error = ud_bmap_read(ip, (u_offset_t)(io_off + done_len),
		    &bn, &contig)) {
			break;
		}

		if (bn == UDF_HOLE) {   /* No holey swapfiles */
			cmn_err(CE_WARN, "SWAP file has HOLES");
			error = EINVAL;
			break;
		}

		cur_len = MIN(io_len - done_len, contig);

		/*
		 * Check if more than one I/O is
		 * required to complete the given
		 * I/O operation
		 */
		if (ip->i_udf->udf_lbsize < PAGESIZE) {
			if (cur_len >= PAGESIZE) {
				multi_io = 0;
				cur_len &= PAGEMASK;
			} else {
				multi_io = 1;
				cur_len = MIN(io_len - done_len, PAGESIZE);
			}
		}
		page_list_break(&cpp, &npp, btop(cur_len));

		bp = pageio_setup(cpp, cur_len, ip->i_devvp, flags);
		ASSERT(bp != NULL);

		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_un.b_addr = (caddr_t)0;
		bp->b_file = vp;
		bp->b_offset = (offset_t)(io_off + done_len);

/*
 *		ub.ub_pageios.value.ul++;
 */
		if (multi_io == 0) {
			(void) bdev_strategy(bp);
		} else {
			error = ud_multi_strat(ip, cpp, bp,
			    (u_offset_t)(io_off + done_len));
			if (error != 0) {
				pageio_done(bp);
				break;
			}
		}
		if (flags & B_READ) {
			ud_pageio_reads++;
		} else {
			ud_pageio_writes++;
		}

		/*
		 * If the request is not B_ASYNC, wait for i/o to complete
		 * and re-assemble the page list to return to the caller.
		 * If it is B_ASYNC we leave the page list in pieces and
		 * cleanup() will dispose of them.
		 */
		if ((flags & B_ASYNC) == 0) {
			error = biowait(bp);
			pageio_done(bp);
			if (error) {
				break;
			}
			page_list_concat(&opp, &cpp);
		}
		cpp = npp;
		npp = NULL;
		done_len += cur_len;
	}

	ASSERT(error || (cpp == NULL && npp == NULL && done_len == io_len));
	if (error) {
		if (flags & B_ASYNC) {
			/* Cleanup unprocessed parts of list */
			page_list_concat(&cpp, &npp);
			if (flags & B_READ) {
				pvn_read_done(cpp, B_ERROR);
			} else {
				pvn_write_done(cpp, B_ERROR);
			}
		} else {
			/* Re-assemble list and let caller clean up */
			page_list_concat(&opp, &cpp);
			page_list_concat(&opp, &npp);
		}
	}

#ifdef	__lock_lint
	rw_exit(&ip->i_contents);
#else
	if (dolock) {
		rw_exit(&ip->i_contents);
	}
#endif
	return (error);
}




/* -------------------- local functions --------------------------- */



int32_t
ud_rdwri(enum uio_rw rw, int32_t ioflag,
	struct ud_inode *ip, caddr_t base, int32_t len,
	offset_t offset, enum uio_seg seg, int32_t *aresid, struct cred *cr)
{
	int32_t error;
	struct uio auio;
	struct iovec aiov;

	ud_printf("ud_rdwri\n");

	bzero((caddr_t)&auio, sizeof (uio_t));
	bzero((caddr_t)&aiov, sizeof (iovec_t));

	aiov.iov_base = base;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_segflg = (int16_t)seg;
	auio.uio_resid = len;

	if (rw == UIO_WRITE) {
		auio.uio_fmode = FWRITE;
		auio.uio_extflg = UIO_COPY_DEFAULT;
		auio.uio_llimit = curproc->p_fsz_ctl;
		error = ud_wrip(ip, &auio, ioflag, cr);
	} else {
		auio.uio_fmode = FREAD;
		auio.uio_extflg = UIO_COPY_CACHED;
		auio.uio_llimit = MAXOFFSET_T;
		error = ud_rdip(ip, &auio, ioflag, cr);
	}

	if (aresid) {
		*aresid = auio.uio_resid;
	} else if (auio.uio_resid) {
		error = EIO;
	}
	return (error);
}

/*
 * Free behind hacks.  The pager is busted.
 * XXX - need to pass the information down to writedone() in a flag like B_SEQ
 * or B_FREE_IF_TIGHT_ON_MEMORY.
 */
int32_t ud_freebehind = 1;
int32_t ud_smallfile = 32 * 1024;

/* ARGSUSED */
int32_t
ud_getpage_miss(struct vnode *vp, u_offset_t off,
	size_t len, struct seg *seg, caddr_t addr, page_t *pl[],
	size_t plsz, enum seg_rw rw, int32_t seq)
{
	struct ud_inode *ip = VTOI(vp);
	int32_t err = 0;
	size_t io_len;
	u_offset_t io_off;
	u_offset_t pgoff;
	page_t *pp;

	pl[0] = NULL;

	/*
	 * Figure out whether the page can be created, or must be
	 * read from the disk
	 */
	if (rw == S_CREATE) {
		if ((pp = page_create_va(vp, off,
		    PAGESIZE, PG_WAIT, seg, addr)) == NULL) {
			cmn_err(CE_WARN, "ud_getpage_miss: page_create");
			return (EINVAL);
		}
		io_len = PAGESIZE;
	} else {
		pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
		    &io_len, off, PAGESIZE, 0);

		/*
		 * Some other thread has entered the page.
		 * ud_getpage will retry page_lookup.
		 */
		if (pp == NULL) {
			return (0);
		}

		/*
		 * Fill the page with as much data as we can from the file.
		 */
		err = ud_page_fill(ip, pp, off, B_READ, &pgoff);
		if (err) {
			pvn_read_done(pp, B_ERROR);
			return (err);
		}

		/*
		 * XXX ??? ufs has io_len instead of pgoff below
		 */
		ip->i_nextrio = off + ((pgoff + PAGESIZE - 1) & PAGEMASK);

		/*
		 * If the file access is sequential, initiate read ahead
		 * of the next cluster.
		 */
		if (seq && ip->i_nextrio < ip->i_size) {
			ud_getpage_ra(vp, off, seg, addr);
		}
	}

outmiss:
	pvn_plist_init(pp, pl, plsz, (offset_t)off, io_len, rw);
	return (err);
}

/* ARGSUSED */
void
ud_getpage_ra(struct vnode *vp,
	u_offset_t off, struct seg *seg, caddr_t addr)
{
	page_t *pp;
	size_t io_len;
	struct ud_inode *ip = VTOI(vp);
	u_offset_t io_off = ip->i_nextrio, pgoff;
	caddr_t addr2 = addr + (io_off - off);
	daddr_t bn;
	int32_t contig = 0;

	/*
	 * Is this test needed?
	 */

	if (addr2 >= seg->s_base + seg->s_size) {
		return;
	}

	contig = 0;
	if (ud_bmap_read(ip, io_off, &bn, &contig) != 0 || bn == UDF_HOLE) {
		return;
	}

	pp = pvn_read_kluster(vp, io_off, seg, addr2,
	    &io_off, &io_len, io_off, PAGESIZE, 1);

	/*
	 * Some other thread has entered the page.
	 * So no read head done here (ie we will have to and wait
	 * for the read when needed).
	 */

	if (pp == NULL) {
		return;
	}

	(void) ud_page_fill(ip, pp, io_off, (B_READ|B_ASYNC), &pgoff);
	ip->i_nextrio =  io_off + ((pgoff + PAGESIZE - 1) & PAGEMASK);
}

int
ud_page_fill(struct ud_inode *ip, page_t *pp, u_offset_t off,
	uint32_t bflgs, u_offset_t *pg_off)
{
	daddr_t bn;
	struct buf *bp;
	caddr_t kaddr, caddr;
	int32_t error = 0, contig = 0, multi_io = 0;
	int32_t lbsize = ip->i_udf->udf_lbsize;
	int32_t lbmask = ip->i_udf->udf_lbmask;
	uint64_t isize;

	isize = (ip->i_size + lbmask) & (~lbmask);
	if (ip->i_desc_type == ICB_FLAG_ONE_AD) {

		/*
		 * Embedded file read file_entry
		 * from buffer cache and copy the required
		 * portions
		 */
		bp = ud_bread(ip->i_dev,
		    ip->i_icb_lbano << ip->i_udf->udf_l2d_shift, lbsize);
		if ((bp->b_error == 0) &&
		    (bp->b_resid == 0)) {

			caddr = bp->b_un.b_addr + ip->i_data_off;

			/*
			 * mapin to kvm
			 */
			kaddr = (caddr_t)ppmapin(pp,
			    PROT_READ | PROT_WRITE, (caddr_t)-1);
			(void) kcopy(caddr, kaddr, ip->i_size);

			/*
			 * mapout of kvm
			 */
			ppmapout(kaddr);
		}
		brelse(bp);
		contig = ip->i_size;
	} else {

		/*
		 * Get the continuous size and block number
		 * at offset "off"
		 */
		if (error = ud_bmap_read(ip, off, &bn, &contig))
			goto out;
		contig = MIN(contig, PAGESIZE);
		contig = (contig + lbmask) & (~lbmask);

		/*
		 * Zero part of the page which we are not
		 * going to read from the disk.
		 */

		if (bn == UDF_HOLE) {

			/*
			 * This is a HOLE. Just zero out
			 * the page
			 */
			if (((off + contig) == isize) ||
			    (contig == PAGESIZE)) {
				pagezero(pp->p_prev, 0, PAGESIZE);
				goto out;
			}
		}

		if (contig < PAGESIZE) {
			uint64_t count;

			count = isize - off;
			if (contig != count) {
				multi_io = 1;
				contig = (int32_t)(MIN(count, PAGESIZE));
			} else {
				pagezero(pp->p_prev, contig, PAGESIZE - contig);
			}
		}

		/*
		 * Get a bp and initialize it
		 */
		bp = pageio_setup(pp, contig, ip->i_devvp, bflgs);
		ASSERT(bp != NULL);

		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_un.b_addr = 0;
		bp->b_file = ip->i_vnode;

		/*
		 * Start I/O
		 */
		if (multi_io == 0) {

			/*
			 * Single I/O is sufficient for this page
			 */
			(void) bdev_strategy(bp);
		} else {

			/*
			 * We need to do the I/O in
			 * piece's
			 */
			error = ud_multi_strat(ip, pp, bp, off);
			if (error != 0) {
				goto out;
			}
		}
		if ((bflgs & B_ASYNC) == 0) {

			/*
			 * Wait for i/o to complete.
			 */

			error = biowait(bp);
			pageio_done(bp);
			if (error) {
				goto out;
			}
		}
	}
	if ((off + contig) >= ip->i_size) {
		contig = ip->i_size - off;
	}

out:
	*pg_off = contig;
	return (error);
}

int32_t
ud_putpages(struct vnode *vp, offset_t off,
	size_t len, int32_t flags, struct cred *cr)
{
	struct ud_inode *ip;
	page_t *pp;
	u_offset_t io_off;
	size_t io_len;
	u_offset_t eoff;
	int32_t err = 0;
	int32_t dolock;

	ud_printf("ud_putpages\n");

	if (vp->v_count == 0) {
		cmn_err(CE_WARN, "ud_putpages: bad v_count");
		return (EINVAL);
	}

	ip = VTOI(vp);

	/*
	 * Acquire the readers/write inode lock before locking
	 * any pages in this inode.
	 * The inode lock is held during i/o.
	 */
	if (len == 0) {
		mutex_enter(&ip->i_tlock);
		ip->i_delayoff = ip->i_delaylen = 0;
		mutex_exit(&ip->i_tlock);
	}
#ifdef	__lock_lint
	rw_enter(&ip->i_contents, RW_READER);
#else
	dolock = (rw_owner(&ip->i_contents) != curthread);
	if (dolock) {
		rw_enter(&ip->i_contents, RW_READER);
	}
#endif

	if (!vn_has_cached_data(vp)) {
#ifdef	__lock_lint
		rw_exit(&ip->i_contents);
#else
		if (dolock) {
			rw_exit(&ip->i_contents);
		}
#endif
		return (0);
	}

	if (len == 0) {
		/*
		 * Search the entire vp list for pages >= off.
		 */
		err = pvn_vplist_dirty(vp, (u_offset_t)off, ud_putapage,
		    flags, cr);
	} else {
		/*
		 * Loop over all offsets in the range looking for
		 * pages to deal with.
		 */
		if ((eoff = blkroundup(ip->i_udf, ip->i_size)) != 0) {
			eoff = MIN(off + len, eoff);
		} else {
			eoff = off + len;
		}

		for (io_off = off; io_off < eoff; io_off += io_len) {
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages, use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || pvn_getdirty(pp, flags) == 0) {
				io_len = PAGESIZE;
			} else {

				err = ud_putapage(vp, pp,
				    &io_off, &io_len, flags, cr);
				if (err != 0) {
					break;
				}
				/*
				 * "io_off" and "io_len" are returned as
				 * the range of pages we actually wrote.
				 * This allows us to skip ahead more quickly
				 * since several pages may've been dealt
				 * with by this iteration of the loop.
				 */
			}
		}
	}
	if (err == 0 && off == 0 && (len == 0 || len >= ip->i_size)) {
		/*
		 * We have just sync'ed back all the pages on
		 * the inode, turn off the IMODTIME flag.
		 */
		mutex_enter(&ip->i_tlock);
		ip->i_flag &= ~IMODTIME;
		mutex_exit(&ip->i_tlock);
	}
#ifdef	__lock_lint
	rw_exit(&ip->i_contents);
#else
	if (dolock) {
		rw_exit(&ip->i_contents);
	}
#endif
	return (err);
}

/* ARGSUSED */
int32_t
ud_putapage(struct vnode *vp,
	page_t *pp, u_offset_t *offp,
	size_t *lenp, int32_t flags, struct cred *cr)
{
	daddr_t bn;
	size_t io_len;
	struct ud_inode *ip;
	int32_t error = 0, contig, multi_io = 0;
	struct udf_vfs *udf_vfsp;
	u_offset_t off, io_off;
	caddr_t kaddr, caddr;
	struct buf *bp = NULL;
	int32_t lbmask;
	uint64_t isize;
	uint16_t crc_len;
	struct file_entry *fe;

	ud_printf("ud_putapage\n");

	ip = VTOI(vp);
	ASSERT(ip);
	ASSERT(RW_LOCK_HELD(&ip->i_contents));
	lbmask = ip->i_udf->udf_lbmask;
	isize = (ip->i_size + lbmask) & (~lbmask);

	udf_vfsp = ip->i_udf;
	ASSERT(udf_vfsp->udf_flags & UDF_FL_RW);

	/*
	 * If the modified time on the inode has not already been
	 * set elsewhere (e.g. for write/setattr) we set the time now.
	 * This gives us approximate modified times for mmap'ed files
	 * which are modified via stores in the user address space.
	 */
	if (((ip->i_flag & IMODTIME) == 0) || (flags & B_FORCE)) {
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= IUPD;
		ITIMES_NOLOCK(ip);
		mutex_exit(&ip->i_tlock);
	}


	/*
	 * Align the request to a block boundry (for old file systems),
	 * and go ask bmap() how contiguous things are for this file.
	 */
	off = pp->p_offset & ~(offset_t)lbmask;
				/* block align it */


	if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
		ASSERT(ip->i_size <= ip->i_max_emb);

		pp = pvn_write_kluster(vp, pp, &io_off,
		    &io_len, off, PAGESIZE, flags);
		if (io_len == 0) {
			io_len = PAGESIZE;
		}

		bp = ud_bread(ip->i_dev,
		    ip->i_icb_lbano << udf_vfsp->udf_l2d_shift,
		    udf_vfsp->udf_lbsize);
		fe = (struct file_entry *)bp->b_un.b_addr;
		if ((bp->b_flags & B_ERROR) ||
		    (ud_verify_tag_and_desc(&fe->fe_tag, UD_FILE_ENTRY,
		    ip->i_icb_block,
		    1, udf_vfsp->udf_lbsize) != 0)) {
			if (pp != NULL)
				pvn_write_done(pp, B_ERROR | B_WRITE | flags);
			if (bp->b_flags & B_ERROR) {
				error = EIO;
			} else {
				error = EINVAL;
			}
			brelse(bp);
			return (error);
		}
		if ((bp->b_error == 0) &&
		    (bp->b_resid == 0)) {

			caddr = bp->b_un.b_addr + ip->i_data_off;
			kaddr = (caddr_t)ppmapin(pp,
			    PROT_READ | PROT_WRITE, (caddr_t)-1);
			(void) kcopy(kaddr, caddr, ip->i_size);
			ppmapout(kaddr);
		}
		crc_len = offsetof(struct file_entry, fe_spec) +
		    SWAP_32(fe->fe_len_ear);
		crc_len += ip->i_size;
		ud_make_tag(ip->i_udf, &fe->fe_tag,
		    UD_FILE_ENTRY, ip->i_icb_block, crc_len);

		bwrite(bp);

		if (flags & B_ASYNC) {
			pvn_write_done(pp, flags);
		}
		contig = ip->i_size;
	} else {

		if (error = ud_bmap_read(ip, off, &bn, &contig)) {
			goto out;
		}
		contig = MIN(contig, PAGESIZE);
		contig = (contig + lbmask) & (~lbmask);

		if (contig < PAGESIZE) {
			uint64_t count;

			count = isize - off;
			if (contig != count) {
				multi_io = 1;
				contig = (int32_t)(MIN(count, PAGESIZE));
			}
		}

		if ((off + contig) > isize) {
			contig = isize - off;
		}

		if (contig > PAGESIZE) {
			if (contig & PAGEOFFSET) {
				contig &= PAGEMASK;
			}
		}

		pp = pvn_write_kluster(vp, pp, &io_off,
		    &io_len, off, contig, flags);
		if (io_len == 0) {
			io_len = PAGESIZE;
		}

		bp = pageio_setup(pp, contig, ip->i_devvp, B_WRITE | flags);
		ASSERT(bp != NULL);

		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_un.b_addr = 0;
		bp->b_file = vp;
		bp->b_offset = (offset_t)off;


		/*
		 * write throttle
		 */
		ASSERT(bp->b_iodone == NULL);
		bp->b_iodone = ud_iodone;
		mutex_enter(&ip->i_tlock);
		ip->i_writes += bp->b_bcount;
		mutex_exit(&ip->i_tlock);

		if (multi_io == 0) {

			(void) bdev_strategy(bp);
		} else {
			error = ud_multi_strat(ip, pp, bp, off);
			if (error != 0) {
				goto out;
			}
		}

		if ((flags & B_ASYNC) == 0) {
			/*
			 * Wait for i/o to complete.
			 */
			error = biowait(bp);
			pageio_done(bp);
		}
	}

	if ((flags & B_ASYNC) == 0) {
		pvn_write_done(pp, ((error) ? B_ERROR : 0) | B_WRITE | flags);
	}

	pp = NULL;

out:
	if (error != 0 && pp != NULL) {
		pvn_write_done(pp, B_ERROR | B_WRITE | flags);
	}

	if (offp) {
		*offp = io_off;
	}
	if (lenp) {
		*lenp = io_len;
	}

	return (error);
}


int32_t
ud_iodone(struct buf *bp)
{
	struct ud_inode *ip;

	ASSERT((bp->b_pages->p_vnode != NULL) && !(bp->b_flags & B_READ));

	bp->b_iodone = NULL;

	ip = VTOI(bp->b_pages->p_vnode);

	mutex_enter(&ip->i_tlock);
	if (ip->i_writes >= ud_LW) {
		if ((ip->i_writes -= bp->b_bcount) <= ud_LW) {
			if (ud_WRITES) {
				cv_broadcast(&ip->i_wrcv); /* wake all up */
			}
		}
	} else {
		ip->i_writes -= bp->b_bcount;
	}
	mutex_exit(&ip->i_tlock);
	iodone(bp);
	return (0);
}

/* ARGSUSED3 */
int32_t
ud_rdip(struct ud_inode *ip, struct uio *uio, int32_t ioflag, cred_t *cr)
{
	struct vnode *vp;
	struct udf_vfs *udf_vfsp;
	krw_t rwtype;
	caddr_t base;
	uint32_t flags;
	int32_t error, n, on, mapon, dofree;
	u_offset_t off;
	long oresid = uio->uio_resid;

	ASSERT(RW_LOCK_HELD(&ip->i_contents));
	if ((ip->i_type != VREG) &&
	    (ip->i_type != VDIR) &&
	    (ip->i_type != VLNK)) {
		return (EIO);
	}

	if (uio->uio_loffset > MAXOFFSET_T) {
		return (0);
	}

	if ((uio->uio_loffset < (offset_t)0) ||
	    ((uio->uio_loffset + uio->uio_resid) < 0)) {
		return (EINVAL);
	}
	if (uio->uio_resid == 0) {
		return (0);
	}

	vp = ITOV(ip);
	udf_vfsp = ip->i_udf;
	mutex_enter(&ip->i_tlock);
	ip->i_flag |= IACC;
	mutex_exit(&ip->i_tlock);

	rwtype = (rw_write_held(&ip->i_contents)?RW_WRITER:RW_READER);

	do {
		offset_t diff;
		u_offset_t uoff = uio->uio_loffset;
		off = uoff & (offset_t)MAXBMASK;
		mapon = (int)(uoff & (offset_t)MAXBOFFSET);
		on = (int)blkoff(udf_vfsp, uoff);
		n = (int)MIN(udf_vfsp->udf_lbsize - on, uio->uio_resid);

		diff = ip->i_size - uoff;

		if (diff <= (offset_t)0) {
			error = 0;
			goto out;
		}
		if (diff < (offset_t)n) {
			n = (int)diff;
		}
		dofree = ud_freebehind &&
		    ip->i_nextr == (off & PAGEMASK) &&
		    off > ud_smallfile;

#ifndef	__lock_lint
		if (rwtype == RW_READER) {
			rw_exit(&ip->i_contents);
		}
#endif

		base = segmap_getmapflt(segkmap, vp, (off + mapon),
		    (uint32_t)n, 1, S_READ);
		error = uiomove(base + mapon, (long)n, UIO_READ, uio);

		flags = 0;
		if (!error) {
			/*
			 * If read a whole block, or read to eof,
			 * won't need this buffer again soon.
			 */
			if (n + on == MAXBSIZE && ud_freebehind && dofree &&
			    freemem < lotsfree + pages_before_pager) {
				flags = SM_FREE | SM_DONTNEED |SM_ASYNC;
			}
			/*
			 * In POSIX SYNC (FSYNC and FDSYNC) read mode,
			 * we want to make sure that the page which has
			 * been read, is written on disk if it is dirty.
			 * And corresponding indirect blocks should also
			 * be flushed out.
			 */
			if ((ioflag & FRSYNC) && (ioflag & (FSYNC|FDSYNC))) {
				flags &= ~SM_ASYNC;
				flags |= SM_WRITE;
			}
			error = segmap_release(segkmap, base, flags);
		} else    {
			(void) segmap_release(segkmap, base, flags);
		}

#ifndef __lock_lint
		if (rwtype == RW_READER) {
			rw_enter(&ip->i_contents, rwtype);
		}
#endif
	} while (error == 0 && uio->uio_resid > 0 && n != 0);
out:
	/*
	 * Inode is updated according to this table if FRSYNC is set.
	 *
	 *	FSYNC	FDSYNC(posix.4)
	 *	--------------------------
	 *	always	IATTCHG|IBDWRITE
	 */
	if (ioflag & FRSYNC) {
		if ((ioflag & FSYNC) ||
		    ((ioflag & FDSYNC) &&
		    (ip->i_flag & (IATTCHG|IBDWRITE)))) {
		rw_exit(&ip->i_contents);
		rw_enter(&ip->i_contents, RW_WRITER);
		ud_iupdat(ip, 1);
		}
	}
	/*
	 * If we've already done a partial read, terminate
	 * the read but return no error.
	 */
	if (oresid != uio->uio_resid) {
		error = 0;
	}
	ITIMES(ip);

	return (error);
}

int32_t
ud_wrip(struct ud_inode *ip, struct uio *uio, int ioflag, struct cred *cr)
{
	caddr_t base;
	struct vnode *vp;
	struct udf_vfs *udf_vfsp;
	uint32_t flags;
	int32_t error = 0, iupdat_flag, n, on, mapon, i_size_changed = 0;
	int32_t pagecreate, newpage;
	uint64_t old_i_size;
	u_offset_t off;
	long start_resid = uio->uio_resid, premove_resid;
	rlim64_t limit = uio->uio_limit;


	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	if ((ip->i_type != VREG) &&
	    (ip->i_type != VDIR) &&
	    (ip->i_type != VLNK)) {
		return (EIO);
	}

	if (uio->uio_loffset >= MAXOFFSET_T) {
		return (EFBIG);
	}
	/*
	 * see udf_l_pathconf
	 */
	if (limit > (((uint64_t)1 << 40) - 1)) {
		limit = ((uint64_t)1 << 40) - 1;
	}
	if (uio->uio_loffset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE], p->p_rctls,
		    p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}
	if ((uio->uio_loffset < (offset_t)0) ||
	    ((uio->uio_loffset + uio->uio_resid) < 0)) {
		return (EINVAL);
	}
	if (uio->uio_resid == 0) {
		return (0);
	}

	mutex_enter(&ip->i_tlock);
	ip->i_flag |= INOACC;

	if (ioflag & (FSYNC | FDSYNC)) {
		ip->i_flag |= ISYNC;
		iupdat_flag = 1;
	}
	mutex_exit(&ip->i_tlock);

	udf_vfsp = ip->i_udf;
	vp = ITOV(ip);

	do {
		u_offset_t uoff = uio->uio_loffset;
		off = uoff & (offset_t)MAXBMASK;
		mapon = (int)(uoff & (offset_t)MAXBOFFSET);
		on = (int)blkoff(udf_vfsp, uoff);
		n = (int)MIN(udf_vfsp->udf_lbsize - on, uio->uio_resid);

		if (ip->i_type == VREG && uoff + n >= limit) {
			if (uoff >= limit) {
				error = EFBIG;
				goto out;
			}
			n = (int)(limit - (rlim64_t)uoff);
		}
		if (uoff + n > ip->i_size) {
			/*
			 * We are extending the length of the file.
			 * bmap is used so that we are sure that
			 * if we need to allocate new blocks, that it
			 * is done here before we up the file size.
			 */
			error = ud_bmap_write(ip, uoff,
			    (int)(on + n), mapon == 0, cr);
			if (error) {
				break;
			}
			i_size_changed = 1;
			old_i_size = ip->i_size;
			ip->i_size = uoff + n;
			/*
			 * If we are writing from the beginning of
			 * the mapping, we can just create the
			 * pages without having to read them.
			 */
			pagecreate = (mapon == 0);
		} else if (n == MAXBSIZE) {
			/*
			 * Going to do a whole mappings worth,
			 * so we can just create the pages w/o
			 * having to read them in.  But before
			 * we do that, we need to make sure any
			 * needed blocks are allocated first.
			 */
			error = ud_bmap_write(ip, uoff,
			    (int)(on + n), 1, cr);
			if (error) {
				break;
			}
			pagecreate = 1;
		} else {
			pagecreate = 0;
		}

		rw_exit(&ip->i_contents);

		/*
		 * Touch the page and fault it in if it is not in
		 * core before segmap_getmapflt can lock it. This
		 * is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to
		 * write to.
		 */
		uio_prefaultpages((long)n, uio);

		base = segmap_getmapflt(segkmap, vp, (off + mapon),
		    (uint32_t)n, !pagecreate, S_WRITE);

		/*
		 * segmap_pagecreate() returns 1 if it calls
		 * page_create_va() to allocate any pages.
		 */
		newpage = 0;
		if (pagecreate) {
			newpage = segmap_pagecreate(segkmap, base,
			    (size_t)n, 0);
		}

		premove_resid = uio->uio_resid;
		error = uiomove(base + mapon, (long)n, UIO_WRITE, uio);

		if (pagecreate &&
		    uio->uio_loffset < roundup(off + mapon + n, PAGESIZE)) {
			/*
			 * We created pages w/o initializing them completely,
			 * thus we need to zero the part that wasn't set up.
			 * This happens on most EOF write cases and if
			 * we had some sort of error during the uiomove.
			 */
			int nzero, nmoved;

			nmoved = (int)(uio->uio_loffset - (off + mapon));
			ASSERT(nmoved >= 0 && nmoved <= n);
			nzero = roundup(on + n, PAGESIZE) - nmoved;
			ASSERT(nzero > 0 && mapon + nmoved + nzero <= MAXBSIZE);
			(void) kzero(base + mapon + nmoved, (uint32_t)nzero);
		}

		/*
		 * Unlock the pages allocated by page_create_va()
		 * in segmap_pagecreate()
		 */
		if (newpage) {
			segmap_pageunlock(segkmap, base, (size_t)n, S_WRITE);
		}

		if (error) {
			/*
			 * If we failed on a write, we may have already
			 * allocated file blocks as well as pages.  It's
			 * hard to undo the block allocation, but we must
			 * be sure to invalidate any pages that may have
			 * been allocated.
			 */
			(void) segmap_release(segkmap, base, SM_INVAL);
		} else {
			flags = 0;
			/*
			 * Force write back for synchronous write cases.
			 */
			if ((ioflag & (FSYNC|FDSYNC)) || ip->i_type == VDIR) {
				/*
				 * If the sticky bit is set but the
				 * execute bit is not set, we do a
				 * synchronous write back and free
				 * the page when done.  We set up swap
				 * files to be handled this way to
				 * prevent servers from keeping around
				 * the client's swap pages too long.
				 * XXX - there ought to be a better way.
				 */
				if (IS_SWAPVP(vp)) {
					flags = SM_WRITE | SM_FREE |
					    SM_DONTNEED;
					iupdat_flag = 0;
				} else {
					flags = SM_WRITE;
				}
			} else if (((mapon + n) == MAXBSIZE) ||
			    IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write and
				 * mark the buffer to indicate that
				 * it won't be needed again soon.
				 */
				flags = SM_WRITE |SM_ASYNC | SM_DONTNEED;
			}
			error = segmap_release(segkmap, base, flags);

			/*
			 * If the operation failed and is synchronous,
			 * then we need to unwind what uiomove() last
			 * did so we can potentially return an error to
			 * the caller.  If this write operation was
			 * done in two pieces and the first succeeded,
			 * then we won't return an error for the second
			 * piece that failed.  However, we only want to
			 * return a resid value that reflects what was
			 * really done.
			 *
			 * Failures for non-synchronous operations can
			 * be ignored since the page subsystem will
			 * retry the operation until it succeeds or the
			 * file system is unmounted.
			 */
			if (error) {
				if ((ioflag & (FSYNC | FDSYNC)) ||
				    ip->i_type == VDIR) {
					uio->uio_resid = premove_resid;
				} else {
					error = 0;
				}
			}
		}

		/*
		 * Re-acquire contents lock.
		 */
		rw_enter(&ip->i_contents, RW_WRITER);
		/*
		 * If the uiomove() failed or if a synchronous
		 * page push failed, fix up i_size.
		 */
		if (error) {
			if (i_size_changed) {
				/*
				 * The uiomove failed, and we
				 * allocated blocks,so get rid
				 * of them.
				 */
				(void) ud_itrunc(ip, old_i_size, 0, cr);
			}
		} else {
			/*
			 * XXX - Can this be out of the loop?
			 */
			ip->i_flag |= IUPD | ICHG;
			if (i_size_changed) {
				ip->i_flag |= IATTCHG;
			}
			if ((ip->i_perm & (IEXEC | (IEXEC >> 5) |
			    (IEXEC >> 10))) != 0 &&
			    (ip->i_char & (ISUID | ISGID)) != 0 &&
			    secpolicy_vnode_setid_retain(cr,
			    (ip->i_char & ISUID) != 0 && ip->i_uid == 0) != 0) {
				/*
				 * Clear Set-UID & Set-GID bits on
				 * successful write if not privileged
				 * and at least one of the execute bits
				 * is set.  If we always clear Set-GID,
				 * mandatory file and record locking is
				 * unuseable.
				 */
				ip->i_char &= ~(ISUID | ISGID);
			}
		}
	} while (error == 0 && uio->uio_resid > 0 && n != 0);

out:
	/*
	 * Inode is updated according to this table -
	 *
	 *	FSYNC	FDSYNC(posix.4)
	 *	--------------------------
	 *	always@	IATTCHG|IBDWRITE
	 *
	 * @ -  If we are doing synchronous write the only time we should
	 *	not be sync'ing the ip here is if we have the stickyhack
	 *	activated, the file is marked with the sticky bit and
	 *	no exec bit, the file length has not been changed and
	 *	no new blocks have been allocated during this write.
	 */
	if ((ip->i_flag & ISYNC) != 0) {
		/*
		 * we have eliminated nosync
		 */
		if ((ip->i_flag & (IATTCHG|IBDWRITE)) ||
		    ((ioflag & FSYNC) && iupdat_flag)) {
			ud_iupdat(ip, 1);
		}
	}

	/*
	 * If we've already done a partial-write, terminate
	 * the write but return no error.
	 */
	if (start_resid != uio->uio_resid) {
		error = 0;
	}
	ip->i_flag &= ~(INOACC | ISYNC);
	ITIMES_NOLOCK(ip);

	return (error);
}

int32_t
ud_multi_strat(struct ud_inode *ip,
	page_t *pp, struct buf *bp, u_offset_t start)
{
	daddr_t bn;
	int32_t error = 0, io_count, contig, alloc_sz, i;
	uint32_t io_off;
	mio_master_t *mm = NULL;
	mio_slave_t *ms = NULL;
	struct buf *rbp;

	ASSERT(!(start & PAGEOFFSET));

	/*
	 * Figure out how many buffers to allocate
	 */
	io_count = 0;
	for (io_off = 0; io_off < bp->b_bcount; io_off += contig) {
		contig = 0;
		if (error = ud_bmap_read(ip, (u_offset_t)(start + io_off),
		    &bn, &contig)) {
			goto end;
		}
		if (contig == 0) {
			goto end;
		}
		contig = MIN(contig, PAGESIZE - io_off);
		if (bn != UDF_HOLE) {
			io_count ++;
		} else {
			/*
			 * HOLE
			 */
			if (bp->b_flags & B_READ) {

				/*
				 * This is a hole and is read
				 * it should be filled with 0's
				 */
				pagezero(pp, io_off, contig);
			}
		}
	}


	if (io_count != 0) {

		/*
		 * Allocate memory for all the
		 * required number of buffers
		 */
		alloc_sz = sizeof (mio_master_t) +
		    (sizeof (mio_slave_t) * io_count);
		mm = (mio_master_t *)kmem_zalloc(alloc_sz, KM_SLEEP);
		if (mm == NULL) {
			error = ENOMEM;
			goto end;
		}

		/*
		 * initialize master
		 */
		mutex_init(&mm->mm_mutex, NULL, MUTEX_DEFAULT, NULL);
		mm->mm_size = alloc_sz;
		mm->mm_bp = bp;
		mm->mm_resid = 0;
		mm->mm_error = 0;
		mm->mm_index = master_index++;

		ms = (mio_slave_t *)(((caddr_t)mm) + sizeof (mio_master_t));

		/*
		 * Initialize buffers
		 */
		io_count = 0;
		for (io_off = 0; io_off < bp->b_bcount; io_off += contig) {
			contig = 0;
			if (error = ud_bmap_read(ip,
			    (u_offset_t)(start + io_off),
			    &bn, &contig)) {
				goto end;
			}
			ASSERT(contig);
			if ((io_off + contig) > bp->b_bcount) {
				contig = bp->b_bcount - io_off;
			}
			if (bn != UDF_HOLE) {
				/*
				 * Clone the buffer
				 * and prepare to start I/O
				 */
				ms->ms_ptr = mm;
				bioinit(&ms->ms_buf);
				rbp = bioclone(bp, io_off, (size_t)contig,
				    bp->b_edev, bn, ud_slave_done,
				    &ms->ms_buf, KM_NOSLEEP);
				ASSERT(rbp == &ms->ms_buf);
				mm->mm_resid += contig;
				io_count++;
				ms ++;
			}
		}

		/*
		 * Start I/O's
		 */
		ms = (mio_slave_t *)(((caddr_t)mm) + sizeof (mio_master_t));
		for (i = 0; i < io_count; i++) {
			(void) bdev_strategy(&ms->ms_buf);
			ms ++;
		}
	}

end:
	if (error != 0) {
		bp->b_flags |= B_ERROR;
		bp->b_error = error;
		if (mm != NULL) {
			mutex_destroy(&mm->mm_mutex);
			kmem_free(mm, mm->mm_size);
		}
	}
	return (error);
}

int32_t
ud_slave_done(struct buf *bp)
{
	mio_master_t *mm;
	int32_t resid;

	ASSERT(SEMA_HELD(&bp->b_sem));
	ASSERT((bp->b_flags & B_DONE) == 0);

	mm = ((mio_slave_t *)bp)->ms_ptr;

	/*
	 * Propagate error and byte count info from slave struct to
	 * the master struct
	 */
	mutex_enter(&mm->mm_mutex);
	if (bp->b_flags & B_ERROR) {

		/*
		 * If multiple slave buffers get
		 * error we forget the old errors
		 * this is ok because we any way
		 * cannot return multiple errors
		 */
		mm->mm_error = bp->b_error;
	}
	mm->mm_resid -= bp->b_bcount;
	resid = mm->mm_resid;
	mutex_exit(&mm->mm_mutex);

	/*
	 * free up the resources allocated to cloned buffers.
	 */
	bp_mapout(bp);
	biofini(bp);

	if (resid == 0) {

		/*
		 * This is the last I/O operation
		 * clean up and return the original buffer
		 */
		if (mm->mm_error) {
			mm->mm_bp->b_flags |= B_ERROR;
			mm->mm_bp->b_error = mm->mm_error;
		}
		biodone(mm->mm_bp);
		mutex_destroy(&mm->mm_mutex);
		kmem_free(mm, mm->mm_size);
	}
	return (0);
}

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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/acl.h>
#include <sys/flock.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "vncache.h"

#define	O_RWMASK	(O_WRONLY | O_RDWR) /* == 3 */

int fop_shrlock_enable = 0;

int stat_to_vattr(const struct stat *, vattr_t *);
int fop__getxvattr(vnode_t *, xvattr_t *);
int fop__setxvattr(vnode_t *, xvattr_t *);


/* ARGSUSED */
int
fop_open(
	vnode_t **vpp,
	int mode,
	cred_t *cr,
	caller_context_t *ct)
{

	if ((*vpp)->v_type == VREG) {
		if (mode & FREAD)
			atomic_add_32(&((*vpp)->v_rdcnt), 1);
		if (mode & FWRITE)
			atomic_add_32(&((*vpp)->v_wrcnt), 1);
	}

	/* call to ->vop_open was here */

	return (0);
}

/* ARGSUSED */
int
fop_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{

	/* call to ->vop_close was here */

	/*
	 * Check passed in count to handle possible dups. Vnode counts are only
	 * kept on regular files
	 */
	if ((vp->v_type == VREG) && (count == 1))  {
		if (flag & FREAD) {
			ASSERT(vp->v_rdcnt > 0);
			atomic_add_32(&(vp->v_rdcnt), -1);
		}
		if (flag & FWRITE) {
			ASSERT(vp->v_wrcnt > 0);
			atomic_add_32(&(vp->v_wrcnt), -1);
		}
	}
	return (0);
}

/* ARGSUSED */
int
fop_read(
	vnode_t *vp,
	uio_t *uio,
	int ioflag,
	cred_t *cr,
	caller_context_t *ct)
{
	struct stat st;
	struct iovec *iov;
	ssize_t resid;
	size_t cnt;
	int n;

	/*
	 * If that caller asks for read beyond end of file,
	 * that causes the pread call to block.  (Ugh!)
	 * Get the file size and return what we can.
	 */
	(void) fstat(vp->v_fd, &st);
	resid = uio->uio_resid;
	if ((uio->uio_loffset + resid) > st.st_size)
		resid = st.st_size - uio->uio_loffset;

	while (resid > 0) {

		ASSERT(uio->uio_iovcnt > 0);
		iov = uio->uio_iov;

		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		cnt = iov->iov_len;
		if (cnt > resid)
			cnt = resid;

		n = pread(vp->v_fd, iov->iov_base, cnt, uio->uio_loffset);
		if (n < 0)
			return (errno);

		iov->iov_base += n;
		iov->iov_len -= n;

		uio->uio_resid -= n;
		uio->uio_loffset += n;

		resid -= n;
	}

	return (0);
}

/* ARGSUSED */
int
fop_write(
	vnode_t *vp,
	uio_t *uio,
	int ioflag,
	cred_t *cr,
	caller_context_t *ct)
{
	struct iovec *iov;
	size_t cnt;
	int n;

	while (uio->uio_resid > 0) {

		ASSERT(uio->uio_iovcnt > 0);
		iov = uio->uio_iov;

		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		cnt = iov->iov_len;
		if (cnt > uio->uio_resid)
			cnt = uio->uio_resid;

		n = pwrite(vp->v_fd, iov->iov_base, iov->iov_len,
		    uio->uio_loffset);
		if (n < 0)
			return (errno);

		iov->iov_base += n;
		iov->iov_len -= n;

		uio->uio_resid -= n;
		uio->uio_loffset += n;
	}

	if (ioflag == FSYNC) {
		(void) fsync(vp->v_fd);
	}

	return (0);
}

/* ARGSUSED */
int
fop_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_setfl(
	vnode_t *vp,
	int oflags,
	int nflags,
	cred_t *cr,
	caller_context_t *ct)
{
	/* allow any flags? See fs_setfl */
	return (0);
}

/* ARGSUSED */
int
fop_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int error;
	struct stat st;

	if (fstat(vp->v_fd, &st) == -1)
		return (errno);
	error = stat_to_vattr(&st, vap);

	if (vap->va_mask & AT_XVATTR)
		(void) fop__getxvattr(vp, (xvattr_t *)vap);

	return (error);
}

/* ARGSUSED */
int
fop_setattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	timespec_t times[2];

	if (vap->va_mask & AT_SIZE) {
		if (ftruncate(vp->v_fd, vap->va_size) == -1)
			return (errno);
	}

	/* AT_MODE or anything else? */

	if (vap->va_mask & AT_XVATTR)
		(void) fop__setxvattr(vp, (xvattr_t *)vap);

	if (vap->va_mask & (AT_ATIME | AT_MTIME)) {
		if (vap->va_mask & AT_ATIME) {
			times[0] = vap->va_atime;
		} else {
			times[0].tv_sec = 0;
			times[0].tv_nsec = UTIME_OMIT;
		}
		if (vap->va_mask & AT_MTIME) {
			times[1] = vap->va_mtime;
		} else {
			times[1].tv_sec = 0;
			times[1].tv_nsec = UTIME_OMIT;
		}

		(void) futimens(vp->v_fd, times);
	}

	return (0);
}

/* ARGSUSED */
int
fop_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
int
fop_lookup(
	vnode_t *dvp,
	char *name,
	vnode_t **vpp,
	pathname_t *pnp,
	int flags,
	vnode_t *rdir,
	cred_t *cr,
	caller_context_t *ct,
	int *deflags,		/* Returned per-dirent flags */
	pathname_t *ppnp)	/* Returned case-preserved name in directory */
{
	int fd;
	int omode = O_RDWR | O_NOFOLLOW;
	vnode_t *vp;
	struct stat st;

	if (flags & LOOKUP_XATTR)
		return (ENOENT);

	/*
	 * If lookup is for "", just return dvp.
	 */
	if (name[0] == '\0') {
		vn_hold(dvp);
		*vpp = dvp;
		return (0);
	}

	if (fstatat(dvp->v_fd, name, &st, AT_SYMLINK_NOFOLLOW) == -1)
		return (errno);

	vp = vncache_lookup(&st);
	if (vp != NULL) {
		/* lookup gave us a hold */
		*vpp = vp;
		return (0);
	}

	if (S_ISDIR(st.st_mode))
		omode = O_RDONLY | O_NOFOLLOW;

again:
	fd = openat(dvp->v_fd, name, omode, 0);
	if (fd < 0) {
		if ((omode & O_RWMASK) == O_RDWR) {
			omode &= ~O_RWMASK;
			omode |= O_RDONLY;
			goto again;
		}
		return (errno);
	}

	if (fstat(fd, &st) == -1) {
		(void) close(fd);
		return (errno);
	}

	vp = vncache_enter(&st, dvp, name, fd);

	*vpp = vp;
	return (0);
}

/* ARGSUSED */
int
fop_create(
	vnode_t *dvp,
	char *name,
	vattr_t *vap,
	vcexcl_t excl,
	int mode,
	vnode_t **vpp,
	cred_t *cr,
	int flags,
	caller_context_t *ct,
	vsecattr_t *vsecp)	/* ACL to set during create */
{
	struct stat st;
	vnode_t *vp;
	int err, fd, omode;

	/*
	 * If creating "", just return dvp.
	 */
	if (name[0] == '\0') {
		vn_hold(dvp);
		*vpp = dvp;
		return (0);
	}

	err = fstatat(dvp->v_fd, name, &st, AT_SYMLINK_NOFOLLOW);
	if (err != 0)
		err = errno;

	vp = NULL;
	if (err == 0) {
		/* The file already exists. */
		if (excl == EXCL)
			return (EEXIST);

		vp = vncache_lookup(&st);
		/* vp gained a hold */
	}

	if (vp == NULL) {
		/*
		 * Open it. (may or may not exist)
		 */
		omode = O_RDWR | O_CREAT | O_NOFOLLOW;
		if (excl == EXCL)
			omode |= O_EXCL;
	open_again:
		fd = openat(dvp->v_fd, name, omode, mode);
		if (fd < 0) {
			if ((omode & O_RWMASK) == O_RDWR) {
				omode &= ~O_RWMASK;
				omode |= O_RDONLY;
				goto open_again;
			}
			return (errno);
		}
		(void) fstat(fd, &st);

		vp = vncache_enter(&st, dvp, name, fd);
		/* vp has its initial hold */
	}

	/* Should have the vp now. */
	if (vp == NULL)
		return (EFAULT);

	if (vp->v_type == VDIR && vap->va_type != VDIR) {
		vn_rele(vp);
		return (EISDIR);
	}
	if (vp->v_type != VDIR && vap->va_type == VDIR) {
		vn_rele(vp);
		return (ENOTDIR);
	}

	/*
	 * Might need to set attributes.
	 */
	(void) fop_setattr(vp, vap, 0, cr, ct);

	*vpp = vp;
	return (0);
}

/* ARGSUSED */
int
fop_remove(
	vnode_t *dvp,
	char *name,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{

	if (unlinkat(dvp->v_fd, name, 0))
		return (errno);

	return (0);
}

/* ARGSUSED */
int
fop_link(
	vnode_t *to_dvp,
	vnode_t *fr_vp,
	char *to_name,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int err;

	/*
	 * Would prefer to specify "from" as the combination:
	 * (fr_vp->v_fd, NULL) but linkat does not permit it.
	 */
	err = linkat(AT_FDCWD, fr_vp->v_path, to_dvp->v_fd, to_name,
	    AT_SYMLINK_FOLLOW);
	if (err == -1)
		err = errno;

	return (err);
}

/* ARGSUSED */
int
fop_rename(
	vnode_t *from_dvp,
	char *from_name,
	vnode_t *to_dvp,
	char *to_name,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	struct stat st;
	vnode_t *vp;
	int err;

	if (fstatat(from_dvp->v_fd, from_name, &st,
	    AT_SYMLINK_NOFOLLOW) == -1)
		return (errno);

	vp = vncache_lookup(&st);
	if (vp == NULL)
		return (ENOENT);

	err = renameat(from_dvp->v_fd, from_name, to_dvp->v_fd, to_name);
	if (err == -1)
		err = errno;
	else
		vncache_renamed(vp, to_dvp, to_name);

	vn_rele(vp);

	return (err);
}

/* ARGSUSED */
int
fop_mkdir(
	vnode_t *dvp,
	char *name,
	vattr_t *vap,
	vnode_t **vpp,
	cred_t *cr,
	caller_context_t *ct,
	int flags,
	vsecattr_t *vsecp)	/* ACL to set during create */
{
	struct stat st;
	int err, fd;

	mode_t mode = vap->va_mode & 0777;

	if (mkdirat(dvp->v_fd, name, mode) == -1)
		return (errno);

	if ((fd = openat(dvp->v_fd, name, O_RDONLY)) == -1)
		return (errno);
	if (fstat(fd, &st) == -1) {
		err = errno;
		(void) close(fd);
		return (err);
	}

	*vpp = vncache_enter(&st, dvp, name, fd);

	/*
	 * Might need to set attributes.
	 */
	(void) fop_setattr(*vpp, vap, 0, cr, ct);

	return (0);
}

/* ARGSUSED */
int
fop_rmdir(
	vnode_t *dvp,
	char *name,
	vnode_t *cdir,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{

	if (unlinkat(dvp->v_fd, name, AT_REMOVEDIR) == -1)
		return (errno);

	return (0);
}

/* ARGSUSED */
int
fop_readdir(
	vnode_t *vp,
	uio_t *uiop,
	cred_t *cr,
	int *eofp,
	caller_context_t *ct,
	int flags)
{
	struct iovec *iov;
	int cnt;
	int error = 0;
	int fd = vp->v_fd;

	if (eofp) {
		*eofp = 0;
	}

	error = lseek(fd, uiop->uio_loffset, SEEK_SET);
	if (error == -1)
		return (errno);

	ASSERT(uiop->uio_iovcnt > 0);
	iov = uiop->uio_iov;
	if (iov->iov_len < sizeof (struct dirent))
		return (EINVAL);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	cnt = getdents(fd, (struct dirent *)(uiop->uio_iov->iov_base),
	    uiop->uio_resid);
	if (cnt == -1)
		return (errno);
	if (cnt == 0) {
		if (eofp) {
			*eofp = 1;
		}
		return (ENOENT);
	}

	iov->iov_base += cnt;
	iov->iov_len  -= cnt;
	uiop->uio_resid -= cnt;
	uiop->uio_loffset = lseek(fd, 0LL, SEEK_CUR);

	return (0);
}

/* ARGSUSED */
int
fop_symlink(
	vnode_t *dvp,
	char *linkname,
	vattr_t *vap,
	char *target,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_readlink(
	vnode_t *vp,
	uio_t *uiop,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_fsync(
	vnode_t *vp,
	int syncflag,
	cred_t *cr,
	caller_context_t *ct)
{

	if (fsync(vp->v_fd) == -1)
		return (errno);

	return (0);
}

/* ARGSUSED */
void
fop_inactive(
	vnode_t *vp,
	cred_t *cr,
	caller_context_t *ct)
{
	vncache_inactive(vp);
}

/* ARGSUSED */
int
fop_fid(
	vnode_t *vp,
	fid_t *fidp,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_rwlock(
	vnode_t *vp,
	int write_lock,
	caller_context_t *ct)
{
	/* See: fs_rwlock */
	return (-1);
}

/* ARGSUSED */
void
fop_rwunlock(
	vnode_t *vp,
	int write_lock,
	caller_context_t *ct)
{
	/* See: fs_rwunlock */
}

/* ARGSUSED */
int
fop_seek(
	vnode_t *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_cmp(
	vnode_t *vp1,
	vnode_t *vp2,
	caller_context_t *ct)
{
	/* See fs_cmp */
	return (vncache_cmp(vp1, vp2));
}

/* ARGSUSED */
int
fop_frlock(
	vnode_t *vp,
	int cmd,
	flock64_t *bfp,
	int flag,
	offset_t offset,
	struct flk_callback *flk_cbp,
	cred_t *cr,
	caller_context_t *ct)
{
	/* See fs_frlock */

	switch (cmd) {
	case F_GETLK:
	case F_SETLK_NBMAND:
	case F_SETLK:
	case F_SETLKW:
		break;
	default:
		return (EINVAL);
	}

	if (fcntl(vp->v_fd, cmd, bfp) == -1)
		return (errno);

	return (0);
}

/* ARGSUSED */
int
fop_space(
	vnode_t *vp,
	int cmd,
	flock64_t *bfp,
	int flag,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	/* See fs_frlock */

	switch (cmd) {
	case F_ALLOCSP:
	case F_FREESP:
		break;
	default:
		return (EINVAL);
	}

	if (fcntl(vp->v_fd, cmd, bfp) == -1)
		return (errno);

	return (0);
}

/* ARGSUSED */
int
fop_realvp(
	vnode_t *vp,
	vnode_t **vpp,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_getpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	uint_t *protp,
	struct page **plarr,
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_putpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_map(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_addmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_delmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_poll(
	vnode_t *vp,
	short events,
	int anyyet,
	short *reventsp,
	struct pollhead **phpp,
	caller_context_t *ct)
{
	*reventsp = 0;
	if (events & POLLIN)
		*reventsp |= POLLIN;
	if (events & POLLRDNORM)
		*reventsp |= POLLRDNORM;
	if (events & POLLRDBAND)
		*reventsp |= POLLRDBAND;
	if (events & POLLOUT)
		*reventsp |= POLLOUT;
	if (events & POLLWRBAND)
		*reventsp |= POLLWRBAND;
	*phpp = NULL; /* or fake_pollhead? */

	return (0);
}

/* ARGSUSED */
int
fop_dump(
	vnode_t *vp,
	caddr_t addr,
	offset_t lbdn,
	offset_t dblks,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/*
 * See fs_pathconf
 */
/* ARGSUSED */
int
fop_pathconf(
	vnode_t *vp,
	int cmd,
	ulong_t *valp,
	cred_t *cr,
	caller_context_t *ct)
{
	register ulong_t val;
	register int error = 0;

	switch (cmd) {

	case _PC_LINK_MAX:
		val = MAXLINK;
		break;

	case _PC_MAX_CANON:
		val = MAX_CANON;
		break;

	case _PC_MAX_INPUT:
		val = MAX_INPUT;
		break;

	case _PC_NAME_MAX:
		val = MAXNAMELEN;
		break;

	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		val = MAXPATHLEN;
		break;

	case _PC_PIPE_BUF:
		val = PIPE_BUF;
		break;

	case _PC_NO_TRUNC:
		val = (ulong_t)-1;
		break;

	case _PC_VDISABLE:
		val = _POSIX_VDISABLE;
		break;

	case _PC_CHOWN_RESTRICTED:
		val = 1; /* chown restricted enabled */
		break;

	case _PC_FILESIZEBITS:
		val = (ulong_t)-1;    /* large file support */
		break;

	case _PC_ACL_ENABLED:
		val = 0;
		break;

	case _PC_CASE_BEHAVIOR:
		val = _CASE_SENSITIVE;
		break;

	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		val = 0;
		break;

	case _PC_ACCESS_FILTERING:
		val = 0;
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error == 0)
		*valp = val;
	return (error);
}

/* ARGSUSED */
int
fop_pageio(
	vnode_t *vp,
	struct page *pp,
	u_offset_t io_off,
	size_t io_len,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_dumpctl(
	vnode_t *vp,
	int action,
	offset_t *blkp,
	caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
void
fop_dispose(
	vnode_t *vp,
	struct page *pp,
	int flag,
	int dn,
	cred_t *cr,
	caller_context_t *ct)
{
}

/* ARGSUSED */
int
fop_setsecattr(
	vnode_t *vp,
	vsecattr_t *vsap,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{
	return (0);
}

/*
 * Fake up just enough of this so we can test get/set SDs.
 */
/* ARGSUSED */
int
fop_getsecattr(
	vnode_t *vp,
	vsecattr_t *vsecattr,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{

	vsecattr->vsa_aclcnt	= 0;
	vsecattr->vsa_aclentsz	= 0;
	vsecattr->vsa_aclentp	= NULL;
	vsecattr->vsa_dfaclcnt	= 0;	/* Default ACLs are not fabricated */
	vsecattr->vsa_dfaclentp	= NULL;

	if (vsecattr->vsa_mask & (VSA_ACLCNT | VSA_ACL)) {
		aclent_t *aclentp;
		size_t aclsize;

		aclsize = sizeof (aclent_t);
		vsecattr->vsa_aclcnt = 1;
		vsecattr->vsa_aclentp = kmem_zalloc(aclsize, KM_SLEEP);
		aclentp = vsecattr->vsa_aclentp;

		aclentp->a_type = OTHER_OBJ;
		aclentp->a_perm = 0777;
		aclentp->a_id = (gid_t)-1;
		aclentp++;
	} else if (vsecattr->vsa_mask & (VSA_ACECNT | VSA_ACE)) {
		ace_t *acl;

		acl = kmem_alloc(sizeof (ace_t), KM_SLEEP);
		acl->a_who = (uint32_t)-1;
		acl->a_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
		acl->a_flags = ACE_EVERYONE;
		acl->a_access_mask  = ACE_MODIFY_PERMS;

		vsecattr->vsa_aclentp = (void *)acl;
		vsecattr->vsa_aclcnt = 1;
		vsecattr->vsa_aclentsz = sizeof (ace_t);
	}

	return (0);
}

/* ARGSUSED */
int
fop_shrlock(
	vnode_t *vp,
	int cmd,
	struct shrlock *shr,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{

	switch (cmd) {
	case F_SHARE:
	case F_SHARE_NBMAND:
	case F_UNSHARE:
		break;
	default:
		return (EINVAL);
	}

	if (!fop_shrlock_enable)
		return (0);

	if (fcntl(vp->v_fd, cmd, shr) == -1)
		return (errno);

	return (0);
}

/* ARGSUSED */
int
fop_vnevent(vnode_t *vp, vnevent_t vnevent, vnode_t *dvp, char *fnm,
    caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_reqzcbuf(vnode_t *vp, enum uio_rw ioflag, xuio_t *uiop, cred_t *cr,
    caller_context_t *ct)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
fop_retzcbuf(vnode_t *vp, xuio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	return (ENOSYS);
}


/*
 * ***************************************************************
 * other VOP support
 */

/*
 * Convert stat(2) formats to vnode types and vice versa.  (Knows about
 * numerical order of S_IFMT and vnode types.)
 */
enum vtype iftovt_tab[] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VNON
};

ushort_t vttoif_tab[] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFIFO,
	S_IFDOOR, 0, S_IFSOCK, S_IFPORT, 0
};

/*
 * stat_to_vattr()
 *
 * Convert from a stat structure to an vattr structure
 * Note: only set fields according to va_mask
 */

int
stat_to_vattr(const struct stat *st, vattr_t *vap)
{

	if (vap->va_mask & AT_TYPE)
		vap->va_type = IFTOVT(st->st_mode);

	if (vap->va_mask & AT_MODE)
		vap->va_mode = st->st_mode;

	if (vap->va_mask & AT_UID)
		vap->va_uid = st->st_uid;

	if (vap->va_mask & AT_GID)
		vap->va_gid = st->st_gid;

	if (vap->va_mask & AT_FSID)
		vap->va_fsid = st->st_dev;

	if (vap->va_mask & AT_NODEID)
		vap->va_nodeid = st->st_ino;

	if (vap->va_mask & AT_NLINK)
		vap->va_nlink = st->st_nlink;

	if (vap->va_mask & AT_SIZE)
		vap->va_size = (u_offset_t)st->st_size;

	if (vap->va_mask & AT_ATIME) {
		vap->va_atime.tv_sec  = st->st_atim.tv_sec;
		vap->va_atime.tv_nsec = st->st_atim.tv_nsec;
	}

	if (vap->va_mask & AT_MTIME) {
		vap->va_mtime.tv_sec  = st->st_mtim.tv_sec;
		vap->va_mtime.tv_nsec = st->st_mtim.tv_nsec;
	}

	if (vap->va_mask & AT_CTIME) {
		vap->va_ctime.tv_sec  = st->st_ctim.tv_sec;
		vap->va_ctime.tv_nsec = st->st_ctim.tv_nsec;
	}

	if (vap->va_mask & AT_RDEV)
		vap->va_rdev = st->st_rdev;

	if (vap->va_mask & AT_BLKSIZE)
		vap->va_blksize = (uint_t)st->st_blksize;


	if (vap->va_mask & AT_NBLOCKS)
		vap->va_nblocks = (u_longlong_t)st->st_blocks;

	if (vap->va_mask & AT_SEQ)
		vap->va_seq = 0;

	return (0);
}

/* ARGSUSED */
void
flk_init_callback(flk_callback_t *flk_cb,
	callb_cpr_t *(*cb_fcn)(flk_cb_when_t, void *), void *cbdata)
{
}

void
vn_hold(vnode_t *vp)
{
	mutex_enter(&vp->v_lock);
	vp->v_count++;
	mutex_exit(&vp->v_lock);
}

void
vn_rele(vnode_t *vp)
{
	VERIFY3U(vp->v_count, !=, 0);
	mutex_enter(&vp->v_lock);
	if (vp->v_count == 1) {
		mutex_exit(&vp->v_lock);
		vncache_inactive(vp);
	} else {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
	}
}

int
vn_has_other_opens(
	vnode_t *vp,
	v_mode_t mode)
{

	switch (mode) {
	case V_WRITE:
		if (vp->v_wrcnt > 1)
			return (V_TRUE);
		break;
	case V_RDORWR:
		if ((vp->v_rdcnt > 1) || (vp->v_wrcnt > 1))
			return (V_TRUE);
		break;
	case V_RDANDWR:
		if ((vp->v_rdcnt > 1) && (vp->v_wrcnt > 1))
			return (V_TRUE);
		break;
	case V_READ:
		if (vp->v_rdcnt > 1)
			return (V_TRUE);
		break;
	}

	return (V_FALSE);
}

/*
 * vn_is_opened() checks whether a particular file is opened and
 * whether the open is for read and/or write.
 *
 * Vnode counts are only kept on regular files (v_type=VREG).
 */
int
vn_is_opened(
	vnode_t *vp,
	v_mode_t mode)
{

	ASSERT(vp != NULL);

	switch (mode) {
	case V_WRITE:
		if (vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_RDANDWR:
		if (vp->v_rdcnt && vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_RDORWR:
		if (vp->v_rdcnt || vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_READ:
		if (vp->v_rdcnt)
			return (V_TRUE);
		break;
	}

	return (V_FALSE);
}

/*
 * vn_is_mapped() checks whether a particular file is mapped and whether
 * the file is mapped read and/or write.
 */
/* ARGSUSED */
int
vn_is_mapped(
	vnode_t *vp,
	v_mode_t mode)
{
	return (V_FALSE);
}

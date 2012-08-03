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
 *
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989 AT&T.
 *	All rights reserved.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pathconf.h>
#include <sys/utsname.h>
#include <sys/dnlc.h>
#include <sys/acl.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/sdt.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode.h>
#include <nfs/nfs_acl.h>
#include <nfs/lm.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <vm/seg_vn.h>

#include <fs/fs_subr.h>

#include <sys/ddi.h>

static int	nfs_rdwrlbn(vnode_t *, page_t *, u_offset_t, size_t, int,
			cred_t *);
static int	nfswrite(vnode_t *, caddr_t, uint_t, int, cred_t *);
static int	nfsread(vnode_t *, caddr_t, uint_t, int, size_t *, cred_t *);
static int	nfssetattr(vnode_t *, struct vattr *, int, cred_t *);
static int	nfslookup_dnlc(vnode_t *, char *, vnode_t **, cred_t *);
static int	nfslookup_otw(vnode_t *, char *, vnode_t **, cred_t *, int);
static int	nfsrename(vnode_t *, char *, vnode_t *, char *, cred_t *,
			caller_context_t *);
static int	nfsreaddir(vnode_t *, rddir_cache *, cred_t *);
static int	nfs_bio(struct buf *, cred_t *);
static int	nfs_getapage(vnode_t *, u_offset_t, size_t, uint_t *,
			page_t *[], size_t, struct seg *, caddr_t,
			enum seg_rw, cred_t *);
static void	nfs_readahead(vnode_t *, u_offset_t, caddr_t, struct seg *,
			cred_t *);
static int	nfs_sync_putapage(vnode_t *, page_t *, u_offset_t, size_t,
			int, cred_t *);
static int	nfs_sync_pageio(vnode_t *, page_t *, u_offset_t, size_t,
			int, cred_t *);
static void	nfs_delmap_callback(struct as *, void *, uint_t);

/*
 * Error flags used to pass information about certain special errors
 * which need to be handled specially.
 */
#define	NFS_EOF			-98

/*
 * These are the vnode ops routines which implement the vnode interface to
 * the networked file system.  These routines just take their parameters,
 * make them look networkish by putting the right info into interface structs,
 * and then calling the appropriate remote routine(s) to do the work.
 *
 * Note on directory name lookup cacheing:  If we detect a stale fhandle,
 * we purge the directory cache relative to that vnode.  This way, the
 * user won't get burned by the cache repeatedly.  See <nfs/rnode.h> for
 * more details on rnode locking.
 */

static int	nfs_open(vnode_t **, int, cred_t *, caller_context_t *);
static int	nfs_close(vnode_t *, int, int, offset_t, cred_t *,
			caller_context_t *);
static int	nfs_read(vnode_t *, struct uio *, int, cred_t *,
			caller_context_t *);
static int	nfs_write(vnode_t *, struct uio *, int, cred_t *,
			caller_context_t *);
static int	nfs_ioctl(vnode_t *, int, intptr_t, int, cred_t *, int *,
			caller_context_t *);
static int	nfs_getattr(vnode_t *, struct vattr *, int, cred_t *,
			caller_context_t *);
static int	nfs_setattr(vnode_t *, struct vattr *, int, cred_t *,
			caller_context_t *);
static int	nfs_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int	nfs_accessx(void *, int, cred_t *);
static int	nfs_readlink(vnode_t *, struct uio *, cred_t *,
			caller_context_t *);
static int	nfs_fsync(vnode_t *, int, cred_t *, caller_context_t *);
static void	nfs_inactive(vnode_t *, cred_t *, caller_context_t *);
static int	nfs_lookup(vnode_t *, char *, vnode_t **, struct pathname *,
			int, vnode_t *, cred_t *, caller_context_t *,
			int *, pathname_t *);
static int	nfs_create(vnode_t *, char *, struct vattr *, enum vcexcl,
			int, vnode_t **, cred_t *, int, caller_context_t *,
			vsecattr_t *);
static int	nfs_remove(vnode_t *, char *, cred_t *, caller_context_t *,
			int);
static int	nfs_link(vnode_t *, vnode_t *, char *, cred_t *,
			caller_context_t *, int);
static int	nfs_rename(vnode_t *, char *, vnode_t *, char *, cred_t *,
			caller_context_t *, int);
static int	nfs_mkdir(vnode_t *, char *, struct vattr *, vnode_t **,
			cred_t *, caller_context_t *, int, vsecattr_t *);
static int	nfs_rmdir(vnode_t *, char *, vnode_t *, cred_t *,
			caller_context_t *, int);
static int	nfs_symlink(vnode_t *, char *, struct vattr *, char *,
			cred_t *, caller_context_t *, int);
static int	nfs_readdir(vnode_t *, struct uio *, cred_t *, int *,
			caller_context_t *, int);
static int	nfs_fid(vnode_t *, fid_t *, caller_context_t *);
static int	nfs_rwlock(vnode_t *, int, caller_context_t *);
static void	nfs_rwunlock(vnode_t *, int, caller_context_t *);
static int	nfs_seek(vnode_t *, offset_t, offset_t *, caller_context_t *);
static int	nfs_getpage(vnode_t *, offset_t, size_t, uint_t *,
			page_t *[], size_t, struct seg *, caddr_t,
			enum seg_rw, cred_t *, caller_context_t *);
static int	nfs_putpage(vnode_t *, offset_t, size_t, int, cred_t *,
			caller_context_t *);
static int	nfs_map(vnode_t *, offset_t, struct as *, caddr_t *, size_t,
			uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int	nfs_addmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
			uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int	nfs_frlock(vnode_t *, int, struct flock64 *, int, offset_t,
			struct flk_callback *, cred_t *, caller_context_t *);
static int	nfs_space(vnode_t *, int, struct flock64 *, int, offset_t,
			cred_t *, caller_context_t *);
static int	nfs_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int	nfs_delmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
			uint_t, uint_t, uint_t, cred_t *, caller_context_t *);
static int	nfs_pathconf(vnode_t *, int, ulong_t *, cred_t *,
			caller_context_t *);
static int	nfs_pageio(vnode_t *, page_t *, u_offset_t, size_t, int,
			cred_t *, caller_context_t *);
static int	nfs_setsecattr(vnode_t *, vsecattr_t *, int, cred_t *,
			caller_context_t *);
static int	nfs_getsecattr(vnode_t *, vsecattr_t *, int, cred_t *,
			caller_context_t *);
static int	nfs_shrlock(vnode_t *, int, struct shrlock *, int, cred_t *,
			caller_context_t *);

struct vnodeops *nfs_vnodeops;

const fs_operation_def_t nfs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = nfs_open },
	VOPNAME_CLOSE,		{ .vop_close = nfs_close },
	VOPNAME_READ,		{ .vop_read = nfs_read },
	VOPNAME_WRITE,		{ .vop_write = nfs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = nfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = nfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = nfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = nfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = nfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = nfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = nfs_remove },
	VOPNAME_LINK,		{ .vop_link = nfs_link },
	VOPNAME_RENAME,		{ .vop_rename = nfs_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = nfs_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = nfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = nfs_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = nfs_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = nfs_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = nfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = nfs_inactive },
	VOPNAME_FID,		{ .vop_fid = nfs_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = nfs_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = nfs_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = nfs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = nfs_frlock },
	VOPNAME_SPACE,		{ .vop_space = nfs_space },
	VOPNAME_REALVP,		{ .vop_realvp = nfs_realvp },
	VOPNAME_GETPAGE,	{ .vop_getpage = nfs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = nfs_putpage },
	VOPNAME_MAP,		{ .vop_map = nfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = nfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = nfs_delmap },
	VOPNAME_DUMP,		{ .vop_dump = nfs_dump },
	VOPNAME_PATHCONF,	{ .vop_pathconf = nfs_pathconf },
	VOPNAME_PAGEIO,		{ .vop_pageio = nfs_pageio },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = nfs_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = nfs_getsecattr },
	VOPNAME_SHRLOCK,	{ .vop_shrlock = nfs_shrlock },
	VOPNAME_VNEVENT, 	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * XXX:  This is referenced in modstubs.s
 */
struct vnodeops *
nfs_getvnodeops(void)
{
	return (nfs_vnodeops);
}

/* ARGSUSED */
static int
nfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	int error;
	struct vattr va;
	rnode_t *rp;
	vnode_t *vp;

	vp = *vpp;
	rp = VTOR(vp);
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	mutex_enter(&rp->r_statelock);
	if (rp->r_cred == NULL) {
		crhold(cr);
		rp->r_cred = cr;
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * If there is no cached data or if close-to-open
	 * consistency checking is turned off, we can avoid
	 * the over the wire getattr.  Otherwise, if the
	 * file system is mounted readonly, then just verify
	 * the caches are up to date using the normal mechanism.
	 * Else, if the file is not mmap'd, then just mark
	 * the attributes as timed out.  They will be refreshed
	 * and the caches validated prior to being used.
	 * Else, the file system is mounted writeable so
	 * force an over the wire GETATTR in order to ensure
	 * that all cached data is valid.
	 */
	if (vp->v_count > 1 ||
	    ((vn_has_cached_data(vp) || HAVE_RDDIR_CACHE(rp)) &&
	    !(VTOMI(vp)->mi_flags & MI_NOCTO))) {
		if (vn_is_readonly(vp))
			error = nfs_validate_caches(vp, cr);
		else if (rp->r_mapcnt == 0 && vp->v_count == 1) {
			PURGE_ATTRCACHE(vp);
			error = 0;
		} else {
			va.va_mask = AT_ALL;
			error = nfs_getattr_otw(vp, &va, cr);
		}
	} else
		error = 0;

	return (error);
}

/* ARGSUSED */
static int
nfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	rnode_t *rp;
	int error;
	struct vattr va;

	/*
	 * zone_enter(2) prevents processes from changing zones with NFS files
	 * open; if we happen to get here from the wrong zone we can't do
	 * anything over the wire.
	 */
	if (VTOMI(vp)->mi_zone != nfs_zone()) {
		/*
		 * We could attempt to clean up locks, except we're sure
		 * that the current process didn't acquire any locks on
		 * the file: any attempt to lock a file belong to another zone
		 * will fail, and one can't lock an NFS file and then change
		 * zones, as that fails too.
		 *
		 * Returning an error here is the sane thing to do.  A
		 * subsequent call to VN_RELE() which translates to a
		 * nfs_inactive() will clean up state: if the zone of the
		 * vnode's origin is still alive and kicking, an async worker
		 * thread will handle the request (from the correct zone), and
		 * everything (minus the final nfs_getattr_otw() call) should
		 * be OK. If the zone is going away nfs_async_inactive() will
		 * throw away cached pages inline.
		 */
		return (EIO);
	}

	/*
	 * If we are using local locking for this filesystem, then
	 * release all of the SYSV style record locks.  Otherwise,
	 * we are doing network locking and we need to release all
	 * of the network locks.  All of the locks held by this
	 * process on this file are released no matter what the
	 * incoming reference count is.
	 */
	if (VTOMI(vp)->mi_flags & MI_LLOCK) {
		cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
		cleanshares(vp, ttoproc(curthread)->p_pid);
	} else
		nfs_lockrelease(vp, flag, offset, cr);

	if (count > 1)
		return (0);

	/*
	 * If the file has been `unlinked', then purge the
	 * DNLC so that this vnode will get reycled quicker
	 * and the .nfs* file on the server will get removed.
	 */
	rp = VTOR(vp);
	if (rp->r_unldvp != NULL)
		dnlc_purge_vp(vp);

	/*
	 * If the file was open for write and there are pages,
	 * then if the file system was mounted using the "no-close-
	 *	to-open" semantics, then start an asynchronous flush
	 *	of the all of the pages in the file.
	 * else the file system was not mounted using the "no-close-
	 *	to-open" semantics, then do a synchronous flush and
	 *	commit of all of the dirty and uncommitted pages.
	 *
	 * The asynchronous flush of the pages in the "nocto" path
	 * mostly just associates a cred pointer with the rnode so
	 * writes which happen later will have a better chance of
	 * working.  It also starts the data being written to the
	 * server, but without unnecessarily delaying the application.
	 */
	if ((flag & FWRITE) && vn_has_cached_data(vp)) {
		if ((VTOMI(vp)->mi_flags & MI_NOCTO)) {
			error = nfs_putpage(vp, (offset_t)0, 0, B_ASYNC,
			    cr, ct);
			if (error == EAGAIN)
				error = 0;
		} else
			error = nfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
		if (!error) {
			mutex_enter(&rp->r_statelock);
			error = rp->r_error;
			rp->r_error = 0;
			mutex_exit(&rp->r_statelock);
		}
	} else {
		mutex_enter(&rp->r_statelock);
		error = rp->r_error;
		rp->r_error = 0;
		mutex_exit(&rp->r_statelock);
	}

	/*
	 * If RWRITEATTR is set, then issue an over the wire GETATTR to
	 * refresh the attribute cache with a set of attributes which
	 * weren't returned from a WRITE.  This will enable the close-
	 * to-open processing to work.
	 */
	if (rp->r_flags & RWRITEATTR)
		(void) nfs_getattr_otw(vp, &va, cr);

	return (error);
}

/* ARGSUSED */
static int
nfs_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	rnode_t *rp;
	u_offset_t off;
	offset_t diff;
	int on;
	size_t n;
	caddr_t base;
	uint_t flags;
	int error;
	mntinfo_t *mi;

	rp = VTOR(vp);
	mi = VTOMI(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);

	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_READER));

	if (vp->v_type != VREG)
		return (EISDIR);

	if (uiop->uio_resid == 0)
		return (0);

	if (uiop->uio_loffset > MAXOFF32_T)
		return (EFBIG);

	if (uiop->uio_loffset < 0 ||
	    uiop->uio_loffset + uiop->uio_resid > MAXOFF32_T)
		return (EINVAL);

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((rp->r_flags & RDIRECTIO) || (mi->mi_flags & MI_DIRECTIO)) &&
	    rp->r_mapcnt == 0 && rp->r_inmap == 0 &&
	    !vn_has_cached_data(vp))) {
		size_t bufsize;
		size_t resid = 0;

		/*
		 * Let's try to do read in as large a chunk as we can
		 * (Filesystem (NFS client) bsize if possible/needed).
		 * For V3, this is 32K and for V2, this is 8K.
		 */
		bufsize = MIN(uiop->uio_resid, VTOMI(vp)->mi_curread);
		base = kmem_alloc(bufsize, KM_SLEEP);
		do {
			n = MIN(uiop->uio_resid, bufsize);
			error = nfsread(vp, base, uiop->uio_offset, n,
			    &resid, cr);
			if (!error) {
				n -= resid;
				error = uiomove(base, n, UIO_READ, uiop);
			}
		} while (!error && uiop->uio_resid > 0 && n > 0);
		kmem_free(base, bufsize);
		return (error);
	}

	error = 0;

	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		error = nfs_validate_caches(vp, cr);
		if (error)
			break;

		mutex_enter(&rp->r_statelock);
		while (rp->r_flags & RINCACHEPURGE) {
			if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
				mutex_exit(&rp->r_statelock);
				return (EINTR);
			}
		}
		diff = rp->r_size - uiop->uio_loffset;
		mutex_exit(&rp->r_statelock);
		if (diff <= 0)
			break;
		if (diff < n)
			n = (size_t)diff;

		if (vpm_enable) {
			/*
			 * Copy data.
			 */
			error = vpm_data_copy(vp, off + on, n, uiop,
			    1, NULL, 0, S_READ);
		} else {
			base = segmap_getmapflt(segkmap, vp, off + on, n,
			    1, S_READ);
			error = uiomove(base + on, n, UIO_READ, uiop);
		}

		if (!error) {
			/*
			 * If read a whole block or read to eof,
			 * won't need this buffer again soon.
			 */
			mutex_enter(&rp->r_statelock);
			if (n + on == MAXBSIZE ||
			    uiop->uio_loffset == rp->r_size)
				flags = SM_DONTNEED;
			else
				flags = 0;
			mutex_exit(&rp->r_statelock);
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
		}
	} while (!error && uiop->uio_resid > 0);

	return (error);
}

/* ARGSUSED */
static int
nfs_write(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	rnode_t *rp;
	u_offset_t off;
	caddr_t base;
	uint_t flags;
	int remainder;
	size_t n;
	int on;
	int error;
	int resid;
	offset_t offset;
	rlim_t limit;
	mntinfo_t *mi;

	rp = VTOR(vp);

	mi = VTOMI(vp);
	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (vp->v_type != VREG)
		return (EISDIR);

	if (uiop->uio_resid == 0)
		return (0);

	if (ioflag & FAPPEND) {
		struct vattr va;

		/*
		 * Must serialize if appending.
		 */
		if (nfs_rw_lock_held(&rp->r_rwlock, RW_READER)) {
			nfs_rw_exit(&rp->r_rwlock);
			if (nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER,
			    INTR(vp)))
				return (EINTR);
		}

		va.va_mask = AT_SIZE;
		error = nfsgetattr(vp, &va, cr);
		if (error)
			return (error);
		uiop->uio_loffset = va.va_size;
	}

	if (uiop->uio_loffset > MAXOFF32_T)
		return (EFBIG);

	offset = uiop->uio_loffset + uiop->uio_resid;

	if (uiop->uio_loffset < 0 || offset > MAXOFF32_T)
		return (EINVAL);

	if (uiop->uio_llimit > (rlim64_t)MAXOFF32_T) {
		limit = MAXOFF32_T;
	} else {
		limit = (rlim_t)uiop->uio_llimit;
	}

	/*
	 * Check to make sure that the process will not exceed
	 * its limit on file size.  It is okay to write up to
	 * the limit, but not beyond.  Thus, the write which
	 * reaches the limit will be short and the next write
	 * will return an error.
	 */
	remainder = 0;
	if (offset > limit) {
		remainder = offset - limit;
		uiop->uio_resid = limit - uiop->uio_offset;
		if (uiop->uio_resid <= 0) {
			proc_t *p = ttoproc(curthread);

			uiop->uio_resid += remainder;
			mutex_enter(&p->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    p->p_rctls, p, RCA_UNSAFE_SIGINFO);
			mutex_exit(&p->p_lock);
			return (EFBIG);
		}
	}

	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_READER, INTR(vp)))
		return (EINTR);

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((rp->r_flags & RDIRECTIO) || (mi->mi_flags & MI_DIRECTIO)) &&
	    rp->r_mapcnt == 0 && rp->r_inmap == 0 &&
	    !vn_has_cached_data(vp))) {
		size_t bufsize;
		int count;
		uint_t org_offset;

nfs_fwrite:
		if (rp->r_flags & RSTALE) {
			resid = uiop->uio_resid;
			offset = uiop->uio_loffset;
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			goto bottom;
		}
		bufsize = MIN(uiop->uio_resid, mi->mi_curwrite);
		base = kmem_alloc(bufsize, KM_SLEEP);
		do {
			resid = uiop->uio_resid;
			offset = uiop->uio_loffset;
			count = MIN(uiop->uio_resid, bufsize);
			org_offset = uiop->uio_offset;
			error = uiomove(base, count, UIO_WRITE, uiop);
			if (!error) {
				error = nfswrite(vp, base, org_offset,
				    count, cr);
			}
		} while (!error && uiop->uio_resid > 0);
		kmem_free(base, bufsize);
		goto bottom;
	}

	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		resid = uiop->uio_resid;
		offset = uiop->uio_loffset;

		if (rp->r_flags & RSTALE) {
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			break;
		}

		/*
		 * Don't create dirty pages faster than they
		 * can be cleaned so that the system doesn't
		 * get imbalanced.  If the async queue is
		 * maxed out, then wait for it to drain before
		 * creating more dirty pages.  Also, wait for
		 * any threads doing pagewalks in the vop_getattr
		 * entry points so that they don't block for
		 * long periods.
		 */
		mutex_enter(&rp->r_statelock);
		while ((mi->mi_max_threads != 0 &&
		    rp->r_awcount > 2 * mi->mi_max_threads) ||
		    rp->r_gcount > 0) {
			if (INTR(vp)) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
					mutex_exit(&rp->r_statelock);
					if (lwp != NULL)
						lwp->lwp_nostop--;
					error = EINTR;
					goto bottom;
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
				cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)n, uiop);

		if (vpm_enable) {
			/*
			 * It will use kpm mappings, so no need to
			 * pass an address.
			 */
			error = writerp(rp, NULL, n, uiop, 0);
		} else  {
			if (segmap_kpm) {
				int pon = uiop->uio_loffset & PAGEOFFSET;
				size_t pn = MIN(PAGESIZE - pon,
				    uiop->uio_resid);
				int pagecreate;

				mutex_enter(&rp->r_statelock);
				pagecreate = (pon == 0) && (pn == PAGESIZE ||
				    uiop->uio_loffset + pn >= rp->r_size);
				mutex_exit(&rp->r_statelock);

				base = segmap_getmapflt(segkmap, vp, off + on,
				    pn, !pagecreate, S_WRITE);

				error = writerp(rp, base + pon, n, uiop,
				    pagecreate);

			} else {
				base = segmap_getmapflt(segkmap, vp, off + on,
				    n, 0, S_READ);
				error = writerp(rp, base + on, n, uiop, 0);
			}
		}

		if (!error) {
			if (mi->mi_flags & MI_NOAC)
				flags = SM_WRITE;
			else if (n + on == MAXBSIZE || IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write
				 * and mark the buffer to
				 * indicate that it won't be
				 * needed again soon.
				 */
				flags = SM_WRITE | SM_ASYNC | SM_DONTNEED;
			} else
				flags = 0;
			if ((ioflag & (FSYNC|FDSYNC)) ||
			    (rp->r_flags & ROUTOFSPACE)) {
				flags &= ~SM_ASYNC;
				flags |= SM_WRITE;
			}
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
			/*
			 * In the event that we got an access error while
			 * faulting in a page for a write-only file just
			 * force a write.
			 */
			if (error == EACCES)
				goto nfs_fwrite;
		}
	} while (!error && uiop->uio_resid > 0);

bottom:
	if (error) {
		uiop->uio_resid = resid + remainder;
		uiop->uio_loffset = offset;
	} else
		uiop->uio_resid += remainder;

	nfs_rw_exit(&rp->r_lkserlock);

	return (error);
}

/*
 * Flags are composed of {B_ASYNC, B_INVAL, B_FREE, B_DONTNEED}
 */
static int
nfs_rdwrlbn(vnode_t *vp, page_t *pp, u_offset_t off, size_t len,
	int flags, cred_t *cr)
{
	struct buf *bp;
	int error;

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);
	bp = pageio_setup(pp, len, vp, flags);
	ASSERT(bp != NULL);

	/*
	 * pageio_setup should have set b_addr to 0.  This
	 * is correct since we want to do I/O on a page
	 * boundary.  bp_mapin will use this addr to calculate
	 * an offset, and then set b_addr to the kernel virtual
	 * address it allocated for us.
	 */
	ASSERT(bp->b_un.b_addr == 0);

	bp->b_edev = 0;
	bp->b_dev = 0;
	bp->b_lblkno = lbtodb(off);
	bp->b_file = vp;
	bp->b_offset = (offset_t)off;
	bp_mapin(bp);

	error = nfs_bio(bp, cr);

	bp_mapout(bp);
	pageio_done(bp);

	return (error);
}

/*
 * Write to file.  Writes to remote server in largest size
 * chunks that the server can handle.  Write is synchronous.
 */
static int
nfswrite(vnode_t *vp, caddr_t base, uint_t offset, int count, cred_t *cr)
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfswriteargs wa;
	struct nfsattrstat ns;
	int error;
	int tsize;
	int douprintf;

	douprintf = 1;

	rp = VTOR(vp);
	mi = VTOMI(vp);

	ASSERT(nfs_zone() == mi->mi_zone);

	wa.wa_args = &wa.wa_args_buf;
	wa.wa_fhandle = *VTOFH(vp);

	do {
		tsize = MIN(mi->mi_curwrite, count);
		wa.wa_data = base;
		wa.wa_begoff = offset;
		wa.wa_totcount = tsize;
		wa.wa_count = tsize;
		wa.wa_offset = offset;

		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}
		wa.wa_mblk = NULL;
		do {
			error = rfs2call(mi, RFS_WRITE,
			    xdr_writeargs, (caddr_t)&wa,
			    xdr_attrstat, (caddr_t)&ns, cr,
			    &douprintf, &ns.ns_status, 0, NULL);
		} while (error == ENFS_TRYAGAIN);
		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		if (!error) {
			error = geterrno(ns.ns_status);
			/*
			 * Can't check for stale fhandle and purge caches
			 * here because pages are held by nfs_getpage.
			 * Just mark the attribute cache as timed out
			 * and set RWRITEATTR to indicate that the file
			 * was modified with a WRITE operation.
			 */
			if (!error) {
				count -= tsize;
				base += tsize;
				offset += tsize;
				if (mi->mi_io_kstats) {
					mutex_enter(&mi->mi_lock);
					KSTAT_IO_PTR(mi->mi_io_kstats)->
					    writes++;
					KSTAT_IO_PTR(mi->mi_io_kstats)->
					    nwritten += tsize;
					mutex_exit(&mi->mi_lock);
				}
				lwp_stat_update(LWP_STAT_OUBLK, 1);
				mutex_enter(&rp->r_statelock);
				PURGE_ATTRCACHE_LOCKED(rp);
				rp->r_flags |= RWRITEATTR;
				mutex_exit(&rp->r_statelock);
			}
		}
	} while (!error && count);

	return (error);
}

/*
 * Read from a file.  Reads data in largest chunks our interface can handle.
 */
static int
nfsread(vnode_t *vp, caddr_t base, uint_t offset,
    int count, size_t *residp, cred_t *cr)
{
	mntinfo_t *mi;
	struct nfsreadargs ra;
	struct nfsrdresult rr;
	int tsize;
	int error;
	int douprintf;
	failinfo_t fi;
	rnode_t *rp;
	struct vattr va;
	hrtime_t t;

	rp = VTOR(vp);
	mi = VTOMI(vp);

	ASSERT(nfs_zone() == mi->mi_zone);

	douprintf = 1;

	ra.ra_fhandle = *VTOFH(vp);

	fi.vp = vp;
	fi.fhp = (caddr_t)&ra.ra_fhandle;
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	do {
		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		do {
			tsize = MIN(mi->mi_curread, count);
			rr.rr_data = base;
			ra.ra_offset = offset;
			ra.ra_totcount = tsize;
			ra.ra_count = tsize;
			ra.ra_data = base;
			t = gethrtime();
			error = rfs2call(mi, RFS_READ,
			    xdr_readargs, (caddr_t)&ra,
			    xdr_rdresult, (caddr_t)&rr, cr,
			    &douprintf, &rr.rr_status, 0, &fi);
		} while (error == ENFS_TRYAGAIN);

		if (mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		if (!error) {
			error = geterrno(rr.rr_status);
			if (!error) {
				count -= rr.rr_count;
				base += rr.rr_count;
				offset += rr.rr_count;
				if (mi->mi_io_kstats) {
					mutex_enter(&mi->mi_lock);
					KSTAT_IO_PTR(mi->mi_io_kstats)->reads++;
					KSTAT_IO_PTR(mi->mi_io_kstats)->nread +=
					    rr.rr_count;
					mutex_exit(&mi->mi_lock);
				}
				lwp_stat_update(LWP_STAT_INBLK, 1);
			}
		}
	} while (!error && count && rr.rr_count == tsize);

	*residp = count;

	if (!error) {
		/*
		 * Since no error occurred, we have the current
		 * attributes and we need to do a cache check and then
		 * potentially update the cached attributes.  We can't
		 * use the normal attribute check and cache mechanisms
		 * because they might cause a cache flush which would
		 * deadlock.  Instead, we just check the cache to see
		 * if the attributes have changed.  If it is, then we
		 * just mark the attributes as out of date.  The next
		 * time that the attributes are checked, they will be
		 * out of date, new attributes will be fetched, and
		 * the page cache will be flushed.  If the attributes
		 * weren't changed, then we just update the cached
		 * attributes with these attributes.
		 */
		/*
		 * If NFS_ACL is supported on the server, then the
		 * attributes returned by server may have minimal
		 * permissions sometimes denying access to users having
		 * proper access.  To get the proper attributes, mark
		 * the attributes as expired so that they will be
		 * regotten via the NFS_ACL GETATTR2 procedure.
		 */
		error = nattr_to_vattr(vp, &rr.rr_attr, &va);
		mutex_enter(&rp->r_statelock);
		if (error || !CACHE_VALID(rp, va.va_mtime, va.va_size) ||
		    (mi->mi_flags & MI_ACL)) {
			mutex_exit(&rp->r_statelock);
			PURGE_ATTRCACHE(vp);
		} else {
			if (rp->r_mtime <= t) {
				nfs_attrcache_va(vp, &va);
			}
			mutex_exit(&rp->r_statelock);
		}
	}

	return (error);
}

/* ARGSUSED */
static int
nfs_ioctl(vnode_t *vp, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp,
	caller_context_t *ct)
{

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	switch (cmd) {
		case _FIODIRECTIO:
			return (nfs_directio(vp, (int)arg, cr));
		default:
			return (ENOTTY);
	}
}

/* ARGSUSED */
static int
nfs_getattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	rnode_t *rp;

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	/*
	 * If it has been specified that the return value will
	 * just be used as a hint, and we are only being asked
	 * for size, fsid or rdevid, then return the client's
	 * notion of these values without checking to make sure
	 * that the attribute cache is up to date.
	 * The whole point is to avoid an over the wire GETATTR
	 * call.
	 */
	rp = VTOR(vp);
	if (flags & ATTR_HINT) {
		if (vap->va_mask ==
		    (vap->va_mask & (AT_SIZE | AT_FSID | AT_RDEV))) {
			mutex_enter(&rp->r_statelock);
			if (vap->va_mask | AT_SIZE)
				vap->va_size = rp->r_size;
			if (vap->va_mask | AT_FSID)
				vap->va_fsid = rp->r_attr.va_fsid;
			if (vap->va_mask | AT_RDEV)
				vap->va_rdev = rp->r_attr.va_rdev;
			mutex_exit(&rp->r_statelock);
			return (0);
		}
	}

	/*
	 * Only need to flush pages if asking for the mtime
	 * and if there any dirty pages or any outstanding
	 * asynchronous (write) requests for this file.
	 */
	if (vap->va_mask & AT_MTIME) {
		if (vn_has_cached_data(vp) &&
		    ((rp->r_flags & RDIRTY) || rp->r_awcount > 0)) {
			mutex_enter(&rp->r_statelock);
			rp->r_gcount++;
			mutex_exit(&rp->r_statelock);
			error = nfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
			mutex_enter(&rp->r_statelock);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				if (!rp->r_error)
					rp->r_error = error;
			}
			if (--rp->r_gcount == 0)
				cv_broadcast(&rp->r_cv);
			mutex_exit(&rp->r_statelock);
		}
	}

	return (nfsgetattr(vp, vap, cr));
}

/*ARGSUSED4*/
static int
nfs_setattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
		caller_context_t *ct)
{
	int error;
	uint_t mask;
	struct vattr va;

	mask = vap->va_mask;

	if (mask & AT_NOSET)
		return (EINVAL);

	if ((mask & AT_SIZE) &&
	    vap->va_type == VREG &&
	    vap->va_size > MAXOFF32_T)
		return (EFBIG);

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	va.va_mask = AT_UID | AT_MODE;

	error = nfsgetattr(vp, &va, cr);
	if (error)
		return (error);

	error = secpolicy_vnode_setattr(cr, vp, vap, &va, flags, nfs_accessx,
	    vp);

	if (error)
		return (error);

	error = nfssetattr(vp, vap, flags, cr);

	if (error == 0 && (mask & AT_SIZE) && vap->va_size == 0)
		vnevent_truncate(vp, ct);

	return (error);
}

static int
nfssetattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr)
{
	int error;
	uint_t mask;
	struct nfssaargs args;
	struct nfsattrstat ns;
	int douprintf;
	rnode_t *rp;
	struct vattr va;
	mode_t omode;
	mntinfo_t *mi;
	vsecattr_t *vsp;
	hrtime_t t;

	mask = vap->va_mask;

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);

	rp = VTOR(vp);

	/*
	 * Only need to flush pages if there are any pages and
	 * if the file is marked as dirty in some fashion.  The
	 * file must be flushed so that we can accurately
	 * determine the size of the file and the cached data
	 * after the SETATTR returns.  A file is considered to
	 * be dirty if it is either marked with RDIRTY, has
	 * outstanding i/o's active, or is mmap'd.  In this
	 * last case, we can't tell whether there are dirty
	 * pages, so we flush just to be sure.
	 */
	if (vn_has_cached_data(vp) &&
	    ((rp->r_flags & RDIRTY) ||
	    rp->r_count > 0 ||
	    rp->r_mapcnt > 0)) {
		ASSERT(vp->v_type != VCHR);
		error = nfs_putpage(vp, (offset_t)0, 0, 0, cr, NULL);
		if (error && (error == ENOSPC || error == EDQUOT)) {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = error;
			mutex_exit(&rp->r_statelock);
		}
	}

	/*
	 * If the system call was utime(2) or utimes(2) and the
	 * application did not specify the times, then set the
	 * mtime nanosecond field to 1 billion.  This will get
	 * translated from 1 billion nanoseconds to 1 million
	 * microseconds in the over the wire request.  The
	 * server will use 1 million in the microsecond field
	 * to tell whether both the mtime and atime should be
	 * set to the server's current time.
	 *
	 * This is an overload of the protocol and should be
	 * documented in the NFS Version 2 protocol specification.
	 */
	if ((mask & AT_MTIME) && !(flags & ATTR_UTIME)) {
		vap->va_mtime.tv_nsec = 1000000000;
		if (NFS_TIME_T_OK(vap->va_mtime.tv_sec) &&
		    NFS_TIME_T_OK(vap->va_atime.tv_sec)) {
			error = vattr_to_sattr(vap, &args.saa_sa);
		} else {
			/*
			 * Use server times. vap time values will not be used.
			 * To ensure no time overflow, make sure vap has
			 * valid values, but retain the original values.
			 */
			timestruc_t	mtime = vap->va_mtime;
			timestruc_t	atime = vap->va_atime;
			time_t		now;

			now = gethrestime_sec();
			if (NFS_TIME_T_OK(now)) {
				/* Just in case server does not know of this */
				vap->va_mtime.tv_sec = now;
				vap->va_atime.tv_sec = now;
			} else {
				vap->va_mtime.tv_sec = 0;
				vap->va_atime.tv_sec = 0;
			}
			error = vattr_to_sattr(vap, &args.saa_sa);
			/* set vap times back on */
			vap->va_mtime = mtime;
			vap->va_atime = atime;
		}
	} else {
		/* Either do not set times or use the client specified times */
		error = vattr_to_sattr(vap, &args.saa_sa);
	}
	if (error) {
		/* req time field(s) overflow - return immediately */
		return (error);
	}
	args.saa_fh = *VTOFH(vp);

	va.va_mask = AT_MODE;
	error = nfsgetattr(vp, &va, cr);
	if (error)
		return (error);
	omode = va.va_mode;

	mi = VTOMI(vp);

	douprintf = 1;

	t = gethrtime();

	error = rfs2call(mi, RFS_SETATTR,
	    xdr_saargs, (caddr_t)&args,
	    xdr_attrstat, (caddr_t)&ns, cr,
	    &douprintf, &ns.ns_status, 0, NULL);

	/*
	 * Purge the access cache and ACL cache if changing either the
	 * owner of the file, the group owner, or the mode.  These may
	 * change the access permissions of the file, so purge old
	 * information and start over again.
	 */
	if ((mask & (AT_UID | AT_GID | AT_MODE)) && (mi->mi_flags & MI_ACL)) {
		(void) nfs_access_purge_rp(rp);
		if (rp->r_secattr != NULL) {
			mutex_enter(&rp->r_statelock);
			vsp = rp->r_secattr;
			rp->r_secattr = NULL;
			mutex_exit(&rp->r_statelock);
			if (vsp != NULL)
				nfs_acl_free(vsp);
		}
	}

	if (!error) {
		error = geterrno(ns.ns_status);
		if (!error) {
			/*
			 * If changing the size of the file, invalidate
			 * any local cached data which is no longer part
			 * of the file.  We also possibly invalidate the
			 * last page in the file.  We could use
			 * pvn_vpzero(), but this would mark the page as
			 * modified and require it to be written back to
			 * the server for no particularly good reason.
			 * This way, if we access it, then we bring it
			 * back in.  A read should be cheaper than a
			 * write.
			 */
			if (mask & AT_SIZE) {
				nfs_invalidate_pages(vp,
				    (vap->va_size & PAGEMASK), cr);
			}
			(void) nfs_cache_fattr(vp, &ns.ns_attr, &va, t, cr);
			/*
			 * If NFS_ACL is supported on the server, then the
			 * attributes returned by server may have minimal
			 * permissions sometimes denying access to users having
			 * proper access.  To get the proper attributes, mark
			 * the attributes as expired so that they will be
			 * regotten via the NFS_ACL GETATTR2 procedure.
			 */
			if (mi->mi_flags & MI_ACL) {
				PURGE_ATTRCACHE(vp);
			}
			/*
			 * This next check attempts to deal with NFS
			 * servers which can not handle increasing
			 * the size of the file via setattr.  Most
			 * of these servers do not return an error,
			 * but do not change the size of the file.
			 * Hence, this check and then attempt to set
			 * the file size by writing 1 byte at the
			 * offset of the end of the file that we need.
			 */
			if ((mask & AT_SIZE) &&
			    ns.ns_attr.na_size < (uint32_t)vap->va_size) {
				char zb = '\0';

				error = nfswrite(vp, &zb,
				    vap->va_size - sizeof (zb),
				    sizeof (zb), cr);
			}
			/*
			 * Some servers will change the mode to clear the setuid
			 * and setgid bits when changing the uid or gid.  The
			 * client needs to compensate appropriately.
			 */
			if (mask & (AT_UID | AT_GID)) {
				int terror;

				va.va_mask = AT_MODE;
				terror = nfsgetattr(vp, &va, cr);
				if (!terror &&
				    (((mask & AT_MODE) &&
				    va.va_mode != vap->va_mode) ||
				    (!(mask & AT_MODE) &&
				    va.va_mode != omode))) {
					va.va_mask = AT_MODE;
					if (mask & AT_MODE)
						va.va_mode = vap->va_mode;
					else
						va.va_mode = omode;
					(void) nfssetattr(vp, &va, 0, cr);
				}
			}
		} else {
			PURGE_ATTRCACHE(vp);
			PURGE_STALE_FH(error, vp, cr);
		}
	} else {
		PURGE_ATTRCACHE(vp);
	}

	return (error);
}

static int
nfs_accessx(void *vp, int mode, cred_t *cr)
{
	ASSERT(nfs_zone() == VTOMI((vnode_t *)vp)->mi_zone);
	return (nfs_access(vp, mode, 0, cr, NULL));
}

/* ARGSUSED */
static int
nfs_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	struct vattr va;
	int error;
	mntinfo_t *mi;
	int shift = 0;

	mi = VTOMI(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (mi->mi_flags & MI_ACL) {
		error = acl_access2(vp, mode, flags, cr);
		if (mi->mi_flags & MI_ACL)
			return (error);
	}

	va.va_mask = AT_MODE | AT_UID | AT_GID;
	error = nfsgetattr(vp, &va, cr);
	if (error)
		return (error);

	/*
	 * Disallow write attempts on read-only
	 * file systems, unless the file is a
	 * device node.
	 */
	if ((mode & VWRITE) && vn_is_readonly(vp) && !IS_DEVVP(vp))
		return (EROFS);

	/*
	 * Disallow attempts to access mandatory lock files.
	 */
	if ((mode & (VWRITE | VREAD | VEXEC)) &&
	    MANDLOCK(vp, va.va_mode))
		return (EACCES);

	/*
	 * Access check is based on only
	 * one of owner, group, public.
	 * If not owner, then check group.
	 * If not a member of the group,
	 * then check public access.
	 */
	if (crgetuid(cr) != va.va_uid) {
		shift += 3;
		if (!groupmember(va.va_gid, cr))
			shift += 3;
	}

	return (secpolicy_vnode_access2(cr, vp, va.va_uid,
	    va.va_mode << shift, mode));
}

static int nfs_do_symlink_cache = 1;

/* ARGSUSED */
static int
nfs_readlink(vnode_t *vp, struct uio *uiop, cred_t *cr, caller_context_t *ct)
{
	int error;
	struct nfsrdlnres rl;
	rnode_t *rp;
	int douprintf;
	failinfo_t fi;

	/*
	 * We want to be consistent with UFS semantics so we will return
	 * EINVAL instead of ENXIO. This violates the XNFS spec and
	 * the RFC 1094, which are wrong any way. BUGID 1138002.
	 */
	if (vp->v_type != VLNK)
		return (EINVAL);

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	rp = VTOR(vp);
	if (nfs_do_symlink_cache && rp->r_symlink.contents != NULL) {
		error = nfs_validate_caches(vp, cr);
		if (error)
			return (error);
		mutex_enter(&rp->r_statelock);
		if (rp->r_symlink.contents != NULL) {
			error = uiomove(rp->r_symlink.contents,
			    rp->r_symlink.len, UIO_READ, uiop);
			mutex_exit(&rp->r_statelock);
			return (error);
		}
		mutex_exit(&rp->r_statelock);
	}


	rl.rl_data = kmem_alloc(NFS_MAXPATHLEN, KM_SLEEP);

	fi.vp = vp;
	fi.fhp = NULL;		/* no need to update, filehandle not copied */
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	douprintf = 1;

	error = rfs2call(VTOMI(vp), RFS_READLINK,
	    xdr_readlink, (caddr_t)VTOFH(vp),
	    xdr_rdlnres, (caddr_t)&rl, cr,
	    &douprintf, &rl.rl_status, 0, &fi);

	if (error) {

		kmem_free((void *)rl.rl_data, NFS_MAXPATHLEN);
		return (error);
	}

	error = geterrno(rl.rl_status);
	if (!error) {
		error = uiomove(rl.rl_data, (int)rl.rl_count, UIO_READ, uiop);
		if (nfs_do_symlink_cache && rp->r_symlink.contents == NULL) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_symlink.contents == NULL) {
				rp->r_symlink.contents = rl.rl_data;
				rp->r_symlink.len = (int)rl.rl_count;
				rp->r_symlink.size = NFS_MAXPATHLEN;
				mutex_exit(&rp->r_statelock);
			} else {
				mutex_exit(&rp->r_statelock);

				kmem_free((void *)rl.rl_data,
				    NFS_MAXPATHLEN);
			}
		} else {

			kmem_free((void *)rl.rl_data, NFS_MAXPATHLEN);
		}
	} else {
		PURGE_STALE_FH(error, vp, cr);

		kmem_free((void *)rl.rl_data, NFS_MAXPATHLEN);
	}

	/*
	 * Conform to UFS semantics (see comment above)
	 */
	return (error == ENXIO ? EINVAL : error);
}

/*
 * Flush local dirty pages to stable storage on the server.
 *
 * If FNODSYNC is specified, then there is nothing to do because
 * metadata changes are not cached on the client before being
 * sent to the server.
 */
/* ARGSUSED */
static int
nfs_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	int error;

	if ((syncflag & FNODSYNC) || IS_SWAPVP(vp))
		return (0);

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	error = nfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
	if (!error)
		error = VTOR(vp)->r_error;
	return (error);
}


/*
 * Weirdness: if the file was removed or the target of a rename
 * operation while it was open, it got renamed instead.  Here we
 * remove the renamed file.
 */
/* ARGSUSED */
static void
nfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	rnode_t *rp;

	ASSERT(vp != DNLC_NO_VNODE);

	/*
	 * If this is coming from the wrong zone, we let someone in the right
	 * zone take care of it asynchronously.  We can get here due to
	 * VN_RELE() being called from pageout() or fsflush().  This call may
	 * potentially turn into an expensive no-op if, for instance, v_count
	 * gets incremented in the meantime, but it's still correct.
	 */
	if (nfs_zone() != VTOMI(vp)->mi_zone) {
		nfs_async_inactive(vp, cr, nfs_inactive);
		return;
	}

	rp = VTOR(vp);
redo:
	if (rp->r_unldvp != NULL) {
		/*
		 * Save the vnode pointer for the directory where the
		 * unlinked-open file got renamed, then set it to NULL
		 * to prevent another thread from getting here before
		 * we're done with the remove.  While we have the
		 * statelock, make local copies of the pertinent rnode
		 * fields.  If we weren't to do this in an atomic way, the
		 * the unl* fields could become inconsistent with respect
		 * to each other due to a race condition between this
		 * code and nfs_remove().  See bug report 1034328.
		 */
		mutex_enter(&rp->r_statelock);
		if (rp->r_unldvp != NULL) {
			vnode_t *unldvp;
			char *unlname;
			cred_t *unlcred;
			struct nfsdiropargs da;
			enum nfsstat status;
			int douprintf;
			int error;

			unldvp = rp->r_unldvp;
			rp->r_unldvp = NULL;
			unlname = rp->r_unlname;
			rp->r_unlname = NULL;
			unlcred = rp->r_unlcred;
			rp->r_unlcred = NULL;
			mutex_exit(&rp->r_statelock);

			/*
			 * If there are any dirty pages left, then flush
			 * them.  This is unfortunate because they just
			 * may get thrown away during the remove operation,
			 * but we have to do this for correctness.
			 */
			if (vn_has_cached_data(vp) &&
			    ((rp->r_flags & RDIRTY) || rp->r_count > 0)) {
				ASSERT(vp->v_type != VCHR);
				error = nfs_putpage(vp, (offset_t)0, 0, 0,
				    cr, ct);
				if (error) {
					mutex_enter(&rp->r_statelock);
					if (!rp->r_error)
						rp->r_error = error;
					mutex_exit(&rp->r_statelock);
				}
			}

			/*
			 * Do the remove operation on the renamed file
			 */
			setdiropargs(&da, unlname, unldvp);

			douprintf = 1;

			(void) rfs2call(VTOMI(unldvp), RFS_REMOVE,
			    xdr_diropargs, (caddr_t)&da,
			    xdr_enum, (caddr_t)&status, unlcred,
			    &douprintf, &status, 0, NULL);

			if (HAVE_RDDIR_CACHE(VTOR(unldvp)))
				nfs_purge_rddir_cache(unldvp);
			PURGE_ATTRCACHE(unldvp);

			/*
			 * Release stuff held for the remove
			 */
			VN_RELE(unldvp);
			kmem_free(unlname, MAXNAMELEN);
			crfree(unlcred);
			goto redo;
		}
		mutex_exit(&rp->r_statelock);
	}

	rp_addfree(rp, cr);
}

/*
 * Remote file system operations having to do with directory manipulation.
 */

/* ARGSUSED */
static int
nfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	int error;
	vnode_t *vp;
	vnode_t *avp = NULL;
	rnode_t *drp;

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);

	drp = VTOR(dvp);

	/*
	 * Are we looking up extended attributes?  If so, "dvp" is
	 * the file or directory for which we want attributes, and
	 * we need a lookup of the hidden attribute directory
	 * before we lookup the rest of the path.
	 */
	if (flags & LOOKUP_XATTR) {
		bool_t cflag = ((flags & CREATE_XATTR_DIR) != 0);
		mntinfo_t *mi;

		mi = VTOMI(dvp);
		if (!(mi->mi_flags & MI_EXTATTR))
			return (EINVAL);

		if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR(dvp)))
			return (EINTR);

		(void) nfslookup_dnlc(dvp, XATTR_DIR_NAME, &avp, cr);
		if (avp == NULL)
			error = acl_getxattrdir2(dvp, &avp, cflag, cr, 0);
		else
			error = 0;

		nfs_rw_exit(&drp->r_rwlock);

		if (error) {
			if (mi->mi_flags & MI_EXTATTR)
				return (error);
			return (EINVAL);
		}
		dvp = avp;
		drp = VTOR(dvp);
	}

	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_READER, INTR(dvp))) {
		error = EINTR;
		goto out;
	}

	error = nfslookup(dvp, nm, vpp, pnp, flags, rdir, cr, 0);

	nfs_rw_exit(&drp->r_rwlock);

	/*
	 * If vnode is a device, create special vnode.
	 */
	if (!error && IS_DEVVP(*vpp)) {
		vp = *vpp;
		*vpp = specvp(vp, vp->v_rdev, vp->v_type, cr);
		VN_RELE(vp);
	}

out:
	if (avp != NULL)
		VN_RELE(avp);

	return (error);
}

static int nfs_lookup_neg_cache = 1;

#ifdef DEBUG
static int nfs_lookup_dnlc_hits = 0;
static int nfs_lookup_dnlc_misses = 0;
static int nfs_lookup_dnlc_neg_hits = 0;
static int nfs_lookup_dnlc_disappears = 0;
static int nfs_lookup_dnlc_lookups = 0;
#endif

/* ARGSUSED */
int
nfslookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
	int flags, vnode_t *rdir, cred_t *cr, int rfscall_flags)
{
	int error;

	ASSERT(nfs_zone() == VTOMI(dvp)->mi_zone);

	/*
	 * If lookup is for "", just return dvp.  Don't need
	 * to send it over the wire, look it up in the dnlc,
	 * or perform any access checks.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * Can't do lookups in non-directories.
	 */
	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * If we're called with RFSCALL_SOFT, it's important that
	 * the only rfscall is one we make directly; if we permit
	 * an access call because we're looking up "." or validating
	 * a dnlc hit, we'll deadlock because that rfscall will not
	 * have the RFSCALL_SOFT set.
	 */
	if (rfscall_flags & RFSCALL_SOFT)
		goto callit;

	/*
	 * If lookup is for ".", just return dvp.  Don't need
	 * to send it over the wire or look it up in the dnlc,
	 * just need to check access.
	 */
	if (strcmp(nm, ".") == 0) {
		error = nfs_access(dvp, VEXEC, 0, cr, NULL);
		if (error)
			return (error);
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * Lookup this name in the DNLC.  If there was a valid entry,
	 * then return the results of the lookup.
	 */
	error = nfslookup_dnlc(dvp, nm, vpp, cr);
	if (error || *vpp != NULL)
		return (error);

callit:
	error = nfslookup_otw(dvp, nm, vpp, cr, rfscall_flags);

	return (error);
}

static int
nfslookup_dnlc(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr)
{
	int error;
	vnode_t *vp;

	ASSERT(*nm != '\0');
	ASSERT(nfs_zone() == VTOMI(dvp)->mi_zone);

	/*
	 * Lookup this name in the DNLC.  If successful, then validate
	 * the caches and then recheck the DNLC.  The DNLC is rechecked
	 * just in case this entry got invalidated during the call
	 * to nfs_validate_caches.
	 *
	 * An assumption is being made that it is safe to say that a
	 * file exists which may not on the server.  Any operations to
	 * the server will fail with ESTALE.
	 */
#ifdef DEBUG
	nfs_lookup_dnlc_lookups++;
#endif
	vp = dnlc_lookup(dvp, nm);
	if (vp != NULL) {
		VN_RELE(vp);
		if (vp == DNLC_NO_VNODE && !vn_is_readonly(dvp)) {
			PURGE_ATTRCACHE(dvp);
		}
		error = nfs_validate_caches(dvp, cr);
		if (error)
			return (error);
		vp = dnlc_lookup(dvp, nm);
		if (vp != NULL) {
			error = nfs_access(dvp, VEXEC, 0, cr, NULL);
			if (error) {
				VN_RELE(vp);
				return (error);
			}
			if (vp == DNLC_NO_VNODE) {
				VN_RELE(vp);
#ifdef DEBUG
				nfs_lookup_dnlc_neg_hits++;
#endif
				return (ENOENT);
			}
			*vpp = vp;
#ifdef DEBUG
			nfs_lookup_dnlc_hits++;
#endif
			return (0);
		}
#ifdef DEBUG
		nfs_lookup_dnlc_disappears++;
#endif
	}
#ifdef DEBUG
	else
		nfs_lookup_dnlc_misses++;
#endif

	*vpp = NULL;

	return (0);
}

static int
nfslookup_otw(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr,
	int rfscall_flags)
{
	int error;
	struct nfsdiropargs da;
	struct nfsdiropres dr;
	int douprintf;
	failinfo_t fi;
	hrtime_t t;

	ASSERT(*nm != '\0');
	ASSERT(dvp->v_type == VDIR);
	ASSERT(nfs_zone() == VTOMI(dvp)->mi_zone);

	setdiropargs(&da, nm, dvp);

	fi.vp = dvp;
	fi.fhp = NULL;		/* no need to update, filehandle not copied */
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	douprintf = 1;

	t = gethrtime();

	error = rfs2call(VTOMI(dvp), RFS_LOOKUP,
	    xdr_diropargs, (caddr_t)&da,
	    xdr_diropres, (caddr_t)&dr, cr,
	    &douprintf, &dr.dr_status, rfscall_flags, &fi);

	if (!error) {
		error = geterrno(dr.dr_status);
		if (!error) {
			*vpp = makenfsnode(&dr.dr_fhandle, &dr.dr_attr,
			    dvp->v_vfsp, t, cr, VTOR(dvp)->r_path, nm);
			/*
			 * If NFS_ACL is supported on the server, then the
			 * attributes returned by server may have minimal
			 * permissions sometimes denying access to users having
			 * proper access.  To get the proper attributes, mark
			 * the attributes as expired so that they will be
			 * regotten via the NFS_ACL GETATTR2 procedure.
			 */
			if (VTOMI(*vpp)->mi_flags & MI_ACL) {
				PURGE_ATTRCACHE(*vpp);
			}
			if (!(rfscall_flags & RFSCALL_SOFT))
				dnlc_update(dvp, nm, *vpp);
		} else {
			PURGE_STALE_FH(error, dvp, cr);
			if (error == ENOENT && nfs_lookup_neg_cache)
				dnlc_enter(dvp, nm, DNLC_NO_VNODE);
		}
	}

	return (error);
}

/* ARGSUSED */
static int
nfs_create(vnode_t *dvp, char *nm, struct vattr *va, enum vcexcl exclusive,
	int mode, vnode_t **vpp, cred_t *cr, int lfaware, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int error;
	struct nfscreatargs args;
	struct nfsdiropres dr;
	int douprintf;
	vnode_t *vp;
	rnode_t *rp;
	struct vattr vattr;
	rnode_t *drp;
	vnode_t *tempvp;
	hrtime_t t;

	drp = VTOR(dvp);

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR(dvp)))
		return (EINTR);

	/*
	 * We make a copy of the attributes because the caller does not
	 * expect us to change what va points to.
	 */
	vattr = *va;

	/*
	 * If the pathname is "", just use dvp.  Don't need
	 * to send it over the wire, look it up in the dnlc,
	 * or perform any access checks.
	 */
	if (*nm == '\0') {
		error = 0;
		VN_HOLD(dvp);
		vp = dvp;
	/*
	 * If the pathname is ".", just use dvp.  Don't need
	 * to send it over the wire or look it up in the dnlc,
	 * just need to check access.
	 */
	} else if (strcmp(nm, ".") == 0) {
		error = nfs_access(dvp, VEXEC, 0, cr, ct);
		if (error) {
			nfs_rw_exit(&drp->r_rwlock);
			return (error);
		}
		VN_HOLD(dvp);
		vp = dvp;
	/*
	 * We need to go over the wire, just to be sure whether the
	 * file exists or not.  Using the DNLC can be dangerous in
	 * this case when making a decision regarding existence.
	 */
	} else {
		error = nfslookup_otw(dvp, nm, &vp, cr, 0);
	}
	if (!error) {
		if (exclusive == EXCL)
			error = EEXIST;
		else if (vp->v_type == VDIR && (mode & VWRITE))
			error = EISDIR;
		else {
			/*
			 * If vnode is a device, create special vnode.
			 */
			if (IS_DEVVP(vp)) {
				tempvp = vp;
				vp = specvp(vp, vp->v_rdev, vp->v_type, cr);
				VN_RELE(tempvp);
			}
			if (!(error = VOP_ACCESS(vp, mode, 0, cr, ct))) {
				if ((vattr.va_mask & AT_SIZE) &&
				    vp->v_type == VREG) {
					vattr.va_mask = AT_SIZE;
					error = nfssetattr(vp, &vattr, 0, cr);

					if (!error) {
						/*
						 * Existing file was truncated;
						 * emit a create event.
						 */
						vnevent_create(vp, ct);
					}
				}
			}
		}
		nfs_rw_exit(&drp->r_rwlock);
		if (error) {
			VN_RELE(vp);
		} else {
			*vpp = vp;
		}
		return (error);
	}

	ASSERT(vattr.va_mask & AT_TYPE);
	if (vattr.va_type == VREG) {
		ASSERT(vattr.va_mask & AT_MODE);
		if (MANDMODE(vattr.va_mode)) {
			nfs_rw_exit(&drp->r_rwlock);
			return (EACCES);
		}
	}

	dnlc_remove(dvp, nm);

	setdiropargs(&args.ca_da, nm, dvp);

	/*
	 * Decide what the group-id of the created file should be.
	 * Set it in attribute list as advisory...then do a setattr
	 * if the server didn't get it right the first time.
	 */
	error = setdirgid(dvp, &vattr.va_gid, cr);
	if (error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}
	vattr.va_mask |= AT_GID;

	/*
	 * This is a completely gross hack to make mknod
	 * work over the wire until we can wack the protocol
	 */
#define	IFCHR		0020000		/* character special */
#define	IFBLK		0060000		/* block special */
#define	IFSOCK		0140000		/* socket */

	/*
	 * dev_t is uint_t in 5.x and short in 4.x. Both 4.x
	 * supports 8 bit majors. 5.x supports 14 bit majors. 5.x supports 18
	 * bits in the minor number where 4.x supports 8 bits.  If the 5.x
	 * minor/major numbers <= 8 bits long, compress the device
	 * number before sending it. Otherwise, the 4.x server will not
	 * create the device with the correct device number and nothing can be
	 * done about this.
	 */
	if (vattr.va_type == VCHR || vattr.va_type == VBLK) {
		dev_t d = vattr.va_rdev;
		dev32_t dev32;

		if (vattr.va_type == VCHR)
			vattr.va_mode |= IFCHR;
		else
			vattr.va_mode |= IFBLK;

		(void) cmpldev(&dev32, d);
		if (dev32 & ~((SO4_MAXMAJ << L_BITSMINOR32) | SO4_MAXMIN))
			vattr.va_size = (u_offset_t)dev32;
		else
			vattr.va_size = (u_offset_t)nfsv2_cmpdev(d);

		vattr.va_mask |= AT_MODE|AT_SIZE;
	} else if (vattr.va_type == VFIFO) {
		vattr.va_mode |= IFCHR;		/* xtra kludge for namedpipe */
		vattr.va_size = (u_offset_t)NFS_FIFO_DEV;	/* blech */
		vattr.va_mask |= AT_MODE|AT_SIZE;
	} else if (vattr.va_type == VSOCK) {
		vattr.va_mode |= IFSOCK;
		/*
		 * To avoid triggering bugs in the servers set AT_SIZE
		 * (all other RFS_CREATE calls set this).
		 */
		vattr.va_size = 0;
		vattr.va_mask |= AT_MODE|AT_SIZE;
	}

	args.ca_sa = &args.ca_sa_buf;
	error = vattr_to_sattr(&vattr, args.ca_sa);
	if (error) {
		/* req time field(s) overflow - return immediately */
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	douprintf = 1;

	t = gethrtime();

	error = rfs2call(VTOMI(dvp), RFS_CREATE,
	    xdr_creatargs, (caddr_t)&args,
	    xdr_diropres, (caddr_t)&dr, cr,
	    &douprintf, &dr.dr_status, 0, NULL);

	PURGE_ATTRCACHE(dvp);	/* mod time changed */

	if (!error) {
		error = geterrno(dr.dr_status);
		if (!error) {
			if (HAVE_RDDIR_CACHE(drp))
				nfs_purge_rddir_cache(dvp);
			vp = makenfsnode(&dr.dr_fhandle, &dr.dr_attr,
			    dvp->v_vfsp, t, cr, NULL, NULL);
			/*
			 * If NFS_ACL is supported on the server, then the
			 * attributes returned by server may have minimal
			 * permissions sometimes denying access to users having
			 * proper access.  To get the proper attributes, mark
			 * the attributes as expired so that they will be
			 * regotten via the NFS_ACL GETATTR2 procedure.
			 */
			if (VTOMI(vp)->mi_flags & MI_ACL) {
				PURGE_ATTRCACHE(vp);
			}
			dnlc_update(dvp, nm, vp);
			rp = VTOR(vp);
			if (vattr.va_size == 0) {
				mutex_enter(&rp->r_statelock);
				rp->r_size = 0;
				mutex_exit(&rp->r_statelock);
				if (vn_has_cached_data(vp)) {
					ASSERT(vp->v_type != VCHR);
					nfs_invalidate_pages(vp,
					    (u_offset_t)0, cr);
				}
			}

			/*
			 * Make sure the gid was set correctly.
			 * If not, try to set it (but don't lose
			 * any sleep over it).
			 */
			if (vattr.va_gid != rp->r_attr.va_gid) {
				vattr.va_mask = AT_GID;
				(void) nfssetattr(vp, &vattr, 0, cr);
			}

			/*
			 * If vnode is a device create special vnode
			 */
			if (IS_DEVVP(vp)) {
				*vpp = specvp(vp, vp->v_rdev, vp->v_type, cr);
				VN_RELE(vp);
			} else
				*vpp = vp;
		} else {
			PURGE_STALE_FH(error, dvp, cr);
		}
	}

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

/*
 * Weirdness: if the vnode to be removed is open
 * we rename it instead of removing it and nfs_inactive
 * will remove the new name.
 */
/* ARGSUSED */
static int
nfs_remove(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct, int flags)
{
	int error;
	struct nfsdiropargs da;
	enum nfsstat status;
	vnode_t *vp;
	char *tmpname;
	int douprintf;
	rnode_t *rp;
	rnode_t *drp;

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);
	drp = VTOR(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR(dvp)))
		return (EINTR);

	error = nfslookup(dvp, nm, &vp, NULL, 0, NULL, cr, 0);
	if (error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	if (vp->v_type == VDIR && secpolicy_fs_linkdir(cr, dvp->v_vfsp)) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (EPERM);
	}

	/*
	 * First just remove the entry from the name cache, as it
	 * is most likely the only entry for this vp.
	 */
	dnlc_remove(dvp, nm);

	/*
	 * If the file has a v_count > 1 then there may be more than one
	 * entry in the name cache due multiple links or an open file,
	 * but we don't have the real reference count so flush all
	 * possible entries.
	 */
	if (vp->v_count > 1)
		dnlc_purge_vp(vp);

	/*
	 * Now we have the real reference count on the vnode
	 */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	if (vp->v_count > 1 &&
	    (rp->r_unldvp == NULL || strcmp(nm, rp->r_unlname) == 0)) {
		mutex_exit(&rp->r_statelock);
		tmpname = newname();
		error = nfsrename(dvp, nm, dvp, tmpname, cr, ct);
		if (error)
			kmem_free(tmpname, MAXNAMELEN);
		else {
			mutex_enter(&rp->r_statelock);
			if (rp->r_unldvp == NULL) {
				VN_HOLD(dvp);
				rp->r_unldvp = dvp;
				if (rp->r_unlcred != NULL)
					crfree(rp->r_unlcred);
				crhold(cr);
				rp->r_unlcred = cr;
				rp->r_unlname = tmpname;
			} else {
				kmem_free(rp->r_unlname, MAXNAMELEN);
				rp->r_unlname = tmpname;
			}
			mutex_exit(&rp->r_statelock);
		}
	} else {
		mutex_exit(&rp->r_statelock);
		/*
		 * We need to flush any dirty pages which happen to
		 * be hanging around before removing the file.  This
		 * shouldn't happen very often and mostly on file
		 * systems mounted "nocto".
		 */
		if (vn_has_cached_data(vp) &&
		    ((rp->r_flags & RDIRTY) || rp->r_count > 0)) {
			error = nfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				mutex_enter(&rp->r_statelock);
				if (!rp->r_error)
					rp->r_error = error;
				mutex_exit(&rp->r_statelock);
			}
		}

		setdiropargs(&da, nm, dvp);

		douprintf = 1;

		error = rfs2call(VTOMI(dvp), RFS_REMOVE,
		    xdr_diropargs, (caddr_t)&da,
		    xdr_enum, (caddr_t)&status, cr,
		    &douprintf, &status, 0, NULL);

		/*
		 * The xattr dir may be gone after last attr is removed,
		 * so flush it from dnlc.
		 */
		if (dvp->v_flag & V_XATTRDIR)
			dnlc_purge_vp(dvp);

		PURGE_ATTRCACHE(dvp);	/* mod time changed */
		PURGE_ATTRCACHE(vp);	/* link count changed */

		if (!error) {
			error = geterrno(status);
			if (!error) {
				if (HAVE_RDDIR_CACHE(drp))
					nfs_purge_rddir_cache(dvp);
			} else {
				PURGE_STALE_FH(error, dvp, cr);
			}
		}
	}

	if (error == 0) {
		vnevent_remove(vp, dvp, nm, ct);
	}
	VN_RELE(vp);

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

/* ARGSUSED */
static int
nfs_link(vnode_t *tdvp, vnode_t *svp, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int error;
	struct nfslinkargs args;
	enum nfsstat status;
	vnode_t *realvp;
	int douprintf;
	rnode_t *tdrp;

	if (nfs_zone() != VTOMI(tdvp)->mi_zone)
		return (EPERM);
	if (VOP_REALVP(svp, &realvp, ct) == 0)
		svp = realvp;

	args.la_from = VTOFH(svp);
	setdiropargs(&args.la_to, tnm, tdvp);

	tdrp = VTOR(tdvp);
	if (nfs_rw_enter_sig(&tdrp->r_rwlock, RW_WRITER, INTR(tdvp)))
		return (EINTR);

	dnlc_remove(tdvp, tnm);

	douprintf = 1;

	error = rfs2call(VTOMI(svp), RFS_LINK,
	    xdr_linkargs, (caddr_t)&args,
	    xdr_enum, (caddr_t)&status, cr,
	    &douprintf, &status, 0, NULL);

	PURGE_ATTRCACHE(tdvp);	/* mod time changed */
	PURGE_ATTRCACHE(svp);	/* link count changed */

	if (!error) {
		error = geterrno(status);
		if (!error) {
			if (HAVE_RDDIR_CACHE(tdrp))
				nfs_purge_rddir_cache(tdvp);
		}
	}

	nfs_rw_exit(&tdrp->r_rwlock);

	if (!error) {
		/*
		 * Notify the source file of this link operation.
		 */
		vnevent_link(svp, ct);
	}
	return (error);
}

/* ARGSUSED */
static int
nfs_rename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	vnode_t *realvp;

	if (nfs_zone() != VTOMI(odvp)->mi_zone)
		return (EPERM);
	if (VOP_REALVP(ndvp, &realvp, ct) == 0)
		ndvp = realvp;

	return (nfsrename(odvp, onm, ndvp, nnm, cr, ct));
}

/*
 * nfsrename does the real work of renaming in NFS Version 2.
 */
static int
nfsrename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, cred_t *cr,
    caller_context_t *ct)
{
	int error;
	enum nfsstat status;
	struct nfsrnmargs args;
	int douprintf;
	vnode_t *nvp = NULL;
	vnode_t *ovp = NULL;
	char *tmpname;
	rnode_t *rp;
	rnode_t *odrp;
	rnode_t *ndrp;

	ASSERT(nfs_zone() == VTOMI(odvp)->mi_zone);
	if (strcmp(onm, ".") == 0 || strcmp(onm, "..") == 0 ||
	    strcmp(nnm, ".") == 0 || strcmp(nnm, "..") == 0)
		return (EINVAL);

	odrp = VTOR(odvp);
	ndrp = VTOR(ndvp);
	if ((intptr_t)odrp < (intptr_t)ndrp) {
		if (nfs_rw_enter_sig(&odrp->r_rwlock, RW_WRITER, INTR(odvp)))
			return (EINTR);
		if (nfs_rw_enter_sig(&ndrp->r_rwlock, RW_WRITER, INTR(ndvp))) {
			nfs_rw_exit(&odrp->r_rwlock);
			return (EINTR);
		}
	} else {
		if (nfs_rw_enter_sig(&ndrp->r_rwlock, RW_WRITER, INTR(ndvp)))
			return (EINTR);
		if (nfs_rw_enter_sig(&odrp->r_rwlock, RW_WRITER, INTR(odvp))) {
			nfs_rw_exit(&ndrp->r_rwlock);
			return (EINTR);
		}
	}

	/*
	 * Lookup the target file.  If it exists, it needs to be
	 * checked to see whether it is a mount point and whether
	 * it is active (open).
	 */
	error = nfslookup(ndvp, nnm, &nvp, NULL, 0, NULL, cr, 0);
	if (!error) {
		/*
		 * If this file has been mounted on, then just
		 * return busy because renaming to it would remove
		 * the mounted file system from the name space.
		 */
		if (vn_mountedvfs(nvp) != NULL) {
			VN_RELE(nvp);
			nfs_rw_exit(&odrp->r_rwlock);
			nfs_rw_exit(&ndrp->r_rwlock);
			return (EBUSY);
		}

		/*
		 * Purge the name cache of all references to this vnode
		 * so that we can check the reference count to infer
		 * whether it is active or not.
		 */
		/*
		 * First just remove the entry from the name cache, as it
		 * is most likely the only entry for this vp.
		 */
		dnlc_remove(ndvp, nnm);
		/*
		 * If the file has a v_count > 1 then there may be more
		 * than one entry in the name cache due multiple links
		 * or an open file, but we don't have the real reference
		 * count so flush all possible entries.
		 */
		if (nvp->v_count > 1)
			dnlc_purge_vp(nvp);

		/*
		 * If the vnode is active and is not a directory,
		 * arrange to rename it to a
		 * temporary file so that it will continue to be
		 * accessible.  This implements the "unlink-open-file"
		 * semantics for the target of a rename operation.
		 * Before doing this though, make sure that the
		 * source and target files are not already the same.
		 */
		if (nvp->v_count > 1 && nvp->v_type != VDIR) {
			/*
			 * Lookup the source name.
			 */
			error = nfslookup(odvp, onm, &ovp, NULL, 0, NULL,
			    cr, 0);

			/*
			 * The source name *should* already exist.
			 */
			if (error) {
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (error);
			}

			/*
			 * Compare the two vnodes.  If they are the same,
			 * just release all held vnodes and return success.
			 */
			if (ovp == nvp) {
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (0);
			}

			/*
			 * Can't mix and match directories and non-
			 * directories in rename operations.  We already
			 * know that the target is not a directory.  If
			 * the source is a directory, return an error.
			 */
			if (ovp->v_type == VDIR) {
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (ENOTDIR);
			}

			/*
			 * The target file exists, is not the same as
			 * the source file, and is active.  Link it
			 * to a temporary filename to avoid having
			 * the server removing the file completely.
			 */
			tmpname = newname();
			error = nfs_link(ndvp, nvp, tmpname, cr, NULL, 0);
			if (error == EOPNOTSUPP) {
				error = nfs_rename(ndvp, nnm, ndvp, tmpname,
				    cr, NULL, 0);
			}
			if (error) {
				kmem_free(tmpname, MAXNAMELEN);
				VN_RELE(ovp);
				VN_RELE(nvp);
				nfs_rw_exit(&odrp->r_rwlock);
				nfs_rw_exit(&ndrp->r_rwlock);
				return (error);
			}
			rp = VTOR(nvp);
			mutex_enter(&rp->r_statelock);
			if (rp->r_unldvp == NULL) {
				VN_HOLD(ndvp);
				rp->r_unldvp = ndvp;
				if (rp->r_unlcred != NULL)
					crfree(rp->r_unlcred);
				crhold(cr);
				rp->r_unlcred = cr;
				rp->r_unlname = tmpname;
			} else {
				kmem_free(rp->r_unlname, MAXNAMELEN);
				rp->r_unlname = tmpname;
			}
			mutex_exit(&rp->r_statelock);
		}
	}

	if (ovp == NULL) {
		/*
		 * When renaming directories to be a subdirectory of a
		 * different parent, the dnlc entry for ".." will no
		 * longer be valid, so it must be removed.
		 *
		 * We do a lookup here to determine whether we are renaming
		 * a directory and we need to check if we are renaming
		 * an unlinked file.  This might have already been done
		 * in previous code, so we check ovp == NULL to avoid
		 * doing it twice.
		 */

		error = nfslookup(odvp, onm, &ovp, NULL, 0, NULL, cr, 0);

		/*
		 * The source name *should* already exist.
		 */
		if (error) {
			nfs_rw_exit(&odrp->r_rwlock);
			nfs_rw_exit(&ndrp->r_rwlock);
			if (nvp) {
				VN_RELE(nvp);
			}
			return (error);
		}
		ASSERT(ovp != NULL);
	}

	dnlc_remove(odvp, onm);
	dnlc_remove(ndvp, nnm);

	setdiropargs(&args.rna_from, onm, odvp);
	setdiropargs(&args.rna_to, nnm, ndvp);

	douprintf = 1;

	error = rfs2call(VTOMI(odvp), RFS_RENAME,
	    xdr_rnmargs, (caddr_t)&args,
	    xdr_enum, (caddr_t)&status, cr,
	    &douprintf, &status, 0, NULL);

	PURGE_ATTRCACHE(odvp);	/* mod time changed */
	PURGE_ATTRCACHE(ndvp);	/* mod time changed */

	if (!error) {
		error = geterrno(status);
		if (!error) {
			if (HAVE_RDDIR_CACHE(odrp))
				nfs_purge_rddir_cache(odvp);
			if (HAVE_RDDIR_CACHE(ndrp))
				nfs_purge_rddir_cache(ndvp);
			/*
			 * when renaming directories to be a subdirectory of a
			 * different parent, the dnlc entry for ".." will no
			 * longer be valid, so it must be removed
			 */
			rp = VTOR(ovp);
			if (ndvp != odvp) {
				if (ovp->v_type == VDIR) {
					dnlc_remove(ovp, "..");
					if (HAVE_RDDIR_CACHE(rp))
						nfs_purge_rddir_cache(ovp);
				}
			}

			/*
			 * If we are renaming the unlinked file, update the
			 * r_unldvp and r_unlname as needed.
			 */
			mutex_enter(&rp->r_statelock);
			if (rp->r_unldvp != NULL) {
				if (strcmp(rp->r_unlname, onm) == 0) {
					(void) strncpy(rp->r_unlname,
					    nnm, MAXNAMELEN);
					rp->r_unlname[MAXNAMELEN - 1] = '\0';

					if (ndvp != rp->r_unldvp) {
						VN_RELE(rp->r_unldvp);
						rp->r_unldvp = ndvp;
						VN_HOLD(ndvp);
					}
				}
			}
			mutex_exit(&rp->r_statelock);
		} else {
			/*
			 * System V defines rename to return EEXIST, not
			 * ENOTEMPTY if the target directory is not empty.
			 * Over the wire, the error is NFSERR_ENOTEMPTY
			 * which geterrno maps to ENOTEMPTY.
			 */
			if (error == ENOTEMPTY)
				error = EEXIST;
		}
	}

	if (error == 0) {
		if (nvp)
			vnevent_rename_dest(nvp, ndvp, nnm, ct);

		if (odvp != ndvp)
			vnevent_rename_dest_dir(ndvp, ct);

		ASSERT(ovp != NULL);
		vnevent_rename_src(ovp, odvp, onm, ct);
	}

	if (nvp) {
		VN_RELE(nvp);
	}
	VN_RELE(ovp);

	nfs_rw_exit(&odrp->r_rwlock);
	nfs_rw_exit(&ndrp->r_rwlock);

	return (error);
}

/* ARGSUSED */
static int
nfs_mkdir(vnode_t *dvp, char *nm, struct vattr *va, vnode_t **vpp, cred_t *cr,
	caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int error;
	struct nfscreatargs args;
	struct nfsdiropres dr;
	int douprintf;
	rnode_t *drp;
	hrtime_t t;

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);

	setdiropargs(&args.ca_da, nm, dvp);

	/*
	 * Decide what the group-id and set-gid bit of the created directory
	 * should be.  May have to do a setattr to get the gid right.
	 */
	error = setdirgid(dvp, &va->va_gid, cr);
	if (error)
		return (error);
	error = setdirmode(dvp, &va->va_mode, cr);
	if (error)
		return (error);
	va->va_mask |= AT_MODE|AT_GID;

	args.ca_sa = &args.ca_sa_buf;
	error = vattr_to_sattr(va, args.ca_sa);
	if (error) {
		/* req time field(s) overflow - return immediately */
		return (error);
	}

	drp = VTOR(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR(dvp)))
		return (EINTR);

	dnlc_remove(dvp, nm);

	douprintf = 1;

	t = gethrtime();

	error = rfs2call(VTOMI(dvp), RFS_MKDIR,
	    xdr_creatargs, (caddr_t)&args,
	    xdr_diropres, (caddr_t)&dr, cr,
	    &douprintf, &dr.dr_status, 0, NULL);

	PURGE_ATTRCACHE(dvp);	/* mod time changed */

	if (!error) {
		error = geterrno(dr.dr_status);
		if (!error) {
			if (HAVE_RDDIR_CACHE(drp))
				nfs_purge_rddir_cache(dvp);
			/*
			 * The attributes returned by RFS_MKDIR can not
			 * be depended upon, so mark the attribute cache
			 * as purged.  A subsequent GETATTR will get the
			 * correct attributes from the server.
			 */
			*vpp = makenfsnode(&dr.dr_fhandle, &dr.dr_attr,
			    dvp->v_vfsp, t, cr, NULL, NULL);
			PURGE_ATTRCACHE(*vpp);
			dnlc_update(dvp, nm, *vpp);

			/*
			 * Make sure the gid was set correctly.
			 * If not, try to set it (but don't lose
			 * any sleep over it).
			 */
			if (va->va_gid != VTOR(*vpp)->r_attr.va_gid) {
				va->va_mask = AT_GID;
				(void) nfssetattr(*vpp, va, 0, cr);
			}
		} else {
			PURGE_STALE_FH(error, dvp, cr);
		}
	}

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

/* ARGSUSED */
static int
nfs_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int error;
	enum nfsstat status;
	struct nfsdiropargs da;
	vnode_t *vp;
	int douprintf;
	rnode_t *drp;

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);
	drp = VTOR(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR(dvp)))
		return (EINTR);

	/*
	 * Attempt to prevent a rmdir(".") from succeeding.
	 */
	error = nfslookup(dvp, nm, &vp, NULL, 0, NULL, cr, 0);
	if (error) {
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	if (vp == cdir) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (EINVAL);
	}

	setdiropargs(&da, nm, dvp);

	/*
	 * First just remove the entry from the name cache, as it
	 * is most likely an entry for this vp.
	 */
	dnlc_remove(dvp, nm);

	/*
	 * If there vnode reference count is greater than one, then
	 * there may be additional references in the DNLC which will
	 * need to be purged.  First, trying removing the entry for
	 * the parent directory and see if that removes the additional
	 * reference(s).  If that doesn't do it, then use dnlc_purge_vp
	 * to completely remove any references to the directory which
	 * might still exist in the DNLC.
	 */
	if (vp->v_count > 1) {
		dnlc_remove(vp, "..");
		if (vp->v_count > 1)
			dnlc_purge_vp(vp);
	}

	douprintf = 1;

	error = rfs2call(VTOMI(dvp), RFS_RMDIR,
	    xdr_diropargs, (caddr_t)&da,
	    xdr_enum, (caddr_t)&status, cr,
	    &douprintf, &status, 0, NULL);

	PURGE_ATTRCACHE(dvp);	/* mod time changed */

	if (error) {
		VN_RELE(vp);
		nfs_rw_exit(&drp->r_rwlock);
		return (error);
	}

	error = geterrno(status);
	if (!error) {
		if (HAVE_RDDIR_CACHE(drp))
			nfs_purge_rddir_cache(dvp);
		if (HAVE_RDDIR_CACHE(VTOR(vp)))
			nfs_purge_rddir_cache(vp);
	} else {
		PURGE_STALE_FH(error, dvp, cr);
		/*
		 * System V defines rmdir to return EEXIST, not
		 * ENOTEMPTY if the directory is not empty.  Over
		 * the wire, the error is NFSERR_ENOTEMPTY which
		 * geterrno maps to ENOTEMPTY.
		 */
		if (error == ENOTEMPTY)
			error = EEXIST;
	}

	if (error == 0) {
		vnevent_rmdir(vp, dvp, nm, ct);
	}
	VN_RELE(vp);

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

/* ARGSUSED */
static int
nfs_symlink(vnode_t *dvp, char *lnm, struct vattr *tva, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	int error;
	struct nfsslargs args;
	enum nfsstat status;
	int douprintf;
	rnode_t *drp;

	if (nfs_zone() != VTOMI(dvp)->mi_zone)
		return (EPERM);
	setdiropargs(&args.sla_from, lnm, dvp);
	args.sla_sa = &args.sla_sa_buf;
	error = vattr_to_sattr(tva, args.sla_sa);
	if (error) {
		/* req time field(s) overflow - return immediately */
		return (error);
	}
	args.sla_tnm = tnm;

	drp = VTOR(dvp);
	if (nfs_rw_enter_sig(&drp->r_rwlock, RW_WRITER, INTR(dvp)))
		return (EINTR);

	dnlc_remove(dvp, lnm);

	douprintf = 1;

	error = rfs2call(VTOMI(dvp), RFS_SYMLINK,
	    xdr_slargs, (caddr_t)&args,
	    xdr_enum, (caddr_t)&status, cr,
	    &douprintf, &status, 0, NULL);

	PURGE_ATTRCACHE(dvp);	/* mod time changed */

	if (!error) {
		error = geterrno(status);
		if (!error) {
			if (HAVE_RDDIR_CACHE(drp))
				nfs_purge_rddir_cache(dvp);
		} else {
			PURGE_STALE_FH(error, dvp, cr);
		}
	}

	nfs_rw_exit(&drp->r_rwlock);

	return (error);
}

#ifdef DEBUG
static int nfs_readdir_cache_hits = 0;
static int nfs_readdir_cache_shorts = 0;
static int nfs_readdir_cache_waits = 0;
static int nfs_readdir_cache_misses = 0;
static int nfs_readdir_readahead = 0;
#endif

static int nfs_shrinkreaddir = 0;

/*
 * Read directory entries.
 * There are some weird things to look out for here.  The uio_offset
 * field is either 0 or it is the offset returned from a previous
 * readdir.  It is an opaque value used by the server to find the
 * correct directory block to read. The count field is the number
 * of blocks to read on the server.  This is advisory only, the server
 * may return only one block's worth of entries.  Entries may be compressed
 * on the server.
 */
/* ARGSUSED */
static int
nfs_readdir(vnode_t *vp, struct uio *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	int error;
	size_t count;
	rnode_t *rp;
	rddir_cache *rdc;
	rddir_cache *nrdc;
	rddir_cache *rrdc;
#ifdef DEBUG
	int missed;
#endif
	rddir_cache srdc;
	avl_index_t where;

	rp = VTOR(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_READER));
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	/*
	 * Make sure that the directory cache is valid.
	 */
	if (HAVE_RDDIR_CACHE(rp)) {
		if (nfs_disable_rddir_cache) {
			/*
			 * Setting nfs_disable_rddir_cache in /etc/system
			 * allows interoperability with servers that do not
			 * properly update the attributes of directories.
			 * Any cached information gets purged before an
			 * access is made to it.
			 */
			nfs_purge_rddir_cache(vp);
		} else {
			error = nfs_validate_caches(vp, cr);
			if (error)
				return (error);
		}
	}

	/*
	 * UGLINESS: SunOS 3.2 servers apparently cannot always handle an
	 * RFS_READDIR request with rda_count set to more than 0x400. So
	 * we reduce the request size here purely for compatibility.
	 *
	 * In general, this is no longer required.  However, if a server
	 * is discovered which can not handle requests larger than 1024,
	 * nfs_shrinkreaddir can be set to 1 to enable this backwards
	 * compatibility.
	 *
	 * In any case, the request size is limited to NFS_MAXDATA bytes.
	 */
	count = MIN(uiop->uio_iov->iov_len,
	    nfs_shrinkreaddir ? 0x400 : NFS_MAXDATA);

	nrdc = NULL;
#ifdef DEBUG
	missed = 0;
#endif
top:
	/*
	 * Short circuit last readdir which always returns 0 bytes.
	 * This can be done after the directory has been read through
	 * completely at least once.  This will set r_direof which
	 * can be used to find the value of the last cookie.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_direof != NULL &&
	    uiop->uio_offset == rp->r_direof->nfs_ncookie) {
		mutex_exit(&rp->r_statelock);
#ifdef DEBUG
		nfs_readdir_cache_shorts++;
#endif
		if (eofp)
			*eofp = 1;
		if (nrdc != NULL)
			rddir_cache_rele(nrdc);
		return (0);
	}
	/*
	 * Look for a cache entry.  Cache entries are identified
	 * by the NFS cookie value and the byte count requested.
	 */
	srdc.nfs_cookie = uiop->uio_offset;
	srdc.buflen = count;
	rdc = avl_find(&rp->r_dir, &srdc, &where);
	if (rdc != NULL) {
		rddir_cache_hold(rdc);
		/*
		 * If the cache entry is in the process of being
		 * filled in, wait until this completes.  The
		 * RDDIRWAIT bit is set to indicate that someone
		 * is waiting and then the thread currently
		 * filling the entry is done, it should do a
		 * cv_broadcast to wakeup all of the threads
		 * waiting for it to finish.
		 */
		if (rdc->flags & RDDIR) {
			nfs_rw_exit(&rp->r_rwlock);
			rdc->flags |= RDDIRWAIT;
#ifdef DEBUG
			nfs_readdir_cache_waits++;
#endif
			if (!cv_wait_sig(&rdc->cv, &rp->r_statelock)) {
				/*
				 * We got interrupted, probably
				 * the user typed ^C or an alarm
				 * fired.  We free the new entry
				 * if we allocated one.
				 */
				mutex_exit(&rp->r_statelock);
				(void) nfs_rw_enter_sig(&rp->r_rwlock,
				    RW_READER, FALSE);
				rddir_cache_rele(rdc);
				if (nrdc != NULL)
					rddir_cache_rele(nrdc);
				return (EINTR);
			}
			mutex_exit(&rp->r_statelock);
			(void) nfs_rw_enter_sig(&rp->r_rwlock,
			    RW_READER, FALSE);
			rddir_cache_rele(rdc);
			goto top;
		}
		/*
		 * Check to see if a readdir is required to
		 * fill the entry.  If so, mark this entry
		 * as being filled, remove our reference,
		 * and branch to the code to fill the entry.
		 */
		if (rdc->flags & RDDIRREQ) {
			rdc->flags &= ~RDDIRREQ;
			rdc->flags |= RDDIR;
			if (nrdc != NULL)
				rddir_cache_rele(nrdc);
			nrdc = rdc;
			mutex_exit(&rp->r_statelock);
			goto bottom;
		}
#ifdef DEBUG
		if (!missed)
			nfs_readdir_cache_hits++;
#endif
		/*
		 * If an error occurred while attempting
		 * to fill the cache entry, just return it.
		 */
		if (rdc->error) {
			error = rdc->error;
			mutex_exit(&rp->r_statelock);
			rddir_cache_rele(rdc);
			if (nrdc != NULL)
				rddir_cache_rele(nrdc);
			return (error);
		}

		/*
		 * The cache entry is complete and good,
		 * copyout the dirent structs to the calling
		 * thread.
		 */
		error = uiomove(rdc->entries, rdc->entlen, UIO_READ, uiop);

		/*
		 * If no error occurred during the copyout,
		 * update the offset in the uio struct to
		 * contain the value of the next cookie
		 * and set the eof value appropriately.
		 */
		if (!error) {
			uiop->uio_offset = rdc->nfs_ncookie;
			if (eofp)
				*eofp = rdc->eof;
		}

		/*
		 * Decide whether to do readahead.  Don't if
		 * have already read to the end of directory.
		 */
		if (rdc->eof) {
			rp->r_direof = rdc;
			mutex_exit(&rp->r_statelock);
			rddir_cache_rele(rdc);
			if (nrdc != NULL)
				rddir_cache_rele(nrdc);
			return (error);
		}

		/*
		 * Check to see whether we found an entry
		 * for the readahead.  If so, we don't need
		 * to do anything further, so free the new
		 * entry if one was allocated.  Otherwise,
		 * allocate a new entry, add it to the cache,
		 * and then initiate an asynchronous readdir
		 * operation to fill it.
		 */
		srdc.nfs_cookie = rdc->nfs_ncookie;
		srdc.buflen = count;
		rrdc = avl_find(&rp->r_dir, &srdc, &where);
		if (rrdc != NULL) {
			if (nrdc != NULL)
				rddir_cache_rele(nrdc);
		} else {
			if (nrdc != NULL)
				rrdc = nrdc;
			else {
				rrdc = rddir_cache_alloc(KM_NOSLEEP);
			}
			if (rrdc != NULL) {
				rrdc->nfs_cookie = rdc->nfs_ncookie;
				rrdc->buflen = count;
				avl_insert(&rp->r_dir, rrdc, where);
				rddir_cache_hold(rrdc);
				mutex_exit(&rp->r_statelock);
				rddir_cache_rele(rdc);
#ifdef DEBUG
				nfs_readdir_readahead++;
#endif
				nfs_async_readdir(vp, rrdc, cr, nfsreaddir);
				return (error);
			}
		}

		mutex_exit(&rp->r_statelock);
		rddir_cache_rele(rdc);
		return (error);
	}

	/*
	 * Didn't find an entry in the cache.  Construct a new empty
	 * entry and link it into the cache.  Other processes attempting
	 * to access this entry will need to wait until it is filled in.
	 *
	 * Since kmem_alloc may block, another pass through the cache
	 * will need to be taken to make sure that another process
	 * hasn't already added an entry to the cache for this request.
	 */
	if (nrdc == NULL) {
		mutex_exit(&rp->r_statelock);
		nrdc = rddir_cache_alloc(KM_SLEEP);
		nrdc->nfs_cookie = uiop->uio_offset;
		nrdc->buflen = count;
		goto top;
	}

	/*
	 * Add this entry to the cache.
	 */
	avl_insert(&rp->r_dir, nrdc, where);
	rddir_cache_hold(nrdc);
	mutex_exit(&rp->r_statelock);

bottom:
#ifdef DEBUG
	missed = 1;
	nfs_readdir_cache_misses++;
#endif
	/*
	 * Do the readdir.
	 */
	error = nfsreaddir(vp, nrdc, cr);

	/*
	 * If this operation failed, just return the error which occurred.
	 */
	if (error != 0)
		return (error);

	/*
	 * Since the RPC operation will have taken sometime and blocked
	 * this process, another pass through the cache will need to be
	 * taken to find the correct cache entry.  It is possible that
	 * the correct cache entry will not be there (although one was
	 * added) because the directory changed during the RPC operation
	 * and the readdir cache was flushed.  In this case, just start
	 * over.  It is hoped that this will not happen too often... :-)
	 */
	nrdc = NULL;
	goto top;
	/* NOTREACHED */
}

static int
nfsreaddir(vnode_t *vp, rddir_cache *rdc, cred_t *cr)
{
	int error;
	struct nfsrddirargs rda;
	struct nfsrddirres rd;
	rnode_t *rp;
	mntinfo_t *mi;
	uint_t count;
	int douprintf;
	failinfo_t fi, *fip;

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);
	count = rdc->buflen;

	rp = VTOR(vp);
	mi = VTOMI(vp);

	rda.rda_fh = *VTOFH(vp);
	rda.rda_offset = rdc->nfs_cookie;

	/*
	 * NFS client failover support
	 * suppress failover unless we have a zero cookie
	 */
	if (rdc->nfs_cookie == (off_t)0) {
		fi.vp = vp;
		fi.fhp = (caddr_t)&rda.rda_fh;
		fi.copyproc = nfscopyfh;
		fi.lookupproc = nfslookup;
		fi.xattrdirproc = acl_getxattrdir2;
		fip = &fi;
	} else {
		fip = NULL;
	}

	rd.rd_entries = kmem_alloc(rdc->buflen, KM_SLEEP);
	rd.rd_size = count;
	rd.rd_offset = rda.rda_offset;

	douprintf = 1;

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_runq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	do {
		rda.rda_count = MIN(count, mi->mi_curread);
		error = rfs2call(mi, RFS_READDIR,
		    xdr_rddirargs, (caddr_t)&rda,
		    xdr_getrddirres, (caddr_t)&rd, cr,
		    &douprintf, &rd.rd_status, 0, fip);
	} while (error == ENFS_TRYAGAIN);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_runq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	/*
	 * Since we are actually doing a READDIR RPC, we must have
	 * exclusive access to the cache entry being filled.  Thus,
	 * it is safe to update all fields except for the flags
	 * field.  The r_statelock in the rnode must be held to
	 * prevent two different threads from simultaneously
	 * attempting to update the flags field.  This can happen
	 * if we are turning off RDDIR and the other thread is
	 * trying to set RDDIRWAIT.
	 */
	ASSERT(rdc->flags & RDDIR);
	if (!error) {
		error = geterrno(rd.rd_status);
		if (!error) {
			rdc->nfs_ncookie = rd.rd_offset;
			rdc->eof = rd.rd_eof ? 1 : 0;
			rdc->entlen = rd.rd_size;
			ASSERT(rdc->entlen <= rdc->buflen);
#ifdef DEBUG
			rdc->entries = rddir_cache_buf_alloc(rdc->buflen,
			    KM_SLEEP);
#else
			rdc->entries = kmem_alloc(rdc->buflen, KM_SLEEP);
#endif
			bcopy(rd.rd_entries, rdc->entries, rdc->entlen);
			rdc->error = 0;
			if (mi->mi_io_kstats) {
				mutex_enter(&mi->mi_lock);
				KSTAT_IO_PTR(mi->mi_io_kstats)->reads++;
				KSTAT_IO_PTR(mi->mi_io_kstats)->nread +=
				    rd.rd_size;
				mutex_exit(&mi->mi_lock);
			}
		} else {
			PURGE_STALE_FH(error, vp, cr);
		}
	}
	if (error) {
		rdc->entries = NULL;
		rdc->error = error;
	}
	kmem_free(rd.rd_entries, rdc->buflen);

	mutex_enter(&rp->r_statelock);
	rdc->flags &= ~RDDIR;
	if (rdc->flags & RDDIRWAIT) {
		rdc->flags &= ~RDDIRWAIT;
		cv_broadcast(&rdc->cv);
	}
	if (error)
		rdc->flags |= RDDIRREQ;
	mutex_exit(&rp->r_statelock);

	rddir_cache_rele(rdc);

	return (error);
}

#ifdef DEBUG
static int nfs_bio_do_stop = 0;
#endif

static int
nfs_bio(struct buf *bp, cred_t *cr)
{
	rnode_t *rp = VTOR(bp->b_vp);
	int count;
	int error;
	cred_t *cred;
	uint_t offset;

	DTRACE_IO1(start, struct buf *, bp);

	ASSERT(nfs_zone() == VTOMI(bp->b_vp)->mi_zone);
	offset = dbtob(bp->b_blkno);

	if (bp->b_flags & B_READ) {
		mutex_enter(&rp->r_statelock);
		if (rp->r_cred != NULL) {
			cred = rp->r_cred;
			crhold(cred);
		} else {
			rp->r_cred = cr;
			crhold(cr);
			cred = cr;
			crhold(cred);
		}
		mutex_exit(&rp->r_statelock);
	read_again:
		error = bp->b_error = nfsread(bp->b_vp, bp->b_un.b_addr,
		    offset, bp->b_bcount, &bp->b_resid, cred);

		crfree(cred);
		if (!error) {
			if (bp->b_resid) {
				/*
				 * Didn't get it all because we hit EOF,
				 * zero all the memory beyond the EOF.
				 */
				/* bzero(rdaddr + */
				bzero(bp->b_un.b_addr +
				    bp->b_bcount - bp->b_resid, bp->b_resid);
			}
			mutex_enter(&rp->r_statelock);
			if (bp->b_resid == bp->b_bcount &&
			    offset >= rp->r_size) {
				/*
				 * We didn't read anything at all as we are
				 * past EOF.  Return an error indicator back
				 * but don't destroy the pages (yet).
				 */
				error = NFS_EOF;
			}
			mutex_exit(&rp->r_statelock);
		} else if (error == EACCES) {
			mutex_enter(&rp->r_statelock);
			if (cred != cr) {
				if (rp->r_cred != NULL)
					crfree(rp->r_cred);
				rp->r_cred = cr;
				crhold(cr);
				cred = cr;
				crhold(cred);
				mutex_exit(&rp->r_statelock);
				goto read_again;
			}
			mutex_exit(&rp->r_statelock);
		}
	} else {
		if (!(rp->r_flags & RSTALE)) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_cred != NULL) {
				cred = rp->r_cred;
				crhold(cred);
			} else {
				rp->r_cred = cr;
				crhold(cr);
				cred = cr;
				crhold(cred);
			}
			mutex_exit(&rp->r_statelock);
		write_again:
			mutex_enter(&rp->r_statelock);
			count = MIN(bp->b_bcount, rp->r_size - offset);
			mutex_exit(&rp->r_statelock);
			if (count < 0)
				cmn_err(CE_PANIC, "nfs_bio: write count < 0");
#ifdef DEBUG
			if (count == 0) {
				zcmn_err(getzoneid(), CE_WARN,
				    "nfs_bio: zero length write at %d",
				    offset);
				nfs_printfhandle(&rp->r_fh);
				if (nfs_bio_do_stop)
					debug_enter("nfs_bio");
			}
#endif
			error = nfswrite(bp->b_vp, bp->b_un.b_addr, offset,
			    count, cred);
			if (error == EACCES) {
				mutex_enter(&rp->r_statelock);
				if (cred != cr) {
					if (rp->r_cred != NULL)
						crfree(rp->r_cred);
					rp->r_cred = cr;
					crhold(cr);
					crfree(cred);
					cred = cr;
					crhold(cred);
					mutex_exit(&rp->r_statelock);
					goto write_again;
				}
				mutex_exit(&rp->r_statelock);
			}
			bp->b_error = error;
			if (error && error != EINTR) {
				/*
				 * Don't print EDQUOT errors on the console.
				 * Don't print asynchronous EACCES errors.
				 * Don't print EFBIG errors.
				 * Print all other write errors.
				 */
				if (error != EDQUOT && error != EFBIG &&
				    (error != EACCES ||
				    !(bp->b_flags & B_ASYNC)))
					nfs_write_error(bp->b_vp, error, cred);
				/*
				 * Update r_error and r_flags as appropriate.
				 * If the error was ESTALE, then mark the
				 * rnode as not being writeable and save
				 * the error status.  Otherwise, save any
				 * errors which occur from asynchronous
				 * page invalidations.  Any errors occurring
				 * from other operations should be saved
				 * by the caller.
				 */
				mutex_enter(&rp->r_statelock);
				if (error == ESTALE) {
					rp->r_flags |= RSTALE;
					if (!rp->r_error)
						rp->r_error = error;
				} else if (!rp->r_error &&
				    (bp->b_flags &
				    (B_INVAL|B_FORCE|B_ASYNC)) ==
				    (B_INVAL|B_FORCE|B_ASYNC)) {
					rp->r_error = error;
				}
				mutex_exit(&rp->r_statelock);
			}
			crfree(cred);
		} else {
			error = rp->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
		}
	}

	if (error != 0 && error != NFS_EOF)
		bp->b_flags |= B_ERROR;

	DTRACE_IO1(done, struct buf *, bp);

	return (error);
}

/* ARGSUSED */
static int
nfs_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	struct nfs_fid *fp;
	rnode_t *rp;

	rp = VTOR(vp);

	if (fidp->fid_len < (sizeof (struct nfs_fid) - sizeof (short))) {
		fidp->fid_len = sizeof (struct nfs_fid) - sizeof (short);
		return (ENOSPC);
	}
	fp = (struct nfs_fid *)fidp;
	fp->nf_pad = 0;
	fp->nf_len = sizeof (struct nfs_fid) - sizeof (short);
	bcopy(rp->r_fh.fh_buf, fp->nf_data, NFS_FHSIZE);
	return (0);
}

/* ARGSUSED2 */
static int
nfs_rwlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	rnode_t *rp = VTOR(vp);

	if (!write_lock) {
		(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_READER, FALSE);
		return (V_WRITELOCK_FALSE);
	}

	if ((rp->r_flags & RDIRECTIO) || (VTOMI(vp)->mi_flags & MI_DIRECTIO)) {
		(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_READER, FALSE);
		if (rp->r_mapcnt == 0 && !vn_has_cached_data(vp))
			return (V_WRITELOCK_FALSE);
		nfs_rw_exit(&rp->r_rwlock);
	}

	(void) nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER, FALSE);
	return (V_WRITELOCK_TRUE);
}

/* ARGSUSED */
static void
nfs_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	rnode_t *rp = VTOR(vp);

	nfs_rw_exit(&rp->r_rwlock);
}

/* ARGSUSED */
static int
nfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{

	/*
	 * Because we stuff the readdir cookie into the offset field
	 * someone may attempt to do an lseek with the cookie which
	 * we want to succeed.
	 */
	if (vp->v_type == VDIR)
		return (0);
	if (*noffp < 0 || *noffp > MAXOFF32_T)
		return (EINVAL);
	return (0);
}

/*
 * number of NFS_MAXDATA blocks to read ahead
 * optimized for 100 base-T.
 */
static int nfs_nra = 4;

#ifdef DEBUG
static int nfs_lostpage = 0;	/* number of times we lost original page */
#endif

/*
 * Return all the pages from [off..off+len) in file
 */
/* ARGSUSED */
static int
nfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	rnode_t *rp;
	int error;
	mntinfo_t *mi;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	ASSERT(off <= MAXOFF32_T);
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	if (protp != NULL)
		*protp = PROT_ALL;

	/*
	 * Now valididate that the caches are up to date.
	 */
	error = nfs_validate_caches(vp, cr);
	if (error)
		return (error);

	rp = VTOR(vp);
	mi = VTOMI(vp);
retry:
	mutex_enter(&rp->r_statelock);

	/*
	 * Don't create dirty pages faster than they
	 * can be cleaned so that the system doesn't
	 * get imbalanced.  If the async queue is
	 * maxed out, then wait for it to drain before
	 * creating more dirty pages.  Also, wait for
	 * any threads doing pagewalks in the vop_getattr
	 * entry points so that they don't block for
	 * long periods.
	 */
	if (rw == S_CREATE) {
		while ((mi->mi_max_threads != 0 &&
		    rp->r_awcount > 2 * mi->mi_max_threads) ||
		    rp->r_gcount > 0)
			cv_wait(&rp->r_cv, &rp->r_statelock);
	}

	/*
	 * If we are getting called as a side effect of an nfs_write()
	 * operation the local file size might not be extended yet.
	 * In this case we want to be able to return pages of zeroes.
	 */
	if (off + len > rp->r_size + PAGEOFFSET && seg != segkmap) {
		mutex_exit(&rp->r_statelock);
		return (EFAULT);		/* beyond EOF */
	}

	mutex_exit(&rp->r_statelock);

	if (len <= PAGESIZE) {
		error = nfs_getapage(vp, off, len, protp, pl, plsz,
		    seg, addr, rw, cr);
	} else {
		error = pvn_getpages(nfs_getapage, vp, off, len, protp,
		    pl, plsz, seg, addr, rw, cr);
	}

	switch (error) {
	case NFS_EOF:
		nfs_purge_caches(vp, NFS_NOPURGE_DNLC, cr);
		goto retry;
	case ESTALE:
		PURGE_STALE_FH(error, vp, cr);
	}

	return (error);
}

/*
 * Called from pvn_getpages or nfs_getpage to get a particular page.
 */
/* ARGSUSED */
static int
nfs_getapage(vnode_t *vp, u_offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr)
{
	rnode_t *rp;
	uint_t bsize;
	struct buf *bp;
	page_t *pp;
	u_offset_t lbn;
	u_offset_t io_off;
	u_offset_t blkoff;
	u_offset_t rablkoff;
	size_t io_len;
	uint_t blksize;
	int error;
	int readahead;
	int readahead_issued = 0;
	int ra_window; /* readahead window */
	page_t *pagefound;

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	rp = VTOR(vp);
	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);

reread:
	bp = NULL;
	pp = NULL;
	pagefound = NULL;

	if (pl != NULL)
		pl[0] = NULL;

	error = 0;
	lbn = off / bsize;
	blkoff = lbn * bsize;

	/*
	 * Queueing up the readahead before doing the synchronous read
	 * results in a significant increase in read throughput because
	 * of the increased parallelism between the async threads and
	 * the process context.
	 */
	if ((off & ((vp->v_vfsp->vfs_bsize) - 1)) == 0 &&
	    rw != S_CREATE &&
	    !(vp->v_flag & VNOCACHE)) {
		mutex_enter(&rp->r_statelock);

		/*
		 * Calculate the number of readaheads to do.
		 * a) No readaheads at offset = 0.
		 * b) Do maximum(nfs_nra) readaheads when the readahead
		 *    window is closed.
		 * c) Do readaheads between 1 to (nfs_nra - 1) depending
		 *    upon how far the readahead window is open or close.
		 * d) No readaheads if rp->r_nextr is not within the scope
		 *    of the readahead window (random i/o).
		 */

		if (off == 0)
			readahead = 0;
		else if (blkoff == rp->r_nextr)
			readahead = nfs_nra;
		else if (rp->r_nextr > blkoff &&
		    ((ra_window = (rp->r_nextr - blkoff) / bsize)
		    <= (nfs_nra - 1)))
			readahead = nfs_nra - ra_window;
		else
			readahead = 0;

		rablkoff = rp->r_nextr;
		while (readahead > 0 && rablkoff + bsize < rp->r_size) {
			mutex_exit(&rp->r_statelock);
			if (nfs_async_readahead(vp, rablkoff + bsize,
			    addr + (rablkoff + bsize - off), seg, cr,
			    nfs_readahead) < 0) {
				mutex_enter(&rp->r_statelock);
				break;
			}
			readahead--;
			rablkoff += bsize;
			/*
			 * Indicate that we did a readahead so
			 * readahead offset is not updated
			 * by the synchronous read below.
			 */
			readahead_issued = 1;
			mutex_enter(&rp->r_statelock);
			/*
			 * set readahead offset to
			 * offset of last async readahead
			 * request.
			 */
			rp->r_nextr = rablkoff;
		}
		mutex_exit(&rp->r_statelock);
	}

again:
	if ((pagefound = page_exists(vp, off)) == NULL) {
		if (pl == NULL) {
			(void) nfs_async_readahead(vp, blkoff, addr, seg, cr,
			    nfs_readahead);
		} else if (rw == S_CREATE) {
			/*
			 * Block for this page is not allocated, or the offset
			 * is beyond the current allocation size, or we're
			 * allocating a swap slot and the page was not found,
			 * so allocate it and return a zero page.
			 */
			if ((pp = page_create_va(vp, off,
			    PAGESIZE, PG_WAIT, seg, addr)) == NULL)
				cmn_err(CE_PANIC, "nfs_getapage: page_create");
			io_len = PAGESIZE;
			mutex_enter(&rp->r_statelock);
			rp->r_nextr = off + PAGESIZE;
			mutex_exit(&rp->r_statelock);
		} else {
			/*
			 * Need to go to server to get a BLOCK, exception to
			 * that being while reading at offset = 0 or doing
			 * random i/o, in that case read only a PAGE.
			 */
			mutex_enter(&rp->r_statelock);
			if (blkoff < rp->r_size &&
			    blkoff + bsize >= rp->r_size) {
				/*
				 * If only a block or less is left in
				 * the file, read all that is remaining.
				 */
				if (rp->r_size <= off) {
					/*
					 * Trying to access beyond EOF,
					 * set up to get at least one page.
					 */
					blksize = off + PAGESIZE - blkoff;
				} else
					blksize = rp->r_size - blkoff;
			} else if ((off == 0) ||
			    (off != rp->r_nextr && !readahead_issued)) {
				blksize = PAGESIZE;
				blkoff = off; /* block = page here */
			} else
				blksize = bsize;
			mutex_exit(&rp->r_statelock);

			pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
			    &io_len, blkoff, blksize, 0);

			/*
			 * Some other thread has entered the page,
			 * so just use it.
			 */
			if (pp == NULL)
				goto again;

			/*
			 * Now round the request size up to page boundaries.
			 * This ensures that the entire page will be
			 * initialized to zeroes if EOF is encountered.
			 */
			io_len = ptob(btopr(io_len));

			bp = pageio_setup(pp, io_len, vp, B_READ);
			ASSERT(bp != NULL);

			/*
			 * pageio_setup should have set b_addr to 0.  This
			 * is correct since we want to do I/O on a page
			 * boundary.  bp_mapin will use this addr to calculate
			 * an offset, and then set b_addr to the kernel virtual
			 * address it allocated for us.
			 */
			ASSERT(bp->b_un.b_addr == 0);

			bp->b_edev = 0;
			bp->b_dev = 0;
			bp->b_lblkno = lbtodb(io_off);
			bp->b_file = vp;
			bp->b_offset = (offset_t)off;
			bp_mapin(bp);

			/*
			 * If doing a write beyond what we believe is EOF,
			 * don't bother trying to read the pages from the
			 * server, we'll just zero the pages here.  We
			 * don't check that the rw flag is S_WRITE here
			 * because some implementations may attempt a
			 * read access to the buffer before copying data.
			 */
			mutex_enter(&rp->r_statelock);
			if (io_off >= rp->r_size && seg == segkmap) {
				mutex_exit(&rp->r_statelock);
				bzero(bp->b_un.b_addr, io_len);
			} else {
				mutex_exit(&rp->r_statelock);
				error = nfs_bio(bp, cr);
			}

			/*
			 * Unmap the buffer before freeing it.
			 */
			bp_mapout(bp);
			pageio_done(bp);

			if (error == NFS_EOF) {
				/*
				 * If doing a write system call just return
				 * zeroed pages, else user tried to get pages
				 * beyond EOF, return error.  We don't check
				 * that the rw flag is S_WRITE here because
				 * some implementations may attempt a read
				 * access to the buffer before copying data.
				 */
				if (seg == segkmap)
					error = 0;
				else
					error = EFAULT;
			}

			if (!readahead_issued && !error) {
				mutex_enter(&rp->r_statelock);
				rp->r_nextr = io_off + io_len;
				mutex_exit(&rp->r_statelock);
			}
		}
	}

out:
	if (pl == NULL)
		return (error);

	if (error) {
		if (pp != NULL)
			pvn_read_done(pp, B_ERROR);
		return (error);
	}

	if (pagefound) {
		se_t se = (rw == S_CREATE ? SE_EXCL : SE_SHARED);

		/*
		 * Page exists in the cache, acquire the appropriate lock.
		 * If this fails, start all over again.
		 */
		if ((pp = page_lookup(vp, off, se)) == NULL) {
#ifdef DEBUG
			nfs_lostpage++;
#endif
			goto reread;
		}
		pl[0] = pp;
		pl[1] = NULL;
		return (0);
	}

	if (pp != NULL)
		pvn_plist_init(pp, pl, plsz, off, io_len, rw);

	return (error);
}

static void
nfs_readahead(vnode_t *vp, u_offset_t blkoff, caddr_t addr, struct seg *seg,
	cred_t *cr)
{
	int error;
	page_t *pp;
	u_offset_t io_off;
	size_t io_len;
	struct buf *bp;
	uint_t bsize, blksize;
	rnode_t *rp = VTOR(vp);

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);

	mutex_enter(&rp->r_statelock);
	if (blkoff < rp->r_size && blkoff + bsize > rp->r_size) {
		/*
		 * If less than a block left in file read less
		 * than a block.
		 */
		blksize = rp->r_size - blkoff;
	} else
		blksize = bsize;
	mutex_exit(&rp->r_statelock);

	pp = pvn_read_kluster(vp, blkoff, segkmap, addr,
	    &io_off, &io_len, blkoff, blksize, 1);
	/*
	 * The isra flag passed to the kluster function is 1, we may have
	 * gotten a return value of NULL for a variety of reasons (# of free
	 * pages < minfree, someone entered the page on the vnode etc). In all
	 * cases, we want to punt on the readahead.
	 */
	if (pp == NULL)
		return;

	/*
	 * Now round the request size up to page boundaries.
	 * This ensures that the entire page will be
	 * initialized to zeroes if EOF is encountered.
	 */
	io_len = ptob(btopr(io_len));

	bp = pageio_setup(pp, io_len, vp, B_READ);
	ASSERT(bp != NULL);

	/*
	 * pageio_setup should have set b_addr to 0.  This is correct since
	 * we want to do I/O on a page boundary. bp_mapin() will use this addr
	 * to calculate an offset, and then set b_addr to the kernel virtual
	 * address it allocated for us.
	 */
	ASSERT(bp->b_un.b_addr == 0);

	bp->b_edev = 0;
	bp->b_dev = 0;
	bp->b_lblkno = lbtodb(io_off);
	bp->b_file = vp;
	bp->b_offset = (offset_t)blkoff;
	bp_mapin(bp);

	/*
	 * If doing a write beyond what we believe is EOF, don't bother trying
	 * to read the pages from the server, we'll just zero the pages here.
	 * We don't check that the rw flag is S_WRITE here because some
	 * implementations may attempt a read access to the buffer before
	 * copying data.
	 */
	mutex_enter(&rp->r_statelock);
	if (io_off >= rp->r_size && seg == segkmap) {
		mutex_exit(&rp->r_statelock);
		bzero(bp->b_un.b_addr, io_len);
		error = 0;
	} else {
		mutex_exit(&rp->r_statelock);
		error = nfs_bio(bp, cr);
		if (error == NFS_EOF)
			error = 0;
	}

	/*
	 * Unmap the buffer before freeing it.
	 */
	bp_mapout(bp);
	pageio_done(bp);

	pvn_read_done(pp, error ? B_READ | B_ERROR : B_READ);

	/*
	 * In case of error set readahead offset
	 * to the lowest offset.
	 * pvn_read_done() calls VN_DISPOSE to destroy the pages
	 */
	if (error && rp->r_nextr > io_off) {
		mutex_enter(&rp->r_statelock);
		if (rp->r_nextr > io_off)
			rp->r_nextr = io_off;
		mutex_exit(&rp->r_statelock);
	}
}

/*
 * Flags are composed of {B_INVAL, B_FREE, B_DONTNEED, B_FORCE}
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 && off == 0 (entire vp list),
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 */
/* ARGSUSED */
static int
nfs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	rnode_t *rp;

	ASSERT(cr != NULL);

	/*
	 * XXX - Why should this check be made here?
	 */
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (len == 0 && !(flags & B_INVAL) && vn_is_readonly(vp))
		return (0);

	if (!(flags & B_ASYNC) && nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	ASSERT(off <= MAXOFF32_T);

	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);
	error = nfs_putpages(vp, off, len, flags, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_count--;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);

	return (error);
}

/*
 * Write out a single page, possibly klustering adjacent dirty pages.
 */
int
nfs_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp, size_t *lenp,
	int flags, cred_t *cr)
{
	u_offset_t io_off;
	u_offset_t lbn_off;
	u_offset_t lbn;
	size_t io_len;
	uint_t bsize;
	int error;
	rnode_t *rp;

	ASSERT(!vn_is_readonly(vp));
	ASSERT(pp != NULL);
	ASSERT(cr != NULL);
	ASSERT((flags & B_ASYNC) || nfs_zone() == VTOMI(vp)->mi_zone);

	rp = VTOR(vp);
	ASSERT(rp->r_count > 0);

	ASSERT(pp->p_offset <= MAXOFF32_T);

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);
	lbn = pp->p_offset / bsize;
	lbn_off = lbn * bsize;

	/*
	 * Find a kluster that fits in one block, or in
	 * one page if pages are bigger than blocks.  If
	 * there is less file space allocated than a whole
	 * page, we'll shorten the i/o request below.
	 */
	pp = pvn_write_kluster(vp, pp, &io_off, &io_len, lbn_off,
	    roundup(bsize, PAGESIZE), flags);

	/*
	 * pvn_write_kluster shouldn't have returned a page with offset
	 * behind the original page we were given.  Verify that.
	 */
	ASSERT((pp->p_offset / bsize) >= lbn);

	/*
	 * Now pp will have the list of kept dirty pages marked for
	 * write back.  It will also handle invalidation and freeing
	 * of pages that are not dirty.  Check for page length rounding
	 * problems.
	 */
	if (io_off + io_len > lbn_off + bsize) {
		ASSERT((io_off + io_len) - (lbn_off + bsize) < PAGESIZE);
		io_len = lbn_off + bsize - io_off;
	}
	/*
	 * The RMODINPROGRESS flag makes sure that nfs(3)_bio() sees a
	 * consistent value of r_size. RMODINPROGRESS is set in writerp().
	 * When RMODINPROGRESS is set it indicates that a uiomove() is in
	 * progress and the r_size has not been made consistent with the
	 * new size of the file. When the uiomove() completes the r_size is
	 * updated and the RMODINPROGRESS flag is cleared.
	 *
	 * The RMODINPROGRESS flag makes sure that nfs(3)_bio() sees a
	 * consistent value of r_size. Without this handshaking, it is
	 * possible that nfs(3)_bio() picks  up the old value of r_size
	 * before the uiomove() in writerp() completes. This will result
	 * in the write through nfs(3)_bio() being dropped.
	 *
	 * More precisely, there is a window between the time the uiomove()
	 * completes and the time the r_size is updated. If a VOP_PUTPAGE()
	 * operation intervenes in this window, the page will be picked up,
	 * because it is dirty (it will be unlocked, unless it was
	 * pagecreate'd). When the page is picked up as dirty, the dirty
	 * bit is reset (pvn_getdirty()). In nfs(3)write(), r_size is
	 * checked. This will still be the old size. Therefore the page will
	 * not be written out. When segmap_release() calls VOP_PUTPAGE(),
	 * the page will be found to be clean and the write will be dropped.
	 */
	if (rp->r_flags & RMODINPROGRESS) {
		mutex_enter(&rp->r_statelock);
		if ((rp->r_flags & RMODINPROGRESS) &&
		    rp->r_modaddr + MAXBSIZE > io_off &&
		    rp->r_modaddr < io_off + io_len) {
			page_t *plist;
			/*
			 * A write is in progress for this region of the file.
			 * If we did not detect RMODINPROGRESS here then this
			 * path through nfs_putapage() would eventually go to
			 * nfs(3)_bio() and may not write out all of the data
			 * in the pages. We end up losing data. So we decide
			 * to set the modified bit on each page in the page
			 * list and mark the rnode with RDIRTY. This write
			 * will be restarted at some later time.
			 */
			plist = pp;
			while (plist != NULL) {
				pp = plist;
				page_sub(&plist, pp);
				hat_setmod(pp);
				page_io_unlock(pp);
				page_unlock(pp);
			}
			rp->r_flags |= RDIRTY;
			mutex_exit(&rp->r_statelock);
			if (offp)
				*offp = io_off;
			if (lenp)
				*lenp = io_len;
			return (0);
		}
		mutex_exit(&rp->r_statelock);
	}

	if (flags & B_ASYNC) {
		error = nfs_async_putapage(vp, pp, io_off, io_len, flags, cr,
		    nfs_sync_putapage);
	} else
		error = nfs_sync_putapage(vp, pp, io_off, io_len, flags, cr);

	if (offp)
		*offp = io_off;
	if (lenp)
		*lenp = io_len;
	return (error);
}

static int
nfs_sync_putapage(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
	int flags, cred_t *cr)
{
	int error;
	rnode_t *rp;

	flags |= B_WRITE;

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);
	error = nfs_rdwrlbn(vp, pp, io_off, io_len, flags, cr);

	rp = VTOR(vp);

	if ((error == ENOSPC || error == EDQUOT || error == EACCES) &&
	    (flags & (B_INVAL|B_FORCE)) != (B_INVAL|B_FORCE)) {
		if (!(rp->r_flags & ROUTOFSPACE)) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= ROUTOFSPACE;
			mutex_exit(&rp->r_statelock);
		}
		flags |= B_ERROR;
		pvn_write_done(pp, flags);
		/*
		 * If this was not an async thread, then try again to
		 * write out the pages, but this time, also destroy
		 * them whether or not the write is successful.  This
		 * will prevent memory from filling up with these
		 * pages and destroying them is the only alternative
		 * if they can't be written out.
		 *
		 * Don't do this if this is an async thread because
		 * when the pages are unlocked in pvn_write_done,
		 * some other thread could have come along, locked
		 * them, and queued for an async thread.  It would be
		 * possible for all of the async threads to be tied
		 * up waiting to lock the pages again and they would
		 * all already be locked and waiting for an async
		 * thread to handle them.  Deadlock.
		 */
		if (!(flags & B_ASYNC)) {
			error = nfs_putpage(vp, io_off, io_len,
			    B_INVAL | B_FORCE, cr, NULL);
		}
	} else {
		if (error)
			flags |= B_ERROR;
		else if (rp->r_flags & ROUTOFSPACE) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags &= ~ROUTOFSPACE;
			mutex_exit(&rp->r_statelock);
		}
		pvn_write_done(pp, flags);
	}

	return (error);
}

/* ARGSUSED */
static int
nfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
	caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	int error;
	rnode_t *rp;
	struct vattr va;

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off > MAXOFF32_T)
		return (EFBIG);

	if (off < 0 || off + len < 0)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	/*
	 * If there is cached data and if close-to-open consistency
	 * checking is not turned off and if the file system is not
	 * mounted readonly, then force an over the wire getattr.
	 * Otherwise, just invoke nfsgetattr to get a copy of the
	 * attributes.  The attribute cache will be used unless it
	 * is timed out and if it is, then an over the wire getattr
	 * will be issued.
	 */
	va.va_mask = AT_ALL;
	if (vn_has_cached_data(vp) &&
	    !(VTOMI(vp)->mi_flags & MI_NOCTO) && !vn_is_readonly(vp))
		error = nfs_getattr_otw(vp, &va, cr);
	else
		error = nfsgetattr(vp, &va, cr);
	if (error)
		return (error);

	/*
	 * Check to see if the vnode is currently marked as not cachable.
	 * This means portions of the file are locked (through VOP_FRLOCK).
	 * In this case the map request must be refused.  We use
	 * rp->r_lkserlock to avoid a race with concurrent lock requests.
	 */
	rp = VTOR(vp);

	/*
	 * Atomically increment r_inmap after acquiring r_rwlock. The
	 * idea here is to acquire r_rwlock to block read/write and
	 * not to protect r_inmap. r_inmap will inform nfs_read/write()
	 * that we are in nfs_map(). Now, r_rwlock is acquired in order
	 * and we can prevent the deadlock that would have occurred
	 * when nfs_addmap() would have acquired it out of order.
	 *
	 * Since we are not protecting r_inmap by any lock, we do not
	 * hold any lock when we decrement it. We atomically decrement
	 * r_inmap after we release r_lkserlock.
	 */

	if (nfs_rw_enter_sig(&rp->r_rwlock, RW_WRITER, INTR(vp)))
		return (EINTR);
	atomic_add_int(&rp->r_inmap, 1);
	nfs_rw_exit(&rp->r_rwlock);

	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_READER, INTR(vp))) {
		atomic_add_int(&rp->r_inmap, -1);
		return (EINTR);
	}
	if (vp->v_flag & VNOCACHE) {
		error = EAGAIN;
		goto done;
	}

	/*
	 * Don't allow concurrent locks and mapping if mandatory locking is
	 * enabled.
	 */
	if ((flk_has_remote_locks(vp) || lm_has_sleep(vp)) &&
	    MANDLOCK(vp, va.va_mode)) {
		error = EAGAIN;
		goto done;
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto done;
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = (flags & MAP_TYPE);
	vn_a.prot = (uchar_t)prot;
	vn_a.maxprot = (uchar_t)maxprot;
	vn_a.flags = (flags & ~MAP_TYPE);
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);

done:
	nfs_rw_exit(&rp->r_lkserlock);
	atomic_add_int(&rp->r_inmap, -1);
	return (error);
}

/* ARGSUSED */
static int
nfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
	caller_context_t *ct)
{
	rnode_t *rp;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	rp = VTOR(vp);
	atomic_add_long((ulong_t *)&rp->r_mapcnt, btopr(len));

	return (0);
}

/* ARGSUSED */
static int
nfs_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag, offset_t offset,
	struct flk_callback *flk_cbp, cred_t *cr, caller_context_t *ct)
{
	netobj lm_fh;
	int rc;
	u_offset_t start, end;
	rnode_t *rp;
	int error = 0, intr = INTR(vp);

	/* check for valid cmd parameter */
	if (cmd != F_GETLK && cmd != F_SETLK && cmd != F_SETLKW)
		return (EINVAL);
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	/* Verify l_type. */
	switch (bfp->l_type) {
	case F_RDLCK:
		if (cmd != F_GETLK && !(flag & FREAD))
			return (EBADF);
		break;
	case F_WRLCK:
		if (cmd != F_GETLK && !(flag & FWRITE))
			return (EBADF);
		break;
	case F_UNLCK:
		intr = 0;
		break;

	default:
		return (EINVAL);
	}

	/* check the validity of the lock range */
	if (rc = flk_convert_lock_data(vp, bfp, &start, &end, offset))
		return (rc);
	if (rc = flk_check_lock_data(start, end, MAXOFF32_T))
		return (rc);

	/*
	 * If the filesystem is mounted using local locking, pass the
	 * request off to the local locking code.
	 */
	if (VTOMI(vp)->mi_flags & MI_LLOCK) {
		if (offset > MAXOFF32_T)
			return (EFBIG);
		if (cmd == F_SETLK || cmd == F_SETLKW) {
			/*
			 * For complete safety, we should be holding
			 * r_lkserlock.  However, we can't call
			 * lm_safelock and then fs_frlock while
			 * holding r_lkserlock, so just invoke
			 * lm_safelock and expect that this will
			 * catch enough of the cases.
			 */
			if (!lm_safelock(vp, bfp, cr))
				return (EAGAIN);
		}
		return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
	}

	rp = VTOR(vp);

	/*
	 * Check whether the given lock request can proceed, given the
	 * current file mappings.
	 */
	if (nfs_rw_enter_sig(&rp->r_lkserlock, RW_WRITER, intr))
		return (EINTR);
	if (cmd == F_SETLK || cmd == F_SETLKW) {
		if (!lm_safelock(vp, bfp, cr)) {
			rc = EAGAIN;
			goto done;
		}
	}

	/*
	 * Flush the cache after waiting for async I/O to finish.  For new
	 * locks, this is so that the process gets the latest bits from the
	 * server.  For unlocks, this is so that other clients see the
	 * latest bits once the file has been unlocked.  If currently dirty
	 * pages can't be flushed, then don't allow a lock to be set.  But
	 * allow unlocks to succeed, to avoid having orphan locks on the
	 * server.
	 */
	if (cmd != F_GETLK) {
		mutex_enter(&rp->r_statelock);
		while (rp->r_count > 0) {
			if (intr) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (cv_wait_sig(&rp->r_cv, &rp->r_statelock)
				    == 0) {
					if (lwp != NULL)
						lwp->lwp_nostop--;
					rc = EINTR;
					break;
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
			cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
		if (rc != 0)
			goto done;
		error = nfs_putpage(vp, (offset_t)0, 0, B_INVAL, cr, ct);
		if (error) {
			if (error == ENOSPC || error == EDQUOT) {
				mutex_enter(&rp->r_statelock);
				if (!rp->r_error)
					rp->r_error = error;
				mutex_exit(&rp->r_statelock);
			}
			if (bfp->l_type != F_UNLCK) {
				rc = ENOLCK;
				goto done;
			}
		}
	}

	lm_fh.n_len = sizeof (fhandle_t);
	lm_fh.n_bytes = (char *)VTOFH(vp);

	/*
	 * Call the lock manager to do the real work of contacting
	 * the server and obtaining the lock.
	 */
	rc = lm_frlock(vp, cmd, bfp, flag, offset, cr, &lm_fh, flk_cbp);

	if (rc == 0)
		nfs_lockcompletion(vp, cmd);

done:
	nfs_rw_exit(&rp->r_lkserlock);
	return (rc);
}

/*
 * Free storage space associated with the specified vnode.  The portion
 * to be freed is specified by bfp->l_start and bfp->l_len (already
 * normalized to a "whence" of 0).
 *
 * This is an experimental facility whose continued existence is not
 * guaranteed.  Currently, we only support the special case
 * of l_len == 0, meaning free to end of file.
 */
/* ARGSUSED */
static int
nfs_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int error;

	ASSERT(vp->v_type == VREG);
	if (cmd != F_FREESP)
		return (EINVAL);

	if (offset > MAXOFF32_T)
		return (EFBIG);

	if ((bfp->l_start > MAXOFF32_T) || (bfp->l_end > MAXOFF32_T) ||
	    (bfp->l_len > MAXOFF32_T))
		return (EFBIG);

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	error = convoff(vp, bfp, 0, offset);
	if (!error) {
		ASSERT(bfp->l_start >= 0);
		if (bfp->l_len == 0) {
			struct vattr va;

			/*
			 * ftruncate should not change the ctime and
			 * mtime if we truncate the file to its
			 * previous size.
			 */
			va.va_mask = AT_SIZE;
			error = nfsgetattr(vp, &va, cr);
			if (error || va.va_size == bfp->l_start)
				return (error);
			va.va_mask = AT_SIZE;
			va.va_size = bfp->l_start;
			error = nfssetattr(vp, &va, 0, cr);

			if (error == 0 && bfp->l_start == 0)
				vnevent_truncate(vp, ct);
		} else
			error = EINVAL;
	}

	return (error);
}

/* ARGSUSED */
static int
nfs_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{

	return (EINVAL);
}

/*
 * Setup and add an address space callback to do the work of the delmap call.
 * The callback will (and must be) deleted in the actual callback function.
 *
 * This is done in order to take care of the problem that we have with holding
 * the address space's a_lock for a long period of time (e.g. if the NFS server
 * is down).  Callbacks will be executed in the address space code while the
 * a_lock is not held.	Holding the address space's a_lock causes things such
 * as ps and fork to hang because they are trying to acquire this lock as well.
 */
/* ARGSUSED */
static int
nfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
	caller_context_t *ct)
{
	int			caller_found;
	int			error;
	rnode_t			*rp;
	nfs_delmap_args_t	*dmapp;
	nfs_delmapcall_t	*delmap_call;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);
	/*
	 * A process may not change zones if it has NFS pages mmap'ed
	 * in, so we can't legitimately get here from the wrong zone.
	 */
	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);

	rp = VTOR(vp);

	/*
	 * The way that the address space of this process deletes its mapping
	 * of this file is via the following call chains:
	 * - as_free()->SEGOP_UNMAP()/segvn_unmap()->VOP_DELMAP()/nfs_delmap()
	 * - as_unmap()->SEGOP_UNMAP()/segvn_unmap()->VOP_DELMAP()/nfs_delmap()
	 *
	 * With the use of address space callbacks we are allowed to drop the
	 * address space lock, a_lock, while executing the NFS operations that
	 * need to go over the wire.  Returning EAGAIN to the caller of this
	 * function is what drives the execution of the callback that we add
	 * below.  The callback will be executed by the address space code
	 * after dropping the a_lock.  When the callback is finished, since
	 * we dropped the a_lock, it must be re-acquired and segvn_unmap()
	 * is called again on the same segment to finish the rest of the work
	 * that needs to happen during unmapping.
	 *
	 * This action of calling back into the segment driver causes
	 * nfs_delmap() to get called again, but since the callback was
	 * already executed at this point, it already did the work and there
	 * is nothing left for us to do.
	 *
	 * To Summarize:
	 * - The first time nfs_delmap is called by the current thread is when
	 * we add the caller associated with this delmap to the delmap caller
	 * list, add the callback, and return EAGAIN.
	 * - The second time in this call chain when nfs_delmap is called we
	 * will find this caller in the delmap caller list and realize there
	 * is no more work to do thus removing this caller from the list and
	 * returning the error that was set in the callback execution.
	 */
	caller_found = nfs_find_and_delete_delmapcall(rp, &error);
	if (caller_found) {
		/*
		 * 'error' is from the actual delmap operations.  To avoid
		 * hangs, we need to handle the return of EAGAIN differently
		 * since this is what drives the callback execution.
		 * In this case, we don't want to return EAGAIN and do the
		 * callback execution because there are none to execute.
		 */
		if (error == EAGAIN)
			return (0);
		else
			return (error);
	}

	/* current caller was not in the list */
	delmap_call = nfs_init_delmapcall();

	mutex_enter(&rp->r_statelock);
	list_insert_tail(&rp->r_indelmap, delmap_call);
	mutex_exit(&rp->r_statelock);

	dmapp = kmem_alloc(sizeof (nfs_delmap_args_t), KM_SLEEP);

	dmapp->vp = vp;
	dmapp->off = off;
	dmapp->addr = addr;
	dmapp->len = len;
	dmapp->prot = prot;
	dmapp->maxprot = maxprot;
	dmapp->flags = flags;
	dmapp->cr = cr;
	dmapp->caller = delmap_call;

	error = as_add_callback(as, nfs_delmap_callback, dmapp,
	    AS_UNMAP_EVENT, addr, len, KM_SLEEP);

	return (error ? error : EAGAIN);
}

/*
 * Remove some pages from an mmap'd vnode.  Just update the
 * count of pages.  If doing close-to-open, then flush all
 * of the pages associated with this file.  Otherwise, start
 * an asynchronous page flush to write out any dirty pages.
 * This will also associate a credential with the rnode which
 * can be used to write the pages.
 */
/* ARGSUSED */
static void
nfs_delmap_callback(struct as *as, void *arg, uint_t event)
{
	int			error;
	rnode_t			*rp;
	mntinfo_t		*mi;
	nfs_delmap_args_t	*dmapp = (nfs_delmap_args_t *)arg;

	rp = VTOR(dmapp->vp);
	mi = VTOMI(dmapp->vp);

	atomic_add_long((ulong_t *)&rp->r_mapcnt, -btopr(dmapp->len));
	ASSERT(rp->r_mapcnt >= 0);

	/*
	 * Initiate a page flush if there are pages, the file system
	 * was not mounted readonly, the segment was mapped shared, and
	 * the pages themselves were writeable.
	 */
	if (vn_has_cached_data(dmapp->vp) && !vn_is_readonly(dmapp->vp) &&
	    dmapp->flags == MAP_SHARED && (dmapp->maxprot & PROT_WRITE)) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= RDIRTY;
		mutex_exit(&rp->r_statelock);
		/*
		 * If this is a cross-zone access a sync putpage won't work, so
		 * the best we can do is try an async putpage.  That seems
		 * better than something more draconian such as discarding the
		 * dirty pages.
		 */
		if ((mi->mi_flags & MI_NOCTO) ||
		    nfs_zone() != mi->mi_zone)
			error = nfs_putpage(dmapp->vp, dmapp->off, dmapp->len,
			    B_ASYNC, dmapp->cr, NULL);
		else
			error = nfs_putpage(dmapp->vp, dmapp->off, dmapp->len,
			    0, dmapp->cr, NULL);
		if (!error) {
			mutex_enter(&rp->r_statelock);
			error = rp->r_error;
			rp->r_error = 0;
			mutex_exit(&rp->r_statelock);
		}
	} else
		error = 0;

	if ((rp->r_flags & RDIRECTIO) || (mi->mi_flags & MI_DIRECTIO))
		(void) nfs_putpage(dmapp->vp, dmapp->off, dmapp->len,
		    B_INVAL, dmapp->cr, NULL);

	dmapp->caller->error = error;
	(void) as_delete_callback(as, arg);
	kmem_free(dmapp, sizeof (nfs_delmap_args_t));
}

/* ARGSUSED */
static int
nfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	int error = 0;

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	/*
	 * This looks a little weird because it's written in a general
	 * manner but we make little use of cases.  If cntl() ever gets
	 * widely used, the outer switch will make more sense.
	 */

	switch (cmd) {

	/*
	 * Large file spec - need to base answer new query with
	 * hardcoded constant based on the protocol.
	 */
	case _PC_FILESIZEBITS:
		*valp = 32;
		return (0);

	case _PC_LINK_MAX:
	case _PC_NAME_MAX:
	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC: {
		mntinfo_t *mi;
		struct pathcnf *pc;

		if ((mi = VTOMI(vp)) == NULL || (pc = mi->mi_pathconf) == NULL)
			return (EINVAL);
		error = _PC_ISSET(cmd, pc->pc_mask);    /* error or bool */
		switch (cmd) {
		case _PC_LINK_MAX:
			*valp = pc->pc_link_max;
			break;
		case _PC_NAME_MAX:
			*valp = pc->pc_name_max;
			break;
		case _PC_PATH_MAX:
		case _PC_SYMLINK_MAX:
			*valp = pc->pc_path_max;
			break;
		case _PC_CHOWN_RESTRICTED:
			/*
			 * if we got here, error is really a boolean which
			 * indicates whether cmd is set or not.
			 */
			*valp = error ? 1 : 0;	/* see above */
			error = 0;
			break;
		case _PC_NO_TRUNC:
			/*
			 * if we got here, error is really a boolean which
			 * indicates whether cmd is set or not.
			 */
			*valp = error ? 1 : 0;	/* see above */
			error = 0;
			break;
		}
		return (error ? EINVAL : 0);
		}

	case _PC_XATTR_EXISTS:
		*valp = 0;
		if (vp->v_vfsp->vfs_flag & VFS_XATTR) {
			vnode_t *avp;
			rnode_t *rp;
			mntinfo_t *mi = VTOMI(vp);

			if (!(mi->mi_flags & MI_EXTATTR))
				return (0);

			rp = VTOR(vp);
			if (nfs_rw_enter_sig(&rp->r_rwlock, RW_READER,
			    INTR(vp)))
				return (EINTR);

			error = nfslookup_dnlc(vp, XATTR_DIR_NAME, &avp, cr);
			if (error || avp == NULL)
				error = acl_getxattrdir2(vp, &avp, 0, cr, 0);

			nfs_rw_exit(&rp->r_rwlock);

			if (error == 0 && avp != NULL) {
				error = do_xattr_exists_check(avp, valp, cr);
				VN_RELE(avp);
			}
		}
		return (error ? EINVAL : 0);

	case _PC_ACL_ENABLED:
		*valp = _ACL_ACLENT_ENABLED;
		return (0);

	default:
		return (EINVAL);
	}
}

/*
 * Called by async thread to do synchronous pageio. Do the i/o, wait
 * for it to complete, and cleanup the page list when done.
 */
static int
nfs_sync_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
	int flags, cred_t *cr)
{
	int error;

	ASSERT(nfs_zone() == VTOMI(vp)->mi_zone);
	error = nfs_rdwrlbn(vp, pp, io_off, io_len, flags, cr);
	if (flags & B_READ)
		pvn_read_done(pp, (error ? B_ERROR : 0) | flags);
	else
		pvn_write_done(pp, (error ? B_ERROR : 0) | flags);
	return (error);
}

/* ARGSUSED */
static int
nfs_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
	int flags, cred_t *cr, caller_context_t *ct)
{
	int error;
	rnode_t *rp;

	if (pp == NULL)
		return (EINVAL);

	if (io_off > MAXOFF32_T)
		return (EFBIG);
	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);

	if (flags & B_ASYNC) {
		error = nfs_async_pageio(vp, pp, io_off, io_len, flags, cr,
		    nfs_sync_pageio);
	} else
		error = nfs_rdwrlbn(vp, pp, io_off, io_len, flags, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_count--;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
	return (error);
}

/* ARGSUSED */
static int
nfs_setsecattr(vnode_t *vp, vsecattr_t *vsecattr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	mntinfo_t *mi;

	mi = VTOMI(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (mi->mi_flags & MI_ACL) {
		error = acl_setacl2(vp, vsecattr, flag, cr);
		if (mi->mi_flags & MI_ACL)
			return (error);
	}

	return (ENOSYS);
}

/* ARGSUSED */
static int
nfs_getsecattr(vnode_t *vp, vsecattr_t *vsecattr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	mntinfo_t *mi;

	mi = VTOMI(vp);

	if (nfs_zone() != mi->mi_zone)
		return (EIO);
	if (mi->mi_flags & MI_ACL) {
		error = acl_getacl2(vp, vsecattr, flag, cr);
		if (mi->mi_flags & MI_ACL)
			return (error);
	}

	return (fs_fab_acl(vp, vsecattr, flag, cr, ct));
}

/* ARGSUSED */
static int
nfs_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	int error;
	struct shrlock nshr;
	struct nfs_owner nfs_owner;
	netobj lm_fh;

	if (nfs_zone() != VTOMI(vp)->mi_zone)
		return (EIO);

	/*
	 * check for valid cmd parameter
	 */
	if (cmd != F_SHARE && cmd != F_UNSHARE && cmd != F_HASREMOTELOCKS)
		return (EINVAL);

	/*
	 * Check access permissions
	 */
	if (cmd == F_SHARE &&
	    (((shr->s_access & F_RDACC) && !(flag & FREAD)) ||
	    ((shr->s_access & F_WRACC) && !(flag & FWRITE))))
		return (EBADF);

	/*
	 * If the filesystem is mounted using local locking, pass the
	 * request off to the local share code.
	 */
	if (VTOMI(vp)->mi_flags & MI_LLOCK)
		return (fs_shrlock(vp, cmd, shr, flag, cr, ct));

	switch (cmd) {
	case F_SHARE:
	case F_UNSHARE:
		lm_fh.n_len = sizeof (fhandle_t);
		lm_fh.n_bytes = (char *)VTOFH(vp);

		/*
		 * If passed an owner that is too large to fit in an
		 * nfs_owner it is likely a recursive call from the
		 * lock manager client and pass it straight through.  If
		 * it is not a nfs_owner then simply return an error.
		 */
		if (shr->s_own_len > sizeof (nfs_owner.lowner)) {
			if (((struct nfs_owner *)shr->s_owner)->magic !=
			    NFS_OWNER_MAGIC)
				return (EINVAL);

			if (error = lm_shrlock(vp, cmd, shr, flag, &lm_fh)) {
				error = set_errno(error);
			}
			return (error);
		}
		/*
		 * Remote share reservations owner is a combination of
		 * a magic number, hostname, and the local owner
		 */
		bzero(&nfs_owner, sizeof (nfs_owner));
		nfs_owner.magic = NFS_OWNER_MAGIC;
		(void) strncpy(nfs_owner.hname, uts_nodename(),
		    sizeof (nfs_owner.hname));
		bcopy(shr->s_owner, nfs_owner.lowner, shr->s_own_len);
		nshr.s_access = shr->s_access;
		nshr.s_deny = shr->s_deny;
		nshr.s_sysid = 0;
		nshr.s_pid = ttoproc(curthread)->p_pid;
		nshr.s_own_len = sizeof (nfs_owner);
		nshr.s_owner = (caddr_t)&nfs_owner;

		if (error = lm_shrlock(vp, cmd, &nshr, flag, &lm_fh)) {
			error = set_errno(error);
		}

		break;

	case F_HASREMOTELOCKS:
		/*
		 * NFS client can't store remote locks itself
		 */
		shr->s_access = 0;
		error = 0;
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

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

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/mode.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <sys/sysmacros.h>

/*
 * ino64_t is a unsigned long on LP64 and unsigned long long on ILP32,
 * the compiler emits many warnings when calling xdr_u_longlong_t with an
 * unsigned long pointer on LP64 even though it's safe.
 */
#define	xdr_ino64(xdrs, p)	xdr_u_longlong_t((xdrs), (u_longlong_t *)(p))

/*
 * cfs_time_t is an int in both LP64 and ILP32. To avoid compiler warnings
 * define its xdr here explicitly
 */
#define	xdr_cfs_time_t(xdrs, p)	xdr_int((xdrs), (int *)(p))

#define	CACHEFS_LOG_MAX_BUFFERED	65536
#define	CACHEFS_LOG_LOWATER		 8192
#define	CACHEFS_LOG_ENCODE_SIZE		 4096

#if (defined(_SYSCALL32_IMPL) || defined(_LP64))

#define	OUT_IF_TIME_OVERFLOW(cachep, time)				\
	if (TIME_OVERFLOW(time)) {					\
		cachefs_log_error(cachep, EOVERFLOW, 1);		\
		goto out;						\
	}

#define	RET_IF_TIME_OVERFLOW(cachep, time)				\
	if (TIME_OVERFLOW(time)) {					\
		cachefs_log_error(cachep, EOVERFLOW, 1);		\
		return;							\
	}

#else /* not (_SYSCALL32_IMPL || _LP64) */

#define	OUT_IF_TIME_OVERFLOW(cachep, time)

#define	RET_IF_TIME_OVERFLOW(cachep, time)

#endif /* (_SYSCALL32_IMPL || _LP64) */

typedef struct cachefs_log_work_list {
	void *data;
	size_t size;
	xdrproc_t translate;
	struct cachefs_log_work_list *next;
} *cachefs_log_work_list_t;

/* forward declarations of static functions */
static void cachefs_log_enqueue(cachefscache_t *, void *, int, xdrproc_t);
static int cachefs_log_save_lc(cachefscache_t *);
static int cachefs_log_write_header(struct vnode *, cachefscache_t *, int);

static bool_t cachefs_xdr_logfile_header(XDR *,
    struct cachefs_log_logfile_header *);
static bool_t cachefs_xdr_mount(XDR *, struct cachefs_log_mount_record *);
static bool_t cachefs_xdr_umount(XDR *, struct cachefs_log_umount_record *);
static bool_t cachefs_xdr_getpage(XDR *, struct cachefs_log_getpage_record *);
static bool_t cachefs_xdr_readdir(XDR *, struct cachefs_log_readdir_record *);
static bool_t cachefs_xdr_readlink(XDR *,
    struct cachefs_log_readlink_record *);
static bool_t cachefs_xdr_remove(XDR *, struct cachefs_log_remove_record *);
static bool_t cachefs_xdr_rmdir(XDR *, struct cachefs_log_rmdir_record *);
static bool_t cachefs_xdr_truncate(XDR *,
    struct cachefs_log_truncate_record *);
static bool_t cachefs_xdr_putpage(XDR *, struct cachefs_log_putpage_record *);
static bool_t cachefs_xdr_create(XDR *, struct cachefs_log_create_record *);
static bool_t cachefs_xdr_mkdir(XDR *, struct cachefs_log_mkdir_record *);
static bool_t cachefs_xdr_rename(XDR *, struct cachefs_log_rename_record *);
static bool_t cachefs_xdr_symlink(XDR *, struct cachefs_log_symlink_record *);
static bool_t cachefs_xdr_populate(XDR *,
    struct cachefs_log_populate_record *);
static bool_t cachefs_xdr_csymlink(XDR *,
    struct cachefs_log_csymlink_record *);
static bool_t cachefs_xdr_filldir(XDR *,
    struct cachefs_log_filldir_record *);
static bool_t cachefs_xdr_mdcreate(XDR *,
    struct cachefs_log_mdcreate_record *);
static bool_t cachefs_xdr_gpfront(XDR *,
    struct cachefs_log_gpfront_record *);
static bool_t cachefs_xdr_rfdir(XDR *,
    struct cachefs_log_rfdir_record *);
static bool_t cachefs_xdr_ualloc(XDR *,
    struct cachefs_log_ualloc_record *);
static bool_t cachefs_xdr_calloc(XDR *,
    struct cachefs_log_calloc_record *);
static bool_t cachefs_xdr_nocache(XDR *,
    struct cachefs_log_nocache_record *);


extern time_t time;

/*
 * cachefs_log_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
 *
 * called from /dev/kstat or somesuch.
 *
 */

int
cachefs_log_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	cachefs_log_control_t *lc = (cachefs_log_control_t *)ksp->ks_data;
	cachefs_log_control_t *buflc = (cachefs_log_control_t *)buf;
	cachefscache_t *cachep = (cachefscache_t *)(uintptr_t)lc->lc_cachep;
	cachefs_log_cookie_t *cl = cachep->c_log;
	int error = 0;

	ASSERT(MUTEX_HELD(&cachep->c_log_mutex));

	/* if they just want to read the kstat, get that out of the way. */
	if (rw != KSTAT_WRITE) {
		bcopy(lc, buflc, sizeof (*lc));
		return (0);
	}

	/* make sure they're passing us a valid control cookie */
	if ((buflc->lc_cachep != lc->lc_cachep) ||
	    (buflc->lc_magic != CACHEFS_LOG_MAGIC))
		return (EIO);

	/*
	 * if logging is currently off
	 *   o insist that we're being handed a logfile path
	 *   o set cl, and give our cachep its value
	 *
	 * after that, if something goes wrong, we must call
	 * cachefs_log_error to clear cachep->c_log.
	 */
	if (cl == NULL) {
		if (buflc->lc_path[0] == '\0')
			return (EIO);
		cl = cachep->c_log = cachefs_log_create_cookie(lc);
		if (cl == NULL) {
			cachefs_log_error(cachep, ENOMEM, 0);
			return (EIO);
		}
	}

	/*
	 * if we're being handed an empty logpath, then they must be
	 * turning off logging; also, logging must have been turned on
	 * before, or else the previous paragraph would have caught
	 * it.
	 */
	if (buflc->lc_path[0] == '\0') {
		cachefs_log_process_queue(cachep, 0);
		cachep->c_log = NULL;
		cachefs_log_destroy_cookie(cl);
		bzero(lc, sizeof (*lc));
		lc->lc_magic = CACHEFS_LOG_MAGIC;
		lc->lc_cachep = (uint64_t)(uintptr_t)cachep;
		(void) VOP_REMOVE(cachep->c_dirvp, LOG_STATUS_NAME, kcred, NULL,
		    0);
		return (0);
	}

	/*
	 * if we get here, we know that we're being handed a valid log
	 * control cookie, and that a path is set.  try to open the
	 * log file, even if it's the same path, because they might
	 * have removed the old log file out from under us.  if it
	 * really is the same file, no harm done.
	 */
	if ((error = cachefs_log_logfile_open(cachep, buflc->lc_path)) != 0) {
		cachefs_log_error(cachep, error, 0);
		return (EIO);
	}

	/*
	 * if we get here, we have a valid logfile open.  we don't do
	 * anything here with the bitmap of what's being logged, other
	 * than copy it.  we're home free!
	 */
	bcopy(buflc, lc, sizeof (*lc));
	if ((error = cachefs_log_save_lc(cachep)) != 0) {
		cachefs_log_error(cachep, error, 0);
		return (EIO);
	}

	return (0);
}

static int
cachefs_log_save_lc(cachefscache_t *cachep)
{
	cachefs_log_control_t *lc = (cachefs_log_control_t *)cachep->c_log_ctl;
	struct vnode *savevp;
	struct vattr attr;
	int error = 0;

	if (lc == NULL)
		return (EINVAL);

	attr.va_mode = S_IFREG | 0666;
	attr.va_uid = 0;
	attr.va_gid = 0;
	attr.va_type = VREG;
	attr.va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;

	if (((error = VOP_LOOKUP(cachep->c_dirvp, LOG_STATUS_NAME, &savevp,
	    NULL, 0, NULL, kcred, NULL, NULL, NULL)) != 0) &&
	    ((error = VOP_CREATE(cachep->c_dirvp, LOG_STATUS_NAME, &attr, EXCL,
	    0600, &savevp, kcred, 0, NULL, NULL)) != 0))
		return (error);
	ASSERT(savevp != NULL);
	if (savevp == NULL)
		return (ENOENT);

	error = vn_rdwr(UIO_WRITE, savevp,
	    (caddr_t)lc, sizeof (*lc),
	    0LL, UIO_SYSSPACE, FSYNC, (rlim64_t)RLIM_INFINITY, kcred, NULL);

	VN_RELE(savevp);

	return (error);
}

/*
 * cachefs_log_cookie_t *cachefs_log_create_cookie(void *)
 *
 * creates and initializes the cookie, which lives in cachep.  called
 * from either a kstat write which turns on logging, or from
 * initializing cachep when a log-info-file exists.
 */

cachefs_log_cookie_t *
cachefs_log_create_cookie(cachefs_log_control_t *lc)
{
	cachefs_log_cookie_t *rc;

	rc = cachefs_kmem_zalloc(sizeof (*rc), KM_NOSLEEP);
	if (rc == NULL)
		return (NULL);

	rc->cl_magic = CACHEFS_LOG_MAGIC;
	rc->cl_logctl = lc;

	return (rc);
}

/*
 * void cachefs_log_destroy_cookie(cachefs_log_cookie_t *)
 *
 * destroys the log cookie.  called from cachefs_log_error, or from
 * destroying the cachep.
 *
 */

void
cachefs_log_destroy_cookie(cachefs_log_cookie_t *cl)
{
	cachefs_log_work_list_t node, oldnode;

	if (cl == NULL)
		return;

	ASSERT(cl->cl_magic == CACHEFS_LOG_MAGIC);

	cl->cl_magic++;
	node = cl->cl_head;
	while (node != NULL) {
		cachefs_kmem_free(node->data, node->size);
		oldnode = node;
		node = node->next;
		cachefs_kmem_free(oldnode, sizeof (*oldnode));
	}
	if (cl->cl_logvp != NULL)
		VN_RELE(cl->cl_logvp);
	cachefs_kmem_free(cl, sizeof (*cl));
}

/*
 * int cachefs_log_logfile_open(cachefscache_t *, char *)
 *
 * opens the logfile, and stores the path string if its successful.
 *
 * returns an errno if one occurred.
 *
 */

int
cachefs_log_logfile_open(cachefscache_t *cachep, char *path)
{
	cachefs_log_cookie_t *cl = cachep->c_log;
	struct vnode *newvp = NULL;
	int error = 0;
	int i;

	ASSERT(MUTEX_HELD(&cachep->c_log_mutex));
	ASSERT(cl != NULL);
	ASSERT(cl->cl_magic == CACHEFS_LOG_MAGIC);

	/* lookup the pathname -- it must already exist! */
	error = lookupname(path, UIO_SYSSPACE, FOLLOW, NULL, &newvp);
	if (error)
		goto out;
	ASSERT(newvp != NULL);
	if (newvp == NULL) {
		error = ENOENT; /* XXX this shouldn't happen (yeah right) */
		goto out;
	}

	/* easy out if we just re-opened the same logfile */
	if (cl->cl_logvp == newvp) {
		VN_RELE(newvp);
		goto out;
	}

	/* XXX we may change this to allow named pipes */
	if (newvp->v_type != VREG) {
		error = EINVAL;
		goto out;
	}
	if (vn_matchops(newvp, cachefs_getvnodeops())) {
		error = EINVAL;
		goto out;
	}

	/* write out the header */
	error = cachefs_log_write_header(newvp, cachep, 0);
	if (error)
		goto out;

	/* if we get here, we successfully opened the log. */
	if (cl->cl_logvp != NULL)
		VN_RELE(cl->cl_logvp);
	cl->cl_logvp = newvp;

	/*
	 * `fake' a mount entry for each mounted cachefs filesystem.
	 * this is overkill, but it's easiest and most foolproof way
	 * to do things here.  the user-level consumers of the logfile
	 * have to expect extraneous mount entries and deal with it
	 * correctly.
	 */
	mutex_exit(&cachep->c_log_mutex);
	for (i = 0; i < cachefs_kstat_key_n; i++) {
		cachefs_kstat_key_t *k;
		struct vfs *vfsp;
		struct fscache *fscp;

		k = cachefs_kstat_key + i;
		if (! k->ks_mounted)
			continue;

		vfsp = (struct vfs *)(uintptr_t)k->ks_vfsp;
		fscp = VFS_TO_FSCACHE(vfsp);
		cachefs_log_mount(cachep, 0, vfsp, fscp,
		    (char *)(uintptr_t)k->ks_mountpoint, UIO_SYSSPACE,
		    (char *)(uintptr_t)k->ks_cacheid);
	}
	mutex_enter(&cachep->c_log_mutex);

out:
	if ((error != 0) && (newvp != NULL))
		VN_RELE(newvp);
	return (error);
}

/*
 * called when an error occurred during logging.  send the error to
 * syslog, invalidate the logfile, and stop logging.
 */

void
cachefs_log_error(cachefscache_t *cachep, int error, int getlock)
{
	cachefs_log_cookie_t *cl = cachep->c_log;
	cachefs_log_control_t *lc = cachep->c_log_ctl;
	int writable = 0;

	ASSERT((getlock) || (MUTEX_HELD(&cachep->c_log_mutex)));

	if (getlock)
		mutex_enter(&cachep->c_log_mutex);

	if ((cachep->c_flags & (CACHE_NOCACHE | CACHE_NOFILL)) == 0)
		writable = 1;

	cmn_err(CE_WARN, "cachefs logging: error %d\n", error);

	if ((writable) && (cl != NULL) && (cl->cl_logvp != NULL))
		(void) cachefs_log_write_header(cl->cl_logvp, cachep, error);

	cachep->c_log = NULL;
	if (cl != NULL)
		cachefs_log_destroy_cookie(cl);
	bzero(lc, sizeof (cachefs_log_control_t));
	lc->lc_magic = CACHEFS_LOG_MAGIC;
	lc->lc_cachep = (uint64_t)(uintptr_t)cachep;
	if (writable)
		(void) VOP_REMOVE(cachep->c_dirvp, LOG_STATUS_NAME, kcred, NULL,
		    0);

	if (getlock)
		mutex_exit(&cachep->c_log_mutex);
}

static int
cachefs_log_write_header(struct vnode *vp, cachefscache_t *cachep, int error)
{
	struct cachefs_log_logfile_header header, oheader;
	char buffy[2 * sizeof (header)];
	int Errno = 0;
	struct vattr attr;
	int gotold = 0;
	XDR xdrm;

	attr.va_mask = AT_SIZE;
	if ((error = VOP_GETATTR(vp, &attr, 0, kcred, NULL)) != 0)
		goto out;
	if (attr.va_size != 0) {
		error = vn_rdwr(UIO_READ, vp, buffy,
		    MIN(sizeof (buffy), attr.va_size),
		    0LL, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY, kcred, NULL);
		if (error != 0)
			goto out;

		xdrm.x_ops = NULL;
		xdrmem_create(&xdrm, buffy, sizeof (buffy), XDR_DECODE);
		if ((xdrm.x_ops == NULL) ||
		    (! cachefs_xdr_logfile_header(&xdrm, &oheader))) {
			if (xdrm.x_ops != NULL)
				xdr_destroy(&xdrm);
			error = EINVAL;
			goto out;
		}
		xdr_destroy(&xdrm);
		gotold = 1;

		if (oheader.lh_magic != CACHEFS_LOG_MAGIC) {
			error = EINVAL;
			goto out;
		}
	}

	xdrm.x_ops = NULL;

	xdrmem_create(&xdrm, buffy, sizeof (buffy), XDR_ENCODE);

	if (gotold) {
		header = oheader;
	} else {
		header.lh_magic = CACHEFS_LOG_MAGIC;
		header.lh_revision = CACHEFS_LOG_FILE_REV;
		header.lh_blocks = cachep->c_usage.cu_blksused;
		header.lh_files = cachep->c_usage.cu_filesused;
		header.lh_maxbsize = MAXBSIZE;
		header.lh_pagesize = PAGESIZE;
	}

	/* these are things that we stomp over for every header write */
	header.lh_errno = Errno;

	if (! cachefs_xdr_logfile_header(&xdrm, &header)) {
		error = ENOMEM;
		goto out;
	}

	error = vn_rdwr(UIO_WRITE, vp,
	    (caddr_t)buffy, xdr_getpos(&xdrm),
	    0LL, UIO_SYSSPACE, FSYNC, (rlim64_t)RLIM_INFINITY, kcred, NULL);
	if (error)
		goto out;

out:
	if (xdrm.x_ops != NULL)
		xdr_destroy(&xdrm);
	return (error);
}

/*
 * enqueues a record to be written to the logfile.
 */

static void
cachefs_log_enqueue(cachefscache_t *cachep, void *record, int size,
    xdrproc_t translate)
{
	cachefs_log_cookie_t *cl;
	cachefs_log_work_list_t newnode, oldnode;

	mutex_enter(&cachep->c_log_mutex);
	cl = cachep->c_log;

	if (cl == NULL) { /* someone turned off logging out from under us */
		mutex_exit(&cachep->c_log_mutex);
		cachefs_kmem_free(record, size);
		return;
	}
	ASSERT(cl->cl_magic == CACHEFS_LOG_MAGIC);

	cl->cl_size += size;
	newnode = cachefs_kmem_zalloc(sizeof (*newnode), KM_NOSLEEP);
	if ((cl->cl_size > CACHEFS_LOG_MAX_BUFFERED) || (newnode == NULL)) {
		cachefs_log_error(cachep, ENOMEM, 0);
		if (newnode != NULL)
			cachefs_kmem_free(newnode, sizeof (*newnode));
		cachefs_kmem_free(record, size);
		mutex_exit(&cachep->c_log_mutex);
		return;
	}

	newnode->data = record;
	newnode->size = size;
	newnode->translate = translate;
	newnode->next = NULL;

	oldnode = (cachefs_log_work_list_t)cl->cl_tail;
	if (oldnode != NULL)
		oldnode->next = newnode;
	cl->cl_tail = newnode;
	if (cl->cl_head == NULL)
		cl->cl_head = newnode;
	mutex_exit(&cachep->c_log_mutex);

	if (cl->cl_size >= CACHEFS_LOG_LOWATER) {
		mutex_enter(&cachep->c_workq.wq_queue_lock);
		cachep->c_workq.wq_logwork = 1;
		cv_signal(&cachep->c_workq.wq_req_cv);
		mutex_exit(&cachep->c_workq.wq_queue_lock);
	}
}

/*
 * processes the log queue.  run by an async worker thread, or via
 * cachefs_cache_sync().
 */

void
cachefs_log_process_queue(cachefscache_t *cachep, int getlock)
{
	cachefs_log_cookie_t *cl;
	cachefs_log_work_list_t work, workhead, oldwork;
	struct vnode *logvp = NULL;
	struct uio uio;
	struct iovec iov;
	int error = 0;
	XDR xdrm;
	char *buffy = NULL;

	/*
	 * NULL out the x_ops field of XDR.  this way, if x_ops !=
	 * NULL, we know that we did the xdr*_create() successfully.
	 * this is documented in the xdr_create man page.
	 */

	xdrm.x_ops = NULL;

	/* see if we're still logging */
	if (getlock)
		mutex_enter(&cachep->c_log_mutex);
	cl = cachep->c_log;
	if ((cl == NULL) || (cl->cl_magic != CACHEFS_LOG_MAGIC)) {
		if (getlock)
			mutex_exit(&cachep->c_log_mutex);
		return;
	}

	/* get the work, and let go of the mutex asap. */
	workhead = cl->cl_head;
	cl->cl_head = cl->cl_tail = NULL;
	cl->cl_size = 0;
	logvp = cl->cl_logvp;
	ASSERT(logvp != NULL);
	if (logvp == NULL) {
		if (getlock)
			mutex_exit(&cachep->c_log_mutex);
		return;
	}
	VN_HOLD(logvp);
	if (getlock)
		mutex_exit(&cachep->c_log_mutex);

	/* we don't use vn_rdwr() because there's no way to set FNONBLOCK */

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = 0; /* fake -- we do FAPPEND */
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_llimit = MAXOFFSET_T;
	uio.uio_fmode = FWRITE | FNONBLOCK;
	uio.uio_extflg = UIO_COPY_CACHED;

	buffy = cachefs_kmem_alloc(CACHEFS_LOG_ENCODE_SIZE, KM_SLEEP);
	xdrmem_create(&xdrm, buffy, CACHEFS_LOG_ENCODE_SIZE, XDR_ENCODE);

	(void) VOP_RWLOCK(logvp, V_WRITELOCK_TRUE, NULL);
	for (work = workhead; work != NULL; work = work->next) {
		if (! (work->translate)(&xdrm, work->data)) {
			VOP_RWUNLOCK(logvp, V_WRITELOCK_TRUE, NULL);
			error = ENOMEM;
			goto out;
		}

		iov.iov_base = buffy;
		iov.iov_len = uio.uio_resid = xdr_getpos(&xdrm);
		(void) xdr_setpos(&xdrm, 0);

		error = VOP_WRITE(logvp, &uio, FAPPEND, kcred, NULL);

		/* XXX future -- check for EAGAIN */

		if ((error) || (uio.uio_resid)) {
			if (uio.uio_resid != 0)
				error = EIO;
			VOP_RWUNLOCK(logvp, V_WRITELOCK_TRUE, NULL);
			goto out;
		}
	}
	VOP_RWUNLOCK(logvp, V_WRITELOCK_TRUE, NULL);

out:
	if (xdrm.x_ops != NULL)
		xdr_destroy(&xdrm);
	if (buffy != NULL)
		cachefs_kmem_free(buffy, CACHEFS_LOG_ENCODE_SIZE);

	/*
	 * if an error occurred, we need to free the buffers ourselves.
	 * cachefs_destory_cookie() can't do it.
	 */

	work = workhead;
	while (work != NULL) {
		cachefs_kmem_free(work->data, work->size);
		oldwork = work;
		work = work->next;
		cachefs_kmem_free(oldwork, sizeof (*oldwork));
	}
	if (logvp != NULL)
		VN_RELE(logvp);
	if (error) {
		cachefs_log_error(cachep, error, 1);
		return;
	}
}

static bool_t
cachefs_xdr_logfile_header(XDR *xdrs, struct cachefs_log_logfile_header *h)
{
	if ((! xdr_u_int(xdrs, &h->lh_magic)) ||
	    (! xdr_u_int(xdrs, &h->lh_revision)) ||
	    (! xdr_int(xdrs, &h->lh_errno)) ||
	    (! xdr_u_int(xdrs, &h->lh_blocks)) ||
	    (! xdr_u_int(xdrs, &h->lh_files)) ||
	    (! xdr_u_int(xdrs, &h->lh_maxbsize)) ||
	    (! xdr_u_int(xdrs, &h->lh_pagesize)))
		return (FALSE);

	return (TRUE);
}

/*
 * the routines for logging each transaction follow...
 */

void
cachefs_log_mount(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fscache_t *fscp, char *upath, enum uio_seg seg, char *cacheid)
{
	struct cachefs_log_mount_record *record;
	char *cacheidt;
	char *path = NULL;
	size_t len;
	int len1, len2;
	int size, error;

	/* In Solaris 64 - if can't represent time don't bother */
	OUT_IF_TIME_OVERFLOW(cachep, time)
	if (seg == UIO_USERSPACE) {
		path = cachefs_kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
		if (path == NULL) {
			cachefs_log_error(cachep, ENOMEM, 1);
			goto out;
		}
		if ((error = copyinstr(upath, path, MAXPATHLEN, &len)) != 0) {
			cachefs_log_error(cachep, error, 1);
			goto out;
		}
	} else {
		path = upath;
	}

	len1 = (path != NULL) ? strlen(path) : 0;
	len2 = (cacheid != NULL) ? strlen(cacheid) : 0;
	size = (int)sizeof (*record) + len1 + len2 -
	    (int)CLPAD(cachefs_log_mount_record, path);
	record = cachefs_kmem_zalloc(size, KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		goto out;
	}

	record->type = CACHEFS_LOG_MOUNT;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;

	if (fscp) {
		record->flags = fscp->fs_info.fi_mntflags;
		record->popsize = fscp->fs_info.fi_popsize;
		record->fgsize = fscp->fs_info.fi_fgsize;
	}

	record->pathlen = (ushort_t)len1;
	record->cacheidlen = (ushort_t)len2;
	if (path != NULL)
		(void) strcpy(record->path, path);
	cacheidt = record->path + len1 + 1;
	if (cacheid != NULL)
		(void) strcpy(cacheidt, cacheid);

	cachefs_log_enqueue(cachep, record, size, cachefs_xdr_mount);

out:
	if ((seg == UIO_USERSPACE) && (path != NULL))
		cachefs_kmem_free(path, MAXPATHLEN);
}

static bool_t
cachefs_xdr_mount(XDR *xdrs, struct cachefs_log_mount_record *rec)
{
	char *path = rec->path;
	char *cacheid;

	cacheid = path + strlen(path) + 1;

	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_u_int(xdrs, &rec->flags)) ||
	    (! xdr_u_int(xdrs, &rec->popsize)) ||
	    (! xdr_u_int(xdrs, &rec->fgsize)) ||
	    (! xdr_u_short(xdrs, &rec->pathlen)) ||
	    (! xdr_u_short(xdrs, &rec->cacheidlen)) ||
	    (! xdr_wrapstring(xdrs, &path)) ||
	    (! xdr_wrapstring(xdrs, &cacheid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_umount(cachefscache_t *cachep, int Errno, struct vfs *vfsp)
{
	struct cachefs_log_umount_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_UMOUNT;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_umount);
}

static bool_t
cachefs_xdr_umount(XDR *xdrs, struct cachefs_log_umount_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_getpage(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, u_offset_t offset, size_t len)
{
	struct cachefs_log_getpage_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_GETPAGE;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->offset = offset;
	record->len = (uint_t)len;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_getpage);
}

static bool_t
cachefs_xdr_getpage(XDR *xdrs, struct cachefs_log_getpage_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_longlong_t(xdrs, &rec->offset)) ||
	    (! xdr_u_int(xdrs, &rec->len)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_readdir(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, u_offset_t offset, int eof)
{
	struct cachefs_log_readdir_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_READDIR;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->offset = offset;
	record->eof = eof;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_readdir);
}

static bool_t
cachefs_xdr_readdir(XDR *xdrs, struct cachefs_log_readdir_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->offset)) ||
	    (! xdr_int(xdrs, &rec->eof)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_readlink(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, size_t length)
{
	struct cachefs_log_readlink_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_READLINK;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->length = (uint_t)length;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_readlink);
}

static bool_t
cachefs_xdr_readlink(XDR *xdrs, struct cachefs_log_readlink_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_int(xdrs, &rec->length)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_remove(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid)
{
	struct cachefs_log_remove_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_REMOVE;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_remove);
}

static bool_t
cachefs_xdr_remove(XDR *xdrs, struct cachefs_log_remove_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_rmdir(cachefscache_t *cachep, int Errno,
    struct vfs *vfsp, fid_t *fidp, ino64_t fileno, uid_t uid)
{
	struct cachefs_log_rmdir_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_RMDIR;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_rmdir);
}

static bool_t
cachefs_xdr_rmdir(XDR *xdrs, struct cachefs_log_rmdir_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_truncate(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, u_offset_t size)
{
	struct cachefs_log_truncate_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_TRUNCATE;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->size = size;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_truncate);
}

static bool_t
cachefs_xdr_truncate(XDR *xdrs, struct cachefs_log_truncate_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_longlong_t(xdrs, &rec->size)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_putpage(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, u_offset_t offset, size_t len)
{
	struct cachefs_log_putpage_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_PUTPAGE;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->offset = offset;
	record->len = (uint_t)len;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_putpage);
}

static bool_t
cachefs_xdr_putpage(XDR *xdrs, struct cachefs_log_putpage_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->offset)) ||
	    (! xdr_u_int(xdrs, &rec->len)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_create(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *filefidp, ino64_t fileno, uid_t uid)
{
	struct cachefs_log_create_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_CREATE;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (filefidp != NULL) {
		CACHEFS_FID_COPY(filefidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_create);
}

static bool_t
cachefs_xdr_create(XDR *xdrs, struct cachefs_log_create_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_mkdir(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *cfidp, ino64_t fileno, uid_t uid)
{
	struct cachefs_log_mkdir_record *record;
	int size;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	size = (int)sizeof (*record);
	record = cachefs_kmem_zalloc(size, KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_MKDIR;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (cfidp != NULL) {
		CACHEFS_FID_COPY(cfidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, size,
	    cachefs_xdr_mkdir);
}

static bool_t
cachefs_xdr_mkdir(XDR *xdrs, struct cachefs_log_mkdir_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_rename(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *gfp, ino64_t fileno, int removed, uid_t uid)
{
	struct cachefs_log_rename_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_RENAME;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (gfp != NULL) {
		CACHEFS_FID_COPY(gfp, &record->gone);
	}
	record->fileno = fileno;
	record->removed = removed;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_rename);
}

static bool_t
cachefs_xdr_rename(XDR *xdrs, struct cachefs_log_rename_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->gone, sizeof (rec->gone))) ||
	    (! xdr_int(xdrs, &rec->removed)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}


void
cachefs_log_symlink(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, int size)
{
	struct cachefs_log_symlink_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_SYMLINK;
	record->time = time;

	record->error = Errno;
	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->size = size;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_symlink);
}

static bool_t
cachefs_xdr_symlink(XDR *xdrs, struct cachefs_log_symlink_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_int(xdrs, &rec->size)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_populate(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, u_offset_t off, size_t popsize)
{
	struct cachefs_log_populate_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_POPULATE;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->off = off;
	record->size = (int)popsize;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_populate);
}

static bool_t
cachefs_xdr_populate(XDR *xdrs, struct cachefs_log_populate_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->off)) ||
	    (! xdr_u_int(xdrs, &rec->size)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_csymlink(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, int size)
{
	struct cachefs_log_csymlink_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_CSYMLINK;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->size = size;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_csymlink);
}

static bool_t
cachefs_xdr_csymlink(XDR *xdrs, struct cachefs_log_csymlink_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_int(xdrs, &rec->size)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_filldir(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, u_offset_t size)
{
	struct cachefs_log_filldir_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_FILLDIR;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->size = (uint_t)size;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_filldir);
}

static bool_t
cachefs_xdr_filldir(XDR *xdrs, struct cachefs_log_filldir_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, (uint_t *)&rec->size)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_mdcreate(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uint_t count)
{
	struct cachefs_log_mdcreate_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_MDCREATE;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->count = count;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_mdcreate);
}

static bool_t
cachefs_xdr_mdcreate(XDR *xdrs, struct cachefs_log_mdcreate_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->count)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_gpfront(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid, u_offset_t offset, uint_t len)
{
	struct cachefs_log_gpfront_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_GPFRONT;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;
	record->off = offset;
	record->len = len;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_gpfront);
}

static bool_t
cachefs_xdr_gpfront(XDR *xdrs, struct cachefs_log_gpfront_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->off)) ||
	    (! xdr_u_int(xdrs, &rec->len)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_rfdir(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, uid_t uid)
{
	struct cachefs_log_rfdir_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_RFDIR;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->uid = uid;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_rfdir);
}

static bool_t
cachefs_xdr_rfdir(XDR *xdrs, struct cachefs_log_rfdir_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_int(xdrs, &rec->uid)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_ualloc(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, u_offset_t off, size_t len)
{
	struct cachefs_log_ualloc_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_UALLOC;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->off = off;
	record->len = (uint_t)len;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_ualloc);
}

static bool_t
cachefs_xdr_ualloc(XDR *xdrs, struct cachefs_log_ualloc_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->off)) ||
	    (! xdr_u_int(xdrs, (uint_t *)&rec->len)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_calloc(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno, u_offset_t off, size_t len)
{
	struct cachefs_log_calloc_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_CALLOC;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;
	record->off = off;
	record->len = (uint_t)len;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_calloc);
}

static bool_t
cachefs_xdr_calloc(XDR *xdrs, struct cachefs_log_calloc_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)) ||
	    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rec->off)) ||
	    (! xdr_u_int(xdrs, &rec->len)))
		return (FALSE);

	return (TRUE);
}

void
cachefs_log_nocache(cachefscache_t *cachep, int Errno, struct vfs *vfsp,
    fid_t *fidp, ino64_t fileno)
{
	struct cachefs_log_nocache_record *record;

	/* In Solaris 64 - if can't represent time don't bother */
	RET_IF_TIME_OVERFLOW(cachep, time)
	record = cachefs_kmem_zalloc(sizeof (*record), KM_NOSLEEP);
	if (record == NULL) {
		cachefs_log_error(cachep, ENOMEM, 1);
		return;
	}

	record->type = CACHEFS_LOG_NOCACHE;
	record->time = time;
	record->error = Errno;

	record->vfsp = (uint64_t)(uintptr_t)vfsp;
	if (fidp != NULL) {
		CACHEFS_FID_COPY(fidp, &record->fid);
	}
	record->fileno = fileno;

	cachefs_log_enqueue(cachep, record, (int)sizeof (*record),
	    cachefs_xdr_nocache);

}

static bool_t
cachefs_xdr_nocache(XDR *xdrs, struct cachefs_log_nocache_record *rec)
{
	if ((! xdr_int(xdrs, &rec->type)) ||
	    (! xdr_int(xdrs, &rec->error)) ||
	    (! xdr_cfs_time_t(xdrs, &rec->time)) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->vfsp, sizeof (rec->vfsp))) ||
	    (! xdr_opaque(xdrs, (caddr_t)&rec->fid, sizeof (rec->fid))) ||
	    (! xdr_ino64(xdrs, &rec->fileno)))
		return (FALSE);

	return (TRUE);
}

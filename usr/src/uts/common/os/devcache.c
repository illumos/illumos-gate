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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/note.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/instance.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/hwconf.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/dacf.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/pathname.h>
#include <sys/kobj.h>
#include <sys/devcache.h>
#include <sys/devcache_impl.h>
#include <sys/sysmacros.h>
#include <sys/varargs.h>
#include <sys/callb.h>

/*
 * This facility provides interfaces to clients to register,
 * read and update cache data in persisted backing store files,
 * usually in /etc/devices.  The data persisted through this
 * mechanism should be stateless data, functioning in the sense
 * of a cache.  Writes are performed by a background daemon
 * thread, permitting a client to schedule an update without
 * blocking, then continue updating the data state in
 * parallel.  The data is only locked by the daemon thread
 * to pack the data in preparation for the write.
 *
 * Data persisted through this mechanism should be capable
 * of being regenerated through normal system operation,
 * for example attaching all disk devices would cause all
 * devids to be registered for those devices.  By caching
 * a devid-device tuple, the system can operate in a
 * more optimal way, directly attaching the device mapped
 * to a devid, rather than burdensomely driving attach of
 * the entire device tree to discover a single device.
 *
 * Note that a client should only need to include
 * <sys/devcache.h> for the supported interfaces.
 *
 * The data per client is entirely within the control of
 * the client.  When reading, data unpacked from the backing
 * store should be inserted in the list.  The pointer to
 * the list can be retrieved via nvf_list().  When writing,
 * the data on the list is to be packed and returned to the
 * nvpdaemon as an nvlist.
 *
 * Obvious restrictions are imposed by the limits of the
 * nvlist format.  The data cannot be read or written
 * piecemeal, and large amounts of data aren't recommended.
 * However, nvlists do allow that data be named and typed
 * and can be size-of-int invariant, and the cached data
 * can be versioned conveniently.
 *
 * The registration involves two steps: a handle is
 * allocated by calling the registration function.
 * This sets up the data referenced by the handle and
 * initializes the lock.  Following registration, the
 * client must initialize the data list.  The list
 * interfaces require that the list element with offset
 * to the node link be provided.  The format of the
 * list element is under the control of the client.
 *
 * Locking: the address of the data list r/w lock provided
 * can be accessed with nvf_lock().  The lock must be held
 * as reader when traversing the list or checking state,
 * such as nvf_is_dirty().  The lock must be held as
 * writer when updating the list or marking it dirty.
 * The lock must not be held when waking the daemon.
 *
 * The data r/w lock is held as writer when the pack,
 * unpack and free list handlers are called.  The
 * lock should not be dropped and must be still held
 * upon return.  The client should also hold the lock
 * as reader when checking if the list is dirty, and
 * as writer when marking the list dirty or initiating
 * a read.
 *
 * The asynchronous nature of updates allows for the
 * possibility that the data may continue to be updated
 * once the daemon has been notified that an update is
 * desired.  The data only needs to be locked against
 * updates when packing the data into the form to be
 * written.  When the write of the packed data has
 * completed, the daemon will automatically reschedule
 * an update if the data was marked dirty after the
 * point at which it was packed.  Before beginning an
 * update, the daemon attempts to lock the data as
 * writer; if the writer lock is already held, it
 * backs off and retries later.  The model is to give
 * priority to the kernel processes generating the
 * data, and that the nature of the data is that
 * it does not change often, can be re-generated when
 * needed, so updates should not happen often and
 * can be delayed until the data stops changing.
 * The client may update the list or mark it dirty
 * any time it is able to acquire the lock as
 * writer first.
 *
 * A failed write will be retried after some delay,
 * in the hope that the cause of the error will be
 * transient, for example a filesystem with no space
 * available.  An update on a read-only filesystem
 * is failed silently and not retried; this would be
 * the case when booted off install media.
 *
 * There is no unregister mechanism as of yet, as it
 * hasn't been needed so far.
 */

/*
 * Global list of files registered and updated by the nvpflush
 * daemon, protected by the nvf_cache_mutex.  While an
 * update is taking place, a file is temporarily moved to
 * the dirty list to avoid locking the primary list for
 * the duration of the update.
 */
list_t		nvf_cache_files;
list_t		nvf_dirty_files;
kmutex_t	nvf_cache_mutex;


/*
 * Allow some delay from an update of the data before flushing
 * to permit simultaneous updates of multiple changes.
 * Changes in the data are expected to be bursty, ie
 * reconfig or hot-plug of a new adapter.
 *
 * kfio_report_error (default 0)
 *	Set to 1 to enable some error messages related to low-level
 *	kernel file i/o operations.
 *
 * nvpflush_delay (default 10)
 *	The number of seconds after data is marked dirty before the
 *	flush daemon is triggered to flush the data.  A longer period
 *	of time permits more data updates per write.  Note that
 *	every update resets the timer so no repository write will
 *	occur while data is being updated continuously.
 *
 * nvpdaemon_idle_time (default 60)
 *	The number of seconds the daemon will sleep idle before exiting.
 *
 */
#define	NVPFLUSH_DELAY		10
#define	NVPDAEMON_IDLE_TIME	60

#define	TICKS_PER_SECOND	(drv_usectohz(1000000))

/*
 * Tunables
 */
int kfio_report_error = 0;		/* kernel file i/o operations */
int kfio_disable_read = 0;		/* disable all reads */
int kfio_disable_write = 0;		/* disable all writes */

int nvpflush_delay	= NVPFLUSH_DELAY;
int nvpdaemon_idle_time	= NVPDAEMON_IDLE_TIME;

static timeout_id_t	nvpflush_id = 0;
static int		nvpflush_timer_busy = 0;
static int		nvpflush_daemon_active = 0;
static kthread_t	*nvpflush_thr_id = 0;

static int		do_nvpflush = 0;
static int		nvpbusy = 0;
static kmutex_t		nvpflush_lock;
static kcondvar_t	nvpflush_cv;
static kthread_id_t	nvpflush_thread;
static clock_t		nvpticks;

static void nvpflush_daemon(void);

#ifdef	DEBUG
int nvpdaemon_debug = 0;
int kfio_debug = 0;
#endif	/* DEBUG */

extern int modrootloaded;
extern void mdi_read_devices_files(void);
extern void mdi_clean_vhcache(void);
extern int sys_shutdown;

/*
 * Initialize the overall cache file management
 */
void
i_ddi_devices_init(void)
{
	list_create(&nvf_cache_files, sizeof (nvfd_t),
	    offsetof(nvfd_t, nvf_link));
	list_create(&nvf_dirty_files, sizeof (nvfd_t),
	    offsetof(nvfd_t, nvf_link));
	mutex_init(&nvf_cache_mutex, NULL, MUTEX_DEFAULT, NULL);
	retire_store_init();
	devid_cache_init();
}

/*
 * Read cache files
 * The files read here should be restricted to those
 * that may be required to mount root.
 */
void
i_ddi_read_devices_files(void)
{
	/*
	 * The retire store should be the first file read as it
	 * may need to offline devices. kfio_disable_read is not
	 * used for retire. For the rationale see the tunable
	 * ddi_retire_store_bypass and comments in:
	 *	uts/common/os/retire_store.c
	 */

	retire_store_read();

	if (!kfio_disable_read) {
		mdi_read_devices_files();
		devid_cache_read();
	}
}

void
i_ddi_start_flush_daemon(void)
{
	nvfd_t	*nvfdp;

	ASSERT(i_ddi_io_initialized());

	mutex_init(&nvpflush_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&nvpflush_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&nvf_cache_mutex);
	for (nvfdp = list_head(&nvf_cache_files); nvfdp;
	    nvfdp = list_next(&nvf_cache_files, nvfdp)) {
		if (NVF_IS_DIRTY(nvfdp)) {
			nvf_wake_daemon();
			break;
		}
	}
	mutex_exit(&nvf_cache_mutex);
}

void
i_ddi_clean_devices_files(void)
{
	devid_cache_cleanup();
	mdi_clean_vhcache();
}

/*
 * Register a cache file to be managed and updated by the nvpflush daemon.
 * All operations are performed through the returned handle.
 * There is no unregister mechanism for now.
 */
nvf_handle_t
nvf_register_file(nvf_ops_t *ops)
{
	nvfd_t *nvfdp;

	nvfdp = kmem_zalloc(sizeof (*nvfdp), KM_SLEEP);

	nvfdp->nvf_ops = ops;
	nvfdp->nvf_flags = 0;
	rw_init(&nvfdp->nvf_lock, NULL, RW_DRIVER, NULL);

	mutex_enter(&nvf_cache_mutex);
	list_insert_tail(&nvf_cache_files, nvfdp);
	mutex_exit(&nvf_cache_mutex);

	return ((nvf_handle_t)nvfdp);
}

/*PRINTFLIKE1*/
void
nvf_error(const char *fmt, ...)
{
	va_list ap;

	if (kfio_report_error) {
		va_start(ap, fmt);
		vcmn_err(CE_NOTE, fmt, ap);
		va_end(ap);
	}
}

/*
 * Some operations clients may use to manage the data
 * to be persisted in a cache file.
 */
char *
nvf_cache_name(nvf_handle_t handle)
{
	return (((nvfd_t *)handle)->nvf_cache_path);
}

krwlock_t *
nvf_lock(nvf_handle_t handle)
{
	return (&(((nvfd_t *)handle)->nvf_lock));
}

list_t *
nvf_list(nvf_handle_t handle)
{
	return (&(((nvfd_t *)handle)->nvf_data_list));
}

void
nvf_mark_dirty(nvf_handle_t handle)
{
	ASSERT(RW_WRITE_HELD(&(((nvfd_t *)handle)->nvf_lock)));
	NVF_MARK_DIRTY((nvfd_t *)handle);
}

int
nvf_is_dirty(nvf_handle_t handle)
{
	ASSERT(RW_LOCK_HELD(&(((nvfd_t *)handle)->nvf_lock)));
	return (NVF_IS_DIRTY((nvfd_t *)handle));
}

static uint16_t
nvp_cksum(uchar_t *buf, int64_t buflen)
{
	uint16_t cksum = 0;
	uint16_t *p = (uint16_t *)buf;
	int64_t n;

	if ((buflen & 0x01) != 0) {
		buflen--;
		cksum = buf[buflen];
	}
	n = buflen / 2;
	while (n-- > 0)
		cksum ^= *p++;
	return (cksum);
}

int
fread_nvlist(char *filename, nvlist_t **ret_nvlist)
{
	struct _buf	*file;
	nvpf_hdr_t	hdr;
	char		*buf;
	nvlist_t	*nvl;
	int		rval;
	uint_t		offset;
	int		n;
	char		c;
	uint16_t	cksum, hdrsum;

	*ret_nvlist = NULL;

	file = kobj_open_file(filename);
	if (file == (struct _buf *)-1) {
		KFDEBUG((CE_CONT, "cannot open file: %s\n", filename));
		return (ENOENT);
	}

	offset = 0;
	n = kobj_read_file(file, (char *)&hdr, sizeof (hdr), offset);
	if (n != sizeof (hdr)) {
		kobj_close_file(file);
		if (n < 0) {
			nvf_error("error reading header: %s\n", filename);
			return (EIO);
		} else if (n == 0) {
			KFDEBUG((CE_CONT, "file empty: %s\n", filename));
		} else {
			nvf_error("header size incorrect: %s\n", filename);
		}
		return (EINVAL);
	}
	offset += n;

	KFDEBUG2((CE_CONT, "nvpf_magic: 0x%x\n", hdr.nvpf_magic));
	KFDEBUG2((CE_CONT, "nvpf_version: %d\n", hdr.nvpf_version));
	KFDEBUG2((CE_CONT, "nvpf_size: %lld\n",
	    (longlong_t)hdr.nvpf_size));
	KFDEBUG2((CE_CONT, "nvpf_hdr_chksum: 0x%x\n",
	    hdr.nvpf_hdr_chksum));
	KFDEBUG2((CE_CONT, "nvpf_chksum: 0x%x\n", hdr.nvpf_chksum));

	cksum = hdr.nvpf_hdr_chksum;
	hdr.nvpf_hdr_chksum = 0;
	hdrsum = nvp_cksum((uchar_t *)&hdr, sizeof (hdr));

	if (hdr.nvpf_magic != NVPF_HDR_MAGIC ||
	    hdr.nvpf_version != NVPF_HDR_VERSION || hdrsum != cksum) {
		kobj_close_file(file);
		if (hdrsum != cksum) {
			nvf_error("%s: checksum error "
			    "(actual 0x%x, expected 0x%x)\n",
			    filename, hdrsum, cksum);
		}
		nvf_error("%s: header information incorrect", filename);
		return (EINVAL);
	}

	ASSERT(hdr.nvpf_size >= 0);

	buf = kmem_alloc(hdr.nvpf_size, KM_SLEEP);
	n = kobj_read_file(file, buf, hdr.nvpf_size, offset);
	if (n != hdr.nvpf_size) {
		kmem_free(buf, hdr.nvpf_size);
		kobj_close_file(file);
		if (n < 0) {
			nvf_error("%s: read error %d", filename, n);
		} else {
			nvf_error("%s: incomplete read %d/%lld",
			    filename, n, (longlong_t)hdr.nvpf_size);
		}
		return (EINVAL);
	}
	offset += n;

	rval = kobj_read_file(file, &c, 1, offset);
	kobj_close_file(file);
	if (rval > 0) {
		nvf_error("%s is larger than %lld\n",
		    filename, (longlong_t)hdr.nvpf_size);
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	cksum = nvp_cksum((uchar_t *)buf, hdr.nvpf_size);
	if (hdr.nvpf_chksum != cksum) {
		nvf_error("%s: checksum error (actual 0x%x, expected 0x%x)\n",
		    filename, hdr.nvpf_chksum, cksum);
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	nvl = NULL;
	rval = nvlist_unpack(buf, hdr.nvpf_size, &nvl, 0);
	if (rval != 0) {
		nvf_error("%s: error %d unpacking nvlist\n",
		    filename, rval);
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	kmem_free(buf, hdr.nvpf_size);
	*ret_nvlist = nvl;
	return (0);
}

static int
kfcreate(char *filename, kfile_t **kfilep)
{
	kfile_t	*fp;
	int	rval;

	ASSERT(modrootloaded);

	fp = kmem_alloc(sizeof (kfile_t), KM_SLEEP);

	fp->kf_vnflags = FCREAT | FWRITE | FTRUNC;
	fp->kf_fname = filename;
	fp->kf_fpos = 0;
	fp->kf_state = 0;

	KFDEBUG((CE_CONT, "create: %s flags 0x%x\n",
	    filename, fp->kf_vnflags));
	rval = vn_open(filename, UIO_SYSSPACE, fp->kf_vnflags,
	    0444, &fp->kf_vp, CRCREAT, 0);
	if (rval != 0) {
		kmem_free(fp, sizeof (kfile_t));
		KFDEBUG((CE_CONT, "%s: create error %d\n",
		    filename, rval));
		return (rval);
	}

	*kfilep = fp;
	return (0);
}

static int
kfremove(char *filename)
{
	int rval;

	KFDEBUG((CE_CONT, "remove: %s\n", filename));
	rval = vn_remove(filename, UIO_SYSSPACE, RMFILE);
	if (rval != 0) {
		KFDEBUG((CE_CONT, "%s: remove error %d\n",
		    filename, rval));
	}
	return (rval);
}

static int
kfread(kfile_t *fp, char *buf, ssize_t bufsiz, ssize_t *ret_n)
{
	ssize_t		resid;
	int		err;
	ssize_t		n;

	ASSERT(modrootloaded);

	if (fp->kf_state != 0)
		return (fp->kf_state);

	err = vn_rdwr(UIO_READ, fp->kf_vp, buf, bufsiz, fp->kf_fpos,
	    UIO_SYSSPACE, 0, (rlim64_t)0, kcred, &resid);
	if (err != 0) {
		KFDEBUG((CE_CONT, "%s: read error %d\n",
		    fp->kf_fname, err));
		fp->kf_state = err;
		return (err);
	}

	ASSERT(resid >= 0 && resid <= bufsiz);
	n = bufsiz - resid;

	KFDEBUG1((CE_CONT, "%s: read %ld bytes ok %ld bufsiz, %ld resid\n",
	    fp->kf_fname, n, bufsiz, resid));

	fp->kf_fpos += n;
	*ret_n = n;
	return (0);
}

static int
kfwrite(kfile_t *fp, char *buf, ssize_t bufsiz, ssize_t *ret_n)
{
	rlim64_t	rlimit;
	ssize_t		resid;
	int		err;
	ssize_t		len;
	ssize_t		n = 0;

	ASSERT(modrootloaded);

	if (fp->kf_state != 0)
		return (fp->kf_state);

	len = bufsiz;
	rlimit = bufsiz + 1;
	for (;;) {
		err = vn_rdwr(UIO_WRITE, fp->kf_vp, buf, len, fp->kf_fpos,
		    UIO_SYSSPACE, FSYNC, rlimit, kcred, &resid);
		if (err) {
			KFDEBUG((CE_CONT, "%s: write error %d\n",
			    fp->kf_fname, err));
			fp->kf_state = err;
			return (err);
		}

		KFDEBUG1((CE_CONT, "%s: write %ld bytes ok %ld resid\n",
		    fp->kf_fname, len-resid, resid));

		ASSERT(resid >= 0 && resid <= len);

		n += (len - resid);
		if (resid == 0)
			break;

		if (resid == len) {
			KFDEBUG((CE_CONT, "%s: filesystem full?\n",
			    fp->kf_fname));
			fp->kf_state = ENOSPC;
			return (ENOSPC);
		}

		len -= resid;
		buf += len;
		fp->kf_fpos += len;
		len = resid;
	}

	ASSERT(n == bufsiz);
	KFDEBUG1((CE_CONT, "%s: wrote %ld bytes ok\n", fp->kf_fname, n));

	*ret_n = n;
	return (0);
}


static int
kfclose(kfile_t *fp)
{
	int		rval;

	KFDEBUG((CE_CONT, "close: %s\n", fp->kf_fname));

	if ((fp->kf_vnflags & FWRITE) && fp->kf_state == 0) {
		rval = VOP_FSYNC(fp->kf_vp, FSYNC, kcred, NULL);
		if (rval != 0) {
			nvf_error("%s: sync error %d\n",
			    fp->kf_fname, rval);
		}
		KFDEBUG((CE_CONT, "%s: sync ok\n", fp->kf_fname));
	}

	rval = VOP_CLOSE(fp->kf_vp, fp->kf_vnflags, 1,
	    (offset_t)0, kcred, NULL);
	if (rval != 0) {
		if (fp->kf_state == 0) {
			nvf_error("%s: close error %d\n",
			    fp->kf_fname, rval);
		}
	} else {
		if (fp->kf_state == 0)
			KFDEBUG((CE_CONT, "%s: close ok\n", fp->kf_fname));
	}

	VN_RELE(fp->kf_vp);
	kmem_free(fp, sizeof (kfile_t));
	return (rval);
}

static int
kfrename(char *oldname, char *newname)
{
	int rval;

	ASSERT(modrootloaded);

	KFDEBUG((CE_CONT, "renaming %s to %s\n", oldname, newname));

	if ((rval = vn_rename(oldname, newname, UIO_SYSSPACE)) != 0) {
		KFDEBUG((CE_CONT, "rename %s to %s: %d\n",
		    oldname, newname, rval));
	}

	return (rval);
}

int
fwrite_nvlist(char *filename, nvlist_t *nvl)
{
	char	*buf;
	char	*nvbuf;
	kfile_t	*fp;
	char	*newname;
	int	len, err, err1;
	size_t	buflen;
	ssize_t	n;

	ASSERT(modrootloaded);

	nvbuf = NULL;
	err = nvlist_pack(nvl, &nvbuf, &buflen, NV_ENCODE_NATIVE, 0);
	if (err != 0) {
		nvf_error("%s: error %d packing nvlist\n",
		    filename, err);
		return (err);
	}

	buf = kmem_alloc(sizeof (nvpf_hdr_t) + buflen, KM_SLEEP);
	bzero(buf, sizeof (nvpf_hdr_t));

	((nvpf_hdr_t *)buf)->nvpf_magic = NVPF_HDR_MAGIC;
	((nvpf_hdr_t *)buf)->nvpf_version = NVPF_HDR_VERSION;
	((nvpf_hdr_t *)buf)->nvpf_size = buflen;
	((nvpf_hdr_t *)buf)->nvpf_chksum = nvp_cksum((uchar_t *)nvbuf, buflen);
	((nvpf_hdr_t *)buf)->nvpf_hdr_chksum =
	    nvp_cksum((uchar_t *)buf, sizeof (nvpf_hdr_t));

	bcopy(nvbuf, buf + sizeof (nvpf_hdr_t), buflen);
	kmem_free(nvbuf, buflen);
	buflen += sizeof (nvpf_hdr_t);

	len = strlen(filename) + MAX_SUFFIX_LEN + 2;
	newname = kmem_alloc(len, KM_SLEEP);


	(void) sprintf(newname, "%s.%s", filename, NEW_FILENAME_SUFFIX);

	/*
	 * To make it unlikely we suffer data loss, write
	 * data to the new temporary file.  Once successful
	 * complete the transaction by renaming the new file
	 * to replace the previous.
	 */

	if ((err = kfcreate(newname, &fp)) == 0) {
		err = kfwrite(fp, buf, buflen, &n);
		if (err) {
			nvf_error("%s: write error - %d\n",
			    newname, err);
		} else {
			if (n != buflen) {
				nvf_error(
				    "%s: partial write %ld of %ld bytes\n",
				    newname, n, buflen);
				nvf_error("%s: filesystem may be full?\n",
				    newname);
				err = EIO;
			}
		}
		if ((err1 = kfclose(fp)) != 0) {
			nvf_error("%s: close error\n", newname);
			if (err == 0)
				err = err1;
		}
		if (err != 0) {
			if (kfremove(newname) != 0) {
				nvf_error("%s: remove failed\n",
				    newname);
			}
		}
	} else {
		nvf_error("%s: create failed - %d\n", filename, err);
	}

	if (err == 0) {
		if ((err = kfrename(newname, filename)) != 0) {
			nvf_error("%s: rename from %s failed\n",
			    newname, filename);
		}
	}

	kmem_free(newname, len);
	kmem_free(buf, buflen);

	return (err);
}

static int
e_fwrite_nvlist(nvfd_t *nvfd, nvlist_t *nvl)
{
	int err;

	if ((err = fwrite_nvlist(nvfd->nvf_cache_path, nvl)) == 0)
		return (DDI_SUCCESS);
	else {
		if (err == EROFS)
			NVF_MARK_READONLY(nvfd);
		return (DDI_FAILURE);
	}
}

static void
nvp_list_free(nvfd_t *nvf)
{
	ASSERT(RW_WRITE_HELD(&nvf->nvf_lock));
	(nvf->nvf_list_free)((nvf_handle_t)nvf);
	ASSERT(RW_WRITE_HELD(&nvf->nvf_lock));
}

/*
 * Read a file in the nvlist format
 *	EIO - i/o error during read
 *	ENOENT - file not found
 *	EINVAL - file contents corrupted
 */
static int
fread_nvp_list(nvfd_t *nvfd)
{
	nvlist_t	*nvl;
	nvpair_t	*nvp;
	char		*name;
	nvlist_t	*sublist;
	int		rval;
	int		rv;

	ASSERT(RW_WRITE_HELD(&(nvfd->nvf_lock)));

	rval = fread_nvlist(nvfd->nvf_cache_path, &nvl);
	if (rval != 0)
		return (rval);
	ASSERT(nvl != NULL);

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);
		ASSERT(strlen(name) > 0);

		switch (nvpair_type(nvp)) {
		case DATA_TYPE_NVLIST:
			rval = nvpair_value_nvlist(nvp, &sublist);
			if (rval != 0) {
				nvf_error(
				    "nvpair_value_nvlist error %s %d\n",
				    name, rval);
				goto error;
			}

			/*
			 * unpack nvlist for this device and
			 * add elements to data list.
			 */
			ASSERT(RW_WRITE_HELD(&(nvfd->nvf_lock)));
			rv = (nvfd->nvf_unpack_nvlist)
			    ((nvf_handle_t)nvfd, sublist, name);
			ASSERT(RW_WRITE_HELD(&(nvfd->nvf_lock)));
			if (rv != 0) {
				nvf_error(
				    "%s: %s invalid list element\n",
				    nvfd->nvf_cache_path, name);
				rval = EINVAL;
				goto error;
			}
			break;

		default:
			nvf_error("%s: %s unsupported data type %d\n",
			    nvfd->nvf_cache_path, name, nvpair_type(nvp));
			rval = EINVAL;
			goto error;
		}
	}

	nvlist_free(nvl);

	return (0);

error:
	nvlist_free(nvl);
	nvp_list_free(nvfd);
	return (rval);
}


int
nvf_read_file(nvf_handle_t nvf_handle)
{
	nvfd_t *nvfd = (nvfd_t *)nvf_handle;
	int rval;

	ASSERT(RW_WRITE_HELD(&nvfd->nvf_lock));

	if (kfio_disable_read)
		return (0);

	KFDEBUG((CE_CONT, "reading %s\n", nvfd->nvf_cache_path));

	rval = fread_nvp_list(nvfd);
	if (rval) {
		switch (rval) {
		case EIO:
			nvfd->nvf_flags |= NVF_F_REBUILD_MSG;
			cmn_err(CE_WARN, "%s: I/O error",
			    nvfd->nvf_cache_path);
			break;
		case ENOENT:
			nvfd->nvf_flags |= NVF_F_CREATE_MSG;
			nvf_error("%s: not found\n",
			    nvfd->nvf_cache_path);
			break;
		case EINVAL:
		default:
			nvfd->nvf_flags |= NVF_F_REBUILD_MSG;
			cmn_err(CE_WARN, "%s: data file corrupted",
			    nvfd->nvf_cache_path);
			break;
		}
	}
	return (rval);
}

static void
nvf_write_is_complete(nvfd_t *fd)
{
	if (fd->nvf_write_complete) {
		(fd->nvf_write_complete)((nvf_handle_t)fd);
	}
}

/*ARGSUSED*/
static void
nvpflush_timeout(void *arg)
{
	clock_t nticks;

	mutex_enter(&nvpflush_lock);
	nticks = nvpticks - ddi_get_lbolt();
	if (nticks > 4) {
		nvpflush_timer_busy = 1;
		mutex_exit(&nvpflush_lock);
		nvpflush_id = timeout(nvpflush_timeout, NULL, nticks);
	} else {
		do_nvpflush = 1;
		NVPDAEMON_DEBUG((CE_CONT, "signal nvpdaemon\n"));
		cv_signal(&nvpflush_cv);
		nvpflush_id = 0;
		nvpflush_timer_busy = 0;
		mutex_exit(&nvpflush_lock);
	}
}

/*
 * After marking a list as dirty, wake the nvpflush daemon
 * to perform the update.
 */
void
nvf_wake_daemon(void)
{
	clock_t nticks;

	/*
	 * If the system isn't up yet or is shutting down,
	 * don't even think about starting a flush.
	 */
	if (!i_ddi_io_initialized() || sys_shutdown)
		return;

	mutex_enter(&nvpflush_lock);

	if (nvpflush_daemon_active == 0) {
		nvpflush_daemon_active = 1;
		mutex_exit(&nvpflush_lock);
		NVPDAEMON_DEBUG((CE_CONT, "starting nvpdaemon thread\n"));
		nvpflush_thr_id = thread_create(NULL, 0,
		    (void (*)())nvpflush_daemon,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
		mutex_enter(&nvpflush_lock);
	}

	nticks = nvpflush_delay * TICKS_PER_SECOND;
	nvpticks = ddi_get_lbolt() + nticks;
	if (nvpflush_timer_busy == 0) {
		nvpflush_timer_busy = 1;
		mutex_exit(&nvpflush_lock);
		nvpflush_id = timeout(nvpflush_timeout, NULL, nticks + 4);
	} else
		mutex_exit(&nvpflush_lock);
}

static int
nvpflush_one(nvfd_t *nvfd)
{
	int rval = DDI_SUCCESS;
	nvlist_t *nvl;

	rw_enter(&nvfd->nvf_lock, RW_READER);

	ASSERT((nvfd->nvf_flags & NVF_F_FLUSHING) == 0);

	if (!NVF_IS_DIRTY(nvfd) ||
	    NVF_IS_READONLY(nvfd) || kfio_disable_write || sys_shutdown) {
		NVF_CLEAR_DIRTY(nvfd);
		rw_exit(&nvfd->nvf_lock);
		return (DDI_SUCCESS);
	}

	if (rw_tryupgrade(&nvfd->nvf_lock) == 0) {
		nvf_error("nvpflush: "
		    "%s rw upgrade failed\n", nvfd->nvf_cache_path);
		rw_exit(&nvfd->nvf_lock);
		return (DDI_FAILURE);
	}
	if (((nvfd->nvf_pack_list)
	    ((nvf_handle_t)nvfd, &nvl)) != DDI_SUCCESS) {
		nvf_error("nvpflush: "
		    "%s nvlist construction failed\n", nvfd->nvf_cache_path);
		ASSERT(RW_WRITE_HELD(&nvfd->nvf_lock));
		rw_exit(&nvfd->nvf_lock);
		return (DDI_FAILURE);
	}
	ASSERT(RW_WRITE_HELD(&nvfd->nvf_lock));

	NVF_CLEAR_DIRTY(nvfd);
	nvfd->nvf_flags |= NVF_F_FLUSHING;
	rw_exit(&nvfd->nvf_lock);

	rval = e_fwrite_nvlist(nvfd, nvl);
	nvlist_free(nvl);

	rw_enter(&nvfd->nvf_lock, RW_WRITER);
	nvfd->nvf_flags &= ~NVF_F_FLUSHING;
	if (rval == DDI_FAILURE) {
		if (NVF_IS_READONLY(nvfd)) {
			rval = DDI_SUCCESS;
			nvfd->nvf_flags &= ~(NVF_F_ERROR | NVF_F_DIRTY);
		} else if ((nvfd->nvf_flags & NVF_F_ERROR) == 0) {
			cmn_err(CE_CONT,
			    "%s: update failed\n", nvfd->nvf_cache_path);
			nvfd->nvf_flags |= NVF_F_ERROR | NVF_F_DIRTY;
		}
	} else {
		if (nvfd->nvf_flags & NVF_F_CREATE_MSG) {
			cmn_err(CE_CONT,
			    "!Creating %s\n", nvfd->nvf_cache_path);
			nvfd->nvf_flags &= ~NVF_F_CREATE_MSG;
		}
		if (nvfd->nvf_flags & NVF_F_REBUILD_MSG) {
			cmn_err(CE_CONT,
			    "!Rebuilding %s\n", nvfd->nvf_cache_path);
			nvfd->nvf_flags &= ~NVF_F_REBUILD_MSG;
		}
		if (nvfd->nvf_flags & NVF_F_ERROR) {
			cmn_err(CE_CONT,
			    "%s: update now ok\n", nvfd->nvf_cache_path);
			nvfd->nvf_flags &= ~NVF_F_ERROR;
		}
		/*
		 * The file may need to be flushed again if the cached
		 * data was touched while writing the earlier contents.
		 */
		if (NVF_IS_DIRTY(nvfd))
			rval = DDI_FAILURE;
	}

	rw_exit(&nvfd->nvf_lock);
	return (rval);
}


static void
nvpflush_daemon(void)
{
	callb_cpr_t cprinfo;
	nvfd_t *nvfdp, *nextfdp;
	clock_t clk;
	int rval;
	int want_wakeup;
	int is_now_clean;

	ASSERT(modrootloaded);

	nvpflush_thread = curthread;
	NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: init\n"));

	CALLB_CPR_INIT(&cprinfo, &nvpflush_lock, callb_generic_cpr, "nvp");
	mutex_enter(&nvpflush_lock);
	for (;;) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		while (do_nvpflush == 0) {
			clk = cv_timedwait(&nvpflush_cv, &nvpflush_lock,
			    ddi_get_lbolt() +
			    (nvpdaemon_idle_time * TICKS_PER_SECOND));
			if ((clk == -1 && do_nvpflush == 0 &&
			    nvpflush_timer_busy == 0) || sys_shutdown) {
				/*
				 * Note that CALLB_CPR_EXIT calls mutex_exit()
				 * on the lock passed in to CALLB_CPR_INIT,
				 * so the lock must be held when invoking it.
				 */
				CALLB_CPR_SAFE_END(&cprinfo, &nvpflush_lock);
				NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: exit\n"));
				ASSERT(mutex_owned(&nvpflush_lock));
				nvpflush_thr_id = NULL;
				nvpflush_daemon_active = 0;
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
			}
		}
		CALLB_CPR_SAFE_END(&cprinfo, &nvpflush_lock);

		nvpbusy = 1;
		want_wakeup = 0;
		do_nvpflush = 0;
		mutex_exit(&nvpflush_lock);

		/*
		 * Try flushing what's dirty, reschedule if there's
		 * a failure or data gets marked as dirty again.
		 * First move each file marked dirty to the dirty
		 * list to avoid locking the list across the write.
		 */
		mutex_enter(&nvf_cache_mutex);
		for (nvfdp = list_head(&nvf_cache_files);
		    nvfdp; nvfdp = nextfdp) {
			nextfdp = list_next(&nvf_cache_files, nvfdp);
			rw_enter(&nvfdp->nvf_lock, RW_READER);
			if (NVF_IS_DIRTY(nvfdp)) {
				list_remove(&nvf_cache_files, nvfdp);
				list_insert_tail(&nvf_dirty_files, nvfdp);
				rw_exit(&nvfdp->nvf_lock);
			} else {
				NVPDAEMON_DEBUG((CE_CONT,
				    "nvpdaemon: not dirty %s\n",
				    nvfdp->nvf_cache_path));
				rw_exit(&nvfdp->nvf_lock);
			}
		}
		mutex_exit(&nvf_cache_mutex);

		/*
		 * Now go through the dirty list
		 */
		for (nvfdp = list_head(&nvf_dirty_files);
		    nvfdp; nvfdp = nextfdp) {
			nextfdp = list_next(&nvf_dirty_files, nvfdp);

			is_now_clean = 0;
			rw_enter(&nvfdp->nvf_lock, RW_READER);
			if (NVF_IS_DIRTY(nvfdp)) {
				NVPDAEMON_DEBUG((CE_CONT,
				    "nvpdaemon: flush %s\n",
				    nvfdp->nvf_cache_path));
				rw_exit(&nvfdp->nvf_lock);
				rval = nvpflush_one(nvfdp);
				rw_enter(&nvfdp->nvf_lock, RW_READER);
				if (rval != DDI_SUCCESS ||
				    NVF_IS_DIRTY(nvfdp)) {
					rw_exit(&nvfdp->nvf_lock);
					NVPDAEMON_DEBUG((CE_CONT,
					    "nvpdaemon: %s dirty again\n",
					    nvfdp->nvf_cache_path));
					want_wakeup = 1;
				} else {
					rw_exit(&nvfdp->nvf_lock);
					nvf_write_is_complete(nvfdp);
					is_now_clean = 1;
				}
			} else {
				NVPDAEMON_DEBUG((CE_CONT,
				    "nvpdaemon: not dirty %s\n",
				    nvfdp->nvf_cache_path));
				rw_exit(&nvfdp->nvf_lock);
				is_now_clean = 1;
			}

			if (is_now_clean) {
				mutex_enter(&nvf_cache_mutex);
				list_remove(&nvf_dirty_files, nvfdp);
				list_insert_tail(&nvf_cache_files,
				    nvfdp);
				mutex_exit(&nvf_cache_mutex);
			}
		}

		if (want_wakeup)
			nvf_wake_daemon();

		mutex_enter(&nvpflush_lock);
		nvpbusy = 0;
	}
}

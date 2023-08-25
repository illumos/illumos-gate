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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.
 */

#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <rpc/types.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <nfs/export.h>
#include <nfs/rnode.h>
#include <rpc/auth.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>
#include <nfs/nfs_log.h>

#define	NUM_RECORDS_TO_WRITE 256
#define	NUM_BYTES_TO_WRITE 65536

static int nfslog_num_records_to_write = NUM_RECORDS_TO_WRITE;
static int nfslog_num_bytes_to_write = NUM_BYTES_TO_WRITE;

/*
 * This struct is used to 'hide' the details of managing the log
 * records internally to the logging code.  Allocation routines
 * are used to obtain pieces of memory for XDR encoding.  This struct
 * is a 'header' to those areas and a opaque cookie is used to pass
 * this data structure between the allocating function and the put
 * function.
 */
struct lr_alloc {
	struct lr_alloc		*next;		/* links for write queuing */
	struct lr_alloc		*prev;
#define	LR_ALLOC_NOFREE	0x1			/* not present, call free */
	int			lr_flags;
	caddr_t			log_record;	/* address to XDR encoding */
	size_t			size;		/* final size of encoding */
	struct kmem_cache	*alloc_cache;	/* keep track of cache ptr */
	struct exportinfo	*exi;		/* who are we related to? */
	struct log_buffer	*lb;
};

struct flush_thread_params {
	struct nfsl_flush_args tp_args;
	int tp_error;
};

static int log_file_create(caddr_t, struct log_file **);
static void log_file_rele(struct log_file *);
static struct log_buffer *log_buffer_create(caddr_t);
static void log_buffer_rele(struct log_buffer *);
static int nfslog_record_append2all(struct lr_alloc *);
static int nfslog_logbuffer_rename(struct log_buffer *);
static void nfslog_logfile_wait(struct log_file *);
static int nfslog_logfile_rename(char *, char *);
static void nfslog_do_flush(struct flush_thread_params *);
static void create_buffer_header(caddr_t *, size_t *, size_t *);

static int nfslog_write_logrecords(struct log_file *, struct lr_alloc *, int);
static void nfslog_free_logrecords(struct lr_alloc *);
static int nfslog_records_flush_to_disk(struct log_buffer *);
static int nfslog_records_flush_to_disk_nolock(struct log_buffer *);

/*
 * Read/Write lock that protects 'nfslog_buffer_list'.
 * This lock must be held when searching or modifying 'nfslog_buffer_list'.
 */
static krwlock_t nfslog_buffer_list_lock;

/*
 * The list of "log_buffer" structures.
 */
struct log_buffer *nfslog_buffer_list = NULL;


#define	LOG_BUFFER_HOLD(lbp)	{ \
	mutex_enter(&(lbp)->lb_lock); \
	(lbp)->lb_refcnt++; \
	mutex_exit(&(lbp)->lb_lock); \
}

#define	LOG_FILE_HOLD(lfp)	{ \
	mutex_enter(&(lfp)->lf_lock); \
	(lfp)->lf_refcnt++; \
	mutex_exit(&(lfp)->lf_lock); \
}

#define	LOG_FILE_RELE(lfp)	{ \
	log_file_rele(lfp); \
}

/*
 * These two macros are used to prep a logfile data structure and
 * associated file for writing data.  Note that the lf_lock is
 * held as a result of the call to the first macro.  This is used
 * for serialization correctness between the logbuffer struct and
 * the logfile struct.
 */
#define	LOG_FILE_LOCK_TO_WRITE(lfp)	{ \
	mutex_enter(&(lfp)->lf_lock); \
	(lfp)->lf_refcnt++; \
	(lfp)->lf_writers++; \
}

#define	LOG_FILE_UNLOCK_FROM_WRITE(lfp)	{ \
	(lfp)->lf_writers--; \
	if ((lfp)->lf_writers == 0 && ((lfp)->lf_flags & L_WAITING)) { \
		(lfp)->lf_flags &= ~L_WAITING; \
		cv_broadcast(&(lfp)->lf_cv_waiters); \
	} \
	mutex_exit(&(lfp)->lf_lock); \
	log_file_rele(lfp); \
}

int rfsl_log_buffer = 0;
static int rfsl_log_file = 0;

/* This array is used for memory allocation of record encoding spaces */
static struct {
	int	size;
	struct kmem_cache *mem_cache;
	char	*cache_name;
} nfslog_mem_alloc[] = {
#define	SMALL_INDX 0
	{ NFSLOG_SMALL_RECORD_SIZE - sizeof (struct lr_alloc),
	NULL, NFSLOG_SMALL_REC_NAME },
#define	MEDIUM_INDX 1
	{ NFSLOG_MEDIUM_RECORD_SIZE - sizeof (struct lr_alloc),
	NULL, NFSLOG_MEDIUM_REC_NAME },
#define	LARGE_INDX 2
	{ NFSLOG_LARGE_RECORD_SIZE - sizeof (struct lr_alloc),
	NULL, NFSLOG_LARGE_REC_NAME },
	{ (-1), NULL }
};

/* Used to calculate the 'real' allocation size */
#define	ALLOC_SIZE(index) \
	(nfslog_mem_alloc[index].size + sizeof (struct lr_alloc))

/*
 * Initialize logging data buffer cache
 */
void
nfslog_init()
{
	int indx;

	rw_init(&nfslog_buffer_list_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Initialize the kmem caches for encoding
	 */
	for (indx = 0; nfslog_mem_alloc[indx].size != (-1); indx++) {
		nfslog_mem_alloc[indx].mem_cache =
		    kmem_cache_create(nfslog_mem_alloc[indx].cache_name,
		    ALLOC_SIZE(indx), 0, NULL, NULL, NULL, NULL, NULL, 0);
	}
}

/*
 * Sets up the necessary log file and related buffers to enable logging
 * on the given export point.
 * Returns 0 on success, non-zero on failure.
 */
int
nfslog_setup(struct exportinfo *exi)
{
	struct exportdata *kex;
	struct log_buffer *lbp;
	struct log_buffer *nlbp;

	kex = &exi->exi_export;
	ASSERT(kex->ex_flags & EX_LOG);

	/*
	 * Logging is enabled for the new export point, check
	 * the existing log_buffer structures to see if the
	 * desired buffer has already been opened. If so, point
	 * the new exportinfo's exi_logbuffer to the existing
	 * one.
	 */
	rw_enter(&nfslog_buffer_list_lock, RW_READER);
	for (lbp = nfslog_buffer_list; lbp != NULL; lbp = lbp->lb_next) {
		LOGGING_DPRINT((10,
		    "searching for buffer... found log_buffer '%s'\n",
		    lbp->lb_path));
		if (strcmp(lbp->lb_path, kex->ex_log_buffer) == 0) {
			/* Found our match. Ref it and return */
			LOG_BUFFER_HOLD(lbp);
			exi->exi_logbuffer = lbp;
			LOGGING_DPRINT((10,  "\tfound log_buffer for '%s'\n",
			    kex->ex_log_buffer));
			rw_exit(&nfslog_buffer_list_lock);
			return (0);
		}
	}
	rw_exit(&nfslog_buffer_list_lock);

	/*
	 * New buffer needed, allocate it.
	 * The buffer list lock has been dropped so we will need to search
	 * the list again to ensure that another thread has not added
	 * a matching buffer.
	 */
	if ((nlbp = log_buffer_create(kex->ex_log_buffer)) == NULL) {
		/*
		 * Failed the buffer creation for some reason so we
		 * will need to return.
		 */
		return (EIO);
	}

	rw_enter(&nfslog_buffer_list_lock, RW_WRITER);
	for (lbp = nfslog_buffer_list; lbp != NULL;
	    lbp = lbp->lb_next) {
		if (strcmp(lbp->lb_path, kex->ex_log_buffer) == 0) {
				/*
				 * A log_buffer already exists for the
				 * indicated buffer, use it instead.
				 */
			LOG_BUFFER_HOLD(lbp);

			exi->exi_logbuffer = lbp;

			LOGGING_DPRINT((10, "found log_buffer for '%s' "
			    "after allocation\n", kex->ex_log_buffer));

			rw_exit(&nfslog_buffer_list_lock);

			log_buffer_rele(nlbp);

			return (0);
		}
	}
	/*
	 * Didn't find an existing log_buffer for this buffer,
	 * use the the newly created one, and add to list.  We
	 * increment the reference count because the node is
	 * entered into the global list.
	 */
	LOGGING_DPRINT((10, "exportfs: adding nlbp=%p to list\n",
	    (void *)nlbp));

	nlbp->lb_next = nfslog_buffer_list;
	nfslog_buffer_list = nlbp;

	LOG_BUFFER_HOLD(nlbp);	/* hold is for export entry */
	exi->exi_logbuffer = nlbp;

	rw_exit(&nfslog_buffer_list_lock);

	return (0);
}

/*
 * Disables logging for the given export point.
 */
void
nfslog_disable(struct exportinfo *exi)
{
	log_buffer_rele(exi->exi_logbuffer);
}

/*
 * Creates the corresponding log_buffer and log_file structures
 * for the the buffer named 'name'.
 * Returns a pointer to the log_buffer structure with reference one.
 */
static struct log_buffer *
log_buffer_create(caddr_t name)
{
	struct log_buffer *buffer;
	struct log_file *logfile;
	int namelen = strlen(name);

	LOGGING_DPRINT((10,  "log_buffer_create: %s\n", name));
	if (log_file_create(name, &logfile))
		return (NULL);

	buffer = (struct log_buffer *)kmem_alloc(sizeof (*buffer), KM_SLEEP);
	buffer->lb_refcnt = 1;
	buffer->lb_rec_id = 0;
	buffer->lb_path = (caddr_t)kmem_alloc(namelen + 1, KM_SLEEP);
	bcopy(name, buffer->lb_path, namelen + 1);
	buffer->lb_logfile = logfile;
	buffer->lb_records = NULL;
	buffer->lb_num_recs = 0;
	buffer->lb_size_queued = 0;
	mutex_init(&buffer->lb_lock, NULL, MUTEX_DEFAULT, NULL);
	rfsl_log_buffer++;

	return (buffer);
}

/*
 * Release a log_buffer structure
 */
static void
log_buffer_rele(struct log_buffer *lbp)
{
	int len;

	mutex_enter(&lbp->lb_lock);
	if (--lbp->lb_refcnt > 1) {
		mutex_exit(&lbp->lb_lock);
		return;
	}

	if (lbp->lb_refcnt < 0) {
		panic("log_rele: log_buffer refcnt < 0");
		/*NOTREACHED*/
	}

	/*
	 * Need to drop the lb_lock before acquiring the
	 * nfslog_buffer_list_lock. To avoid double free we need
	 * to hold an additional reference to the log buffer.
	 * This will ensure that no two threads will simultaneously
	 * be trying to free the same log buffer.
	 */

	if (lbp->lb_refcnt == 1) {

		/*
		 * If the ref count is 1, then the last
		 * unshare/reference has been given up and we need to
		 * clean up the buffer and remove it from the buffer
		 * list.
		 */
		LOGGING_DPRINT((10,
		    "log_buffer_rele lbp=%p disconnecting\n", (void *)lbp));
		/*
		 * Hold additional reference before dropping the lb_lock
		 */

		lbp->lb_refcnt++;
		mutex_exit(&lbp->lb_lock);

		/*
		 * Make sure that all of the buffered records are written.
		 * Don't bother checking the write return value since there
		 * isn't much we can do at this point.
		 */
		(void) nfslog_records_flush_to_disk(lbp);

		rw_enter(&nfslog_buffer_list_lock, RW_WRITER);
		mutex_enter(&lbp->lb_lock);
		/*
		 * Drop the reference count held above.
		 * If the ref count is still > 1 then someone has
		 * stepped in to use this log buffer.  unlock and return.
		 */
		if (--lbp->lb_refcnt > 1) {
			mutex_exit(&lbp->lb_lock);
			rw_exit(&nfslog_buffer_list_lock);
			return;
		}

		if (lbp == nfslog_buffer_list) {
			nfslog_buffer_list = lbp->lb_next;
		} else {
			struct log_buffer *tlbp;

			/* Drop the log_buffer from the master list */
			for (tlbp = nfslog_buffer_list; tlbp->lb_next != NULL;
			    tlbp = tlbp->lb_next) {
				if (tlbp->lb_next == lbp) {
					tlbp->lb_next = lbp->lb_next;
					break;
				}
			}
		}

		mutex_exit(&lbp->lb_lock);
		rw_exit(&nfslog_buffer_list_lock);
	}
	/*
	 * ref count zero; finish clean up.
	 */
	LOGGING_DPRINT((10, "log_buffer_rele lbp=%p freeing\n", (void *)lbp));

	log_file_rele(lbp->lb_logfile);
	len = strlen(lbp->lb_path) + 1;
	kmem_free(lbp->lb_path, len);
	kmem_free(lbp, sizeof (*lbp));
	rfsl_log_buffer--;
}

/*
 * Creates the corresponding log_file structure for the buffer
 * named 'log_file_name'.
 * 'log_file_name' is created by concatenating 'origname' and LOG_INPROG_STRING.
 * 'logfile' is set to be the log_file structure with reference one.
 */
static int
log_file_create(caddr_t origname, struct log_file **lfpp)
{
	vnode_t *vp = NULL;
	char *name;
	int namelen;
	int error;
	struct log_file *logfile = NULL;
	vattr_t va;
	caddr_t loghdr = NULL;
	size_t loghdr_len = 0;
	size_t loghdr_free = 0;

	namelen = strlen(origname) + strlen(LOG_INPROG_STRING);
	name = (caddr_t)kmem_alloc(namelen + 1, KM_SLEEP);
	(void) sprintf(name, "%s%s", origname, LOG_INPROG_STRING);

	LOGGING_DPRINT((3, "log_file_create: %s\n", name));
	error = vn_open(name, UIO_SYSSPACE, FCREAT|FWRITE|FOFFMAX,
	    LOG_MODE, &vp, CRCREAT, 0);
	if (error != 0) {
		nfs_cmn_err(error, CE_WARN,
		    "log_file_create: Can not open %s - error %m", name);
		goto out;
	}
	LOGGING_DPRINT((3, "log_file_create: %s vp=%p v_count=%d\n",
	    name, (void *)vp, vp->v_count));

	logfile = (struct log_file *)kmem_zalloc(sizeof (*logfile), KM_SLEEP);
	logfile->lf_path = name;
	/*
	 * No need to bump the vnode reference count since it is set
	 * to one by vn_open().
	 */
	logfile->lf_vp = vp;
	logfile->lf_refcnt = 1;
	mutex_init(&logfile->lf_lock, NULL, MUTEX_DEFAULT, NULL);
	rfsl_log_file++;

	va.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &va, 0, CRED(), NULL);
	if (error) {
		nfs_cmn_err(error, CE_WARN,
		    "log_file_create: Can not stat %s - error = %m",  name);
		goto out;
	}

	if (va.va_size == 0) {
		struct lr_alloc lr;

		/*
		 * Write Header.
		 */
		create_buffer_header(&loghdr, &loghdr_len, &loghdr_free);
		/*
		 * Dummy up a lr_alloc struct for the write
		 */
		lr.next = lr.prev = &lr;
		lr.lr_flags = 0;
		lr.log_record = loghdr;
		lr.size = loghdr_len;
		lr.alloc_cache = NULL;
		lr.exi = NULL;
		lr.lb = NULL;

		mutex_enter(&logfile->lf_lock);

		error = nfslog_write_logrecords(logfile, &lr, 1);

		mutex_exit(&logfile->lf_lock);

		if (error != 0) {
			nfs_cmn_err(error, CE_WARN,
			    "log_file_create: Can not write header "
			    "on %s - error = %m", name);
			goto out;
		}
	}
	*lfpp = logfile;

	if (loghdr != NULL)
		kmem_free(loghdr, loghdr_free);

	return (0);

out:
	if (vp != NULL) {
		int error1;
		error1 = VOP_CLOSE(vp, FCREAT|FWRITE|FOFFMAX, 1, (offset_t)0,
		    CRED(), NULL);
		if (error1) {
			nfs_cmn_err(error1, CE_WARN,
			    "log_file_create: Can not close %s - "
			    "error = %m", name);
		}
		VN_RELE(vp);
	}

	kmem_free(name, namelen + 1);
	if (logfile != NULL) {
		mutex_destroy(&logfile->lf_lock);
		kmem_free(logfile, sizeof (*logfile));
		rfsl_log_file--;
	}
	if (loghdr != NULL)
		kmem_free(loghdr, loghdr_free);

	return (error);
}

/*
 * Release a log_file structure
 */
static void
log_file_rele(struct log_file *lfp)
{
	int len;
	int error;

	mutex_enter(&lfp->lf_lock);
	if (--lfp->lf_refcnt > 0) {
		LOGGING_DPRINT((10,
		    "log_file_rele lfp=%p decremented refcnt to %d\n",
		    (void *)lfp, lfp->lf_refcnt));
		mutex_exit(&lfp->lf_lock);
		return;
	}
	if (lfp->lf_refcnt < 0) {
		panic("log_file_rele: log_file refcnt < 0");
		/*NOTREACHED*/
	}

	LOGGING_DPRINT((10, "log_file_rele lfp=%p freeing node\n",
	    (void *)lfp));

	lfp->lf_flags &= ~(L_PRINTED | L_ERROR);

	ASSERT(lfp->lf_flags == 0);
	ASSERT(lfp->lf_writers == 0);

	error = VOP_CLOSE(lfp->lf_vp, FCREAT|FWRITE|FOFFMAX, 1, (offset_t)0,
	    CRED(), NULL);
	if (error != 0) {
		nfs_cmn_err(error, CE_WARN,
		    "NFS: Could not close log buffer %s - error = %m",
		    lfp->lf_path);
#ifdef DEBUG
	} else {
		LOGGING_DPRINT((3,
		    "log_file_rele: %s has been closed vp=%p v_count=%d\n",
		    lfp->lf_path, (void *)lfp->lf_vp, lfp->lf_vp->v_count));
#endif
	}
	VN_RELE(lfp->lf_vp);

	len = strlen(lfp->lf_path) + 1;
	kmem_free(lfp->lf_path, len);
	kmem_free(lfp, sizeof (*lfp));
	rfsl_log_file--;
}

/*
 * Allocates a record of the size specified.
 * 'exi' identifies the exportinfo structure being logged.
 * 'size' indicates how much memory should be allocated
 * 'cookie' is used to store an opaque value for the caller for later use
 * 'flags' currently ignored.
 *
 * Returns a pointer to the beginning of the allocated memory.
 * 'cookie' is a pointer to the 'lr_alloc' struct; this will be used
 * to keep track of the encoded record and contains all the info
 * for enqueuing the record on the log buffer for later writing.
 *
 * nfslog_record_put() must be used to 'free' this record or allocation.
 */
/* ARGSUSED */
void *
nfslog_record_alloc(struct exportinfo *exi, int alloc_indx, void **cookie,
    int flags)
{
	struct lr_alloc *lrp;

	lrp = (struct lr_alloc *)
	    kmem_cache_alloc(nfslog_mem_alloc[alloc_indx].mem_cache,
	    KM_NOSLEEP);

	if (lrp == NULL) {
		*cookie = NULL;
		return (NULL);
	}

	lrp->next = lrp;
	lrp->prev = lrp;
	lrp->lr_flags = 0;

	lrp->log_record = (caddr_t)((uintptr_t)lrp +
	    (uintptr_t)sizeof (struct lr_alloc));
	lrp->size = nfslog_mem_alloc[alloc_indx].size;
	lrp->alloc_cache = nfslog_mem_alloc[alloc_indx].mem_cache;
	lrp->exi = exi;

	if (exi->exi_export.ex_flags & EX_LOG) {
		LOG_BUFFER_HOLD(exi->exi_logbuffer);
		lrp->lb = exi->exi_logbuffer;
	} else {
		lrp->lb = NULL;
	}

	*cookie = (void *)lrp;

	LOGGING_DPRINT((3,
	    "nfslog_record_alloc(log_buffer=%p mem=%p size=%lu)\n",
	    (void *)exi->exi_logbuffer, (void *)lrp->log_record, lrp->size));
	return (lrp->log_record);
}

/*
 * After the above nfslog_record_alloc() has been called and a record
 * encoded into the buffer that was returned, this function is called
 * to handle appropriate disposition of the newly created record.
 * The cookie value is the one that was returned from nfslog_record_alloc().
 * Size is the actual size of the record that was encoded.  This is
 * passed in because the size used for the alloc was just an approximation.
 * The sync parameter is used to tell us if we need to force this record
 * to disk and if not it will be queued for later writing.
 *
 * Note that if the size parameter has a value of 0, then the record is
 * not written to the log and the associated data structures are released.
 */
void
nfslog_record_put(void *cookie, size_t size, bool_t sync,
    unsigned int which_buffers)
{
	struct lr_alloc *lrp = (struct lr_alloc *)cookie;
	struct log_buffer *lbp = lrp->lb;

	/*
	 * If the caller has nothing to write or if there is
	 * an apparent error, rele the buffer and free.
	 */
	if (size == 0 || size > lrp->size) {
		nfslog_free_logrecords(lrp);
		return;
	}

	/*
	 * Reset the size to what actually needs to be written
	 * This is used later on when the iovec is built for
	 * writing the records to the log file.
	 */
	lrp->size = size;

	/* append to all if public exi */
	if (which_buffers == NFSLOG_ALL_BUFFERS) {
		(void) nfslog_record_append2all(lrp);
		nfslog_free_logrecords(lrp);
		return;
	}

	/* Insert the record on the list to be written */
	mutex_enter(&lbp->lb_lock);
	if (lbp->lb_records == NULL) {
		lbp->lb_records = (caddr_t)lrp;
		lbp->lb_num_recs = 1;
		lbp->lb_size_queued = lrp->size;
	} else {
		insque(lrp, ((struct lr_alloc *)lbp->lb_records)->prev);
		lbp->lb_num_recs++;
		lbp->lb_size_queued += lrp->size;
	}

	/*
	 * Determine if the queue for this log buffer should be flushed.
	 * This is done by either the number of records queued, the total
	 * size of all records queued or by the request of the caller
	 * via the sync parameter.
	 */
	if (lbp->lb_size_queued >= nfslog_num_bytes_to_write ||
	    lbp->lb_num_recs > nfslog_num_records_to_write || sync == TRUE) {
		mutex_exit(&lbp->lb_lock);
		(void) nfslog_records_flush_to_disk(lbp);
	} else {
		mutex_exit(&lbp->lb_lock);
	}

}

/*
 * Examine the log_buffer struct to see if there are queue log records
 * that need to be written to disk.  If some exist, pull them off of
 * the log buffer and write them to the log file.
 */
static int
nfslog_records_flush_to_disk(struct log_buffer *lbp)
{

	mutex_enter(&lbp->lb_lock);

	if (lbp->lb_records == NULL) {
		mutex_exit(&lbp->lb_lock);
		return (0);
	}
	return	(nfslog_records_flush_to_disk_nolock(lbp));
}

/*
 * Function requires that the caller holds lb_lock.
 * Function flushes any records in the log buffer to the disk.
 * Function drops the lb_lock on return.
 */

static int
nfslog_records_flush_to_disk_nolock(struct log_buffer *lbp)
{
	struct log_file *lfp = NULL;
	struct lr_alloc *lrp_writers;
	int num_recs;
	int error = 0;

	ASSERT(MUTEX_HELD(&lbp->lb_lock));

	lfp = lbp->lb_logfile;

	LOG_FILE_LOCK_TO_WRITE(lfp);
	ASSERT(lbp->lb_records != NULL);

	lrp_writers = (struct lr_alloc *)lbp->lb_records;
	lbp->lb_records = NULL;
	num_recs = lbp->lb_num_recs;
	lbp->lb_num_recs = 0;
	lbp->lb_size_queued = 0;
	mutex_exit(&lbp->lb_lock);
	error = nfslog_write_logrecords(lfp, lrp_writers, num_recs);

	LOG_FILE_UNLOCK_FROM_WRITE(lfp);

	nfslog_free_logrecords(lrp_writers);
	return (error);
}


/*
 * Take care of writing the provided log record(s) to the log file.
 * We group the log records with an iovec and use VOP_WRITE to append
 * them to the end of the log file.
 */
static int
nfslog_write_logrecords(struct log_file *lfp, struct lr_alloc *lrp_writers,
    int num_recs)
{
	struct uio uio;
	struct iovec *iovp;
	int size_iovecs;
	vnode_t *vp;
	struct vattr va;
	struct lr_alloc *lrp;
	int i;
	ssize_t len;
	int ioflag = FAPPEND;
	int error = 0;

	ASSERT(MUTEX_HELD(&lfp->lf_lock));

	vp = lfp->lf_vp;

	size_iovecs = sizeof (struct iovec) * num_recs;
	iovp = (struct iovec *)kmem_alloc(size_iovecs, KM_NOSLEEP);

	if (iovp == NULL) {
		error = ENOMEM;
		goto out;
	}

	/* Build the iovec based on the list of log records */
	i = 0;
	len = 0;
	lrp = lrp_writers;
	do {
		iovp[i].iov_base = lrp->log_record;
		iovp[i].iov_len = lrp->size;
		len += lrp->size;
		lrp = lrp->next;
		i++;
	} while (lrp != lrp_writers);

	ASSERT(i == num_recs);

	uio.uio_iov = iovp;
	uio.uio_iovcnt = num_recs;
	uio.uio_loffset = 0;
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_resid = len;
	uio.uio_llimit = (rlim64_t)MAXOFFSET_T;
	uio.uio_fmode = FWRITE;
	uio.uio_extflg = UIO_COPY_DEFAULT;

	/*
	 * Save the size. If the write fails, reset the size to avoid
	 * corrupted log buffer files.
	 */
	va.va_mask = AT_SIZE;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);  /* UIO_WRITE */
	if ((error = VOP_GETATTR(vp, &va, 0, CRED(), NULL)) == 0) {
		if ((len + va.va_size) < (MAXOFF32_T)) {
			error = VOP_WRITE(vp, &uio, ioflag, CRED(), NULL);
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			if (uio.uio_resid)
				error = ENOSPC;
			if (error)
				(void) VOP_SETATTR(vp, &va, 0, CRED(), NULL);
		} else {
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			if (!(lfp->lf_flags & L_PRINTED)) {
				cmn_err(CE_WARN,
				    "NFS Logging: buffer file %s exceeds 2GB; "
				    "stopped writing buffer \n", lfp->lf_path);
			}
			error = ENOSPC;
		}
	} else {
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
	}

	kmem_free(iovp, size_iovecs);

out:
	if (error) {
		if (!(lfp->lf_flags & L_PRINTED)) {
			nfs_cmn_err(error, CE_WARN,
			    "NFS Logging disabled for buffer %s - "
			    "write error = %m\n", lfp->lf_path);
			lfp->lf_flags |= L_PRINTED;
		}
	} else if (lfp->lf_flags & (L_ERROR | L_PRINTED)) {
		lfp->lf_flags &= ~(L_ERROR | L_PRINTED);
		cmn_err(CE_WARN,
		    "NFS Logging re-enabled for buffer %s\n", lfp->lf_path);
	}

	return (error);
}

static void
nfslog_free_logrecords(struct lr_alloc *lrp_writers)
{
	struct lr_alloc *lrp = lrp_writers;
	struct lr_alloc *lrp_free;

	do {
		lrp_free = lrp;

		lrp = lrp->next;

		/*
		 * Check to see if we are supposed to free this structure
		 * and relese the log_buffer ref count.
		 * It may be the case that the caller does not want this
		 * structure and its record contents freed just yet.
		 */
		if ((lrp_free->lr_flags & LR_ALLOC_NOFREE) == 0) {
			if (lrp_free->lb != NULL)
				log_buffer_rele(lrp_free->lb);
			if (lrp_free->alloc_cache) /* double check */
				kmem_cache_free(lrp_free->alloc_cache,
				    (void *)lrp_free);
		} else {
			/*
			 * after being pulled from the list the
			 * pointers need to be reinitialized.
			 */
			lrp_free->next = lrp_free;
			lrp_free->prev = lrp_free;
		}

	} while (lrp != lrp_writers);
}

/*
 * Rename lbp->lb_logfile to reflect the true name requested by 'share'
 */
static int
nfslog_logbuffer_rename(struct log_buffer *lbp)
{
	struct log_file *lf;
	int error;
	struct log_file *logfile;

	/*
	 * Try our best to get the cache records into the log file
	 * before the rename occurs.
	 */
	(void) nfslog_records_flush_to_disk(lbp);

	/*
	 * Hold lb_lock before retrieving
	 * lb_logfile.
	 * Hold a reference to the
	 * "lf" structure. this is
	 * same as LOG_FILE_HOLD()
	 */
	mutex_enter(&(lbp)->lb_lock);
	lf = lbp->lb_logfile;
	mutex_enter(&(lf)->lf_lock);
	mutex_exit(&(lbp)->lb_lock);
	lf->lf_refcnt++;
	mutex_exit(&(lf)->lf_lock);

	LOGGING_DPRINT((10, "nfslog_logbuffer_rename: renaming %s to %s\n",
	    lf->lf_path, lbp->lb_path));

	/*
	 * rename the current buffer to what the daemon expects
	 */
	error = nfslog_logfile_rename(lf->lf_path, lbp->lb_path);
	if (error != 0)
		goto out;

	/*
	 * Create a new working buffer file and have all new data sent there.
	 */
	error = log_file_create(lbp->lb_path, &logfile);
	if (error != 0) {
		/* Attempt to rename to original */
		(void) nfslog_logfile_rename(lbp->lb_path, lf->lf_path);
		goto out;
	}

	/*
	 * Hold the lb_lock here, this will make
	 * all the threads trying to access lb->logfile block
	 * and get a new logfile structure instead of old one.
	 */
	mutex_enter(&(lbp)->lb_lock);
	lbp->lb_logfile = logfile;
	mutex_exit(&(lbp)->lb_lock);

	LOG_FILE_RELE(lf);	/* release log_buffer's reference */

	/*
	 * Wait for log_file to be in a quiescent state before we
	 * return to our caller to let it proceed with the reading of
	 * this file.
	 */
	nfslog_logfile_wait(lf);

out:
	/*
	 * Release our reference on "lf" in two different cases.
	 * 1. Error condition, release only the reference
	 *    that we held at the begining of this
	 *    routine on "lf" structure.
	 * 2. Fall through condition, no errors but the old
	 *    logfile structure "lf" has been replaced with
	 *    the new "logfile" structure, so release the
	 *    reference that was part of the creation of
	 *    "lf" structure to free up the resources.
	 */

	LOG_FILE_RELE(lf);

	return (error);
}

/*
 * Renames the 'from' file to 'new'.
 */
static int
nfslog_logfile_rename(char *from, char *new)
{
	int error;

	error = vn_rename(from, new, UIO_SYSSPACE);
	if (error != 0) {
		cmn_err(CE_WARN,
		    "nfslog_logfile_rename: couldn't rename %s to %s\n",
		    from, new);
	}
	return (error);
}

/*
 * Wait for the log_file writers to finish before returning
 */
static void
nfslog_logfile_wait(struct log_file *lf)
{
	mutex_enter(&lf->lf_lock);
	while (lf->lf_writers > 0) {
		lf->lf_flags |= L_WAITING;
		(void) cv_wait_sig(&lf->lf_cv_waiters, &lf->lf_lock);
	}
	mutex_exit(&lf->lf_lock);
}

static int
nfslog_record_append2all(struct lr_alloc *lrp)
{
	struct log_buffer *lbp, *nlbp;
	int error, ret_error = 0;
	int lr_flags = lrp->lr_flags;

	rw_enter(&nfslog_buffer_list_lock, RW_READER);
	if ((lbp = nfslog_buffer_list) != NULL)
		LOG_BUFFER_HOLD(lbp);
	for (nlbp = NULL; lbp != NULL; lbp = nlbp) {
		if ((nlbp = lbp->lb_next) != NULL) {
			/*
			 * Remember next element in the list
			 */
			LOG_BUFFER_HOLD(nlbp);
		}
		rw_exit(&nfslog_buffer_list_lock);

		/*
		 * Insert the record on the buffer's list to be written
		 * and then flush the records to the log file.
		 * Make sure to set the no free flag so that the
		 * record can be used for the next write
		 */
		lrp->lr_flags = LR_ALLOC_NOFREE;

		ASSERT(lbp != NULL);
		mutex_enter(&lbp->lb_lock);
		if (lbp->lb_records == NULL) {
			lbp->lb_records = (caddr_t)lrp;
			lbp->lb_num_recs = 1;
			lbp->lb_size_queued = lrp->size;
		} else {
			insque(lrp, ((struct lr_alloc *)lbp->lb_records)->prev);
			lbp->lb_num_recs++;
			lbp->lb_size_queued += lrp->size;
		}

		/*
		 * Flush log records to disk.
		 * Function is called with lb_lock held.
		 * Function drops the lb_lock on return.
		 */
		error = nfslog_records_flush_to_disk_nolock(lbp);

		if (error) {
			ret_error = -1;
			nfs_cmn_err(error, CE_WARN,
			    "rfsl_log_pubfh: could not append record to "
			    "\"%s\" error = %m\n", lbp->lb_path);
		}
		log_buffer_rele(lbp);
		rw_enter(&nfslog_buffer_list_lock, RW_READER);
	}
	rw_exit(&nfslog_buffer_list_lock);

	lrp->lr_flags = lr_flags;

	return (ret_error);
}

#ifdef DEBUG
static int logging_debug = 0;

/*
 * 0) no debugging
 * 3) current test software
 * 10) random stuff
 */
void
nfslog_dprint(const int level, const char *fmt, ...)
{
	va_list args;

	if (logging_debug == level ||
	    (logging_debug > 10 && (logging_debug - 10) >= level)) {
		va_start(args, fmt);
		(void) vprintf(fmt, args);
		va_end(args);
	}
}

#endif /* DEBUG */

/*
 * NFS Log Flush system call
 * Caller must check privileges.
 */
/* ARGSUSED */
int
nfsl_flush(struct nfsl_flush_args *args, model_t model)
{
	struct flush_thread_params *tparams;
	struct nfsl_flush_args *nfsl_args;
	int error = 0;
	ulong_t buffer_len;
	STRUCT_HANDLE(nfsl_flush_args, uap);

	STRUCT_SET_HANDLE(uap, model, args);

	tparams = (struct flush_thread_params *)
	    kmem_zalloc(sizeof (*tparams), KM_SLEEP);

	nfsl_args = &tparams->tp_args;
	nfsl_args->version =  STRUCT_FGET(uap, version);
	if (nfsl_args->version != NFSL_FLUSH_ARGS_VERS) {
		cmn_err(CE_WARN, "nfsl_flush: exected version %d, got %d",
		    NFSL_FLUSH_ARGS_VERS, nfsl_args->version);
		return (EIO);
	}

	nfsl_args->directive = STRUCT_FGET(uap, directive);
	if ((nfsl_args->directive & NFSL_ALL) == 0) {
		/*
		 * Process a specific buffer
		 */
		nfsl_args->buff_len = STRUCT_FGET(uap, buff_len);

		nfsl_args->buff = (char *)
		    kmem_alloc(nfsl_args->buff_len, KM_NOSLEEP);
		if (nfsl_args->buff == NULL)
			return (ENOMEM);

		error = copyinstr((const char *)STRUCT_FGETP(uap, buff),
		    nfsl_args->buff, nfsl_args->buff_len, &buffer_len);
		if (error)
			return (EFAULT);

		if (nfsl_args->buff_len != buffer_len)
			return (EFAULT);
	}

	LOGGING_DPRINT((10, "nfsl_flush: Flushing %s buffer(s)\n",
	    nfsl_args->directive & NFSL_ALL ? "all" : nfsl_args->buff));

	if (nfsl_args->directive & NFSL_SYNC) {
		/*
		 * Do the work synchronously
		 */
		nfslog_do_flush(tparams);
		error = tparams->tp_error;
		kmem_free(nfsl_args->buff, nfsl_args->buff_len);
		kmem_free(tparams, sizeof (*tparams));
	} else {
		/*
		 * Do the work asynchronously
		 */
		(void) zthread_create(NULL, 0, nfslog_do_flush,
		    tparams, 0, minclsyspri);
	}

	return (error);
}

/*
 * This is where buffer flushing would occur, but there is no buffering
 * at this time.
 * Possibly rename the log buffer for processing.
 * Sets tparams->ta_error equal to the value of the error that occurred,
 * 0 otherwise.
 * Returns ENOENT if the buffer is not found.
 */
static void
nfslog_do_flush(struct flush_thread_params *tparams)
{
	struct nfsl_flush_args *args;
	struct log_buffer *lbp, *nlbp;
	int error = ENOENT;
	int found = 0;
	char *buf_inprog;	/* name of buff in progress */
	int buf_inprog_len;

	/*
	 * Sanity check on the arguments.
	 */
	if (!tparams)
		return;
	args = &tparams->tp_args;
	if (!args)
		return;

	rw_enter(&nfslog_buffer_list_lock, RW_READER);
	if ((lbp = nfslog_buffer_list) != NULL) {
		LOG_BUFFER_HOLD(lbp);
	}
	for (nlbp = NULL; lbp != NULL; lbp = nlbp) {
		if ((nlbp = lbp->lb_next) != NULL) {
			LOG_BUFFER_HOLD(nlbp);
		}
		rw_exit(&nfslog_buffer_list_lock);
		if (args->directive & NFSL_ALL) {
			(void) nfslog_records_flush_to_disk(lbp);
		} else {
			if ((strcmp(lbp->lb_path, args->buff) == 0) &&
			    (args->directive & NFSL_RENAME)) {
				error = nfslog_logbuffer_rename(lbp);
				found++;
				if (nlbp != NULL)
					log_buffer_rele(nlbp);
				log_buffer_rele(lbp);
				break;
			}
		}
		log_buffer_rele(lbp);
		rw_enter(&nfslog_buffer_list_lock, RW_READER);
	}
	if (!found)
		rw_exit(&nfslog_buffer_list_lock);

	if (!found && ((args->directive & NFSL_ALL) == 0) &&
	    (args->directive & NFSL_RENAME)) {
		/*
		 * The specified buffer is not currently in use,
		 * simply rename the file indicated.
		 */
		buf_inprog_len = strlen(args->buff) +
		    strlen(LOG_INPROG_STRING) + 1;
		buf_inprog = (caddr_t)kmem_alloc(buf_inprog_len, KM_SLEEP);
		(void) sprintf(buf_inprog, "%s%s",
		    args->buff, LOG_INPROG_STRING);

		error = nfslog_logfile_rename(buf_inprog, args->buff);

		kmem_free(buf_inprog, buf_inprog_len);
	}

out:
	if ((args->directive & NFSL_SYNC) == 0) {
		/*
		 * Work was performed asynchronously, the caller is
		 * no longer waiting for us.
		 * Free the thread arguments and exit.
		 */
		kmem_free(args->buff, args->buff_len);
		kmem_free(tparams, sizeof (*tparams));
		zthread_exit();
	}

	tparams->tp_error = error;
}

/*
 * Generate buffer_header.
 * 'loghdr' points the the buffer_header, and *reclen
 * contains the length of the buffer.
 */
static void
create_buffer_header(caddr_t *loghdr, size_t *reclen, size_t *freesize)
{
	timestruc_t		now;
	nfslog_buffer_header	lh;
	XDR			xdrs;
	unsigned int		final_size;


	/* pick some size that will hold the buffer_header */
	*freesize = NFSLOG_SMALL_RECORD_SIZE;

	/*
	 * Fill header
	 */
	lh.bh_length = 0;	/* don't know yet how large it will be */
	lh.bh_version = NFSLOG_BUF_VERSION;
	lh.bh_flags = 0;
	lh.bh_offset = 0;
	gethrestime(&now);
	TIMESPEC_TO_TIMESPEC32(&lh.bh_timestamp, &now);

	/*
	 * Encode the header
	 */
	*loghdr = (caddr_t)kmem_alloc(*freesize, KM_SLEEP);
	xdrmem_create(&xdrs, *loghdr, *freesize, XDR_ENCODE);

	(void) xdr_nfslog_buffer_header(&xdrs, &lh);

	/*
	 * Reset with final size of the encoded data
	 */
	final_size = xdr_getpos(&xdrs);
	xdr_setpos(&xdrs, 0);
	(void) xdr_u_int(&xdrs, &final_size);

	*reclen = (size_t)final_size;
}

/*
 * ****************************************************************
 * RPC dispatch table for logging
 * Indexed by program, version, proc
 * Based on NFS dispatch table.
 */
struct nfslog_proc_disp {
	bool_t	(*xdrargs)();
	bool_t	(*xdrres)();
	bool_t	affects_transactions;	/* Operation affects transaction */
					/* processing */
};

struct nfslog_vers_disp {
	int	nfslog_dis_nprocs;			/* number of procs */
	struct nfslog_proc_disp	*nfslog_dis_proc_table;	/* proc array */
};

struct nfslog_prog_disp {
	int	nfslog_dis_prog;		/* program number */
	int	nfslog_dis_versmin;		/* Minimum version value */
	int	nfslog_dis_nvers;		/* Number of version values */
	struct nfslog_vers_disp	*nfslog_dis_vers_table;	/* versions array */
};

static int rfs_log_bad = 0;	/* incremented on bad log attempts */
static int rfs_log_good = 0;	/* incremented on successful log attempts */

/*
 * Define the actions taken per prog/vers/proc:
 *
 * In some cases, the nl types are the same as the nfs types and a simple
 * bcopy should suffice. Rather that define tens of identical procedures,
 * simply define these to bcopy. Similarly this takes care of different
 * procs that use same parameter struct.
 */

static struct nfslog_proc_disp nfslog_proc_v2[] = {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */
	{xdr_void, xdr_void, FALSE},

	/* RFS_GETATTR = 1 */
	{xdr_fhandle, xdr_nfslog_getattrres, FALSE},

	/* RFS_SETATTR = 2 */
	{xdr_nfslog_setattrargs, xdr_nfsstat, TRUE},

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */
	{xdr_void, xdr_void, FALSE},

	/* RFS_LOOKUP = 4 */
	{xdr_nfslog_diropargs, xdr_nfslog_diropres, TRUE},

	/* RFS_READLINK = 5 */
	{xdr_fhandle, xdr_nfslog_rdlnres, FALSE},

	/* RFS_READ = 6 */
	{xdr_nfslog_nfsreadargs, xdr_nfslog_rdresult, TRUE},

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */
	{xdr_void, xdr_void, FALSE},

	/* RFS_WRITE = 8 */
	{xdr_nfslog_writeargs, xdr_nfslog_writeresult, TRUE},

	/* RFS_CREATE = 9 */
	{xdr_nfslog_createargs, xdr_nfslog_diropres, TRUE},

	/* RFS_REMOVE = 10 */
	{xdr_nfslog_diropargs, xdr_nfsstat, TRUE},

	/* RFS_RENAME = 11 */
	{xdr_nfslog_rnmargs, xdr_nfsstat, TRUE},

	/* RFS_LINK = 12 */
	{xdr_nfslog_linkargs, xdr_nfsstat, TRUE},

	/* RFS_SYMLINK = 13 */
	{xdr_nfslog_symlinkargs, xdr_nfsstat, TRUE},

	/* RFS_MKDIR = 14 */
	{xdr_nfslog_createargs, xdr_nfslog_diropres, TRUE},

	/* RFS_RMDIR = 15 */
	{xdr_nfslog_diropargs, xdr_nfsstat, TRUE},

	/* RFS_READDIR = 16 */
	{xdr_nfslog_rddirargs, xdr_nfslog_rddirres, TRUE},

	/* RFS_STATFS = 17 */
	{xdr_fhandle, xdr_nfslog_statfs, FALSE},
};


/*
 * NFS VERSION 3
 */

static struct nfslog_proc_disp nfslog_proc_v3[] = {

	/* NFSPROC3_NULL = 0 */
	{xdr_void, xdr_void, FALSE},

	/* NFSPROC3_GETATTR = 1 */
	{xdr_nfslog_nfs_fh3, xdr_nfslog_GETATTR3res, FALSE},

	/* NFSPROC3_SETATTR = 2 */
	{xdr_nfslog_SETATTR3args, xdr_nfslog_SETATTR3res, TRUE},

	/* NFSPROC3_LOOKUP = 3 */
	{xdr_nfslog_diropargs3, xdr_nfslog_LOOKUP3res, TRUE},

	/* NFSPROC3_ACCESS = 4 */
	{xdr_nfslog_ACCESS3args, xdr_nfslog_ACCESS3res, FALSE},

	/* NFSPROC3_READLINK = 5 */
	{xdr_nfslog_nfs_fh3, xdr_nfslog_READLINK3res, FALSE},

	/* NFSPROC3_READ = 6 */
	{xdr_nfslog_READ3args, xdr_nfslog_READ3res, TRUE},

	/* NFSPROC3_WRITE = 7 */
	{xdr_nfslog_WRITE3args, xdr_nfslog_WRITE3res, TRUE},

	/* NFSPROC3_CREATE = 8 */
	{xdr_nfslog_CREATE3args, xdr_nfslog_CREATE3res, TRUE},

	/* NFSPROC3_MKDIR = 9 */
	{xdr_nfslog_MKDIR3args, xdr_nfslog_MKDIR3res, TRUE},

	/* NFSPROC3_SYMLINK = 10 */
	{xdr_nfslog_SYMLINK3args, xdr_nfslog_SYMLINK3res, TRUE},

	/* NFSPROC3_MKNOD = 11 */
	{xdr_nfslog_MKNOD3args, xdr_nfslog_MKNOD3res, TRUE},

	/* NFSPROC3_REMOVE = 12 */
	{xdr_nfslog_REMOVE3args, xdr_nfslog_REMOVE3res, TRUE},

	/* NFSPROC3_RMDIR = 13 */
	{xdr_nfslog_RMDIR3args, xdr_nfslog_RMDIR3res, TRUE},

	/* NFSPROC3_RENAME = 14 */
	{xdr_nfslog_RENAME3args, xdr_nfslog_RENAME3res, TRUE},

	/* NFSPROC3_LINK = 15 */
	{xdr_nfslog_LINK3args, xdr_nfslog_LINK3res, TRUE},

	/* NFSPROC3_READDIR = 16 */
	{xdr_nfslog_READDIR3args, xdr_nfslog_READDIR3res, TRUE},

	/* NFSPROC3_READDIRPLUS = 17 */
	{xdr_nfslog_READDIRPLUS3args, xdr_nfslog_READDIRPLUS3res, TRUE},

	/* NFSPROC3_FSSTAT = 18 */
	{xdr_nfslog_FSSTAT3args, xdr_nfslog_FSSTAT3res, FALSE},

	/* NFSPROC3_FSINFO = 19 */
	{xdr_nfslog_FSINFO3args, xdr_nfslog_FSINFO3res, FALSE},

	/* NFSPROC3_PATHCONF = 20 */
	{xdr_nfslog_PATHCONF3args, xdr_nfslog_PATHCONF3res, FALSE},

	/* NFSPROC3_COMMIT = 21 */
	{xdr_nfslog_COMMIT3args, xdr_nfslog_COMMIT3res, FALSE},
};

static struct nfslog_proc_disp nfslog_proc_v1[] = {
	/*
	 * NFSLOG VERSION 1
	 */

	/* NFSLOG_NULL = 0 */
	{xdr_void, xdr_void, TRUE},

	/* NFSLOG_SHARE = 1 */
	{xdr_nfslog_sharefsargs, xdr_nfslog_sharefsres, TRUE},

	/* NFSLOG_UNSHARE = 2 */
	{xdr_nfslog_sharefsargs, xdr_nfslog_sharefsres, TRUE},

	/* NFSLOG_LOOKUP = 3 */
	{xdr_nfslog_diropargs3, xdr_nfslog_LOOKUP3res, TRUE},

	/* NFSLOG_GETFH = 4 */
	{xdr_nfslog_getfhargs, xdr_nfsstat, TRUE},
};

static struct nfslog_vers_disp nfslog_vers_disptable[] = {
	{sizeof (nfslog_proc_v2) / sizeof (nfslog_proc_v2[0]),
	    nfslog_proc_v2},
	{sizeof (nfslog_proc_v3) / sizeof (nfslog_proc_v3[0]),
	    nfslog_proc_v3},
};

static struct nfslog_vers_disp nfslog_nfslog_vers_disptable[] = {
	{sizeof (nfslog_proc_v1) / sizeof (nfslog_proc_v1[0]),
	    nfslog_proc_v1},
};

static struct nfslog_prog_disp nfslog_dispatch_table[] = {
	{NFS_PROGRAM, NFS_VERSMIN,
		(sizeof (nfslog_vers_disptable) /
		sizeof (nfslog_vers_disptable[0])),
		nfslog_vers_disptable},

	{NFSLOG_PROGRAM, NFSLOG_VERSMIN,
		(sizeof (nfslog_nfslog_vers_disptable) /
		sizeof (nfslog_nfslog_vers_disptable[0])),
		nfslog_nfslog_vers_disptable},
};

static int	nfslog_dispatch_table_arglen = sizeof (nfslog_dispatch_table) /
					sizeof (nfslog_dispatch_table[0]);

/*
 * This function will determine the appropriate export info struct to use
 * and allocate a record id to be used in the written log buffer.
 * Usually this is a straightforward operation but the existence of the
 * multicomponent lookup and its semantics of crossing file system
 * boundaries add to the complexity.  See the comments below...
 */
struct exportinfo *
nfslog_get_exi(
	nfs_export_t *ne,
	struct exportinfo *exi,
	struct svc_req *req,
	caddr_t res,
	unsigned int *nfslog_rec_id)
{
	struct log_buffer *lb;
	struct exportinfo *exi_ret = NULL;
	fhandle_t		*fh;
	nfs_fh3			*fh3;

	if (exi == NULL)
		return (NULL);

	/*
	 * If the exi is marked for logging, allocate a record id and return
	 */
	if (exi->exi_export.ex_flags & EX_LOG) {
		lb = exi->exi_logbuffer;

		/* obtain the unique record id for the caller */
		*nfslog_rec_id = atomic_add_32_nv(&lb->lb_rec_id, (int32_t)1);

		/*
		 * The caller will expect to be able to exi_rele() it,
		 * so exi->exi_count must be incremented before it can
		 * be returned, to make it uniform with exi_ret->exi_count
		 */
		exi_hold(exi);
		return (exi);
	}

	if (exi != ne->exi_public)
		return (NULL);

	/*
	 * Here we have an exi that is not marked for logging.
	 * It is possible that this request is a multicomponent lookup
	 * that was done from the public file handle (not logged) and
	 * the resulting file handle being returned to the client exists
	 * in a file system that is being logged.  If this is the case
	 * we need to log this multicomponent lookup to the appropriate
	 * log buffer.  This will allow for the appropriate path name
	 * mapping to occur at user level.
	 */
	if (req->rq_prog == NFS_PROGRAM) {
		switch (req->rq_vers) {
		case NFS_V3:
			if ((req->rq_proc == NFSPROC3_LOOKUP) &&
			    (((LOOKUP3res *)res)->status == NFS3_OK)) {
				fh3 = &((LOOKUP3res *)res)->res_u.ok.object;
				exi_ret = checkexport(&fh3->fh3_fsid,
				    FH3TOXFIDP(fh3));
			}
			break;

		case NFS_VERSION:
			if ((req->rq_proc == RFS_LOOKUP) &&
			    (((struct nfsdiropres *)
			    res)->dr_status == NFS_OK)) {
				fh =  &((struct nfsdiropres *)res)->
				    dr_u.dr_drok_u.drok_fhandle;
				exi_ret = checkexport(&fh->fh_fsid,
				    (fid_t *)&fh->fh_xlen);
			}
			break;
		default:
			break;
		}
	}

	if (exi_ret != NULL && exi_ret->exi_export.ex_flags & EX_LOG) {
		lb = exi_ret->exi_logbuffer;
		/* obtain the unique record id for the caller */
		*nfslog_rec_id = atomic_add_32_nv(&lb->lb_rec_id, (int32_t)1);

		return (exi_ret);
	}
	return (NULL);
}

#ifdef DEBUG
static long long rfslog_records_ignored = 0;
#endif

/*
 * nfslog_write_record - Fill in the record buffer for writing out.
 * If logrecp is null, log it, otherwise, malloc the record and return it.
 *
 * It is the responsibility of the caller to check whether this exportinfo
 * has logging enabled.
 * Note that nfslog_share_public_record() only needs to check for the
 * existence of at least one logbuffer to which the public filehandle record
 * needs to be logged.
 */
void
nfslog_write_record(struct exportinfo *exi, struct svc_req *req,
    caddr_t args, caddr_t res, cred_t *cr, struct netbuf *pnb,
    unsigned int record_id, unsigned int which_buffers)
{
	struct nfslog_prog_disp	*progtable;	/* prog struct */
	struct nfslog_vers_disp	*verstable;	/* version struct */
	struct nfslog_proc_disp	*disp = NULL;	/* proc struct */
	int			i, vers;
	void			*log_cookie;	/* for logrecord if */
	caddr_t			buffer;
	XDR			xdrs;
	unsigned int		final_size;
	int			encode_ok;
	int			alloc_indx;

	ASSERT(exi != NULL); ASSERT(req != NULL); ASSERT(args != NULL);
	ASSERT(res != NULL); ASSERT(cr != NULL);

	/*
	 * Find program element
	 * Search the list since program can not be used as index
	 */
	for (i = 0; (i < nfslog_dispatch_table_arglen); i++) {
		if (req->rq_prog == nfslog_dispatch_table[i].nfslog_dis_prog)
			break;
	}
	if (i >= nfslog_dispatch_table_arglen) {	/* program not logged */
		/* not an error */
		return;
	}

	/*
	 * Extract the dispatch functions based on program/version
	 */
	progtable = &nfslog_dispatch_table[i];
	vers = req->rq_vers - progtable->nfslog_dis_versmin;
	verstable = &progtable->nfslog_dis_vers_table[vers];
	disp = &verstable->nfslog_dis_proc_table[req->rq_proc];

	if (!(exi->exi_export.ex_flags & EX_LOG_ALLOPS) &&
	    !disp->affects_transactions) {
		/*
		 * Only interested in logging operations affecting
		 * transaction generation. This is not one of them.
		 */
#ifdef DEBUG
		rfslog_records_ignored++;
#endif
		return;
	}

	switch (req->rq_prog) {
	case NFS_PROGRAM:
		switch (req->rq_vers) {
		case NFS_V3:
			switch (req->rq_proc) {
			case NFSPROC3_READDIRPLUS:
				alloc_indx = MEDIUM_INDX;
				break;
			default:
				alloc_indx = SMALL_INDX;
				break;
			}
			break;
		default:
			alloc_indx = SMALL_INDX;
			break;
		}
		break;
	case NFSLOG_PROGRAM:
		alloc_indx = MEDIUM_INDX;
		break;
	default:
		alloc_indx = SMALL_INDX;
		break;
	}

	do {
		encode_ok = FALSE;

		/* Pick the size to alloc; end of the road - return */
		if (nfslog_mem_alloc[alloc_indx].size == (-1)) {
			cmn_err(CE_WARN,
			    "NFSLOG: unable to encode record - prog=%d "
			    "proc = %d", req->rq_prog, req->rq_proc);
			return;
		}

		buffer = nfslog_record_alloc(exi, alloc_indx, &log_cookie, 0);
		if (buffer == NULL) {
			/* Error processing - no space alloced */
			rfs_log_bad++;
			cmn_err(CE_WARN, "NFSLOG: can't get record");
			return;
		}

		xdrmem_create(&xdrs, buffer,
		    nfslog_mem_alloc[alloc_indx].size, XDR_ENCODE);

		/*
		 * Encode the header, args and results of the record
		 */
		if (xdr_nfslog_request_record(&xdrs, exi, req, cr, pnb,
		    nfslog_mem_alloc[alloc_indx].size, record_id) &&
		    (*disp->xdrargs)(&xdrs, args) &&
		    (*disp->xdrres)(&xdrs, res)) {
				encode_ok = TRUE;

				rfs_log_good++;
				/*
				 * Get the final size of the encoded
				 * data and insert that length at the
				 * beginning.
				 */
				final_size = xdr_getpos(&xdrs);
				xdr_setpos(&xdrs, 0);
				(void) xdr_u_int(&xdrs, &final_size);
		} else {
			/* Oops, the encode failed so we need to free memory */
			nfslog_record_put(log_cookie, 0, FALSE, which_buffers);
			alloc_indx++;
		}

	} while (encode_ok == FALSE);


	/*
	 * Take the final log record and put it in the log file.
	 * This may be queued to the file internally and written
	 * later unless the last parameter is TRUE.
	 * If the record_id is 0 then this is most likely a share/unshare
	 * request and it should be written synchronously to the log file.
	 */
	nfslog_record_put(log_cookie,
	    final_size, (record_id == 0), which_buffers);
}

static char *
get_publicfh_path(int *alloc_length)
{
	char *pubpath;
	nfs_export_t *ne = nfs_get_export();

	rw_enter(&ne->exported_lock, RW_READER);

	*alloc_length = ne->exi_public->exi_export.ex_pathlen + 1;
	pubpath = kmem_alloc(*alloc_length, KM_SLEEP);

	(void) strcpy(pubpath, ne->exi_public->exi_export.ex_path);

	rw_exit(&ne->exported_lock);

	return (pubpath);
}

static void
log_public_record(struct exportinfo *exi, cred_t *cr)
{
	struct svc_req	req;
	struct netbuf	nb = {0, 0, NULL};
	int free_length = 0;
	diropargs3 args;
	LOOKUP3res res;

	bzero(&req, sizeof (req));
	req.rq_prog = NFSLOG_PROGRAM;
	req.rq_vers = NFSLOG_VERSION;
	req.rq_proc = NFSLOG_LOOKUP;
	req.rq_cred.oa_flavor = AUTH_NONE;

	bzero(&args, sizeof (diropargs3));
	bzero(&res, sizeof (LOOKUP3res));

	args.dir.fh3_length = 0;
	if ((args.name = get_publicfh_path(&free_length)) == NULL)
		return;
	args.dirp = &args.dir;

	res.status = NFS3_OK;
	res.res_u.ok.object.fh3_length = 0;

	/*
	 * Calling this function with the exi_public
	 * will have the effect of appending the record
	 * to each of the open log buffers
	 */
	nfslog_write_record(exi, &req,
	    (caddr_t)&args, (caddr_t)&res, cr, &nb, 0, NFSLOG_ALL_BUFFERS);

	kmem_free(args.name, free_length);
}

/*
 * nfslog_share_record - logs a share request.
 * This is not an NFS request, but we pretend here...
 */
void
nfslog_share_record(struct exportinfo *exi, cred_t *cr)
{
	struct svc_req	req;
	int		res = 0;
	struct netbuf	nb = {0, 0, NULL};

	ASSERT(exi != NULL);

	if (nfslog_buffer_list == NULL)
		return;

	if (exi->exi_export.ex_flags & EX_LOG) {
		bzero(&req, sizeof (req));
		req.rq_prog = NFSLOG_PROGRAM;
		req.rq_vers = NFSLOG_VERSION;
		req.rq_proc = NFSLOG_SHARE;
		req.rq_cred.oa_flavor = AUTH_NONE;
		nfslog_write_record(exi, &req, (caddr_t)exi, (caddr_t)&res, cr,
		    &nb, 0, NFSLOG_ONE_BUFFER);
	}

	log_public_record(exi, cr);
}

/*
 * nfslog_unshare_record - logs an unshare request.
 * This is not an NFS request, but we pretend here...
 */
void
nfslog_unshare_record(struct exportinfo *exi, cred_t *cr)
{
	struct svc_req	req;
	int		res = 0;
	struct netbuf	nb = {0, 0, NULL};

	ASSERT(exi != NULL);
	ASSERT(exi->exi_export.ex_flags & EX_LOG);

	bzero(&req, sizeof (req));
	req.rq_prog = NFSLOG_PROGRAM;
	req.rq_vers = NFSLOG_VERSION;
	req.rq_proc = NFSLOG_UNSHARE;
	req.rq_cred.oa_flavor = AUTH_NONE;
	nfslog_write_record(exi, &req,
	    (caddr_t)exi, (caddr_t)&res, cr, &nb, 0, NFSLOG_ONE_BUFFER);
}


void
nfslog_getfh(struct exportinfo *exi, fhandle *fh, char *fname, enum uio_seg seg,
    cred_t *cr)
{
	struct svc_req	req;
	int		res = 0;
	struct netbuf	nb = {0, 0, NULL};
	int		error = 0;
	char		*namebuf;
	size_t		len;
	nfslog_getfhargs gfh;

	ASSERT(exi != NULL);
	ASSERT(exi->exi_export.ex_flags & EX_LOG);

	bzero(&req, sizeof (req));
	req.rq_prog = NFSLOG_PROGRAM;
	req.rq_vers = NFSLOG_VERSION;
	req.rq_proc = NFSLOG_GETFH;
	req.rq_cred.oa_flavor = AUTH_NONE;

	namebuf = kmem_alloc(MAXPATHLEN + 4, KM_SLEEP);
	if (seg == UIO_USERSPACE) {
		error = copyinstr(fname, namebuf, MAXPATHLEN, &len);
	} else {
		error = copystr(fname, namebuf, MAXPATHLEN, &len);
	}

	if (!error) {
		gfh.gfh_fh_buf = *fh;
		gfh.gfh_path = namebuf;

		nfslog_write_record(exi, &req, (caddr_t)&gfh, (caddr_t)&res,
		    cr, &nb, 0, NFSLOG_ONE_BUFFER);
	}
	kmem_free(namebuf, MAXPATHLEN + 4);
}

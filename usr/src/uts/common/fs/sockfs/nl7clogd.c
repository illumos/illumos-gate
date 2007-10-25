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

#include <sys/sysmacros.h>
#include <sys/callb.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/pathname.h>
#include <sys/cpuvar.h>
#include <sys/promif.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>

extern boolean_t	nl7c_logd_enabled;
extern boolean_t	nl7c_logd_started;
extern boolean_t	nl7c_logd_cycle;

extern void		nl7clogd_startup(void);

extern boolean_t	nl7c_http_log(uri_desc_t *, uri_desc_t *,
			    nca_request_log_t *, char **, char **, uint32_t *);

static void		logit_flush(void *);

/*
 * NL7C reuses the NCA logging scheme, the directory "/var/nca" contains
 * the symlink "current" to 1 of up to 16 NCA BLF logging files, by default
 * a single logging file "log", optionally paths of up to 16 log files can
 * be specified via ncalogd.conf(4), note that these log files need not be
 * in the "/var/nca" directory.
 *
 * NL7C reuses the NCA logging APIs defined in <inet/nca/ncalogd.h>, at
 * some future date (when NCA is deprecated or improvements are needed)
 * these need to be moved into NL7C.
 *
 * NL7C implements logging differently in 2 ways, 1st the initialization
 * is handled completely in the kernel by NL7C when it's enabled vs NCA
 * when the kmod was loaded, 2nd a simple worker thread with a FIFO queue
 * is used to process log_buf_t's instead of a squeue_t (this is done as
 * squeue_t's are private to NCA and IP at some future date we may us an
 * IP squeue_t):
 *
 *	logd_t - used by various functions to manage a singly linked
 * 	grounded list of log_buf_t's and it's worker thread.
 */

typedef struct logd_s {
	log_buf_t	*head;
	log_buf_t	*tail;
	kthread_t	*worker;
	kcondvar_t	wait;
	kmutex_t	lock;
} logd_t;

/*
 * In-kernel logging:
 *
 *	nl7c_logbuf_max - tunable for the number of preallocated next
 *	log_buf_t(s) for use by log_buf_alloc(), note if the value is
 *	0 (the default) then max_cpus worth will be allocated.
 *
 *	logd - global logd_t used to post log_buf_t's too.
 *
 *	log - global current log_buf_t that logit() logs too.
 *
 *	logv[] - vector of available next logbuf(s) such that when
 *	logbuf is filled another can be used while being processed by
 *	the logger() and kmem_cache_alloc() of a replacement is done.
 *
 *	logvcnt - count of logv[] vector element(s) and the index
 *	plus 1 of the next logbuf.
 *
 *	log_buf_kmc - the kmem_cache to alloc/free log_buf_t's from/to.
 *
 *	fio - the global nca_fio_t used to manage file i/o to a logfile.
 *
 *	dir - path to the directory where the current logfile symlink
 *	is created and the default directory for logfile(s).
 *
 *	symlink - name of the logfile symlink.
 *
 *	symlink_path - path to the logfile symlink.
 *
 *	log_lock - the kmutex_t used to guarantee atomic access of
 * 	all of the above.
 *
 *	flush_tid - logit_flush() timeout id.
 *
 *	LOGBUFV_ALLOC() - macro used to add log_buf_t(s) to logv[].
 */

int			nl7c_logbuf_max = 0;
static logd_t		logd;
static log_buf_t	*log = NULL;
static log_buf_t	**logv = NULL;
static int		logvcnt = 0;
static kmem_cache_t	*log_buf_kmc;
static nca_fio_t	fio;
static caddr_t		dir = "/var/nca/";
static caddr_t		symlink = "current";
static caddr_t		symlink_dir = "/var/nca";
static caddr_t		symlink_path = "/var/nca/current";

static kmutex_t		log_lock;

static timeout_id_t	flush_tid;

#define	LOGBUFV_ALLOC(kmflag) {						\
	log_buf_t	*_p;						\
									\
	ASSERT(mutex_owned(&log_lock));					\
	while (logvcnt < nl7c_logbuf_max) {				\
		/*CONSTCOND*/						\
		if (kmflag == KM_SLEEP)					\
			mutex_exit(&log_lock);				\
		_p = kmem_cache_alloc(log_buf_kmc, kmflag);		\
		/*CONSTCOND*/						\
		if (kmflag == KM_SLEEP) {				\
			mutex_enter(&log_lock);				\
			if (logvcnt == nl7c_logbuf_max) {		\
				mutex_exit(&log_lock);			\
				kmem_cache_free(log_buf_kmc, _p);	\
				mutex_enter(&log_lock);			\
				break;					\
			}						\
		} else {						\
			if (_p == NULL) {				\
				break;					\
			}						\
		}							\
		logv[logvcnt++] = _p;					\
	}								\
}

/*
 * Exports for inet/nca/ncaddi.c:
 */

nca_fio_t		*nl7c_logd_fio = &fio;

static void
log_buf_alloc(int kmflag)
{
	nca_log_buf_hdr_t	*hdr;
	static	ulong_t		seq = 0;

	ASSERT(mutex_owned(&log_lock));

	if (logvcnt == 0) {
		/*
		 * No logv[] to use for the new log global logbuf,
		 * try to allocate one or more before giving up.
		 */
		LOGBUFV_ALLOC(kmflag);
		if (logvcnt == 0) {
			/* No joy, just give up. */
			log = NULL;
			return;
		}
	}
	log = logv[--logvcnt];

	log->size = NCA_DEFAULT_LOG_BUF_SIZE;
	log->cur_pos = sizeof (*hdr);

	hdr = (nca_log_buf_hdr_t *)&log->buffer;
	hdr->nca_loghdr.nca_version = NCA_LOG_VERSION1;
	hdr->nca_loghdr.nca_op = log_op;
	hdr->nca_logstats.n_log_size = NCA_DEFAULT_LOG_BUF_SIZE - sizeof (*hdr);
	hdr->nca_logstats.n_log_recs = 0;
	hdr->nca_logstats.n_log_upcall = seq++;

	/* Try to allocate for at least the one we just used */
	LOGBUFV_ALLOC(kmflag);
}

static void
logd_off()
{
	;
}

static void
logd_log_write(kmutex_t *lock, log_buf_t *lbp)
{
	nca_log_buf_hdr_t *hdr = (nca_log_buf_hdr_t *)lbp->buffer;
	nca_log_stat_t	*sts = &hdr->nca_logstats;
	int		size = sts->n_log_size + sizeof (*hdr);
	vnode_t		*vp;
	uio_t		uio;
	iovec_t		iov;
	int		ret;
	boolean_t	noretry = B_FALSE;
	vattr_t		attr;

	if (size & (DEV_BSIZE - 1)) {
		/*
		 * Not appropriately sized for directio(),
		 * add some filler so it is.
		 */
		sts->n_log_size += DEV_BSIZE - (size & (DEV_BSIZE - 1));
		size = sts->n_log_size + sizeof (*hdr);
	}
retry:
	if (nca_fio_offset(&fio) + size <= nca_fio_size(&fio)) {
		/*
		 * Room in the current log file so write the logbuf out,
		 * exit the logd lock while doing the i/o as to not block
		 * queuing.
		 */
		mutex_exit(lock);

		vp = nca_fio_vp(&fio);
		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
		iov.iov_base = lbp->buffer;
		iov.iov_len = size;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_fmode = 0;
		uio.uio_loffset = (u_offset_t)nca_fio_offset(&fio);
		uio.uio_llimit = curproc->p_fsz_ctl;
		uio.uio_resid = size;
		ret = VOP_WRITE(vp, &uio, 0, kcred, NULL);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		if (ret != 0) {
			if (ret == EFBIG) {
				/*
				 * Out of space for this file,
				 * retry with the next.
				 */
				nca_fio_size(&fio) = nca_fio_offset(&fio);
				if (noretry) {
					nl7c_logd_enabled = B_FALSE;
					goto done;
				} else
					goto next;
			}
		}
		nca_fio_offset(&fio) = uio.uio_loffset;

		mutex_enter(lock);
		goto done;
	}

	/*
	 * Current logfile doesn't have sufficient space
	 * so move on to next file (if any).
	 */
next:
	mutex_exit(lock);
	/* Close current file */
	ret = VOP_CLOSE(nca_fio_vp(&fio), FCREAT|FWRITE|FAPPEND|FTRUNC,
			1, (offset_t)0, kcred, NULL);
	nca_fio_vp(&fio) = NULL;
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd: close of %s failed (error %d)",
		    nca_fio_name(&fio), ret);
		nl7c_logd_enabled = B_FALSE;
		logd_off();
		return;
	}

	/* Go to next file */
	nca_fio_ix(&fio)++;
	if (nca_fio_ix(&fio) == nca_fio_cnt(&fio)) {
		/*
		 * We have reached the last file. If cycling
		 * is not on, disable logging and bailout.
		 */
		if (nl7c_logd_cycle) {
			/* Start from the first file */
			nca_fio_ix(&fio) = 0;
		} else {
			nca_fio_ix(&fio)--;
			nl7c_logd_enabled = B_FALSE;
			logd_off();
			return;
		}
	}

	/* Open the next log file */
	ret = vn_open(nca_fio_name(&fio), UIO_SYSSPACE, FCREAT|FWRITE|FTRUNC,
			0600, &nca_fio_vp(&fio), 0, 0);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd: vn_open of %s failed (error %d)",
			nca_fio_name(&fio), ret);
		nl7c_logd_enabled = B_FALSE;
		logd_off();
		return;
	}

	/* Turn on directio */
	(void) VOP_IOCTL(nca_fio_vp(&fio), _FIODIRECTIO,
			DIRECTIO_ON, 0, kcred, NULL, NULL);

	/* Start writing from the begining of the file */
	nca_fio_offset(&fio) = 0;

	/* Remove the current symlink */
	(void) VOP_REMOVE(nca_fio_dvp(&fio), symlink, kcred, NULL, 0);

	attr.va_mask = AT_MODE | AT_TYPE;
	attr.va_mode = 0777;
	attr.va_type = VLNK;

	/* Create symlink to the new log file */
	ret = VOP_SYMLINK(nca_fio_dvp(&fio), symlink,
			&attr, nca_fio_name(&fio), kcred, NULL, 0);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd: symlink of %s to %s failed",
			symlink, nca_fio_name(&fio));
		nl7c_logd_enabled = B_FALSE;
		logd_off();
		return;
	}
	mutex_enter(lock);
	goto retry;

done:
	if (logvcnt < nl7c_logbuf_max) {
		/* May need to allocate some logbuf(s) for logv[] */
		mutex_enter(&log_lock);
		if (logvcnt < nl7c_logbuf_max) {
			/*
			 * After acquiring the lock still need logbuf(s),
			 * if the global logbuf pointer is NULL then call
			 * log_buf_alloc() as it will fill up logbugv[]
			 * and initialize a new logbuf else fill up just
			 * the logv[] here.
			 */
			if (log == NULL) {
				log_buf_alloc(KM_SLEEP);
			} else {
				/*LINTED*/
				LOGBUFV_ALLOC(KM_SLEEP);
			}
		}
		mutex_exit(&log_lock);
	}
}

static void
logd_worker(logd_t *logdp)
{
	log_buf_t	*lbp;
	kmutex_t	*lock = &logdp->lock;
	kcondvar_t	*wait = &logdp->wait;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "nl7c");
	mutex_enter(lock);

	for (;;) {
		/* Wait for something to do */
		while ((lbp = logdp->head) == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(wait, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}
		if ((logdp->head = lbp->next) == NULL)
			logdp->tail = NULL;
		/* Got a logbuf to write out */
		if (nl7c_logd_enabled)
			logd_log_write(lock, lbp);
		kmem_cache_free(log_buf_kmc, lbp);
	}
}

boolean_t
nl7c_logd_init(int fsz, caddr_t *fnv)
{
	vnode_t	*dvp;
	vnode_t	*svp;
	vnode_t	*vp;
	int	ret;
	caddr_t	*fnp;
	vattr_t	attr;
	uio_t	uio;
	iovec_t	iov;
	char	fbuf[TYPICALMAXPATHLEN + 1];

	/*
	 * Initialize the global logfio.
	 */
	nca_fio_cnt(&fio) = 0;
	nca_fio_ix(&fio) = 0;
	fnp = fnv;
	while (*fnp != NULL) {
		nca_fio_cnt(&fio)++;
		nca_fio_name(&fio) = *fnp;
		nca_fio_size(&fio) = fsz;
		nca_fio_offset(&fio) = 0;
		nca_fio_file(&fio) = nca_fio_ix(&fio);
		nca_fio_vp(&fio) = NULL;

		if (++fnp == &fnv[NCA_FIOV_SZ])
			break;

		nca_fio_ix(&fio)++;
	}
	/*
	 * See if we can start logging from where we left off last time,
	 * first check if the symlink exists.
	 */
	dvp = NULL;
	ret = lookupname(symlink_path, UIO_SYSSPACE, NO_FOLLOW, &dvp, &svp);
	if (ret || dvp == NULL || svp == NULL) {
		if (dvp == NULL) {
			/* No NCA symlink directory, create one */
			attr.va_mask = AT_MODE | AT_TYPE;
			attr.va_mode = 0755;
			attr.va_type = VDIR;
			ret = vn_create(symlink_dir, UIO_SYSSPACE, &attr,
			    EXCL, 0, &dvp, CRMKDIR, 0, 0);
			if (ret) {
				cmn_err(CE_WARN, "nl7c_logd_init: create"
				    " symlink dir of %s failed(%d).",
				    symlink_dir, ret);
				goto error;
			}
		}
		nca_fio_dvp(&fio) = dvp;
		/* No symlink so don't know were to start from */
		goto fresh_start;
	}
	/* Save the symlink dir vnode */
	nca_fio_dvp(&fio) = dvp;

	/* Check if the file pointed by the symlink exists */
	ret = lookupname(symlink_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (ret || vp == NULL)
		goto fresh_start;
	VN_RELE(vp);

	/* Read the symlink and find it in fnv[], else fresh start */
	iov.iov_len = TYPICALMAXPATHLEN;
	iov.iov_base = fbuf;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = iov.iov_len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = 0;
	uio.uio_fmode = 0;
	ret = VOP_READLINK(svp, &uio, kcred, NULL);
	if (ret) {
		(void) VOP_REMOVE(dvp, symlink, kcred, NULL, 0);
		goto fresh_start;
	}

	/* Null terminate the buf */
	fbuf[TYPICALMAXPATHLEN - (int)uio.uio_resid] = '\0';
	fnp = fnv;
	nca_fio_ix(&fio) = 0;
	while (*fnp != NULL) {
		if (strcmp(*fnp, fbuf) == 0)
			break;
		if (++fnp == &fnv[NCA_FIOV_SZ])
			goto fresh_start;
		nca_fio_ix(&fio)++;
	}
	if (*fnp == NULL)
		goto fresh_start;

	/* Start writing to the end of the file */
	ret = vn_open(*fnp, UIO_SYSSPACE,
	    FCREAT|FWRITE|FAPPEND, 0600, &vp, 0, 0);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd_init: vn_open of "
		    "%s failed (error %d)", *fnp, ret);
		goto error;
	}
	nca_fio_vp(&fio) = vp;
	(void) VOP_IOCTL(vp, _FIODIRECTIO, DIRECTIO_ON, 0, kcred, NULL, NULL);
	attr.va_mask = AT_SIZE;
	ret = VOP_GETATTR(nca_fio_vp(&fio), &attr, 0, NULL, NULL);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd_init: getattr of %s failed", *fnp);
		goto error;
	}
	nca_fio_offset(&fio) = (off64_t)attr.va_size;

	goto finish;

fresh_start:
	/*
	 * Here if no previous logging environment found or if the previous
	 * logging environment isn't usable or isn't consistent with the new
	 * fnv[]. Remove the existing symlink (if any) then create the new
	 * symlink to point to the first logfile.
	 */
	nca_fio_ix(&fio) = 0;
	attr.va_mask = AT_MODE | AT_TYPE;
	attr.va_mode = 0777;
	attr.va_type = VLNK;
	(void) VOP_REMOVE(dvp, symlink, kcred, NULL, 0);
	ret = VOP_SYMLINK(dvp, symlink, &attr, nca_fio_name(&fio), kcred, NULL,
	    0);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd_init: symlink of %s to %s failed",
		    symlink_path, nca_fio_name(&fio));
		goto error;
	}
	ret = vn_open(nca_fio_name(&fio), UIO_SYSSPACE,
	    FCREAT|FWRITE|FTRUNC, 0600, &nca_fio_vp(&fio), 0, 0);
	if (ret) {
		cmn_err(CE_WARN, "nl7c_logd_init: vn_open of "
		    "%s failed (error %d)", nca_fio_name(&fio), ret);
		goto error;
	}

	/* Turn on directio */
	(void) VOP_IOCTL(nca_fio_vp(&fio), _FIODIRECTIO,
			DIRECTIO_ON, 0, kcred, NULL, NULL);

finish:
	log_buf_kmc = kmem_cache_create("NL7C_log_buf_kmc", sizeof (log_buf_t),
		0, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&log_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&log_lock);

	if (nl7c_logbuf_max == 0)
		nl7c_logbuf_max = max_ncpus;
	logv = kmem_alloc(nl7c_logbuf_max * sizeof (*logv), KM_SLEEP);
	for (logvcnt = 0; logvcnt < nl7c_logbuf_max; logvcnt++) {
		logv[logvcnt] = kmem_cache_alloc(log_buf_kmc, KM_SLEEP);
	}

	log_buf_alloc(KM_SLEEP);

	mutex_init(&logd.lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&logd.wait, NULL, CV_DEFAULT, NULL);
	logd.head = NULL;
	logd.tail = NULL;
	logd.worker = thread_create(NULL, 0, logd_worker, &logd,
	    0, &p0, TS_RUN, maxclsyspri);

	mutex_exit(&log_lock);

	/* Last, start logger timeout flush */
	logit_flush(NULL);

	return (B_TRUE);

	/*
	 * Error of some sort, free any resources in reverse order.
	 */
error:
	nca_fio_ix(&fio) = 0;
	while (nca_fio_ix(&fio) < nca_fio_cnt(&fio)) {
		char *name = nca_fio_name(&fio);

		if ((vp = nca_fio_vp(&fio)) != NULL)
			VN_RELE(vp);
		kmem_free(name, (strlen(name) + 1));
		nca_fio_ix(&fio)++;
	}
	nca_fio_cnt(&fio) = 0;

	if (svp)
		VN_RELE(svp);

	if (dvp)
		VN_RELE(dvp);

	return (B_FALSE);
}

/*ARGSUSED*/
static void
logit_flush(void *arg)
{
	static log_buf_t *lastlbp = NULL;
	static int	lastpos;
	log_buf_t	*lbp = log;

	flush_tid = 0;

	mutex_enter(&log_lock);
	if (log == NULL) {
		/* No global logbuf ? Nothing to flush. */
		goto out;
	}
	if (lbp != NULL && lbp->cur_pos > (sizeof (nca_log_buf_hdr_t)) &&
		lastlbp == lbp && lastpos == lbp->cur_pos) {
		/*
		 * We have a logbuf and it has log data and it's the
		 * same logbuf and pos as last time and after lock
		 * still true, so flush.
		 */
		nca_log_stat_t	*sp;

		sp = &(((nca_log_buf_hdr_t *)lbp)->nca_logstats);
		sp->n_log_size = lbp->cur_pos;

		/* Link new logbuf onto end of logd and wake logd up */
		mutex_enter(&logd.lock);
		log->next = NULL;
		if (logd.tail == NULL)
			logd.head = log;
		else
			logd.tail->next = log;
		logd.tail = log;
		cv_signal(&logd.wait);

		mutex_exit(&logd.lock);

		log_buf_alloc(KM_NOSLEEP);
	}

	if ((lastlbp = lbp) != NULL)
		lastpos = lbp->cur_pos;

	mutex_exit(&log_lock);
out:
	/* Check again in 1 second */
	flush_tid = timeout(&logit_flush, NULL, hz);
}

void
nl7c_logd_log(uri_desc_t *quri, uri_desc_t *suri, time_t rtime, ipaddr_t faddr)
{
	nca_request_log_t *req;
	char		*wp;
	char		*pep;
	int		sz;
	uint32_t	off = 0;
	int		kmflag = servicing_interrupt() ? KM_NOSLEEP : KM_SLEEP;

	if (! nl7c_logd_enabled)
		return;

	if (! nl7c_logd_started) {
		/* Startup logging */
		nl7clogd_startup();
	}
	mutex_enter(&log_lock);
again:
	if (log == NULL) {
		/* No global logbuf, try to allocate one before giving up. */
		log_buf_alloc(kmflag);
		if (log == NULL) {
			/* No joy, just give up. */
			mutex_exit(&log_lock);
			return;
		}
	}
	/*
	 * Get a pointer to an aligned write position, a pointer to past
	 * the end of the logbuf, and a pointer to the request header.
	 *
	 * As the request header is filled in field by field addtional
	 * storage is allcated following the request header.
	 *
	 * If at any point an allocation from the logbuf overflows (i.e.
	 * resulting in a pointer > pep) the current request logging is
	 * aborted, the current logbuf is posted for write, a new logbuf
	 * is allocated, and start all over.
	 */
	pep = &((char *)log)[log->size];
	wp = (log->buffer + log->cur_pos);
	wp = NCA_LOG_ALIGN(wp);
	req = (nca_request_log_t *)wp;
	if ((wp + sizeof (*req)) >= pep) goto full;
	bzero(wp, sizeof (*req));
	wp += sizeof (*req);

	sz = MIN((quri->path.ep - quri->path.cp), MAX_URL_LEN);
	if ((wp + sz + 1) >= pep) goto full;
	bcopy(quri->path.cp, wp, sz);
	wp += sz;
	*wp++ = 0;
	sz++;
	req->request_url_len = sz;
	req->request_url = off;
	off += sz;

	/*
	 * Set response length now as the scheme log function will
	 * subtract out any header length as we want the entity body
	 * length returned for the response_len.
	 */
	req->response_len = (uint_t)suri->resplen;

	/* Call scheme log */
	if (nl7c_http_log(quri, suri, req, &wp, &pep, &off)) goto full;

	/* Update logbuf */
	log->cur_pos = (wp - log->buffer);

	req->response_status = HS_OK;

	req->start_process_time = (time32_t)rtime;
	req->end_process_time = (time32_t)gethrestime_sec();

	req->remote_host = faddr;

	((nca_log_buf_hdr_t *)log)->nca_logstats.n_log_recs++;
	mutex_exit(&log_lock);
	return;

full:
	/*
	 * The logbuf is full, zero fill from current
	 * write pointer through the end of the buf.
	 */
	wp = (log->buffer + log->cur_pos);
	sz = pep - wp;
	bzero(wp, sz);
	/*
	 * Link new logbuf onto end of logd and wake logd up.
	 */
	mutex_enter(&logd.lock);
	log->next = NULL;
	if (logd.tail == NULL)
		logd.head = log;
	else
		logd.tail->next = log;
	logd.tail = log;
	cv_signal(&logd.wait);
	mutex_exit(&logd.lock);
	/*
	 * Try to allocate a new global logbuf.
	 */
	log_buf_alloc(kmflag);

	goto again;
}

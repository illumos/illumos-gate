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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Kernel asynchronous I/O.
 * This is only for raw devices now (as of Nov. 1993).
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/fs/snode.h>
#include <sys/unistd.h>
#include <sys/cmn_err.h>
#include <vm/as.h>
#include <vm/faultcode.h>
#include <sys/sysmacros.h>
#include <sys/procfs.h>
#include <sys/kmem.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/aio_impl.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/fs/pxfs_ki.h>
#include <sys/contract/process_impl.h>

/*
 * external entry point.
 */
#ifdef _LP64
static int64_t kaioc(long, long, long, long, long, long);
#endif
static int kaio(ulong_t *, rval_t *);


#define	AIO_64	0
#define	AIO_32	1
#define	AIO_LARGEFILE	2

/*
 * implementation specific functions (private)
 */
#ifdef _LP64
static int alio(int, aiocb_t **, int, struct sigevent *);
#endif
static int aionotify(void);
static int aioinit(void);
static int aiostart(void);
static void alio_cleanup(aio_t *, aiocb_t **, int, int);
static int (*check_vp(struct vnode *, int))(vnode_t *, struct aio_req *,
    cred_t *);
static void lio_set_error(aio_req_t *, int portused);
static aio_t *aio_aiop_alloc();
static int aio_req_alloc(aio_req_t **, aio_result_t *);
static int aio_lio_alloc(aio_lio_t **);
static aio_req_t *aio_req_done(void *);
static aio_req_t *aio_req_remove(aio_req_t *);
static int aio_req_find(aio_result_t *, aio_req_t **);
static int aio_hash_insert(struct aio_req_t *, aio_t *);
static int aio_req_setup(aio_req_t **, aio_t *, aiocb_t *,
    aio_result_t *, vnode_t *, int);
static int aio_cleanup_thread(aio_t *);
static aio_lio_t *aio_list_get(aio_result_t *);
static void lio_set_uerror(void *, int);
extern void aio_zerolen(aio_req_t *);
static int aiowait(struct timeval *, int, long	*);
static int aiowaitn(void *, uint_t, uint_t *, timespec_t *);
static int aio_unlock_requests(caddr_t iocblist, int iocb_index,
    aio_req_t *reqlist, aio_t *aiop, model_t model);
static int aio_reqlist_concat(aio_t *aiop, aio_req_t **reqlist, int max);
static int aiosuspend(void *, int, struct  timespec *, int,
    long	*, int);
static int aliowait(int, void *, int, void *, int);
static int aioerror(void *, int);
static int aio_cancel(int, void *, long	*, int);
static int arw(int, int, char *, int, offset_t, aio_result_t *, int);
static int aiorw(int, void *, int, int);

static int alioLF(int, void *, int, void *);
static int aio_req_setupLF(aio_req_t **, aio_t *, aiocb64_32_t *,
    aio_result_t *, vnode_t *, int);
static int alio32(int, void *, int, void *);
static int driver_aio_write(vnode_t *vp, struct aio_req *aio, cred_t *cred_p);
static int driver_aio_read(vnode_t *vp, struct aio_req *aio, cred_t *cred_p);

#ifdef  _SYSCALL32_IMPL
static void aiocb_LFton(aiocb64_32_t *, aiocb_t *);
void	aiocb_32ton(aiocb32_t *, aiocb_t *);
#endif /* _SYSCALL32_IMPL */

/*
 * implementation specific functions (external)
 */
void aio_req_free(aio_t *, aio_req_t *);

/*
 * Event Port framework
 */

void aio_req_free_port(aio_t *, aio_req_t *);
static int aio_port_callback(void *, int *, pid_t, int, void *);

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>
#include <sys/syscall.h>

#ifdef _LP64

static struct sysent kaio_sysent = {
	6,
	SE_NOUNLOAD | SE_64RVAL | SE_ARGC,
	(int (*)())kaioc
};

#ifdef _SYSCALL32_IMPL
static struct sysent kaio_sysent32 = {
	7,
	SE_NOUNLOAD | SE_64RVAL,
	kaio
};
#endif  /* _SYSCALL32_IMPL */

#else   /* _LP64 */

static struct sysent kaio_sysent = {
	7,
	SE_NOUNLOAD | SE_32RVAL1,
	kaio
};

#endif  /* _LP64 */

/*
 * Module linkage information for the kernel.
 */

static struct modlsys modlsys = {
	&mod_syscallops,
	"kernel Async I/O",
	&kaio_sysent
};

#ifdef  _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"kernel Async I/O for 32 bit compatibility",
	&kaio_sysent32
};
#endif  /* _SYSCALL32_IMPL */


static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef  _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

int
_init(void)
{
	int retval;

	if ((retval = mod_install(&modlinkage)) != 0)
		return (retval);

	return (0);
}

int
_fini(void)
{
	int retval;

	retval = mod_remove(&modlinkage);

	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#ifdef	_LP64
static int64_t
kaioc(
	long	a0,
	long	a1,
	long	a2,
	long	a3,
	long	a4,
	long	a5)
{
	int	error;
	long	rval = 0;

	switch ((int)a0 & ~AIO_POLL_BIT) {
	case AIOREAD:
		error = arw((int)a0, (int)a1, (char *)a2, (int)a3,
		    (offset_t)a4, (aio_result_t *)a5, FREAD);
		break;
	case AIOWRITE:
		error = arw((int)a0, (int)a1, (char *)a2, (int)a3,
		    (offset_t)a4, (aio_result_t *)a5, FWRITE);
		break;
	case AIOWAIT:
		error = aiowait((struct timeval *)a1, (int)a2, &rval);
		break;
	case AIOWAITN:
		error = aiowaitn((void *)a1, (uint_t)a2, (uint_t *)a3,
		    (timespec_t *)a4);
		break;
	case AIONOTIFY:
		error = aionotify();
		break;
	case AIOINIT:
		error = aioinit();
		break;
	case AIOSTART:
		error = aiostart();
		break;
	case AIOLIO:
		error = alio((int)a1, (aiocb_t **)a2, (int)a3,
		    (struct sigevent *)a4);
		break;
	case AIOLIOWAIT:
		error = aliowait((int)a1, (void *)a2, (int)a3,
		    (struct sigevent *)a4, AIO_64);
		break;
	case AIOSUSPEND:
		error = aiosuspend((void *)a1, (int)a2, (timespec_t *)a3,
		    (int)a4, &rval, AIO_64);
		break;
	case AIOERROR:
		error = aioerror((void *)a1, AIO_64);
		break;
	case AIOAREAD:
		error = aiorw((int)a0, (void *)a1, FREAD, AIO_64);
		break;
	case AIOAWRITE:
		error = aiorw((int)a0, (void *)a1, FWRITE, AIO_64);
		break;
	case AIOCANCEL:
		error = aio_cancel((int)a1, (void *)a2, &rval, AIO_64);
		break;

	/*
	 * The large file related stuff is valid only for
	 * 32 bit kernel and not for 64 bit kernel
	 * On 64 bit kernel we convert large file calls
	 * to regular 64bit calls.
	 */

	default:
		error = EINVAL;
	}
	if (error)
		return ((int64_t)set_errno(error));
	return (rval);
}
#endif

static int
kaio(
	ulong_t *uap,
	rval_t *rvp)
{
	long rval = 0;
	int	error = 0;
	offset_t	off;


		rvp->r_vals = 0;
#if defined(_LITTLE_ENDIAN)
	off = ((u_offset_t)uap[5] << 32) | (u_offset_t)uap[4];
#else
	off = ((u_offset_t)uap[4] << 32) | (u_offset_t)uap[5];
#endif

	switch (uap[0] & ~AIO_POLL_BIT) {
	/*
	 * It must be the 32 bit system call on 64 bit kernel
	 */
	case AIOREAD:
		return (arw((int)uap[0], (int)uap[1], (char *)uap[2],
		    (int)uap[3], off, (aio_result_t *)uap[6], FREAD));
	case AIOWRITE:
		return (arw((int)uap[0], (int)uap[1], (char *)uap[2],
		    (int)uap[3], off, (aio_result_t *)uap[6], FWRITE));
	case AIOWAIT:
		error = aiowait((struct	timeval *)uap[1], (int)uap[2],
		    &rval);
		break;
	case AIOWAITN:
		error = aiowaitn((void *)uap[1], (uint_t)uap[2],
		    (uint_t *)uap[3], (timespec_t *)uap[4]);
		break;
	case AIONOTIFY:
		return (aionotify());
	case AIOINIT:
		return (aioinit());
	case AIOSTART:
		return (aiostart());
	case AIOLIO:
		return (alio32((int)uap[1], (void *)uap[2], (int)uap[3],
		    (void *)uap[4]));
	case AIOLIOWAIT:
		return (aliowait((int)uap[1], (void *)uap[2],
		    (int)uap[3], (struct sigevent *)uap[4], AIO_32));
	case AIOSUSPEND:
		error = aiosuspend((void *)uap[1], (int)uap[2],
		    (timespec_t *)uap[3], (int)uap[4],
		    &rval, AIO_32);
		break;
	case AIOERROR:
		return (aioerror((void *)uap[1], AIO_32));
	case AIOAREAD:
		return (aiorw((int)uap[0], (void *)uap[1],
		    FREAD, AIO_32));
	case AIOAWRITE:
		return (aiorw((int)uap[0], (void *)uap[1],
		    FWRITE, AIO_32));
	case AIOCANCEL:
		error = (aio_cancel((int)uap[1], (void *)uap[2], &rval,
		    AIO_32));
		break;
	case AIOLIO64:
		return (alioLF((int)uap[1], (void *)uap[2],
		    (int)uap[3], (void *)uap[4]));
	case AIOLIOWAIT64:
		return (aliowait(uap[1], (void *)uap[2],
		    (int)uap[3], (void *)uap[4], AIO_LARGEFILE));
	case AIOSUSPEND64:
		error = aiosuspend((void *)uap[1], (int)uap[2],
		    (timespec_t *)uap[3], (int)uap[4], &rval,
		    AIO_LARGEFILE);
		break;
	case AIOERROR64:
		return (aioerror((void *)uap[1], AIO_LARGEFILE));
	case AIOAREAD64:
		return (aiorw((int)uap[0], (void *)uap[1], FREAD,
		    AIO_LARGEFILE));
	case AIOAWRITE64:
		return (aiorw((int)uap[0], (void *)uap[1], FWRITE,
		    AIO_LARGEFILE));
	case AIOCANCEL64:
		error = (aio_cancel((int)uap[1], (void *)uap[2],
		    &rval, AIO_LARGEFILE));
		break;
	default:
		return (EINVAL);
	}

	rvp->r_val1 = rval;
	return (error);
}

/*
 * wake up LWPs in this process that are sleeping in
 * aiowait().
 */
static int
aionotify(void)
{
	aio_t	*aiop;

	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (0);

	mutex_enter(&aiop->aio_mutex);
	aiop->aio_notifycnt++;
	cv_broadcast(&aiop->aio_waitcv);
	mutex_exit(&aiop->aio_mutex);

	return (0);
}

static int
timeval2reltime(struct timeval *timout, timestruc_t *rqtime,
	timestruc_t **rqtp, int *blocking)
{
#ifdef	_SYSCALL32_IMPL
	struct timeval32 wait_time_32;
#endif
	struct timeval wait_time;
	model_t	model = get_udatamodel();

	*rqtp = NULL;
	if (timout == NULL) {		/* wait indefinitely */
		*blocking = 1;
		return (0);
	}

	/*
	 * Need to correctly compare with the -1 passed in for a user
	 * address pointer, with both 32 bit and 64 bit apps.
	 */
	if (model == DATAMODEL_NATIVE) {
		if ((intptr_t)timout == (intptr_t)-1) {	/* don't wait */
			*blocking = 0;
			return (0);
		}

		if (copyin(timout, &wait_time, sizeof (wait_time)))
			return (EFAULT);
	}
#ifdef	_SYSCALL32_IMPL
	else {
		/*
		 * -1 from a 32bit app. It will not get sign extended.
		 * don't wait if -1.
		 */
		if ((intptr_t)timout == (intptr_t)((uint32_t)-1)) {
			*blocking = 0;
			return (0);
		}

		if (copyin(timout, &wait_time_32, sizeof (wait_time_32)))
			return (EFAULT);
		TIMEVAL32_TO_TIMEVAL(&wait_time, &wait_time_32);
	}
#endif  /* _SYSCALL32_IMPL */

	if (wait_time.tv_sec == 0 && wait_time.tv_usec == 0) {	/* don't wait */
		*blocking = 0;
		return (0);
	}

	if (wait_time.tv_sec < 0 ||
	    wait_time.tv_usec < 0 || wait_time.tv_usec >= MICROSEC)
		return (EINVAL);

	rqtime->tv_sec = wait_time.tv_sec;
	rqtime->tv_nsec = wait_time.tv_usec * 1000;
	*rqtp = rqtime;
	*blocking = 1;

	return (0);
}

static int
timespec2reltime(timespec_t *timout, timestruc_t *rqtime,
	timestruc_t **rqtp, int *blocking)
{
#ifdef	_SYSCALL32_IMPL
	timespec32_t wait_time_32;
#endif
	model_t	model = get_udatamodel();

	*rqtp = NULL;
	if (timout == NULL) {
		*blocking = 1;
		return (0);
	}

	if (model == DATAMODEL_NATIVE) {
		if (copyin(timout, rqtime, sizeof (*rqtime)))
			return (EFAULT);
	}
#ifdef	_SYSCALL32_IMPL
	else {
		if (copyin(timout, &wait_time_32, sizeof (wait_time_32)))
			return (EFAULT);
		TIMESPEC32_TO_TIMESPEC(rqtime, &wait_time_32);
	}
#endif  /* _SYSCALL32_IMPL */

	if (rqtime->tv_sec == 0 && rqtime->tv_nsec == 0) {
		*blocking = 0;
		return (0);
	}

	if (rqtime->tv_sec < 0 ||
	    rqtime->tv_nsec < 0 || rqtime->tv_nsec >= NANOSEC)
		return (EINVAL);

	*rqtp = rqtime;
	*blocking = 1;

	return (0);
}

/*ARGSUSED*/
static int
aiowait(
	struct timeval	*timout,
	int	dontblockflg,
	long	*rval)
{
	int 		error;
	aio_t		*aiop;
	aio_req_t	*reqp;
	clock_t		status;
	int		blocking;
	int		timecheck;
	timestruc_t	rqtime;
	timestruc_t	*rqtp;

	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (EINVAL);

	/*
	 * Establish the absolute future time for the timeout.
	 */
	error = timeval2reltime(timout, &rqtime, &rqtp, &blocking);
	if (error)
		return (error);
	if (rqtp) {
		timestruc_t now;
		timecheck = timechanged;
		gethrestime(&now);
		timespecadd(rqtp, &now);
	}

	mutex_enter(&aiop->aio_mutex);
	for (;;) {
		/* process requests on poll queue */
		if (aiop->aio_pollq) {
			mutex_exit(&aiop->aio_mutex);
			aio_cleanup(0);
			mutex_enter(&aiop->aio_mutex);
		}
		if ((reqp = aio_req_remove(NULL)) != NULL) {
			*rval = (long)reqp->aio_req_resultp;
			break;
		}
		/* user-level done queue might not be empty */
		if (aiop->aio_notifycnt > 0) {
			aiop->aio_notifycnt--;
			*rval = 1;
			break;
		}
		/* don't block if no outstanding aio */
		if (aiop->aio_outstanding == 0 && dontblockflg) {
			error = EINVAL;
			break;
		}
		if (blocking) {
			status = cv_waituntil_sig(&aiop->aio_waitcv,
			    &aiop->aio_mutex, rqtp, timecheck);

			if (status > 0)		/* check done queue again */
				continue;
			if (status == 0) {	/* interrupted by a signal */
				error = EINTR;
				*rval = -1;
			} else {		/* timer expired */
				error = ETIME;
			}
		}
		break;
	}
	mutex_exit(&aiop->aio_mutex);
	if (reqp) {
		aphysio_unlock(reqp);
		aio_copyout_result(reqp);
		mutex_enter(&aiop->aio_mutex);
		aio_req_free(aiop, reqp);
		mutex_exit(&aiop->aio_mutex);
	}
	return (error);
}

/*
 * aiowaitn can be used to reap completed asynchronous requests submitted with
 * lio_listio, aio_read or aio_write.
 * This function only reaps asynchronous raw I/Os.
 */

/*ARGSUSED*/
static int
aiowaitn(void *uiocb, uint_t nent, uint_t *nwait, timespec_t *timout)
{
	int 		error = 0;
	aio_t		*aiop;
	aio_req_t	*reqlist = NULL;
	caddr_t		iocblist = NULL;	/* array of iocb ptr's */
	uint_t		waitcnt, cnt = 0;	/* iocb cnt */
	size_t		iocbsz;			/* users iocb size */
	size_t		riocbsz;		/* returned iocb size */
	int		iocb_index = 0;
	model_t		model = get_udatamodel();
	int		blocking = 1;
	int		timecheck;
	timestruc_t	rqtime;
	timestruc_t	*rqtp;

	aiop = curproc->p_aio;
	if (aiop == NULL || nent == 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

	if (aiop->aio_outstanding == 0)
		return (EAGAIN);

	if (copyin(nwait, &waitcnt, sizeof (uint_t)))
		return (EFAULT);

	/* set *nwait to zero, if we must return prematurely */
	if (copyout(&cnt, nwait, sizeof (uint_t)))
		return (EFAULT);

	if (waitcnt == 0) {
		blocking = 0;
		rqtp = NULL;
		waitcnt = nent;
	} else {
		error = timespec2reltime(timout, &rqtime, &rqtp, &blocking);
		if (error)
			return (error);
	}

	if (model == DATAMODEL_NATIVE)
		iocbsz = (sizeof (aiocb_t *) * nent);
#ifdef	_SYSCALL32_IMPL
	else
		iocbsz = (sizeof (caddr32_t) * nent);
#endif  /* _SYSCALL32_IMPL */

	/*
	 * Only one aio_waitn call is allowed at a time.
	 * The active aio_waitn will collect all requests
	 * out of the "done" list and if necessary it will wait
	 * for some/all pending requests to fulfill the nwait
	 * parameter.
	 * A second or further aio_waitn calls will sleep here
	 * until the active aio_waitn finishes and leaves the kernel
	 * If the second call does not block (poll), then return
	 * immediately with the error code : EAGAIN.
	 * If the second call should block, then sleep here, but
	 * do not touch the timeout. The timeout starts when this
	 * aio_waitn-call becomes active.
	 */

	mutex_enter(&aiop->aio_mutex);

	while (aiop->aio_flags & AIO_WAITN) {
		if (blocking == 0) {
			mutex_exit(&aiop->aio_mutex);
			return (EAGAIN);
		}

		/* block, no timeout */
		aiop->aio_flags |= AIO_WAITN_PENDING;
		if (!cv_wait_sig(&aiop->aio_waitncv, &aiop->aio_mutex)) {
			mutex_exit(&aiop->aio_mutex);
			return (EINTR);
		}
	}

	/*
	 * Establish the absolute future time for the timeout.
	 */
	if (rqtp) {
		timestruc_t now;
		timecheck = timechanged;
		gethrestime(&now);
		timespecadd(rqtp, &now);
	}

	if (iocbsz > aiop->aio_iocbsz && aiop->aio_iocb != NULL) {
		kmem_free(aiop->aio_iocb, aiop->aio_iocbsz);
		aiop->aio_iocb = NULL;
	}

	if (aiop->aio_iocb == NULL) {
		iocblist = kmem_zalloc(iocbsz, KM_NOSLEEP);
		if (iocblist == NULL) {
			mutex_exit(&aiop->aio_mutex);
			return (ENOMEM);
		}
		aiop->aio_iocb = (aiocb_t **)iocblist;
		aiop->aio_iocbsz = iocbsz;
	} else {
		iocblist = (char *)aiop->aio_iocb;
	}

	aiop->aio_waitncnt = waitcnt;
	aiop->aio_flags |= AIO_WAITN;

	for (;;) {
		/* push requests on poll queue to done queue */
		if (aiop->aio_pollq) {
			mutex_exit(&aiop->aio_mutex);
			aio_cleanup(0);
			mutex_enter(&aiop->aio_mutex);
		}

		/* check for requests on done queue */
		if (aiop->aio_doneq) {
			cnt += aio_reqlist_concat(aiop, &reqlist, nent - cnt);
			aiop->aio_waitncnt = waitcnt - cnt;
		}

		/* user-level done queue might not be empty */
		if (aiop->aio_notifycnt > 0) {
			aiop->aio_notifycnt--;
			error = 0;
			break;
		}

		/*
		 * if we are here second time as a result of timer
		 * expiration, we reset error if there are enough
		 * aiocb's to satisfy request.
		 * We return also if all requests are already done
		 * and we picked up the whole done queue.
		 */

		if ((cnt >= waitcnt) || (cnt > 0 && aiop->aio_pending == 0 &&
		    aiop->aio_doneq == NULL)) {
			error = 0;
			break;
		}

		if ((cnt < waitcnt) && blocking) {
			int rval = cv_waituntil_sig(&aiop->aio_waitcv,
			    &aiop->aio_mutex, rqtp, timecheck);
			if (rval > 0)
				continue;
			if (rval < 0) {
				error = ETIME;
				blocking = 0;
				continue;
			}
			error = EINTR;
		}
		break;
	}

	mutex_exit(&aiop->aio_mutex);

	if (cnt > 0) {

		iocb_index = aio_unlock_requests(iocblist, iocb_index, reqlist,
		    aiop, model);

		if (model == DATAMODEL_NATIVE)
			riocbsz = (sizeof (aiocb_t *) * cnt);
#ifdef	_SYSCALL32_IMPL
		else
			riocbsz = (sizeof (caddr32_t) * cnt);
#endif  /* _SYSCALL32_IMPL */

		if (copyout(iocblist, uiocb, riocbsz) ||
		    copyout(&cnt, nwait, sizeof (uint_t)))
			error = EFAULT;
	}

	/* check if there is another thread waiting for execution */
	mutex_enter(&aiop->aio_mutex);
	aiop->aio_flags &= ~AIO_WAITN;
	if (aiop->aio_flags & AIO_WAITN_PENDING) {
		aiop->aio_flags &= ~AIO_WAITN_PENDING;
		cv_signal(&aiop->aio_waitncv);
	}
	mutex_exit(&aiop->aio_mutex);

	return (error);
}

/*
 * aio_unlock_requests
 * copyouts the result of the request as well as the return value.
 * It builds the list of completed asynchronous requests,
 * unlocks the allocated memory ranges and
 * put the aio request structure back into the free list.
 */

static int
aio_unlock_requests(
	caddr_t	iocblist,
	int	iocb_index,
	aio_req_t *reqlist,
	aio_t	*aiop,
	model_t	model)
{
	aio_req_t	*reqp, *nreqp;

	if (model == DATAMODEL_NATIVE) {
		for (reqp = reqlist; reqp != NULL;  reqp = nreqp) {
			(((caddr_t *)iocblist)[iocb_index++]) =
			    reqp->aio_req_iocb.iocb;
			nreqp = reqp->aio_req_next;
			aphysio_unlock(reqp);
			aio_copyout_result(reqp);
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		}
	}
#ifdef	_SYSCALL32_IMPL
	else {
		for (reqp = reqlist; reqp != NULL;  reqp = nreqp) {
			((caddr32_t *)iocblist)[iocb_index++] =
			    reqp->aio_req_iocb.iocb32;
			nreqp = reqp->aio_req_next;
			aphysio_unlock(reqp);
			aio_copyout_result(reqp);
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		}
	}
#endif	/* _SYSCALL32_IMPL */
	return (iocb_index);
}

/*
 * aio_reqlist_concat
 * moves "max" elements from the done queue to the reqlist queue and removes
 * the AIO_DONEQ flag.
 * - reqlist queue is a simple linked list
 * - done queue is a double linked list
 */

static int
aio_reqlist_concat(aio_t *aiop, aio_req_t **reqlist, int max)
{
	aio_req_t *q2, *q2work, *list;
	int count = 0;

	list = *reqlist;
	q2 = aiop->aio_doneq;
	q2work = q2;
	while (max-- > 0) {
		q2work->aio_req_flags &= ~AIO_DONEQ;
		q2work = q2work->aio_req_next;
		count++;
		if (q2work == q2)
			break;
	}

	if (q2work == q2) {
		/* all elements revised */
		q2->aio_req_prev->aio_req_next = list;
		list = q2;
		aiop->aio_doneq = NULL;
	} else {
		/*
		 * max < elements in the doneq
		 * detach only the required amount of elements
		 * out of the doneq
		 */
		q2work->aio_req_prev->aio_req_next = list;
		list = q2;

		aiop->aio_doneq = q2work;
		q2work->aio_req_prev = q2->aio_req_prev;
		q2->aio_req_prev->aio_req_next = q2work;
	}
	*reqlist = list;
	return (count);
}

/*ARGSUSED*/
static int
aiosuspend(
	void	*aiocb,
	int	nent,
	struct	timespec	*timout,
	int	flag,
	long	*rval,
	int	run_mode)
{
	int 		error;
	aio_t		*aiop;
	aio_req_t	*reqp, *found, *next;
	caddr_t		cbplist = NULL;
	aiocb_t		*cbp, **ucbp;
#ifdef	_SYSCALL32_IMPL
	aiocb32_t	*cbp32;
	caddr32_t	*ucbp32;
#endif  /* _SYSCALL32_IMPL */
	aiocb64_32_t	*cbp64;
	int		rv;
	int		i;
	size_t		ssize;
	model_t		model = get_udatamodel();
	int		blocking;
	int		timecheck;
	timestruc_t	rqtime;
	timestruc_t	*rqtp;

	aiop = curproc->p_aio;
	if (aiop == NULL || nent <= 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

	/*
	 * Establish the absolute future time for the timeout.
	 */
	error = timespec2reltime(timout, &rqtime, &rqtp, &blocking);
	if (error)
		return (error);
	if (rqtp) {
		timestruc_t now;
		timecheck = timechanged;
		gethrestime(&now);
		timespecadd(rqtp, &now);
	}

	/*
	 * If we are not blocking and there's no IO complete
	 * skip aiocb copyin.
	 */
	if (!blocking && (aiop->aio_pollq == NULL) &&
	    (aiop->aio_doneq == NULL)) {
		return (EAGAIN);
	}

	if (model == DATAMODEL_NATIVE)
		ssize = (sizeof (aiocb_t *) * nent);
#ifdef	_SYSCALL32_IMPL
	else
		ssize = (sizeof (caddr32_t) * nent);
#endif  /* _SYSCALL32_IMPL */

	cbplist = kmem_alloc(ssize, KM_NOSLEEP);
	if (cbplist == NULL)
		return (ENOMEM);

	if (copyin(aiocb, cbplist, ssize)) {
		error = EFAULT;
		goto done;
	}

	found = NULL;
	/*
	 * we need to get the aio_cleanupq_mutex since we call
	 * aio_req_done().
	 */
	mutex_enter(&aiop->aio_cleanupq_mutex);
	mutex_enter(&aiop->aio_mutex);
	for (;;) {
		/* push requests on poll queue to done queue */
		if (aiop->aio_pollq) {
			mutex_exit(&aiop->aio_mutex);
			mutex_exit(&aiop->aio_cleanupq_mutex);
			aio_cleanup(0);
			mutex_enter(&aiop->aio_cleanupq_mutex);
			mutex_enter(&aiop->aio_mutex);
		}
		/* check for requests on done queue */
		if (aiop->aio_doneq) {
			if (model == DATAMODEL_NATIVE)
				ucbp = (aiocb_t **)cbplist;
#ifdef	_SYSCALL32_IMPL
			else
				ucbp32 = (caddr32_t *)cbplist;
#endif  /* _SYSCALL32_IMPL */
			for (i = 0; i < nent; i++) {
				if (model == DATAMODEL_NATIVE) {
					if ((cbp = *ucbp++) == NULL)
						continue;
					if (run_mode != AIO_LARGEFILE)
						reqp = aio_req_done(
						    &cbp->aio_resultp);
					else {
						cbp64 = (aiocb64_32_t *)cbp;
						reqp = aio_req_done(
						    &cbp64->aio_resultp);
					}
				}
#ifdef	_SYSCALL32_IMPL
				else {
					if (run_mode == AIO_32) {
						if ((cbp32 =
						    (aiocb32_t *)(uintptr_t)
						    *ucbp32++) == NULL)
							continue;
						reqp = aio_req_done(
						    &cbp32->aio_resultp);
					} else if (run_mode == AIO_LARGEFILE) {
						if ((cbp64 =
						    (aiocb64_32_t *)(uintptr_t)
						    *ucbp32++) == NULL)
							continue;
						reqp = aio_req_done(
						    &cbp64->aio_resultp);
					}

				}
#endif  /* _SYSCALL32_IMPL */
				if (reqp) {
					reqp->aio_req_next = found;
					found = reqp;
				}
				if (aiop->aio_doneq == NULL)
					break;
			}
			if (found)
				break;
		}
		if (aiop->aio_notifycnt > 0) {
			/*
			 * nothing on the kernel's queue. the user
			 * has notified the kernel that it has items
			 * on a user-level queue.
			 */
			aiop->aio_notifycnt--;
			*rval = 1;
			error = 0;
			break;
		}
		/* don't block if nothing is outstanding */
		if (aiop->aio_outstanding == 0) {
			error = EAGAIN;
			break;
		}
		if (blocking) {
			/*
			 * drop the aio_cleanupq_mutex as we are
			 * going to block.
			 */
			mutex_exit(&aiop->aio_cleanupq_mutex);
			rv = cv_waituntil_sig(&aiop->aio_waitcv,
			    &aiop->aio_mutex, rqtp, timecheck);
			/*
			 * we have to drop aio_mutex and
			 * grab it in the right order.
			 */
			mutex_exit(&aiop->aio_mutex);
			mutex_enter(&aiop->aio_cleanupq_mutex);
			mutex_enter(&aiop->aio_mutex);
			if (rv > 0)	/* check done queue again */
				continue;
			if (rv == 0)	/* interrupted by a signal */
				error = EINTR;
			else		/* timer expired */
				error = ETIME;
		} else {
			error = EAGAIN;
		}
		break;
	}
	mutex_exit(&aiop->aio_mutex);
	mutex_exit(&aiop->aio_cleanupq_mutex);
	for (reqp = found; reqp != NULL; reqp = next) {
		next = reqp->aio_req_next;
		aphysio_unlock(reqp);
		aio_copyout_result(reqp);
		mutex_enter(&aiop->aio_mutex);
		aio_req_free(aiop, reqp);
		mutex_exit(&aiop->aio_mutex);
	}
done:
	kmem_free(cbplist, ssize);
	return (error);
}

/*
 * initialize aio by allocating an aio_t struct for this
 * process.
 */
static int
aioinit(void)
{
	proc_t *p = curproc;
	aio_t *aiop;
	mutex_enter(&p->p_lock);
	if ((aiop = p->p_aio) == NULL) {
		aiop = aio_aiop_alloc();
		p->p_aio = aiop;
	}
	mutex_exit(&p->p_lock);
	if (aiop == NULL)
		return (ENOMEM);
	return (0);
}

/*
 * start a special thread that will cleanup after aio requests
 * that are preventing a segment from being unmapped. as_unmap()
 * blocks until all phsyio to this segment is completed. this
 * doesn't happen until all the pages in this segment are not
 * SOFTLOCKed. Some pages will be SOFTLOCKed when there are aio
 * requests still outstanding. this special thread will make sure
 * that these SOFTLOCKed pages will eventually be SOFTUNLOCKed.
 *
 * this function will return an error if the process has only
 * one LWP. the assumption is that the caller is a separate LWP
 * that remains blocked in the kernel for the life of this process.
 */
static int
aiostart(void)
{
	proc_t *p = curproc;
	aio_t *aiop;
	int first, error = 0;

	if (p->p_lwpcnt == 1)
		return (EDEADLK);
	mutex_enter(&p->p_lock);
	if ((aiop = p->p_aio) == NULL)
		error = EINVAL;
	else {
		first = aiop->aio_ok;
		if (aiop->aio_ok == 0)
			aiop->aio_ok = 1;
	}
	mutex_exit(&p->p_lock);
	if (error == 0 && first == 0) {
		return (aio_cleanup_thread(aiop));
		/* should return only to exit */
	}
	return (error);
}

/*
 * Associate an aiocb with a port.
 * This function is used by aiorw() to associate a transaction with a port.
 * Allocate an event port structure (port_alloc_event()) and store the
 * delivered user pointer (portnfy_user) in the portkev_user field of the
 * port_kevent_t structure..
 * The aio_req_portkev pointer in the aio_req_t structure was added to identify
 * the port association.
 */

static int
aio_req_assoc_port_rw(port_notify_t *pntfy, aiocb_t *cbp,
	aio_req_t *reqp, int event)
{
	port_kevent_t	*pkevp = NULL;
	int		error;

	error = port_alloc_event(pntfy->portnfy_port, PORT_ALLOC_DEFAULT,
	    PORT_SOURCE_AIO, &pkevp);
	if (error) {
		if ((error == ENOMEM) || (error == EAGAIN))
			error = EAGAIN;
		else
			error = EINVAL;
	} else {
		port_init_event(pkevp, (uintptr_t)cbp, pntfy->portnfy_user,
		    aio_port_callback, reqp);
		pkevp->portkev_events = event;
		reqp->aio_req_portkev = pkevp;
		reqp->aio_req_port = pntfy->portnfy_port;
	}
	return (error);
}

#ifdef _LP64

/*
 * Asynchronous list IO. A chain of aiocb's are copied in
 * one at a time. If the aiocb is invalid, it is skipped.
 * For each aiocb, the appropriate driver entry point is
 * called. Optimize for the common case where the list
 * of requests is to the same file descriptor.
 *
 * One possible optimization is to define a new driver entry
 * point that supports a list of IO requests. Whether this
 * improves performance depends somewhat on the driver's
 * locking strategy. Processing a list could adversely impact
 * the driver's interrupt latency.
 */
static int
alio(
	int		mode_arg,
	aiocb_t		**aiocb_arg,
	int		nent,
	struct sigevent	*sigev)
{
	file_t		*fp;
	file_t		*prev_fp = NULL;
	int		prev_mode = -1;
	struct vnode	*vp;
	aio_lio_t	*head;
	aio_req_t	*reqp;
	aio_t		*aiop;
	caddr_t		cbplist;
	aiocb_t		cb;
	aiocb_t		*aiocb = &cb;
	aiocb_t		*cbp;
	aiocb_t		**ucbp;
	struct sigevent sigevk;
	sigqueue_t	*sqp;
	int		(*aio_func)();
	int		mode;
	int		error = 0;
	int		aio_errors = 0;
	int		i;
	size_t		ssize;
	int		deadhead = 0;
	int		aio_notsupported = 0;
	int		lio_head_port;
	int		aio_port;
	int		aio_thread;
	port_kevent_t	*pkevtp = NULL;
	int		portused = 0;
	port_notify_t	pnotify;
	int		event;

	aiop = curproc->p_aio;
	if (aiop == NULL || nent <= 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

	ssize = (sizeof (aiocb_t *) * nent);
	cbplist = kmem_alloc(ssize, KM_SLEEP);
	ucbp = (aiocb_t **)cbplist;

	if (copyin(aiocb_arg, cbplist, ssize) ||
	    (sigev && copyin(sigev, &sigevk, sizeof (struct sigevent)))) {
		kmem_free(cbplist, ssize);
		return (EFAULT);
	}

	/* Event Ports  */
	if (sigev &&
	    (sigevk.sigev_notify == SIGEV_THREAD ||
	    sigevk.sigev_notify == SIGEV_PORT)) {
		if (sigevk.sigev_notify == SIGEV_THREAD) {
			pnotify.portnfy_port = sigevk.sigev_signo;
			pnotify.portnfy_user = sigevk.sigev_value.sival_ptr;
		} else if (copyin(sigevk.sigev_value.sival_ptr,
		    &pnotify, sizeof (pnotify))) {
			kmem_free(cbplist, ssize);
			return (EFAULT);
		}
		error = port_alloc_event(pnotify.portnfy_port,
		    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO, &pkevtp);
		if (error) {
			if (error == ENOMEM || error == EAGAIN)
				error = EAGAIN;
			else
				error = EINVAL;
			kmem_free(cbplist, ssize);
			return (error);
		}
		lio_head_port = pnotify.portnfy_port;
		portused = 1;
	}

	/*
	 * a list head should be allocated if notification is
	 * enabled for this list.
	 */
	head = NULL;

	if (mode_arg == LIO_WAIT || sigev) {
		mutex_enter(&aiop->aio_mutex);
		error = aio_lio_alloc(&head);
		mutex_exit(&aiop->aio_mutex);
		if (error)
			goto done;
		deadhead = 1;
		head->lio_nent = nent;
		head->lio_refcnt = nent;
		head->lio_port = -1;
		head->lio_portkev = NULL;
		if (sigev && sigevk.sigev_notify == SIGEV_SIGNAL &&
		    sigevk.sigev_signo > 0 && sigevk.sigev_signo < NSIG) {
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_NOSLEEP);
			if (sqp == NULL) {
				error = EAGAIN;
				goto done;
			}
			sqp->sq_func = NULL;
			sqp->sq_next = NULL;
			sqp->sq_info.si_code = SI_ASYNCIO;
			sqp->sq_info.si_pid = curproc->p_pid;
			sqp->sq_info.si_ctid = PRCTID(curproc);
			sqp->sq_info.si_zoneid = getzoneid();
			sqp->sq_info.si_uid = crgetuid(curproc->p_cred);
			sqp->sq_info.si_signo = sigevk.sigev_signo;
			sqp->sq_info.si_value = sigevk.sigev_value;
			head->lio_sigqp = sqp;
		} else {
			head->lio_sigqp = NULL;
		}
		if (pkevtp) {
			/*
			 * Prepare data to send when list of aiocb's
			 * has completed.
			 */
			port_init_event(pkevtp, (uintptr_t)sigev,
			    (void *)(uintptr_t)pnotify.portnfy_user,
			    NULL, head);
			pkevtp->portkev_events = AIOLIO;
			head->lio_portkev = pkevtp;
			head->lio_port = pnotify.portnfy_port;
		}
	}

	for (i = 0; i < nent; i++, ucbp++) {

		cbp = *ucbp;
		/* skip entry if it can't be copied. */
		if (cbp == NULL || copyin(cbp, aiocb, sizeof (*aiocb))) {
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}

		/* skip if opcode for aiocb is LIO_NOP */
		mode = aiocb->aio_lio_opcode;
		if (mode == LIO_NOP) {
			cbp = NULL;
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}

		/* increment file descriptor's ref count. */
		if ((fp = getf(aiocb->aio_fildes)) == NULL) {
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * check the permission of the partition
		 */
		if ((fp->f_flag & mode) == 0) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * common case where requests are to the same fd
		 * for the same r/w operation.
		 * for UFS, need to set EBADFD
		 */
		vp = fp->f_vnode;
		if (fp != prev_fp || mode != prev_mode) {
			aio_func = check_vp(vp, mode);
			if (aio_func == NULL) {
				prev_fp = NULL;
				releasef(aiocb->aio_fildes);
				lio_set_uerror(&cbp->aio_resultp, EBADFD);
				aio_notsupported++;
				if (head) {
					mutex_enter(&aiop->aio_mutex);
					head->lio_nent--;
					head->lio_refcnt--;
					mutex_exit(&aiop->aio_mutex);
				}
				continue;
			} else {
				prev_fp = fp;
				prev_mode = mode;
			}
		}

		error = aio_req_setup(&reqp, aiop, aiocb,
		    &cbp->aio_resultp, vp, 0);
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		reqp->aio_req_lio = head;
		deadhead = 0;

		/*
		 * Set the errno field now before sending the request to
		 * the driver to avoid a race condition
		 */
		(void) suword32(&cbp->aio_resultp.aio_errno,
		    EINPROGRESS);

		reqp->aio_req_iocb.iocb = (caddr_t)cbp;

		event = (mode == LIO_READ)? AIOAREAD : AIOAWRITE;
		aio_port = (aiocb->aio_sigevent.sigev_notify == SIGEV_PORT);
		aio_thread = (aiocb->aio_sigevent.sigev_notify == SIGEV_THREAD);
		if (aio_port | aio_thread) {
			port_kevent_t *lpkevp;
			/*
			 * Prepare data to send with each aiocb completed.
			 */
			if (aio_port) {
				void *paddr =
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
				if (copyin(paddr, &pnotify, sizeof (pnotify)))
					error = EFAULT;
			} else {	/* aio_thread */
				pnotify.portnfy_port =
				    aiocb->aio_sigevent.sigev_signo;
				pnotify.portnfy_user =
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
			}
			if (error)
				/* EMPTY */;
			else if (pkevtp != NULL &&
			    pnotify.portnfy_port == lio_head_port)
				error = port_dup_event(pkevtp, &lpkevp,
				    PORT_ALLOC_DEFAULT);
			else
				error = port_alloc_event(pnotify.portnfy_port,
				    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO,
				    &lpkevp);
			if (error == 0) {
				port_init_event(lpkevp, (uintptr_t)cbp,
				    (void *)(uintptr_t)pnotify.portnfy_user,
				    aio_port_callback, reqp);
				lpkevp->portkev_events = event;
				reqp->aio_req_portkev = lpkevp;
				reqp->aio_req_port = pnotify.portnfy_port;
			}
		}

		/*
		 * send the request to driver.
		 */
		if (error == 0) {
			if (aiocb->aio_nbytes == 0) {
				clear_active_fd(aiocb->aio_fildes);
				aio_zerolen(reqp);
				continue;
			}
			error = (*aio_func)(vp, (aio_req_t *)&reqp->aio_req,
			    CRED());
		}

		/*
		 * the fd's ref count is not decremented until the IO has
		 * completed unless there was an error.
		 */
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			if (error == ENOTSUP)
				aio_notsupported++;
			else
				aio_errors++;
			lio_set_error(reqp, portused);
		} else {
			clear_active_fd(aiocb->aio_fildes);
		}
	}

	if (aio_notsupported) {
		error = ENOTSUP;
	} else if (aio_errors) {
		/*
		 * return EIO if any request failed
		 */
		error = EIO;
	}

	if (mode_arg == LIO_WAIT) {
		mutex_enter(&aiop->aio_mutex);
		while (head->lio_refcnt > 0) {
			if (!cv_wait_sig(&head->lio_notify, &aiop->aio_mutex)) {
				mutex_exit(&aiop->aio_mutex);
				error = EINTR;
				goto done;
			}
		}
		mutex_exit(&aiop->aio_mutex);
		alio_cleanup(aiop, (aiocb_t **)cbplist, nent, AIO_64);
	}

done:
	kmem_free(cbplist, ssize);
	if (deadhead) {
		if (head->lio_sigqp)
			kmem_free(head->lio_sigqp, sizeof (sigqueue_t));
		if (head->lio_portkev)
			port_free_event(head->lio_portkev);
		kmem_free(head, sizeof (aio_lio_t));
	}
	return (error);
}

#endif /* _LP64 */

/*
 * Asynchronous list IO.
 * If list I/O is called with LIO_WAIT it can still return
 * before all the I/O's are completed if a signal is caught
 * or if the list include UFS I/O requests. If this happens,
 * libaio will call aliowait() to wait for the I/O's to
 * complete
 */
/*ARGSUSED*/
static int
aliowait(
	int	mode,
	void	*aiocb,
	int	nent,
	void	*sigev,
	int	run_mode)
{
	aio_lio_t	*head;
	aio_t		*aiop;
	caddr_t		cbplist;
	aiocb_t		*cbp, **ucbp;
#ifdef	_SYSCALL32_IMPL
	aiocb32_t	*cbp32;
	caddr32_t	*ucbp32;
	aiocb64_32_t	*cbp64;
#endif
	int		error = 0;
	int		i;
	size_t		ssize = 0;
	model_t		model = get_udatamodel();

	aiop = curproc->p_aio;
	if (aiop == NULL || nent <= 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

	if (model == DATAMODEL_NATIVE)
		ssize = (sizeof (aiocb_t *) * nent);
#ifdef	_SYSCALL32_IMPL
	else
		ssize = (sizeof (caddr32_t) * nent);
#endif  /* _SYSCALL32_IMPL */

	if (ssize == 0)
		return (EINVAL);

	cbplist = kmem_alloc(ssize, KM_SLEEP);

	if (model == DATAMODEL_NATIVE)
		ucbp = (aiocb_t **)cbplist;
#ifdef	_SYSCALL32_IMPL
	else
		ucbp32 = (caddr32_t *)cbplist;
#endif  /* _SYSCALL32_IMPL */

	if (copyin(aiocb, cbplist, ssize)) {
		error = EFAULT;
		goto done;
	}

	/*
	 * To find the list head, we go through the
	 * list of aiocb structs, find the request
	 * its for, then get the list head that reqp
	 * points to
	 */
	head = NULL;

	for (i = 0; i < nent; i++) {
		if (model == DATAMODEL_NATIVE) {
			/*
			 * Since we are only checking for a NULL pointer
			 * Following should work on both native data sizes
			 * as well as for largefile aiocb.
			 */
			if ((cbp = *ucbp++) == NULL)
				continue;
			if (run_mode != AIO_LARGEFILE)
				if (head = aio_list_get(&cbp->aio_resultp))
					break;
			else {
				/*
				 * This is a case when largefile call is
				 * made on 32 bit kernel.
				 * Treat each pointer as pointer to
				 * aiocb64_32
				 */
				if (head = aio_list_get((aio_result_t *)
				    &(((aiocb64_32_t *)cbp)->aio_resultp)))
					break;
			}
		}
#ifdef	_SYSCALL32_IMPL
		else {
			if (run_mode == AIO_LARGEFILE) {
				if ((cbp64 = (aiocb64_32_t *)
				    (uintptr_t)*ucbp32++) == NULL)
					continue;
				if (head = aio_list_get((aio_result_t *)
				    &cbp64->aio_resultp))
					break;
			} else if (run_mode == AIO_32) {
				if ((cbp32 = (aiocb32_t *)
				    (uintptr_t)*ucbp32++) == NULL)
					continue;
				if (head = aio_list_get((aio_result_t *)
				    &cbp32->aio_resultp))
					break;
			}
		}
#endif	/* _SYSCALL32_IMPL */
	}

	if (head == NULL) {
		error = EINVAL;
		goto done;
	}

	mutex_enter(&aiop->aio_mutex);
	while (head->lio_refcnt > 0) {
		if (!cv_wait_sig(&head->lio_notify, &aiop->aio_mutex)) {
			mutex_exit(&aiop->aio_mutex);
			error = EINTR;
			goto done;
		}
	}
	mutex_exit(&aiop->aio_mutex);
	alio_cleanup(aiop, (aiocb_t **)cbplist, nent, run_mode);
done:
	kmem_free(cbplist, ssize);
	return (error);
}

aio_lio_t *
aio_list_get(aio_result_t *resultp)
{
	aio_lio_t	*head = NULL;
	aio_t		*aiop;
	aio_req_t 	**bucket;
	aio_req_t 	*reqp;
	long		index;

	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (NULL);

	if (resultp) {
		index = AIO_HASH(resultp);
		bucket = &aiop->aio_hash[index];
		for (reqp = *bucket; reqp != NULL;
		    reqp = reqp->aio_hash_next) {
			if (reqp->aio_req_resultp == resultp) {
				head = reqp->aio_req_lio;
				return (head);
			}
		}
	}
	return (NULL);
}


static void
lio_set_uerror(void *resultp, int error)
{
	/*
	 * the resultp field is a pointer to where the
	 * error should be written out to the user's
	 * aiocb.
	 *
	 */
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		(void) sulword(&((aio_result_t *)resultp)->aio_return,
		    (ssize_t)-1);
		(void) suword32(&((aio_result_t *)resultp)->aio_errno, error);
	}
#ifdef	_SYSCALL32_IMPL
	else {
		(void) suword32(&((aio_result32_t *)resultp)->aio_return,
		    (uint_t)-1);
		(void) suword32(&((aio_result32_t *)resultp)->aio_errno, error);
	}
#endif  /* _SYSCALL32_IMPL */
}

/*
 * do cleanup completion for all requests in list. memory for
 * each request is also freed.
 */
static void
alio_cleanup(aio_t *aiop, aiocb_t **cbp, int nent, int run_mode)
{
	int i;
	aio_req_t *reqp;
	aio_result_t *resultp;
	aiocb64_32_t *aiocb_64;

	for (i = 0; i < nent; i++) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (cbp[i] == NULL)
				continue;
			if (run_mode == AIO_LARGEFILE) {
				aiocb_64 = (aiocb64_32_t *)cbp[i];
				resultp = (aio_result_t *)
				    &aiocb_64->aio_resultp;
			} else
				resultp = &cbp[i]->aio_resultp;
		}
#ifdef	_SYSCALL32_IMPL
		else {
			aiocb32_t *aiocb_32;
			caddr32_t *cbp32;

			cbp32 = (caddr32_t *)cbp;
			if (cbp32[i] == NULL)
				continue;
			if (run_mode == AIO_32) {
				aiocb_32 = (aiocb32_t *)(uintptr_t)cbp32[i];
				resultp = (aio_result_t *)&aiocb_32->
				    aio_resultp;
			} else if (run_mode == AIO_LARGEFILE) {
				aiocb_64 = (aiocb64_32_t *)(uintptr_t)cbp32[i];
				resultp = (aio_result_t *)&aiocb_64->
				    aio_resultp;
			}
		}
#endif  /* _SYSCALL32_IMPL */
		/*
		 * we need to get the aio_cleanupq_mutex since we call
		 * aio_req_done().
		 */
		mutex_enter(&aiop->aio_cleanupq_mutex);
		mutex_enter(&aiop->aio_mutex);
		reqp = aio_req_done(resultp);
		mutex_exit(&aiop->aio_mutex);
		mutex_exit(&aiop->aio_cleanupq_mutex);
		if (reqp != NULL) {
			aphysio_unlock(reqp);
			aio_copyout_result(reqp);
			mutex_enter(&aiop->aio_mutex);
			aio_req_free(aiop, reqp);
			mutex_exit(&aiop->aio_mutex);
		}
	}
}

/*
 * Write out the results for an aio request that is done.
 */
static int
aioerror(void *cb, int run_mode)
{
	aio_result_t *resultp;
	aio_t *aiop;
	aio_req_t *reqp;
	int retval;

	aiop = curproc->p_aio;
	if (aiop == NULL || cb == NULL)
		return (EINVAL);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (run_mode == AIO_LARGEFILE)
			resultp = (aio_result_t *)&((aiocb64_32_t *)cb)->
			    aio_resultp;
		else
			resultp = &((aiocb_t *)cb)->aio_resultp;
	}
#ifdef	_SYSCALL32_IMPL
	else {
		if (run_mode == AIO_LARGEFILE)
			resultp = (aio_result_t *)&((aiocb64_32_t *)cb)->
			    aio_resultp;
		else if (run_mode == AIO_32)
			resultp = (aio_result_t *)&((aiocb32_t *)cb)->
			    aio_resultp;
	}
#endif  /* _SYSCALL32_IMPL */
	/*
	 * we need to get the aio_cleanupq_mutex since we call
	 * aio_req_find().
	 */
	mutex_enter(&aiop->aio_cleanupq_mutex);
	mutex_enter(&aiop->aio_mutex);
	retval = aio_req_find(resultp, &reqp);
	mutex_exit(&aiop->aio_mutex);
	mutex_exit(&aiop->aio_cleanupq_mutex);
	if (retval == 0) {
		aphysio_unlock(reqp);
		aio_copyout_result(reqp);
		mutex_enter(&aiop->aio_mutex);
		aio_req_free(aiop, reqp);
		mutex_exit(&aiop->aio_mutex);
		return (0);
	} else if (retval == 1)
		return (EINPROGRESS);
	else if (retval == 2)
		return (EINVAL);
	return (0);
}

/*
 * 	aio_cancel - if no requests outstanding,
 *			return AIO_ALLDONE
 *			else
 *			return AIO_NOTCANCELED
 */
static int
aio_cancel(
	int	fildes,
	void 	*cb,
	long	*rval,
	int	run_mode)
{
	aio_t *aiop;
	void *resultp;
	int index;
	aio_req_t **bucket;
	aio_req_t *ent;


	/*
	 * Verify valid file descriptor
	 */
	if ((getf(fildes)) == NULL) {
		return (EBADF);
	}
	releasef(fildes);

	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (EINVAL);

	if (aiop->aio_outstanding == 0) {
		*rval = AIO_ALLDONE;
		return (0);
	}

	mutex_enter(&aiop->aio_mutex);
	if (cb != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (run_mode == AIO_LARGEFILE)
				resultp = (aio_result_t *)&((aiocb64_32_t *)cb)
				    ->aio_resultp;
			else
				resultp = &((aiocb_t *)cb)->aio_resultp;
		}
#ifdef	_SYSCALL32_IMPL
		else {
			if (run_mode == AIO_LARGEFILE)
				resultp = (aio_result_t *)&((aiocb64_32_t *)cb)
				    ->aio_resultp;
			else if (run_mode == AIO_32)
				resultp = (aio_result_t *)&((aiocb32_t *)cb)
				    ->aio_resultp;
		}
#endif  /* _SYSCALL32_IMPL */
		index = AIO_HASH(resultp);
		bucket = &aiop->aio_hash[index];
		for (ent = *bucket; ent != NULL; ent = ent->aio_hash_next) {
			if (ent->aio_req_resultp == resultp) {
				if ((ent->aio_req_flags & AIO_PENDING) == 0) {
					mutex_exit(&aiop->aio_mutex);
					*rval = AIO_ALLDONE;
					return (0);
				}
				mutex_exit(&aiop->aio_mutex);
				*rval = AIO_NOTCANCELED;
				return (0);
			}
		}
		mutex_exit(&aiop->aio_mutex);
		*rval = AIO_ALLDONE;
		return (0);
	}

	for (index = 0; index < AIO_HASHSZ; index++) {
		bucket = &aiop->aio_hash[index];
		for (ent = *bucket; ent != NULL; ent = ent->aio_hash_next) {
			if (ent->aio_req_fd == fildes) {
				if ((ent->aio_req_flags & AIO_PENDING) != 0) {
					mutex_exit(&aiop->aio_mutex);
					*rval = AIO_NOTCANCELED;
					return (0);
				}
			}
		}
	}
	mutex_exit(&aiop->aio_mutex);
	*rval = AIO_ALLDONE;
	return (0);
}

/*
 * solaris version of asynchronous read and write
 */
static int
arw(
	int	opcode,
	int	fdes,
	char	*bufp,
	int	bufsize,
	offset_t	offset,
	aio_result_t	*resultp,
	int		mode)
{
	file_t		*fp;
	int		error;
	struct vnode	*vp;
	aio_req_t	*reqp;
	aio_t		*aiop;
	int		(*aio_func)();
#ifdef _LP64
	aiocb_t		aiocb;
#else
	aiocb64_32_t	aiocb64;
#endif

	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (EINVAL);

	if ((fp = getf(fdes)) == NULL) {
		return (EBADF);
	}

	/*
	 * check the permission of the partition
	 */
	if ((fp->f_flag & mode) == 0) {
		releasef(fdes);
		return (EBADF);
	}

	vp = fp->f_vnode;
	aio_func = check_vp(vp, mode);
	if (aio_func == NULL) {
		releasef(fdes);
		return (EBADFD);
	}
#ifdef _LP64
	aiocb.aio_fildes = fdes;
	aiocb.aio_buf = bufp;
	aiocb.aio_nbytes = bufsize;
	aiocb.aio_offset = offset;
	aiocb.aio_sigevent.sigev_notify = 0;
	error = aio_req_setup(&reqp, aiop, &aiocb, resultp, vp, 1);
#else
	aiocb64.aio_fildes = fdes;
	aiocb64.aio_buf = (caddr32_t)bufp;
	aiocb64.aio_nbytes = bufsize;
	aiocb64.aio_offset = offset;
	aiocb64.aio_sigevent.sigev_notify = 0;
	error = aio_req_setupLF(&reqp, aiop, &aiocb64, resultp, vp, 1);
#endif
	if (error) {
		releasef(fdes);
		return (error);
	}

	/*
	 * enable polling on this request if the opcode has
	 * the AIO poll bit set
	 */
	if (opcode & AIO_POLL_BIT)
		reqp->aio_req_flags |= AIO_POLL;

	if (bufsize == 0) {
		clear_active_fd(fdes);
		aio_zerolen(reqp);
		return (0);
	}
	/*
	 * send the request to driver.
	 */
	error = (*aio_func)(vp, (aio_req_t *)&reqp->aio_req, CRED());
	/*
	 * the fd is stored in the aio_req_t by aio_req_setup(), and
	 * is released by the aio_cleanup_thread() when the IO has
	 * completed.
	 */
	if (error) {
		releasef(fdes);
		mutex_enter(&aiop->aio_mutex);
		aio_req_free(aiop, reqp);
		aiop->aio_pending--;
		if (aiop->aio_flags & AIO_REQ_BLOCK)
			cv_signal(&aiop->aio_cleanupcv);
		mutex_exit(&aiop->aio_mutex);
		return (error);
	}
	clear_active_fd(fdes);
	return (0);
}

/*
 * posix version of asynchronous read and write
 */
static int
aiorw(
	int		opcode,
	void		*aiocb_arg,
	int		mode,
	int		run_mode)
{
#ifdef _SYSCALL32_IMPL
	aiocb32_t	aiocb32;
	struct	sigevent32 *sigev32;
	port_notify32_t	pntfy32;
#endif
	aiocb64_32_t	aiocb64;
	aiocb_t		aiocb;
	file_t		*fp;
	int		error, fd;
	size_t		bufsize;
	struct vnode	*vp;
	aio_req_t	*reqp;
	aio_t		*aiop;
	int		(*aio_func)();
	aio_result_t	*resultp;
	struct	sigevent *sigev;
	model_t		model;
	int		aio_use_port = 0;
	port_notify_t	pntfy;

	model = get_udatamodel();
	aiop = curproc->p_aio;
	if (aiop == NULL)
		return (EINVAL);

	if (model == DATAMODEL_NATIVE) {
		if (run_mode != AIO_LARGEFILE) {
			if (copyin(aiocb_arg, &aiocb, sizeof (aiocb_t)))
				return (EFAULT);
			bufsize = aiocb.aio_nbytes;
			resultp = &(((aiocb_t *)aiocb_arg)->aio_resultp);
			if ((fp = getf(fd = aiocb.aio_fildes)) == NULL) {
				return (EBADF);
			}
			sigev = &aiocb.aio_sigevent;
		} else {
			/*
			 * We come here only when we make largefile
			 * call on 32 bit kernel using 32 bit library.
			 */
			if (copyin(aiocb_arg, &aiocb64, sizeof (aiocb64_32_t)))
				return (EFAULT);
			bufsize = aiocb64.aio_nbytes;
			resultp = (aio_result_t *)&(((aiocb64_32_t *)aiocb_arg)
			    ->aio_resultp);
			if ((fp = getf(fd = aiocb64.aio_fildes)) == NULL)
				return (EBADF);
			sigev = (struct sigevent *)&aiocb64.aio_sigevent;
		}

		if (sigev->sigev_notify == SIGEV_PORT) {
			if (copyin((void *)sigev->sigev_value.sival_ptr,
			    &pntfy, sizeof (port_notify_t))) {
				releasef(fd);
				return (EFAULT);
			}
			aio_use_port = 1;
		} else if (sigev->sigev_notify == SIGEV_THREAD) {
			pntfy.portnfy_port = aiocb.aio_sigevent.sigev_signo;
			pntfy.portnfy_user =
			    aiocb.aio_sigevent.sigev_value.sival_ptr;
			aio_use_port = 1;
		}
	}
#ifdef	_SYSCALL32_IMPL
	else {
		if (run_mode == AIO_32) {
			/* 32 bit system call is being made on 64 bit kernel */
			if (copyin(aiocb_arg, &aiocb32, sizeof (aiocb32_t)))
				return (EFAULT);

			bufsize = aiocb32.aio_nbytes;
			aiocb_32ton(&aiocb32, &aiocb);
			resultp = (aio_result_t *)&(((aiocb32_t *)aiocb_arg)->
			    aio_resultp);
			if ((fp = getf(fd = aiocb32.aio_fildes)) == NULL) {
				return (EBADF);
			}
			sigev32 = &aiocb32.aio_sigevent;
		} else if (run_mode == AIO_LARGEFILE) {
			/*
			 * We come here only when we make largefile
			 * call on 64 bit kernel using 32 bit library.
			 */
			if (copyin(aiocb_arg, &aiocb64, sizeof (aiocb64_32_t)))
				return (EFAULT);
			bufsize = aiocb64.aio_nbytes;
			aiocb_LFton(&aiocb64, &aiocb);
			resultp = (aio_result_t *)&(((aiocb64_32_t *)aiocb_arg)
			    ->aio_resultp);
			if ((fp = getf(fd = aiocb64.aio_fildes)) == NULL)
				return (EBADF);
			sigev32 = &aiocb64.aio_sigevent;
		}

		if (sigev32->sigev_notify == SIGEV_PORT) {
			if (copyin(
			    (void *)(uintptr_t)sigev32->sigev_value.sival_ptr,
			    &pntfy32, sizeof (port_notify32_t))) {
				releasef(fd);
				return (EFAULT);
			}
			pntfy.portnfy_port = pntfy32.portnfy_port;
			pntfy.portnfy_user = (void *)(uintptr_t)
			    pntfy32.portnfy_user;
			aio_use_port = 1;
		} else if (sigev32->sigev_notify == SIGEV_THREAD) {
			pntfy.portnfy_port = sigev32->sigev_signo;
			pntfy.portnfy_user = (void *)(uintptr_t)
			    sigev32->sigev_value.sival_ptr;
			aio_use_port = 1;
		}
	}
#endif  /* _SYSCALL32_IMPL */

	/*
	 * check the permission of the partition
	 */

	if ((fp->f_flag & mode) == 0) {
		releasef(fd);
		return (EBADF);
	}

	vp = fp->f_vnode;
	aio_func = check_vp(vp, mode);
	if (aio_func == NULL) {
		releasef(fd);
		return (EBADFD);
	}
	if (run_mode == AIO_LARGEFILE)
		error = aio_req_setupLF(&reqp, aiop, &aiocb64, resultp, vp, 0);
	else
		error = aio_req_setup(&reqp, aiop, &aiocb, resultp, vp, 0);

	if (error) {
		releasef(fd);
		return (error);
	}
	/*
	 * enable polling on this request if the opcode has
	 * the AIO poll bit set
	 */
	if (opcode & AIO_POLL_BIT)
		reqp->aio_req_flags |= AIO_POLL;

	if (model == DATAMODEL_NATIVE)
		reqp->aio_req_iocb.iocb = aiocb_arg;
#ifdef  _SYSCALL32_IMPL
	else
		reqp->aio_req_iocb.iocb32 = (caddr32_t)(uintptr_t)aiocb_arg;
#endif

	if (aio_use_port) {
		int event = (run_mode == AIO_LARGEFILE)?
		    ((mode == FREAD)? AIOAREAD64 : AIOAWRITE64) :
		    ((mode == FREAD)? AIOAREAD : AIOAWRITE);
		error = aio_req_assoc_port_rw(&pntfy, aiocb_arg, reqp, event);
	}

	/*
	 * send the request to driver.
	 */
	if (error == 0) {
		if (bufsize == 0) {
			clear_active_fd(fd);
			aio_zerolen(reqp);
			return (0);
		}
		error = (*aio_func)(vp, (aio_req_t *)&reqp->aio_req, CRED());
	}

	/*
	 * the fd is stored in the aio_req_t by aio_req_setup(), and
	 * is released by the aio_cleanup_thread() when the IO has
	 * completed.
	 */
	if (error) {
		releasef(fd);
		mutex_enter(&aiop->aio_mutex);
		if (aio_use_port)
			aio_deq(&aiop->aio_portpending, reqp);
		aio_req_free(aiop, reqp);
		aiop->aio_pending--;
		if (aiop->aio_flags & AIO_REQ_BLOCK)
			cv_signal(&aiop->aio_cleanupcv);
		mutex_exit(&aiop->aio_mutex);
		return (error);
	}
	clear_active_fd(fd);
	return (0);
}


/*
 * set error for a list IO entry that failed.
 */
static void
lio_set_error(aio_req_t *reqp, int portused)
{
	aio_t *aiop = curproc->p_aio;

	if (aiop == NULL)
		return;

	mutex_enter(&aiop->aio_mutex);
	if (portused)
		aio_deq(&aiop->aio_portpending, reqp);
	aiop->aio_pending--;
	/* request failed, AIO_PHYSIODONE set to aviod physio cleanup. */
	reqp->aio_req_flags |= AIO_PHYSIODONE;
	/*
	 * Need to free the request now as its never
	 * going to get on the done queue
	 *
	 * Note: aio_outstanding is decremented in
	 *	 aio_req_free()
	 */
	aio_req_free(aiop, reqp);
	if (aiop->aio_flags & AIO_REQ_BLOCK)
		cv_signal(&aiop->aio_cleanupcv);
	mutex_exit(&aiop->aio_mutex);
}

/*
 * check if a specified request is done, and remove it from
 * the done queue. otherwise remove anybody from the done queue
 * if NULL is specified.
 */
static aio_req_t *
aio_req_done(void *resultp)
{
	aio_req_t **bucket;
	aio_req_t *ent;
	aio_t *aiop = curproc->p_aio;
	long index;

	ASSERT(MUTEX_HELD(&aiop->aio_cleanupq_mutex));
	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if (resultp) {
		index = AIO_HASH(resultp);
		bucket = &aiop->aio_hash[index];
		for (ent = *bucket; ent != NULL; ent = ent->aio_hash_next) {
			if (ent->aio_req_resultp == (aio_result_t *)resultp) {
				if (ent->aio_req_flags & AIO_DONEQ) {
					return (aio_req_remove(ent));
				}
				return (NULL);
			}
		}
		/* no match, resultp is invalid */
		return (NULL);
	}
	return (aio_req_remove(NULL));
}

/*
 * determine if a user-level resultp pointer is associated with an
 * active IO request. Zero is returned when the request is done,
 * and the request is removed from the done queue. Only when the
 * return value is zero, is the "reqp" pointer valid. One is returned
 * when the request is inprogress. Two is returned when the request
 * is invalid.
 */
static int
aio_req_find(aio_result_t *resultp, aio_req_t **reqp)
{
	aio_req_t **bucket;
	aio_req_t *ent;
	aio_t *aiop = curproc->p_aio;
	long index;

	ASSERT(MUTEX_HELD(&aiop->aio_cleanupq_mutex));
	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	index = AIO_HASH(resultp);
	bucket = &aiop->aio_hash[index];
	for (ent = *bucket; ent != NULL; ent = ent->aio_hash_next) {
		if (ent->aio_req_resultp == resultp) {
			if (ent->aio_req_flags & AIO_DONEQ) {
				*reqp = aio_req_remove(ent);
				return (0);
			}
			return (1);
		}
	}
	/* no match, resultp is invalid */
	return (2);
}

/*
 * remove a request from the done queue.
 */
static aio_req_t *
aio_req_remove(aio_req_t *reqp)
{
	aio_t *aiop = curproc->p_aio;

	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if (reqp != NULL) {
		ASSERT(reqp->aio_req_flags & AIO_DONEQ);
		if (reqp->aio_req_next == reqp) {
			/* only one request on queue */
			if (reqp ==  aiop->aio_doneq) {
				aiop->aio_doneq = NULL;
			} else {
				ASSERT(reqp == aiop->aio_cleanupq);
				aiop->aio_cleanupq = NULL;
			}
		} else {
			reqp->aio_req_next->aio_req_prev = reqp->aio_req_prev;
			reqp->aio_req_prev->aio_req_next = reqp->aio_req_next;
			/*
			 * The request can be either on the aio_doneq or the
			 * aio_cleanupq
			 */
			if (reqp == aiop->aio_doneq)
				aiop->aio_doneq = reqp->aio_req_next;

			if (reqp == aiop->aio_cleanupq)
				aiop->aio_cleanupq = reqp->aio_req_next;
		}
		reqp->aio_req_flags &= ~AIO_DONEQ;
		reqp->aio_req_next = NULL;
		reqp->aio_req_prev = NULL;
	} else if ((reqp = aiop->aio_doneq) != NULL) {
		ASSERT(reqp->aio_req_flags & AIO_DONEQ);
		if (reqp == reqp->aio_req_next) {
			/* only one request on queue */
			aiop->aio_doneq = NULL;
		} else {
			reqp->aio_req_prev->aio_req_next = reqp->aio_req_next;
			reqp->aio_req_next->aio_req_prev = reqp->aio_req_prev;
			aiop->aio_doneq = reqp->aio_req_next;
		}
		reqp->aio_req_flags &= ~AIO_DONEQ;
		reqp->aio_req_next = NULL;
		reqp->aio_req_prev = NULL;
	}
	if (aiop->aio_doneq == NULL && (aiop->aio_flags & AIO_WAITN))
		cv_broadcast(&aiop->aio_waitcv);
	return (reqp);
}

static int
aio_req_setup(
	aio_req_t	**reqpp,
	aio_t 		*aiop,
	aiocb_t 	*arg,
	aio_result_t 	*resultp,
	vnode_t		*vp,
	int		old_solaris_req)
{
	sigqueue_t	*sqp = NULL;
	aio_req_t 	*reqp;
	struct uio 	*uio;
	struct sigevent *sigev;
	int		error;

	sigev = &arg->aio_sigevent;
	if (sigev->sigev_notify == SIGEV_SIGNAL &&
	    sigev->sigev_signo > 0 && sigev->sigev_signo < NSIG) {
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_NOSLEEP);
		if (sqp == NULL)
			return (EAGAIN);
		sqp->sq_func = NULL;
		sqp->sq_next = NULL;
		sqp->sq_info.si_code = SI_ASYNCIO;
		sqp->sq_info.si_pid = curproc->p_pid;
		sqp->sq_info.si_ctid = PRCTID(curproc);
		sqp->sq_info.si_zoneid = getzoneid();
		sqp->sq_info.si_uid = crgetuid(curproc->p_cred);
		sqp->sq_info.si_signo = sigev->sigev_signo;
		sqp->sq_info.si_value = sigev->sigev_value;
	}

	mutex_enter(&aiop->aio_mutex);

	if (aiop->aio_flags & AIO_REQ_BLOCK) {
		mutex_exit(&aiop->aio_mutex);
		if (sqp)
			kmem_free(sqp, sizeof (sigqueue_t));
		return (EIO);
	}
	/*
	 * get an aio_reqp from the free list or allocate one
	 * from dynamic memory.
	 */
	if (error = aio_req_alloc(&reqp, resultp)) {
		mutex_exit(&aiop->aio_mutex);
		if (sqp)
			kmem_free(sqp, sizeof (sigqueue_t));
		return (error);
	}
	aiop->aio_pending++;
	aiop->aio_outstanding++;
	reqp->aio_req_flags = AIO_PENDING;
	if (old_solaris_req) {
		/* this is an old solaris aio request */
		reqp->aio_req_flags |= AIO_SOLARIS;
		aiop->aio_flags |= AIO_SOLARIS_REQ;
	}
	if (sigev->sigev_notify == SIGEV_THREAD ||
	    sigev->sigev_notify == SIGEV_PORT)
		aio_enq(&aiop->aio_portpending, reqp, 0);
	mutex_exit(&aiop->aio_mutex);
	/*
	 * initialize aio request.
	 */
	reqp->aio_req_fd = arg->aio_fildes;
	reqp->aio_req_sigqp = sqp;
	reqp->aio_req_iocb.iocb = NULL;
	reqp->aio_req_lio = NULL;
	reqp->aio_req_buf.b_file = vp;
	uio = reqp->aio_req.aio_uio;
	uio->uio_iovcnt = 1;
	uio->uio_iov->iov_base = (caddr_t)arg->aio_buf;
	uio->uio_iov->iov_len = arg->aio_nbytes;
	uio->uio_loffset = arg->aio_offset;
	*reqpp = reqp;
	return (0);
}

/*
 * Allocate p_aio struct.
 */
static aio_t *
aio_aiop_alloc(void)
{
	aio_t	*aiop;

	ASSERT(MUTEX_HELD(&curproc->p_lock));

	aiop = kmem_zalloc(sizeof (struct aio), KM_NOSLEEP);
	if (aiop) {
		mutex_init(&aiop->aio_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&aiop->aio_cleanupq_mutex, NULL, MUTEX_DEFAULT,
		    NULL);
		mutex_init(&aiop->aio_portq_mutex, NULL, MUTEX_DEFAULT, NULL);
	}
	return (aiop);
}

/*
 * Allocate an aio_req struct.
 */
static int
aio_req_alloc(aio_req_t **nreqp, aio_result_t *resultp)
{
	aio_req_t *reqp;
	aio_t *aiop = curproc->p_aio;

	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if ((reqp = aiop->aio_free) != NULL) {
		aiop->aio_free = reqp->aio_req_next;
		bzero(reqp, sizeof (*reqp));
	} else {
		/*
		 * Check whether memory is getting tight.
		 * This is a temporary mechanism to avoid memory
		 * exhaustion by a single process until we come up
		 * with a per process solution such as setrlimit().
		 */
		if (freemem < desfree)
			return (EAGAIN);
		reqp = kmem_zalloc(sizeof (struct aio_req_t), KM_NOSLEEP);
		if (reqp == NULL)
			return (EAGAIN);
	}
	reqp->aio_req.aio_uio = &reqp->aio_req_uio;
	reqp->aio_req.aio_uio->uio_iov = &reqp->aio_req_iov;
	reqp->aio_req.aio_private = reqp;
	reqp->aio_req_buf.b_offset = -1;
	reqp->aio_req_resultp = resultp;
	if (aio_hash_insert(reqp, aiop)) {
		reqp->aio_req_next = aiop->aio_free;
		aiop->aio_free = reqp;
		return (EBUSY);
	}
	*nreqp = reqp;
	return (0);
}

/*
 * Allocate an aio_lio_t struct.
 */
static int
aio_lio_alloc(aio_lio_t **head)
{
	aio_lio_t *liop;
	aio_t *aiop = curproc->p_aio;

	ASSERT(MUTEX_HELD(&aiop->aio_mutex));

	if ((liop = aiop->aio_lio_free) != NULL) {
		aiop->aio_lio_free = liop->lio_next;
	} else {
		/*
		 * Check whether memory is getting tight.
		 * This is a temporary mechanism to avoid memory
		 * exhaustion by a single process until we come up
		 * with a per process solution such as setrlimit().
		 */
		if (freemem < desfree)
			return (EAGAIN);

		liop = kmem_zalloc(sizeof (aio_lio_t), KM_NOSLEEP);
		if (liop == NULL)
			return (EAGAIN);
	}
	*head = liop;
	return (0);
}

/*
 * this is a special per-process thread that is only activated if
 * the process is unmapping a segment with outstanding aio. normally,
 * the process will have completed the aio before unmapping the
 * segment. If the process does unmap a segment with outstanding aio,
 * this special thread will guarentee that the locked pages due to
 * aphysio() are released, thereby permitting the segment to be
 * unmapped. In addition to this, the cleanup thread is woken up
 * during DR operations to release the locked pages.
 */

static int
aio_cleanup_thread(aio_t *aiop)
{
	proc_t *p = curproc;
	struct as *as = p->p_as;
	int poked = 0;
	kcondvar_t *cvp;
	int exit_flag = 0;
	int rqclnup = 0;

	sigfillset(&curthread->t_hold);
	sigdiffset(&curthread->t_hold, &cantmask);
	for (;;) {
		/*
		 * if a segment is being unmapped, and the current
		 * process's done queue is not empty, then every request
		 * on the doneq with locked resources should be forced
		 * to release their locks. By moving the doneq request
		 * to the cleanupq, aio_cleanup() will process the cleanupq,
		 * and place requests back onto the doneq. All requests
		 * processed by aio_cleanup() will have their physical
		 * resources unlocked.
		 */
		mutex_enter(&aiop->aio_mutex);
		if ((aiop->aio_flags & AIO_CLEANUP) == 0) {
			aiop->aio_flags |= AIO_CLEANUP;
			mutex_enter(&as->a_contents);
			if (aiop->aio_rqclnup) {
				aiop->aio_rqclnup = 0;
				rqclnup = 1;
			}
			mutex_exit(&as->a_contents);
			if (aiop->aio_doneq) {
				aio_req_t *doneqhead = aiop->aio_doneq;
				aiop->aio_doneq = NULL;
				aio_cleanupq_concat(aiop, doneqhead, AIO_DONEQ);
			}
		}
		mutex_exit(&aiop->aio_mutex);
		aio_cleanup(AIO_CLEANUP_THREAD);
		/*
		 * thread should block on the cleanupcv while
		 * AIO_CLEANUP is set.
		 */
		cvp = &aiop->aio_cleanupcv;
		mutex_enter(&aiop->aio_mutex);

		if (aiop->aio_pollq != NULL || aiop->aio_cleanupq != NULL ||
		    aiop->aio_notifyq != NULL ||
		    aiop->aio_portcleanupq != NULL) {
			mutex_exit(&aiop->aio_mutex);
			continue;
		}
		mutex_enter(&as->a_contents);

		/*
		 * AIO_CLEANUP determines when the cleanup thread
		 * should be active. This flag is set when
		 * the cleanup thread is awakened by as_unmap() or
		 * due to DR operations.
		 * The flag is cleared when the blocking as_unmap()
		 * that originally awakened us is allowed to
		 * complete. as_unmap() blocks when trying to
		 * unmap a segment that has SOFTLOCKed pages. when
		 * the segment's pages are all SOFTUNLOCKed,
		 * as->a_flags & AS_UNMAPWAIT should be zero.
		 *
		 * In case of cleanup request by DR, the flag is cleared
		 * once all the pending aio requests have been processed.
		 *
		 * The flag shouldn't be cleared right away if the
		 * cleanup thread was interrupted because the process
		 * is doing forkall(). This happens when cv_wait_sig()
		 * returns zero, because it was awakened by a pokelwps().
		 * If the process is not exiting, it must be doing forkall().
		 */
		if ((poked == 0) &&
		    ((!rqclnup && (AS_ISUNMAPWAIT(as) == 0)) ||
		    (aiop->aio_pending == 0))) {
			aiop->aio_flags &= ~(AIO_CLEANUP | AIO_CLEANUP_PORT);
			cvp = &as->a_cv;
			rqclnup = 0;
		}
		mutex_exit(&aiop->aio_mutex);
		if (poked) {
			/*
			 * If the process is exiting/killed, don't return
			 * immediately without waiting for pending I/O's
			 * and releasing the page locks.
			 */
			if (p->p_flag & (SEXITLWPS|SKILLED)) {
				/*
				 * If exit_flag is set, then it is
				 * safe to exit because we have released
				 * page locks of completed I/O's.
				 */
				if (exit_flag)
					break;

				mutex_exit(&as->a_contents);

				/*
				 * Wait for all the pending aio to complete.
				 */
				mutex_enter(&aiop->aio_mutex);
				aiop->aio_flags |= AIO_REQ_BLOCK;
				while (aiop->aio_pending != 0)
					cv_wait(&aiop->aio_cleanupcv,
					    &aiop->aio_mutex);
				mutex_exit(&aiop->aio_mutex);
				exit_flag = 1;
				continue;
			} else if (p->p_flag &
			    (SHOLDFORK|SHOLDFORK1|SHOLDWATCH)) {
				/*
				 * hold LWP until it
				 * is continued.
				 */
				mutex_exit(&as->a_contents);
				mutex_enter(&p->p_lock);
				stop(PR_SUSPENDED, SUSPEND_NORMAL);
				mutex_exit(&p->p_lock);
				poked = 0;
				continue;
			}
		} else {
			/*
			 * When started this thread will sleep on as->a_cv.
			 * as_unmap will awake this thread if the
			 * segment has SOFTLOCKed pages (poked = 0).
			 * 1. pokelwps() awakes this thread =>
			 *    break the loop to check SEXITLWPS, SHOLDFORK, etc
			 * 2. as_unmap awakes this thread =>
			 *    to break the loop it is necessary that
			 *    - AS_UNMAPWAIT is set (as_unmap is waiting for
			 *	memory to be unlocked)
			 *    - AIO_CLEANUP is not set
			 *	(if AIO_CLEANUP is set we have to wait for
			 *	pending requests. aio_done will send a signal
			 *	for every request which completes to continue
			 *	unmapping the corresponding address range)
			 * 3. A cleanup request will wake this thread up, ex.
			 *    by the DR operations. The aio_rqclnup flag will
			 *    be set.
			 */
			while (poked == 0) {
				/*
				 * The clean up requests that came in
				 * after we had just cleaned up, couldn't
				 * be causing the unmap thread to block - as
				 * unmap event happened first.
				 * Let aio_done() wake us up if it sees a need.
				 */
				if (aiop->aio_rqclnup &&
				    (aiop->aio_flags & AIO_CLEANUP) == 0)
					break;
				poked = !cv_wait_sig(cvp, &as->a_contents);
				if (AS_ISUNMAPWAIT(as) == 0)
					cv_signal(cvp);
				if (aiop->aio_outstanding != 0)
					break;
			}
		}
		mutex_exit(&as->a_contents);
	}
exit:
	mutex_exit(&as->a_contents);
	ASSERT((curproc->p_flag & (SEXITLWPS|SKILLED)));
	aston(curthread);	/* make thread do post_syscall */
	return (0);
}

/*
 * save a reference to a user's outstanding aio in a hash list.
 */
static int
aio_hash_insert(
	aio_req_t *aio_reqp,
	aio_t *aiop)
{
	long index;
	aio_result_t *resultp = aio_reqp->aio_req_resultp;
	aio_req_t *current;
	aio_req_t **nextp;

	index = AIO_HASH(resultp);
	nextp = &aiop->aio_hash[index];
	while ((current = *nextp) != NULL) {
		if (current->aio_req_resultp == resultp)
			return (DUPLICATE);
		nextp = &current->aio_hash_next;
	}
	*nextp = aio_reqp;
	aio_reqp->aio_hash_next = NULL;
	return (0);
}

static int
(*check_vp(struct vnode *vp, int mode))(vnode_t *, struct aio_req *,
    cred_t *)
{
	struct snode *sp;
	dev_t		dev;
	struct cb_ops  	*cb;
	major_t		major;
	int		(*aio_func)();

	dev = vp->v_rdev;
	major = getmajor(dev);

	/*
	 * return NULL for requests to files and STREAMs so
	 * that libaio takes care of them.
	 */
	if (vp->v_type == VCHR) {
		/* no stream device for kaio */
		if (STREAMSTAB(major)) {
			return (NULL);
		}
	} else {
		return (NULL);
	}

	/*
	 * Check old drivers which do not have async I/O entry points.
	 */
	if (devopsp[major]->devo_rev < 3)
		return (NULL);

	cb = devopsp[major]->devo_cb_ops;

	if (cb->cb_rev < 1)
		return (NULL);

	/*
	 * Check whether this device is a block device.
	 * Kaio is not supported for devices like tty.
	 */
	if (cb->cb_strategy == nodev || cb->cb_strategy == NULL)
		return (NULL);

	/*
	 * Clustering: If vnode is a PXFS vnode, then the device may be remote.
	 * We cannot call the driver directly. Instead return the
	 * PXFS functions.
	 */

	if (IS_PXFSVP(vp)) {
		if (mode & FREAD)
			return (clpxfs_aio_read);
		else
			return (clpxfs_aio_write);
	}
	if (mode & FREAD)
		aio_func = (cb->cb_aread == nodev) ? NULL : driver_aio_read;
	else
		aio_func = (cb->cb_awrite == nodev) ? NULL : driver_aio_write;

	/*
	 * Do we need this ?
	 * nodev returns ENXIO anyway.
	 */
	if (aio_func == nodev)
		return (NULL);

	sp = VTOS(vp);
	smark(sp, SACC);
	return (aio_func);
}

/*
 * Clustering: We want check_vp to return a function prototyped
 * correctly that will be common to both PXFS and regular case.
 * We define this intermediate function that will do the right
 * thing for driver cases.
 */

static int
driver_aio_write(vnode_t *vp, struct aio_req *aio, cred_t *cred_p)
{
	dev_t dev;
	struct cb_ops  	*cb;

	ASSERT(vp->v_type == VCHR);
	ASSERT(!IS_PXFSVP(vp));
	dev = VTOS(vp)->s_dev;
	ASSERT(STREAMSTAB(getmajor(dev)) == NULL);

	cb = devopsp[getmajor(dev)]->devo_cb_ops;

	ASSERT(cb->cb_awrite != nodev);
	return ((*cb->cb_awrite)(dev, aio, cred_p));
}

/*
 * Clustering: We want check_vp to return a function prototyped
 * correctly that will be common to both PXFS and regular case.
 * We define this intermediate function that will do the right
 * thing for driver cases.
 */

static int
driver_aio_read(vnode_t *vp, struct aio_req *aio, cred_t *cred_p)
{
	dev_t dev;
	struct cb_ops  	*cb;

	ASSERT(vp->v_type == VCHR);
	ASSERT(!IS_PXFSVP(vp));
	dev = VTOS(vp)->s_dev;
	ASSERT(!STREAMSTAB(getmajor(dev)));

	cb = devopsp[getmajor(dev)]->devo_cb_ops;

	ASSERT(cb->cb_aread != nodev);
	return ((*cb->cb_aread)(dev, aio, cred_p));
}

/*
 * This routine is called when a largefile call is made by a 32bit
 * process on a ILP32 or LP64 kernel. All 64bit processes are large
 * file by definition and will call alio() instead.
 */
static int
alioLF(
	int		mode_arg,
	void		*aiocb_arg,
	int		nent,
	void		*sigev)
{
	file_t		*fp;
	file_t		*prev_fp = NULL;
	int		prev_mode = -1;
	struct vnode	*vp;
	aio_lio_t	*head;
	aio_req_t	*reqp;
	aio_t		*aiop;
	caddr_t		cbplist;
	aiocb64_32_t	cb64;
	aiocb64_32_t	*aiocb = &cb64;
	aiocb64_32_t	*cbp;
	caddr32_t	*ucbp;
#ifdef _LP64
	aiocb_t		aiocb_n;
#endif
	struct sigevent32	sigevk;
	sigqueue_t	*sqp;
	int		(*aio_func)();
	int		mode;
	int		error = 0;
	int		aio_errors = 0;
	int		i;
	size_t		ssize;
	int		deadhead = 0;
	int		aio_notsupported = 0;
	int		lio_head_port;
	int		aio_port;
	int		aio_thread;
	port_kevent_t	*pkevtp = NULL;
	int		portused = 0;
	port_notify32_t	pnotify;
	int		event;

	aiop = curproc->p_aio;
	if (aiop == NULL || nent <= 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

	ASSERT(get_udatamodel() == DATAMODEL_ILP32);

	ssize = (sizeof (caddr32_t) * nent);
	cbplist = kmem_alloc(ssize, KM_SLEEP);
	ucbp = (caddr32_t *)cbplist;

	if (copyin(aiocb_arg, cbplist, ssize) ||
	    (sigev && copyin(sigev, &sigevk, sizeof (sigevk)))) {
		kmem_free(cbplist, ssize);
		return (EFAULT);
	}

	/* Event Ports  */
	if (sigev &&
	    (sigevk.sigev_notify == SIGEV_THREAD ||
	    sigevk.sigev_notify == SIGEV_PORT)) {
		if (sigevk.sigev_notify == SIGEV_THREAD) {
			pnotify.portnfy_port = sigevk.sigev_signo;
			pnotify.portnfy_user = sigevk.sigev_value.sival_ptr;
		} else if (copyin(
		    (void *)(uintptr_t)sigevk.sigev_value.sival_ptr,
		    &pnotify, sizeof (pnotify))) {
			kmem_free(cbplist, ssize);
			return (EFAULT);
		}
		error = port_alloc_event(pnotify.portnfy_port,
		    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO, &pkevtp);
		if (error) {
			if (error == ENOMEM || error == EAGAIN)
				error = EAGAIN;
			else
				error = EINVAL;
			kmem_free(cbplist, ssize);
			return (error);
		}
		lio_head_port = pnotify.portnfy_port;
		portused = 1;
	}

	/*
	 * a list head should be allocated if notification is
	 * enabled for this list.
	 */
	head = NULL;

	if (mode_arg == LIO_WAIT || sigev) {
		mutex_enter(&aiop->aio_mutex);
		error = aio_lio_alloc(&head);
		mutex_exit(&aiop->aio_mutex);
		if (error)
			goto done;
		deadhead = 1;
		head->lio_nent = nent;
		head->lio_refcnt = nent;
		head->lio_port = -1;
		head->lio_portkev = NULL;
		if (sigev && sigevk.sigev_notify == SIGEV_SIGNAL &&
		    sigevk.sigev_signo > 0 && sigevk.sigev_signo < NSIG) {
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_NOSLEEP);
			if (sqp == NULL) {
				error = EAGAIN;
				goto done;
			}
			sqp->sq_func = NULL;
			sqp->sq_next = NULL;
			sqp->sq_info.si_code = SI_ASYNCIO;
			sqp->sq_info.si_pid = curproc->p_pid;
			sqp->sq_info.si_ctid = PRCTID(curproc);
			sqp->sq_info.si_zoneid = getzoneid();
			sqp->sq_info.si_uid = crgetuid(curproc->p_cred);
			sqp->sq_info.si_signo = sigevk.sigev_signo;
			sqp->sq_info.si_value.sival_int =
			    sigevk.sigev_value.sival_int;
			head->lio_sigqp = sqp;
		} else {
			head->lio_sigqp = NULL;
		}
		if (pkevtp) {
			/*
			 * Prepare data to send when list of aiocb's
			 * has completed.
			 */
			port_init_event(pkevtp, (uintptr_t)sigev,
			    (void *)(uintptr_t)pnotify.portnfy_user,
			    NULL, head);
			pkevtp->portkev_events = AIOLIO64;
			head->lio_portkev = pkevtp;
			head->lio_port = pnotify.portnfy_port;
		}
	}

	for (i = 0; i < nent; i++, ucbp++) {

		cbp = (aiocb64_32_t *)(uintptr_t)*ucbp;
		/* skip entry if it can't be copied. */
		if (cbp == NULL || copyin(cbp, aiocb, sizeof (*aiocb))) {
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}

		/* skip if opcode for aiocb is LIO_NOP */
		mode = aiocb->aio_lio_opcode;
		if (mode == LIO_NOP) {
			cbp = NULL;
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}

		/* increment file descriptor's ref count. */
		if ((fp = getf(aiocb->aio_fildes)) == NULL) {
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * check the permission of the partition
		 */
		if ((fp->f_flag & mode) == 0) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * common case where requests are to the same fd
		 * for the same r/w operation
		 * for UFS, need to set EBADFD
		 */
		vp = fp->f_vnode;
		if (fp != prev_fp || mode != prev_mode) {
			aio_func = check_vp(vp, mode);
			if (aio_func == NULL) {
				prev_fp = NULL;
				releasef(aiocb->aio_fildes);
				lio_set_uerror(&cbp->aio_resultp, EBADFD);
				aio_notsupported++;
				if (head) {
					mutex_enter(&aiop->aio_mutex);
					head->lio_nent--;
					head->lio_refcnt--;
					mutex_exit(&aiop->aio_mutex);
				}
				continue;
			} else {
				prev_fp = fp;
				prev_mode = mode;
			}
		}

#ifdef	_LP64
		aiocb_LFton(aiocb, &aiocb_n);
		error = aio_req_setup(&reqp, aiop, &aiocb_n,
		    (aio_result_t *)&cbp->aio_resultp, vp, 0);
#else
		error = aio_req_setupLF(&reqp, aiop, aiocb,
		    (aio_result_t *)&cbp->aio_resultp, vp, 0);
#endif  /* _LP64 */
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		reqp->aio_req_lio = head;
		deadhead = 0;

		/*
		 * Set the errno field now before sending the request to
		 * the driver to avoid a race condition
		 */
		(void) suword32(&cbp->aio_resultp.aio_errno,
		    EINPROGRESS);

		reqp->aio_req_iocb.iocb32 = *ucbp;

		event = (mode == LIO_READ)? AIOAREAD64 : AIOAWRITE64;
		aio_port = (aiocb->aio_sigevent.sigev_notify == SIGEV_PORT);
		aio_thread = (aiocb->aio_sigevent.sigev_notify == SIGEV_THREAD);
		if (aio_port | aio_thread) {
			port_kevent_t *lpkevp;
			/*
			 * Prepare data to send with each aiocb completed.
			 */
			if (aio_port) {
				void *paddr = (void *)(uintptr_t)
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
				if (copyin(paddr, &pnotify, sizeof (pnotify)))
					error = EFAULT;
			} else {	/* aio_thread */
				pnotify.portnfy_port =
				    aiocb->aio_sigevent.sigev_signo;
				pnotify.portnfy_user =
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
			}
			if (error)
				/* EMPTY */;
			else if (pkevtp != NULL &&
			    pnotify.portnfy_port == lio_head_port)
				error = port_dup_event(pkevtp, &lpkevp,
				    PORT_ALLOC_DEFAULT);
			else
				error = port_alloc_event(pnotify.portnfy_port,
				    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO,
				    &lpkevp);
			if (error == 0) {
				port_init_event(lpkevp, (uintptr_t)*ucbp,
				    (void *)(uintptr_t)pnotify.portnfy_user,
				    aio_port_callback, reqp);
				lpkevp->portkev_events = event;
				reqp->aio_req_portkev = lpkevp;
				reqp->aio_req_port = pnotify.portnfy_port;
			}
		}

		/*
		 * send the request to driver.
		 */
		if (error == 0) {
			if (aiocb->aio_nbytes == 0) {
				clear_active_fd(aiocb->aio_fildes);
				aio_zerolen(reqp);
				continue;
			}
			error = (*aio_func)(vp, (aio_req_t *)&reqp->aio_req,
			    CRED());
		}

		/*
		 * the fd's ref count is not decremented until the IO has
		 * completed unless there was an error.
		 */
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			if (error == ENOTSUP)
				aio_notsupported++;
			else
				aio_errors++;
			lio_set_error(reqp, portused);
		} else {
			clear_active_fd(aiocb->aio_fildes);
		}
	}

	if (aio_notsupported) {
		error = ENOTSUP;
	} else if (aio_errors) {
		/*
		 * return EIO if any request failed
		 */
		error = EIO;
	}

	if (mode_arg == LIO_WAIT) {
		mutex_enter(&aiop->aio_mutex);
		while (head->lio_refcnt > 0) {
			if (!cv_wait_sig(&head->lio_notify, &aiop->aio_mutex)) {
				mutex_exit(&aiop->aio_mutex);
				error = EINTR;
				goto done;
			}
		}
		mutex_exit(&aiop->aio_mutex);
		alio_cleanup(aiop, (aiocb_t **)cbplist, nent, AIO_LARGEFILE);
	}

done:
	kmem_free(cbplist, ssize);
	if (deadhead) {
		if (head->lio_sigqp)
			kmem_free(head->lio_sigqp, sizeof (sigqueue_t));
		if (head->lio_portkev)
			port_free_event(head->lio_portkev);
		kmem_free(head, sizeof (aio_lio_t));
	}
	return (error);
}

#ifdef  _SYSCALL32_IMPL
static void
aiocb_LFton(aiocb64_32_t *src, aiocb_t *dest)
{
	dest->aio_fildes = src->aio_fildes;
	dest->aio_buf = (void *)(uintptr_t)src->aio_buf;
	dest->aio_nbytes = (size_t)src->aio_nbytes;
	dest->aio_offset = (off_t)src->aio_offset;
	dest->aio_reqprio = src->aio_reqprio;
	dest->aio_sigevent.sigev_notify = src->aio_sigevent.sigev_notify;
	dest->aio_sigevent.sigev_signo = src->aio_sigevent.sigev_signo;

	/*
	 * See comment in sigqueue32() on handling of 32-bit
	 * sigvals in a 64-bit kernel.
	 */
	dest->aio_sigevent.sigev_value.sival_int =
	    (int)src->aio_sigevent.sigev_value.sival_int;
	dest->aio_sigevent.sigev_notify_function = (void (*)(union sigval))
	    (uintptr_t)src->aio_sigevent.sigev_notify_function;
	dest->aio_sigevent.sigev_notify_attributes = (pthread_attr_t *)
	    (uintptr_t)src->aio_sigevent.sigev_notify_attributes;
	dest->aio_sigevent.__sigev_pad2 = src->aio_sigevent.__sigev_pad2;
	dest->aio_lio_opcode = src->aio_lio_opcode;
	dest->aio_state = src->aio_state;
	dest->aio__pad[0] = src->aio__pad[0];
}
#endif

/*
 * This function is used only for largefile calls made by
 * 32 bit applications.
 */
static int
aio_req_setupLF(
	aio_req_t	**reqpp,
	aio_t		*aiop,
	aiocb64_32_t	*arg,
	aio_result_t	*resultp,
	vnode_t		*vp,
	int		old_solaris_req)
{
	sigqueue_t	*sqp = NULL;
	aio_req_t	*reqp;
	struct uio	*uio;
	struct sigevent32 *sigev;
	int 		error;

	sigev = &arg->aio_sigevent;
	if (sigev->sigev_notify == SIGEV_SIGNAL &&
	    sigev->sigev_signo > 0 && sigev->sigev_signo < NSIG) {
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_NOSLEEP);
		if (sqp == NULL)
			return (EAGAIN);
		sqp->sq_func = NULL;
		sqp->sq_next = NULL;
		sqp->sq_info.si_code = SI_ASYNCIO;
		sqp->sq_info.si_pid = curproc->p_pid;
		sqp->sq_info.si_ctid = PRCTID(curproc);
		sqp->sq_info.si_zoneid = getzoneid();
		sqp->sq_info.si_uid = crgetuid(curproc->p_cred);
		sqp->sq_info.si_signo = sigev->sigev_signo;
		sqp->sq_info.si_value.sival_int = sigev->sigev_value.sival_int;
	}

	mutex_enter(&aiop->aio_mutex);

	if (aiop->aio_flags & AIO_REQ_BLOCK) {
		mutex_exit(&aiop->aio_mutex);
		if (sqp)
			kmem_free(sqp, sizeof (sigqueue_t));
		return (EIO);
	}
	/*
	 * get an aio_reqp from the free list or allocate one
	 * from dynamic memory.
	 */
	if (error = aio_req_alloc(&reqp, resultp)) {
		mutex_exit(&aiop->aio_mutex);
		if (sqp)
			kmem_free(sqp, sizeof (sigqueue_t));
		return (error);
	}
	aiop->aio_pending++;
	aiop->aio_outstanding++;
	reqp->aio_req_flags = AIO_PENDING;
	if (old_solaris_req) {
		/* this is an old solaris aio request */
		reqp->aio_req_flags |= AIO_SOLARIS;
		aiop->aio_flags |= AIO_SOLARIS_REQ;
	}
	if (sigev->sigev_notify == SIGEV_THREAD ||
	    sigev->sigev_notify == SIGEV_PORT)
		aio_enq(&aiop->aio_portpending, reqp, 0);
	mutex_exit(&aiop->aio_mutex);
	/*
	 * initialize aio request.
	 */
	reqp->aio_req_fd = arg->aio_fildes;
	reqp->aio_req_sigqp = sqp;
	reqp->aio_req_iocb.iocb = NULL;
	reqp->aio_req_lio = NULL;
	reqp->aio_req_buf.b_file = vp;
	uio = reqp->aio_req.aio_uio;
	uio->uio_iovcnt = 1;
	uio->uio_iov->iov_base = (caddr_t)(uintptr_t)arg->aio_buf;
	uio->uio_iov->iov_len = arg->aio_nbytes;
	uio->uio_loffset = arg->aio_offset;
	*reqpp = reqp;
	return (0);
}

/*
 * This routine is called when a non largefile call is made by a 32bit
 * process on a ILP32 or LP64 kernel.
 */
static int
alio32(
	int		mode_arg,
	void		*aiocb_arg,
	int		nent,
	void		*sigev)
{
	file_t		*fp;
	file_t		*prev_fp = NULL;
	int		prev_mode = -1;
	struct vnode	*vp;
	aio_lio_t	*head;
	aio_req_t	*reqp;
	aio_t		*aiop;
	caddr_t		cbplist;
	aiocb_t		cb;
	aiocb_t		*aiocb = &cb;
#ifdef	_LP64
	aiocb32_t	*cbp;
	caddr32_t	*ucbp;
	aiocb32_t	cb32;
	aiocb32_t	*aiocb32 = &cb32;
	struct sigevent32	sigevk;
#else
	aiocb_t		*cbp, **ucbp;
	struct sigevent	sigevk;
#endif
	sigqueue_t	*sqp;
	int		(*aio_func)();
	int		mode;
	int		error = 0;
	int		aio_errors = 0;
	int		i;
	size_t		ssize;
	int		deadhead = 0;
	int		aio_notsupported = 0;
	int		lio_head_port;
	int		aio_port;
	int		aio_thread;
	port_kevent_t	*pkevtp = NULL;
	int		portused = 0;
#ifdef	_LP64
	port_notify32_t	pnotify;
#else
	port_notify_t	pnotify;
#endif
	int		event;

	aiop = curproc->p_aio;
	if (aiop == NULL || nent <= 0 || nent > _AIO_LISTIO_MAX)
		return (EINVAL);

#ifdef	_LP64
	ssize = (sizeof (caddr32_t) * nent);
#else
	ssize = (sizeof (aiocb_t *) * nent);
#endif
	cbplist = kmem_alloc(ssize, KM_SLEEP);
	ucbp = (void *)cbplist;

	if (copyin(aiocb_arg, cbplist, ssize) ||
	    (sigev && copyin(sigev, &sigevk, sizeof (struct sigevent32)))) {
		kmem_free(cbplist, ssize);
		return (EFAULT);
	}

	/* Event Ports  */
	if (sigev &&
	    (sigevk.sigev_notify == SIGEV_THREAD ||
	    sigevk.sigev_notify == SIGEV_PORT)) {
		if (sigevk.sigev_notify == SIGEV_THREAD) {
			pnotify.portnfy_port = sigevk.sigev_signo;
			pnotify.portnfy_user = sigevk.sigev_value.sival_ptr;
		} else if (copyin(
		    (void *)(uintptr_t)sigevk.sigev_value.sival_ptr,
		    &pnotify, sizeof (pnotify))) {
			kmem_free(cbplist, ssize);
			return (EFAULT);
		}
		error = port_alloc_event(pnotify.portnfy_port,
		    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO, &pkevtp);
		if (error) {
			if (error == ENOMEM || error == EAGAIN)
				error = EAGAIN;
			else
				error = EINVAL;
			kmem_free(cbplist, ssize);
			return (error);
		}
		lio_head_port = pnotify.portnfy_port;
		portused = 1;
	}

	/*
	 * a list head should be allocated if notification is
	 * enabled for this list.
	 */
	head = NULL;

	if (mode_arg == LIO_WAIT || sigev) {
		mutex_enter(&aiop->aio_mutex);
		error = aio_lio_alloc(&head);
		mutex_exit(&aiop->aio_mutex);
		if (error)
			goto done;
		deadhead = 1;
		head->lio_nent = nent;
		head->lio_refcnt = nent;
		head->lio_port = -1;
		head->lio_portkev = NULL;
		if (sigev && sigevk.sigev_notify == SIGEV_SIGNAL &&
		    sigevk.sigev_signo > 0 && sigevk.sigev_signo < NSIG) {
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_NOSLEEP);
			if (sqp == NULL) {
				error = EAGAIN;
				goto done;
			}
			sqp->sq_func = NULL;
			sqp->sq_next = NULL;
			sqp->sq_info.si_code = SI_ASYNCIO;
			sqp->sq_info.si_pid = curproc->p_pid;
			sqp->sq_info.si_ctid = PRCTID(curproc);
			sqp->sq_info.si_zoneid = getzoneid();
			sqp->sq_info.si_uid = crgetuid(curproc->p_cred);
			sqp->sq_info.si_signo = sigevk.sigev_signo;
			sqp->sq_info.si_value.sival_int =
			    sigevk.sigev_value.sival_int;
			head->lio_sigqp = sqp;
		} else {
			head->lio_sigqp = NULL;
		}
		if (pkevtp) {
			/*
			 * Prepare data to send when list of aiocb's has
			 * completed.
			 */
			port_init_event(pkevtp, (uintptr_t)sigev,
			    (void *)(uintptr_t)pnotify.portnfy_user,
			    NULL, head);
			pkevtp->portkev_events = AIOLIO;
			head->lio_portkev = pkevtp;
			head->lio_port = pnotify.portnfy_port;
		}
	}

	for (i = 0; i < nent; i++, ucbp++) {

		/* skip entry if it can't be copied. */
#ifdef	_LP64
		cbp = (aiocb32_t *)(uintptr_t)*ucbp;
		if (cbp == NULL || copyin(cbp, aiocb32, sizeof (*aiocb32)))
#else
		cbp = (aiocb_t *)*ucbp;
		if (cbp == NULL || copyin(cbp, aiocb, sizeof (*aiocb)))
#endif
		{
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}
#ifdef	_LP64
		/*
		 * copy 32 bit structure into 64 bit structure
		 */
		aiocb_32ton(aiocb32, aiocb);
#endif /* _LP64 */

		/* skip if opcode for aiocb is LIO_NOP */
		mode = aiocb->aio_lio_opcode;
		if (mode == LIO_NOP) {
			cbp = NULL;
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			continue;
		}

		/* increment file descriptor's ref count. */
		if ((fp = getf(aiocb->aio_fildes)) == NULL) {
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * check the permission of the partition
		 */
		if ((fp->f_flag & mode) == 0) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, EBADF);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		/*
		 * common case where requests are to the same fd
		 * for the same r/w operation
		 * for UFS, need to set EBADFD
		 */
		vp = fp->f_vnode;
		if (fp != prev_fp || mode != prev_mode) {
			aio_func = check_vp(vp, mode);
			if (aio_func == NULL) {
				prev_fp = NULL;
				releasef(aiocb->aio_fildes);
				lio_set_uerror(&cbp->aio_resultp, EBADFD);
				aio_notsupported++;
				if (head) {
					mutex_enter(&aiop->aio_mutex);
					head->lio_nent--;
					head->lio_refcnt--;
					mutex_exit(&aiop->aio_mutex);
				}
				continue;
			} else {
				prev_fp = fp;
				prev_mode = mode;
			}
		}

		error = aio_req_setup(&reqp, aiop, aiocb,
		    (aio_result_t *)&cbp->aio_resultp, vp, 0);
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			aio_errors++;
			continue;
		}

		reqp->aio_req_lio = head;
		deadhead = 0;

		/*
		 * Set the errno field now before sending the request to
		 * the driver to avoid a race condition
		 */
		(void) suword32(&cbp->aio_resultp.aio_errno,
		    EINPROGRESS);

		reqp->aio_req_iocb.iocb32 = (caddr32_t)(uintptr_t)cbp;

		event = (mode == LIO_READ)? AIOAREAD : AIOAWRITE;
		aio_port = (aiocb->aio_sigevent.sigev_notify == SIGEV_PORT);
		aio_thread = (aiocb->aio_sigevent.sigev_notify == SIGEV_THREAD);
		if (aio_port | aio_thread) {
			port_kevent_t *lpkevp;
			/*
			 * Prepare data to send with each aiocb completed.
			 */
#ifdef _LP64
			if (aio_port) {
				void *paddr = (void  *)(uintptr_t)
				    aiocb32->aio_sigevent.sigev_value.sival_ptr;
				if (copyin(paddr, &pnotify, sizeof (pnotify)))
					error = EFAULT;
			} else {	/* aio_thread */
				pnotify.portnfy_port =
				    aiocb32->aio_sigevent.sigev_signo;
				pnotify.portnfy_user =
				    aiocb32->aio_sigevent.sigev_value.sival_ptr;
			}
#else
			if (aio_port) {
				void *paddr =
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
				if (copyin(paddr, &pnotify, sizeof (pnotify)))
					error = EFAULT;
			} else {	/* aio_thread */
				pnotify.portnfy_port =
				    aiocb->aio_sigevent.sigev_signo;
				pnotify.portnfy_user =
				    aiocb->aio_sigevent.sigev_value.sival_ptr;
			}
#endif
			if (error)
				/* EMPTY */;
			else if (pkevtp != NULL &&
			    pnotify.portnfy_port == lio_head_port)
				error = port_dup_event(pkevtp, &lpkevp,
				    PORT_ALLOC_DEFAULT);
			else
				error = port_alloc_event(pnotify.portnfy_port,
				    PORT_ALLOC_DEFAULT, PORT_SOURCE_AIO,
				    &lpkevp);
			if (error == 0) {
				port_init_event(lpkevp, (uintptr_t)cbp,
				    (void *)(uintptr_t)pnotify.portnfy_user,
				    aio_port_callback, reqp);
				lpkevp->portkev_events = event;
				reqp->aio_req_portkev = lpkevp;
				reqp->aio_req_port = pnotify.portnfy_port;
			}
		}

		/*
		 * send the request to driver.
		 */
		if (error == 0) {
			if (aiocb->aio_nbytes == 0) {
				clear_active_fd(aiocb->aio_fildes);
				aio_zerolen(reqp);
				continue;
			}
			error = (*aio_func)(vp, (aio_req_t *)&reqp->aio_req,
			    CRED());
		}

		/*
		 * the fd's ref count is not decremented until the IO has
		 * completed unless there was an error.
		 */
		if (error) {
			releasef(aiocb->aio_fildes);
			lio_set_uerror(&cbp->aio_resultp, error);
			if (head) {
				mutex_enter(&aiop->aio_mutex);
				head->lio_nent--;
				head->lio_refcnt--;
				mutex_exit(&aiop->aio_mutex);
			}
			if (error == ENOTSUP)
				aio_notsupported++;
			else
				aio_errors++;
			lio_set_error(reqp, portused);
		} else {
			clear_active_fd(aiocb->aio_fildes);
		}
	}

	if (aio_notsupported) {
		error = ENOTSUP;
	} else if (aio_errors) {
		/*
		 * return EIO if any request failed
		 */
		error = EIO;
	}

	if (mode_arg == LIO_WAIT) {
		mutex_enter(&aiop->aio_mutex);
		while (head->lio_refcnt > 0) {
			if (!cv_wait_sig(&head->lio_notify, &aiop->aio_mutex)) {
				mutex_exit(&aiop->aio_mutex);
				error = EINTR;
				goto done;
			}
		}
		mutex_exit(&aiop->aio_mutex);
		alio_cleanup(aiop, (aiocb_t **)cbplist, nent, AIO_32);
	}

done:
	kmem_free(cbplist, ssize);
	if (deadhead) {
		if (head->lio_sigqp)
			kmem_free(head->lio_sigqp, sizeof (sigqueue_t));
		if (head->lio_portkev)
			port_free_event(head->lio_portkev);
		kmem_free(head, sizeof (aio_lio_t));
	}
	return (error);
}


#ifdef  _SYSCALL32_IMPL
void
aiocb_32ton(aiocb32_t *src, aiocb_t *dest)
{
	dest->aio_fildes = src->aio_fildes;
	dest->aio_buf = (caddr_t)(uintptr_t)src->aio_buf;
	dest->aio_nbytes = (size_t)src->aio_nbytes;
	dest->aio_offset = (off_t)src->aio_offset;
	dest->aio_reqprio = src->aio_reqprio;
	dest->aio_sigevent.sigev_notify = src->aio_sigevent.sigev_notify;
	dest->aio_sigevent.sigev_signo = src->aio_sigevent.sigev_signo;

	/*
	 * See comment in sigqueue32() on handling of 32-bit
	 * sigvals in a 64-bit kernel.
	 */
	dest->aio_sigevent.sigev_value.sival_int =
	    (int)src->aio_sigevent.sigev_value.sival_int;
	dest->aio_sigevent.sigev_notify_function = (void (*)(union sigval))
	    (uintptr_t)src->aio_sigevent.sigev_notify_function;
	dest->aio_sigevent.sigev_notify_attributes = (pthread_attr_t *)
	    (uintptr_t)src->aio_sigevent.sigev_notify_attributes;
	dest->aio_sigevent.__sigev_pad2 = src->aio_sigevent.__sigev_pad2;
	dest->aio_lio_opcode = src->aio_lio_opcode;
	dest->aio_state = src->aio_state;
	dest->aio__pad[0] = src->aio__pad[0];
}
#endif /* _SYSCALL32_IMPL */

/*
 * aio_port_callback() is called just before the event is retrieved from the
 * port. The task of this callback function is to finish the work of the
 * transaction for the application, it means :
 * - copyout transaction data to the application
 *	(this thread is running in the right process context)
 * - keep trace of the transaction (update of counters).
 * - free allocated buffers
 * The aiocb pointer is the object element of the port_kevent_t structure.
 *
 * flag :
 *	PORT_CALLBACK_DEFAULT : do copyout and free resources
 *	PORT_CALLBACK_CLOSE   : don't do copyout, free resources
 */

/*ARGSUSED*/
int
aio_port_callback(void *arg, int *events, pid_t pid, int flag, void *evp)
{
	aio_t		*aiop = curproc->p_aio;
	aio_req_t	*reqp = arg;
	struct	iovec	*iov;
	struct	buf	*bp;
	void		*resultp;

	if (pid != curproc->p_pid) {
		/* wrong proc !!, can not deliver data here ... */
		return (EACCES);
	}

	mutex_enter(&aiop->aio_portq_mutex);
	reqp->aio_req_portkev = NULL;
	aio_req_remove_portq(aiop, reqp); /* remove request from portq */
	mutex_exit(&aiop->aio_portq_mutex);
	aphysio_unlock(reqp);		/* unlock used pages */
	mutex_enter(&aiop->aio_mutex);
	if (reqp->aio_req_flags & AIO_COPYOUTDONE) {
		aio_req_free_port(aiop, reqp);	/* back to free list */
		mutex_exit(&aiop->aio_mutex);
		return (0);
	}

	iov = reqp->aio_req_uio.uio_iov;
	bp = &reqp->aio_req_buf;
	resultp = (void *)reqp->aio_req_resultp;
	aio_req_free_port(aiop, reqp);	/* request struct back to free list */
	mutex_exit(&aiop->aio_mutex);
	if (flag == PORT_CALLBACK_DEFAULT)
		aio_copyout_result_port(iov, bp, resultp);
	return (0);
}

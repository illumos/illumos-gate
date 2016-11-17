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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * The illumos kernel provides two clock backends: CLOCK_REALTIME, the
 * adjustable system wall clock; and CLOCK_HIGHRES, the monotonically
 * increasing time source that is not subject to drift or adjustment.  By
 * contrast, the Linux kernel is furnished with an overabundance of narrowly
 * differentiated clock types.
 *
 * Fortunately, most of the commonly used Linux clock types are either similar
 * enough to the native clock backends that they can be directly mapped, or
 * represent queries to the per-process and per-LWP microstate counters.
 *
 * CLOCK_BOOTTIME is identical to CLOCK_MONOTONIC, except that it takes into
 * account time that the system is suspended. Since that is uninteresting to
 * us, we treat it the same.
 */

#include <sys/time.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>
#include <lx_signum.h>

/*
 * From "uts/common/os/timer.c":
 */
extern int clock_settime(clockid_t, timespec_t *);
extern int clock_gettime(clockid_t, timespec_t *);
extern int clock_getres(clockid_t, timespec_t *);
extern int nanosleep(timespec_t *, timespec_t *);


static int lx_emul_clock_getres(clockid_t, timespec_t *);
static int lx_emul_clock_gettime(clockid_t, timespec_t *);
static int lx_emul_clock_settime(clockid_t, timespec_t *);

typedef struct lx_clock_backend {
	clockid_t lclk_ntv_id;
	int (*lclk_clock_getres)(clockid_t, timespec_t *);
	int (*lclk_clock_gettime)(clockid_t, timespec_t *);
	int (*lclk_clock_settime)(clockid_t, timespec_t *);
} lx_clock_backend_t;

/*
 * NOTE: The Linux man pages state this structure is obsolete and is
 * unsupported, so it is declared here for sizing purposes only.
 */
struct lx_timezone {
	int tz_minuteswest;	/* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};

/*
 * Use the native clock_* system call implementation, but with a translated
 * clock identifier:
 */
#define	NATIVE(ntv_id)							\
	{ ntv_id, clock_getres, clock_gettime, clock_settime }

/*
 * This backend is not supported, so we provide an emulation handler:
 */
#define	EMUL(ntv_id)							\
	{ ntv_id, lx_emul_clock_getres, lx_emul_clock_gettime,		\
	    lx_emul_clock_settime }

static lx_clock_backend_t lx_clock_backends[] = {
	NATIVE(CLOCK_REALTIME),		/* LX_CLOCK_REALTIME */
	NATIVE(CLOCK_HIGHRES),		/* LX_CLOCK_MONOTONIC */
	EMUL(CLOCK_PROCESS_CPUTIME_ID),	/* LX_CLOCK_PROCESS_CPUTIME_ID */
	EMUL(CLOCK_THREAD_CPUTIME_ID),	/* LX_CLOCK_THREAD_CPUTIME_ID */
	NATIVE(CLOCK_HIGHRES),		/* LX_CLOCK_MONOTONIC_RAW */
	NATIVE(CLOCK_REALTIME),		/* LX_CLOCK_REALTIME_COARSE */
	NATIVE(CLOCK_HIGHRES),		/* LX_CLOCK_MONOTONIC_COARSE */
	NATIVE(CLOCK_HIGHRES)		/* LX_CLOCK_BOOTTIME */
};

#define	LX_CLOCK_MAX \
	(sizeof (lx_clock_backends) / sizeof (lx_clock_backends[0]))
#define	LX_CLOCK_BACKEND(clk) (((clk) < LX_CLOCK_MAX && (clk) >= 0) ? \
	&lx_clock_backends[(clk)] : NULL)

/*
 * Linux defines the size of the sigevent structure to be 64 bytes.  In order
 * to meet that definition, the trailing union includes a member which pads it
 * out to the desired length for the given architecture.
 */
#define	LX_SIGEV_PAD_SIZE	((64 - \
	(sizeof (int) * 2 + sizeof (union sigval))) / sizeof (int))

typedef struct {
	union sigval	lx_sigev_value;
	int		lx_sigev_signo;
	int		lx_sigev_notify;
	union {
		int	lx_pad[LX_SIGEV_PAD_SIZE];
		int	lx_tid;
		struct {
			void (*lx_notify_function)(union sigval);
			void *lx_notify_attribute;
		} lx_sigev_thread;
	} lx_sigev_un;
} lx_sigevent_t;


#ifdef _SYSCALL32_IMPL

#define	LX_SIGEV32_PAD_SIZE	((64 - \
	(sizeof (int) * 2 + sizeof (union sigval32))) / sizeof (int))

typedef struct {
	union sigval32	lx_sigev_value;
	int		lx_sigev_signo;
	int		lx_sigev_notify;
	union {
		int	lx_pad[LX_SIGEV32_PAD_SIZE];
		int	lx_tid;
		struct {
			caddr32_t lx_notify_function;
			caddr32_t lx_notify_attribute;
		} lx_sigev_thread;
	} lx_sigev_un;
} lx_sigevent32_t;

#endif /* _SYSCALL32_IMPL */

#define	LX_SIGEV_SIGNAL		0
#define	LX_SIGEV_NONE		1
#define	LX_SIGEV_THREAD		2
#define	LX_SIGEV_THREAD_ID	4

/*
 * Access private SIGEV_THREAD_ID callback state in itimer_t
 */
#define	LX_SIGEV_THREAD_ID_LPID(it)	((it)->it_cb_data[0])
#define	LX_SIGEV_THREAD_ID_TID(it)	((it)->it_cb_data[1])


/* ARGSUSED */
static int
lx_emul_clock_settime(clockid_t clock, timespec_t *tp)
{
	return (set_errno(EINVAL));
}

static int
lx_emul_clock_gettime(clockid_t clock, timespec_t *tp)
{
	timespec_t t;

	switch (clock) {
	case CLOCK_PROCESS_CPUTIME_ID: {
		proc_t *p = ttoproc(curthread);
		hrtime_t snsecs, unsecs;

		/*
		 * Based on getrusage() in "rusagesys.c":
		 */
		mutex_enter(&p->p_lock);
		unsecs = mstate_aggr_state(p, LMS_USER);
		snsecs = mstate_aggr_state(p, LMS_SYSTEM);
		mutex_exit(&p->p_lock);

		hrt2ts(unsecs + snsecs, &t);
		break;
	}

	case CLOCK_THREAD_CPUTIME_ID: {
		klwp_t *lwp = ttolwp(curthread);
		struct mstate *ms = &lwp->lwp_mstate;
		hrtime_t snsecs, unsecs;

		/*
		 * Based on getrusage_lwp() in "rusagesys.c":
		 */
		unsecs = ms->ms_acct[LMS_USER];
		snsecs = ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];

		scalehrtime(&unsecs);
		scalehrtime(&snsecs);

		hrt2ts(unsecs + snsecs, &t);
		break;
	}

	default:
		return (set_errno(EINVAL));
	}

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		timespec32_t t32;

		if (TIMESPEC_OVERFLOW(&t)) {
			return (set_errno(EOVERFLOW));
		}
		TIMESPEC_TO_TIMESPEC32(&t32, &t);

		if (copyout(&t32, tp, sizeof (t32)) != 0) {
			return (set_errno(EFAULT));
		}

		return (0);
	}
#endif

	if (copyout(&t, tp, sizeof (t)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}

static int
lx_emul_clock_getres(clockid_t clock, timespec_t *tp)
{
	timespec_t t;

	if (tp == NULL) {
		return (0);
	}

	switch (clock) {
	case CLOCK_PROCESS_CPUTIME_ID:
	case CLOCK_THREAD_CPUTIME_ID:
		/*
		 * These clock backends return microstate accounting values for
		 * the LWP or the entire process.  The Linux kernel claims they
		 * have nanosecond resolution; so will we.
		 */
		t.tv_sec = 0;
		t.tv_nsec = 1;
		break;

	default:
		return (set_errno(EINVAL));
	}

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		timespec32_t t32;

		if (TIMESPEC_OVERFLOW(&t)) {
			return (set_errno(EOVERFLOW));
		}
		TIMESPEC_TO_TIMESPEC32(&t32, &t);

		if (copyout(&t32, tp, sizeof (t32)) != 0) {
			return (set_errno(EFAULT));
		}

		return (0);
	}
#endif

	if (copyout(&t, tp, sizeof (t)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}

static void
lx_clock_unsupported(int clock)
{
	char buf[100];

	(void) snprintf(buf, sizeof (buf), "unsupported clock: %d", clock);
	lx_unsupported(buf);
}

long
lx_clock_settime(int clock, timespec_t *tp)
{
	lx_clock_backend_t *backend;

	if ((backend = LX_CLOCK_BACKEND(clock)) == NULL) {
		lx_clock_unsupported(clock);
		return (set_errno(EINVAL));
	}

	return (backend->lclk_clock_settime(backend->lclk_ntv_id, tp));
}

long
lx_clock_gettime(int clock, timespec_t *tp)
{
	lx_clock_backend_t *backend;

	if ((backend = LX_CLOCK_BACKEND(clock)) == NULL) {
		lx_clock_unsupported(clock);
		return (set_errno(EINVAL));
	}

	return (backend->lclk_clock_gettime(backend->lclk_ntv_id, tp));
}

long
lx_clock_getres(int clock, timespec_t *tp)
{
	lx_clock_backend_t *backend;

	if ((backend = LX_CLOCK_BACKEND(clock)) == NULL) {
		lx_clock_unsupported(clock);
		return (set_errno(EINVAL));
	}

	/*
	 * It is important this check is performed after the clock
	 * check. Both glibc and musl, in their clock_getcpuclockid(),
	 * use clock_getres() with a NULL tp to validate a clock
	 * value. Performing the tp check before the clock check could
	 * indicate a valid clock to libc when it shouldn't.
	 */
	if (tp == NULL) {
		return (0);
	}

	return (backend->lclk_clock_getres(backend->lclk_ntv_id, tp));
}

static int
lx_ltos_sigev(lx_sigevent_t *lev, struct sigevent *sev)
{
	bzero(sev, sizeof (*sev));

	switch (lev->lx_sigev_notify) {
	case LX_SIGEV_NONE:
		sev->sigev_notify = SIGEV_NONE;
		break;

	case LX_SIGEV_SIGNAL:
	case LX_SIGEV_THREAD_ID:
		sev->sigev_notify = SIGEV_SIGNAL;
		break;

	case LX_SIGEV_THREAD:
		/*
		 * Just as in illumos, SIGEV_THREAD handling is performed in
		 * userspace with the help of SIGEV_SIGNAL/SIGEV_THREAD_ID.
		 *
		 * It's not expected to make an appearance in the syscall.
		 */
	default:
		return (EINVAL);
	}

	sev->sigev_signo = lx_ltos_signo(lev->lx_sigev_signo, 0);
	sev->sigev_value = lev->lx_sigev_value;

	/* Ensure SIGEV_SIGNAL has a valid signo to work with. */
	if (sev->sigev_notify == SIGEV_SIGNAL && sev->sigev_signo == 0) {
		return (EINVAL);
	}
	return (0);
}

static int
lx_sigev_copyin(lx_sigevent_t *userp, lx_sigevent_t *levp)
{
#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		lx_sigevent32_t lev32;

		if (copyin(userp, &lev32, sizeof (lev32)) != 0) {
			return (EFAULT);
		}
		levp->lx_sigev_value.sival_int = lev32.lx_sigev_value.sival_int;
		levp->lx_sigev_signo = lev32.lx_sigev_signo;
		levp->lx_sigev_notify = lev32.lx_sigev_notify;
		levp->lx_sigev_un.lx_tid = lev32.lx_sigev_un.lx_tid;
	} else
#endif /* _SYSCALL32_IMPL */
	{
		if (copyin(userp, levp, sizeof (lx_sigevent_t)) != 0) {
			return (EFAULT);
		}
	}
	return (0);
}

static void
lx_sigev_thread_fire(itimer_t *it)
{
	proc_t *p = it->it_proc;
	pid_t lpid = (pid_t)LX_SIGEV_THREAD_ID_LPID(it);
	id_t tid = (id_t)LX_SIGEV_THREAD_ID_TID(it);
	lwpdir_t *ld;

	ASSERT(MUTEX_HELD(&it->it_mutex));
	ASSERT(it->it_pending == 0);
	ASSERT(it->it_flags & IT_SIGNAL);
	ASSERT(MUTEX_HELD(&p->p_lock));

	ld = lwp_hash_lookup(p, tid);
	if (ld != NULL) {
		lx_lwp_data_t *lwpd;
		kthread_t *t;

		t = ld->ld_entry->le_thread;
		lwpd = ttolxlwp(t);
		if (lwpd != NULL && lwpd->br_pid == lpid) {
			/*
			 * A thread matching the LX pid is still present in the
			 * process.  Send a targeted signal as requested.
			 */
			it->it_pending = 1;
			mutex_exit(&it->it_mutex);
			sigaddqa(p, t, it->it_sigq);
			return;
		}
	}

	mutex_exit(&it->it_mutex);
}

long
lx_timer_create(int clock, lx_sigevent_t *sevp, timer_t *tidp)
{
	int error;
	lx_sigevent_t lev;
	struct sigevent sev;
	clock_backend_t *backend = NULL;
	proc_t *p = curproc;
	itimer_t *itp;
	timer_t tid;

	if (clock == -2) {
		/*
		 * A change was made to the old userspace timer emulation to
		 * handle this specific clock ID for MapR.  It was wrongly
		 * mapped to CLOCK_REALTIME rather than CLOCK_THREAD_CPUTIME_ID
		 * which it maps to.  Until the CLOCK_*_CPUTIME_ID timers can
		 * be emulated, the admittedly incorrect mapping will remain.
		 */
		backend = clock_get_backend(CLOCK_REALTIME);
	} else {
		lx_clock_backend_t *lback = LX_CLOCK_BACKEND(clock);

		if (lback != NULL) {
			backend = clock_get_backend(lback->lclk_ntv_id);
		}
	}
	if (backend == NULL) {
		return (set_errno(EINVAL));
	}

	/* We have to convert the Linux sigevent layout to the illumos layout */
	if (sevp != NULL) {
		if ((error = lx_sigev_copyin(sevp, &lev)) != 0) {
			return (set_errno(error));
		}
		if ((error = lx_ltos_sigev(&lev, &sev)) != 0) {
			return (set_errno(error));
		}
	} else {
		bzero(&sev, sizeof (sev));
		sev.sigev_notify = SIGEV_SIGNAL;
		sev.sigev_signo = SIGALRM;
	}

	if ((error = timer_setup(backend, &sev, NULL, &itp, &tid)) != 0) {
		return (set_errno(error));
	}

	/*
	 * The SIGEV_THREAD_ID notification method in Linux allows the caller
	 * to target a specific thread to receive the signal.  The IT_CALLBACK
	 * timer functionality is used to fulfill this need.  After translating
	 * the LX pid to a SunOS thread ID (ensuring it exists in the current
	 * process), those IDs are attached to the timer along with the custom
	 * lx_sigev_thread_fire callback.  This targets the signal notification
	 * properly when the timer fires.
	 */
	if (lev.lx_sigev_notify == LX_SIGEV_THREAD_ID) {
		pid_t lpid, spid;
		id_t stid;

		lpid = (pid_t)lev.lx_sigev_un.lx_tid;
		if (lx_lpid_to_spair(lpid, &spid, &stid) != 0 ||
		    spid != curproc->p_pid) {
			error = EINVAL;
			goto err;
		}

		itp->it_flags |= IT_CALLBACK;
		itp->it_cb_func = lx_sigev_thread_fire;
		LX_SIGEV_THREAD_ID_LPID(itp) = lpid;
		LX_SIGEV_THREAD_ID_TID(itp) = stid;
	}

	/*
	 * When the sigevent is not specified, its sigev_value field is
	 * expected to be populated with the timer ID.
	 */
	if (sevp == NULL) {
		itp->it_sigq->sq_info.si_value.sival_int = tid;
	}

	if (copyout(&tid, tidp, sizeof (timer_t)) != 0) {
		error = EFAULT;
		goto err;
	}

	timer_release(p, itp);
	return (0);

err:
	timer_delete_grabbed(p, tid, itp);
	return (set_errno(error));
}

long
lx_gettimeofday(struct timeval *tvp, struct lx_timezone *tzp)
{
	struct lx_timezone tz;

	bzero(&tz, sizeof (tz));

	/*
	 * We want to be similar to libc which just does a fasttrap to
	 * gethrestime and simply converts that result. We follow how uniqtime
	 * does the conversion but we can't use that code since it does some
	 * extra work which can cause the result to bounce around based on which
	 * CPU we run on.
	 */
	if (tvp != NULL) {
		struct timeval tv;
		timestruc_t ts;
		int usec, nsec;

		gethrestime(&ts);
		nsec = ts.tv_nsec;
		usec = nsec + (nsec >> 2);
		usec = nsec + (usec >> 1);
		usec = nsec + (usec >> 2);
		usec = nsec + (usec >> 4);
		usec = nsec - (usec >> 3);
		usec = nsec + (usec >> 2);
		usec = nsec + (usec >> 3);
		usec = nsec + (usec >> 4);
		usec = nsec + (usec >> 1);
		usec = nsec + (usec >> 6);
		usec = usec >> 10;

		tv.tv_sec = ts.tv_sec;
		tv.tv_usec = usec;

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&tv, tvp, sizeof (tv)) != 0)
				return (set_errno(EFAULT));
		}
#ifdef _SYSCALL32_IMPL
		else {
			struct timeval32 tv32;

			if (TIMEVAL_OVERFLOW(&tv))
				return (set_errno(EOVERFLOW));
			TIMEVAL_TO_TIMEVAL32(&tv32, &tv);

			if (copyout(&tv32, tvp, sizeof (tv32)))
				return (set_errno(EFAULT));
		}
#endif
	}

	/*
	 * The Linux man page states use of the second parameter is obsolete,
	 * but gettimeofday(2) should still return EFAULT if it is set
	 * to a bad non-NULL pointer (sigh...)
	 */
	if (tzp != NULL && copyout(&tz, tzp, sizeof (tz)) != 0)
		return (set_errno(EFAULT));

	return (0);
}

/*
 * On Linux a bad buffer will set errno to EFAULT, and on Illumos the failure
 * mode is documented as "undefined."
 */
long
lx_time(time_t *tp)
{
	timestruc_t ts;
	struct timeval tv;

	gethrestime(&ts);
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = 0;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (tp != NULL &&
		    copyout(&tv.tv_sec, tp, sizeof (tv.tv_sec)) != 0)
			return (set_errno(EFAULT));

		return (tv.tv_sec);
	}
#ifdef _SYSCALL32_IMPL
	else {
		struct timeval32 tv32;

		if (TIMEVAL_OVERFLOW(&tv))
			return (set_errno(EOVERFLOW));
		TIMEVAL_TO_TIMEVAL32(&tv32, &tv);

		if (tp != NULL &&
		    copyout(&tv32.tv_sec, tp, sizeof (tv32.tv_sec)))
			return (set_errno(EFAULT));

		return (tv32.tv_sec);
	}
#endif /* _SYSCALL32_IMPL */
	/* NOTREACHED */
}

long
lx_nanosleep(timespec_t *rqtp, timespec_t *rmtp)
{
	return (nanosleep(rqtp, rmtp));
}

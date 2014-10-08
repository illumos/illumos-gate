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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/cred_impl.h>
#include <sys/ucred.h>
#include <ucred.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <strings.h>
#include <pthread.h>
#include <time.h>
#include <thread.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/lx_syscall.h>
#include <sys/lx_debug.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_sched.h>

/* Linux only has three valid policies, SCHED_FIFO, SCHED_RR and SCHED_OTHER */
static int
validate_policy(int policy)
{
	switch (policy) {
		case LX_SCHED_FIFO:
			return (SCHED_FIFO);

		case LX_SCHED_RR:
			return (SCHED_RR);

		case LX_SCHED_OTHER:
			return (SCHED_OTHER);

		default:
			lx_debug("validate_policy: illegal policy: %d", policy);
			return (-EINVAL);
	}
}

/*
 * Check to see if we have the permissions to set scheduler parameters and
 * policy, based on Linux' demand that such commands fail with errno set to
 * EPERM if the current euid is not the euid or ruid of the process in
 * question.
 */
static int
check_schedperms(pid_t pid)
{
	size_t sz;
	ucred_t *cr;
	uid_t euid;

	euid = geteuid();

	if (pid == getpid()) {
		/*
		 * If we're the process to be checked, simply check the euid
		 * against our ruid.
		 */
		if (euid != getuid())
			return (-EPERM);

		return (0);
	}

	/*
	 * We allocate a ucred_t ourselves rather than call ucred_get(3C)
	 * because ucred_get() calls malloc(3C), which the brand library cannot
	 * use.  Because we allocate the space with SAFE_ALLOCA(), there's
	 * no need to free it when we're done.
	 */
	sz = ucred_size();
	cr = (ucred_t *)SAFE_ALLOCA(sz);

	if (cr == NULL)
		return (-ENOMEM);

	/*
	 * If we can't access the process' credentials, fail with errno EPERM
	 * as the call would not have succeeded anyway.
	 */
	if (syscall(SYS_ucredsys, UCREDSYS_UCREDGET, pid, cr) != 0)
		return ((errno == EACCES) ? -EPERM : -errno);

	if ((euid != ucred_geteuid(cr)) && (euid != ucred_getruid(cr)))
		return (-EPERM);

	return (0);
}

static int
ltos_sparam(int policy, struct lx_sched_param *lsp, struct sched_param *sp)
{
	struct lx_sched_param ls;
	int smin = sched_get_priority_min(policy);
	int smax = sched_get_priority_max(policy);

	if (uucopy(lsp, &ls, sizeof (struct lx_sched_param)) != 0)
		return (-errno);

	bzero(sp, sizeof (struct sched_param));

	/*
	 * Linux has a fixed priority range, 0 - 99, which we need to convert to
	 * Solaris's dynamic range. Linux considers lower numbers to be
	 * higher priority, so we'll invert the priority within Solaris's range.
	 *
	 * The formula to convert between ranges is:
	 *
	 *	L * (smax - smin)
	 * S =  -----------------  + smin
	 *	  (lmax - lmin)
	 *
	 * where S is the Solaris equivalent of the linux priority L.
	 *
	 * To invert the priority, we use:
	 * S' = smax - S + smin
	 *
	 * Together, these two formulas become:
	 *
	 *		L * (smax - smin)
	 *   S = smax - -----------------  + 2smin
	 *			99
	 */
	sp->sched_priority = smax -
	    ((ls.lx_sched_prio * (smax - smin)) / LX_PRI_MAX) + 2*smin;

	lx_debug("ltos_sparam: linux prio %d = Solaris prio %d "
	    "(Solaris range %d,%d)\n", ls.lx_sched_prio, sp->sched_priority,
	    smin, smax);

	return (0);
}

static int
stol_sparam(int policy, struct sched_param *sp, struct lx_sched_param *lsp)
{
	struct lx_sched_param ls;
	int smin = sched_get_priority_min(policy);
	int smax = sched_get_priority_max(policy);

	if (policy == SCHED_OTHER) {
		/*
		 * In Linux, the only valid SCHED_OTHER scheduler priority is 0
		 */
		ls.lx_sched_prio = 0;
	} else {
		/*
		 * Convert Solaris's dynamic, inverted priority range to the
		 * fixed Linux range of 1 - 99.
		 *
		 * The formula is (see above):
		 *
		 *	(smax - s + 2smin) * 99
		 *  l = -----------------------
		 *		smax - smin
		 */
		ls.lx_sched_prio = ((smax - sp->sched_priority + 2*smin) *
		    LX_PRI_MAX) / (smax - smin);
	}

	lx_debug("stol_sparam: policy %d: Solaris prio %d = linux prio %d "
	    "(Solaris range %d,%d)\n", policy,
	    sp->sched_priority, ls.lx_sched_prio, smin, smax);

	return ((uucopy(&ls, lsp, sizeof (struct lx_sched_param)) != 0)
	    ? -errno : 0);
}

#define	BITINDEX(ind)	(ind / (sizeof (ulong_t) * 8))
#define	BITSHIFT(ind)	(1 << (ind % (sizeof (ulong_t) * 8)))

/* ARGSUSED */
long
lx_sched_getaffinity(uintptr_t pid, uintptr_t len, uintptr_t maskp)
{
	int	sz;
	ulong_t	*lmask, *zmask;
	int	i;

	sz = syscall(SYS_brand, B_GET_AFFINITY_MASK, pid, len, maskp);
	if (sz == -1)
		return (-errno);

	/*
	 * If the target LWP hasn't ever had an affinity mask set, the kernel
	 * will return a mask of all 0's. If that is the case we must build a
	 * default mask that has all valid bits turned on.
	 */
	lmask = SAFE_ALLOCA(sz);
	zmask = SAFE_ALLOCA(sz);
	if (lmask == NULL || zmask == NULL)
		return (-ENOMEM);

	bzero(zmask, sz);

	if (uucopy((void *)maskp, lmask, sz) != 0)
		return (-EFAULT);

	if (bcmp(lmask, zmask, sz) != 0)
		return (sz);

	for (i = 0; i < sz * 8; i++) {
		if (p_online(i, P_STATUS) != -1) {
			lmask[BITINDEX(i)] |= BITSHIFT(i);
		}
	}

	if (uucopy(lmask, (void *)maskp, sz) != 0)
		return (-EFAULT);

	return (sz);
}

/* ARGSUSED */
long
lx_sched_setaffinity(uintptr_t pid, uintptr_t len, uintptr_t maskp)
{
	int		ret;
	int		sz;
	int		i;
	int		found;
	ulong_t		*lmask;
	pid_t		s_pid;
	lwpid_t		s_tid;
	processorid_t	cpuid = NULL;

	if ((pid_t)pid < 0)
		return (-EINVAL);

	if (lx_lpid_to_spair(pid, &s_pid, &s_tid) < 0)
		return (-ESRCH);

	/*
	 * We only support setting affinity masks for threads in
	 * the calling process.
	 */
	if (s_pid != getpid())
		return (-EPERM);

	/*
	 * First, get the minimum bitmask size from the kernel.
	 */
	sz = syscall(SYS_brand, B_GET_AFFINITY_MASK, 0, 0, 0);
	if (sz == -1)
		return (-errno);

	lmask = SAFE_ALLOCA(sz);
	if (lmask == NULL)
		return (-ENOMEM);

	if (uucopy((void *)maskp, lmask, sz) != 0)
		return (-EFAULT);

	/*
	 * Make sure the mask contains at least one processor that is
	 * physically on the system. Reduce the user's mask to the set of
	 * physically present CPUs. Keep track of how many valid
	 * bits are set in the user's mask.
	 */

	for (found = 0, i = 0; i < sz * 8; i++) {
		if (p_online(i, P_STATUS) == -1) {
			/*
			 * This CPU doesn't exist, so clear this bit from
			 * the user's mask.
			 */
			lmask[BITINDEX(i)] &= ~BITSHIFT(i);
			continue;
		}

		if ((lmask[BITINDEX(i)] & BITSHIFT(i)) == BITSHIFT(i)) {
			found++;
			cpuid = i;
		}
	}

	if (found == 0) {
		lx_debug("\tlx_sched_setaffinity: mask has no present CPUs\n");
		return (-EINVAL);
	}

	/*
	 * If only one bit is set, bind the thread to that procesor;
	 * otherwise, clear the binding.
	 */
	if (found == 1) {
		lx_debug("\tlx_sched_setaffinity: binding thread %d to cpu%d\n",
		    s_tid, cpuid);
		if (processor_bind(P_LWPID, s_tid, cpuid, NULL) != 0)
			/*
			 * It could be that the requested processor is offline,
			 * so we'll just abandon our good-natured attempt to
			 * bind to it.
			 */
			lx_debug("couldn't bind LWP %d to cpu %d: %s\n", s_tid,
			    cpuid, strerror(errno));
	} else {
		lx_debug("\tlx_sched_setaffinity: clearing thr %d binding\n",
		    s_tid);
		if (processor_bind(P_LWPID, s_tid, PBIND_NONE, NULL) != 0) {
			lx_debug("couldn't clear CPU binding for LWP %d: %s\n",
			    s_tid, strerror(errno));
		}
	}

	/*
	 * Finally, ask the kernel to make a note of our current (though fairly
	 * meaningless) affinity mask.
	 */
	ret = syscall(SYS_brand, B_SET_AFFINITY_MASK, pid, sz, lmask);

	return ((ret == 0) ? 0 : -errno);
}

long
lx_sched_getparam(uintptr_t pid, uintptr_t param)
{
	int	policy, ret;
	pid_t	s_pid;
	lwpid_t	s_tid;

	struct sched_param sp;

	if (((pid_t)pid < 0) || (param == NULL))
		return (-EINVAL);

	if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) < 0)
		return (-ESRCH);

	/*
	 * If we're attempting to get information on our own process, we can
	 * get data on a per-thread basis; if not, punt and use the specified
	 * pid.
	 */
	if (s_pid == getpid()) {
		if ((ret = pthread_getschedparam(s_tid, &policy, &sp)) != 0)
			return (-ret);
	} else {
		if (sched_getparam(s_pid, &sp) == -1)
			return (-errno);

		if ((policy = sched_getscheduler(s_pid)) < 0)
			return (-errno);
	}

	/*
	 * Make sure that any non-SCHED_FIFO non-SCHED_RR scheduler is mapped
	 * onto SCHED_OTHER.
	 */
	if (policy != SCHED_FIFO && policy != SCHED_RR)
		policy = SCHED_OTHER;

	return (stol_sparam(policy, &sp, (struct lx_sched_param *)param));
}

long
lx_sched_setparam(uintptr_t pid, uintptr_t param)
{
	int	err, policy;
	pid_t	s_pid;
	lwpid_t	s_tid;
	struct lx_sched_param lp;
	struct sched_param sp;

	if (((pid_t)pid < 0) || (param == NULL))
		return (-EINVAL);

	if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) < 0)
		return (-ESRCH);

	if (s_pid == getpid()) {
		struct sched_param dummy;

		if ((err = pthread_getschedparam(s_tid, &policy, &dummy)) != 0)
			return (-err);
	} else
		if ((policy = sched_getscheduler(s_pid)) < 0)
			return (-errno);

	lx_debug("sched_setparam(): current policy %d", policy);

	if (uucopy((void *)param, &lp, sizeof (lp)) != 0)
		return (-errno);

	/*
	 * In Linux, the only valid SCHED_OTHER scheduler priority is 0
	 */
	if ((policy == SCHED_OTHER) && (lp.lx_sched_prio != 0))
		return (-EINVAL);

	if ((err = ltos_sparam(policy, (struct lx_sched_param *)&lp,
	    &sp)) != 0)
		return (err);

	/*
	 * Check if we're allowed to change the scheduler for the process.
	 *
	 * If we're operating on a thread, we can't just call
	 * pthread_setschedparam() because as all threads reside within a
	 * single Solaris process, Solaris will allow the modification
	 *
	 * If we're operating on a process, we can't just call sched_setparam()
	 * because Solaris will allow the call to succeed if the scheduler
	 * parameters do not differ from those being installed, but Linux wants
	 * the call to fail.
	 */
	if ((err = check_schedperms(s_pid)) != 0)
		return (err);

	if (s_pid == getpid())
		return (((err = pthread_setschedparam(s_tid, policy, &sp)) != 0)
		    ? -err : 0);

	return ((sched_setparam(s_pid, &sp) == -1) ? -errno : 0);
}

long
lx_sched_rr_get_interval(uintptr_t pid, uintptr_t timespec)
{
	struct timespec ts;
	pid_t	s_pid;

	if ((pid_t)pid < 0)
		return (-EINVAL);

	if (lx_lpid_to_spid((pid_t)pid, &s_pid) < 0)
		return (-ESRCH);

	if (uucopy((struct timespec *)timespec, &ts,
	    sizeof (struct timespec)) != 0)
		return (-errno);

	return ((sched_rr_get_interval(s_pid, &ts) == -1) ? -errno : 0);
}

long
lx_sched_getscheduler(uintptr_t pid)
{
	int	policy, rv;
	pid_t	s_pid;
	lwpid_t	s_tid;

	if ((pid_t)pid < 0)
		return (-EINVAL);

	if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) < 0)
		return (-ESRCH);

	if (s_pid == getpid()) {
		struct sched_param dummy;

		if ((rv = pthread_getschedparam(s_tid, &policy, &dummy)) != 0)
			return (-rv);
	} else
		if ((policy = sched_getscheduler(s_pid)) < 0)
			return (-errno);

	/*
	 * Linux only supports certain policies; avoid confusing apps with
	 * alien policies.
	 */
	switch (policy) {
	case SCHED_FIFO:
		return (LX_SCHED_FIFO);
	case SCHED_OTHER:
		return (LX_SCHED_OTHER);
	case SCHED_RR:
		return (LX_SCHED_RR);
	default:
		break;
	}

	return (LX_SCHED_OTHER);
}

long
lx_sched_setscheduler(uintptr_t pid, uintptr_t policy, uintptr_t param)
{
	int	rt_pol;
	int	rv;
	pid_t	s_pid;
	lwpid_t	s_tid;
	struct lx_sched_param lp;

	struct sched_param sp;

	if (((pid_t)pid < 0) || (param == NULL))
		return (-EINVAL);

	if ((rt_pol = validate_policy((int)policy)) < 0)
		return (rt_pol);

	if ((rv = ltos_sparam(policy, (struct lx_sched_param *)param,
	    &sp)) != 0)
		return (rv);

	if (uucopy((void *)param, &lp, sizeof (lp)) != 0)
		return (-errno);

	if (rt_pol == LX_SCHED_OTHER) {
		/*
		 * In Linux, the only valid SCHED_OTHER scheduler priority is 0
		 */
		if (lp.lx_sched_prio != 0)
			return (-EINVAL);

		/*
		 * If we're already SCHED_OTHER, there's nothing else to do.
		 */
		if (lx_sched_getscheduler(pid) == LX_SCHED_OTHER)
			return (0);
	}

	if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) < 0)
		return (-ESRCH);

	/*
	 * Check if we're allowed to change the scheduler for the process.
	 *
	 * If we're operating on a thread, we can't just call
	 * pthread_setschedparam() because as all threads reside within a
	 * single Solaris process, Solaris will allow the modification.
	 *
	 * If we're operating on a process, we can't just call
	 * sched_setscheduler() because Solaris will allow the call to succeed
	 * if the scheduler and scheduler parameters do not differ from those
	 * being installed, but Linux wants the call to fail.
	 */
	if ((rv = check_schedperms(s_pid)) != 0)
		return (rv);

	if (s_pid == getpid()) {
		struct sched_param param;
		int pol;

		if ((pol = sched_getscheduler(s_pid)) == -1)
			return (-errno);

		/*
		 * sched_setscheduler() returns the previous scheduling policy
		 * on success, so call pthread_getschedparam() to get the
		 * current thread's scheduling policy and return that if the
		 * call to pthread_setschedparam() succeeds.
		 */
		if ((rv = pthread_getschedparam(s_tid, &pol, &param)) != 0)
			return (-rv);

		return (((rv = pthread_setschedparam(s_tid, rt_pol, &sp)) != 0)
		    ? -rv : pol);
	}

	return (((rv = sched_setscheduler(s_pid, rt_pol, &sp)) == -1)
	    ? -errno : rv);
}

long
lx_sched_get_priority_min(uintptr_t policy)
{
	/*
	 * In Linux, the only valid SCHED_OTHER scheduler priority is 0.
	 * Linux scheduling priorities are not alterable, so there is no
	 * Solaris translation necessary.
	 */
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		return (LX_SCHED_PRIORITY_MIN_RRFIFO);
	case LX_SCHED_OTHER:
		return (LX_SCHED_PRIORITY_MIN_OTHER);
	default:
		break;
	}
	return (-EINVAL);
}

long
lx_sched_get_priority_max(uintptr_t policy)
{
	/*
	 * In Linux, the only valid SCHED_OTHER scheduler priority is 0
	 * Linux scheduling priorities are not alterable, so there is no
	 * Solaris translation necessary.
	 */
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		return (LX_SCHED_PRIORITY_MAX_RRFIFO);
	case LX_SCHED_OTHER:
		return (LX_SCHED_PRIORITY_MAX_OTHER);
	default:
		break;
	}
	return (-EINVAL);
}

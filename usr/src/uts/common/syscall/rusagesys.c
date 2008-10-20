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

/*
 * Implement fast getrusage call
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <sys/vm_usage.h>

static int
getrusage(void *user_rusage)
{
	struct rusage r;
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	hrtime_t snsecs, unsecs;
	klwp_t *lwp;

	bzero(&r, sizeof (struct rusage));

	mutex_enter(&p->p_lock);

	if (p->p_defunct > 0) {
		r.ru_majflt	= p->p_ru.majflt;
		r.ru_minflt	= p->p_ru.minflt;
		r.ru_nswap	= p->p_ru.nswap;
		r.ru_inblock	= p->p_ru.inblock;
		r.ru_oublock	= p->p_ru.oublock;
		r.ru_msgsnd	= p->p_ru.msgsnd;
		r.ru_msgrcv	= p->p_ru.msgrcv;
		r.ru_nsignals	= p->p_ru.nsignals;
		r.ru_nvcsw	= p->p_ru.nvcsw;
		r.ru_nivcsw	= p->p_ru.nivcsw;
	}

	unsecs = mstate_aggr_state(p, LMS_USER);
	snsecs = mstate_aggr_state(p, LMS_SYSTEM);

	do {
		if (t->t_proc_flag & TP_LWPEXIT)
			continue;

		lwp = ttolwp(t);

		r.ru_majflt	+= lwp->lwp_ru.majflt;
		r.ru_minflt	+= lwp->lwp_ru.minflt;
		r.ru_nswap	+= lwp->lwp_ru.nswap;
		r.ru_inblock	+= lwp->lwp_ru.inblock;
		r.ru_oublock	+= lwp->lwp_ru.oublock;
		r.ru_msgsnd	+= lwp->lwp_ru.msgsnd;
		r.ru_msgrcv	+= lwp->lwp_ru.msgrcv;
		r.ru_nsignals	+= lwp->lwp_ru.nsignals;
		r.ru_nvcsw	+= lwp->lwp_ru.nvcsw;
		r.ru_nivcsw	+= lwp->lwp_ru.nivcsw;

	} while ((t = t->t_forw) != curthread);

	mutex_exit(&p->p_lock);

	hrt2tv(unsecs, &r.ru_utime);
	hrt2tv(snsecs, &r.ru_stime);

#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct rusage32 r32;

		bzero(&r32, sizeof (struct rusage32));

		r32.ru_utime.tv_sec  = r.ru_utime.tv_sec;
		r32.ru_utime.tv_usec = r.ru_utime.tv_usec;
		r32.ru_stime.tv_sec  = r.ru_stime.tv_sec;
		r32.ru_stime.tv_usec = r.ru_stime.tv_usec;

		r32.ru_majflt	= (int32_t)r.ru_majflt;
		r32.ru_minflt	= (int32_t)r.ru_minflt;
		r32.ru_nswap	= (int32_t)r.ru_nswap;
		r32.ru_inblock	= (int32_t)r.ru_inblock;
		r32.ru_oublock	= (int32_t)r.ru_oublock;
		r32.ru_msgsnd	= (int32_t)r.ru_msgsnd;
		r32.ru_msgrcv	= (int32_t)r.ru_msgrcv;
		r32.ru_nsignals	= (int32_t)r.ru_nsignals;
		r32.ru_nvcsw	= (int32_t)r.ru_nvcsw;
		r32.ru_nivcsw	= (int32_t)r.ru_nivcsw;
		if (copyout(&r32, user_rusage, sizeof (r32)) != 0)
			return (set_errno(EFAULT));
	} else
#endif /* _SYSCALL32_IMPL */

		if (copyout(&r, user_rusage, sizeof (r)) != 0)
			return (set_errno(EFAULT));

	return (0);
}

static int
getrusage_chld(void *user_rusage)
{
	struct rusage r;
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	hrtime_t snsecs, unsecs;

	bzero(&r, sizeof (struct rusage));

	mutex_enter(&p->p_lock);

	unsecs = p->p_cacct[LMS_USER];
	snsecs = p->p_cacct[LMS_SYSTEM] + p->p_cacct[LMS_TRAP];

	r.ru_majflt	= p->p_cru.majflt;
	r.ru_minflt	= p->p_cru.minflt;
	r.ru_nswap	= p->p_cru.nswap;
	r.ru_inblock	= p->p_cru.inblock;
	r.ru_oublock	= p->p_cru.oublock;
	r.ru_msgsnd	= p->p_cru.msgsnd;
	r.ru_msgrcv	= p->p_cru.msgrcv;
	r.ru_nsignals	= p->p_cru.nsignals;
	r.ru_nvcsw	= p->p_cru.nvcsw;
	r.ru_nivcsw	= p->p_cru.nivcsw;

	mutex_exit(&p->p_lock);

	hrt2tv(unsecs, &r.ru_utime);
	hrt2tv(snsecs, &r.ru_stime);
#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct rusage32 r32;

		bzero(&r32, sizeof (struct rusage32));

		r32.ru_utime.tv_sec  = r.ru_utime.tv_sec;
		r32.ru_utime.tv_usec = r.ru_utime.tv_usec;
		r32.ru_stime.tv_sec  = r.ru_stime.tv_sec;
		r32.ru_stime.tv_usec = r.ru_stime.tv_usec;

		r32.ru_majflt	= (int32_t)r.ru_majflt;
		r32.ru_minflt	= (int32_t)r.ru_minflt;
		r32.ru_nswap	= (int32_t)r.ru_nswap;
		r32.ru_inblock	= (int32_t)r.ru_inblock;
		r32.ru_oublock	= (int32_t)r.ru_oublock;
		r32.ru_msgsnd	= (int32_t)r.ru_msgsnd;
		r32.ru_msgrcv	= (int32_t)r.ru_msgrcv;
		r32.ru_nsignals	= (int32_t)r.ru_nsignals;
		r32.ru_nvcsw	= (int32_t)r.ru_nvcsw;
		r32.ru_nivcsw	= (int32_t)r.ru_nivcsw;
		if (copyout(&r32, user_rusage, sizeof (r32)) != 0)
			return (set_errno(EFAULT));
	} else
#endif /* _SYSCALL32_IMPL */

		if (copyout(&r, user_rusage, sizeof (r)) != 0)
			return (set_errno(EFAULT));

	return (0);
}

static int
getrusage_lwp(void *user_rusage)
{
	struct rusage r;
	kthread_t *t = curthread;
	klwp_t *lwp;
	hrtime_t snsecs, unsecs;
	struct mstate *ms;

	bzero(&r, sizeof (struct rusage));

	lwp = ttolwp(t);
	ms = &lwp->lwp_mstate;
	unsecs = ms->ms_acct[LMS_USER];
	snsecs = ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];
	scalehrtime(&unsecs);
	scalehrtime(&snsecs);
	r.ru_majflt	= lwp->lwp_ru.majflt;
	r.ru_minflt	= lwp->lwp_ru.minflt;
	r.ru_nswap	= lwp->lwp_ru.nswap;
	r.ru_inblock	= lwp->lwp_ru.inblock;
	r.ru_oublock	= lwp->lwp_ru.oublock;
	r.ru_msgsnd	= lwp->lwp_ru.msgsnd;
	r.ru_msgrcv	= lwp->lwp_ru.msgrcv;
	r.ru_nsignals	= lwp->lwp_ru.nsignals;
	r.ru_nvcsw	= lwp->lwp_ru.nvcsw;
	r.ru_nivcsw	= lwp->lwp_ru.nivcsw;

	hrt2tv(unsecs, &r.ru_utime);
	hrt2tv(snsecs, &r.ru_stime);
#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct rusage32 r32;

		bzero(&r32, sizeof (struct rusage32));

		r32.ru_utime.tv_sec  = r.ru_utime.tv_sec;
		r32.ru_utime.tv_usec = r.ru_utime.tv_usec;
		r32.ru_stime.tv_sec  = r.ru_stime.tv_sec;
		r32.ru_stime.tv_usec = r.ru_stime.tv_usec;

		r32.ru_majflt	= (int32_t)r.ru_majflt;
		r32.ru_minflt	= (int32_t)r.ru_minflt;
		r32.ru_nswap	= (int32_t)r.ru_nswap;
		r32.ru_inblock	= (int32_t)r.ru_inblock;
		r32.ru_oublock	= (int32_t)r.ru_oublock;
		r32.ru_msgsnd	= (int32_t)r.ru_msgsnd;
		r32.ru_msgrcv	= (int32_t)r.ru_msgrcv;
		r32.ru_nsignals	= (int32_t)r.ru_nsignals;
		r32.ru_nvcsw	= (int32_t)r.ru_nvcsw;
		r32.ru_nivcsw	= (int32_t)r.ru_nivcsw;
		if (copyout(&r32, user_rusage, sizeof (r32)) != 0)
			return (set_errno(EFAULT));
	} else
#endif /* _SYSCALL32_IMPL */

		if (copyout(&r, user_rusage, sizeof (r)) != 0)
			return (set_errno(EFAULT));

	return (0);
}

int
rusagesys(int code, void *arg1, void *arg2, void *arg3, void *arg4)
{
	switch (code) {

	case _RUSAGESYS_GETRUSAGE:
		return (getrusage(arg1));
	case _RUSAGESYS_GETRUSAGE_CHLD:
		return (getrusage_chld(arg1));
	case _RUSAGESYS_GETRUSAGE_LWP:
		return (getrusage_lwp(arg1));
	case _RUSAGESYS_GETVMUSAGE:
		return (vm_getusage((uint_t)(uintptr_t)arg1, (time_t)arg2,
		    (vmusage_t *)arg3, (size_t *)arg4, 0));
	default:
		return (set_errno(EINVAL));
	}
}

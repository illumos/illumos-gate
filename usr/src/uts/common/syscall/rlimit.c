/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <sys/param.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/ulimit.h>
#include <sys/debug.h>
#include <sys/rctl.h>

#include <vm/as.h>

/*
 * Perhaps ulimit could be moved into a user library, as calls to
 * getrlimit and setrlimit, were it not for binary compatibility
 * restrictions.
 */
long
ulimit(int cmd, long arg)
{
	proc_t *p = curproc;
	long	retval;

	switch (cmd) {

	case UL_GFILLIM: /* Return current file size limit. */
	{
		rlim64_t filesize;

		mutex_enter(&p->p_lock);
		filesize = rctl_enforced_value(rctlproc_legacy[RLIMIT_FSIZE],
		    p->p_rctls, p);
		mutex_exit(&p->p_lock);

		if (get_udatamodel() == DATAMODEL_ILP32) {
			/*
			 * File size is returned in blocks for ulimit.
			 * This function is deprecated and therefore LFS API
			 * didn't define the behaviour of ulimit.
			 * Here we return maximum value of file size possible
			 * so that applications that do not check errors
			 * continue to work.
			 */
			if (filesize > MAXOFF32_T)
				filesize = MAXOFF32_T;
			retval = ((int)filesize >> SCTRSHFT);
		} else
			retval = filesize >> SCTRSHFT;
		break;
	}

	case UL_SFILLIM: /* Set new file size limit. */
	{
		int error = 0;
		rlim64_t lim = (rlim64_t)arg;
		struct rlimit64 rl64;
		rctl_alloc_gp_t *gp = rctl_rlimit_set_prealloc(1);

		if (lim >= (((rlim64_t)MAXOFFSET_T) >> SCTRSHFT))
			lim = (rlim64_t)RLIM64_INFINITY;
		else
			lim <<= SCTRSHFT;

		rl64.rlim_max = rl64.rlim_cur = lim;
		mutex_enter(&p->p_lock);
		if (error = rctl_rlimit_set(rctlproc_legacy[RLIMIT_FSIZE], p,
		    &rl64, gp, RCTL_LOCAL_DENY | RCTL_LOCAL_SIGNAL, SIGXFSZ,
		    CRED())) {
			mutex_exit(&p->p_lock);
			rctl_prealloc_destroy(gp);
			return (set_errno(error));
		}
		mutex_exit(&p->p_lock);
		rctl_prealloc_destroy(gp);
		retval = arg;
		break;
	}

	case UL_GMEMLIM: /* Return maximum possible break value. */
	{
		struct seg *seg;
		struct seg *nextseg;
		struct as *as = p->p_as;
		caddr_t brkend;
		caddr_t brkbase;
		size_t size;
		rlim64_t size_ctl;
		rlim64_t vmem_ctl;

		/*
		 * Find the segment with a virtual address
		 * greater than the end of the current break.
		 */
		nextseg = NULL;
		mutex_enter(&p->p_lock);
		brkbase = (caddr_t)p->p_brkbase;
		brkend = (caddr_t)p->p_brkbase + p->p_brksize;
		mutex_exit(&p->p_lock);

		/*
		 * Since we can't return less than the current break,
		 * initialize the return value to the current break
		 */
		retval = (long)brkend;

		AS_LOCK_ENTER(as, RW_READER);
		for (seg = as_findseg(as, brkend, 0); seg != NULL;
		    seg = AS_SEGNEXT(as, seg)) {
			if (seg->s_base >= brkend) {
				nextseg = seg;
				break;
			}
		}

		mutex_enter(&p->p_lock);
		size_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_DATA],
		    p->p_rctls, p);
		vmem_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_VMEM],
		    p->p_rctls, p);
		mutex_exit(&p->p_lock);

		/*
		 * First, calculate the maximum break value based on
		 * the user's RLIMIT_DATA, but also taking into account
		 * that this value cannot be greater than as->a_userlimit.
		 * We also take care to make sure that we don't overflow
		 * in the calculation.
		 */
		/*
		 * Since we are casting the RLIMIT_DATA value to a
		 * ulong (a 32-bit value in the 32-bit kernel) we have
		 * to pass this assertion.
		 */
		ASSERT32((size_t)size_ctl <= UINT32_MAX);

		size = (size_t)size_ctl;
		if (as->a_userlimit - brkbase > size)
			retval = MAX((size_t)retval, (size_t)(brkbase + size));
					/* don't return less than current */
		else
			retval = (long)as->a_userlimit;

		/*
		 * The max break cannot extend into the next segment
		 */
		if (nextseg != NULL)
			retval = MIN((uintptr_t)retval,
			    (uintptr_t)nextseg->s_base);

		/*
		 * Handle the case where there is an limit on RLIMIT_VMEM
		 */
		if (vmem_ctl < UINT64_MAX) {
			/* calculate brkend based on the end of page */
			caddr_t brkendpg = (caddr_t)roundup((uintptr_t)brkend,
			    PAGESIZE);
			/*
			 * Large Files: The following assertion has to pass
			 * through to ensure the correctness of the cast.
			 */
			ASSERT32(vmem_ctl <= UINT32_MAX);

			size = (size_t)(vmem_ctl & PAGEMASK);

			if (as->a_size < size)
				size -= as->a_size;
			else
				size = 0;
			/*
			 * Take care to not overflow the calculation
			 */
			if (as->a_userlimit - brkendpg > size)
				retval = MIN((size_t)retval,
				    (size_t)(brkendpg + size));
		}

		AS_LOCK_EXIT(as);

		/* truncate to same boundary as sbrk */

		switch (get_udatamodel()) {
		default:
		case DATAMODEL_ILP32:
			retval = retval & ~(8-1);
			break;
		case DATAMODEL_LP64:
			retval = retval & ~(16-1);
			break;
		}
		break;
	}

	case UL_GDESLIM: /* Return approximate number of open files */
	{
		rlim64_t fdno_ctl;

		mutex_enter(&curproc->p_lock);
		fdno_ctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_NOFILE],
		    curproc->p_rctls, curproc);
		ASSERT(fdno_ctl <= INT_MAX);
		retval = (rlim_t)fdno_ctl;
		mutex_exit(&curproc->p_lock);
		break;
	}

	default:
		return (set_errno(EINVAL));

	}
	return (retval);
}

#ifdef _SYSCALL32_IMPL

int
ulimit32(int cmd, int arg)
{
	return ((int)ulimit(cmd, (long)arg));
}

#endif	/* _SYSCALL32_IMPL */

#if defined(_ILP32) || defined(_SYSCALL32_IMPL)

/*
 * Large Files: getrlimit returns RLIM_SAVED_CUR or RLIM_SAVED_MAX when
 * rlim_cur or rlim_max is not representable in 32-bit rlim_t. These
 * values are just tokens which will be used in setrlimit to set the
 * correct limits. The current limits are saved in the saved_rlimit members
 * in user structures when the token is returned. setrlimit restores
 * the limit values to these saved values when the token is passed.
 * Consider the following common scenario of the apps:
 *
 * 		limit = getrlimit();
 *		savedlimit = limit;
 * 		limit = limit1;
 *		setrlimit(limit)
 *		// execute all processes in the new rlimit state.
 *		setrlimit(savedlimit) // restore the old values.
 *
 * Most apps don't check error returns from getrlimit or setrlimit
 * and this is why we return tokens when the correct value
 * cannot be represented in rlim_t. For more discussion refer to
 * the LFS API document.
 *
 * In the 64-bit kernel, all existing resource limits are treated in this
 * manner.  In the 32-bit kernel, CPU time is treated equivalently to the
 * file size limit above; the VM-related limits are not.  The macro,
 * RLIM_SAVED(x), returns true if the resource limit should be handled in
 * this way on the current kernel.
 */
int
getrlimit32(int resource, struct rlimit32 *rlp)
{
	struct rlimit32 rlim32;
	struct rlimit64 rlim64;
	struct proc *p = curproc;
	struct user *up = PTOU(p);
	int savecur = 0;
	int savemax = 0;

	if (resource < 0 || resource >= RLIM_NLIMITS)
		return (set_errno(EINVAL));

	mutex_enter(&p->p_lock);
	(void) rctl_rlimit_get(rctlproc_legacy[resource], p, &rlim64);
	mutex_exit(&p->p_lock);

	if (rlim64.rlim_max > (rlim64_t)UINT32_MAX) {

		if (rlim64.rlim_max == RLIM64_INFINITY)
			rlim32.rlim_max = RLIM32_INFINITY;
		else {
			savemax = 1;
			rlim32.rlim_max = RLIM32_SAVED_MAX;
			/*CONSTCOND*/
			ASSERT(RLIM_SAVED(resource));
		}

		if (rlim64.rlim_cur == RLIM64_INFINITY)
			rlim32.rlim_cur = RLIM32_INFINITY;
		else if (rlim64.rlim_cur == rlim64.rlim_max) {
			savecur = 1;
			rlim32.rlim_cur = RLIM32_SAVED_MAX;
			/*CONSTCOND*/
			ASSERT(RLIM_SAVED(resource));
		} else if (rlim64.rlim_cur > (rlim64_t)UINT32_MAX) {
			savecur = 1;
			rlim32.rlim_cur = RLIM32_SAVED_CUR;
			/*CONSTCOND*/
			ASSERT(RLIM_SAVED(resource));
		} else
			rlim32.rlim_cur = rlim64.rlim_cur;

		/*
		 * save the current limits in user structure.
		 */
		/*CONSTCOND*/
		if (RLIM_SAVED(resource)) {
			mutex_enter(&p->p_lock);
			if (savemax)
				up->u_saved_rlimit[resource].rlim_max =
				    rlim64.rlim_max;
			if (savecur)
				up->u_saved_rlimit[resource].rlim_cur =
				    rlim64.rlim_cur;
			mutex_exit(&p->p_lock);
		}
	} else {
		ASSERT(rlim64.rlim_cur <= (rlim64_t)UINT32_MAX);
		rlim32.rlim_max = rlim64.rlim_max;
		rlim32.rlim_cur = rlim64.rlim_cur;
	}

	if (copyout(&rlim32, rlp, sizeof (rlim32)))
		return (set_errno(EFAULT));

	return (0);
}

/*
 * See comments above getrlimit32(). When the tokens are passed in the
 * rlimit structure the values are considered equal to the values
 * stored in saved_rlimit members of user structure.
 * When the user passes RLIM_INFINITY to set the resource limit to
 * unlimited internally understand this value as RLIM64_INFINITY and
 * let rlimit() do the job.
 */
int
setrlimit32(int resource, struct rlimit32 *rlp)
{
	struct rlimit32 rlim32;
	struct rlimit64 rlim64;
	struct rlimit64 saved_rlim;
	int	error;
	struct proc *p = ttoproc(curthread);
	struct user *up = PTOU(p);
	rctl_alloc_gp_t *gp;

	if (resource < 0 || resource >= RLIM_NLIMITS)
		return (set_errno(EINVAL));
	if (copyin(rlp, &rlim32, sizeof (rlim32)))
		return (set_errno(EFAULT));

	gp = rctl_rlimit_set_prealloc(1);

	/*
	 * Disallow resource limit tunnelling
	 */
	/*CONSTCOND*/
	if (RLIM_SAVED(resource)) {
		mutex_enter(&p->p_lock);
		saved_rlim = up->u_saved_rlimit[resource];
		mutex_exit(&p->p_lock);
	} else {
		saved_rlim.rlim_max = (rlim64_t)rlim32.rlim_max;
		saved_rlim.rlim_cur = (rlim64_t)rlim32.rlim_cur;
	}

	switch (rlim32.rlim_cur) {
	case RLIM32_INFINITY:
		rlim64.rlim_cur = RLIM64_INFINITY;
		break;
	case RLIM32_SAVED_CUR:
		rlim64.rlim_cur = saved_rlim.rlim_cur;
		break;
	case RLIM32_SAVED_MAX:
		rlim64.rlim_cur = saved_rlim.rlim_max;
		break;
	default:
		rlim64.rlim_cur = (rlim64_t)rlim32.rlim_cur;
		break;
	}

	switch (rlim32.rlim_max) {
	case RLIM32_INFINITY:
		rlim64.rlim_max = RLIM64_INFINITY;
		break;
	case RLIM32_SAVED_MAX:
		rlim64.rlim_max = saved_rlim.rlim_max;
		break;
	case RLIM32_SAVED_CUR:
		rlim64.rlim_max = saved_rlim.rlim_cur;
		break;
	default:
		rlim64.rlim_max = (rlim64_t)rlim32.rlim_max;
		break;
	}

	mutex_enter(&p->p_lock);
	if (error = rctl_rlimit_set(rctlproc_legacy[resource], p, &rlim64, gp,
	    rctlproc_flags[resource], rctlproc_signals[resource], CRED())) {
		mutex_exit(&p->p_lock);
		rctl_prealloc_destroy(gp);
		return (set_errno(error));
	}
	mutex_exit(&p->p_lock);
	rctl_prealloc_destroy(gp);

	return (0);
}

#endif	/* _ILP32 && _SYSCALL32_IMPL */

int
getrlimit64(int resource, struct rlimit64 *rlp)
{
	struct rlimit64 rlim64;
	struct proc *p = ttoproc(curthread);

	if (resource < 0 || resource >= RLIM_NLIMITS)
		return (set_errno(EINVAL));

	mutex_enter(&p->p_lock);
	(void) rctl_rlimit_get(rctlproc_legacy[resource], p, &rlim64);
	mutex_exit(&p->p_lock);

	if (copyout(&rlim64, rlp, sizeof (rlim64)))
		return (set_errno(EFAULT));
	return (0);
}

int
setrlimit64(int resource, struct rlimit64 *rlp)
{
	struct rlimit64 rlim64;
	struct proc *p = ttoproc(curthread);
	int	error;
	rctl_alloc_gp_t *gp;

	if (resource < 0 || resource >= RLIM_NLIMITS)
		return (set_errno(EINVAL));
	if (copyin(rlp, &rlim64, sizeof (rlim64)))
		return (set_errno(EFAULT));

	gp = rctl_rlimit_set_prealloc(1);

	mutex_enter(&p->p_lock);
	if (error = rctl_rlimit_set(rctlproc_legacy[resource], p, &rlim64, gp,
	    rctlproc_flags[resource], rctlproc_signals[resource], CRED())) {
		mutex_exit(&p->p_lock);
		rctl_prealloc_destroy(gp);
		return (set_errno(error));
	}
	mutex_exit(&p->p_lock);
	rctl_prealloc_destroy(gp);
	return (0);

}

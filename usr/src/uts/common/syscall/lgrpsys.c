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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * lgroup system calls
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/sunddi.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/cpupart.h>
#include <sys/lgrp.h>
#include <sys/lgrp_user.h>
#include <sys/promif.h>		/* for prom_printf() */
#include <sys/sysmacros.h>
#include <sys/policy.h>

#include <vm/as.h>


/* definitions for mi_validity */
#define	VALID_ADDR	1
#define	VALID_REQ	2

/*
 * run through the given number of addresses and requests and return the
 * corresponding memory information for each address
 */
static int
meminfo(int addr_count, struct meminfo *mip)
{
	size_t		in_size, out_size, req_size, val_size;
	struct as	*as;
	struct hat	*hat;
	int		i, j, out_idx, info_count;
	lgrp_t		*lgrp;
	pfn_t		pfn;
	ssize_t		pgsz;
	int		*req_array, *val_array;
	uint64_t	*in_array, *out_array;
	uint64_t	addr, paddr;
	uintptr_t	vaddr;
	int		ret = 0;
	struct meminfo minfo;
#if defined(_SYSCALL32_IMPL)
	struct meminfo32 minfo32;
#endif

	/*
	 * Make sure that there is at least one address to translate and
	 * limit how many virtual addresses the kernel can do per call
	 */
	if (addr_count < 1)
		return (set_errno(EINVAL));
	else if (addr_count > MAX_MEMINFO_CNT)
		addr_count = MAX_MEMINFO_CNT;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(mip, &minfo, sizeof (struct meminfo)))
			return (set_errno(EFAULT));
	}
#if defined(_SYSCALL32_IMPL)
	else {
		bzero(&minfo, sizeof (minfo));
		if (copyin(mip, &minfo32, sizeof (struct meminfo32)))
			return (set_errno(EFAULT));
		minfo.mi_inaddr = (const uint64_t *)(uintptr_t)
		    minfo32.mi_inaddr;
		minfo.mi_info_req = (const uint_t *)(uintptr_t)
		    minfo32.mi_info_req;
		minfo.mi_info_count = minfo32.mi_info_count;
		minfo.mi_outdata = (uint64_t *)(uintptr_t)
		    minfo32.mi_outdata;
		minfo.mi_validity = (uint_t *)(uintptr_t)
		    minfo32.mi_validity;
	}
#endif
	/*
	 * all the input parameters have been copied in:-
	 * addr_count - number of input addresses
	 * minfo.mi_inaddr - array of input addresses
	 * minfo.mi_info_req - array of types of information requested
	 * minfo.mi_info_count - no. of pieces of info requested for each addr
	 * minfo.mi_outdata - array into which the results are placed
	 * minfo.mi_validity -  array containing bitwise result codes; 0th bit
	 *			evaluates validity of corresponding input
	 *			address, 1st bit validity of response to first
	 *			member of info_req, etc.
	 */

	/* make sure mi_info_count is within limit */
	info_count = minfo.mi_info_count;
	if (info_count < 1 || info_count > MAX_MEMINFO_REQ)
		return (set_errno(EINVAL));

	/*
	 * allocate buffer in_array for the input addresses and copy them in
	 */
	in_size = sizeof (uint64_t) * addr_count;
	in_array = kmem_alloc(in_size, KM_SLEEP);
	if (copyin(minfo.mi_inaddr, in_array, in_size)) {
		kmem_free(in_array, in_size);
		return (set_errno(EFAULT));
	}

	/*
	 * allocate buffer req_array for the input info_reqs and copy them in
	 */
	req_size = sizeof (uint_t) * info_count;
	req_array = kmem_alloc(req_size, KM_SLEEP);
	if (copyin(minfo.mi_info_req, req_array, req_size)) {
		kmem_free(req_array, req_size);
		kmem_free(in_array, in_size);
		return (set_errno(EFAULT));
	}

	/*
	 * Validate privs for each req.
	 */
	for (i = 0; i < info_count; i++) {
		switch (req_array[i] & MEMINFO_MASK) {
		case MEMINFO_VLGRP:
		case MEMINFO_VPAGESIZE:
			break;
		default:
			if (secpolicy_meminfo(CRED()) != 0) {
				kmem_free(req_array, req_size);
				kmem_free(in_array, in_size);
				return (set_errno(EPERM));
			}
			break;
		}
	}

	/*
	 * allocate buffer out_array which holds the results and will have
	 * to be copied out later
	 */
	out_size = sizeof (uint64_t) * addr_count * info_count;
	out_array = kmem_alloc(out_size, KM_SLEEP);

	/*
	 * allocate buffer val_array which holds the validity bits and will
	 * have to be copied out later
	 */
	val_size = sizeof (uint_t) * addr_count;
	val_array = kmem_alloc(val_size, KM_SLEEP);

	if ((req_array[0] & MEMINFO_MASK) == MEMINFO_PLGRP) {
		/* find the corresponding lgroup for each physical address */
		for (i = 0; i < addr_count; i++) {
			paddr = in_array[i];
			pfn = btop(paddr);
			lgrp = lgrp_pfn_to_lgrp(pfn);
			if (lgrp) {
				out_array[i] = lgrp->lgrp_id;
				val_array[i] = VALID_ADDR | VALID_REQ;
			} else {
				out_array[i] = NULL;
				val_array[i] = 0;
			}
		}
	} else {
		/* get the corresponding memory info for each virtual address */
		as = curproc->p_as;

		AS_LOCK_ENTER(as, RW_READER);
		hat = as->a_hat;
		for (i = out_idx = 0; i < addr_count; i++, out_idx +=
		    info_count) {
			addr = in_array[i];
			vaddr = (uintptr_t)(addr & ~PAGEOFFSET);
			if (!as_segat(as, (caddr_t)vaddr)) {
				val_array[i] = 0;
				continue;
			}
			val_array[i] = VALID_ADDR;
			pfn = hat_getpfnum(hat, (caddr_t)vaddr);
			if (pfn != PFN_INVALID) {
				paddr = (uint64_t)((pfn << PAGESHIFT) |
				    (addr & PAGEOFFSET));
				for (j = 0; j < info_count; j++) {
					switch (req_array[j] & MEMINFO_MASK) {
					case MEMINFO_VPHYSICAL:
						/*
						 * return the physical address
						 * corresponding to the input
						 * virtual address
						 */
						out_array[out_idx + j] = paddr;
						val_array[i] |= VALID_REQ << j;
						break;
					case MEMINFO_VLGRP:
						/*
						 * return the lgroup of physical
						 * page corresponding to the
						 * input virtual address
						 */
						lgrp = lgrp_pfn_to_lgrp(pfn);
						if (lgrp) {
							out_array[out_idx + j] =
							    lgrp->lgrp_id;
							val_array[i] |=
							    VALID_REQ << j;
						}
						break;
					case MEMINFO_VPAGESIZE:
						/*
						 * return the size of physical
						 * page corresponding to the
						 * input virtual address
						 */
						pgsz = hat_getpagesize(hat,
						    (caddr_t)vaddr);
						if (pgsz != -1) {
							out_array[out_idx + j] =
							    pgsz;
							val_array[i] |=
							    VALID_REQ << j;
						}
						break;
					case MEMINFO_VREPLCNT:
						/*
						 * for future use:-
						 * return the no. replicated
						 * physical pages corresponding
						 * to the input virtual address,
						 * so it is always 0 at the
						 * moment
						 */
						out_array[out_idx + j] = 0;
						val_array[i] |= VALID_REQ << j;
						break;
					case MEMINFO_VREPL:
						/*
						 * for future use:-
						 * return the nth physical
						 * replica of the specified
						 * virtual address
						 */
						break;
					case MEMINFO_VREPL_LGRP:
						/*
						 * for future use:-
						 * return the lgroup of nth
						 * physical replica of the
						 * specified virtual address
						 */
						break;
					case MEMINFO_PLGRP:
						/*
						 * this is for physical address
						 * only, shouldn't mix with
						 * virtual address
						 */
						break;
					default:
						break;
					}
				}
			}
		}
		AS_LOCK_EXIT(as);
	}

	/* copy out the results and validity bits and free the buffers */
	if ((copyout(out_array, minfo.mi_outdata, out_size) != 0) ||
	    (copyout(val_array, minfo.mi_validity, val_size) != 0))
		ret = set_errno(EFAULT);

	kmem_free(in_array, in_size);
	kmem_free(out_array, out_size);
	kmem_free(req_array, req_size);
	kmem_free(val_array, val_size);

	return (ret);
}


/*
 * Initialize lgroup affinities for thread
 */
void
lgrp_affinity_init(lgrp_affinity_t **bufaddr)
{
	if (bufaddr)
		*bufaddr = NULL;
}


/*
 * Free lgroup affinities for thread and set to NULL
 * just in case thread gets recycled
 */
void
lgrp_affinity_free(lgrp_affinity_t **bufaddr)
{
	if (bufaddr && *bufaddr) {
		kmem_free(*bufaddr, nlgrpsmax * sizeof (lgrp_affinity_t));
		*bufaddr = NULL;
	}
}


#define	P_ANY	-2	/* cookie specifying any ID */


/*
 * Find LWP with given ID in specified process and get its affinity for
 * specified lgroup
 */
lgrp_affinity_t
lgrp_affinity_get_thread(proc_t *p, id_t lwpid, lgrp_id_t lgrp)
{
	lgrp_affinity_t aff;
	int		found;
	kthread_t	*t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	aff = LGRP_AFF_NONE;
	found = 0;
	t = p->p_tlist;
	/*
	 * The process may be executing in proc_exit() and its p->p_list may be
	 * already NULL.
	 */
	if (t == NULL)
		return (set_errno(ESRCH));

	do {
		if (t->t_tid == lwpid || lwpid == P_ANY) {
			thread_lock(t);
			/*
			 * Check to see whether caller has permission to set
			 * affinity for LWP
			 */
			if (t->t_cid == 0 || !hasprocperm(t->t_cred, CRED())) {
				thread_unlock(t);
				return (set_errno(EPERM));
			}

			if (t->t_lgrp_affinity)
				aff = t->t_lgrp_affinity[lgrp];
			thread_unlock(t);
			found = 1;
			break;
		}
	} while ((t = t->t_forw) != p->p_tlist);
	if (!found)
		aff = set_errno(ESRCH);

	return (aff);
}


/*
 * Get lgroup affinity for given LWP
 */
lgrp_affinity_t
lgrp_affinity_get(lgrp_affinity_args_t *ap)
{
	lgrp_affinity_t		aff;
	lgrp_affinity_args_t	args;
	id_t			id;
	idtype_t		idtype;
	lgrp_id_t		lgrp;
	proc_t			*p;
	kthread_t		*t;

	/*
	 * Copyin arguments
	 */
	if (copyin(ap, &args, sizeof (lgrp_affinity_args_t)) != 0)
		return (set_errno(EFAULT));

	id = args.id;
	idtype = args.idtype;
	lgrp = args.lgrp;

	/*
	 * Check for invalid lgroup
	 */
	if (lgrp < 0 || lgrp == LGRP_NONE)
		return (set_errno(EINVAL));

	/*
	 * Check for existing lgroup
	 */
	if (lgrp > lgrp_alloc_max)
		return (set_errno(ESRCH));

	/*
	 * Get lgroup affinity for given LWP or process
	 */
	switch (idtype) {

	case P_LWPID:
		/*
		 * LWP in current process
		 */
		p = curproc;
		mutex_enter(&p->p_lock);
		if (id != P_MYID)	/* different thread */
			aff = lgrp_affinity_get_thread(p, id, lgrp);
		else {			/* current thread */
			aff = LGRP_AFF_NONE;
			t = curthread;
			thread_lock(t);
			if (t->t_lgrp_affinity)
				aff = t->t_lgrp_affinity[lgrp];
			thread_unlock(t);
		}
		mutex_exit(&p->p_lock);
		break;

	case P_PID:
		/*
		 * Process
		 */
		mutex_enter(&pidlock);

		if (id == P_MYID)
			p = curproc;
		else {
			p = prfind(id);
			if (p == NULL) {
				mutex_exit(&pidlock);
				return (set_errno(ESRCH));
			}
		}

		mutex_enter(&p->p_lock);
		aff = lgrp_affinity_get_thread(p, P_ANY, lgrp);
		mutex_exit(&p->p_lock);

		mutex_exit(&pidlock);
		break;

	default:
		aff = set_errno(EINVAL);
		break;
	}

	return (aff);
}


/*
 * Find lgroup for which this thread has most affinity in specified partition
 * starting from home lgroup unless specified starting lgroup is preferred
 */
lpl_t *
lgrp_affinity_best(kthread_t *t, struct cpupart *cpupart, lgrp_id_t start,
    boolean_t prefer_start)
{
	lgrp_affinity_t	*affs;
	lgrp_affinity_t	best_aff;
	lpl_t		*best_lpl;
	lgrp_id_t	finish;
	lgrp_id_t	home;
	lgrp_id_t	lgrpid;
	lpl_t		*lpl;

	ASSERT(t != NULL);
	ASSERT((MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0) ||
	    (MUTEX_HELD(&ttoproc(t)->p_lock) && THREAD_LOCK_HELD(t)));
	ASSERT(cpupart != NULL);

	if (t->t_lgrp_affinity == NULL)
		return (NULL);

	affs = t->t_lgrp_affinity;

	/*
	 * Thread bound to CPU
	 */
	if (t->t_bind_cpu != PBIND_NONE) {
		cpu_t	*cp;

		/*
		 * Find which lpl has most affinity among leaf lpl directly
		 * containing CPU and its ancestor lpls
		 */
		cp = cpu[t->t_bind_cpu];

		best_lpl = lpl = cp->cpu_lpl;
		best_aff = affs[best_lpl->lpl_lgrpid];
		while (lpl->lpl_parent != NULL) {
			lpl = lpl->lpl_parent;
			lgrpid = lpl->lpl_lgrpid;
			if (affs[lgrpid] > best_aff) {
				best_lpl = lpl;
				best_aff = affs[lgrpid];
			}
		}
		return (best_lpl);
	}

	/*
	 * Start searching from home lgroup unless given starting lgroup is
	 * preferred or home lgroup isn't in given pset.  Use root lgroup as
	 * starting point if both home and starting lgroups aren't in given
	 * pset.
	 */
	ASSERT(start >= 0 && start <= lgrp_alloc_max);
	home = t->t_lpl->lpl_lgrpid;
	if (!prefer_start && LGRP_CPUS_IN_PART(home, cpupart))
		lgrpid = home;
	else if (start != LGRP_NONE && LGRP_CPUS_IN_PART(start, cpupart))
		lgrpid = start;
	else
		lgrpid = LGRP_ROOTID;

	best_lpl = &cpupart->cp_lgrploads[lgrpid];
	best_aff = affs[lgrpid];
	finish = lgrpid;
	do {
		/*
		 * Skip any lgroups that don't have CPU resources
		 * in this processor set.
		 */
		if (!LGRP_CPUS_IN_PART(lgrpid, cpupart)) {
			if (++lgrpid > lgrp_alloc_max)
				lgrpid = 0;	/* wrap the search */
			continue;
		}

		/*
		 * Find lgroup with most affinity
		 */
		lpl = &cpupart->cp_lgrploads[lgrpid];
		if (affs[lgrpid] > best_aff) {
			best_aff = affs[lgrpid];
			best_lpl = lpl;
		}

		if (++lgrpid > lgrp_alloc_max)
			lgrpid = 0;	/* wrap the search */

	} while (lgrpid != finish);

	/*
	 * No lgroup (in this pset) with any affinity
	 */
	if (best_aff == LGRP_AFF_NONE)
		return (NULL);

	lgrpid = best_lpl->lpl_lgrpid;
	ASSERT(LGRP_CPUS_IN_PART(lgrpid, cpupart) && best_lpl->lpl_ncpu > 0);

	return (best_lpl);
}


/*
 * Set thread's affinity for given lgroup
 */
int
lgrp_affinity_set_thread(kthread_t *t, lgrp_id_t lgrp, lgrp_affinity_t aff,
    lgrp_affinity_t **aff_buf)
{
	lgrp_affinity_t	*affs;
	lgrp_id_t	best;
	lpl_t		*best_lpl;
	lgrp_id_t	home;
	int		retval;

	ASSERT(t != NULL);
	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	retval = 0;

	thread_lock(t);

	/*
	 * Check to see whether caller has permission to set affinity for
	 * thread
	 */
	if (t->t_cid == 0 || !hasprocperm(t->t_cred, CRED())) {
		thread_unlock(t);
		return (set_errno(EPERM));
	}

	if (t->t_lgrp_affinity == NULL) {
		if (aff == LGRP_AFF_NONE) {
			thread_unlock(t);
			return (0);
		}
		ASSERT(aff_buf != NULL && *aff_buf != NULL);
		t->t_lgrp_affinity = *aff_buf;
		*aff_buf = NULL;
	}

	affs = t->t_lgrp_affinity;
	affs[lgrp] = aff;

	/*
	 * Find lgroup for which thread has most affinity,
	 * starting with lgroup for which affinity being set
	 */
	best_lpl = lgrp_affinity_best(t, t->t_cpupart, lgrp, B_TRUE);

	/*
	 * Rehome if found lgroup with more affinity than home or lgroup for
	 * which affinity is being set has same affinity as home
	 */
	home = t->t_lpl->lpl_lgrpid;
	if (best_lpl != NULL && best_lpl != t->t_lpl) {
		best = best_lpl->lpl_lgrpid;
		if (affs[best] > affs[home] || (affs[best] == affs[home] &&
		    best == lgrp))
			lgrp_move_thread(t, best_lpl, 1);
	}

	thread_unlock(t);

	return (retval);
}


/*
 * Set process' affinity for specified lgroup
 */
int
lgrp_affinity_set_proc(proc_t *p, lgrp_id_t lgrp, lgrp_affinity_t aff,
    lgrp_affinity_t **aff_buf_array)
{
	lgrp_affinity_t	*buf;
	int		err = 0;
	int		i;
	int		retval;
	kthread_t	*t;

	ASSERT(MUTEX_HELD(&pidlock) && MUTEX_HELD(&p->p_lock));
	ASSERT(aff_buf_array != NULL);

	i = 0;
	t = p->p_tlist;
	if (t != NULL) {
		do {
			/*
			 * Set lgroup affinity for thread
			 */
			buf = aff_buf_array[i];
			retval = lgrp_affinity_set_thread(t, lgrp, aff, &buf);

			if (err == 0 && retval != 0)
				err = retval;

			/*
			 * Advance pointer to next buffer
			 */
			if (buf == NULL) {
				ASSERT(i < p->p_lwpcnt);
				aff_buf_array[i] = NULL;
				i++;
			}

		} while ((t = t->t_forw) != p->p_tlist);
	}
	return (err);
}


/*
 * Set LWP's or process' affinity for specified lgroup
 *
 * When setting affinities, pidlock, process p_lock, and thread_lock()
 * need to be held in that order to protect target thread's pset, process,
 * process contents, and thread contents.  thread_lock() does splhigh(),
 * so it ends up having similiar effect as kpreempt_disable(), so it will
 * protect calls to lgrp_move_thread() and lgrp_choose() from pset changes.
 */
int
lgrp_affinity_set(lgrp_affinity_args_t *ap)
{
	lgrp_affinity_t		aff;
	lgrp_affinity_t		*aff_buf;
	lgrp_affinity_args_t	args;
	id_t			id;
	idtype_t		idtype;
	lgrp_id_t		lgrp;
	int			nthreads;
	proc_t			*p;
	int			retval;

	/*
	 * Copyin arguments
	 */
	if (copyin(ap, &args, sizeof (lgrp_affinity_args_t)) != 0)
		return (set_errno(EFAULT));

	idtype = args.idtype;
	id = args.id;
	lgrp = args.lgrp;
	aff = args.aff;

	/*
	 * Check for invalid lgroup
	 */
	if (lgrp < 0 || lgrp == LGRP_NONE)
		return (set_errno(EINVAL));

	/*
	 * Check for existing lgroup
	 */
	if (lgrp > lgrp_alloc_max)
		return (set_errno(ESRCH));

	/*
	 * Check for legal affinity
	 */
	if (aff != LGRP_AFF_NONE && aff != LGRP_AFF_WEAK &&
	    aff != LGRP_AFF_STRONG)
		return (set_errno(EINVAL));

	/*
	 * Must be process or LWP ID
	 */
	if (idtype != P_LWPID && idtype != P_PID)
		return (set_errno(EINVAL));

	/*
	 * Set given LWP's or process' affinity for specified lgroup
	 */
	switch (idtype) {

	case P_LWPID:
		/*
		 * Allocate memory for thread's lgroup affinities
		 * ahead of time w/o holding locks
		 */
		aff_buf = kmem_zalloc(nlgrpsmax * sizeof (lgrp_affinity_t),
		    KM_SLEEP);

		p = curproc;

		/*
		 * Set affinity for thread
		 */
		mutex_enter(&p->p_lock);
		if (id == P_MYID) {		/* current thread */
			retval = lgrp_affinity_set_thread(curthread, lgrp, aff,
			    &aff_buf);
		} else if (p->p_tlist == NULL) {
			retval = set_errno(ESRCH);
		} else {			/* other thread */
			int		found = 0;
			kthread_t	*t;

			t = p->p_tlist;
			do {
				if (t->t_tid == id) {
					retval = lgrp_affinity_set_thread(t,
					    lgrp, aff, &aff_buf);
					found = 1;
					break;
				}
			} while ((t = t->t_forw) != p->p_tlist);
			if (!found)
				retval = set_errno(ESRCH);
		}
		mutex_exit(&p->p_lock);

		/*
		 * Free memory for lgroup affinities,
		 * since thread didn't need it
		 */
		if (aff_buf)
			kmem_free(aff_buf,
			    nlgrpsmax * sizeof (lgrp_affinity_t));

		break;

	case P_PID:

		do {
			lgrp_affinity_t	**aff_buf_array;
			int		i;
			size_t		size;

			/*
			 * Get process
			 */
			mutex_enter(&pidlock);

			if (id == P_MYID)
				p = curproc;
			else
				p = prfind(id);

			if (p == NULL) {
				mutex_exit(&pidlock);
				return (set_errno(ESRCH));
			}

			/*
			 * Get number of threads in process
			 *
			 * NOTE: Only care about user processes,
			 *	 so p_lwpcnt should be number of threads.
			 */
			mutex_enter(&p->p_lock);
			nthreads = p->p_lwpcnt;
			mutex_exit(&p->p_lock);

			mutex_exit(&pidlock);

			if (nthreads < 1)
				return (set_errno(ESRCH));

			/*
			 * Preallocate memory for lgroup affinities for
			 * each thread in process now to avoid holding
			 * any locks.  Allocate an array to hold a buffer
			 * for each thread.
			 */
			aff_buf_array = kmem_zalloc(nthreads *
			    sizeof (lgrp_affinity_t *), KM_SLEEP);

			size = nlgrpsmax * sizeof (lgrp_affinity_t);
			for (i = 0; i < nthreads; i++)
				aff_buf_array[i] = kmem_zalloc(size, KM_SLEEP);

			mutex_enter(&pidlock);

			/*
			 * Get process again since dropped locks to allocate
			 * memory (except current process)
			 */
			if (id != P_MYID)
				p = prfind(id);

			/*
			 * Process went away after we dropped locks and before
			 * reacquiring them, so drop locks, free memory, and
			 * return.
			 */
			if (p == NULL) {
				mutex_exit(&pidlock);
				for (i = 0; i < nthreads; i++)
					kmem_free(aff_buf_array[i], size);
				kmem_free(aff_buf_array,
				    nthreads * sizeof (lgrp_affinity_t *));
				return (set_errno(ESRCH));
			}

			mutex_enter(&p->p_lock);

			/*
			 * See whether number of threads is same
			 * If not, drop locks, free memory, and try again
			 */
			if (nthreads != p->p_lwpcnt) {
				mutex_exit(&p->p_lock);
				mutex_exit(&pidlock);
				for (i = 0; i < nthreads; i++)
					kmem_free(aff_buf_array[i], size);
				kmem_free(aff_buf_array,
				    nthreads * sizeof (lgrp_affinity_t *));
				continue;
			}

			/*
			 * Set lgroup affinity for threads in process
			 */
			retval = lgrp_affinity_set_proc(p, lgrp, aff,
			    aff_buf_array);

			mutex_exit(&p->p_lock);
			mutex_exit(&pidlock);

			/*
			 * Free any leftover memory, since some threads may
			 * have already allocated memory and set lgroup
			 * affinities before
			 */
			for (i = 0; i < nthreads; i++)
				if (aff_buf_array[i] != NULL)
					kmem_free(aff_buf_array[i], size);
			kmem_free(aff_buf_array,
			    nthreads * sizeof (lgrp_affinity_t *));

			break;

		} while (nthreads != p->p_lwpcnt);

		break;

	default:
		retval = set_errno(EINVAL);
		break;
	}

	return (retval);
}


/*
 * Return the latest generation number for the lgroup hierarchy
 * with the given view
 */
lgrp_gen_t
lgrp_generation(lgrp_view_t view)
{
	cpupart_t	*cpupart;
	uint_t		gen;

	kpreempt_disable();

	/*
	 * Determine generation number for given view
	 */
	if (view == LGRP_VIEW_OS)
		/*
		 * Return generation number of lgroup hierarchy for OS view
		 */
		gen = lgrp_gen;
	else {
		/*
		 * For caller's view, use generation numbers for lgroup
		 * hierarchy and caller's pset
		 * NOTE: Caller needs to check for change in pset ID
		 */
		cpupart = curthread->t_cpupart;
		ASSERT(cpupart);
		gen = lgrp_gen + cpupart->cp_gen;
	}

	kpreempt_enable();

	return (gen);
}


lgrp_id_t
lgrp_home_thread(kthread_t *t)
{
	lgrp_id_t	home;

	ASSERT(t != NULL);
	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	thread_lock(t);

	/*
	 * Check to see whether caller has permission to set affinity for
	 * thread
	 */
	if (t->t_cid == 0 || !hasprocperm(t->t_cred, CRED())) {
		thread_unlock(t);
		return (set_errno(EPERM));
	}

	home = lgrp_home_id(t);

	thread_unlock(t);
	return (home);
}


/*
 * Get home lgroup of given process or thread
 */
lgrp_id_t
lgrp_home_get(idtype_t idtype, id_t id)
{
	proc_t		*p;
	lgrp_id_t	retval;
	kthread_t	*t;

	/*
	 * Get home lgroup of given LWP or process
	 */
	switch (idtype) {

	case P_LWPID:
		p = curproc;

		/*
		 * Set affinity for thread
		 */
		mutex_enter(&p->p_lock);
		if (id == P_MYID) {		/* current thread */
			retval = lgrp_home_thread(curthread);
		} else if (p->p_tlist == NULL) {
			retval = set_errno(ESRCH);
		} else {			/* other thread */
			int	found = 0;

			t = p->p_tlist;
			do {
				if (t->t_tid == id) {
					retval = lgrp_home_thread(t);
					found = 1;
					break;
				}
			} while ((t = t->t_forw) != p->p_tlist);
			if (!found)
				retval = set_errno(ESRCH);
		}
		mutex_exit(&p->p_lock);
		break;

	case P_PID:
		/*
		 * Get process
		 */
		mutex_enter(&pidlock);

		if (id == P_MYID)
			p = curproc;
		else
			p = prfind(id);

		if (p == NULL) {
			mutex_exit(&pidlock);
			return (set_errno(ESRCH));
		}

		mutex_enter(&p->p_lock);
		t = p->p_tlist;
		if (t == NULL)
			retval = set_errno(ESRCH);
		else
			retval = lgrp_home_thread(t);
		mutex_exit(&p->p_lock);

		mutex_exit(&pidlock);

		break;

	default:
		retval = set_errno(EINVAL);
		break;
	}

	return (retval);
}


/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 */
int
lgrp_latency(lgrp_id_t from, lgrp_id_t to)
{
	lgrp_t		*from_lgrp;
	int		i;
	int		latency;
	int		latency_max;
	lgrp_t		*to_lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (from < 0 || to < 0)
		return (set_errno(EINVAL));

	if (from > lgrp_alloc_max || to > lgrp_alloc_max)
		return (set_errno(ESRCH));

	from_lgrp = lgrp_table[from];
	to_lgrp = lgrp_table[to];

	if (!LGRP_EXISTS(from_lgrp) || !LGRP_EXISTS(to_lgrp)) {
		return (set_errno(ESRCH));
	}

	/*
	 * Get latency for same lgroup
	 */
	if (from == to) {
		latency = from_lgrp->lgrp_latency;
		return (latency);
	}

	/*
	 * Get latency between leaf lgroups
	 */
	if (from_lgrp->lgrp_childcnt == 0 && to_lgrp->lgrp_childcnt == 0)
		return (lgrp_plat_latency(from_lgrp->lgrp_plathand,
		    to_lgrp->lgrp_plathand));

	/*
	 * Determine max latency between resources in two lgroups
	 */
	latency_max = 0;
	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_t	*from_rsrc;
		int	j;
		lgrp_t	*to_rsrc;

		from_rsrc = lgrp_table[i];
		if (!LGRP_EXISTS(from_rsrc) ||
		    !klgrpset_ismember(from_lgrp->lgrp_set[LGRP_RSRC_CPU], i))
			continue;

		for (j = 0; j <= lgrp_alloc_max; j++) {
			to_rsrc = lgrp_table[j];
			if (!LGRP_EXISTS(to_rsrc) ||
			    klgrpset_ismember(to_lgrp->lgrp_set[LGRP_RSRC_MEM],
			    j) == 0)
				continue;
			latency = lgrp_plat_latency(from_rsrc->lgrp_plathand,
			    to_rsrc->lgrp_plathand);
			if (latency > latency_max)
				latency_max = latency;
		}
	}
	return (latency_max);
}


/*
 * Return lgroup interface version number
 * 0 - none
 * 1 - original
 * 2 - lgrp_latency_cookie() and lgrp_resources() added
 */
int
lgrp_version(int version)
{
	/*
	 * Return LGRP_VER_NONE when requested version isn't supported
	 */
	if (version < LGRP_VER_NONE || version > LGRP_VER_CURRENT)
		return (LGRP_VER_NONE);

	/*
	 * Return current version when LGRP_VER_NONE passed in
	 */
	if (version == LGRP_VER_NONE)
		return (LGRP_VER_CURRENT);

	/*
	 * Otherwise, return supported version.
	 */
	return (version);
}


/*
 * Snapshot of lgroup hieararchy
 *
 * One snapshot is kept and is based on the kernel's native data model, so
 * a 32-bit snapshot is kept for the 32-bit kernel and a 64-bit one for the
 * 64-bit kernel.  If a 32-bit user wants a snapshot from the 64-bit kernel,
 * the kernel generates a 32-bit snapshot from the data in its 64-bit snapshot.
 *
 * The format is defined by lgroup snapshot header and the layout of
 * the snapshot in memory is as follows:
 * 1) lgroup snapshot header
 *    - specifies format of snapshot
 *    - defined by lgrp_snapshot_header_t
 * 2) lgroup info array
 *    - contains information about each lgroup
 *    - one element for each lgroup
 *    - each element is defined by lgrp_info_t
 * 3) lgroup CPU ID array
 *    - contains list (array) of CPU IDs for each lgroup
 *    - lgrp_info_t points into array and specifies how many CPUs belong to
 *      given lgroup
 * 4) lgroup parents array
 *    - contains lgroup bitmask of parents for each lgroup
 *    - bitmask is an array of unsigned longs and its size depends on nlgrpsmax
 * 5) lgroup children array
 *    - contains lgroup bitmask of children for each lgroup
 *    - bitmask is an array of unsigned longs and its size depends on nlgrpsmax
 * 6) lgroup resources array
 *    - contains lgroup bitmask of resources for each lgroup
 *    - bitmask is an array of unsigned longs and its size depends on nlgrpsmax
 * 7) lgroup latency table
 *    - contains latency from each lgroup to each of other lgroups
 *
 * NOTE:  Must use nlgrpsmax for per lgroup data structures because lgroups
 *	  may be sparsely allocated.
 */
lgrp_snapshot_header_t	*lgrp_snap = NULL;	/* lgroup snapshot */
static kmutex_t		lgrp_snap_lock;		/* snapshot lock */


/*
 * Take a snapshot of lgroup hierarchy and return size of buffer
 * needed to hold snapshot
 */
static int
lgrp_snapshot(void)
{
	size_t		bitmask_size;
	size_t		bitmasks_size;
	size_t		bufsize;
	int		cpu_index;
	size_t		cpuids_size;
	int		i;
	int		j;
	size_t		info_size;
	size_t		lats_size;
	ulong_t		*lgrp_children;
	processorid_t	*lgrp_cpuids;
	lgrp_info_t	*lgrp_info;
	int		**lgrp_lats;
	ulong_t		*lgrp_parents;
	ulong_t		*lgrp_rsets;
	ulong_t		*lgrpset;
	int		snap_ncpus;
	int		snap_nlgrps;
	int		snap_nlgrpsmax;
	size_t		snap_hdr_size;
#ifdef	_SYSCALL32_IMPL
	model_t		model = DATAMODEL_NATIVE;

	/*
	 * Have up-to-date snapshot, so check to see whether caller is 32-bit
	 * program and need to return size of 32-bit snapshot now.
	 */
	model = get_udatamodel();
	if (model == DATAMODEL_ILP32 && lgrp_snap &&
	    lgrp_snap->ss_gen == lgrp_gen) {

		snap_nlgrpsmax = lgrp_snap->ss_nlgrps_max;

		/*
		 * Calculate size of buffer needed for 32-bit snapshot,
		 * rounding up size of each object to allow for alignment
		 * of next object in buffer.
		 */
		snap_hdr_size = P2ROUNDUP(sizeof (lgrp_snapshot_header32_t),
		    sizeof (caddr32_t));
		info_size =
		    P2ROUNDUP(snap_nlgrpsmax * sizeof (lgrp_info32_t),
		    sizeof (processorid_t));
		cpuids_size =
		    P2ROUNDUP(lgrp_snap->ss_ncpus * sizeof (processorid_t),
		    sizeof (ulong_t));

		/*
		 * lgroup bitmasks needed for parents, children, and resources
		 * for each lgroup and pset lgroup set
		 */
		bitmask_size = BT_SIZEOFMAP(snap_nlgrpsmax);
		bitmasks_size = (((2 + LGRP_RSRC_COUNT) *
		    snap_nlgrpsmax) + 1) * bitmask_size;

		/*
		 * Size of latency table and buffer
		 */
		lats_size = snap_nlgrpsmax * sizeof (caddr32_t) +
		    snap_nlgrpsmax * snap_nlgrpsmax * sizeof (int);

		bufsize = snap_hdr_size + info_size + cpuids_size +
		    bitmasks_size + lats_size;
		return (bufsize);
	}
#endif	/* _SYSCALL32_IMPL */

	/*
	 * Check whether snapshot is up-to-date
	 * Free it and take another one if not
	 */
	if (lgrp_snap) {
		if (lgrp_snap->ss_gen == lgrp_gen)
			return (lgrp_snap->ss_size);

		kmem_free(lgrp_snap, lgrp_snap->ss_size);
		lgrp_snap = NULL;
	}

	/*
	 * Allocate memory for snapshot
	 * w/o holding cpu_lock while waiting for memory
	 */
	while (lgrp_snap == NULL) {
		int	old_generation;

		/*
		 * Take snapshot of lgroup generation number
		 * and configuration size dependent information
		 * NOTE: Only count number of online CPUs,
		 * since only online CPUs appear in lgroups.
		 */
		mutex_enter(&cpu_lock);
		old_generation = lgrp_gen;
		snap_ncpus = ncpus_online;
		snap_nlgrps = nlgrps;
		snap_nlgrpsmax = nlgrpsmax;
		mutex_exit(&cpu_lock);

		/*
		 * Calculate size of buffer needed for snapshot,
		 * rounding up size of each object to allow for alignment
		 * of next object in buffer.
		 */
		snap_hdr_size = P2ROUNDUP(sizeof (lgrp_snapshot_header_t),
		    sizeof (void *));
		info_size = P2ROUNDUP(snap_nlgrpsmax * sizeof (lgrp_info_t),
		    sizeof (processorid_t));
		cpuids_size = P2ROUNDUP(snap_ncpus * sizeof (processorid_t),
		    sizeof (ulong_t));
		/*
		 * lgroup bitmasks needed for pset lgroup set and  parents,
		 * children, and resource sets for each lgroup
		 */
		bitmask_size = BT_SIZEOFMAP(snap_nlgrpsmax);
		bitmasks_size = (((2 + LGRP_RSRC_COUNT) *
		    snap_nlgrpsmax) + 1) * bitmask_size;

		/*
		 * Size of latency table and buffer
		 */
		lats_size = snap_nlgrpsmax * sizeof (int *) +
		    snap_nlgrpsmax * snap_nlgrpsmax * sizeof (int);

		bufsize = snap_hdr_size + info_size + cpuids_size +
		    bitmasks_size + lats_size;

		/*
		 * Allocate memory for buffer
		 */
		lgrp_snap = kmem_zalloc(bufsize, KM_NOSLEEP);
		if (lgrp_snap == NULL)
			return (set_errno(ENOMEM));

		/*
		 * Check whether generation number has changed
		 */
		mutex_enter(&cpu_lock);
		if (lgrp_gen == old_generation)
			break;		/* hasn't change, so done. */

		/*
		 * Generation number changed, so free memory and try again.
		 */
		mutex_exit(&cpu_lock);
		kmem_free(lgrp_snap, bufsize);
		lgrp_snap = NULL;
	}

	/*
	 * Fill in lgroup snapshot header
	 * (including pointers to tables of lgroup info, CPU IDs, and parents
	 * and children)
	 */
	lgrp_snap->ss_version = LGRP_VER_CURRENT;

	/*
	 * XXX For now, liblgrp only needs to know whether the hierarchy
	 * XXX only has one level or not
	 */
	if (snap_nlgrps == 1)
		lgrp_snap->ss_levels = 1;
	else
		lgrp_snap->ss_levels = 2;

	lgrp_snap->ss_root = LGRP_ROOTID;

	lgrp_snap->ss_nlgrps = lgrp_snap->ss_nlgrps_os = snap_nlgrps;
	lgrp_snap->ss_nlgrps_max = snap_nlgrpsmax;
	lgrp_snap->ss_ncpus = snap_ncpus;
	lgrp_snap->ss_gen = lgrp_gen;
	lgrp_snap->ss_view = LGRP_VIEW_OS;
	lgrp_snap->ss_pset = 0;		/* NOTE: caller should set if needed */
	lgrp_snap->ss_size = bufsize;
	lgrp_snap->ss_magic = (uintptr_t)lgrp_snap;

	lgrp_snap->ss_info = lgrp_info =
	    (lgrp_info_t *)((uintptr_t)lgrp_snap + snap_hdr_size);

	lgrp_snap->ss_cpuids = lgrp_cpuids =
	    (processorid_t *)((uintptr_t)lgrp_info + info_size);

	lgrp_snap->ss_lgrpset = lgrpset =
	    (ulong_t *)((uintptr_t)lgrp_cpuids + cpuids_size);

	lgrp_snap->ss_parents = lgrp_parents =
	    (ulong_t *)((uintptr_t)lgrpset + bitmask_size);

	lgrp_snap->ss_children = lgrp_children =
	    (ulong_t *)((uintptr_t)lgrp_parents + (snap_nlgrpsmax *
	    bitmask_size));

	lgrp_snap->ss_rsets = lgrp_rsets =
	    (ulong_t *)((uintptr_t)lgrp_children + (snap_nlgrpsmax *
	    bitmask_size));

	lgrp_snap->ss_latencies = lgrp_lats =
	    (int **)((uintptr_t)lgrp_rsets + (LGRP_RSRC_COUNT *
	    snap_nlgrpsmax * bitmask_size));

	/*
	 * Fill in lgroup information
	 */
	cpu_index = 0;
	for (i = 0; i < snap_nlgrpsmax; i++) {
		struct cpu	*cp;
		int		cpu_count;
		struct cpu	*head;
		int		k;
		lgrp_t		*lgrp;

		lgrp = lgrp_table[i];
		if (!LGRP_EXISTS(lgrp)) {
			bzero(&lgrp_info[i], sizeof (lgrp_info[i]));
			lgrp_info[i].info_lgrpid = LGRP_NONE;
			continue;
		}

		lgrp_info[i].info_lgrpid = i;
		lgrp_info[i].info_latency = lgrp->lgrp_latency;

		/*
		 * Fill in parents, children, and lgroup resources
		 */
		lgrp_info[i].info_parents =
		    (ulong_t *)((uintptr_t)lgrp_parents + (i * bitmask_size));

		if (lgrp->lgrp_parent)
			BT_SET(lgrp_info[i].info_parents,
			    lgrp->lgrp_parent->lgrp_id);

		lgrp_info[i].info_children =
		    (ulong_t *)((uintptr_t)lgrp_children + (i * bitmask_size));

		for (j = 0; j < snap_nlgrpsmax; j++)
			if (klgrpset_ismember(lgrp->lgrp_children, j))
				BT_SET(lgrp_info[i].info_children, j);

		lgrp_info[i].info_rset =
		    (ulong_t *)((uintptr_t)lgrp_rsets +
		    (i * LGRP_RSRC_COUNT * bitmask_size));

		for (j = 0; j < LGRP_RSRC_COUNT; j++) {
			ulong_t	*rset;

			rset = (ulong_t *)((uintptr_t)lgrp_info[i].info_rset +
			    (j * bitmask_size));
			for (k = 0; k < snap_nlgrpsmax; k++)
				if (klgrpset_ismember(lgrp->lgrp_set[j], k))
					BT_SET(rset, k);
		}

		/*
		 * Fill in CPU IDs
		 */
		cpu_count = 0;
		lgrp_info[i].info_cpuids = NULL;
		cp = head = lgrp->lgrp_cpu;
		if (head != NULL) {
			lgrp_info[i].info_cpuids = &lgrp_cpuids[cpu_index];
			do {
				lgrp_cpuids[cpu_index] = cp->cpu_id;
				cpu_index++;
				cpu_count++;
				cp = cp->cpu_next_lgrp;
			} while (cp != head);
		}
		ASSERT(cpu_count == lgrp->lgrp_cpucnt);
		lgrp_info[i].info_ncpus = cpu_count;

		/*
		 * Fill in memory sizes for lgroups that directly contain
		 * memory
		 */
		if (klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_MEM], i)) {
			lgrp_info[i].info_mem_free =
			    lgrp_mem_size(i, LGRP_MEM_SIZE_FREE);
			lgrp_info[i].info_mem_install =
			    lgrp_mem_size(i, LGRP_MEM_SIZE_INSTALL);
		}

		/*
		 * Fill in latency table and buffer
		 */
		lgrp_lats[i] = (int *)((uintptr_t)lgrp_lats + snap_nlgrpsmax *
		    sizeof (int *) + i * snap_nlgrpsmax * sizeof (int));
		for (j = 0; j < snap_nlgrpsmax; j++) {
			lgrp_t	*to;

			to = lgrp_table[j];
			if (!LGRP_EXISTS(to))
				continue;
			lgrp_lats[i][j] = lgrp_latency(lgrp->lgrp_id,
			    to->lgrp_id);
		}
	}
	ASSERT(cpu_index == snap_ncpus);


	mutex_exit(&cpu_lock);

#ifdef	_SYSCALL32_IMPL
	/*
	 * Check to see whether caller is 32-bit program and need to return
	 * size of 32-bit snapshot now that snapshot has been taken/updated.
	 * May not have been able to do this earlier if snapshot was out of
	 * date or didn't exist yet.
	 */
	if (model == DATAMODEL_ILP32) {

		snap_nlgrpsmax = lgrp_snap->ss_nlgrps_max;

		/*
		 * Calculate size of buffer needed for 32-bit snapshot,
		 * rounding up size of each object to allow for alignment
		 * of next object in buffer.
		 */
		snap_hdr_size = P2ROUNDUP(sizeof (lgrp_snapshot_header32_t),
		    sizeof (caddr32_t));
		info_size =
		    P2ROUNDUP(snap_nlgrpsmax * sizeof (lgrp_info32_t),
		    sizeof (processorid_t));
		cpuids_size =
		    P2ROUNDUP(lgrp_snap->ss_ncpus * sizeof (processorid_t),
		    sizeof (ulong_t));

		bitmask_size = BT_SIZEOFMAP(snap_nlgrpsmax);
		bitmasks_size = (((2 + LGRP_RSRC_COUNT) * snap_nlgrpsmax) +
		    1) * bitmask_size;


		/*
		 * Size of latency table and buffer
		 */
		lats_size = (snap_nlgrpsmax * sizeof (caddr32_t)) +
		    (snap_nlgrpsmax * snap_nlgrpsmax * sizeof (int));

		bufsize = snap_hdr_size + info_size + cpuids_size +
		    bitmasks_size + lats_size;
		return (bufsize);
	}
#endif	/* _SYSCALL32_IMPL */

	return (lgrp_snap->ss_size);
}


/*
 * Copy snapshot into given user buffer, fix up any pointers in buffer to point
 * into user instead of kernel address space, and return size of buffer
 * needed to hold snapshot
 */
static int
lgrp_snapshot_copy(char *buf, size_t bufsize)
{
	size_t			bitmask_size;
	int			cpu_index;
	size_t			cpuids_size;
	int			i;
	size_t			info_size;
	lgrp_info_t		*lgrp_info;
	int			retval;
	size_t			snap_hdr_size;
	int			snap_ncpus;
	int			snap_nlgrpsmax;
	lgrp_snapshot_header_t	*user_snap;
	lgrp_info_t		*user_info;
	lgrp_info_t		*user_info_buffer;
	processorid_t		*user_cpuids;
	ulong_t			*user_lgrpset;
	ulong_t			*user_parents;
	ulong_t			*user_children;
	int			**user_lats;
	int			**user_lats_buffer;
	ulong_t			*user_rsets;

	if (lgrp_snap == NULL)
		return (0);

	if (buf == NULL || bufsize <= 0)
		return (lgrp_snap->ss_size);

	/*
	 * User needs to try getting size of buffer again
	 * because given buffer size is too small.
	 * The lgroup hierarchy may have changed after they asked for the size
	 * but before the snapshot was taken.
	 */
	if (bufsize < lgrp_snap->ss_size)
		return (set_errno(EAGAIN));

	snap_ncpus = lgrp_snap->ss_ncpus;
	snap_nlgrpsmax = lgrp_snap->ss_nlgrps_max;

	/*
	 * Fill in lgrpset now because caller may have change psets
	 */
	kpreempt_disable();
	for (i = 0; i < snap_nlgrpsmax; i++) {
		if (klgrpset_ismember(curthread->t_cpupart->cp_lgrpset,
		    i)) {
			BT_SET(lgrp_snap->ss_lgrpset, i);
		}
	}
	kpreempt_enable();

	/*
	 * Copy lgroup snapshot (snapshot header, lgroup info, and CPU IDs)
	 * into user buffer all at once
	 */
	if (copyout(lgrp_snap, buf, lgrp_snap->ss_size) != 0)
		return (set_errno(EFAULT));

	/*
	 * Round up sizes of lgroup snapshot header and info for alignment
	 */
	snap_hdr_size = P2ROUNDUP(sizeof (lgrp_snapshot_header_t),
	    sizeof (void *));
	info_size = P2ROUNDUP(snap_nlgrpsmax * sizeof (lgrp_info_t),
	    sizeof (processorid_t));
	cpuids_size = P2ROUNDUP(snap_ncpus * sizeof (processorid_t),
	    sizeof (ulong_t));

	bitmask_size = BT_SIZEOFMAP(snap_nlgrpsmax);

	/*
	 * Calculate pointers into user buffer for lgroup snapshot header,
	 * info, and CPU IDs
	 */
	user_snap = (lgrp_snapshot_header_t *)buf;
	user_info = (lgrp_info_t *)((uintptr_t)user_snap + snap_hdr_size);
	user_cpuids = (processorid_t *)((uintptr_t)user_info + info_size);
	user_lgrpset = (ulong_t *)((uintptr_t)user_cpuids + cpuids_size);
	user_parents = (ulong_t *)((uintptr_t)user_lgrpset + bitmask_size);
	user_children = (ulong_t *)((uintptr_t)user_parents +
	    (snap_nlgrpsmax * bitmask_size));
	user_rsets = (ulong_t *)((uintptr_t)user_children +
	    (snap_nlgrpsmax * bitmask_size));
	user_lats = (int **)((uintptr_t)user_rsets +
	    (LGRP_RSRC_COUNT * snap_nlgrpsmax * bitmask_size));

	/*
	 * Copyout magic number (ie. pointer to beginning of buffer)
	 */
	if (copyout(&buf, &user_snap->ss_magic, sizeof (buf)) != 0)
		return (set_errno(EFAULT));

	/*
	 * Fix up pointers in user buffer to point into user buffer
	 * not kernel snapshot
	 */
	if (copyout(&user_info, &user_snap->ss_info, sizeof (user_info)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_cpuids, &user_snap->ss_cpuids,
	    sizeof (user_cpuids)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_lgrpset, &user_snap->ss_lgrpset,
	    sizeof (user_lgrpset)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_parents, &user_snap->ss_parents,
	    sizeof (user_parents)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_children, &user_snap->ss_children,
	    sizeof (user_children)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_rsets, &user_snap->ss_rsets,
	    sizeof (user_rsets)) != 0)
		return (set_errno(EFAULT));

	if (copyout(&user_lats, &user_snap->ss_latencies,
	    sizeof (user_lats)) != 0)
		return (set_errno(EFAULT));

	/*
	 * Make copies of lgroup info and latency table, fix up pointers,
	 * and then copy them into user buffer
	 */
	user_info_buffer = kmem_zalloc(info_size, KM_NOSLEEP);
	if (user_info_buffer == NULL)
		return (set_errno(ENOMEM));

	user_lats_buffer = kmem_zalloc(snap_nlgrpsmax * sizeof (int *),
	    KM_NOSLEEP);
	if (user_lats_buffer == NULL) {
		kmem_free(user_info_buffer, info_size);
		return (set_errno(ENOMEM));
	}

	lgrp_info = (lgrp_info_t *)((uintptr_t)lgrp_snap + snap_hdr_size);
	bcopy(lgrp_info, user_info_buffer, info_size);

	cpu_index = 0;
	for (i = 0; i < snap_nlgrpsmax; i++) {
		ulong_t	*snap_rset;

		/*
		 * Skip non-existent lgroups
		 */
		if (user_info_buffer[i].info_lgrpid == LGRP_NONE)
			continue;

		/*
		 * Update free memory size since it changes frequently
		 * Only do so for lgroups directly containing memory
		 *
		 * NOTE: This must be done before changing the pointers to
		 *	 point into user space since we need to dereference
		 *	 lgroup resource set
		 */
		snap_rset = &lgrp_info[i].info_rset[LGRP_RSRC_MEM *
		    BT_BITOUL(snap_nlgrpsmax)];
		if (BT_TEST(snap_rset, i))
			user_info_buffer[i].info_mem_free =
			    lgrp_mem_size(i, LGRP_MEM_SIZE_FREE);

		/*
		 * Fix up pointers to parents, children, resources, and
		 * latencies
		 */
		user_info_buffer[i].info_parents =
		    (ulong_t *)((uintptr_t)user_parents + (i * bitmask_size));
		user_info_buffer[i].info_children =
		    (ulong_t *)((uintptr_t)user_children + (i * bitmask_size));
		user_info_buffer[i].info_rset =
		    (ulong_t *)((uintptr_t)user_rsets +
		    (i * LGRP_RSRC_COUNT * bitmask_size));
		user_lats_buffer[i] = (int *)((uintptr_t)user_lats +
		    (snap_nlgrpsmax * sizeof (int *)) + (i * snap_nlgrpsmax *
		    sizeof (int)));

		/*
		 * Fix up pointer to CPU IDs
		 */
		if (user_info_buffer[i].info_ncpus == 0) {
			user_info_buffer[i].info_cpuids = NULL;
			continue;
		}
		user_info_buffer[i].info_cpuids = &user_cpuids[cpu_index];
		cpu_index += user_info_buffer[i].info_ncpus;
	}
	ASSERT(cpu_index == snap_ncpus);

	/*
	 * Copy lgroup info and latency table with pointers fixed up to point
	 * into user buffer out to user buffer now
	 */
	retval = lgrp_snap->ss_size;
	if (copyout(user_info_buffer, user_info, info_size) != 0)
		retval = set_errno(EFAULT);
	kmem_free(user_info_buffer, info_size);

	if (copyout(user_lats_buffer, user_lats, snap_nlgrpsmax *
	    sizeof (int *)) != 0)
		retval = set_errno(EFAULT);
	kmem_free(user_lats_buffer, snap_nlgrpsmax * sizeof (int *));

	return (retval);
}


#ifdef	_SYSCALL32_IMPL
/*
 * Make 32-bit copy of snapshot, fix up any pointers in buffer to point
 * into user instead of kernel address space, copy 32-bit snapshot into
 * given user buffer, and return size of buffer needed to hold snapshot
 */
static int
lgrp_snapshot_copy32(caddr32_t buf, size32_t bufsize)
{
	size32_t			bitmask_size;
	size32_t			bitmasks_size;
	size32_t			children_size;
	int				cpu_index;
	size32_t			cpuids_size;
	int				i;
	int				j;
	size32_t			info_size;
	size32_t			lats_size;
	lgrp_info_t			*lgrp_info;
	lgrp_snapshot_header32_t	*lgrp_snap32;
	lgrp_info32_t			*lgrp_info32;
	processorid_t			*lgrp_cpuids32;
	caddr32_t			*lgrp_lats32;
	int				**lgrp_lats32_kernel;
	uint_t				*lgrp_set32;
	uint_t				*lgrp_parents32;
	uint_t				*lgrp_children32;
	uint_t				*lgrp_rsets32;
	size32_t			parents_size;
	size32_t			rsets_size;
	size32_t			set_size;
	size32_t			snap_hdr_size;
	int				snap_ncpus;
	int				snap_nlgrpsmax;
	size32_t			snap_size;

	if (lgrp_snap == NULL)
		return (0);

	snap_ncpus = lgrp_snap->ss_ncpus;
	snap_nlgrpsmax = lgrp_snap->ss_nlgrps_max;

	/*
	 * Calculate size of buffer needed for 32-bit snapshot,
	 * rounding up size of each object to allow for alignment
	 * of next object in buffer.
	 */
	snap_hdr_size = P2ROUNDUP(sizeof (lgrp_snapshot_header32_t),
	    sizeof (caddr32_t));
	info_size = P2ROUNDUP(snap_nlgrpsmax * sizeof (lgrp_info32_t),
	    sizeof (processorid_t));
	cpuids_size = P2ROUNDUP(snap_ncpus * sizeof (processorid_t),
	    sizeof (ulong_t));

	bitmask_size = BT_SIZEOFMAP32(snap_nlgrpsmax);

	set_size = bitmask_size;
	parents_size = snap_nlgrpsmax * bitmask_size;
	children_size = snap_nlgrpsmax * bitmask_size;
	rsets_size = P2ROUNDUP(LGRP_RSRC_COUNT * snap_nlgrpsmax *
	    (int)bitmask_size, sizeof (caddr32_t));

	bitmasks_size = set_size + parents_size + children_size + rsets_size;

	/*
	 * Size of latency table and buffer
	 */
	lats_size = (snap_nlgrpsmax * sizeof (caddr32_t)) +
	    (snap_nlgrpsmax * snap_nlgrpsmax * sizeof (int));

	snap_size = snap_hdr_size + info_size + cpuids_size + bitmasks_size +
	    lats_size;

	if (buf == NULL || bufsize <= 0) {
		return (snap_size);
	}

	/*
	 * User needs to try getting size of buffer again
	 * because given buffer size is too small.
	 * The lgroup hierarchy may have changed after they asked for the size
	 * but before the snapshot was taken.
	 */
	if (bufsize < snap_size)
		return (set_errno(EAGAIN));

	/*
	 * Make 32-bit copy of snapshot, fix up pointers to point into user
	 * buffer not kernel, and then copy whole thing into user buffer
	 */
	lgrp_snap32 = kmem_zalloc(snap_size, KM_NOSLEEP);
	if (lgrp_snap32 == NULL)
		return (set_errno(ENOMEM));

	/*
	 * Calculate pointers into 32-bit copy of snapshot
	 * for lgroup info, CPU IDs, pset lgroup bitmask, parents, children,
	 * resources, and latency table and buffer
	 */
	lgrp_info32 = (lgrp_info32_t *)((uintptr_t)lgrp_snap32 +
	    snap_hdr_size);
	lgrp_cpuids32 = (processorid_t *)((uintptr_t)lgrp_info32 + info_size);
	lgrp_set32 = (uint_t *)((uintptr_t)lgrp_cpuids32 + cpuids_size);
	lgrp_parents32 = (uint_t *)((uintptr_t)lgrp_set32 + set_size);
	lgrp_children32 = (uint_t *)((uintptr_t)lgrp_parents32 + parents_size);
	lgrp_rsets32 = (uint_t *)((uintptr_t)lgrp_children32 + children_size);
	lgrp_lats32 = (caddr32_t *)((uintptr_t)lgrp_rsets32 + rsets_size);

	/*
	 * Make temporary lgroup latency table of pointers for kernel to use
	 * to fill in rows of table with latencies from each lgroup
	 */
	lgrp_lats32_kernel =  kmem_zalloc(snap_nlgrpsmax * sizeof (int *),
	    KM_NOSLEEP);
	if (lgrp_lats32_kernel == NULL) {
		kmem_free(lgrp_snap32, snap_size);
		return (set_errno(ENOMEM));
	}

	/*
	 * Fill in 32-bit lgroup snapshot header
	 * (with pointers into user's buffer for lgroup info, CPU IDs,
	 * bit masks, and latencies)
	 */
	lgrp_snap32->ss_version = lgrp_snap->ss_version;
	lgrp_snap32->ss_levels = lgrp_snap->ss_levels;
	lgrp_snap32->ss_nlgrps = lgrp_snap32->ss_nlgrps_os =
	    lgrp_snap->ss_nlgrps;
	lgrp_snap32->ss_nlgrps_max = snap_nlgrpsmax;
	lgrp_snap32->ss_root = lgrp_snap->ss_root;
	lgrp_snap32->ss_ncpus = lgrp_snap->ss_ncpus;
	lgrp_snap32->ss_gen = lgrp_snap->ss_gen;
	lgrp_snap32->ss_view = LGRP_VIEW_OS;
	lgrp_snap32->ss_size = snap_size;
	lgrp_snap32->ss_magic = buf;
	lgrp_snap32->ss_info = buf + snap_hdr_size;
	lgrp_snap32->ss_cpuids = lgrp_snap32->ss_info + info_size;
	lgrp_snap32->ss_lgrpset = lgrp_snap32->ss_cpuids + cpuids_size;
	lgrp_snap32->ss_parents = lgrp_snap32->ss_lgrpset + bitmask_size;
	lgrp_snap32->ss_children = lgrp_snap32->ss_parents +
	    (snap_nlgrpsmax * bitmask_size);
	lgrp_snap32->ss_rsets = lgrp_snap32->ss_children +
	    (snap_nlgrpsmax * bitmask_size);
	lgrp_snap32->ss_latencies = lgrp_snap32->ss_rsets +
	    (LGRP_RSRC_COUNT * snap_nlgrpsmax * bitmask_size);

	/*
	 * Fill in lgrpset now because caller may have change psets
	 */
	kpreempt_disable();
	for (i = 0; i < snap_nlgrpsmax; i++) {
		if (klgrpset_ismember(curthread->t_cpupart->cp_lgrpset,
		    i)) {
			BT_SET32(lgrp_set32, i);
		}
	}
	kpreempt_enable();

	/*
	 * Fill in 32-bit copy of lgroup info and fix up pointers
	 * to point into user's buffer instead of kernel's
	 */
	cpu_index = 0;
	lgrp_info = lgrp_snap->ss_info;
	for (i = 0; i < snap_nlgrpsmax; i++) {
		uint_t	*children;
		uint_t	*lgrp_rset;
		uint_t	*parents;
		ulong_t	*snap_rset;

		/*
		 * Skip non-existent lgroups
		 */
		if (lgrp_info[i].info_lgrpid == LGRP_NONE) {
			bzero(&lgrp_info32[i], sizeof (lgrp_info32[i]));
			lgrp_info32[i].info_lgrpid = LGRP_NONE;
			continue;
		}

		/*
		 * Fill in parents, children, lgroup resource set, and
		 * latencies from snapshot
		 */
		parents = (uint_t *)((uintptr_t)lgrp_parents32 +
		    i * bitmask_size);
		children = (uint_t *)((uintptr_t)lgrp_children32 +
		    i * bitmask_size);
		snap_rset = (ulong_t *)((uintptr_t)lgrp_snap->ss_rsets +
		    (i * LGRP_RSRC_COUNT * BT_SIZEOFMAP(snap_nlgrpsmax)));
		lgrp_rset = (uint_t *)((uintptr_t)lgrp_rsets32 +
		    (i * LGRP_RSRC_COUNT * bitmask_size));
		lgrp_lats32_kernel[i] = (int *)((uintptr_t)lgrp_lats32 +
		    snap_nlgrpsmax * sizeof (caddr32_t) + i * snap_nlgrpsmax *
		    sizeof (int));
		for (j = 0; j < snap_nlgrpsmax; j++) {
			int	k;
			uint_t	*rset;

			if (BT_TEST(&lgrp_snap->ss_parents[i], j))
				BT_SET32(parents, j);

			if (BT_TEST(&lgrp_snap->ss_children[i], j))
				BT_SET32(children, j);

			for (k = 0; k < LGRP_RSRC_COUNT; k++) {
				rset = (uint_t *)((uintptr_t)lgrp_rset +
				    k * bitmask_size);
				if (BT_TEST(&snap_rset[k], j))
					BT_SET32(rset, j);
			}

			lgrp_lats32_kernel[i][j] =
			    lgrp_snap->ss_latencies[i][j];
		}

		/*
		 * Fix up pointer to latency buffer
		 */
		lgrp_lats32[i] = lgrp_snap32->ss_latencies +
		    snap_nlgrpsmax * sizeof (caddr32_t) + i * snap_nlgrpsmax *
		    sizeof (int);

		/*
		 * Fix up pointers for parents, children, and resources
		 */
		lgrp_info32[i].info_parents = lgrp_snap32->ss_parents +
		    (i * bitmask_size);
		lgrp_info32[i].info_children = lgrp_snap32->ss_children +
		    (i * bitmask_size);
		lgrp_info32[i].info_rset = lgrp_snap32->ss_rsets +
		    (i * LGRP_RSRC_COUNT * bitmask_size);

		/*
		 * Fill in memory and CPU info
		 * Only fill in memory for lgroups directly containing memory
		 */
		snap_rset = &lgrp_info[i].info_rset[LGRP_RSRC_MEM *
		    BT_BITOUL(snap_nlgrpsmax)];
		if (BT_TEST(snap_rset, i)) {
			lgrp_info32[i].info_mem_free = lgrp_mem_size(i,
			    LGRP_MEM_SIZE_FREE);
			lgrp_info32[i].info_mem_install =
			    lgrp_info[i].info_mem_install;
		}

		lgrp_info32[i].info_ncpus = lgrp_info[i].info_ncpus;

		lgrp_info32[i].info_lgrpid = lgrp_info[i].info_lgrpid;
		lgrp_info32[i].info_latency = lgrp_info[i].info_latency;

		if (lgrp_info32[i].info_ncpus == 0) {
			lgrp_info32[i].info_cpuids = 0;
			continue;
		}

		/*
		 * Fix up pointer for CPU IDs
		 */
		lgrp_info32[i].info_cpuids = lgrp_snap32->ss_cpuids +
		    (cpu_index * sizeof (processorid_t));
		cpu_index += lgrp_info32[i].info_ncpus;
	}
	ASSERT(cpu_index == snap_ncpus);

	/*
	 * Copy lgroup CPU IDs into 32-bit snapshot
	 * before copying it out into user's buffer
	 */
	bcopy(lgrp_snap->ss_cpuids, lgrp_cpuids32, cpuids_size);

	/*
	 * Copy 32-bit lgroup snapshot into user's buffer all at once
	 */
	if (copyout(lgrp_snap32, (void *)(uintptr_t)buf, snap_size) != 0) {
		kmem_free(lgrp_snap32, snap_size);
		kmem_free(lgrp_lats32_kernel, snap_nlgrpsmax * sizeof (int *));
		return (set_errno(EFAULT));
	}

	kmem_free(lgrp_snap32, snap_size);
	kmem_free(lgrp_lats32_kernel, snap_nlgrpsmax * sizeof (int *));

	return (snap_size);
}
#endif	/* _SYSCALL32_IMPL */


int
lgrpsys(int subcode, long ia, void *ap)
{
	size_t	bufsize;
	int	latency;

	switch (subcode) {

	case LGRP_SYS_AFFINITY_GET:
		return (lgrp_affinity_get((lgrp_affinity_args_t *)ap));

	case LGRP_SYS_AFFINITY_SET:
		return (lgrp_affinity_set((lgrp_affinity_args_t *)ap));

	case LGRP_SYS_GENERATION:
		return (lgrp_generation(ia));

	case LGRP_SYS_HOME:
		return (lgrp_home_get((idtype_t)ia, (id_t)(uintptr_t)ap));

	case LGRP_SYS_LATENCY:
		mutex_enter(&cpu_lock);
		latency = lgrp_latency(ia, (lgrp_id_t)(uintptr_t)ap);
		mutex_exit(&cpu_lock);
		return (latency);

	case LGRP_SYS_MEMINFO:
		return (meminfo(ia, (struct meminfo *)ap));

	case LGRP_SYS_VERSION:
		return (lgrp_version(ia));

	case LGRP_SYS_SNAPSHOT:
		mutex_enter(&lgrp_snap_lock);
		bufsize = lgrp_snapshot();
		if (ap && ia > 0) {
			if (get_udatamodel() == DATAMODEL_NATIVE)
				bufsize = lgrp_snapshot_copy(ap, ia);
#ifdef	_SYSCALL32_IMPL
			else
				bufsize = lgrp_snapshot_copy32(
				    (caddr32_t)(uintptr_t)ap, ia);
#endif	/* _SYSCALL32_IMPL */
		}
		mutex_exit(&lgrp_snap_lock);
		return (bufsize);

	default:
		break;

	}

	return (set_errno(EINVAL));
}

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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include <sys/nsctl/nsc_rmspin.h>
#include "../nsctl.h"
#include "nskernd.h"

struct nsc_nlwp {
	struct nsc_nlwp	*next;
	void		(*fn)(void *);
	void		*arg;
	volatile int	ready;
	int		errno;
	kcondvar_t	child_cv;
};

kmutex_t nsc_proc_lock;
kcondvar_t nsc_proc_cv;

static struct nsc_nlwp *nsc_nlwp_top;

void
_nsc_start_proc(void)
{
	mutex_init(&nsc_proc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&nsc_proc_cv, NULL, CV_DRIVER, NULL);
}


void
_nsc_stop_proc(void)
{
	mutex_destroy(&nsc_proc_lock);
	cv_destroy(&nsc_proc_cv);
}


/*
 * Create a daemon (server) proc.
 *
 * If 'rt' is TRUE, then increase the scheduling priority of the lwp.
 * Exactly how, if at all, this feature is implemented is at the
 * discretion of nskernd.
 *
 * Returns 0 or errno.
 */

int
nsc_create_process(void (*func)(void *), void *arg, boolean_t rt)
{
	struct nsc_nlwp *nlwp, **nlwpp;
	struct nskernd *nsk = NULL;
	int rc = 0;

	nlwp = kmem_zalloc(sizeof (*nlwp), KM_NOSLEEP);
	nsk = kmem_zalloc(sizeof (*nsk), KM_NOSLEEP);
	if (!nlwp || !nsk) {
		if (nlwp) {
			kmem_free(nlwp, sizeof (*nlwp));
		}
		if (nsk) {
			kmem_free(nsk, sizeof (*nsk));
		}
		return (ENOMEM);
	}

	nlwp->fn = func;
	nlwp->arg = arg;

	mutex_enter(&nsc_proc_lock);

	nlwp->next = nsc_nlwp_top;
	nsc_nlwp_top = nlwp;

	mutex_exit(&nsc_proc_lock);

	nsk->command = NSKERND_NEWLWP;
	nsk->data1 = (uint64_t)(unsigned long)nlwp;
	nsk->data2 = (uint64_t)rt;

	rc = nskernd_get(nsk);

	/* user level returns error in nsk->data1 */
	if (!rc && nsk->data1)
		rc = nsk->data1;

	mutex_enter(&nsc_proc_lock);

	if (!rc) {
		/*
		 * wait for the child to start and check in.
		 */

		while (! nlwp->ready) {
			cv_wait(&nsc_proc_cv, &nsc_proc_lock);
		}
	}

	/*
	 * remove from list of outstanding requests.
	 */

	for (nlwpp = &nsc_nlwp_top; (*nlwpp); nlwpp = &((*nlwpp)->next)) {
		if (*nlwpp == nlwp) {
			*nlwpp = nlwp->next;
			break;
		}
	}

	mutex_exit(&nsc_proc_lock);

	kmem_free(nlwp, sizeof (*nlwp));
	kmem_free(nsk, sizeof (*nsk));
	return (rc);
}


/*
 * Child lwp calls this function when it returns to the kernel.
 *
 * Check if the args are still on the pending list.  If they are, then
 * run the required function.  If they are not, then something went
 * wrong, so just return back to userland and die.
 */
void
nsc_runlwp(uint64_t arg)
{
	struct nsc_nlwp *nlwp;
	void (*fn)(void *);
	void *fn_arg;

	fn_arg = NULL;
	fn = NULL;

	mutex_enter(&nsc_proc_lock);

	/*
	 * check that the request is still on the list of work to do
	 */

	for (nlwp = nsc_nlwp_top; nlwp; nlwp = nlwp->next) {
		if (nlwp == (struct nsc_nlwp *)(unsigned long)arg) {
			fn_arg = nlwp->arg;
			fn = nlwp->fn;

			/* mark as ready */
			nlwp->ready = 1;
			cv_broadcast(&nsc_proc_cv);

			break;
		}
	}

	mutex_exit(&nsc_proc_lock);

	if (fn) {
		(*fn)(fn_arg);
	}
}


/*
 * Create a thread that acquires an inter-node lock.
 *
 * mode  - 0 (read), 1 (write).
 * lockp - used to return the opaque address of a sync structure, which
 *	   must be passed to nsc_do_unlock() later.
 *
 * Returns 0 or errno.
 */

int
nsc_do_lock(int mode, void **lockp)
{
	struct nsc_nlwp *nlwp = NULL, **nlwpp;
	struct nskernd *nsk = NULL;
	int rc = 0;

	nlwp = kmem_zalloc(sizeof (*nlwp), KM_NOSLEEP);
	nsk = kmem_zalloc(sizeof (*nsk), KM_NOSLEEP);
	if (!nlwp || !nsk) {
		if (nlwp) {
			kmem_free(nlwp, sizeof (*nlwp));
		}
		if (nsk) {
			kmem_free(nsk, sizeof (*nsk));
		}
		return (ENOMEM);
	}

	cv_init(&nlwp->child_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&nsc_proc_lock);

	nlwp->next = nsc_nlwp_top;
	nsc_nlwp_top = nlwp;

	mutex_exit(&nsc_proc_lock);

	nsk->command = NSKERND_LOCK;
	nsk->data1 = (uint64_t)(unsigned long)nlwp;
	nsk->data2 = (uint64_t)mode;

	rc = nskernd_get(nsk);

	/* user level returns error in nsk->data1 */
	if (!rc && nsk->data1)
		rc = nsk->data1;

	mutex_enter(&nsc_proc_lock);

	if (!rc) {
		/*
		 * wait for the child to start and check in.
		 */

		while (! nlwp->ready) {
			cv_wait(&nsc_proc_cv, &nsc_proc_lock);
		}

		/* retrieve errno from child's lock operation */
		rc = (int)nlwp->errno;
	}

	if (rc) {
		/*
		 * error - remove from list of outstanding requests as
		 * child will not be checking in (nskernd_get() failed
		 * or user thread create failed) or will not be waiting
		 * (child thread lock failure).
		 */

		for (nlwpp = &nsc_nlwp_top; (*nlwpp);
		    nlwpp = &((*nlwpp)->next)) {
			if (*nlwpp == nlwp) {
				*nlwpp = nlwp->next;
				break;
			}
		}

		mutex_exit(&nsc_proc_lock);

		cv_destroy(&nlwp->child_cv);
		kmem_free(nlwp, sizeof (*nlwp));
		kmem_free(nsk, sizeof (*nsk));
		*lockp = NULL;
		return (rc);
	}

	/* success, return argument for nsc_do_unlock() */

	mutex_exit(&nsc_proc_lock);

	kmem_free(nsk, sizeof (*nsk));
	*lockp = nlwp;
	return (0);
}


void
nsc_do_unlock(void *arg)
{
	struct nsc_nlwp *nlwp;

	/* find child on work list */

	mutex_enter(&nsc_proc_lock);

	for (nlwp = nsc_nlwp_top; nlwp; nlwp = nlwp->next) {
		if (nlwp == (struct nsc_nlwp *)arg) {
			/* signal unlock */
			nlwp->ready = 0;
			cv_broadcast(&nlwp->child_cv);
		}
	}

	mutex_exit(&nsc_proc_lock);
}


/*
 * Lock child thread calls this function when it returns to the kernel.
 *
 * Check if the args are still on the pending list.  If they are, then
 * post the lock results and wait for the unlock.  If they are not,
 * then something went wrong, so just return back to userland and die.
 */
void
nsc_lockchild(uint64_t arg, uint64_t errno)
{
	struct nsc_nlwp *nlwp, **nlwpp;

	if (!arg) {
		return;
	}

	mutex_enter(&nsc_proc_lock);

	/*
	 * check that the request is still on the list of work to do
	 */

	for (nlwp = nsc_nlwp_top; nlwp; nlwp = nlwp->next) {
		if (nlwp == (struct nsc_nlwp *)(unsigned long)arg) {
			/* mark as ready */
			nlwp->errno = (int)errno;
			nlwp->ready = 1;
			cv_broadcast(&nsc_proc_cv);
			break;
		}
	}

	if (!nlwp || errno) {
		/*
		 * Error - either this request is no longer on the work
		 * queue, or there was an error in the userland lock code
		 * in which case the lock caller (currently blocked in
		 * nsc_do_lock() will do the cleanup.
		 */
		mutex_exit(&nsc_proc_lock);
		return;
	}

	/*
	 * no errors, so wait for an unlock
	 */

	while (nlwp->ready) {
		cv_wait(&nlwp->child_cv, &nsc_proc_lock);
	}

	/*
	 * remove self from list of outstanding requests.
	 */

	for (nlwpp = &nsc_nlwp_top; (*nlwpp); nlwpp = &((*nlwpp)->next)) {
		if (*nlwpp == nlwp) {
			*nlwpp = nlwp->next;
			break;
		}
	}

	/*
	 * cleanup
	 */

	cv_destroy(&nlwp->child_cv);
	kmem_free(nlwp, sizeof (*nlwp));

	mutex_exit(&nsc_proc_lock);
}

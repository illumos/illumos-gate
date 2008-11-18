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

#include <thread.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <tiuser.h>
#include <syslog.h>
#include <zone.h>
#include <sys/priocntl.h>
#include <sys/fxpriocntl.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include "thrpool.h"

extern	int	_nfssys(int, void *);

/*
 * Thread to call into the kernel and do work on behalf of NFS.
 */
static void *
svcstart(void *arg)
{
	int id = (int)arg;

	/*
	 * Create a kernel worker thread to service
	 * new incoming requests on a pool.
	 */
	_nfssys(SVCPOOL_RUN, &id);

	/*
	 * Returned from the kernel, this thread's work is done,
	 * and it should exit. For new incoming requests,
	 * svcblock() will spawn another worker thread by
	 * calling svcstart() again.
	 */
	thr_exit(NULL);
	return (NULL);
}

static void *
svc_rdma_creator(void *arg)
{
	struct rdma_svc_args *rsap = (struct rdma_svc_args *)arg;

	if (_nfssys(RDMA_SVC_INIT, rsap) < 0) {
		if (errno != ENODEV) {
			(void) syslog(LOG_INFO, "RDMA transport startup "
			    "failed with %m");
		}
	}
	free(rsap);
	thr_exit(NULL);
	return (NULL);
}

/*
 * User-space "creator" thread. This thread blocks in the kernel
 * until new worker threads need to be created for the service
 * pool. On return to userspace, if there is no error, create a
 * new thread for the service pool.
 */
static void *
svcblock(void *arg)
{
	int id = (int)arg;

	/* CONSTCOND */
	while (1) {
		thread_t tid;

		/*
		 * Call into the kernel, and hang out there
		 * until a thread needs to be created.
		 */
		if (_nfssys(SVCPOOL_WAIT, &id) < 0) {
			if (errno == ECANCELED || errno == EINTR ||
			    errno == EBUSY)
				/*
				 * If we get back ECANCELED or EINTR,
				 * the service pool is exiting, and we
				 * may as well clean up this thread. If
				 * EBUSY is returned, there's already a
				 * thread looping on this pool, so we
				 * should give up.
				 */
				break;
			else
				continue;
		}

		/*
		 * User portion of the thread does no real work since
		 * the svcpool threads actually spend their entire
		 * lives in the kernel. So, user portion of the thread
		 * should have the smallest stack possible.
		 */
		(void) thr_create(NULL, THR_MIN_STACK, svcstart, (void *)id,
		    THR_BOUND | THR_DETACHED, &tid);
	}

	thr_exit(NULL);
	return (NULL);
}

void
svcsetprio(void)
{
	pcinfo_t pcinfo;
	pri_t maxupri;

	/*
	 * By default, all threads should be part of the FX scheduler
	 * class. As nfsd/lockd server threads used to be part of the
	 * kernel, they're used to being scheduled in the SYS class.
	 * Userland threads shouldn't be in SYS, but they can be given a
	 * higher priority by default. This change still renders nfsd/lockd
	 * managable by an admin by utilizing commands to change scheduling
	 * manually, or by using resource management tools such as pools
	 * to associate them with a different scheduling class and segregate
	 * the workload.
	 *
	 * We set the threads' priority to the upper bound for priorities
	 * in FX. This should be 60, but since the desired action is to
	 * make nfsd/lockd more important than TS threads, we bow to the
	 * system's knowledge rather than setting it manually. Furthermore,
	 * since the SYS class doesn't timeslice, use an "infinite" quantum.
	 * If anything fails, just log the failure and let the daemon
	 * default to TS.
	 *
	 * The change of scheduling class is expected to fail in a non-global
	 * zone, so we avoid worrying the zone administrator unnecessarily.
	 */
	(void) strcpy(pcinfo.pc_clname, "FX");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) != -1) {
		maxupri = ((fxinfo_t *)pcinfo.pc_clinfo)->fx_maxupri;
		if (priocntl(P_LWPID, P_MYID, PC_SETXPARMS, "FX",
		    FX_KY_UPRILIM, maxupri, FX_KY_UPRI, maxupri,
		    FX_KY_TQNSECS, FX_TQINF, NULL) != 0 &&
		    getzoneid() == GLOBAL_ZONEID)
			(void) syslog(LOG_ERR, "Unable to use FX scheduler: "
			    "%m. Using system default scheduler.");
	} else
		(void) syslog(LOG_ERR, "Unable to determine parameters "
		    "for FX scheduler. Using system default scheduler.");
}

int
svcrdma(int id, int versmin, int versmax, int delegation)
{
	thread_t tid;
	struct rdma_svc_args *rsa;

	rsa = (struct rdma_svc_args *)malloc(sizeof (struct rdma_svc_args));
	rsa->poolid = (uint32_t)id;
	rsa->netid = NULL;
	rsa->nfs_versmin = versmin;
	rsa->nfs_versmax = versmax;
	rsa->delegation = delegation;

	/*
	 * Create a thread to handle RDMA start and stop.
	 */
	if (thr_create(NULL, THR_MIN_STACK * 2, svc_rdma_creator, (void *)rsa,
	    THR_BOUND | THR_DETACHED, &tid))
		return (1);

	return (0);
}

int
svcwait(int id)
{
	thread_t tid;

	/*
	 * Create a bound thread to wait for kernel LWPs that
	 * need to be created. This thread also has little need
	 * of stackspace, so should be created with that in mind.
	 */
	if (thr_create(NULL, THR_MIN_STACK * 2, svcblock, (void *)id,
	    THR_BOUND | THR_DETACHED, &tid))
		return (1);

	return (0);
}

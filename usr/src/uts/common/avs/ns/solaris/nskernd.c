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
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "../nsctl.h"
#include "../nsctl/nsc_ioctl.h"
#include "nskernd.h"

void *proc_nskernd;
int nskernd_iscluster;

static kmutex_t nskernd_lock;

static kcondvar_t nskernd_ask_cv;
static kcondvar_t nskernd_k_cv;
static kcondvar_t nskernd_u_cv;

static volatile int nskernd_k_wait;
static volatile int nskernd_u_wait;

static int nskernd_norun;

static volatile int nskernd_ask;
static struct nskernd nskernd_kdata;

void
nskernd_init(void)
{
	mutex_init(&nskernd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&nskernd_ask_cv, NULL, CV_DRIVER, NULL);
	cv_init(&nskernd_k_cv, NULL, CV_DRIVER, NULL);
	cv_init(&nskernd_u_cv, NULL, CV_DRIVER, NULL);

	nskernd_norun = 0;
}


void
nskernd_deinit(void)
{
	mutex_destroy(&nskernd_lock);
	cv_destroy(&nskernd_ask_cv);
	cv_destroy(&nskernd_k_cv);
	cv_destroy(&nskernd_u_cv);
}


static int
nskernd_start(const int iscluster)
{
	int rc = 0;

	mutex_enter(&nskernd_lock);

	if (proc_nskernd != NULL) {
		rc = 1;
	} else if (nskernd_norun != 0) {
		rc = 2;
	} else {
		(void) drv_getparm(UPROCP, (void *)&proc_nskernd);
		nskernd_iscluster = iscluster;
	}

	mutex_exit(&nskernd_lock);

	return (rc);
}


/*
 * must be called with nskernd_lock held.
 */
void
nskernd_cleanup(void)
{
	proc_nskernd = NULL;
	cv_broadcast(&nskernd_ask_cv);
	cv_broadcast(&nskernd_k_cv);
}


void
nskernd_stop(void)
{
	mutex_enter(&nskernd_lock);

	if (proc_nskernd == NULL) {
		nskernd_norun = 1;
		mutex_exit(&nskernd_lock);
		return;
	}

	while (nskernd_u_wait == 0) {
		nskernd_k_wait++;
		cv_wait(&nskernd_k_cv, &nskernd_lock);
		nskernd_k_wait--;

		if (proc_nskernd == NULL) {
			mutex_exit(&nskernd_lock);
			return;
		}
	}

	nskernd_kdata.command = NSKERND_STOP;
	nskernd_kdata.data1 = (uint64_t)1;	/* kernel has done cleanup */

	nskernd_cleanup();

	cv_signal(&nskernd_u_cv);
	mutex_exit(&nskernd_lock);
}


int
nskernd_get(struct nskernd *nskp)
{
	mutex_enter(&nskernd_lock);

	if (proc_nskernd == NULL) {
		mutex_exit(&nskernd_lock);
		return (ENXIO);
	}

	while (nskernd_u_wait == 0 || nskernd_ask) {
		nskernd_k_wait++;
		cv_wait(&nskernd_k_cv, &nskernd_lock);
		nskernd_k_wait--;

		if (proc_nskernd == NULL) {
			mutex_exit(&nskernd_lock);
			return (ENXIO);
		}
	}

	bcopy(nskp, &nskernd_kdata, sizeof (*nskp));
	nskernd_ask++;

	cv_signal(&nskernd_u_cv);

	cv_wait(&nskernd_ask_cv, &nskernd_lock);

	if (proc_nskernd == NULL) {
		nskernd_ask--;
		mutex_exit(&nskernd_lock);
		return (ENXIO);
	}

	bcopy(&nskernd_kdata, nskp, sizeof (*nskp));
	nskernd_ask--;

	if (nskernd_k_wait > 0)
		cv_signal(&nskernd_k_cv);

	mutex_exit(&nskernd_lock);
	return (0);
}


int
nskernd_command(intptr_t arg, int mode, int *rvalp)
{
	struct nskernd *udata = NULL;
	uint64_t arg1, arg2;
	int rc;

	*rvalp = 0;
	rc = 0;

	udata = kmem_alloc(sizeof (*udata), KM_SLEEP);
	if (ddi_copyin((void *)arg, udata, sizeof (*udata), mode) < 0) {
		kmem_free(udata, sizeof (*udata));
		return (EFAULT);
	}

	switch (udata->command) {
	case NSKERND_START:		/* User program start */
		*rvalp = nskernd_start(udata->data1);
		break;

	case NSKERND_STOP:		/* User program requesting stop */
		mutex_enter(&nskernd_lock);
		nskernd_cleanup();
		mutex_exit(&nskernd_lock);
		break;

	case NSKERND_WAIT:
		mutex_enter(&nskernd_lock);

		bcopy(udata, &nskernd_kdata, sizeof (*udata));

		if (nskernd_ask > 0)
			cv_signal(&nskernd_ask_cv);

		nskernd_u_wait++;

		if (cv_wait_sig(&nskernd_u_cv, &nskernd_lock) != 0) {
			/*
			 * woken by cv_signal() or cv_broadcast()
			 */
			bcopy(&nskernd_kdata, udata, sizeof (*udata));
		} else {
			/*
			 * signal - the user process has blocked all
			 * signals except for SIGTERM and the
			 * uncatchables, so the process is about to die
			 * and we need to clean up.
			 */
			udata->command = NSKERND_STOP;
			udata->data1 = (uint64_t)1;	 /* cleanup done */

			nskernd_cleanup();
		}

		nskernd_u_wait--;

		mutex_exit(&nskernd_lock);

		if (ddi_copyout(udata, (void *)arg,
		    sizeof (*udata), mode) < 0) {
			rc = EFAULT;
			break;
		}

		break;

	case NSKERND_NEWLWP:
		/* save kmem by freeing the udata structure */
		arg1 = udata->data1;
		kmem_free(udata, sizeof (*udata));
		udata = NULL;
		nsc_runlwp(arg1);
		break;

	case NSKERND_LOCK:
		/* save kmem by freeing the udata structure */
		arg1 = udata->data1;
		arg2 = udata->data2;
		kmem_free(udata, sizeof (*udata));
		udata = NULL;
		nsc_lockchild(arg1, arg2);
		break;

	default:
		cmn_err(CE_WARN, "nskernd: unknown command %d", udata->command);
		rc = EINVAL;
		break;
	}

	if (udata != NULL) {
		kmem_free(udata, sizeof (*udata));
		udata = NULL;
	}

	return (rc);
}

/*
 * This function is included for SV ioctl processing only.
 */

int
nskernd_isdaemon(void)
{
	void *this_proc;

	if (proc_nskernd == NULL)
		return (0);
	if (drv_getparm(UPROCP, (void *)&this_proc) != 0)
		return (0);
	return (proc_nskernd == this_proc);
}

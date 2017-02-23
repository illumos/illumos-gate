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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implements the kernel side of the debugger/kernel work queue.
 */

#include <kmdb/kmdb_kdi.h>
#include <kmdb/kctl/kctl.h>
#include <kmdb/kctl/kctl_wr.h>

#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/kdi_impl.h>
#include <sys/callb.h>

#define	KCTL_WR_PROCESS_NORMAL		(void *)0
#define	KCTL_WR_PROCESS_UNLOADING	(void *)1

/*
 * Processes events from the debugger -> driver notification queue.  Returns
 * 1 if the debugger should be awakened after the queue has been processed.
 */
static int
kctl_wr_process_cb(kmdb_wr_t *wn, void *arg)
{
	int unloading = (arg == KCTL_WR_PROCESS_UNLOADING);

	switch (WR_TASK(wn)) {
	case WNTASK_DMOD_LOAD: {
		/*
		 * If this is an ack, then we're getting back a message from a
		 * load we initiated.  Free it.  If it's not an ack, we process
		 * the message (attempt to load the requested module) and send
		 * an ack back to the debugger.
		 */
		kmdb_wr_load_t *dlr = (kmdb_wr_load_t *)wn;

		if (WR_ISACK(dlr)) {
			kctl_dprintf("received ack for dmod load of %s",
			    dlr->dlr_fname);
			kctl_dmod_load_ack(dlr);
			return (0);
		} else
			kctl_dprintf("received dmod load request %s",
			    dlr->dlr_fname);

		if (unloading) {
			/*
			 * If the user didn't wait for all dmods to load before
			 * they triggered the debugger unload, we may have some
			 * dmod load requests on the queue in front of the
			 * blizzard of dmod unload requests that the debugger
			 * will generate as part of its unload.  The debugger
			 * won't have generated unloads for pending dmods, so
			 * we can safely ignore the load requests.
			 */
			kctl_dprintf("skipping load of dmod %s due to "
			    "in-process unload");
		} else
			(void) kctl_dmod_load(dlr); /* dlr will have errno */

		WR_ACK(dlr);
		kmdb_wr_debugger_notify(dlr);
		return (1);
	}

	case WNTASK_DMOD_LOAD_ALL:
		/*
		 * We don't initiate all-module loads, so this can't be an
		 * ack.  We process the load-all, and send the message back
		 * to the driver as an ack.
		 */
		ASSERT(!WR_ISACK(wn));

		kctl_dprintf("received request to load all dmods");

		(void) kctl_dmod_load_all();

		WR_ACK(wn);
		kmdb_wr_debugger_notify(wn);
		return (1);

	case WNTASK_DMOD_UNLOAD: {
		/*
		 * The driver received an unload request.  We don't initiate
		 * unloads, so this can't be an ack.  We process the unload,
		 * and send the message back to the driver as an ack.
		 */
		kmdb_wr_unload_t *dur = (kmdb_wr_unload_t *)wn;

		ASSERT(!WR_ISACK(dur));
		ASSERT(kctl.kctl_boot_ops == NULL);

		kctl_dprintf("received dmod unload message %s",
		    dur->dur_modname);

		kctl_dmod_unload(dur);

		WR_ACK(dur);
		kmdb_wr_debugger_notify(dur);
		return (1);
	}

	case WNTASK_DMOD_PATH_CHANGE: {
		/*
		 * We don't initiate path changes, so this can't be an ack.
		 * This request type differs from the others in that we only
		 * return it (as an ack) when we're done with it.  We're only
		 * done with it when we receive another one, or when the
		 * debugger is unloading.
		 */
		kmdb_wr_path_t *pth = (kmdb_wr_path_t *)wn;
		kmdb_wr_path_t *opth;

		ASSERT(!WR_ISACK(pth));

		kctl_dprintf("received path change message");

		if ((opth = kctl_dmod_path_set(pth)) != NULL) {
			/* We have an old path request to return */
			WR_ACK(opth);
			kmdb_wr_debugger_notify(opth);

			/*
			 * The debugger can process the returned path change
			 * request at its leisure
			 */
			return (0);
		}

		/* Nothing to do */
		return (0);
	}

	default:
		cmn_err(CE_WARN, "Received unknown work request %d from kmdb\n",
		    wn->wn_task);
		/* Drop message */
		return (0);
	}

	/*NOTREACHED*/
}

int
kctl_wr_process(void)
{
	return (kmdb_wr_driver_process(kctl_wr_process_cb,
	    KCTL_WR_PROCESS_NORMAL));
}

/*
 * Catches the "work to do" soft interrupt, and passes the notification along
 * to the worker thread.
 */
/*ARGSUSED*/
void
kctl_wrintr(void)
{
	kctl.kctl_wr_avail = 0;

	sema_v(&kctl.kctl_wr_avail_sem);
}

/*
 * This routine is called by the debugger while the world is resuming.
 */
void
kctl_wrintr_fire(void)
{
	kctl.kctl_wr_avail = 1;

	kdi_softcall(kctl_wrintr);
}

/*
 * Given the possibility of asynchronous unload, the locking semantics are
 * somewhat tricky.  See kctl_main.c
 */
/*ARGSUSED*/
static void
kctl_wr_thread(void *arg)
{
	callb_cpr_t cprinfo;
	kmutex_t cprlock;

	mutex_init(&cprlock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cprinfo, &cprlock, callb_generic_cpr, "kmdb work");

	for (;;) {
		/*
		 * XXX what should I do here for panic?  It'll spin unless I
		 * can figure out a way to park it.  Presumably I don't want to
		 * let it exit.
		 */
		mutex_enter(&cprlock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		mutex_exit(&cprlock);

		sema_p(&kctl.kctl_wr_avail_sem);

		mutex_enter(&cprlock);
		CALLB_CPR_SAFE_END(&cprinfo, &cprlock);
		mutex_exit(&cprlock);

		kctl_dprintf("kctl worker thread - waking up");

		if (kmdb_kdi_get_unload_request() ||
		    kctl.kctl_wr_state != KCTL_WR_ST_RUN) {
			/*
			 * We've either got a debugger-initiated unload (if
			 * unload_request returned true), or we're stopping due
			 * to an error discovered by the driver (if
			 * kctl_worker_run is no longer non-zero).  Start
			 * cleaning up.
			 */

			/*
			 * The debugger has already deactivated itself, and will
			 * have dumped a bunch of stuff on the queue.  We need
			 * to process it before exiting.
			 */
			(void) kmdb_wr_driver_process(kctl_wr_process_cb,
			    KCTL_WR_PROCESS_UNLOADING);
			break;
		}

		/*
		 * A non-zero return means we've passed messages back to the
		 * debugger for processing, so we need to wake the debugger up.
		 */
		if (kctl_wr_process() > 0)
			kmdb_kdi_kmdb_enter();
	}

	/*
	 * NULL out the dmod search path, so we can send the current one back
	 * to the debugger.  XXX this should probably be somewhere else.
	 */
	kctl_dmod_path_reset();

	/*
	 * The debugger will send us unload notifications for each dmod that it
	 * noticed.  If, for example, the debugger is unloaded before the first
	 * start, it won't have noticed any of the dmods we loaded.  We'll need
	 * to initiate the unloads ourselves.
	 */
	kctl_dmod_unload_all();

	kctl.kctl_wr_state = KCTL_WR_ST_STOPPED;

	/*
	 * Must be last, as it concludes by setting state to INACTIVE.  The
	 * kctl data structure must not be accessed by this thread after that
	 * point.
	 */
	kctl_cleanup();

	mutex_enter(&cprlock);
	CALLB_CPR_EXIT(&cprinfo);
	mutex_destroy(&cprlock);
}

void
kctl_wr_thr_start(void)
{
	kctl.kctl_wr_avail = 0;
	kctl.kctl_wr_state = KCTL_WR_ST_RUN;
	kctl.kctl_wr_thr = thread_create(NULL, 0, kctl_wr_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}

void
kctl_wr_thr_stop(void)
{
	ASSERT(kctl.kctl_wr_state == KCTL_WR_ST_RUN);
	kctl.kctl_wr_state = KCTL_WR_ST_STOP;
	sema_v(&kctl.kctl_wr_avail_sem);
}

void
kctl_wr_thr_join(void)
{
	thread_join(kctl.kctl_wr_thr->t_did);
}

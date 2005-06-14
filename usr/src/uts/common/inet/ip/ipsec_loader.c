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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/sysmacros.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <inet/ipsec_impl.h>

/*
 * Loader commands..
 */
#define	IPSEC_LOADER_EXITNOW	-1
#define	IPSEC_LOADER_LOADNOW	1

/*
 * The following variables are kept because IPsec should be loaded only when
 * it is used.
 */
static kt_did_t ipsec_loader_tid;
kmutex_t ipsec_loader_lock;
static int ipsec_loader_sig = IPSEC_LOADER_WAIT;
int ipsec_loader_state = IPSEC_LOADER_WAIT;
static kcondvar_t ipsec_loader_sig_cv;	/* For loader_sig conditions. */


/*
 * NOTE:  This function is entered w/o holding any STREAMS perimeters.
 */
/* ARGSUSED */
static void
ipsec_loader(void *ignoreme)
{
	extern int keysock_plumb_ipsec(void);
	callb_cpr_t cprinfo;
	boolean_t ipsec_failure = B_FALSE;

	CALLB_CPR_INIT(&cprinfo, &ipsec_loader_lock, callb_generic_cpr,
	    "ipsec_loader");
	mutex_enter(&ipsec_loader_lock);
	for (;;) {

		/*
		 * Wait for someone to tell me to continue.
		 */
		while (ipsec_loader_sig == IPSEC_LOADER_WAIT) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&ipsec_loader_sig_cv, &ipsec_loader_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &ipsec_loader_lock);
		}

		/* IPSEC_LOADER_EXITNOW implies signal by _fini(). */
		if (ipsec_loader_sig == IPSEC_LOADER_EXITNOW) {
			/*
			 * Let user patch ipsec_loader_tid to
			 * 0 to try again.
			 */
			ipsec_loader_state = IPSEC_LOADER_FAILED;
			ipsec_loader_sig = IPSEC_LOADER_WAIT;

			/* ipsec_loader_lock is held at this point! */
			ASSERT(MUTEX_HELD(&ipsec_loader_lock));
			CALLB_CPR_EXIT(&cprinfo);
			ASSERT(!MUTEX_HELD(&ipsec_loader_lock));
			thread_exit();
		}
		mutex_exit(&ipsec_loader_lock);

		/*
		 * Load IPsec, which is done by modloading keysock and calling
		 * keysock_plumb_ipsec().
		 */

		/* Pardon my hardcoding... */
		if (modload("drv", "keysock") == -1) {
			cmn_err(CE_WARN, "IP: Cannot load keysock.");
			/*
			 * Only this function can set ipsec_failure.  If the
			 * damage can be repaired, use adb to set this to
			 * B_FALSE and try again.
			 */
			ipsec_failure = B_TRUE;
		} else if (keysock_plumb_ipsec() != 0) {
			cmn_err(CE_WARN, "IP: Cannot plumb IPsec.");
			/*
			 * Only this function can set ipsec_failure.  If the
			 * damage can be repaired, use adb to set this to
			 * B_FALSE and try again.
			 */
			ipsec_failure = B_TRUE;
		} else {
			ipsec_failure = B_FALSE;
		}

		mutex_enter(&ipsec_loader_lock);
		if (ipsec_failure) {
			if (ipsec_loader_sig == IPSEC_LOADER_LOADNOW)
				ipsec_loader_sig = IPSEC_LOADER_WAIT;
			ipsec_loader_state = IPSEC_LOADER_FAILED;
		} else {
			ipsec_loader_state = IPSEC_LOADER_SUCCEEDED;
		}
		mutex_exit(&ipsec_loader_lock);

		ip_ipsec_load_complete();

		mutex_enter(&ipsec_loader_lock);
		if (!ipsec_failure) {
			CALLB_CPR_EXIT(&cprinfo);
			ASSERT(!MUTEX_HELD(&ipsec_loader_lock));
			ipsec_register_prov_update();
			thread_exit();
		}
	}
}

/*
 * Called from ip_ddi_init() to initialize ipsec loader thread.
 */
void
ipsec_loader_init(void)
{
	mutex_init(&ipsec_loader_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ipsec_loader_sig_cv, NULL, CV_DEFAULT, NULL);
}

/*
 * Called from ip_ddi_destroy() to take down ipsec loader thread.
 */
void
ipsec_loader_destroy(void)
{
	kt_did_t tid;

	mutex_enter(&ipsec_loader_lock);
	tid = ipsec_loader_tid;
	if (tid != 0) {
		ipsec_loader_sig = IPSEC_LOADER_EXITNOW;
		cv_signal(&ipsec_loader_sig_cv);
		ipsec_loader_tid = 0;
	}
	mutex_exit(&ipsec_loader_lock);

	/*
	 * Wait for ipsec_loader() to finish before we destroy
	 * cvs and mutexes.
	 */
	if (tid != 0)
		thread_join(tid);

	mutex_destroy(&ipsec_loader_lock);
	cv_destroy(&ipsec_loader_sig_cv);
}

void
ipsec_loader_start(void)
{
	kthread_t *tp;

	mutex_enter(&ipsec_loader_lock);

	if (ipsec_loader_tid == 0) {
		tp = thread_create(NULL, 0, ipsec_loader, NULL, 0, &p0,
		    TS_RUN, MAXCLSYSPRI);
		ipsec_loader_tid = tp->t_did;
	}
	/* Else we lost the race, oh well. */
	mutex_exit(&ipsec_loader_lock);
}

void
ipsec_loader_loadnow()
{
	/*
	 * It is possible that an algorithm update message was
	 * received before IPsec is loaded. Such messages are
	 * saved in spdsock for later processing. Since IPsec
	 * loading can be initiated by interfaces different
	 * than spdsock, we must trigger the processing of
	 * update messages from the ipsec loader.
	 */
	spdsock_update_pending_algs();

	mutex_enter(&ipsec_loader_lock);
	if ((ipsec_loader_state == IPSEC_LOADER_WAIT) &&
	    (ipsec_loader_sig == IPSEC_LOADER_WAIT)) {
		ipsec_loader_sig = IPSEC_LOADER_LOADNOW;
		cv_signal(&ipsec_loader_sig_cv);
	}
	mutex_exit(&ipsec_loader_lock);
}

/*
 * Dummy callback routine (placeholder) to avoid keysock plumbing
 * races.  Used in conjunction with qtimeout() and qwait() to wait
 * until ipsec has loaded -- the qwait() in ipsec_loader_loadwait will
 * wake up once this routine returns.
 */

/* ARGSUSED */
static void
loader_nop(void *ignoreme)
{
}

/*
 * Called from keysock driver open to delay until ipsec is done loading.
 * Returns B_TRUE if it worked, B_FALSE if it didn't.
 */
boolean_t
ipsec_loader_wait(queue_t *q)
{
	/*
	 * 30ms delay per loop is arbitrary; it takes ~300ms to
	 * load and plumb ipsec on an ultra-1.
	 */

	while (ipsec_loader_state == IPSEC_LOADER_WAIT) {
		(void) qtimeout(q, loader_nop, 0, drv_usectohz(30000));
		qwait(q);
	}

	return (ipsec_loader_state == IPSEC_LOADER_SUCCEEDED);
}

/*
 * Just check to see if IPsec is loaded (or not).
 */
boolean_t
ipsec_loaded(void)
{
	return (ipsec_loader_state == IPSEC_LOADER_SUCCEEDED);
}

/*
 * Check to see if IPsec loading failed.
 */
boolean_t
ipsec_failed(void)
{
	return (ipsec_loader_state == IPSEC_LOADER_FAILED);
}

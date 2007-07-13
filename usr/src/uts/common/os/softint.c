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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/spl.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kdi_impl.h>

/*
 * Handle software interrupts through 'softcall' mechanism
 *
 * At present softcall mechanism uses a global list headed by softhead.
 * Entries are added to tail and removed from head so as to preserve FIFO
 * nature of entries in the softcall list. softcall() takes care of adding
 * entries to the softtail.
 *
 * softint must take care of executing the entries in the FIFO
 * order. It could be called simultaneously from multiple cpus, however only
 * one instance of softint should process the softcall list, this is
 * ensured by
 * - the state the variable softcall_state will be at time to time.
 *   (IDLE->PEND->DRAIN->IDLE)
 *
 * These states are needed for softcall mechanism since  Solaris has only
 * one interface(ie. siron ) as of now for
 * - raising a soft interrupt architecture independently(ie not through
 *   setsoftint(..) )
 * - to process the softcall queue.
 */

#define	NSOFTCALLS	200
/*
 * Defined states for softcall processing.
 */
#define	SOFT_IDLE		0x01	/* no processing is needed */
#define	SOFT_PEND		0x02	/* softcall list needs processing */
#define	SOFT_DRAIN		0x04	/* the list is being processed */

typedef struct softcall {
	void (*sc_func)(void *);	/* function to call */
	void *sc_arg;			/* arg to pass to func */
	struct softcall *sc_next;	/* next in list */
} softcall_t;

static softcall_t softcalls[NSOFTCALLS], *softhead, *softtail, *softfree;
static uint_t	softcall_state;

/*
 * protects softcall lists and control variable softcall_state.
 */
static kmutex_t	softcall_lock;

static void (*kdi_softcall_func)(void);

extern void siron(void);
extern void kdi_siron(void);

void
softcall_init(void)
{
	softcall_t *sc;

	for (sc = softcalls; sc < &softcalls[NSOFTCALLS]; sc++) {
		sc->sc_next = softfree;
		softfree = sc;
	}
	mutex_init(&softcall_lock, NULL, MUTEX_SPIN, (void *)ipltospl(SPL8));
}

/*
 * Call function func with argument arg
 * at some later time at software interrupt priority
 */
void
softcall(void (*func)(void *), void *arg)
{
	softcall_t *sc;

	/*
	 * protect against cross-calls
	 */
	mutex_enter(&softcall_lock);
	/* coalesce identical softcalls */
	for (sc = softhead; sc != 0; sc = sc->sc_next) {
		if (sc->sc_func == func && sc->sc_arg == arg) {
			mutex_exit(&softcall_lock);
			return;
		}
	}

	if ((sc = softfree) == 0)
		panic("too many softcalls");
	softfree = sc->sc_next;
	sc->sc_func = func;
	sc->sc_arg = arg;
	sc->sc_next = 0;

	if (softhead) {
		softtail->sc_next = sc;
		softtail = sc;
		mutex_exit(&softcall_lock);
	} else {
		softhead = softtail = sc;
		if (softcall_state == SOFT_DRAIN)
			/*
			 * softint is already running; no need to
			 * raise a siron. Due to lock protection of
			 * softhead / softcall state, we know
			 * that softint() will see the new addition to
			 * the softhead queue.
			 */
			mutex_exit(&softcall_lock);
		else {
			softcall_state = SOFT_PEND;
			mutex_exit(&softcall_lock);
			siron();
		}
	}
}

void
kdi_softcall(void (*func)(void))
{
	kdi_softcall_func = func;

	if (softhead == NULL)
		kdi_siron();
}

/*
 * Called to process software interrupts take one off queue, call it,
 * repeat.
 *
 * Note queue may change during call; softcall_lock and state variables
 * softcall_state ensures that
 * -we don't have multiple cpus pulling from the list (thus causing
 *  a violation of FIFO order).
 * -we don't miss a new entry having been added to the head.
 * -we don't miss a wakeup.
 */

void
softint(void)
{
	softcall_t *sc;
	void (*func)();
	caddr_t arg;

	/*
	 * Check if we are asked to process the softcall list.
	 */
	mutex_enter(&softcall_lock);
	if (softcall_state != SOFT_PEND) {
		mutex_exit(&softcall_lock);
		goto out;
	}
	softcall_state = SOFT_DRAIN;

	for (;;) {
		if ((sc = softhead) != NULL) {
			func = sc->sc_func;
			arg = sc->sc_arg;
			softhead = sc->sc_next;
			sc->sc_next = softfree;
			softfree = sc;
		}
		if (sc == NULL) {
			softcall_state = SOFT_IDLE;
			mutex_exit(&softcall_lock);
			break;
		}
		mutex_exit(&softcall_lock);
		func(arg);
		mutex_enter(&softcall_lock);
	}
out:
	if ((func = kdi_softcall_func) != NULL) {
		kdi_softcall_func = NULL;
		func();
	}
}

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
 */

#define	NSOFTCALLS	200

typedef struct softcall {
	void (*sc_func)(void *);	/* function to call */
	void *sc_arg;			/* arg to pass to func */
	struct softcall *sc_next;	/* next in list */
} softcall_t;

static softcall_t softcalls[NSOFTCALLS], *softhead, *softtail, *softfree;

static kmutex_t	softcall_lock;		/* protects softcall lists */

static void (*kdi_softcall_func)(void);

extern void siron(void);

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
		mutex_exit(&softcall_lock);
		siron();
	}
}

void
kdi_softcall(void (*func)(void))
{
	kdi_softcall_func = func;

	if (softhead == NULL)
		siron();
}

/*
 * Called to process software interrupts
 * take one off queue, call it, repeat
 * Note queue may change during call
 */
void
softint(void)
{
	softcall_t *sc;
	void (*func)();
	caddr_t arg;

	for (;;) {
		mutex_enter(&softcall_lock);
		if ((sc = softhead) != NULL) {
			func = sc->sc_func;
			arg = sc->sc_arg;
			softhead = sc->sc_next;
			sc->sc_next = softfree;
			softfree = sc;
		}
		mutex_exit(&softcall_lock);
		if (sc == NULL)
			break;
		func(arg);
	}

	if ((func = kdi_softcall_func) != NULL) {
		kdi_softcall_func = NULL;
		func();
	}
}

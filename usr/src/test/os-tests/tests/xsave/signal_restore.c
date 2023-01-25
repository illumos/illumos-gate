/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Comptuer Company
 */

/*
 * Verify that the FPU contents are correctly restored after taking a signal. We
 * do this by going through and setting up a signal handler for SIGINFO and then
 * we do the following as tightly as possible: overwriting the FPU contents and
 * then calling thr_kill(). As part of the regression for #15254, we also
 * purposefully go off CPU in the signal handler to try to wreak havoc.
 */

#include <err.h>
#include <stdlib.h>
#include <ucontext.h>
#include <limits.h>
#include <signal.h>
#include <thread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xsave_util.h"

static xsu_fpu_t init_vals, signal_vals, found;
static volatile int exit_status = EXIT_SUCCESS;
static volatile int took_sig = 0;
static uint32_t sr_hwsup;

static void
signal_restore_siginfo(int sig, siginfo_t *sip, void *ucp)
{
	struct timespec ts;
	took_sig = 1;

	ts.tv_sec = 0;
	ts.tv_nsec = 10 * MILLISEC;

	/*
	 * yield doesn't guarantee that we go off CPU, but try a few anyways.
	 * There's a slight chance that nanosleep will modify the FPU state, but
	 * we can hope we're lucky and that the libc function won't.
	 */
	xsu_setfpu(&signal_vals, sr_hwsup);
	yield();
	yield();
	(void) nanosleep(&ts, NULL);
	xsu_getfpu(&found, sr_hwsup);

	if (xsu_same(&signal_vals, &found, sr_hwsup)) {
		(void) printf("TEST PASSED: FPU contents didn't change in "
		    "signal handler\n");
	} else {
		warnx("TEST FAILED: FPU contents changed in signal handler!");
		exit_status = EXIT_FAILURE;
	}

}

int
main(void)
{
	int ret;
	thread_t self = thr_self();
	uint32_t start = arc4random();
	uint32_t hwsup = xsu_hwsupport();
	struct sigaction sa;

	sr_hwsup = hwsup;
	sa.sa_sigaction = signal_restore_siginfo;
	sa.sa_flags = SA_RESETHAND;

	if (sigaction(SIGINFO, &sa, NULL) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: failed to set up signal "
		    "handler");
	}

	(void) printf("filling starting at 0x%x\n", start);
	xsu_fill(&init_vals, hwsup, start);
	xsu_fill(&signal_vals, hwsup, start + INT_MAX);

	(void) memset(&sa, 0, sizeof (struct sigaction));

	xsu_setfpu(&init_vals, hwsup);
	ret = thr_kill(self, SIGINFO);
	xsu_getfpu(&found, hwsup);

	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: failed to deliver "
		    "signal");
	}

	if (took_sig == 0) {
		errx(EXIT_FAILURE, "TEST FAILED: signal handler did not run");
	}

	(void) printf("TEST PASSED: SIGINFO successfully delivered\n");

	if (xsu_same(&init_vals, &found, hwsup)) {
		(void) printf("TEST PASSED: FPU contents successfully "
		    "restored\n");
	} else {
		warnx("TEST FAILED: FPU contents were not restored!");
		exit_status = EXIT_FAILURE;
	}

	return (exit_status);
}

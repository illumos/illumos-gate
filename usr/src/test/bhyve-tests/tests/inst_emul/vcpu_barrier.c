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
 * Copyright 2023 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"

static pthread_t vcpu0_tid;
static bool timed_out = false;

static void *
vcpu0_thread(void *arg)
{
	struct vcpu *vcpu = arg;

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		int err = vm_run(vcpu, &ventry, &vexit);
		if (err != 0) {
			test_fail_errno(err, "error during vm_run()");
		}
		switch (vexit.exitcode) {
		case VM_EXITCODE_BOGUS:
			/* We expect a BOGUS exit from the barrier */
			return (NULL);
		default:
			test_fail_vmexit(&vexit);
		}
	} while (true);
}

static void
sigalrm_handler(int sig)
{
	(void) pthread_cancel(vcpu0_tid);
	timed_out = true;
}

static void
configure_timeout(void)
{
	struct sigaction sa = {
		.sa_handler = sigalrm_handler,
	};
	struct sigaction old_sa;
	if (sigaction(SIGALRM, &sa, &old_sa) != 0) {
		test_fail_errno(errno,
		    "could not prep signal handling for bad access");
	}

	/* set a simple 1s-in-the-future alarm */
	(void) alarm(1);
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(suite_name);
	assert(ctx != NULL);

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	/* Activate vcpu0 as if it were running */
	err = vm_activate_cpu(vcpu);
	if (err != 0) {
		test_fail_errno(err, "could not activate vcpu0");
	}

	/*
	 * Set unorthodox run-state for vcpu0: wait-for-SIPI
	 * This way it will dawdle in the kernel during VM_RUN, despite there
	 * being no code to execute.  Normally the emulated APIC would not allow
	 * a CPU to SIPI itself, making this state impossible to reach.
	 */
	err = vm_set_run_state(vcpu, VRS_INIT, 0);
	if (err != 0) {
		test_fail_errno(err, "could not set vcpu0 run_state");
	}

	/* Get the vCPU thread running (and stuck in the kernel)... */
	if (pthread_create(&vcpu0_tid, NULL, vcpu0_thread, (void *)vcpu) != 0) {
		test_fail_errno(errno, "could not create thread for vcpu0");
	}

	/* configure a timeout in case the barrier failed */
	configure_timeout();

	/* ... then issue our barrier: */
	err = vm_vcpu_barrier(vcpu);
	if (err != 0) {
		test_fail_errno(err, "failed to issue vcpu barrier");
	}

	void *status = NULL;
	if (pthread_join(vcpu0_tid, &status) != 0) {
		test_fail_errno(errno, "could not join thread for vcpu0");
	}

	/* cancel any timeout now that thread was joined */
	(void) alarm(0);

	if (timed_out) {
		test_fail_msg("timed out while waiting for barrier\n");
	}

	test_pass();
}

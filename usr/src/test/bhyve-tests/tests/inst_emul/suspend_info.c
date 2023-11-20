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

/*
 * Check that supporting information for a VM_EXITCODE_SUSPENDED exit is correct
 * for a vCPU-specific event (triple-fault).
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"

#define	VCPU0_STACK	(MEM_LOC_STACK)
#define	VCPU1_STACK	(MEM_LOC_STACK - 0x1000)

struct vcpu_thread_ctx {
	struct vmctx *ctx;
	enum vm_suspend_how *howp;
	int *sourcep;
};

static void *
vcpu0_thread(void *arg)
{
	struct vcpu_thread_ctx *vtc = arg;
	struct vmctx *ctx = vtc->ctx;

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(ctx, 0, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED:
			if (vexit.exitcode != VM_EXITCODE_SUSPENDED) {
				test_fail_vmexit(&vexit);
			}
			*vtc->howp = vexit.u.suspended.how;
			*vtc->sourcep = vexit.u.suspended.source;
			return (NULL);
		default:
			test_fail_vmexit(&vexit);
		}
	} while (true);
}

static void
vcpu0_setup(struct vmctx *ctx)
{
	int err;

	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, VCPU0_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}
	err = vm_set_register(ctx, 0, VM_REG_GUEST_RDI, 0);
	if (err != 0) {
		test_fail_errno(err, "failed to set %rdi");
	}
}

static pthread_t
vcpu0_spawn(struct vcpu_thread_ctx *vtc)
{
	pthread_t tid;
	if (pthread_create(&tid, NULL, vcpu0_thread, (void *)vtc) != 0) {
		test_fail_errno(errno, "could not create thread for vcpu0");
	}

	return (tid);
}

static void
vcpu0_join(pthread_t tid)
{
	void *status = NULL;
	if (pthread_join(tid, &status) != 0) {
		test_fail_errno(errno, "could not join thread for vcpu0");
	}
	assert(status == NULL);
}

static void
test_plain_suspend(struct vmctx *ctx, enum vm_suspend_how test_how)
{
	enum vm_suspend_how how;
	int source;
	struct vcpu_thread_ctx vcpu0 = {
		.ctx = ctx,
		.howp = &how,
		.sourcep = &source,
	};
	pthread_t tid;
	int err;

	vcpu0_setup(ctx);
	tid = vcpu0_spawn(&vcpu0);
	err = vm_suspend(ctx, test_how);
	if (err != 0) {
		test_fail_errno(err, "vm_suspend() failure");
	}
	vcpu0_join(tid);

	if (how != test_how) {
		test_fail_msg("Unexpected suspend how %d != %d\n",
		    how, test_how);
	}
	if (source != -1) {
		test_fail_msg("Unexpected suspend source %d != %d\n",
		    source, -1);
	}

	/* Reset VM for another test */
	test_reinitialize(ctx, 0);
}

static void
test_emitted_triplefault(struct vmctx *ctx)
{
	enum vm_suspend_how vcpu0_how;
	int vcpu0_source;
	struct vcpu_thread_ctx vcpu0 = {
		.ctx = ctx,
		.howp = &vcpu0_how,
		.sourcep = &vcpu0_source,
	};
	int err;
	pthread_t tid;

	vcpu0_setup(ctx);

	/* Setup vCPU1 like vCPU0, but with ID of 1 in %rdi */
	err = test_setup_vcpu(ctx, 1, MEM_LOC_PAYLOAD, VCPU1_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu1");
	}
	err = vm_set_register(ctx, 1, VM_REG_GUEST_RDI, 1);
	if (err != 0) {
		test_fail_errno(err, "failed to set %rdi");
	}

	/*
	 * Get vcpu0 running on a separate thread, ready to have its day
	 * "ruined" by a triple-fault on vcpu1
	 */
	tid = vcpu0_spawn(&vcpu0);

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };
	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(ctx, 1, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED: {
			/* expect immediate triple-fault from ud2a */
			if (vexit.exitcode != VM_EXITCODE_SUSPENDED) {
				test_fail_vmexit(&vexit);
			}
			vcpu0_join(tid);
			const enum vm_suspend_how vcpu1_how =
			    vexit.u.suspended.how;
			const int vcpu1_source = vexit.u.suspended.source;

			if (vcpu0_how != VM_SUSPEND_TRIPLEFAULT ||
			    vcpu0_how != vcpu1_how) {
				test_fail_msg("Unexpected 'how' for "
				    "triple-fault: vcpu0=%d, vcpu1=%d, "
				    "expected=%d",
				    vcpu0_how, vcpu1_how,
				    VM_SUSPEND_TRIPLEFAULT);
			}
			if (vcpu0_source != 1 ||
			    vcpu0_source != vcpu1_source) {
				test_fail_msg("Unexpected 'source' for "
				    "triple-fault: vcpu0=%d, vcpu1=%d, "
				    "expected=%d",
				    vcpu0_source, vcpu1_source, 1);
			}
			return;
		}

		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;

	ctx = test_initialize(test_suite_name);

	/*
	 * Try injecting the various suspend types, and confirm that vcpu0 exits
	 * with the expected details.
	 */
	test_plain_suspend(ctx, VM_SUSPEND_RESET);
	test_plain_suspend(ctx, VM_SUSPEND_POWEROFF);
	test_plain_suspend(ctx, VM_SUSPEND_HALT);

	/*
	 * Let vCPU1 generate a triple-fault, and confirm that it is emitted by
	 * both exiting vCPU threads, with the proper details.
	 */
	test_emitted_triplefault(ctx);

	test_pass();
}

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
#include <strings.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"

static uint32_t opt_repeat_count = 1000;
static bool opt_summarize = false;

/* Names of the test phases running in guest context */
static const char *test_metric_idents[] = {
	"MSR",
	"PIO",
	"MMIO",
};

/* Track which test phase the guest is executing */
static uint_t current_test = 0;
/* Cache the queried CPU frequency */
static uint64_t cpu_freq = 0;

static uint64_t
query_cpu_freq(struct vmctx *ctx)
{
	const int vmfd = vm_get_device_fd(ctx);
	struct vdi_time_info_v1 time_info;
	struct vm_data_xfer xfer = {
		.vdx_class = VDC_VMM_TIME,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_time_info_v1),
		.vdx_data = &time_info,
	};

	if (ioctl(vmfd, VM_DATA_READ, &xfer) != 0) {
		errx(EXIT_FAILURE, "VMM_DATA_READ of time info failed");
	}
	return (time_info.vt_guest_freq);
}

static double
cycles_to_ns(uint64_t cycles)
{
	return ((cycles * 1000000000.0) / cpu_freq);
}

static void
print_result(struct vmctx *ctx, uintptr_t gpa, uint_t test_idx)
{
	if (test_idx >= ARRAY_SIZE(test_metric_idents)) {
		test_fail_msg("unexpected test iteration");
		return;
	}

	const uint64_t *data =
	    vm_map_gpa(ctx, gpa, opt_repeat_count * sizeof (uint64_t));
	assert(data != NULL);

	printf("%s", test_metric_idents[test_idx]);
	if (opt_summarize) {
		double sum = 0.0;
		for (uint32_t i = 0; i < opt_repeat_count; i++) {
			sum += cycles_to_ns(data[i]);
		}
		printf(",%0.2f", sum / opt_repeat_count);
	} else {
		for (uint32_t i = 0; i < opt_repeat_count; i++) {
			printf(",%0.2f", cycles_to_ns(data[i]));
		}
	}
	printf("\n");
}

static void
handle_exit(struct vmctx *ctx, const struct vm_exit *vexit,
    struct vm_entry *ventry)
{
	uint32_t outval;

	if (vexit_match_inout(vexit, true, IOP_TEST_PARAM0, 4, NULL)) {
		ventry_fulfill_inout(vexit, ventry, opt_repeat_count);
		return;
	}
	if (vexit_match_inout(vexit, false, IOP_TEST_VALUE, 4, &outval)) {
		ventry_fulfill_inout(vexit, ventry, 0);
		print_result(ctx, (uintptr_t)outval, current_test);
		/* proceed to next test */
		current_test++;
		return;
	}

	test_fail_vmexit(vexit);
}

static void
usage(const char *progname, int status)
{
	char *base = strdup(progname);

	(void) printf("usage: %s [args]\n"
	    "\t-n <count>\tNumber of repetitions (default: 1000)\n"
	    "\t-s\t\tSummarize (average) results\n"
	    "\t-h\t\tPrint this help\n", basename(base));
	exit(status);
}

static void
parse_args(int argc, char *argv[])
{
	int c;
	unsigned long num_parsed;

	while ((c = getopt(argc, argv, ":hsn:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
			break;
		case 's':
			opt_summarize = true;
			break;
		case 'n':
			errno = 0;
			num_parsed = strtoul(optarg, NULL, 10);
			if (num_parsed == 0 && errno != 0) {
				perror("Invalid repeat count");
				usage(argv[0], EXIT_FAILURE);
			}
			if (num_parsed <= 0 || num_parsed > UINT32_MAX) {
				(void) printf(
				    "Repeat count must be between 1 - %lu\n",
				    UINT32_MAX);
				usage(argv[0], EXIT_FAILURE);
			}
			opt_repeat_count = num_parsed;
			break;
		case ':':
			(void) printf("Missing argument for option '%c'\n",
			    optopt);
			usage(argv[0], EXIT_FAILURE);
			break;
		case '?':
			(void) printf("Unrecognized option '%c'\n", optopt);
			usage(argv[0], EXIT_FAILURE);
			break;
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	int err;

	parse_args(argc, argv);

	ctx = test_initialize(test_suite_name);

	err = test_setup_vcpu(ctx, 0, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}
	cpu_freq = query_cpu_freq(ctx);

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(ctx, 0, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED:
			handle_exit(ctx, &vexit, &ventry);
			break;

		case VEK_TEST_PASS:
			/*
			 * Skip the normal "PASS" message, since the consumer is
			 * interested in the data itself.
			 */
			exit(EXIT_SUCCESS);
			break;
		case VEK_TEST_MSG:
			test_msg_print(ctx);
			break;
		case VEK_TEST_FAIL:
		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}

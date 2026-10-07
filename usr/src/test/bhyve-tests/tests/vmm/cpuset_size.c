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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Check that VM_GET_CPUS works for a caller whose set is a different size from
 * the kernel's own, and that it refuses a size which would lose members or is
 * larger than a page.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/sysmacros.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

static const int test_vcpus[] = { 0, 9 };

static void
activate(struct vmctx *ctx, int vcpuid)
{
	struct vcpu *vcpu;

	if ((vcpu = vm_vcpu_open(ctx, vcpuid)) == NULL)
		err(EXIT_FAILURE, "could not open vcpu %d", vcpuid);
	if (vm_activate_cpu(vcpu) != 0)
		err(EXIT_FAILURE, "could not activate vcpu %d", vcpuid);
	vm_vcpu_close(vcpu);
}

static int
get_cpus(int vmfd, int which, void *buf, int size)
{
	struct vm_cpuset req = {
		.which = which,
		.cpusetsize = size,
		.cpus = buf,
	};

	return (ioctl(vmfd, VM_GET_CPUS, &req));
}

static void
check_set(const uint8_t *buf, size_t size)
{
	for (size_t bit = 0; bit < size * NBBY; bit++) {
		bool expect = false;

		for (uint_t i = 0; i < ARRAY_SIZE(test_vcpus); i++) {
			if ((size_t)test_vcpus[i] == bit)
				expect = true;
		}
		if ((((buf[bit / NBBY] >> (bit % NBBY)) & 1) != 0) != expect) {
			errx(EXIT_FAILURE, "bit %zu of a %zu-byte set is %s",
			    bit, size, expect ? "clear" : "set");
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	cpuset_t cpus;
	uint8_t buf[4096];
	int vmfd;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL)
		errx(EXIT_FAILURE, "could not open test VM");
	vmfd = vm_get_device_fd(ctx);

	for (uint_t i = 0; i < ARRAY_SIZE(test_vcpus); i++)
		activate(ctx, test_vcpus[i]);

	/* An empty set is refused */
	if (get_cpus(vmfd, VM_ACTIVE_CPUS, buf, 0) == 0 || errno != ERANGE)
		errx(EXIT_FAILURE, "empty set was not refused with ERANGE");

	/* As is one larger than a page */
	if (get_cpus(vmfd, VM_ACTIVE_CPUS, buf, PAGESIZE + 1) == 0 ||
	    errno != ERANGE) {
		errx(EXIT_FAILURE, "oversized set was not refused with ERANGE");
	}

	/* As is an unknown kind of set */
	if (get_cpus(vmfd, 0xbad, buf, sizeof (buf)) == 0 || errno != EINVAL)
		errx(EXIT_FAILURE, "unknown set was not refused with EINVAL");

	/* A set too small to hold vCPU 9 is refused rather than truncated */
	if (get_cpus(vmfd, VM_ACTIVE_CPUS, buf, 1) == 0 || errno != ERANGE)
		errx(EXIT_FAILURE, "lossy set was not refused with ERANGE");

	/* Any set which can hold every member is filled */
	const size_t sizes[] = { 2, 3, 8, 16, 32, sizeof (buf) };
	for (uint_t i = 0; i < ARRAY_SIZE(sizes); i++) {
		(void) memset(buf, 0xff, sizeof (buf));
		if (get_cpus(vmfd, VM_ACTIVE_CPUS, buf, sizes[i]) != 0) {
			err(EXIT_FAILURE, "VM_GET_CPUS with a %zu-byte set",
			    sizes[i]);
		}
		check_set(buf, sizes[i]);
	}

	/* The libvmmapi wrapper, with its own idea of cpuset_t, agrees */
	if (vm_active_cpus(ctx, &cpus) != 0)
		err(EXIT_FAILURE, "vm_active_cpus");
	check_set((const uint8_t *)&cpus, sizeof (cpus));

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}

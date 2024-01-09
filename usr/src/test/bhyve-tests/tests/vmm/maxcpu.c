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

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	/* Query VM_MAXCPU equivalent via VM topology */
	uint16_t sockets, cores, threads, maxcpus;
	if (vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus) != 0) {
		err(EXIT_FAILURE,
		    "could not query maxcpu via vm_get_topology()");
	}

	for (int i = 0; i < maxcpus; i++) {
		struct vcpu *vcpu;
		uint64_t val = 0;

		if ((vcpu = vm_vcpu_open(ctx, i)) == NULL) {
			err(EXIT_FAILURE, "could not open vcpu %d", i);
		}

		/* Check that all valid vCPUs can be activated... */
		if (vm_activate_cpu(vcpu) != 0) {
			err(EXIT_FAILURE, "could not activate vcpu %d", i);
		}

		/* and that we can do something basic (like read a register) */
		if (vm_get_register(vcpu, VM_REG_GUEST_RAX, &val) != 0) {
			err(EXIT_FAILURE, "could not read %%rax on vcpu %d", i);
		}

		vm_vcpu_close(vcpu);
	}

	/* Check some bogus inputs as well */
	const int bad_inputs[] = {-1, maxcpus, maxcpus + 1};
	for (uint_t i = 0; i < ARRAY_SIZE(bad_inputs); i++) {
		const int vcpu = bad_inputs[i];

		if (vm_vcpu_open(ctx, vcpu) != NULL) {
			errx(EXIT_FAILURE,
			    "unexpected open for invalid vcpu %d", i);
		}
	}

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}

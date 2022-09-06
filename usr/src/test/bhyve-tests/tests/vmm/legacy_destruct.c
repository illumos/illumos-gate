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
 * Copyright 2022 Oxide Computer Company
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

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could open test VM");
	}

	/*
	 * It would be odd if we had the freshly created VM instance, but it did
	 * not appear to exist.
	 */
	assert(check_instance_usable(suite_name));

	vm_close(ctx);

	/* Instance should remain, even though we closed it */
	if (!check_instance_usable(suite_name)) {
		err(EXIT_FAILURE, "instance missing after vm_close()");
	}

	/*
	 * The common destroy_instance() uses the "legacy" destruction mechanism
	 * via the vmmctl device.
	 */
	if (destroy_instance(suite_name) != 0) {
		errx(EXIT_FAILURE, "ioctl(VMM_DESTROY_VM) failed");
	}

	/* Instance should be gone at this point */
	if (check_instance_usable(suite_name)) {
		err(EXIT_FAILURE, "instance still accessible after destroy");
	}

	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}

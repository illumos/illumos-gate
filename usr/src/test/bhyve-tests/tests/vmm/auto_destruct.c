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
#include <assert.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_drv_test.h>
#include <vmmapi.h>

#include "common.h"

bool
test_for_instance(const char *suite_name)
{
	char vm_name[VM_MAX_NAMELEN];
	char vm_path[MAXPATHLEN];

	name_test_vm(suite_name, vm_name);
	(void) snprintf(vm_path, sizeof (vm_path), "/dev/vmm/%s", vm_name);

	struct stat buf;
	return (stat(vm_path, &buf) == 0);
}

int
destroy_instance(const char *suite_name)
{
	int ctl_fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (ctl_fd < 0) {
		return (-1);
	}

	struct vm_destroy_req req;
	name_test_vm(suite_name, req.name);

	if (ioctl(ctl_fd, VMM_DESTROY_VM, &req) != 0) {
		/* Preserve the destroy error across the close() */
		int err = errno;
		(void) close(ctl_fd);
		errno = err;
		return (-1);
	} else {
		(void) close(ctl_fd);
		return (0);
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (EXIT_FAILURE);
	}

	/*
	 * It would be odd if we had the freshly created VM instance, but it did
	 * not appear to exist.
	 */
	assert(test_for_instance(suite_name));

	/* Make sure that auto-destruct is off */
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 0) != 0) {
		perror("could not disable auto-destruct");
		return (EXIT_FAILURE);
	}

	vm_close(ctx);
	if (!test_for_instance(suite_name)) {
		perror("instance missing after close");
		return (EXIT_FAILURE);
	}
	ctx = NULL;

	if (destroy_instance(suite_name) != 0) {
		perror("could not clean up instance");
		return (EXIT_FAILURE);
	}

	/* Now repeat that process, but enable auto-destruct */
	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (EXIT_FAILURE);
	}
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 1) != 0) {
		perror("could not enable auto-destruct");
		return (EXIT_FAILURE);
	}
	vm_close(ctx);
	ctx = NULL;
	/* At this point, the instance should be gone */
	if (test_for_instance(suite_name)) {
		(void) fprintf(stderr,
		    "instance did not auto-destruct as expected");
		return (EXIT_FAILURE);
	}

	/*
	 * Repeat the test again, but establish a vmm_drv hold first.
	 * The instance should auto-destruct when the hold is released.
	 */
	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (EXIT_FAILURE);
	}
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 1) != 0) {
		perror("could not enable auto-destruct");
		return (EXIT_FAILURE);
	}
	int vdtfd = open_drv_test();
	if (vdtfd < 0) {
		perror("could open drv_test device");
		return (EXIT_FAILURE);
	}
	if (ioctl(vdtfd, VDT_IOC_HOLD, vm_get_device_fd(ctx)) != 0) {
		perror("could not hold VM from vmm_drv device");
		return (EXIT_FAILURE);
	}
	vm_close(ctx);
	ctx = NULL;
	if (!test_for_instance(suite_name)) {
		(void) fprintf(stderr,
		    "instance auto-destructed despite existing vmm_drv hold");
		return (EXIT_FAILURE);
	}
	if (ioctl(vdtfd, VDT_IOC_RELE, 0) != 0) {
		perror("could not release VM from vmm_drv device");
		return (EXIT_FAILURE);
	}
	if (test_for_instance(suite_name)) {
		(void) fprintf(stderr,
		    "instance did not auto-destructed after vmm_drv release");
		return (EXIT_FAILURE);
	}

	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}

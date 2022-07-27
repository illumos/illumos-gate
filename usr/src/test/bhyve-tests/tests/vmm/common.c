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
#include <strings.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>


/*
 * Generate name for test VM based on the name of the test suite (and the pid).
 */
void
name_test_vm(const char *test_suite_name, char *outp)
{
	(void) snprintf(outp, VM_MAX_NAMELEN, "bhyve-test-%s-%d",
	    test_suite_name, getpid());
}

/*
 * Create a test VM. The name of the test suite will be used to derive the name
 * of the instance.
 */
struct vmctx *
create_test_vm(const char *test_suite_name)
{
	char name[VM_MAX_NAMELEN];
	int res;

	name_test_vm(test_suite_name, name);

	res = vm_create(name, 0);
	if (res != 0) {
		return (NULL);
	}

	return (vm_open(name));
}

/*
 * Given a segment ID, length, and name, allocate a memseg in the given VM.
 */
int
alloc_memseg(struct vmctx *ctx, int segid, size_t len, const char *name)
{
	struct vm_memseg memseg = {
		.segid = segid,
		.len = len,
	};
	(void) strlcpy(memseg.name, name, sizeof (memseg.name));

	int fd = vm_get_device_fd(ctx);

	return (ioctl(fd, VM_ALLOC_MEMSEG, &memseg));
}

/*
 * Open the vmm_drv_test device.
 */
int
open_drv_test(void)
{
	return (open("/dev/vmm_drv_test", O_RDWR));
}

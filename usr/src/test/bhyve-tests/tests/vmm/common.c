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

#include <sys/types.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

struct vmctx *
create_test_vm(const char *test_suite_name)
{
	char name[VM_MAX_NAMELEN];
	int res;

	(void) snprintf(name, sizeof (name), "bhyve-test-%s-%d",
	    test_suite_name, getpid());

	res = vm_create(name, 0);
	if (res != 0) {
		return (NULL);
	}

	return (vm_open(name));
}

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

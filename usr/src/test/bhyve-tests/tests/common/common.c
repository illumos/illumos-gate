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
#include <strings.h>
#include <fcntl.h>
#include <errno.h>

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


/*
 * Test if VMM instance exists (and is not being destroyed).
 */
bool
check_instance_usable(const char *suite_name)
{
	char vm_name[VM_MAX_NAMELEN];
	char vm_path[MAXPATHLEN];

	name_test_vm(suite_name, vm_name);
	(void) snprintf(vm_path, sizeof (vm_path), "/dev/vmm/%s", vm_name);

	int fd = open(vm_path, O_RDWR, 0);
	if (fd < 0) {
		return (false);
	}

	const int destroy_pending = ioctl(fd, VM_DESTROY_PENDING, 0);
	(void) close(fd);

	return (destroy_pending == 0);
}

/*
 * Does an instance exist in /dev/vmm?  (No check for in-progress destroy)
 */
bool
check_instance_exists(const char *suite_name)
{
	char vm_name[VM_MAX_NAMELEN];
	char vm_path[MAXPATHLEN];

	name_test_vm(suite_name, vm_name);
	(void) snprintf(vm_path, sizeof (vm_path), "/dev/vmm/%s", vm_name);

	return (access(vm_path, F_OK) == 0);
}


/*
 * Destroy a VMM instance via the vmmctl device.
 */
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

/*
 * Returns true if running on AMD
 */
bool
cpu_vendor_amd(void)
{
	uint_t regs[4];
	char cpu_vendor[13];

	do_cpuid(0, regs);
	((uint_t *)&cpu_vendor)[0] = regs[1];
	((uint_t *)&cpu_vendor)[1] = regs[3];
	((uint_t *)&cpu_vendor)[2] = regs[2];
	cpu_vendor[12] = '\0';

	return (strcmp(cpu_vendor, "AuthenticAMD") == 0 ||
	    strcmp(cpu_vendor, "HygonGenuine") == 0);
}

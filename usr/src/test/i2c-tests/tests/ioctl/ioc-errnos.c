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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * While most ioctls all embed information that is i2c specific when they fail,
 * there are a few general classes of errors that can be generated with errnos:
 *
 *  - ENOTTY: When we ask for an ioctl on the wrong device minor class
 *  - EFAULT: When we pass a bad address for the ioctl
 *  - EBADF:  When we have an fd that's not open for read/write
 *  - EPERM:  When we don't have the requisite privileges to perfom the
 *            operation
 *
 * This test assumes we use the setup-full target.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/debug.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <priv.h>
#include <sys/i2c/ioctl.h>

#include "i2c_ioctl_util.h"

static void *ioctl_fault_addr;
static priv_set_t *ioctl_basic_set;
static priv_set_t *ioctl_orig_set;

typedef struct {
	char *info_name;
	int info_ioctl;
	i2c_dev_t info_type;
	bool info_write;
	bool info_perm;
} i2c_ioctl_info_t;

const i2c_ioctl_info_t i2c_ioctls[] = { {
	.info_name = "UI2C_IOCTL_CTRL_NPROPS",
	.info_ioctl = UI2C_IOCTL_CTRL_NPROPS,
	.info_type = I2C_D_CTRL,
	.info_write = false,
	.info_perm = false
}, {
	.info_name = "UI2C_IOCTL_CTRL_PROP_INFO",
	.info_ioctl = UI2C_IOCTL_CTRL_PROP_INFO,
	.info_type = I2C_D_CTRL,
	.info_write = false,
	.info_perm = false
}, {
	.info_name = "UI2C_IOCTL_CTRL_PROP_GET",
	.info_ioctl = UI2C_IOCTL_CTRL_PROP_GET,
	.info_type = I2C_D_CTRL,
	.info_write = false,
	.info_perm = false
}, {
	.info_name = "UI2C_IOCTL_CTRL_PROP_SET",
	.info_ioctl = UI2C_IOCTL_CTRL_PROP_SET,
	.info_type = I2C_D_CTRL,
	.info_write = true,
	.info_perm = true
}, {
	.info_name = "UI2C_IOCTL_DEVICE_ADD",
	.info_ioctl = UI2C_IOCTL_DEVICE_ADD,
	.info_type = I2C_D_PORT,
	.info_write = true,
	.info_perm = true
}, {
	.info_name = "UI2C_IOCTL_DEVICE_REMOVE",
	.info_ioctl = UI2C_IOCTL_DEVICE_REMOVE,
	.info_type = I2C_D_PORT,
	.info_write = true,
	.info_perm = true
}, {
	.info_name = "UI2C_IOCTL_I2C_REQ",
	.info_ioctl = UI2C_IOCTL_I2C_REQ,
	.info_type = I2C_D_PORT,
	.info_write = true,
	.info_perm = true
}, {
	.info_name = "UI2C_IOCTL_SMBUS_REQ",
	.info_ioctl = UI2C_IOCTL_SMBUS_REQ,
	.info_type = I2C_D_PORT,
	.info_write = true,
	.info_perm = true
}, {
	.info_name = "UI2C_IOCTL_PORT_INFO",
	.info_ioctl = UI2C_IOCTL_PORT_INFO,
	.info_type = I2C_D_PORT,
	.info_write = false,
	.info_perm = false
}, {
	.info_name = "UI2C_IOCTL_DEV_INFO",
	.info_ioctl = UI2C_IOCTL_DEV_INFO,
	.info_type = I2C_D_DEVICE,
	.info_write = false,
	.info_perm = false
}, {
	.info_name = "UI2C_IOCTL_MUX_INFO",
	.info_ioctl = UI2C_IOCTL_MUX_INFO,
	.info_type = I2C_D_MUX,
	.info_write = false,
	.info_perm = false
} };

static const char *ioctl_paths[4] = {
	[I2C_D_CTRL] = "i2csim0",
	[I2C_D_PORT] = "i2csim0/0",
	[I2C_D_MUX] = "i2csim0/0/0x70/mux",
	[I2C_D_DEVICE] = "i2csim0/0/0x10"
};

static bool
i2c_ioctl_fail(const i2c_ioctl_info_t *info, int fd, int exp,
    void *arg, const char *desc)
{
	if (ioctl(fd, info->info_ioctl, arg) == 0) {
		warnx("TEST FAILED: %s: %s: ioctl returned zero, but "
		    "expected %s", info->info_name, desc, strerrorname_np(exp));
		return (false);
	}

	if (errno != exp) {
		int e = errno;
		warnx("TEST FAILED: %s: %s: ioctl failed with %s, but "
		    "expected %s", info->info_name, desc, strerrorname_np(e),
		    strerrorname_np(exp));
		return (false);
	}

	(void) printf("TEST PASSED: %s: %s\n", info->info_name, desc);
	return (true);
}

static bool
i2c_ioctl_test_one(const i2c_ioctl_info_t *info)
{
	bool ret = true;

	/*
	 * First, verify it generates ENOTTY on the wrong device type.
	 */
	for (i2c_dev_t d = I2C_D_CTRL; d < I2C_D_OTHER; d++) {
		char buf[128];
		if (info->info_type == d)
			continue;
		(void) snprintf(buf, sizeof (buf), "wrong device type 0x%x "
		    "returns ENOTTY", d);
		int fd = i2c_ioctl_test_get_fd(d, ioctl_paths[d], O_RDWR);
		if (!i2c_ioctl_fail(info, fd, ENOTTY, NULL, buf)) {
			ret = false;
		}
		VERIFY0(close(fd));
	}

	/* EBADF */
	if (info->info_write) {
		/*
		 * Currently the nexus doesn't allow opening the device without
		 * read permissions, so we only test cases where writing is
		 * required. If this changes, then we should add an analogous
		 * test for read.
		 */
		int fd = i2c_ioctl_test_get_fd(info->info_type,
		    ioctl_paths[info->info_type], O_RDONLY);
		if (!i2c_ioctl_fail(info, fd, EBADF, 0, "EBADF (O_RDONLY)")) {
			ret = false;
		}
	}

	/* EPERM */
	if (info->info_perm) {
		int fd = i2c_ioctl_test_get_fd(info->info_type,
		    ioctl_paths[info->info_type], O_RDWR);
		VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, ioctl_basic_set));
		if (!i2c_ioctl_fail(info, fd, EPERM, 0, "missing privs")) {
			ret = false;
		}
		VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, ioctl_orig_set));
	}

	/* EFAULT */
	int fd = i2c_ioctl_test_get_fd(info->info_type,
	    ioctl_paths[info->info_type], O_RDWR);
	if (!i2c_ioctl_fail(info, fd, EFAULT, ioctl_fault_addr,
	    "bad address")) {
		ret = false;
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	ioctl_fault_addr = mmap(NULL, sysconf(_SC_PAGESIZE) * 4, PROT_NONE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (ioctl_fault_addr == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "bad page");
	}

	ioctl_basic_set = priv_allocset();
	ioctl_orig_set = priv_allocset();
	if (ioctl_basic_set == NULL || ioctl_orig_set == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to allocate "
		    "privilege sets");
	}
	priv_basicset(ioctl_basic_set);

	if (getppriv(PRIV_EFFECTIVE, ioctl_orig_set) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to get "
		    "current privilege set");
	}

	for (size_t i = 0; i < ARRAY_SIZE(i2c_ioctls); i++) {
		if (!i2c_ioctl_test_one(&i2c_ioctls[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}
	return (ret);
}

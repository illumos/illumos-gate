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
 * Common functions for the various ioctl tests that we're using.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <libdevinfo.h>
#include <unistd.h>
#include <libproc.h>

#include "nvme_ioctl_util.h"

/*
 * Cached copies of devinfo nodes to speed up subsequent lookups.
 */
static di_node_t nvme_test_root;
static di_node_t nvme_test_dev;

/*
 * Lock ioctl template structures. These are all non-blocking locks because we
 * don't want the tests to hang in error.
 */
const nvme_ioctl_lock_t nvme_test_ctrl_wrlock = {
	.nil_ent = NVME_LOCK_E_CTRL,
	.nil_level = NVME_LOCK_L_WRITE,
	.nil_flags = NVME_LOCK_F_DONT_BLOCK
};

const nvme_ioctl_lock_t nvme_test_ctrl_rdlock = {
	.nil_ent = NVME_LOCK_E_CTRL,
	.nil_level = NVME_LOCK_L_READ,
	.nil_flags = NVME_LOCK_F_DONT_BLOCK
};

const nvme_ioctl_lock_t nvme_test_ns_wrlock = {
	.nil_common = { .nioc_nsid = 1 },
	.nil_ent = NVME_LOCK_E_NS,
	.nil_level = NVME_LOCK_L_WRITE,
	.nil_flags = NVME_LOCK_F_DONT_BLOCK
};

const nvme_ioctl_lock_t nvme_test_ns_rdlock = {
	.nil_common = { .nioc_nsid = 1 },
	.nil_ent = NVME_LOCK_E_NS,
	.nil_level = NVME_LOCK_L_READ,
	.nil_flags = NVME_LOCK_F_DONT_BLOCK
};

const nvme_ioctl_unlock_t nvme_test_ctrl_unlock = {
	.niu_ent = NVME_LOCK_E_CTRL
};

const nvme_ioctl_unlock_t nvme_test_ns_unlock = {
	.niu_common = { .nioc_nsid = 1 },
	.niu_ent = NVME_LOCK_E_NS
};

static int
nvme_ioctl_test_find_nsid(di_node_t di, uint32_t nsid, int oflag)
{
	int fd;
	const char *type;
	char name[128], *mpath, path[PATH_MAX];
	di_minor_t minor;

	if (nsid == 0) {
		type = DDI_NT_NVME_NEXUS;
		(void) strlcpy(name, "devctl", sizeof (name));
	} else {
		type = DDI_NT_NVME_ATTACHMENT_POINT;
		(void) snprintf(name, sizeof (name), "%u", nsid);
	}

	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(di, minor)) != DI_MINOR_NIL) {
		if (strcmp(di_minor_nodetype(minor), type) == 0 &&
		    strcmp(di_minor_name(minor), name) == 0) {
			break;
		}
	}

	if (minor == DI_MINOR_NIL) {
		errx(EXIT_FAILURE, "failed to find minor for nsid %u on %s%d",
		    nsid, di_driver_name(di), di_instance(di));
	}

	mpath = di_devfs_minor_path(minor);
	if (mpath == NULL) {
		err(EXIT_FAILURE, "failed to get minor device path for nsid %u "
		    "on %s%d", nsid,  di_driver_name(di), di_instance(di));
	}

	if (snprintf(path, sizeof (path), "/devices%s", mpath) >=
	    sizeof (path)) {
		errx(EXIT_FAILURE, "failed to construct full /devices path for "
		    "%s: snprintf buffer would have overflowed", mpath);
	}
	di_devfs_path_free(mpath);

	fd = open(path, oflag);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open minor path %s", path);
	}

	return (fd);
}

/*
 * The ioctl tests expect an NVMe device to be nominated for use to test
 * against. Translate that device into an fd.
 */
int
nvme_ioctl_test_get_fd_flags(uint32_t nsid, int oflag)
{
	const char *dev, *errstr;
	long long ll;

	if (nvme_test_dev != NULL) {
		return (nvme_ioctl_test_find_nsid(nvme_test_dev, nsid, oflag));
	}

	dev = getenv(NVME_TEST_DEV_ENVVAR);
	if (dev == NULL) {
		errx(EXIT_FAILURE, "cannot run test, missing required NVMe "
		    "device, please set the %s environment variable",
		    NVME_TEST_DEV_ENVVAR);
	}

	if (strncmp("nvme", dev, 4) != 0) {
		errx(EXIT_FAILURE, "%s environment variable device %s does "
		    "not begin with 'nvme'", NVME_TEST_DEV_ENVVAR, dev);
	}

	ll = strtonum(dev + 4, 0, INT32_MAX, &errstr);
	if (errstr != NULL) {
		errx(EXIT_FAILURE, "failed to parse %s environment variable "
		    "device %s instance: value is %s", NVME_TEST_DEV_ENVVAR,
		    dev, errstr);
	}

	if (nvme_test_root == NULL) {
		nvme_test_root = di_init("/", DINFOCPYALL);
		if (nvme_test_root == DI_NODE_NIL) {
			err(EXIT_FAILURE, "failed to initialize libdevinfo");
		}
	}

	for (di_node_t di = di_drv_first_node("nvme", nvme_test_root);
	    di != DI_NODE_NIL; di = di_drv_next_node(di)) {
		if (di_instance(di) == (int)ll) {
			nvme_test_dev = di;
			return (nvme_ioctl_test_find_nsid(di, nsid, oflag));
		}
	}

	errx(EXIT_FAILURE, "failed to find %s environment variable device %s: "
	    "cannot run test", NVME_TEST_DEV_ENVVAR, dev);
}

int
nvme_ioctl_test_get_fd(uint32_t nsid)
{
	return (nvme_ioctl_test_get_fd_flags(nsid, O_RDWR));
}

/*
 * This is a wrapper that requires we successfully lock something.
 */
void
nvme_ioctl_test_lock(int fd, const nvme_ioctl_lock_t *lockp)
{
	nvme_ioctl_lock_t lock = *lockp;
	const char *targ = lockp->nil_ent == NVME_LOCK_E_CTRL ?
	    "controller" : "namespace";
	const char *level = lockp->nil_level == NVME_LOCK_L_READ ?
	    "read" : "write";

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: cannot proceed with tests due "
		    "to failure to issue %s %s lock ioctl", targ, level);
	} else if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		errx(EXIT_FAILURE, "TEST FAILED: cannot proceed with tests due "
		    "to failure to obtain %s %s lock, got 0x%x", targ, level,
		    lock.nil_common.nioc_drv_err);
	}
}

/*
 * Determine if a thread is blocked in our locking ioctl. We use proc_sysname()
 * so we can avoid encoding the system call number of the ioctl into the test
 * directly.
 */
bool
nvme_ioctl_test_thr_blocked(thread_t thr)
{
	lwpstatus_t lwp;
	char name[SYS2STR_MAX];

	if (proc_get_lwpstatus(getpid(), (uint_t)thr, &lwp) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: unable to continue test "
		    "execution as we failed to retrieve the lwpsinfo_t data "
		    "for thread 0x%x", thr);
	}

	if ((lwp.pr_flags & PR_ASLEEP) == 0)
		return (false);

	if (proc_sysname(lwp.pr_syscall, name, sizeof (name)) == NULL)
		return (false);

	return (strcmp(name, "ioctl") == 0);
}

const char *
nvme_ioctl_test_cmdstr(int cmd)
{
	switch (cmd) {
	case NVME_IOC_CTRL_INFO:
		return ("NVME_IOC_CTRL_INFO");
	case NVME_IOC_IDENTIFY:
		return ("NVME_IOC_IDENTIFY");
	case NVME_IOC_GET_LOGPAGE:
		return ("NVME_IOC_GET_LOGPAGE");
	case NVME_IOC_GET_FEATURE:
		return ("NVME_IOC_GET_FEATURE");
	case NVME_IOC_FORMAT:
		return ("NVME_IOC_FORMAT");
	case NVME_IOC_BD_DETACH:
		return ("NVME_IOC_BD_DETACH");
	case NVME_IOC_BD_ATTACH:
		return ("NVME_IOC_BD_ATTACH");
	case NVME_IOC_FIRMWARE_DOWNLOAD:
		return ("NVME_IOC_FIRMWARE_DOWNLOAD");
	case NVME_IOC_FIRMWARE_COMMIT:
		return ("NVME_IOC_FIRMWARE_COMMIT");
	case NVME_IOC_PASSTHRU:
		return ("NVME_IOC_PASSTHRU");
	case NVME_IOC_NS_INFO:
		return ("NVME_IOC_NS_INFO");
	case NVME_IOC_LOCK:
		return ("NVME_IOC_LOCK");
	case NVME_IOC_UNLOCK:
		return ("NVME_IOC_UNLOCK");
	case NVME_IOC_CTRL_ATTACH:
		return ("NVME_IOC_CTRL_ATTACH");
	case NVME_IOC_CTRL_DETACH:
		return ("NVME_IOC_CTRL_DETACH");
	case NVME_IOC_NS_CREATE:
		return ("NVME_IOC_NS_CREATE");
	case NVME_IOC_NS_DELETE:
		return ("NVME_IOC_NS_DELETE");
	default:
		return ("unknown");
	}
}

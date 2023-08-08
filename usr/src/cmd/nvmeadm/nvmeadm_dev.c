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
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <err.h>
#include <libdevinfo.h>
#include <sys/nvme.h>
#include <assert.h>

#include "nvmeadm.h"


static boolean_t
nvme_ioctl(int fd, int ioc, size_t *bufsize, void **buf, uint64_t arg,
    uint64_t *res)
{
	nvme_ioctl_t nioc = { 0 };
	void *ptr = NULL;
	int ret;

	if (bufsize != NULL && *bufsize != 0) {
		assert(buf != NULL);

		if (*buf != NULL) {
			nioc.n_buf = (uintptr_t)*buf;
		} else {
			ptr = calloc(1, *bufsize);
			if (ptr == NULL)
				err(-1, "nvme_ioctl()");

			nioc.n_buf = (uintptr_t)ptr;
		}

		nioc.n_len = *bufsize;
	}

	nioc.n_arg = arg;

	ret = ioctl(fd, ioc, &nioc);

	if (res != NULL)
		*res = nioc.n_arg;

	if (ret != 0) {
		/*
		 * We're not clearing *res here as there may be cases where
		 * we get an error _and_ we have interesting information in
		 * returned in *res that callers of this functions might be
		 * interested in.
		 */

		if (debug)
			warn("nvme_ioctl()");
		if (ptr != NULL)
			free(ptr);

		return (B_FALSE);
	}

	if (bufsize != NULL)
		*bufsize = nioc.n_len;

	if (buf != NULL)
		*buf = (void *)nioc.n_buf;

	return (B_TRUE);
}

nvme_capabilities_t *
nvme_capabilities(int fd)
{
	void *cap = NULL;
	size_t bufsize = sizeof (nvme_capabilities_t);

	(void) nvme_ioctl(fd, NVME_IOC_CAPABILITIES, &bufsize, &cap, 0, NULL);

	return (cap);
}

nvme_version_t *
nvme_version(int fd)
{
	void *vs = NULL;
	size_t bufsize = sizeof (nvme_version_t);

	(void) nvme_ioctl(fd, NVME_IOC_VERSION, &bufsize, &vs, 0, NULL);

	return (vs);
}

void *
nvme_identify(int fd, uint8_t cns)
{
	void *idctl = NULL;
	size_t bufsize = NVME_IDENTIFY_BUFSIZE;

	(void) nvme_ioctl(fd, NVME_IOC_IDENTIFY, &bufsize, &idctl, cns, NULL);

	return (idctl);
}

void *
nvme_get_logpage(int fd, uint8_t logpage, size_t *bufsize)
{
	void *buf = NULL;

	(void) nvme_ioctl(fd, NVME_IOC_GET_LOGPAGE, bufsize, &buf, logpage,
	    NULL);

	return (buf);
}

boolean_t
nvme_get_feature(int fd, uint8_t feature, uint32_t arg, uint64_t *res,
    size_t *bufsize, void **buf)
{
	return (nvme_ioctl(fd, NVME_IOC_GET_FEATURES, bufsize, buf,
	    (uint64_t)feature << 32 | arg, res));
}

int
nvme_intr_cnt(int fd)
{
	uint64_t res = 0;

	if (!nvme_ioctl(fd, NVME_IOC_INTR_CNT, NULL, NULL, 0, &res))
		return (-1);

	return ((int)res);
}

boolean_t
nvme_format_nvm(int fd, uint8_t lbaf, uint8_t ses)
{
	nvme_format_nvm_t frmt = { 0 };

	frmt.b.fm_lbaf = lbaf & 0xf;
	frmt.b.fm_ses = ses & 0x7;

	return (nvme_ioctl(fd, NVME_IOC_FORMAT, NULL, NULL, frmt.r, NULL));
}

boolean_t
nvme_detach(int fd)
{
	return (nvme_ioctl(fd, NVME_IOC_DETACH, NULL, NULL, 0, NULL));
}

boolean_t
nvme_attach(int fd)
{
	return (nvme_ioctl(fd, NVME_IOC_ATTACH, NULL, NULL, 0, NULL));
}

boolean_t
nvme_firmware_load(int fd, void *buf, size_t len, offset_t offset, uint16_t *sc)
{
	boolean_t rv;
	uint64_t res;

	rv = nvme_ioctl(fd, NVME_IOC_FIRMWARE_DOWNLOAD, &len, &buf, offset,
	    &res);

	/*
	 * If the hardware returned a command-specific status code, we'll get
	 * it as a negative value from the driver.
	 */
	if ((int64_t)res < 0)
		*sc = (uint16_t)-(int64_t)res;
	else
		*sc = 0;

	return (rv);
}

boolean_t
nvme_firmware_commit(int fd, int slot, int action, uint16_t *sc)
{
	boolean_t rv;
	uint64_t res;

	rv = nvme_ioctl(fd, NVME_IOC_FIRMWARE_COMMIT, NULL, NULL,
	    ((uint64_t)action << 32) | slot, &res);

	/*
	 * If the hardware returned a command-specific status code, we'll get
	 * it as a negative value from the driver.
	 */
	if ((int64_t)res < 0)
		*sc = (uint16_t)-(int64_t)res;
	else
		*sc = 0;

	return (rv);
}

nvme_ns_state_t
nvme_namespace_state(int fd)
{
	nvme_ns_info_t *info = NULL;
	size_t buflen = sizeof (nvme_ns_info_t);

	/*
	 * Ask the driver for the namespace state.
	 */
	if (nvme_ioctl(fd, NVME_IOC_NS_INFO, &buflen, (void **)&info, 0,
	    NULL)) {
		nvme_ns_state_t s = info->nni_state;
		free(info);
		return (s);
	}

	/*
	 * We're only here if the ioctl failed, which it really shouldnt. If so,
	 * we treat this the same as if the namespace was ignored.
	 */
	return (NVME_NS_STATE_IGNORED);
}

int
nvme_open(di_minor_t minor, boolean_t excl)
{
	char *devpath, *path;
	int fd;

	if ((devpath = di_devfs_minor_path(minor)) == NULL)
		err(-1, "nvme_open()");

	if (asprintf(&path, "/devices%s", devpath) < 0) {
		di_devfs_path_free(devpath);
		err(-1, "nvme_open()");
	}

	di_devfs_path_free(devpath);

	fd = open(path, O_RDWR | (excl ? O_EXCL: 0));

	if (fd < 0) {
		if (debug)
			warn("nvme_open(%s)", path);
		free(path);
		return (-1);
	}
	free(path);

	return (fd);
}

void
nvme_close(int fd)
{
	(void) close(fd);
}

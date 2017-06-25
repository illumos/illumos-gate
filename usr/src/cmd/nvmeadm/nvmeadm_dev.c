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
 * Copyright 2016 Nexenta Systems, Inc.
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

	if (buf != NULL)
		*buf = NULL;

	if (res != NULL)
		*res = ~0ULL;

	if (bufsize != NULL && *bufsize != 0) {
		assert(buf != NULL);

		if ((nioc.n_buf = (uintptr_t)calloc(*bufsize, 1)) == NULL)
			err(-1, "nvme_ioctl()");

		nioc.n_len = *bufsize;
	}

	nioc.n_arg = arg;

	if (ioctl(fd, ioc, &nioc) != 0) {
		if (debug)
			warn("nvme_ioctl()");
		if (nioc.n_buf != 0)
			free((void *)nioc.n_buf);

		return (B_FALSE);
	}

	if (res != NULL)
		*res = nioc.n_arg;

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

nvme_identify_ctrl_t *
nvme_identify_ctrl(int fd)
{
	void *idctl = NULL;
	size_t bufsize = NVME_IDENTIFY_BUFSIZE;

	(void) nvme_ioctl(fd, NVME_IOC_IDENTIFY_CTRL, &bufsize, &idctl, 0,
	    NULL);

	return (idctl);
}

nvme_identify_nsid_t *
nvme_identify_nsid(int fd)
{
	void *idns = NULL;
	size_t bufsize = NVME_IDENTIFY_BUFSIZE;

	(void) nvme_ioctl(fd, NVME_IOC_IDENTIFY_NSID, &bufsize, &idns, 0, NULL);

	return (idns);
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

	(void) nvme_ioctl(fd, NVME_IOC_INTR_CNT, NULL, NULL, 0, &res);
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

int
nvme_open(di_minor_t minor)
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

	fd = open(path, O_RDWR);
	free(path);

	if (fd < 0) {
		if (debug)
			warn("nvme_open(%s)", path);
		return (-1);
	}

	return (fd);
}

void
nvme_close(int fd)
{
	(void) close(fd);
}

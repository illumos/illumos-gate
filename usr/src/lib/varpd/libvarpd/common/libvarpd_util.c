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
 * Copyright 2015 Joyent, Inc.
 */

#include <libvarpd_impl.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

const char *
libvarpd_isaext(void)
{
#if defined(__amd64)
	return ("64");
#elif defined(__i386)
	return ("");
#else
#error	"unknown ISA"
#endif
}

int
libvarpd_dirwalk(varpd_impl_t *vip, const char *path, const char *suffix,
    libvarpd_dirwalk_f func, void *arg)
{
	int ret;
	size_t slen;
	char *dirpath, *filepath;
	DIR *dirp;
	struct dirent *dp;
	assert(vip != NULL && path != NULL);

	if (asprintf(&dirpath, "%s/%s", path, libvarpd_isaext()) == -1)
		return (errno);

	if ((dirp = opendir(dirpath)) == NULL) {
		ret = errno;
		return (ret);
	}

	slen = strlen(suffix);
	for (;;) {
		size_t len;

		errno = 0;
		dp = readdir(dirp);
		if (dp == NULL) {
			ret = errno;
			break;
		}

		len = strlen(dp->d_name);
		if (len <= slen)
			continue;

		if (strcmp(suffix, dp->d_name + (len - slen)) != 0)
			continue;

		if (asprintf(&filepath, "%s/%s", dirpath, dp->d_name) == -1) {
			ret = errno;
			break;
		}

		if (func(vip, filepath, arg) != 0) {
			free(filepath);
			ret = 0;
			break;
		}

		free(filepath);
	}

	(void) closedir(dirp);
	free(dirpath);
	return (ret);
}

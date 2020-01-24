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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/sysmacros.h>

#include <libgen.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>

#include "Pcontrol.h"

/*
 * Walk all file descriptors open for a process and call func() for each.
 */
int
proc_fdwalk(pid_t pid, proc_fdwalk_f *func, void *arg)
{
	struct dirent *dirent;
	DIR *fddir;
	char *dir;
	int ret = 0;

	if (asprintf(&dir, "%s/%d/fd", procfs_path, (int)pid) == -1)
		return (-1);

	if ((fddir = opendir(dir)) == NULL) {
		free(dir);
		return (-1);
	}

	free(dir);

	while ((dirent = readdir(fddir)) != NULL) {
		prfdinfo_t *info;
		char *errptr;
		int fd;

		if (!isdigit(dirent->d_name[0]))
			continue;

		fd = (int)strtol(dirent->d_name, &errptr, 10);
		if (errptr != NULL && *errptr != '\0')
			continue;

		if ((info = proc_get_fdinfo(pid, fd)) == NULL)
			continue;

		ret = func(info, arg);

		free(info);

		if (ret != 0)
			break;
	}

	(void) closedir(fddir);
	return (ret);
}

int
proc_fdinfowalk(const prfdinfo_t *info, proc_fdinfowalk_f *func, void *arg)
{
	off_t off = offsetof(prfdinfo_t, pr_misc);
	int ret = 0;

	for (;;) {
		const pr_misc_header_t *misc;
		uint_t type;
		size_t size;

		misc = (pr_misc_header_t *)((uint8_t *)info + off);

		/* Found terminating record */
		if (misc->pr_misc_size == 0)
			break;

		off += misc->pr_misc_size;

		type = misc->pr_misc_type;
		size = misc->pr_misc_size - sizeof (pr_misc_header_t);
		misc++;

		ret = func(type, misc, size, arg);

		if (ret != 0)
			break;
	}

	return (ret);
}

prfdinfo_t *
proc_get_fdinfo(pid_t pid, int fd)
{
	prfdinfo_t *info = NULL;
	char *fname;
	uint_t retries;
	int ifd, err = EIO;

	if (asprintf(&fname, "%s/%d/fdinfo/%d",
	    procfs_path, (int)pid, fd) == -1) {
		return (NULL);
	}

	if ((ifd = open(fname, O_RDONLY)) == -1) {
		free(fname);
		return (NULL);
	}

	free(fname);

	/*
	 * There is a race between stat()-ing the file and reading from
	 * it where the size may change. To protect against that, we
	 * walk the returned data to ensure that it is properly
	 * terminated. If not, increase the buffer size and try again.
	 */

	for (retries = 1; retries < 5; retries++) {
		struct stat st;
		off_t off;
		size_t l;

		if (fstat(ifd, &st) == -1) {
			err = errno;
			break;
		}

		st.st_size *= retries;

		if ((info = reallocf(info, st.st_size)) == NULL) {
			err = errno;
			break;
		}

		if ((l = read(ifd, info, st.st_size)) == -1) {
			err = errno;
			break;
		}

		/* Walk the data to check that is properly terminated. */

		off = offsetof(prfdinfo_t, pr_misc);

		while (off <= l - sizeof (pr_misc_header_t)) {
			pr_misc_header_t *misc;

			misc = (pr_misc_header_t *)((uint8_t *)info + off);

			if (misc->pr_misc_size == 0) {
				/* Found terminator record */
				(void) close(ifd);
				return (info);
			}

			/* Next record */
			off += misc->pr_misc_size;
		}
	}

	(void) close(ifd);
	free(info);

	errno = err;

	return (NULL);
}

typedef struct proc_fdinfo_misc_cbdata {
	uint_t type;
	const void *data;
	size_t len;
} pfm_data_t;

static int
proc_fdinfo_misc_cb(uint_t type, const void *data, size_t len, void *datap)
{
	pfm_data_t *cb = (pfm_data_t *)datap;

	if (type == cb->type) {
		cb->data = data;
		cb->len = len;
		return (1);
	}
	return (0);
}

const void *
proc_fdinfo_misc(const prfdinfo_t *info, uint_t type, size_t *buflen)
{
	pfm_data_t cb;

	cb.data = NULL;
	cb.type = type;

	(void) proc_fdinfowalk(info, proc_fdinfo_misc_cb, (void *)&cb);

	if (cb.data != NULL) {
		if (buflen != NULL)
			*buflen = cb.len;

		return (cb.data);
	}

	return (NULL);
}

static int
proc_fdinfo_dup_cb(uint_t type, const void *data, size_t len, void *datap)
{
	size_t *sz = (size_t *)datap;

	*sz += len + sizeof (pr_misc_header_t);
	return (0);
}


prfdinfo_t *
proc_fdinfo_dup(const prfdinfo_t *old)
{
	prfdinfo_t *new;
	size_t sz = offsetof(prfdinfo_t, pr_misc);

	/* Determine the size of the miscellaneous items */
	(void) proc_fdinfowalk(old, proc_fdinfo_dup_cb, (void *)&sz);

	/* Add the size of the terminator record */
	sz += sizeof (pr_misc_header_t);

	if ((new = calloc(1, sz)) == NULL)
		return (NULL);

	bcopy(old, new, sz);

	return (new);
}

void
proc_fdinfo_free(prfdinfo_t *info)
{
	free(info);
}

/*
 * Convert a prfdinfo_core_t to prfdinfo_t
 */
int
proc_fdinfo_from_core(const prfdinfo_core_t *core, prfdinfo_t **infop)
{
	prfdinfo_t *info;
	size_t len, slen = 0;

	len = offsetof(prfdinfo_t, pr_misc) + sizeof (pr_misc_header_t);
	if (*core->pr_path != '\0') {
		slen = strlen(core->pr_path) + 1;
		len += PRFDINFO_ROUNDUP(slen) + sizeof (pr_misc_header_t);
	}

	if ((info = calloc(1, len)) == NULL)
		return (-1);

	*infop = info;

	info->pr_fd = core->pr_fd;
	info->pr_mode = core->pr_mode;
	info->pr_uid = core->pr_uid;
	info->pr_gid = core->pr_gid;
	info->pr_major = core->pr_major;
	info->pr_minor = core->pr_minor;
	info->pr_rmajor = core->pr_rmajor;
	info->pr_rminor = core->pr_rminor;
	info->pr_size = core->pr_size;
	info->pr_ino = core->pr_ino;
	info->pr_fileflags = core->pr_fileflags;
	info->pr_fdflags = core->pr_fdflags;
	info->pr_offset = core->pr_offset;

	if (slen != 0) {
		pr_misc_header_t *misc;

		misc = (pr_misc_header_t *)&info->pr_misc;

		misc->pr_misc_size = sizeof (*misc) + PRFDINFO_ROUNDUP(slen);
		misc->pr_misc_type = PR_PATHNAME;
		misc++;
		bcopy(core->pr_path, misc, slen);
	}

	return (0);
}

/*
 * Convert a prfdinfo_t to prfdinfo_core_t
 */
int
proc_fdinfo_to_core(const prfdinfo_t *info, prfdinfo_core_t *core)
{
	const char *path;
	size_t pathl;

	bzero(core, sizeof (*core));

	core->pr_fd = info->pr_fd;
	core->pr_mode = info->pr_mode;
	core->pr_uid = info->pr_uid;
	core->pr_gid = info->pr_gid;
	core->pr_major = info->pr_major;
	core->pr_minor = info->pr_minor;
	core->pr_rmajor = info->pr_rmajor;
	core->pr_rminor = info->pr_rminor;
	core->pr_size = info->pr_size;
	core->pr_ino = info->pr_ino;
	core->pr_fileflags = info->pr_fileflags;
	core->pr_fdflags = info->pr_fdflags;
	core->pr_offset = info->pr_offset;

	path = proc_fdinfo_misc(info, PR_PATHNAME, &pathl);
	if (path != NULL) {
		/*
		 * Rather than provide a truncated path in the pr_path field
		 * just leave it empty if the path will not fit.
		 */
		if (pathl <= sizeof (core->pr_path) - 1)
			bcopy(path, core->pr_path, pathl + 1);
	}

	return (0);
}

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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <librename.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <synch.h>

typedef enum librename_atomic_state {
	LIBRENAME_ATOMIC_INITIAL = 0x0,
	LIBRENAME_ATOMIC_FSYNC,
	LIBRENAME_ATOMIC_RENAME,
	LIBRENAME_ATOMIC_POSTSYNC,
	LIBRENAME_ATOMIC_COMPLETED
} librename_atomic_state_t;

struct librename_atomic {
	char *lra_fname;			/* RO */
	char *lra_altname;			/* RO */
	int lra_dirfd;				/* RO */
	int lra_tmpfd;				/* RO */
	mutex_t lra_lock;
	librename_atomic_state_t lra_state;	/* lra_lock */
};

int
librename_atomic_fdinit(int fd, const char *file, const char *prefix,
    int mode, int flags, librename_atomic_t **outp)
{
	int ret;
	int oflags;
	librename_atomic_t *lrap;
	struct stat st;

	if (fd < 0 || file == NULL || outp == NULL)
		return (EINVAL);

	if (flags & ~(LIBRENAME_ATOMIC_NOUNLINK | LIBRENAME_ATOMIC_CLOEXEC))
		return (EINVAL);

	if (strchr(file, '/') != NULL)
		return (EINVAL);

	if (prefix != NULL && strchr(prefix, '/') != NULL)
		return (EINVAL);

	*outp = NULL;
	lrap = malloc(sizeof (librename_atomic_t));
	if (lrap == NULL)
		return (errno);

	if (fstat(fd, &st) != 0) {
		ret = errno;
		free(lrap);
		return (ret);
	}

	if (!S_ISDIR(st.st_mode)) {
		free(lrap);
		return (ENOTDIR);
	}

	if ((lrap->lra_dirfd = dup(fd)) == -1) {
		ret = errno;
		free(lrap);
		return (ret);
	}

	lrap->lra_fname = strdup(file);
	if (lrap->lra_fname == NULL) {
		ret = errno;
		VERIFY0(close(lrap->lra_dirfd));
		free(lrap);
		return (ret);
	}

	if (prefix == NULL) {
		ret = asprintf(&lrap->lra_altname, ".%d.%s", (int)getpid(),
		    file);
	} else {
		ret = asprintf(&lrap->lra_altname, "%s%s", prefix, file);
	}
	if (ret == -1) {
		ret = errno;
		free(lrap->lra_fname);
		VERIFY0(close(lrap->lra_dirfd));
		free(lrap);
		return (errno);
	}

	oflags = O_CREAT | O_TRUNC | O_RDWR | O_NOFOLLOW;
	if (flags & LIBRENAME_ATOMIC_NOUNLINK)
		oflags |= O_EXCL;

	if (flags & LIBRENAME_ATOMIC_CLOEXEC)
		oflags |= O_CLOEXEC;

	lrap->lra_tmpfd = openat(lrap->lra_dirfd, lrap->lra_altname,
	    oflags, mode);
	if (lrap->lra_tmpfd < 0) {
		ret = errno;
		free(lrap->lra_altname);
		free(lrap->lra_fname);
		VERIFY0(close(lrap->lra_dirfd));
		free(lrap);
		return (ret);
	}

	VERIFY0(mutex_init(&lrap->lra_lock, USYNC_THREAD, NULL));

	lrap->lra_state = LIBRENAME_ATOMIC_INITIAL;
	*outp = lrap;
	return (0);
}

int
librename_atomic_init(const char *dir, const char *file, const char *prefix,
    int mode, int flags, librename_atomic_t **outp)
{
	int fd, ret;

	if ((fd = open(dir, O_RDONLY)) < 0)
		return (errno);

	ret = librename_atomic_fdinit(fd, file, prefix, mode, flags, outp);
	VERIFY0(close(fd));

	return (ret);
}

int
librename_atomic_fd(librename_atomic_t *lrap)
{
	return (lrap->lra_tmpfd);
}

/*
 * To atomically commit a file, we need to go through and do the following:
 *
 *  o fsync the source
 *  o run rename
 *  o fsync the source again and the directory.
 */
int
librename_atomic_commit(librename_atomic_t *lrap)
{
	int ret = 0;

	VERIFY0(mutex_lock(&lrap->lra_lock));
	if (lrap->lra_state == LIBRENAME_ATOMIC_COMPLETED) {
		ret = EINVAL;
		goto out;
	}

	if (fsync(lrap->lra_tmpfd) != 0) {
		ret = errno;
		goto out;
	}
	lrap->lra_state = LIBRENAME_ATOMIC_FSYNC;

	if (renameat(lrap->lra_dirfd, lrap->lra_altname, lrap->lra_dirfd,
	    lrap->lra_fname) != 0) {
		ret = errno;
		goto out;
	}
	lrap->lra_state = LIBRENAME_ATOMIC_RENAME;

	if (fsync(lrap->lra_tmpfd) != 0) {
		ret = errno;
		goto out;
	}
	lrap->lra_state = LIBRENAME_ATOMIC_POSTSYNC;

	if (fsync(lrap->lra_dirfd) != 0) {
		ret = errno;
		goto out;
	}
	lrap->lra_state = LIBRENAME_ATOMIC_COMPLETED;

out:
	VERIFY0(mutex_unlock(&lrap->lra_lock));
	return (ret);
}

void
librename_atomic_fini(librename_atomic_t *lrap)
{

	free(lrap->lra_altname);
	free(lrap->lra_fname);
	VERIFY0(close(lrap->lra_tmpfd));
	VERIFY0(close(lrap->lra_dirfd));
	VERIFY0(mutex_destroy(&lrap->lra_lock));
	free(lrap);
}

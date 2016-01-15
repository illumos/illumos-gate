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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/lx_fcntl.h>

#define	LX_LINK_ALLOWED	(LX_AT_SYMLINK_FOLLOW | LX_AT_EMPTY_PATH)

static long
lx_link_common(int ffd, char *from, int tfd, char *to, int flags)
{
	int error;
	vnode_t *fsvp = NULL, *tsvp = NULL;
	enum symfollow follow = NO_FOLLOW;

	if ((flags & ~LX_LINK_ALLOWED) != 0) {
		return (set_errno(EINVAL));
	}
	if ((flags & LX_AT_EMPTY_PATH) == 0) {
		char c;

		/*
		 * Check that both 'from' and 'to' names are non-empty if
		 * AT_EMPTY_PATH is not set.
		 */
		if (copyin(from, &c, sizeof (c)) != 0) {
			return (set_errno(EFAULT));
		} else if (c == '\0') {
			return (set_errno(ENOENT));
		}
		if (copyin(to, &c, sizeof (c)) != 0) {
			return (set_errno(EFAULT));
		} else if (c == '\0') {
			return (set_errno(ENOENT));
		}

		/*
		 * XXX: When our support for LX capabilities improves, ENOENT
		 * should be thrown when a process lacking CAP_DAC_READ_SEARCH
		 * attempts to use the AT_EMPTY_PATH flag.
		 */
	}
	if ((flags & LX_AT_SYMLINK_FOLLOW) != 0) {
		follow = FOLLOW;
	}

	if ((error = fgetstartvp(ffd, from, &fsvp)) != 0) {
		goto out;
	}
	if ((error = fgetstartvp(tfd, to, &tsvp)) != 0) {
		goto out;
	}
	error = vn_linkat(fsvp, from, follow, tsvp, to, UIO_USERSPACE);

out:
	if (fsvp != NULL) {
		VN_RELE(fsvp);
	}
	if (tsvp != NULL) {
		VN_RELE(tsvp);
	}
	if (error) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_link(char *from, char *to)
{
	return (lx_link_common(AT_FDCWD, from, AT_FDCWD, to, 0));
}

long
lx_linkat(int ffd, char *from, int tfd, char *to, int flags)
{
	ffd = (ffd == LX_AT_FDCWD) ? AT_FDCWD : ffd;
	tfd = (tfd == LX_AT_FDCWD) ? AT_FDCWD : tfd;

	return (lx_link_common(ffd, from, tfd, to, flags));
}

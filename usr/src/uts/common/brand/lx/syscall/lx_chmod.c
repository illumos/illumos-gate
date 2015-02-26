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

#include <sys/fcntl.h>
#include <sys/thread.h>
#include <sys/klwp.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>

/*
 * From "uts/common/syscall/chmod.c":
 */
extern int fchmodat(int, char *, int, int);

static long
lx_fchmodat_wrapper(int fd, char *path, int mode, int flag)
{
	long rval;

	if (fd == LX_AT_FDCWD) {
		fd = AT_FDCWD;
	}

	if ((rval = fchmodat(fd, path, mode, flag)) != 0) {
		lx_proc_data_t *pd = ttolxproc(curthread);
		klwp_t *lwp = ttolwp(curthread);

		/*
		 * If the process is in "install mode", return success
		 * if the operation failed due to an absent file.
		 */
		if ((pd->l_flags & LX_PROC_INSTALL_MODE) &&
		    lwp->lwp_errno == ENOENT) {
			lwp->lwp_errno = 0;
			return (0);
		}
	}

	return (rval);
}

long
lx_fchmodat(int fd, char *path, int mode)
{
	return (lx_fchmodat_wrapper(fd, path, mode, 0));
}

long
lx_fchmod(int fd, int mode)
{
	return (lx_fchmodat_wrapper(fd, NULL, mode, 0));
}

long
lx_chmod(char *path, int mode)
{
	return (lx_fchmodat_wrapper(AT_FDCWD, path, mode, 0));
}

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inttypes.h>

#include <sys/lx_types.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>

extern int fcntl(int, int, intptr_t);
extern int openat(int, char *, int, int);
extern int open(char *, int, int);
extern int close(int);
extern int ioctl(int, int, intptr_t);
extern int lookupnameat(char *, enum uio_seg, int, vnode_t **, vnode_t **,
    vnode_t *);

static int
ltos_open_flags(uintptr_t p2)
{
	int flags;

	if ((p2 & O_ACCMODE) == LX_O_RDONLY)
		flags = O_RDONLY;
	else if ((p2 & O_ACCMODE) == LX_O_WRONLY)
		flags = O_WRONLY;
	else
		flags = O_RDWR;

	if (p2 & LX_O_CREAT) {
		flags |= O_CREAT;
	}

	if (p2 & LX_O_EXCL)
		flags |= O_EXCL;
	if (p2 & LX_O_NOCTTY)
		flags |= O_NOCTTY;
	if (p2 & LX_O_TRUNC)
		flags |= O_TRUNC;
	if (p2 & LX_O_APPEND)
		flags |= O_APPEND;
	if (p2 & LX_O_NONBLOCK)
		flags |= O_NONBLOCK;
	if (p2 & LX_O_SYNC)
		flags |= O_SYNC;
	if (p2 & LX_O_LARGEFILE)
		flags |= O_LARGEFILE;
	if (p2 & LX_O_NOFOLLOW)
		flags |= O_NOFOLLOW;
	if (p2 & LX_O_CLOEXEC)
		flags |= O_CLOEXEC;

	/*
	 * Linux uses the LX_O_DIRECT flag to do raw, synchronous I/O to the
	 * device backing the fd in question.  Illumos doesn't have similar
	 * functionality, but we can attempt to simulate it using the flags
	 * (O_RSYNC|O_SYNC) and directio(3C).
	 *
	 * The LX_O_DIRECT flag also requires that the transfer size and
	 * alignment of I/O buffers be a multiple of the logical block size for
	 * the underlying file system, but frankly there isn't an easy way to
	 * support that functionality without doing something like adding an
	 * fcntl(2) flag to denote LX_O_DIRECT mode.
	 *
	 * Since LX_O_DIRECT is merely a performance advisory, we'll just
	 * emulate what we can and trust that the only applications expecting
	 * an error when performing I/O from a misaligned buffer or when
	 * passing a transfer size is not a multiple of the underlying file
	 * system block size will be test suites.
	 */
	if (p2 & LX_O_DIRECT)
		flags |= (O_RSYNC|O_SYNC);

	return (flags);
}

static int
lx_open_postprocess(int fd, int fmode)
{
	if (fmode & LX_O_DIRECT) {
		(void) ioctl(fd, _FIODIRECTIO, DIRECTIO_ON);
	}

	/*
	 * Set the ASYNC flag if passsed.
	 */
	if (fmode & LX_O_ASYNC) {
		int res;

		if ((res = fcntl(fd, F_SETFL, FASYNC)) != 0) {
			(void) close(fd);
			return (res);
		}
	}

	return (fd);
}

long
lx_openat(int atfd, char *path, int fmode, int cmode)
{
	int flags, fd;
	mode_t mode = 0;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flags = ltos_open_flags(fmode);

	/*
	 * We use the FSEARCH flag to make sure this is a directory. We have to
	 * explicitly add 1 to emulate the FREAD/FWRITE mapping of the OPENMODE
	 * macro since it won't get set via OPENMODE when FSEARCH is used.
	 */
	if (fmode & LX_O_DIRECTORY) {
		flags |= FSEARCH;
		flags++;
	}

	if (flags & O_CREAT)
		mode = (mode_t)cmode;

	ttolwp(curthread)->lwp_errno = 0;
	fd = openat(atfd, path, flags, mode);
	if (ttolwp(curthread)->lwp_errno != 0) {
		if ((fmode & LX_O_DIRECTORY) &&
		    ttolwp(curthread)->lwp_errno != ENOTDIR) {
			/*
			 * We got an error trying to open a file as a directory.
			 * We need to determine if we should return the original
			 * error or ENOTDIR.
			 */
			vnode_t *startvp;
			vnode_t *vp;
			int oerror, error = 0;

			oerror = ttolwp(curthread)->lwp_errno;

			if (atfd == AT_FDCWD) {
				/* regular open */
				startvp = NULL;
			} else {
				char startchar;

				if (copyin(path, &startchar, sizeof (char)))
					return (set_errno(oerror));

				/* if startchar is / then startfd is ignored */
				if (startchar == '/') {
					startvp = NULL;
				} else {
					file_t *startfp;

					if ((startfp = getf(atfd)) == NULL)
						return (set_errno(oerror));
					startvp = startfp->f_vnode;
					VN_HOLD(startvp);
					releasef(atfd);
				}
			}

			if (lookupnameat(path, UIO_USERSPACE,
			    (fmode & LX_O_NOFOLLOW) ?  NO_FOLLOW : FOLLOW,
			    NULLVPP, &vp, startvp) != 0) {
				if (startvp != NULL)
					VN_RELE(startvp);
				return (set_errno(oerror));
			}

			if (startvp != NULL)
				VN_RELE(startvp);

			if (vp->v_type != VDIR)
				error = ENOTDIR;

			VN_RELE(vp);
			if (error != 0)
				return (set_errno(ENOTDIR));

			set_errno(oerror);
		}
		return (ttolwp(curthread)->lwp_errno);
	}

	return (lx_open_postprocess(fd, fmode));
}

long
lx_open(char *path, int fmode, int cmode)
{
	return (lx_openat(LX_AT_FDCWD, path, fmode, cmode));
}

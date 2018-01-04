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
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inttypes.h>
#include <sys/mutex.h>

#include <sys/lx_types.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>
#include <sys/brand.h>

extern int fcntl(int, int, intptr_t);
extern int openat(int, char *, int, int);
extern int open(char *, int, int);
extern int close(int);
extern int cioctl(file_t *, int, intptr_t, int *);
extern int lookupnameat(char *, enum uio_seg, int, vnode_t **, vnode_t **,
    vnode_t *);


static int
ltos_open_flags(int input)
{
	int flags;

	if (input & LX_O_PATH) {
		input &= (LX_O_DIRECTORY | LX_O_NOFOLLOW | LX_O_CLOEXEC);
	}

	/* This depends on the Linux ACCMODE flags being the same as SunOS. */
	flags = (input & LX_O_ACCMODE);

	if (input & LX_O_CREAT) {
		flags |= O_CREAT;
	}

	if (input & LX_O_EXCL)
		flags |= O_EXCL;
	if (input & LX_O_NOCTTY)
		flags |= O_NOCTTY;
	if (input & LX_O_TRUNC)
		flags |= O_TRUNC;
	if (input & LX_O_APPEND)
		flags |= O_APPEND;
	if (input & LX_O_NONBLOCK)
		flags |= O_NONBLOCK;
	if (input & LX_O_SYNC)
		flags |= O_SYNC;
	if (input & LX_O_LARGEFILE)
		flags |= O_LARGEFILE;
	if (input & LX_O_NOFOLLOW)
		flags |= O_NOFOLLOW;
	if (input & LX_O_CLOEXEC)
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
	if (input & LX_O_DIRECT)
		flags |= (O_RSYNC|O_SYNC);

	return (flags);
}

#define	LX_POSTPROCESS_OPTS	(LX_O_DIRECT | LX_O_ASYNC | LX_O_PATH)

static int
lx_open_postprocess(int fd, int fmode)
{
	file_t *fp;
	int rv, error = 0;

	if ((fmode & LX_POSTPROCESS_OPTS) == 0) {
		/* Skip out early, if possible */
		return (0);
	}

	if ((fp = getf(fd)) == NULL) {
		/*
		 * It is possible that this fd was closed by the time we
		 * arrived here if some one is hammering away with close().
		 */
		return (EIO);
	}

	if (fmode & LX_O_DIRECT && error == 0) {
		(void) VOP_IOCTL(fp->f_vnode, _FIODIRECTIO, DIRECTIO_ON,
		    fp->f_flag, fp->f_cred, &rv, NULL);
	}

	if (fmode & LX_O_ASYNC && error == 0) {
		if ((error = VOP_SETFL(fp->f_vnode, fp->f_flag, FASYNC,
		    fp->f_cred, NULL)) == 0) {
			mutex_enter(&fp->f_tlock);
			fp->f_flag |= FASYNC;
			mutex_exit(&fp->f_tlock);
		}
	}

	if (fmode & LX_O_PATH && error == 0) {
		/*
		 * While the O_PATH flag has no direct analog in SunOS, it is
		 * emulated by removing both FREAD and FWRITE from f_flag.
		 * This causes read(2) and write(2) result in EBADF and can be
		 * checked for in other syscalls to tigger the correct behavior
		 * there.
		 */
		mutex_enter(&fp->f_tlock);
		fp->f_flag &= ~(FREAD|FWRITE);
		mutex_exit(&fp->f_tlock);
	}

	releasef(fd);
	if (error != 0) {
		(void) closeandsetf(fd, NULL);
	}
	return (error);
}

long
lx_openat(int atfd, char *path, int fmode, int cmode)
{
	int flags, fd, error;
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

			(void) set_errno(oerror);
		}

		if (ttolwp(curthread)->lwp_errno == EINTR)
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;

		return (ttolwp(curthread)->lwp_errno);
	}

	if ((error = lx_open_postprocess(fd, fmode)) != 0) {
		return (set_errno(error));
	}
	return (fd);
}

long
lx_open(char *path, int fmode, int cmode)
{
	return (lx_openat(LX_AT_FDCWD, path, fmode, cmode));
}

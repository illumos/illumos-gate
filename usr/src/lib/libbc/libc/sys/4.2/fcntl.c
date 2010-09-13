/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1990-1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/ioccom.h>
#include <sys/syscall.h>


/* The following is an array of fcntl commands. The numbers listed
 * below are from SVR4. Array is indexed with SunOS 4.1 numbers to
 * obtain the SVR4 numbers.
 */
int cmd_op[14] = {0, 1, 2, 3, 4, 23, 24, 14, 6, 7, 21, 20, -1, 22};

/* SVR4/SunOS 5.0 equivalent modes */
#define N_O_NDELAY      0x04
#define N_O_SYNC	0x10
#define N_O_NONBLOCK    0x80
#define N_O_CREAT       0x100
#define N_O_TRUNC       0x200
#define N_O_EXCL	0x400

#define	S5_FASYNC 0x1000

/* from SVR4 stropts.h */
#define	S5_S_RDNORM		0x0040
#define	S5_S_WRNORM		0x0004
#define	S5_S_RDBAND		0x0080
#define	S5_S_BANDURG		0x0200
#define	S5_I_SETSIG		(('S'<<8)|011)
#define	S5_I_GETSIG		(('S'<<8)|012)

/* Mask corresponding to the bits above in SunOS 4.x */
#define FLAGS_MASK      (O_SYNC|O_NONBLOCK|O_CREAT|O_TRUNC|O_EXCL \
			|O_NDELAY|FNBIO|FASYNC)
#define N_FLAGS_MASK    (N_O_NDELAY|N_O_SYNC|N_O_NONBLOCK|N_O_CREAT \
			|N_O_TRUNC|N_O_EXCL|S5_FASYNC)

struct n_flock {
	short	l_type;
	short	l_whence;
	long	l_start;
	long	l_len;	  /* len == 0 means until end of file */
	long	l_sysid;
	long	l_pid;
	long	pad[4];	 /* reserve area */
} ;


int fcntl(fd, cmd, arg)
int fd, cmd, arg;
{
	return(bc_fcntl(fd, cmd, arg));
}


int bc_fcntl(fd, cmd, arg)
int fd, cmd, arg;
{
	int fds, ret;
	struct flock *savarg;
	struct n_flock nfl;
	extern int errno;
	int i, narg;

	if ((cmd == F_SETOWN) || (cmd == F_GETOWN)) {
		ret = _s_fcntl(fd, cmd_op[cmd], arg);
		if ((ret != -1) || (errno != EINVAL))
			return (ret);
		else {
			if (cmd == F_GETOWN) {
				if (_ioctl(fd, S5_I_GETSIG, &i) < 0) {
					if (errno == EINVAL)
						i = 0;
					else
						return (-1);
				}
				if (i & (S5_S_RDBAND|S5_S_BANDURG|
				    S5_S_RDNORM|S5_S_WRNORM))
					return (getpid());
				return (0);
			} else { /* cmd == F_SETOWN */
				i = S5_S_RDNORM|S5_S_WRNORM|S5_S_RDBAND|S5_S_BANDURG;
				return (ioctl(fd, S5_I_SETSIG, i));
			}
		}
	}
	if (cmd == F_SETFL) {
		if (arg & FLAGS_MASK) {
			narg = arg & ~FLAGS_MASK;
			if (arg & FASYNC)
				narg |= S5_FASYNC;
			if (arg & O_SYNC)
				narg |= N_O_SYNC;
			if (arg & O_CREAT)
				narg |= N_O_CREAT;
			if (arg & O_TRUNC)
				narg |= N_O_TRUNC;
			if (arg & O_EXCL)
				narg |= N_O_EXCL;
			if (arg & (O_NDELAY)) 
				narg |= N_O_NDELAY;
			if (arg & O_NONBLOCK) 
				narg |= N_O_NONBLOCK;
			if (arg & FNBIO)
				narg |= N_O_NDELAY;
			arg = narg;
		}
	} else if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK)  {
		if (arg == 0 || arg == -1) {
			errno = EFAULT;
			return(-1);
		}
		savarg = (struct flock *)arg;
		arg = (int) &nfl;
		nfl.l_type = savarg->l_type;
		nfl.l_whence = savarg->l_whence;
		nfl.l_start = savarg->l_start;
		nfl.l_len = savarg->l_len;
		nfl.l_pid = savarg->l_pid;
	}			

	ret = _s_fcntl(fd, cmd_op[cmd], arg);

	if (ret != -1) {
		if (cmd == F_DUPFD) {
			if ((fds = fd_get(fd)) != -1) 
				fd_add(ret, fds);
		} else if (cmd == F_GETFL) {
			if (ret & N_FLAGS_MASK) {
				narg = ret & ~N_FLAGS_MASK;
				if (ret & S5_FASYNC)
					narg |= FASYNC;
				if (ret & N_O_SYNC)
					narg |= O_SYNC;
				if (ret & N_O_NONBLOCK)
					narg |= O_NONBLOCK;
				if (ret & N_O_CREAT)
					narg |= O_CREAT;
				if (ret & N_O_TRUNC)
					narg |= O_TRUNC;
				if (ret & N_O_EXCL)
					narg |= O_EXCL;
				if (ret & (N_O_NDELAY))
					narg |= O_NDELAY;
				ret = narg;
			}
		} else if (cmd == F_SETLK || cmd == F_SETLKW ||
			cmd == F_GETLK) {
			savarg->l_type = nfl.l_type;
			savarg->l_whence = nfl.l_whence;
			savarg->l_start = nfl.l_start;
			savarg->l_len = nfl.l_len;
			savarg->l_pid = nfl.l_pid;
			arg = (int) savarg;
		}
	}
	return(ret);
}	

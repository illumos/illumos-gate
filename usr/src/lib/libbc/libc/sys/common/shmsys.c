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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from S5R2 1.3 */

#include	<syscall.h>
#include	<varargs.h>
#include	<sys/types.h>
#include	<sys/ipc.h>
#include	<sys/shm.h>
#include	<sys/errno.h>


/* shmsys dispatch argument */
#define	SHMAT	0
#define	SHMCTL	1
#define	SHMDT	2
#define SHMGET	3

struct shmid_sv {
	struct ipc_perm shm_perm;
	int		shm_segsz;
	struct anon_map	*shm_amp;
	unsigned short	shm_lkcnt;
	char		pad[2];
	short		shm_lpid;
	short		shm_cpid;
	unsigned short	shm_nattch;
	unsigned short	shm_cnattch;
	time_t		shm_atime;
	time_t		shm_dtime;
	time_t		shm_ctime;
};
	

char *
shmat(shmid, shmaddr, shmflg)
	int shmid;
	char *shmaddr;
	int shmflg;
{
	return ((char *)_syscall(SYS_shmsys, SHMAT, shmid, shmaddr, shmflg));
}

shmctl(shmid, cmd, buf)
	int shmid, cmd;
	struct shmid_ds *buf;
{
	struct shmid_sv n_buf;
	int ret;
	extern int errno;

	if (buf == (struct shmid_ds *)-1) {
		errno = EFAULT;
		return(-1);
	}

	if (buf == 0) {
		ret = _syscall(SYS_shmsys, SHMCTL, shmid, cmd, 0);
	} else {
		n_buf.shm_perm = buf->shm_perm;
		n_buf.shm_segsz = buf->shm_segsz;
		n_buf.shm_amp = buf->shm_amp;
		n_buf.shm_lpid = buf->shm_lpid;
		n_buf.shm_cpid = buf->shm_cpid;
		n_buf.shm_nattch = buf->shm_nattch;
		n_buf.shm_atime = buf->shm_atime;
		n_buf.shm_dtime = buf->shm_dtime;
		n_buf.shm_ctime = buf->shm_ctime;
		n_buf.shm_lkcnt = 0;
		n_buf.shm_cnattch = 0;

		ret = _syscall(SYS_shmsys, SHMCTL, shmid, cmd, &n_buf);

		buf->shm_perm = n_buf.shm_perm;
		buf->shm_segsz = n_buf.shm_segsz;
		buf->shm_amp = n_buf.shm_amp;
		buf->shm_lpid = n_buf.shm_lpid;
		buf->shm_cpid = n_buf.shm_cpid;
		buf->shm_nattch = n_buf.shm_nattch;
		buf->shm_atime = n_buf.shm_atime;
		buf->shm_dtime = n_buf.shm_dtime;
		buf->shm_ctime = n_buf.shm_ctime;
	}

	return(ret);
}

shmdt(shmaddr)
	char *shmaddr;
{

	return (_syscall(SYS_shmsys, SHMDT, shmaddr));
}

shmget(key, size, shmflg)
	key_t key;
	int size, shmflg;
{
	return (_syscall(SYS_shmsys, SHMGET, key, size, shmflg));
}

shmsys(sysnum, va_alist)
int sysnum;
va_dcl
{
        va_list ap;
	int shmid, shmflg, cmd, size;
	char *shmaddr;
	struct shmid_ds *buf;
	key_t key;

	va_start(ap);
	switch (sysnum) {
	case SHMAT:
			shmid=va_arg(ap, int);
			shmaddr=va_arg(ap, char *);
			shmflg=va_arg(ap, int);
			return((int)shmat(shmid, shmaddr, shmflg));
	case SHMCTL:
			shmid=va_arg(ap, int);
			cmd=va_arg(ap, int);
			buf=va_arg(ap, struct shmid_ds *);
			return(shmctl(shmid, cmd, buf));
	case SHMDT:
			shmaddr=va_arg(ap, char *);
			return(shmdt(shmaddr));
	case SHMGET:
			key=va_arg(ap, key_t);
			size=va_arg(ap, int);
			shmflg=va_arg(ap, int);
			return(shmget(key, size, shmflg));
	}
}

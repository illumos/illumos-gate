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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "../common/compat.h"
#include <stdio.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * If writing to a utmp-like file, map the utmp structure to
 * new format on the fly.
 */
extern int errno;

extern int conv2utmp(char *, char *, int);
extern int conv2utmpx(char *, char *, int);

int
write(int fd, char *buf, int size)
{
	return (bc_write(fd, buf, size));
}

int
bc_write(int fd, char *buf, int size)
{
	int ret, off;
	int nsize;
	char *nbuf;
	
	if (fd_get(fd) != -1) { /* writing utmp (utmpx actually) */
		nsize = getmodsize(size, sizeof (struct compat_utmp), 
		    sizeof (struct utmpx));

		if ((nbuf = (void *)malloc(nsize)) == NULL) {
			(void) fprintf(stderr, "write: malloc failed\n");
			exit(-1);
		}
		
		(void) memset(nbuf, 0, nsize);

		ret = conv2utmpx(nbuf, buf, size);

		if ((ret = _write(fd, nbuf, ret)) == -1) {
			if (errno == EAGAIN)
				errno = EWOULDBLOCK;
			free(nbuf);
			return (-1);
		}

		free(nbuf);
	
		ret = getmodsize(ret, sizeof (struct utmpx), 
		    sizeof (struct compat_utmp));

		return (ret);
	}

	if ((ret = _write(fd, buf, size)) == -1) {
		if (errno == EAGAIN)
			errno = EWOULDBLOCK;
	}
	return (ret);
	
}

/* From SunOS/SVR4 utmp.h */
#define	USER_PROCESS 7
#define	DEAD_PROCESS 8

extern int
conv2utmpx(char *nbuf, char *buf, int len)
{
	struct compat_utmp *ut;
	struct utmpx *utx;

	utx = (struct utmpx *) nbuf;
	ut  = (struct compat_utmp  *) buf;

	while ((char *)ut < (buf + len)) {
                (void) strcpy(utx->ut_user, ut->ut_name);
		(void) memset(utx->ut_id, 0, sizeof (utx->ut_id));
		(void) strcpy(utx->ut_line, ut->ut_line);
		utx->ut_pid = 0;
		if ((strcmp(utx->ut_user, "") == 0) && 
		    (strcmp(utx->ut_host, "") == 0))
			utx->ut_type = DEAD_PROCESS;
		else
			utx->ut_type = USER_PROCESS;	
		utx->ut_exit.e_termination = 0;
		utx->ut_exit.e_exit = 0;
		utx->ut_tv.tv_sec = ut->ut_time;
		utx->ut_tv.tv_usec = 0;
		utx->ut_session = 0;
		utx->ut_syslen = sizeof (ut->ut_name) + 1;
		(void) strcpy(utx->ut_host, ut->ut_host);
		ut++;
		utx++;	
	}
	return ((char *) utx - nbuf);
}

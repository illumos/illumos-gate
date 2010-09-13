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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _run_setkey = run_setkey
#pragma weak _run_crypt = run_crypt
#pragma weak _crypt_close = crypt_close
#pragma weak _makekey = makekey

#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <thread.h>
#include <sys/types.h>
#include <unistd.h>
#include <strings.h>
#include <crypt.h>
#include "des_soft.h"
#include "lib_gen.h"

#define	READER	0
#define	WRITER	1
#define	KSIZE 	8

/*  Global Variables  */
static char key[KSIZE+1];
struct header {
	long offset;
	unsigned int count;
};

static mutex_t lock = DEFAULTMUTEX;

static int cryptopen();
static int writekey();

void	_exit();

int
run_setkey(int p[2], const char *keyparam)
{
	(void) mutex_lock(&lock);
	if (cryptopen(p) == -1) {
		(void) mutex_unlock(&lock);
		return (-1);
	}
	(void)  strncpy(key, keyparam, KSIZE);
	if (*key == 0) {
		(void) crypt_close_nolock(p);
		(void) mutex_unlock(&lock);
		return (0);
	}
	if (writekey(p, key) == -1) {
		(void) mutex_unlock(&lock);
		return (-1);
	}
	(void) mutex_unlock(&lock);
	return (1);
}

static char cmd[] = "exec /usr/bin/crypt -p 2>/dev/null";
static int
cryptopen(int p[2])
{
	char c;

	if (__p2open(cmd, p) < 0)
		return (-1);
	if (read(p[WRITER], &c, 1) != 1) { /* check that crypt is working on */
					    /* other end */
		(void)  crypt_close(p); /* remove defunct process */
		return (-1);
	}
	return (1);
}

static int
writekey(int p[2], char *keyarg)
{
	void (*pstat) ();
	pstat = signal(SIGPIPE, SIG_IGN); /* don't want pipe errors to cause */
					    /*  death */
	if (write(p[READER], keyarg, KSIZE) != KSIZE) {
		(void)  crypt_close(p); /* remove defunct process */
		(void)  signal(SIGPIPE, pstat);
		return (-1);
	}
	(void)  signal(SIGPIPE, pstat);
	return (1);
}


int
run_crypt(long offset, char *buffer, unsigned int count, int p[2])
{
	struct header header;
	void (*pstat) ();

	(void) mutex_lock(&lock);
	header.count = count;
	header.offset = offset;
	pstat = signal(SIGPIPE, SIG_IGN);
	if (write(p[READER], (char *)&header, sizeof (header))
	    != sizeof (header)) {
		(void) crypt_close_nolock(p);
		(void) signal(SIGPIPE, pstat);
		(void) mutex_unlock(&lock);
		return (-1);
	}
	if (write(p[READER], buffer, count) < count) {
		(void) crypt_close_nolock(p);
		(void) signal(SIGPIPE, pstat);
		(void) mutex_unlock(&lock);
		return (-1);
	}
	if (read(p[WRITER], buffer,  count) < count) {
		(void) crypt_close_nolock(p);
		(void) signal(SIGPIPE, pstat);
		(void) mutex_unlock(&lock);
		return (-1);
	}
	(void) signal(SIGPIPE, pstat);
	(void) mutex_unlock(&lock);
	return (0);
}

int
makekey(int b[2])
{
	int i;
	long gorp;
	char tempbuf[KSIZE], *a, *temp;

	(void) mutex_lock(&lock);
	a = key;
	temp = tempbuf;
	for (i = 0; i < KSIZE; i++)
		temp[i] = *a++;
	gorp = getuid() + getgid();

	for (i = 0; i < 4; i++)
		temp[i] ^= (char)((gorp>>(8*i))&0377);

	if (cryptopen(b) == -1) {
		(void) mutex_unlock(&lock);
		return (-1);
	}
	if (writekey(b, temp) == -1) {
		(void) mutex_unlock(&lock);
		return (-1);
	}
	(void) mutex_unlock(&lock);
	return (0);
}

int
crypt_close_nolock(int p[2])
{

	if (p[0] == 0 && p[1] == 0 || p[0] < 0 || p[1] < 0) {
		return (-1);
	}

	return (__p2close(p, NULL, SIGKILL));
}

int
crypt_close(int p[2])
{
	(void) mutex_lock(&lock);
	(void) crypt_close_nolock(p);
	(void) mutex_unlock(&lock);
	return (0);
}

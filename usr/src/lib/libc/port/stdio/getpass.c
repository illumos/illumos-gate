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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#pragma weak _getpass = getpass
#pragma weak _getpassphrase = getpassphrase

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stropts.h>
#include <termio.h>
#include <thread.h>
#include <synch.h>
#include "libc.h"
#include "stdiom.h"
#include "tsd.h"

static int intrupt;
static char *__getpass(const char *, int);

#define	MAXPASSWD	256	/* max significant characters in password */
#define	SMLPASSWD	8	/* unix standard  characters in password */


char *
getpass(const char *prompt)
{
	return ((char *)__getpass(prompt, SMLPASSWD));
}

char *
getpassphrase(const char *prompt)
{
	return ((char *)__getpass(prompt, MAXPASSWD));
}

	static void catch(int);

static char *
__getpass(const char *prompt, int size)
{
	struct termio ttyb;
	unsigned short flags;
	char *p;
	int c;
	FILE	*fi;
	char *pbuf = tsdalloc(_T_GETPASS, MAXPASSWD + 1, NULL);
	struct sigaction act, osigint, osigtstp;

	if (pbuf == NULL ||
	    (fi = fopen("/dev/tty", "r+F")) == NULL)
		return (NULL);
	setbuf(fi, NULL);

	intrupt = 0;
	act.sa_flags = 0;
	act.sa_handler = catch;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGINT, &act, &osigint);	/* trap interrupt */
	act.sa_handler = SIG_IGN;
	(void) sigaction(SIGTSTP, &act, &osigtstp);	/* ignore stop */
	(void) ioctl(fileno(fi), TCGETA, &ttyb);
	flags = ttyb.c_lflag;
	ttyb.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	(void) ioctl(fileno(fi), TCSETAF, &ttyb);

	(void) fputs(prompt, fi);
	p = pbuf;
	while (!intrupt &&
	    (c = GETC(fi)) != '\n' && c != '\r' && c != EOF) {
		if (p < &pbuf[ size ])
			*p++ = (char)c;
	}
	*p = '\0';
	(void) PUTC('\n', fi);

	ttyb.c_lflag = flags;
	(void) ioctl(fileno(fi), TCSETAW, &ttyb);
	(void) sigaction(SIGINT, &osigint, NULL);
	(void) sigaction(SIGTSTP, &osigtstp, NULL);
	(void) fclose(fi);
	if (intrupt) {		/* if interrupted erase the input */
		pbuf[0] = '\0';
		(void) kill(getpid(), SIGINT);
	}
	return (pbuf);
}

static void
catch(int x __unused)
{
	intrupt = 1;
}

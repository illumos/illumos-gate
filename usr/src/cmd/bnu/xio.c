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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

#ifdef X_PROTOCOL

#define XBUFSIZ 512
static jmp_buf Xfailbuf;
extern int xrdblk();
extern unsigned msgtime;

/*
 * x.25 protocol
 */
/* ARGSUSED */
static void
xalarm(sig)
int sig;
{
	longjmp(Xfailbuf, 1);
}

static void (*xsig)();

/*
 * turn on protocol timer
 */
int
xturnon()
{
	xsig=signal(SIGALRM, xalarm);
	return(0);
}

int
xturnoff()
{
	(void) signal(SIGALRM, xsig);
	return(0);
}

/*
 * write message across x.25 link
 *	type	-> message type
 *	str	-> message body (ascii string)
 *	fn	-> x.25 file descriptor
 * return
 *	0
 */
int
xwrmsg(type, str, fn)
char *str;
int fn;
char type;
{
	char *s;
	char bufr[XBUFSIZ];

	bufr[0] = type;
	s = &bufr[1];
	while (*str)
		*s++ = *str++;
	*s = '\0';
	if (*(--s) == '\n')
		*s = '\0';
	(void) (*Write)(fn, bufr, strlen(bufr) + 1);
	return(0);
}

/*
 * read message from x.25 link
 *	str	-> message buffer
 *	fn	-> x.25 file descriptor
 * return
 *	FAIL	-> send timed out
 *	0	-> ok message in str
 */
int
xrdmsg(char *str, int fn)
{
	int len;

	if(setjmp(Xfailbuf))
		return(FAIL);

	(void) alarm(msgtime);
	for (;;) {
		if( (len = (*Read)(fn, str, XBUFSIZ)) == 0)
			continue;
		if (len < 0) {
			(void) alarm(0);
			return(FAIL);
		}
		str += len;
		if (*(str - 1) == '\0')
			break;
	}
	(void) alarm(0);
	return(0);
}

/*
 * read data from file fp1 and write
 * on x.25 link
 *	fp1	-> file descriptor
 *	fn	-> x.25 descriptor
 * returns:
 *	FAIL	->failure in x.25 link
 *	0	-> ok
 */
int
xwrdata(FILE *fp1, int fn)
{
	int fd1;
	int len, ret;
	unsigned long bytes;
	char bufr[XBUFSIZ];

	bytes = 0L;
	fd1 = fileno( fp1 );
	while ((len = read( fd1, bufr, XBUFSIZ )) > 0) {
		bytes += len;
		putfilesize(bytes);
		ret = (*Write)(fn, bufr, len);
		if (ret != len) {
			return(FAIL);
		}
		if (len != XBUFSIZ)
			break;
	}
	ret = (*Write)(fn, bufr, 0);
	return(0);
}

/*
 * read data from x.25 link and
 * write into file
 *	fp2	-> file descriptor
 *	fn	-> x.25 descriptor
 * returns:
 *	0	-> ok
 *	FAIL	-> failure on x.25 link
 */
int
xrddata(int fn, FILE *fp2)
{
	int fd2;
	int len;
	int ret = SUCCESS;
	unsigned long bytes;
	char bufr[XBUFSIZ];

	bytes = 0L;
	fd2 = fileno( fp2 );
	for (;;) {
		len = xrdblk(bufr, XBUFSIZ, fn);
		if (len < 0) {
			return(FAIL);
		}
		bytes += len;
		putfilesize(bytes);
		if( ret == SUCCESS && write( fd2, bufr, len ) != len )
			ret = errno;
		if (len < XBUFSIZ)
			break;
	}
	return(ret);
}

/*
 * read blank from x.25 link
 * reads are timed
 *	blk	-> address of buffer
 *	len	-> size to read
 *	fn	-> x.25 descriptor
 * returns:
 *	FAIL	-> link error timeout on link
 *	i	-> # of bytes read
 */
int
xrdblk(char *blk, int len, int fn)
{
	int i, ret;

	if(setjmp(Xfailbuf))
		return(FAIL);

	(void) alarm(msgtime);
	for (i = 0; i < len; i += ret) {
		if ((ret = (*Read)(fn, blk, len - i)) < 0) {
			(void) alarm(0);
			return(FAIL);
		}
		blk += ret;
		if (ret == 0)
			break;
	}
	(void) alarm(0);
	return(i);
}
#endif /* X_PROTOCOL */

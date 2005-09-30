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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

#ifdef D_PROTOCOL
#include <dk.h>

#define XBUFSIZ 1024
time_t time();
static jmp_buf Dfailbuf;
extern int drdblk();

/*
 * Datakit protocol
 */
/* ARGSUSED */
static void
dalarm(sig)
int sig;
{
	longjmp(Dfailbuf,1);
}

static void (*dsig)();
#ifndef V8
static short dkrmode[3] = { DKR_BLOCK, 0, 0 };
static short dkeof[3] = { 106, 0, 0 };	/* End of File signal */
#endif

/*
 * turn on protocol
 */
int
dturnon()
{
#ifdef V8
	extern int dkp_ld;
#endif

	dsig=signal(SIGALRM, dalarm);
#ifdef V8
	if (dkproto(Ofn, dkp_ld) < 0)
	   {
		DEBUG(3, "%s\n", "No dkp_ld");
		return(-1);
	   }
#else
	if((*Ioctl)(Ofn, DIOCRMODE, dkrmode) < 0) {
	    int ret;
	    ret=(*Ioctl)(Ofn, DIOCRMODE, dkrmode);
	    DEBUG(4, "dturnon: ret=%d, ", ret);
	    DEBUG(4, "Ofn=%d, ", Ofn);
	    DEBUG(4, "errno=%d\n", errno);
	    return(-1);
	}
#endif /* V8 */
	return(0);
}

int
dturnoff()
{
	(void) signal(SIGALRM, dsig);
	return(0);
}

/*
 * write message across Datakit link
 *	type	-> message type
 *	str	-> message body (ascii string)
 *	fn	-> Datakit file descriptor
 * return
 *	SUCCESS	-> message sent
 *	FAIL	-> write failed
 */
int
dwrmsg(type, str, fn)
register char *str;
int fn;
char type;
{
	register char *s;
	char bufr[XBUFSIZ];

	bufr[0] = type;
	s = &bufr[1];
	while (*str)
		*s++ = *str++;
	*s = '\0';
	if (*(--s) == '\n')
		*s = '\0';
	return((*Write)(fn, bufr, (unsigned) strlen(bufr) + 1) < 0 ? FAIL : SUCCESS);
}

/*
 * read message from Datakit link
 *	str	-> message buffer
 *	fn	-> Datakit file descriptor
 * return
 *	FAIL	-> send timed out
 *	SUCCESS	-> ok message in str
 */
int
drdmsg(str, fn)
register char *str;
{

	register int len;

	if(setjmp(Dfailbuf))
		return(FAIL);

	(void) alarm(60);
	for (;;) {
		if( (len = (*Read)(fn, str, XBUFSIZ)) <= 0) {
			(void) alarm(0);
			return(FAIL);
		}
		str += len;
		if (*(str - 1) == '\0')
			break;
	}
	(void) alarm(0);
	return(SUCCESS);
}

/*
 * read data from file fp1 and write
 * on Datakit link
 *	fp1	-> file descriptor
 *	fn	-> Datakit descriptor
 * returns:
 *	FAIL	->failure in Datakit link
 *	SUCCESS	-> ok
 */
int
dwrdata(fp1, fn)
FILE *fp1;
{
	register int fd1;
	register int len, ret;
	unsigned long bytes;
	char bufr[XBUFSIZ];

	bytes = 0L;
	fd1 = fileno( fp1 );
	while ((len = read( fd1, bufr, XBUFSIZ )) > 0) {
		bytes += len;
		putfilesize(bytes);
		ret = (*Write)(fn, bufr, (unsigned) len);
		if (ret != len) {
			return(FAIL);
		}
		if (len != XBUFSIZ)
			break;
	}
	ASSERT(len >= 0, "DISK READ ERROR", strerror(errno), len);
#ifndef V8
	(*Ioctl)(fn, DIOCXCTL, dkeof);
#endif
	ret = (*Write)(fn, bufr, (unsigned) 0);
	return(SUCCESS);
}

/*
 * read data from Datakit link and
 * write into file
 *	fp2	-> file descriptor
 *	fn	-> Datakit descriptor
 * returns:
 *	SUCCESS	-> ok
 *	FAIL	-> failure on Datakit link
 */
int
drddata(fn, fp2)
FILE *fp2;
{
	register int fd2;
	register int len;
	register int ret = SUCCESS;
	unsigned long bytes;
	char bufr[XBUFSIZ];

	bytes = 0L;
	fd2 = fileno( fp2 );
	for (;;) {
		len = drdblk(bufr, XBUFSIZ, fn);
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
 * read block from Datakit link
 * reads are timed
 *	blk	-> address of buffer
 *	len	-> size to read
 *	fn	-> Datakit descriptor
 * returns:
 *	FAIL	-> link error timeout on link
 *	i	-> # of bytes read
 */
int
drdblk(blk, len,  fn)
register char *blk;
{
	register int i, ret;
	struct dkqqabo	why;

	if(setjmp(Dfailbuf))
		return(FAIL);

	for (i = 0; i < len; i += ret) {
		(void) alarm(60);
		if ((ret = (*Read)(fn, blk, (unsigned) len - i)) < 0) {
			(void) alarm(0);
			return(FAIL);
		}
		blk += ret;
		if (ret == 0) {	/* zero length block contains only EOF signal */
			ioctl(fn, DIOCQQABO, &why);
			if (why.rcv_ctlchar != dkeof[0])
				i = FAIL;
			break;
		}
	}
	(void) alarm(0);
	return(i);
}
#endif /* D_PROTOCOL */

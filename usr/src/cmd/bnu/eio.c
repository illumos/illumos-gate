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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

#ifdef	E_PROTOCOL

#ifndef MIN
#define     MIN(a,b) (((a)<(b))?(a):(b))
#endif

#if defined(BSD4_2) || defined (ATTSVR4)
#include <netinet/in.h>
#endif /* BSD4_2 || ATTSVR4 */

#define	EBUFSIZ	1024
#define	EMESGLEN 20

#define TBUFSIZE 1024
#define TPACKSIZE	512

extern long lseek();	/* Find offset into the file. */
static jmp_buf Failbuf;
extern int erdblk();
extern unsigned msgtime;

static char Erdstash[EBUFSIZ];
static int Erdlen;

/*
 * error-free channel protocol
 */
/* ARGSUSED */
static void
ealarm(sig)
int sig;
{
	longjmp(Failbuf, 1);
}
static void (*esig)();

/*
 * turn on protocol timer
 */
int
eturnon()
{
	esig=signal(SIGALRM, ealarm);
	return(0);
}

int
eturnoff()
{
	signal(SIGALRM, esig);
	return(0);
}

/*
 * write message across link
 *	type	-> message type
 *	str	-> message body (ascii string)
 *	fn	-> link file descriptor
 * return
 *	FAIL	-> write failed
 *	SUCCESS	-> write succeeded
 */
int
ewrmsg(char type, char *str, int fn)
{
	return(etwrmsg(type, str, fn, 0));
}

/*
 * read message from link
 *	str	-> message buffer
 *	fn	-> file descriptor
 * return
 *	FAIL	-> read timed out
 *	SUCCESS	-> ok message in str
 */
int
erdmsg(char *str, int fn)
{
	return(etrdmsg(str, fn, 0));
}

/*
 * read data from file fp1 and write
 * on link
 *	fp1	-> file descriptor
 *	fn	-> link descriptor
 * returns:
 *	FAIL	->failure in link
 *	SUCCESS	-> ok
 */
int
ewrdata(fp1, fn)
FILE *fp1;
int	fn;
{
	int ret;
	int	fd1;
	int len;
	unsigned long bytes;
	char bufr[EBUFSIZ];
	struct stat	statbuf;
	off_t	msglen;
	char	cmsglen[EMESGLEN];
	off_t	startPoint;	/* Offset from begining of the file in
				 *   case we are restarting from a check
				 *   point.
				 */

	if (setjmp(Failbuf)) {
		DEBUG(7, "ewrdata failed\n%s", "");
		return(FAIL);
	}
	bytes = 0L;
	fd1 = fileno(fp1);
	fstat(fd1, &statbuf);
	startPoint = lseek(fd1, 0L, 1);
	if (startPoint < 0)
	{
		DEBUG(7, "ewrdata lseek failed.  Errno=%d\n", errno);
		return(FAIL);
	}
	msglen = statbuf.st_size - startPoint;
	if (msglen < 0)
	{
		DEBUG(7, "ewrdata: startPoint past end of file.\n%s", "");
		return(FAIL);
	}
	sprintf(cmsglen, "%ld", (long) msglen);
	DEBUG(9, "ewrdata writing %d ...", sizeof(cmsglen));
	alarm(msgtime);
	ret = (*Write)(fn, cmsglen, sizeof(cmsglen));
	alarm(0);
	DEBUG(9, "ret %d\n", ret);
	if (ret != sizeof(cmsglen))
		return(FAIL);
	DEBUG(7, "ewrdata planning to send %ld bytes to remote.\n", msglen);
	while ((len = read( fd1, bufr, EBUFSIZ )) > 0) {
		DEBUG(9, "ewrdata writing %d ...", len);
		alarm(msgtime);
		bytes += len;
		putfilesize(bytes);
		ret = (*Write)(fn, bufr, (unsigned) len);
		alarm(0);
		DEBUG(9, "ewrdata ret %d\n", ret);
		if (ret != len)
			return(FAIL);
		if ((msglen -= len) <= 0)
			break;
	}
	if (len < 0 || (len == 0 && msglen != 0)) return(FAIL);
	return(SUCCESS);
}

/*
 * read data from link and
 * write into file
 *	fp2	-> file descriptor
 *	fn	-> link descriptor
 * returns:
 *	SUCCESS	-> ok
 *	FAIL	-> failure on link
 */
int
erddata(int fn, FILE *fp2)
{
	int ret;
	int	fd2;
	char bufr[EBUFSIZ];
	int	len;
	long	msglen, bytes;
	char	cmsglen[EMESGLEN], *cptr, *erdptr = Erdstash;

	DEBUG(9, "erddata wants %d\n", sizeof(cmsglen));
	if (Erdlen > 0) {
		DEBUG(9, "%d bytes stashed\n", Erdlen);
		if (Erdlen >= sizeof(cmsglen)) {
			memcpy(cmsglen, erdptr, sizeof(cmsglen));
			Erdlen -= sizeof(cmsglen);
			erdptr += sizeof(cmsglen);
			ret = len = 0;
		} else {
			memcpy(cmsglen, Erdstash, Erdlen);
			cptr = cmsglen + Erdlen;
			len = sizeof(cmsglen) - Erdlen;
			ret = erdblk(cptr, len, fn);
			Erdlen = 0;
		}
	} else {
		len = sizeof(cmsglen);
		ret = erdblk(cmsglen, sizeof(cmsglen), fn);
	}
	if (ret != len)
		return(FAIL);
	ret = SUCCESS;
	sscanf(cmsglen, "%ld", &msglen);
	if ( ((msglen-1)/512 +1) > Ulimit )
		ret = EFBIG;
	DEBUG(7, "erddata file is %ld bytes\n", msglen);
	fd2 = fileno( fp2 );

	if (Erdlen > 0) {
		DEBUG(9, "%d bytes stashed\n", Erdlen);
		if (write(fileno(fp2), erdptr, Erdlen) != Erdlen)
			return(FAIL);
		msglen -= Erdlen;
		Erdlen = 0;
		DEBUG(7, "erddata remainder is %ld bytes\n", msglen);
	}

	for (;;) {
		len = erdblk(bufr, (int) MIN(msglen, EBUFSIZ), fn);
		DEBUG(9, "erdblk ret %d\n", len);
		if (len < 0) {
			DEBUG(7, "erdblk failed\n%s", "");
			return(FAIL);
		}

		/*
		 * handle the case for remote socket close.
		 */
		if (len == 0) {
			ret = errno;
			DEBUG(7, "erddata: remote socket closed, errno %d\n",
				    ret);
			break;
		}
		bytes += len;
		putfilesize(bytes);
		if ((msglen -= len) < 0) {
			DEBUG(7, "erdblk read too much\n%s", "");
			return(FAIL);
		}
		/* this write is to file -- use write(2), not (*Write) */
		if ( ret == SUCCESS && write( fd2, bufr, len ) != len ) {
			ret = errno;
			DEBUG(7, "erddata: write to file failed, errno %d\n", ret);
		}
		if (msglen == 0)
			break;
	}
	return(ret);
}

/*
 * read block from link
 * reads are timed
 *	blk	-> address of buffer
 *	len	-> size to read
 *	fn	-> link descriptor
 * returns:
 *	FAIL	-> link error timeout on link
 *	i	-> # of bytes read (must not be 0)
 */
int
erdblk(char *blk, int len, int fn)
{
	int i, ret;

	if(setjmp(Failbuf)) {
		DEBUG(7, "timeout (%d sec)\n", msgtime);
		return(FAIL);
	}

	alarm(msgtime);
	for (i = 0; i < len; i += ret) {
		DEBUG(9, "erdblk ask %d ", len - i);
		if ((ret = (*Read)(fn, blk, (unsigned) len - i)) < 0) {
			alarm(0);
			DEBUG(7, "erdblk read failed\n%s", "");
			return(FAIL);
		}
		DEBUG(9, "erdblk got %d\n", ret);
		if (ret == 0)
			break;
		blk += ret;
	}
	alarm(0);
	return(i);
}

struct tbuf {
	long t_nbytes;
	char t_data[TBUFSIZE];
};

/*
 * read message from link
 *	str	-> message buffer
 *	fn	-> file descriptor
 * return
 *	FAIL	-> read timed out
 *	SUCCESS	-> ok message in str
 */
int
trdmsg(char *str, int fn)
{
	return(etrdmsg(str, fn, TPACKSIZE));
}

/*
 * write message across link
 *	type	-> message type
 *	str	-> message body (ascii string)
 *	fn	-> link file descriptor
 * return
 *	FAIL	-> write failed
 *	SUCCESS	-> write succeeded
 */
int
twrmsg(char type, char *str, int fn)
{
	return(etwrmsg(type, str, fn, TPACKSIZE));
}

/*
 * read data from file fp1 and write on link
 *	fp1	-> file descriptor
 *	fn	-> link descriptor
 * returns:
 *	FAIL	->failure in link
 *	SUCCESS	-> ok
 */
int
twrdata(fp1, fn)
FILE *fp1;
int	fn;
{
	int ret;
	int len;
	unsigned long bytes;
	struct tbuf bufr;
	struct stat statbuf;

	if (setjmp(Failbuf)) {
		DEBUG(7, "twrdata failed\n", 0);
		return(FAIL);
	}
	fstat(fileno(fp1), &statbuf);
	bytes = 0L;
	while ((len = read(fileno(fp1), bufr.t_data, TBUFSIZE)) > 0) {
		bufr.t_nbytes = htonl((long)len);
		DEBUG(7, "twrdata writing %d ...", len);
		bytes += len;
		putfilesize(bytes);
		len += sizeof(long);
		alarm(msgtime);
		ret = (*Write)(fn, (char *)&bufr, (unsigned) len);
		alarm(0);
		DEBUG(7, "ret %d\n", ret);
		if (ret != len)
			return(FAIL);
		if (len != TBUFSIZE+sizeof(long))
			break;
	}
	bufr.t_nbytes = 0;
	alarm(msgtime);
	ret = write(fn, (char *)&bufr, sizeof(long));
	alarm(0);
	if (ret != sizeof(long))
		return FAIL;
	return(SUCCESS);
}

/*
 * read data from link and write into file
 *	fp2	-> file descriptor
 *	fn	-> link descriptor
 * returns:
 *	SUCCESS	-> ok
 *	FAIL	-> failure on link
 */
int
trddata(int fn, FILE *fp2)
{
	int len, nread;
	long Nbytes;
	unsigned long bytes = 0L;
	char bufr[TBUFSIZE];

	for (;;) {
		len = erdblk((char *)&Nbytes, sizeof(Nbytes), fn);
		DEBUG(7, "trddata ret %d\n", len);
		if (len != sizeof(Nbytes))
			return(FAIL);
		Nbytes = ntohl(Nbytes);
		DEBUG(7,"trddata expecting %ld bytes\n", Nbytes);
		nread = Nbytes;
		if (nread == 0)
			break;
		len = erdblk(bufr, nread, fn);
		if (len != Nbytes)
			return(FAIL);
		bytes += len;
		putfilesize(bytes);
		if (write(fileno(fp2), bufr, len) != len)
			return(FAIL);
	}
	return(SUCCESS);
}

/*
 * read message from link
 *	str	-> message buffer
 *	fn	-> file descriptor
 *	i	-> if non-zero, amount to read; o.w., read up to '\0'
 * return
 *	FAIL	-> read timed out
 *	SUCCESS	-> ok message in str
 *
 * 'e' is fatally flawed -- in a byte stream world, rdmsg can pick up
 * the cmsglen on a R request.  if this happens, we stash the excess
 * where rddata can pick it up.
 */

int
etrdmsg(char *str, int fn, int i)
{
	int len;
	int nullterm = 0;
	char *null, *argstr;


	if (i == 0) {
		DEBUG(9, "etrdmsg looking for null terminator\n", 0);
		nullterm++;
		i = EBUFSIZ;
		argstr = str;
	}

	if(setjmp(Failbuf)) {
		DEBUG(7, "timeout (%d sec)\n", msgtime);
		return(FAIL);
	}

	alarm(msgtime);
	for (;;) {
		DEBUG(9, "etrdmsg want %d ...", i);
		len = (*Read)(fn, str, i);
		DEBUG(9, "got %d\n", len);
		if (len == 0)
			continue;	/* timeout will get this */
		if (len < 0) {
			alarm(0);
			return(FAIL);
		}
		str += len;
		i -= len;
		if (nullterm) {
			/* no way can a msg be as long as EBUFSIZ-1 ... */
			*str = 0;
			null = strchr(argstr, '\0');
			if (null != str) {
				null++;	/* start of stash */
				memcpy(Erdstash + Erdlen, null, str - null);
				Erdlen += str - null;
				break;
			} else
				argstr = str;
		} else {
			if (i == 0)
				break;
		}
	}
	alarm(0);
	return(SUCCESS);
}

/*
 * write message across link
 *	type	-> message type
 *	str	-> message body (ascii string)
 *	fn	-> link file descriptor
 *	len	-> if non-zero, amount to write;
		   o.w., write up to '\0' (inclusive)
 * return
 *	FAIL	-> write failed
 *	SUCCESS	-> write succeeded
 */
int
etwrmsg(type, str, fn, len)
char type;
char *str;
int fn, len;
{
	char bufr[EBUFSIZ], *endstr;
	int ret;

	bufr[0] = type;

	/* point endstr to last character to be sent */
	if ((endstr = strchr(str, '\n')) != 0)
		*endstr = 0;
	else
		endstr = str + strlen(str);

	memcpy(bufr+1, str, (endstr - str) + 1);	/* include '\0' */
	if (len == 0)
		len = (endstr - str) + 2;	/* include bufr[0] and '\0' */
	else
		bufr[len-1] = 0;		/* 't' needs this terminator */


	if (setjmp(Failbuf)) {
		DEBUG(7, "etwrmsg write failed\n", 0);
		return(FAIL);
	}
	DEBUG(9, "etwrmsg want %d ... ", len);
	alarm(msgtime);
	ret = (*Write)(fn, bufr, (unsigned) len);
	alarm(0);
	DEBUG(9, "sent %d\n", ret);
	if (ret != len)
		return(FAIL);
	return(SUCCESS);
}
#endif	/* E_PROTOCOL */

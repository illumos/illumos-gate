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

#include "pk.h"

struct pack *Pk;
extern int pkread(), pkwrite();
extern void pkclose();

static int grdblk(char *, int);
static int gwrblk(char *, int);

extern int packsize, xpacksize;

jmp_buf Getjbuf, Gfailbuf;

static void (*gsig)();

/* ARGSUSED */
static void
galarm(sig)
int sig;
{
	signal(SIGALRM, galarm);
	longjmp(Getjbuf, 1);
}

void
pkfail()
{
	longjmp(Gfailbuf, 1);
}

int
gturnon()
{
	struct pack *pkopen();
	if (setjmp(Gfailbuf))
		return(FAIL);
	gsig=signal(SIGALRM, galarm);
	if (Debug > 4)
		pkdebug = 1;
	Pk = pkopen(Ifn, Ofn);
	if (Pk == NULL)
		return(FAIL);
	return(0);
}

int
gturnoff()
{
	if(setjmp(Gfailbuf))
		return(FAIL);
	pkclose();
	(void) signal(SIGALRM, gsig);
	return(0);
}

/*ARGSUSED*/
int
gwrmsg(type, str, fn)
char type, *str;
{
	char bufr[BUFSIZ], *s;
	int len, i;

	if(setjmp(Gfailbuf))
		return(FAIL);
	bufr[0] = type;
	s = &bufr[1];
	while (*str)
		*s++ = *str++;
	*s = '\0';
	if (*(--s) == '\n')
		*s = '\0';
	len = strlen(bufr) + 1;
	if ((i = len % xpacksize) != 0) {
		len = len + xpacksize - i;
		bufr[len - 1] = '\0';
	}
	gwrblk(bufr, len);
	return(0);
}


/*ARGSUSED*/
int
grdmsg(str, fn)
char *str;
{
	unsigned len;

	if(setjmp(Gfailbuf))
		return(FAIL);
	for (;;) {
		len = pkread(str, packsize);
		if (len == 0)
			continue;
		str += len;
		if (*(str - 1) == '\0')
			break;
	}
	return(0);
}


/*ARGSUSED*/
int
gwrdata(fp1, fn)
FILE *fp1;
{
	char bufr[BUFSIZ];
	int fd1;
	int len;
	int ret;
	unsigned long bytes;

	if(setjmp(Gfailbuf))
		return(FAIL);
	bytes = 0L;
	fd1 = fileno( fp1 );
	while ((len = read( fd1, bufr, BUFSIZ )) > 0) {
		bytes += len;
		putfilesize(bytes);
		ret = gwrblk(bufr, len);
		if (ret != len) {
			return(FAIL);
		}
		if (len != BUFSIZ)
			break;
	}
	ret = gwrblk(bufr, 0);
	return(0);
}

/*ARGSUSED*/
int
grddata(fn, fp2)
FILE *fp2;
{
	int ret = SUCCESS;
	int fd2;
	int len;
	char bufr[BUFSIZ];
	unsigned long bytes;

	if(setjmp(Gfailbuf))
		return(FAIL);
	bytes = 0L;
	fd2 = fileno( fp2 );
	for (;;) {
		len = grdblk(bufr, BUFSIZ);
		if (len < 0) {
			return(FAIL);
		}
		bytes += len;
		putfilesize(bytes);
		if ( ret == SUCCESS && write( fd2, bufr, len ) != len) {
			ret = errno;
			DEBUG(7, "grddata: write to file failed, errno %d\n", errno);
		}
		if (len < BUFSIZ)
			break;
	}
	return(ret);
}


static
int
grdblk(blk, len)
char *blk;
{
	int i, ret;

	for (i = 0; i < len; i += ret) {
		ret = pkread(blk, len - i);
		if (ret < 0)
			return(FAIL);
		blk += ret;
		if (ret == 0)
			return(i);
	}
	return(i);
}


static int
gwrblk(blk, len)
char *blk;
{
	return(pkwrite(blk, len));
}

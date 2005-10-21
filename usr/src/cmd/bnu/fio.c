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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * flow control protocol.
 *
 * This protocol relies on flow control of the data stream.
 * It is meant for working over links that can (almost) be
 * guaranteed to be errorfree, specifically X.25/PAD links.
 * A sumcheck is carried out over a whole file only. If a
 * transport fails the receiver can request retransmission(s).
 * This protocol uses a 7-bit datapath only, so it can be
 * used on links that are not 8-bit transparent.
 *
 * When using this protocol with an X.25 PAD:
 * Although this protocol uses no control chars except CR,
 * control chars NULL and ^P are used before this protocol
 * is started; since ^P is the default char for accessing
 * PAD X.28 command mode, be sure to disable that access
 * (PAD par 1). Also make sure both flow control pars
 * (5 and 12) are set. The CR used in this proto is meant
 * to trigger packet transmission, hence par 3 should be 
 * set to 2; a good value for the Idle Timer (par 4) is 10.
 * All other pars should be set to 0.
 *
 * Normally a calling site will take care of setting the
 * local PAD pars via an X.28 command and those of the remote
 * PAD via an X.29 command, unless the remote site has a
 * special channel assigned for this protocol with the proper
 * par settings.
 *
 * Additional comments for hosts with direct X.25 access:
 * - the global variable IsTcpIp, when set, excludes the ioctl's,
 *   so the same binary can run on X.25 and non-X.25 hosts;
 * - reads are done in small chunks, which can be smaller than
 *   the packet size; your X.25 driver must support that.
 *
 *
 * Author:
 *	Piet Beertema, CWI, Amsterdam, Sep 1984
 * Modified for X.25 hosts:
 *	Robert Elz, Melbourne Univ, Mar 1985
 */

#include "uucp.h"
#ifdef F_PROTOCOL

extern unsigned msgtime;

/* privates */
static int frdblk(), fwrblk();

#define FIBUFSIZ	4096	/* for X.25 interfaces: set equal to packet size,
				 * but see comment above
				 */

#define FOBUFSIZ	4096	/* for X.25 interfaces: set equal to packet size;
				 * otherwise make as large as feasible to reduce
				 * number of write system calls 
				 */

#ifndef MAXMSGLEN
#define MAXMSGLEN	BUFSIZ
#endif	/* MAXMSGLEN */

static int fchksum;
static jmp_buf Ffailbuf;

/* ARGSUSED */
static void
falarm(sig)
	int sig;
{
	signal(SIGALRM, falarm);
	longjmp(Ffailbuf, 1);
}

static void (*fsig)();

static int ioctlok;
#ifdef ATTSVTTY
static struct termio ttbuf;
#else
static struct sgttyb ttbuf;
#endif

int
fturnon(void)
{
	int ret;
#ifdef ATTSVTTY
	struct termio save_ttbuf;
#else
	struct sgttyb save_ttbuf;
#endif

#ifdef ATTSVTTY
	if (ioctl(Ifn, TCGETA, &ttbuf) >= 0) {
		ioctlok = 1;
		save_ttbuf = ttbuf;
		ioctl(Ifn, TCGETA, &ttbuf);
		ttbuf.c_iflag = IXOFF|IXON|ISTRIP;
		ttbuf.c_cc[VMIN] = FIBUFSIZ > 64 ? 64 : FIBUFSIZ;
		ttbuf.c_cc[VTIME] = 5;
		ret = ioctl(Ifn, TCSETA, &ttbuf);
		ASSERT(ret >= 0, "STTY FAILED", "", ret);
		ttbuf = save_ttbuf;
	}
#else /* !ATTSVTTY */
	if (ioctl(Ifn, TIOCGETP, &ttbuf) >= 0) {
		ioctlok = 1;
		save_ttbuf = ttbuf;
		ttbuf.sg_flags = ANYP|CBREAK|TANDEM;
		ret = ioctl(Ifn, TIOCSETP, &ttbuf);
		ASSERT(ret >= 0, "STTY FAILED", "", ret);
		ttbuf = save_ttbuf;
	}
#endif /* ATTSVTTY */
	fsig = signal(SIGALRM, falarm);
	/* give the other side time to perform its ioctl;
	 * otherwise it may flush out the first data this
	 * side is about to send.
	 */
	sleep(2);
	return SUCCESS;
}

int
fturnoff(void)
{
	if (ioctlok) {
#ifdef ATTSVTTY
		(void) ioctl(Ifn, TCSETA, &ttbuf);
#else
		(void) ioctl(Ifn, TIOCSETP, &ttbuf);
#endif
	}
	(void) signal(SIGALRM, fsig);
	sleep(2);
	return SUCCESS;
}

int
fwrmsg(type, str, fn)
char *str;
int fn;
char type;
{
	char *s;
	char bufr[MAXMSGLEN];

	s = bufr;
	*s++ = type;
	while (*str)
		*s++ = *str++;
	if (*(s-1) == '\n')
		s--;
	*s++ = '\r';
	*s = 0;
	(void) write(fn, bufr, s - bufr);
	return SUCCESS;
}

int
frdmsg(str, fn)
char *str;
int fn;
{
	char *smax;

	if (setjmp(Ffailbuf))
		return FAIL;
	smax = str + MAXMSGLEN - 1;
	(void) alarm(msgtime);
	for (;;) {
		if (read(fn, str, 1) <= 0)
			goto msgerr;
		*str &= 0177;
		if (*str == '\r')
			break;
		if (*str < ' ') {
			continue;
		}
		if (str++ >= smax)
			goto msgerr;
	}
	*str = '\0';
	(void) alarm(0);
	return SUCCESS;
msgerr:
	(void) alarm(0);
	return FAIL;
}

int
fwrdata(fp1, fn)
FILE *fp1;
int fn;
{
	int alen, ret;
	char ack, ibuf[MAXMSGLEN];
	int flen, retries = 0;
	long fbytes;

	ret = FAIL;
retry:
	fchksum = 0xffff;
	fbytes = 0L;
	ack = '\0';
	do {
		alen = fwrblk(fn, fp1, &flen);
		fbytes += flen;
		if (alen <= 0) {
			goto acct;
		}
	} while (!feof(fp1) && !ferror(fp1));
	DEBUG(8, "\nchecksum: %04x\n", fchksum);
	if (frdmsg(ibuf, fn) != FAIL) {
		if ((ack = ibuf[0]) == 'G')
			ret = SUCCESS;
		DEBUG(4, "ack - '%c'\n", ack);
	}
acct:
	DEBUG(7, "%d retries\n", retries);
	if (ack == 'R') {
		DEBUG(4, "RETRY:\n", 0);
		fseek(fp1, 0L, 0);
		retries++;
		goto retry;
	}
	return ret;
}

/* max. attempts to retransmit a file: */
#define MAXRETRIES	(fbytes < 10000L ? 2 : 1)

int
frddata(fn, fp2)
int fn;
FILE *fp2;
{
	int flen;
	char eof;
	char ibuf[FIBUFSIZ];
	int ret, retries = 0;
	long alen, fbytes;

	ret = FAIL;
retry:
	fchksum = 0xffff;
	fbytes = 0L;
	do {
		flen = frdblk(ibuf, fn, &alen);
		if (flen < 0)
			goto acct;
		if (eof = flen > FIBUFSIZ)
			flen -= FIBUFSIZ + 1;
		fbytes += flen;
		if (fwrite(ibuf, sizeof (char), flen, fp2) != flen)
			goto acct;
	} while (!eof);
	ret = SUCCESS;
acct:
	DEBUG(7, "%d retries\n", retries);
	if (ret == FAIL) {
		if (retries++ < MAXRETRIES) {
			DEBUG(8, "send ack: 'R'\n", 0);
			fwrmsg('R', "", fn);
			fseek(fp2, 0L, 0);
			DEBUG(4, "RETRY:\n", 0);
			goto retry;
		}
		DEBUG(8, "send ack: 'Q'\n", 0);
		fwrmsg('Q', "", fn);
	}
	else {
		DEBUG(8, "send ack: 'G'\n", 0);
		fwrmsg('G', "", fn);
	}
	return ret;
}

static int
frdbuf(blk, len, fn)
char *blk;
int len;
int fn;
{
	static int ret = FIBUFSIZ / 2;

	if (setjmp(Ffailbuf))
		return FAIL;
	(void) alarm(msgtime);
	ret = read(fn, blk, len);
	alarm(0);
	return ret <= 0 ? FAIL : ret;
}

#if !defined(ATTSVKILL)
/* call ultouch every TC calls to either frdblk or fwrblk  */
#define TC	20
static int tc = TC;
#endif	/* !defined(ATTSVKILL) */

/* Byte conversion:
 *
 *   from	 pre	   to
 * 000-037	 172	 100-137
 * 040-171		 040-171
 * 172-177	 173	 072-077
 * 200-237	 174	 100-137
 * 240-371	 175	 040-171
 * 372-377	 176	 072-077
 */

static int
fwrblk(fn, fp, lenp)
int fn;
FILE *fp;
int *lenp;
{
	char *op;
	int c, sum, nl, len;
	char obuf[FOBUFSIZ + 8];
	int ret;

#if !defined(ATTSVKILL)
	/* call ultouch occasionally */
	if (--tc < 0) {
		tc = TC;
		ultouch();
	}
#endif /*!defined(ATTSVKILL)*/
	op = obuf;
	nl = 0;
	len = 0;
	sum = fchksum;
	while ((c = getc(fp)) != EOF) {
		len++;
		if (sum & 0x8000) {
			sum <<= 1;
			sum++;
		} else
			sum <<= 1;
		sum += c;
		sum &= 0xffff;
		if (c & 0200) {
			c &= 0177;
			if (c < 040) {
				*op++ = '\174';
				*op++ = c + 0100;
			} else
			if (c <= 0171) {
				*op++ = '\175';
				*op++ = c;
			}
			else {
				*op++ = '\176';
				*op++ = c - 0100;
			}
			nl += 2;
		} else {
			if (c < 040) {
				*op++ = '\172';
				*op++ = c + 0100;
				nl += 2;
			} else
			if (c <= 0171) {
				*op++ = c;
				nl++;
			} else {
				*op++ = '\173';
				*op++ = c - 0100;
				nl += 2;
			}
		}
		if (nl >= FOBUFSIZ - 1) {
			/*
			 * peek at next char, see if it will fit
			 */
			c = getc(fp);
			if (c == EOF)
				break;
			(void) ungetc(c, fp);
			if (nl >= FOBUFSIZ || c < 040 || c > 0171)
				goto writeit;
		}
	}
	/*
	 * At EOF - append checksum, there is space for it...
	 */
	sprintf(op, "\176\176%04x\r", sum);
	nl += strlen(op);
writeit:
	*lenp = len;
	fchksum = sum;
	DEBUG(8, "%d/", len);
	DEBUG(8, "%d,", nl);
	ret = write(fn, obuf, nl);
	return ret == nl ? nl : ret < 0 ? 0 : -ret;
}

static int
frdblk(ip, fn, rlen)
char *ip;
int fn;
long *rlen;
{
	char *op, c;
	int sum, len, nl;
	char buf[5], *erbp = ip;
	int i;
	static char special = 0;

#if !defined(ATTSVKILL)
	/* call ultouch occasionally */
	if (--tc < 0) {
		tc = TC;
		ultouch();
	}
#endif /*!defined(ATTSVKILL)*/
	if ((len = frdbuf(ip, FIBUFSIZ, fn)) == FAIL) {
		*rlen = 0;
		goto dcorr;
	}
	*rlen = len;
	DEBUG(8, "%d/", len);
	op = ip;
	nl = 0;
	sum = fchksum;
	do {
		if ((*ip &= 0177) >= '\172') {
			if (special) {
				DEBUG(8, "%d", nl);
				special = 0;
				op = buf;
				if (*ip++ != '\176' || (i = --len) > 5)
					goto dcorr;
				while (i--)
					*op++ = *ip++ & 0177;
				while (len < 5) {
					i = frdbuf(&buf[len], 5 - len, fn);
					if (i == FAIL) {
						len = FAIL;
						goto dcorr;
					}
					DEBUG(8, ",%d", i);
					len += i;
					*rlen += i;
					while (i--)
						*op++ &= 0177;
				}
				if (buf[4] != '\r')
					goto dcorr;
				sscanf(buf, "%4x", &fchksum);
				DEBUG(8, "\nchecksum: %04x\n", sum);
				if (fchksum == sum)
					return FIBUFSIZ + 1 + nl;
				else {
					DEBUG(8, "\n", 0);
					DEBUG(4, "Bad checksum\n", 0);
					return FAIL;
				}
			}
			special = *ip++;
		} else {
			if (*ip < '\040') {
				/* error: shouldn't get control chars */
				goto dcorr;
			}
			switch (special) {
			case 0:
				c = *ip++;
				break;
			case '\172':
				c = *ip++ - 0100;
				break;
			case '\173':
				c = *ip++ + 0100;
				break;
			case '\174':
				c = *ip++ + 0100;
				break;
			case '\175':
				c = *ip++ + 0200;
				break;
			case '\176':
				c = *ip++ + 0300;
				break;
			}
			*op++ = c;
			if (sum & 0x8000) {
				sum <<= 1;
				sum++;
			} else
				sum <<= 1;
			sum += c & 0377;
			sum &= 0xffff;
			special = 0;
			nl++;
		}
	} while (--len);
	fchksum = sum;
	DEBUG(8, "%d,", nl);
	return nl;
dcorr:
	DEBUG(8, "\n", 0);
	DEBUG(4, "Data corrupted\n", 0);
	while (len != FAIL) {
		if ((len = frdbuf(erbp, FIBUFSIZ, fn)) != FAIL)
			*rlen += len;
	}
	return FAIL;
}
#endif /* F_PROTOCOL */

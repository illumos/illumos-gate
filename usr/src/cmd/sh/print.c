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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * UNIX shell
 *
 */

#include	"defs.h"
#include	<sys/param.h>
#include	<locale.h>
#include	<wctype.h>	/* iswprint() */

#define		BUFLEN		256

unsigned char numbuf[21];

static unsigned char buffer[BUFLEN];
static unsigned char *bufp = buffer;
static int index = 0;
static int buffd = 1;

void	prc_buff(unsigned char c);
void	prs_buff(unsigned char *s);
void	prn_buff(int n);
void	prs_cntl(unsigned char *s);
void	prs(unsigned char *as);
void	itos(int n);

/*
 * printing and io conversion
 */
void
prp()
{
	if ((flags & prompt) == 0 && cmdadr) {
		prs_cntl(cmdadr);
		prs((unsigned char *)colon);
	}
}

void
prs(unsigned char *as)
{
	if (as) {
		write(output, as, length(as) - 1);
	}
}

void
prc(unsigned char c)
{
	if (c) {
		write(output, &c, 1);
	}
}

void
prwc(wchar_t c)
{
	char	mb[MB_LEN_MAX + 1];
	int	len;

	if (c == 0) {
		return;
	}
	if ((len = wctomb(mb, c)) < 0) {
		mb[0] = (unsigned char)c;
		len = 1;
	}
	write(output, mb, len);
}

void
prt(long t)
{
	int hr, min, sec;

	t += HZ / 2;
	t /= HZ;
	sec = t % 60;
	t /= 60;
	min = t % 60;

	if ((hr = t / 60) != 0) {
		prn_buff(hr);
		prc_buff('h');
	}

	prn_buff(min);
	prc_buff('m');
	prn_buff(sec);
	prc_buff('s');
}

void
prn(int n)
{
	itos(n);

	prs(numbuf);
}

void
itos(int n)
{
	unsigned char buf[21];
	unsigned char *abuf = &buf[20];
	int d;

	*--abuf = (unsigned char)'\0';

	do {
		 *--abuf = (unsigned char)('0' + n - 10 * (d = n / 10));
	} while ((n = d) != 0);

	strncpy(numbuf, abuf, sizeof (numbuf));
}

int
stoi(unsigned char *icp)
{
	unsigned char	*cp = icp;
	int	r = 0;
	unsigned char	c;

	while ((c = *cp, digit(c)) && c && r >= 0) {
		r = r * 10 + c - '0';
		cp++;
	}
	if (r < 0 || cp == icp) {
		failed(icp, badnum);
		/* NOTREACHED */
	} else {
		return (r);
	}
}

int
ltos(long n)
{
	int i;

	numbuf[20] = '\0';
	for (i = 19; i >= 0; i--) {
		numbuf[i] = n % 10 + '0';
		if ((n /= 10) == 0) {
			break;
		}
	}
	return (i);
}

static int
ulltos(u_longlong_t n)
{
	int i;

	/* The max unsigned long long is 20 characters (+1 for '\0') */
	numbuf[20] = '\0';
	for (i = 19; i >= 0; i--) {
		numbuf[i] = n % 10 + '0';
		if ((n /= 10) == 0) {
			break;
		}
	}
	return (i);
}

void
flushb()
{
	if (index) {
		bufp[index] = '\0';
		write(buffd, bufp, length(bufp) - 1);
		index = 0;
	}
}

void
prc_buff(unsigned char c)
{
	if (c) {
		if (buffd != -1 && index + 1 >= BUFLEN) {
			flushb();
		}

		bufp[index++] = c;
	} else {
		flushb();
		write(buffd, &c, 1);
	}
}

void
prs_buff(unsigned char *s)
{
	int len = length(s) - 1;

	if (buffd != -1 && index + len >= BUFLEN) {
		flushb();
	}

	if (buffd != -1 && len >= BUFLEN) {
		write(buffd, s, len);
	} else {
		movstr(s, &bufp[index]);
		index += len;
	}
}

static unsigned char *
octal(unsigned char c, unsigned char *ptr)
{
	*ptr++ = '\\';
	*ptr++ = ((unsigned int)c >> 6) + '0';
	*ptr++ = (((unsigned int)c >> 3) & 07) + '0';
	*ptr++ = (c & 07) + '0';
	return (ptr);
}

void
prs_cntl(unsigned char *s)
{
	int n;
	wchar_t wc;
	unsigned char *olds = s;
	unsigned char *ptr = bufp;
	wchar_t c;

	if ((n = mbtowc(&wc, (const char *)s, MB_LEN_MAX)) <= 0) {
		n = 0;
	}
	while (n != 0) {
		if (n < 0) {
			ptr = octal(*s++, ptr);
		} else {
			c = wc;
			s += n;
			if (!iswprint(c)) {
				if (c < '\040' && c > 0) {
					/*
					 * assumes ASCII char
					 * translate a control character
					 * into a printable sequence
					 */
					*ptr++ = '^';
					*ptr++ = (c + 0100);
				} else if (c == 0177) {
					/* '\0177' does not work */
					*ptr++ = '^';
					*ptr++ = '?';
				} else {
					/*
					 * unprintable 8-bit byte sequence
					 * assumes all legal multibyte
					 * sequences are
					 * printable
					 */
					ptr = octal(*olds, ptr);
				}
			} else {
				while (n--) {
					*ptr++ = *olds++;
				}
			}
		}
		if (buffd != -1 && ptr >= &bufp[BUFLEN-4]) {
			*ptr = '\0';
			prs(bufp);
			ptr = bufp;
		}
		olds = s;
		if ((n = mbtowc(&wc, (const char *)s, MB_LEN_MAX)) <= 0) {
			n = 0;
		}
	}
	*ptr = '\0';
	prs(bufp);
}

void
prull_buff(u_longlong_t lc)
{
	prs_buff(&numbuf[ulltos(lc)]);
}

void
prn_buff(int n)
{
	itos(n);

	prs_buff(numbuf);
}

int
setb(int fd)
{
	int ofd;

	if ((ofd = buffd) == -1) {
		if (bufp+index+1 >= brkend) {
			growstak(bufp+index+1);
		}
		if (bufp[index-1]) {
			bufp[index++] = 0;
		}
		endstak(bufp+index);
	} else {
		flushb();
	}
	if ((buffd = fd) == -1) {
		bufp = locstak();
	} else {
		bufp = buffer;
	}
	index = 0;
	return (ofd);
}

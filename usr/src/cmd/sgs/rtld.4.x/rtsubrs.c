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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1987, 1988, 1989, 1990 by Sun Microsystems, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

/*
 * Subroutines for the 4.0 compatibility run-time link editor.
 */
#include <varargs.h>
#include <sys/types.h>

/*
 * Local "printf" & stdio facilities.
 */
int	stdout = 1;			/* File descriptor for output */
int	stderr = 2;			/* File descriptor for errors */

static char *printn();
static void prf();
static void doprf();
static int _write();

/*
 * printf
 */
/*VARARGS1*/
printf(fmt, va_alist)
	char *fmt;
	va_dcl
{
	va_list x1;

	va_start(x1);
	prf(stdout, fmt, x1);
	va_end(x1);
}

/*
 * fprintf
 */
/*VARARGS2*/
fprintf(fd, fmt, va_alist)
	int fd;
	char *fmt;
	va_dcl
{
	va_list x1;

	va_start(x1);
	prf(fd, fmt, x1);
	va_end(x1);
}

/*
 * panic
 */
/*VARARGS2*/
panic(fmt, va_alist)
	char *fmt;
	va_dcl
{
	va_list x1;
	extern char *program_name;

	va_start(x1);
	prf(stderr, "%s (4.x.ld.so): ", program_name);
	prf(stderr, fmt, x1);
	prf(stderr, "\n", x1);
	va_end(x1);
	_exit(127);
	/* NOTREACHED */
}

/*
 * sprintf
 */
/*VARARGS2*/
sprintf(cp, fmt, va_alist)
	char *cp;
	char *fmt;
	va_dcl
{
	va_list x1;

	va_start(x1);
	doprf(-1, fmt, x1, cp);
	va_end(x1);
}

/*
 * printf worker functions
 */
static void
prf(fd, fmt, adx)
	int fd;
	char *fmt;
	va_list adx;
{
	char linebuf[128];

	doprf(fd, fmt, adx, linebuf);
}

static void
doprf(fd, fmt, adx, linebuf)
	int fd;
	register char *fmt;
	register va_list adx;
	char *linebuf;
{
	register int c;			/* Character temporary */
	register char *lbp;		/* Pointer into stack buffer */
	register char *s;		/* %s temporary */
	int i;				/* General integer temporary */
	int b;				/* Conversion base */

#define	PUTCHAR(c)	{ \
			if (lbp >= &linebuf[128]) { \
				_write(fd, linebuf, lbp - &linebuf[0]); \
				lbp = &linebuf[0]; \
			} \
			*lbp++ = (c); \
			}

	lbp = &linebuf[0];
loop:
	while ((c = *fmt++) != '%') {
		if (c == '\0') {
			_write(fd, linebuf, lbp - &linebuf[0]);
			return;
		}
		PUTCHAR(c);
	}
again:
	c = *fmt++;
	/* THIS CODE IS VAX DEPENDENT IN HANDLING %l? AND %c */
	switch (c) {

	case 'x': case 'X':
		b = 16;
		goto number;
	case 'd': case 'D':
	case 'u':		/* what a joke */
		b = 10;
		goto number;
	case 'o': case 'O':
		b = 8;
number:
		lbp = printn(fd, va_arg(adx, u_long), b, &linebuf[0], lbp,
		    &linebuf[128]);
		break;

	case 'c':
		b = va_arg(adx, int);
		for (i = 24; i >= 0; i -= 8)
			if (c = (b >> i) & 0x7f) {
				PUTCHAR(c);
			}
		break;

	case 's':
		s = va_arg(adx, char *);
		while (c = *s++) {
			PUTCHAR(c);
		}
		break;

	case '%':
		PUTCHAR('%');
		break;
	}
	goto loop;
}

/*
 * Printn prints a number n in base b.
 */
static char *
printn(fd, n, b, linebufp, lbp, linebufend)
	int fd;				/* File descriptor to get output */
	u_long n;			/* Number */
	int b;				/* Base */
	char *linebufp;			/* Buffer location */
	register char *lbp;		/* Current offset in buffer */
	char *linebufend;		/* Where buffer ends */
{
	char prbuf[11];			/* Local result accumulator */
	register char *cp;

#undef PUTCHAR
#define	PUTCHAR(c)	{ \
			if (lbp >= linebufend) { \
				_write(fd, linebufp, lbp - linebufp); \
				lbp = linebufp; \
			} \
			*lbp++ = (c); \
			}

	if (b == 10 && (int)n < 0) {
		PUTCHAR('-');
		n = (unsigned)(-(int)n);
	}
	cp = prbuf;
	do {
		*cp++ = "0123456789abcdef"[n%b];
		n /= b;
	} while (n);
	do {
		PUTCHAR(*--cp);
	} while (cp > prbuf);
	return (lbp);
}

static int
_write(fd, buf, len)
	int fd;
	char *buf;
	int len;
{

	if (fd == -1) {
		*(buf + len) = '\0';
		return (0);
	}
	return (write(fd, buf, len));
}

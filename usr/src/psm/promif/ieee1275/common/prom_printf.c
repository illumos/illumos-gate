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
 * Copyright (c) 1995-1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/varargs.h>

static void _doprint(const char *, va_list, char **);
static void _printn(uint64_t, int, int, int, char **);

/*
 * Emit character functions...
 */

static void
_pput_flush(char *start, char *end)
{
	while (prom_write(prom_stdout_ihandle(),
	    start, end - start, 0, BYTE) == -1)
		;
}

static void
_sput(char c, char **p)
{
	**p = c;
	*p += 1;
}

/*VARARGS1*/
void
prom_printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	_doprint(fmt, adx, (char **)0);
	va_end(adx);
}

void
prom_vprintf(const char *fmt, va_list adx)
{
	_doprint(fmt, adx, (char **)0);
}

/*VARARGS2*/
char *
prom_sprintf(char *s, const char *fmt, ...)
{
	char *bp = s;
	va_list adx;

	va_start(adx, fmt);
	_doprint(fmt, adx, &bp);
	*bp++ = (char)0;
	va_end(adx);
	return (s);
}

char *
prom_vsprintf(char *s, const char *fmt, va_list adx)
{
	char *bp = s;

	_doprint(fmt, adx, &bp);
	*bp++ = (char)0;
	return (s);
}

static void
_doprint(const char *fmt, va_list adx, char **bp)
{
	int b, c, i, pad, width, ells;
	char *s, *start;
	char localbuf[100], *lbp;
	int64_t l;
	uint64_t ul;

	if (bp == 0) {
		bp = &lbp;
		lbp = &localbuf[0];
	}
	start = *bp;
loop:
	width = 0;
	while ((c = *fmt++) != '%') {
		if (c == '\0')
			goto out;
		if (c == '\n') {
			_sput('\r', bp);
			_sput('\n', bp);
			if (start == localbuf) {
				_pput_flush(start, *bp);
				lbp = &localbuf[0];
			}
		} else
			_sput((char)c, bp);
		if (start == localbuf && (*bp - start > 80)) {
			_pput_flush(start, *bp);
			lbp = &localbuf[0];
		}
	}

	c = *fmt++;
	for (pad = ' '; c == '0'; c = *fmt++)
		pad = '0';

	for (width = 0; c >= '0' && c <= '9'; c = *fmt++)
		width = width * 10 + c - '0';

	for (ells = 0; c == 'l'; c = *fmt++)
		ells++;

	switch (c) {
	case 'd':
	case 'D':
		b = 10;
		if (ells == 0)
			l = (int64_t)va_arg(adx, int);
		else if (ells == 1)
			l = (int64_t)va_arg(adx, long);
		else
			l = (int64_t)va_arg(adx, int64_t);
		if (l < 0) {
			_sput('-', bp);
			width--;
			ul = -l;
		} else
			ul = l;
		goto number;

	case 'p':
		ells = 1;
		/*FALLTHROUGH*/
	case 'x':
	case 'X':
		b = 16;
		goto u_number;

	case 'u':
		b = 10;
		goto u_number;

	case 'o':
	case 'O':
		b = 8;
u_number:
		if (ells == 0)
			ul = (uint64_t)va_arg(adx, u_int);
		else if (ells == 1)
			ul = (uint64_t)va_arg(adx, u_long);
		else
			ul = (uint64_t)va_arg(adx, uint64_t);
number:
		_printn(ul, b, width, pad, bp);
		break;

	case 'c':
		b = va_arg(adx, int);
		for (i = 24; i >= 0; i -= 8)
			if ((c = ((b >> i) & 0x7f)) != 0) {
				if (c == '\n')
					_sput('\r', bp);
				_sput((char)c, bp);
			}
		break;

	case 's':
		s = va_arg(adx, char *);
		while ((c = *s++) != 0) {
			if (c == '\n')
				_sput('\r', bp);
			_sput((char)c, bp);
			if (start == localbuf && (*bp - start > 80)) {
				_pput_flush(start, *bp);
				lbp = &localbuf[0];
			}
		}
		break;

	case '%':
		_sput('%', bp);
		break;
	}
	if (start == localbuf && (*bp - start > 80)) {
		_pput_flush(start, *bp);
		lbp = &localbuf[0];
	}
	goto loop;
out:
	if (start == localbuf && (*bp - start > 0))
		_pput_flush(start, *bp);
}

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep kernel stacks.
 */
static void
_printn(uint64_t n, int b, int width, int pad, char **bp)
{
	char prbuf[40];
	char *cp;

	cp = prbuf;
	do {
		*cp++ = "0123456789abcdef"[n%b];
		n /= b;
		width--;
	} while (n);
	while (width-- > 0)
		*cp++ = (char)pad;
	do {
		_sput(*--cp, bp);
	} while (cp > prbuf);
}

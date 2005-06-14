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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/varargs.h>

static void _doprint(const char *, va_list, void (*)(char, char **), char **);
static void _printn(uint64_t, int, int, int, void (*)(char, char **), char **);

/*
 * Emit character functions...
 */

/*ARGSUSED*/
static void
_pput(char c, char **p)
{
	(void) prom_putchar(c);
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
	(void) _doprint(fmt, adx, _pput, (char **)0);
	va_end(adx);
}

void
prom_vprintf(const char *fmt, va_list adx)
{
	va_list tadx;

	va_copy(tadx, adx);
	(void) _doprint(fmt, tadx, _pput, (char **)0);
	va_end(tadx);
}

/*VARARGS2*/
char *
prom_sprintf(char *s, const char *fmt, ...)
{
	char *bp = s;
	va_list adx;

	va_start(adx, fmt);
	(void) _doprint(fmt, adx, _sput, &bp);
	*bp++ = (char)0;
	va_end(adx);
	return (s);
}

char *
prom_vsprintf(char *s, const char *fmt, va_list adx)
{
	char *bp = s;

	(void) _doprint(fmt, adx, _sput, &bp);
	*bp++ = (char)0;
	return (s);
}

static void
_doprint(const char *fmt, va_list adx, void (*emit)(char, char **), char **bp)
{
	int b, c, i, pad, width, ells;
	register char *s;
	int64_t	l;
	uint64_t ul;

loop:
	width = 0;
	while ((c = *fmt++) != '%') {
		if (c == '\0')
			return;
		if (c == '\n')
			(*emit)('\r', bp);
		(*emit)(c, bp);
	}

	c = *fmt++;

	for (pad = ' '; c == '0'; c = *fmt++)
		pad = '0';

	for (width = 0; c >= '0' && c <= '9'; c = *fmt++)
		width = (width * 10) + (c - '0');

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
			(*emit)('-', bp);
			width--;
			ul = -l;
		} else
			ul = l;
		goto number;

	case 'p':
		ells = 1;
		/* FALLTHROUGH */
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
			ul = (uint64_t)va_arg(adx, uint_t);
		else if (ells == 1)
			ul = (uint64_t)va_arg(adx, ulong_t);
		else
			ul = (uint64_t)va_arg(adx, uint64_t);
number:
		_printn(ul, b, width, pad, emit, bp);
		break;

	case 'c':
		b = va_arg(adx, int);
		for (i = 24; i >= 0; i -= 8)
			if ((c = ((b >> i) & 0x7f)) != 0) {
				if (c == '\n')
					(*emit)('\r', bp);
				(*emit)(c, bp);
			}
		break;
	case 's':
		s = va_arg(adx, char *);
		while ((c = *s++) != 0) {
			if (c == '\n')
				(*emit)('\r', bp);
			(*emit)(c, bp);
		}
		break;

	case '%':
		(*emit)('%', bp);
		break;
	}
	goto loop;
}

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep kernel stacks.
 */
static void
_printn(uint64_t n, int b, int width, int pad, void (*emit)(char, char **),
	char **bp)
{
	char prbuf[40];
	register char *cp;

	cp = prbuf;
	do {
		*cp++ = "0123456789abcdef"[n%b];
		n /= b;
		width--;
	} while (n);
	while (width-- > 0)
		*cp++ = (char)pad;
	do {
		(*emit)(*--cp, bp);
	} while (cp > prbuf);
}

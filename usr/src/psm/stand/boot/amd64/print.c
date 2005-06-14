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

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/varargs.h>
#include <sys/promif.h>

#include <amd64/print.h>
#include <amd64/amd64.h>

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep stacks.
 */
static void
__amd64_printn(uint64_t n, int b, int width, int pad,
    void (*put)(void *, int), void *arg)
{
	char prbuf[65];
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
		(*put)(arg, *--cp);
	} while (cp > prbuf);
}

/*
 * This routine is highly specific to amd64, and is essentially a
 * complete kludge which allows amd64 to print using the 64-bit regs
 * from an LP64 kernel.
 *
 * The worst part about it is the assumptions around decoding string
 * pointers -- we assume that the top bits of the string pointer can
 * be discarded yet still remain as a valid address.
 *
 * cell size == sizeof (long long)
 */
static void
__amd64_doprnt64(
	const char *fmt,
	va_list adx,
	void (*put)(void *, int),
	void *arg)
{
	int b, c, i, pad, width, ells;
	char *s;
	int64_t l;
	uint64_t ul;

loop:
	while ((c = *fmt++) != '%') {
		if (c == '\0')
			goto out;
		(*put)(arg, c);
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
			l = (int64_t)(int)va_arg(adx, int64_t);
		else if (ells == 1)
			l = (int64_t)va_arg(adx, int64_t);
		else
			l = (int64_t)va_arg(adx, int64_t);
		if (l < 0) {
			(*put)(arg, '-');
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
			ul = (uint64_t)(uint_t)va_arg(adx, uint64_t);
		else if (ells == 1)
			ul = (uint64_t)va_arg(adx, uint64_t);
		else
			ul = (uint64_t)va_arg(adx, uint64_t);
number:
		__amd64_printn(ul, b, width, pad, put, arg);
		break;

	case 'c':
		b = (int)va_arg(adx, uint64_t);
		for (i = 24; i >= 0; i -= 8)
			if ((c = ((b >> i) & 0x7f)) != 0)
				(*put)(arg, (char)c);
		break;

	/*
	 * Yuck.  We're encoding the assumption that a valid 32-bit pointer
	 * can be obtained by simply truncating the 64-bit pointer.
	 */
	case 's':
		s = (char *)(uintptr_t)va_arg(adx, uint64_t);
		for (width -= strlen(s); width > 0; width--)
			(*put)(arg, pad);
		while ((c = *s++) != 0)
			(*put)(arg, c);
		break;

	case '%':
		(*put)(arg, (char)c);
		break;

	default:
		break;
	}
	goto loop;
out:
	;
}

struct strbuf {
	char *sb_base;
	char *sb_ptr;
	size_t sb_maxsize;
};

static void
sput(void *arg, int c)
{
	struct strbuf *sb = arg;

	if (c == '\n')
		sput(arg, '\r');

	if ((sb->sb_ptr - sb->sb_base) >= sb->sb_maxsize)
		sb->sb_ptr++;
	else
		*sb->sb_ptr++ = (char)c;
}

static int
amd64_vsnprintf_helper(char *s, size_t n, const char *fmt, va_list ap,
	void (*doprnt)(const char *, va_list, void (*)(void *, int), void *))
{
	struct strbuf sbuf, *sb = &sbuf;
	int count;

	sb->sb_base = sb->sb_ptr = s;
	sb->sb_maxsize = n;

	(*doprnt)(fmt, ap, sput, sb);

	/*
	 * Ensure there's a trailing NULL to terminate the string
	 */
	if (sb->sb_maxsize == 0)
		return ((int)(sb->sb_ptr - sb->sb_base));
	if ((count = sb->sb_ptr - sb->sb_base) >= sb->sb_maxsize)
		sb->sb_ptr = sb->sb_base + sb->sb_maxsize - 1;
	if (sb->sb_ptr)
		*sb->sb_ptr = '\0';
	return (count);
}

/*
 * Specialized vsnprintf() that is used to print arguments from
 * an environment where the native argument size is 64-bit
 */
int
amd64_vsnprintf64(char *s, size_t n, const char *fmt, va_list ap)
{
	return (amd64_vsnprintf_helper(s, n, fmt, ap, __amd64_doprnt64));
}

int
amd64_snprintf64(char *s, size_t n, const char *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = amd64_vsnprintf64(s, n, fmt, ap);
	va_end(ap);
	return (r);
}

struct amd64buf {
	char *vb_base;
	char *vb_ptr;
	size_t vb_maxsize;
	struct bootops *vb_bop;
};

void
amd64_vpanic(const char *fmt, va_list ap)
{
	printf("amd64_panic: ");
	prom_vprintf(fmt, ap);
	printf("\n");
	amd64_system_reset();
}

void
amd64_panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	amd64_vpanic(fmt, ap);
	va_end(ap);
}

void
amd64_warning(const char *fmt, ...)
{
	va_list ap;

	printf("amd64 warning: ");
	va_start(ap, fmt);
	prom_vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

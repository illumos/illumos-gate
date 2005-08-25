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
 * helper functions for switching to realmode and make a bios call.
 * The only interesting functions are copyin_args and copyout_args.
 * The rest are for debugging via a serial line.
 */

#include "util.h"
#include "biosint.h"
#include "chario.h"
#include "serial.h"

/* Forward declarations. */
static void putchar(int c);
static void itoa(char *buf, int base, int d);

void
copyin_args(int intnum, struct int_pb *ic)
{
	extern int ic_int;
	extern uint16_t ic_ax, ic_bx, ic_cx, ic_dx;
	extern uint16_t ic_bp, ic_si, ic_di, ic_ds, ic_es;

	ic_int = intnum;
	ic_ax = ic->ax;
	ic_bx = ic->bx;
	ic_cx = ic->cx;
	ic_dx = ic->dx;
	ic_bp = ic->bp;
	ic_si = ic->si;
	ic_di = ic->di;
	ic_ds = ic->ds;
	ic_es = ic->es;
}

void
copyout_args(struct int_pb *ic)
{
	extern uint16_t ic_ax, ic_bx, ic_cx, ic_dx;
	extern uint16_t ic_bp, ic_si, ic_di, ic_ds, ic_es;

	ic->ax = ic_ax;
	ic->bx = ic_bx;
	ic->cx = ic_cx;
	ic->dx = ic_dx;
	ic->bp = ic_bp;
	ic->si = ic_si;
	ic->di = ic_di;
	ic->ds = ic_ds;
	ic->es = ic_es;
}

/*
 * Convert the integer D to a string and save the string in BUF. If
 * BASE is equal to 'd', interpret that D is decimal, and if BASE is
 * equal to 'x', interpret that D is hexadecimal.
 */
static void
itoa(char *buf, int base, int d)
{
	char *p = buf;
	char *p1, *p2;
	unsigned long ud = d;
	int divisor = 10;

	/* If %d is specified and D is minus, put `-' in the head. */
	if (base == 'd' && d < 0) {
		*p++ = '-';
		buf++;
		ud = -d;
	} else if (base == 'x') {
		divisor = 16;
	}

	/* Divide UD by DIVISOR until UD == 0. */
	do {
		int remainder = ud % divisor;

		*p++ = (remainder < 10) ?
		    remainder + '0' : remainder + 'a' - 10;
	}

	while (ud /= divisor)
		;

	/* Terminate BUF. */
	*p = 0;

	/* Reverse BUF. */
	p1 = buf;
	p2 = p - 1;
	while (p1 < p2) {
		char tmp = *p1;
		*p1 = *p2;
		*p2 = tmp;
		p1++;
		p2--;
	}
}

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep kernel stacks.
 */
/* XXX need to support 64-bit numbers */
static void
_printn(uint_t n, int b, int width, int pad)
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
		putchar(*--cp);
	} while (cp > prbuf);
}

/*
 * Format a string and print it on the screen, just like the libc
 * function printf.
 */
void
vprintf(const char *fmt, va_list adx)
{
	int b, c, i, pad, width, ells;
	char *s;
	int64_t l;
	uint64_t ul;

loop:
	width = 0;
	while ((c = *fmt++) != '%') {
		if (c == '\0')
			return;
		putchar(c);
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
			putchar('-');
			width--;
			putchar('-');
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
		_printn((uint_t)ul, b, width, pad);
		break;

	case 'c':
		b = va_arg(adx, int);
		for (i = 24; i >= 0; i -= 8)
			if ((c = ((b >> i) & 0x7f)) != 0) {
				putchar(c);
			}
		break;
	case 's':
		s = va_arg(adx, char *);
		while ((c = *s++) != 0) {
			putchar(c);
		}
		break;

	case '%':
		putchar('%');
		break;
	}
	goto loop;

}

/*
 * Format a string and print it on the screen, just like the libc
 * function printf.
 */
void
printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vprintf(fmt, adx);
	va_end(adx);
}

/* serial port stuff */
static int port = 0x3f8;

static void
serial_putchar(int c)
{
	int checks = 10000;

	while (((inb(port + LSR) & XHRE) == 0) && checks--)
		;
	outb(port + DAT, (char)c);
}

static void
_doputchar(int c)
{
	serial_putchar(c);
}

void
putchar(int c)
{
	static int bhcharpos = 0;

	if (c == '\t') {
			do {
				_doputchar(' ');
			} while (++bhcharpos % 8);
			return;
	} else  if (c == '\n') {
			bhcharpos = 0;
			_doputchar('\r');
			_doputchar(c);
			return;
	} else if (c == '\b') {
			if (bhcharpos)
				bhcharpos--;
			_doputchar(c);
			return;
	}

	bhcharpos++;
	_doputchar(c);
}

void
print_long(int reg)
{
	printf("long = 0x%x\n", reg);
}

void
print_word(ushort_t reg)
{
	printf("word = 0x%x\n", reg);
}

void
print_regs()
{
	extern int call_esp, ic_int;
	extern uint16_t call_cs, call_ss;

	printf("call_cs = %x, call_ss = %x\r\n", call_cs, call_ss);
	printf("intnum = %x, esp = %x\r\n", ic_int, call_esp);
}

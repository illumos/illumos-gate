/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"

void	p2dig_ull(unsigned long long);
void	p2dig_int(int);
void	flush(void);
void	Putchar(tchar);


/*
 * C Shell
 */

void
psecs_ull(unsigned long long l)
{
	unsigned long long i;

	i = l / 3600;
	if (i) {
		printf("%llu:", i);
		i = l % 3600;
		p2dig_ull(i / 60);
		goto minsec;
	}
	i = l;
	printf("%llu", i / 60);
minsec:
	i %= 60;
	printf(":");
	p2dig_ull(i);
}

void
psecs_int(int l)
{
	int i;

	i = l / 3600;
	if (i) {
		printf("%d:", i);
		i = l % 3600;
		p2dig_int(i / 60);
		goto minsec;
	}
	i = l;
	printf("%d", i / 60);
minsec:
	i %= 60;
	printf(":");
	p2dig_int(i);
}

void
p2dig_ull(unsigned long long i)
{
	printf("%llu%llu", i / 10, i % 10);
}

void
p2dig_int(int i)
{
	printf("%d%d", i / 10, i % 10);
}

char linbuf[128];
char *linp = linbuf;

#ifdef MBCHAR

/*
 * putbyte() send a byte to SHOUT.  No interpretation is done
 * except an un-QUOTE'd control character, which is displayed
 * as ^x.
 */
void
putbyte(int c)
{

	if ((c & QUOTE) == 0 && (c == 0177 || c < ' ' && c != '\t' &&
	    c != '\n')) {
		putbyte('^');
		if (c == 0177) {
			c = '?';
		} else {
			c |= 'A' - 1;
		}
	}
	c &= TRIM;
	*linp++ = c;

	if (c == '\n' || linp >= &linbuf[sizeof (linbuf) - 1 - MB_CUR_MAX]) {
		/* 'cause the next Putchar() call may overflow the buffer.  */
		flush();
	}
}

/*
 * Putchar(tc) does what putbyte(c) do for a byte c.
 * Note that putbyte(c) just send the byte c (provided c is not
 * a control character) as it is, while Putchar(tc) may expand the
 * character tc to some byte sequnce that represents the character
 * in EUC form.
 */
void
Putchar(tchar tc)
{
	int	n;

	if (isascii(tc&TRIM)) {
		putbyte((int)tc);
		return;
	}
	tc &= TRIM;
	n = wctomb(linp, tc);
	if (n == -1) {
		return;
	}
	linp += n;
	if (linp >= &linbuf[sizeof (linbuf) - 1 - MB_CUR_MAX]) {
		flush();
	}
}

#else	/* !MBCHAR */

/*
 * putbyte() send a byte to SHOUT.  No interpretation is done
 * except an un-QUOTE'd control character, which is displayed
 * as ^x.
 */
void
putbyte(int c)
{

	if ((c & QUOTE) == 0 && (c == 0177 || c < ' ' && c != '\t' &&
	    c != '\n')) {
		putbyte('^');
		if (c == 0177) {
			c = '?';
		} else {
			c |= 'A' - 1;
		}
	}
	c &= TRIM;
	*linp++ = c;
	if (c == '\n' || linp >= &linbuf[sizeof (linbuf) - 2]) {
		flush();
	}
}

/*
 * Putchar(tc) does what putbyte(c) do for a byte c.
 * For single-byte character only environment, there is no
 * difference between Putchar() and putbyte() though.
 */
void
Putchar(tchar tc)
{
	putbyte((int)tc);
}

#endif	/* !MBCHAR */

void
draino(void)
{
	linp = linbuf;
}

void
flush(void)
{
	int unit;
	int lmode;

	if (linp == linbuf) {
		return;
	}
	if (haderr) {
		unit = didfds ? 2 : SHDIAG;
	} else {
		unit = didfds ? 1 : SHOUT;
	}
#ifdef TIOCLGET
	if (didfds == 0 && ioctl(unit, TIOCLGET,  (char *)&lmode) == 0 &&
	    lmode&LFLUSHO) {
		lmode = LFLUSHO;
		(void) ioctl(unit, TIOCLBIC,  (char *)&lmode);
		(void) write(unit, "\n", 1);
	}
#endif
	(void) write(unit, linbuf, linp - linbuf);
	linp = linbuf;
}

/*
 * Should not be needed.
 */
void
write_string(char *s)
{
	int unit;
	/*
	 * First let's make it sure to flush out things.
	 */
	flush();

	if (haderr) {
		unit = didfds ? 2 : SHDIAG;
	} else {
		unit = didfds ? 1 : SHOUT;
	}

	(void) write(unit, s, strlen(s));
}

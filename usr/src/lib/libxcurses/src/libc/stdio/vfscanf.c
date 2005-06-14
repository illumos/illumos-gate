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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * System V.2 Emulation Stdio Library -- vfscanf
 *
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: vfscanf.c 1.27 1995/09/20 19:07:52 ant Exp $";
#endif
#endif

#include <mks.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef __FLOAT__
#include <math.h>
#endif

#define	CONVTYPE	1
#define STAR		2
#define PERCENT		3
#define NUMBER		4
#define MODCONVL	5
#define NSCAN		6
#define	BRACKET		7
#define MODCONVH	8

#define BASE16	16
#define BASE10	10
#define BASE8	8
#define NOBASE	0
#define SIGNED	1
#define UNSIGNED 0

#define	CBUFSIZ	100	/* size of character buffer for input conversion */

struct lexlist {
	char	name;
	char	type;
};
static struct lexlist *lexp;
static struct lexlist lexlist[] ={
	'*',	STAR,
	'%',	PERCENT,
	'l',	MODCONVL,
	'h',	MODCONVH,
	'n',	NSCAN,
	'[',	BRACKET,
	'd',	CONVTYPE,
	'S',	CONVTYPE,	/* dummy entry (for multibyte characters) */
	's',	CONVTYPE,
	'u',	CONVTYPE,
	'c',	CONVTYPE,
	'x',	CONVTYPE,
	'o',	CONVTYPE,
	'0',	NUMBER,
	'1',	NUMBER,
	'2',	NUMBER,
	'3',	NUMBER,
	'4',	NUMBER,
	'5',	NUMBER,
	'6',	NUMBER,
	'7',	NUMBER,
	'8',	NUMBER,
	'9',	NUMBER,
	'i',	CONVTYPE,
	'f',	CONVTYPE,
	'e',	CONVTYPE,
	'g',	CONVTYPE,
	0,	0
};

static int	scan(int, const char *, const char *);
static	int	gettoken(void);
static	void	whitespace(void);
static	int	match(const char *, char *);
static	long	unsigned	getnum(int, int, int);
static	int	getin(void);
static	void	unget(int);
#ifdef	__FLOAT__
static	double	lstrtod(void);
#endif

static	int	ungot;		/* getin/unget char */
static	FILE	*fpin;		/* input file pointer */
static	int	pflag;		/*indicator of conversion description present */
static	int	width;		/* field width value */
static	const	char	*fmtptr;	/* format string pointer */
static	int	charcnt;	/* number of characters scanned (for %n) */
static	int	from;		/* token type we've come from */
static	int	gfail;		/* getnum() fail flag, non-zero for fail */
 
/*
 * Convert formatted input from given input.
 * This is the workhorse for scanf, sscanf, and fscanf.
 * Returns the number of matched and assigned input items.
 */
int
mks_vfscanf(FILE *pfin, const char *fmt, va_list ap)
{
	int	nitems;
	int	ltoken;
	int	c;
	int	modconv;	/* flag indicating conversion modifier */
	int	suppression;	/* flag to suppress conversion */

	long unsigned number;	/* return value from getnumber */

	ungot = EOF;
	fpin = pfin;
	fmtptr = fmt;
	from = 'X';
	nitems = 0;
	charcnt = 0;

	for (;;) {
		if (from == 'X') {
			pflag = 0;
			modconv = 0;
			suppression = 0;
			width = 0;
		}
		ltoken = gettoken();

		switch (ltoken) {

		case 0:
			goto retitems;
	
		case MODCONVL:
		case MODCONVH:
			switch (from) {
	
			case 'A':
			case 'D':
			case 'P':
				from = 'E';
				modconv = ltoken;
				break;
			default:
				from = 'X';
				break;
			}
			break;
	
		case CONVTYPE:
			switch (from) {

			int	intassign;

			case 'E':
			case 'P':
			case 'D':
			case 'A':
				from = 'X';
				intassign = 1;
				pflag = 0;

				switch (lexp->name) {

				case 'd':
					number = getnum(BASE10, width, SIGNED);
					if (gfail)
						goto retitems;
					break;
				case 'u':
					number = getnum(BASE10, width, UNSIGNED);
					if (gfail)
						goto retitems;
					break;
				case 'x':
					number = getnum(BASE16, width, SIGNED);
					if (gfail)
						goto retitems;
					break;
				case 'o':
					number = getnum(BASE8, width, SIGNED);
					if (gfail)
						goto retitems;
					break;
				case 'i':
					number = getnum(NOBASE, width, SIGNED);
					if (gfail)
						goto retitems;
					break;
				case 'c':
				/* 'S' dummy entry (for multibyte characters) */
				case 'S':
				case 's': {
					int gotitem = 0;
					char	*str;

					if (!suppression)
						str = va_arg(ap, char *);

					/* Input whitespace is not skipped
					 * for %c, which implies that %c
					 * can return whitespace.
					 */
					if (lexp->name != 'c')
						whitespace();
					for (;;) {
						c = getin();

						/* Only %s and %S stop on 
						 * whitespace. 
						 */
						if (lexp->name != 'c' && isspace(c)) {
							unget(c);
							break;
						}
						if (c == EOF) {
							if(!gotitem)
								goto retitems;
							break;
						}

						gotitem = 1;
						if (!suppression)
							*str++ = c;

						if (width) {
							if (--width == 0)
								break;
						}
					}

					/*
					 * ANSI C states that %c does not 
					 * terminate with a null character.
					 */
					if (!suppression && lexp->name != 'c')
						*str = '\0';
					intassign = 0;
					break;
				}
#ifdef	__FLOAT__
				case 'f':
				case 'g':
				case 'e': {
					double	fresult;

					fresult = lstrtod();
					if(gfail)
						goto retitems;
					if(suppression)
						break;
					if (modconv == MODCONVL)
						*(double *)va_arg(ap, double *) = fresult;
					else
						*(float *)va_arg(ap, float *) = (float)fresult;
					/*FALLTHROUGH*/
				}
#else	/* !__FLOAT__ */
				case 'f':
				case 'g':
				case 'e':
#endif	/* __FLOAT__ */
				default:
					intassign = 0;
					break;
				}

				if (suppression)
					break;
				else
					nitems++;

				if (intassign == 0)
					break;

				switch (modconv) {

				case MODCONVH:
					*(short *)va_arg(ap, short *) = (short)number;
					break;
				case MODCONVL:
					*(long *)va_arg(ap, long *) = (long)number;
					break;
				default:
					*(int *)va_arg(ap, int *) = (int)number;
					break;
				}
				break;
			default:
				from = 'X';
				break;
			}
			break;
	
		case STAR:
			if (from == 'P') {
				from = 'A';
				suppression = 1;
			} else {
				from = 'X';
			}
			break;
	
		case PERCENT:
			if (from == 'P') {
				from = 'X';
				pflag = 0;
				c = getin();
				if (c != '%')
					goto retitems;
			} else {
				from = 'X';
			}
			break;
	
		case NUMBER:
			if (from == 'P' || from == 'A') {
				from = 'D';
			} else {
				from = 'X';
			}
			break;
	
		case NSCAN:
			if (from == 'P') {
				pflag = 0;
				if (!suppression) {
					*(int *)va_arg(ap, int *) = charcnt;
				}
			}
			from = 'X';
			break;
	
		case BRACKET:
			switch (from) {

			case 'A':
			case 'D':
			case 'P': {
				char *ptr;

				pflag = 0;
				if (width == 0)
					width = INT_MAX;
				ptr = suppression ? NULL : va_arg(ap, char *);
				if (match(fmtptr, ptr) && !feof(fpin) 
				&& !suppression)
					nitems++;
				while (*fmtptr++ != ']')
					;
				break;
			}
			default:
				break;
			}
			from = 'X';
			break;
	
		default:
			c = *(fmtptr-1);
			if (c == ' ' || c == '\t' || c == '\n' || c == '\f')
				whitespace();
			else {
				c = getin();

				if (c != *(fmtptr-1))
					goto retitems;
			}
			from = 'X';
			break;
		}
	}
retitems:
	if (ungot != EOF) {
		ungetc(ungot, fpin);
		ungot = EOF;
	}
	return nitems==0 ? EOF : nitems;
}

static int
gettoken()
{
	char	c;

	if (*fmtptr == 0)
		return 0;	/* return 0 for end of string */

	c = *fmtptr++;

	if (pflag) {
		for(lexp=lexlist; lexp->name != 0; lexp++) {
			if (c == lexp->name) {
				if (lexp->type == NUMBER) {
					width = (int) strtol(fmtptr-1, (char **)0, BASE10);
					while (*fmtptr >= '0' && *fmtptr <= '9')
						fmtptr++;
				} else if (c == 'c') {
					/* No width specified for %c, default
					 * is one.
					 */
					width = 1;
				}
				return lexp->type;
			}
		}
		return -1;
	}

	if (c == '%') {
		pflag = 1;
		from = 'P';
		return gettoken();
	}
	return -1;
}

static void
whitespace()
{
	register int	c;

	do {
		c = getin();
	} while (isspace(c));

	unget(c);
}

static int
scan(int ch, const char *str, const char *estr)
{
	for (; str < estr; ++str)
		if (*str == ch)
			return 1;

	return 0;
}

static int
match(const char *str, char *outstr)
{
	int	complement;
	int	i;
	char	start, end;
	int	c;
	const	char	*bscan, *escan;

	if (*str == '^') {
		complement = 1;
		str++;
	} else
		complement = 0;

	start = *str++;
	end = 0;
	if (*str == '-') {
		if (str[2] == ']')
			end = str[1];
	}
	if (start > end) {
		bscan = str - 1;
		while (*str++ != ']')
			;
		escan = str - 1;

		for (i=0; i<width; i++) {
			if ((c = getin()) == EOF)
				return 0;
			if (!scan(c, bscan, escan) ^ complement)
				break;
			if (outstr != NULL)
				*outstr++ = c;
		}
	} else {
		for (i=0; i<width; i++) {
			c = getin();
			if (complement) {
				if (c >= start && c <= end)
					break;
				else if (outstr != NULL)
					*outstr++ = c;
			} else {
				if (c < start || c > end)
					break;
				else if (outstr != NULL)
					*outstr++ = c;
			}
		}
	}

	if (i < width)
		unget(c);

	if (outstr != NULL)
		*outstr = '\0';
	return (i > 1);
}

/*
 * Get a number from the input stream.
 * The base, if zero, will be determined by the nature of the number.
 * A leading 0x means hexadecimal, a leading 0 for octal, otherwise decimal.
 * 
 * if the width is 0 then the max input string length of number is used.
 *
 * The sign tell us that a signed number is expected (rather than the
 *	'u' conversion type which is unsigned).
 */
static long unsigned
getnum(int base, int width, int sign)
{
	char	*s;
	char	cbuf[CBUFSIZ];			/* char buffer for number */
	int	w;
	register int	c;
	int	neg;
	long	ret;

	gfail = 0;
	whitespace();

	if (width == 0)
		width = sizeof cbuf;

	neg = 0;
	if (sign) {
		c = getin();
		if (c == '+' || c == '-')
			neg = c=='-' ? 1 : 0;
		else
			unget(c);
	}

	if (base == 0) {
		base = 10;
		c = getin();
		if (c == '0') {
			base = 8;
			c = getin();
			if (c == 'X' || c == 'x')
				base = 16;
			else
				unget(c);
		} else
			unget(c);
	}
	if (base == 10) {
		w = 0;
		s = cbuf;
		while (w < width && w < sizeof cbuf) {
			c = getin();
			switch (c) {
	
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				*s++ = c;
				w++;
				continue;
			default:
				unget(c);
				w = width;	/* force end of loop */
				break;
			}
		}
		*s = '\0';
		ret = strtol(cbuf, (char **)0, 10);
		goto retn;
	}
	if (base == 8) {
		w = 0;
		s = cbuf;
		while (w < width && w < sizeof cbuf) {
			c = getin();
			switch (c) {
	
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				*s++ = c;
				w++;
				continue;
			default:
				unget(c);
				w = width;	/* force end of loop */
				break;
			}
		}
		*s = '\0';
		ret = strtol(cbuf, (char **)0, 8);
		goto retn;
	}
	if (base == 16) {
		w = 0;
		s = cbuf;
		while (w < width && w < sizeof cbuf) {
			c = getin();
			c = toupper(c);
			switch (c) {
	
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
				*s++ = c;
				w++;
				continue;
			default:
				unget(c);
				w = width;	/* force end of loop */
				break;
			}
		}
		*s = '\0';
		ret = strtol(cbuf, (char **)0, 16);
		goto retn;
	}

/*
 * if we get this far then a bad base was passed.
 */
	gfail = -1;

retn:
	if (*cbuf == '\0')	/* No number at all?? */
		gfail = -1;
	if (neg)
		ret = -ret;
	return ret;
}

#ifdef	__FLOAT__
static double
lstrtod()
{
	int	slen;
	int	neg, eneg;
	char	cbuf[CBUFSIZ];
	register int	c;
	register char	*sp, *s1, *s2, *s3;
	double	total, exp, tens;

	neg = eneg = 1;
	gfail = 0;

	whitespace();

	c = getin();

	if (c == '-' || c == '+')
		if (c == '-') {
			neg = -1;
			c = getin();
		}

	sp = s1 = cbuf;
	while (c >= '0' && c <= '9') {
		*sp++ = c;
		c = getin();
	}

	s2 = sp;
	if (c == '.') {
		c = getin();
		while (c >= '0' && c <= '9') {
			*sp++ = c;
			c = getin();
		}
	}

	s3 = sp;
	if (c == 'e' || c == 'E') {
		c = getin();
		if (c == '-' || c == '+')
			if (c == '-') {
				eneg = -1;
				c = getin();
			}
		while (c >= '0' && c <= '9') {
			*sp++ = c;
			c = getin();
		}
	}
	*sp = '\0';

	if (s1 == s2 && s2 == s3) {
		gfail = -1;
		return 0.0;
	}
	unget(c);

	/*
	 * convert the three strings (integer, fraction, and exponent)
	 * into a floating point number.
	 */

	total = 0.0;
	tens = 1.0;
	for (sp=s2-1; sp >= s1; sp--) {
		total += (*sp -'0') * tens;
		tens *= 10.0;
	}

	tens = .1;
	for (sp=s2; sp < s3; sp++) {
		total += (*sp - '0') * tens;
		tens /= 10.0;
	}
	total *= (double)neg;

	exp = 0.0;
	tens = 1.0;
	if ((slen = strlen(s3)) > 0) {
		sp = s3 + slen - 1;
		for ( ; sp >= s3; sp--) {
			exp += (*sp - '0') * tens;
			tens *= 10.0;
		}
	}
	*sp = '\0';

	exp *= (double)eneg;

	total *= pow(10.0, exp);

	return total;
}
#endif	/* __FLOAT__ */

static	int
getin()
{
	int	c;

	if (ungot != EOF) {
		c = ungot;
		ungot = EOF;
	} else
		c = getc(fpin);
	charcnt++;
	return c;
}

static void
unget(int c)
{
	/* Dont' use ungetc because it doesn't work with m_fsopen */
	ungot = c;
	charcnt--;
}


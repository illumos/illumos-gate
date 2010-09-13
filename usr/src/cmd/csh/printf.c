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

/*
 * Hacked "printf" which prints through putbyte and Putchar.
 * putbyte() is used to send a pure byte, which might be a part
 * of a mutlibyte character, mainly for %s.  A control character
 * for putbyte() may be QUOTE'd meaning not to convert it to ^x
 * sequence.  In all other cases Putchar() is used to send a character
 * in tchar (== wchar_t + * optional QUOE.)
 * DONT USE WITH STDIO!
 * This printf has been hacked again so that it understands tchar string
 * when the format specifier %t is used.  Also %c has been expanded
 * to take a tchar character as well as normal int.
 * %t is supported in its simplest form; no width or precision will
 * be understood.
 * Assumption here is that sizeof(tchar)<=sizeof(int) so that tchar is
 * passed as int.  Otherwise, %T must be specified instead of %c to
 * print a character in tchar.
 */

#include <stdarg.h>
#include <values.h>
#include "sh.h" /* For tchar. */

#define	HIBITLL		(1ULL << 63)

void _print(char *format, va_list *args);

static char *p;

int
printf(const char *format, ...)
{
	va_list stupid;

	p = (char *)gettext(format);
	va_start(stupid, format);
	_print(p, &stupid);
	va_end(stupid);

	return (0);
}

/*
 *	Floating-point code is included or not, depending
 *	on whether the preprocessor variable FLOAT is 1 or 0.
 */

/* Maximum number of digits in any integer (long) representation */
#define	MAXDIGS	20

/* Convert a digit character to the corresponding number */
#define	tonumber(x)	((x) - '0')

/* Convert a number between 0 and 9 to the corresponding digit */
#define	todigit(x)	((x) + '0')

/* Maximum total number of digits in E format */
#define	MAXECVT	17

/* Maximum number of digits after decimal point in F format */
#define	MAXFCVT	60

/* Maximum significant figures in a floating-point number */
#define	MAXFSIG	17

/* Maximum number of characters in an exponent */
#define	MAXESIZ	4

/* Maximum (positive) exponent or greater */
#define	MAXEXP	40



#define	max(a, b) ((a) > (b) ? (a) : (b))
#define	min(a, b) ((a) < (b) ? (a) : (b))

/* If this symbol is nonzero, allow '0' as a flag */
#define	FZERO 1

#if FLOAT
/*
 *	System-supplied routines for floating conversion
 */
char *fcvt();
char *ecvt();
#endif

void
_print(char *format, va_list *args)
{
	/* Current position in format */
	char *cp;

	/* Starting and ending points for value to be printed */
	char *bp, *p;
	tchar *tbp, *tep;	/* For "%t". */
	tchar tcbuf[2];		/* For "%c" or "%T". */

	/* Field width and precision */
	int width, prec;

	/* Format code */
	char fcode;

	/* Number of padding zeroes required on the left */
	int lzero;

	/* Flags - nonzero if corresponding character appears in format */
	bool length;		/* l */
	bool double_length;	/* ll */
	bool fplus;		/* + */
	bool fminus;		/* - */
	bool fblank;		/* blank */
	bool fsharp;		/* # */
#if FZERO
	bool fzero;		/* 0 */
#endif

	/* Pointer to sign, "0x", "0X", or empty */
	char *prefix;
#if FLOAT
	/* Exponent or empty */
	char *suffix;

	/* Buffer to create exponent */
	char expbuf[MAXESIZ + 1];

	/* Number of padding zeroes required on the right */
	int rzero;

	/* The value being converted, if real */
	double dval;

	/* Output values from fcvt and ecvt */
	int decpt, sign;

	/* Scratch */
	int k;

	/* Values are developed in this buffer */
	char buf[max(MAXDIGS, max(MAXFCVT + DMAXEXP, MAXECVT) + 1)];
#else
	char buf[MAXDIGS];
#endif
	/* The value being converted, if integer */
	long long val;

	/* Set to point to a translate table for digits of whatever radix */
	char *tab;

	/* Work variables */
	int n, hradix, lowbit;

	cp = format;

	/*
	 *	The main loop -- this loop goes through one iteration
	 *	for each ordinary character or format specification.
	 */
	while (*cp)
		if (*cp != '%') {
			/* Ordinary (non-%) character */
			putbyte (*cp++);
		} else {
			/*
			 *	% has been found.
			 *	First, parse the format specification.
			 */

			/* Scan the <flags> */
			fplus = fminus = fblank = fsharp = 0;
#if FZERO
			fzero = 0;
#endif
scan:
			switch (*++cp) {
			case '+':
				fplus = 1;
				goto scan;
			case '-':
				fminus = 1;
				goto scan;
			case ' ':
				fblank = 1;
				goto scan;
			case '#':
				fsharp = 1;
				goto scan;
#if FZERO
			case '0':
				fzero = 1;
				goto scan;
#endif
			}

			/* Scan the field width */
			if (*cp == '*') {
				width = va_arg (*args, int);
				if (width < 0) {
					width = -width;
					fminus = 1;
				}
				cp++;
			} else {
				width = 0;
				while (isdigit(*cp)) {
					n = tonumber(*cp++);
					width = width * 10 + n;
				}
			}

			/* Scan the precision */
			if (*cp == '.') {

				/* '*' instead of digits? */
				if (*++cp == '*') {
					prec = va_arg(*args, int);
					cp++;
				} else {
					prec = 0;
					while (isdigit(*cp)) {
						n = tonumber(*cp++);
						prec = prec * 10 + n;
					}
				}
			} else {
				prec = -1;
			}

			/* Scan the length modifier */
			double_length = length = 0;
			switch (*cp) {
			case 'l':
				if (*(cp + 1) == 'l') {
					cp++;
					double_length = 1;
				} else {
					length = 1;
				}
				/* No break */
			case 'h':
				cp++;
			}

			/*
			 *	The character addressed by cp must be the
			 *	format letter -- there is nothing left for
			 *	it to be.
			 *
			 *	The status of the +, -, #, blank, and 0
			 *	flags are reflected in the variables
			 *	"fplus", "fminus", "fsharp", "fblank",
			 *	and "fzero", respectively.
			 *	"width" and "prec" contain numbers
			 *	corresponding to the digit strings
			 *	before and after the decimal point,
			 *	respectively. If there was no decimal
			 *	point, "prec" is -1.
			 *
			 *	The following switch sets things up
			 *	for printing.  What ultimately gets
			 *	printed will be padding blanks, a prefix,
			 *	left padding zeroes, a value, right padding
			 *	zeroes, a suffix, and more padding
			 *	blanks.  Padding blanks will not appear
			 *	simultaneously on both the left and the
			 *	right.  Each case in this switch will
			 *	compute the value, and leave in several
			 *	variables the information necessary to
			 *	construct what is to be printed.
			 *
			 *	The prefix is a sign, a blank, "0x", "0X",
			 *	or null, and is addressed by "prefix".
			 *
			 *	The suffix is either null or an exponent,
			 *	and is addressed by "suffix".
			 *
			 *	The value to be printed starts at "bp"
			 *	and continues up to and not including "p".
			 *
			 *	"lzero" and "rzero" will contain the number
			 *	of padding zeroes required on the left
			 *	and right, respectively.  If either of
			 *	these variables is negative, it will be
			 *	treated as if it were zero.
			 *
			 *	The number of padding blanks, and whether
			 *	they go on the left or the right, will be
			 *	computed on exit from the switch.
			 */

			lzero = 0;
			prefix = "";
#if FLOAT
			rzero = lzero;
			suffix = prefix;
#endif
			switch (fcode = *cp++) {

			/*
			 *	fixed point representations
			 *
			 *	"hradix" is half the radix for the conversion.
			 *	Conversion is unsigned unless fcode is 'd'.
			 *	HIBITLL is 1000...000 binary, and is equal to
			 *		the maximum negative number.
			 *	We assume a 2's complement machine
			 */

			case 'D':
			case 'U':
				length = 1;
			case 'd':
			case 'u':
				hradix = 5;
				goto fixed;

			case 'O':
				length = 1;
			case 'o':
				hradix = 4;
				goto fixed;

			case 'X':
			case 'x':
				hradix = 8;

fixed:
				/* Establish default precision */
				if (prec < 0) {
					prec = 1;
				}

				/* Fetch the argument to be printed */
				if (double_length) {
					val = va_arg(*args, long long);
				} else if (length) {
					val = va_arg(*args, long);
				} else if (fcode == 'd') {
					val = va_arg(*args, int);
				} else {
					val = va_arg(*args, unsigned);
				}

				/* If signed conversion, establish sign */
				if (fcode == 'd' || fcode == 'D') {
					if (val < 0) {
						prefix = "-";
						/*
						 *	Negate, checking in
						 *	advance for possible
						 *	overflow.
						 */
						if (val != HIBITLL) {
							val = -val;
						}
					} else if (fplus) {
						prefix = "+";
					} else if (fblank) {
						prefix = " ";
					}
				}
#if FZERO
				if (fzero) {
					int n = width - strlen(prefix);
					if (n > prec) {
						prec = n;
					}
				}
#endif
				/* Set translate table for digits */
				if (fcode == 'X') {
					tab = "0123456789ABCDEF";
				} else {
					tab = "0123456789abcdef";
				}

				/* Develop the digits of the value */
				p = bp = buf + MAXDIGS;
				while (val) {
					lowbit = val & 1;
					val = (val >> 1) & ~HIBITLL;
					*--bp = tab[val % hradix * 2 + lowbit];
					val /= hradix;
				}

				/* Calculate padding zero requirement */
				lzero = bp - p + prec;

				/* Handle the # flag */
				if (fsharp && bp != p) {
					switch (fcode) {
					case 'o':
						if (lzero < 1)
							lzero = 1;
						break;
					case 'x':
						prefix = "0x";
						break;
					case 'X':
						prefix = "0X";
						break;
					}
				}

				break;
#if FLOAT
			case 'E':
			case 'e':
				/*
				 *	E-format.  The general strategy
				 *	here is fairly easy: we take
				 *	what ecvt gives us and re-format it.
				 */

				/* Establish default precision */
				if (prec < 0) {
					prec = 6;
				}

				/* Fetch the value */
				dval = va_arg(*args, double);

				/* Develop the mantissa */
				bp = ecvt(dval,
				    min(prec + 1, MAXECVT),
				    &decpt,
				    &sign);

				/* Determine the prefix */
e_merge:
				if (sign) {
					prefix = "-";
				} else if (fplus) {
					prefix = "+";
				} else if (fblank) {
					prefix = " ";
				}

				/* Place the first digit in the buffer */
				p = &buf[0];
				*p++ = *bp != '\0' ? *bp++ : '0';

				/* Put in a decimal point if needed */
				if (prec != 0 || fsharp) {
					*p++ = '.';
				}

				/* Create the rest of the mantissa */
				rzero = prec;
				while (rzero > 0 && *bp != '\0') {
					--rzero;
					*p++ = *bp++;
				}

				bp = &buf[0];

				/* Create the exponent */
				suffix = &expbuf[MAXESIZ];
				*suffix = '\0';
				if (dval != 0) {
					n = decpt - 1;
					if (n < 0) {
						n = -n;
					}
					while (n != 0) {
						*--suffix = todigit(n % 10);
						n /= 10;
					}
				}

				/* Prepend leading zeroes to the exponent */
				while (suffix > &expbuf[MAXESIZ - 2]) {
					*--suffix = '0';
				}

				/* Put in the exponent sign */
				*--suffix = (decpt > 0 || dval == 0) ?
				    '+' : '-';

				/* Put in the e */
				*--suffix = isupper(fcode) ? 'E' : 'e';

				break;

			case 'f':
				/*
				 *	F-format floating point.  This is
				 *	a good deal less simple than E-format.
				 *	The overall strategy will be to call
				 *	fcvt, reformat its result into buf,
				 *	and calculate how many trailing
				 *	zeroes will be required.  There will
				 *	never be any leading zeroes needed.
				 */

				/* Establish default precision */
				if (prec < 0) {
					prec = 6;
				}

				/* Fetch the value */
				dval = va_arg(*args, double);

				/* Do the conversion */
				bp = fcvt(dval,
				    min(prec, MAXFCVT),
				    &decpt,
				    &sign);

				/* Determine the prefix */
f_merge:
				if (sign && decpt > -prec &&
				    *bp != '\0' && *bp != '0') {
					prefix = "-";
				} else if (fplus) {
					prefix = "+";
				} else if (fblank) {
					prefix = " ";
				}

				/* Initialize buffer pointer */
				p = &buf[0];

				/* Emit the digits before the decimal point */
				n = decpt;
				k = 0;
				if (n <= 0) {
					*p++ = '0';
				} else {
					do {
						if (*bp == '\0' ||
						    k >= MAXFSIG) {
							*p++ = '0';
						} else {
							*p++ = *bp++;
							++k;
						}
					} while (--n != 0);
				}

				/* Decide whether we need a decimal point */
				if (fsharp || prec > 0) {
					*p++ = '.';
				}

				/* Digits (if any) after the decimal point */
				n = min(prec, MAXFCVT);
				rzero = prec - n;
				while (--n >= 0) {
					if (++decpt <= 0 || *bp == '\0' ||
					    k >= MAXFSIG) {
						*p++ = '0';
					} else {
						*p++ = *bp++;
						++k;
					}
				}

				bp = &buf[0];

				break;

			case 'G':
			case 'g':
				/*
				 *	g-format.  We play around a bit
				 *	and then jump into e or f, as needed.
				 */

				/* Establish default precision */
				if (prec < 0) {
					prec = 6;
				}

				/* Fetch the value */
				dval = va_arg(*args, double);

				/* Do the conversion */
				bp = ecvt(dval,
				    min(prec, MAXECVT),
				    &decpt,
				    &sign);
				if (dval == 0) {
					decpt = 1;
				}

				k = prec;
				if (!fsharp) {
					n = strlen(bp);
					if (n < k) {
						k = n;
					}
					while (k >= 1 && bp[k-1] == '0') {
						--k;
					}
				}

				if (decpt < -3 || decpt > prec) {
					prec = k - 1;
					goto e_merge;
				} else {
					prec = k - decpt;
					goto f_merge;
				}

#endif
			case 'c':
#ifdef MBCHAR_1 /* sizeof(int)>=sizeof(tchar) */
/*
 * A tchar arg is passed as int so we used the normal %c to specify
 * such an arugument.
 */
				tcbuf[0] = va_arg(*args, int);
				tbp = &tcbuf[0];
				tep = tbp + 1;
				fcode = 't'; /* Fake the rest of code. */
				break;
#else
/*
 * We would have to invent another new format speficier such as "%T" to
 * take a tchar arg.  Let's worry about when that time comes.
 */
				/*
				 * Following code take care of a char arg
				 * only.
				 */
				buf[0] = va_arg(*args, int);
				bp = &buf[0];
				p = bp + 1;
				break;
			case 'T': /* Corresponding arg is tchar. */
				tcbuf[0] = va_arg(*args, tchar);
				tbp = &tcbuf[0];
				tep = tbp + 1;
				fcode = 't'; /* Fake the rest of code. */
				break;
#endif
			case 's':
				bp = va_arg(*args, char *);
				if (bp == 0) {
nullstr:				bp = "(null)";
					p = bp + strlen("(null)");
					break;
				}
				if (prec < 0) {
					prec = MAXINT;
				}
				for (n = 0; *bp++ != '\0' && n < prec; n++)
					;
				p = --bp;
				bp -= n;
				break;

			case 't':
				/*
				 * Special format specifier "%t" tells
				 * printf() to print char strings written
				 * as tchar string.
				 */
				tbp = va_arg(*args, tchar *);
				if (tbp == 0) {
					fcode = 's'; /* Act as if it were %s. */
					goto nullstr;
				}
				if (prec < 0) {
					prec = MAXINT;
				}
				for (n = 0; *tbp++ != 0 && n < prec; n++)
					;
				tep = --tbp;
				tbp -= n;

				/*
				 * Just to make the following padding
				 * calculation not to go very crazy...
				 */
				bp = NULL;
				p = bp + n;
				break;

			case '\0':
				cp--;
				break;

			default:
				p = bp = &fcode;
				p++;
				break;

			}
			if (fcode != '\0') {
				/* Calculate number of padding blanks */
				int nblank;
				nblank = width
#if FLOAT
					- (rzero < 0 ? 0:  rzero)
					- strlen(suffix)
#endif
					- (p - bp)
					- (lzero < 0 ? 0 : lzero)
					- strlen(prefix);

				/* Blanks on left if required */
				if (!fminus) {
					while (--nblank >= 0) {
						Putchar(' ');
					}
				}

				/* Prefix, if any */
				while (*prefix != '\0') {
					Putchar(*prefix++);
				}

				/* Zeroes on the left */
				while (--lzero >= 0) {
					Putchar('0');
				}

				/* The value itself */
				if (fcode == 't') {	/* %t is special. */
					while (tbp < tep) {
					    Putchar(*tbp++);
					}
				} else {	/* For rest of the cases. */
					while (bp < p) {
					    putbyte(*bp++);
					}
				}
#if FLOAT
				/* Zeroes on the right */
				while (--rzero >= 0)
					Putchar('0');

				/* The suffix */
				while (*suffix != '\0') {
					Putchar(*suffix++);
				}
#endif
				/* Blanks on the right if required */
				if (fminus) {
					while (--nblank >= 0) {
						Putchar(' ');
					}
				}
			}
		}
}

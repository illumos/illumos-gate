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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	_doprnt: common code for printf, fprintf, sprintf
 */

#include <sys/types.h>
#include "file64.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <values.h>
#include <nan.h>
#include <memory.h>
#include <string.h>
#include "print.h"	/* parameters & macros for doprnt */
#include "stdiom.h"
#include <locale.h>
#include <stddef.h>
#include "_locale.h"
#include "libc.h"

#define	PUT(p, n)	{ unsigned char *newbufptr; \
			if ((newbufptr = bufptr + (n)) > bufferend) { \
				_dowrite((p), (n), iop, &bufptr); \
			} else { \
				(void) memcpy(bufptr, (p), (n)); \
				bufptr = newbufptr; \
			} \
			}
#define	PAD(s, n)	{ int nn; \
			for (nn = (n); nn > 20; nn -= 20) \
				_dowrite((s), 20, iop, &bufptr); \
			PUT((s), nn); \
			}

#define	SNLEN	5	/* Length of string used when printing a NaN */

/* bit positions for flags used in doprnt */

#define	LENGTH	1	/* l */
#define	FPLUS	2	/* + */
#define	FMINUS	  4	/* - */
#define	FBLANK	  8	/* blank */
#define	FSHARP	 16	/* # */
#define	PADZERO  32	/* padding zeroes requested via '0' */
#define	DOTSEEN  64	/* dot appeared in format specification */
#define	SUFFIX	128	/* a suffix is to appear in the output */
#define	RZERO	256	/* there will be trailing zeros in output */
#define	LZERO	512	/* there will be leading zeroes in output */
#define	SHORT  1024	/* h */

/*
 *	Positional Parameter information
 */
#define	MAXARGS	30	/* max. number of args for fast positional paramters */

/*
 * stva_list is used to subvert C's restriction that a variable with an
 * array type can not appear on the left hand side of an assignment operator.
 * By putting the array inside a structure, the functionality of assigning to
 * the whole array through a simple assignment is achieved..
 */
typedef struct stva_list {
	va_list	ap;
} stva_list;

static char _blanks[] = "                    ";
static char _zeroes[] = "00000000000000000000";
static char uc_digs[] = "0123456789ABCDEF";
static char lc_digs[] = "0123456789abcdef";
static char  lc_nan[] = "nan0x";
static char  uc_nan[] = "NAN0X";
static char  lc_inf[] = "inf";
static char  uc_inf[] = "INF";

/*
 * forward declarations
 */
void _mkarglst(char *, stva_list, stva_list []);
void _getarg(char *, stva_list *, int);
static int _lowdigit(long *);
static void _dowrite(char *, ssize_t, FILE *, unsigned char **);

static int
_lowdigit(long *valptr)
{	/* This function computes the decimal low-order digit of the number */
	/* pointed to by valptr, and returns this digit after dividing   */
	/* *valptr by ten.  This function is called ONLY to compute the */
	/* low-order digit of a long whose high-order bit is set. */

	int lowbit = (int)(*valptr & 1);
	long value = (*valptr >> 1) & ~HIBITL;

	*valptr = value / 5;
	return ((int)(value % 5 * 2 + lowbit + '0'));
}

/* The function _dowrite carries out buffer pointer bookkeeping surrounding */
/* a call to fwrite.  It is called only when the end of the file output */
/* buffer is approached or in other unusual situations. */
static void
_dowrite(char *p, ssize_t n, FILE *iop, unsigned char **ptrptr)
{
	if (!(iop->_flag & _IOREAD)) {
		iop->_cnt -= (*ptrptr - iop->_ptr);
		iop->_ptr = *ptrptr;
		_bufsync(iop, _bufend(iop));
		(void) fwrite(p, 1, n, iop);
		*ptrptr = iop->_ptr;
	} else
		*ptrptr = (unsigned char *) memcpy(*ptrptr, p, n) + n;
}

int
_doprnt(char *format, va_list in_args, FILE *iop)
{

	/* bufptr is used inside of doprnt instead of iop->_ptr; */
	/* bufferend is a copy of _bufend(iop), if it exists.  For */
	/* dummy file descriptors (iop->_flag & _IOREAD), bufferend */
	/* may be meaningless. Dummy file descriptors are used so that */
	/* sprintf and vsprintf may share the _doprnt routine with the */
	/* rest of the printf family. */

	unsigned char *bufptr;
	unsigned char *bufferend;

	/* This variable counts output characters. */
	int	count = 0;

	/* Starting and ending points for value to be printed */
	char	*bp;
	char	*p;

	/* Field width and precision */
	int	width, prec;

	/* Format code */
	int	fcode;

	/* Number of padding zeroes required on the left and right */
	int	lzero, rzero;

	/* Flags - bit positions defined by LENGTH, FPLUS, FMINUS, FBLANK, */
	/* and FSHARP are set if corresponding character is in format */
	/* Bit position defined by PADZERO means extra space in the field */
	/* should be padded with leading zeroes rather than with blanks */
	int	flagword;

	/* Values are developed in this buffer */
	char	buf[max(MAXDIGS, 1+max(MAXFCVT+MAXEXP, MAXECVT))];

	/* Pointer to sign, "0x", "0X", or empty */
	char	*prefix;

	/* Exponent or empty */
	char	*suffix;

	/* Buffer to create exponent */
	char	expbuf[MAXESIZ + 1];

	/* Length of prefix and of suffix */
	int	prefixlength, suffixlength;

	/* Combined length of leading zeroes, trailing zeroes, and suffix */
	int 	otherlength;

	/* The value being converted, if integer */
	long	val;

	/* The value being converted, if real */
	double	dval;

	/* Output values from fcvt and ecvt */
	int	decpt, sign;

	/* Pointer to a translate table for digits of whatever radix */
	char	*tab;

	/* Work variables */
	int	k, lradix, mradix;

	/* Variables used to flag an infinities and nans, resp. */
	/* Nan_flg is used with two purposes: to flag a NaN and */
	/* as the length of the string ``NAN0X'' (``nan0x'') */
	int	 inf_nan = 0, NaN_flg = 0;

	/* Pointer to string "NAN0X" or "nan0x" */
	char	 *SNAN;

	/* Flag for negative infinity or NaN */
	int neg_in = 0;

	/* variables for positional parameters */
	char	*sformat = format;	/* save the beginning of the format */
	int	fpos = 1;		/* 1 if first positional parameter */
	stva_list args;		/* used to step through the argument list */
	stva_list sargs;
		/* used to save the start of the argument list */
	stva_list bargs;
		/* used to restore args if positional width or precision */
	stva_list arglst[MAXARGS];
		/*
		 * array giving the appropriate values for va_arg() to
		 * retrieve the corresponding argument:
		 * arglst[0] is the first argument,
		 * arglst[1] is the second argument, etc.
		 */
	int	starflg = 0;	/* set to 1 if * format specifier seen */
	/*
	 * Initialize args and sargs to the start of the argument list.
	 * Note that ANSI guarantees that the address of the first member of
	 * a structure will be the same as the address of the structure.
	 * See equivalent code in libc doprnt.c
	 */

#if !(defined(__amd64) && defined(__GNUC__))	/* XX64 - fix me */
	va_copy(args.ap, in_args);
#endif
	sargs = args;

	/* if first I/O to the stream get a buffer */
	/* Note that iop->_base should not equal 0 for sprintf and vsprintf */
	if (iop->_base == 0 && _findbuf(iop) == 0)
		return (EOF);

	/* initialize buffer pointer and buffer end pointer */
	bufptr = iop->_ptr;
	bufferend = (iop->_flag & _IOREAD) ?
	    (unsigned char *)((long)bufptr | (-1L & ~HIBITL))
	    : _bufend(iop);

	/*
	 *	The main loop -- this loop goes through one iteration
	 *	for each string of ordinary characters or format specification.
	 */
	for (;;) {
		ptrdiff_t pdiff;

		if ((fcode = *format) != '\0' && fcode != '%') {
			bp = format;
			do {
				format++;
			} while ((fcode = *format) != '\0' && fcode != '%');

			pdiff = format - bp;
				/* pdiff = no. of non-% chars */
			count += pdiff;
			PUT(bp, pdiff);
		}
		if (fcode == '\0') {  /* end of format; return */
			ptrdiff_t d = bufptr - iop->_ptr;
			iop->_cnt -= d;
			iop->_ptr = bufptr;
			if (bufptr + iop->_cnt > bufferend &&
			    !(iop->_flag & _IOREAD))
				_bufsync(iop, bufferend);
				/*
				 * in case of interrupt during last
				 * several lines
				 */
			if (iop->_flag & (_IONBF | _IOLBF) &&
			    (iop->_flag & _IONBF ||
			    memchr((char *)(bufptr-count), '\n', count) !=
			    NULL))
				(void) _xflsbuf(iop);
			return (ferror(iop) ? EOF : count);
		}

		/*
		 *	% has been found.
		 *	The following switch is used to parse the format
		 *	specification and to perform the operation specified
		 *	by the format letter.  The program repeatedly goes
		 *	back to this switch until the format letter is
		 *	encountered.
		 */
		width = prefixlength = otherlength = flagword =
		    suffixlength = 0;
		format++;

	charswitch:

		switch (fcode = *format++) {

		case '+':
			flagword |= FPLUS;
			goto charswitch;
		case '-':
			flagword |= FMINUS;
			flagword &= ~PADZERO; /* ignore 0 flag */
			goto charswitch;
		case ' ':
			flagword |= FBLANK;
			goto charswitch;
		case '#':
			flagword |= FSHARP;
			goto charswitch;

		/* Scan the field width and precision */
		case '.':
			flagword |= DOTSEEN;
			prec = 0;
			goto charswitch;

		case '*':
			if (isdigit(*format)) {
				starflg = 1;
				bargs = args;
				goto charswitch;
			}
			if (!(flagword & DOTSEEN)) {
				width = va_arg(args.ap, int);
				if (width < 0) {
					width = -width;
					flagword ^= FMINUS;
				}
			} else {
				prec = va_arg(args.ap, int);
				if (prec < 0)
					prec = 0;
			}
			goto charswitch;

		case '$':
			{
			int		position;
			stva_list	targs;
			if (fpos) {
				_mkarglst(sformat, sargs, arglst);
				fpos = 0;
			}
			if (flagword & DOTSEEN) {
				position = prec;
				prec = 0;
			} else {
				position = width;
				width = 0;
			}
			if (position <= 0) {
				/* illegal position */
				format--;
				continue;
			}
			if (position <= MAXARGS) {
				targs = arglst[position - 1];
			} else {
				targs = arglst[MAXARGS - 1];
				_getarg(sformat, &targs, position);
			}
			if (!starflg)
				args = targs;
			else {
				starflg = 0;
				args = bargs;
				if (flagword & DOTSEEN)
					prec = va_arg(targs.ap, int);
				else
					width = va_arg(targs.ap, int);
			}
			goto charswitch;
			}

		case '0':	/* obsolescent spec:  leading zero in width */
				/* means pad with leading zeros */
			if (!(flagword & (DOTSEEN | FMINUS)))
				flagword |= PADZERO;
			/* FALLTHROUGH */
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			{
				int num = fcode - '0';
				while (isdigit(fcode = *format)) {
					num = num * 10 + fcode - '0';
					format++;
				}
				if (flagword & DOTSEEN)
					prec = num;
				else
					width = num;
				goto charswitch;
			}

		/* Scan the length modifier */
		case 'l':
			flagword |= LENGTH;
			goto charswitch;
		case 'h':
			flagword |= SHORT;
			goto charswitch;
		case 'L':
			goto charswitch;

		/*
		 *	The character addressed by format must be
		 *	the format letter -- there is nothing
		 *	left for it to be.
		 *
		 *	The status of the +, -, #, and blank
		 *	flags are reflected in the variable
		 *	"flagword".  "width" and "prec" contain
		 *	numbers corresponding to the digit
		 *	strings before and after the decimal
		 *	point, respectively. If there was no
		 *	decimal point, then flagword & DOTSEEN
		 *	is false and the value of prec is meaningless.
		 *
		 *	The following switch cases set things up
		 *	for printing.  What ultimately gets
		 *	printed will be padding blanks, a
		 *	prefix, left padding zeroes, a value,
		 *	right padding zeroes, a suffix, and
		 *	more padding blanks.  Padding blanks
		 *	will not appear simultaneously on both
		 *	the left and the right.  Each case in
		 *	this switch will compute the value, and
		 *	leave in several variables the informa-
		 *	tion necessary to construct what is to
		 *	be printed.
		 *
		 *	The prefix is a sign, a blank, "0x",
		 *	"0X", or null, and is addressed by
		 *	"prefix".
		 *
		 *	The suffix is either null or an
		 *	exponent, and is addressed by "suffix".
		 *	If there is a suffix, the flagword bit
		 *	SUFFIX will be set.
		 *
		 *	The value to be printed starts at "bp"
		 *	and continues up to and not including
		 *	"p".
		 *
		 *	"lzero" and "rzero" will contain the
		 *	number of padding zeroes required on
		 *	the left and right, respectively.
		 *	The flagword bits LZERO and RZERO tell
		 *	whether padding zeros are required.
		 *
		 *	The number of padding blanks, and
		 *	whether they go on the left or the
		 *	right, will be computed on exit from
		 *	the switch.
		 */




		/*
		 *	decimal fixed point representations
		 *
		 *	HIBITL is 100...000
		 *	binary, and is equal to	the maximum
		 *	negative number.
		 *	We assume a 2's complement machine
		 */

		case 'i':
		case 'd':
			/* Fetch the argument to be printed */
			if (flagword & LENGTH)
				val = va_arg(args.ap, long);
			else
				val = va_arg(args.ap, int);

			if (flagword & SHORT)
				val = (short)val;

			/* Set buffer pointer to last digit */
			p = bp = buf + MAXDIGS;

			/* If signed conversion, make sign */
			if (val < 0) {
				prefix = "-";
				prefixlength = 1;
				/*
				 * Negate, checking in
				 * advance for possible
				 * overflow.
				 */
				if (val != HIBITL)
					val = -val;
				else	/* number is -HIBITL; convert last */
					/* digit now and get positive number */
					*--bp = _lowdigit(&val);
			} else if (flagword & FPLUS) {
				prefix = "+";
				prefixlength = 1;
			} else if (flagword & FBLANK) {
				prefix = " ";
				prefixlength = 1;
			}

		decimal:
			{
				long qval = val;
				long saveq;

				if (qval <= 9) {
					if (qval != 0 || !(flagword & DOTSEEN))
						*--bp = (char)(qval + '0');
				} else {
					do {
						saveq = qval;
						qval /= 10;
						*--bp = (char)(saveq -
						    qval * 10 + '0');
					} while (qval > 9);
					*--bp = (char)(qval + '0');
					pdiff = (ptrdiff_t)saveq;
				}
			}

			/* Calculate minimum padding zero requirement */
			if (flagword & DOTSEEN) {
				int leadzeroes = prec - (int)(p - bp);
				if (leadzeroes > 0) {
					otherlength = lzero = leadzeroes;
					flagword |= LZERO;
				}
			}

			break;

		case 'u':
			/* Fetch the argument to be printed */
			if (flagword & LENGTH)
				val = va_arg(args.ap, long);
			else
				val = va_arg(args.ap, unsigned);

			if (flagword & SHORT)
				val = (unsigned short)val;

			p = bp = buf + MAXDIGS;

			if (val & HIBITL)
				*--bp = _lowdigit(&val);

			goto decimal;

		/*
		 *	non-decimal fixed point representations
		 *	for radix equal to a power of two
		 *
		 *	"mradix" is one less than the radix for the conversion.
		 *	"lradix" is one less than the base 2 log
		 *	of the radix for the conversion. Conversion is unsigned.
		 *	HIBITL is 100...000
		 *	binary, and is equal to	the maximum
		 *	negative number.
		 *	We assume a 2's complement machine
		 */

		case 'o':
			mradix = 7;
			lradix = 2;
			goto fixed;

		case 'X':
		case 'x':
		case 'p':
			mradix = 15;
			lradix = 3;

		fixed:
			/* Fetch the argument to be printed */
			if (flagword & LENGTH)
				val = va_arg(args.ap, long);
			else
				val = va_arg(args.ap, unsigned);

			if (flagword & SHORT)
				val = (unsigned short)val;

			/* Set translate table for digits */
			tab = (fcode == 'X') ? uc_digs : lc_digs;

			/* Entry point when printing a double which is a NaN */
		put_pc:
			/* Develop the digits of the value */
			p = bp = buf + MAXDIGS;
			{
				long qval = val;
				if (qval == 0) {
					if (!(flagword & DOTSEEN)) {
						otherlength = lzero = 1;
						flagword |= LZERO;
					}
				} else
					do {
						*--bp = tab[qval & mradix];
						qval = ((qval >> 1) & ~HIBITL)
						    >> lradix;
					} while (qval != 0);
			}

			/* Calculate minimum padding zero requirement */
			if (flagword & DOTSEEN) {
				int leadzeroes = prec - (int)(p - bp);
				if (leadzeroes > 0) {
					otherlength = lzero = leadzeroes;
					flagword |= LZERO;
				}
			}

			/* Handle the # flag */
			if (flagword & FSHARP && val != 0)
				switch (fcode) {
				case 'o':
					if (!(flagword & LZERO)) {
						otherlength = lzero = 1;
						flagword |= LZERO;
					}
					break;
				case 'x':
					prefix = "0x";
					prefixlength = 2;
					break;
				case 'X':
					prefix = "0X";
					prefixlength = 2;
					break;
				}

			break;

		case 'E':
		case 'e':
			/*
			 * E-format.  The general strategy
			 * here is fairly easy: we take
			 * what ecvt gives us and re-format it.
			 */

			/* Establish default precision */
			if (!(flagword & DOTSEEN))
				prec = 6;

			/* Fetch the value */
			dval = va_arg(args.ap, double);

			/* Check for NaNs and Infinities */
			if (IsNANorINF(dval)) {
				if (IsINF(dval)) {
					if (IsNegNAN(dval))
						neg_in = 1;
					inf_nan = 1;
					bp = (fcode == 'E')? uc_inf: lc_inf;
					p = bp + 3;
					break;
				} else {
					if (IsNegNAN(dval))
						neg_in = 1;
					inf_nan = 1;
					val = GETNaNPC(dval);
					NaN_flg = SNLEN;
					mradix = 15;
					lradix = 3;
					if (fcode == 'E') {
						SNAN = uc_nan;
						tab =  uc_digs;
					} else {
						SNAN =  lc_nan;
						tab =  lc_digs;
					}
					goto put_pc;
				}
			}
			/* Develop the mantissa */
			bp = ecvt(dval, min(prec + 1, MAXECVT), &decpt, &sign);

			/* Determine the prefix */
		e_merge:
			if (sign) {
				prefix = "-";
				prefixlength = 1;
			} else if (flagword & FPLUS) {
				prefix = "+";
				prefixlength = 1;
			} else if (flagword & FBLANK) {
				prefix = " ";
				prefixlength = 1;
			}

			/* Place the first digit in the buffer */
			p = &buf[0];
			*p++ = (*bp != '\0') ? *bp++ : '0';

			/* Put in a decimal point if needed */
			if (prec != 0 || (flagword & FSHARP))
				*p++ = _numeric[0];

			/* Create the rest of the mantissa */
			{
				int rz = prec;
				for (; rz > 0 && *bp != '\0'; --rz)
					*p++ = *bp++;
				if (rz > 0) {
					otherlength = rzero = rz;
					flagword |= RZERO;
				}
			}

			bp = &buf[0];

			/* Create the exponent */
			*(suffix = &expbuf[MAXESIZ]) = '\0';
			if (dval != 0) {
				int nn = decpt - 1;
				if (nn < 0)
					nn = -nn;
				for (; nn > 9; nn /= 10)
					*--suffix = todigit(nn % 10);
				*--suffix = todigit(nn);
			}

			/* Prepend leading zeroes to the exponent */
			while (suffix > &expbuf[MAXESIZ - 2])
				*--suffix = '0';

			/* Put in the exponent sign */
			*--suffix = (decpt > 0 || dval == 0) ? '+' : '-';

			/* Put in the e */
			*--suffix = isupper(fcode) ? 'E'  : 'e';

			/* compute size of suffix */
			otherlength += (suffixlength =
			    (int)(&expbuf[MAXESIZ] - suffix));
			flagword |= SUFFIX;

			break;

		case 'f':
			/*
			 * F-format floating point.  This is a
			 * good deal less simple than E-format.
			 * The overall strategy will be to call
			 * fcvt, reformat its result into buf,
			 * and calculate how many trailing
			 * zeroes will be required.  There will
			 * never be any leading zeroes needed.
			 */

			/* Establish default precision */
			if (!(flagword & DOTSEEN))
				prec = 6;

			/* Fetch the value */
			dval = va_arg(args.ap, double);

			/* Check for NaNs and Infinities  */
			if (IsNANorINF(dval)) {
				if (IsINF(dval)) {
					if (IsNegNAN(dval))
						neg_in = 1;
					inf_nan = 1;
					bp = lc_inf;
					p = bp + 3;
					break;
				} else {
					if (IsNegNAN(dval))
						neg_in = 1;
					inf_nan = 1;
					val  = GETNaNPC(dval);
					NaN_flg = SNLEN;
					mradix = 15;
					lradix = 3;
					tab =  lc_digs;
					SNAN = lc_nan;
					goto put_pc;
				}
			}
			/* Do the conversion */
			bp = fcvt(dval, min(prec, MAXFCVT), &decpt, &sign);

			/* Determine the prefix */
		f_merge:
			if (sign) {
				prefix = "-";
				prefixlength = 1;
			} else if (flagword & FPLUS) {
				prefix = "+";
				prefixlength = 1;
			} else if (flagword & FBLANK) {
				prefix = " ";
				prefixlength = 1;
			}

			/* Initialize buffer pointer */
			p = &buf[0];
			{
				int nn = decpt;

				/* Emit the digits before the decimal point */
				k = 0;
				do {
					*p++ = (nn <= 0 || *bp == '\0' ||
					    k >= MAXFSIG) ?
					    '0' : (k++, *bp++);
				} while (--nn > 0);

				/* Decide whether we need a decimal point */
				if ((flagword & FSHARP) || prec > 0)
					*p++ = _numeric[0];

				/* Digits (if any) after the decimal point */
				nn = min(prec, MAXFCVT);
				if (prec > nn) {
					flagword |= RZERO;
					otherlength = rzero = prec - nn;
				}
				while (--nn >= 0)
					*p++ = (++decpt <= 0 || *bp == '\0' ||
					    k >= MAXFSIG) ?
					    '0' : (k++, *bp++);
			}

			bp = &buf[0];

			break;

		case 'G':
		case 'g':
			/*
			 * g-format.  We play around a bit
			 * and then jump into e or f, as needed.
			 */

			/* Establish default precision */
			if (!(flagword & DOTSEEN))
				prec = 6;
			else if (prec == 0)
				prec = 1;

			/* Fetch the value */
			dval = va_arg(args.ap, double);

			/* Check for NaN and Infinities  */
			if (IsNANorINF(dval)) {
				if (IsINF(dval)) {
					if (IsNegNAN(dval))
						neg_in = 1;
					bp = (fcode == 'G') ? uc_inf : lc_inf;
					p = bp + 3;
					inf_nan = 1;
					break;
				} else {
					if (IsNegNAN(dval))
						neg_in = 1;
					inf_nan = 1;
					val  = GETNaNPC(dval);
					NaN_flg = SNLEN;
					mradix = 15;
					lradix = 3;
					if (fcode == 'G') {
						SNAN = uc_nan;
						tab = uc_digs;
					} else {
						SNAN = lc_nan;
						tab =  lc_digs;
					}
					goto put_pc;
				}
			}

			/* Do the conversion */
			bp = ecvt(dval, min(prec, MAXECVT), &decpt, &sign);
			if (dval == 0)
				decpt = 1;
			{
				int kk = prec;
				size_t sz;

				if (!(flagword & FSHARP)) {
					sz = strlen(bp);
					if (sz < kk)
						kk = (int)sz;
					while (kk >= 1 && bp[kk-1] == '0')
						--kk;
				}

				if (decpt < -3 || decpt > prec) {
					prec = kk - 1;
					goto e_merge;
				}
				prec = kk - decpt;
				goto f_merge;
			}

		case '%':
			buf[0] = (char)fcode;
			goto c_merge;

		case 'c':
			buf[0] = va_arg(args.ap, int);
		c_merge:
			p = (bp = &buf[0]) + 1;
			break;

		case 's':
			bp = va_arg(args.ap, char *);
			if (!(flagword & DOTSEEN))
				p = bp + strlen(bp);
			else { /* a strnlen function would  be useful here! */
				char *qp = bp;
				while (*qp++ != '\0' && --prec >= 0)
					;
				p = qp - 1;
			}
			break;

		case 'n':
			{
				if (flagword & LENGTH) {
					long *svcount;
					svcount = va_arg(args.ap, long *);
					*svcount = count;
				} else if (flagword & SHORT) {
					short *svcount;
					svcount = va_arg(args.ap, short *);
					*svcount = (short)count;
				} else {
					int *svcount;
					svcount = va_arg(args.ap, int *);
					*svcount = count;
				}
				continue;
			}

		default: /* this is technically an error; what we do is to */
			/* back up the format pointer to the offending char */
			/* and continue with the format scan */
			format--;
			continue;

		}

		if (inf_nan) {
			if (neg_in) {
				prefix = "-";
				prefixlength = 1;
				neg_in = 0;
			} else if (flagword & FPLUS) {
				prefix = "+";
				prefixlength = 1;
			} else if (flagword & FBLANK) {
				prefix = " ";
				prefixlength = 1;
			}
			inf_nan = 0;
		}

		/* Calculate number of padding blanks */
		k = (int)(pdiff = p - bp) + prefixlength + otherlength +
		    NaN_flg;
		if (width <= k)
			count += k;
		else {
			count += width;

			/* Set up for padding zeroes if requested */
			/* Otherwise emit padding blanks unless output is */
			/* to be left-justified.  */

			if (flagword & PADZERO) {
				if (!(flagword & LZERO)) {
					flagword |= LZERO;
					lzero = width - k;
				}
				else
					lzero += width - k;
				k = width; /* cancel padding blanks */
			} else
				/* Blanks on left if required */
				if (!(flagword & FMINUS))
					PAD(_blanks, width - k);
		}

		/* Prefix, if any */
		if (prefixlength != 0)
			PUT(prefix, prefixlength);

		/* If value is NaN, put string NaN */
		if (NaN_flg) {
			PUT(SNAN, SNLEN);
			NaN_flg = 0;
		}

		/* Zeroes on the left */
		if (flagword & LZERO)
			PAD(_zeroes, lzero);

		/* The value itself */
		if (pdiff > 0)
			PUT(bp, pdiff);

		if (flagword & (RZERO | SUFFIX | FMINUS)) {
			/* Zeroes on the right */
			if (flagword & RZERO)
				PAD(_zeroes, rzero);

			/* The suffix */
			if (flagword & SUFFIX)
				PUT(suffix, suffixlength);

			/* Blanks on the right if required */
			if (flagword & FMINUS && width > k)
				PAD(_blanks, width - k);
		}
	}
}

/*
 * This function initializes arglst, to contain the appropriate va_list values
 * for the first MAXARGS arguments.
 */
void
_mkarglst(char *fmt, stva_list args, stva_list arglst[])
{
	static char digits[] = "01234567890", skips[] = "# +-.0123456789hL$";

	enum types {INT = 1, LONG, CHAR_PTR, DOUBLE, LONG_DOUBLE, VOID_PTR,
		LONG_PTR, INT_PTR};
	enum types typelst[MAXARGS], curtype;
	int maxnum, n, curargno, flags;

	/*
	 * Algorithm	1. set all argument types to zero.
	 *		2. walk through fmt putting arg types in typelst[].
	 *		3. walk through args using va_arg(args.ap, typelst[n])
	 *		   and set arglst[] to the appropriate values.
	 * Assumptions:	Cannot use %*$... to specify variable position.
	 */

	(void) memset((void *)typelst, 0, sizeof (typelst));
	maxnum = -1;
	curargno = 0;
	while ((fmt = strchr(fmt, '%')) != 0) {
		size_t sz;

		fmt++;	/* skip % */
		if (fmt[sz = strspn(fmt, digits)] == '$') {
			curargno = atoi(fmt) - 1;
				/* convert to zero base */
			if (curargno < 0)
				continue;
			fmt += sz + 1;
		}
		flags = 0;
	again:;
		fmt += strspn(fmt, skips);
		switch (*fmt++) {
		case '%':	/* there is no argument! */
			continue;
		case 'l':
			flags |= 0x1;
			goto again;
		case '*':	/* int argument used for value */
			/* check if there is a positional parameter */
			if (isdigit(*fmt)) {
				int	targno;
				targno = atoi(fmt) - 1;
				fmt += strspn(fmt, digits);
				if (*fmt == '$')
					fmt++; /* skip '$' */
				if (targno >= 0 && targno < MAXARGS) {
					typelst[targno] = INT;
					if (maxnum < targno)
						maxnum = targno;
				}
				goto again;
			}
			flags |= 0x2;
			curtype = INT;
			break;
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			curtype = DOUBLE;
			break;
		case 's':
			curtype = CHAR_PTR;
			break;
		case 'p':
			curtype = VOID_PTR;
			break;
		case 'n':
			if (flags & 0x1)
				curtype = LONG_PTR;
			else
				curtype = INT_PTR;
			break;
		default:
			if (flags & 0x1)
				curtype = LONG;
			else
				curtype = INT;
			break;
		}
		if (curargno >= 0 && curargno < MAXARGS) {
			typelst[curargno] = curtype;
			if (maxnum < curargno)
				maxnum = curargno;
		}
		curargno++;	/* default to next in list */
		if (flags & 0x2)	/* took care of *, keep going */
		{
			flags ^= 0x2;
			goto again;
		}
	}
	for (n = 0; n <= maxnum; n++) {
		arglst[n] = args;
		if (typelst[n] == 0)
			typelst[n] = INT;

		switch (typelst[n]) {
		case INT:
			(void) va_arg(args.ap, int);
			break;
		case LONG:
			(void) va_arg(args.ap, long);
			break;
		case CHAR_PTR:
			(void) va_arg(args.ap, char *);
			break;
		case DOUBLE:
			(void) va_arg(args.ap, double);
			break;
		case LONG_DOUBLE:
			(void) va_arg(args.ap, double);
			break;
		case VOID_PTR:
			(void) va_arg(args.ap, void *);
			break;
		case LONG_PTR:
			(void) va_arg(args.ap, long *);
			break;
		case INT_PTR:
			(void) va_arg(args.ap, int *);
			break;
		}
	}
}

/*
 * This function is used to find the va_list value for arguments whose
 * position is greater than MAXARGS.  This function is slow, so hopefully
 * MAXARGS will be big enough so that this function need only be called in
 * unusual circumstances.
 * pargs is assumed to contain the value of arglst[MAXARGS - 1].
 */
void
_getarg(char *fmt, stva_list *pargs, int argno)
{
	static char digits[] = "01234567890", skips[] = "# +-.0123456789h$";
	int i, curargno, flags;
	size_t n;
	char	*sfmt = fmt;
	int	found = 1;

	i = MAXARGS;
	curargno = 1;
	while (found) {
		fmt = sfmt;
		found = 0;
		while ((i != argno) && (fmt = strchr(fmt, '%')) != 0) {
			fmt++;	/* skip % */
			if (fmt[n = strspn(fmt, digits)] == '$') {
				curargno = atoi(fmt);
				if (curargno <= 0)
					continue;
				fmt += n + 1;
			}

			/* find conversion specifier for next argument */
			if (i != curargno) {
				curargno++;
				continue;
			} else
				found = 1;
			flags = 0;
		again:;
			fmt += strspn(fmt, skips);
			switch (*fmt++) {
			case '%':	/* there is no argument! */
				continue;
			case 'l':
				flags |= 0x1;
				goto again;
			case '*':	/* int argument used for value */
				/*
				 * check if there is a positional parameter;
				 * if so, just skip it; its size will be
				 * correctly determined by default
				 */
				if (isdigit(*fmt)) {
					fmt += strspn(fmt, digits);
					if (*fmt == '$')
						fmt++; /* skip '$' */
					goto again;
				}
				flags |= 0x2;
				(void) va_arg((*pargs).ap, int);
				break;
			case 'e':
			case 'E':
			case 'f':
			case 'g':
			case 'G':
				if (flags & 0x1)
					(void) va_arg((*pargs).ap, double);
				else
					(void) va_arg((*pargs).ap, double);
				break;
			case 's':
				(void) va_arg((*pargs).ap, char *);
				break;
			case 'p':
				(void) va_arg((*pargs).ap, void *);
				break;
			case 'n':
				if (flags & 0x1)
					(void) va_arg((*pargs).ap, long *);
				else
					(void) va_arg((*pargs).ap, int *);
				break;
			default:
				if (flags & 0x1)
					(void) va_arg((*pargs).ap, long int);
				else
					(void) va_arg((*pargs).ap, int);
				break;
			}
			i++;
			curargno++;	/* default to next in list */
			if (flags & 0x2)	/* took care of *, keep going */
			{
				flags ^= 0x2;
				goto again;
			}
		}

		/*
		 * missing specifier for parameter, assume parameter is an int
		 */
		if (!found && i != argno) {
			(void) va_arg((*pargs).ap, int);
			i++;
			curargno = i;
			found = 1;
		}
	}
}

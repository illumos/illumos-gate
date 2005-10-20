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

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	_doprnt: common code for printf, fprintf, sprintf
 *	Floating-point code is included or not, depending
 *	on whether the preprocessor variable FLOAT is 1 or 0.
 */
#define MAXARGS 50
#ifndef FLOAT
#define	FLOAT	1	/* YES! we want floating */
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <values.h>
#include <locale.h>
#include "doprnt.h"
#include "stdiom.h"
#include <string.h>	/* strchr, strlen, strspn */

#define max(a,b)	((a) > (b) ? (a) : (b))
#define min(a,b)	((a) < (b) ? (a) : (b))

/* If this symbol is nonzero, allow '0' as a flag */
/* If this symbol is nonzero, allow '0' as a flag */
#define FZERO 1

#if FLOAT
/*
 *	libc/gen/common functions for floating-point conversion
 */
#include <floatingpoint.h>
extern void _fourdigitsquick();
#endif

#define emitchar(c)   { if (--filecnt < 0) { \
				FILE *iop = file; \
				if (((iop->_flag & (_IOLBF|_IONBF)) == 0 \
				    || -filecnt >= iop->_bufsiz)) { \
					iop->_ptr = fileptr; \
					if (iop->_flag & _IOSTRG) \
						return iop->_ptr - iop->_base; \
					else \
						(void) _xflsbuf(iop); \
					fileptr = iop->_ptr; \
					filecnt = iop->_cnt; \
					filecnt--; \
				    } \
			} \
			*fileptr++ = (unsigned)(c); \
			count++; \
                      }

static char *nullstr = "(null)";
static char *lowerhex = "0123456789abcdef";
static char *upperhex = "0123456789ABCDEF";

/* stva_list is used to subvert C's restriction that a variable with an
 * array type can not appear on the left hand side of an assignment operator.
 * By putting the array inside a structure, the functionality of assigning to
 * the whole array through a simple assignment is achieved..
*/
typedef struct stva_list {
	va_list ap;
} stva_list;

void	_mkarglst(char *, stva_list, stva_list []);
void	_getarg(char *, stva_list *, int);
static char	*_check_dol(char *, int *);

int
_doprnt(char *format, va_list in_args, FILE *file)
{
	char convertbuffer[1024] ;
	
	/* Current position in format */
	char *cp;

	/* Starting and ending points for value to be printed */
	char *bp;
	char *p;

	/* Pointer and count for I/O buffer */
	unsigned char *fileptr;
	int filecnt;

	/* Field width and precision */
	int width;
	int prec;

	/* Format code */
	char fcode;

	/* Number of padding zeroes required on the left */
	int lzero;

	/* Flags - nonzero if corresponding character appears in format */
	bool fplus;		/* + */
	bool fminus;		/* - */
	bool fblank;		/* blank */
	bool fsharp;		/* # */
#if FZERO
	bool ansi_fzero;	/* 0 for ansi-dictated formats */
	bool compat_fzero;	/* 0 for backward compatibility */
#endif
	bool Lsize;             /* Capital L for size = long double = quadruple */

	/* Pointer to sign, "0x", "0X", or empty */
	char *prefix;

	/* Scratch */
	int nblank;

#if FLOAT
	/* Exponent or empty */
	char *suffix;

	/* Buffer to create exponent */
	char expbuf[7];  /* "e+xxxx\0" */

	/* Number of padding zeroes required on the right */
	int rzero;

	/* Length of exponent suffix. */
	int suffixlength;

	/* The value being converted, if real or quadruple */
	double dval;
	quadruple qval;

	/* Output values from fconvert and econvert */
	int decpt, sign;

	/* Values are developed in this buffer */
	char buf[1034];		/* Size of convertbuffer, plus some for exponent and sign. */

	/* Current locale's decimal point */
	char decpt_char = *(localeconv()->decimal_point);

#else
	/* Values are developed in this buffer */
	char buf[MAXDIGS];
#endif


	/* The value being converted, if integer */
	unsigned long val;

	/* Work variables */
	int n;
	char c;
	char radix;
	int svswitch = 0;
	/* count of output characters */
	int count;

	/* variables for positional parameters */
	char    *sformat = format;      /* save the beginning of the format */
	int     fpos = 1;               /* 1 if first positional parameter */
	stva_list       args,   /* used to step through the argument list */
			args_width, 	/* for width */
			args_prec, 	/* for prec */
			sargs;  /* used to save the start of the argument list */
	stva_list       arglst[MAXARGS];/* array giving the approriate values
					 * for va_arg() to retrieve the
				  	 * corresponding argument:
					 * arglst[0] is the first argument
				         * arglst[1] is the second argument, etc.
				         */
											      int index = 0;			/* argument placeolder */
											     /* Initialize args and sargs to the start of the argument list.
        * Note that ANSI guarantees that the address of the first member of
        * a structure will be the same as the address of the structure. */
											       args_width = args_prec = args = sargs = *(struct stva_list *)&in_args;


/*  initialize p an bp (starting and ending points)  bugid 1141781 */

	p = bp = NULL;

	cp = format;
	if ((c = *cp++) != '\0') {
		/*
		 * We know we're going to write something; make sure
		 * we can write and set up buffers, etc..
		 */
		if (_WRTCHK(file))
			return(EOF);
	} else
		return(0);	/* no fault, no error */

	count = 0;
	fileptr = file->_ptr;
	filecnt = file->_cnt;

	/*
	 *	The main loop -- this loop goes through one iteration
	 *	for each ordinary character or format specification.
	 */
	do {
		if (c != '%') {
			/* Ordinary (non-%) character */
			emitchar(c);
		} else {
			/*
			 *	% has been spotted!
			 *
			 *	First, try the 99% cases.
			 *	then parse the format specification.
			 *
			 *	Note that this code assumes the Sun
			 *	Workstation environment (all params
			 *	passed as int == long, no interrupts
			 *	for fixed point overflow from negating
			 *	the most negative number).
			 */
		skipit:
			switch(c = *cp++) {

			case 'l':
			case 'h':
				/* Quickly ignore long & short specifiers */
				goto skipit;

			case 's':
				bp = va_arg(args.ap, char *);
				if (bp == NULL)
					bp = nullstr;
				while (c = *bp++)
					emitchar(c);
				p = bp;
				continue;

			case 'c':
				c = va_arg(args.ap, int);
			emitc:
				emitchar(c);
				continue;

			case 'i':
			case 'd':
			case 'D':
				val = va_arg(args.ap, int);
				if ((long) val < 0) {
					emitchar('-');
					val = -val;
				}
				goto udcommon;

			case 'U':
			case 'u':
				val = va_arg(args.ap, unsigned);
			udcommon:
                                {
                                char *stringp = lowerhex;
                                bp = buf+MAXDIGS;
                                stringp = lowerhex;
                                do {
                                        *--bp = stringp[val%10];
                                        val /= 10;
                                } while (val);
				}
                                goto intout;

			case 'X':
				{
				char *stringp = upperhex;
				val = va_arg(args.ap, unsigned);
				bp = buf + MAXDIGS;
				if (val == 0)
					goto zero;
				while (val) {
					*--bp = stringp[val%16];
					val /= 16;
				}
				}
				goto intout;

			case 'x':
			case 'p':
				{
				char *stringp = lowerhex;
				val = va_arg(args.ap, unsigned);
				bp = buf + MAXDIGS;
				if (val == 0)
					goto zero;
				while (val) {
					*--bp = stringp[val%16];
					val /= 16;
				}
				}
				goto intout;

			case 'O':
			case 'o':
				{
				char *stringp = lowerhex;
				val = va_arg(args.ap, unsigned);
				bp = buf + MAXDIGS;
				if (val == 0)
					goto zero;
				while (val) {
					*--bp = stringp[val%8];
					val /= 8;
				}
				}
				/* Common code to output integers */
			intout:
				p = buf + MAXDIGS;
				while (bp < p) {
					c = *bp++;
					emitchar(c);
				}
				continue;

			zero:
				c = '0';
				goto emitc;

			default:
				/*
				 * let AT&T deal with it
				 */
				cp-= 2;
			}

			Lsize = 0;      /* Not long double unless we say so. */
                        /* Scan the <flags> */
			fplus = 0;
			fminus = 0;
			fblank = 0;
			fsharp = 0;
#if FZERO
			ansi_fzero = 0;
			compat_fzero = 0;
#endif
		scan:	switch (*++cp) {
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
				ansi_fzero = 1;
				compat_fzero = 1;
				goto scan;
#endif
			}

			/* Scan the field width */
			if (*cp == '*') {
				char *p;
				int val;

				p = _check_dol(cp+1, &val);
				if (p != (char *)NULL) {
					/*
					 * argument re-order
					 */
					if (fpos) {
						_mkarglst(sformat, sargs, arglst);
						fpos = 0;
					}
					if (val <= MAXARGS) {
						args_width = arglst[val - 1];
					} else {
						args_width = arglst[MAXARGS - 1];
						_getarg(sformat, &args_width, val);
					}
					width = va_arg(args_width.ap, int);
					if (width < 0) {
						width = -width;
						fminus = 1;
					}
					cp = p;
				}
				else {
					width = va_arg(args.ap, int);
					if (width < 0) {
						width = -width;
						fminus = 1;
					}
					cp++;
				}
			} else {
				index = width = 0;
				while (isdigit(*cp)) {
					n = tonumber(*cp++);
					index = width = width * 10 + n;
				}
			}

			/* Scan the precision */
			if (*cp == '.') {

				/* '*' instead of digits? */
				if (*++cp == '*') {
					char *p;
					int val;

					p = _check_dol(cp+1, &val);
					if (p != (char *)NULL) {
						/*
						 * argument re-order
						 */
						if (fpos) {
							_mkarglst(sformat, sargs, arglst);
							fpos = 0;
						}
						if (val <= MAXARGS) {
							args_prec = arglst[val - 1];
						} else {
							args_prec = arglst[MAXARGS - 1];
							_getarg(sformat, &args_prec, val);
						}
						prec = va_arg(args_prec.ap, int);
						cp = p;
					}
					else {
						prec = va_arg(args.ap, int);
						cp++;
					}
				} else {
					prec = 0;
					while (isdigit(*cp)) {
						n = tonumber(*cp++);
						prec = prec * 10 + n;
					}
				}
			} else
				prec = -1;

			if (*cp == '$') {
				if (fpos) {
					_mkarglst(sformat, sargs, arglst);
					fpos = 0;
				}
				if (index <= MAXARGS) {
					args = arglst[index - 1];
				} else {
					args = arglst[MAXARGS - 1];
					_getarg(sformat, &args, index);
				}
				goto scan;
			}
			/*
			 *	The character addressed by cp must be the
			 *	format letter -- there is nothing left for
			 *	it to be.
			 *
			 *	The status of the +, -, #, blank, and 0
			 *	flags are reflected in the variables
			 *	"fplus", "fminus", "fsharp", "fblank",
			 *	and "ansi_fzero"/"compat_fzero", respectively.
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
			rzero = 0;
			suffix = prefix;
#endif

#if FZERO
		  	/* if both zero-padding and left-justify flags
			 * are used, ignore zero-padding, per ansi c
			 */
		  	if (ansi_fzero & fminus) {
				ansi_fzero = 0;
				compat_fzero = 0;
			}

		  	/* if zero-padding and precision are specified, 
			 * ignore zero-padding for ansi-dictated formats,
			 * per ansi c
			 */
		  	if (ansi_fzero & (prec != -1)) ansi_fzero = 0; 
#endif
			  
		next:
			switch (fcode = *cp++) {

			/* toss the length modifier, if any */
			case 'l':
			case 'h':
				goto next;

                       	case 'L':
                      		Lsize = 1;      /* Remember long double size. */
                         	goto next;

			/*
			 *	fixed point representations
			 *
			 *	"radix" is the radix for the conversion.
			 *	Conversion is unsigned unless fcode is 'd'.
			 *	We assume a 2's complement machine and
			 *	that fixed point overflow (from negating
			 *	the largest negative int) is ignored.
			 */

			case 'i':
			case 'D':
			case 'U':
			case 'd':
			case 'u':
				radix = 10;
				goto fixed;

			case 'O':
			case 'o':
				radix = 8;
				goto fixed;

			case 'X':
			case 'x':
				radix = 16;

			fixed:
				/* Establish default precision */
				if (prec < 0)
					prec = 1;

				/* Fetch the argument to be printed */
				val = va_arg(args.ap, unsigned);

				/* If signed conversion, establish sign */
				if (fcode == 'd' || fcode == 'D' || fcode == 'i') {
					if ((long) val < 0) {
						prefix = "-";
						val = -val;
					} else if (fplus)
						prefix = "+";
					else if (fblank)
						prefix = " ";
				}
				/* Set translate table for digits */
				{
				char *stringp;
				if (fcode == 'X')
					stringp = upperhex;
				else
					stringp = lowerhex;

				/* Develop the digits of the value */
				bp = buf + MAXDIGS;
				switch(radix) {
				case 8:	/*octal*/
					while (val) {
						*--bp = stringp[val%8];
						val /= 8;
					}
					break;
				case 16:/*hex*/
					while (val) {
						*--bp = stringp[val%16];
						val /= 16;
					}
					break;
				default:
					while (val) {
						*--bp = stringp[val%10];
						val /= 10;
					}
					break;
				} /* switch */
				}

				/* Calculate padding zero requirement */
				p = buf + MAXDIGS;

				/* Handle the # flag */
				if (fsharp && bp != p) {
					switch (fcode) {
					case 'x':
						prefix = "0x";
						break;
					case 'X':
						prefix = "0X";
						break;
					}
				}
#if FZERO
				if (ansi_fzero) {
					n = width - strlen(prefix);
					if (n > prec)
						prec = n;
				}
#endif
				lzero = bp - p + prec;

				/* Handle the # flag for 'o' */
				if (fsharp && bp != p && fcode == 'o' &&
				    lzero < 1) {
					lzero = 1;
				}
				break;
#if FLOAT

#if	defined(__sparc)
#define GETQVAL /* Sun-4 macro to get a quad q from the argument list, passed as a pointer. */ \
      { qval = *(va_arg(args.ap, quadruple*)) ; }
#else
#define GETQVAL /* Sun-3 macro to get a quad q from the argument list, passed as a value. */ \
      { int iq ; unsigned long * pl = (unsigned long *) (&qval) ; for(iq=0;iq<4;iq++) pl[iq] = (unsigned long) va_arg(args.ap, unsigned long) ; }
#endif

			case 'E':
			case 'e':
				/*
				 *	E-format.  The general strategy
				 *	here is fairly easy: we take
				 *	what econvert gives us and re-format it.
				 */

				/* Establish default precision */
				if (prec < 0)
					prec = 6;

				/* Fetch the value */
                               if (Lsize == 0) { /* Double */
                                dval = va_arg(args.ap, double);
                                bp = econvert(dval, prec + 1, &decpt, &sign, convertbuffer);
                               } else { /* Long Double = quadruple */
                               GETQVAL;
                               bp = qeconvert(&qval, prec + 1, &decpt, &sign, convertbuffer);
                               }

				/* Determine the prefix */
				if (sign)
					prefix = "-";
				else if (fplus)
					prefix = "+";
				else if (fblank)
					prefix = " ";
				if (convertbuffer[0] > '9')
					{ /* handle infinity, nan */
					bp = &convertbuffer[0];
					for (p = bp+1 ; *p != 0 ; p++) ;
					goto ebreak ;
					}
				{
				char *stringp;
				/* Place the first digit in the buffer */
				stringp = &buf[0];
				*stringp++ = *bp != '\0'? *bp++: '0';

				/* Put in a decimal point if needed */
				if (prec != 0 || fsharp)
					*stringp++ = decpt_char;

				/* Create the rest of the mantissa */
				rzero = prec;
				while (rzero > 0 && *bp!= '\0') {
					--rzero;
					*stringp++ = *bp++;
				}
				p = stringp;
				}

				bp = &buf[0];

				/* Create the exponent */
				if (convertbuffer[0] != '0')
					n = decpt - 1;
				else
					n = 0 ;
				if (n < 0)
					n = -n;
				_fourdigitsquick( (short unsigned) n, &(expbuf[2]) ) ;
				expbuf[6] = 0 ;
				if (n < 100)
					/*
                                         * Normally two digit exponent field,
                                         * three or four if required.
					 */
					{ suffix = &(expbuf[4]) ; suffixlength = 4 ; }
                                else if (n < 1000)
                                        { suffix = &(expbuf[3]) ; suffixlength = 5 ; }
                                else 
                                        { suffix = &(expbuf[2]) ; suffixlength = 6 ; }
				/* Put in the exponent sign */
				*--suffix = (decpt > 0 || convertbuffer[0] == '0' )? '+': '-';

				/* Put in the e; note kludge in 'g' format */
				*--suffix = fcode;
ebreak:
#if FZERO
				if (compat_fzero &! fminus)
					/* Calculate padding zero requirement */
					lzero = width - (strlen(prefix)
					    + (p - buf) + rzero + suffixlength);
#endif
				break;

			case 'f':
				/*
				 *	F-format floating point.  This is
				 *	a good deal less simple than E-format.
				 *	The overall strategy will be to call
				 *	fconvert, reformat its result into buf,
				 *	and calculate how many trailing
				 *	zeroes will be required.  There will
				 *	never be any leading zeroes needed.
				 */

				/* Establish default precision */
				if (prec < 0)
					prec = 6;

                                if (Lsize == 0) {
                                dval = va_arg(args.ap, double);
                                bp = fconvert(dval, prec, &decpt, &sign, convertbuffer);
                                } else {
                                GETQVAL ;
                                bp = qfconvert(&qval, prec, &decpt, &sign, convertbuffer);
                                }
 
				/* Determine the prefix */
				if (sign)
					prefix = "-";
				else if (fplus)
					prefix = "+";
				else if (fblank)
					prefix = " ";
				if (convertbuffer[0] > '9')
					{ /* handle infinity, nan */
					bp = &convertbuffer[0];
					for (p = bp+1 ; *p != 0 ; p++) ;
					goto fbreak ;    
					}
				{
				char *stringp;
				/* Initialize buffer pointer */
				stringp = &buf[0];

				/* Emit the digits before the decimal point */
				n = decpt;
				if (n <= 0)
					*stringp++ = '0';
				else
					do
						if (*bp == '\0' )
							*stringp++ = '0';
						else {
							*stringp++ = *bp++;
						}
					while (--n != 0);

				/* Decide whether we need a decimal point */
				if (fsharp || prec > 0)
					*stringp++ = decpt_char;

				/* Digits(if any) after the decimal point */
				n = prec;
				rzero = prec - n;
				while (--n >= 0) {
					if (++decpt <= 0 || *bp == '\0')
						*stringp++ = '0';
					else {
						*stringp++ = *bp++;
					}
				}
#if FZERO
				if (compat_fzero &! fminus)
					/* Calculate padding zero requirement */
					lzero = width - (strlen(prefix)
					    + (stringp - buf) + rzero);
#endif
				p = stringp;
				}

				bp = &buf[0];
fbreak:
				break;

			case 'G':
			case 'g':
				/*
				 *	g-format.  We play around a bit
				 *	and then jump into e or f, as needed.
				 */
			
				/* Establish default precision */
				if (prec < 0)
					prec = 6;
				else if (prec == 0)
					prec = 1;

                                if (Lsize == 0) {
                                dval = va_arg(args.ap, double);
                                bp = gconvert(dval, prec, fsharp, convertbuffer);
                                } else {
                                GETQVAL;
                                bp = qgconvert(&qval, prec, fsharp, convertbuffer);
                                }
				bp = convertbuffer ;
				if (convertbuffer[0] == '-') {
					prefix = "-" ;
					bp++;
					}
				else if (fplus)
					prefix = "+";
				else if (fblank)
					prefix = " ";
				if (isupper(fcode))
				        { /* Put in a big E for small minds. */
				        for (p = bp ; (*p != NULL) && (*p != 'e') ; p++) ;
				        if (*p == 'e') *p = 'E' ;
				        for (; (*p != NULL) ; p++) ;
				                                /* Find end of string. */
			                }
				else
				        for (p = bp ; *p != NULL ; p++) ;
				                                /* Find end of string. */
				rzero = 0;
#if FZERO
				if (compat_fzero & !fminus)
					/* Calculate padding zero requirement */
					lzero = width - (strlen(prefix)
					    + (p - bp) + rzero);
#endif
				break ;

#endif
			case 'c':
				buf[0] = va_arg(args.ap, int);
				bp = &buf[0];
				p = bp + 1;
				break;

                        case 's':
				bp = va_arg(args.ap, char *);
				if (prec < 0)
					prec = MAXINT;
				/* avoid *(0) */
				if (bp == NULL)
					bp = nullstr;
				for (n=0; *bp++ != '\0' && n < prec; n++) 
					;
#if FZERO
				if (compat_fzero &! fminus)
				        lzero = width - n;
#endif
				p = --bp;
				bp -= n;
				break;

			case '\0':
				/* well, what's the punch line? */
				goto out;

			case 'n':
				svswitch = 1;
				break;
			default:
				p = bp = &fcode;
				p++;
				break;

			}
			/* Calculate number of padding blanks */
			nblank = width
#if FLOAT
				- (rzero < 0? 0: rzero)
				- strlen(suffix)
#endif
				- (p - bp)
				- (lzero < 0? 0: lzero)
				- strlen(prefix);

			/* Blanks on left if required */
			if (!fminus)
				while (--nblank >= 0)
					emitchar(' ');

			/* Prefix, if any */
			while (*prefix != '\0') {
				emitchar(*prefix);
				prefix++;
			}

			/* Zeroes on the left */
			while (--lzero >= 0)
				emitchar('0');
			
			/* The value itself */
			while (bp < p) {
				emitchar(*bp);
				bp++;
			}
#if FLOAT
			/* Zeroes on the right */
			while (--rzero >= 0)
				emitchar('0');

			/* The suffix */
			while (*suffix != '\0') {
				emitchar(*suffix);
				suffix++;
			}
#endif
			/* Blanks on the right if required */
			if (fminus)
				while (--nblank >= 0)
					emitchar(' ');
			/* If %n is seen, save count in argument */
			if (svswitch == 1) {
				long *svcount;
				svcount = va_arg (args.ap, long *);
				*svcount = count;
				svswitch = 0;
			}
		} /* else */
	} while ((c = *cp++) != '\0');	/* do */
out:
	file->_ptr = fileptr;
	file->_cnt = filecnt;
	if (file->_flag & (_IONBF | _IOLBF) &&
	    (file->_flag & _IONBF ||
	     memchr((char *)file->_base, '\n', fileptr - file->_base) != NULL))
		(void) _xflsbuf(file);
	return (ferror(file)? EOF: count);
}

#if	defined(__sparc)
/*
 * We use "double *" instead of "quadruple *" to skip over the pointer to
 * long double on the argument list since a pointer is a pointer after all.
 */
#define SKIPQVAL { \
	(void) va_arg(args.ap, double *); \
} 
#else	/* Sun-3 */
#define SKIPQVAL { \
	int iq; \
	for (iq = 0; iq < 4; iq++) \
		(void) va_arg(args.ap, unsigned long); \
}
#endif
/*
 * This function initializes arglst, to contain the appropriate va_list values
 * for the first MAXARGS arguments.
 */
void
_mkarglst(char *fmt, stva_list args, stva_list arglst[])
{
	static char *digits = "01234567890", *skips = "# +-.0123456789h$";

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

	(void)memset((void *)typelst, 0, sizeof(typelst));
	maxnum = -1;
	curargno = 0;
	while ((fmt = strchr(fmt, '%')) != 0)
	{
		fmt++;	/* skip % */
		if (fmt[n = strspn(fmt, digits)] == '$')
		{
			curargno = atoi(fmt) - 1;	/* convert to zero base */
			fmt += n + 1;
		}
		flags = 0;
	again:;
		fmt += strspn(fmt, skips);
		switch (*fmt++)
		{
		case '%':	/*there is no argument! */
			continue;
		case 'l':
			flags |= 0x1;
			goto again;
		case 'L':
			flags |= 0x8;
			goto again;
		case '*':	/* int argument used for value */
			flags |= 0x2;
			curtype = INT;
			break;
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			if (flags & 0x8)
				curtype = LONG_DOUBLE;
			else
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
		if (curargno >= 0 && curargno < MAXARGS)
		{
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
	for (n = 0 ; n <= maxnum; n++)
	{
		arglst[n] = args;
		if (typelst[n] == 0)
			typelst[n] = INT;
		
		switch (typelst[n])
		{
		case INT:
			va_arg(args.ap, int);
			break;
		case LONG:
			va_arg(args.ap, long);
			break;
		case CHAR_PTR:
			va_arg(args.ap, char *);
			break;
		case DOUBLE:
			va_arg(args.ap, double);
			break;
		case LONG_DOUBLE:
			SKIPQVAL
			break;
		case VOID_PTR:
			va_arg(args.ap, void *);
			break;
		case LONG_PTR:
			va_arg(args.ap, long *);
			break;
		case INT_PTR:
			va_arg(args.ap, int *);
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
	static char *digits = "01234567890", *skips = "# +-.0123456789h$";
	int i, n, curargno, flags;
	char	*sfmt = fmt;
	int	found = 1;

	curargno = i = MAXARGS;
	while (found)
	{
		fmt = sfmt;
		found = 0;
		while ((i != argno) && (fmt = strchr(fmt, '%')) != 0)
		{
			fmt++;	/* skip % */
			if (fmt[n = strspn(fmt, digits)] == '$')
			{
				curargno = atoi(fmt);
				fmt += n + 1;
			}

			/* find conversion specifier for next argument */
			if (i != curargno)
			{
				curargno++;
				continue;
			} else
				found = 1;
			flags = 0;
		again:;
			fmt += strspn(fmt, skips);
			switch (*fmt++)
			{
			case '%':	/*there is no argument! */
				continue;
			case 'l':
				flags |= 0x1;
				goto again;
			case 'L':
				flags |= 0x8;
				goto again;
			case '*':	/* int argument used for value */
				flags |= 0x2;
				(void)va_arg((*pargs).ap, int);
				break;
			case 'e':
			case 'E':
			case 'f':
			case 'g':
			case 'G':
				if (flags & 0x8) {
#define	args	(*pargs)
					SKIPQVAL
#undef	args
				}
				else
					(void)va_arg((*pargs).ap, double);
				break;
			case 's':
				(void)va_arg((*pargs).ap, char *);
				break;
			case 'p':
				(void)va_arg((*pargs).ap, void *);
				break;
			case 'n':
				if (flags & 0x1)
					(void)va_arg((*pargs).ap, long *);
				else
					(void)va_arg((*pargs).ap, int *);
				break;
			default:
				if (flags & 0x1)
					(void)va_arg((*pargs).ap, long int);
				else
					(void)va_arg((*pargs).ap, int);
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

		/* missing specifier for parameter, assume parameter is an int */
		if (!found && i != argno) {
			(void)va_arg((*pargs).ap, int);
			i++;
			curargno++;
			found = 1;
		}
	}
}


/*
 * parse a string, mini parse
 */
static char *
_check_dol(char *s, int *val)
{
	char *os;	/* save old string */
	int tmp_val = 0;
	int flag = 0;

	while (isdigit (*s)) {
		++flag;
		tmp_val = tmp_val*10 + *s - '0';
		s++;
	}
	if (flag == 0)
		return ((char *)NULL);
	if (*s == '$') {
		*val = tmp_val;
		return(++s);
	}
	return ((char *)NULL);
}

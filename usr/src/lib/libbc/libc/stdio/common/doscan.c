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

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <values.h>
#include <floatingpoint.h>
#include <errno.h>
#include <memory.h>

#define NCHARS	(1 << BITSPERBYTE)
#define locgetc()	(chcount+=1,getc(iop))
#define locungetc(x)	(chcount-=1,ungetc(x,iop))

static int chcount,flag_eof;

static int	number(int, int, int, int, FILE *, va_list *);
static int	string(int, int, int, char *, FILE *, va_list *);
static unsigned char	*setup(unsigned char *, char *);

#ifdef S5EMUL
#define	isws(c)		isspace(c)
#else
/*
 * _sptab[c+1] is 1 iff 'c' is a white space character according to the
 * 4.2BSD "scanf" definition - namely, SP, TAB, and NL are the only
 * whitespace characters.
 */
static char _sptab[1+256] = {
	0,				/* EOF - not a whitespace char */
	0,0,0,0,0,0,0,0,
	0,1,1,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	1,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
};

#define	isws(c)		((_sptab + 1)[c] != 0)
#endif

int
_doscan(FILE *iop, unsigned char *fmt, va_list va_alist)
{
	char tab[NCHARS];
	int ch;
	int nmatch = 0, len, inchar, stow, size;
	chcount=0; flag_eof=0;

	/*******************************************************
	 * Main loop: reads format to determine a pattern,
	 *		and then goes to read input stream
	 *		in attempt to match the pattern.
	 *******************************************************/
	for ( ; ; )
	{
		if ( (ch = *fmt++) == '\0')
			return(nmatch); /* end of format */
		if (isws(ch))
		{
		  	if (!flag_eof) 
			{
			   while (isws(inchar = locgetc()))
				;
			   if (inchar == EOF) {
				chcount--;
				flag_eof = 1;
			   }
			   else if (locungetc(inchar) == EOF)
				flag_eof = 1;
			}
		  continue;
		}
		if (ch != '%' || (ch = *fmt++) == '%')
                {
			if ( (inchar = locgetc()) == ch )
				continue;
			if (inchar != EOF) {
				if (locungetc(inchar) != EOF)
					return(nmatch); /* failed to match input */
			} else {
				chcount--;
			}
			break;
		}
		if (ch == '*')
		{
			stow = 0;
			ch = *fmt++;
		}
		else
			stow = 1;

		for (len = 0; isdigit(ch); ch = *fmt++)
			len = len * 10 + ch - '0';
		if (len == 0)
			len = MAXINT;
		if ( (size = ch) == 'l' || (size == 'h') || (size == 'L') )
			ch = *fmt++;
		if (ch == '\0' ||
		    ch == '[' && (fmt = setup(fmt, tab)) == NULL)
			return(EOF); /* unexpected end of format */
		if (isupper(ch))  /* no longer documented */
		{
			/*
			 * The rationale behind excluding the size
			 * of 'L' is that the 'L' size specifier was
			 * introduced in ANSI/ISO-C.  If the user
			 * specifies a format of %LG, it can mean
			 * nothing other than "long double", be the
			 * code ANSI or not.  Mapping it to "double"
			 * makes no sense.
			 */
			if (size != 'L')
				size = 'l';
#ifdef S5EMUL
			ch = _tolower(ch);
#else
			ch = tolower(ch);
#endif
		}
		switch(ch)
		{
		 case 'c':
		 case 's':
		 case '[':
			  if ((size = string(stow,ch,len,tab,iop,&va_alist)) < 0)
				goto out;	/* EOF seen, nothing converted */
			  break;
                 case 'n':
			  if (stow == 0)
				continue;
			  if (size == 'h')
				*va_arg(va_alist, short *) = (short) chcount;
		          else if (size == 'l')
				*va_arg(va_alist, long *) = (long) chcount;
			  else
			  	*va_arg(va_alist, int *) = (int) chcount;
			  continue;
                 default:
			 if ((size = number(stow, ch, len, size, iop, &va_alist)) < 0)
				goto out;	/* EOF seen, nothing converted */
			 break;
                 }
		   if (size)
			nmatch += stow;
		   else 
			return((flag_eof && !nmatch) ? EOF : nmatch);
		continue;
	}
out:
	return (nmatch != 0 ? nmatch : EOF); /* end of input */
}

/*
 **************************************************************
 * Functions to read the input stream in an attempt to match incoming
 * data to the current pattern from the main loop of _doscan().
 **************************************************************
 */
static int
number(int stow, int type, int len, int size, FILE *iop, va_list *listp)
{
	char numbuf[64], inchar, lookahead;
	char *np = numbuf;
	int c, base;
	int digitseen = 0, floater = 0, negflg = 0;
	long lcval = 0;
	switch(type)
	{
	case 'e':
	case 'f':
	case 'g':
		floater++;
	case 'd':
	case 'u':
	case 'i':
		base = 10;
		break;
	case 'o':
		base = 8;
		break;
	case 'x':
		base = 16;
		break;
	default:
		return(0); /* unrecognized conversion character */
	}
	if (!flag_eof)
	{
		while (isws(c = locgetc()))
			;
	}
	else
		c = locgetc();
	if (c == EOF) {
		chcount--;
		return(-1);	/* EOF before match */
	}
        if (floater != 0) {     /* Handle floating point with
                                 * file_to_decimal. */
                decimal_mode    dm;
                decimal_record  dr;
                fp_exception_field_type efs;
                enum decimal_string_form form;
                char           *echar;
                int             nread, ic;
                char            buffer[1024];
                char           *nb = buffer;

                locungetc(c);
		if (len > 1024)
			len = 1024;
                file_to_decimal(&nb, len, 0, &dr, &form, &echar, iop, &nread);
                if (stow && (form != invalid_form)) {
                        dm.rd = fp_direction;
                        if (size == 'l') {      /* double */
                                decimal_to_double((double *) va_arg(*listp, double *), &dm, &dr, &efs);
                        } else if (size == 'L') {      /* quad */
                                decimal_to_quadruple((quadruple *)va_arg(*listp, double *), &dm, &dr, &efs);
                        } else {/* single */
                                decimal_to_single((float *) va_arg(*listp, float *), &dm, &dr, &efs);
                        }
			if ((efs & (1 << fp_overflow)) != 0) {
				errno = ERANGE;
			}
			if ((efs & (1 << fp_underflow)) != 0) {
				errno = ERANGE;
                        }
                }
		chcount += nread;	/* Count characters read. */
                c = *nb;        /* Get first unused character. */
                ic = c;
                if (c == NULL) {
                        ic = locgetc();
                        c = ic;
                        /*
                         * If null, first unused may have been put back
                         * already.
                         */
                }         
                if (ic == EOF) {
                        chcount--;
                        flag_eof = 1;
                } else if (locungetc(c) == EOF)
                        flag_eof = 1;
                return ((form == invalid_form) ? 0 : 1);        /* successful match if
                                                                 * non-zero */
        }
	switch(c) {
	case '-':
		negflg++;
		if (type == 'u')
			break;
	case '+': /* fall-through */
		if (--len <= 0)
			break;
		if ( (c = locgetc()) != '0')
			break;
        case '0':
                if ( (type != 'i') || (len <= 1) )  
		   break;
	        if ( ((inchar = locgetc()) == 'x') || (inchar == 'X') ) 
	        {
		      /* If not using sscanf and *
		       * at the buffer's end     *
		       * then LOOK ahead         */

                   if ( (iop->_flag & _IOSTRG) || (iop->_cnt != 0) )
		      lookahead = locgetc();
		   else
		   {
		      if ( read(fileno(iop),np,1) == 1)
		         lookahead = *np;
                      else
		         lookahead = EOF;
                      chcount += 1;
                   }    
		   if ( isxdigit(lookahead) )
		   {
		       base =16;

		       if ( len <= 2)
		       {
			  locungetc(lookahead);
			  len -= 1;            /* Take into account the 'x'*/
                       }
		       else 
		       {
		          c = lookahead;
			  len -= 2;           /* Take into account '0x'*/
		       }
                   }
	           else
	           {
	               locungetc(lookahead);
	               locungetc(inchar);
                   }
		}
	        else
	        {
		    locungetc(inchar);
	            base = 8;
                }
	}
	if (!negflg || type != 'u')
	    for (; --len  >= 0 ; *np++ = c, c = locgetc()) 
	    {
		if (np > numbuf + 62)           
		{
		    errno = ERANGE;
		    return(0);
                }
		if (isdigit(c))
		{
			int digit;
			digit = c - '0';
			if (base == 8)
			{
				if (digit >= 8)
					break;
				if (stow)
					lcval = (lcval<<3) + digit;
			}
			else
			{
				if (stow)
				{
					if (base == 10)
						lcval = (((lcval<<2) + lcval)<<1) + digit;
					else /* base == 16 */
						lcval = (lcval<<4) + digit;
				}
			}
			digitseen++;


			continue;
		}
		else if (base == 16 && isxdigit(c))
		{
			int digit;
			digit = c - (isupper(c) ? 'A' - 10 : 'a' - 10);
			if (stow)
				lcval = (lcval<<4) + digit;
			digitseen++;
			continue;
		}
		break;
	    }


	if (stow && digitseen)
		{
	 	/* suppress possible overflow on 2's-comp negation */
			if (negflg && lcval != HIBITL)
				lcval = -lcval;
			if (size == 'l')
				*va_arg(*listp, long *) = lcval;
			else if (size == 'h')
				*va_arg(*listp, short *) = (short)lcval;
			else
				*va_arg(*listp, int *) = (int)lcval;
		}
	if (c == EOF) {
		chcount--;
		flag_eof=1;
	} else if (locungetc(c) == EOF)
		flag_eof=1;
	return (digitseen); /* successful match if non-zero */
}

static int
string(int stow, int type, int len, char *tab, FILE *iop, va_list *listp)
{
	int ch;
	char *ptr;
	char *start;

	start = ptr = stow ? va_arg(*listp, char *) : NULL;
	if (type == 's')
	{
		if (!flag_eof)
		{
			while (isws(ch = locgetc()))
				;
		}
		else
			ch = locgetc();
		if (ch == EOF)
			return(-1);	/* EOF before match */
		while (ch != EOF && !isws(ch))
		{
			if (stow)
				*ptr = ch;
			ptr++;
			if (--len <= 0)
				break;
			ch = locgetc();
		}
	} else if (type == 'c') {
		if (len == MAXINT)
			len = 1;
		while ( (ch = locgetc()) != EOF)
		{
			if (stow)
				*ptr = ch;
			ptr++;
			if (--len <= 0)
				break;
		}
	} else { /* type == '[' */
		while ( (ch = locgetc()) != EOF && !tab[ch])
		{
			if (stow)
				*ptr = ch;
			ptr++;
			if (--len <= 0)
				break;
		}
	}
	if (ch == EOF )
	{
		chcount-=1;
		flag_eof = 1;
	}
	else if (len > 0 && locungetc(ch) == EOF)
		flag_eof = 1;
	if (ptr == start)
		return(0); /* no match */
	if (stow && type != 'c')
		*ptr = '\0';
	return (1); /* successful match */
}

static unsigned char *
setup(unsigned char *fmt, char *tab)
{
	int b, c, d, t = 0;

	if (*fmt == '^')
	{
		t++;
		fmt++;
	}
	(void) memset(tab, !t, NCHARS);
	if ( (c = *fmt) == ']' || c == '-')  /* first char is special */
	{
		tab[c] = t;
		fmt++;
	}
	while ( (c = *fmt++) != ']')
	{
		if (c == '\0')
			return(NULL); /* unexpected end of format */
		if (c == '-' && (d = *fmt) != ']' && (b = fmt[-2]) < d)
		{
			(void) memset(&tab[b], t, d - b + 1);
			fmt++;
		}
		else
			tab[c] = t;
	}
	return (fmt);
}

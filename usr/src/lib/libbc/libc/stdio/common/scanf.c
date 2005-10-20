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

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>

#define ON	1
#define OFF	0

#define ARGMAX  64
static unsigned char newap[ARGMAX * sizeof(double)];
static unsigned char newform[256];

extern int _doscan();

static int	format_arg(unsigned char *, unsigned char *, unsigned char *);

int
scanf(char *fmt, ...)
{
	va_list ap;
	char *nf;
	int ret_val;
	

	va_start(ap, fmt);
	if (strlen(fmt) >= sizeof(newform)) {
		nf = malloc(strlen(fmt)+1);
		if (format_arg((unsigned char *)strcpy(nf, fmt), ap, newap)
		    == ON) {
			va_end(ap);
			ret_val = _doscan(stdin, nf, newap);
			free(nf);
			return(ret_val);
		}
		free(nf);
	} else if (format_arg((unsigned char *)strcpy(newform, fmt), ap, newap)
	    == ON) {
		va_end(ap);
		return(_doscan(stdin, newform, newap));
	}
	ret_val = _doscan(stdin, fmt, ap);
	va_end(ap);
	return (ret_val);
}

int
fscanf(FILE *iop, char *fmt, ...)
{
	va_list ap;
	char *nf;
	int ret_val;

#ifdef POSIX
        if ( !(iop->_flag & (_IOREAD|_IORW)) ) {
                iop->_flag |= _IOERR;
                errno = EBADF;
                return (EOF);
        }
#endif	/* POSIX */
	va_start(ap, fmt);
	if (strlen(fmt) >= sizeof(newform)) {
		nf = malloc(strlen(fmt)+1);
		if (format_arg((unsigned char *)strcpy(nf, fmt), ap, newap)
		    == ON) {
			va_end(ap);
			ret_val = _doscan(stdin, nf, newap);
			free(nf);
			return(ret_val);
		}
		free(nf);
	} else if (format_arg((unsigned char *)strcpy(newform, fmt), ap, newap)
	    == ON) {
		va_end(ap);
		return(_doscan(iop, newform, newap));
	}
	ret_val = _doscan(iop, fmt, ap);
	va_end(ap);
	return (ret_val);
}

int
sscanf(char *str, char *fmt, ...)
{
	va_list ap;
	FILE strbuf;
	char *nf;
	int ret_val;

	va_start(ap, fmt);
	strbuf._flag = _IOREAD|_IOSTRG;
	strbuf._ptr = strbuf._base = (unsigned char*)str;
	strbuf._cnt = strlen(str);
	strbuf._bufsiz = strbuf._cnt;
	if (strlen(fmt) >= sizeof(newform)) {
		nf = malloc(strlen(fmt)+1);
		if (format_arg((unsigned char *)strcpy(nf, fmt), ap, newap)
		    == ON) {
			va_end(ap);
			ret_val = _doscan(stdin, nf, newap);
			free(nf);
			return(ret_val);
		}
		free(nf);
	} else if (format_arg((unsigned char *)strcpy(newform, fmt), ap, newap)
	    == ON) {
		va_end(ap);
		return(_doscan(&strbuf, newform, newap));
	}
	ret_val = _doscan(&strbuf, fmt, ap);
	va_end(ap);
	return (ret_val);
}

/*
 * This function reorganises the format string and argument list.
 */


#ifndef NL_ARGMAX
#define NL_ARGMAX	9
#endif

struct al {
	int a_num;		/* arg # specified at this position */
	unsigned char *a_start;	/* ptr to 'n' part of '%n$' in format str */
	unsigned char *a_end;	/* ptr to '$'+1 part of '%n$' in format str */
	int *a_val;		/* pointers to arguments */
};

static int
format_arg(unsigned char *format, unsigned char *list, unsigned char *newlist)
{
	unsigned char *aptr, *bptr, *cptr;
	int i, fcode, nl_fmt, num, length, j;
	unsigned char *fmtsav;
	struct al args[ARGMAX + 1];

#ifdef VTEST
	{
		int fd;
		fd = creat("/tmp/SCANF", 0666);
	}
#endif
	for (i = 0; i <= ARGMAX; args[i++].a_num = 0);
	nl_fmt = 0;
	i = j = 1;
	while (*format) {
		while ((fcode = *format++) != '\0' && fcode != '%') ;
		if (!fcode || i > ARGMAX)
			break;
	charswitch:
		switch (fcode = *format++) {
		case 'l':
		case 'h':
			goto charswitch;
		case '0': case '1': case '2':
		case '3': case '4': case '5':
		case '6': case '7': case '8':
		case '9':
			num = fcode - '0';
			fmtsav = format;
			while (isdigit(fcode = *format)) {
				num = num * 10 + fcode - '0';
				format++;
			}
			if (*format == '$') {
				nl_fmt++;
				args[i].a_start = fmtsav - 1;
				args[i].a_end = ++format;
				if (num > NL_ARGMAX)
					num = num;
				args[i].a_num = num;
			}
			goto charswitch;
	/* now have arg type only to parse */
		case 'd': case 'u': case 'o':
		case 'x': case 'e': case 'f':
		case 'g': case 'c': case '[':
		case 's':
			if (nl_fmt == 0)
				return(OFF);
			if (!args[i].a_num) {
				args[i].a_start = args[i].a_end = format - 1;
				args[i].a_num = j++;
			}
			i++;
			break;
		case '*':
		case '%':
			break;
		default:
			format--;
			break;
		}
	}
	length = i;
	if (nl_fmt == 0)
		return (OFF);
	for (i = 1; i < length && args[i].a_num == 0; i++);

	/*
	 * Reformat the format string
	 */
	cptr = aptr = args[i].a_start;
	do {
		bptr = args[i++].a_end;
		for (; i < length && args[i].a_num == 0; i++);
		if (i == length) 
			while (*cptr++);
		else
			cptr = args[i].a_start;
		for (; bptr != cptr; *aptr++ = *bptr++);
	} while (i < length);

	/*
	 * Create arglist
	 * assuming that pointer to all variable type have
	 * same size.
	 */
	for (i = 1; i < length; i++)
		args[i].a_val = ((int **)(list += sizeof(int *)))[-1];

	for (i = 1; i < length; i++) {
		int **ptr;
		ptr = (int **)newlist;
		*ptr = args[args[i].a_num].a_val;
		newlist += sizeof(int *);
	}
	return(ON);
}

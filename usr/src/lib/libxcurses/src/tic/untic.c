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
 *	untic.c			CURSES Library
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	Portions of this code Copyright 1982 by Pavel Curtis.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/tic/rcs/untic.c 1.18 1995/06/22 20:04:01 ant Exp $";
#endif
#endif

#include <mks.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <term.h>
#include <unistd.h>
#include <m_ord.h>

#ifdef _XOPEN_CURSES
/*
 * MKS XCurses to be conforming has to avoid name space pollution
 * by using reserved prefixes.  Map the pre-XCurses names to the
 * new ones.
 */
#define BOOLCOUNT       __COUNT_BOOL
#define NUMCOUNT        __COUNT_NUM
#define STRCOUNT        __COUNT_STR
#define boolnames       __m_boolnames
#define boolcodes       __m_boolcodes
#define boolfnames      __m_boolfnames
#define numnames        __m_numnames
#define numcodes        __m_numcodes
#define numfnames       __m_numfnames
#define strnames        __m_strnames
#define strcodes        __m_strcodes
#define strfnames       __m_strfnames
#define __t_term_header terminfo_header_t
#define TERMINFO_MAGIC  __TERMINFO_MAGIC
#define Booleans        _bool
#define Numbers         _num
#define Strings         _str
#define term_names	_names
#endif

extern char *_cmdname;

/* Exit Status */
#define SUCCESS		0
#define NOT_DEFINED	1
#define USAGE		2
#define BAD_TERMINAL	3
#define NOT_VALID	4
#define ERROR		5

STATIC char *escape ANSI((int));
STATIC void error ANSI((char *, ...));		/* GENTEXT: error */
STATIC void untic ANSI((TERMINAL *));

char **Bool;
char **Num;
char **Str;

char usage[] = m_textstr(3137, "usage:  %s [-CILV] [term_name ...]\n", "U _");
char version[] = m_textstr(
	3138, "%s - Display compiled terminfo database entry.  Oct 92\n", "I _"
);


int
main(argc, argv)
int argc;
char **argv;
{
	int err;
	char *ap, **av = argv;
	setlocale(LC_ALL, "");
	_cmdname = *argv;
	Bool = boolnames;
	Num = numnames;
	Str = strnames;
	for (--argc, ++argv; 0 < argc && **argv == '-'; --argc, ++argv) {
		ap = &argv[0][1];
		if (*ap == '-' && ap[1] == '\0') {
			--argc;
			++argv;
			break;
		}
		while (*ap != '\0') {
			switch (*ap++) {
			case 'C':
				Bool = boolcodes;
				Num = numcodes;
				Str = strcodes;
				break;
			case 'I':
				Bool = boolnames;
				Num = numnames;
				Str = strnames;
				break;
			case 'L':
				Bool = boolfnames;
				Num = numfnames;
				Str = strfnames;
				break;
			case 'V':
				(void) fprintf(
					stderr, m_strmsg(version), _cmdname
				);
				break;
			default:
				(void) fprintf(
					stderr, m_strmsg(usage), _cmdname
				);
				return (USAGE);
			}
			break;
		}
	}
	if (argc <= 0) {
		if ((ap = getenv("TERM")) == NULL) {
			(void) fprintf(stderr, m_strmsg(usage), _cmdname);
			return (USAGE);
		}
		/* Assume that, even if there were no parameters, space
		 * for argv[0] (the command name) and argv[1] (NULL) would
		 * have been put aside.  We can use this space to fake a
		 * a single default parameter.
		 */
		argc = 1;
		argv[0] = ap;
		argv[1] = NULL;
	
	}
	use_env(0);
	for (; 0 < argc; --argc, ++argv) {
		(void) setupterm(*argv, STDOUT_FILENO, &err);
		switch (err) {
		case 1:
			untic(cur_term);
			(void) del_curterm(cur_term);
			break;
		case 0:
			error(
				m_textmsg(202, "Unknown terminal \"%s\".\n", "E term"),
				*argv
			); 
			return (BAD_TERMINAL);
		case -1:
			error(m_textmsg(203, "No terminfo database.\n", "E")); 
			return (BAD_TERMINAL);
		}
	}
	return (SUCCESS);
}

/*f
 *	Dump the contents of a compiled terminfo file into a
 *	human readable format. 
 */
STATIC void
untic(tp) 
TERMINAL *tp;
{
	int i;
	char *p;
	(void) printf("%s,\n", tp->term_names);
	for (i = 0; i < BOOLCOUNT; ++i) {
		if (tp->Booleans[i])
			(void) printf("\t%s,\n", Bool[i]);
	}
	for (i = 0; i < NUMCOUNT; ++i) {
		if (tp->Numbers[i] != -1)
			(void) printf("\t%s#%d,\n", Num[i],tp->Numbers[i]);
	}
	for (i = 0; i < STRCOUNT; ++i) {
		if (tp->Strings[i] != NULL) {
			(void) printf("\t%s=", Str[i]);
			for (p = tp->Strings[i]; *p != '\0'; ++p)
				(void) fputs(escape(*p), stdout);
			(void) fputs(",\n", stdout);
		}
	}
	(void) putchar('\n');
}

/*f
 *	Display error message.
 */
STATIC void
error VARARG1(char*, fmt)
{
	va_list ap;
	(void) fprintf(stderr, "%s: ", _cmdname);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*f
 *	This routine is a codeset independent method of specifying a translation
 *	from an internal binary value, to an unambiguous printable format.
 *	This mapping is defined by Table 2-13 in section 2-12 of POSIX.2.
 *
 * 	This table has been extended to account for tic/infocmp specification
 *	of additional characters: <escape>, <space>, <colon>, <caret>, <comma> 
 */
char *
escape(c)
int c;
{
	int i;
	static char buf[5];
	static int cntl_code[] = { 
		'\0', '\\', M_ALERT, '\b', '\f', '\n', '\r', '\t', 
		M_VTAB, M_ESCAPE, ' ', ':', '^', ',', 
		-1
	};
	static char *cntl_str[] = {
		"\\0", "\\\\", "\\a", "\\b", "\\f", "\\n", "\\r", "\\t",
		"\\v", "\\E", "\\s", "\\:", "\\^", "\\,"
	};
	for (i = 0; cntl_code[i] != -1; ++i)
		if (c == cntl_code[i])
			return (cntl_str[i]);
	if (!isprint(c))
		(void) sprintf(buf, "\\%03.3o", (unsigned char) c);
	else
		buf[0] = c, buf[1] = '\0';
	return (buf);
}

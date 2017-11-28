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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* This is a private header file.				*/

/* extensible strings */

#ifndef _S_STRING_H
#define	_S_STRING_H

#include <string.h>

typedef struct string {
	char *base;	/* base of string */
	char *end;	/* end of allocated space+1 */
	char *ptr;	/* ptr into string */
} string;

/*
 * LINT:  expect lint warnings from the following macros
 * Some macros have an integer at the end, which has null effect according
 * to lint, but causes the last expression to be evaluated as an int (didn't
 * change this).
 */
#define	s_clone(s)	s_copy((s)->ptr)
#define	s_curlen(s)	((s)->ptr - (s)->base)
#define	s_dup(s)	s_copy((s)->base)
#define	s_getc(s)	(*((s)->ptr++))
#define	s_peek(s)	(*((s)->ptr))
#define	s_putc(s, c)	(((s)->ptr < (s)->end) ? \
	(*((s)->ptr)++ = (char)(c)) : s_grow((s), (c)))
#define	s_reset(s)	((s) ? (*((s)->ptr = (s)->base) = '\0', (s)) : s_new())
#define	s_restart(s)	((s)->ptr = (s)->base)
#define	s_skipc(s)	((s)->ptr++)
#define	s_space(s)	((s)->end - (s)->base)
#define	s_terminate(s)  (((s)->ptr < (s)->end) ? \
	(*(s)->ptr = 0) : (s_grow((s), 0), (s)->ptr--, 0))
#define	s_to_c(s)	((s)->base)
#define	s_ptr_to_c(s)	((s)->ptr)

#ifdef __STDC__
extern string *s_append(string *to, char *from);
extern string *s_array(char *, size_t len);
extern string *s_copy(char *);
extern void s_free(string *);
extern int s_grow(string *sp, int c);
extern string *s_new(void);
extern string *s_parse(string *from, string *to);
extern char *s_read_line(FILE *fp, string *to);
extern size_t s_read_to_eof(FILE *fp, string *to);
extern string *s_seq_read(FILE *fp, string *to, int lineortoken);
extern void s_skipwhite(string *from);
extern string *s_tok(string *, char *);
extern void s_tolower(string *);
#else
extern string *s_append();
extern string *s_array();
extern string *s_copy();
extern void s_free();
extern int s_grow();
extern string *s_new();
extern string *s_parse();
extern char *s_read_line();
extern size_t s_read_to_eof();
extern string *s_seq_read();
extern void s_skipwhite();
extern string *s_tok();
extern void s_tolower();
#endif

/* controlling the action of s_seq_read */
#define	TOKEN 0		/* read the next whitespace delimited token */
#define	LINE 1		/* read the next logical input line */
#define	s_getline(a, b) s_seq_read(a, b, LINE)
#define	s_gettoken(a, b) s_seq_read(a, b, TOKEN)

#endif /* _S_STRING_H */

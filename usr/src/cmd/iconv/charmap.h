/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _CHARMAP_H
#define	_CHARMAP_H

/*
 * CHARMAP file handling for iconv.
 */

/* Common header files. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <libintl.h>

enum cmap_pass {
	CMAP_PASS_FROM,
	CMAP_PASS_TO
};

extern int com_char;
extern int esc_char;
extern int mb_cur_max;
extern int mb_cur_min;
extern int last_kw;
extern int verbose;
extern int yydebug;
extern int lineno;
extern int debug;
extern int warnings;
extern int cflag;
extern int sflag;

int yyparse(void);
void yyerror(const char *);
void errf(const char *, ...);
void warn(const char *, ...);

void reset_scanner(const char *);
void scan_to_eol(void);

/* charmap.c - CHARMAP handling */
void init_charmap(void);
void add_charmap(char *, char *);
void add_charmap_posix(void);
void add_charmap_range(char *, char *, char *);

void charmap_init(char *to, char *fr);
size_t cm_iconv(const char **iptr, size_t *ileft, char **optr, size_t *oleft);
void charmap_dump(void);

#define	_(x)	gettext(x)

#endif /* _CHARMAP_H */

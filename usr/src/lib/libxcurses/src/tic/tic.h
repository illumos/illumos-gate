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

/*
 *	tic.h			Terminal Information Compiler
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	Portions of this code Copyright 1982 by Pavel Curtis.
 *
 */

#ifndef tic_h
#define tic_h	1

#ifdef M_RCSID
#ifndef lint
static char const tic_h_rcsID[] = "$Header: /rd/src/tic/rcs/tic.h 1.11 1995/06/22 20:03:36 ant Exp $";
#endif
#endif

#include <mks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <term.h>
#include <time.h>

extern char *_cmdname;

/* Exit Status */
#define SUCCESS		0
#define NOT_DEFINED	1
#define USAGE		2
#define BAD_TERMINAL	3
#define NOT_VALID	4
#define ERROR		5

#define TERM_NAMES_LENGTH	128
#define TERM_ENTRY_LENGTH	4096
#define swap(x)			(((x >> 8) & 0377) + 256 * (x & 0377))

extern int term_names;		/* string offset */
extern char *string_table;
extern char *source_file;

#ifdef _XOPEN_CURSES
/* 
 * MKS XCurses to be conforming has to avoid name space pollution
 * by using reserved prefixes.  Map the pre-XCurses names to the
 * new ones.
 */
#define BOOLCOUNT	__COUNT_BOOL
#define NUMCOUNT	__COUNT_NUM
#define STRCOUNT	__COUNT_STR
#define boolnames       __m_boolnames
#define boolcodes       __m_boolcodes
#define boolfnames      __m_boolfnames
#define numnames        __m_numnames
#define numcodes        __m_numcodes
#define numfnames       __m_numfnames
#define strnames        __m_strnames
#define strcodes        __m_strcodes
#define strfnames       __m_strfnames
#define __t_term_header	terminfo_header_t
#define TERMINFO_MAGIC	__TERMINFO_MAGIC
#define Booleans	_bool
#define Numbers		_num
#define Strings		_str
#endif

extern char boolean[BOOLCOUNT];	/* 0, 1, cancel 2 */
extern short number[NUMCOUNT];	/* positive value, missing -1, cancel -2 */
extern short string[STRCOUNT];	/* positive offset, missing -1, cancel -2 */
	
extern int check_only;
extern char *destination;	/* destination directory for object files */
extern time_t start_time;	/* time at start of compilation */
extern int curr_line;		/* current line # in input */
extern long curr_file_pos;	/* file offset of current line */
extern int debug_level;		/* level of debugging output */

#define DEBUG(level, fmt, a1) \
	if (level <= debug_level) \
		 fprintf(stderr, fmt, a1);

/*
 *	These are the types of tokens returned by the scanner.
 *	The first three are also used in the hash table of capability
 *	names.  The scanner returns one of these values after loading
 *	the specifics into the global structure curr_token.
 *
 *	Note that EOF is also, implicitly, a token type.
 */
#define	BOOLEAN	0	/* Boolean capability */
#define	NUMBER 	1	/* Numeric capability */
#define	STRING 	2	/* String-valued capability */
#define	CANCEL 	3	/* Capability to be cancelled in following tc's */
#define	NAMES  	4	/* The names for a terminal type */
#define	UNDEF	5	/* Invalid token */

/*
 *	The global structure in which the specific parts of a
 *	scanned token are returned.
 */
typedef struct token {
	char *tk_name;		/* name of capability */
	int tk_valnumber;	/* value of capability (if a number) */
	char *tk_valstring;	/* value of capability (if a string) */
} token;

extern token curr_token;

/*
 *	Functions
 */
extern void compile ANSI((void));
extern void err_abort(char const *_Fmt, ...);	/* GENTEXT: err_abort */
extern int find(char const *_Capname, void **_Arrayp, int *_Indexp);
extern void panic_mode ANSI((int _Ch));
extern void reset ANSI((void));
extern void reset_input ANSI((void));
extern void warning(char const *_Fmt, ...);	/* GENTEXT: warning */

extern int warnings;

#define syserr_abort	err_abort

#endif /* tic_h */

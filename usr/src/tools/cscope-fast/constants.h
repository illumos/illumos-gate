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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *	cscope - interactive C symbol cross-reference
 *
 *	preprocessor macro and constant definitions
 */

/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>

#define	ctrl(x)	(x & 037)	/* control character macro */

/* database output macros that update its offset */
#define	dbputc(c)		(++dboffset, (void) putc(c, newrefs))
#define	dbfputs(s)		(dboffset += fputs(s, newrefs))
#define	dbfprintf(s, f, a)	(dboffset += fprintf(s, f, a))

/* fast string equality tests (avoids most strcmp() calls) */
#define	strequal(s1, s2)	(*(s1) == *(s2) && strcmp(s1, s2) == 0)
#define	strnotequal(s1, s2)	(*(s1) != *(s2) || strcmp(s1, s2) != 0)

/* set the mark character for searching the cross-reference file */
#define	setmark(c)	(blockmark = c, block[blocklen] = blockmark)

/* get the next character in the cross-reference */
/* note that blockp is assumed not to be null */
#define	getrefchar()	(*(++blockp + 1) != '\0' ? *blockp : \
			(readblock() != NULL ? *blockp : '\0'))

/* skip the next character in the cross-reference */
/*
 * note that blockp is assumed not to be null and that
 * this macro will always be in a statement by itself
 */
#define	skiprefchar()	if (*(++blockp + 1) == '\0') (void) readblock()

#define	ESC	'\033'		/* escape character */
#define	MSGLEN	PATLEN + 80	/* displayed message length */
#define	READ	4		/* access(2) parameter */
#define	WRITE	2		/* access(2) parameter */

/* these also appear in the fscanf format string in countrefs() */
#define	NUMLEN	6		/* line number length */
#define	PATHLEN	PATH_MAX	/* file pathname length */

/* default file names */
#define	INVNAME		"cscope.in.out"	/* inverted index to the database */
#define	INVPOST		"cscope.po.out"	/* inverted index postings */
#define	NAMEFILE	"cscope.files"	/* source file names and options */
#define	REFFILE		"cscope.out"	/* symbol database */

/*
 * cross-reference database mark characters (when new ones are added,
 * update the cscope.out format description in cscope.1)
 */
#define	ASSIGNMENT	'='
#define	CLASSDEF	'c'
#define	DEFINE		'#'
#define	DEFINEEND	')'
#define	ENUMDEF		'e'
#define	ESUEND		';'
#define	FCNCALL		'`'
#define	FCNDEF		'$'
#define	FCNEND		'}'
#define	GLOBALDEF	'g'
#define	INCLUDE		'~'
#define	LOCALDEF	'l'
#define	MEMBERDEF	'm'
#define	NEWFILE		'@'
#define	PARAMETER	'p'
#define	STRUCTDEF	's'
#define	TYPEDEF		't'
#define	UNIONDEF	'u'

/* other scanner token types */
#define	LEXEOF	0
#define	IDENT	1
#define	NEWLINE	2

/* screen lines */
#define	FLDLINE	(LINES - FIELDS - 1)	/* first input field line */
#define	MSGLINE	0			/* message line */
#define	PRLINE	(LINES - 1)		/* input prompt line */
#define	REFLINE	3			/* first displayed reference line */

/* input fields (value matches field order on screen) */
#define	SYMBOL		0
#define	DEFINITION	1
#define	CALLEDBY	2
#define	CALLING		3
#define	ASSIGN		4
#define	CHANGE		5
#define	STRING		6
#define	FILENAME	7
#define	INCLUDES	8
#define	FIELDS		9

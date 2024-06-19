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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * esclex.h -- public definitions for esclex module
 *
 * this module provides lexical analysis (i.e. tokenizing the
 * input files) and the lex-level error routines expected by
 * yacc like yyerror().  yylex() and yyerror() are called only
 * by yacc-generated code.  the lex_X() routines are called
 * only by main().
 *
 * the tokstr struct is the communication mechanism between the lexer
 * and the parser.
 */

#ifndef	_ESC_COMMON_ESCLEX_H
#define	_ESC_COMMON_ESCLEX_H

#ifdef	__cplusplus
extern "C" {
#endif

/* information returned by lexer for tokens with string table entries */
struct tokstr {
	const char *s;		/* the string (in the string table) */
	const char *file;	/* file where this token appeared */
	int line;		/* line where this token appeared */
};

void lex_init(char **av, const char *cppargs, int lexecho);
int lex_fini(void);
void lex_free(void);
const unsigned long long *lex_s2ullp_lut_lookup(struct lut *root,
    const char *s);

/* lut containing "ident" strings */
extern struct lut *Ident;

/* lut containing "dictionary" strings */
extern struct lut *Dicts;

/* lut containing valid timeval suffixes */
extern struct lut *Timesuffixlut;

/* flags set by #pragmas */
extern int Pragma_new_errors_only;
extern int Pragma_trust_ereports;
extern int Pragma_allow_cycles;

/* exported by esclex.c but names are mandated by the way yacc works... */
int yylex(void);
int yyerror(const char *s);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_ESCLEX_H */

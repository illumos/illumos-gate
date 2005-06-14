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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_LEX_H
#define	_MDB_LEX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_argvec.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_module.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

extern void mdb_lex_debug(int);
extern void mdb_lex_reset(void);

extern void yyerror(const char *, ...);
extern void yyperror(const char *, ...);
extern void yydiscard(void);

extern int yyparse(void);
extern int yywrap(void);


struct mdb_lex_state;
struct mdb_frame;

void mdb_lex_state_save(struct mdb_lex_state *);
void mdb_lex_state_restore(struct mdb_lex_state *);
void mdb_lex_state_create(struct mdb_frame *);
void mdb_lex_state_destroy(struct mdb_frame *);

/*
 * The lex and yacc debugging code as generated uses printf and fprintf
 * for debugging output.  We redefine these to refer to our yyprintf
 * and yyfprintf routines, which are wrappers around mdb_iob_vprintf.
 */

#define	printf	(void) yyprintf
#define	fprintf	(void) yyfprintf

extern int yyprintf(const char *, ...);
extern int yyfprintf(FILE *, const char *, ...);

extern int yylineno;

/*
 * Maximum depth we can have in our yacc state stack.  The yacc default is 150,
 * but this should be more than enough for our simple mdb expressions.
 */
#define	YYMAXDEPTH	100
/*
 * Maximum size of our lex yytext buffer.
 */
#define	YYLMAX		BUFSIZ

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_LEX_H */

%{
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * escparse.y -- parser for esc
 *
 * this is the yacc-based parser for Eversholt.  the syntax is simple
 * and is defined by the LALR(1) grammar described by this file.  there
 * should be no shift/reduce or reduce/reduce messages when building this
 * file.
 *
 * as the input is parsed, a parse tree is built by calling the
 * tree_X() functions defined in tree.c.  any syntax errors cause
 * us to skip to the next semicolon, achieved via the "error" clause
 * in the stmt rule below.  the yacc state machine code will call
 * yyerror() in esclex.c and that will keep count of the errors and
 * display the filename, line number, and current input stream of tokens
 * to help the user figure out the problem.  the -Y flag to this program
 * turns on the yacc debugging output which is quite large.  you probably
 * only need to do that if you're debugging the grammar below.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "tree.h"

%}
%union {
	struct tokstr tok;
	struct node *np;
}

%right '='

/*
 * make sure ':' comes immediately after '?' in precedence declarations
 */
%right '?'
%nonassoc ':'

%left OR
%left AND
%left '|'
%left '^'
%left '&'
%left EQ NE
%left LE GE '<' '>'
%left LSHIFT RSHIFT
%left '-' '+'
%left '*' '%' DIV '/'
%right '!' '~'
%left '.'

%token <tok> PROP MASK ARROW EVENT ENGINE ASRU FRU COUNT CONFIG
%token <tok> ID QUOTE NUMBER IF PATHFUNC
%type <tok> enameid
%type <np> root stmtlist stmt nvpairlist nvpair nvname nvexpr
%type <np> exprlist expr iterid ename pname epname eexprlist ipname iname
%type <np> numexpr cexpr func pfunc parglist parg
%type <np> eventlist event nork norkexpr globid propbody

%%

root	: stmtlist
		{ (void)tree_root($1); }
	;

stmtlist   : /*empty*/
		{ $$ = NULL; }
        | stmtlist stmt
		{ $$ = tree_expr(T_LIST, $1, $2); }
	;

stmt	: error ';'
     		{ $$ = tree_nothing(); }
	| IF '(' expr ')' stmt
		{ $$ = $5; }
	| IF '(' expr ')' '{' stmtlist '}'
		{ $$ = $6; }
	| EVENT event nvpairlist ';'
		{ $$ = tree_decl(T_EVENT, $2, $3, $1.file, $1.line); }
	| ENGINE event nvpairlist ';'
		{ $$ = tree_decl(T_ENGINE, $2, $3, $1.file, $1.line); }
	| PROP propbody ';'
		{
			$$ = tree_stmt(T_PROP, $2, $1.file, $1.line);
		}
	| MASK propbody ';'
		{
			$$ = tree_stmt(T_MASK, $2, $1.file, $1.line);
		}
	| ASRU pname nvpairlist ';'
		{
			$$ = tree_decl(T_ASRU, $2, $3, $1.file, $1.line);
		}
	| FRU pname nvpairlist ';'
		{
			$$ = tree_decl(T_FRU, $2, $3, $1.file, $1.line);
		}
	| CONFIG ipname nvpairlist ';'
		{
			$$ = tree_decl(T_CONFIG, $2, $3, $1.file, $1.line);
		}
	| /*superfluous semicolons are ignored*/ ';'
     		{ $$ = tree_nothing(); }
	;

propbody: eventlist nork ARROW nork eventlist
		{
			$$ = tree_arrow($1, $2, $4, $5);
		}
	| propbody nork ARROW nork eventlist
		{
			$$ = tree_arrow($1, $2, $4, $5);
		}
	;

nork	: /* empty */
		{ $$ = NULL; }
	| '(' norkexpr ')'
		{ $$ = $2; }
	;

norkexpr: NUMBER
		{ $$ = tree_num($1.s, $1.file, $1.line); }
	| ID
		/* really can only be 'A', enforced by check_arrow() later */
       		{ $$ = tree_name($1.s, IT_NONE, $1.file, $1.line); }
	| '(' norkexpr ')'
		{ $$ = $2; }
	| norkexpr '-' norkexpr
		{ $$ = tree_expr(T_SUB, $1, $3); }
	| norkexpr '+' norkexpr
		{ $$ = tree_expr(T_ADD, $1, $3); }
	| norkexpr '*' norkexpr
		{ $$ = tree_expr(T_MUL, $1, $3); }
	| norkexpr DIV norkexpr
		{ $$ = tree_expr(T_DIV, $1, $3); }
	| norkexpr '%' norkexpr
		{ $$ = tree_expr(T_MOD, $1, $3); }
	;

nvpairlist: /* empty */
		{ $$ = NULL; }
	| nvpair
	| nvpairlist ',' nvpair
		{ $$ = tree_expr(T_LIST, $1, $3); }
	;
	  
nvpair	: nvname '=' nvexpr
		{ $$ = tree_expr(T_NVPAIR, $1, $3); }
	| ENGINE '=' nvexpr
		/* "engine" is a reserved word, but a valid property name */
		{
			$$ = tree_expr(T_NVPAIR,
				tree_name($1.s, IT_NONE, $1.file, $1.line), $3);
		}
	| COUNT '=' nvexpr
		/* "count" is a reserved word, but a valid property name */
		{
			$$ = tree_expr(T_NVPAIR,
				tree_name($1.s, IT_NONE, $1.file, $1.line), $3);
		}
	;

nvname	: ID
		{ $$ = tree_name($1.s, IT_NONE, $1.file, $1.line); }
	| nvname '-' ID
		{
			/* hack to allow dashes in property names */
			$$ = tree_name_repairdash($1, $3.s);
		}
	;

/* the RHS of an nvpair can be a value, or an ename, or an ename@pname */
nvexpr	: numexpr
	| ename epname
		{ $$ = tree_event($1, $2, NULL); }
	| pname
	| globid
	| func
	| NUMBER ID
		/*
		 * ID must be timevals only ("ms", "us", etc.).
		 * enforced by tree_timeval().
		 */
		{ $$ = tree_timeval($1.s, $2.s, $1.file, $1.line); }
	| QUOTE
		{ $$ = tree_quote($1.s, $1.file, $1.line); }
	;

/* arithmetic operations, no variables or symbols */
numexpr	: numexpr '-' numexpr
		{ $$ = tree_expr(T_SUB, $1, $3); }
	| numexpr '+' numexpr
		{ $$ = tree_expr(T_ADD, $1, $3); }
	| numexpr '*' numexpr
		{ $$ = tree_expr(T_MUL, $1, $3); }
	| numexpr DIV numexpr
		{ $$ = tree_expr(T_DIV, $1, $3); }
	| numexpr '/' numexpr
		{ $$ = tree_expr(T_DIV, $1, $3); }
	| numexpr '%' numexpr
		{ $$ = tree_expr(T_MOD, $1, $3); }
 	| '(' numexpr ')'
		{ $$ = $2; }
	| NUMBER
		{ $$ = tree_num($1.s, $1.file, $1.line); }
	;

eventlist: event
	| eventlist ',' event
		{ $$ = tree_expr(T_LIST, $1, $3); }
	;

event	: ename epname eexprlist
		{ $$ = tree_event($1, $2, $3); }
	;

epname	: /* empty */
		{ $$ = NULL; }
	| '@' pname
		{ $$ = $2; }
	;

eexprlist: /* empty */
		{ $$ = NULL; }
	| '{' exprlist '}'
		{ $$ = $2; }
	;

exprlist: expr
	| exprlist ',' expr
		{ $$ = tree_expr(T_LIST, $1, $3); }
	;

/*
 * note that expr does not include pname, to avoid reduce/reduce
 * conflicts between cexpr and iterid involving the use of ID
 */
expr	: cexpr
	| NUMBER ID
		/*
		 * ID must be timevals only ("ms", "us", etc.).
		 * enforced by tree_timeval().
		 */
		{ $$ = tree_timeval($1.s, $2.s, $1.file, $1.line); }
	;

cexpr	: cexpr '=' cexpr
		{ $$ = tree_expr(T_ASSIGN, $1, $3); }
	| cexpr '?' cexpr
		{ $$ = tree_expr(T_CONDIF, $1, $3); }
	| cexpr ':' cexpr
		{ $$ = tree_expr(T_CONDELSE, $1, $3); }
	| cexpr OR cexpr
		{ $$ = tree_expr(T_OR, $1, $3); }
 	| cexpr AND cexpr
		{ $$ = tree_expr(T_AND, $1, $3); }
	| cexpr '|' cexpr
		{ $$ = tree_expr(T_BITOR, $1, $3); }
	| cexpr '^' cexpr
		{ $$ = tree_expr(T_BITXOR, $1, $3); }
	| cexpr '&' cexpr
		{ $$ = tree_expr(T_BITAND, $1, $3); }
	| cexpr EQ cexpr
		{ $$ = tree_expr(T_EQ, $1, $3); }
	| cexpr NE cexpr
		{ $$ = tree_expr(T_NE, $1, $3); }
	| cexpr '<' cexpr
		{ $$ = tree_expr(T_LT, $1, $3); }
	| cexpr LE cexpr
		{ $$ = tree_expr(T_LE, $1, $3); }
	| cexpr '>' cexpr
		{ $$ = tree_expr(T_GT, $1, $3); }
	| cexpr GE cexpr
		{ $$ = tree_expr(T_GE, $1, $3); }
	| cexpr LSHIFT cexpr
		{ $$ = tree_expr(T_LSHIFT, $1, $3); }
	| cexpr RSHIFT cexpr
		{ $$ = tree_expr(T_RSHIFT, $1, $3); }
	| cexpr '-' cexpr
		{ $$ = tree_expr(T_SUB, $1, $3); }
	| cexpr '+' cexpr
		{ $$ = tree_expr(T_ADD, $1, $3); }
	| cexpr '*' cexpr
		{ $$ = tree_expr(T_MUL, $1, $3); }
	| cexpr DIV cexpr
		{ $$ = tree_expr(T_DIV, $1, $3); }
	| cexpr '/' cexpr
		{ $$ = tree_expr(T_DIV, $1, $3); }
	| cexpr '%' cexpr
		{ $$ = tree_expr(T_MOD, $1, $3); }
	|  '!' cexpr
		{ $$ = tree_expr(T_NOT, $2, NULL); }
	|  '~' cexpr
		{ $$ = tree_expr(T_BITNOT, $2, NULL); }
	| '(' cexpr ')'
		{ $$ = $2; }
	| func
	| NUMBER
		{ $$ = tree_num($1.s, $1.file, $1.line); }
	| ID
       		{
			/* iteration variable */
			$$ = tree_name($1.s, IT_NONE, $1.file, $1.line);
		}
	| globid
	| QUOTE
		{ $$ = tree_quote($1.s, $1.file, $1.line); }
	;

func	: ID '(' ')'
		{ $$ = tree_func($1.s, NULL, $1.file, $1.line); }
	| ID '(' exprlist ')'
		{ $$ = tree_func($1.s, $3, $1.file, $1.line); }
	| PATHFUNC '(' parglist ')'
		{ $$ = tree_func($1.s, $3, $1.file, $1.line); }
	| pfunc
	;

parglist: parg
	| parglist ',' parg
		{ $$ = tree_expr(T_LIST, $1, $3); }
	;

parg	: pfunc
	| pname
		{ $$ = tree_pname($1); }
	| QUOTE
		{ $$ = tree_quote($1.s, $1.file, $1.line); }
	;

/*
 * these functions are in the grammar so we can force the arg to be
 * a path or an event.  they show up as functions in the parse tree.
 */
pfunc	: ASRU '(' pname ')'
		{ $$ = tree_func($1.s, tree_pname($3), $1.file, $1.line); }
	| FRU '(' pname ')'
		{ $$ = tree_func($1.s, tree_pname($3), $1.file, $1.line); }
	| COUNT '(' event ')'
		{ $$ = tree_func($1.s, $3, $1.file, $1.line); }
	;

globid	: '$' ID
       		{ $$ = tree_globid($2.s, $2.file, $2.line); }
	;

iterid	: ID
       		{ $$ = tree_name($1.s, IT_VERTICAL, $1.file, $1.line); }
	| ID '[' ']'
       		{ $$ = tree_name($1.s, IT_VERTICAL, $1.file, $1.line); }
	| ID '[' cexpr ']'
       		{
			$$ = tree_name_iterator(
			   tree_name($1.s, IT_VERTICAL, $1.file, $1.line), $3);
		}
	| ID '<' '>'
       		{ $$ = tree_name($1.s, IT_HORIZONTAL, $1.file, $1.line); }
	| ID '<' ID '>'
       		{
			$$ = tree_name_iterator(
			    tree_name($1.s, IT_HORIZONTAL, $1.file, $1.line),
			    tree_name($3.s, IT_NONE, $3.file, $3.line));
		}
	| ID '-' iterid
		{
			/* hack to allow dashes in path name components */
			$$ = tree_name_repairdash2($1.s, $3);
		}
	;

/* iname is an ID where we can peel numbers off the end */
iname	: ID
       		{ $$ = tree_iname($1.s, $1.file, $1.line); }
	;

/* base case of ID.ID instead of just ID requires ename to contain one dot */
ename	: ID '.' enameid
       		{
			$$ = tree_name_append(
			    tree_name($1.s, IT_ENAME, $1.file, $1.line),
			    tree_name($3.s, IT_NONE, $3.file, $3.line));
		}
	| ename '.' enameid
		{
			$$ = tree_name_append($1,
			    tree_name($3.s, IT_NONE, $3.file, $3.line));
		}
	| ename '-' enameid
		{
			/*
			 * hack to allow dashes in class names.  when we
			 * detect the dash here, we know we're in a class
			 * name because the left recursion of this rule
			 * means we've already matched at least:
			 * 	ID '.' ID
			 * so the ename here has an incomplete final
			 * component (because the lexer stopped at the
			 * dash).  so we repair that final component here.
			 */
			$$ = tree_name_repairdash($1, $3.s);
		}
	;

/* like an ID, but we let reserved words act unreserved in enames */
enameid	: ID
	| PROP
	| MASK
	| EVENT
	| ENGINE
	| ASRU
	| FRU
	| CONFIG
	| IF
	;

/* pname is a pathname, like x/y, x<i>/y[0], etc */
pname	: iterid
	| pname '/' iterid
		{ $$ = tree_name_append($1, $3); }
	;

/* ipname is an "instanced" pathname, like x0/y1 */
ipname	: iname
	| ipname '/' iname
		{ $$ = tree_name_append($1, $3); }
	;

%%

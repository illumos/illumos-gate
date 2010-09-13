%{
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
%}
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



%{
#ident	"%Z%%M%	%I%	%E% SMI"
%}
%token	FIRSTTOKEN	/* must be first */
%token	FINAL FATAL
%token	LT LE GT GE EQ NE
%token	MATCH NOTMATCH
%token	APPEND
%token	ADD MINUS MULT DIVIDE MOD UMINUS
%token	ASSIGN ADDEQ SUBEQ MULTEQ DIVEQ MODEQ
%token	JUMP
%token	XBEGIN XEND
%token	NL
%token	PRINT PRINTF SPRINTF SPLIT
%token	IF ELSE WHILE FOR IN NEXT EXIT BREAK CONTINUE
%token	PROGRAM PASTAT PASTAT2


%right	ASGNOP
%left	BOR
%left	AND
%left	NOT
%left	NUMBER VAR ARRAY FNCN SUBSTR LSUBSTR INDEX
%left	GETLINE
%nonassoc RELOP MATCHOP
%left	OR
%left	STRING  DOT CCL NCCL CHAR
%left	'(' '^' '$'
%left	CAT
%left	'+' '-'
%left	'*' '/' '%'
%left	STAR PLUS QUEST
%left	POSTINCR PREINCR POSTDECR PREDECR INCR DECR
%left	FIELD INDIRECT
%token	JUMPTRUE JUMPFALSE PUSH GETREC
%token	NEWSTAT
%token	IN_INIT IN_EXIT
%token	LASTTOKEN	/* has to be last */


%{
#include "awk.def"
#ifndef	DEBUG
#	define	PUTS(x)
#endif
static wchar_t L_record[] = L"$record";
static wchar_t L_zeronull[] = L"$zero&null";
%}
%%


program:
		begin pa_stats end	{
			if (errorflag==0)
				winner = (NODE *)stat3(PROGRAM, $1, $2, $3); }
	| error			{ yyclearin; yyerror("bailing out"); }
	;


begin:
		XBEGIN '{' stat_list '}'	{ $$ = $3; }
	| begin NL
	| 	{ $$ = (int) 0; }
	;


end:
		XEND '{' stat_list '}'	{ $$ = $3; }
	| end NL
	|	{ $$ = (int) 0; }
	;


compound_conditional:
		conditional BOR conditional	{ $$ = op2(BOR, $1, $3); }
	| conditional AND conditional	{ $$ = op2(AND, $1, $3); }
	| NOT conditional		{ $$ = op1(NOT, $2); }
	| '(' compound_conditional ')'	{ $$ = $2; }
	;


compound_pattern:
		pattern BOR pattern	{ $$ = op2(BOR, $1, $3); }
	| pattern AND pattern	{ $$ = op2(AND, $1, $3); }
	| NOT pattern		{ $$ = op1(NOT, $2); }
	| '(' compound_pattern ')'	{ $$ = $2; }
	;


conditional:
		expr  {
		$$ = op2(NE, $1,
			valtonode(lookup(L_zeronull, symtab, 0), CCON));
		}
	| rel_expr
	| lex_expr
	| compound_conditional
	;


else:
		ELSE optNL
	;


field:
		FIELD		{ $$ = valtonode($1, CFLD); }
	| INDIRECT term { $$ = op1(INDIRECT, $2); }
	;


if:
		IF '(' conditional ')' optNL	{ $$ = $3; }
	;


lex_expr:
		expr MATCHOP regular_expr	{
			$$ = op2($2, $1, makedfa($3)); }
	| '(' lex_expr ')'		{ $$ = $2; }
	;


var:
		NUMBER	{ $$ = valtonode($1, CCON); }
	| STRING 	{ $$ = valtonode($1, CCON); }
	| VAR		{ $$ = valtonode($1, CVAR); }
	| VAR '[' expr ']'	{ $$ = op2(ARRAY, $1, $3); }
	| field
	;
term:
		var
	| GETLINE	{ $$ = op1(GETLINE, 0); }
	| FNCN		{
		$$ = op2(FNCN, $1,
			valtonode(lookup(L_record, symtab, 0), CFLD));
			}
	| FNCN '(' ')'	{
				$$ = op2(FNCN, $1,
				valtonode(lookup(L_record, symtab, 0), CFLD));
			}
	| FNCN '(' expr ')'	{ $$ = op2(FNCN, $1, $3); }
	| SPRINTF print_list	{ $$ = op1($1, $2); }
	| SUBSTR '(' expr ',' expr ',' expr ')'
			{ $$ = op3(SUBSTR, $3, $5, $7); }
	| SUBSTR '(' expr ',' expr ')'
			{ $$ = op3(SUBSTR, $3, $5, 0); }
	| SPLIT '(' expr ',' VAR ',' expr ')'
			{ $$ = op3(SPLIT, $3, $5, $7); }
	| SPLIT '(' expr ',' VAR ')'
			{ $$ = op3(SPLIT, $3, $5, 0); }
	| INDEX '(' expr ',' expr ')'
			{ $$ = op2(INDEX, $3, $5); }
	| '(' expr ')'			{$$ = $2; }
	| term '+' term			{ $$ = op2(ADD, $1, $3); }
	| term '-' term			{ $$ = op2(MINUS, $1, $3); }
	| term '*' term			{ $$ = op2(MULT, $1, $3); }
	| term '/' term			{ $$ = op2(DIVIDE, $1, $3); }
	| term '%' term			{ $$ = op2(MOD, $1, $3); }
	| '-' term %prec QUEST		{ $$ = op1(UMINUS, $2); }
	| '+' term %prec QUEST		{ $$ = $2; }
	| INCR var	{ $$ = op1(PREINCR, $2); }
	| DECR var	{ $$ = op1(PREDECR, $2); }
	| var INCR	{ $$= op1(POSTINCR, $1); }
	| var DECR	{ $$= op1(POSTDECR, $1); }
	;


expr:
		term
	| expr term	{ $$ = op2(CAT, $1, $2); }
	| var ASGNOP expr	{ $$ = op2($2, $1, $3); }
	;


optNL:
		NL
	|
	;


pa_stat:
		pattern	{ $$ = stat2(PASTAT, $1, genprint()); }
	| pattern '{' stat_list '}'	{ $$ = stat2(PASTAT, $1, $3); }
	| pattern ',' pattern		{ $$ = pa2stat($1, $3, genprint()); }
	| pattern ',' pattern '{' stat_list '}'
					{ $$ = pa2stat($1, $3, $5); }
	| '{' stat_list '}'	{ $$ = stat2(PASTAT, 0, $2); }
	;


pa_stats:
		pa_stats pa_stat st	{ $$ = linkum($1, $2); }
	|	{ $$ = (int)0; }
	| pa_stats pa_stat	{ $$ = linkum($1, $2); }
	;


pattern:
		regular_expr	{
		$$ = op2(MATCH,
		valtonode(lookup(L_record, symtab, 0), CFLD), makedfa($1));
		}
	| rel_expr
	| lex_expr
	| compound_pattern
	;


print_list:
	expr
	| pe_list
	|	{
			$$ = valtonode(lookup(L_record, symtab, 0), CFLD);
			}
	;


pe_list:
		expr ',' expr	{$$ = linkum($1, $3); }
	| pe_list ',' expr	{$$ = linkum($1, $3); }
	| '(' pe_list ')'		{$$ = $2; }
	;


redir:
		RELOP
	| '|'
	;


regular_expr:
		'/'	{ startreg(); }
		r '/'
		{ $$ = $3; }
	;


r:
		CHAR		{ $$ = op2(CHAR, (NODE *) 0, $1); }
	| DOT		{ $$ = op2(DOT, (NODE *) 0, (NODE *) 0); }
	| CCL		{ $$ = op2(CCL, (NODE *) 0, cclenter($1)); }
	| NCCL		{ $$ = op2(NCCL, (NODE *) 0, cclenter($1)); }
	| '^'		{ $$ = op2(CHAR, (NODE *) 0, HAT); }
	| '$'		{ $$ = op2(CHAR, (NODE *) 0, (NODE *) 0); }
	| r OR r	{ $$ = op2(OR, $1, $3); }
	| r r   %prec CAT
			{ $$ = op2(CAT, $1, $2); }
	| r STAR	{ $$ = op2(STAR, $1, (NODE *) 0); }
	| r PLUS	{ $$ = op2(PLUS, $1, (NODE *) 0); }
	| r QUEST	{ $$ = op2(QUEST, $1, (NODE *) 0); }
	| '(' r ')'	{ $$ = $2; }
	;


rel_expr:
		expr RELOP expr
		{ $$ = op2($2, $1, $3); }
	| '(' rel_expr ')'
		{ $$ = $2; }
	;


st:
		NL
	| ';'
	;


simple_stat:
		PRINT print_list redir expr
		{ $$ = stat3($1, $2, $3, $4); }
	| PRINT print_list
		{ $$ = stat3($1, $2, 0, 0); }
	| PRINTF print_list redir expr
		{ $$ = stat3($1, $2, $3, $4); }
	| PRINTF print_list
		{ $$ = stat3($1, $2, 0, 0); }
	| expr	{ $$ = exptostat($1); }
	|		{ $$ = (int)0; }
	| error		{ yyclearin; yyerror("illegal statement"); $$ = (int)0; }
	;


statement:
		simple_stat st
	| if statement		{ $$ = stat3(IF, $1, $2, 0); }
	| if statement else statement
		{ $$ = stat3(IF, $1, $2, $4); }
	| while statement	{ $$ = stat2(WHILE, $1, $2); }
	| for
	| NEXT st		{ $$ = stat1(NEXT, 0); }
	| EXIT st		{ $$ = stat1(EXIT, 0); }
	| EXIT expr st		{ $$ = stat1(EXIT, $2); }
	| BREAK st		{ $$ = stat1(BREAK, 0); }
	| CONTINUE st		{ $$ = stat1(CONTINUE, 0); }
	| '{' stat_list '}'	{ $$ = $2; }
	;


stat_list:
		stat_list statement	{ $$ = linkum($1, $2); }
	|			{ $$ = (int)0; }
	;


while:
		WHILE '(' conditional ')' optNL	{ $$ = $3; }
	;


for:
	FOR '(' simple_stat ';' conditional ';' simple_stat ')' optNL statement
		{ $$ = stat4(FOR, $3, $5, $7, $10); }
	| FOR '(' simple_stat ';'  ';' simple_stat ')' optNL statement
		{ $$ = stat4(FOR, $3, 0, $6, $9); }
	| FOR '(' VAR IN VAR ')' optNL statement
		{ $$ = stat3(IN, $3, $5, $8); }
	;


%%

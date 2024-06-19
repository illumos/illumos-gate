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
/*
 * awk -- YACC grammar
 *
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 *
 * Copyright 1986, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * This Software is unpublished, valuable, confidential property of
 * Mortice Kern Systems Inc.  Use is authorized only in accordance
 * with the terms and conditions of the source licence agreement
 * protecting this Software.  Any unauthorized use or disclosure of
 * this Software is strictly prohibited and will result in the
 * termination of the licence agreement.
 *
 * NOTE: this grammar correctly produces NO shift/reduce conflicts from YACC.
 *
 */

/*
 * Do not use any character constants as tokens, so the resulting C file
 * is codeset independent.
 */

#include "awk.h"
static NODE * fliplist ANSI((NODE *np));
%}

%union	{
	NODE	*node;
};

/*
 * Do not use any character constants as tokens, so the resulting C file
 * is codeset independent.
 *
 * Declare terminal symbols before their operator
 * precedences to get them in a contiguous block
 * for giant switches in action() and exprreduce().
 */
/* Tokens from exprreduce() */
%token	<node>	PARM ARRAY UFUNC FIELD IN INDEX CONCAT
%token	<node>	NOT AND OR EXP QUEST
%token	<node>	EQ NE GE LE GT LT
%token	<node>	ADD SUB MUL DIV REM INC DEC PRE_INC PRE_DEC
%token	<node>	GETLINE CALLFUNC RE TILDE NRE

/* Tokens shared by exprreduce() and action() */
%token		ASG

/* Tokens from action() */
%token	<node>	PRINT PRINTF
%token	<node>	EXIT RETURN BREAK CONTINUE NEXT
%token	<node>	DELETE WHILE DO FOR FORIN IF

/*
 * Terminal symbols not used in action() and exprrreduce()
 * switch statements.
 */
%token	<node>	CONSTANT VAR FUNC
%token	<node>	DEFFUNC BEGIN END CLOSE ELSE PACT
%right		ELSE
%token		DOT CALLUFUNC

/*
 * Tokens not used in grammar
 */
%token		KEYWORD SVAR
%token		PIPESYM

/*
 * Tokens representing character constants
 * TILDE, '~', taken care of above
 */
%token BAR		/* '|' */
       CARAT		/* '^' */
       LANGLE		/* '<' */
       RANGLE		/* '>' */
       PLUSC		/* '+' */
       HYPHEN		/* '-' */
       STAR		/* '*' */
       SLASH		/* '/' */
       PERCENT		/* '%' */
       EXCLAMATION	/* '!' */
       DOLLAR		/* '$' */
       LSQUARE		/* '[' */
       RSQUARE		/* ']' */
       LPAREN		/* '(' */
       RPAREN		/* ')' */
       SEMI		/* ';' */
       LBRACE		/* '{' */
       RBRACE		/* '}' */

/*
 * Priorities of operators
 * Lowest to highest
 */
%left	COMMA
%right	BAR PIPE WRITE APPEND
%right	ASG AADD ASUB AMUL ADIV AREM AEXP
%right	QUEST COLON
%left	OR
%left	AND
%left	IN
%left	CARAT
%left	TILDE NRE
%left	EQ NE LANGLE RANGLE GE LE
%left	CONCAT
%left	PLUSC HYPHEN
%left	STAR SLASH PERCENT
%right	UPLUS UMINUS
%right	EXCLAMATION
%right	EXP
%right	INC DEC URE
%left	DOLLAR LSQUARE RSQUARE
%left	LPAREN RPAREN

%type	<node>	prog rule pattern expr rvalue lvalue fexpr varlist varlist2
%type	<node>	statement statlist fileout exprlist eexprlist simplepattern
%type	<node>	getline optvar var
%type	<node>	dummy

%start	dummy
%%

dummy:
		prog			{
			yytree = fliplist(yytree);
		}
		;
prog:
	  rule				{
		yytree = $1;
	}
	| rule SEMI prog		{
		if ($1 != NNULL) {
			if (yytree != NNULL)
				yytree = node(COMMA, $1, yytree); else
				yytree = $1;
		}
	}
	;

rule:	  pattern LBRACE statlist RBRACE	{
		$$ = node(PACT, $1, $3);
		doing_begin = 0;
	}
	| LBRACE statlist RBRACE		{
		npattern++;
		$$ = node(PACT, NNULL, $2);
	}
	| pattern				{
		$$ = node(PACT, $1, node(PRINT, NNULL, NNULL));
		doing_begin = 0;
	}
	| DEFFUNC VAR
		{ $2->n_type = UFUNC; funparm = 1; }
	    LPAREN varlist RPAREN
		{ funparm = 0; }
	    LBRACE statlist { uexit($5); } RBRACE {
		$2->n_ufunc = node(DEFFUNC, $5, fliplist($9));
		$$ = NNULL;
	}
	| DEFFUNC UFUNC				{
		awkerr((char *) gettext("function \"%S\" redefined"), $2->n_name);
		/* NOTREACHED */
	}
	|					{
		$$ = NNULL;
	}
	;

pattern:
	  simplepattern
	| expr COMMA expr			{
		++npattern;
		$$ = node(COMMA, $1, $3);
	}
	;

simplepattern:
	  BEGIN					{
		$$ = node(BEGIN, NNULL, NNULL);
		doing_begin++;
	}
	| END					{
		++npattern;
		$$ = node(END, NNULL, NNULL);
	}
	| expr					 {
		++npattern;
		$$ = $1;
	}
	;

eexprlist:
	  exprlist
	|					{
		$$ = NNULL;
	}
	;

exprlist:
	  expr %prec COMMA
	| exprlist COMMA expr			{
		$$ = node(COMMA, $1, $3);
	}
	;

varlist:
						{
		$$ = NNULL;
	}
	| varlist2
	;

varlist2:
	  var
	| var COMMA varlist2			{
		$$ = node(COMMA, $1, $3);
	}
	;

fexpr:
	  expr
	|					{
		$$ = NNULL;
	}
	;

/*
 * Normal expression (includes regular expression)
 */
expr:
	  expr PLUSC expr			{
		$$ = node(ADD, $1, $3);
	}
	| expr HYPHEN expr			{
		$$ = node(SUB, $1, $3);
	}
	| expr STAR expr			{
		$$ = node(MUL, $1, $3);
	}
	| expr SLASH expr			{
		$$ = node(DIV, $1, $3);
	}
	| expr PERCENT expr			{
		$$ = node(REM, $1, $3);
	}
	| expr EXP expr				{
		$$ = node(EXP, $1, $3);
	}
	| expr AND expr				{
		$$ = node(AND, $1, $3);
	}
	| expr OR expr				{
		$$ = node(OR, $1, $3);
	}
	| expr QUEST expr COLON expr		{
		$$ = node(QUEST, $1, node(COLON, $3, $5));
	}
	| lvalue ASG expr			{
		$$ = node(ASG, $1, $3);
	}
	| lvalue AADD expr			{
		$$ = node(AADD, $1, $3);
	}
	| lvalue ASUB expr			{
		$$ = node(ASUB, $1, $3);
	}
	| lvalue AMUL expr			{
		$$ = node(AMUL, $1, $3);
	}
	| lvalue ADIV expr			{
		$$ = node(ADIV, $1, $3);
	}
	| lvalue AREM expr			{
		$$ = node(AREM, $1, $3);
	}
	| lvalue AEXP expr			{
		$$ = node(AEXP, $1, $3);
	}
	| lvalue INC				{
		$$ = node(INC, $1, NNULL);
	}
	| lvalue DEC				{
		$$ = node(DEC, $1, NNULL);
	}
	| expr EQ expr				{
		$$ = node(EQ, $1, $3);
	}
	| expr NE expr				{
		$$ = node(NE, $1, $3);
	}
	| expr RANGLE expr			{
		$$ = node(GT, $1, $3);
	}
	| expr LANGLE expr			{
		$$ = node(LT, $1, $3);
	}
	| expr GE expr				{
		$$ = node(GE, $1, $3);
	}
	| expr LE expr				{
		$$ = node(LE, $1, $3);
	}
	| expr TILDE expr			{
		$$ = node(TILDE, $1, $3);
	}
	| expr NRE expr				{
		$$ = node(NRE, $1, $3);
	}
	| expr IN var				{
		$$ = node(IN, $3, $1);
	}
	| LPAREN exprlist RPAREN IN var		{
		$$ = node(IN, $5, $2);
	}
	| getline
	| rvalue
	| expr CONCAT expr			{
		$$ = node(CONCAT, $1, $3);
	}
	;

lvalue:
	  DOLLAR rvalue				{
		$$ = node(FIELD, $2, NNULL);
	}
	/*
	 * Prevents conflict with FOR LPAREN var IN var RPAREN production
	 */
	| var %prec COMMA
	| var LSQUARE exprlist RSQUARE		{
		$$ = node(INDEX, $1, $3);
	}
	;

var:
	  VAR
	| PARM
	;

rvalue:
	  lvalue %prec COMMA
	| CONSTANT
	| LPAREN expr RPAREN term		{
		$$ = $2;
	}
	| EXCLAMATION expr			{
		$$ = node(NOT, $2, NNULL);
	}
	| HYPHEN expr %prec UMINUS		{
		$$ = node(SUB, const0, $2);
	}
	| PLUSC expr %prec UPLUS		{
		$$ = $2;
	}
	| DEC lvalue				{
		$$ = node(PRE_DEC, $2, NNULL);
	}
	| INC lvalue				{
		$$ = node(PRE_INC, $2, NNULL);
	}
	| FUNC					{
		$$ = node(CALLFUNC, $1, NNULL);
	}
	| FUNC LPAREN eexprlist RPAREN term	{
		$$ = node(CALLFUNC, $1, $3);
	}
	| UFUNC LPAREN eexprlist RPAREN term	{
		$$ = node(CALLUFUNC, $1, $3);
	}
	| VAR LPAREN eexprlist RPAREN term	{
		$$ = node(CALLUFUNC, $1, $3);
	}
	| SLASH {redelim='/';} URE SLASH %prec URE	{
		$$ = $<node>3;
	}
	;

statement:
	  FOR LPAREN fexpr SEMI fexpr SEMI fexpr RPAREN statement {
		$$ = node(FOR, node(COMMA, $3, node(COMMA, $5, $7)), $9);
	}
	| FOR LPAREN var IN var RPAREN statement {
		register NODE *np;

		/*
		 * attempt to optimize statements for the form
		 *    for (i in x) delete x[i]
		 * to
		 *    delete x
		 */
		np = $7;
		if (np != NNULL
		 && np->n_type == DELETE
		 && (np = np->n_left)->n_type == INDEX
		 && np->n_left == $5
		 && np->n_right == $3)
			$$ = node(DELETE, $5, NNULL);
		else
			$$ = node(FORIN, node(IN, $3, $5), $7);
	}
	| WHILE LPAREN expr RPAREN statement	{
		$$ = node(WHILE, $3, $5);
	}
	| DO statement WHILE LPAREN expr RPAREN	{
		$$ = node(DO, $5, $2);
	}
	| IF LPAREN expr RPAREN statement ELSE statement {
		$$ = node(IF, $3, node(ELSE, $5, $7));
	}
	| IF LPAREN expr RPAREN statement %prec ELSE	{
		$$ = node(IF, $3, node(ELSE, $5, NNULL));
	}
	| CONTINUE SEMI				{
		$$ = node(CONTINUE, NNULL, NNULL);
	}
	| BREAK SEMI				{
		$$ = node(BREAK, NNULL, NNULL);
	}
	| NEXT SEMI				{
		$$ = node(NEXT, NNULL, NNULL);
	}
	| DELETE lvalue SEMI			{
		$$ = node(DELETE, $2, NNULL);
	}
	| RETURN fexpr SEMI			{
		$$ = node(RETURN, $2, NNULL);
	}
	| EXIT fexpr SEMI			{
		$$ = node(EXIT, $2, NNULL);
	}
	| PRINT eexprlist fileout SEMI		{
		$$ = node(PRINT, $2, $3);
	}
	| PRINT LPAREN exprlist RPAREN fileout SEMI	{
		$$ = node(PRINT, $3, $5);
	}
	| PRINTF exprlist fileout SEMI		{
		$$ = node(PRINTF, $2, $3);
	}
	| PRINTF LPAREN exprlist RPAREN fileout SEMI	{
		$$ = node(PRINTF, $3, $5);
	}
	| expr SEMI				{
		$$ = $1;
	}
	| SEMI					{
		$$ = NNULL;
	}
	| LBRACE statlist RBRACE		{
		$$ = $2;
	}
	;


statlist:
	  statement
	| statlist statement			{
		if ($1 == NNULL)
			$$ = $2;
		else if ($2 == NNULL)
			$$ = $1;
		else
			$$ = node(COMMA, $1, $2);
	}
	;

fileout:
	  WRITE expr				{
		$$ = node(WRITE, $2, NNULL);
	}
	| APPEND expr				{
		$$ = node(APPEND, $2, NNULL);
	}
	| PIPE expr				{
		$$ = node(PIPE, $2, NNULL);
	}
	|					{
		$$ = NNULL;
	}
	;

getline:
	  GETLINE optvar %prec WRITE		{
		$$ = node(GETLINE, $2, NNULL);
	}
	| expr BAR GETLINE optvar		{
		$$ = node(GETLINE, $4, node(PIPESYM, $1, NNULL));
	}
	| GETLINE optvar LANGLE expr		{
		$$ = node(GETLINE, $2, node(LT, $4, NNULL));
	}
	;

optvar:
	  lvalue
	|					{
		$$ = NNULL;
	}
	;

term:
	  {catterm = 1;}
	;
%%
/*
 * Flip a left-recursively generated list
 * so that it can easily be traversed from left
 * to right without recursion.
 */
static NODE *
fliplist(NODE *np)
{
	int type;

	if (np!=NNULL && !isleaf(np->n_flags)
#if 0
		 && (type = np->n_type)!=FUNC && type!=UFUNC
#endif
	) {
		np->n_right = fliplist(np->n_right);
		if ((type=np->n_type)==COMMA) {
			register NODE *lp;

			while ((lp = np->n_left)!=NNULL && lp->n_type==COMMA) {
				register NODE* *spp;

				lp->n_right = fliplist(lp->n_right);
				for (spp = &lp->n_right;
				    *spp != NNULL && (*spp)->n_type==COMMA;
				     spp = &(*spp)->n_right)
					;
				np->n_left = *spp;
				*spp = np;
				np = lp;
			}
		}
		if (np->n_left != NULL &&
		    (type = np->n_left->n_type)!= FUNC && type!=UFUNC)
			np->n_left = fliplist(np->n_left);
	}
	return (np);
}

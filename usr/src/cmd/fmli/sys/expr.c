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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
/*
 * FMLI begin 
 */
#include	<setjmp.h>
#include	"wish.h"
/* #include	"message.h" */
#include	"eval.h"

static jmp_buf Jumpenv;
/*
 * FMLI end
 */

# define A_STRING 258
# define NOARG 259
# define OR 260
# define AND 261
# define EQ 262
# define LT 263
# define GT 264
# define GEQ 265
# define LEQ 266
# define NEQ 267
# define ADD 268
# define SUBT 269
# define MULT 270
# define DIV 271
# define REM 272
# define MCH 273
# define MATCH 274

#define ESIZE	256
#define EQL(x,y) !strcmp(x,y)

long atol();
char *strcpy(), *strncpy();
static char	**Av;
static char *buf;
static int	Ac;
static int	Argi;
static int noarg;
static int paren;

static char Mstring[1][128];

static char *ltoa(long l);
static int ematch(char *s, char *p);
static int yyerror(char *s);

extern int nbra;

static char *operator[] = { 
	"|", "&", "+", "-", "*", "/", "%", ":",
	"=", "==", "<", "<=", ">", ">=", "!=",
	"match", "\0" };
static int op[] = { 
	OR, AND, ADD,  SUBT, MULT, DIV, REM, MCH,
	EQ, EQ, LT, LEQ, GT, GEQ, NEQ,
	MATCH };
static int pri[] = {
	1,2,3,3,3,3,3,3,4,4,5,5,5,6,7};

int
yylex() {
	char *p;
	int i;

	if(Argi >= Ac) return NOARG;

	p = Av[Argi];

	if((*p == '(' || *p == ')') && p[1] == '\0' )
		return (int)*p;
	for(i = 0; *operator[i]; ++i)
		if(EQL(operator[i], p))
			return op[i];


	return A_STRING;
}

static char *
rel(oper, r1, r2)
char *r1, *r2; 
{
	long i;

	if(ematch(r1, "-\\{0,1\\}[0-9]*$") && ematch(r2, "-\\{0,1\\}[0-9]*$"))
		i = atol(r1) - atol(r2);
	else
		i = strcmp(r1, r2);
	switch(oper) {
	case EQ: 
		i = i==0; 
		break;
	case GT: 
		i = i>0; 
		break;
	case GEQ: 
		i = i>=0; 
		break;
	case LT: 
		i = i<0; 
		break;
	case LEQ: 
		i = i<=0; 
		break;
	case NEQ: 
		i = i!=0; 
		break;
	}
	return i? "1": "0";
}

static char *
arith(oper, r1, r2)
char *r1, *r2; 
{
	long i1, i2;
	char *rv;

	if(!(ematch(r1, "-\\{0,1\\}[0-9]*$") && ematch(r2, "-\\{0,1\\}[0-9]*$")))
		yyerror("non-numeric argument");
	i1 = atol(r1);
	i2 = atol(r2);

	switch(oper) {
	case ADD: 
		i1 = i1 + i2; 
		break;
	case SUBT: 
		i1 = i1 - i2; 
		break;
	case MULT: 
		i1 = i1 * i2; 
		break;
	case DIV: 
		if (i2 == 0)
			yyerror("division by zero");
		i1 = i1 / i2; 
		break;
	case REM: 
		if (i2 == 0)
			yyerror("division by zero");
		i1 = i1 % i2; 
		break;
	}
	rv = malloc(16);
	(void) strcpy(rv, ltoa(i1));
	return rv;
}
static char *
conj(oper, r1, r2) char *r1, *r2; 
{
	char *rv;

	switch(oper) {

	case OR:
		if(EQL(r1, "0")
		    || EQL(r1, ""))
			if(EQL(r2, "0")
			    || EQL(r2, ""))
				rv = "0";
			else
				rv = r2;
		else
			rv = r1;
		break;
	case AND:
		if(EQL(r1, "0")
		    || EQL(r1, ""))
			rv = "0";
		else if(EQL(r2, "0")
		    || EQL(r2, ""))
			rv = "0";
		else
			rv = r1;
		break;
	}
	return rv;
}

static char *
match(s, p)
char *s, *p;
{
	char *rv;

	(void) strcpy(rv=malloc(8), ltoa((long)ematch(s, p)));
	if(nbra) {
		rv = malloc((unsigned) strlen(Mstring[0]) + 1);
		(void) strcpy(rv, Mstring[0]);
	}
	return rv;
}

static int
ematch(char *s, char *p)
{
	static char expbuf[ESIZE];
	void errxx();
	int num;
	extern char *braslist[], *braelist[], *loc2;

	compile(p, expbuf, &expbuf[512], 0, errxx);
	if(nbra > 1)
		yyerror("Too many '\\('s");
	if(advance(s, expbuf)) {
		if(nbra == 1) {
			p = braslist[0];
			num = braelist[0] - p;
			if ((num > 127) || (num < 0)) yyerror("Paren problem");
			(void) strncpy(Mstring[0], p, num);
			Mstring[0][num] = '\0';
		}
		return(loc2-s);
	}
	return(0);
}

void
errxx()
{
	yyerror("RE error");
}

static int
yyerror(char *s)
{
	char tmpbuf[BUFSIZ];

 /*
  * Changed the expr prefix to fmlexpr.         mek
  */
	sprintf(tmpbuf, "fmlexpr: %s\n", s);
	mess_temp(tmpbuf);
	mess_flash(tmpbuf);
	doupdate();
	longjmp(Jumpenv, 1);
	/*NOTREACHED*/
}

static char *
ltoa(long l)
{
	static int str[20];
	char *sp = (char *) &str[18];	/*u370*/
	int i;
	int neg = 0;

	if(l == 0x80000000L)
		return "-2147483648";
	if(l < 0)
		++neg, l = -l;
	str[19] = '\0';
	do {
		i = l % 10;
		*sp-- = '0' + i;
		l /= 10;
	} 
	while(l);
	if(neg)
		*sp-- = '-';
	return ++sp;
}

static char *
expres(prior,par)  int prior, par; 
{
	int ylex, temp, op1;
	char *r1, *ra, *rb;
	ylex = yylex();
	if (ylex >= NOARG && ylex < MATCH) {
		yyerror("syntax error");
	}
	if (ylex == A_STRING) {
		r1 = Av[Argi++];
		temp = Argi;
	}
	else {
		if (ylex == '(') {
			paren++;
			Argi++;
			r1 = expres(0,Argi);
			Argi--;
		}
	}
lop:
	ylex = yylex();
	if (ylex > NOARG && ylex < MATCH) {
		op1 = ylex;
		Argi++;
		if (pri[op1-OR] <= prior ) 
			return r1;
		else {
			switch(op1) {
			case OR:
			case AND:
				r1 = conj(op1,r1,expres(pri[op1-OR],0));
				break;
			case EQ:
			case LT:
			case GT:
			case LEQ:
			case GEQ:
			case NEQ:
				r1=rel(op1,r1,expres(pri[op1-OR],0));
				break;
			case ADD:
			case SUBT:
			case MULT:
			case DIV:
			case REM:
				r1=arith(op1,r1,expres(pri[op1-OR],0));
				break;
			case MCH:
				r1=match(r1,expres(pri[op1-OR],0));
				break;
			}
			if(noarg == 1) {
				return r1;
			}
			Argi--;
			goto lop;
		}
	}
	ylex = yylex();
	if(ylex == ')') {
		if(par == Argi) {
			yyerror("syntax error");
		}
		if(par != 0) {
			paren--;
			Argi++;
		}
		Argi++;
		return r1;
	}
	ylex = yylex();
	if(ylex > MCH && ylex <= MATCH) {
		if (Argi == temp) {
			return r1;
		}
		op1 = ylex;
		Argi++;
		switch(op1) {
		case MATCH:
			rb = expres(pri[op1-OR],0);
			ra = expres(pri[op1-OR],0);
		}
		switch(op1) {
		case MATCH: 
			r1 = match(rb,ra); 
			break;
		}
		if(noarg == 1) {
			return r1;
		}
		Argi--;
		goto lop;
	}
	ylex = yylex();
	if (ylex == NOARG) {
		noarg = 1;
	}
	return r1;
}

int
cmd_expr(argc, argv, instr, outstr)
int argc;
char **argv; 
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
{
	Ac = argc;
	Argi = 1;
	noarg = 0;
	paren = 0;
	Av = argv;
	buf = NULL;

	Mstring[0][0] = '\0';

	/*
	 * FMLI: return FAIL if setjmp returns a non-zero value
	 * (i.e., called by longjmp() in yyerror())
	 */
	if (setjmp(Jumpenv) != 0)
		return(FAIL);

	buf = expres(0,1);
	if(Ac != Argi || paren != 0) {
		yyerror("syntax error");
	}

	/*
	 * use FMLI output routines
	 */
	(void) putastr(buf, outstr);
	(void) putastr("\n", outstr);
	return((!strcmp(buf, "0") || !buf[0])? FAIL: SUCCESS);
}

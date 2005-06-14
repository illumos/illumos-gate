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
/*	  All Rights Reserved	*/

%{
#pragma ident	"%Z%%M%	%I%	%E% SMI"
%}

/* Yacc productions for "expr" command: */

%{
typedef	char *yystype;
#define	YYSTYPE	yystype
%}

%token OR AND ADD SUBT MULT DIV REM EQ GT GEQ LT LEQ NEQ
%token A_STRING SUBSTR LENGTH INDEX NOARG MATCH

/* operators listed below in increasing precedence: */
%left OR
%left AND
%left EQ LT GT GEQ LEQ NEQ
%left ADD SUBT
%left MULT DIV REM
%left MCH
%left MATCH
%left SUBSTR
%left LENGTH INDEX
%%

/* a single `expression' is evaluated and printed: */

expression:	expr NOARG = {
			printf("%s\n", $1);
			exit((!strcmp($1,"0")||!strcmp($1,"\0"))? 1: 0);
			}
	;


expr:	'(' expr ')' = { $$ = $2; }
	| expr OR expr   = { $$ = conj(OR, $1, $3); }
	| expr AND expr   = { $$ = conj(AND, $1, $3); }
	| expr EQ expr   = { $$ = rel(EQ, $1, $3); }
	| expr GT expr   = { $$ = rel(GT, $1, $3); }
	| expr GEQ expr   = { $$ = rel(GEQ, $1, $3); }
	| expr LT expr   = { $$ = rel(LT, $1, $3); }
	| expr LEQ expr   = { $$ = rel(LEQ, $1, $3); }
	| expr NEQ expr   = { $$ = rel(NEQ, $1, $3); }
	| expr ADD expr   = { $$ = arith(ADD, $1, $3); }
	| expr SUBT expr   = { $$ = arith(SUBT, $1, $3); }
	| expr MULT expr   = { $$ = arith(MULT, $1, $3); }
	| expr DIV expr   = { $$ = arith(DIV, $1, $3); }
	| expr REM expr   = { $$ = arith(REM, $1, $3); }
	| expr MCH expr	 = { $$ = match($1, $3); }
	| MATCH expr expr = { $$ = match($2, $3); }
	| SUBSTR expr expr expr = { $$ = substr($2, $3, $4); }
	| LENGTH expr       = { $$ = length($2); }
	| INDEX expr expr = { $$ = index($2, $3); }
	| A_STRING
	;
%%

#define ESIZE	256
#define EQL(x,y) !strcmp(x,y)

#define INIT	register char *sp = instring;
#define GETC()		(*sp++)
#define PEEKC()		(*sp)
#define UNGETC(c)	(--sp)
#define RETURN(c)	return
#define ERROR(c)	errxx(c)
#include  <regexp.h>
#include  <malloc.h>

long atol();
char *ltoa(), *strcpy(), *strncpy();
void exit();
char	**Av;
int	Ac;
int	Argi;

char Mstring[1][128];


char *operator[] = {
	"|", "&", "+", "-", "*", "/", "%", ":",
	"=", "==", "<", "<=", ">", ">=", "!=",
	"match", "substr", "length", "index", "\0" };
int op[] = {
	OR, AND, ADD,  SUBT, MULT, DIV, REM, MCH,
	EQ, EQ, LT, LEQ, GT, GEQ, NEQ,
	MATCH, SUBSTR, LENGTH, INDEX };
yylex() {
	register char *p;
	register i;

	if(Argi >= Ac) return NOARG;

	p = Av[Argi++];

	if((*p == '(' || *p == ')') && p[1] == '\0' )
		return (int)*p;
	for(i = 0; *operator[i]; ++i)
		if(EQL(operator[i], p))
			return op[i];

	yylval = p;
	return A_STRING;
}

char *rel(oper, r1, r2) register char *r1, *r2;
{
	register long i;

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

char *arith(oper, r1, r2) char *r1, *r2;
{
	long i1, i2;
	register char *rv;

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
char *conj(oper, r1, r2) char *r1, *r2;
{
	register char *rv;

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

char *substr(v, s, w) char *v, *s, *w; {
register si, wi;
register char *res;

	si = atol(s);
	wi = atol(w);
	while(--si) if(*v) ++v;

	res = v;

	while(wi--) if(*v) ++v;

	*v = '\0';
	return res;
}

char *index(s, t) char *s, *t; {
	register long i, j;
	register char *rv;

	for(i = 0; s[i] ; ++i)
		for(j = 0; t[j] ; ++j)
			if(s[i]==t[j]) {
				(void) strcpy(rv = malloc(8), ltoa(++i));
				return rv;
			}
	return "0";
}

char *length(s) register char *s; {
	register long i = 0;
	register char *rv;

	while(*s++) ++i;

	rv = malloc(8);
	(void) strcpy(rv, ltoa(i));
	return rv;
}

char *match(s, p)
char *s, *p;
{
	register char *rv;

	(void) strcpy(rv=malloc(8), ltoa((long)ematch(s, p)));
	if(nbra) {
		rv = malloc((unsigned) strlen(Mstring[0]) + 1);
		(void) strcpy(rv, Mstring[0]);
	}
	return rv;
}

ematch(s, p)
char *s;
register char *p;
{
	static char expbuf[ESIZE];
	char *compile();
	register num;
	extern char *braslist[], *braelist[], *loc2;

	compile(p, expbuf, &expbuf[ESIZE], 0);
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

errxx(err)
register err;
{
	register char *message;

	switch(err) {
		case 11:
			message = "Range endpoint too large";
			break;
		case 16:
			message = "Bad number";
			break;
		case 25:
			message = "``\\digit'' out of range";
			break;
		case 36:
			message = "Illegal or missing delimiter";
			break;
		case 41:
			message = "No remembered search string";
			break;
		case 42:
			message = "\\( \\) imbalance";
			break;
		case 43:
			message = "Too many \\(";
			break;
		case 44:
			message = "More than 2 numbers given in \\{ \\}";
			break;
		case 45:
			message = "} expected after \\";
			break;
		case 46:
			message = "First number exceeds second in \\{ \\}";
			break;
		case 49:
			message = "[ ] imbalance";
			break;
		case 50:
			message = "Regular expression too long";
			break;
		default:
			message = "Unknown regexp error code!!";
			break;
	}
	yyerror(message);
}

yyerror(s)
char *s;
{
	(void) write(2, "expr: ", 6);
	(void) write(2, s, (unsigned) strlen(s));
	(void) write(2, "\n", 1);
	exit(2);
}

char *ltoa(l)
long l;
{
	static char str[20];
	register char *sp;
	register i;
	register neg;

	if(l == 0x80000000L)
		return "-2147483648";
	neg = 0;
	if(l < 0)
		++neg, l = -l;
	sp = &str[20];
	*--sp = '\0';
	do {
		i = l % 10;
		*--sp = '0' + i;
		l /= 10;
	} 
	while(l);
	if(neg)
		*--sp = '-';
	return sp;
}

main(argc, argv) char **argv;
{
	Ac = argc;
	Argi = 1;
	Av = argv;
	yyparse();
}

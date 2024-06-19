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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

%{
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <signal.h>

static void getout(int)	__NORETURN;
static int *bundle(int, ...);
static void usage(void);

int	cpeek(char, int, char, int, char);
int	yyerror(const char *);

#define	STRING_SIZE	(BC_STRING_MAX + 3)	/* string plus quotes */
						/* plus NULL */

FILE	*in;
char	cary[LINE_MAX+1];
char	*cp = { cary };
char	*cpend = &cary[LINE_MAX];	/* last address (not the null char) */
char	string[STRING_SIZE];
char	*str = { string };
int	crs = '0';
int	rcrs = '0';		/* reset crs */
int	bindx = 0;
int	lev = 0;			/* current scope level */
int	ln;				/* line number of current file */
int	*ttp;
char	*ss;				/* current input source */
int	bstack[10] = { 0 };
char	*numb[15] = {
	" 0", " 1", " 2", " 3", " 4", " 5",
	" 6", " 7", " 8", " 9", " 10", " 11",
	" 12", " 13", " 14"
};
int	*pre, *post;
int	interact = 0;			/* talking to a tty? */
%}

%union {
	int *iptr;
	char *cptr;
	int cc;
	}
%start start;
%type <iptr> stat def slist dlets e
%type <iptr> re fprefix cargs eora cons constant lora
%right '='
%left '+' '-'
%left '*' '/' '%'
%right '^'
%left UMINUS

%token <cptr> LETTER
%type <cptr> EQOP CRS
%token <cc> DIGIT SQRT LENGTH _IF FFF EQ
%token <cc> _WHILE _FOR NE LE GE INCR DECR
%token <cc> _RETURN _BREAK _DEFINE BASE OBASE SCALE
%token <cc> EQPL EQMI EQMUL EQDIV EQREM EQEXP
%token <cptr> _AUTO DOT
%token <cc> QSTR

%%
start	:
	| start stat tail
		{
			output($2);
		}
	| start def dargs ')' '{' dlist slist '}'
		{
			ttp = bundle(6, pre, $7, post, "0", numb[lev], "Q");
			conout(ttp, (char *)$2);
			rcrs = crs;
			output((int *)"");
			lev = bindx = 0;
		}
	;

dlist	: tail
	| dlist _AUTO dlets tail
	;

stat	: e
		{
			bundle(2, $1, "ps.");
		}
	|
		{
			bundle(1, "");
		}
	| QSTR
		{
			bundle(3, "[", $1, "]P");
		}
	| LETTER '=' e
		{
			bundle(3, $3, "s", $1);
		}
	| LETTER '[' e ']' '=' e
		{
			bundle(4, $6, $3, ":", geta($1));
		}
	| LETTER EQOP e
		{
			bundle(6, "l", $1, $3, $2, "s", $1);
		}
	| LETTER '[' e ']' EQOP e
		{
			bundle(8, $3, ";", geta($1), $6, $5, $3, ":", geta($1));
		}
	| _BREAK
		{
			bundle(2, numb[lev-bstack[bindx-1]], "Q");
		}
	| _RETURN '(' e ')'
		{
			bundle(4, $3, post, numb[lev], "Q");
		}
	| _RETURN '(' ')'
		{
			bundle(4, "0", post, numb[lev], "Q");
		}
	| _RETURN
		{
			bundle(4, "0", post, numb[lev], "Q");
		}
	| SCALE '=' e
		{
			bundle(2, $3, "k");
		}
	| SCALE EQOP e
		{
			bundle(4, "K", $3, $2, "k");
		}
	| BASE '=' e
		{
			bundle(2, $3, "i");
		}
	| BASE EQOP e
		{
			bundle(4, "I", $3, $2, "i");
		}
	| OBASE '=' e
		{
			bundle(2, $3, "o");
		}
	| OBASE EQOP e
		{
			bundle(4, "O", $3, $2, "o");
		}
	| '{' slist '}'
		{
			$$ = $2;
		}
	| FFF
		{
			bundle(1, "fY");
		}
	| error
		{
			bundle(1, "c");
		}
	| _IF CRS BLEV '(' re ')' stat
		{
			conout($7, $2);
			bundle(3, $5, $2, " ");
		}
	| _WHILE CRS '(' re ')' stat BLEV
		{
			bundle(3, $6, $4, $2);
			conout($$, $2);
			bundle(3, $4, $2, " ");
		}
	| fprefix CRS re ';' e ')' stat BLEV
		{
			bundle(5, $7, $5, "s.", $3, $2);
			conout($$, $2);
			bundle(5, $1, "s.", $3, $2, " ");
		}
	| '~' LETTER '=' e
		{
			bundle(3, $4, "S", $2);
		}
	;

EQOP	: EQPL
		{
			$$ = "+";
		}
	| EQMI
		{
			$$ = "-";
		}
	| EQMUL
		{
			$$ = "*";
		}
	| EQDIV
		{
			$$ = "/";
		}
	| EQREM
		{
			$$ = "%%";
		}
	| EQEXP
		{
			$$ = "^";
		}
	;

fprefix	: _FOR '(' e ';'
		{
			$$ = $3;
		}
	;

BLEV	:
		{
			--bindx;
		}
	;

slist	: stat
	| slist tail stat
		{
			bundle(2, $1, $3);
		}
	;

tail	: '\n'
		{
			ln++;
		}
	| ';'
	;

re	: e EQ e
		{
			$$ = bundle(3, $1, $3, "=");
		}
	| e '<' e
		{
			bundle(3, $1, $3, ">");
		}
	| e '>' e
		{
			bundle(3, $1, $3, "<");
		}
	| e NE e
		{
			bundle(3, $1, $3, "!=");
		}
	| e GE e
		{
			bundle(3, $1, $3, "!>");
		}
	| e LE e
		{
			bundle(3, $1, $3, "!<");
		}
	| e
		{
			bundle(2, $1, " 0!=");
		}
	;

e	: e '+' e
		{
			bundle(3, $1, $3, "+");
		}
	| e '-' e
		{
			bundle(3, $1, $3, "-");
		}
	| '-' e		%prec UMINUS
		{
			bundle(3, " 0", $2, "-");
		}
	| e '*' e
		{
			bundle(3, $1, $3, "*");
		}
	| e '/' e
		{
			bundle(3, $1, $3, "/");
		}
	| e '%' e
		{
			bundle(3, $1, $3, "%%");
		}
	| e '^' e
		{
			bundle(3, $1, $3, "^");
		}
	| LETTER '[' e ']'
		{
			bundle(3, $3, ";", geta($1));
		}
	| LETTER INCR
		{
			bundle(4, "l", $1, "d1+s", $1);
		}
	| INCR LETTER
		{
			bundle(4, "l", $2, "1+ds", $2);
		}
	| DECR LETTER
		{
			bundle(4, "l", $2, "1-ds", $2);
		}
	| LETTER DECR
		{
			bundle(4, "l", $1, "d1-s", $1);
		}
	| LETTER '[' e ']' INCR
		{
			bundle(7, $3, ";", geta($1), "d1+", $3, ":", geta($1));
		}
	| INCR LETTER '[' e ']'
		{
			bundle(7, $4, ";", geta($2), "1+d", $4, ":", geta($2));
		}
	| LETTER '[' e ']' DECR
		{
			 bundle(7, $3, ";", geta($1), "d1-", $3, ":", geta($1));
		}
	| DECR LETTER '[' e ']'
		{
			bundle(7, $4, ";", geta($2), "1-d", $4, ":", geta($2));
		}
	| SCALE INCR
		{
			bundle(1, "Kd1+k");
		}
	| INCR SCALE
		{
			bundle(1, "K1+dk");
		}
	| SCALE DECR
		{
			bundle(1, "Kd1-k");
		}
	| DECR SCALE
		{
			bundle(1, "K1-dk");
		}
	| BASE INCR
		{
			bundle(1, "Id1+i");
		}
	| INCR BASE
		{
			bundle(1, "I1+di");
		}
	| BASE DECR
		{
			bundle(1, "Id1-i");
		}
	| DECR BASE
		{
			bundle(1, "I1-di");
		}
	| OBASE INCR
		{
			bundle(1, "Od1+o");
		}
	| INCR OBASE
		{
			bundle(1, "O1+do");
		}
	| OBASE DECR
		{
			bundle(1, "Od1-o");
		}
	| DECR OBASE
		{
			bundle(1, "O1-do");
		}
	| LETTER '(' cargs ')'
		{
			bundle(4, $3, "l", getf($1), "x");
		}
	| LETTER '(' ')'
		{
			bundle(3, "l", getf($1), "x");
		}
	| cons
		{
			bundle(2, " ", $1);
		}
	| DOT cons
		{
			bundle(2, " .", $2);
		}
	| cons DOT cons
		{
			bundle(4, " ", $1, ".", $3);
		}
	| cons DOT
		{
			bundle(3, " ", $1, ".");
		}
	| DOT
		{
			$<cptr>$ = "l.";
		}
	| LETTER
		{
			bundle(2, "l", $1);
		}
	| LETTER '=' e
		{
			bundle(3, $3, "ds", $1);
		}
	| LETTER EQOP e		%prec '='
		{
			bundle(6, "l", $1, $3, $2, "ds", $1);
		}
	| LETTER '[' e ']' '=' e
		{
			bundle(5, $6, "d", $3, ":", geta($1));
		}
	| LETTER '[' e ']' EQOP e
		{
			bundle(9, $3, ";", geta($1), $6, $5, "d", $3, ":",
			    geta($1));
		}
	| LENGTH '(' e ')'
		{
			bundle(2, $3, "Z");
		}
	| SCALE '(' e ')'
		{
			bundle(2, $3, "X");	/* must be before '(' e ')' */
		}
	| '(' e ')'
		{
			$$ = $2;
		}
	| '?'
		{
			bundle(1, "?");
		}
	| SQRT '(' e ')'
		{
			bundle(2, $3, "v");
		}
	| '~' LETTER
		{
			bundle(2, "L", $2);
		}
	| SCALE '=' e
		{
			bundle(2, $3, "dk");
		}
	| SCALE EQOP e		%prec '='
		{
			bundle(4, "K", $3, $2, "dk");
		}
	| BASE '=' e
		{
			bundle(2, $3, "di");
		}
	| BASE EQOP e		%prec '='
		{
			bundle(4, "I", $3, $2, "di");
		}
	| OBASE '=' e
		{
			bundle(2, $3, "do");
		}
	| OBASE EQOP e		%prec '='
		{
			bundle(4, "O", $3, $2, "do");
		}
	| SCALE
		{
			bundle(1, "K");
		}
	| BASE
		{
			bundle(1, "I");
		}
	| OBASE
		{
			bundle(1, "O");
		}
	;

cargs	: eora
	| cargs ',' eora
		{
			bundle(2, $1, $3);
		}
	;
eora	: e
	| LETTER '[' ']'
		{
			bundle(2, "l", geta($1));
		}
	;

cons	: constant
		{
			*cp++ = '\0';
		}

constant: '_'
		{
			checkbuffer();
			$<cptr>$ = cp;
			*cp++ = '_';
		}
	| DIGIT
		{
			checkbuffer();
			$<cptr>$ = cp;
			*cp++ = $1;
		}
	| constant DIGIT
		{
			checkbuffer();
			*cp++ = $2;
		}
	;

CRS	:
		{
			checkbuffer();
			$$ = cp;
			*cp++ = crs++;
			*cp++ = '\0';
			if (crs == '[')
				crs += 3;
			if (crs == 'a')
				crs = '{';
			if (crs >= 0241) {
				(void) yyerror("program too big");
				getout(1);
			}
			bstack[bindx++] = lev++;
		}
	;

def	: _DEFINE LETTER '('
		{
			$$ = getf($2);
			pre = (int *)"";
			post = (int *)"";
			lev = 1;
			bstack[bindx = 0] = 0;
		}
	;

dargs	:		/* empty */
	| lora
		{
			pp($1);
		}
	| dargs ',' lora
		{
			pp($3);
		}
	;

dlets	: lora
		{
			tp($1);
		}
	| dlets ',' lora
		{
			tp($3);
		}
	;

lora	: LETTER
		{
			$<cptr>$ = $1;
		}
	| LETTER '[' ']'
		{
			$$ = geta($1);
		}
	;

%%
#define	error	256

int	peekc = -1;
int	ifile;			/* current index into sargv */
int	sargc;			/* size of sargv[] */
char	**sargv;		/* saved arg list without options */

char funtab[52] = {
	01, 0, 02, 0, 03, 0, 04, 0, 05, 0, 06, 0, 07, 0,
	010, 0, 011, 0, 012, 0, 013, 0, 014, 0, 015, 0, 016, 0, 017, 0,
	020, 0, 021, 0, 022, 0, 023, 0, 024, 0, 025, 0, 026, 0, 027, 0,
	030, 0, 031, 0, 032, 0
};

unsigned char atab[52] = {
	0241, 0, 0242, 0, 0243, 0, 0244, 0, 0245, 0, 0246, 0, 0247, 0, 0250, 0,
	0251, 0, 0252, 0, 0253, 0, 0254, 0, 0255, 0, 0256, 0, 0257, 0, 0260, 0,
	0261, 0, 0262, 0, 0263, 0, 0264, 0, 0265, 0, 0266, 0, 0267, 0, 0270, 0,
	0271, 0, 0272, 0
};

char *letr[26] = {
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
	"k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
	"u", "v", "w", "x", "y", "z"
};

int
yylex(void)
{
	int c, ch;

restart:
	c = getch();
	peekc = -1;
	while (c == ' ' || c == '\t')
		c = getch();
	if (c == '\\') {
		(void) getch();
		goto restart;
	}
	if (c <= 'z' && c >= 'a') {
		/* look ahead to look for reserved words */
		peekc = getch();
		if (peekc >= 'a' && peekc <= 'z') {
			/* must be reserved word */
			if (c == 'i' && peekc == 'f') {
				c = _IF;
				goto skip;
			}
			if (c == 'w' && peekc == 'h') {
				c = _WHILE;
				goto skip;
			}
			if (c == 'f' && peekc == 'o') {
				c = _FOR;
				goto skip;
			}
			if (c == 's' && peekc == 'q') {
				c = SQRT;
				goto skip;
			}
			if (c == 'r' && peekc == 'e') {
				c = _RETURN;
				goto skip;
			}
			if (c == 'b' && peekc == 'r') {
				c = _BREAK;
				goto skip;
			}
			if (c == 'd' && peekc == 'e') {
				c = _DEFINE;
				goto skip;
			}
			if (c == 's' && peekc == 'c') {
				c = SCALE;
				goto skip;
			}
			if (c == 'b' && peekc == 'a') {
				c = BASE;
				goto skip;
			}
			if (c == 'i' && peekc == 'b') {
				c = BASE;
				goto skip;
			}
			if (c == 'o' && peekc == 'b') {
				c = OBASE;
				goto skip;
			}
			if (c == 'd' && peekc == 'i') {
				c = FFF;
				goto skip;
			}
			if (c == 'a' && peekc == 'u') {
				c = _AUTO;
				goto skip;
			}
			if (c == 'l' && peekc == 'e') {
				c = LENGTH;
				goto skip;
			}
			if (c == 'q' && peekc == 'u') {
				getout(0);
			}
			/* could not be found */
			return (error);

skip:	/* skip over rest of word */
			peekc = -1;
			while ((ch = getch()) >= 'a' && ch <= 'z')
				;
			peekc = ch;
			return (c);
		}

		/* usual case; just one single letter */

		yylval.cptr = letr[c-'a'];
		return (LETTER);
	}

	if (c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
		yylval.cc = c;
		return (DIGIT);
	}

	switch (c) {
	case '.':
		return (DOT);

	case '=':
		switch ((peekc = getch())) {
		case '=':
			c = EQ;
			goto gotit;

		case '+':
			c = EQPL;
			goto gotit;

		case '-':
			c = EQMI;
			goto gotit;

		case '*':
			c = EQMUL;
			goto gotit;

		case '/':
			c = EQDIV;
			goto gotit;

		case '%':
			c = EQREM;
			goto gotit;

		case '^':
			c = EQEXP;
			goto gotit;

		default:
			return ('=');
gotit:
			peekc = -1;
			return (c);
		}

	case '+':
		return (cpeek('+', INCR, '=', EQPL, '+'));

	case '-':
		return (cpeek('-', DECR, '=', EQMI, '-'));

	case '*':
		return (cpeek('=', EQMUL, '\0', 0, '*'));

	case '%':
		return (cpeek('=', EQREM, '\0', 0, '%'));

	case '^':
		return (cpeek('=', EQEXP, '\0', 0, '^'));

	case '<':
		return (cpeek('=', LE, '\0', 0, '<'));

	case '>':
		return (cpeek('=', GE, '\0', 0, '>'));

	case '!':
		return (cpeek('=', NE, '\0', 0, '!'));

	case '/':
		if ((peekc = getch()) == '=') {
			peekc = -1;
			return (EQDIV);
		}
		if (peekc == '*') {
			peekc = -1;
			while ((getch() != '*') || ((peekc = getch()) != '/'))
				;
			peekc = -1;
			goto restart;
		}
		else
			return (c);

	case '"':
		yylval.cptr = str;
		while ((c = getch()) != '"') {
			*str++ = c;
			if (str >= &string[STRING_SIZE-1]) {
				(void) yyerror("string space exceeded");
				getout(1);
			}
		}
		*str++ = '\0';
		return (QSTR);

	default:
		return (c);
	}
}

int
cpeek(char c1, int yes1, char c2, int yes2, char none)
{
	int r;

	peekc = getch();
	if (peekc == c1)
		r = yes1;
	else if (peekc == c2)
		r = yes2;
	else
		return (none);
	peekc = -1;
	return (r);
}


int
getch(void)
{
	int ch;
	char mbuf[LINE_MAX];

loop:
	ch = (peekc < 0) ? getc(in) : peekc;
	peekc = -1;
	if (ch != EOF)
		return (ch);

	if (++ifile >= sargc) {
		if (ifile >= sargc+1)
			getout(0);
		in = stdin;
		ln = 0;
		goto loop;
	}

	(void) fclose(in);
	if ((in = fopen(sargv[ifile], "r")) != NULL) {
		ln = 0;
		ss = sargv[ifile];
		goto loop;
	}
	(void) snprintf(mbuf, sizeof (mbuf), "can't open input file %s",
		sargv[ifile]);
	ln = -1;
	ss = "command line";
	(void) yyerror(mbuf);
	getout(1);
	/*NOTREACHED*/
}

#define	b_sp_max	5000
int b_space[b_sp_max];
int *b_sp_nxt = { b_space };

int	bdebug = 0;

static int *
bundle(int i, ...)
{
	va_list ap;
	int *q;

	va_start(ap, i);
	q = b_sp_nxt;
	if (bdebug)
		printf("bundle %d elements at %o\n", i, q);
	while (i-- > 0) {
		if (b_sp_nxt >= & b_space[b_sp_max])
			(void) yyerror("bundling space exceeded");
		*b_sp_nxt++ = va_arg(ap, int);
	}
	* b_sp_nxt++ = 0;
	yyval.iptr = q;
	va_end(ap);
	return (q);
}

void
routput(int *p)
{
	if (bdebug) printf("routput(%o)\n", p);
	if (p >= &b_space[0] && p < &b_space[b_sp_max]) {
		/* part of a bundle */
		while (*p != 0)
			routput((int *)*p++);
	}
	else
		printf((char *)p);	 /* character string */
}

void
output(int *p)
{
	routput(p);
	b_sp_nxt = & b_space[0];
	printf("\n");
	(void) fflush(stdout);
	cp = cary;
	crs = rcrs;
}

void
conout(int *p, char *s)
{
	printf("[");
	routput(p);
	printf("]s%s\n", s);
	(void) fflush(stdout);
	lev--;
}

int
yyerror(const char *s)
{
	if (ifile >= sargc)
		ss = "teletype";

	if (ss == 0 || *ss == 0)
		(void) fprintf(stderr, gettext("%s on line %d\n"), s, ln+1);
	else
		(void) fprintf(stderr, gettext("%s on line %d, %s\n"),
		    s, ln+1, ss);
	(void) fflush(stderr);

	cp = cary;
	crs = rcrs;
	bindx = 0;
	lev = 0;
	b_sp_nxt = &b_space[0];
	return (0);
}

void
checkbuffer(void)
{
	/* Do not exceed the last char in input line buffer */
	if (cp >= cpend) {
		(void) yyerror("line too long\n");
		getout(1);
	}
}

void
pp(int *s)
{
	/* puts the relevant stuff on pre and post for the letter s */

	(void) bundle(3, "S", s, pre);
	pre = yyval.iptr;
	(void) bundle(4, post, "L", s, "s.");
	post = yyval.iptr;
}

void
tp(int *s)
{		/* same as pp, but for temps */
	bundle(3, "0S", s, pre);
	pre = yyval.iptr;
	bundle(4, post, "L", s, "s.");
	post = yyval.iptr;
}

void
yyinit(int argc, char **argv)
{
	char	mbuf[LINE_MAX];

	(void) signal(SIGINT, SIG_IGN);		/* ignore all interrupts */

	sargv = argv;
	sargc = argc;
	if (sargc == 0)
		in = stdin;
	else if ((in = fopen(sargv[0], "r")) == NULL) {
		(void) snprintf(mbuf, sizeof (mbuf), "can't open input file %s",
			sargv[0]);
		ln = -1;
		ss = "command line";
		(void) yyerror(mbuf);
		getout(1);
	}
	ifile = 0;
	ln = 0;
	ss = sargv[0];
}

static void
getout(int code)
{
	printf("q");
	(void) fflush(stdout);
	exit(code);
}

int *
getf(char *p)
{
	return ((int *) &funtab[2*(*p -0141)]);
}

int *
geta(char *p)
{
	return ((int *) &atab[2*(*p - 0141)]);
}

int
main(int argc, char **argv)
{
	int	p[2];
	int	cflag = 0;
	int	lflag = 0;
	int	flag = 0;
	char	**av;
	int	filecounter = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((flag = getopt(argc, argv, "dcl")) != EOF) {
		switch (flag) {
		case 'd':
		case 'c':
			cflag++;
			break;

		case 'l':
			lflag++;
			break;

		default:
			fflush(stdout);
			usage();
			break;
		}
	}

	argc -= optind;
	av = &argv[optind];

	/*
	* argc is the count of arguments, which should be filenames,
	* remaining in argv. av is a pointer to the first of the
	* remaining arguments.
	*/

	for (filecounter = 0; filecounter < argc; filecounter++) {
		if ((strlen(av[filecounter])) >= PATH_MAX) {
			(void) fprintf(stderr,
			    gettext("File argument too long\n"));
			exit(2);
		}
	}

	if (lflag) {
		/*
		* if the user wants to include the math library, prepend
		* the math library filename to the argument list by
		* overwriting the last option (there must be at least one
		* supplied option if this is being done).
		*/
		av = &argv[optind-1];
		av[0] = "/usr/lib/lib.b";
		argc++;
	}

	if (cflag) {
		yyinit(argc, av);
		yyparse();
		exit(0);
	}

	pipe(p);
	if (fork() == 0) {
		(void) close(1);
		dup(p[1]);
		(void) close(p[0]);
		(void) close(p[1]);
		yyinit(argc, av);
		yyparse();
		exit(0);
	}
	(void) close(0);
	dup(p[0]);
	(void) close(p[0]);
	(void) close(p[1]);
#ifdef XPG6
	execl("/usr/xpg6/bin/dc", "dc", "-", 0);
#else
	execl("/usr/bin/dc", "dc", "-", 0);
#endif

	return (1);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: bc [ -c ] [ -l ] [ file ... ]\n"));
	exit(2);
}

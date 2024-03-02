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
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <regexpr.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#define	A_STRING 258
#define	NOARG 259
#define	OR 260
#define	AND 261
#define	EQ 262
#define	LT 263
#define	GT 264
#define	GEQ 265
#define	LEQ 266
#define	NEQ 267
#define	ADD 268
#define	SUBT 269
#define	MULT 270
#define	DIV 271
#define	REM 272
#define	MCH 273
#define	MATCH 274
#define	SUBSTR 275
#define	LENGTH 276
#define	INDEX  277

/* size of subexpression array */
#define	MSIZE	LINE_MAX
#define	error(c)	errxx()
#define	EQL(x, y) (strcmp(x, y) == 0)

#define	ERROR(c)	errxx()
#define	MAX_MATCH 20
static int ematch(char *, char *);
static void yyerror(char *);
static void errxx();
static void *exprmalloc(size_t size);

static char *ltoa();
static char *lltoa();
static char	**Av;
static char *buf;
static int	Ac;
static int	Argi;
static int noarg;
static int paren;
/*
 *	Array used to store subexpressions in regular expressions
 *	Only one subexpression allowed per regular expression currently
 */
static char Mstring[1][MSIZE];


static char *operator[] = {
	"|", "&", "+", "-", "*", "/", "%", ":",
	"=", "==", "<", "<=", ">", ">=", "!=",
	"match",
	"substr", "length", "index",
	"\0" };
static	int op[] = {
	OR, AND, ADD,  SUBT, MULT, DIV, REM, MCH,
	EQ, EQ, LT, LEQ, GT, GEQ, NEQ,
	MATCH,
	SUBSTR, LENGTH, INDEX
	};
static	int pri[] = {
	1, 2, 3, 3, 3, 3, 3, 3, 4, 4, 5, 5, 5, 6, 7,
	7, 7, 7
	};


/*
 * clean_buf - XCU4 mod to remove leading zeros from negative signed
 *		numeric output, e.g., -00001 becomes -1
 */
static void
clean_buf(char *buf)
{
	int i = 0;
	int is_a_num = 1;
	int len;
	long long num;

	if (buf[0] == '\0')
		return;
	len = strlen(buf);
	if (len <= 0)
		return;

	if (buf[0] == '-') {
		i++;		/* Skip the leading '-' see while loop */
		if (len <= 1)	/* Is it a '-' all by itself? */
			return; /* Yes, so return */

		while (i < len) {
			if (! isdigit(buf[i])) {
				is_a_num = 0;
				break;
			}
			i++;
		}
		if (is_a_num) {
			(void) sscanf(buf, "%lld", &num);
			(void) sprintf(buf, "%lld", num);
		}
	}
}

/*
 * End XCU4 mods.
 */

static int
yylex(void)
{
	char *p;
	int i;

	if (Argi >= Ac)
		return (NOARG);

	p = Av[Argi];

	if ((*p == '(' || *p == ')') && p[1] == '\0')
		return ((int)*p);
	for (i = 0; *operator[i]; ++i)
		if (EQL(operator[i], p))
			return (op[i]);


	return (A_STRING);
}

static char *
rel(int oper, char *r1, char *r2)
{
	long long i, l1, l2;

	if (ematch(r1, "-\\{0,1\\}[0-9]*$") &&
	    ematch(r2, "-\\{0,1\\}[0-9]*$")) {
		errno = 0;
		l1 = strtoll(r1, (char **)NULL, 10);
		l2 = strtoll(r2, (char **)NULL, 10);
		if (errno) {
#ifdef XPG6
		/* XPG6: stdout will always contain newline even on error */
			(void) write(1, "\n", 1);
#endif
			if (errno == ERANGE) {
				(void) fprintf(stderr, gettext(
				    "expr: Integer argument too large\n"));
				exit(3);
			} else {
				perror("expr");
				exit(3);
			}
		}
		switch (oper) {
		case EQ:
			i = (l1 == l2);
			break;
		case GT:
			i = (l1 > l2);
			break;
		case GEQ:
			i = (l1 >= l2);
			break;
		case LT:
			i = (l1 < l2);
			break;
		case LEQ:
			i = (l1 <= l2);
			break;
		case NEQ:
			i = (l1 != l2);
			break;
		}
	}
	else
	{
			i = strcoll(r1, r2);
		switch (oper) {
		case EQ:
			i = i == 0;
			break;
		case GT:
			i = i > 0;
			break;
		case GEQ:
			i = i >= 0;
			break;
		case LT:
			i = i < 0;
			break;
		case LEQ:
			i = i <= 0;
			break;
		case NEQ:
			i = i != 0;
			break;
		}
	}
	return (i ? "1": "0");
}

static char *
arith(int oper, char *r1, char *r2)
{
	long long i1, i2;
	char *rv;

	if (!(ematch(r1, "-\\{0,1\\}[0-9]*$") &&
	    ematch(r2, "-\\{0,1\\}[0-9]*$")))
		yyerror("non-numeric argument");
	errno = 0;
	i1 = strtoll(r1, (char **)NULL, 10);
	i2 = strtoll(r2, (char **)NULL, 10);
	if (errno) {
#ifdef XPG6
	/* XPG6: stdout will always contain newline even on error */
		(void) write(1, "\n", 1);
#endif
		if (errno == ERANGE) {
			(void) fprintf(stderr, gettext(
			    "expr: Integer argument too large\n"));
			exit(3);
		} else {
			perror("expr");
			exit(3);
		}
	}

	switch (oper) {
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
	rv = exprmalloc(25);
	(void) strcpy(rv, lltoa(i1));
	return (rv);
}

static char
*conj(int oper, char *r1, char *r2)
{
	char *rv;

	switch (oper) {

	case OR:
		if (EQL(r1, "0") || EQL(r1, "")) {
			if (EQL(r2, "0") || EQL(r2, ""))
				rv = "0";
			else
				rv = r2;
		} else
			rv = r1;
		break;
	case AND:
		if (EQL(r1, "0") || EQL(r1, ""))
			rv = "0";
		else if (EQL(r2, "0") || EQL(r2, ""))
			rv = "0";
		else
			rv = r1;
		break;
	}
	return (rv);
}

char *
substr(char *v, char *s, char *w)
{
	int si, wi;
	char *res;

	si = atol(s);
	wi = atol(w);
	while (--si)
		if (*v) ++v;

	res = v;

	while (wi--)
		if (*v) ++v;

	*v = '\0';
	return (res);
}

char *
index(char *s, char *t)
{
	long i, j;
	char *rv;

	for (i = 0; s[i]; ++i)
		for (j = 0; t[j]; ++j)
			if (s[i] == t[j]) {
				(void) strcpy(rv = exprmalloc(8), ltoa(++i));
				return (rv);
			}
	return ("0");
}

char *
length(char *s)
{
	long i = 0;
	char *rv;

	while (*s++) ++i;

	rv = exprmalloc(8);
	(void) strcpy(rv, ltoa(i));
	return (rv);
}

static char *
match(char *s, char *p)
{
	char *rv;
	long val;			/* XCU4 */

	(void) strcpy(rv = exprmalloc(8), ltoa(val = (long)ematch(s, p)));
	if (nbra /* && val != 0 */) {
		rv = exprmalloc((unsigned)strlen(Mstring[0]) + 1);
		(void) strcpy(rv, Mstring[0]);
	}
	return (rv);
}


/*
 * ematch	- XCU4 mods involve calling compile/advance which simulate
 *		  the obsolete compile/advance functions using regcomp/regexec
 */
static int
ematch(char *s, char *p)
{
	static char *expbuf;
	char *nexpbuf;
	int num;
#ifdef XPG4
	int nmatch;		/* number of matched bytes */
	char tempbuf[256];
	char *tmptr1 = 0;	/* If tempbuf is not large enough */
	char *tmptr;
	int nmbchars;		/* number characters in multibyte string */
#endif

	nexpbuf = compile(p, (char *)0, (char *)0);	/* XCU4 regex mod */
	if (0 /* XXX nbra > 1*/)
		yyerror("Too many '\\('s");
	if (regerrno) {
		if (regerrno != 41 || expbuf == NULL)
			errxx();
	} else {
		if (expbuf)
			free(expbuf);
		expbuf = nexpbuf;
	}
	if (advance(s, expbuf)) {
		if (nbra > 0) {
			p = braslist[0];
			num = braelist[0] - p;
			if ((num > MSIZE - 1) || (num < 0))
				yyerror("string too long");
			(void) strncpy(Mstring[0], p, num);
			Mstring[0][num] = '\0';
		}
#ifdef XPG4
		/*
		 *  Use mbstowcs to find the number of multibyte characters
		 *  in the multibyte string beginning at s, and
		 *  ending at loc2.  Create a separate string
		 *  of the substring, so it can be passed to mbstowcs.
		 */
		nmatch = loc2 - s;
		if (nmatch > ((sizeof (tempbuf) / sizeof (char)) - 1)) {
			tmptr1 = exprmalloc(nmatch + 1);
			tmptr = tmptr1;
		} else {
			tmptr = tempbuf;
		}
		memcpy(tmptr, s, nmatch);
		*(tmptr + nmatch) = '\0';
		if ((nmbchars = mbstowcs(NULL, tmptr, 0)) == -1) {
			yyerror("invalid multibyte character encountered");
			if (tmptr1 != NULL)
				free(tmptr1);
			return (0);
		}
		if (tmptr1 != NULL)
			free(tmptr1);
		return (nmbchars);
#else
		return (loc2-s);
#endif
	}
	return (0);
}

static void
errxx()
{
	yyerror("RE error");
}

static void
yyerror(char *s)
{
#ifdef XPG6
	/* XPG6: stdout will always contain newline even on error */
	(void) write(1, "\n", 1);
#endif
	(void) write(2, "expr: ", 6);
	(void) write(2, gettext(s), (unsigned)strlen(gettext(s)));
	(void) write(2, "\n", 1);
	exit(2);
	/* NOTREACHED */
}

static char *
ltoa(long l)
{
	static char str[20];
	char *sp = &str[18];	/* u370 */
	int i;
	int neg = 0;

	if ((unsigned long)l == 0x80000000UL)
		return ("-2147483648");
	if (l < 0)
		++neg, l = -l;
	str[19] = '\0';
	do {
		i = l % 10;
		*sp-- = '0' + i;
		l /= 10;
	} while (l);
	if (neg)
		*sp-- = '-';
	return (++sp);
}

static char *
lltoa(long long l)
{
	static char str[25];
	char *sp = &str[23];
	int i;
	int neg = 0;

	if (l == 0x8000000000000000ULL)
		return ("-9223372036854775808");
	if (l < 0)
		++neg, l = -l;
	str[24] = '\0';
	do {
		i = l % 10;
		*sp-- = '0' + i;
		l /= 10;
	} while (l);
	if (neg)
		*sp-- = '-';
	return (++sp);
}

static char *
expres(int prior, int par)
{
	int ylex, temp, op1;
	char *r1, *ra, *rb, *rc;
	ylex = yylex();
	if (ylex >= NOARG && ylex < MATCH) {
		yyerror("syntax error");
	}
	if (ylex == A_STRING) {
		r1 = Av[Argi++];
		temp = Argi;
	} else {
		if (ylex == '(') {
			paren++;
			Argi++;
			r1 = expres(0, Argi);
			Argi--;
		}
	}
lop:
	ylex = yylex();
	if (ylex > NOARG && ylex < MATCH) {
		op1 = ylex;
		Argi++;
		if (pri[op1-OR] <= prior)
			return (r1);
		else {
			switch (op1) {
			case OR:
			case AND:
				r1 = conj(op1, r1, expres(pri[op1-OR], 0));
				break;
			case EQ:
			case LT:
			case GT:
			case LEQ:
			case GEQ:
			case NEQ:
				r1 = rel(op1, r1, expres(pri[op1-OR], 0));
				break;
			case ADD:
			case SUBT:
			case MULT:
			case DIV:
			case REM:
				r1 = arith(op1, r1, expres(pri[op1-OR], 0));
				break;
			case MCH:
				r1 = match(r1, expres(pri[op1-OR], 0));
				break;
			}
			if (noarg == 1) {
				return (r1);
			}
			Argi--;
			goto lop;
		}
	}
	ylex = yylex();
	if (ylex == ')') {
		if (par == Argi) {
			yyerror("syntax error");
		}
		if (par != 0) {
			paren--;
			Argi++;
		}
		Argi++;
		return (r1);
	}
	ylex = yylex();
	if (ylex > MCH && ylex <= INDEX) {
		if (Argi == temp) {
			return (r1);
		}
		op1 = ylex;
		Argi++;
		switch (op1) {
		case MATCH:
			rb = expres(pri[op1-OR], 0);
			ra = expres(pri[op1-OR], 0);
			break;
		case SUBSTR:
			rc = expres(pri[op1-OR], 0);
			rb = expres(pri[op1-OR], 0);
			ra = expres(pri[op1-OR], 0);
			break;
		case LENGTH:
			ra = expres(pri[op1-OR], 0);
			break;
		case INDEX:
			rb = expres(pri[op1-OR], 0);
			ra = expres(pri[op1-OR], 0);
			break;
		}
		switch (op1) {
		case MATCH:
			r1 = match(rb, ra);
			break;
		case SUBSTR:
			r1 = substr(rc, rb, ra);
			break;
		case LENGTH:
			r1 = length(ra);
			break;
		case INDEX:
			r1 = index(rb, ra);
			break;
		}
		if (noarg == 1) {
			return (r1);
		}
		Argi--;
		goto lop;
	}
	ylex = yylex();
	if (ylex == NOARG) {
		noarg = 1;
	}
	return (r1);
}

void *
exprmalloc(size_t size)
{
	void *rv;

	if ((rv = malloc(size)) == NULL) {
		char *s = gettext("malloc error");

		(void) write(2, "expr: ", 6);
		(void) write(2, s, (unsigned)strlen(s));
		(void) write(2, "\n", 1);
		exit(3);
	}
	return (rv);
}

int
main(int argc, char **argv)
{
	/*
	 * XCU4 allow "--" as argument
	 */
	if (argc > 1 && strcmp(argv[1], "--") == 0)
		argv++, argc--;
	/*
	 * XCU4 - print usage message when invoked without args
	 */
	if (argc < 2) {
#ifdef XPG6
	/* XPG6: stdout will always contain newline even on error */
		(void) write(1, "\n", 1);
#endif
		(void) fprintf(stderr, gettext("Usage: expr expression\n"));
		exit(3);
	}
	Ac = argc;
	Argi = 1;
	noarg = 0;
	paren = 0;
	Av = argv;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	buf = expres(0, 1);
	if (Ac != Argi || paren != 0) {
		yyerror("syntax error");
	}
	/*
	 * XCU4 - strip leading zeros from numeric output
	 */
	clean_buf(buf);
	(void) write(1, buf, (unsigned)strlen(buf));
	(void) write(1, "\n", 1);
	return ((strcmp(buf, "0") == 0 || buf[0] == 0) ? 1 : 0);
}

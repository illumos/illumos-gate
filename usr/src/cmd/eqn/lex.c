/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "e.h"
#include "e.def"
#include <locale.h>

#define	SSIZE	400
char	token[SSIZE];
int	sp;
#define	putbak(c)	*ip++ = c;
#define	PUSHBACK	300	/* maximum pushback characters */
char	ibuf[PUSHBACK+SSIZE];	/* pushback buffer for definitions, etc. */
char	*ip	= ibuf;

extern tbl *keytbl[];
extern tbl *deftbl[];

void define(int);
void delim(void);
void getstr(char *, int);
void include(void);
int openinfile(void);
void pbstr(char *);
void space(void);

int
gtc(void)
{
loop:
	if (ip > ibuf)
		return (*--ip);	/* already present */
	lastchar = getc(curfile);
	if (lastchar == '\n')
		linect++;
	if (lastchar != EOF)
		return (lastchar);
	if (++ifile > svargc) {
		return (EOF);
	}
	(void) fclose(curfile);
	linect = 1;
	if (openinfile() == 0)
		goto loop;
	return (EOF);
}
/*
 *	open file indexed by ifile in svargv, return non zero if fail
 */
int
openinfile(void)
{
	if (strcmp(svargv[ifile], "-") == 0) {
		curfile = stdin;
		return (0);
	} else if ((curfile = fopen(svargv[ifile], "r")) != NULL) {
		return (0);
	}
	error(FATAL, gettext("can't open file %s"), svargv[ifile]);
	return (1);
}

void
pbstr(char *str)
{
	char *p;

	p = str;
	while (*p++)
		;
	--p;
	if (ip >= &ibuf[PUSHBACK])
		error(FATAL, gettext("pushback overflow"));
	while (p > str)
		putbak(*--p);
}

int
yylex(void)
{
	int c;
	tbl *tp, *lookup();

beg:
	while ((c = gtc()) == ' ' || c == '\n')
		;
	yylval = c;
	switch (c) {

	case EOF:
		return (EOF);
	case '~':
		return (SPACE);
	case '^':
		return (THIN);
	case '\t':
		return (TAB);
	case '{':
		return ('{');
	case '}':
		return ('}');
	case '"':
		for (sp = 0; (c = gtc()) != '"' && c != '\n'; ) {
			if (c == '\\')
				if ((c = gtc()) != '"')
					token[sp++] = '\\';
			token[sp++] = c;
			if (sp >= SSIZE)
				error(FATAL, gettext(
				    "quoted string %.20s... too long"), token);
		}
		token[sp] = '\0';
		yylval = (int)&token[0];
		if (c == '\n')
			error(!FATAL, gettext("missing \" in %.20s"), token);
		return (QTEXT);
	}
	if (c == righteq)
		return (EOF);

	putbak(c);
	getstr(token, SSIZE);
	if (dbg) printf(".\tlex token = |%s|\n", token);
	if ((tp = lookup(deftbl, token, NULL)) != NULL) {
		putbak(' ');
		pbstr(tp->defn);
		putbak(' ');
		if (dbg)
			printf(".\tfound %s|=%s|\n", token, tp->defn);
	} else if ((tp = lookup(keytbl, token, NULL)) == NULL) {
		if (dbg) printf(".\t%s is not a keyword\n", token);
		return (CONTIG);
	} else if (tp->defn == (char *)DEFINE ||
	    tp->defn == (char *)NDEFINE || tp->defn == (char *)TDEFINE)
		define((int)tp->defn);
	else if (tp->defn == (char *)DELIM)
		delim();
	else if (tp->defn == (char *)GSIZE)
		globsize();
	else if (tp->defn == (char *)GFONT)
		globfont();
	else if (tp->defn == (char *)INCLUDE)
		include();
	else if (tp->defn == (char *)SPACE)
		space();
	else {
		return ((int)tp->defn);
	}
	goto beg;
}

void
getstr(char *s, int n)
{
	int c;
	char *p;

	p = s;
	while ((c = gtc()) == ' ' || c == '\n')
		;
	if (c == EOF) {
		*s = 0;
		return;
	}
	while (c != ' ' && c != '\t' && c != '\n' && c != '{' && c != '}' &&
	    c != '"' && c != '~' && c != '^' && c != righteq) {
		if (c == '\\')
			if ((c = gtc()) != '"')
				*p++ = '\\';
		*p++ = c;
		if (--n <= 0)
			error(FATAL, gettext("token %.20s... too long"), s);
		c = gtc();
	}
	if (c == '{' || c == '}' || c == '"' || c == '~' || c == '^' ||
	    c == '\t' || c == righteq)
		putbak(c);
	*p = '\0';
	yylval = (int)s;
}

int
cstr(char *s, int quote, int maxs)
{
	int del, c, i;

	s[0] = 0;
	while ((del = gtc()) == ' ' || del == '\t')
		;
	if (quote) {
		for (i = 0; (c = gtc()) != del && c != EOF; ) {
			s[i++] = c;
			if (i >= maxs)
				return (1);	/* disaster */
		}
	} else {
		if (del == '\n')
			return (1);
		s[0] = del;
		for (i = 1; (c = gtc()) != ' ' && c != '\t' &&
		    c != '\n' && c != EOF; /* empty */) {
			s[i++] = c;
			if (i >= maxs)
				return (1);	/* disaster */
		}
	}
	s[i] = '\0';
	if (c == EOF)
		error(FATAL, gettext("Unexpected end of input at %.20s"), s);
	return (0);
}

void
define(int type)
{
	char *strsave(), *p1, *p2;
	tbl *lookup();

	getstr(token, SSIZE);	/* get name */
	if (type != DEFINE) {
		(void) cstr(token, 1, SSIZE);	/* skip the definition too */
		return;
	}
	p1 = strsave(token);
	if (cstr(token, 1, SSIZE))
		error(FATAL, gettext(
		    "Unterminated definition at %.20s"), token);
	p2 = strsave(token);
	lookup(deftbl, p1, p2);
	if (dbg) printf(".\tname %s defined as %s\n", p1, p2);
}

char    *spaceval   = NULL;

void
space(void) /* collect line of form "space amt" to replace \x in output */
{
	char *strsave();

	getstr(token, SSIZE);
	spaceval = strsave(token);
	if (dbg) printf(".\tsetting space to %s\n", token);
}


char *
strsave(char *s)
{
	char *malloc();
	char *q;

	q = malloc(strlen(s)+1);
	if (q == NULL)
		error(FATAL, gettext("out of space in strsave on %s"), s);
	strcpy(q, s);
	return (q);
}

void
include(void)
{
	error(!FATAL, gettext("Include not yet implemented"));
}

void
delim(void)
{
	yyval = eqnreg = 0;
	if (cstr(token, 0, SSIZE))
		error(FATAL, gettext("Bizarre delimiters at %.20s"), token);
	lefteq = token[0];
	righteq = token[1];
	if (lefteq == 'o' && righteq == 'f')
		lefteq = righteq = '\0';
}

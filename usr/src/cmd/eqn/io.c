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
#include <stdlib.h>
#include <locale.h>

#define	MAXLINE	8192	/* maximum input line */

char in[MAXLINE+1];	/* input buffer */
int noeqn;

void error(int, char *, char *);

static void do_inline(void);
int eqn(int, char *[]);
static int getline(char *);
static void init(void);
void nrwid(int, int, int);
int oalloc(void);
void ofree(int);
static void setfile(int, char *[]);
void setps(int);

int
main(int argc, char *argv[])
{
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	return (eqn(argc, argv));
}

int
eqn(int argc, char *argv[])
{
	int i, type;

	setfile(argc, argv);
	init_tbl();	/* install keywords in tables */
	while ((type = getline(in)) != EOF) {
		eqline = linect;
		if (in[0] == '.' && in[1] == 'E' && in[2] == 'Q') {
			for (i = 11; i < 100; used[i++] = 0)
				;
			printf("%s", in);
			printf(".nr 99 \\n(.s\n.nr 98 \\n(.f\n");
			markline = 0;
			init();
			yyparse();
			if (eqnreg > 0) {
				printf(".nr %d \\w'\\*(%d'\n", eqnreg, eqnreg);
				/*
				 * printf(".if \\n(%d>\\n(.l .tm too-long eqn,
				 * file %s, between lines %d-%d\n",
				 * eqnreg, svargv[ifile], eqline, linect);
				 */

				/* for -ms macros */
				printf(".nr MK %d\n", markline);

				printf(".if %d>\\n(.v .ne %du\n", eqnht, eqnht);
				printf(".rn %d 10\n", eqnreg);
				if (!noeqn) printf("\\*(10\n");
			}
			printf(".ps \\n(99\n.ft \\n(98\n");
			printf(".EN");
			if (lastchar == EOF) {
				putchar('\n');
				break;
			}
			if (putchar(lastchar) != '\n')
				while (putchar(gtc()) != '\n')
					;
		} else if (type == lefteq)
			do_inline();
		else
			printf("%s", in);
	}
	return (0);
}

static int
getline(char *s)
{
	int c;
	while ((*s++ = c = gtc()) != '\n' && c != EOF && c != lefteq)
		if (s >= in+MAXLINE) {
			error(!FATAL, gettext(
			    "input line too long: %.20s\n"), in);
			in[MAXLINE] = '\0';
			break;
		}
	if (c == lefteq)
		s--;
	*s++ = '\0';
	return (c);
}

static void
do_inline(void)
{
	int ds;

	printf(".nr 99 \\n(.s\n.nr 98 \\n(.f\n");
	ds = oalloc();
	printf(".rm %d \n", ds);
	do {
		if (*in)
			printf(".as %d \"%s\n", ds, in);
		init();
		yyparse();
		if (eqnreg > 0) {
			printf(".as %d \\*(%d\n", ds, eqnreg);
			ofree(eqnreg);
		}
		printf(".ps \\n(99\n.ft \\n(98\n");
	} while (getline(in) == lefteq);
	if (*in)
		printf(".as %d \"%s", ds, in);
	printf(".ps \\n(99\n.ft \\n(98\n");
	printf("\\*(%d\n", ds);
	ofree(ds);
}

void
putout(int p1)
{
	extern int gsize, gfont;
	int before, after;
	if (dbg)
		printf(".\tanswer <- S%d, h=%d,b=%d\n", p1, eht[p1], ebase[p1]);
	eqnht = eht[p1];
	printf(".ds %d \\x'0'", p1);
	/* suppposed to leave room for a subscript or superscript */
#ifndef NEQN
	before = eht[p1] - ebase[p1] - VERT(EM(1.2, ps));
#else	/* NEQN */
	before = eht[p1] - ebase[p1] - VERT(3);	/* 3 = 1.5 lines */
#endif	/* NEQN	*/
	if (spaceval != NULL)
		printf("\\x'0-%s'", spaceval);
	else if (before > 0)
		printf("\\x'0-%du'", before);
	printf("\\f%c\\s%d\\*(%d%s\\s\\n(99\\f\\n(98",
	    gfont, gsize, p1, rfont[p1] == ITAL ? "\\|" : "");
#ifndef NEQN
	after = ebase[p1] - VERT(EM(0.2, ps));
#else	/* NEQN */
	after = ebase[p1] - VERT(1);
#endif	/* NEQN */
	if (spaceval == NULL && after > 0)
		printf("\\x'%du'", after);
	putchar('\n');
	eqnreg = p1;
	if (spaceval != NULL) {
		free(spaceval);
		spaceval = NULL;
	}

}

int
max(int i, int j)
{
	return (i > j ? i : j);
}

int
oalloc(void)
{
	int i;
	char ebuf[3];

	for (i = 11; i < 100; i++)
		if (used[i]++ == 0)
			return (i);
	(void) snprintf(ebuf, sizeof (ebuf), "%d", i);
	error(FATAL, gettext("no eqn strings left"), ebuf);
	return (0);
}

void
ofree(int n)
{
	used[n] = 0;
}

void
setps(int p)
{
	printf(".ps %d\n", EFFPS(p));
}

void
nrwid(int n1, int p, int n2)
{
	printf(".nr %d \\w'\\s%d\\*(%d'\n", n1, EFFPS(p), n2);
}

static void
setfile(int argc, char *argv[])
{
	static char *nullstr = "-";

	svargc = --argc;
	svargv = argv;
	while (svargc > 0 && svargv[1][0] == '-') {
		switch (svargv[1][1]) {

		case 'd': lefteq = svargv[1][2]; righteq = svargv[1][3]; break;
		case 's': gsize = atoi(&svargv[1][2]); break;
		case 'p': deltaps = atoi(&svargv[1][2]); break;
		case 'f': gfont = svargv[1][2]; break;
		case 'e': noeqn++; break;
		case 0:	goto endargs;
		default: dbg = 1;
		}
		svargc--;
		svargv++;
	}
endargs:
	ifile = 1;
	linect = 1;
	if (svargc <= 0) {
		curfile = stdin;
		svargv[1] = nullstr;
	}
	else
		openinfile();	/* opens up the first input file */
}

void
yyerror(void)
{
}

static void
init(void)
{
	ct = 0;
	ps = gsize;
	ft = gfont;
	setps(ps);
	printf(".ft %c\n", ft);
}

void
error(int fatal, char *s1, char *s2)
{
	if (fatal > 0)
		printf(gettext("eqn fatal error: "));
	printf(s1, s2);
	printf(gettext("\nfile %s, between lines %d and %d\n"),
	    svargv[ifile], eqline, linect);
	fprintf(stderr, gettext("eqn: "));
	if (fatal > 0)
		fprintf(stderr, gettext("fatal error: "));
	fprintf(stderr, s1, s2);
	fprintf(stderr, gettext("\nfile %s, between lines %d and %d\n"),
	    svargv[ifile], eqline, linect);
	if (fatal > 0)
		exit(1);
}

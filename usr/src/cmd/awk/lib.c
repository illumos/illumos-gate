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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 2.13	*/

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include "awk.h"
#include "y.tab.h"

#define	getfval(p)	\
	(((p)->tval & (ARR|FLD|REC|NUM)) == NUM ? (p)->fval : r_getfval(p))
#define	getsval(p)	\
	(((p)->tval & (ARR|FLD|REC|STR)) == STR ? (p)->sval : r_getsval(p))

extern	Awkfloat r_getfval();
extern	uchar	*r_getsval();

FILE	*infile	= NULL;
uchar	*file	= (uchar*) "";
uchar	recdata[RECSIZE];
uchar	*record	= recdata;
uchar	fields[RECSIZE];

int	donefld;	/* 1 = implies rec broken into fields */
int	donerec;	/* 1 = record is valid (no flds have changed) */

Cell fldtab[MAXFLD];	/* room for fields */

int	maxfld	= 0;	/* last used field */
int	argno	= 1;	/* current input argument number */
extern	Awkfloat *ARGC;
extern	uchar	*getargv();

initgetrec()
{
	int i;
	uchar *p;

	for (i = 1; i < *ARGC; i++) {
		if (!isclvar(p = getargv(i)))	/* find 1st real filename */
			return;
		setclvar(p);	/* a commandline assignment before filename */
		argno++;
	}
	infile = stdin;		/* no filenames, so use stdin */
	/* *FILENAME = file = (uchar*) "-"; */
}

getrec(buf)
	uchar *buf;
{
	int c;
	static int firsttime = 1;

	if (firsttime) {
		firsttime = 0;
		initgetrec();
	}
	dprintf(("RS=<%s>, FS=<%s>, ARGC=%f, FILENAME=%s\n",
		*RS, *FS, *ARGC, *FILENAME));
	donefld = 0;
	donerec = 1;
	buf[0] = 0;
	while (argno < *ARGC || infile == stdin) {
		dprintf(("argno=%d, file=|%s|\n", argno, file));
		if (infile == NULL) {	/* have to open a new file */
			file = getargv(argno);
			if (*file == '\0') {	/* it's been zapped */
				argno++;
				continue;
			}
			if (isclvar(file)) {	/* a var=value arg */
				setclvar(file);
				argno++;
				continue;
			}
			*FILENAME = file;
			dprintf(("opening file %s\n", file));
			if (*file == '-' && *(file+1) == '\0')
				infile = stdin;
			else if ((infile = fopen((char *)file, "r")) == NULL)
				ERROR "can't open file %s", file FATAL;
			setfval(fnrloc, 0.0);
		}
		c = readrec(buf, RECSIZE, infile);
		if (c != 0 || buf[0] != '\0') {	/* normal record */
			if (buf == record) {
				if (!(recloc->tval & DONTFREE))
					xfree(recloc->sval);
				recloc->sval = record;
				recloc->tval = REC | STR | DONTFREE;
				if (isnumber(recloc->sval)) {
					recloc->fval = atof(recloc->sval);
					recloc->tval |= NUM;
				}
			}
			setfval(nrloc, nrloc->fval+1);
			setfval(fnrloc, fnrloc->fval+1);
			return (1);
		}
		/* EOF arrived on this file; set up next */
		if (infile != stdin)
			fclose(infile);
		infile = NULL;
		argno++;
	}
	return (0);	/* true end of file */
}

readrec(buf, bufsize, inf)	/* read one record into buf */
	uchar *buf;
	int bufsize;
	FILE *inf;
{
	register int sep, c;
	register uchar *rr;
	int	count;

	if ((sep = **RS) == 0) {
		sep = '\n';
		/* skip leading \n's */
		while ((c = getc(inf)) == '\n' && c != EOF)
			;
		if (c != EOF)
			ungetc(c, inf);
	}
	for (rr = buf, count = 0; ; ) {
		while ((c = getc(inf)) != sep && c != EOF) {
			count++;
			if (count > bufsize)
				ERROR "input record `%.20s...' too long",
				    buf FATAL;
			*rr++ = c;
		}
		if (**RS == sep || c == EOF)
			break;
		if ((c = getc(inf)) == '\n' || c == EOF) /* 2 in a row */
			break;
		count += 2;
		if (count > bufsize)
			ERROR "input record `%.20s...' too long", buf FATAL;
		*rr++ = '\n';
		*rr++ = c;
	}
	*rr = 0;
	dprintf(("readrec saw <%s>, returns %d\n",
		buf, c == EOF && rr == buf ? 0 : 1));
	return (c == EOF && rr == buf ? 0 : 1);
}

/* get ARGV[n] */
uchar *
getargv(n)
	int n;
{
	Cell *x;
	uchar *s, temp[10];
	extern Array *ARGVtab;

	sprintf((char *)temp, "%d", n);
	x = setsymtab(temp, "", 0.0, STR, ARGVtab);
	s = getsval(x);
	dprintf(("getargv(%d) returns |%s|\n", n, s));
	return (s);
}

setclvar(s)	/* set var=value from s */
uchar *s;
{
	uchar *p;
	Cell *q;

	for (p = s; *p != '='; p++)
		;
	*p++ = 0;
	p = qstring(p, '\0');
	q = setsymtab(s, p, 0.0, STR, symtab);
	setsval(q, p);
	if (isnumber(q->sval)) {
		q->fval = atof(q->sval);
		q->tval |= NUM;
	}
	dprintf(("command line set %s to |%s|\n", s, p));
}


fldbld()
{
	register uchar *r, *fr, sep;
	Cell *p;
	int i;

	if (donefld)
		return;
	if (!(recloc->tval & STR))
		getsval(recloc);
	r = recloc->sval;	/* was record! */
	fr = fields;
	i = 0;	/* number of fields accumulated here */
	if (strlen(*FS) > 1) {	/* it's a regular expression */
		i = refldbld(r, *FS);
	} else if ((sep = **FS) == ' ') {
		for (i = 0; ; ) {
			while (*r == ' ' || *r == '\t' || *r == '\n')
				r++;
			if (*r == 0)
				break;
			i++;
			if (i >= MAXFLD)
				break;
			if (!(fldtab[i].tval & DONTFREE))
				xfree(fldtab[i].sval);
			fldtab[i].sval = fr;
			fldtab[i].tval = FLD | STR | DONTFREE;
			do
				*fr++ = *r++;
			while (*r != ' ' && *r != '\t' && *r != '\n' &&
				*r != '\0');
			*fr++ = 0;
		}
		*fr = 0;
	} else if (*r != 0) {	/* if 0, it's a null field */
		for (;;) {
			i++;
			if (i >= MAXFLD)
				break;
			if (!(fldtab[i].tval & DONTFREE))
				xfree(fldtab[i].sval);
			fldtab[i].sval = fr;
			fldtab[i].tval = FLD | STR | DONTFREE;
			/* \n always a separator */
			while (*r != sep && *r != '\n' && *r != '\0')
				*fr++ = *r++;
			*fr++ = 0;
			if (*r++ == 0)
				break;
		}
		*fr = 0;
	}
	if (i >= MAXFLD)
		ERROR "record `%.20s...' has too many fields", record FATAL;
	/* clean out junk from previous record */
	cleanfld(i, maxfld);
	maxfld = i;
	donefld = 1;
	for (p = fldtab+1; p <= fldtab+maxfld; p++) {
		if (isnumber(p->sval)) {
			p->fval = atof(p->sval);
			p->tval |= NUM;
		}
	}
	setfval(nfloc, (Awkfloat) maxfld);
	if (dbg)
		for (p = fldtab; p <= fldtab+maxfld; p++)
			printf("field %d: |%s|\n", p-fldtab, p->sval);
}

cleanfld(n1, n2)	/* clean out fields n1..n2 inclusive */
{
	static uchar *nullstat = (uchar *) "";
	register Cell *p, *q;

	for (p = &fldtab[n2], q = &fldtab[n1]; p > q; p--) {
		if (!(p->tval & DONTFREE))
			xfree(p->sval);
		p->tval = FLD | STR | DONTFREE;
		p->sval = nullstat;
	}
}

newfld(n)	/* add field n (after end) */
{
	if (n >= MAXFLD)
		ERROR "creating too many fields", record FATAL;
	cleanfld(maxfld, n);
	maxfld = n;
	setfval(nfloc, (Awkfloat) n);
}

refldbld(rec, fs)	/* build fields from reg expr in FS */
	uchar *rec, *fs;
{
	fa *makedfa();
	uchar *fr;
	int i, tempstat;
	fa *pfa;

	fr = fields;
	*fr = '\0';
	if (*rec == '\0')
		return (0);
	pfa = makedfa(fs, 1);
	dprintf(("into refldbld, rec = <%s>, pat = <%s>\n", rec, fs));
	tempstat = pfa->initstat;
	for (i = 1; i < MAXFLD; i++) {
		if (!(fldtab[i].tval & DONTFREE))
			xfree(fldtab[i].sval);
		fldtab[i].tval = FLD | STR | DONTFREE;
		fldtab[i].sval = fr;
		dprintf(("refldbld: i=%d\n", i));
		if (nematch(pfa, rec)) {
			pfa->initstat = 2;
			dprintf(("match %s (%d chars)\n", patbeg, patlen));
			strncpy(fr, rec, patbeg-rec);
			fr += patbeg - rec + 1;
			*(fr-1) = '\0';
			rec = patbeg + patlen;
		} else {
			dprintf(("no match %s\n", rec));
			strcpy(fr, rec);
			pfa->initstat = tempstat;
			break;
		}
	}
	return (i);
}

recbld()
{
	int i;
	register uchar *r, *p;
	static uchar rec[RECSIZE];

	if (donerec == 1)
		return;
	r = rec;
	for (i = 1; i <= *NF; i++) {
		p = getsval(&fldtab[i]);
		while ((r < rec + RECSIZE) && (*r = *p++))
			r++;
		if (i < *NF)
			for (p = *OFS; (r < rec + RECSIZE) && (*r = *p++); )
				r++;
	}
	if (r >= rec + RECSIZE)
		ERROR "built giant record `%.20s...'", record FATAL;
	*r = '\0';
	dprintf(("in recbld FS=%o, recloc=%o\n", **FS, recloc));
	recloc->tval = REC | STR | DONTFREE;
	recloc->sval = record = rec;
	dprintf(("in recbld FS=%o, recloc=%o\n", **FS, recloc));
	dprintf(("recbld = |%s|\n", record));
	donerec = 1;
}

Cell *
fieldadr(n)
{
	if (n < 0 || n >= MAXFLD)
		ERROR "trying to access field %d", n FATAL;
	return (&fldtab[n]);
}

int	errorflag	= 0;
char	errbuf[200];

yyerror(s)
	uchar *s;
{
	extern uchar *cmdname, *curfname;
	static int been_here = 0;

	if (been_here++ > 2)
		return;
	fprintf(stderr, "%s: %s", cmdname, s);
	fprintf(stderr, gettext(" at source line %lld"), lineno);
	if (curfname != NULL)
		fprintf(stderr, gettext(" in function %s"), curfname);
	fprintf(stderr, "\n");
	errorflag = 2;
	eprint();
}

fpecatch()
{
	ERROR "floating point exception" FATAL;
}

extern int bracecnt, brackcnt, parencnt;

bracecheck()
{
	int c;
	static int beenhere = 0;

	if (beenhere++)
		return;
	while ((c = input()) != EOF && c != '\0')
		bclass(c);
	bcheck2(bracecnt, '{', '}');
	bcheck2(brackcnt, '[', ']');
	bcheck2(parencnt, '(', ')');
}

bcheck2(n, c1, c2)
{
	if (n == 1)
		fprintf(stderr, gettext("\tmissing %c\n"), c2);
	else if (n > 1)
		fprintf(stderr, gettext("\t%d missing %c's\n"), n, c2);
	else if (n == -1)
		fprintf(stderr, gettext("\textra %c\n"), c2);
	else if (n < -1)
		fprintf(stderr, gettext("\t%d extra %c's\n"), -n, c2);
}

error(f, s)
	int f;
	char *s;
{
	extern Node *curnode;
	extern uchar *cmdname;

	fflush(stdout);
	fprintf(stderr, "%s: ", cmdname);
	fprintf(stderr, "%s", s);
	fprintf(stderr, "\n");
	if (compile_time != 2 && NR && *NR > 0) {
		fprintf(stderr, gettext(" input record number %g"), *FNR);
		if (strcmp(*FILENAME, "-") != 0)
			fprintf(stderr, gettext(", file %s"), *FILENAME);
		fprintf(stderr, "\n");
	}
	if (compile_time != 2 && curnode)
		fprintf(stderr, gettext(" source line number %lld\n"),
		    curnode->lineno);
	else if (compile_time != 2 && lineno)
		fprintf(stderr, gettext(" source line number %lld\n"), lineno);
	eprint();
	if (f) {
		if (dbg)
			abort();
		exit(2);
	}
}

eprint()	/* try to print context around error */
{
	uchar *p, *q;
	int c;
	static int been_here = 0;
	extern uchar ebuf[300], *ep;

	if (compile_time == 2 || compile_time == 0 || been_here++ > 0)
		return;
	p = ep - 1;
	if (p > ebuf && *p == '\n')
		p--;
	for (; p > ebuf && *p != '\n' && *p != '\0'; p--)
		;
	while (*p == '\n')
		p++;
	fprintf(stderr, gettext(" context is\n\t"));
	for (q = ep-1; q >= p && *q != ' ' && *q != '\t' && *q != '\n';
		q--)
		;
	for (; p < q; p++)
		if (*p)
			putc(*p, stderr);
	fprintf(stderr, " >>> ");
	for (; p < ep; p++)
		if (*p)
			putc(*p, stderr);
	fprintf(stderr, " <<< ");
	if (*ep)
		while ((c = input()) != '\n' && c != '\0' && c != EOF) {
			putc(c, stderr);
			bclass(c);
		}
	putc('\n', stderr);
	ep = ebuf;
}

bclass(c)
{
	switch (c) {
	case '{': bracecnt++; break;
	case '}': bracecnt--; break;
	case '[': brackcnt++; break;
	case ']': brackcnt--; break;
	case '(': parencnt++; break;
	case ')': parencnt--; break;
	}
}

double
errcheck(x, s)
	double x;
	uchar *s;
{
	extern int errno;

	if (errno == EDOM) {
		errno = 0;
		ERROR "%s argument out of domain", s WARNING;
		x = 1;
	} else if (errno == ERANGE) {
		errno = 0;
		ERROR "%s result out of range", s WARNING;
		x = 1;
	}
	return (x);
}

PUTS(s) uchar *s; {
	dprintf(("%s\n", s));
}

isclvar(s)	/* is s of form var=something? */
	char *s;
{
	char *os = s;

	for (; *s; s++)
		if (!(isalnum(*s) || *s == '_'))
			break;
	return (*s == '=' && s > os && *(s+1) != '=');
}

#define	MAXEXPON	38	/* maximum exponent for fp number */

isnumber(s)
register uchar *s;
{
	register int d1, d2;
	int point;
	uchar *es;
	extern char	radixpoint;

	d1 = d2 = point = 0;
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '\0')
		return (0);	/* empty stuff isn't number */
	if (*s == '+' || *s == '-')
		s++;
	if (!isdigit(*s) && *s != radixpoint)
		return (0);
	if (isdigit(*s)) {
		do {
			d1++;
			s++;
		} while (isdigit(*s));
	}
	if (d1 >= MAXEXPON)
		return (0);	/* too many digits to convert */
	if (*s == radixpoint) {
		point++;
		s++;
	}
	if (isdigit(*s)) {
		d2++;
		do {
			s++;
		} while (isdigit(*s));
	}
	if (!(d1 || point && d2))
		return (0);
	if (*s == 'e' || *s == 'E') {
		s++;
		if (*s == '+' || *s == '-')
			s++;
		if (!isdigit(*s))
			return (0);
		es = s;
		do {
			s++;
		} while (isdigit(*s));
		if (s - es > 2)
			return (0);
		else if (s - es == 2 &&
			(int)(10 * (*es-'0') + *(es+1)-'0') >= MAXEXPON)
			return (0);
	}
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '\0')
		return (1);
	else
		return (0);
}

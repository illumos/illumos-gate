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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include "awk.def"
#include "awk.h"
#include <ctype.h>
#include <wctype.h>
#include "awktype.h"
#include <stdlib.h>
#include <stdarg.h>

FILE	*infile	= NULL;
wchar_t *file;
#define	RECSIZE (5 * 512)
wchar_t record[RECSIZE];
wchar_t fields[RECSIZE];
wchar_t L_NULL[] = L"";


#define	MAXFLD	100
int	donefld;	/* 1 = implies rec broken into fields */
int	donerec;	/* 1 = record is valid (no flds have changed) */
int	mustfld;	/* 1 = NF seen, so always break */
static wchar_t L_record[] = L"$record";


#define	FINIT	{ OCELL, CFLD, 0, L_NULL, 0.0, FLD|STR }
CELL fldtab[MAXFLD] = {		/* room for fields */
	{ OCELL, CFLD, L_record, record, 0.0, STR|FLD},
		FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT,
	FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT, FINIT
};
int	maxfld	= 0;	/* last used field */
/* pointer to CELL for maximum field assigned to */
CELL	*maxmfld = &fldtab[0];

static int isclvar(wchar_t *);
static void setclvar(wchar_t *);
void fldbld(void);

int
getrec(void)
{
	wchar_t *rr, *er;
	int c, sep;
	FILE *inf;
	extern int svargc;
	extern wchar_t **svargv;


	dprintf("**RS=%o, **FS=%o\n", **RS, **FS, NULL);
	donefld = 0;
	donerec = 1;
	record[0] = 0;
	er = record + RECSIZE;
	while (svargc > 0) {
		dprintf("svargc=%d, *svargv=%ws\n", svargc, *svargv, NULL);
		if (infile == NULL) {	/* have to open a new file */
			/*
			 * If the argument contains a '=', determine if the
			 * argument needs to be treated as a variable assignment
			 * or as the pathname of a file.
			 */
			if (isclvar(*svargv)) {
				/* it's a var=value argument */
				setclvar(*svargv);
				if (svargc > 1) {
					svargv++;
					svargc--;
					continue;
				}
				*svargv = L"-";
			}
			*FILENAME = file = *svargv;
			dprintf("opening file %ws\n", file, NULL, NULL);
			if (*file == (wchar_t)L'-')
				infile = stdin;
			else if ((infile = fopen(toeuccode(file), "r")) == NULL)
				error(FATAL, "can't open %ws", file);
		}
		if ((sep = **RS) == 0)
			sep = '\n';
		inf = infile;
		for (rr = record; /* dummy */; /* dummy */) {
			for (; (c = getwc(inf)) != sep && c != EOF && rr < er;
			    *rr++ = c)
				;
			if (rr >= er)
				error(FATAL, "record `%.20ws...' too long",
				    record);
			if (**RS == sep || c == EOF)
				break;
			if ((c = getwc(inf)) == '\n' || c == EOF)
			/* 2 in a row */
				break;
			*rr++ = '\n';
			*rr++ = c;
		}
		if (rr >= er)
			error(FATAL, "record `%.20ws...' too long", record);
		*rr = 0;
		if (mustfld)
			fldbld();
		if (c != EOF || rr > record) {	/* normal record */
			recloc->tval &= ~NUM;
			recloc->tval |= STR;
			++nrloc->fval;
			nrloc->tval &= ~STR;
			nrloc->tval |= NUM;
			return (1);
		}
		/* EOF arrived on this file; set up next */
		if (infile != stdin)
			fclose(infile);
		infile = NULL;
		svargc--;
		svargv++;
	}
	return (0);	/* true end of file */
}

/*
 * isclvar()
 *
 * Returns 1 if the input string, arg, is a variable assignment,
 * otherwise returns 0.
 *
 * An argument to awk can be either a pathname of a file, or a variable
 * assignment.  An operand that begins with an undersore or alphabetic
 * character from the portable character set, followed by a sequence of
 * underscores, digits, and alphabetics from the portable character set,
 * followed by the '=' character, shall specify a variable assignment
 * rather than a pathname.
 */
static int
isclvar(wchar_t *arg)
{
	wchar_t	*tmpptr = arg;

	if (tmpptr != NULL) {

		/* Begins with an underscore or alphabetic character */
		if (iswalpha(*tmpptr) || *tmpptr == '_') {

			/*
			 * followed by a sequence of underscores, digits,
			 * and alphabetics
			 */
			for (tmpptr++; *tmpptr; tmpptr++) {
				if (!(iswalnum(*tmpptr) || (*tmpptr == '_'))) {
					break;
				}
			}
			return (*tmpptr == '=');
		}
	}

	return (0);
}

static void
setclvar(wchar_t *s)	/* set var=value from s */
{
	wchar_t *p;
	CELL *q;


	for (p = s; *p != '='; p++)
		;
	*p++ = 0;
	q = setsymtab(s, tostring(p), 0.0, STR, symtab);
	setsval(q, p);
	dprintf("command line set %ws to |%ws|\n", s, p, NULL);
}


void
fldbld(void)
{
	wchar_t *r, *fr, sep, c;
	static wchar_t L_NF[] = L"NF";
	CELL *p, *q;
	int i, j;


	r = record;
	fr = fields;
	i = 0;	/* number of fields accumulated here */
	if ((sep = **FS) == ' ')
		for (i = 0; /* dummy */; /* dummy */) {
			c = *r;
			while (iswblank(c) || c == '\t' || c == '\n')
				c = *(++r);
			if (*r == 0)
				break;
			i++;
			if (i >= MAXFLD)
				error(FATAL,
			"record `%.20ws...' has too many fields", record);
			if (!(fldtab[i].tval&FLD))
				xfree(fldtab[i].sval);
			fldtab[i].sval = fr;
			fldtab[i].tval = FLD | STR;
			do {
				*fr++ = *r++;
				c = *r;
			} while (! iswblank(c) && c != '\t' &&
			    c != '\n' && c != '\0');


			*fr++ = 0;

	} else if (*r != 0)	/* if 0, it's a null field */
		for (;;) {
			i++;
			if (i >= MAXFLD)
				error(FATAL,
			"record `%.20ws...' has too many fields", record);
			if (!(fldtab[i].tval&FLD))
				xfree(fldtab[i].sval);
			fldtab[i].sval = fr;
			fldtab[i].tval = FLD | STR;
			while ((c = *r) != sep && c != '\n' && c != '\0')
				/* \n always a separator */
				*fr++ = *r++;
			*fr++ = 0;
			if (*r++ == 0)
				break;
		}
	*fr = 0;
	/* clean out junk from previous record */
	for (p = maxmfld, q = &fldtab[i]; p > q; p--) {
		if (!(p->tval&FLD))
			xfree(p->sval);
		p->tval = STR | FLD;
		p->sval = L_NULL;
	}
	maxfld = i;
	maxmfld = &fldtab[i];
	donefld = 1;
	for (i = 1; i <= maxfld; i++)
		if (isanumber(fldtab[i].sval)) {
			fldtab[i].fval = watof(fldtab[i].sval);
			fldtab[i].tval |= NUM;
		}
	setfval(lookup(L_NF, symtab, 0), (awkfloat) maxfld);
	if (dbg)
		for (i = 0; i <= maxfld; i++)
			printf("field %d: |%ws|\n", i, fldtab[i].sval);
}


void
recbld(void)
{
	int i;
	wchar_t *r, *p;


	if (donefld == 0 || donerec == 1)
		return;
	r = record;
	for (i = 1; i <= *NF; i++) {
		p = getsval(&fldtab[i]);
		while (*r++ = *p++)
			;
		*(r-1) = **OFS;
	}
	*(r-1) = '\0';
	dprintf("in recbld FS=%o, recloc=%o\n", **FS, recloc, NULL);
	recloc->tval = STR | FLD;
	dprintf("in recbld FS=%o, recloc=%o\n", **FS, recloc, NULL);
	if (r > record+RECSIZE)
		error(FATAL, "built giant record `%.20ws...'", record);
	dprintf("recbld = |%ws|\n", record, NULL, NULL);
}


CELL *
fieldadr(int n)
{
	if (n < 0 || n >= MAXFLD)
		error(FATAL, "trying to access field %d", n);
	return (&fldtab[n]);
}


int	errorflag	= 0;


int
yyerror(char *s)
{
	fprintf(stderr,
	    gettext("awk: %s near line %lld\n"), gettext(s), lineno);
	errorflag = 2;
	return (0);
}


void
error(int f, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "awk: ");
	vfprintf(stderr, gettext(fmt), ap);
	va_end(ap);
	fprintf(stderr, "\n");
	if (NR && *NR > 0)
		fprintf(stderr, gettext(" record number %g\n"), *NR);
	if (f)
		exit(2);
}


void
PUTS(char *s)
{
	dprintf("%s\n", s, NULL, NULL);
}


#define	MAXEXPON	38	/* maximum exponenet for fp number */


int
isanumber(wchar_t *s)
{
	int d1, d2;
	int point;
	wchar_t *es;
	extern wchar_t	radixpoint;

	d1 = d2 = point = 0;
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '\0')
		return (0);	/* empty stuff isn't number */
	if (*s == '+' || *s == '-')
		s++;
	/*
	 * Since, iswdigit() will include digit from other than code set 0,
	 * we have to check it from code set 0 or not.
	 */
	if (!(iswdigit(*s) && iswascii(*s)) && *s != radixpoint)
		return (0);
	if (iswdigit(*s) && iswascii(*s)) {
		do {
			d1++;
			s++;
		} while (iswdigit(*s) && iswascii(*s));
	}
	if (d1 >= MAXEXPON)
		return (0);	/* too many digits to convert */
	if (*s == radixpoint) {
		point++;
		s++;
	}
	if (iswdigit(*s) && iswascii(*s)) {
		d2++;
		do {
			s++;
		} while (iswdigit(*s) && iswascii(*s));
	}


	if (!(d1 || point && d2))
		return (0);
	if (*s == 'e' || *s == 'E') {
		s++;
		if (*s == '+' || *s == '-')
			s++;
		if (!(iswdigit(*s) && iswascii(*s)))
			return (0);
		es = s;
		do {
			s++;
		} while (iswdigit(*s) && iswascii(*s));


		if (s - es > 2)
			return (0);
		else if (s - es == 2 &&
		    10 * (*es-'0') + *(es+1)-'0' >= MAXEXPON)
			return (0);
	}
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '\0')
		return (1);
	else
		return (0);
}
char *
toeuccode(str)
wchar_t *str;
{
	static char euccode[RECSIZE];

	(void) wcstombs(euccode, str, RECSIZE);
	return (euccode);
}

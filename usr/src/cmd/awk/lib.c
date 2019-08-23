/*
 * Copyright (C) Lucent Technologies 1997
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that the copyright notice and this
 * permission notice and warranty disclaimer appear in supporting
 * documentation, and that the name Lucent Technologies or any of
 * its entities not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.
 *
 * LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

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

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) Lucent Technologies 1997	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include "awk.h"
#include "y.tab.h"

static FILE	*infile	= NULL;
static char	*file	= "";
char	*record;
size_t	recsize	= RECSIZE;
static char	*fields;
static size_t	fieldssize = RECSIZE;
static char	*rtbuf;
static size_t	rtbufsize = RECSIZE;

Cell	**fldtab;	/* pointers to Cells */
char	inputFS[100] = " ";

#define	MAXFLD	2
int	nfields	= MAXFLD;	/* last allocated slot for $i */

int	donefld;	/* 1 = implies rec broken into fields */
int	donerec;	/* 1 = record is valid (no flds have changed) */

static int	lastfld	= 0;	/* last used field */
static int	argno	= 1;	/* current input argument number */

static Cell dollar0 = { OCELL, CFLD, NULL, "", 0.0, REC|STR|DONTFREE };
static Cell dollar1 = { OCELL, CFLD, NULL, "", 0.0, FLD|STR|DONTFREE };

static	char	*getargv(int);
static	void	cleanfld(int, int);
static	int	refldbld(const char *, const char *);
static	void	bcheck2(int, int, int);
static	void	eprint(void);
static	void	bclass(int);

void
recinit(unsigned int n)
{
	if ((record = (char *)malloc(n)) == NULL ||
	    (fields = (char *)malloc(n+2)) == NULL ||
	    (fldtab = (Cell **)malloc((nfields+1) * sizeof (Cell *))) == NULL ||
	    (fldtab[0] = (Cell *)malloc(sizeof (Cell))) == NULL)
		FATAL("out of space for $0 and fields");
	*fldtab[0] = dollar0;
	fldtab[0]->sval = record;
	fldtab[0]->nval = tostring("0");
	makefields(1, nfields);
}

void
makefields(int n1, int n2)		/* create $n1..$n2 inclusive */
{
	char temp[50];
	int i;

	for (i = n1; i <= n2; i++) {
		fldtab[i] = (Cell *)malloc(sizeof (Cell));
		if (fldtab[i] == NULL)
			FATAL("out of space in makefields %d", i);
		*fldtab[i] = dollar1;
		(void) sprintf(temp, "%d", i);
		fldtab[i]->nval = tostring(temp);
	}
}

static void
initgetrec(void)
{
	int i;
	char *p;

	for (i = 1; i < *ARGC; i++) {
		p = getargv(i); /* find 1st real filename */
		if (p == NULL || *p == '\0') {  /* deleted or zapped */
			argno++;
			continue;
		}
		if (!isclvar(p)) {
			(void) setsval(lookup("FILENAME", symtab), p);
			return;
		}
		setclvar(p);	/* a commandline assignment before filename */
		argno++;
	}
	infile = stdin;		/* no filenames, so use stdin */
}

/*
 * POSIX specifies that fields are supposed to be evaluated as if they were
 * split using the value of FS at the time that the record's value ($0) was
 * read.
 *
 * Since field-splitting is done lazily, we save the current value of FS
 * whenever a new record is read in (implicitly or via getline), or when
 * a new value is assigned to $0.
 */
void
savefs(void)
{
	if (strlen(getsval(fsloc)) >= sizeof (inputFS))
		FATAL("field separator %.10s... is too long", *FS);
	(void) strcpy(inputFS, *FS);
}

static int firsttime = 1;

/*
 * get next input record
 * note: cares whether buf == record
 */
int
getrec(char **pbuf, size_t *pbufsize, int isrecord)
{
	int c;
	char *buf = *pbuf;
	uschar saveb0;
	size_t bufsize = *pbufsize, savebufsize = bufsize;

	if (firsttime) {
		firsttime = 0;
		initgetrec();
	}
	dprintf(("RS=<%s>, FS=<%s>, ARGC=%f, FILENAME=%s\n",
	    *RS, *FS, *ARGC, *FILENAME));
	if (isrecord) {
		donefld = 0;
		donerec = 1;
		savefs();
	}
	saveb0 = buf[0];
	buf[0] = '\0';
	while (argno < *ARGC || infile == stdin) {
		dprintf(("argno=%d, file=|%s|\n", argno, file));
		if (infile == NULL) {	/* have to open a new file */
			file = getargv(argno);
			if (file == NULL || *file == '\0') {
				/* deleted or zapped */
				argno++;
				continue;
			}
			if (isclvar(file)) {
				/* a var=value arg */
				setclvar(file);
				argno++;
				continue;
			}
			*FILENAME = file;
			dprintf(("opening file %s\n", file));
			if (*file == '-' && *(file+1) == '\0')
				infile = stdin;
			else if ((infile = fopen(file, "rF")) == NULL)
				FATAL("can't open file %s", file);
			(void) setfval(fnrloc, 0.0);
		}
		c = readrec(&buf, &bufsize, infile);

		if (c != 0 || buf[0] != '\0') {	/* normal record */
			if (isrecord) {
				if (freeable(recloc))
					xfree(recloc->sval);
				recloc->sval = buf;	/* buf == record */
				recloc->tval = REC | STR | DONTFREE;
				if (is_number(recloc->sval)) {
					recloc->fval =
					    atof(recloc->sval);
					recloc->tval |= NUM;
				}
			}
			(void) setfval(nrloc, nrloc->fval+1);
			(void) setfval(fnrloc, fnrloc->fval+1);
			*pbuf = buf;
			*pbufsize = bufsize;
			return (1);
		}
		/* EOF arrived on this file; set up next */
		if (infile != stdin)
			(void) fclose(infile);
		infile = NULL;
		argno++;
	}
	buf[0] = saveb0;
	*pbuf = buf;
	*pbufsize = savebufsize;
	return (0);	/* true end of file */
}

void
nextfile(void)
{
	if (infile != NULL && infile != stdin)
		(void) fclose(infile);
	infile = NULL;
	argno++;
}

/*
 * read one record into buf
 */
int
readrec(char **pbuf, size_t *pbufsize, FILE *inf)
{
	int sep, c;
	char *rr, *rt, *buf = *pbuf;
	size_t bufsize = *pbufsize;
	char *rs = getsval(rsloc);

	if (rtbuf == NULL && (rtbuf = malloc(rtbufsize)) == NULL)
		FATAL("out of memory in readrec");

	rr = buf;
	rt = rtbuf;

	if ((sep = *rs) == '\0') {
		sep = '\n';
		/* skip leading \n's */
		while ((c = getc(inf)) == '\n' && c != EOF)
			;
		if (c != EOF)
			(void) ungetc(c, inf);
	}
	while ((c = getc(inf)) != EOF) {
		if (c != sep) {
			if (rr-buf+1 > bufsize) {
				(void) adjbuf(&buf, &bufsize,
				    1+rr-buf, recsize, &rr, "readrec1");
			}
			*rr++ = c;
			continue;
		}

		/*
		 * Ensure enough space for either a single separator
		 * character, or at least two '\n' chars (when RS is
		 * the empty string).
		 */
		(void) adjbuf(&rtbuf, &rtbufsize,
		    2+rt-rtbuf, recsize, &rt, "readrec2");

		if (*rs == sep) {
			*rt++ = sep;
			break;
		}

		if ((c = getc(inf)) == '\n') { /* 2 in a row */
			*rt++ = '\n';
			*rt++ = '\n';
			while ((c = getc(inf)) == '\n' && c != EOF) {
				/* Read any further \n's and add them to RT. */
				(void) adjbuf(&rtbuf, &rtbufsize,
				    1+rt-rtbuf, recsize, &rt, "readrec3");
				*rt++ = '\n';
			}
			if (c != EOF)
				(void) ungetc(c, inf);
			break;
		}

		if (c == EOF) {
			*rt++ = '\n';
			break;
		}

		(void) adjbuf(&buf, &bufsize,
		    2+rr-buf, recsize, &rr, "readrec4");
		*rr++ = '\n';
		*rr++ = c;
	}
	(void) adjbuf(&buf, &bufsize, 1+rr-buf, recsize, &rr, "readrec5");
	(void) adjbuf(&rtbuf, &rtbufsize, 1+rt-rtbuf, recsize, &rt, "readrec6");
	*rr = '\0';
	*rt = '\0';
	dprintf(("readrec saw <%s>, returns %d\n",
	    buf, c == EOF && rr == buf ? 0 : 1));
	*pbuf = buf;
	*pbufsize = bufsize;
	if (c == EOF && rr == buf) {
		return (0);
	} else {
		(void) setsval(rtloc, rtbuf);
		return (1);
	}
}

/* get ARGV[n] */
static char *
getargv(int n)
{
	Cell *x;
	char *s, temp[50];
	extern Array *ARGVtab;

	(void) sprintf(temp, "%d", n);
	if (lookup(temp, ARGVtab) == NULL)
		return (NULL);
	x = setsymtab(temp, "", 0.0, STR, ARGVtab);
	s = getsval(x);
	dprintf(("getargv(%d) returns |%s|\n", n, s));
	return (s);
}

void
setclvar(char *s)	/* set var=value from s */
{
	char *p;
	Cell *q;

	for (p = s; *p != '='; p++)
		;
	*p++ = 0;
	p = qstring(p, '\0');
	q = setsymtab(s, p, 0.0, STR, symtab);
	(void) setsval(q, p);
	if (is_number(q->sval)) {
		q->fval = atof(q->sval);
		q->tval |= NUM;
	}
	dprintf(("command line set %s to |%s|\n", s, p));
	free(p);
}

void
fldbld(void)	/* create fields from current record */
{
	/* this relies on having fields[] the same length as $0 */
	/* the fields are all stored in this one array with \0's */
	/* possibly with a final trailing \0 not associated with any field */
	char *r, *fr, sep;
	Cell *p;
	int i, j, n;

	if (donefld)
		return;
	if (!isstr(fldtab[0]))
		(void) getsval(fldtab[0]);
	r = fldtab[0]->sval;
	n = strlen(r);
	if (n > fieldssize) {
		xfree(fields);
		/* possibly 2 final \0s */
		if ((fields = (char *)malloc(n + 2)) == NULL)
			FATAL("out of space for fields in fldbld %d", n);
		fieldssize = n;
	}
	fr = fields;

	i = 0;	/* number of fields accumulated here */
	if (strlen(inputFS) > 1) {	/* it's a regular expression */
		i = refldbld(r, inputFS);
	} else if ((sep = *inputFS) == ' ') {	/* default whitespace */
		for (i = 0; ; ) {
			while (*r == ' ' || *r == '\t' || *r == '\n')
				r++;
			if (*r == '\0')
				break;
			i++;
			if (i > nfields)
				growfldtab(i);
			if (freeable(fldtab[i]))
				xfree(fldtab[i]->sval);
			fldtab[i]->sval = fr;
			fldtab[i]->tval = FLD | STR | DONTFREE;
			do
				*fr++ = *r++;
			while (*r != ' ' && *r != '\t' && *r != '\n' &&
			    *r != '\0')
				;
			*fr++ = '\0';
		}
		*fr = '\0';
	} else if ((sep = *inputFS) == '\0') {
		/* new: FS="" => 1 char/field */
		for (i = 0; *r != '\0'; r++) {
			char buf[2];
			i++;
			if (i > nfields)
				growfldtab(i);
			if (freeable(fldtab[i]))
				xfree(fldtab[i]->sval);
			buf[0] = *r;
			buf[1] = '\0';
			fldtab[i]->sval = tostring(buf);
			fldtab[i]->tval = FLD | STR;
		}
		*fr = '\0';
	} else if (*r != '\0') {	/* if 0, it's a null field */
		/*
		 * subtlecase : if length(FS) == 1 && length(RS > 0)
		 * \n is NOT a field separator (cf awk book 61,84).
		 * this variable is tested in the inner while loop.
		 */
		int rtest = '\n';  /* normal case */
		if (strlen(*RS) > 0)
			rtest = '\0';
		for (;;) {
			i++;
			if (i > nfields)
				growfldtab(i);
			if (freeable(fldtab[i]))
				xfree(fldtab[i]->sval);
			fldtab[i]->sval = fr;
			fldtab[i]->tval = FLD | STR | DONTFREE;
			/* \n is always a separator */
			while (*r != sep && *r != rtest && *r != '\0')
				*fr++ = *r++;
			*fr++ = '\0';
			if (*r++ == '\0')
				break;
		}
		*fr = '\0';
	}
	if (i > nfields)
		FATAL("record `%.30s...' has too many fields; can't happen", r);
	/* clean out junk from previous record */
	cleanfld(i+1, lastfld);
	lastfld = i;
	donefld = 1;
	for (j = 1; j <= lastfld; j++) {
		p = fldtab[j];
		if (is_number(p->sval)) {
			p->fval = atof(p->sval);
			p->tval |= NUM;
		}
	}
	(void) setfval(nfloc, (Awkfloat)lastfld);
	donerec = 1; /* restore */
	if (dbg) {
		for (j = 0; j <= lastfld; j++) {
			p = fldtab[j];
			(void) printf("field %d (%s): |%s|\n",
			    j, p->nval, p->sval);
		}
	}
}

/* clean out fields n1 .. n2 inclusive; nvals remain intact */
static void
cleanfld(int n1, int n2)
{
	Cell *p;
	int i;

	for (i = n1; i <= n2; i++) {
		p = fldtab[i];
		if (freeable(p))
			xfree(p->sval);
		p->sval = "";
		p->tval = FLD | STR | DONTFREE;
	}
}

void
newfld(int n)	/* add field n after end of existing lastfld */
{
	if (n > nfields)
		growfldtab(n);
	cleanfld(lastfld+1, n);
	lastfld = n;
	(void) setfval(nfloc, (Awkfloat)n);
}

void
setlastfld(int n)	/* set lastfld cleaning fldtab cells if necessary */
{
	if (n < 0)
		FATAL("cannot set NF to a negative value");
	if (n > nfields)
		growfldtab(n);

	if (lastfld < n)
		cleanfld(lastfld+1, n);
	else
		cleanfld(n+1, lastfld);

	lastfld = n;
}

Cell *
fieldadr(int n)	/* get nth field */
{
	if (n < 0)
		FATAL("trying to access out of range field %d", n);
	if (n > nfields)	/* fields after NF are empty */
		growfldtab(n);	/* but does not increase NF */
	return (fldtab[n]);
}

void
growfldtab(int n)	/* make new fields up to at least $n */
{
	int nf = 2 * nfields;
	size_t s;

	if (n > nf)
		nf = n;
	s = (nf+1) * (sizeof (Cell *));  /* freebsd: how much do we need? */
	if (s / sizeof (Cell *) - 1 == nf) /* didn't overflow */
		fldtab = (Cell **)realloc(fldtab, s);
	else					/* overflow sizeof int */
		xfree(fldtab);	/* make it null */
	if (fldtab == NULL)
		FATAL("out of space creating %d fields", nf);
	makefields(nfields+1, nf);
	nfields = nf;
}

/* build fields from reg expr in FS */
static int
refldbld(const char *rec, const char *fs)
{
	/* this relies on having fields[] the same length as $0 */
	/* the fields are all stored in this one array with \0's */
	char *fr;
	int i, tempstat, n;
	fa *pfa;

	n = strlen(rec);
	if (n > fieldssize) {
		xfree(fields);
		if ((fields = (char *)malloc(n+1)) == NULL)
			FATAL("out of space for fields in refldbld %d", n);
		fieldssize = n;
	}
	fr = fields;
	*fr = '\0';
	if (*rec == '\0')
		return (0);
	pfa = makedfa(fs, 1);
	dprintf(("into refldbld, rec = <%s>, pat = <%s>\n", rec, fs));
	tempstat = pfa->initstat;
	for (i = 1; ; i++) {
		if (i > nfields)
			growfldtab(i);
		if (freeable(fldtab[i]))
			xfree(fldtab[i]->sval);
		fldtab[i]->tval = FLD | STR | DONTFREE;
		fldtab[i]->sval = fr;
		dprintf(("refldbld: i=%d\n", i));
		if (nematch(pfa, rec)) {
			pfa->initstat = 2;	/* horrible coupling to b.c */
			dprintf(("match %s (%d chars)\n", patbeg, patlen));
			(void) strncpy(fr, rec, patbeg-rec);
			fr += patbeg - rec + 1;
			*(fr-1) = '\0';
			rec = patbeg + patlen;
		} else {
			dprintf(("no match %s\n", rec));
			(void) strcpy(fr, rec);
			pfa->initstat = tempstat;
			break;
		}
	}
	return (i);
}

void
recbld(void)	/* create $0 from $1..$NF if necessary */
{
	int i;
	char *p;
	size_t cnt, len, olen;
	char *sep = getsval(ofsloc);

	if (donerec == 1)
		return;
	cnt = 0;
	olen = strlen(sep);
	for (i = 1; i <= *NF; i++) {
		p = getsval(fldtab[i]);
		len = strlen(p);
		expand_buf(&record, &recsize, cnt + len + olen);
		(void) memcpy(&record[cnt], p, len);
		cnt += len;
		if (i < *NF) {
			(void) memcpy(&record[cnt], sep, olen);
			cnt += olen;
		}
	}
	record[cnt] = '\0';
	dprintf(("in recbld inputFS=%s, recloc=%p\n", inputFS, (void *)recloc));
	if (freeable(recloc))
		xfree(recloc->sval);
	recloc->tval = REC | STR | DONTFREE;
	recloc->sval = record;
	dprintf(("in recbld inputFS=%s, recloc=%p\n", inputFS, (void *)recloc));
	dprintf(("recbld = |%s|\n", record));
	donerec = 1;
}

int	errorflag	= 0;

void
yyerror(const char *s)
{
	SYNTAX("%s", s);
}

void
SYNTAX(const char *fmt, ...)
{
	extern char *cmdname, *curfname;
	static int been_here = 0;
	va_list varg;

	if (been_here++ > 2)
		return;
	(void) fprintf(stderr, "%s: ", cmdname);
	va_start(varg, fmt);
	(void) vfprintf(stderr, fmt, varg);
	va_end(varg);
	(void) fprintf(stderr, " at source line %lld", lineno);
	if (curfname != NULL)
		(void) fprintf(stderr, " in function %s", curfname);
	if (compile_time == 1 && cursource() != NULL)
		(void) fprintf(stderr, " source file %s", cursource());
	(void) fprintf(stderr, "\n");
	errorflag = 2;
	eprint();
}

void
fpecatch(int n)
{
	FATAL("floating point exception %d", n);
}

extern int bracecnt, brackcnt, parencnt;

void
bracecheck(void)
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

/*ARGSUSED*/
static void
bcheck2(int n, int c1, int c2)
{
	if (n == 1)
		(void) fprintf(stderr, gettext("\tmissing %c\n"), c2);
	else if (n > 1)
		(void) fprintf(stderr, gettext("\t%d missing %c's\n"), n, c2);
	else if (n == -1)
		(void) fprintf(stderr, gettext("\textra %c\n"), c2);
	else if (n < -1)
		(void) fprintf(stderr, gettext("\t%d extra %c's\n"), -n, c2);
}

void
FATAL(const char *fmt, ...)
{
	extern char *cmdname;
	va_list varg;

	(void) fflush(stdout);
	(void) fprintf(stderr, "%s: ", cmdname);
	va_start(varg, fmt);
	(void) vfprintf(stderr, fmt, varg);
	va_end(varg);
	error();
	if (dbg > 1)		/* core dump if serious debugging on */
		abort();
	exit(2);
}

void
WARNING(const char *fmt, ...)
{
	extern char *cmdname;
	va_list varg;

	(void) fflush(stdout);
	(void) fprintf(stderr, "%s: ", cmdname);
	va_start(varg, fmt);
	(void) vfprintf(stderr, fmt, varg);
	va_end(varg);
	error();
}

void
error(void)
{
	extern Node *curnode;

	(void) fprintf(stderr, "\n");
	if (compile_time != 2 && NR && *NR > 0) {
		(void) fprintf(stderr,
		    gettext(" input record number %g"), *FNR);
		if (strcmp(*FILENAME, "-") != 0)
			(void) fprintf(stderr, gettext(", file %s"), *FILENAME);
		(void) fprintf(stderr, "\n");
	}
	if (compile_time != 2 && curnode)
		(void) fprintf(stderr, gettext(" source line number %lld"),
		    curnode->lineno);
	else if (compile_time != 2 && lineno) {
		(void) fprintf(stderr,
		    gettext(" source line number %lld"), lineno);
	}
	if (compile_time == 1 && cursource() != NULL)
		(void) fprintf(stderr, gettext(" source file %s"), cursource());
	(void) fprintf(stderr, "\n");
	eprint();
}

static void
eprint(void)	/* try to print context around error */
{
	char *p, *q;
	int c;
	static int been_here = 0;
	extern char ebuf[], *ep;

	if (compile_time == 2 || compile_time == 0 || been_here++ > 0)
		return;
	if (ebuf == ep)
		return;
	p = ep - 1;
	if (p > ebuf && *p == '\n')
		p--;
	for (; p > ebuf && *p != '\n' && *p != '\0'; p--)
		;
	while (*p == '\n')
		p++;
	(void) fprintf(stderr, gettext(" context is\n\t"));
	for (q = ep-1; q >= p && *q != ' ' && *q != '\t' && *q != '\n'; q--)
		;
	for (; p < q; p++)
		if (*p)
			(void) putc(*p, stderr);
	(void) fprintf(stderr, " >>> ");
	for (; p < ep; p++)
		if (*p)
			(void) putc(*p, stderr);
	(void) fprintf(stderr, " <<< ");
	if (*ep)
		while ((c = input()) != '\n' && c != '\0' && c != EOF) {
			(void) putc(c, stderr);
			bclass(c);
		}
	(void) putc('\n', stderr);
	ep = ebuf;
}

static void
bclass(int c)
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
errcheck(double x, const char *s)
{
	if (errno == EDOM) {
		errno = 0;
		WARNING("%s argument out of domain", s);
		x = 1;
	} else if (errno == ERANGE) {
		errno = 0;
		WARNING("%s result out of range", s);
		x = 1;
	}
	return (x);
}

int
isclvar(const char *s)	/* is s of form var=something ? */
{
	if (s != NULL) {

		/* Must begin with an underscore or alphabetic character */
		if (isalpha(*s) || (*s == '_')) {

			for (s++; *s; s++) {
				/*
				 * followed by a sequence of underscores,
				 * digits, and alphabetics
				 */
				if (!(isalnum(*s) || *s == '_')) {
					break;
				}
			}
			return (*s == '=' && *(s + 1) != '=');
		}
	}

	return (0);
}

#include <math.h>
int
is_number(const char *s)
{
	double r;
	char *ep;
	errno = 0;
	r = strtod(s, &ep);
	if (ep == s || r == HUGE_VAL || errno == ERANGE)
		return (0);
	while (*ep == ' ' || *ep == '\t' || *ep == '\n')
		ep++;
	if (*ep == '\0')
		return (1);
	else
		return (0);
}

void
r_expand_buf(char **optr, size_t *sizep, size_t req)
{
	char	*nptr;
	size_t	amt, size = *sizep;

	if (size != 0 && req < (size - 1))
		return;
	amt = req + 1 - size;
	amt = (amt / LINE_INCR + 1) * LINE_INCR;

	if ((nptr = realloc(*optr, size + amt)) == NULL)
		FATAL("out of space in expand_buf");
	/* initial buffer should have NULL terminated */
	if (size == 0)
		*nptr = '\0';
	*sizep += amt;
	*optr = nptr;
}

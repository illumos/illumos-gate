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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include "awk.h"
#include "y.tab.h"

uchar	*record;
size_t	record_size;

int	donefld;	/* 1 = implies rec broken into fields */
int	donerec;	/* 1 = record is valid (no flds have changed) */

static struct fldtab_chunk {
	struct fldtab_chunk	*next;
	Cell			fields[FLD_INCR];
} *fldtab_head, *fldtab_tail;

static	size_t	fldtab_maxidx;

static FILE	*infile	= NULL;
static uchar	*file	= (uchar*) "";
static uchar	*fields;
static size_t	fields_size = LINE_INCR;

static int	maxfld	= 0;	/* last used field */
static int	argno	= 1;	/* current input argument number */

static	uchar	*getargv(int);
static	void	cleanfld(int, int);
static	int	refldbld(uchar *, uchar *);
static	void	bcheck2(int, int, int);
static	void	eprint(void);
static	void	bclass(int);

static void
initgetrec(void)
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

int
getrec(uchar **bufp, size_t *bufsizep)
{
	int c;
	static int firsttime = 1;
	uchar_t	*buf, *nbuf;
	size_t	len;

	if (firsttime) {
		firsttime = 0;
		initgetrec();
	}
	dprintf(("RS=<%s>, FS=<%s>, ARGC=%f, FILENAME=%s\n",
	    *RS, *FS, *ARGC, *FILENAME));
	donefld = 0;
	donerec = 1;
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
			(void) setfval(fnrloc, 0.0);
		}
		c = readrec(&nbuf, &len, infile);
		expand_buf(bufp, bufsizep, len);
		buf = *bufp;
		(void) memcpy(buf, nbuf, len);
		buf[len] = '\0';
		free(nbuf);

		if (c != 0 || buf[0] != '\0') {	/* normal record */
			if (bufp == &record) {
				if (!(recloc->tval & DONTFREE))
					xfree(recloc->sval);
				recloc->sval = record;
				recloc->tval = REC | STR | DONTFREE;
				if (is_number(recloc->sval)) {
					recloc->fval =
					    atof((const char *)recloc->sval);
					recloc->tval |= NUM;
				}
			}
			(void) setfval(nrloc, nrloc->fval+1);
			(void) setfval(fnrloc, fnrloc->fval+1);
			return (1);
		}
		/* EOF arrived on this file; set up next */
		if (infile != stdin)
			(void) fclose(infile);
		infile = NULL;
		argno++;
	}
	return (0);	/* true end of file */
}

int
readrec(uchar **bufp, size_t *sizep, FILE *inf)	/* read one record into buf */
{
	int sep, c;
	uchar	*buf;
	int	count;
	size_t	bufsize;

	init_buf(&buf, &bufsize, LINE_INCR);
	if ((sep = **RS) == 0) {
		sep = '\n';
		/* skip leading \n's */
		while ((c = getc(inf)) == '\n' && c != EOF)
			;
		if (c != EOF)
			(void) ungetc(c, inf);
	}
	count = 0;
	for (;;) {
		while ((c = getc(inf)) != sep && c != EOF) {
			expand_buf(&buf, &bufsize, count);
			buf[count++] = c;
		}
		if (**RS == sep || c == EOF)
			break;
		if ((c = getc(inf)) == '\n' || c == EOF) /* 2 in a row */
			break;
		expand_buf(&buf, &bufsize, count + 1);
		buf[count++] = '\n';
		buf[count++] = c;
	}
	buf[count] = '\0';
	dprintf(("readrec saw <%s>, returns %d\n",
	    buf, c == EOF && count == 0 ? 0 : 1));
	*bufp = buf;
	*sizep = count;
	return (c == EOF && count == 0 ? 0 : 1);
}

/* get ARGV[n] */
static uchar *
getargv(int n)
{
	Cell *x;
	uchar *s, temp[11];
	extern Array *ARGVtab;

	(void) sprintf((char *)temp, "%d", n);
	x = setsymtab(temp, (uchar *)"", 0.0, STR, ARGVtab);
	s = getsval(x);
	dprintf(("getargv(%d) returns |%s|\n", n, s));
	return (s);
}

void
setclvar(uchar *s)	/* set var=value from s */
{
	uchar *p;
	Cell *q;

	for (p = s; *p != '='; p++)
		;
	*p++ = 0;
	p = qstring(p, '\0');
	q = setsymtab(s, p, 0.0, STR, symtab);
	(void) setsval(q, p);
	if (is_number(q->sval)) {
		q->fval = atof((const char *)q->sval);
		q->tval |= NUM;
	}
	dprintf(("command line set %s to |%s|\n", s, p));
	free(p);
}

void
fldbld(void)
{
	uchar *r, *fr, sep;
	Cell *p;
	int i;
	size_t	len;

	if (donefld)
		return;
	if (!(recloc->tval & STR))
		(void) getsval(recloc);
	r = recloc->sval;	/* was record! */

	/* make sure fields is always allocated */
	adjust_buf(&fields, fields_size);

	/*
	 * make sure fields has enough size. We don't expand the buffer
	 * in the middle of the loop, since p->sval has already pointed
	 * the address in the fields.
	 */
	len = strlen((char *)r) + 1;
	expand_buf(&fields, &fields_size, len);
	fr = fields;

	i = 0;	/* number of fields accumulated here */
	if (strlen((char *)*FS) > 1) {	/* it's a regular expression */
		i = refldbld(r, *FS);
	} else if ((sep = **FS) == ' ') {
		for (i = 0; ; ) {
			while (*r == ' ' || *r == '\t' || *r == '\n')
				r++;
			if (*r == 0)
				break;
			i++;
			p = getfld(i);
			if (!(p->tval & DONTFREE))
				xfree(p->sval);
			p->sval = fr;
			p->tval = FLD | STR | DONTFREE;
			do
				*fr++ = *r++;
			while (*r != ' ' && *r != '\t' && *r != '\n' &&
			    *r != '\0')
				;
			*fr++ = 0;
		}
		*fr = 0;
	} else if (*r != 0) {	/* if 0, it's a null field */
		for (;;) {
			i++;
			p = getfld(i);
			if (!(p->tval & DONTFREE))
				xfree(p->sval);
			p->sval = fr;
			p->tval = FLD | STR | DONTFREE;
			/* \n always a separator */
			while (*r != sep && *r != '\n' && *r != '\0')
				*fr++ = *r++;
			*fr++ = 0;
			if (*r++ == 0)
				break;
		}
		*fr = 0;
	}
	/* clean out junk from previous record */
	cleanfld(i, maxfld);
	maxfld = i;
	donefld = 1;
	for (i = 1; i <= maxfld; i++) {
		p = getfld(i);
		if (is_number(p->sval)) {
			p->fval = atof((const char *)p->sval);
			p->tval |= NUM;
		}
	}

	(void) setfval(nfloc, (Awkfloat) maxfld);
	if (dbg) {
		for (i = 0; i <= maxfld; i++) {
			p = getfld(i);
			(void) printf("field %d: |%s|\n", i, p->sval);
		}
	}
}

static void
cleanfld(int n1, int n2)	/* clean out fields n1..n2 inclusive */
{
	static uchar *nullstat = (uchar *) "";
	Cell *p;
	int	i;

	for (i = n2; i > n1; i--) {
		p = getfld(i);
		if (!(p->tval & DONTFREE))
			xfree(p->sval);
		p->tval = FLD | STR | DONTFREE;
		p->sval = nullstat;
	}
}

void
newfld(int n)	/* add field n (after end) */
{
	if (n < 0)
		ERROR "accessing invalid field", record FATAL;
	(void) getfld(n);
	cleanfld(maxfld, n);
	maxfld = n;
	(void) setfval(nfloc, (Awkfloat) n);
}

/*
 * allocate field table. We don't reallocate the table since there
 * might be somewhere recording the address of the table.
 */
static void
morefld(void)
{
	int	i;
	struct fldtab_chunk *fldcp;
	Cell	*newfld;

	if ((fldcp = calloc(sizeof (struct fldtab_chunk), 1)) == NULL)
		ERROR "out of space in morefld" FATAL;

	newfld = &fldcp->fields[0];
	for (i = 0; i < FLD_INCR; i++) {
		newfld[i].ctype = OCELL;
		newfld[i].csub = CFLD;
		newfld[i].nval = NULL;
		newfld[i].sval = (uchar *)"";
		newfld[i].fval = 0.0;
		newfld[i].tval = FLD|STR|DONTFREE;
		newfld[i].cnext = NULL;
	}
	/*
	 * link this field chunk
	 */
	if (fldtab_head == NULL)
		fldtab_head = fldcp;
	else
		fldtab_tail->next = fldcp;
	fldtab_tail = fldcp;
	fldcp->next = NULL;

	fldtab_maxidx += FLD_INCR;
}

Cell *
getfld(int idx)
{
	struct fldtab_chunk *fldcp;
	int	cbase;

	if (idx < 0)
		ERROR "trying to access field %d", idx FATAL;
	while (idx >= fldtab_maxidx)
		morefld();
	cbase = 0;
	for (fldcp = fldtab_head; fldcp != NULL; fldcp = fldcp->next) {
		if (idx < (cbase + FLD_INCR))
			return (&fldcp->fields[idx - cbase]);
		cbase += FLD_INCR;
	}
	/* should never happen */
	ERROR "trying to access invalid field %d", idx FATAL;
	return (NULL);
}

int
fldidx(Cell *vp)
{
	struct fldtab_chunk *fldcp;
	Cell	*tbl;
	int	cbase;

	cbase = 0;
	for (fldcp = fldtab_head; fldcp != NULL; fldcp = fldcp->next) {
		tbl = &fldcp->fields[0];
		if (vp >= tbl && vp < (tbl + FLD_INCR))
			return (cbase + (vp - tbl));
		cbase += FLD_INCR;
	}
	/* should never happen */
	ERROR "trying to access unknown field" FATAL;
	return (0);
}

static int
refldbld(uchar *rec, uchar *fs)	/* build fields from reg expr in FS */
{
	uchar *fr;
	int i, tempstat;
	fa *pfa;
	Cell	*p;
	size_t	len;

	/* make sure fields is allocated */
	adjust_buf(&fields, fields_size);
	fr = fields;
	*fr = '\0';
	if (*rec == '\0')
		return (0);

	len = strlen((char *)rec) + 1;
	expand_buf(&fields, &fields_size, len);
	fr = fields;

	pfa = makedfa(fs, 1);
	dprintf(("into refldbld, rec = <%s>, pat = <%s>\n", rec, fs));
	tempstat = pfa->initstat;
	for (i = 1; ; i++) {
		p = getfld(i);
		if (!(p->tval & DONTFREE))
			xfree(p->sval);
		p->tval = FLD | STR | DONTFREE;
		p->sval = fr;
		dprintf(("refldbld: i=%d\n", i));
		if (nematch(pfa, rec)) {
			pfa->initstat = 2;
			dprintf(("match %s (%d chars)\n", patbeg, patlen));
			(void) strncpy((char *)fr, (char *)rec, patbeg-rec);
			fr += patbeg - rec + 1;
			*(fr-1) = '\0';
			rec = patbeg + patlen;
		} else {
			dprintf(("no match %s\n", rec));
			(void) strcpy((char *)fr, (char *)rec);
			pfa->initstat = tempstat;
			break;
		}
	}
	return (i);
}

void
recbld(void)
{
	int i;
	uchar *p;
	size_t cnt, len, olen;

	if (donerec == 1)
		return;
	cnt = 0;
	olen = strlen((char *)*OFS);
	for (i = 1; i <= *NF; i++) {
		p = getsval(getfld(i));
		len = strlen((char *)p);
		expand_buf(&record, &record_size, cnt + len + olen);
		(void) memcpy(&record[cnt], p, len);
		cnt += len;
		if (i < *NF) {
			(void) memcpy(&record[cnt], *OFS, olen);
			cnt += olen;
		}
	}
	record[cnt] = '\0';
	dprintf(("in recbld FS=%o, recloc=%p\n", **FS, (void *)recloc));
	if (!(recloc->tval & DONTFREE))
		xfree(recloc->sval);
	recloc->tval = REC | STR | DONTFREE;
	recloc->sval = record;
	dprintf(("in recbld FS=%o, recloc=%p\n", **FS, (void *)recloc));
	dprintf(("recbld = |%s|\n", record));
	donerec = 1;
}

Cell *
fieldadr(int n)
{
	if (n < 0)
		ERROR "trying to access field %d", n FATAL;
	return (getfld(n));
}

int	errorflag	= 0;
char	errbuf[200];

void
yyerror(char *s)
{
	extern uchar *cmdname, *curfname;
	static int been_here = 0;

	if (been_here++ > 2)
		return;
	(void) fprintf(stderr, "%s: %s", cmdname, s);
	(void) fprintf(stderr, gettext(" at source line %lld"), lineno);
	if (curfname != NULL)
		(void) fprintf(stderr, gettext(" in function %s"), curfname);
	(void) fprintf(stderr, "\n");
	errorflag = 2;
	eprint();
}

/*ARGSUSED*/
void
fpecatch(int sig)
{
	ERROR "floating point exception" FATAL;
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
error(int f, char *s)
{
	extern Node *curnode;
	extern uchar *cmdname;

	(void) fflush(stdout);
	(void) fprintf(stderr, "%s: ", cmdname);
	(void) fprintf(stderr, "%s", s);
	(void) fprintf(stderr, "\n");
	if (compile_time != 2 && NR && *NR > 0) {
		(void) fprintf(stderr,
		    gettext(" input record number %g"), *FNR);
		if (strcmp((char *)*FILENAME, "-") != 0)
			(void) fprintf(stderr, gettext(", file %s"), *FILENAME);
		(void) fprintf(stderr, "\n");
	}
	if (compile_time != 2 && curnode)
		(void) fprintf(stderr, gettext(" source line number %lld\n"),
		    curnode->lineno);
	else if (compile_time != 2 && lineno) {
		(void) fprintf(stderr,
		    gettext(" source line number %lld\n"), lineno);
	}
	eprint();
	if (f) {
		if (dbg)
			abort();
		exit(2);
	}
}

static void
eprint(void)	/* try to print context around error */
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
errcheck(double x, char *s)
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

void
PUTS(uchar *s)
{
	dprintf(("%s\n", s));
}

int
isclvar(uchar *s)	/* is s of form var=something? */
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

#define	MAXEXPON	38	/* maximum exponent for fp number */

int
is_number(uchar *s)
{
	int d1, d2;
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
		if (s - es > 2) {
			return (0);
		} else if (s - es == 2 &&
		    (int)(10 * (*es-'0') + *(es+1)-'0') >= MAXEXPON) {
			return (0);
		}
	}
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '\0')
		return (1);
	else
		return (0);
}

void
init_buf(uchar **optr, size_t *sizep, size_t amt)
{
	uchar	*nptr = NULL;

	if ((nptr = malloc(amt)) == NULL)
		ERROR "out of space in init_buf" FATAL;
	/* initial buffer should have NULL terminated */
	*nptr = '\0';
	if (sizep != NULL)
		*sizep = amt;
	*optr = nptr;
}

void
r_expand_buf(uchar **optr, size_t *sizep, size_t req)
{
	uchar	*nptr;
	size_t	amt, size = *sizep;

	if (size != 0 && req < (size - 1))
		return;
	amt = req + 1 - size;
	amt = (amt / LINE_INCR + 1) * LINE_INCR;

	if ((nptr = realloc(*optr, size + amt)) == NULL)
		ERROR "out of space in expand_buf" FATAL;
	/* initial buffer should have NULL terminated */
	if (size == 0)
		*nptr = '\0';
	*sizep += amt;
	*optr = nptr;
}

void
adjust_buf(uchar **optr, size_t size)
{
	uchar	*nptr;

	if ((nptr = realloc(*optr, size)) == NULL)
		ERROR "out of space in adjust_buf" FATAL;
	*optr = nptr;
}

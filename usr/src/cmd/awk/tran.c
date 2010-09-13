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

#define	DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "awk.h"
#include "y.tab.h"

#define	FULLTAB	2	/* rehash when table gets this x full */
#define	GROWTAB 4	/* grow table by this factor */

Array	*symtab;	/* main symbol table */

uchar	**FS;		/* initial field sep */
uchar	**RS;		/* initial record sep */
uchar	**OFS;		/* output field sep */
uchar	**ORS;		/* output record sep */
uchar	**OFMT;		/* output format for numbers */
Awkfloat *NF;		/* number of fields in current record */
Awkfloat *NR;		/* number of current record */
Awkfloat *FNR;		/* number of current record in current file */
uchar	**FILENAME;	/* current filename argument */
Awkfloat *ARGC;		/* number of arguments from command line */
uchar	**SUBSEP;	/* subscript separator for a[i,j,k]; default \034 */
Awkfloat *RSTART;	/* start of re matched with ~; origin 1 (!) */
Awkfloat *RLENGTH;	/* length of same */

Cell	*recloc;	/* location of record */
Cell	*nrloc;		/* NR */
Cell	*nfloc;		/* NF */
Cell	*fnrloc;	/* FNR */
Array	*ARGVtab;	/* symbol table containing ARGV[...] */
Array	*ENVtab;	/* symbol table containing ENVIRON[...] */
Cell	*rstartloc;	/* RSTART */
Cell	*rlengthloc;	/* RLENGTH */
Cell	*symtabloc;	/* SYMTAB */

Cell	*nullloc;
Node	*nullnode;	/* zero&null, converted into a node for comparisons */

static	void	rehash(Array *);

void
syminit(void)
{
	init_buf(&record, &record_size, LINE_INCR);

	/* initialize $0 */
	recloc = getfld(0);
	recloc->nval = (uchar *)"$0";
	recloc->sval = record;
	recloc->tval = REC|STR|DONTFREE;

	symtab = makesymtab(NSYMTAB);
	(void) setsymtab((uchar *)"0", (uchar *)"0", 0.0,
	    NUM|STR|CON|DONTFREE, symtab);
	/* this is used for if(x)... tests: */
	nullloc = setsymtab((uchar *)"$zero&null", (uchar *)"", 0.0,
	    NUM|STR|CON|DONTFREE, symtab);
	nullnode = valtonode(nullloc, CCON);
	FS = &setsymtab((uchar *)"FS", (uchar *)" ", 0.0,
	    STR|DONTFREE, symtab)->sval;
	RS = &setsymtab((uchar *)"RS", (uchar *)"\n", 0.0,
	    STR|DONTFREE, symtab)->sval;
	OFS = &setsymtab((uchar *)"OFS", (uchar *)" ", 0.0,
	    STR|DONTFREE, symtab)->sval;
	ORS = &setsymtab((uchar *)"ORS", (uchar *)"\n", 0.0,
	    STR|DONTFREE, symtab)->sval;
	OFMT = &setsymtab((uchar *)"OFMT", (uchar *)"%.6g", 0.0,
	    STR|DONTFREE, symtab)->sval;
	FILENAME = &setsymtab((uchar *)"FILENAME", (uchar *)"-", 0.0,
	    STR|DONTFREE, symtab)->sval;
	nfloc = setsymtab((uchar *)"NF", (uchar *)"", 0.0, NUM, symtab);
	NF = &nfloc->fval;
	nrloc = setsymtab((uchar *)"NR", (uchar *)"", 0.0, NUM, symtab);
	NR = &nrloc->fval;
	fnrloc = setsymtab((uchar *)"FNR", (uchar *)"", 0.0, NUM, symtab);
	FNR = &fnrloc->fval;
	SUBSEP = &setsymtab((uchar *)"SUBSEP", (uchar *)"\034", 0.0,
	    STR|DONTFREE, symtab)->sval;
	rstartloc = setsymtab((uchar *)"RSTART", (uchar *)"", 0.0,
	    NUM, symtab);
	RSTART = &rstartloc->fval;
	rlengthloc = setsymtab((uchar *)"RLENGTH", (uchar *)"", 0.0,
	    NUM, symtab);
	RLENGTH = &rlengthloc->fval;
	symtabloc = setsymtab((uchar *)"SYMTAB", (uchar *)"", 0.0, ARR, symtab);
	symtabloc->sval = (uchar *)symtab;
}

void
arginit(int ac, uchar *av[])
{
	Cell *cp;
	int i;
	uchar temp[11];

	/* first make FILENAME first real argument */
	for (i = 1; i < ac; i++) {
		if (!isclvar(av[i])) {
			(void) setsval(lookup((uchar *)"FILENAME", symtab),
			    av[i]);
			break;
		}
	}
	ARGC = &setsymtab((uchar *)"ARGC", (uchar *)"", (Awkfloat)ac,
	    NUM, symtab)->fval;
	cp = setsymtab((uchar *)"ARGV", (uchar *)"", 0.0, ARR, symtab);
	ARGVtab = makesymtab(NSYMTAB);	/* could be (int) ARGC as well */
	cp->sval = (uchar *) ARGVtab;
	for (i = 0; i < ac; i++) {
		(void) sprintf((char *)temp, "%d", i);
		if (is_number(*av)) {
			(void) setsymtab(temp, *av, atof((const char *)*av),
			    STR|NUM, ARGVtab);
		} else {
			(void) setsymtab(temp, *av, 0.0, STR, ARGVtab);
		}
		av++;
	}
}

void
envinit(uchar *envp[])
{
	Cell *cp;
	uchar *p;

	cp = setsymtab((uchar *)"ENVIRON", (uchar *)"", 0.0, ARR, symtab);
	ENVtab = makesymtab(NSYMTAB);
	cp->sval = (uchar *) ENVtab;
	for (; *envp; envp++) {
		if ((p = (uchar *)strchr((char *)*envp, '=')) == NULL)
			continue;
		*p++ = 0;	/* split into two strings at = */
		if (is_number(p)) {
			(void) setsymtab(*envp, p, atof((const char *)p),
			    STR|NUM, ENVtab);
		} else {
			(void) setsymtab(*envp, p, 0.0, STR, ENVtab);
		}
		/* restore in case env is passed down to a shell */
		p[-1] = '=';
	}
}

Array *
makesymtab(int n)
{
	Array *ap;
	Cell **tp;

	ap = (Array *)malloc(sizeof (Array));
	tp = (Cell **)calloc(n, sizeof (Cell *));
	if (ap == NULL || tp == NULL)
		ERROR "out of space in makesymtab" FATAL;
	ap->nelem = 0;
	ap->size = n;
	ap->tab = tp;
	return (ap);
}

void
freesymtab(Cell *ap)	/* free symbol table */
{
	Cell *cp, *next;
	Array *tp;
	int i;

	if (!isarr(ap))
		return;
	/*LINTED align*/
	tp = (Array *)ap->sval;
	if (tp == NULL)
		return;
	for (i = 0; i < tp->size; i++) {
		for (cp = tp->tab[i]; cp != NULL; cp = next) {
			next = cp->cnext;
			xfree(cp->nval);
			if (freeable(cp))
				xfree(cp->sval);
			free(cp);
		}
	}
	free(tp->tab);
	free(tp);
}

void
freeelem(Cell *ap, uchar *s)		/* free elem s from ap (i.e., ap["s"] */
{
	Array *tp;
	Cell *p, *prev = NULL;
	int h;

	/*LINTED align*/
	tp = (Array *)ap->sval;
	h = hash(s, tp->size);
	for (p = tp->tab[h]; p != NULL; prev = p, p = p->cnext)
		if (strcmp((char *)s, (char *)p->nval) == 0) {
			if (prev == NULL)	/* 1st one */
				tp->tab[h] = p->cnext;
			else			/* middle somewhere */
				prev->cnext = p->cnext;
			if (freeable(p))
				xfree(p->sval);
			free(p->nval);
			free(p);
			tp->nelem--;
			return;
		}
}

Cell *
setsymtab(uchar *n, uchar *s, Awkfloat f, unsigned int t, Array *tp)
{
	register int h;
	register Cell *p;

	if (n != NULL && (p = lookup(n, tp)) != NULL) {
		dprintf(("setsymtab found %p: n=%s", (void *)p, p->nval));
		dprintf((" s=\"%s\" f=%g t=%p\n",
		    p->sval, p->fval, (void *)p->tval));
		return (p);
	}
	p = (Cell *)malloc(sizeof (Cell));
	if (p == NULL)
		ERROR "symbol table overflow at %s", n FATAL;
	p->nval = tostring(n);
	p->sval = s ? tostring(s) : tostring((uchar *)"");
	p->fval = f;
	p->tval = t;
	p->csub = 0;

	tp->nelem++;
	if (tp->nelem > FULLTAB * tp->size)
		rehash(tp);
	h = hash(n, tp->size);
	p->cnext = tp->tab[h];
	tp->tab[h] = p;
	dprintf(("setsymtab set %p: n=%s", (void *)p, p->nval));
	dprintf((" s=\"%s\" f=%g t=%p\n", p->sval, p->fval, (void *)p->tval));
	return (p);
}

int
hash(uchar *s, int n)	/* form hash value for string s */
{
	register unsigned hashval;

	for (hashval = 0; *s != '\0'; s++)
		hashval = (*s + 31 * hashval);
	return (hashval % n);
}

static void
rehash(Array *tp)	/* rehash items in small table into big one */
{
	int i, nh, nsz;
	Cell *cp, *op, **np;

	nsz = GROWTAB * tp->size;
	np = (Cell **)calloc(nsz, sizeof (Cell *));
	if (np == NULL)
		ERROR "out of space in rehash" FATAL;
	for (i = 0; i < tp->size; i++) {
		for (cp = tp->tab[i]; cp; cp = op) {
			op = cp->cnext;
			nh = hash(cp->nval, nsz);
			cp->cnext = np[nh];
			np[nh] = cp;
		}
	}
	free(tp->tab);
	tp->tab = np;
	tp->size = nsz;
}

Cell *
lookup(uchar *s, Array *tp)	/* look for s in tp */
{
	register Cell *p;
	int h;

	h = hash(s, tp->size);
	for (p = tp->tab[h]; p != NULL; p = p->cnext) {
		if (strcmp((char *)s, (char *)p->nval) == 0)
			return (p);	/* found it */
	}
	return (NULL);			/* not found */
}

Awkfloat
setfval(Cell *vp, Awkfloat f)
{
	int	i;

	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "assign to");
	if (vp->tval & FLD) {
		donerec = 0;	/* mark $0 invalid */
		i = fldidx(vp);
		if (i > *NF)
			newfld(i);
		dprintf(("setting field %d to %g\n", i, f));
	} else if (vp->tval & REC) {
		donefld = 0;	/* mark $1... invalid */
		donerec = 1;
	}
	vp->tval &= ~STR;	/* mark string invalid */
	vp->tval |= NUM;	/* mark number ok */
	dprintf(("setfval %p: %s = %g, t=%p\n", (void *)vp,
	    vp->nval ? vp->nval : (unsigned char *)"NULL",
	    f, (void *)vp->tval));
	return (vp->fval = f);
}

void
funnyvar(Cell *vp, char *rw)
{
	if (vp->tval & ARR)
		ERROR "can't %s %s; it's an array name.", rw, vp->nval FATAL;
	if (vp->tval & FCN)
		ERROR "can't %s %s; it's a function.", rw, vp->nval FATAL;
	ERROR "funny variable %o: n=%s s=\"%s\" f=%g t=%o",
	    vp, vp->nval, vp->sval, vp->fval, vp->tval CONT;
}

uchar *
setsval(Cell *vp, uchar *s)
{
	int	i;

	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "assign to");
	if (vp->tval & FLD) {
		donerec = 0;	/* mark $0 invalid */
		i = fldidx(vp);
		if (i > *NF)
			newfld(i);
		dprintf(("setting field %d to %s\n", i, s));
	} else if (vp->tval & REC) {
		donefld = 0;	/* mark $1... invalid */
		donerec = 1;
	}
	vp->tval &= ~NUM;
	vp->tval |= STR;
	if (freeable(vp))
		xfree(vp->sval);
	vp->tval &= ~DONTFREE;
	dprintf(("setsval %p: %s = \"%s\", t=%p\n",
	    (void *)vp,
	    vp->nval ? (char *)vp->nval : "",
	    s,
	    (void *)(vp->tval ? (char *)vp->tval : "")));
	return (vp->sval = tostring(s));
}

Awkfloat
r_getfval(Cell *vp)
{
	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "read value of");
	if ((vp->tval & FLD) && donefld == 0)
		fldbld();
	else if ((vp->tval & REC) && donerec == 0)
		recbld();
	if (!isnum(vp)) {	/* not a number */
		vp->fval = atof((const char *)vp->sval);	/* best guess */
		if (is_number(vp->sval) && !(vp->tval&CON))
			vp->tval |= NUM;	/* make NUM only sparingly */
	}
	dprintf(("getfval %p: %s = %g, t=%p\n",
	    (void *)vp, vp->nval, vp->fval, (void *)vp->tval));
	return (vp->fval);
}

uchar *
r_getsval(Cell *vp)
{
	uchar s[256];

	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "read value of");
	if ((vp->tval & FLD) && donefld == 0)
		fldbld();
	else if ((vp->tval & REC) && donerec == 0)
		recbld();
	if ((vp->tval & STR) == 0) {
		if (!(vp->tval&DONTFREE))
			xfree(vp->sval);
		if ((long long)vp->fval == vp->fval) {
			(void) snprintf((char *)s, sizeof (s),
			    "%.20g", vp->fval);
		} else {
			/*LINTED*/
			(void) snprintf((char *)s, sizeof (s),
			    (char *)*OFMT, vp->fval);
		}
		vp->sval = tostring(s);
		vp->tval &= ~DONTFREE;
		vp->tval |= STR;
	}
	dprintf(("getsval %p: %s = \"%s\", t=%p\n",
	    (void *)vp,
	    vp->nval ? (char *)vp->nval : "",
	    vp->sval ? (char *)vp->sval : "",
	    (void *)vp->tval));
	return (vp->sval);
}

uchar *
tostring(uchar *s)
{
	register uchar *p;

	p = (uchar *)malloc(strlen((char *)s)+1);
	if (p == NULL)
		ERROR "out of space in tostring on %s", s FATAL;
	(void) strcpy((char *)p, (char *)s);
	return (p);
}

uchar *
qstring(uchar *s, int delim)	/* collect string up to delim */
{
	uchar *cbuf, *ret;
	int c, n;
	size_t	cbufsz, cnt;

	init_buf(&cbuf, &cbufsz, LINE_INCR);

	for (cnt = 0; (c = *s) != delim; s++) {
		if (c == '\n') {
			ERROR "newline in string %.10s...", cbuf SYNTAX;
		} else if (c != '\\') {
			expand_buf(&cbuf, &cbufsz, cnt);
			cbuf[cnt++] = c;
		} else {	/* \something */
			expand_buf(&cbuf, &cbufsz, cnt);
			switch (c = *++s) {
			case '\\':	cbuf[cnt++] = '\\'; break;
			case 'n':	cbuf[cnt++] = '\n'; break;
			case 't':	cbuf[cnt++] = '\t'; break;
			case 'b':	cbuf[cnt++] = '\b'; break;
			case 'f':	cbuf[cnt++] = '\f'; break;
			case 'r':	cbuf[cnt++] = '\r'; break;
			default:
				if (!isdigit(c)) {
					cbuf[cnt++] = c;
					break;
				}
				n = c - '0';
				if (isdigit(s[1])) {
					n = 8 * n + *++s - '0';
					if (isdigit(s[1]))
						n = 8 * n + *++s - '0';
				}
				cbuf[cnt++] = n;
				break;
			}
		}
	}
	cbuf[cnt] = '\0';
	ret = tostring(cbuf);
	free(cbuf);
	return (ret);
}

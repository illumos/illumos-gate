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

#define	DEBUG
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "awk.h"
#include "y.tab.h"

#define	FULLTAB	2	/* rehash when table gets this x full */
#define	GROWTAB 4	/* grow table by this factor */

Array	*symtab;	/* main symbol table */

char	**FS;		/* initial field sep */
char	**RS;		/* initial record sep */
char	**OFS;		/* output field sep */
char	**ORS;		/* output record sep */
char	**OFMT;		/* output format for numbers */
Awkfloat *NF;		/* number of fields in current record */
Awkfloat *NR;		/* number of current record */
Awkfloat *FNR;		/* number of current record in current file */
char	**FILENAME;	/* current filename argument */
Awkfloat *ARGC;		/* number of arguments from command line */
char	**SUBSEP;	/* subscript separator for a[i,j,k]; default \034 */
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

Cell	*nullloc;	/* a guaranteed empty cell */
Node	*nullnode;	/* zero&null, converted into a node for comparisons */

static	void	rehash(Array *);

void
syminit(void)	/* initialize symbol table with builtin vars */
{
	init_buf(&record, &recsize, LINE_INCR);

	/* initialize $0 */
	recloc = getfld(0);
	recloc->nval = "$0";
	recloc->sval = record;
	recloc->tval = REC|STR|DONTFREE;

	symtab = makesymtab(NSYMTAB);
	(void) setsymtab("0", "0", 0.0,
	    NUM|STR|CON|DONTFREE, symtab);
	/* this is used for if(x)... tests: */
	nullloc = setsymtab("$zero&null", "", 0.0,
	    NUM|STR|CON|DONTFREE, symtab);
	nullnode = celltonode(nullloc, CCON);

	FS = &setsymtab("FS", " ", 0.0,
	    STR|DONTFREE, symtab)->sval;
	RS = &setsymtab("RS", "\n", 0.0,
	    STR|DONTFREE, symtab)->sval;
	OFS = &setsymtab("OFS", " ", 0.0, STR|DONTFREE, symtab)->sval;
	ORS = &setsymtab("ORS", "\n", 0.0,
	    STR|DONTFREE, symtab)->sval;
	OFMT = &setsymtab("OFMT", "%.6g", 0.0,
	    STR|DONTFREE, symtab)->sval;
	FILENAME = &setsymtab("FILENAME", "-", 0.0,
	    STR|DONTFREE, symtab)->sval;
	nfloc = setsymtab("NF", "", 0.0, NUM, symtab);
	NF = &nfloc->fval;
	nrloc = setsymtab("NR", "", 0.0, NUM, symtab);
	NR = &nrloc->fval;
	fnrloc = setsymtab("FNR", "", 0.0, NUM, symtab);
	FNR = &fnrloc->fval;
	SUBSEP = &setsymtab("SUBSEP", "\034", 0.0,
	    STR|DONTFREE, symtab)->sval;
	rstartloc = setsymtab("RSTART", "", 0.0, NUM, symtab);
	RSTART = &rstartloc->fval;
	rlengthloc = setsymtab("RLENGTH", "", 0.0, NUM, symtab);
	RLENGTH = &rlengthloc->fval;
	symtabloc = setsymtab("SYMTAB", "", 0.0, ARR, symtab);
	symtabloc->sval = (char *)symtab;
}

void
arginit(int ac, char **av)	/* set up ARGV and ARGC */
{
	Cell *cp;
	int i;
	char temp[50];

	/* first make FILENAME first real argument */
	for (i = 1; i < ac; i++) {
		if (!isclvar(av[i])) {
			(void) setsval(lookup("FILENAME", symtab),
			    av[i]);
			break;
		}
	}
	ARGC = &setsymtab("ARGC", "", (Awkfloat)ac, NUM, symtab)->fval;
	cp = setsymtab("ARGV", "", 0.0, ARR, symtab);
	ARGVtab = makesymtab(NSYMTAB);	/* could be (int) ARGC as well */
	cp->sval = (char *)ARGVtab;
	for (i = 0; i < ac; i++) {
		(void) sprintf(temp, "%d", i);
		if (is_number(*av)) {
			(void) setsymtab(temp, *av, atof(*av),
			    STR|NUM, ARGVtab);
		} else {
			(void) setsymtab(temp, *av, 0.0, STR, ARGVtab);
		}
		av++;
	}
}

void
envinit(char **envp)	/* set up ENVIRON variable */
{
	Cell *cp;
	char *p;

	cp = setsymtab("ENVIRON", "", 0.0, ARR, symtab);
	ENVtab = makesymtab(NSYMTAB);
	cp->sval = (char *)ENVtab;
	for (; *envp; envp++) {
		if ((p = strchr(*envp, '=')) == NULL)
			continue;
		*p++ = 0;	/* split into two strings at = */
		if (is_number(p)) {
			(void) setsymtab(*envp, p, atof(p),
			    STR|NUM, ENVtab);
		} else {
			(void) setsymtab(*envp, p, 0.0, STR, ENVtab);
		}
		/* restore in case env is passed down to a shell */
		p[-1] = '=';
	}
}

Array *
makesymtab(int n)	/* make a new symbol table */
{
	Array *ap;
	Cell **tp;

	ap = (Array *)malloc(sizeof (Array));
	tp = (Cell **)calloc(n, sizeof (Cell *));
	if (ap == NULL || tp == NULL)
		FATAL("out of space in makesymtab");
	ap->nelem = 0;
	ap->size = n;
	ap->tab = tp;
	return (ap);
}

void
freesymtab(Cell *ap)	/* free a symbol table */
{
	Cell *cp, *temp;
	Array *tp;
	int i;

	if (!isarr(ap))
		return;
	/*LINTED align*/
	tp = (Array *)ap->sval;
	if (tp == NULL)
		return;
	for (i = 0; i < tp->size; i++) {
		for (cp = tp->tab[i]; cp != NULL; cp = temp) {
			xfree(cp->nval);
			if (freeable(cp))
				xfree(cp->sval);
			temp = cp->cnext;	/* avoids freeing then using */
			free(cp);
			tp->nelem--;
		}
		tp->tab[i] = 0;
	}
	if (tp->nelem != 0) {
		WARNING("can't happen: inconsistent element count freeing %s",
		    ap->nval);
	}
	free(tp->tab);
	free(tp);
}

void
freeelem(Cell *ap, const char *s)	/* free elem s from ap (i.e., ap["s"] */
{
	Array *tp;
	Cell *p, *prev = NULL;
	int h;

	/*LINTED align*/
	tp = (Array *)ap->sval;
	h = hash(s, tp->size);
	for (p = tp->tab[h]; p != NULL; prev = p, p = p->cnext)
		if (strcmp(s, p->nval) == 0) {
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
setsymtab(const char *n, const char *s, Awkfloat f, unsigned int t, Array *tp)
{
	int h;
	Cell *p;

	if (n != NULL && (p = lookup(n, tp)) != NULL) {
		dprintf(("setsymtab found %p: n=%s s=\"%s\" f=%g t=%o\n",
		    (void *)p, NN(p->nval), NN(p->sval), p->fval, p->tval));
		return (p);
	}
	p = (Cell *)malloc(sizeof (Cell));
	if (p == NULL)
		FATAL("out of space for symbol table at %s", n);
	p->nval = tostring(n);
	p->sval = s ? tostring(s) : tostring("");
	p->fval = f;
	p->tval = t;
	p->csub = CUNK;

	tp->nelem++;
	if (tp->nelem > FULLTAB * tp->size)
		rehash(tp);
	h = hash(n, tp->size);
	p->cnext = tp->tab[h];
	tp->tab[h] = p;
	dprintf(("setsymtab set %p: n=%s s=\"%s\" f=%g t=%o\n",
	    (void *)p, p->nval, p->sval, p->fval, p->tval));
	return (p);
}

int
hash(const char *s, int n)	/* form hash value for string s */
{
	unsigned int hashval;

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
	if (np == NULL)		/* can't do it, but can keep running. */
		return;		/* someone else will run out later. */
	for (i = 0; i < tp->size; i++) {
		for (cp = tp->tab[i]; cp != NULL; cp = op) {
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
lookup(const char *s, Array *tp)	/* look for s in tp */
{
	Cell *p;
	int h;

	h = hash(s, tp->size);
	for (p = tp->tab[h]; p != NULL; p = p->cnext) {
		if (strcmp(s, p->nval) == 0)
			return (p);	/* found it */
	}
	return (NULL);			/* not found */
}

Awkfloat
setfval(Cell *vp, Awkfloat f)	/* set float val of a Cell */
{
	int	i;

	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "assign to");
	if (isfld(vp)) {
		donerec = 0;	/* mark $0 invalid */
		i = fldidx(vp);
		if (i > *NF)
			newfld(i);
		dprintf(("setting field %d to %g\n", i, f));
	} else if (isrec(vp)) {
		donefld = 0;	/* mark $1... invalid */
		donerec = 1;
	}
	vp->tval &= ~STR;	/* mark string invalid */
	vp->tval |= NUM;	/* mark number ok */
	dprintf(("setfval %p: %s = %g, t=%o\n", (void *)vp,
	    NN(vp->nval), f, vp->tval));
	return (vp->fval = f);
}

void
funnyvar(Cell *vp, const char *rw)
{
	if (isarr(vp))
		FATAL("can't %s %s; it's an array name.", rw, vp->nval);
	if (isfcn(vp))
		FATAL("can't %s %s; it's a function.", rw, vp->nval);
	WARNING("funny variable %p: n=%s s=\"%s\" f=%g t=%o",
	    vp, vp->nval, vp->sval, vp->fval, vp->tval);
}

char *
setsval(Cell *vp, const char *s)	/* set string val of a Cell */
{
	int	i;

	dprintf(("starting setsval %p: %s = \"%s\", t=%o, r,f=%d,%d\n",
	    (void *)vp, NN(vp->nval), s, vp->tval, donerec, donefld));
	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "assign to");
	if (isfld(vp)) {
		donerec = 0;	/* mark $0 invalid */
		i = fldidx(vp);
		if (i > *NF)
			newfld(i);
		dprintf(("setting field %d to %s\n", i, s));
	} else if (isrec(vp)) {
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
r_getfval(Cell *vp)	/* get float val of a Cell */
{
	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "read value of");
	if (isfld(vp) && donefld == 0)
		fldbld();
	else if (isrec(vp) && donerec == 0)
		recbld();
	if (!isnum(vp)) {	/* not a number */
		vp->fval = atof(vp->sval);	/* best guess */
		if (is_number(vp->sval) && !(vp->tval&CON))
			vp->tval |= NUM;	/* make NUM only sparingly */
	}
	dprintf(("getfval %p: %s = %g, t=%p\n",
	    (void *)vp, NN(vp->nval), vp->fval, (void *)vp->tval));
	return (vp->fval);
}

char *
r_getsval(Cell *vp)
{
	char s[256];

	if ((vp->tval & (NUM | STR)) == 0)
		funnyvar(vp, "read value of");
	if (isfld(vp) && donefld == 0)
		fldbld();
	else if (isrec(vp) && donerec == 0)
		recbld();
	if (isstr(vp) == 0) {
		if (freeable(vp))
			xfree(vp->sval);
		if ((long long)vp->fval == vp->fval) {
			(void) snprintf(s, sizeof (s),
			    "%.20g", vp->fval);
		} else {
			/*LINTED*/
			(void) snprintf(s, sizeof (s),
			    (char *)*OFMT, vp->fval);
		}
		vp->sval = tostring(s);
		vp->tval &= ~DONTFREE;
		vp->tval |= STR;
	}
	dprintf(("getsval %p: %s = \"%s (%p)\", t=%o\n",
	    (void *)vp, NN(vp->nval), vp->sval, (void *)vp->sval, vp->tval));
	return (vp->sval);
}

char *
tostring(const char *s)	/* make a copy of string s */
{
	char *p = strdup(s);
	if (p == NULL)
		FATAL("out of space in tostring on %s", s);
	return (p);
}

char *
qstring(const char *s, int delim)	/* collect string up to delim */
{
	char *cbuf, *ret;
	int c, n;
	size_t	cbufsz, cnt;

	init_buf(&cbuf, &cbufsz, LINE_INCR);

	for (cnt = 0; (c = *s) != delim; s++) {
		if (c == '\n') {
			SYNTAX("newline in string %.10s...", cbuf);
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

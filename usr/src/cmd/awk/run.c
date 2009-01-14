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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#define	tempfree(x, s)	if (istemp(x)) tfree(x, s)

#define	execute(p) r_execute(p)

#define	DEBUG
#include	"awk.h"
#include	<math.h>
#include	"y.tab.h"
#include	<stdio.h>
#include	<ctype.h>
#include	<setjmp.h>
#include	<time.h>

#ifndef	FOPEN_MAX
#define	FOPEN_MAX	15	/* max number of open files, from ANSI std. */
#endif


static jmp_buf env;

static	Cell	*r_execute(Node *);
static	Cell	*gettemp(char *), *copycell(Cell *);
static	FILE	*openfile(int, uchar *), *redirect(int, Node *);

int	paircnt;
Node	*winner = NULL;

static Cell	*tmps;

static Cell	truecell	= { OBOOL, BTRUE, 0, 0, 1.0, NUM };
Cell	*true	= &truecell;
static Cell	falsecell	= { OBOOL, BFALSE, 0, 0, 0.0, NUM };
Cell	*false	= &falsecell;
static Cell	breakcell	= { OJUMP, JBREAK, 0, 0, 0.0, NUM };
Cell	*jbreak	= &breakcell;
static Cell	contcell	= { OJUMP, JCONT, 0, 0, 0.0, NUM };
Cell	*jcont	= &contcell;
static Cell	nextcell	= { OJUMP, JNEXT, 0, 0, 0.0, NUM };
Cell	*jnext	= &nextcell;
static Cell	exitcell	= { OJUMP, JEXIT, 0, 0, 0.0, NUM };
Cell	*jexit	= &exitcell;
static Cell	retcell		= { OJUMP, JRET, 0, 0, 0.0, NUM };
Cell	*jret	= &retcell;
static Cell	tempcell	= { OCELL, CTEMP, 0, 0, 0.0, NUM };

Node	*curnode = NULL;	/* the node being executed, for debugging */

static	void	tfree(Cell *, char *);
static	void	closeall(void);
static	double	ipow(double, int);

void
run(Node *a)
{
	(void) execute(a);
	closeall();
}

static Cell *
r_execute(Node *u)
{
	register Cell *(*proc)();
	register Cell *x;
	register Node *a;

	if (u == NULL)
		return (true);
	for (a = u; ; a = a->nnext) {
		curnode = a;
		if (isvalue(a)) {
			x = (Cell *) (a->narg[0]);
			if ((x->tval & FLD) && !donefld)
				fldbld();
			else if ((x->tval & REC) && !donerec)
				recbld();
			return (x);
		}
		/* probably a Cell* but too risky to print */
		if (notlegal(a->nobj))
			ERROR "illegal statement" FATAL;
		proc = proctab[a->nobj-FIRSTTOKEN];
		x = (*proc)(a->narg, a->nobj);
		if ((x->tval & FLD) && !donefld)
			fldbld();
		else if ((x->tval & REC) && !donerec)
			recbld();
		if (isexpr(a))
			return (x);
		/* a statement, goto next statement */
		if (isjump(x))
			return (x);
		if (a->nnext == (Node *)NULL)
			return (x);
		tempfree(x, "execute");
	}
}

/*ARGSUSED*/
Cell *
program(Node **a, int n)
{
	register Cell *x;

	if (setjmp(env) != 0)
		goto ex;
	if (a[0]) {		/* BEGIN */
		x = execute(a[0]);
		if (isexit(x))
			return (true);
		if (isjump(x)) {
			ERROR "illegal break, continue or next from BEGIN"
			    FATAL;
		}
		tempfree(x, "");
	}
loop:
	if (a[1] || a[2])
		while (getrec(&record, &record_size) > 0) {
			x = execute(a[1]);
			if (isexit(x))
				break;
			tempfree(x, "");
		}
ex:
	if (setjmp(env) != 0)
		goto ex1;
	if (a[2]) {		/* END */
		x = execute(a[2]);
		if (iscont(x))	/* read some more */
			goto loop;
		if (isbreak(x) || isnext(x))
			ERROR "illegal break or next from END" FATAL;
		tempfree(x, "");
	}
ex1:
	return (true);
}

struct Frame {
	int nargs;	/* number of arguments in this call */
	Cell *fcncell;	/* pointer to Cell for function */
	Cell **args;	/* pointer to array of arguments after execute */
	Cell *retval;	/* return value */
};

#define	NARGS	30

struct Frame *frame = NULL; /* base of stack frames; dynamically allocated */
int	nframe = 0;		/* number of frames allocated */
struct Frame *fp = NULL;	/* frame pointer. bottom level unused */

/*ARGSUSED*/
Cell *
call(Node **a, int n)
{
	static Cell newcopycell =
		{ OCELL, CCOPY, 0, (uchar *) "", 0.0, NUM|STR|DONTFREE };
	int i, ncall, ndef, freed = 0;
	Node *x;
	Cell *args[NARGS], *oargs[NARGS], *y, *z, *fcn;
	uchar *s;

	fcn = execute(a[0]);	/* the function itself */
	s = fcn->nval;
	if (!isfunc(fcn))
		ERROR "calling undefined function %s", s FATAL;
	if (frame == NULL) {
		fp = frame = (struct Frame *)calloc(nframe += 100,
		    sizeof (struct Frame));
		if (frame == NULL) {
			ERROR "out of space for stack frames calling %s",
			    s FATAL;
		}
	}
	for (ncall = 0, x = a[1]; x != NULL; x = x->nnext) /* args in call */
		ncall++;
	ndef = (int)fcn->fval;			/* args in defn */
	dprintf(("calling %s, %d args (%d in defn), fp=%d\n",
	    s, ncall, ndef, fp-frame));
	if (ncall > ndef) {
		ERROR "function %s called with %d args, uses only %d",
		    s, ncall, ndef WARNING;
	}
	if (ncall + ndef > NARGS) {
		ERROR "function %s has %d arguments, limit %d",
		    s, ncall+ndef, NARGS FATAL;
	}
	for (i = 0, x = a[1]; x != NULL; i++, x = x->nnext) {
		/* get call args */
		dprintf(("evaluate args[%d], fp=%d:\n", i, fp-frame));
		y = execute(x);
		oargs[i] = y;
		dprintf(("args[%d]: %s %f <%s>, t=%o\n",
		    i, y->nval, y->fval,
		    isarr(y) ? "(array)" : (char *)y->sval, y->tval));
		if (isfunc(y)) {
			ERROR "can't use function %s as argument in %s",
			    y->nval, s FATAL;
		}
		if (isarr(y))
			args[i] = y;	/* arrays by ref */
		else
			args[i] = copycell(y);
		tempfree(y, "callargs");
	}
	for (; i < ndef; i++) { /* add null args for ones not provided */
		args[i] = gettemp("nullargs");
		*args[i] = newcopycell;
	}
	fp++;	/* now ok to up frame */
	if (fp >= frame + nframe) {
		int dfp = fp - frame;	/* old index */
		frame = (struct Frame *)
		    realloc(frame, (nframe += 100) * sizeof (struct Frame));
		if (frame == NULL)
			ERROR "out of space for stack frames in %s", s FATAL;
		fp = frame + dfp;
	}
	fp->fcncell = fcn;
	fp->args = args;
	fp->nargs = ndef;	/* number defined with (excess are locals) */
	fp->retval = gettemp("retval");

	dprintf(("start exec of %s, fp=%d\n", s, fp-frame));
	/*LINTED align*/
	y = execute((Node *)(fcn->sval));	/* execute body */
	dprintf(("finished exec of %s, fp=%d\n", s, fp-frame));

	for (i = 0; i < ndef; i++) {
		Cell *t = fp->args[i];
		if (isarr(t)) {
			if (t->csub == CCOPY) {
				if (i >= ncall) {
					freesymtab(t);
					t->csub = CTEMP;
				} else {
					oargs[i]->tval = t->tval;
					oargs[i]->tval &= ~(STR|NUM|DONTFREE);
					oargs[i]->sval = t->sval;
					tempfree(t, "oargsarr");
				}
			}
		} else {
			t->csub = CTEMP;
			tempfree(t, "fp->args");
			if (t == y) freed = 1;
		}
	}
	tempfree(fcn, "call.fcn");
	if (isexit(y) || isnext(y))
		return (y);
	if (!freed)
		tempfree(y, "fcn ret"); /* this can free twice! */
	z = fp->retval;			/* return value */
	dprintf(("%s returns %g |%s| %o\n",
	    s, getfval(z), getsval(z), z->tval));
	fp--;
	return (z);
}

static Cell *
copycell(Cell *x)	/* make a copy of a cell in a temp */
{
	Cell *y;

	y = gettemp("copycell");
	y->csub = CCOPY;	/* prevents freeing until call is over */
	y->nval = x->nval;
	y->sval = x->sval ? tostring(x->sval) : NULL;
	y->fval = x->fval;
	/* copy is not constant or field is DONTFREE right? */
	y->tval = x->tval & ~(CON|FLD|REC|DONTFREE);
	return (y);
}

/*ARGSUSED*/
Cell *
arg(Node **a, int nnn)
{
	int n;

	n = (int)a[0];	/* argument number, counting from 0 */
	dprintf(("arg(%d), fp->nargs=%d\n", n, fp->nargs));
	if (n+1 > fp->nargs) {
		ERROR "argument #%d of function %s was not supplied",
		    n+1, fp->fcncell->nval FATAL;
	}
	return (fp->args[n]);
}

Cell *
jump(Node **a, int n)
{
	register Cell *y;

	switch (n) {
	case EXIT:
		if (a[0] != NULL) {
			y = execute(a[0]);
			errorflag = (int)getfval(y);
			tempfree(y, "");
		}
		longjmp(env, 1);
		/*NOTREACHED*/
	case RETURN:
		if (a[0] != NULL) {
			y = execute(a[0]);
			if ((y->tval & (STR|NUM)) == (STR|NUM)) {
				(void) setsval(fp->retval, getsval(y));
				fp->retval->fval = getfval(y);
				fp->retval->tval |= NUM;
			} else if (y->tval & STR)
				(void) setsval(fp->retval, getsval(y));
			else if (y->tval & NUM)
				(void) setfval(fp->retval, getfval(y));
			tempfree(y, "");
		}
		return (jret);
	case NEXT:
		return (jnext);
	case BREAK:
		return (jbreak);
	case CONTINUE:
		return (jcont);
	default:	/* can't happen */
		ERROR "illegal jump type %d", n FATAL;
	}
	/*NOTREACHED*/
	return (NULL);
}

Cell *
getline(Node **a, int n)
{
	/* a[0] is variable, a[1] is operator, a[2] is filename */
	register Cell *r, *x;
	uchar *buf;
	FILE *fp;
	size_t len;

	(void) fflush(stdout);	/* in case someone is waiting for a prompt */
	r = gettemp("");
	if (a[1] != NULL) {		/* getline < file */
		x = execute(a[2]);		/* filename */
		if ((int)a[1] == '|')	/* input pipe */
			a[1] = (Node *)LE;	/* arbitrary flag */
		fp = openfile((int)a[1], getsval(x));
		tempfree(x, "");
		buf = NULL;
		if (fp == NULL)
			n = -1;
		else
			n = readrec(&buf, &len, fp);
		if (n > 0) {
			if (a[0] != NULL) {	/* getline var <file */
				(void) setsval(execute(a[0]), buf);
			} else {			/* getline <file */
				if (!(recloc->tval & DONTFREE))
					xfree(recloc->sval);
				expand_buf(&record, &record_size, len);
				(void) memcpy(record, buf, len);
				record[len] = '\0';
				recloc->sval = record;
				recloc->tval = REC | STR | DONTFREE;
				donerec = 1; donefld = 0;
			}
		}
		if (buf != NULL)
			free(buf);
	} else {			/* bare getline; use current input */
		if (a[0] == NULL)	/* getline */
			n = getrec(&record, &record_size);
		else {			/* getline var */
			init_buf(&buf, &len, LINE_INCR);
			n = getrec(&buf, &len);
			(void) setsval(execute(a[0]), buf);
			free(buf);
		}
	}
	(void) setfval(r, (Awkfloat)n);
	return (r);
}

/*ARGSUSED*/
Cell *
getnf(Node **a, int n)
{
	if (donefld == 0)
		fldbld();
	return ((Cell *)a[0]);
}

/*ARGSUSED*/
Cell *
array(Node **a, int n)
{
	register Cell *x, *y, *z;
	register uchar *s;
	register Node *np;
	uchar	*buf;
	size_t	bsize, tlen, len, slen;

	x = execute(a[0]);	/* Cell* for symbol table */
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = '\0';
	tlen = 0;
	slen = strlen((char *)*SUBSEP);
	for (np = a[1]; np; np = np->nnext) {
		y = execute(np);	/* subscript */
		s = getsval(y);
		len = strlen((char *)s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		if (np->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
		tempfree(y, "");
	}
	if (!isarr(x)) {
		dprintf(("making %s into an array\n", x->nval));
		if (freeable(x))
			xfree(x->sval);
		x->tval &= ~(STR|NUM|DONTFREE);
		x->tval |= ARR;
		x->sval = (uchar *) makesymtab(NSYMTAB);
	}
	/*LINTED align*/
	z = setsymtab(buf, (uchar *)"", 0.0, STR|NUM, (Array *)x->sval);
	z->ctype = OCELL;
	z->csub = CVAR;
	tempfree(x, "");
	free(buf);
	return (z);
}

/*ARGSUSED*/
Cell *
delete(Node **a, int n)
{
	Cell *x, *y;
	Node *np;
	uchar *buf, *s;
	size_t bsize, tlen, slen, len;

	x = execute(a[0]);	/* Cell* for symbol table */
	if (!isarr(x))
		return (true);
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = '\0';
	tlen = 0;
	slen = strlen((char *)*SUBSEP);
	for (np = a[1]; np; np = np->nnext) {
		y = execute(np);	/* subscript */
		s = getsval(y);
		len = strlen((char *)s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		if (np->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
		tempfree(y, "");
	}
	freeelem(x, buf);
	tempfree(x, "");
	free(buf);
	return (true);
}

/*ARGSUSED*/
Cell *
intest(Node **a, int n)
{
	register Cell *x, *ap, *k;
	Node *p;
	uchar *buf;
	uchar *s;
	size_t bsize, tlen, slen, len;

	ap = execute(a[1]);	/* array name */
	if (!isarr(ap))
		ERROR "%s is not an array", ap->nval FATAL;
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = 0;
	tlen = 0;
	slen = strlen((char *)*SUBSEP);
	for (p = a[0]; p; p = p->nnext) {
		x = execute(p);	/* expr */
		s = getsval(x);
		len = strlen((char *)s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		tempfree(x, "");
		if (p->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
	}
	/*LINTED align*/
	k = lookup(buf, (Array *)ap->sval);
	tempfree(ap, "");
	free(buf);
	if (k == NULL)
		return (false);
	else
		return (true);
}


Cell *
matchop(Node **a, int n)
{
	register Cell *x, *y;
	register uchar *s, *t;
	register int i;
	fa *pfa;
	int (*mf)() = match, mode = 0;

	if (n == MATCHFCN) {
		mf = pmatch;
		mode = 1;
	}
	x = execute(a[1]);
	s = getsval(x);
	if (a[0] == 0)
		i = (*mf)(a[2], s);
	else {
		y = execute(a[2]);
		t = getsval(y);
		pfa = makedfa(t, mode);
		i = (*mf)(pfa, s);
		tempfree(y, "");
	}
	tempfree(x, "");
	if (n == MATCHFCN) {
		int start = patbeg - s + 1;
		if (patlen < 0)
			start = 0;
		(void) setfval(rstartloc, (Awkfloat)start);
		(void) setfval(rlengthloc, (Awkfloat)patlen);
		x = gettemp("");
		x->tval = NUM;
		x->fval = start;
		return (x);
	} else if (n == MATCH && i == 1 || n == NOTMATCH && i == 0)
		return (true);
	else
		return (false);
}


Cell *
boolop(Node **a, int n)
{
	register Cell *x, *y;
	register int i;

	x = execute(a[0]);
	i = istrue(x);
	tempfree(x, "");
	switch (n) {
	case BOR:
		if (i)
			return (true);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y, "");
		return (i ? true : false);
	case AND:
		if (!i)
			return (false);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y, "");
		return (i ? true : false);
	case NOT:
		return (i ? false : true);
	default:	/* can't happen */
		ERROR "unknown boolean operator %d", n FATAL;
	}
	/*NOTREACHED*/
	return (NULL);
}

Cell *
relop(Node **a, int n)
{
	register int i;
	register Cell *x, *y;
	Awkfloat j;

	x = execute(a[0]);
	y = execute(a[1]);
	if (x->tval&NUM && y->tval&NUM) {
		j = x->fval - y->fval;
		i = j < 0 ? -1: (j > 0 ? 1: 0);
	} else {
		i = strcmp((char *)getsval(x), (char *)getsval(y));
	}
	tempfree(x, "");
	tempfree(y, "");
	switch (n) {
	case LT:	return (i < 0 ? true : false);
	case LE:	return (i <= 0 ? true : false);
	case NE:	return (i != 0 ? true : false);
	case EQ:	return (i == 0 ? true : false);
	case GE:	return (i >= 0 ? true : false);
	case GT:	return (i > 0 ? true : false);
	default:	/* can't happen */
		ERROR "unknown relational operator %d", n FATAL;
	}
	/*NOTREACHED*/
	return (false);
}

static void
tfree(Cell *a, char *s)
{
	if (dbg > 1) {
		(void) printf("## tfree %.8s %06lo %s\n",
		    s, (ulong_t)a, a->sval ? a->sval : (uchar *)"");
	}
	if (freeable(a))
		xfree(a->sval);
	if (a == tmps)
		ERROR "tempcell list is curdled" FATAL;
	a->cnext = tmps;
	tmps = a;
}

static Cell *
gettemp(char *s)
{
	int i;
	register Cell *x;

	if (!tmps) {
		tmps = (Cell *)calloc(100, sizeof (Cell));
		if (!tmps)
			ERROR "no space for temporaries" FATAL;
		for (i = 1; i < 100; i++)
			tmps[i-1].cnext = &tmps[i];
		tmps[i-1].cnext = 0;
	}
	x = tmps;
	tmps = x->cnext;
	*x = tempcell;
	if (dbg > 1)
		(void) printf("## gtemp %.8s %06lo\n", s, (ulong_t)x);
	return (x);
}

/*ARGSUSED*/
Cell *
indirect(Node **a, int n)
{
	register Cell *x;
	register int m;
	register uchar *s;

	x = execute(a[0]);
	m = (int)getfval(x);
	if (m == 0 && !is_number(s = getsval(x)))	/* suspicion! */
		ERROR "illegal field $(%s)", s FATAL;
	tempfree(x, "");
	x = fieldadr(m);
	x->ctype = OCELL;
	x->csub = CFLD;
	return (x);
}

/*ARGSUSED*/
Cell *
substr(Node **a, int nnn)
{
	register int k, m, n;
	register uchar *s;
	int temp;
	register Cell *x, *y, *z;

	x = execute(a[0]);
	y = execute(a[1]);
	if (a[2] != 0)
		z = execute(a[2]);
	s = getsval(x);
	k = strlen((char *)s) + 1;
	if (k <= 1) {
		tempfree(x, "");
		tempfree(y, "");
		if (a[2] != 0)
			tempfree(z, "");
		x = gettemp("");
		(void) setsval(x, (uchar *)"");
		return (x);
	}
	m = (int)getfval(y);
	if (m <= 0)
		m = 1;
	else if (m > k)
		m = k;
	tempfree(y, "");
	if (a[2] != 0) {
		n = (int)getfval(z);
		tempfree(z, "");
	} else
		n = k - 1;
	if (n < 0)
		n = 0;
	else if (n > k - m)
		n = k - m;
	dprintf(("substr: m=%d, n=%d, s=%s\n", m, n, s));
	y = gettemp("");
	temp = s[n + m - 1];	/* with thanks to John Linderman */
	s[n + m - 1] = '\0';
	(void) setsval(y, s + m - 1);
	s[n + m - 1] = temp;
	tempfree(x, "");
	return (y);
}

/*ARGSUSED*/
Cell *
sindex(Node **a, int nnn)
{
	register Cell *x, *y, *z;
	register uchar *s1, *s2, *p1, *p2, *q;
	Awkfloat v = 0.0;

	x = execute(a[0]);
	s1 = getsval(x);
	y = execute(a[1]);
	s2 = getsval(y);

	z = gettemp("");
	for (p1 = s1; *p1 != '\0'; p1++) {
		for (q = p1, p2 = s2; *p2 != '\0' && *q == *p2; q++, p2++)
			;
		if (*p2 == '\0') {
			v = (Awkfloat) (p1 - s1 + 1);	/* origin 1 */
			break;
		}
	}
	tempfree(x, "");
	tempfree(y, "");
	(void) setfval(z, v);
	return (z);
}

void
format(uchar **bufp, uchar *s, Node *a)
{
	uchar *fmt;
	register uchar *os;
	register Cell *x;
	int flag = 0, len;
	uchar_t	*buf;
	size_t bufsize, fmtsize, cnt, tcnt, ret;

	init_buf(&buf, &bufsize, LINE_INCR);
	init_buf(&fmt, &fmtsize, LINE_INCR);
	os = s;
	cnt = 0;
	while (*s) {
		if (*s != '%') {
			expand_buf(&buf, &bufsize, cnt);
			buf[cnt++] = *s++;
			continue;
		}
		if (*(s+1) == '%') {
			expand_buf(&buf, &bufsize, cnt);
			buf[cnt++] = '%';
			s += 2;
			continue;
		}
		for (tcnt = 0; ; s++) {
			expand_buf(&fmt, &fmtsize, tcnt);
			fmt[tcnt++] = *s;
			if (*s == '\0')
				break;
			if (isalpha(*s) && *s != 'l' && *s != 'h' && *s != 'L')
				break;	/* the ansi panoply */
			if (*s == '*') {
				if (a == NULL) {
					ERROR
		"not enough args in printf(%s) or sprintf(%s)", os, os FATAL;
				}
				x = execute(a);
				a = a->nnext;
				tcnt--;
				expand_buf(&fmt, &fmtsize, tcnt + 12);
				ret = sprintf((char *)&fmt[tcnt], "%d",
				    (int)getfval(x));
				tcnt += ret;
				tempfree(x, "");
			}
		}
		fmt[tcnt] = '\0';

		switch (*s) {
		case 'f': case 'e': case 'g': case 'E': case 'G':
			flag = 1;
			break;
		case 'd': case 'i':
			flag = 2;
			if (*(s-1) == 'l')
				break;
			fmt[tcnt - 1] = 'l';
			expand_buf(&fmt, &fmtsize, tcnt);
			fmt[tcnt++] = 'd';
			fmt[tcnt] = '\0';
			break;
		case 'o': case 'x': case 'X': case 'u':
			flag = *(s-1) == 'l' ? 2 : 3;
			break;
		case 's':
			flag = 4;
			break;
		case 'c':
			flag = 5;
			break;
		default:
			flag = 0;
			break;
		}
		if (flag == 0) {
			len = strlen((char *)fmt);
			expand_buf(&buf, &bufsize, cnt + len);
			(void) memcpy(&buf[cnt], fmt, len);
			cnt += len;
			buf[cnt] = '\0';
			continue;
		}
		if (a == NULL) {
			ERROR
	"not enough args in printf(%s) or sprintf(%s)", os, os FATAL;
		}
		x = execute(a);
		a = a->nnext;
		for (;;) {
			/* make sure we have at least 1 byte space */
			expand_buf(&buf, &bufsize, cnt + 1);
			len = bufsize - cnt;
			switch (flag) {
			case 1:
				/*LINTED*/
				ret = snprintf((char *)&buf[cnt], len,
				    (char *)fmt, getfval(x));
				break;
			case 2:
				/*LINTED*/
				ret = snprintf((char *)&buf[cnt], len,
				    (char *)fmt, (long)getfval(x));
				break;
			case 3:
				/*LINTED*/
				ret = snprintf((char *)&buf[cnt], len,
				    (char *)fmt, (int)getfval(x));
				break;
			case 4:
				/*LINTED*/
				ret = snprintf((char *)&buf[cnt], len,
				    (char *)fmt, getsval(x));
				break;
			case 5:
				if (isnum(x)) {
					/*LINTED*/
					ret = snprintf((char *)&buf[cnt], len,
					    (char *)fmt, (int)getfval(x));
				} else {
					/*LINTED*/
					ret = snprintf((char *)&buf[cnt], len,
					    (char *)fmt, getsval(x)[0]);
				}
				break;
			default:
				ret = 0;
			}
			if (ret < len)
				break;
			expand_buf(&buf, &bufsize, cnt + ret);
		}
		tempfree(x, "");
		cnt += ret;
		s++;
	}
	buf[cnt] = '\0';
	for (; a; a = a->nnext)	/* evaluate any remaining args */
		(void) execute(a);
	*bufp = tostring(buf);
	free(buf);
	free(fmt);
}

/*ARGSUSED*/
Cell *
a_sprintf(Node **a, int n)
{
	register Cell *x;
	register Node *y;
	uchar *buf;

	y = a[0]->nnext;
	x = execute(a[0]);
	format(&buf, getsval(x), y);
	tempfree(x, "");
	x = gettemp("");
	x->sval = buf;
	x->tval = STR;
	return (x);
}

/*ARGSUSED*/
Cell *
aprintf(Node **a, int n)
{
	FILE *fp;
	register Cell *x;
	register Node *y;
	uchar *buf;

	y = a[0]->nnext;
	x = execute(a[0]);
	format(&buf, getsval(x), y);
	tempfree(x, "");
	if (a[1] == NULL)
		(void) fputs((char *)buf, stdout);
	else {
		fp = redirect((int)a[1], a[2]);
		(void) fputs((char *)buf, fp);
		(void) fflush(fp);
	}
	free(buf);
	return (true);
}

Cell *
arith(Node **a, int n)
{
	Awkfloat i, j;
	double v;
	register Cell *x, *y, *z;

	x = execute(a[0]);
	i = getfval(x);
	tempfree(x, "");
	if (n != UMINUS) {
		y = execute(a[1]);
		j = getfval(y);
		tempfree(y, "");
	}
	z = gettemp("");
	switch (n) {
	case ADD:
		i += j;
		break;
	case MINUS:
		i -= j;
		break;
	case MULT:
		i *= j;
		break;
	case DIVIDE:
		if (j == 0)
			ERROR "division by zero" FATAL;
		i /= j;
		break;
	case MOD:
		if (j == 0)
			ERROR "division by zero in mod" FATAL;
		(void) modf(i/j, &v);
		i = i - j * v;
		break;
	case UMINUS:
		i = -i;
		break;
	case POWER:
		if (j >= 0 && modf(j, &v) == 0.0) /* pos integer exponent */
			i = ipow(i, (int)j);
		else
			i = errcheck(pow(i, j), "pow");
		break;
	default:	/* can't happen */
		ERROR "illegal arithmetic operator %d", n FATAL;
	}
	(void) setfval(z, i);
	return (z);
}

static double
ipow(double x, int n)
{
	double v;

	if (n <= 0)
		return (1.0);
	v = ipow(x, n/2);
	if (n % 2 == 0)
		return (v * v);
	else
		return (x * v * v);
}

Cell *
incrdecr(Node **a, int n)
{
	register Cell *x, *z;
	register int k;
	Awkfloat xf;

	x = execute(a[0]);
	xf = getfval(x);
	k = (n == PREINCR || n == POSTINCR) ? 1 : -1;
	if (n == PREINCR || n == PREDECR) {
		(void) setfval(x, xf + k);
		return (x);
	}
	z = gettemp("");
	(void) setfval(z, xf);
	(void) setfval(x, xf + k);
	tempfree(x, "");
	return (z);
}

Cell *
assign(Node **a, int n)
{
	register Cell *x, *y;
	Awkfloat xf, yf;
	double v;

	y = execute(a[1]);
	x = execute(a[0]);	/* order reversed from before... */
	if (n == ASSIGN) {	/* ordinary assignment */
		if ((y->tval & (STR|NUM)) == (STR|NUM)) {
			(void) setsval(x, getsval(y));
			x->fval = getfval(y);
			x->tval |= NUM;
		} else if (y->tval & STR)
			(void) setsval(x, getsval(y));
		else if (y->tval & NUM)
			(void) setfval(x, getfval(y));
		else
			funnyvar(y, "read value of");
		tempfree(y, "");
		return (x);
	}
	xf = getfval(x);
	yf = getfval(y);
	switch (n) {
	case ADDEQ:
		xf += yf;
		break;
	case SUBEQ:
		xf -= yf;
		break;
	case MULTEQ:
		xf *= yf;
		break;
	case DIVEQ:
		if (yf == 0)
			ERROR "division by zero in /=" FATAL;
		xf /= yf;
		break;
	case MODEQ:
		if (yf == 0)
			ERROR "division by zero in %%=" FATAL;
		(void) modf(xf/yf, &v);
		xf = xf - yf * v;
		break;
	case POWEQ:
		if (yf >= 0 && modf(yf, &v) == 0.0) /* pos integer exponent */
			xf = ipow(xf, (int)yf);
		else
			xf = errcheck(pow(xf, yf), "pow");
		break;
	default:
		ERROR "illegal assignment operator %d", n FATAL;
		break;
	}
	tempfree(y, "");
	(void) setfval(x, xf);
	return (x);
}

/*ARGSUSED*/
Cell *
cat(Node **a, int q)
{
	register Cell *x, *y, *z;
	register int n1, n2;
	register uchar *s;

	x = execute(a[0]);
	y = execute(a[1]);
	(void) getsval(x);
	(void) getsval(y);
	n1 = strlen((char *)x->sval);
	n2 = strlen((char *)y->sval);
	s = (uchar *)malloc(n1 + n2 + 1);
	if (s == NULL) {
		ERROR "out of space concatenating %.15s and %.15s",
		    x->sval, y->sval FATAL;
	}
	(void) strcpy((char *)s, (char *)x->sval);
	(void) strcpy((char *)s + n1, (char *)y->sval);
	tempfree(y, "");
	z = gettemp("");
	z->sval = s;
	z->tval = STR;
	tempfree(x, "");
	return (z);
}

/*ARGSUSED*/
Cell *
pastat(Node **a, int n)
{
	register Cell *x;

	if (a[0] == 0)
		x = execute(a[1]);
	else {
		x = execute(a[0]);
		if (istrue(x)) {
			tempfree(x, "");
			x = execute(a[1]);
		}
	}
	return (x);
}

/*ARGSUSED*/
Cell *
dopa2(Node **a, int n)
{
	Cell	*x;
	int	pair;
	static int	*pairstack = NULL;

	if (!pairstack) {
		/* first time */
		dprintf(("paircnt: %d\n", paircnt));
		pairstack = (int *)malloc(sizeof (int) * paircnt);
		if (!pairstack)
			ERROR "out of space in dopa2" FATAL;
		(void) memset(pairstack, 0, sizeof (int) * paircnt);
	}

	pair = (int)a[3];
	if (pairstack[pair] == 0) {
		x = execute(a[0]);
		if (istrue(x))
			pairstack[pair] = 1;
		tempfree(x, "");
	}
	if (pairstack[pair] == 1) {
		x = execute(a[1]);
		if (istrue(x))
			pairstack[pair] = 0;
		tempfree(x, "");
		x = execute(a[2]);
		return (x);
	}
	return (false);
}

/*ARGSUSED*/
Cell *
split(Node **a, int nnn)
{
	Cell *x, *y, *ap;
	register uchar *s;
	register int sep;
	uchar *t, temp, num[11], *fs;
	int n, tempstat;

	y = execute(a[0]);	/* source string */
	s = getsval(y);
	if (a[2] == 0)		/* fs string */
		fs = *FS;
	else if ((int)a[3] == STRING) {	/* split(str,arr,"string") */
		x = execute(a[2]);
		fs = getsval(x);
	} else if ((int)a[3] == REGEXPR)
		fs = (uchar *)"(regexpr)";	/* split(str,arr,/regexpr/) */
	else
		ERROR "illegal type of split()" FATAL;
	sep = *fs;
	ap = execute(a[1]);	/* array name */
	freesymtab(ap);
	dprintf(("split: s=|%s|, a=%s, sep=|%s|\n", s, ap->nval, fs));
	ap->tval &= ~STR;
	ap->tval |= ARR;
	ap->sval = (uchar *)makesymtab(NSYMTAB);

	n = 0;
	if (*s != '\0' && strlen((char *)fs) > 1 || (int)a[3] == REGEXPR) {
		/* reg expr */
		fa *pfa;
		if ((int)a[3] == REGEXPR) {	/* it's ready already */
			pfa = (fa *)a[2];
		} else {
			pfa = makedfa(fs, 1);
		}
		if (nematch(pfa, s)) {
			tempstat = pfa->initstat;
			pfa->initstat = 2;
			do {
				n++;
				(void) sprintf((char *)num, "%d", n);
				temp = *patbeg;
				*patbeg = '\0';
				if (is_number(s)) {
					(void) setsymtab(num, s,
					    atof((char *)s),
					    /*LINTED align*/
					    STR|NUM, (Array *)ap->sval);
				} else {
					(void) setsymtab(num, s, 0.0,
					    /*LINTED align*/
					    STR, (Array *)ap->sval);
				}
				*patbeg = temp;
				s = patbeg + patlen;
				if (*(patbeg+patlen-1) == 0 || *s == 0) {
					n++;
					(void) sprintf((char *)num, "%d", n);
					(void) setsymtab(num, (uchar *)"", 0.0,
					    /*LINTED align*/
					    STR, (Array *)ap->sval);
					pfa->initstat = tempstat;
					goto spdone;
				}
			} while (nematch(pfa, s));
		}
		n++;
		(void) sprintf((char *)num, "%d", n);
		if (is_number(s)) {
			(void) setsymtab(num, s, atof((char *)s),
			    /*LINTED align*/
			    STR|NUM, (Array *)ap->sval);
		} else {
			/*LINTED align*/
			(void) setsymtab(num, s, 0.0, STR, (Array *)ap->sval);
		}
spdone:
		pfa = NULL;
	} else if (sep == ' ') {
		for (n = 0; ; ) {
			while (*s == ' ' || *s == '\t' || *s == '\n')
				s++;
			if (*s == 0)
				break;
			n++;
			t = s;
			do
				s++;
			while (*s != ' ' && *s != '\t' &&
			    *s != '\n' && *s != '\0')
				;
			temp = *s;
			*s = '\0';
			(void) sprintf((char *)num, "%d", n);
			if (is_number(t)) {
				(void) setsymtab(num, t, atof((char *)t),
				    /*LINTED align*/
				    STR|NUM, (Array *)ap->sval);
			} else {
				(void) setsymtab(num, t, 0.0,
				    /*LINTED align*/
				    STR, (Array *)ap->sval);
			}
			*s = temp;
			if (*s != 0)
				s++;
		}
	} else if (*s != 0) {
		for (;;) {
			n++;
			t = s;
			while (*s != sep && *s != '\n' && *s != '\0')
				s++;
			temp = *s;
			*s = '\0';
			(void) sprintf((char *)num, "%d", n);
			if (is_number(t)) {
				(void) setsymtab(num, t, atof((char *)t),
				    /*LINTED align*/
				    STR|NUM, (Array *)ap->sval);
			} else {
				(void) setsymtab(num, t, 0.0,
				    /*LINTED align*/
				    STR, (Array *)ap->sval);
			}
			*s = temp;
			if (*s++ == 0)
				break;
		}
	}
	tempfree(ap, "");
	tempfree(y, "");
	if (a[2] != 0 && (int)a[3] == STRING)
		tempfree(x, "");
	x = gettemp("");
	x->tval = NUM;
	x->fval = n;
	return (x);
}

/*ARGSUSED*/
Cell *
condexpr(Node **a, int n)
{
	register Cell *x;

	x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x, "");
		x = execute(a[1]);
	} else {
		tempfree(x, "");
		x = execute(a[2]);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
ifstat(Node **a, int n)
{
	register Cell *x;

	x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x, "");
		x = execute(a[1]);
	} else if (a[2] != 0) {
		tempfree(x, "");
		x = execute(a[2]);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
whilestat(Node **a, int n)
{
	register Cell *x;

	for (;;) {
		x = execute(a[0]);
		if (!istrue(x))
			return (x);
		tempfree(x, "");
		x = execute(a[1]);
		if (isbreak(x)) {
			x = true;
			return (x);
		}
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x, "");
	}
}

/*ARGSUSED*/
Cell *
dostat(Node **a, int n)
{
	register Cell *x;

	for (;;) {
		x = execute(a[0]);
		if (isbreak(x))
			return (true);
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x, "");
		x = execute(a[1]);
		if (!istrue(x))
			return (x);
		tempfree(x, "");
	}
}

/*ARGSUSED*/
Cell *
forstat(Node **a, int n)
{
	register Cell *x;

	x = execute(a[0]);
	tempfree(x, "");
	for (;;) {
		if (a[1] != 0) {
			x = execute(a[1]);
			if (!istrue(x))
				return (x);
			else
				tempfree(x, "");
		}
		x = execute(a[3]);
		if (isbreak(x))		/* turn off break */
			return (true);
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x, "");
		x = execute(a[2]);
		tempfree(x, "");
	}
}

/*ARGSUSED*/
Cell *
instat(Node **a, int n)
{
	register Cell *x, *vp, *arrayp, *cp, *ncp;
	Array *tp;
	int i;

	vp = execute(a[0]);
	arrayp = execute(a[1]);
	if (!isarr(arrayp))
		ERROR "%s is not an array", arrayp->nval FATAL;
	/*LINTED align*/
	tp = (Array *)arrayp->sval;
	tempfree(arrayp, "");
	for (i = 0; i < tp->size; i++) { /* this routine knows too much */
		for (cp = tp->tab[i]; cp != NULL; cp = ncp) {
			(void) setsval(vp, cp->nval);
			ncp = cp->cnext;
			x = execute(a[2]);
			if (isbreak(x)) {
				tempfree(vp, "");
				return (true);
			}
			if (isnext(x) || isexit(x) || isret(x)) {
				tempfree(vp, "");
				return (x);
			}
			tempfree(x, "");
		}
	}
	return (true);
}

/*ARGSUSED*/
Cell *
bltin(Node **a, int n)
{
	register Cell *x, *y;
	Awkfloat u;
	register int t;
	uchar *p, *buf;
	Node *nextarg;

	t = (int)a[0];
	x = execute(a[1]);
	nextarg = a[1]->nnext;
	switch (t) {
	case FLENGTH:
		u = (Awkfloat)strlen((char *)getsval(x)); break;
	case FLOG:
		u = errcheck(log(getfval(x)), "log"); break;
	case FINT:
		(void) modf(getfval(x), &u); break;
	case FEXP:
		u = errcheck(exp(getfval(x)), "exp"); break;
	case FSQRT:
		u = errcheck(sqrt(getfval(x)), "sqrt"); break;
	case FSIN:
		u = sin(getfval(x)); break;
	case FCOS:
		u = cos(getfval(x)); break;
	case FATAN:
		if (nextarg == 0) {
			ERROR "atan2 requires two arguments; returning 1.0"
			    WARNING;
			u = 1.0;
		} else {
			y = execute(a[1]->nnext);
			u = atan2(getfval(x), getfval(y));
			tempfree(y, "");
			nextarg = nextarg->nnext;
		}
		break;
	case FSYSTEM:
		/* in case something is buffered already */
		(void) fflush(stdout);
		/* 256 is unix-dep */
		u = (Awkfloat)system((char *)getsval(x)) / 256;
		break;
	case FRAND:
		u = (Awkfloat)(rand() % 32767) / 32767.0;
		break;
	case FSRAND:
		if (x->tval & REC)	/* no argument provided */
			u = time((time_t *)0);
		else
			u = getfval(x);
		srand((int)u); u = (int)u;
		break;
	case FTOUPPER:
	case FTOLOWER:
		buf = tostring(getsval(x));
		if (t == FTOUPPER) {
			for (p = buf; *p; p++)
				if (islower(*p))
					*p = toupper(*p);
		} else {
			for (p = buf; *p; p++)
				if (isupper(*p))
					*p = tolower(*p);
		}
		tempfree(x, "");
		x = gettemp("");
		(void) setsval(x, buf);
		free(buf);
		return (x);
	default:	/* can't happen */
		ERROR "illegal function type %d", t FATAL;
		break;
	}
	tempfree(x, "");
	x = gettemp("");
	(void) setfval(x, u);
	if (nextarg != 0) {
		ERROR "warning: function has too many arguments" WARNING;
		for (; nextarg; nextarg = nextarg->nnext)
			(void) execute(nextarg);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
print(Node **a, int n)
{
	register Node *x;
	register Cell *y;
	FILE *fp;

	if (a[1] == 0)
		fp = stdout;
	else
		fp = redirect((int)a[1], a[2]);
	for (x = a[0]; x != NULL; x = x->nnext) {
		y = execute(x);
		(void) fputs((char *)getsval(y), fp);
		tempfree(y, "");
		if (x->nnext == NULL)
			(void) fputs((char *)*ORS, fp);
		else
			(void) fputs((char *)*OFS, fp);
	}
	if (a[1] != 0)
		(void) fflush(fp);
	return (true);
}

/*ARGSUSED*/
Cell *
nullproc(Node **a, int n)
{
	return (0);
}

struct {
	FILE	*fp;
	uchar	*fname;
	int	mode;	/* '|', 'a', 'w' */
} files[FOPEN_MAX];

static FILE *
redirect(int a, Node *b)
{
	FILE *fp;
	Cell *x;
	uchar *fname;

	x = execute(b);
	fname = getsval(x);
	fp = openfile(a, fname);
	if (fp == NULL)
		ERROR "can't open file %s", fname FATAL;
	tempfree(x, "");
	return (fp);
}

static FILE *
openfile(int a, uchar *s)
{
	register int i, m;
	register FILE *fp;

	if (*s == '\0')
		ERROR "null file name in print or getline" FATAL;
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fname &&
		    strcmp((char *)s, (char *)files[i].fname) == 0) {
			if (a == files[i].mode ||
			    a == APPEND && files[i].mode == GT) {
				return (files[i].fp);
			}
		}
	}
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fp == 0)
			break;
	}
	if (i >= FOPEN_MAX)
		ERROR "%s makes too many open files", s FATAL;
	(void) fflush(stdout);	/* force a semblance of order */
	m = a;
	if (a == GT) {
		fp = fopen((char *)s, "w");
	} else if (a == APPEND) {
		fp = fopen((char *)s, "a");
		m = GT;	/* so can mix > and >> */
	} else if (a == '|') {	/* output pipe */
		fp = popen((char *)s, "w");
	} else if (a == LE) {	/* input pipe */
		fp = popen((char *)s, "r");
	} else if (a == LT) {	/* getline <file */
		fp = strcmp((char *)s, "-") == 0 ?
		    stdin : fopen((char *)s, "r");	/* "-" is stdin */
	} else	/* can't happen */
		ERROR "illegal redirection" FATAL;
	if (fp != NULL) {
		files[i].fname = tostring(s);
		files[i].fp = fp;
		files[i].mode = m;
	}
	return (fp);
}

/*ARGSUSED*/
Cell *
closefile(Node **a, int n)
{
	register Cell *x;
	int i, stat;

	x = execute(a[0]);
	(void) getsval(x);
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fname &&
		    strcmp((char *)x->sval, (char *)files[i].fname) == 0) {
			if (ferror(files[i].fp)) {
				ERROR "i/o error occurred on %s",
				    files[i].fname WARNING;
			}
			if (files[i].mode == '|' || files[i].mode == LE)
				stat = pclose(files[i].fp);
			else
				stat = fclose(files[i].fp);
			if (stat == EOF) {
				ERROR "i/o error occurred closing %s",
				    files[i].fname WARNING;
			}
			xfree(files[i].fname);
			/* watch out for ref thru this */
			files[i].fname = NULL;
			files[i].fp = NULL;
		}
	}
	tempfree(x, "close");
	return (true);
}

static void
closeall(void)
{
	int i, stat;

	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fp) {
			if (ferror(files[i].fp)) {
				ERROR "i/o error occurred on %s",
				    files[i].fname WARNING;
			}
			if (files[i].mode == '|' || files[i].mode == LE)
				stat = pclose(files[i].fp);
			else
				stat = fclose(files[i].fp);
			if (stat == EOF) {
				ERROR "i/o error occurred while closing %s",
				    files[i].fname WARNING;
			}
		}
	}
}

/*ARGSUSED*/
Cell *
sub(Node **a, int nnn)
{
	register uchar *sptr;
	register Cell *x, *y, *result;
	uchar *buf, *t;
	fa *pfa;
	size_t	bsize, cnt, len;

	x = execute(a[3]);	/* target string */
	t = getsval(x);
	if (a[0] == 0)
		pfa = (fa *)a[1];	/* regular expression */
	else {
		y = execute(a[1]);
		pfa = makedfa(getsval(y), 1);
		tempfree(y, "");
	}
	y = execute(a[2]);	/* replacement string */
	result = false;
	if (pmatch(pfa, t)) {
		init_buf(&buf, &bsize, LINE_INCR);
		cnt = 0;
		sptr = t;
		len = patbeg - sptr;
		if (len > 0) {
			expand_buf(&buf, &bsize, cnt + len);
			(void) memcpy(buf, sptr, len);
			cnt += len;
		}
		sptr = getsval(y);
		while (*sptr != 0) {
			expand_buf(&buf, &bsize, cnt);
			if (*sptr == '\\' &&
			    (*(sptr+1) == '&' || *(sptr+1) == '\\')) {
				sptr++;		/* skip \, */
				buf[cnt++] = *sptr++; /* add & or \ */
			} else if (*sptr == '&') {
				expand_buf(&buf, &bsize, cnt + patlen);
				sptr++;
				(void) memcpy(&buf[cnt], patbeg, patlen);
				cnt += patlen;
			} else {
				buf[cnt++] = *sptr++;
			}
		}
		sptr = patbeg + patlen;
		if ((patlen == 0 && *patbeg) || (patlen && *(sptr-1))) {
			len = strlen((char *)sptr);
			expand_buf(&buf, &bsize, cnt + len);
			(void) memcpy(&buf[cnt], sptr, len);
			cnt += len;
		}
		buf[cnt] = '\0';
		(void) setsval(x, buf);
		free(buf);
		result = true;
	}
	tempfree(x, "");
	tempfree(y, "");
	return (result);
}

/*ARGSUSED*/
Cell *
gsub(Node **a, int nnn)
{
	register Cell *x, *y;
	register uchar *rptr, *sptr, *t;
	uchar *buf;
	register fa *pfa;
	int mflag, tempstat, num;
	size_t	bsize, cnt, len;

	mflag = 0;	/* if mflag == 0, can replace empty string */
	num = 0;
	x = execute(a[3]);	/* target string */
	t = getsval(x);
	if (a[0] == 0)
		pfa = (fa *) a[1];	/* regular expression */
	else {
		y = execute(a[1]);
		pfa = makedfa(getsval(y), 1);
		tempfree(y, "");
	}
	y = execute(a[2]);	/* replacement string */
	if (pmatch(pfa, t)) {
		tempstat = pfa->initstat;
		pfa->initstat = 2;
		init_buf(&buf, &bsize, LINE_INCR);
		rptr = getsval(y);
		cnt = 0;
		do {
			if (patlen == 0 && *patbeg != 0) {
				/* matched empty string */
				if (mflag == 0) {	/* can replace empty */
					num++;
					sptr = rptr;
					while (*sptr != 0) {
						expand_buf(&buf, &bsize, cnt);
						if (*sptr == '\\' &&
						    (*(sptr+1) == '&' ||
						    *(sptr+1) == '\\')) {
							sptr++;
							buf[cnt++] = *sptr++;
						} else if (*sptr == '&') {
							expand_buf(&buf,
							    &bsize,
							    cnt + patlen);
							sptr++;
							(void) memcpy(&buf[cnt],
							    patbeg, patlen);
							cnt += patlen;
						} else {
							buf[cnt++] = *sptr++;
						}
					}
				}
				if (*t == 0)	/* at end */
					goto done;
				expand_buf(&buf, &bsize, cnt);
				buf[cnt++] = *t++;
				mflag = 0;
			} else {	/* matched nonempty string */
				num++;
				sptr = t;
				len = patbeg - sptr;
				if (len > 0) {
					expand_buf(&buf, &bsize, cnt + len);
					(void) memcpy(&buf[cnt], sptr, len);
					cnt += len;
				}
				sptr = rptr;
				while (*sptr != 0) {
					expand_buf(&buf, &bsize, cnt);
					if (*sptr == '\\' &&
					    (*(sptr+1) == '&' ||
					    *(sptr+1) == '\\')) {
						sptr++;
						buf[cnt++] = *sptr++;
					} else if (*sptr == '&') {
						expand_buf(&buf, &bsize,
						    cnt + patlen);
						sptr++;
						(void) memcpy(&buf[cnt],
						    patbeg, patlen);
						cnt += patlen;
					} else {
						buf[cnt++] = *sptr++;
					}
				}
				t = patbeg + patlen;
				if ((*(t-1) == 0) || (*t == 0))
					goto done;
				mflag = 1;
			}
		} while (pmatch(pfa, t));
		sptr = t;
		len = strlen((char *)sptr);
		expand_buf(&buf, &bsize, len + cnt);
		(void) memcpy(&buf[cnt], sptr, len);
		cnt += len;
	done:
		buf[cnt] = '\0';
		(void) setsval(x, buf);
		free(buf);
		pfa->initstat = tempstat;
	}
	tempfree(x, "");
	tempfree(y, "");
	x = gettemp("");
	x->tval = NUM;
	x->fval = num;
	return (x);
}

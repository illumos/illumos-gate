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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#define	DEBUG
#include	<stdio.h>
#include	<ctype.h>
#include	<setjmp.h>
#include	<math.h>
#include	<time.h>
#include	"awk.h"
#include	"y.tab.h"

#define	tempfree(x)	if (istemp(x)) tfree(x)

#ifndef	FOPEN_MAX
#define	FOPEN_MAX	15	/* max number of open files, from ANSI std. */
#endif


static jmp_buf env;

static	Cell	*execute(Node *);
static	Cell	*gettemp(void), *copycell(Cell *);
static	FILE	*openfile(int, const char *), *redirect(int, Node *);

Node	*winner = NULL;		/* root of parse tree */

static Cell	*tmps;		/* free temporary cells for execution */

static Cell	truecell	= { OBOOL, BTRUE, 0, 0, 1.0, NUM };
Cell	*True	= &truecell;
static Cell	falsecell	= { OBOOL, BFALSE, 0, 0, 0.0, NUM };
Cell	*False	= &falsecell;
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

static	void	tfree(Cell *);
static	void	closeall(void);
static	double	ipow(double, int);

/*
 * buffer memory management
 *
 * pbuf:    address of pointer to buffer being managed
 * psiz:    address of buffer size variable
 * minlen:  minimum length of buffer needed
 * quantum: buffer size quantum
 * pbptr:   address of movable pointer into buffer, or 0 if none
 * whatrtn: name of the calling routine if failure should cause fatal error
 *
 * return   0 for realloc failure, !=0 for success
 */
int
adjbuf(char **pbuf, size_t *psiz, size_t minlen, size_t quantum, char **pbptr,
    const char *whatrtn)
{
	if (minlen > *psiz) {
		char *tbuf;
		int rminlen = quantum ? minlen % quantum : 0;
		int boff = pbptr ? *pbptr - *pbuf : 0;
		/* round up to next multiple of quantum */
		if (rminlen)
			minlen += quantum - rminlen;
		tbuf = (char *)realloc(*pbuf, minlen);
		dprintf(("adjbuf %s: %d %d (pbuf=%p, tbuf=%p)\n", whatrtn,
		    *psiz, minlen, (void *)*pbuf, (void *)tbuf));
		if (tbuf == NULL) {
			if (whatrtn)
				FATAL("out of memory in %s", whatrtn);
			return (0);
		}
		*pbuf = tbuf;
		*psiz = minlen;
		if (pbptr)
			*pbptr = tbuf + boff;
	}
	return (1);
}

void
run(Node *a)	/* execution of parse tree starts here */
{
	(void) execute(a);
	closeall();
}

static Cell *
execute(Node *u)	/* execute a node of the parse tree */
{
	Cell *(*proc)(Node **, int);
	Cell *x;
	Node *a;

	if (u == NULL)
		return (True);
	for (a = u; ; a = a->nnext) {
		curnode = a;
		if (isvalue(a)) {
			x = (Cell *) (a->narg[0]);
			if (isfld(x) && !donefld)
				fldbld();
			else if (isrec(x) && !donerec)
				recbld();
			return (x);
		}
		/* probably a Cell* but too risky to print */
		if (notlegal(a->nobj))
			FATAL("illegal statement");
		proc = proctab[a->nobj-FIRSTTOKEN];
		x = (*proc)(a->narg, a->nobj);
		if (isfld(x) && !donefld)
			fldbld();
		else if (isrec(x) && !donerec)
			recbld();
		if (isexpr(a))
			return (x);
		/* a statement, goto next statement */
		if (isjump(x))
			return (x);
		if (a->nnext == NULL)
			return (x);
		tempfree(x);
	}
}

/* execute an awk program */
/* a[0] = BEGIN, a[1] = body, a[2] = END */
/*ARGSUSED*/
Cell *
program(Node **a, int n)
{
	Cell *x;

	if (setjmp(env) != 0)
		goto ex;
	if (a[0]) {		/* BEGIN */
		x = execute(a[0]);
		if (isexit(x))
			return (True);
		if (isjump(x)) {
			FATAL("illegal break, continue, or next from BEGIN");
		}
		tempfree(x);
	}
loop:
	if (a[1] || a[2])
		while (getrec(&record, &recsize) > 0) {
			x = execute(a[1]);
			if (isexit(x))
				break;
			tempfree(x);
		}
ex:
	if (setjmp(env) != 0)	/* handles exit within END */
		goto ex1;
	if (a[2]) {		/* END */
		x = execute(a[2]);
		if (iscont(x))	/* read some more */
			goto loop;
		if (isbreak(x) || isnext(x))
			FATAL("illegal break or next from END");
		tempfree(x);
	}
ex1:
	return (True);
}

struct Frame {	/* stack frame for awk function calls */
	int nargs;	/* number of arguments in this call */
	Cell *fcncell;	/* pointer to Cell for function */
	Cell **args;	/* pointer to array of arguments after execute */
	Cell *retval;	/* return value */
};

#define	NARGS	30	/* max args in a call */

struct Frame *frame = NULL;	/* base of stack frames; dynamically alloc'd */
int	nframe = 0;		/* number of frames allocated */
struct Frame *fp = NULL;	/* frame pointer. bottom level unused */

/*ARGSUSED*/
Cell *
call(Node **a, int n)	/* function call.  very kludgy and fragile */
{
	static Cell newcopycell =
		{ OCELL, CCOPY, 0, "", 0.0, NUM|STR|DONTFREE };
	int i, ncall, ndef;
	/* handles potential double freeing when fcn & param share a tempcell */
	int freed = 0;
	Node *x;
	Cell *args[NARGS], *oargs[NARGS];	/* BUG: fixed size arrays */
	Cell *y, *z, *fcn;
	char *s;

	fcn = execute(a[0]);	/* the function itself */
	s = fcn->nval;
	if (!isfcn(fcn))
		FATAL("calling undefined function %s", s);
	if (frame == NULL) {
		fp = frame = (struct Frame *)calloc(nframe += 100,
		    sizeof (struct Frame));
		if (frame == NULL) {
			FATAL("out of space for stack frames calling %s", s);
		}
	}
	for (ncall = 0, x = a[1]; x != NULL; x = x->nnext) /* args in call */
		ncall++;
	ndef = (int)fcn->fval;			/* args in defn */
	dprintf(("calling %s, %d args (%d in defn), fp=%d\n",
	    s, ncall, ndef, fp-frame));
	if (ncall > ndef) {
		WARNING("function %s called with %d args, uses only %d",
		    s, ncall, ndef);
	}
	if (ncall + ndef > NARGS) {
		FATAL("function %s has %d arguments, limit %d",
		    s, ncall+ndef, NARGS);
	}
	for (i = 0, x = a[1]; x != NULL; i++, x = x->nnext) {
		/* get call args */
		dprintf(("evaluate args[%d], fp=%d:\n", i, fp-frame));
		y = execute(x);
		oargs[i] = y;
		dprintf(("args[%d]: %s %f <%s>, t=%o\n",
		    i, NN(y->nval), y->fval,
		    isarr(y) ? "(array)" : NN(y->sval), y->tval));
		if (isfcn(y)) {
			FATAL("can't use function %s as argument in %s",
			    y->nval, s);
		}
		if (isarr(y))
			args[i] = y;	/* arrays by ref */
		else
			args[i] = copycell(y);
		tempfree(y);
	}
	for (; i < ndef; i++) {	/* add null args for ones not provided */
		args[i] = gettemp();
		*args[i] = newcopycell;
	}
	fp++;	/* now ok to up frame */
	if (fp >= frame + nframe) {
		int dfp = fp - frame;	/* old index */
		frame = (struct Frame *)
		    realloc(frame, (nframe += 100) * sizeof (struct Frame));
		if (frame == NULL)
			FATAL("out of space for stack frames in %s", s);
		fp = frame + dfp;
	}
	fp->fcncell = fcn;
	fp->args = args;
	fp->nargs = ndef;	/* number defined with (excess are locals) */
	fp->retval = gettemp();

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
					tempfree(t);
				}
			}
		} else {
			t->csub = CTEMP;
			tempfree(t);
			if (t == y) freed = 1;
		}
	}
	tempfree(fcn);
	if (isexit(y) || isnext(y))
		return (y);
	if (freed == 0) {
		tempfree(y);	/* don't free twice! */
	}
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

	y = gettemp();
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
arg(Node **a, int nnn)	/* nth argument of a function */
{
	int n;

	n = ptoi(a[0]);	/* argument number, counting from 0 */
	dprintf(("arg(%d), fp->nargs=%d\n", n, fp->nargs));
	if (n+1 > fp->nargs) {
		FATAL("argument #%d of function %s was not supplied",
		    n+1, fp->fcncell->nval);
	}
	return (fp->args[n]);
}

Cell *
jump(Node **a, int n)	/* break, continue, next, nextfile, return */
{
	Cell *y;

	switch (n) {
	case EXIT:
		if (a[0] != NULL) {
			y = execute(a[0]);
			errorflag = (int)getfval(y);
			tempfree(y);
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
			else		/* can't happen */
				FATAL("bad type variable %d", y->tval);
			tempfree(y);
		}
		return (jret);
	case NEXT:
		return (jnext);
	case BREAK:
		return (jbreak);
	case CONTINUE:
		return (jcont);
	default:	/* can't happen */
		FATAL("illegal jump type %d", n);
	}
	/*NOTREACHED*/
	return (NULL);
}

Cell *
awkgetline(Node **a, int n)	/* get next line from specific input */
{
	/* a[0] is variable, a[1] is operator, a[2] is filename */
	Cell *r, *x;
	char *buf;
	FILE *fp;
	size_t len;
	int mode;

	(void) fflush(stdout);	/* in case someone is waiting for a prompt */
	r = gettemp();
	if (a[1] != NULL) {		/* getline < file */
		x = execute(a[2]);		/* filename */
		mode = ptoi(a[1]);
		if (mode == '|')	/* input pipe */
			mode = LE;	/* arbitrary flag */
		fp = openfile(mode, getsval(x));
		tempfree(x);
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
				expand_buf(&record, &recsize, len);
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
			n = getrec(&record, &recsize);
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
getnf(Node **a, int n)	/* get NF */
{
	if (donefld == 0)
		fldbld();
	return ((Cell *)a[0]);
}

/*ARGSUSED*/
Cell *
array(Node **a, int n)	/* a[0] is symtab, a[1] is list of subscripts */
{
	Cell *x, *y, *z;
	char *s;
	Node *np;
	char *buf;
	size_t	bsize, tlen, len, slen;

	x = execute(a[0]);	/* Cell* for symbol table */
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = '\0';
	tlen = 0;
	slen = strlen(*SUBSEP);
	for (np = a[1]; np != NULL; np = np->nnext) {
		y = execute(np);	/* subscript */
		s = getsval(y);
		len = strlen(s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		if (np->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
		tempfree(y);
	}
	if (!isarr(x)) {
		dprintf(("making %s into an array\n", NN(x->nval)));
		if (freeable(x))
			xfree(x->sval);
		x->tval &= ~(STR|NUM|DONTFREE);
		x->tval |= ARR;
		x->sval = (char *)makesymtab(NSYMTAB);
	}
	/*LINTED align*/
	z = setsymtab(buf, "", 0.0, STR|NUM, (Array *)x->sval);
	z->ctype = OCELL;
	z->csub = CVAR;
	tempfree(x);
	free(buf);
	return (z);
}

/*ARGSUSED*/
Cell *
awkdelete(Node **a, int n)	/* a[0] is symtab, a[1] is list of subscripts */
{
	Cell *x, *y;
	Node *np;
	char *buf, *s;
	size_t bsize, tlen, slen, len;

	x = execute(a[0]);	/* Cell* for symbol table */
	if (!isarr(x))
		return (True);
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = '\0';
	tlen = 0;
	slen = strlen(*SUBSEP);
	for (np = a[1]; np != NULL; np = np->nnext) {
		y = execute(np);	/* subscript */
		s = getsval(y);
		len = strlen(s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		if (np->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
		tempfree(y);
	}
	freeelem(x, buf);
	tempfree(x);
	free(buf);
	return (True);
}

/*ARGSUSED*/
Cell *
intest(Node **a, int n)	/* a[0] is index (list), a[1] is symtab */
{
	Cell *x, *ap, *k;
	Node *p;
	char *buf;
	char *s;
	size_t bsize, tlen, slen, len;

	ap = execute(a[1]);	/* array name */
	if (!isarr(ap))
		FATAL("%s is not an array", ap->nval);
	init_buf(&buf, &bsize, LINE_INCR);
	buf[0] = '\0';
	tlen = 0;
	slen = strlen(*SUBSEP);
	for (p = a[0]; p != NULL; p = p->nnext) {
		x = execute(p);	/* expr */
		s = getsval(x);
		len = strlen(s);
		expand_buf(&buf, &bsize, tlen + len + slen);
		(void) memcpy(&buf[tlen], s, len);
		tlen += len;
		tempfree(x);
		if (p->nnext) {
			(void) memcpy(&buf[tlen], *SUBSEP, slen);
			tlen += slen;
		}
		buf[tlen] = '\0';
	}
	/*LINTED align*/
	k = lookup(buf, (Array *)ap->sval);
	tempfree(ap);
	free(buf);
	if (k == NULL)
		return (False);
	else
		return (True);
}


Cell *
matchop(Node **a, int n)	/* ~ and match() */
{
	Cell *x, *y;
	char *s, *t;
	int i;
	fa *pfa;
	int (*mf)(fa *, const char *) = match, mode = 0;

	if (n == MATCHFCN) {
		mf = pmatch;
		mode = 1;
	}
	x = execute(a[1]);	/* a[1] = target text */
	s = getsval(x);
	if (a[0] == NULL)	/* a[1] == 0: already-compiled reg expr */
		i = (*mf)((fa *)a[2], s);
	else {
		y = execute(a[2]);	/* a[2] = regular expr */
		t = getsval(y);
		pfa = makedfa(t, mode);
		i = (*mf)(pfa, s);
		tempfree(y);
	}
	tempfree(x);
	if (n == MATCHFCN) {
		int start = patbeg - s + 1;
		if (patlen < 0)
			start = 0;
		(void) setfval(rstartloc, (Awkfloat)start);
		(void) setfval(rlengthloc, (Awkfloat)patlen);
		x = gettemp();
		x->tval = NUM;
		x->fval = start;
		return (x);
	} else if ((n == MATCH && i == 1) || (n == NOTMATCH && i == 0))
		return (True);
	else
		return (False);
}


Cell *
boolop(Node **a, int n)	/* a[0] || a[1], a[0] && a[1], !a[0] */
{
	Cell *x, *y;
	int i;

	x = execute(a[0]);
	i = istrue(x);
	tempfree(x);
	switch (n) {
	case BOR:
		if (i)
			return (True);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y);
		return (i ? True : False);
	case AND:
		if (!i)
			return (False);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y);
		return (i ? True : False);
	case NOT:
		return (i ? False : True);
	default:	/* can't happen */
		FATAL("unknown boolean operator %d", n);
	}
	/*NOTREACHED*/
	return (NULL);
}

Cell *
relop(Node **a, int n)	/* a[0] < a[1], etc. */
{
	int i;
	Cell *x, *y;
	Awkfloat j;

	x = execute(a[0]);
	y = execute(a[1]);
	if (x->tval&NUM && y->tval&NUM) {
		j = x->fval - y->fval;
		i = j < 0 ? -1: (j > 0 ? 1: 0);
	} else {
		i = strcmp(getsval(x), getsval(y));
	}
	tempfree(x);
	tempfree(y);
	switch (n) {
	case LT:	return (i < 0 ? True : False);
	case LE:	return (i <= 0 ? True : False);
	case NE:	return (i != 0 ? True : False);
	case EQ:	return (i == 0 ? True : False);
	case GE:	return (i >= 0 ? True : False);
	case GT:	return (i > 0 ? True : False);
	default:	/* can't happen */
		FATAL("unknown relational operator %d", n);
	}
	/*NOTREACHED*/
	return (False);
}

static void
tfree(Cell *a)	/* free a tempcell */
{
	if (freeable(a)) {
		dprintf(("freeing %s %s %o\n",
		    NN(a->nval), NN(a->sval), a->tval));
		xfree(a->sval);
	}
	if (a == tmps)
		FATAL("tempcell list is curdled");
	a->cnext = tmps;
	tmps = a;
}

static Cell *
gettemp(void)	/* get a tempcell */
{
	int i;
	Cell *x;

	if (!tmps) {
		tmps = (Cell *)calloc(100, sizeof (Cell));
		if (!tmps)
			FATAL("out of space for temporaries");
		for (i = 1; i < 100; i++)
			tmps[i-1].cnext = &tmps[i];
		tmps[i-1].cnext = NULL;
	}
	x = tmps;
	tmps = x->cnext;
	*x = tempcell;
	dprintf(("gtemp %.8s %06lo\n", NN(x->nval), (ulong_t)x));
	return (x);
}

/*ARGSUSED*/
Cell *
indirect(Node **a, int n)	/* $( a[0] ) */
{
	Cell *x;
	int m;
	char *s;

	x = execute(a[0]);
	m = (int)getfval(x);
	if (m == 0 && !is_number(s = getsval(x)))	/* suspicion! */
		FATAL("illegal field $(%s)", s);
	tempfree(x);
	x = fieldadr(m);
	x->ctype = OCELL;	/* BUG?  why are these needed? */
	x->csub = CFLD;
	return (x);
}

/*ARGSUSED*/
Cell *
substr(Node **a, int nnn)		/* substr(a[0], a[1], a[2]) */
{
	int k, m, n;
	char *s;
	int temp;
	Cell *x, *y, *z = NULL;

	x = execute(a[0]);
	y = execute(a[1]);
	if (a[2] != NULL)
		z = execute(a[2]);
	s = getsval(x);
	k = strlen(s) + 1;
	if (k <= 1) {
		tempfree(x);
		tempfree(y);
		if (a[2] != NULL) {
			tempfree(z);
		}
		x = gettemp();
		(void) setsval(x, "");
		return (x);
	}
	m = (int)getfval(y);
	if (m <= 0)
		m = 1;
	else if (m > k)
		m = k;
	tempfree(y);
	if (a[2] != NULL) {
		n = (int)getfval(z);
		tempfree(z);
	} else
		n = k - 1;
	if (n < 0)
		n = 0;
	else if (n > k - m)
		n = k - m;
	dprintf(("substr: m=%d, n=%d, s=%s\n", m, n, s));
	y = gettemp();
	temp = s[n + m - 1];	/* with thanks to John Linderman */
	s[n + m - 1] = '\0';
	(void) setsval(y, s + m - 1);
	s[n + m - 1] = temp;
	tempfree(x);
	return (y);
}

/*ARGSUSED*/
Cell *
sindex(Node **a, int nnn)		/* index(a[0], a[1]) */
{
	Cell *x, *y, *z;
	char *s1, *s2, *p1, *p2, *q;
	Awkfloat v = 0.0;

	x = execute(a[0]);
	s1 = getsval(x);
	y = execute(a[1]);
	s2 = getsval(y);

	z = gettemp();
	for (p1 = s1; *p1 != '\0'; p1++) {
		for (q = p1, p2 = s2; *p2 != '\0' && *q == *p2; q++, p2++)
			;
		if (*p2 == '\0') {
			v = (Awkfloat) (p1 - s1 + 1);	/* origin 1 */
			break;
		}
	}
	tempfree(x);
	tempfree(y);
	(void) setfval(z, v);
	return (z);
}

void
format(char **bufp, char *s, Node *a)
{
	char *fmt;
	const char *os;
	Cell *x;
	int flag = 0, len;
	char *buf;
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
			if (isalpha((uschar)*s) &&
			    *s != 'l' && *s != 'h' && *s != 'L')
				break;	/* the ansi panoply */
			if (*s == '*') {
				if (a == NULL) {
					FATAL("not enough args in printf(%s) "
					    "or sprintf(%s)", os, os);
				}
				x = execute(a);
				a = a->nnext;
				tcnt--;
				expand_buf(&fmt, &fmtsize, tcnt + 12);
				ret = sprintf(&fmt[tcnt], "%d",
				    (int)getfval(x));
				tcnt += ret;
				tempfree(x);
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
			len = strlen(fmt);
			expand_buf(&buf, &bufsize, cnt + len);
			(void) memcpy(&buf[cnt], fmt, len);
			cnt += len;
			buf[cnt] = '\0';
			continue;
		}
		if (a == NULL) {
			FATAL("not enough args in printf(%s) "
			    "or sprintf(%s)", os, os);
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
				ret = snprintf(&buf[cnt], len,
				    fmt, getfval(x));
				break;
			case 2:
				/*LINTED*/
				ret = snprintf(&buf[cnt], len,
				    fmt, (long)getfval(x));
				break;
			case 3:
				/*LINTED*/
				ret = snprintf(&buf[cnt], len,
				    fmt, (int)getfval(x));
				break;
			case 4:
				/*LINTED*/
				ret = snprintf(&buf[cnt], len,
				    fmt, getsval(x));
				break;
			case 5:
				if (isnum(x)) {
					/*LINTED*/
					ret = snprintf(&buf[cnt], len,
					    fmt, (int)getfval(x));
				} else {
					/*LINTED*/
					ret = snprintf(&buf[cnt], len,
					    fmt, getsval(x)[0]);
				}
				break;
			default:
				ret = 0;
			}
			if (ret < len)
				break;
			expand_buf(&buf, &bufsize, cnt + ret);
		}
		tempfree(x);
		cnt += ret;
		s++;
	}
	buf[cnt] = '\0';
	for (; a != NULL; a = a->nnext)	/* evaluate any remaining args */
		(void) execute(a);
	*bufp = tostring(buf);
	free(buf);
	free(fmt);
}

/*ARGSUSED*/
Cell *
awksprintf(Node **a, int n)		/* sprintf(a[0]) */
{
	Cell *x;
	Node *y;
	char *buf;

	y = a[0]->nnext;
	x = execute(a[0]);
	format(&buf, getsval(x), y);
	tempfree(x);
	x = gettemp();
	x->sval = buf;
	x->tval = STR;
	return (x);
}

/*ARGSUSED*/
Cell *
awkprintf(Node **a, int n)		/* printf */
{
	/* a[0] is list of args, starting with format string */
	/* a[1] is redirection operator, a[2] is redirection file */
	FILE *fp;
	Cell *x;
	Node *y;
	char *buf;

	y = a[0]->nnext;
	x = execute(a[0]);
	format(&buf, getsval(x), y);
	tempfree(x);
	if (a[1] == NULL) {
		(void) fputs(buf, stdout);
	} else {
		fp = redirect(ptoi(a[1]), a[2]);
		(void) fputs(buf, fp);
		(void) fflush(fp);
	}
	free(buf);
	return (True);
}

Cell *
arith(Node **a, int n)	/* a[0] + a[1], etc.  also -a[0] */
{
	Awkfloat i, j = 0;
	double v;
	Cell *x, *y, *z;

	x = execute(a[0]);
	i = getfval(x);
	tempfree(x);
	if (n != UMINUS) {
		y = execute(a[1]);
		j = getfval(y);
		tempfree(y);
	}
	z = gettemp();
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
			FATAL("division by zero");
		i /= j;
		break;
	case MOD:
		if (j == 0)
			FATAL("division by zero in mod");
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
		FATAL("illegal arithmetic operator %d", n);
	}
	(void) setfval(z, i);
	return (z);
}

static double
ipow(double x, int n)	/* x**n.  ought to be done by pow, but isn't always */
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
incrdecr(Node **a, int n)		/* a[0]++, etc. */
{
	Cell *x, *z;
	int k;
	Awkfloat xf;

	x = execute(a[0]);
	xf = getfval(x);
	k = (n == PREINCR || n == POSTINCR) ? 1 : -1;
	if (n == PREINCR || n == PREDECR) {
		(void) setfval(x, xf + k);
		return (x);
	}
	z = gettemp();
	(void) setfval(z, xf);
	(void) setfval(x, xf + k);
	tempfree(x);
	return (z);
}

/* a[0] = a[1], a[0] += a[1], etc. */
/* this is subtle; don't muck with it. */
Cell *
assign(Node **a, int n)
{
	Cell *x, *y;
	Awkfloat xf, yf;
	double v;

	y = execute(a[1]);
	x = execute(a[0]);	/* order reversed from before... */
	if (n == ASSIGN) {	/* ordinary assignment */
		if ((y->tval & (STR|NUM)) == (STR|NUM)) {
			(void) setsval(x, getsval(y));
			x->fval = getfval(y);
			x->tval |= NUM;
		} else if (isstr(y))
			(void) setsval(x, getsval(y));
		else if (isnum(y))
			(void) setfval(x, getfval(y));
		else
			funnyvar(y, "read value of");
		tempfree(y);
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
			FATAL("division by zero in /=");
		xf /= yf;
		break;
	case MODEQ:
		if (yf == 0)
			FATAL("division by zero in %%=");
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
		FATAL("illegal assignment operator %d", n);
		break;
	}
	tempfree(y);
	(void) setfval(x, xf);
	return (x);
}

/*ARGSUSED*/
Cell *
cat(Node **a, int q)	/* a[0] cat a[1] */
{
	Cell *x, *y, *z;
	int n1, n2;
	char *s;

	x = execute(a[0]);
	y = execute(a[1]);
	(void) getsval(x);
	(void) getsval(y);
	n1 = strlen(x->sval);
	n2 = strlen(y->sval);
	s = (char *)malloc(n1 + n2 + 1);
	if (s == NULL) {
		FATAL("out of space concatenating %.15s... and %.15s...",
		    x->sval, y->sval);
	}
	(void) strcpy(s, x->sval);
	(void) strcpy(s + n1, y->sval);
	tempfree(x);
	tempfree(y);
	z = gettemp();
	z->sval = s;
	z->tval = STR;
	return (z);
}

/*ARGSUSED*/
Cell *
pastat(Node **a, int n)	/* a[0] { a[1] } */
{
	Cell *x;

	if (a[0] == NULL)
		x = execute(a[1]);
	else {
		x = execute(a[0]);
		if (istrue(x)) {
			tempfree(x);
			x = execute(a[1]);
		}
	}
	return (x);
}

/*ARGSUSED*/
Cell *
dopa2(Node **a, int n)	/* a[0], a[1] { a[2] } */
{
	Cell	*x;
	int	pair;

	if (!pairstack) {
		/* first time */
		dprintf(("paircnt: %d\n", paircnt));
		pairstack = (int *)calloc(paircnt, sizeof (int));
		if (pairstack == NULL)
			FATAL("out of space in dopa2");
	}

	pair = ptoi(a[3]);
	if (pairstack[pair] == 0) {
		x = execute(a[0]);
		if (istrue(x))
			pairstack[pair] = 1;
		tempfree(x);
	}
	if (pairstack[pair] == 1) {
		x = execute(a[1]);
		if (istrue(x))
			pairstack[pair] = 0;
		tempfree(x);
		x = execute(a[2]);
		return (x);
	}
	return (False);
}

/*ARGSUSED*/
Cell *
split(Node **a, int nnn)	/* split(a[0], a[1], a[2]); a[3] is type */
{
	Cell *x, *y, *ap;
	char *s;
	int sep;
	char *t, temp, num[50], *fs = NULL;
	int n, tempstat, arg3type;

	y = execute(a[0]);	/* source string */
	s = getsval(y);
	arg3type = ptoi(a[3]);
	if (a[2] == NULL)		/* fs string */
		fs = *FS;
	else if (arg3type == STRING) {	/* split(str,arr,"string") */
		x = execute(a[2]);
		fs = getsval(x);
	} else if (arg3type == REGEXPR)
		fs = "(regexpr)";	/* split(str,arr,/regexpr/) */
	else
		FATAL("illegal type of split");
	sep = *fs;
	ap = execute(a[1]);	/* array name */
	freesymtab(ap);
	dprintf(("split: s=|%s|, a=%s, sep=|%s|\n", s, NN(ap->nval), fs));
	ap->tval &= ~STR;
	ap->tval |= ARR;
	ap->sval = (char *)makesymtab(NSYMTAB);

	n = 0;
	if (*s != '\0' && (strlen(fs) > 1 || arg3type == REGEXPR)) {
		/* reg expr */
		fa *pfa;
		if (arg3type == REGEXPR) {	/* it's ready already */
			pfa = (fa *)a[2];
		} else {
			pfa = makedfa(fs, 1);
		}
		if (nematch(pfa, s)) {
			tempstat = pfa->initstat;
			pfa->initstat = 2;
			do {
				n++;
				(void) sprintf(num, "%d", n);
				temp = *patbeg;
				*patbeg = '\0';
				if (is_number(s)) {
					(void) setsymtab(num, s,
					    atof(s),
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
					(void) sprintf(num, "%d", n);
					(void) setsymtab(num, "", 0.0,
					    /*LINTED align*/
					    STR, (Array *)ap->sval);
					pfa->initstat = tempstat;
					goto spdone;
				}
			} while (nematch(pfa, s));
		}
		n++;
		(void) sprintf(num, "%d", n);
		if (is_number(s)) {
			(void) setsymtab(num, s, atof(s),
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
			if (*s == '\0')
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
			(void) sprintf(num, "%d", n);
			if (is_number(t)) {
				(void) setsymtab(num, t, atof(t),
				    /*LINTED align*/
				    STR|NUM, (Array *)ap->sval);
			} else {
				(void) setsymtab(num, t, 0.0,
				    /*LINTED align*/
				    STR, (Array *)ap->sval);
			}
			*s = temp;
			if (*s != '\0')
				s++;
		}
	} else if (*s != '\0') {
		for (;;) {
			n++;
			t = s;
			while (*s != sep && *s != '\n' && *s != '\0')
				s++;
			temp = *s;
			*s = '\0';
			(void) sprintf(num, "%d", n);
			if (is_number(t)) {
				(void) setsymtab(num, t, atof(t),
				    /*LINTED align*/
				    STR|NUM, (Array *)ap->sval);
			} else {
				(void) setsymtab(num, t, 0.0,
				    /*LINTED align*/
				    STR, (Array *)ap->sval);
			}
			*s = temp;
			if (*s++ == '\0')
				break;
		}
	}
	tempfree(ap);
	tempfree(y);
	if (a[2] != NULL && arg3type == STRING) {
		tempfree(x);
	}
	x = gettemp();
	x->tval = NUM;
	x->fval = n;
	return (x);
}

/*ARGSUSED*/
Cell *
condexpr(Node **a, int n)	/* a[0] ? a[1] : a[2] */
{
	Cell *x;

	x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x);
		x = execute(a[1]);
	} else {
		tempfree(x);
		x = execute(a[2]);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
ifstat(Node **a, int n)	/* if (a[0]) a[1]; else a[2] */
{
	Cell *x;

	x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x);
		x = execute(a[1]);
	} else if (a[2] != NULL) {
		tempfree(x);
		x = execute(a[2]);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
whilestat(Node **a, int n)	/* while (a[0]) a[1] */
{
	Cell *x;

	for (;;) {
		x = execute(a[0]);
		if (!istrue(x))
			return (x);
		tempfree(x);
		x = execute(a[1]);
		if (isbreak(x)) {
			x = True;
			return (x);
		}
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x);
	}
}

/*ARGSUSED*/
Cell *
dostat(Node **a, int n)	/* do a[0]; while(a[1]) */
{
	Cell *x;

	for (;;) {
		x = execute(a[0]);
		if (isbreak(x))
			return (True);
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x);
		x = execute(a[1]);
		if (!istrue(x))
			return (x);
		tempfree(x);
	}
}

/*ARGSUSED*/
Cell *
forstat(Node **a, int n)	/* for (a[0]; a[1]; a[2]) a[3] */
{
	Cell *x;

	x = execute(a[0]);
	tempfree(x);
	for (;;) {
		if (a[1] != NULL) {
			x = execute(a[1]);
			if (!istrue(x))
				return (x);
			else
				tempfree(x);
		}
		x = execute(a[3]);
		if (isbreak(x))		/* turn off break */
			return (True);
		if (isnext(x) || isexit(x) || isret(x))
			return (x);
		tempfree(x);
		x = execute(a[2]);
		tempfree(x);
	}
}

/*ARGSUSED*/
Cell *
instat(Node **a, int n)	/* for (a[0] in a[1]) a[2] */
{
	Cell *x, *vp, *arrayp, *cp, *ncp;
	Array *tp;
	int i;

	vp = execute(a[0]);
	arrayp = execute(a[1]);
	if (!isarr(arrayp)) {
		FATAL("%s is not an array", arrayp->nval);
	}
	/*LINTED align*/
	tp = (Array *)arrayp->sval;
	tempfree(arrayp);
	for (i = 0; i < tp->size; i++) { /* this routine knows too much */
		for (cp = tp->tab[i]; cp != NULL; cp = ncp) {
			(void) setsval(vp, cp->nval);
			ncp = cp->cnext;
			x = execute(a[2]);
			if (isbreak(x)) {
				tempfree(vp);
				return (True);
			}
			if (isnext(x) || isexit(x) || isret(x)) {
				tempfree(vp);
				return (x);
			}
			tempfree(x);
		}
	}
	return (True);
}

/*ARGSUSED*/
Cell *
bltin(Node **a, int n)	/* builtin functions. a[0] is type, a[1] is arg list */
{
	Cell *x, *y;
	Awkfloat u;
	int t;
	char *p, *buf;
	Node *nextarg;

	t = ptoi(a[0]);
	x = execute(a[1]);
	nextarg = a[1]->nnext;
	switch (t) {
	case FLENGTH:
		u = (Awkfloat)strlen(getsval(x)); break;
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
		if (nextarg == NULL) {
			WARNING("atan2 requires two arguments; returning 1.0");
			u = 1.0;
		} else {
			y = execute(a[1]->nnext);
			u = atan2(getfval(x), getfval(y));
			tempfree(y);
			nextarg = nextarg->nnext;
		}
		break;
	case FSYSTEM:
		/* in case something is buffered already */
		(void) fflush(stdout);
		/* 256 is unix-dep */
		u = (Awkfloat)system(getsval(x)) / 256;
		break;
	case FRAND:
		/* in principle, rand() returns something in 0..RAND_MAX */
		u = (Awkfloat) (rand() % RAND_MAX) / RAND_MAX;
		break;
	case FSRAND:
		if (isrec(x))	/* no argument provided */
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
				if (islower((uschar)*p))
					*p = toupper((uschar)*p);
		} else {
			for (p = buf; *p; p++)
				if (isupper((uschar)*p))
					*p = tolower((uschar)*p);
		}
		tempfree(x);
		x = gettemp();
		(void) setsval(x, buf);
		free(buf);
		return (x);
	default:	/* can't happen */
		FATAL("illegal function type %d", t);
		break;
	}
	tempfree(x);
	x = gettemp();
	(void) setfval(x, u);
	if (nextarg != NULL) {
		WARNING("warning: function has too many arguments");
		for (; nextarg != NULL; nextarg = nextarg->nnext)
			(void) execute(nextarg);
	}
	return (x);
}

/*ARGSUSED*/
Cell *
printstat(Node **a, int n)	/* print a[0] */
{
	Node *x;
	Cell *y;
	FILE *fp;

	if (a[1] == NULL)	/* a[1] is redirection operator, a[2] is file */
		fp = stdout;
	else
		fp = redirect(ptoi(a[1]), a[2]);
	for (x = a[0]; x != NULL; x = x->nnext) {
		y = execute(x);
		(void) fputs(getsval(y), fp);
		tempfree(y);
		if (x->nnext == NULL)
			(void) fputs(*ORS, fp);
		else
			(void) fputs(*OFS, fp);
	}
	if (a[1] != NULL)
		(void) fflush(fp);
	return (True);
}

/*ARGSUSED*/
Cell *
nullproc(Node **a, int n)
{
	return (0);
}

struct {
	FILE	*fp;
	char	*fname;
	int	mode;	/* '|', 'a', 'w' */
} files[FOPEN_MAX];

static FILE *
redirect(int a, Node *b)	/* set up all i/o redirections */
{
	FILE *fp;
	Cell *x;
	char *fname;

	x = execute(b);
	fname = getsval(x);
	fp = openfile(a, fname);
	if (fp == NULL)
		FATAL("can't open file %s", fname);
	tempfree(x);
	return (fp);
}

static FILE *
openfile(int a, const char *s)
{
	int i, m;
	FILE *fp = NULL;

	if (*s == '\0')
		FATAL("null file name in print or getline");
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fname && strcmp(s, files[i].fname) == 0) {
			if (a == files[i].mode ||
			    (a == APPEND && files[i].mode == GT)) {
				return (files[i].fp);
			}
		}
	}
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fp == 0)
			break;
	}
	if (i >= FOPEN_MAX)
		FATAL("%s makes too many open files", s);
	(void) fflush(stdout);	/* force a semblance of order */
	m = a;
	if (a == GT) {
		fp = fopen(s, "w");
	} else if (a == APPEND) {
		fp = fopen(s, "a");
		m = GT;	/* so can mix > and >> */
	} else if (a == '|') {	/* output pipe */
		fp = popen(s, "w");
	} else if (a == LE) {	/* input pipe */
		fp = popen(s, "r");
	} else if (a == LT) {	/* getline <file */
		fp = strcmp(s, "-") == 0 ?
		    stdin : fopen(s, "r");	/* "-" is stdin */
	} else	/* can't happen */
		FATAL("illegal redirection %d", a);
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
	Cell *x;
	int i, stat;

	x = execute(a[0]);
	(void) getsval(x);
	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fname && strcmp(x->sval, files[i].fname) == 0) {
			if (ferror(files[i].fp)) {
				WARNING("i/o error occurred on %s",
				    files[i].fname);
			}
			if (files[i].mode == '|' || files[i].mode == LE)
				stat = pclose(files[i].fp);
			else
				stat = fclose(files[i].fp);
			if (stat == EOF) {
				WARNING("i/o error occurred closing %s",
				    files[i].fname);
			}
			xfree(files[i].fname);
			/* watch out for ref thru this */
			files[i].fname = NULL;
			files[i].fp = NULL;
		}
	}
	tempfree(x);
	return (True);
}

static void
closeall(void)
{
	int i, stat;

	for (i = 0; i < FOPEN_MAX; i++) {
		if (files[i].fp) {
			if (ferror(files[i].fp)) {
				WARNING("i/o error occurred on %s",
				    files[i].fname);
			}
			if (files[i].mode == '|' || files[i].mode == LE)
				stat = pclose(files[i].fp);
			else
				stat = fclose(files[i].fp);
			if (stat == EOF) {
				WARNING("i/o error occurred while closing %s",
				    files[i].fname);
			}
		}
	}
}

/*ARGSUSED*/
Cell *
sub(Node **a, int nnn)	/* substitute command */
{
	char *sptr;
	Cell *x, *y, *result;
	char *t, *buf;
	fa *pfa;
	size_t bufsz = recsize;
	size_t cnt = 0, len;

	if ((buf = (char *)malloc(bufsz)) == NULL)
		FATAL("out of memory in sub");
	x = execute(a[3]);	/* target string */
	t = getsval(x);
	if (a[0] == NULL)	/* 0 => a[1] is already-compiled regexpr */
		pfa = (fa *)a[1];	/* regular expression */
	else {
		y = execute(a[1]);
		pfa = makedfa(getsval(y), 1);
		tempfree(y);
	}
	y = execute(a[2]);	/* replacement string */
	result = False;
	if (pmatch(pfa, t)) {
		sptr = t;
		len = patbeg - sptr;
		if (len > 0) {
			(void) adjbuf(&buf, &bufsz, cnt + len,
			    recsize, NULL, "sub");
			(void) memcpy(buf, sptr, len);
			cnt += len;
		}
		sptr = getsval(y);
		while (*sptr != '\0') {
			(void) adjbuf(&buf, &bufsz, 1 + cnt + patlen,
			    recsize, NULL, "sub");
			if (*sptr == '\\' &&
			    (*(sptr+1) == '&' || *(sptr+1) == '\\')) {
				sptr++;		/* skip \, */
				buf[cnt++] = *sptr++; /* add & or \ */
			} else if (*sptr == '&') {
				sptr++;
				(void) memcpy(&buf[cnt], patbeg, patlen);
				cnt += patlen;
			} else {
				buf[cnt++] = *sptr++;
			}
		}
		sptr = patbeg + patlen;
		if ((patlen == 0 && *patbeg) || (patlen && *(sptr-1))) {
			len = strlen(sptr);
			(void) adjbuf(&buf, &bufsz, 1 + cnt + len,
			    recsize, NULL, "sub");
			(void) memcpy(&buf[cnt], sptr, len);
			cnt += len;
		}
		buf[cnt] = '\0';
		(void) setsval(x, buf);	/* BUG: should be able to avoid copy */
		result = True;
	}
	tempfree(x);
	tempfree(y);
	free(buf);
	return (result);
}

/*ARGSUSED*/
Cell *
gsub(Node **a, int nnn)	/* global substitute */
{
	Cell *x, *y;
	char *rptr, *sptr, *t;
	char *buf;
	fa *pfa;
	int mflag, tempstat, num;
	size_t bufsz = recsize;
	size_t cnt, len;

	if ((buf = (char *)malloc(bufsz)) == NULL)
		FATAL("out of memory in gsub");
	mflag = 0;	/* if mflag == 0, can replace empty string */
	num = 0;
	x = execute(a[3]);	/* target string */
	t = getsval(x);
	if (a[0] == NULL)	/* 0 => a[1] is already-compiled regexpr */
		pfa = (fa *)a[1];	/* regular expression */
	else {
		y = execute(a[1]);
		pfa = makedfa(getsval(y), 1);
		tempfree(y);
	}
	y = execute(a[2]);	/* replacement string */
	if (pmatch(pfa, t)) {
		tempstat = pfa->initstat;
		pfa->initstat = 2;
		rptr = getsval(y);
		cnt = 0;
		do {
			if (patlen == 0 && *patbeg != '\0') {
				/* matched empty string */
				if (mflag == 0) {	/* can replace empty */
					num++;
					sptr = rptr;
					while (*sptr != '\0') {
						(void) adjbuf(&buf, &bufsz,
						    1 + cnt, recsize,
						    NULL, "gsub");
						if (*sptr == '\\' &&
						    (*(sptr+1) == '&' ||
						    *(sptr+1) == '\\')) {
							sptr++;
							buf[cnt++] = *sptr++;
						} else if (*sptr == '&') {
							(void) adjbuf(&buf,
							    &bufsz,
							    1 + cnt + patlen,
							    recsize,
							    NULL, "gsub");
							sptr++;
							(void) memcpy(&buf[cnt],
							    patbeg, patlen);
							cnt += patlen;
						} else {
							buf[cnt++] = *sptr++;
						}
					}
				}
				if (*t == '\0')	/* at end */
					goto done;
				(void) adjbuf(&buf, &bufsz, 1 + cnt,
				    recsize, NULL, "gsub");
				buf[cnt++] = *t++;
				mflag = 0;
			} else {	/* matched nonempty string */
				num++;
				sptr = t;
				len = patbeg - sptr;
				if (len > 0) {
					(void) adjbuf(&buf, &bufsz,
					    1 + cnt + len, recsize,
					    NULL, "gsub");
					(void) memcpy(&buf[cnt], sptr, len);
					cnt += len;
				}
				sptr = rptr;
				while (*sptr != '\0') {
					(void) adjbuf(&buf, &bufsz, 1 + cnt,
					    recsize, NULL, "gsub");
					if (*sptr == '\\' &&
					    (*(sptr+1) == '&' ||
					    *(sptr+1) == '\\')) {
						sptr++;
						buf[cnt++] = *sptr++;
					} else if (*sptr == '&') {
						sptr++;
						(void) adjbuf(&buf, &bufsz,
						    1 + cnt + patlen, recsize,
						    NULL, "gsub");
						(void) memcpy(&buf[cnt],
						    patbeg, patlen);
						cnt += patlen;
					} else {
						buf[cnt++] = *sptr++;
					}
				}
				t = patbeg + patlen;
				if ((*(t-1) == '\0') || (*t == '\0'))
					goto done;
				mflag = 1;
			}
		} while (pmatch(pfa, t));
		sptr = t;
		len = strlen(sptr);
		(void) adjbuf(&buf, &bufsz, 1 + len + cnt,
		    recsize, NULL, "gsub");
		(void) memcpy(&buf[cnt], sptr, len);
		cnt += len;
	done:
		buf[cnt] = '\0';
		(void) setsval(x, buf);
		free(buf);
		pfa->initstat = tempstat;
	}
	tempfree(x);
	tempfree(y);
	x = gettemp();
	x->tval = NUM;
	x->fval = num;
	return (x);
}

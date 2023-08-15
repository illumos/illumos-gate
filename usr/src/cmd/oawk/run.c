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
#define	tempfree(a)	{if (istemp(a)) {xfree(a->sval); a->tval = 0; }}

#include	"awk.def"
#include	"math.h"
#include	"awk.h"
#include	"stdio.h"
#include "ctype.h"
#include "wctype.h"
#include "awktype.h"
#include <stdlib.h>

#define	RECSIZE BUFSIZ

#define	FILENUM	10
struct
{
	FILE *fp;
	int type;
	wchar_t *fname;
} files[FILENUM];
FILE *popen();

extern CELL *execute(), *nodetoobj(), *fieldel(), *dopa2(), *gettemp();

#define	PA2NUM	29
int	pairstack[PA2NUM], paircnt;
NODE	*winner = NULL;
#define	MAXTMP	20
CELL	tmps[MAXTMP];

static CELL	truecell	={ OBOOL, BTRUE, 0, 0, 0.0, NUM, 0 };
CELL	*true	= &truecell;
static CELL	falsecell	={ OBOOL, BFALSE, 0, 0, 0.0, NUM, 0 };
CELL	*false	= &falsecell;
static CELL	breakcell	={ OJUMP, JBREAK, 0, 0, 0.0, NUM, 0 };
CELL	*jbreak	= &breakcell;
static CELL	contcell	={ OJUMP, JCONT, 0, 0, 0.0, NUM, 0 };
CELL	*jcont	= &contcell;
static CELL	nextcell	={ OJUMP, JNEXT, 0, 0, 0.0, NUM, 0 };
CELL	*jnext	= &nextcell;
static CELL	exitcell	={ OJUMP, JEXIT, 0, 0, 0.0, NUM, 0 };
CELL	*jexit	= &exitcell;
static CELL	tempcell	={ OCELL, CTEMP, 0, 0, 0.0, NUM, 0 };

static void redirprint(wchar_t *s, int a, NODE *b);

void freesymtab(CELL *ap);
void fldbld(void);

void
run(NODE *a)
{
	int i;

	execute(a);
	/* Wait for children to complete if output to a pipe. */
	for (i=0; i<FILENUM; i++)
		if (files[i].fp && files[i].type == '|')
			pclose(files[i].fp);
}


CELL *
execute(NODE *u)
{
	CELL *(*proc)();
	CELL *x;
	NODE *a;

	if (u == NULL)
		return (true);
	for (a = u; /* dummy */; a = a->nnext) {
		if (cantexec(a))
			return (nodetoobj(a));
		if (notlegal(a->nobj))
			error(FATAL, "illegal statement %o", a);
		proc = proctab[a->nobj-FIRSTTOKEN];
		x = (*proc)(a->narg, a->nobj);
		if (isfld(x))
			fldbld();
		if (isexpr(a))
			return (x);
		/* a statement, goto next statement */
		if (isjump(x))
			return (x);
		if (a->nnext == (NODE *)NULL)
			return (x);
		tempfree(x);
	}
}




CELL *
program(NODE **a, int n)
{
	CELL *x;

	if (a[0] != NULL) {
		x = execute(a[0]);
		if (isexit(x))
			return (true);
		if (isjump(x))
			error(FATAL, "unexpected break, continue or next");
		tempfree(x);
	}
	while (getrec()) {
		x = execute(a[1]);
		if (isexit(x)) {
			tempfree(x);
			break;
		}
		tempfree(x);
	}
	if (a[2] != NULL) {
		x = execute(a[2]);
		if (isbreak(x) || isnext(x) || iscont(x))
			error(FATAL, "unexpected break, continue or next");
		tempfree(x);
	}
	return (true);
}




CELL *
getaline(void)
{
	CELL *x;

	x = gettemp();
	setfval(x, (awkfloat) getrec());
	return (x);
}




CELL *
array(NODE **a, int n)
{
	CELL *x, *y;
	extern CELL *arrayel();

	x = execute(a[1]);
	y = arrayel(a[0], x);
	tempfree(x);
	return (y);
}




CELL *
arrayel(NODE *a, CELL *b)
{
	wchar_t *s;
	CELL *x;
	int i;
	CELL *y;

	s = getsval(b);
	x = (CELL *) a;
	if (!(x->tval&ARR)) {
		xfree(x->sval);
		x->tval &= ~STR;
		x->tval |= ARR;
		x->sval = (wchar_t *) makesymtab();
	}
	y = setsymtab(s, tostring(L_NULL), 0.0, STR|NUM, x->sval);
	y->ctype = OCELL;
	y->csub = CVAR;
	return (y);
}

CELL *
matchop(NODE **a, int n)
{
	CELL *x;
	wchar_t *s;
	int i;

	x = execute(a[0]);
	s = getsval(x);
	tempfree(x);
	i = match(a[1], s);
	if (n == MATCH && i == 1 || n == NOTMATCH && i == 0)
		return (true);
	else
		return (false);
}




CELL *
boolop(NODE **a, int n)
{
	CELL *x, *y;
	int i;




	x = execute(a[0]);
	i = istrue(x);
	tempfree(x);
	switch (n) {
	case BOR:
		if (i) return (true);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y);
		if (i) return (true);
		else return (false);
	case AND:
		if (!i) return (false);
		y = execute(a[1]);
		i = istrue(y);
		tempfree(y);
		if (i) return (true);
		else return (false);
	case NOT:
		if (i) return (false);
		else return (true);
	default:
		error(FATAL, "unknown boolean operator %d", n);
	}
	return (false);
}




CELL *
relop(NODE **a, int n)
{
	int i;
	CELL *x, *y;
	awkfloat j;
	wchar_t *xs, *ys;




	x = execute(a[0]);
	y = execute(a[1]);
	if (x->tval&NUM && y->tval&NUM) {
		j = x->fval - y->fval;
		i = j<0? -1: (j>0? 1: 0);
	} else {
		xs = getsval(x);
		ys = getsval(y);
		if (xs && ys)
			i = wscoll(xs, ys);
		else
			return (false);
	}
	tempfree(x);
	tempfree(y);
	switch (n) {
	case LT:	if (i<0) return (true);
			else return (false);
	case LE:	if (i<=0) return (true);
			else return (false);
	case NE:	if (i!=0) return (true);
			else return (false);
	case EQ:	if (i == 0) return (true);
			else return (false);
	case GE:	if (i>=0) return (true);
			else return (false);
	case GT:	if (i>0) return (true);
			else return (false);
	default:
		error(FATAL, "unknown relational operator %d", n);
	}
	return (false);
}








CELL *
gettemp(void)
{
	int i;
	CELL *x;




	for (i=0; i<MAXTMP; i++)
		if (tmps[i].tval == 0)
			break;
	if (i == MAXTMP)
		error(FATAL, "out of temporaries in gettemp");
	tmps[i] = tempcell;
	x = &tmps[i];
	return (x);
}




CELL *
indirect(NODE **a, int n)
{
	CELL *x;
	int m;
	CELL *fieldadr();

	x = execute(a[0]);
	m = getfval(x);
	tempfree(x);
	x = fieldadr(m);
	x->ctype = OCELL;
	x->csub = CFLD;
	return (x);
}




CELL *
substr(NODE **a, int nnn)
{
	int k, m, n;
	wchar_t *s, temp;
	CELL *x, *y;

	y = execute(a[0]);
	s = getsval(y);
	k = wslen(s) + 1;
	if (k <= 1) {
		x = gettemp();
		setsval(x, L_NULL);
		return (x);
	}
	x = execute(a[1]);
	m = getfval(x);
	if (m <= 0)
		m = 1;
	else if (m > k)
		m = k;
	tempfree(x);
	if (a[2] != 0) {
		x = execute(a[2]);
		n = getfval(x);
		tempfree(x);
	}
	else
		n = k - 1;
	if (n < 0)
		n = 0;
	else if (n > k - m)
		n = k - m;
	dprintf("substr: m=%d, n=%d, s=%ws\n", m, n, s);
	x = gettemp();
	temp = s[n+m-1];
	s[n+m-1] = (wchar_t)0x0;
	setsval(x, s + m - 1);
	s[n+m-1] = temp;
	tempfree(y);
	return (x);
}




CELL *
sindex(NODE **a, int nnn)
{
	CELL *x;
	wchar_t *s1, *s2, *p1, *p2, *q;

	x = execute(a[0]);
	s1 = getsval(x);
	tempfree(x);
	x = execute(a[1]);
	s2 = getsval(x);
	tempfree(x);

	x = gettemp();
	for (p1 = s1; *p1 != (wchar_t)0x0; p1++) {
		for (q=p1, p2=s2; *p2 != (wchar_t)0x0 && *q == *p2; q++, p2++)
			;
		if (*p2 == (wchar_t)0x0) {
			setfval(x, (awkfloat) (p1 - s1 + 1));	/* origin 1 */
			return (x);
		}
	}
	setfval(x, 0.0);
	return (x);
}




wchar_t *
format(wchar_t *s, NODE *a)
{
	wchar_t *buf, *ep, *str;
	wchar_t *p;
	char *t;
	wchar_t *os;
	wchar_t tbuf[2*RECSIZE];
	char fmt[200];
	CELL *x;
	int flag = 0;
	awkfloat xf;

	os = s;
	p = buf= (wchar_t *)malloc(RECSIZE * sizeof (wchar_t));

	if (p == NULL)
		error(FATAL, "out of space in format");
	ep = p + RECSIZE;
	while (*s) {
		if (*s != '%') {
			*p++ = *s++;
			continue;
		}
		if (*(s+1) == '%') {
			*p++ = '%';
			s += 2;
			continue;
		}
		for (t=fmt; *s != '\0'; s++)
		{
			if (*s == 's' || *s == 'c')
				*t++ = 'w';
			*t++ = *s;
			if (*s >= 'a' && *s <= 'z' && *s != 'l')
				break;
			if (*s == '*') {
				if (a == NULL) {
					error(FATAL,
			"not enough arguments in printf(%ws) or sprintf(%ws)",
					os, os);
				}
				x = execute(a);
				a = a->nnext;
				sprintf(t-1, "%d", (int) getfval(x));
				t = fmt + strlen(fmt);
				tempfree(x);
			}

		}
		*t = '\0';
		if (t >= fmt + sizeof (fmt))
			error(FATAL, "format item %.20ws... too long", os);
		switch (*s) {
		case 'f': case 'e': case 'g':
			flag = 1;
			break;
		case 'd':
			flag = 2;
			if (*(s-1) == 'l') break;
			*(t-1) = 'l';
			*t = 'd';
			*++t = '\0';
			break;
		case 'o': case 'x':
			flag = *(s-1) == 'l' ? 2 : 3;
			break;
		case 'c':
			flag = 3;
			break;
		case 's':
			flag = 4;
			break;
		default:
			flag = 0;
			break;
		}
		if (flag == 0) {
			wsprintf(p, "%s", fmt);
			p += wslen(p);
			continue;
		}
		if (a == NULL) {
			error(FATAL,
	"not enough arguments in printf(%ws) or sprintf(%ws)", os, os);
		}
		x = execute(a);
		a = a->nnext;

		/*
		 * Get the string to check length; %s is the usual problem;
		 * other conversions can cause overrun if they occur when
		 * the buffer is almost filled.
		 */
		if (flag == 4)	{ /* watch out for converting to numbers! */
			str = getsval(x);
		}
		else {
			xf = getfval(x);
			if (flag == 1) wsprintf(tbuf, fmt, xf);
			else if (flag == 2) wsprintf(tbuf, fmt, (long)xf);
			else if (flag == 3) wsprintf(tbuf, fmt, (int)xf);
			if (wslen(tbuf) >= RECSIZE)
				error(FATAL, "formatted item %s... too long",
						tbuf);
			str = tbuf;
		}
		/*
		 * If string overruns the buffer, reallocate;
		 * consider length of format string
		 */
		if (p + wslen(str) + wslen(s) + 1 >= ep) {
			int newlen, oldlen;

			oldlen = p - buf;
			/* Add RECSIZE for additional space */
			newlen = oldlen + wslen(str) + RECSIZE;
			buf = realloc(buf, (unsigned) newlen * sizeof(wchar_t));
			if (buf == NULL)
				error(FATAL, "out of format space");
			p = buf + oldlen;
			ep = buf + newlen;
		}
		/* Transfer string to buffer */
		if (flag == 4)
			wsprintf(p, fmt, str);
		else
			wscpy(p, str);

		tempfree(x);
		p += wslen(p);
		if (p >= ep)
			error(FATAL, "formatted string too long");
		s++;
	}
	*p = '\0';
	return (buf);
}


CELL *
a_sprintf(NODE **a, int n)
{
	CELL *x;
	NODE *y;
	wchar_t *s;

	y = a[0]->nnext;
	x = execute(a[0]);
	s = format(getsval(x), y);
	tempfree(x);
	x = gettemp();
	x->sval = s;
	x->tval = STR;
	return (x);
}


CELL *
arith(NODE **a, int n)
{
	awkfloat i, j;
	CELL *x, *y, *z;

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
			error(FATAL, "division by zero");
		i /= j;
		break;
	case MOD:
		if (j == 0)
			error(FATAL, "division by zero");
		i = i - j*(long)(i/j);
		break;
	case UMINUS:
		i = -i;
		break;
	default:
		error(FATAL, "illegal arithmetic operator %d", n);
	}
	setfval(z, i);
	return (z);
}




CELL *
incrdecr(NODE **a, int n)
{
	CELL *x, *z;
	int k;
	awkfloat xf;

	x = execute(a[0]);
	xf = getfval(x);
	k = (n == PREINCR || n == POSTINCR) ? 1 : -1;
	if (n == PREINCR || n == PREDECR) {
		setfval(x, xf + k);
		return (x);
	}
	z = gettemp();
	setfval(z, xf);
	setfval(x, xf + k);
	tempfree(x);
	return (z);
}



CELL *
assign(NODE **a, int n)
{
	CELL *x, *y;
	awkfloat xf, yf;




	x = execute(a[0]);
	y = execute(a[1]);
	if (n == ASSIGN) {	/* ordinary assignment */
		if ((y->tval & (STR|NUM)) == (STR|NUM)) {
			setsval(x, y->sval);
			x->fval = y->fval;
			x->tval |= NUM;

		} else if (y->tval & STR)
			setsval(x, y->sval);
		else if (y->tval & NUM)
			setfval(x, y->fval);
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
			error(FATAL, "division by zero");
		xf /= yf;
		break;
	case MODEQ:
		if (yf == 0)
			error(FATAL, "division by zero");
		xf = xf - yf*(long)(xf/yf);
		break;
	default:
		error(FATAL, "illegal assignment operator %d", n);
		break;
	}
	tempfree(y);
	setfval(x, xf);
	return (x);
}




CELL *
cat(NODE **a, int q)
{
	CELL *x, *y, *z;
	int n1, n2;
	wchar_t *s;




	x = execute(a[0]);
	y = execute(a[1]);
	getsval(x);
	getsval(y);
	n1 = wslen(x->sval);
	n2 = wslen(y->sval);
	if ((s = (wchar_t *) malloc((n1 + n2 + 1) * sizeof (wchar_t))) == NULL)
		error(FATAL, "out of space in cat");
	wscpy(s, x->sval);
	wscpy(s+n1, y->sval);
	tempfree(y);
	z = gettemp();
	z->sval = s;
	z->tval = STR;
	tempfree(x);
	return (z);
}




CELL *
pastat(NODE **a, int n)
{
	CELL *x;




	if (a[0] == 0)
		x = true;
	else
		x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x);
		x = execute(a[1]);
	}
	return (x);
}




CELL *
dopa2(NODE **a, int n)
{
	CELL *x;
	int pair;




	pair = (int) a[3];
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
	return (false);
}




CELL *
aprintf(NODE **a, int n)
{
	CELL *x;




	x = a_sprintf(a, n);
	if (a[1] == NULL) {
		printf("%ws", x->sval);
		tempfree(x);
		return (true);
	}
	redirprint(x->sval, (int)a[1], a[2]);
	return (x);
}




CELL *
split(NODE **a, int nnn)
{
	CELL *x;
	CELL *ap;
	wchar_t *s, *p, c;
	wchar_t *t, temp, num[5];
	wchar_t sep;
	int n, flag;




	x = execute(a[0]);
	s = getsval(x);
	tempfree(x);
	if (a[2] == 0)
		sep = **FS;
	else {
		x = execute(a[2]);
		sep = getsval(x)[0];
		tempfree(x);
	}
	ap = (CELL *) a[1];
	freesymtab(ap);
	dprintf("split: s=|%ws|, a=%ws, sep=|%wc|\n", s, ap->nval, sep);
	ap->tval &= ~STR;
	ap->tval |= ARR;
	ap->sval = (wchar_t *) makesymtab();




	n = 0;
	if (sep == ' ')
		for (n = 0; /* dummy */; /* dummy */) {
			c = *s;
			while (iswblank(c) || c == '\t' || c == '\n')
				c = *(++s);
			if (*s == 0)
				break;
			n++;
			t = s;
			do
				c = *(++s);
			while (! iswblank(c) && c != '\t' &&
				c != '\n' && c != '\0');
			temp = c;
			*s = (wchar_t)0x0;
			wsprintf(num, "%d", n);
			if (isanumber(t))
				setsymtab(num, tostring(t),
						watof(t), STR|NUM, ap->sval);
			else
				setsymtab(num, tostring(t), 0.0, STR, ap->sval);
			*s = temp;
			if (*s != 0)
				s++;

	} else if (*s != 0)
		for (;;) {
			n++;
			t = s;
			while ((c = *s) != sep && c != '\n' && c != '\0')
				s++;
			temp = c;
			*s = (wchar_t)0x0;
			wsprintf(num, "%d", n);
			if (isanumber(t))
				setsymtab(num, tostring(t),
						watof(t), STR|NUM, ap->sval);
			else
				setsymtab(num, tostring(t), 0.0, STR, ap->sval);
			*s = temp;
			if (*s++ == 0)
				break;
		}
	x = gettemp();
	x->tval = NUM;
	x->fval = n;
	return (x);
}




CELL *
ifstat(NODE **a, int n)
{
	CELL *x;




	x = execute(a[0]);
	if (istrue(x)) {
		tempfree(x);
		x = execute(a[1]);

	} else if (a[2] != 0) {
		tempfree(x);
		x = execute(a[2]);
	}
	return (x);
}




CELL *
whilestat(NODE **a, int n)
{
	CELL *x;




	for (;;) {
		x = execute(a[0]);
		if (!istrue(x)) return (x);
		tempfree(x);
		x = execute(a[1]);
		if (isbreak(x)) {
			x = true;
			return (x);
		}
		if (isnext(x) || isexit(x))
			return (x);
		tempfree(x);
	}
}




CELL *
forstat(NODE **a, int n)
{
	CELL *x;
	CELL *z;




	z = execute(a[0]);
	tempfree(z);
	for (;;) {
		if (a[1]!=0) {
			x = execute(a[1]);
			if (!istrue(x)) return (x);
			else tempfree(x);
		}
		x = execute(a[3]);
		if (isbreak(x)) {	/* turn off break */
			x = true;
			return (x);
		}
		if (isnext(x) || isexit(x))
			return (x);
		tempfree(x);
		z = execute(a[2]);
		tempfree(z);
	}
}




CELL *
instat(NODE **a, int n)
{
	CELL *vp, *arrayp, *cp, **tp;
	CELL *x;
	int i;




	vp = (CELL *) a[0];
	arrayp = (CELL *) a[1];
	if (!(arrayp->tval & ARR))
		error(FATAL, "%ws is not an array", arrayp->nval);
	tp = (CELL **) arrayp->sval;
	for (i = 0; i < MAXSYM; i++) {	/* this routine knows too much */
		for (cp = tp[i]; cp != NULL; cp = cp->nextval) {
			setsval(vp, cp->nval);
			x = execute(a[2]);
			if (isbreak(x)) {
				x = true;
				return (x);
			}
			if (isnext(x) || isexit(x))
				return (x);
			tempfree(x);
		}
	}
	return (true);
}




CELL *
jump(NODE **a, int n)
{
	CELL *y;




	switch (n) {
	case EXIT:
		if (a[0] != 0) {
			y = execute(a[0]);
			errorflag = getfval(y);
		}
		return (jexit);
	case NEXT:
		return (jnext);
	case BREAK:
		return (jbreak);
	case CONTINUE:
		return (jcont);
	default:
		error(FATAL, "illegal jump type %d", n);
	}
	return (NULL);
}




CELL *
fncn(NODE **a, int n)
{
	CELL *x;
	awkfloat u;
	int t;
	wchar_t *wp;

	t = (int) a[0];
	x = execute(a[1]);
	if (t == FLENGTH)
		u = (awkfloat) wslen(getsval(x));
	else if (t == FLOG)
		u = log(getfval(x));
	else if (t == FINT)
		u = (awkfloat) (long) getfval(x);
	else if (t == FEXP)
		u = exp(getfval(x));
	else if (t == FSQRT)
		u = sqrt(getfval(x));
	else
		error(FATAL, "illegal function type %d", t);
	tempfree(x);
	x = gettemp();
	setfval(x, u);
	return (x);
}




CELL *
print(NODE **a, int n)
{
	NODE *x;
	CELL *y;
	wchar_t s[RECSIZE];
	wchar_t *ss, *bp, *ep, *os;
	size_t	blen, newlen, sslen, orslen, ofslen, oslen;

	s[0] = '\0';
	bp = s;
	ep = s + RECSIZE;

	blen = 0;
	orslen = wcslen(*ORS);
	ofslen = wcslen(*OFS);

	for (x = a[0]; x != NULL; x = x->nnext) {
		y = execute(x);
		ss = getsval(y);

		/* total new length will be */
		sslen = wcslen(ss);
		if (x->nnext == NULL) {
			os = *ORS;
			oslen = orslen;
		} else {
			os = *OFS;
			oslen = ofslen;
		}
		newlen = blen + sslen + oslen;

		/* allocate larger buffer if needed */
		if (ep < (bp + newlen + 1)) {
			wchar_t	*oldbp = bp;

			if (oldbp == s)
				bp = NULL;
			bp = realloc(bp, sizeof (wchar_t) * (newlen + 1));
			if (bp == NULL)
				error(FATAL, "out of space in print");
			ep = bp + newlen + 1;
			if (oldbp == s)
				(void) wmemcpy(bp, oldbp, blen);
		}
		(void) wmemcpy(bp + blen, ss, sslen);
		(void) wmemcpy(bp + blen + sslen, os, oslen);
		tempfree(y);
		blen = newlen;
		bp[blen] = '\0';
	}
	if (a[1] == NULL) {
		(void) printf("%ws", bp);
		if (bp != s)
			free(bp);
		return (true);
	}

	redirprint(bp, (int)a[1], a[2]);
	if (bp != s)
		free(bp);
	return (false);
}



CELL *
nullproc(void)
{
	return (NULL);
}



CELL *
nodetoobj(NODE *a)
{
	CELL *x;

	x= (CELL *) a->nobj;
	x->ctype = OCELL;
	x->csub = a->subtype;
	if (isfld(x))
		fldbld();
	return (x);
}

static void
redirprint(wchar_t *s, int a, NODE *b)
{
	int i;
	CELL *x;

	x = execute(b);
	getsval(x);
	for (i=0; i<FILENUM; i++)
		if (files[i].fname && wscmp(x->sval, files[i].fname) == 0)
			goto doit;
	for (i=0; i<FILENUM; i++)
		if (files[i].fp == 0)
			break;
	if (i >= FILENUM)
		error(FATAL, "too many output files %d", i);
	if (a == '|')	/* a pipe! */
		files[i].fp = popen(toeuccode(x->sval), "w");
	else if (a == APPEND)
		files[i].fp = fopen(toeuccode(x->sval), "a");
	else if (a == GT)
		files[i].fp = fopen(toeuccode(x->sval), "w");
	else
		error(FATAL, "illegal redirection near line %lld", lineno);
	if (files[i].fp == NULL)
		error(FATAL, "can't open file %ws", x->sval);
	files[i].fname = tostring(x->sval);
	files[i].type = a;
doit:
	fprintf(files[i].fp, "%ws", s);
#ifndef gcos
	fflush(files[i].fp);	/* in case someone is waiting for the output */
#endif
	tempfree(x);
}

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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	DEBUG
#include "awk.h"
#include "y.tab.h"

Node *
nodealloc(int n)
{
	register Node *x;

	x = (Node *)malloc(sizeof (Node) + (n - 1) * sizeof (Node *));
	if (x == NULL)
		ERROR "out of space in nodealloc" FATAL;
	x->nnext = NULL;
	x->lineno = lineno;
	return (x);
}

Node *
exptostat(Node *a)
{
	a->ntype = NSTAT;
	return (a);
}

Node *
node1(int a, Node *b)
{
	register Node *x;

	x = nodealloc(1);
	x->nobj = a;
	x->narg[0] = b;
	return (x);
}

Node *
node2(int a, Node *b, Node *c)
{
	register Node *x;

	x = nodealloc(2);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	return (x);
}

Node *
node3(int a, Node *b, Node *c, Node *d)
{
	register Node *x;

	x = nodealloc(3);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->narg[2] = d;
	return (x);
}

Node *
node4(int a, Node *b, Node *c, Node *d, Node *e)
{
	register Node *x;
	x = nodealloc(4);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->narg[2] = d;
	x->narg[3] = e;
	return (x);
}

Node *
stat3(int a, Node *b, Node *c, Node *d)
{
	register Node *x;

	x = node3(a, b, c, d);
	x->ntype = NSTAT;
	return (x);
}

Node *
op2(int a, Node *b, Node *c)
{
	register Node *x;

	x = node2(a, b, c);
	x->ntype = NEXPR;
	return (x);
}

Node *
op1(int a, Node *b)
{
	register Node *x;

	x = node1(a, b);
	x->ntype = NEXPR;
	return (x);
}

Node *
stat1(int a, Node *b)
{
	register Node *x;

	x = node1(a, b);
	x->ntype = NSTAT;
	return (x);
}

Node *
op3(int a, Node *b, Node *c, Node *d)
{
	register Node *x;

	x = node3(a, b, c, d);
	x->ntype = NEXPR;
	return (x);
}

Node *
op4(int a, Node *b, Node *c, Node *d, Node *e)
{
	register Node *x;

	x = node4(a, b, c, d, e);
	x->ntype = NEXPR;
	return (x);
}

Node *
stat2(int a, Node *b, Node *c)
{
	register Node *x;

	x = node2(a, b, c);
	x->ntype = NSTAT;
	return (x);
}

Node *
stat4(int a, Node *b, Node *c, Node *d, Node *e)
{
	register Node *x;

	x = node4(a, b, c, d, e);
	x->ntype = NSTAT;
	return (x);
}

Node *
valtonode(Cell *a, int b)
{
	register Node *x;

	a->ctype = OCELL;
	a->csub = b;
	x = node1(0, (Node *)a);
	x->ntype = NVALUE;
	return (x);
}

Node *
rectonode(void)
{
	/* return valtonode(lookup("$0", symtab), CFLD); */
	return (valtonode(recloc, CFLD));
}

Node *
makearr(Node *p)
{
	Cell *cp;

	if (isvalue(p)) {
		cp = (Cell *)(p->narg[0]);
		if (isfunc(cp))
			ERROR "%s is a function, not an array", cp->nval SYNTAX;
		else if (!isarr(cp)) {
			xfree(cp->sval);
			cp->sval = (uchar *)makesymtab(NSYMTAB);
			cp->tval = ARR;
		}
	}
	return (p);
}

Node *
pa2stat(Node *a, Node *b, Node *c)
{
	register Node *x;

	x = node4(PASTAT2, a, b, c, (Node *)paircnt);
	paircnt++;
	x->ntype = NSTAT;
	return (x);
}

Node *
linkum(Node *a, Node *b)
{
	register Node *c;

	if (errorflag)	/* don't link things that are wrong */
		return (a);
	if (a == NULL)
		return (b);
	else if (b == NULL)
		return (a);
	for (c = a; c->nnext != NULL; c = c->nnext)
		;
	c->nnext = b;
	return (a);
}

void
defn(Cell *v, Node *vl, Node *st)	/* turn on FCN bit in definition */
{
	Node *p;
	int n;

	if (isarr(v)) {
		ERROR "`%s' is an array name and a function name",
		    v->nval SYNTAX;
		return;
	}
	v->tval = FCN;
	v->sval = (uchar *)st;
	n = 0;	/* count arguments */
	for (p = vl; p; p = p->nnext)
		n++;
	v->fval = n;
	dprintf(("defining func %s (%d args)\n", v->nval, n));
}

int
isarg(uchar *s)	/* is s in argument list for current function? */
{
	extern Node *arglist;
	Node *p = arglist;
	int n;

	for (n = 0; p != 0; p = p->nnext, n++) {
		if (strcmp((char *)((Cell *)(p->narg[0]))->nval,
		    (char *)s) == 0) {
			return (n);
		}
	}
	return (-1);
}

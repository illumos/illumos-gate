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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 2.8	*/

#define DEBUG
#include <stdio.h>
#include "awk.h"
#include "y.tab.h"

Node *nodealloc(n)
{
	register Node *x;
	x = (Node *) malloc(sizeof(Node) + (n-1)*sizeof(Node *));
	if (x == NULL)
		ERROR "out of space in nodealloc" FATAL;
	x->nnext = NULL;
	x->lineno = lineno;
	return(x);
}

Node *exptostat(a) Node *a;
{
	a->ntype = NSTAT;
	return(a);
}

Node *node1(a,b) Node *b;
{
	register Node *x;
	x = nodealloc(1);
	x->nobj = a;
	x->narg[0]=b;
	return(x);
}

Node *node2(a,b,c) Node *b, *c;
{
	register Node *x;
	x = nodealloc(2);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	return(x);
}

Node *node3(a,b,c,d) Node *b, *c, *d;
{
	register Node *x;
	x = nodealloc(3);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->narg[2] = d;
	return(x);
}

Node *node4(a,b,c,d,e) Node *b, *c, *d, *e;
{
	register Node *x;
	x = nodealloc(4);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->narg[2] = d;
	x->narg[3] = e;
	return(x);
}

Node *stat3(a,b,c,d) Node *b, *c, *d;
{
	register Node *x;
	x = node3(a,b,c,d);
	x->ntype = NSTAT;
	return(x);
}

Node *op2(a,b,c) Node *b, *c;
{
	register Node *x;
	x = node2(a,b,c);
	x->ntype = NEXPR;
	return(x);
}

Node *op1(a,b) Node *b;
{
	register Node *x;
	x = node1(a,b);
	x->ntype = NEXPR;
	return(x);
}

Node *stat1(a,b) Node *b;
{
	register Node *x;
	x = node1(a,b);
	x->ntype = NSTAT;
	return(x);
}

Node *op3(a,b,c,d) Node *b, *c, *d;
{
	register Node *x;
	x = node3(a,b,c,d);
	x->ntype = NEXPR;
	return(x);
}

Node *op4(a,b,c,d,e) Node *b, *c, *d, *e;
{
	register Node *x;
	x = node4(a,b,c,d,e);
	x->ntype = NEXPR;
	return(x);
}

Node *stat2(a,b,c) Node *b, *c;
{
	register Node *x;
	x = node2(a,b,c);
	x->ntype = NSTAT;
	return(x);
}

Node *stat4(a,b,c,d,e) Node *b, *c, *d, *e;
{
	register Node *x;
	x = node4(a,b,c,d,e);
	x->ntype = NSTAT;
	return(x);
}

Node *valtonode(a, b) Cell *a;
{
	register Node *x;

	a->ctype = OCELL;
	a->csub = b;
	x = node1(0, (Node *) a);
	x->ntype = NVALUE;
	return(x);
}

Node *rectonode()
{
	/* return valtonode(lookup("$0", symtab), CFLD); */
	return valtonode(recloc, CFLD);
}

Node *makearr(p) Node *p;
{
	Cell *cp;

	if (isvalue(p)) {
		cp = (Cell *) (p->narg[0]);
		if (isfunc(cp))
			ERROR "%s is a function, not an array", cp->nval SYNTAX;
		else if (!isarr(cp)) {
			xfree(cp->sval);
			cp->sval = (uchar *) makesymtab(NSYMTAB);
			cp->tval = ARR;
		}
	}
	return p;
}

Node *pa2stat(a,b,c) Node *a, *b, *c;
{
	register Node *x;
	x = node4(PASTAT2, a, b, c, (Node *) paircnt);
	paircnt++;
	x->ntype = NSTAT;
	return(x);
}

Node *linkum(a,b) Node *a, *b;
{
	register Node *c;

	if (errorflag)	/* don't link things that are wrong */
		return a;
	if (a == NULL) return(b);
	else if (b == NULL) return(a);
	for (c = a; c->nnext != NULL; c = c->nnext)
		;
	c->nnext = b;
	return(a);
}

defn(v, vl, st)	/* turn on FCN bit in definition */
	Cell *v;
	Node *st, *vl;	/* body of function, arglist */
{
	Node *p;
	int n;

	if (isarr(v)) {
		ERROR "`%s' is an array name and a function name", v->nval SYNTAX;
		return;
	}
	v->tval = FCN;
	v->sval = (uchar *) st;
	n = 0;	/* count arguments */
	for (p = vl; p; p = p->nnext)
		n++;
	v->fval = n;
	dprintf( ("defining func %s (%d args)\n", v->nval, n) );
}

isarg(s)	/* is s in argument list for current function? */
	uchar *s;
{
	extern Node *arglist;
	Node *p = arglist;
	int n;

	for (n = 0; p != 0; p = p->nnext, n++)
		if (strcmp(((Cell *)(p->narg[0]))->nval, s) == 0)
			return n;
	return -1;
}

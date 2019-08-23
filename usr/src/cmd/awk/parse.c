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

#define	DEBUG
#include "awk.h"
#include "y.tab.h"

Node *
nodealloc(int n)
{
	Node *x;

	x = (Node *)malloc(sizeof (Node) + (n - 1) * sizeof (Node *));
	if (x == NULL)
		FATAL("out of space in nodealloc");
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
	Node *x;

	x = nodealloc(1);
	x->nobj = a;
	x->narg[0] = b;
	return (x);
}

Node *
node2(int a, Node *b, Node *c)
{
	Node *x;

	x = nodealloc(2);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	return (x);
}

Node *
node3(int a, Node *b, Node *c, Node *d)
{
	Node *x;

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
	Node *x;

	x = nodealloc(4);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->narg[2] = d;
	x->narg[3] = e;
	return (x);
}

Node *
stat1(int a, Node *b)
{
	Node *x;

	x = node1(a, b);
	x->ntype = NSTAT;
	return (x);
}

Node *
stat2(int a, Node *b, Node *c)
{
	Node *x;

	x = node2(a, b, c);
	x->ntype = NSTAT;
	return (x);
}

Node *
stat3(int a, Node *b, Node *c, Node *d)
{
	Node *x;

	x = node3(a, b, c, d);
	x->ntype = NSTAT;
	return (x);
}

Node *
stat4(int a, Node *b, Node *c, Node *d, Node *e)
{
	Node *x;

	x = node4(a, b, c, d, e);
	x->ntype = NSTAT;
	return (x);
}

Node *
op1(int a, Node *b)
{
	Node *x;

	x = node1(a, b);
	x->ntype = NEXPR;
	return (x);
}

Node *
op2(int a, Node *b, Node *c)
{
	Node *x;

	x = node2(a, b, c);
	x->ntype = NEXPR;
	return (x);
}

Node *
op3(int a, Node *b, Node *c, Node *d)
{
	Node *x;

	x = node3(a, b, c, d);
	x->ntype = NEXPR;
	return (x);
}

Node *
op4(int a, Node *b, Node *c, Node *d, Node *e)
{
	Node *x;

	x = node4(a, b, c, d, e);
	x->ntype = NEXPR;
	return (x);
}

Node *
celltonode(Cell *a, int b)
{
	Node *x;

	a->ctype = OCELL;
	a->csub = b;
	x = node1(0, (Node *)a);
	x->ntype = NVALUE;
	return (x);
}

Node *
rectonode(void)	/* make $0 into a Node */
{
	extern Cell *literal0;
	return (op1(INDIRECT, celltonode(literal0, CUNK)));
}

Node *
makearr(Node *p)
{
	Cell *cp;

	if (isvalue(p)) {
		cp = (Cell *)(p->narg[0]);
		if (isfcn(cp))
			SYNTAX("%s is a function, not an array", cp->nval);
		else if (!isarr(cp)) {
			xfree(cp->sval);
			cp->sval = (char *)makesymtab(NSYMTAB);
			cp->tval = ARR;
		}
	}
	return (p);
}

int	paircnt;	/* number of them in use */
int	*pairstack;	/* state of each pat,pat */

Node *
pa2stat(Node *a, Node *b, Node *c)	/* pat, pat {...} */
{
	Node *x;

	x = node4(PASTAT2, a, b, c, itonp(paircnt));
	paircnt++;
	x->ntype = NSTAT;
	return (x);
}

Node *
linkum(Node *a, Node *b)
{
	Node *c;

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

/* turn on FCN bit in definition, */
/* body of function, arglist */
void
defn(Cell *v, Node *vl, Node *st)
{
	Node *p;
	int n;

	if (isarr(v)) {
		SYNTAX("`%s' is an array name and a function name", v->nval);
		return;
	}
	if (isarg(v->nval) != -1) {
		SYNTAX("`%s' is both function name and argument name", v->nval);
		return;
	}

	v->tval = FCN;
	v->sval = (char *)st;
	n = 0;	/* count arguments */
	for (p = vl; p != NULL; p = p->nnext)
		n++;
	v->fval = n;
	dprintf(("defining func %s (%d args)\n", v->nval, n));
}

/* is s in argument list for current function? */
/* return -1 if not, otherwise arg # */
int
isarg(const char *s)
{
	extern Node *arglist;
	Node *p = arglist;
	int n;

	for (n = 0; p != NULL; p = p->nnext, n++)
		if (strcmp(((Cell *)(p->narg[0]))->nval, s) == 0)
			return (n);
	return (-1);
}

int
ptoi(void *p)	/* convert pointer to integer */
{
	return ((int)(long)p);	/* swearing that p fits, of course */
}

Node *
itonp(int i)	/* and vice versa */
{
	return ((Node *)(long)i);
}

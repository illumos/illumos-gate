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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "awk.def"
#include "stdio.h"
#include "awk.h"
#include <stdlib.h>


extern NODE *op2();
extern struct fa *cgotofn();
#define	MAXLIN 256
#define	NCHARS 128
#define	NSTATES 256


#define	type(v)	v->nobj
#define	left(v)	v->narg[0]
#define	right(v)	v->narg[1]
#define	parent(v)	v->nnext


#define	LEAF	case CCL: case NCCL: case CHAR: case DOT:
#define	UNARY	case FINAL: case STAR: case PLUS: case QUEST:


/*
 * encoding in tree NODEs:
 * leaf (CCL, NCCL, CHAR, DOT): left is index,
 * right contains value or pointer to value
 * unary (FINAL, STAR, PLUS, QUEST): left is child, right is null
 * binary (CAT, OR): left and right are children
 * parent contains pointer to parent
 */


struct fa {
union {
		ccl_chars_t s;
		int h;
	} cc;
#define	MLCMPLT(m1, l1, m2, l2) ((m1 != m2 &&\
				(int)m1 < (int)m2) ||\
				(m1 == m2 && (int)l1 < (int)l2))
#define	MLCMPLE(m1, l1, m2, l2) ((m1 != m2 &&\
				(int)m1 <= (int)m2) ||\
				(m1 == m2 && (int)l1 <= (int)l2))
#define	MLCMPGT(m1, l1, m2, l2) ((m1 != m2 &&\
				(int)m1 > (int)m2) ||\
				(m1 == m2 && (int)l1 > (int)l2))
#define	MAX_CODESET	3
	struct fa *st;
};


int	*state[NSTATES];
int	*foll[MAXLIN];
int	setvec[MAXLIN];
NODE	*point[MAXLIN];


int	setcnt;
int	line;


static int	ccln_member();
static int	insert_table();
static int	delete_table();
static void	penter(NODE *p);
static void	follow(NODE *v);
static void	overflo(void);
static void	cfoll(NODE *v);
static void	freetr(NODE *p);
#ifdef DEBUG
#define	ddump_table(t, s)	dump_table(t, s)
#else
#define	ddump_table(t, s)
#endif

struct fa *
makedfa(p)	/* returns dfa for tree pointed to by p */
NODE *p;
{
	NODE *p1;
	struct fa *fap;
	p1 = op2(CAT, op2(STAR, op2(DOT, (NODE *) 0,
		(NODE *) 0), (NODE *) 0), p);
		/* put DOT STAR in front of reg. exp. */
	p1 = op2(FINAL, p1, (NODE *) 0);	/* install FINAL NODE */


	line = 0;
	penter(p1);	/* enter parent pointers and leaf indices */
	point[line] = p1;	/* FINAL NODE */
	setvec[0] = 1;		/* for initial DOT STAR */
	cfoll(p1);	/* set up follow sets */
	fap = cgotofn();
	freetr(p1);	/* add this when alloc works */
	return (fap);
}

static void
penter(NODE *p)	/* set up parent pointers and leaf indices */
{
	switch (type(p)) {
		LEAF
			left(p) = (NODE *)line;
			point[line++] = p;
			break;
		UNARY
			penter(left(p));
			parent(left(p)) = p;
			break;
		case CAT:
		case OR:
			penter(left(p));
			penter(right(p));
			parent(left(p)) = p;
			parent(right(p)) = p;
			break;
		default:
			error(FATAL, "unknown type %d in penter\n", type(p));
			break;
	}
}

static void
freetr(NODE *p)	/* free parse tree and follow sets */
{
	switch (type(p)) {
		LEAF
			xfree(foll[(int)left(p)]);
			xfree(p);
			break;
		UNARY
			freetr(left(p));
			xfree(p);
			break;
		case CAT:
		case OR:
			freetr(left(p));
			freetr(right(p));
			xfree(p);
			break;
		default:
			error(FATAL, "unknown type %d in freetr", type(p));
			break;
	}
}
ccl_chars_t *
cclenter(wchar_t *p)
{
	int 		i, cn;
	wchar_t		c, pc;
	wchar_t		*op;
	ccl_chars_t	*new;
	ccl_chars_t	chars[MAXLIN];

	op = p;
	i = 0;
	while ((c = *p++) != 0) {
		if (c == '-' && i > 0)  {
			if (*p != 0) {
				/*
				 * If there are not in same code set,  the
				 * class should be ignore (make two independent
				 * characters)!
				 */
				c = *p++;
				cn = wcsetno(pc);
				if (cn != wcsetno(c) || pc > c)
					goto char_array;
				i = insert_table(chars, i, cn, pc, cn, c);
				continue;
			}
		}
char_array:
		if (i >= MAXLIN)
			overflo();
		cn = wcsetno(c);
		i = insert_table(chars, i, cn, c, cn, c);
		pc = c;
	}
	dprintf("cclenter: in = |%ws|, ", op, NULL, NULL);
	xfree(op);
	i = (i + 1) * sizeof (ccl_chars_t);
	if ((new = (ccl_chars_t *)malloc(i)) == NULL)
		error(FATAL, "out of space in cclenter on %s", op);
	(void) memcpy((char *)new, (char *)chars, i);
	ddump_table(chars, i / 4);


	return (new);
}

static void
overflo(void)
{
	error(FATAL, "regular expression too long\n");
}

static void
cfoll(NODE *v)	/* enter follow set of each leaf of vertex v into foll[leaf] */
{
	int i;
	int prev;
	int *add();


	switch (type(v)) {
		LEAF
			setcnt = 0;
			for (i = 1; i <= line; i++)
				setvec[i] = 0;
			follow(v);
			foll[(int)left(v)] = add(setcnt);
			break;
		UNARY
			cfoll(left(v));
			break;
		case CAT:
		case OR:
			cfoll(left(v));
			cfoll(right(v));
			break;
		default:
			error(FATAL, "unknown type %d in cfoll", type(v));
	}
}

int
first(NODE *p)		/* collects initially active leaves of p into setvec */
	/* returns 0 or 1 depending on whether p matches empty string */
{
	int b;


	switch (type(p)) {
		LEAF
			if (setvec[(int)left(p)] != 1) {
				setvec[(int)left(p)] = 1;
				setcnt++;
			}
			if (type(p) == CCL &&
			(*(ccl_chars_t *)right(p)).cc_cs == (wchar_t)0x0)
				return (0);		/* empty CCL */
			else return (1);
		case FINAL:
		case PLUS:
			if (first(left(p)) == 0)
				return (0);
			return (1);
		case STAR:
		case QUEST:
			first(left(p));
			return (0);
		case CAT:
			if (first(left(p)) == 0 && first(right(p)) == 0)
				return (0);
			return (1);
		case OR:
			b = first(right(p));
			if (first(left(p)) == 0 || b == 0)
				return (0);
			return (1);
	}
	error(FATAL, "unknown type %d in first\n", type(p));
	return (-1);
}

static void
follow(NODE *v)
		/* collects leaves that can follow v into setvec */
{
	NODE *p;


	if (type(v) == FINAL)
		return;
	p = parent(v);
	switch (type(p)) {
		case STAR:
		case PLUS:	first(v);
				follow(p);
				return;


		case OR:
		case QUEST:	follow(p);
				return;


		case CAT:	if (v == left(p)) { /* v is left child of p */
					if (first(right(p)) == 0) {
						follow(p);
						return;
					}
				} else		/* v is right child */
					follow(p);
				return;
		case FINAL:	if (setvec[line] != 1) {
					setvec[line] = 1;
					setcnt++;
				}
				return;
	}
}


/*
 * There are three type of functions for checking member ship.  Because I have
 * been changed structure of CCL tables.  And some CCL tables end up with NULLs
 * but someone has length and will includes NULLs in table as one of data.
 * Please note, CCL table which has a length data and data will include NULLs,
 * it only used within a this source file("b.c").
 */

int				/* is cs thru ce in s? */
ccl_member(int ns, wchar_t cs, int ne, wchar_t ce, ccl_chars_t *s)
{
	/*
	 * The specified range(cs, ce) must be beside the range between
	 * s->cc_start and s->cc_end to determine member.
	 */
	while (s->cc_cs || s->cc_ce) {
		if (MLCMPLE(s->cc_ns, s->cc_cs, ns, cs) &&
				MLCMPLE(ne, ce, s->cc_ne, s->cc_ce))
			return (1);
		s++;
	}
	return (0);
}


static int			/* is cs thru ce in s? */
ccln_member(int ns, wchar_t cs, int ne, wchar_t ce, ccl_chars_t *s, int n)
{
	/*
	 * The specified range(cs, ce) must be beside the range between
	 * s->cc_start and s->cc_end to determine member.
	 */
	while (n-- > 0) {
		if (MLCMPLE(s->cc_ns, s->cc_cs, ns, cs) &&
				MLCMPLE(ne, ce, s->cc_ne, s->cc_ce))
			return (1);
		s++;
	}
	return (0);
}


int
member(wchar_t c, wchar_t *s)	/* is c in s? */
{
	while (*s)
		if (c == *s++)
			return (1);
	return (0);
}

int
notin(int **array, int n, int *prev) /* is setvec in array[0] thru array[n]? */
{
	int i, j;
	int *ptr;
	for (i = 0; i <= n; i++) {
		ptr = array[i];
		if (*ptr == setcnt) {
			for (j = 0; j < setcnt; j++)
				if (setvec[*(++ptr)] != 1) goto nxt;
			*prev = i;
			return (0);
		}
		nxt: /* dummy */;
	}
	return (1);
}


int *
add(int n)
{		/* remember setvec */
	int *ptr, *p;
	int i;
	if ((p = ptr = (int *)malloc((n+1)*sizeof (int))) == NULL)
		overflo();
	*ptr = n;
	dprintf("add(%d)\n", n, NULL, NULL);
	for (i = 1; i <= line; i++)
		if (setvec[i] == 1) {
			*(++ptr) = i;
		dprintf("  ptr = %o, *ptr = %d, i = %d\n", ptr, *ptr, i);
		}
	dprintf("\n", NULL, NULL, NULL);
	return (p);
}


struct fa *
cgotofn()
{
	int i, k;
	int *ptr;
	int ns, ne;
	wchar_t cs, ce;
	ccl_chars_t *p;
	NODE *cp;
	int j, n, s, ind, numtrans;
	int finflg;
	int curpos, num, prev;
	struct fa *where[NSTATES];


	struct {
		ccl_chars_t	cc;
		int		n;
	} fatab[257];
	struct fa *pfa;


	char index[MAXLIN];
	char iposns[MAXLIN];
	int sposns[MAXLIN];
	int spmax, spinit;
	ccl_chars_t symbol[NCHARS];
	ccl_chars_t isyms[NCHARS];
	ccl_chars_t ssyms[NCHARS];
	int ssmax, symax, ismax, ssinit;


	wchar_t hat;
	int hatcn;


	for (i = 0; i <= line; i++) index[i] = iposns[i] = setvec[i] = 0;
	isyms[0].cc_cs = isyms[0].cc_ce = (wchar_t)0x0;
	for (i = 0; i < NCHARS; i++)
		isyms[i] = symbol[i] = ssyms[i] = isyms[0];
	symax = 0;
	setcnt = 0;
	/* compute initial positions and symbols of state 0 */
	ismax = 0;
	ssmax = 0;
	ptr = state[0] = foll[0];
	spinit = *ptr;
	hat = HAT;
	hatcn = wcsetno(hat);
	for (i = 0; i < spinit; i++) {
		curpos = *(++ptr);
		sposns[i] = curpos;
		iposns[curpos] = 1;
		cp = point[curpos];
		dprintf("i= %d, spinit = %d, curpos = %d\n", i, spinit, curpos);
		switch (type(cp)) {
			case CHAR:
				k = (int)right(cp);
				ns = wcsetno(k);
				if (! ccln_member(ns, k, ns, k,
							isyms, ismax)) {
					ismax = insert_table(isyms, ismax,
								ns, k, ns, k);
				}
				ssyms[ssmax].cc_ns = ns;
				ssyms[ssmax].cc_cs = k;
				ssyms[ssmax].cc_ne = ns;
				ssyms[ssmax++].cc_ce = k;
				break;
			case DOT:
				cs = WC_VERY_SMALL;
				ns = 0;
				ce = HAT - 1;
				ne = hatcn;
				if (! ccln_member(ns, cs, ne, ce,
							isyms, ismax)) {
					ismax = insert_table(isyms, ismax,
								ns, cs, ne, ce);
				}
				ssyms[ssmax].cc_cs = cs;
				ssyms[ssmax].cc_ns = ns;
				ssyms[ssmax].cc_ce = ce;
				ssyms[ssmax++].cc_ne = ne;
				cs = HAT + 1;
				ns = hatcn;
				ce = WC_VERY_LARGE;
				ne = MAX_CODESET;
				if (! ccln_member(ns, cs, ne, ce,
							isyms, ismax)) {
					ismax = insert_table(isyms, ismax,
								ns, cs, ne, ce);
				}
				ssyms[ssmax].cc_cs = cs;
				ssyms[ssmax].cc_ns = ns;
				ssyms[ssmax].cc_ce = ce;
				ssyms[ssmax++].cc_ne = ne;
				break;
			case CCL:
				cs = HAT;
				ns = hatcn;
				for (p = (ccl_chars_t *)right(cp);
					p->cc_cs; p++) {
					if ((p->cc_ns != ns ||\
					p->cc_cs != cs) &&\
				!ccln_member(p->cc_ns, p->cc_cs,
				p->cc_ne, p->cc_ce, isyms, ismax)) {
						ismax = insert_table(isyms,
				ismax, p->cc_ns, p->cc_cs, p->cc_ne, p->cc_ce);
					}
					ssyms[ssmax++] = *p;
				}
				break;
			case NCCL:
				ns = 0;
				cs = WC_VERY_SMALL;
				for (p = (ccl_chars_t *)right(cp);
					p->cc_cs; p++) {
					if ((ns != hatcn || p->cc_cs != HAT) &&
						! ccln_member(ns, cs,
							p->cc_ns, p->cc_cs-1,
								isyms, ismax)) {
						ismax = insert_table(isyms,
								ismax,
								ns, cs,
								p->cc_ns,
								p->cc_cs-1);
					}
					ssyms[ssmax].cc_ns = ns;
					ssyms[ssmax].cc_cs = cs;
					ssyms[ssmax].cc_ne = p->cc_ns;
					ssyms[ssmax++].cc_ce = p->cc_cs-1;
					if (p->cc_ce == (wchar_t)0x0) {
						ns = p->cc_ns;
						cs = p->cc_cs + 1;

					} else {
						ns = p->cc_ne;
						cs = p->cc_ce + 1;
					}
				}
				if ((ns != hatcn || cs != HAT) &&
					! ccln_member(ns, cs,
						MAX_CODESET, WC_VERY_LARGE,
							isyms, ismax)) {
					ismax = insert_table(isyms, ismax,
							ns, cs, MAX_CODESET,
							WC_VERY_LARGE);
				}
				ssyms[ssmax].cc_ns = ns;
				ssyms[ssmax].cc_cs = cs;
				ssyms[ssmax].cc_ne = MAX_CODESET;
				ssyms[ssmax++].cc_ce = WC_VERY_LARGE;
				break;
		}
	}
	ssinit = ssmax;
	symax = 0;
	n = 0;
	for (s = 0; s <= n; s++)  {
		dprintf("s = %d\n", s, NULL, NULL);
		ind = 0;
		numtrans = 0;
		finflg = 0;
		if (*(state[s] + *state[s]) == line) {		/* s final? */
			finflg = 1;
			goto tenter;
		}
		spmax = spinit;
		ssmax = ssinit;
		ptr = state[s];
		num = *ptr;
		for (i = 0; i < num; i++) {
			curpos = *(++ptr);
			if (iposns[curpos] != 1 && index[curpos] != 1) {
				index[curpos] = 1;
				sposns[spmax++] = curpos;
			}
			cp = point[curpos];
			switch (type(cp)) {
				case CHAR:
					k = (int)right(cp);
					ns = wcsetno(k);
					if (! ccln_member(ns, k, ns, k,
							isyms, ismax) &&
						! ccln_member(ns, k, ns, k,
							symbol, symax)) {
						symax = insert_table(symbol,
									symax,
									ns, k,
									ns, k);
					}
					ssyms[ssmax].cc_ns = ns;
					ssyms[ssmax].cc_cs = k;
					ssyms[ssmax].cc_ne = ns;
					ssyms[ssmax++].cc_ce = k;
					break;
				case DOT:
					cs = WC_VERY_SMALL;
					ns = 0;
					ce = HAT - 1;
					ne = hatcn;
					if (! ccln_member(ns, cs, ne, ce,
							isyms, ismax) &&
						! ccln_member(ns, cs, ne, ce,
							symbol, symax)) {
						symax = insert_table(symbol,
									symax,
									ns, cs,
									ne, ce);
					}
					ssyms[ssmax].cc_cs = cs;
					ssyms[ssmax].cc_ns = ns;
					ssyms[ssmax].cc_ce = ce;
					ssyms[ssmax++].cc_ne = ne;
					cs = HAT + 1;
					ns = hatcn;
					ce = WC_VERY_LARGE;
					ne = MAX_CODESET;
					if (! ccln_member(ns, cs, ne, ce,
								isyms, ismax) &&
						! ccln_member(ns, cs, ne, ce,
							symbol, symax)) {
						symax = insert_table(symbol,
									symax,
									ns, cs,
									ne, ce);
					}
					ssyms[ssmax].cc_cs = cs;
					ssyms[ssmax].cc_ns = ns;
					ssyms[ssmax].cc_ce = ce;
					ssyms[ssmax++].cc_ne = ne;
					break;
				case CCL:
					cs = HAT;
					ns = hatcn;
					for (p = (ccl_chars_t *)right(cp);
						p->cc_cs; p++) {
						if ((p->cc_ns != ns ||
							p->cc_cs != cs) &&
							! ccln_member(p->cc_ns,
							p->cc_cs, p->cc_ne,
						p->cc_ce, isyms, ismax) &&
						!ccln_member(p->cc_ns, p->cc_cs,
						p->cc_ne, p->cc_ce, symbol,
						symax)) {
							symax = insert_table(
						symbol, symax, p->cc_ns,
						p->cc_cs, p->cc_ne, p->cc_ce);
						}
						ssyms[ssmax++] = *p;
					}
					break;
				case NCCL:
					ns = 0;
					cs = WC_VERY_SMALL;
		for (p = (ccl_chars_t *)right(cp); p->cc_cs; p++) {
			if ((p->cc_ns != hatcn || p->cc_cs != HAT) &&
					! ccln_member(ns, cs, p->cc_ns,
					p->cc_cs-1, isyms, ismax) &&
					! ccln_member(ns, cs, p->cc_ns,
					p->cc_cs-1, symbol, symax)) {
				symax = insert_table(symbol,
					symax, ns, cs, p->cc_ns, p->cc_cs-1);
						}
						ssyms[ssmax].cc_ns = ns;
						ssyms[ssmax].cc_cs = cs;
						ssyms[ssmax].cc_ne = p->cc_ns;
						ssyms[ssmax++].cc_ce
								= p->cc_cs-1;
						if (p->cc_ce == (wchar_t)0x0) {
							ns = p->cc_ns;
							cs = p->cc_cs + 1;

						} else {
							ns = p->cc_ne;
							cs = p->cc_ce + 1;
						}
					}
		if ((ns != hatcn || cs != HAT) && ! ccln_member(ns, cs,
				MAX_CODESET, WC_VERY_LARGE, isyms, ismax) &&
				! ccln_member(ns, cs, MAX_CODESET,
					WC_VERY_LARGE, symbol, symax)) {
			symax = insert_table(symbol, symax, ns, cs,
								MAX_CODESET,
								WC_VERY_LARGE);
					}
					ssyms[ssmax].cc_ns = ns;
					ssyms[ssmax].cc_cs = cs;
					ssyms[ssmax].cc_ne = MAX_CODESET;
					ssyms[ssmax++].cc_ce = WC_VERY_LARGE;
					break;
			}
		}
		for (j = 0; j < ssmax; j++) {	/* nextstate(s, ssyms[j]) */
			ns = ssyms[j].cc_ns;
			cs = ssyms[j].cc_cs;
			ne = ssyms[j].cc_ne;
			ce = ssyms[j].cc_ce;
dprintf("j = %d, cs = %o, ce = %o\n", j, cs, ce);
			symax = delete_table(symbol, symax, ns, cs, ne, ce);
			setcnt = 0;
			for (k = 0; k <= line; k++) setvec[k] = 0;
			for (i = 0; i < spmax; i++) {
				index[sposns[i]] = 0;
				cp = point[sposns[i]];
				if ((k = type(cp)) != FINAL) {
					if (k == CHAR && ns == ne && cs == ce &&
						cs == (int)right(cp) ||
						k == DOT || k == CCL &&
						ccl_member(ns, cs, ne, ce,
						(ccl_chars_t *)right(cp)) ||
						k == NCCL &&
						!ccl_member(ns, cs, ne, ce,
						(ccl_chars_t *)right(cp))) {
						ptr = foll[sposns[i]];
						num = *ptr;
						for (k = 0; k < num; k++) {
						if (setvec[*(++ptr)] != 1 &&
							iposns[*ptr] != 1) {
							setvec[*ptr] = 1;
								setcnt++;
							}
						}
					}
				}
			} /* end nextstate */
			if (notin(state, n, &prev)) {
				if (n >= NSTATES - 1) {
		printf("cgotofn: notin; state = %d, n = %d\n", state, n, NULL);
					overflo();
				}
				state[++n] = add(setcnt);
				dprintf("	delta(%d,[%o,%o])",
					s, cs, ce);
				dprintf(" = %d, ind = %d\n", n, ind+1, NULL);
				fatab[++ind].cc.cc_ns = ns;
				fatab[ind].cc.cc_cs = cs;
				fatab[ind].cc.cc_ne = ne;
				fatab[ind].cc.cc_ce = ce;
				fatab[ind].n = n;
				numtrans++;
			} else {
				if (prev != 0) {
					dprintf("	delta(%d,[%o,%o])",
						s, cs, ce);
					dprintf("= %d, ind = %d\n",
						prev, ind+1, NULL);
					fatab[++ind].cc.cc_ns = ns;
					fatab[ind].cc.cc_cs = cs;
					fatab[ind].cc.cc_ne = ne;
					fatab[ind].cc.cc_ce = ce;
					fatab[ind].n = prev;
					numtrans++;
				}
			}
		}
	tenter:
		if ((pfa = (struct fa *)malloc((numtrans + 1)
						* sizeof (struct fa))) == NULL)
			overflo();
		where[s] = pfa;
		if (finflg)
			pfa->cc.h = -1;		/* s is a final state */
		else
			pfa->cc.h = numtrans;
		pfa->st = 0;
		for (i = 1, pfa += 1; i <= numtrans; i++, pfa++) {
			pfa->cc.s = fatab[i].cc;
			pfa->st = (struct fa *)fatab[i].n;
		}
	}
	for (i = 0; i <= n; i++) {
		if (i != 0)	/* state[0] is freed later in freetr() */
			xfree(state[i]);	/* free state[i] */
		pfa = where[i];
		pfa->st = where[0];
		dprintf("state %d: (%o)\n", i, pfa, NULL);
		dprintf("	numtrans = %d,	default = %o\n",
			pfa->cc.h, pfa->st, NULL);
		for (k = 1; k <= pfa->cc.h; k++) {
			(pfa+k)->st = where[(int)(pfa+k)->st];
			dprintf("	char = [%o,%o],	nextstate = %o\n",
				(pfa+k)->cc.s.cc_cs, (pfa+k)->cc.s.cc_ce,
				(pfa+k)->st);
		}
	}
	pfa = where[0];
	if ((num = pfa->cc.h) < 0)
		return (where[0]);
	for (pfa += num; num; num--, pfa--)
		if (pfa->cc.s.cc_ns == hatcn && pfa->cc.s.cc_cs == HAT) {
			return (pfa->st);
		}
	return (where[0]);
}


/*
 * Insert CCL entry to CCL table with maintain optimized order.
 */
static int
insert_table(ccl_chars_t *table_base, int table_size, int ns, wchar_t cs,
	int ne, wchar_t ce)
{
	int		i;
	int		tns, tne;
	wchar_t		tcs, tce;
	ccl_chars_t	*table;
	ccl_chars_t	*saved_table;
	int		saved_i;




	dprintf("Inserting {%o, %o} to table %o\n", cs, ce, table_base);
	/*
	 * Searching the table to find out where should put the new item.
	 */
	for (i = 0, table = table_base; i < table_size; i++, table++) {
		tns = table->cc_ns;
		tcs = table->cc_cs;
		tne = table->cc_ne;
		tce = table->cc_ce;
		if (MLCMPLT(ne, ce, tns, (tcs - 1))) {
			/*
			 * Quick! insert to font of current table entries.
			 */
			table_size++;
			for (; i < table_size; i++, table++) {
				tns = table->cc_ns;
				tcs = table->cc_cs;
				tne = table->cc_ne;
				tce = table->cc_ce;
				table->cc_ns = ns;
				table->cc_cs = cs;
				table->cc_ne = ne;
				table->cc_ce = ce;
				ns = tns;
				cs = tcs;
				ne = tne;
				ce = tce;
			}
			goto add_null;
		} else if (MLCMPLE(tns, (tcs - 1), ns, cs) &&
				MLCMPLE(ns, cs, tne, (tce + 1))) {
			/*
			 * Starting point is within the current entry.
			 */
			if (MLCMPGT(tns, tcs, ns, cs)) {
				table->cc_ns = ns;
				table->cc_cs = cs;
			}
			if (MLCMPLE(ne, ce, tne, tce)) {
				return (table_size);
			}
			goto combine;
		}
	}


	/*
	 * Adding new one to end of table.
	 */
	table->cc_ns = ns;
	table->cc_cs = cs;
	table->cc_ne = ne;
	table->cc_ce = ce;


	table_size++;
	goto add_null;




	combine:
	/*
	 * Check and try to combine the new entry with rest of entries.
	 */
	if ((i + 1) >= table_size) {
		table->cc_ne = ne;
		table->cc_ce = ce;
		return (table_size);
	}


	saved_table = table++;
	saved_i = i++;


	/*
	 * Finding the spot where we should put the end point.
	 */
	for (; i < table_size; i++, table++) {
		if (MLCMPLT(ne, ce, table->cc_ns, (table->cc_cs - 1))) {
			break;
		} else
		if (MLCMPLE(table->cc_ns, (table->cc_cs - 1), ne, ce) &&
			MLCMPLE(ne, ce, table->cc_ne, (table->cc_ce + 1))) {
			/*
			 * Tack with this table.
			 */
			if (MLCMPLT(ne, ce, table->cc_ne, table->cc_ce)) {
				ne = table->cc_ne;
				ce = table->cc_ce;
			}
			table++;
			i++;
			break;
		}
	}


	saved_table->cc_ne = ne;
	saved_table->cc_ce = ce;
	saved_i = table_size - (i - saved_i - 1);


	/*
	 * Moving the rest of entries.
	 */
	for (; i < table_size; i++, table++)
		*(++saved_table) = *table;
	table_size = saved_i;


add_null:
	table_base[table_size].cc_cs = (wchar_t)0x0;
	table_base[table_size].cc_ce = (wchar_t)0x0;


	return (table_size);
}




static int
delete_table(ccl_chars_t *table_base, int table_size, int ns, wchar_t cs,
		int ne, wchar_t ce)
{
	int		i;
	int		saved_i;
	ccl_chars_t	*table;
	ccl_chars_t	*saved_table;
	int		tns;
	wchar_t		tcs;
	int		tne;
	wchar_t		tce;




	for (i = 0, table = table_base; i < table_size; i++, table++) {
		tns = table->cc_ns;
		tcs = table->cc_cs;
		tne = table->cc_ne;
		tce = table->cc_ce;
		if (MLCMPLT(ne, ce, tns, tcs))
			return (table_size);
		else if (MLCMPLT(ne, ce, tne, tce)) {
			if (MLCMPLE(ns, cs, tns, tcs)) {
				/*
				 * Shrink type 1.
				 */
				table->cc_ns = ne;
				table->cc_cs = ce + 1;
				return (table_size);

			} else {
				/*
				 * Spliting !!
				 */
				table->cc_ns = ne;
				table->cc_cs = ce + 1;
				tne = ns;
				tce = cs - 1;
				table_size++;
				for (; i < table_size; i++, table++) {
					ns = table->cc_ns;
					cs = table->cc_cs;
					ne = table->cc_ne;
					ce = table->cc_ce;
					table->cc_ns = tns;
					table->cc_cs = tcs;
					table->cc_ne = tne;
					table->cc_ce = tce;
					tns = ns;
					tcs = cs;
					tne = ne;
					tce = ce;
				}
				return (table_size);
			}

		} else if (MLCMPLE(ns, cs, tne, tce)) {
			if (MLCMPGT(ns, cs, tns, tcs)) {
				/*
				 * Shrink current table(type 2).
				 */
				table->cc_ne = ns;
				table->cc_ce = cs - 1;
				table++;
				i++;
			}
			/*
			 * Search for the end point.
			 */
			saved_i = i;
			saved_table = table;
			for (; i < table_size; i++, table++) {
				if (MLCMPLT(ne, ce,
						table->cc_ns, table->cc_cs)) {
					/*
					 * Easy point, no shrinks!
					 */
					break;

				} else if (MLCMPGT(table->cc_ne, table->cc_ce,
						ne, ce)) {
					/*
					 * Shrinking...
					 */
					table->cc_ns = ne;
					table->cc_cs = ce + 1;
					break;
				}


			}
			/*
			 * Moving(removing) backword.
			 */
			saved_i = table_size - (i - saved_i);
			for (; i < table_size; i++)
				*saved_table++ = *table++;
			return (saved_i);
		}
	}
	return (table_size);
}


#ifdef DEBUG
dump_table(ccl_chars_t *table, int size)
{
	int	i;




	if (! dbg)
		return;


	printf("Duming table %o with size %d\n", table, size);
	size++;	/* To watch out NULL */
	for (i = 0; i < size; i++, table++) {
		printf("{%3o, %3o}, ", table->cc_cs, table->cc_ce);
	}
	printf("\n");
}
#endif /* DEBUG */



int
match(struct fa *pfa, wchar_t *p)
{
	int count;
	int n, ns, ne;
	wchar_t c, cs, ce;


	if (p == 0)
		return (0);
	if (pfa->cc.h == 1) { /* fast test for first character, if possible */
		ns = (++pfa)->cc.s.cc_ns;
		cs = (pfa)->cc.s.cc_cs;
		ne = (pfa)->cc.s.cc_ne;
		ce = (pfa)->cc.s.cc_ce;
		do {
			c = *p;
			n = wcsetno(c);
			if (MLCMPLE(ns, cs, n, c) &&
				MLCMPLE(n, c, ne, ce)) {
				p++;
				pfa = pfa->st;
				goto adv;
			}
		} while (*p++ != 0);
		return (0);
	}
	adv: if ((count = pfa->cc.h) < 0)
		return (1);
	do {
		c = *p;
		n = wcsetno(c);
		for (pfa += count; count; count--, pfa--) {
			ns = (pfa)->cc.s.cc_ns;
			cs = (pfa)->cc.s.cc_cs;
			ne = (pfa)->cc.s.cc_ne;
			ce = (pfa)->cc.s.cc_ce;
			if (MLCMPLE(ns, cs, n, c) && MLCMPLE(n, c, ne, ce))
				break;
		}
		pfa = pfa->st;
		if ((count = pfa->cc.h) < 0)
			return (1);
	} while (*p++ != 0);
	return (0);
}

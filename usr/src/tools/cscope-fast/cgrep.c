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
/*	Copyright (c) 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	cscope - interactive C symbol or text cross-reference
 *
 *	text searching functions
 */

#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include <unistd.h>
#include "library.h"

typedef enum {
	NO = 0,
	YES = 1
} BOOL;

typedef struct re_bm {
	int delta0[256];
	int *delta2;
	uchar_t *cmap;
	uchar_t *bmpat;
	int patlen;
} re_bm;

typedef struct Link {
	uchar_t lit;
	struct Node *node;
	struct Link *next;
} Link;

typedef struct Node {
	short out;
	short d;
	short shift1;
	short shift2;
	long id;
	struct Node **tab;
	Link *alts;
	struct Node *fail;
} Node;

typedef struct re_cw {
	int maxdepth, mindepth;
	long nodeid;
	int step[256];
	uchar_t *cmap;
	struct Node *root;
} re_cw;

typedef enum {
	/* lit expression types */
	Literal, Dot, Charclass, EOP,

	/* non-lit expression types */
	Cat, Alternate, Star, Plus, Quest,

	/* not really expression types, just helping */
	Lpar, Rpar, Backslash

} Exprtype;

typedef int ID;

typedef struct Expr {
	Exprtype type;	/* Type of expression (in grammar) */
	ID id;		/* unique ID of lit expression  */
	int lit;	/* Literal character or tag */
	int flen;	/* Number of following lit expressions */
	ID *follow;	/* Array of IDs of following lit expressions */
	struct Expr *l; /* pointer to Left child (or ccl count) */
	struct Expr *r; /* pointer to Right child (or ccl mask) */
	struct Expr *parent; /* pointer to Parent */
} Expr;

typedef struct State {
	struct State *tab[256];
	int cnt; /* number of matched chars on full match, -1 otherwise  */
	int npos;	/* number of IDs in position set for this state. */
	int pos;	/* index into posbase for beginning of IDs */
} State;

typedef struct FID {
	ID	id;	/* Lit Expression id */
	int	fcount; /* Number of Lit exp matches before this one. */
} FID;

typedef struct Positionset {
	int count;	/* Number of lit exps in position set */
	ID last;	/* ID of last lit exp in position set */
	FID *base;	/* array of MAXID FIDS */
			/* 0 means not in position set */
			/* -1 means first in position set */
			/* n (>0) is ID of prev member of position set. */
} Positionset;

typedef struct re_re {
	FID  *posbase;	/* Array of IDs from all states */
	int nposalloc;	/* Allocated size of posbase */
	int posnext;	/* Index into free space in posbase */
	int posreset;	/* Index into end of IDs for initial state in posbase */
	int maxid;	/* Number of (also maximum ID of) lit expressions */
	Expr *root;	/* Pointer to root (EOP) expression */
	Expr **ptr;	/* Pointer to array of ptrs to lit expressions. */
	uchar_t *cmap;	/* Character mapping array */
	Positionset firstpos;
	Positionset tmp;
	int nstates;	/* Number of current states defined */
	int statelim;	/* Limit on number of states before flushing */
	State *states;	/* Array of states */
	State istate;	/* Initial state */
} re_re;

typedef struct {
	uchar_t *cmap;
	re_re *re_ptr;
	re_bm *bm_ptr;
	re_cw *cw_ptr;
	BOOL fullmatch;
	BOOL (*procfn)();
	BOOL (*succfn)();
	uchar_t *loc1;
	uchar_t *loc2;
	uchar_t *expression;
} PATTERN;

typedef enum {
	BEGIN,		/* File is not yet in buffer at all */
	MORE,		/* File is partly in buffer */
	NO_MORE		/* File has been completely read into buffer */
} FILE_STAT;

typedef struct {
	uchar_t	*prntbuf; /* current line of input from data file */
	uchar_t	*newline; /* end of line (real or sentinel \n) */
	long	ln;	/* line number */
} LINE;

#define	NL '\n'

#define	CCL_SIZ		32
#define	CCL_SET(a, c)	((a)[(c) >> 3] |= bittab[(c) & 07])
#define	CCL_CLR(a, c)	((a)[(c) >> 3] &= ~bittab[(c) & 07])
#define	CCL_CHK(a, c)	((a)[(c) >> 3] & bittab[(c) & 07])

#define	ESIZE (BUFSIZ)
#define	MAXBUFSIZE (64*BUFSIZ)

#define	MAXMALLOCS	1024
#define	MAXLIT	256	/* is plenty big enough */
#define	LARGE	MAXBUFSIZE+ESIZE+2

#define	CLEAR(r, rps)	(void) memset((char *)(rps)->base, 0, \
			    (int)((r)->maxid * sizeof (FID))), \
			    (rps)->count = 0, (rps)->last = -1
#define	SET(rps, n, cnt) { \
	if ((rps)->base[n].id == 0) {\
		(rps)->count++;\
		(rps)->base[n].fcount = (cnt);\
		(rps)->base[n].id = (rps)->last;\
		(rps)->last = (n);\
	} else if ((cnt) > (rps)->base[n].fcount) {\
		(rps)->base[n].fcount = (cnt);\
	}}

#define	START	{ _p = tmp; }
#define	ADDL(c)	{ if (_p >= &tmp[MAXLIT]) _p--; *_p++ = c; }
#define	FINISH	{ ADDL(0) if ((_p-tmp) > bestlen) \
		    (void) memmove(best, tmp, bestlen = _p-tmp); }


#define	NEW(N)	(froot?(t = froot, froot = froot->next, t->next = NULL, \
		    t->node = N, t): newlink(0, N))
#define	ADD(N)	if (qtail) qtail = qtail->next = NEW(N); \
			else qtail = qhead = NEW(N)
#define	DEL()	{ Link *_l = qhead; if ((qhead = qhead->next) == NULL) \
			{ qtail = NULL; } _l->next = froot; froot = _l; }

static uchar_t	*buffer;
static uchar_t	*bufend;
static FILE	*output;
static char	*format;
static char	*file;
static int	file_desc;
static FILE_STAT file_stat;
static PATTERN	match_pattern;
static uchar_t	char_map[2][256];
static int	iflag;
static Exprtype	toktype;
static int	toklit, parno, maxid;
static uchar_t	tmp[MAXLIT], best[MAXLIT];
static uchar_t	*_p;
static int	bestlen;
static Node	*next_node;
static Link	*froot, *next_link;
static jmp_buf	env;

static int nmalloc;
static uchar_t	*mallocs[MAXMALLOCS];

static uchar_t	bittab[] = { 1, 2, 4, 8, 16, 32, 64, 128 };

#ifdef	DEBUG
#define		TRACE(n)	(n < debug)
#define		EPRINTSIZE	50000
static void spr(int c, int *p, uchar_t *buf);
void epr(Expr *e, uchar_t *res);
static int debug = 12;
#endif

static void init_file(LINE *cur_ptr);
static void get_line(LINE *cur_ptr, uchar_t *s);
static void get_ncount(LINE *cur_ptr, uchar_t *s);
static int execute(void);
static State *startstate(re_re *r);
static State *stateof(re_re *r, Positionset *ps);
static State *nextstate(re_re *r, State *s, int a);
static State *addstate(re_re *r, Positionset *ps, int cnt);
static BOOL match(Expr *e, int a);
static BOOL first_lit(Positionset *fpos, Expr *e);
static void eptr(re_re *r, Expr *e);
static void efollow(re_re *r, Positionset *fpos, Expr *e);
static void follow(Positionset *fpos, Expr *e);
static void followstate(re_re *r, State *s, int a, Positionset *fpos);
static Expr *eall(re_re *r, PATTERN *pat);
static Expr *d0(re_re *r, PATTERN *pat);
static Expr *d1(re_re *r, PATTERN *pat);
static Expr *d2(re_re *r, PATTERN *pat);
static Expr *d3(re_re *r, PATTERN *pat);
static Expr *newexpr(Exprtype t, int lit, Expr *left, Expr *right);
static void lex(re_re *r, PATTERN *pat);
static int re_lit(PATTERN *pat, uchar_t **b, uchar_t **e);
static void traverse(PATTERN *pat, Expr *e);
static int ccl(PATTERN *pat, uchar_t *tab);
static BOOL altlist(), word();
static BOOL altlist(Expr *e, uchar_t *buf, re_cw *pat);
static Node *newnode(re_cw *c, int d);
static Link *newlink(uchar_t lit, Node *n);
static void fail(Node *root);
static void zeroroot(Node *root, Node *n);
static void shift(re_cw *c);
static void shifttab(Node *n);
static void shiftprop(re_cw *c, Node *n);
static void delta_2(re_bm *b);
static int getstate(re_re *r, Positionset *ps);
static void savestate(re_re *r);
static void stateinit(re_re *r);
static re_bm *re_bmcomp(uchar_t *pb, uchar_t *pe, uchar_t *cmap);
static re_cw *re_cwinit(uchar_t *cmap);
static re_cw *re_recw(re_re *r, uchar_t *map);
static re_re *egprep(PATTERN *pat);
static void re_cwadd(re_cw *c, uchar_t *s, uchar_t *e);
static void re_cwcomp(re_cw *c);
static void eginit(re_re *r);
static BOOL re_bmexec(PATTERN *pat, uchar_t *s, uchar_t *e, uchar_t **mb,
    uchar_t **me);
static BOOL re_cwexec(PATTERN *pat, uchar_t *rs, uchar_t *re, uchar_t **mb,
    uchar_t **me);
static BOOL re_reexec(PATTERN *pat, uchar_t *b, uchar_t *e, uchar_t **mb,
    uchar_t **me);
static uchar_t *egmalloc(size_t n);
static void fgetfile(LINE *cur_ptr);
static void dogre(PATTERN *pat);
static BOOL pattern_match(PATTERN *pat, LINE *lptr);
static BOOL fixloc(uchar_t **mb, uchar_t **me);
static BOOL grepmatch(PATTERN *pat, uchar_t **mb, uchar_t **me);
static void err(char *s);

static char *message;

void
egrepcaseless(int i)
{
	iflag = i;	/* simulate "egrep -i" */
}

char *
egrepinit(char *expression)
{
	static int firsttime = 1;
	int i;

	if (firsttime) {
		firsttime = 0;
		for (i = 0; i < 256; i++) {
			char_map[0][i] = (uchar_t)i;
			char_map[1][i] = tolower(i);
		}
	}
	for (i = 0; i < nmalloc; i ++)
		free(mallocs[i]);
	nmalloc = 0;
	message = NULL;

	match_pattern.expression = (uchar_t *)expression;
	match_pattern.cmap = char_map[iflag];
	if (setjmp(env) == 0) {
		dogre(&match_pattern);
#ifdef	DEBUG
		{
		PATTERN *p = match_pattern;
		if (p->procfn == re_bmexec)
			if (!p->fullmatch)
				if (p->succfn == re_reexec)
					printf("PARTIAL BOYER_MOORE\n");
				else
					printf("PARTIAL B_M with GREP\n");
			else
				printf("FULL BOYER_MOORE\n");
		else if (p->procfn == re_cwexec)
			printf("C_W\n");
		else
			printf("GENERAL\n");
		}
#endif
	}
	return (message);
}

static void
dogre(PATTERN *pat)
{
	uchar_t *lb, *le;

#ifdef	DEBUG
	printf("PATTERN %s\n", pat->expression);
#endif
	pat->re_ptr = egprep(pat);
	bestlen = re_lit(pat, &lb, &le);

	if (bestlen && pat->fullmatch) { /* Full Boyer Moore */
#ifdef	DEBUG
		printf("BESTLEN %d\n", bestlen);
		{
			uchar_t *p;
			for (p = lb; p < le; p++) printf("%c", *p);
			printf("\n");
		}
#endif
		pat->bm_ptr = re_bmcomp(lb, le, pat->cmap);
		pat->procfn = re_bmexec;
		return;
	}
	if (bestlen > 1) {
			/* Partial Boyer Moore */
		pat->bm_ptr = re_bmcomp(lb, le, pat->cmap);
		pat->procfn = re_bmexec;
		pat->fullmatch = NO;
	} else {
		pat->fullmatch = YES;
		if ((pat->cw_ptr = re_recw(pat->re_ptr, pat->cmap)) != NULL) {
			pat->procfn = re_cwexec; /* CW */
			return;
		}
	}
	/* general egrep regular expression */
	pat->succfn = re_reexec;

	if (pat->fullmatch) {
		pat->procfn = pat->succfn;
		pat->succfn = NULL;
	}
}

static BOOL
fixloc(uchar_t **mb, uchar_t **me)
{
	/* Handle match to null string */

	while (*me <= *mb)
		(*me)++;

	if (*(*me - 1) != NL)
		while (**me != NL)
			(*me)++;

	/* Handle match to new-line only */

	if (*mb == *me - 1 && **mb == NL) {
		(*me)++;
	}

	/* Handle match including beginning or ending new-line */

	if (**mb == NL)
		(*mb)++;
	if (*(*me - 1) == NL)
		(*me)--;
	return (YES);
}

static BOOL
grepmatch(PATTERN *pat, uchar_t **mb, uchar_t **me)
{
	uchar_t *s, *f;

	if (pat->fullmatch)
		return (fixloc(mb, me));

	for (f = *me - 1; *f != NL; f++) {
	}
	f++;
	for (s = *mb; *s != NL; s--) {
	}

	if ((*pat->succfn)(pat, s, f, mb, me)) {
		return (YES);
	} else {
		*mb = f;
		return (NO);
	}
}

static void
eginit(re_re *r)
{
	unsigned int n;

	r->ptr = (Expr **)egmalloc(r->maxid * sizeof (Expr *));
	eptr(r, r->root);
	n = r->maxid * sizeof (FID);
	r->firstpos.base = (FID *)egmalloc(n);
	r->tmp.base = (FID *)egmalloc(n);
	CLEAR(r, &r->firstpos);
	if (!first_lit(&r->firstpos, r->root->l)) {
		/*
		 * This expression matches the null string!!!!
		 * Add EOP to beginning position set.
		 */
		SET(&r->firstpos, r->root->id, 0)
		/* (void) printf("first of root->l == 0, b=%s\n", b); */
	}
	stateinit(r);
	(void) addstate(r, &r->firstpos, 0);
	savestate(r);
}

static void
eptr(re_re *r, Expr *e)
{
	if ((e->id < 0) || (e->id >= r->maxid)) {
		err("internal error");
	}
	r->ptr[e->id] = e;
	if (e->type != Charclass) {
		if (e->l) eptr(r, e->l);
		if (e->r) eptr(r, e->r);
	}
}

static BOOL
re_reexec(PATTERN *pat, uchar_t *b, uchar_t *e, uchar_t **mb, uchar_t **me)
{
	re_re *r = pat->re_ptr;
	State *s, *t;

#ifdef	DEBUG
	if (TRACE(10)) {
		uchar_t buf[EPRINTSIZE];
		epr(r->root, buf);
		(void) printf("expr='%s'\n", buf);
	}
#endif
	s = startstate(r);

	for (;;) {
		uchar_t c;

		if (s->cnt >= 0) {
#ifdef	DEBUG
			if (TRACE(6))
				(void) printf("match at input '%s'\n", b);
#endif
			*mb = b - s->cnt;
			*me = b;
			if (fixloc(mb, me))
				return (YES);
		}

		if (b >= e) break;
		c = pat->cmap[*b];
#ifdef	DEBUG
		if (TRACE(4))
			(void) printf("state %d: char '%c'\n", s-r->states, *b);
#endif
		if ((t = s->tab[c]) != NULL) s = t;
		else s = nextstate(r, s, (int)c);
		b++;
	}
#ifdef	DEBUG
	if (TRACE(3)) {
		uchar_t buf[EPRINTSIZE];

		epr(r->root, buf);
		(void) printf("pat = %s\n", buf);
	}
#endif
	return (NO);
}

static BOOL
match(Expr *e, int a)
{
	switch (e->type) {
	case Dot:	return ((BOOL)(a != NL));
	case Literal:	return ((BOOL)(a == e->lit));
	case Charclass:	return ((BOOL)(CCL_CHK((uchar_t *)e->r, a)));
	default:	return (NO);
	}
}

/*
 * generates the followset for a node in fpos
 */
static void
follow(Positionset *fpos, Expr *e)
{
	Expr *p;

	if (e->type == EOP)
		return;
	else
		p = e->parent;
	switch (p->type) {
	case EOP:
		SET(fpos, p->id, 0)
		break;
	case Plus:
	case Star:
		(void) first_lit(fpos, e);
		follow(fpos, p);
		break;
	case Quest:
	case Alternate:
		follow(fpos, p);
		break;
	case Cat:
		if (e == p->r || !first_lit(fpos, p->r))
			follow(fpos, p);
		break;
	default:
		break;
	}
}

/*
 * first_lit returns NO if e is nullable and in the process,
 * ets up fpos.
 */
static BOOL
first_lit(Positionset *fpos, Expr *e)
{
	BOOL k;

	switch (e->type) {
	case Literal:
	case Dot:
	case Charclass:
		SET(fpos, e->id, 0)
		return (YES);
	case EOP:
	case Star:
	case Quest:
		(void) first_lit(fpos, e->l);
		return (NO);
	case Plus:
		return (first_lit(fpos, e->l));
	case Cat:
		return ((BOOL)(first_lit(fpos, e->l) || first_lit(fpos, e->r)));
	case Alternate:
		k = first_lit(fpos, e->r);
		return ((BOOL)(first_lit(fpos, e->l) && k));
	default:
		err("internal error");
	}
	return (NO);
}

static void
efollow(re_re *r, Positionset *fpos, Expr *e)
{
	ID i, *p;

	CLEAR(r, fpos);
	follow(fpos, e);
	e->flen = fpos->count;
	e->follow = (ID *)egmalloc(e->flen * sizeof (ID));
	p = e->follow;
#ifdef	DEBUG
	printf("ID = %d LIT %c FLEN = %d\n", e->id, e->lit, e->flen);
#endif
	for (i = fpos->last; i > 0; i = fpos->base[i].id) {
		*p++ = i;
#ifdef	DEBUG
	printf("FOLLOW ID = %d LIT %c\n", r->ptr[i]->id, r->ptr[i]->lit);
#endif
	}
	if (p != e->follow + e->flen) {
		err("internal error");
	}
}

static State *
addstate(re_re *r, Positionset *ps, int cnt)
{
	ID j;
	FID *p, *q;
	State *s;

	if (cnt) {
		s = r->states + getstate(r, ps);
		(void) memset((char *)s->tab, 0, sizeof (s->tab));
		s->cnt = r->istate.cnt;
	} else {
		s = &r->istate;
		s->cnt = -1;
	}
	s->pos = r->posnext;
	r->posnext += ps->count;
	s->npos = ps->count;
	p = r->posbase + s->pos;
	for (j = ps->last; j > 0; p++, j = q->id) {
		q = &ps->base[j];
		p->id = j;
		p->fcount = q->fcount;
		if (p->id == r->root->id && s->cnt < p->fcount)
			s->cnt = p->fcount;
	}
#ifdef	DEBUG
	if (TRACE(3)) {
		uchar_t buf[2000];
		spr(s->npos, s->pos+r->posbase, buf);
		(void) printf("new state[%d] %s%s\n", s-r->states, buf,
		    s->cnt?" cnt":"");
	}
#endif
	return (s);
}

static State *
nextstate(re_re *r, State *s, int a)
{
	State *news;

	CLEAR(r, &r->tmp);
	followstate(r, s, a, &r->tmp);
	if (s != &r->istate) followstate(r, &r->istate, a, &r->tmp);

#ifdef	DEBUG
	if (TRACE(5)) {
		uchar_t buf[2000];
		ppr(&r->tmp, buf);
		(void) printf("nextstate(%d, '%c'): found %s\n", s-r->states,
		    a, buf);
	}
#endif
	if (r->tmp.count == 0)
		news = &r->istate;
	else if ((news = stateof(r, &r->tmp)) == NULL)
		news = addstate(r, &r->tmp, 1);
	s->tab[a] = news;
#ifdef	DEBUG
	if (TRACE(5)) {
		(void) printf("nextstate(%d, '%c'): returning %ld\n",
		    s-r->states, a, news);
	}
#endif
	return (news);
}

static void
followstate(re_re *r, State *s, int a, Positionset *fpos)
{
	int j;
	ID *q, *eq;
	Expr *e;

	for (j = s->pos; j < (s->pos + s->npos); j++) {
		e = r->ptr[r->posbase[j].id];
		if (e->type == EOP) continue;
		if (match(e, a)) {
			if (e->follow == NULL) efollow(r, &r->firstpos, e);
			for (q = e->follow, eq = q + e->flen; q < eq; q++) {
				SET(fpos, *q, r->posbase[j].fcount + 1)
#ifdef	DEBUG
				printf("CHAR %c FC %c COUNT %d\n", a,
				    r->ptr[*q]->lit, r->posbase[j].fcount+1);
#endif
			}
		}
	}
}

static uchar_t *
egmalloc(size_t n)
{
	uchar_t *x;

	x = (uchar_t *)mymalloc(n);
	mallocs[nmalloc++] = x;
	if (nmalloc >= MAXMALLOCS)
		nmalloc = MAXMALLOCS - 1;
	return (x);
}

#ifdef	DEBUG
void
ppr(Positionse *ps, char *p)
{
	ID n;

	if (ps->count < 1) {
		(void) sprintf(p, "{}");
		return;
	}
	*p++ = '{';
	for (n = ps->last; n > 0; n = ps->base[n].id) {
		(void) sprintf(p, "%d,", n);
		p = strchr(p, 0);
	}
	p[-1] = '}';
}

void
epr(Expr *e, uchar_t *res)
{
	uchar_t r1[EPRINTSIZE], r2[EPRINTSIZE];
	int i;

	if (e == NULL) {
		(void) sprintf(res, "!0!");
		return;
	}
	switch (e->type) {
	case Dot:
	case Literal:
		spr(e->flen, e->follow, r1);
		(void) sprintf(res, "%c%s", e->lit, r1);
		break;
	case Charclass:
		*res++ = '[';
		for (i = 0; i < 256; i++)
			if (CCL_CHK((uchar_t *)e->r, i)) {
				*res++ = i;
			}
		*res++ = ']';
		*res = '\0';
		break;
	case Cat:
		epr(e->l, r1);
		epr(e->r, r2);
		(void) sprintf(res, "%s%s", r1, r2);
		break;
	case Alternate:
		epr(e->l, r1);
		epr(e->r, r2);
		(void) sprintf(res, "(%s|%s)", r1, r2);
		break;
	case Star:
		epr(e->l, r1);
		(void) sprintf(res, "(%s)*", r1);
		break;
	case Plus:
		epr(e->l, r1);
		(void) sprintf(res, "(%s)+", r1);
		break;
	case Quest:
		epr(e->l, r1);
		(void) sprintf(res, "(%s)?", r1);
		break;
	case EOP:
		epr(e->l, r1);
		(void) sprintf(res, "%s<EOP>", r1);
		break;
	default:
		(void) sprintf(res, "<undef type %d>", e->type);
		err(res);
		break;
	}
}

static void
spr(int c, int *p, uchar_t *buf)
{
	if (c > 0) {
		*buf++ = '{';
		*buf = '\0';
		while (--c > 0) {
			(void) sprintf(buf, "%d,", *p++);
			buf = strchr(buf, 0);
		}
		(void) sprintf(buf, "%d}", *p);
	} else
		(void) sprintf(buf, "{}");
}
#endif

static void
stateinit(re_re *r)
{
	/* CONSTANTCONDITION */
	r->statelim = (sizeof (int) < 4 ? 32 : 128);
	r->states = (State *)egmalloc(r->statelim * sizeof (State));

	/* CONSTANTCONDITION */
	r->nposalloc = (sizeof (int) < 4 ? 2048 : 8192);
	r->posbase = (FID *)egmalloc(r->nposalloc * sizeof (FID));
	r->nstates = r->posnext = 0;
}

static void
clrstates(re_re *r)
{
	r->nstates = 0;		/* reclaim space for states and positions */
	r->posnext = r->posreset;
	(void) memset((char *)r->istate.tab, 0, sizeof (r->istate.tab));
}

static void
savestate(re_re *r)
{
	r->posreset = r->posnext;	/* save for reset */
}

static State *
startstate(re_re *r)
{
	return (&r->istate);
}

static int
getstate(re_re *r, Positionset *ps)
{
	if (r->nstates >= r->statelim ||
	    r->posnext + ps->count >= r->nposalloc) {
		clrstates(r);
#ifdef	DEBUG
		printf("%d STATES FLUSHED\n", r->statelim);
#endif
	}
	return (r->nstates++);
}

static State *
stateof(re_re *r, Positionset *ps)
{
	State *s;
	int i;
	FID *p, *e;

	for (i = 0, s = r->states; i < r->nstates; i++, s++) {
		if (s->npos == ps->count) {
			for (p = s->pos+r->posbase, e = p+s->npos; p < e; p++)
				if (ps->base[p->id].id == 0 ||
				    ps->base[p->id].fcount != p->fcount)
					goto next;
			return (s);
		}
	next:;
	}
	return (NULL);
}

static re_re *
egprep(PATTERN *pat)
{
	re_re *r;

	r = (re_re *)egmalloc(sizeof (re_re));
	(void) memset((char *)r, 0, sizeof (re_re));

	pat->loc1 = pat->expression;
	pat->loc2 = pat->expression + strlen((char *)pat->expression);

	parno = 0;
	maxid = 1;
	r->cmap = pat->cmap;
	lex(r, pat);
	r->root = newexpr(EOP, '#', eall(r, pat), (Expr *)NULL);
	r->maxid = maxid;

	eginit(r);
	return (r);
}

static Expr *
newexpr(Exprtype t, int lit, Expr *left, Expr *right)
{
	Expr *e = (Expr *)egmalloc(sizeof (Expr));

	e->type = t;
	e->parent = NULL;
	e->lit = lit;

	if (e->lit) e->id = maxid++;
	else e->id = 0;

	if ((e->l = left) != NULL) {
		left->parent = e;
	}
	if ((e->r = right) != NULL) {
		right->parent = e;
	}
	e->follow = NULL;
	e->flen = 0;
	return (e);
}

static void
lex(re_re *r, PATTERN *pat)
{
	if (pat->loc1 == pat->loc2) {
		toktype = EOP;
		toklit = -1;
	} else switch (toklit = *pat->loc1++) {
	case '.':	toktype = Dot; break;
	case '*':	toktype = Star; break;
	case '+':	toktype = Plus; break;
	case '?':	toktype = Quest; break;
	case '[':	toktype = Charclass; break;
	case '|':	toktype = Alternate; break;
	case '(':	toktype = Lpar; break;
	case ')':	toktype = Rpar; break;
	case '\\':	toktype = Backslash;
			if (pat->loc1 == pat->loc2) {
				err("syntax error - missing character "
				    "after \\");
			} else {
				toklit = r->cmap[*pat->loc1++];
			}
			break;
	case '^': case '$':	toktype = Literal; toklit = NL; break;
	default:	toktype = Literal; toklit = r->cmap[toklit]; break;
	}
}

static int
ccl(PATTERN *pat, uchar_t *tab)
{
	int i;
	int range = 0;
	int lastc = -1;
	int count = 0;
	BOOL comp = NO;

	(void) memset((char *)tab, 0, CCL_SIZ * sizeof (uchar_t));
	if (*pat->loc1 == '^') {
		pat->loc1++;
		comp = YES;
	}
	if (*pat->loc1 == ']') {
		uchar_t c = pat->cmap[*pat->loc1];
		CCL_SET(tab, c);
		lastc = *pat->loc1++;
	}
	/* scan for chars */
	for (; (pat->loc1 < pat->loc2) && (*pat->loc1 != ']'); pat->loc1++) {
		if (*pat->loc1 == '-') {
			if (lastc < 0) CCL_SET(tab, pat->cmap['-']);
			else range = 1;
			continue;
		}
		if (range) {
			for (i = *pat->loc1; i >= lastc; i--) {
				CCL_SET(tab, pat->cmap[i]);
			}
		} else {
			uchar_t c = pat->cmap[*pat->loc1];
			CCL_SET(tab, c);
		}

		range = 0;

		lastc = *pat->loc1;
	}
	if (range) CCL_SET(tab, pat->cmap['-']);

	if (pat->loc1 < pat->loc2) pat->loc1++;
	else err("syntax error - missing ]");

	if (comp) {
		CCL_SET(tab, pat->cmap[NL]);
		for (i = 0; i < CCL_SIZ; i++) tab[i] ^= 0xff;
	}
	for (i = 0; i < 256; i++) {
		if (pat->cmap[i] != i) CCL_CLR(tab, i);
		if (CCL_CHK(tab, i)) {
			lastc = i;
			count++;
		}
	}
	if (count == 1)
		*tab = (char)lastc;
	return (count);
}

/*
 * egrep patterns:
 *
 * Alternation:	d0:	d1 { '|' d1 }*
 * Concatenation:	d1:	d2 { d2 }*
 * Repetition:	d2:	d3 { '*' | '?' | '+' }
 * Literal:	d3:	lit | '.' | '[]' | '(' d0 ')'
 */

static Expr *
d3(re_re *r, PATTERN *pat)
{
	Expr *e;
	uchar_t *tab;
	int count;

	switch (toktype) {
	case Backslash:
	case Literal:
		e = newexpr(Literal, toklit, (Expr *)NULL, (Expr *)NULL);
		lex(r, pat);
		break;
	case Dot:
		e = newexpr(Dot, '.', (Expr *)NULL, (Expr *)NULL);
		lex(r, pat);
		break;
	case Charclass:
		tab = egmalloc(CCL_SIZ * sizeof (uchar_t));
		count = ccl(pat, tab);
		if (count == 1) {
			toklit = *tab;
			e = newexpr(Literal, toklit, (Expr *)NULL,
			    (Expr *)NULL);
		} else {
			e = newexpr(Charclass, '[', (Expr *)NULL, (Expr *)NULL);
			e->l = (Expr *)count;	/* number of chars */
			e->r = (Expr *)tab;	/* bitmap of chars */
		}
		lex(r, pat);
		break;
	case Lpar:
		lex(r, pat);
		count = ++parno;
		e = d0(r, pat);
		if (toktype == Rpar)
			lex(r, pat);
		else
			err("syntax error - missing )");
		return (e);
	default:
		err("syntax error");
		e = NULL;
	}
	return (e);
}

static Expr *
d2(re_re *r, PATTERN *pat)
{
	Expr *e;
	Exprtype t;

	e = d3(r, pat);
	while ((toktype == Star) || (toktype == Plus) || (toktype == Quest)) {
		t = toktype;
		lex(r, pat);
		e = newexpr(t, 0, e, (Expr *)NULL);
	}
	return (e);
}

static Expr *
d1(re_re *r, PATTERN *pat)
{
	Expr *e, *f;

	e = d2(r, pat);
	while ((toktype == Literal) || (toktype == Dot) || (toktype == Lpar) ||
	    (toktype == Backslash) || (toktype == Charclass)) {
		f = d2(r, pat);
		e = newexpr(Cat, 0, e, f);
	}
	return (e);
}

static Expr *
d0(re_re *r, PATTERN *pat)
{
	Expr *e, *f;

	e = d1(r, pat);
	while (toktype == Alternate) {
		lex(r, pat);
		if (toktype == EOP)
			continue;
		f = d1(r, pat);
		e = newexpr(Alternate, 0, e, f);
	}
	return (e);
}

static Expr *
eall(re_re *r, PATTERN *pat)
{
	Expr *e;

	while (toktype == Alternate)	/* bogus but user-friendly */
		lex(r, pat);
	e = d0(r, pat);
	while (toktype == Alternate)	/* bogus but user-friendly */
		lex(r, pat);
	if (toktype != EOP)
		err("syntax error");
	return (e);
}

static void
err(char *s)
{
	message = s;
	longjmp(env, 1);
}

static int
re_lit(PATTERN *pat, uchar_t **b, uchar_t **e)
{
	bestlen = 0;
	pat->fullmatch = YES;
	START
	traverse(pat, pat->re_ptr->root->l);
	FINISH
	if (bestlen < 2)
		return (0);
	*b = egmalloc(bestlen * sizeof (uchar_t));
	(void) memmove(*b, best, bestlen);
	*e = *b + bestlen - 1;
	return (bestlen - 1);
}

static void
traverse(PATTERN *pat, Expr *e)
{
	switch (e->type) {
	case Literal:
		ADDL(e->lit)
		break;
	case Cat:
		traverse(pat, e->l);
		traverse(pat, e->r);
		break;
	case Plus:
		traverse(pat, e->l);
		FINISH	/* can't go on past a + */
		pat->fullmatch = NO;
		START	/* but we can start with one! */
		traverse(pat, e->l);
		break;
	default:
		FINISH
		pat->fullmatch = NO;
		START
		break;
	}
}

static re_bm *
re_bmcomp(uchar_t *pb, uchar_t *pe, uchar_t *cmap)
{
	int j;
	int delta[256];
	re_bm *b;

	b = (re_bm *)egmalloc(sizeof (*b));

	b->patlen = pe - pb;
	b->cmap = cmap;
	b->bmpat = pb;

	delta_2(b);

	for (j = 0; j < 256; j++)
		delta[j] = b->patlen;

	for (pe--; pb < pe; pb++)
		delta[b->cmap[*pb]] = pe - pb;

	delta[b->cmap[*pb]] = LARGE;

	for (j = 0; j < 256; j++)
		b->delta0[j] = delta[b->cmap[j]];
	return (b);
}

static void
delta_2(re_bm *b)
{
	int m = b->patlen;
	int i, k, j;

	b->delta2 = (int *)egmalloc(m * sizeof (int));

	for (j = 0; j < m; j++) {
		k = 1;
again:
		while (k <= j && b->bmpat[j-k] == b->bmpat[j]) k++;

		for (i = j + 1; i < m; i++) {
			if (k <= i && b->bmpat[i-k] != b->bmpat[i]) {
				k++;
				goto again;
			}
		}
		b->delta2[j] = k + m - j - 1;
	}
}

static BOOL
re_bmexec(PATTERN *pat, uchar_t *s, uchar_t *e, uchar_t **mb, uchar_t **me)
{
	re_bm *b = pat->bm_ptr;
	uchar_t *sp;
	int k;

	s += b->patlen - 1;
	while ((unsigned long)s < (unsigned long)e) {
		while ((unsigned long)(s += b->delta0[*s]) < (unsigned long)e)
			;
		if ((unsigned long)s < (unsigned long)(e + b->patlen))
			return (NO); /* no match */
		s -= LARGE;
		for (k = b->patlen-2, sp = s-1; k >= 0; k--) {
			if (b->cmap[*sp--] != b->bmpat[k]) break;
		}
		if (k < 0) {
			*mb = ++sp;
			*me = s+1;
			if (grepmatch(pat, mb, me))
				return (YES);
			s = *mb;
		} else if (k < 0) {
			s++;
		} else {
			int j;
			j = b->delta2[k];
			k = b->delta0[*++sp];
			if ((j > k) || (k == (int)LARGE))
				k = j;
			s = sp + k;
		}
	}
	return (NO);
}

static re_cw *
re_recw(re_re *r, uchar_t *map)
{
	Expr *e, *root = r->root;
	re_cw *pat;
	uchar_t *buf;

	if (root->type != EOP)
		return (NULL);
	e = root->l;
	pat = re_cwinit(map);
	buf = (uchar_t *)egmalloc(20000 * sizeof (uchar_t));
	if (!altlist(e, buf, pat)) {
		return (NULL);
	}
	re_cwcomp(pat);
	return (pat);
}

static BOOL
altlist(Expr *e, uchar_t *buf, re_cw *pat)
{
	if (e->type == Alternate)
		return ((BOOL)(altlist(e->l, buf, pat) &&
		    altlist(e->r, buf, pat)));
	return (word(e, buf, pat));
}

static BOOL
word(Expr *e, uchar_t *buf, re_cw *pat)
{
	static uchar_t *p;

	if (buf) p = buf;

	if (e->type == Cat) {
		if (!word(e->l, (uchar_t *)NULL, pat))
			return (NO);
		if (!word(e->r, (uchar_t *)NULL, pat))
			return (NO);
	} else if (e->type == Literal)
		*p++ = e->lit;
	else
		return (NO);

	if (buf)
		re_cwadd(pat, buf, p);
	return (YES);
}

static re_cw *
re_cwinit(uchar_t *cmap)
{
	re_cw *c;

	froot = NULL;
	next_node = NULL;
	next_link = NULL;
	c = (re_cw *)egmalloc(sizeof (*c));
	c->nodeid = 0;
	c->maxdepth = 0;
	c->mindepth = 10000;
	c->root = newnode(c, 0);
	c->cmap = cmap;
	return (c);
}

static void
re_cwadd(re_cw *c, uchar_t *s, uchar_t *e)
{
	Node *p, *state;
	Link *l;
	int depth;

	state = c->root;
	while (s <= --e) {
		for (l = state->alts; l; l = l->next)
			if (l->lit == *e)
				break;
		if (l == NULL)
			break;
		else
			state = l->node;
	}
	if (s <= e) {
		depth = state->d+1;
		l = newlink(*e--, p = newnode(c, depth++));
		l->next = state->alts;
		state->alts = l;
		state = p;
		while (s <= e) {
			state->alts = newlink(*e--, p = newnode(c, depth++));
			state = p;
		}
		if (c->mindepth >= depth) c->mindepth = depth-1;
	}
	state->out = 1;
}

#ifdef	DEBUG
static
pr(Node *n)
{
	Link *l;

	printf("%d[%d,%d]: ", n->id, n->shift1, n->shift2);
	for (l = n->alts; l; l = l->next) {
		printf("edge from \"%d\" to \"%d\" label {\"%c\"};",
		    n->id, l->node->id, l->lit);
		if (l->node->out) {
			printf(" draw \"%d\" as Doublecircle;", l->node->id);
		}
		if (l->node->fail) {
			printf(" edge from \"%d\" to \"%d\" dashed;",
			    l->node->id, l->node->fail->id);
		}
		printf("\n");
		pr(l->node);
	}
}
#endif

static void
fail(Node *root)
{
	Link *qhead = NULL, *qtail = NULL;
	Link *l, *ll;
	Link *t;
	Node *state, *r, *s;
	int a;

	for (l = root->alts; l; l = l->next) {
		ADD(l->node);
		l->node->fail = root;
	}
	while (qhead) {
		r = qhead->node;
		DEL();
		for (l = r->alts; l; l = l->next) {
			s = l->node;
			a = l->lit;
			ADD(s);
			state = r->fail;
			while (state) {
				for (ll = state->alts; ll; ll = ll->next)
					if (ll->lit == a)
						break;
				if (ll || (state == root)) {
					if (ll)
						state = ll->node;
					/*
					 *	do it here as only other exit is
					 *	state 0
					 */
					if (state->out) {
						s->out = 1;
					}
					break;
				} else
					state = state->fail;
			}
			s->fail = state;
		}
	}
	zeroroot(root, root);
}

static void
zeroroot(Node *root, Node *n)
{
	Link *l;

	if (n->fail == root)
		n->fail = NULL;
	for (l = n->alts; l; l = l->next)
		zeroroot(root, l->node);
}

static void
shift(re_cw *c)
{
	Link *qhead = NULL, *qtail = NULL;
	Link *l;
	Link *t;
	Node *state, *r, *s;
	int k;

	for (k = 0; k < 256; k++)
		c->step[k] = c->mindepth+1;
	c->root->shift1 = 1;
	c->root->shift2 = c->mindepth;
	for (l = c->root->alts; l; l = l->next) {
		l->node->shift2 = c->root->shift2;
		ADD(l->node);
		l->node->fail = NULL;
	}
	while (qhead) {
		r = qhead->node;
		DEL();
		r->shift1 = c->mindepth;
		r->shift2 = c->mindepth;
		if ((state = r->fail) != NULL) {
			do {
				k = r->d - state->d;
				if (k < state->shift1) {
					state->shift1 = k;
				}
				if (r->out && (k < state->shift2)) {
					state->shift2 = k;
				}
			} while ((state = state->fail) != NULL);
		}
		for (l = r->alts; l; l = l->next) {
			s = l->node;
			ADD(s);
		}
	}
	shiftprop(c, c->root);
	shifttab(c->root);
	c->step[0] = 1;
}

static void
shifttab(Node *n)
{
	Link *l;
	Node **nn;

	n->tab = nn = (Node **)egmalloc(256 * sizeof (Node *));
	(void) memset((char *)n->tab, 0, 256 * sizeof (Node *));
	for (l = n->alts; l; l = l->next)
		nn[l->lit] = l->node;
}

static void
shiftprop(re_cw *c, Node *n)
{
	Link *l;
	Node *nn;

	for (l = n->alts; l; l = l->next) {
		if (c->step[l->lit] > l->node->d)
			c->step[l->lit] = l->node->d;
		nn = l->node;
		if (n->shift2 < nn->shift2)
			nn->shift2 = n->shift2;
		shiftprop(c, nn);
	}
}

static void
re_cwcomp(re_cw *c)
{
	fail(c->root);
	shift(c);
}

static BOOL
re_cwexec(PATTERN *pat, uchar_t *rs, uchar_t *re, uchar_t **mb, uchar_t **me)
{
	Node *state;
	Link *l;
	uchar_t *sp;
	uchar_t *s;
	uchar_t *e;
	Node *ostate;
	int k;
	re_cw *c = pat->cw_ptr;
	uchar_t fake[1];
	uchar_t mappedsp;

	fake[0] = 0;
	state = c->root;

	s = rs+c->mindepth-1;
	e = re;
	while (s < e) {
		/* scan */
		for (sp = s; (ostate = state) != NULL; ) {
			mappedsp = c->cmap[*sp];
			if (state->tab) {
				if ((state = state->tab[mappedsp]) == NULL)
					goto nomatch;
			} else {
				for (l = state->alts; ; l = l->next) {
					if (l == NULL)
						goto nomatch;
					if (l->lit == mappedsp) {
						state = l->node;
						break;
					}
				}
			}
			if (state->out) {
				*mb = sp;
				*me = s+1;
				if (fixloc(mb, me))
					return (YES);
			}
			if (--sp < rs) {
				sp = fake;
				break;
			}
		}
	nomatch:
		k = c->step[c->cmap[*sp]] - ostate->d - 1;
		if (k < ostate->shift1)
			k = ostate->shift1;
		if (k > ostate->shift2)
			k = ostate->shift2;
		s += k;
		state = c->root;
	}
	return (NO);
}

static Node *
newnode(re_cw *c, int d)
{
	static Node *lim = NULL;
	static int incr = 256;

	if (!next_node) lim = NULL;
	if (next_node == lim) {
		next_node = (Node *)egmalloc(incr * sizeof (Node));
		lim = next_node + incr;
	}
	next_node->d = d;
	if (d > c->maxdepth) c->maxdepth = d;
	next_node->id = c->nodeid++;
	next_node->alts = NULL;
	next_node->tab = NULL;
	next_node->out = 0;
	return (next_node++);
}

static Link *
newlink(uchar_t lit, Node *n)
{
	static Link *lim = NULL;
	static int incr = 256;

	if (!next_link) lim = NULL;
	if (next_link == lim) {
		next_link = (Link *)egmalloc(incr * sizeof (Link));
		lim = next_link + incr;
	}
	next_link->lit = lit;
	next_link->node = n;
	next_link->next = NULL;
	return (next_link++);
}

int
egrep(char *f, FILE *o, char *fo)
{
	uchar_t		buff[MAXBUFSIZE + ESIZE];

	buffer = buff;
	*buffer++ = NL;  /* New line precedes buffer to prevent runover */
	file = f;
	output = o;
	format = fo;
	return (execute());
}

static int
execute(void)
{
	LINE		current;
	BOOL		matched;
	BOOL	all_searched; /* file being matched until end */

	if ((file_desc = open(file, O_RDONLY)) < 0) {
		return (-1);
	}
	init_file(&current);
		/* while there is more get more text from the data stream */
	for (;;) {
		all_searched = NO;

		/*
		 * Find next new-line in buffer.
		 * Begin after previous new line character
		 */

		current.prntbuf = current.newline + 1;
		current.ln++; /* increment line number */

		if (current.prntbuf < bufend) {
			/* There is more text in buffer */

			/*
			 * Take our next
			 * "line" as the entire remaining buffer.
			 * However, if there is more of the file yet
			 * to be read in, exclude any incomplete
			 * line at end.
			 */
			if (file_stat == NO_MORE) {
				all_searched = YES;
				current.newline = bufend - 1;
				if (*current.newline != NL) {
					current.newline = bufend;
				}
			} else {
				/*
				 * Find end of the last
				 * complete line in the buffer.
				 */
				current.newline = bufend;
				while (*--current.newline != NL) {
				}
				if (current.newline < current.prntbuf) {
					/* end not found */
					current.newline = bufend;
				}
			}
		} else {
			/* There is no more text in the buffer. */
			current.newline = bufend;
		}
		if (current.newline >= bufend) {
			/*
			 * There is no more text in the buffer,
			 * or no new line was found.
			 */
			switch (file_stat) {
			case MORE:	/* file partly unread */
			case BEGIN:
				fgetfile(&current);

				current.ln--;
				continue; /* with while loop */
			case NO_MORE:
				break;
			}
			/* Nothing more to read in for this file. */
			if (current.newline <= current.prntbuf) {
				/* Nothing in the buffer, either */
				/* We are done with the file. */
				current.ln--;
				break; /* out of while loop */
			}
			/* There is no NL at the end of the file */
		}

		matched = pattern_match(&match_pattern, &current);
		if (matched) {
			int nc;

			get_ncount(&current, match_pattern.loc1);
			get_line(&current, match_pattern.loc2);

			nc = current.newline + 1 - current.prntbuf;
			(void) fprintf(output, format, file, current.ln);
			(void) fwrite((char *)current.prntbuf, 1, nc, output);
		} else {
			if (all_searched)
				break; /* out of while loop */

			get_ncount(&current, current.newline + 1);
		}
	}

	(void) close(file_desc);
	return (0);
}

static void
init_file(LINE *cur_ptr)
{
	file_stat = BEGIN;
	cur_ptr->ln = 0;
	bufend = buffer;
	cur_ptr->newline = buffer - 1;
}

static BOOL
pattern_match(PATTERN *pat, LINE *lptr)
{
	if ((*pat->procfn)(pat, lptr->prntbuf - 1, lptr->newline + 1,
	    &pat->loc1, &pat->loc2)) {
		return (YES);
	} else {
		pat->loc1 = lptr->prntbuf;
		pat->loc2 = lptr->newline - 1;
		return (NO);
	}
} /* end of function pattern_match() */

static void
fgetfile(LINE *cur_ptr)
{
	/*
	 * This function reads as much of the current file into the buffer
	 * as will fit.
	 */
	int	bytes;	  /* bytes read in current buffer */
	int	bufsize = MAXBUFSIZE; /* free space in data buffer */
	int	save_current;
	uchar_t	*begin = cur_ptr->prntbuf;

	/*
	 * Bytes of current incomplete line, if any, save_current in buffer.
	 * These must be saved.
	 */
	save_current = (int)(bufend - begin);

	if (file_stat == MORE) {
		/*
		 * A portion of the file fills the buffer. We must clear
		 * out the dead wood to make room for more of the file.
		 */

		int k = 0;

		k = begin - buffer;
		if (!k) {
			/*
			 * We have one humungous current line,
			 * which fills the whole buffer.
			 * Toss it.
			 */
			begin = bufend;
			k = begin - buffer;
			save_current = 0;
		}

		begin = buffer;
		bufend = begin + save_current;

		bufsize = MAXBUFSIZE - save_current;

		if (save_current > 0) {
			/*
			 * Must save portion of current line.
			 * Copy to beginning of buffer.
			 */
			(void) memmove(buffer, buffer + k, save_current);
		}
	}

	/* Now read in the file. */

	do {
		bytes = read(file_desc, (char *)bufend, (unsigned int)bufsize);
		if (bytes < 0) {
			/* can't read any more of file */
			bytes = 0;
		}
		bufend += bytes;
		bufsize -= bytes;
	} while (bytes > 0 && bufsize > 0);


	if (begin >= bufend) {
		/* No new lines or incomplete line in buffer */
		file_stat = NO_MORE;
	} else if (bufsize) {
		/* Still space in the buffer, so we have read entire file */
		file_stat = NO_MORE;
	} else {
		/* We filled entire buffer, so there may be more yet to read */
		file_stat = MORE;
	}
		/* Note: bufend is 1 past last good char */
	*bufend = NL;	/* Sentinel new-line character */
	/* Set newline to character preceding the current line */
	cur_ptr->newline = begin - 1;
}

static void
get_line(LINE *cur_ptr, uchar_t *s)
{
	while (*s++ != NL) {
	}
	cur_ptr->newline = --s;
	cur_ptr->ln++;
}

static void
get_ncount(LINE *cur_ptr, uchar_t *s)
{
	uchar_t	*p = cur_ptr->prntbuf;

	while (*--s != NL) {
	}
	cur_ptr->newline = s++;
	while ((s > p) &&
	    (p = (uchar_t *)memchr((char *)p, NL, s - p)) != NULL) {
		cur_ptr->ln++;
		++p;
	}
	cur_ptr->ln--;
	cur_ptr->prntbuf = s;
}

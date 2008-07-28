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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iexpr.c -- instanced expression cache module
 *
 * this module provides a cache of fully instantized expressions.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include "alloc.h"
#include "out.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "ipath.h"
#include "iexpr.h"
#include "stats.h"
#include "eval.h"
#include "config.h"

#define	IEXPRSZ	1024	/* hash table size */

static struct stats *Niexpr;

/* the cache is a hash table of these structs */
static struct iexpr {
	struct node *np;
	struct iexpr *next;	/* next entry in hash bucket */
	int count;
} *Cache[IEXPRSZ];

/*
 * iexpr_init -- initialize the iexpr module
 */
void
iexpr_init(void)
{
	Niexpr = stats_new_counter("iexpr.niexpr", "iexpr cache entries", 1);
}

/*
 * iexpr_hash -- produce a simple hash from an instanced expression tree
 */
static unsigned
iexpr_hash(struct node *np)
{
	if (np == NULL)
		return (1);

	switch (np->t) {
	case T_GLOBID:
		return ((uintptr_t)np->u.globid.s);

	case T_ASSIGN:
	case T_CONDIF:
	case T_CONDELSE:
	case T_NE:
	case T_EQ:
	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
	case T_BITAND:
	case T_BITOR:
	case T_BITXOR:
	case T_BITNOT:
	case T_LSHIFT:
	case T_RSHIFT:
	case T_LIST:
	case T_AND:
	case T_OR:
	case T_NOT:
	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
		return ((int)np->t *
		    (iexpr_hash(np->u.expr.left) +
		    iexpr_hash(np->u.expr.right)));

	case T_NAME:
		return ((uintptr_t)np->u.name.s);

	case T_EVENT:
		return (iexpr_hash(np->u.event.ename) +
		    iexpr_hash(np->u.event.epname));

	case T_FUNC:
		return ((uintptr_t)np->u.func.s +
		    iexpr_hash(np->u.func.arglist));

	case T_QUOTE:
		return ((uintptr_t)np->u.quote.s);

	case T_NUM:
	case T_TIMEVAL:
		return ((int)np->u.ull);

	default:
		outfl(O_DIE, np->file, np->line,
		    "iexpr_hash: unexpected node type: %s",
		    ptree_nodetype2str(np->t));
	}
	/*NOTREACHED*/
	return (1);
}

/*
 * iexpr_cmp -- compare two instanced expression trees
 */
static int
iexpr_cmp(struct node *np1, struct node *np2)
{
	int diff;

	if (np1 == np2)
		return (0);

	if (np1 == NULL)
		return (1);

	if (np2 == NULL)
		return (-1);

	if (np1->t != np2->t)
		return (np2->t - np1->t);

	/* types match, need to see additional info matches */
	switch (np1->t) {
	case T_GLOBID:
		return (np2->u.globid.s - np1->u.globid.s);

	case T_ASSIGN:
	case T_CONDIF:
	case T_CONDELSE:
	case T_NE:
	case T_EQ:
	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
	case T_BITAND:
	case T_BITOR:
	case T_BITXOR:
	case T_BITNOT:
	case T_LSHIFT:
	case T_RSHIFT:
	case T_LIST:
	case T_AND:
	case T_OR:
	case T_NOT:
	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
		diff = iexpr_cmp(np1->u.expr.left, np2->u.expr.left);
		if (diff != 0)
			return (diff);
		return (iexpr_cmp(np1->u.expr.right, np2->u.expr.right));

	case T_NAME:
		if (np2->u.name.s != np1->u.name.s)
			return (np2->u.name.s - np1->u.name.s);
		diff = iexpr_cmp(np1->u.name.child, np2->u.name.child);
		if (diff != 0)
			return (diff);
		return (iexpr_cmp(np1->u.name.next, np2->u.name.next));

	case T_EVENT:
		diff = iexpr_cmp(np1->u.event.ename, np2->u.event.ename);
		if (diff != 0)
			return (diff);
		return (iexpr_cmp(np1->u.event.epname, np2->u.event.epname));

	case T_FUNC:
		if (np1->u.func.s != np2->u.func.s)
			return (np2->u.func.s - np1->u.func.s);
		return (iexpr_cmp(np1->u.func.arglist, np2->u.func.arglist));

	case T_QUOTE:
		return (np2->u.quote.s - np1->u.quote.s);

	case T_NUM:
	case T_TIMEVAL:
		if (np2->u.ull > np1->u.ull)
			return (1);
		else if (np1->u.ull > np2->u.ull)
			return (-1);
		else
			return (0);

	default:
		outfl(O_DIE, np1->file, np1->line,
		    "iexpr_cmp: unexpected node type: %s",
		    ptree_nodetype2str(np1->t));
	}
	/*NOTREACHED*/
	return (0);
}

/*
 * iexpr -- find instanced expr in cache, or add it if necessary
 */
struct node *
iexpr(struct node *np)
{
	unsigned idx = iexpr_hash(np) % IEXPRSZ;
	struct iexpr *bucketp = Cache[idx];
	struct iexpr *cp;

	/* search cache */
	for (cp = bucketp; cp != NULL; cp = cp->next)
		if (iexpr_cmp(cp->np, np) == 0) {
			/* found it */
			tree_free(np);
			cp->count++;
			return (cp->np);
		}

	/* allocate new cache entry */
	cp = MALLOC(sizeof (*cp));
	cp->np = np;
	cp->next = bucketp;
	cp->count = 1;
	Cache[idx] = cp;

	stats_counter_bump(Niexpr);

	return (np);
}

void
iexpr_free(struct node *np)
{
	unsigned idx = iexpr_hash(np) % IEXPRSZ;
	struct iexpr *cp;
	struct iexpr *prevcp = NULL;

	/* search cache */
	for (cp = Cache[idx]; cp != NULL; cp = cp->next) {
		if (iexpr_cmp(cp->np, np) == 0) {
			/* found it */
			cp->count--;
			if (cp->count == 0) {
				tree_free(cp->np);
				if (prevcp == NULL)
					Cache[idx] = cp->next;
				else
					prevcp->next = cp->next;
				FREE(cp);
			}
			return;
		}
		prevcp = cp;
	}
}

/*
 * iexpr_cached -- return true if np is in the iexpr cache
 */
int
iexpr_cached(struct node *np)
{
	struct iexpr *cp = Cache[iexpr_hash(np) % IEXPRSZ];

	/* search cache */
	for (; cp != NULL; cp = cp->next)
		if (iexpr_cmp(cp->np, np) == 0) {
			/* found it */
			return (1);
		}

	return (0);
}

/*
 * iexpr_fini -- free the iexpr cache
 */
void
iexpr_fini(void)
{
	int i;

	for (i = 0; i < IEXPRSZ; i++) {
		struct iexpr *cp;
		struct iexpr *ncp;

		for (cp = Cache[i]; cp != NULL; cp = ncp) {
			tree_free(cp->np);
			ncp = cp->next;
			FREE(cp);
		}
		Cache[i] = NULL;
	}
}

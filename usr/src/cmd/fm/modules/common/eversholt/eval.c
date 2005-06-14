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
 *
 * eval.c -- constraint evaluation module
 *
 * this module evaluates constraints.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "alloc.h"
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "eval.h"
#include "config.h"
#include "platform.h"


static struct node *eval_dup(struct node *np, struct lut *ex,
			    struct node *epnames[]);

/*
 * begins_with -- return true if rhs path begins with everything in lhs path
 */
static int
begins_with(struct node *lhs, struct node *rhs)
{
	int lnum;
	int rnum;

	if (lhs == NULL)
		return (1);	/* yep -- it all matched */

	if (rhs == NULL)
		return (0);	/* nope, ran out of rhs first */

	ASSERTeq(lhs->t, T_NAME, ptree_nodetype2str);
	ASSERTeq(rhs->t, T_NAME, ptree_nodetype2str);

	if (lhs->u.name.s != rhs->u.name.s)
		return (0);	/* nope, different component names */

	if (lhs->u.name.child && lhs->u.name.child->t == T_NUM)
		lnum = (int)lhs->u.name.child->u.ull;
	else
		out(O_DIE, "begins_with: unexpected lhs child");

	if (rhs->u.name.child && rhs->u.name.child->t == T_NUM)
		rnum = (int)rhs->u.name.child->u.ull;
	else
		out(O_DIE, "begins_with: unexpected rhs child");

	if (lnum != rnum)
		return (0);	/* nope, instance numbers were different */

	return (begins_with(lhs->u.name.next, rhs->u.name.next));
}

/*
 * evaluate a variety of functions and place result in valuep.  return 1 if
 * function evaluation was successful; 0 if otherwise (e.g., the case of an
 * invalid argument to the function)
 */
/*ARGSUSED*/
static int
eval_func(struct node *funcnp, struct lut *ex, struct node *epnames[],
    struct node *np, struct lut **globals,
    struct config *croot, struct arrow *arrowp, int try, struct evalue *valuep)
{
	const char *funcname = funcnp->u.func.s;

	if (funcname == L_within) {
		/* within()'s are not really constraints -- always true */
		valuep->t = UINT64;
		valuep->v = 1;
		return (1);
	} else if (funcname == L_is_under) {
		struct node *lhs;
		struct node *rhs;

		if (np->u.expr.left->t == T_NAME)
			lhs = np->u.expr.left;
		else if (np->u.expr.left->u.func.s == L_fru)
			lhs = eval_fru(np->u.expr.left->u.func.arglist);
		else if (np->u.expr.left->u.func.s == L_asru)
			lhs = eval_asru(np->u.expr.left->u.func.arglist);
		else
			out(O_DIE, "is_under: unexpected lhs type: %s",
			    ptree_nodetype2str(np->u.expr.left->t));

		if (np->u.expr.right->t == T_NAME)
			rhs = np->u.expr.right;
		else if (np->u.expr.right->u.func.s == L_fru)
			rhs = eval_fru(np->u.expr.right->u.func.arglist);
		else if (np->u.expr.right->u.func.s == L_asru)
			rhs = eval_asru(np->u.expr.right->u.func.arglist);
		else
			out(O_DIE, "is_under: unexpected rhs type: %s",
			    ptree_nodetype2str(np->u.expr.right->t));

		/* eval_dup will expand wildcards, iterators, etc... */
		lhs = eval_dup(lhs, ex, epnames);
		rhs = eval_dup(rhs, ex, epnames);
		valuep->t = UINT64;
		valuep->v = begins_with(lhs, rhs);

		out(O_ALTFP|O_VERB2|O_NONL, "eval_func:is_under(");
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, lhs);
		out(O_ALTFP|O_VERB2|O_NONL, ",");
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, rhs);
		out(O_ALTFP|O_VERB2, ") returned %d", (int)valuep->v);

		tree_free(lhs);
		tree_free(rhs);

		return (1);
	}

	if (try)
		return (0);

	if (funcname == L_fru) {
		valuep->t = NODEPTR;
		valuep->v = (unsigned long long)eval_fru(np);
		return (1);
	} else if (funcname == L_asru) {
		valuep->t = NODEPTR;
		valuep->v = (unsigned long long)eval_asru(np);
		return (1);
	} else if (funcname == L_call) {
		return (! platform_call(np, globals, croot, arrowp, valuep));
	} else if (funcname == L_is_connected) {
		return (! config_is_connected(np, croot, valuep));
	} else if (funcname == L_is_on) {
		return (! config_is_on(np, croot, valuep));
	} else if (funcname == L_is_present) {
		return (! config_is_present(np, croot, valuep));
	} else if (funcname == L_is_type) {
		return (! config_is_type(np, croot, valuep));
	} else if (funcname == L_confprop) {
		return (! config_confprop(np, croot, valuep));
	} else if (funcname == L_envprop) {
		outfl(O_DIE, np->file, np->line,
		    "eval_func: %s not yet supported", funcname);
	} else if (funcname == L_payloadprop) {
		outfl(O_ALTFP|O_VERB|O_NONL, np->file, np->line,
		    "payloadprop(\"%s\") ", np->u.quote.s);
		if (funcnp->u.func.cachedval != NULL) {
			*valuep = *(struct evalue *)(funcnp->u.func.cachedval);
			out(O_ALTFP|O_VERB, "cached: %llu", valuep->v);
			return (1);
		} else if (platform_payloadprop(np, valuep)) {
			/* platform_payloadprop() returned false, pass it on */
			out(O_ALTFP|O_VERB, "failed.");
			return (0);
		} else {
			/* got back true, cache the value */
			funcnp->u.func.cachedval =
			    MALLOC(sizeof (struct evalue));
			*(struct evalue *)(funcnp->u.func.cachedval) =
			    *valuep;
			out(O_ALTFP|O_VERB, "returned: %llu", valuep->v);
			return (1);
		}
	} else
		outfl(O_DIE, np->file, np->line,
		    "eval_func: unexpected func: %s", funcname);
	/*NOTREACHED*/
}

static struct node *
eval_wildcardedname(struct node *np, struct lut *ex, struct node *epnames[])
{
	struct node *npstart, *npend, *npref, *newnp;
	struct node *np1, *np2, *retp;
	int i;

	if (epnames == NULL || epnames[0] == NULL)
		return (NULL);

	for (i = 0; epnames[i] != NULL; i++) {
		if (tree_namecmp(np, epnames[i]) == 0)
			return (NULL);
	}

	/*
	 * get to this point if np does not match any of the entries in
	 * epnames.  check if np is a path that must preceded by a wildcard
	 * portion.  for this case we must first determine which epnames[]
	 * entry should be used for wildcarding.
	 */
	npstart = NULL;
	for (i = 0; epnames[i] != NULL; i++) {
		for (npref = epnames[i]; npref; npref = npref->u.name.next) {
			if (npref->u.name.s == np->u.name.s) {
				for (np1 = npref, np2 = np;
				    np1 != NULL && np2 != NULL;
				    np1 = np1->u.name.next,
					    np2 = np2->u.name.next) {
					if (np1->u.name.s != np2->u.name.s)
						break;
				}
				if (np2 == NULL) {
					npstart = epnames[i];
					npend = npref;
					if (np1 == NULL)
						break;
				}
			}
		}

		if (npstart != NULL)
			break;
	}

	if (npstart == NULL) {
		/* no match; np is not a path to be wildcarded */
		return (NULL);
	}

	/*
	 * dup (npstart -- npend) which is the wildcarded portion.  all
	 * children should be T_NUMs.
	 */
	retp = NULL;
	for (npref = npstart;
	    ! (npref == NULL || npref == npend);
	    npref = npref->u.name.next) {
		newnp = newnode(T_NAME, np->file, np->line);

		newnp->u.name.t = npref->u.name.t;
		newnp->u.name.s = npref->u.name.s;
		newnp->u.name.last = newnp;
		newnp->u.name.it = npref->u.name.it;
		newnp->u.name.cp = npref->u.name.cp;

		ASSERT(npref->u.name.child != NULL);
		ASSERT(npref->u.name.child->t == T_NUM);
		newnp->u.name.child = newnode(T_NUM, np->file, np->line);
		newnp->u.name.child->u.ull = npref->u.name.child->u.ull;

		if (retp == NULL) {
			retp = newnp;
		} else {
			retp->u.name.last->u.name.next = newnp;
			retp->u.name.last = newnp;
		}
	}

	ASSERT(retp != NULL);

	/* now append the nonwildcarded portion */
	retp = tree_name_append(retp, eval_dup(np, ex, NULL));

	return (retp);
}

static struct node *
eval_dup(struct node *np, struct lut *ex, struct node *epnames[])
{
	struct node *newnp;

	if (np == NULL)
		return (NULL);

	switch (np->t) {
	case T_GLOBID:
		return (tree_globid(np->u.globid.s, np->file, np->line));

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
		return (tree_expr(np->t,
				    eval_dup(np->u.expr.left, ex, epnames),
				    eval_dup(np->u.expr.right, ex, epnames)));

	case T_NAME: {
		struct iterinfo *iterinfop;
		struct node *newchild = NULL;

		iterinfop = lut_lookup(ex, (void *)np->u.name.s, NULL);
		if (iterinfop != NULL) {
			/* explicit iterator; not part of pathname */
			newnp = newnode(T_NUM, np->file, np->line);
			newnp->u.ull = iterinfop->num;
			return (newnp);
		}

		/* see if np is a path with wildcard portion */
		newnp = eval_wildcardedname(np, ex, epnames);
		if (newnp != NULL)
			return (newnp);

		/* turn off wildcarding for child */
		newchild = eval_dup(np->u.name.child, ex, NULL);

		if (newchild != NULL) {
			if (newchild->t != T_NUM) {
				/*
				 * not a number, eh?  we must resolve this
				 * to a number.
				 */
				struct evalue value;

				if (eval_expr(newchild, ex, epnames,
				    NULL, NULL, NULL, 1, &value) == 0 ||
				    value.t != UINT64) {
					outfl(O_DIE, np->file, np->line,
					    "eval_dup: could not resolve "
					    "iterator of %s", np->u.name.s);
				}

				tree_free(newchild);
				newchild = newnode(T_NUM, np->file, np->line);
				newchild->u.ull = value.v;
			}

			newnp = newnode(np->t, np->file, np->line);
			newnp->u.name.s = np->u.name.s;
			newnp->u.name.it = np->u.name.it;
			newnp->u.name.cp = np->u.name.cp;

			newnp->u.name.last = newnp;
			newnp->u.name.child = newchild;

			if (np->u.name.next != NULL) {
				/* turn off wildcarding for next */
				return (tree_name_append(newnp,
					eval_dup(np->u.name.next, ex, NULL)));
			} else {
				return (newnp);
			}
		} else {
			outfl(O_DIE, np->file, np->line,
			    "eval_dup: internal error: \"%s\" is neither "
			    "an iterator nor a pathname", np->u.name.s);
		}
		/*NOTREACHED*/
		break;
	}

	case T_FUNC:
		return (tree_func(np->u.func.s,
		    eval_dup(np->u.func.arglist, ex, epnames),
		    np->file, np->line));

	case T_QUOTE:
		newnp = newnode(T_QUOTE, np->file, np->line);
		newnp->u.quote.s = np->u.quote.s;
		return (newnp);

	case T_NUM:
		newnp = newnode(T_NUM, np->file, np->line);
		newnp->u.ull = np->u.ull;
		return (newnp);

	default:
		outfl(O_DIE, np->file, np->line,
		    "eval_dup: unexpected node type: %s",
		    ptree_nodetype2str(np->t));
	}
	/*NOTREACHED*/
}

/*
 * eval_potential -- see if constraint is potentially true
 *
 * this function is used at instance tree creation time to see if
 * any constraints are already known to be false.  if this function
 * returns false, then the constraint will always be false and there's
 * no need to include the propagation arrow in the instance tree.
 *
 * if this routine returns true, either the constraint is known to
 * be always true (so there's no point in attaching the constraint
 * to the propagation arrow in the instance tree), or the constraint
 * contains "deferred" expressions like global variables or poller calls
 * and so it must be evaluated during calls to fme_eval().  in this last
 * case, where a constraint needs to be attached to the propagation arrow
 * in the instance tree, this routine returns a newly created constraint
 * in *newc where all the non-deferred things have been filled in.
 *
 * so in summary:
 *
 *	return of false: constraint can never be true, *newc will be NULL.
 *
 *	return of true with *newc unchanged: constraint will always be true.
 *
 *	return of true with *newc changed: use new constraint in *newc.
 *
 * the lookup table for all explicit iterators, ex, is passed in.
 *
 * *newc can either be NULL on entry, or if can contain constraints from
 * previous calls to eval_potential() (i.e. for building up an instance
 * tree constraint from several potential constraints).  if *newc already
 * contains constraints, anything added to it will be joined by adding
 * a T_AND node at the top of *newc.
 */
int
eval_potential(struct node *np, struct lut *ex, struct node *epnames[],
	    struct node **newc)
{
	struct node *newnp;
	struct evalue value;

	if (eval_expr(np, ex, epnames, NULL, NULL, NULL, 1, &value) == 0) {
		/*
		 * couldn't eval expression because
		 * it contains deferred items.  make
		 * a duplicate expression with all the
		 * non-deferred items expanded.
		 */
		newnp = eval_dup(np, ex, epnames);

		if (*newc == NULL) {
			/*
			 * constraint is potentially true if deferred
			 * expression in newnp is true.  *newc was NULL
			 * so new constraint is just the one in newnp.
			 */
			*newc = newnp;
			return (1);
		} else {
			/*
			 * constraint is potentially true if deferred
			 * expression in newnp is true.  *newc already
			 * contained a constraint so add an AND with the
			 * constraint in newnp.
			 */
			*newc = tree_expr(T_AND, *newc, newnp);
			return (1);
		}
	} else if (value.t == UNDEFINED) {
		/* constraint can never be true */
		return (0);
	} else if (value.t == UINT64 && value.v == 0) {
		/* constraint can never be true */
		return (0);
	} else {
		/* constraint is always true (nothing deferred to eval) */
		return (1);
	}
}

static int
check_expr_args(struct evalue *lp, struct evalue *rp, enum datatype dtype,
		struct node *np)
{
	if (dtype != UNDEFINED && lp->t != dtype) {
		outfl(O_OK, np->file, np->line,
			"invalid datatype of argument for operation %s",
			ptree_nodetype2str(np->t));
		return (1);
	}

	if (rp != NULL && lp->t != rp->t) {
		outfl(O_OK, np->file, np->line,
			"mismatch in datatype of arguments for operation %s",
			ptree_nodetype2str(np->t));
		return (1);
	}

	return (0);
}

/*
 * eval_expr -- evaluate expression into *valuep
 *
 * the meaning of the return value depends on the input value of try.
 *
 * for try == 1: if any deferred items are encounted, bail out and return
 * false.  returns true if we made it through entire expression without
 * hitting any deferred items.
 *
 * for try == 0: return true if all operations were performed successfully.
 * return false if otherwise.  for example, any of the following conditions
 * will result in a false return value:
 *   - attempted use of an uninitialized global variable
 *   - failure in function evaluation
 *   - illegal arithmetic operation (argument out of range)
 */
int
eval_expr(struct node *np, struct lut *ex, struct node *epnames[],
	struct lut **globals, struct config *croot, struct arrow *arrowp,
	int try, struct evalue *valuep)
{
	struct evalue *gval;
	struct evalue lval;
	struct evalue rval;

	if (np == NULL) {
		valuep->t = UINT64;
		valuep->v = 1;	/* no constraint means "true" */
		return (1);
	}

	valuep->t = UNDEFINED;

	switch (np->t) {
	case T_GLOBID:
		if (try)
			return (0);

		/*
		 * only handle case of getting (and not setting) the value
		 * of a global variable
		 */
		gval = lut_lookup(*globals, (void *)np->u.globid.s, NULL);
		if (gval == NULL) {
			valuep->t = UNDEFINED;
			return (0);
		} else {
			valuep->t = gval->t;
			valuep->v = gval->v;
			return (1);
		}

	case T_ASSIGN:
		if (try)
			return (0);

		/*
		 * first evaluate rhs, then try to store value in lhs which
		 * should be a global variable
		 */
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
			    arrowp, try, &rval))
			return (0);

		ASSERT(np->u.expr.left->t == T_GLOBID);
		gval = lut_lookup(*globals,
				(void *)np->u.expr.left->u.globid.s, NULL);

		if (gval == NULL) {
			gval = MALLOC(sizeof (*gval));
			*globals = lut_add(*globals,
					(void *) np->u.expr.left->u.globid.s,
					gval, NULL);
		}

		gval->t = rval.t;
		gval->v = rval.v;
		valuep->t = rval.t;
		valuep->v = rval.v;
		return (1);

	case T_EQ:
#define	IMPLICIT_ASSIGN_IN_EQ
#ifdef IMPLICIT_ASSIGN_IN_EQ
		/*
		 * if lhs is an uninitialized global variable, perform
		 * an assignment.
		 *
		 * one insidious side effect of implicit assignment is
		 * that the "==" operator does not return a Boolean if
		 * implicit assignment was performed.
		 */
		if (try == 0 &&
		    np->u.expr.left->t == T_GLOBID &&
		    (gval = lut_lookup(*globals,
			(void *)np->u.expr.left->u.globid.s, NULL)) == NULL) {
			if (!eval_expr(np->u.expr.right, ex, epnames, globals,
					croot, arrowp, try, &rval))
				return (0);

			gval = MALLOC(sizeof (*gval));
			*globals = lut_add(*globals,
					(void *) np->u.expr.left->u.globid.s,
					gval, NULL);

			gval->t = rval.t;
			gval->v = rval.v;
			valuep->t = rval.t;
			valuep->v = rval.v;
			return (1);
		}
#endif  /* IMPLICIT_ASSIGN_IN_EQ */

		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v == rval.v);
		return (1);

	case T_LT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v < rval.v);
		return (1);

	case T_LE:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v <= rval.v);
		return (1);

	case T_GT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v > rval.v);
		return (1);

	case T_GE:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v >= rval.v);
		return (1);

	case T_BITAND:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v & rval.v);
		return (1);

	case T_BITOR:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v | rval.v);
		return (1);

	case T_BITXOR:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v ^ rval.v);
		return (1);

	case T_BITNOT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		ASSERT(np->u.expr.right == NULL);
		if (check_expr_args(&lval, NULL, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = ~ lval.v;
		return (1);

	case T_LSHIFT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v << rval.v);
		return (1);

	case T_RSHIFT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v >> rval.v);
		return (1);

	case T_CONDIF: {
		struct node *retnp;
		int dotrue = 0;

		/*
		 * evaluate
		 *	expression ? stmtA [ : stmtB ]
		 *
		 * first see if expression is true or false, then determine
		 * if stmtA (or stmtB, if it exists) should be evaluated.
		 *
		 * "dotrue = 1" means stmtA should be evaluated.
		 */
		if (eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval) &&
		    lval.t != UNDEFINED && lval.v != 0)
			dotrue = 1;

		ASSERT(np->u.expr.right != NULL);
		if (np->u.expr.right->t == T_CONDELSE) {
			if (dotrue)
				retnp = np->u.expr.right->u.expr.left;
			else
				retnp = np->u.expr.right->u.expr.right;
		} else {
			/* no ELSE clause */
			if (dotrue)
				retnp = np->u.expr.right;
			else {
				valuep->t = UINT64;
				valuep->v = 0;
				return (0);
			}
		}

		if (!eval_expr(retnp, ex, epnames, globals, croot,
			    arrowp, try, valuep))
			return (0);
		return (1);
	}

	case T_CONDELSE:
		/*
		 * shouldn't get here, since T_CONDELSE is supposed to be
		 * evaluated as part of T_CONDIF
		 */
		out(O_ALTFP|O_DIE, "eval_expr: wrong context for operation %s",
		    ptree_nodetype2str(np->t));
		return (0);

	case T_NE:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UNDEFINED, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v != rval.v);
		return (1);

	case T_LIST:
	case T_AND:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, valuep))
			return (0);
		if (valuep->v == 0) {
			valuep->t = UINT64;
			return (1);
		}
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, valuep))
			return (0);
		valuep->t = UINT64;
		valuep->v = valuep->v == 0 ? 0 : 1;
		return (1);

	case T_OR:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, valuep))
			return (0);
		if (valuep->v != 0) {
			valuep->t = UINT64;
			valuep->v = 1;
			return (1);
		}
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, valuep))
			return (0);
		valuep->t = UINT64;
		valuep->v = valuep->v == 0 ? 0 : 1;
		return (1);

	case T_NOT:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, valuep))
			return (0);
		valuep->t = UINT64;
		valuep->v = ! valuep->v;
		return (1);

	case T_ADD:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = lval.v + rval.v;
		return (1);

	case T_SUB:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* since valuep is unsigned, return false if lval.v < rval.v */
		if (lval.v < rval.v) {
			out(O_ERR, "eval_expr: T_SUB result is out of range");
			valuep->t = UNDEFINED;
			return (0);
		}

		valuep->t = lval.t;
		valuep->v = lval.v - rval.v;
		return (1);

	case T_MUL:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = lval.v * rval.v;
		return (1);

	case T_DIV:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* return false if dividing by zero */
		if (rval.v == 0) {
			out(O_ERR, "eval_expr: T_DIV division by zero");
			valuep->t = UNDEFINED;
			return (0);
		}

		valuep->t = lval.t;
		valuep->v = lval.v / rval.v;
		return (1);

	case T_MOD:
		if (!eval_expr(np->u.expr.left, ex, epnames, globals, croot,
				arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, epnames, globals, croot,
				arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* return false if dividing by zero */
		if (rval.v == 0) {
			out(O_ERR, "eval_expr: T_MOD division by zero");
			valuep->t = UNDEFINED;
			return (0);
		}

		valuep->t = lval.t;
		valuep->v = lval.v % rval.v;
		return (1);

	case T_NAME:
		if (try) {
			struct iterinfo *iterinfop;

			/*
			 * at itree_create() time, we can expand simple
			 * iterators.  anything else we'll punt on.
			 */
			iterinfop = lut_lookup(ex, (void *)np->u.name.s, NULL);
			if (iterinfop != NULL) {
				/* explicit iterator; not part of pathname */
				valuep->t = UINT64;
				valuep->v = (unsigned long long)iterinfop->num;
				return (1);
			}
			return (0);
		}

		/* return address of struct node */
		valuep->t = NODEPTR;
		valuep->v = (unsigned long long)np;
		return (1);

	case T_QUOTE:
		valuep->t = STRING;
		valuep->v = (unsigned long long)np->u.quote.s;
		return (1);

	case T_FUNC:
		return (eval_func(np, ex, epnames, np->u.func.arglist,
				globals, croot, arrowp, try, valuep));

	case T_NUM:
		valuep->t = UINT64;
		valuep->v = np->u.ull;
		return (1);

	default:
		outfl(O_DIE, np->file, np->line,
		    "eval_expr: unexpected node type: %s",
		    ptree_nodetype2str(np->t));
	}
	/*NOTREACHED*/
}

/*
 * eval_fru() and eval_asru() don't do much, but are called from a number
 * of places.
 */
struct node *
eval_fru(struct node *np)
{
	ASSERT(np->t == T_NAME);
	return (np);
}

struct node *
eval_asru(struct node *np)
{
	ASSERT(np->t == T_NAME);
	return (np);
}

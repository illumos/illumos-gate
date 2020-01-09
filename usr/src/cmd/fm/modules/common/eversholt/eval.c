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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * eval.c -- constraint evaluation module
 *
 * this module evaluates constraints.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fm/libtopo.h>
#include "alloc.h"
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "ipath.h"
#include "eval.h"
#include "config.h"
#include "platform.h"
#include "fme.h"
#include "stats.h"

static struct node *eval_dup(struct node *np, struct lut *ex,
    struct node *events[]);
static int check_expr_args(struct evalue *lp, struct evalue *rp,
    enum datatype dtype, struct node *np);
static struct node *eval_fru(struct node *np);
static struct node *eval_asru(struct node *np);

extern fmd_hdl_t *Hdl;	/* handle from eft.c */

/*
 * begins_with -- return true if rhs path begins with everything in lhs path
 */
static int
begins_with(struct node *lhs, struct node *rhs, struct lut *ex)
{
	int lnum;
	int rnum;
	struct iterinfo *iterinfop;

	if (lhs == NULL)
		return (1);	/* yep -- it all matched */

	if (rhs == NULL)
		return (0);	/* nope, ran out of rhs first */

	ASSERTeq(lhs->t, T_NAME, ptree_nodetype2str);
	ASSERTeq(rhs->t, T_NAME, ptree_nodetype2str);

	if (lhs->u.name.s != rhs->u.name.s)
		return (0);	/* nope, different component names */

	if (lhs->u.name.child && lhs->u.name.child->t == T_NUM) {
		lnum = (int)lhs->u.name.child->u.ull;
	} else if (lhs->u.name.child && lhs->u.name.child->t == T_NAME) {
		iterinfop = lut_lookup(ex, (void *)lhs->u.name.child->u.name.s,
		    NULL);
		if (iterinfop != NULL)
			lnum = iterinfop->num;
		else
			out(O_DIE, "begins_with: unexpected lhs child");
	} else {
		out(O_DIE, "begins_with: unexpected lhs child");
	}

	if (rhs->u.name.child && rhs->u.name.child->t == T_NUM) {
		rnum = (int)rhs->u.name.child->u.ull;
	} else if (rhs->u.name.child && rhs->u.name.child->t == T_NAME) {
		iterinfop = lut_lookup(ex, (void *)rhs->u.name.child->u.name.s,
		    NULL);
		if (iterinfop != NULL)
			rnum = iterinfop->num;
		else
			out(O_DIE, "begins_with: unexpected rhs child");
	} else {
		out(O_DIE, "begins_with: unexpected rhs child");
	}

	if (lnum != rnum)
		return (0);	/* nope, instance numbers were different */

	return (begins_with(lhs->u.name.next, rhs->u.name.next, ex));
}

/*
 * eval_getname - used by eval_func to evaluate a name, preferably without using
 * eval_dup (but if it does have to use eval_dup then the *dupedp flag is set).
 */
static struct node *
eval_getname(struct node *funcnp, struct lut *ex, struct node *events[],
    struct node *np, struct lut **globals,
    struct config *croot, struct arrow *arrowp, int try, int *dupedp)
{
	struct node *nodep;
	const char *funcname = funcnp->u.func.s;
	struct evalue val;

	if (np->t == T_NAME)
		nodep = np;
	else if (np->t == T_FUNC && np->u.func.s == L_fru)
		nodep = eval_fru(np->u.func.arglist);
	else if (np->t == T_FUNC && np->u.func.s == L_asru)
		nodep = eval_asru(np->u.func.arglist);
	else if (np->t == T_FUNC) {
		if (eval_expr(np, ex, events, globals, croot, arrowp, try,
		    &val) == 0)
			/*
			 * Can't evaluate yet. Return null so constraint is
			 * deferred.
			 */
			return (NULL);
		if (val.t == NODEPTR)
			return ((struct node *)(uintptr_t)val.v);
		else
			/*
			 * just return the T_FUNC - which the caller will
			 * reject.
			 */
			return (np);
	} else
		out(O_DIE, "%s: unexpected type: %s",
		    funcname, ptree_nodetype2str(np->t));
	if (try) {
		if (eval_expr(nodep, ex, events, globals, croot,
		    arrowp, try, &val) && val.t == NODEPTR)
			nodep = (struct node *)(uintptr_t)val.v;
		else {
			*dupedp = 1;
			nodep = eval_dup(nodep, ex, events);
		}
	}
	return (nodep);
}

/*ARGSUSED*/
static int
eval_cat(struct node *np, struct lut *ex, struct node *events[],
	struct lut **globals, struct config *croot, struct arrow *arrowp,
	int try, struct evalue *valuep)
{
	if (np->t == T_LIST) {
		struct evalue lval;
		struct evalue rval;
		int len;
		char *s;

		if (!eval_cat(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_cat(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		len = snprintf(NULL, 0, "%s%s", (char *)(uintptr_t)lval.v,
		    (char *)(uintptr_t)rval.v);
		s = MALLOC(len + 1);

		(void) snprintf(s, len + 1, "%s%s", (char *)(uintptr_t)lval.v,
		    (char *)(uintptr_t)rval.v);
		outfl(O_ALTFP|O_VERB2, np->file, np->line,
		    "eval_cat: %s %s returns %s", (char *)(uintptr_t)lval.v,
		    (char *)(uintptr_t)rval.v, s);
		valuep->t = STRING;
		valuep->v = (uintptr_t)stable(s);
		FREE(s);
	} else {
		if (!eval_expr(np, ex, events, globals, croot,
		    arrowp, try, valuep))
			return (0);
		if (check_expr_args(valuep, NULL, STRING, np))
			return (0);
	}
	return (1);
}

/*
 * evaluate a variety of functions and place result in valuep.  return 1 if
 * function evaluation was successful; 0 if otherwise (e.g., the case of an
 * invalid argument to the function)
 */
/*ARGSUSED*/
static int
eval_func(struct node *funcnp, struct lut *ex, struct node *events[],
    struct node *np, struct lut **globals,
    struct config *croot, struct arrow *arrowp, int try, struct evalue *valuep)
{
	const char *funcname = funcnp->u.func.s;
	int duped_lhs = 0, duped_rhs = 0, duped = 0;
	struct node *lhs;
	struct node *rhs;
	struct config *cp;
	struct node *nodep;
	char *path;
	struct evalue val;

	if (funcname == L_within) {
		/* within()'s are not really constraints -- always true */
		valuep->t = UINT64;
		valuep->v = 1;
		return (1);
	} else if (funcname == L_is_under) {
		lhs = eval_getname(funcnp, ex, events, np->u.expr.left, globals,
		    croot, arrowp, try, &duped_lhs);
		rhs = eval_getname(funcnp, ex, events, np->u.expr.right,
		    globals, croot, arrowp, try, &duped_rhs);
		if (!rhs || !lhs)
			return (0);
		if (rhs->t != T_NAME || lhs->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		valuep->t = UINT64;
		valuep->v = begins_with(lhs, rhs, ex);
		out(O_ALTFP|O_VERB2|O_NONL, "eval_func:is_under(");
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, lhs);
		out(O_ALTFP|O_VERB2|O_NONL, ",");
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, rhs);
		out(O_ALTFP|O_VERB2|O_NONL, ") returned %d", (int)valuep->v);

		if (duped_lhs)
			tree_free(lhs);
		if (duped_rhs)
			tree_free(rhs);
		return (1);
	} else if (funcname == L_confprop || funcname == L_confprop_defined) {
		const char *s;

		/* for now s will point to a quote [see addconfigprop()] */
		ASSERT(np->u.expr.right->t == T_QUOTE);

		nodep = eval_getname(funcnp, ex, events, np->u.expr.left,
		    globals, croot, arrowp, try, &duped);
		if (!nodep)
			return (0);
		if (nodep->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		if (nodep->u.name.last->u.name.cp != NULL) {
			cp = nodep->u.name.last->u.name.cp;
		} else {
			path = ipath2str(NULL, ipath(nodep));
			cp = config_lookup(croot, path, 0);
			FREE((void *)path);
		}
		if (cp == NULL) {
			if (funcname == L_confprop) {
				out(O_ALTFP|O_VERB3, "%s: path ", funcname);
				ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, nodep);
				out(O_ALTFP|O_VERB3, " not found");
				valuep->v = (uintptr_t)stable("");
				valuep->t = STRING;
				if (duped)
					tree_free(nodep);
				return (1);
			} else {
				valuep->v = 0;
				valuep->t = UINT64;
				if (duped)
					tree_free(nodep);
				return (1);
			}
		}
		s = config_getprop(cp, np->u.expr.right->u.quote.s);
		if (s == NULL && strcmp(np->u.expr.right->u.quote.s,
		    "class-code") == 0)
			s = config_getprop(cp, "CLASS-CODE");
		if (s == NULL) {
			if (funcname == L_confprop) {
				out(O_ALTFP|O_VERB3|O_NONL,
				    "%s: \"%s\" not found for path ",
				    funcname, np->u.expr.right->u.quote.s);
				ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, nodep);
				valuep->v = (uintptr_t)stable("");
				valuep->t = STRING;
				if (duped)
					tree_free(nodep);
				return (1);
			} else {
				valuep->v = 0;
				valuep->t = UINT64;
				if (duped)
					tree_free(nodep);
				return (1);
			}
		}

		if (funcname == L_confprop) {
			valuep->v = (uintptr_t)stable(s);
			valuep->t = STRING;
			out(O_ALTFP|O_VERB3|O_NONL, "  %s(\"", funcname);
			ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, nodep);
			out(O_ALTFP|O_VERB3|O_NONL,
			    "\", \"%s\") = \"%s\"  ",
			    np->u.expr.right->u.quote.s,
			    (char *)(uintptr_t)valuep->v);
		} else {
			valuep->v = 1;
			valuep->t = UINT64;
		}
		if (duped)
			tree_free(nodep);
		return (1);
	} else if (funcname == L_is_connected) {
		const char *connstrings[] = { "connected", "CONNECTED", NULL };
		struct config *cp[2];
		const char *matchthis[2], *s;
		char *nameslist, *w;
		int i, j;

		lhs = eval_getname(funcnp, ex, events, np->u.expr.left, globals,
		    croot, arrowp, try, &duped_lhs);
		rhs = eval_getname(funcnp, ex, events, np->u.expr.right,
		    globals, croot, arrowp, try, &duped_rhs);
		if (!rhs || !lhs)
			return (0);
		if (rhs->t != T_NAME || lhs->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		path = ipath2str(NULL, ipath(lhs));
		matchthis[1] = stable(path);
		if (lhs->u.name.last->u.name.cp != NULL)
			cp[0] = lhs->u.name.last->u.name.cp;
		else
			cp[0] = config_lookup(croot, path, 0);
		FREE((void *)path);
		path = ipath2str(NULL, ipath(rhs));
		matchthis[0] = stable(path);
		if (rhs->u.name.last->u.name.cp != NULL)
			cp[1] = rhs->u.name.last->u.name.cp;
		else
			cp[1] = config_lookup(croot, path, 0);
		FREE((void *)path);
		if (duped_lhs)
			tree_free(lhs);
		if (duped_rhs)
			tree_free(rhs);

		valuep->t = UINT64;
		valuep->v = 0;
		if (cp[0] == NULL || cp[1] == NULL)
			return (1);

		/* to thine self always be connected */
		if (cp[0] == cp[1]) {
			valuep->v = 1;
			return (1);
		}

		/*
		 * Extract "connected" property from each cp. Search this
		 * property for the name associated with the other cp[].
		 */
		for (i = 0; i < 2 && valuep->v == 0; i++) {
			for (j = 0; connstrings[j] != NULL && valuep->v == 0;
			    j++) {
				s = config_getprop(cp[i],
				    stable(connstrings[j]));
				if (s != NULL) {
					nameslist = STRDUP(s);
					w = strtok(nameslist, " ,");
					while (w != NULL) {
						if (stable(w) == matchthis[i]) {
							valuep->v = 1;
							break;
						}
						w = strtok(NULL, " ,");
					}
					FREE(nameslist);
				}
			}
		}
		return (1);
	} else if (funcname == L_is_type) {
		const char *typestrings[] = { "type", "TYPE", NULL };
		const char *s;
		int i;

		nodep = eval_getname(funcnp, ex, events, np, globals,
		    croot, arrowp, try, &duped);
		if (!nodep)
			return (0);
		if (nodep->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		if (nodep->u.name.last->u.name.cp != NULL) {
			cp = nodep->u.name.last->u.name.cp;
		} else {
			path = ipath2str(NULL, ipath(nodep));
			cp = config_lookup(croot, path, 0);
			FREE((void *)path);
		}
		if (duped)
			tree_free(nodep);

		valuep->t = STRING;
		valuep->v = (uintptr_t)stable("");
		if (cp == NULL)
			return (1);
		for (i = 0; typestrings[i] != NULL; i++) {
			s = config_getprop(cp, stable(typestrings[i]));
			if (s != NULL) {
				valuep->v = (uintptr_t)stable(s);
				break;
			}
		}
		return (1);
	} else if (funcname == L_is_on) {
		const char *onstrings[] = { "on", "ON", NULL };
		const char *truestrings[] = { "yes", "YES", "y", "Y",
				    "true", "TRUE", "t", "T", "1", NULL };
		const char *s;
		int i, j;

		nodep = eval_getname(funcnp, ex, events, np, globals,
		    croot, arrowp, try, &duped);
		if (!nodep)
			return (0);
		if (nodep->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		if (nodep->u.name.last->u.name.cp != NULL) {
			cp = nodep->u.name.last->u.name.cp;
		} else {
			path = ipath2str(NULL, ipath(nodep));
			cp = config_lookup(croot, path, 0);
			FREE((void *)path);
		}
		if (duped)
			tree_free(nodep);

		valuep->t = UINT64;
		valuep->v = 0;
		if (cp == NULL)
			return (1);
		for (i = 0; onstrings[i] != NULL; i++) {
			s = config_getprop(cp, stable(onstrings[i]));
			if (s != NULL) {
				s = stable(s);
				for (j = 0; truestrings[j] != NULL; j++) {
					if (s == stable(truestrings[j])) {
						valuep->v = 1;
						return (1);
					}
				}
			}
		}
		return (1);
	} else if (funcname == L_is_present) {
		nodep = eval_getname(funcnp, ex, events, np, globals,
		    croot, arrowp, try, &duped);
		if (!nodep)
			return (0);
		if (nodep->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		if (nodep->u.name.last->u.name.cp != NULL) {
			cp = nodep->u.name.last->u.name.cp;
		} else {
			path = ipath2str(NULL, ipath(nodep));
			cp = config_lookup(croot, path, 0);
			FREE((void *)path);
		}
		if (duped)
			tree_free(nodep);

		valuep->t = UINT64;
		valuep->v = 0;
		if (cp != NULL)
			valuep->v = 1;
		return (1);
	} else if (funcname == L_has_fault) {
		nvlist_t *rsrc = NULL;

		nodep = eval_getname(funcnp, ex, events, np->u.expr.left,
		    globals, croot, arrowp, try, &duped);
		if (!nodep)
			return (0);
		if (nodep->t != T_NAME) {
			valuep->t = UNDEFINED;
			return (1);
		}

		path = ipath2str(NULL, ipath(nodep));
		platform_unit_translate(0, croot, TOPO_PROP_RESOURCE,
		    &rsrc, path);
		outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line, "has_fault(");
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, nodep);
		out(O_ALTFP|O_VERB2|O_NONL, "(%s), \"%s\") ", path,
		    np->u.expr.right->u.quote.s);
		FREE((void *)path);
		if (duped)
			tree_free(nodep);

		if (rsrc == NULL) {
			valuep->v = 0;
			out(O_ALTFP|O_VERB2, "no path");
		} else {
			valuep->v = fmd_nvl_fmri_has_fault(Hdl, rsrc,
			    FMD_HAS_FAULT_RESOURCE,
			    strcmp(np->u.expr.right->u.quote.s, "") == 0 ?
			    NULL : (char *)np->u.expr.right->u.quote.s);
			out(O_ALTFP|O_VERB2, "returned %lld", valuep->v);
			nvlist_free(rsrc);
		}
		valuep->t = UINT64;
		return (1);
	} else if (funcname == L_count) {
		struct stats *statp;
		struct istat_entry ent;

		ASSERTinfo(np->t == T_EVENT, ptree_nodetype2str(np->t));

		nodep = np->u.event.epname;
		if (try) {
			if (eval_expr(nodep, ex, events, globals,
			    croot, arrowp, try, &val) && val.t == NODEPTR)
				nodep = (struct node *)(uintptr_t)val.v;
			else {
				duped = 1;
				nodep = eval_dup(nodep, ex, events);
			}
		}
		ent.ename = np->u.event.ename->u.name.s;
		ent.ipath = ipath(nodep);
		valuep->t = UINT64;
		if ((statp = (struct stats *)
		    lut_lookup(Istats, &ent, (lut_cmp)istat_cmp)) == NULL)
			valuep->v = 0;
		else
			valuep->v = stats_counter_value(statp);
		if (duped)
			tree_free(nodep);
		return (1);
	} else if (funcname == L_envprop) {
		outfl(O_DIE, np->file, np->line,
		    "eval_func: %s not yet supported", funcname);
	}

	if (try)
		return (0);

	if (funcname == L_fru) {
		valuep->t = NODEPTR;
		valuep->v = (uintptr_t)eval_fru(np);
		return (1);
	} else if (funcname == L_asru) {
		valuep->t = NODEPTR;
		valuep->v = (uintptr_t)eval_asru(np);
		return (1);
	} else if (funcname == L_defined) {
		ASSERTeq(np->t, T_GLOBID, ptree_nodetype2str);
		valuep->t = UINT64;
		valuep->v = (lut_lookup(*globals,
		    (void *)np->u.globid.s, NULL) != NULL);
		return (1);
	} else if (funcname == L_call) {
		return (! platform_call(np, globals, croot, arrowp, valuep));
	} else if (funcname == L_payloadprop) {
		outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
		    "payloadprop(\"%s\") ", np->u.quote.s);

		if (arrowp->head->myevent->count == 0) {
			/*
			 * Haven't seen this ereport yet, so must defer
			 */
			out(O_ALTFP|O_VERB2, "ereport not yet seen - defer.");
			return (0);
		} else if (platform_payloadprop(np, valuep)) {
			/* platform_payloadprop() returned false */
			out(O_ALTFP|O_VERB, "not found.");
			valuep->t = UNDEFINED;
			return (1);
		} else {
			switch (valuep->t) {
			case NODEPTR:
				if (((struct node *)(uintptr_t)
				    (valuep->v))->t == T_NAME) {
					char *s = ipath2str(NULL,
					    ipath((struct node *)
					    (uintptr_t)valuep->v));
					out(O_ALTFP|O_VERB2,
					    "found: \"%s\"", s);
					FREE(s);
				} else
					out(O_ALTFP|O_VERB2, "found: %llu",
					    valuep->v);
				break;
			case UINT64:
				out(O_ALTFP|O_VERB2, "found: %llu", valuep->v);
				break;
			case STRING:
				out(O_ALTFP|O_VERB2, "found: \"%s\"",
				    (char *)(uintptr_t)valuep->v);
				break;
			default:
				out(O_ALTFP|O_VERB2, "found: undefined");
				break;
			}
			return (1);
		}
	} else if (funcname == L_setpayloadprop) {
		struct evalue *payloadvalp;
		int alloced = 0;

		ASSERTinfo(np->t == T_LIST, ptree_nodetype2str(np->t));
		ASSERTinfo(np->u.expr.left->t == T_QUOTE,
		    ptree_nodetype2str(np->u.expr.left->t));

		if (!(arrowp->head->myevent->cached_state & REQMNTS_CREDIBLE))
			return (0);

		outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
		    "setpayloadprop: %s: %s=",
		    arrowp->tail->myevent->enode->u.event.ename->u.name.s,
		    np->u.expr.left->u.quote.s);
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, np->u.expr.right);

		/*
		 * allocate a struct evalue to hold the payload property's
		 * value, unless we've been here already, in which case we
		 * might calculate a different value, but we'll store it
		 * in the already-allocated struct evalue.
		 */
		if ((payloadvalp = (struct evalue *)lut_lookup(
		    arrowp->tail->myevent->payloadprops,
		    (void *)np->u.expr.left->u.quote.s, NULL)) == NULL) {
			payloadvalp = MALLOC(sizeof (*payloadvalp));
			alloced = 1;
		}

		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, payloadvalp)) {
			out(O_ALTFP|O_VERB2, " (cannot eval)");
			if (alloced)
				FREE(payloadvalp);
			return (0);
		} else {
			if (payloadvalp->t == UNDEFINED) {
				/* function is always true */
				out(O_ALTFP|O_VERB2, " (undefined)");
				valuep->t = UINT64;
				valuep->v = 1;
				return (1);
			}
			if (payloadvalp->t == UINT64)
				out(O_ALTFP|O_VERB2,
				    " (%llu)", payloadvalp->v);
			else
				out(O_ALTFP|O_VERB2, " (\"%s\")",
				    (char *)(uintptr_t)payloadvalp->v);
		}

		/* add to table of payload properties for current problem */
		arrowp->tail->myevent->payloadprops =
		    lut_add(arrowp->tail->myevent->payloadprops,
		    (void *)np->u.expr.left->u.quote.s,
		    (void *)payloadvalp, NULL);

		/* function is always true */
		valuep->t = UINT64;
		valuep->v = 1;
		return (1);
	} else if (funcname == L_cat) {
		int retval = eval_cat(np, ex, events, globals, croot,
		    arrowp, try, valuep);

		outfl(O_ALTFP|O_VERB2, np->file, np->line,
		    "cat: returns %s", (char *)(uintptr_t)valuep->v);
		return (retval);
	} else if (funcname == L_setserdn || funcname == L_setserdt ||
	    funcname == L_setserdsuffix || funcname == L_setserdincrement) {
		struct evalue *serdvalp;
		int alloced = 0;
		char *str;
		struct event *flt = arrowp->tail->myevent;

		if (!(arrowp->head->myevent->cached_state & REQMNTS_CREDIBLE))
			return (0);

		if (funcname == L_setserdn)
			str = "n";
		else if (funcname == L_setserdt)
			str = "t";
		else if (funcname == L_setserdsuffix)
			str = "suffix";
		else if (funcname == L_setserdincrement)
			str = "increment";

		/*
		 * allocate a struct evalue to hold the serd property's
		 * value, unless we've been here already, in which case we
		 * might calculate a different value, but we'll store it
		 * in the already-allocated struct evalue.
		 */
		if ((serdvalp = (struct evalue *)lut_lookup(flt->serdprops,
		    (void *)str, (lut_cmp)strcmp)) == NULL) {
			serdvalp = MALLOC(sizeof (*serdvalp));
			alloced = 1;
		}

		if (!eval_expr(np, ex, events, globals, croot, arrowp, try,
		    serdvalp)) {
			outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
			    "setserd%s: %s: ", str,
			    flt->enode->u.event.ename->u.name.s);
			ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, np);
			out(O_ALTFP|O_VERB2, " (cannot eval)");
			if (alloced)
				FREE(serdvalp);
			return (0);
		} else if (serdvalp->t == UNDEFINED) {
			outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
			    "setserd%s: %s: ", str,
			    flt->enode->u.event.ename->u.name.s);
			ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, np);
			out(O_ALTFP|O_VERB2, " (undefined)");
		} else {
			outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
			    "setserd%s: %s: ", str,
			    flt->enode->u.event.ename->u.name.s);
			ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, np);
			if ((funcname == L_setserdincrement ||
			    funcname == L_setserdn) && serdvalp->t == STRING) {
				serdvalp->t = UINT64;
				serdvalp->v = strtoull((char *)
				    (uintptr_t)serdvalp->v, NULL, 0);
			}
			if (funcname == L_setserdt && serdvalp->t == UINT64) {
				int len = snprintf(NULL, 0, "%lldns",
				    serdvalp->v);
				char *buf = MALLOC(len + 1);

				(void) snprintf(buf, len + 1, "%lldns",
				    serdvalp->v);
				serdvalp->t = STRING;
				serdvalp->v = (uintptr_t)stable(buf);
				FREE(buf);
			}
			if (funcname == L_setserdsuffix &&
			    serdvalp->t == UINT64) {
				int len = snprintf(NULL, 0, "%lld",
				    serdvalp->v);
				char *buf = MALLOC(len + 1);

				(void) snprintf(buf, len + 1, "%lld",
				    serdvalp->v);
				serdvalp->t = STRING;
				serdvalp->v = (uintptr_t)stable(buf);
				FREE(buf);
			}

			if (serdvalp->t == UINT64)
				out(O_ALTFP|O_VERB2, " (%llu)", serdvalp->v);
			else
				out(O_ALTFP|O_VERB2, " (\"%s\")",
				    (char *)(uintptr_t)serdvalp->v);
			flt->serdprops = lut_add(flt->serdprops, (void *)str,
			    (void *)serdvalp, (lut_cmp)strcmp);
		}
		valuep->t = UINT64;
		valuep->v = 1;
		return (1);
	} else if (funcname == L_payloadprop_defined) {
		outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
		    "payloadprop_defined(\"%s\") ", np->u.quote.s);

		if (arrowp->head->myevent->count == 0) {
			/*
			 * Haven't seen this ereport yet, so must defer
			 */
			out(O_ALTFP|O_VERB2, "ereport not yet seen - defer.");
			return (0);
		} else if (platform_payloadprop(np, NULL)) {
			/* platform_payloadprop() returned false */
			valuep->v = 0;
			out(O_ALTFP|O_VERB2, "not found.");
		} else {
			valuep->v = 1;
			out(O_ALTFP|O_VERB2, "found.");
		}
		valuep->t = UINT64;
		return (1);
	} else if (funcname == L_payloadprop_contains) {
		int nvals;
		struct evalue *vals;
		struct evalue cmpval;

		ASSERTinfo(np->t == T_LIST, ptree_nodetype2str(np->t));
		ASSERTinfo(np->u.expr.left->t == T_QUOTE,
		    ptree_nodetype2str(np->u.expr.left->t));

		outfl(O_ALTFP|O_VERB2|O_NONL, np->file, np->line,
		    "payloadprop_contains(\"%s\", ",
		    np->u.expr.left->u.quote.s);
		ptree_name_iter(O_ALTFP|O_VERB2|O_NONL, np->u.expr.right);
		out(O_ALTFP|O_VERB2|O_NONL, ") ");

		/* evaluate the expression we're comparing against */
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &cmpval)) {
			out(O_ALTFP|O_VERB2|O_NONL,
			    "(cannot eval) ");
			return (0);
		} else {
			switch (cmpval.t) {
			case UNDEFINED:
				out(O_ALTFP|O_VERB2, "(undefined type)");
				break;

			case UINT64:
				out(O_ALTFP|O_VERB2,
				    "(%llu) ", cmpval.v);
				break;

			case STRING:
				out(O_ALTFP|O_VERB2,
				    "(\"%s\") ", (char *)(uintptr_t)cmpval.v);
				break;

			case NODEPTR:
				out(O_ALTFP|O_VERB2|O_NONL, "(");
				ptree_name_iter(O_ALTFP|O_VERB2|O_NONL,
				    (struct node *)(uintptr_t)(cmpval.v));
				out(O_ALTFP|O_VERB2, ") ");
				break;
			}
		}

		/* get the payload values and check for a match */
		vals = platform_payloadprop_values(np->u.expr.left->u.quote.s,
		    &nvals);
		valuep->t = UINT64;
		valuep->v = 0;
		if (arrowp->head->myevent->count == 0) {
			/*
			 * Haven't seen this ereport yet, so must defer
			 */
			out(O_ALTFP|O_VERB2, "ereport not yet seen - defer.");
			return (0);
		} else if (nvals == 0) {
			out(O_ALTFP|O_VERB2, "not found.");
			return (1);
		} else {
			struct evalue preval;
			int i;

			out(O_ALTFP|O_VERB2|O_NONL, "found %d values ", nvals);

			for (i = 0; i < nvals; i++) {

				preval.t = vals[i].t;
				preval.v = vals[i].v;

				if (check_expr_args(&vals[i], &cmpval,
				    UNDEFINED, np))
					continue;

				/*
				 * If we auto-converted the value to a
				 * string, we need to free the
				 * original tree value.
				 */
				if (preval.t == NODEPTR &&
				    ((struct node *)(uintptr_t)(preval.v))->t ==
				    T_NAME) {
					tree_free((struct node *)(uintptr_t)
					    preval.v);
				}

				if (vals[i].v == cmpval.v) {
					valuep->v = 1;
					break;
				}
			}

			if (valuep->v)
				out(O_ALTFP|O_VERB2, "match.");
			else
				out(O_ALTFP|O_VERB2, "no match.");

			for (i = 0; i < nvals; i++) {
				if (vals[i].t == NODEPTR) {
					tree_free((struct node *)(uintptr_t)
					    vals[i].v);
					break;
				}
			}
			FREE(vals);
		}
		return (1);
	} else if (funcname == L_confcall) {
		return (!platform_confcall(np, globals, croot, arrowp, valuep));
	} else
		outfl(O_DIE, np->file, np->line,
		    "eval_func: unexpected func: %s", funcname);
	/*NOTREACHED*/
	return (0);
}

/*
 * defines for u.expr.temp - these are used for T_OR and T_AND so that if
 * we worked out that part of the expression was true or false during an
 * earlier eval_expr, then we don't need to dup that part.
 */

#define	EXPR_TEMP_BOTH_UNK	0
#define	EXPR_TEMP_LHS_UNK	1
#define	EXPR_TEMP_RHS_UNK	2

static struct node *
eval_dup(struct node *np, struct lut *ex, struct node *events[])
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
	case T_NOT:
	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
		return (tree_expr(np->t,
		    eval_dup(np->u.expr.left, ex, events),
		    eval_dup(np->u.expr.right, ex, events)));
	case T_LIST:
	case T_AND:
		switch (np->u.expr.temp) {
		case EXPR_TEMP_LHS_UNK:
			return (eval_dup(np->u.expr.left, ex, events));
		case EXPR_TEMP_RHS_UNK:
			return (eval_dup(np->u.expr.right, ex, events));
		default:
			return (tree_expr(np->t,
			    eval_dup(np->u.expr.left, ex, events),
			    eval_dup(np->u.expr.right, ex, events)));
		}

	case T_OR:
		switch (np->u.expr.temp) {
		case EXPR_TEMP_LHS_UNK:
			return (eval_dup(np->u.expr.left, ex, events));
		case EXPR_TEMP_RHS_UNK:
			return (eval_dup(np->u.expr.right, ex, events));
		default:
			return (tree_expr(T_OR,
			    eval_dup(np->u.expr.left, ex, events),
			    eval_dup(np->u.expr.right, ex, events)));
		}

	case T_NAME: {
		struct iterinfo *iterinfop;
		int got_matchf = 0;
		int got_matcht = 0;
		struct evalue value;
		struct node *np1f, *np2f, *np1t, *np2t, *retp = NULL;
		struct node *npstart, *npcont, *npend, *npref, *newnp, *nprest;

		/*
		 * Check if we already have a match of the nonwildcarded path
		 * in oldepname (check both to and from events).
		 */
		for (np1f = np, np2f = events[0]->u.event.oldepname;
		    np1f != NULL && np2f != NULL;
		    np1f = np1f->u.name.next, np2f = np2f->u.name.next) {
			if (strcmp(np1f->u.name.s, np2f->u.name.s) != 0)
				break;
			if (np1f->u.name.child->t != np2f->u.name.child->t)
				break;
			if (np1f->u.name.child->t == T_NUM &&
			    np1f->u.name.child->u.ull !=
			    np2f->u.name.child->u.ull)
				break;
			if (np1f->u.name.child->t == T_NAME &&
			    strcmp(np1f->u.name.child->u.name.s,
			    np2f->u.name.child->u.name.s) != 0)
				break;
			got_matchf++;
		}
		for (np1t = np, np2t = events[1]->u.event.oldepname;
		    np1t != NULL && np2t != NULL;
		    np1t = np1t->u.name.next, np2t = np2t->u.name.next) {
			if (strcmp(np1t->u.name.s, np2t->u.name.s) != 0)
				break;
			if (np1t->u.name.child->t != np2t->u.name.child->t)
				break;
			if (np1t->u.name.child->t == T_NUM &&
			    np1t->u.name.child->u.ull !=
			    np2t->u.name.child->u.ull)
				break;
			if (np1t->u.name.child->t == T_NAME &&
			    strcmp(np1t->u.name.child->u.name.s,
			    np2t->u.name.child->u.name.s) != 0)
				break;
			got_matcht++;
		}
		nprest = np;
		if (got_matchf || got_matcht) {
			/*
			 * so we are wildcarding. Copy ewname in full, plus
			 * matching section of oldepname. Use whichever gives
			 * the closest match.
			 */
			if (got_matchf > got_matcht) {
				npstart = events[0]->u.event.ewname;
				npcont = events[0]->u.event.oldepname;
				npend = np2f;
				nprest = np1f;
			} else {
				npstart = events[1]->u.event.ewname;
				npcont = events[1]->u.event.oldepname;
				npend = np2t;
				nprest = np1t;
			}
			for (npref = npstart; npref != NULL;
			    npref = npref->u.name.next) {
				newnp = newnode(T_NAME, np->file, np->line);
				newnp->u.name.t = npref->u.name.t;
				newnp->u.name.s = npref->u.name.s;
				newnp->u.name.last = newnp;
				newnp->u.name.it = npref->u.name.it;
				newnp->u.name.cp = npref->u.name.cp;
				newnp->u.name.child =
				    newnode(T_NUM, np->file, np->line);
				if (eval_expr(npref->u.name.child, ex, events,
				    NULL, NULL, NULL, 1, &value) == 0 ||
				    value.t != UINT64) {
					outfl(O_DIE, np->file, np->line,
					    "eval_dup: could not resolve "
					    "iterator of %s", np->u.name.s);
				}
				newnp->u.name.child->u.ull = value.v;
				if (retp == NULL) {
					retp = newnp;
				} else {
					retp->u.name.last->u.name.next = newnp;
					retp->u.name.last = newnp;
				}
			}
			for (npref = npcont; npref != NULL && npref != npend;
			    npref = npref->u.name.next) {
				newnp = newnode(T_NAME, np->file, np->line);
				newnp->u.name.t = npref->u.name.t;
				newnp->u.name.s = npref->u.name.s;
				newnp->u.name.last = newnp;
				newnp->u.name.it = npref->u.name.it;
				newnp->u.name.cp = npref->u.name.cp;
				newnp->u.name.child =
				    newnode(T_NUM, np->file, np->line);
				if (eval_expr(npref->u.name.child, ex, events,
				    NULL, NULL, NULL, 1, &value) == 0 ||
				    value.t != UINT64) {
					outfl(O_DIE, np->file, np->line,
					    "eval_dup: could not resolve "
					    "iterator of %s", np->u.name.s);
				}
				newnp->u.name.child->u.ull = value.v;
				if (retp == NULL) {
					retp = newnp;
				} else {
					retp->u.name.last->u.name.next = newnp;
					retp->u.name.last = newnp;
				}
			}
		} else {
			/*
			 * not wildcarding - check if explicit iterator
			 */
			iterinfop = lut_lookup(ex, (void *)np->u.name.s, NULL);
			if (iterinfop != NULL) {
				/* explicit iterator; not part of pathname */
				newnp = newnode(T_NUM, np->file, np->line);
				newnp->u.ull = iterinfop->num;
				return (newnp);
			}
		}

		/*
		 * finally, whether wildcarding or not, we need to copy the
		 * remaining part of the path (if any). This must be defined
		 * absolutely (no more expansion/wildcarding).
		 */
		for (npref = nprest; npref != NULL;
		    npref = npref->u.name.next) {
			newnp = newnode(T_NAME, np->file, np->line);
			newnp->u.name.t = npref->u.name.t;
			newnp->u.name.s = npref->u.name.s;
			newnp->u.name.last = newnp;
			newnp->u.name.it = npref->u.name.it;
			newnp->u.name.cp = npref->u.name.cp;
			newnp->u.name.child =
			    newnode(T_NUM, np->file, np->line);
			if (eval_expr(npref->u.name.child, ex, events,
			    NULL, NULL, NULL, 1, &value) == 0 ||
			    value.t != UINT64) {
				outfl(O_DIE, np->file, np->line,
				    "eval_dup: could not resolve "
				    "iterator of %s", np->u.name.s);
			}
			newnp->u.name.child->u.ull = value.v;
			if (retp == NULL) {
				retp = newnp;
			} else {
				retp->u.name.last->u.name.next = newnp;
				retp->u.name.last = newnp;
			}
		}
		return (retp);
	}

	case T_EVENT:
		newnp = newnode(T_NAME, np->file, np->line);

		newnp->u.name.t = np->u.event.ename->u.name.t;
		newnp->u.name.s = np->u.event.ename->u.name.s;
		newnp->u.name.it = np->u.event.ename->u.name.it;
		newnp->u.name.last = newnp;

		return (tree_event(newnp,
		    eval_dup(np->u.event.epname, ex, events),
		    eval_dup(np->u.event.eexprlist, ex, events)));

	case T_FUNC:
		return (tree_func(np->u.func.s,
		    eval_dup(np->u.func.arglist, ex, events),
		    np->file, np->line));

	case T_QUOTE:
		newnp = newnode(T_QUOTE, np->file, np->line);
		newnp->u.quote.s = np->u.quote.s;
		return (newnp);

	case T_NUM:
		newnp = newnode(T_NUM, np->file, np->line);
		newnp->u.ull = np->u.ull;
		return (newnp);

	case T_TIMEVAL:
		newnp = newnode(T_TIMEVAL, np->file, np->line);
		newnp->u.ull = np->u.ull;
		return (newnp);

	default:
		outfl(O_DIE, np->file, np->line,
		    "eval_dup: unexpected node type: %s",
		    ptree_nodetype2str(np->t));
	}
	/*NOTREACHED*/
	return (0);
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
eval_potential(struct node *np, struct lut *ex, struct node *events[],
	    struct node **newc, struct config *croot)
{
	struct node *newnp;
	struct evalue value;

	if (eval_expr(np, ex, events, NULL, croot, NULL, 1, &value) == 0) {
		/*
		 * couldn't eval expression because
		 * it contains deferred items.  make
		 * a duplicate expression with all the
		 * non-deferred items expanded.
		 */
		newnp = eval_dup(np, ex, events);

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
	/* auto-convert T_NAMES to strings */
	if (lp->t == NODEPTR && ((struct node *)(uintptr_t)(lp->v))->t ==
	    T_NAME) {
		char *s = ipath2str(NULL,
		    ipath((struct node *)(uintptr_t)lp->v));
		lp->t = STRING;
		lp->v = (uintptr_t)stable(s);
		FREE(s);
		out(O_ALTFP|O_VERB2, "convert lhs path to \"%s\"",
		    (char *)(uintptr_t)lp->v);
	}
	if (rp != NULL &&
	    rp->t == NODEPTR && ((struct node *)(uintptr_t)(rp->v))->t ==
	    T_NAME) {
		char *s = ipath2str(NULL,
		    ipath((struct node *)(uintptr_t)rp->v));
		rp->t = STRING;
		rp->v = (uintptr_t)stable(s);
		FREE(s);
		out(O_ALTFP|O_VERB2, "convert rhs path to \"%s\"",
		    (char *)(uintptr_t)rp->v);
	}

	/* auto-convert numbers to strings */
	if (dtype == STRING) {
		if (lp->t == UINT64) {
			int len = snprintf(NULL, 0, "%llx", lp->v);
			char *s = MALLOC(len + 1);

			(void) snprintf(s, len + 1, "%llx", lp->v);
			lp->t = STRING;
			lp->v = (uintptr_t)stable(s);
			FREE(s);
		}
		if (rp != NULL && rp->t == UINT64) {
			int len = snprintf(NULL, 0, "%llx", rp->v);
			char *s = MALLOC(len + 1);

			(void) snprintf(s, len + 1, "%llx", rp->v);
			rp->t = STRING;
			rp->v = (uintptr_t)stable(s);
			FREE(s);
		}
	}

	/* auto-convert strings to numbers */
	if (dtype == UINT64) {
		if (lp->t == STRING) {
			lp->t = UINT64;
			lp->v = strtoull((char *)(uintptr_t)lp->v, NULL, 0);
		}
		if (rp != NULL && rp->t == STRING) {
			rp->t = UINT64;
			rp->v = strtoull((char *)(uintptr_t)rp->v, NULL, 0);
		}
	}

	if (dtype != UNDEFINED && lp->t != dtype) {
		outfl(O_DIE, np->file, np->line,
		    "invalid datatype of argument for operation %s",
		    ptree_nodetype2str(np->t));
		/* NOTREACHED */
		return (1);
	}

	if (rp != NULL && lp->t != rp->t) {
		outfl(O_DIE, np->file, np->line,
		    "mismatch in datatype of arguments for operation %s",
		    ptree_nodetype2str(np->t));
		/* NOTREACHED */
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
eval_expr(struct node *np, struct lut *ex, struct node *events[],
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
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);

		ASSERT(np->u.expr.left->t == T_GLOBID);
		gval = lut_lookup(*globals,
		    (void *)np->u.expr.left->u.globid.s, NULL);

		if (gval == NULL) {
			gval = MALLOC(sizeof (*gval));
			*globals = lut_add(*globals,
			    (void *) np->u.expr.left->u.globid.s, gval, NULL);
		}

		gval->t = rval.t;
		gval->v = rval.v;

		if (gval->t == UINT64) {
			out(O_ALTFP|O_VERB2,
			    "assign $%s=%llu",
			    np->u.expr.left->u.globid.s, gval->v);
		} else {
			out(O_ALTFP|O_VERB2,
			    "assign $%s=\"%s\"",
			    np->u.expr.left->u.globid.s,
			    (char *)(uintptr_t)gval->v);
		}

		/*
		 * but always return true -- an assignment should not
		 * cause a constraint to be false.
		 */
		valuep->t = UINT64;
		valuep->v = 1;
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
			if (!eval_expr(np->u.expr.right, ex, events, globals,
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

		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (rval.t == UINT64 || lval.t == UINT64) {
			if (check_expr_args(&lval, &rval, UINT64, np))
				return (0);
		} else {
			if (check_expr_args(&lval, &rval, UNDEFINED, np))
				return (0);
		}

		valuep->t = UINT64;
		valuep->v = (lval.v == rval.v);
		return (1);

	case T_LT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v < rval.v);
		return (1);

	case T_LE:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v <= rval.v);
		return (1);

	case T_GT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v > rval.v);
		return (1);

	case T_GE:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v >= rval.v);
		return (1);

	case T_BITAND:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v & rval.v);
		return (1);

	case T_BITOR:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v | rval.v);
		return (1);

	case T_BITXOR:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = (lval.v ^ rval.v);
		return (1);

	case T_BITNOT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		ASSERT(np->u.expr.right == NULL);
		if (check_expr_args(&lval, NULL, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = ~ lval.v;
		return (1);

	case T_LSHIFT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = UINT64;
		valuep->v = (lval.v << rval.v);
		return (1);

	case T_RSHIFT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
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
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);

		if (lval.t != UNDEFINED && lval.v != 0)
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
				outfl(O_DIE, np->file, np->line,
				    "eval_expr: missing condelse");
			}
		}

		if (!eval_expr(retnp, ex, events, globals, croot,
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
		/*NOTREACHED*/
		break;

	case T_NE:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (rval.t == UINT64 || lval.t == UINT64) {
			if (check_expr_args(&lval, &rval, UINT64, np))
				return (0);
		} else {
			if (check_expr_args(&lval, &rval, UNDEFINED, np))
				return (0);
		}

		valuep->t = UINT64;
		valuep->v = (lval.v != rval.v);
		return (1);

	case T_LIST:
	case T_AND:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, valuep)) {
			/*
			 * if lhs is unknown, still check rhs. If that
			 * is false we can return false irrespective of lhs
			 */
			if (!try) {
				np->u.expr.temp = EXPR_TEMP_BOTH_UNK;
				return (0);
			}
			if (!eval_expr(np->u.expr.right, ex, events, globals,
			    croot, arrowp, try, valuep)) {
				np->u.expr.temp = EXPR_TEMP_BOTH_UNK;
				return (0);
			}
			if (valuep->v != 0) {
				np->u.expr.temp = EXPR_TEMP_LHS_UNK;
				return (0);
			}
		}
		if (valuep->v == 0) {
			valuep->t = UINT64;
			return (1);
		}
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, valuep)) {
			np->u.expr.temp = EXPR_TEMP_RHS_UNK;
			return (0);
		}
		valuep->t = UINT64;
		valuep->v = valuep->v == 0 ? 0 : 1;
		return (1);

	case T_OR:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, valuep)) {
			/*
			 * if lhs is unknown, still check rhs. If that
			 * is true we can return true irrespective of lhs
			 */
			if (!try) {
				np->u.expr.temp = EXPR_TEMP_BOTH_UNK;
				return (0);
			}
			if (!eval_expr(np->u.expr.right, ex, events, globals,
			    croot, arrowp, try, valuep)) {
				np->u.expr.temp = EXPR_TEMP_BOTH_UNK;
				return (0);
			}
			if (valuep->v == 0) {
				np->u.expr.temp = EXPR_TEMP_LHS_UNK;
				return (0);
			}
		}
		if (valuep->v != 0) {
			valuep->t = UINT64;
			valuep->v = 1;
			return (1);
		}
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, valuep)) {
			np->u.expr.temp = EXPR_TEMP_RHS_UNK;
			return (0);
		}
		valuep->t = UINT64;
		valuep->v = valuep->v == 0 ? 0 : 1;
		return (1);

	case T_NOT:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, valuep))
			return (0);
		valuep->t = UINT64;
		valuep->v = ! valuep->v;
		return (1);

	case T_ADD:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = lval.v + rval.v;
		return (1);

	case T_SUB:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* since valuep is unsigned, return false if lval.v < rval.v */
		if (lval.v < rval.v) {
			outfl(O_DIE, np->file, np->line,
			    "eval_expr: T_SUB result is out of range");
		}

		valuep->t = lval.t;
		valuep->v = lval.v - rval.v;
		return (1);

	case T_MUL:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		valuep->t = lval.t;
		valuep->v = lval.v * rval.v;
		return (1);

	case T_DIV:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* return false if dividing by zero */
		if (rval.v == 0) {
			outfl(O_DIE, np->file, np->line,
			    "eval_expr: T_DIV division by zero");
		}

		valuep->t = lval.t;
		valuep->v = lval.v / rval.v;
		return (1);

	case T_MOD:
		if (!eval_expr(np->u.expr.left, ex, events, globals, croot,
		    arrowp, try, &lval))
			return (0);
		if (!eval_expr(np->u.expr.right, ex, events, globals, croot,
		    arrowp, try, &rval))
			return (0);
		if (check_expr_args(&lval, &rval, UINT64, np))
			return (0);

		/* return false if dividing by zero */
		if (rval.v == 0) {
			outfl(O_DIE, np->file, np->line,
			    "eval_expr: T_MOD division by zero");
		}

		valuep->t = lval.t;
		valuep->v = lval.v % rval.v;
		return (1);

	case T_NAME:
		if (try) {
			struct iterinfo *iterinfop;
			struct node *np1, *np2;
			int i, gotmatch = 0;

			/*
			 * Check if we have an exact match of the nonwildcarded
			 * path in oldepname - if so we can just use the
			 * full wildcarded path in epname.
			 */
			for (i = 0; i < 1; i++) {
				for (np1 = np,
				    np2 = events[i]->u.event.oldepname;
				    np1 != NULL && np2 != NULL;
				    np1 = np1->u.name.next,
				    np2 = np2->u.name.next) {
					if (strcmp(np1->u.name.s,
					    np2->u.name.s) != 0)
						break;
					if (np1->u.name.child->t !=
					    np2->u.name.child->t)
						break;
					if (np1->u.name.child->t == T_NUM &&
					    np1->u.name.child->u.ull !=
					    np2->u.name.child->u.ull)
						break;
					if (np1->u.name.child->t == T_NAME &&
					    strcmp(np1->u.name.child->u.name.s,
					    np2->u.name.child->u.name.s) != 0)
						break;
					gotmatch++;
				}
				if (np1 == NULL && np2 == NULL) {
					valuep->t = NODEPTR;
					valuep->v = (uintptr_t)
					    events[i]->u.event.epname;
					return (1);
				}
			}
			if (!gotmatch) {
				/*
				 * we're not wildcarding. However at
				 * itree_create() time, we can also expand
				 * simple iterators - so check for those.
				 */
				iterinfop = lut_lookup(ex, (void *)np->u.name.s,
				    NULL);
				if (iterinfop != NULL) {
					valuep->t = UINT64;
					valuep->v =
					    (unsigned long long)iterinfop->num;
					return (1);
				}
			}
			/*
			 * For anything else we'll have to wait for eval_dup().
			 */
			return (0);
		}

		/* return address of struct node */
		valuep->t = NODEPTR;
		valuep->v = (uintptr_t)np;
		return (1);

	case T_QUOTE:
		valuep->t = STRING;
		valuep->v = (uintptr_t)np->u.quote.s;
		return (1);

	case T_FUNC:
		return (eval_func(np, ex, events, np->u.func.arglist,
		    globals, croot, arrowp, try, valuep));

	case T_NUM:
	case T_TIMEVAL:
		valuep->t = UINT64;
		valuep->v = np->u.ull;
		return (1);

	default:
		outfl(O_DIE, np->file, np->line,
		    "eval_expr: unexpected node type: %s",
		    ptree_nodetype2str(np->t));
	}
	/*NOTREACHED*/
	return (0);
}

/*
 * eval_fru() and eval_asru() don't do much, but are called from a number
 * of places.
 */
static struct node *
eval_fru(struct node *np)
{
	ASSERT(np->t == T_NAME);
	return (np);
}

static struct node *
eval_asru(struct node *np)
{
	ASSERT(np->t == T_NAME);
	return (np);
}

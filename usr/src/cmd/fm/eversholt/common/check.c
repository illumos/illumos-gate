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
 * check.c -- routines for checking the prop tree
 *
 * this module provides semantic checks on the parse tree.  most of
 * these checks happen during the construction of the parse tree,
 * when the various tree_X() routines call the various check_X()
 * routines.  in a couple of special cases, a check function will
 * process the parse tree after it has been fully constructed.  these
 * cases are noted in the comments above the check function.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "check.h"

static int check_reportlist(enum nodetype t, const char *s, struct node *np);
static int check_num(enum nodetype t, const char *s, struct node *np);
static int check_quote(enum nodetype t, const char *s, struct node *np);
static int check_action(enum nodetype t, const char *s, struct node *np);
static int check_num_func(enum nodetype t, const char *s, struct node *np);
static int check_fru_asru(enum nodetype t, const char *s, struct node *np);
static int check_engine(enum nodetype t, const char *s, struct node *np);
static int check_count(enum nodetype t, const char *s, struct node *np);
static int check_timeval(enum nodetype t, const char *s, struct node *np);
static int check_id(enum nodetype t, const char *s, struct node *np);
static int check_serd_method(enum nodetype t, const char *s, struct node *np);
static int check_serd_id(enum nodetype t, const char *s, struct node *np);
static int check_nork(struct node *np);
static void check_cycle_lhs(struct node *stmtnp, struct node *arrow);
static void check_cycle_lhs_try(struct node *stmtnp, struct node *lhs,
    struct node *rhs);
static void check_cycle_rhs(struct node *rhs);
static void check_proplists_lhs(enum nodetype t, struct node *lhs);

static struct {
	enum nodetype t;
	const char *name;
	int required;
	int (*checker)(enum nodetype t, const char *s, struct node *np);
	int outflags;
} Allowednames[] = {
	{ T_FAULT, "FITrate", 0, check_num_func, O_ERR },
	{ T_FAULT, "FRU", 0, check_fru_asru, O_ERR },
	{ T_FAULT, "ASRU", 0, check_fru_asru, O_ERR },
	{ T_FAULT, "message", 0, check_num_func, O_ERR },
	{ T_FAULT, "retire", 0, check_num_func, O_ERR },
	{ T_FAULT, "response", 0, check_num_func, O_ERR },
	{ T_FAULT, "action", 0, check_action, O_ERR },
	{ T_FAULT, "count", 0, check_count, O_ERR },
	{ T_FAULT, "engine", 0, check_engine, O_ERR },
	{ T_UPSET, "engine", 0, check_engine, O_ERR },
	{ T_DEFECT, "FRU", 0, check_fru_asru, O_ERR },
	{ T_DEFECT, "ASRU", 0, check_fru_asru, O_ERR },
	{ T_DEFECT, "engine", 0, check_engine, O_ERR },
	{ T_EREPORT, "poller", 0, check_id, O_ERR },
	{ T_EREPORT, "delivery", 0, check_timeval, O_ERR },
	{ T_EREPORT, "discard_if_config_unknown", 0, check_num, O_ERR },
	{ T_SERD, "N", 1, check_num, O_ERR },
	{ T_SERD, "T", 1, check_timeval, O_ERR },
	{ T_SERD, "method", 0, check_serd_method, O_ERR },
	{ T_SERD, "trip", 0, check_reportlist, O_ERR },
	{ T_SERD, "FRU", 0, check_fru_asru, O_ERR },
	{ T_SERD, "id", 0, check_serd_id, O_ERR },
	{ T_ERROR, "ASRU", 0, check_fru_asru, O_ERR },
	{ T_CONFIG, NULL, 0, check_quote, O_ERR },
	{ 0, NULL, 0 },
};

void
check_init(void)
{
	int i;

	for (i = 0; Allowednames[i].t; i++)
		if (Allowednames[i].name != NULL)
			Allowednames[i].name = stable(Allowednames[i].name);
}

void
check_fini(void)
{
}

/*ARGSUSED*/
void
check_report_combination(struct node *np)
{
	/* nothing to check for here.  poller is only prop and it is optional */
}

/*
 * check_path_iterators -- verify all iterators are explicit
 */
static void
check_path_iterators(struct node *np)
{
	if (np == NULL)
		return;

	switch (np->t) {
		case T_ARROW:
			check_path_iterators(np->u.arrow.lhs);
			check_path_iterators(np->u.arrow.rhs);
			break;

		case T_LIST:
			check_path_iterators(np->u.expr.left);
			check_path_iterators(np->u.expr.right);
			break;

		case T_EVENT:
			check_path_iterators(np->u.event.epname);
			break;

		case T_NAME:
			if (np->u.name.child == NULL)
				outfl(O_DIE, np->file, np->line,
				    "internal error: check_path_iterators: "
				    "unexpected implicit iterator: %s",
				    np->u.name.s);
			check_path_iterators(np->u.name.next);
			break;

		default:
			outfl(O_DIE, np->file, np->line,
			    "internal error: check_path_iterators: "
			    "unexpected type: %s",
			    ptree_nodetype2str(np->t));
	}
}

void
check_arrow(struct node *np)
{
	ASSERTinfo(np->t == T_ARROW, ptree_nodetype2str(np->t));

	if (np->u.arrow.lhs->t != T_ARROW &&
	    np->u.arrow.lhs->t != T_LIST &&
	    np->u.arrow.lhs->t != T_EVENT) {
		outfl(O_ERR,
		    np->u.arrow.lhs->file, np->u.arrow.lhs->line,
		    "%s not allowed on left-hand side of arrow",
		    ptree_nodetype2str(np->u.arrow.lhs->t));
	}

	if (!check_nork(np->u.arrow.nnp) ||
	    !check_nork(np->u.arrow.knp))
		outfl(O_ERR, np->file, np->line,
		    "counts associated with propagation arrows "
		    "must be integers");

	check_path_iterators(np);
}

/*
 * make sure the nork values are valid.
 * Nork values must be "A" for all(T_NAME),
 * a number(T_NUM), or a simple
 * expression(T_SUB, T_ADD, T_MUL, T_DIV)
 */
static int
check_nork(struct node *np)
{
	int rval = 0;

	/* NULL means no nork value which is allowed */
	if (np == NULL) {
		rval = 1;
	}
	else
	{
		/* if the nork is a name it must be A for "All" */
		if (np->t == T_NAME)
			if (*np->u.name.s == 'A')
				return (1);

		/*  T_NUM allowed */
		if (np->t == T_NUM)
			rval = 1;

		/*  simple expressions allowed */
		if (np->t == T_SUB ||
		    np->t == T_ADD ||
		    np->t == T_MUL ||
		    np->t == T_DIV)
			rval = 1;
	}

	return (rval);
}

static int
check_reportlist(enum nodetype t, const char *s, struct node *np)
{
	if (np == NULL)
		return (1);
	else if (np->t == T_EVENT) {
		if (np->u.event.ename->u.name.t != N_EREPORT) {
			outfl(O_ERR, np->file, np->line,
			    "%s %s property must begin with \"ereport.\"",
			    ptree_nodetype2str(t), s);
		} else if (tree_event2np_lut_lookup(Ereports, np) == NULL) {
			outfl(O_ERR, np->file, np->line,
			    "%s %s property contains undeclared name",
			    ptree_nodetype2str(t), s);
		}
		check_type_iterator(np);
	} else if (np->t == T_LIST) {
		(void) check_reportlist(t, s, np->u.expr.left);
		(void) check_reportlist(t, s, np->u.expr.right);
	}
	return (1);
}

static int
check_num(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_NUM)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be a single number",
		    ptree_nodetype2str(t), s);
	return (1);
}

/*ARGSUSED1*/
static int
check_quote(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_QUOTE)
		outfl(O_ERR, np->file, np->line,
		    "%s properties must be quoted strings",
		    ptree_nodetype2str(t));
	return (1);
}

static int
check_action(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));

	if (np->t != T_FUNC)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be a function or list of functions",
		    ptree_nodetype2str(t), s);
	return (1);
}

static int
check_num_func(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_NUM && np->t != T_FUNC)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be a number or function",
		    ptree_nodetype2str(t), s);
	return (1);
}

static int
check_fru_asru(enum nodetype t, const char *s, struct node *np)
{
	ASSERT(s != NULL);

	/* make sure it is a node type T_NAME? */
	if (np->t == T_NAME) {
		if (s == L_ASRU) {
			if (tree_name2np_lut_lookup_name(ASRUs, np) == NULL)
				outfl(O_ERR, np->file, np->line,
				    "ASRU property contains undeclared asru");
		} else if (s == L_FRU) {
			if (tree_name2np_lut_lookup_name(FRUs, np) == NULL)
				outfl(O_ERR, np->file, np->line,
				    "FRU property contains undeclared fru");
		} else {
			outfl(O_ERR, np->file, np->line,
			    "illegal property name in %s declaration: %s",
			    ptree_nodetype2str(t), s);
		}
		check_type_iterator(np);
	} else
		outfl(O_ERR, np->file, np->line,
		    "illegal type used for %s property: %s",
		    s, ptree_nodetype2str(np->t));
	return (1);
}

static int
check_engine(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_EVENT)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be an engine name "
		    "(i.e. serd.x or serd.x@a/b)",
		    ptree_nodetype2str(t), s);

	return (1);
}

static int
check_count(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_EVENT)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be an engine name "
		    "(i.e. stat.x or stat.x@a/b)",
		    ptree_nodetype2str(t), s);

	/* XXX confirm engine has been declared */
	return (1);
}

static int
check_timeval(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_TIMEVAL)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be a number with time units",
		    ptree_nodetype2str(t), s);
	return (1);
}

static int
check_id(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_NAME || np->u.name.next || np->u.name.child)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be simple name",
		    ptree_nodetype2str(t), s);
	return (1);
}

static int
check_serd_method(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_NAME || np->u.name.next || np->u.name.child ||
	    (np->u.name.s != L_volatile &&
	    np->u.name.s != L_persistent))
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be \"volatile\" or \"persistent\"",
		    ptree_nodetype2str(t), s);
	return (1);
}

static int
check_serd_id(enum nodetype t, const char *s, struct node *np)
{
	ASSERTinfo(np != NULL, ptree_nodetype2str(t));
	if (np->t != T_GLOBID)
		outfl(O_ERR, np->file, np->line,
		    "%s %s property must be a global ID",
		    ptree_nodetype2str(t), s);
	return (1);
}

void
check_stmt_required_properties(struct node *stmtnp)
{
	struct lut *lutp = stmtnp->u.stmt.lutp;
	struct node *np = stmtnp->u.stmt.np;
	int i;

	for (i = 0; Allowednames[i].t; i++)
		if (stmtnp->t == Allowednames[i].t &&
		    Allowednames[i].required &&
		    tree_s2np_lut_lookup(lutp, Allowednames[i].name) == NULL)
			outfl(Allowednames[i].outflags,
			    np->file, np->line,
			    "%s statement missing property: %s",
			    ptree_nodetype2str(stmtnp->t),
			    Allowednames[i].name);
}

void
check_stmt_allowed_properties(enum nodetype t,
    struct node *nvpairnp, struct lut *lutp)
{
	int i;
	const char *s = nvpairnp->u.expr.left->u.name.s;
	struct node *np;

	for (i = 0; Allowednames[i].t; i++)
		if (t == Allowednames[i].t && Allowednames[i].name == NULL) {
			/* NULL name means just call checker */
			(*Allowednames[i].checker)(t, s,
			    nvpairnp->u.expr.right);
			return;
		} else if (t == Allowednames[i].t && s == Allowednames[i].name)
			break;
	if (Allowednames[i].name == NULL)
		outfl(O_ERR, nvpairnp->file, nvpairnp->line,
		    "illegal property name in %s declaration: %s",
		    ptree_nodetype2str(t), s);
	else if ((np = tree_s2np_lut_lookup(lutp, s)) != NULL) {
		/*
		 * redeclaring prop is allowed if value is the same
		 */
		if (np->t != nvpairnp->u.expr.right->t)
			outfl(O_ERR, nvpairnp->file, nvpairnp->line,
			    "property redeclared (with differnt type) "
			    "in %s declaration: %s",
			    ptree_nodetype2str(t), s);
		switch (np->t) {
			case T_NUM:
			case T_TIMEVAL:
				if (np->u.ull == nvpairnp->u.expr.right->u.ull)
					return;
				break;

			case T_NAME:
				if (tree_namecmp(np,
				    nvpairnp->u.expr.right) == 0)
					return;
				break;

			case T_EVENT:
				if (tree_eventcmp(np,
				    nvpairnp->u.expr.right) == 0)
					return;
				break;

			default:
				outfl(O_ERR, nvpairnp->file, nvpairnp->line,
				    "value for property \"%s\" is an "
				    "invalid type: %s",
				    nvpairnp->u.expr.left->u.name.s,
				    ptree_nodetype2str(np->t));
				return;
		}
		outfl(O_ERR, nvpairnp->file, nvpairnp->line,
		    "property redeclared in %s declaration: %s",
		    ptree_nodetype2str(t), s);
	} else
		(*Allowednames[i].checker)(t, s, nvpairnp->u.expr.right);
}

void
check_propnames(enum nodetype t, struct node *np, int from, int to)
{
	struct node *dnp;
	struct lut *lutp;

	ASSERT(np != NULL);
	ASSERTinfo(np->t == T_EVENT || np->t == T_LIST || np->t == T_ARROW,
	    ptree_nodetype2str(np->t));

	if (np->t == T_EVENT) {
		switch (np->u.event.ename->u.name.t) {
		case N_UNSPEC:
			outfl(O_ERR, np->file, np->line,
			    "name in %s statement must begin with "
			    "type (example: \"error.\")",
			    ptree_nodetype2str(t));
			return;
		case N_FAULT:
			lutp = Faults;
			if (to) {
				outfl(O_ERR, np->file, np->line,
				    "%s has fault on right side of \"->\"",
				    ptree_nodetype2str(t));
				return;
			}
			if (!from) {
				outfl(O_DIE, np->file, np->line,
				    "internal error: %s has fault without "
				    "from flag",
				    ptree_nodetype2str(t));
			}
			break;
		case N_UPSET:
			lutp = Upsets;
			if (to) {
				outfl(O_ERR, np->file, np->line,
				    "%s has upset on right side of \"->\"",
				    ptree_nodetype2str(t));
				return;
			}
			if (!from)
				outfl(O_DIE, np->file, np->line,
				    "internal error: %s has upset without "
				    "from flag",
				    ptree_nodetype2str(t));
			break;
		case N_DEFECT:
			lutp = Defects;
			if (to) {
				outfl(O_ERR, np->file, np->line,
				    "%s has defect on right side of \"->\"",
				    ptree_nodetype2str(t));
				return;
			}
			if (!from) {
				outfl(O_DIE, np->file, np->line,
				    "internal error: %s has defect without "
				    "from flag",
				    ptree_nodetype2str(t));
			}
			break;
		case N_ERROR:
			lutp = Errors;
			if (!from && !to)
				outfl(O_DIE, np->file, np->line,
				    "%s has error without from or to flags",
				    ptree_nodetype2str(t));
			break;
		case N_EREPORT:
			lutp = Ereports;
			if (from) {
				outfl(O_ERR, np->file, np->line,
				    "%s has report on left side of \"->\"",
				    ptree_nodetype2str(t));
				return;
			}
			if (!to)
				outfl(O_DIE, np->file, np->line,
				    "internal error: %s has report without "
				    "to flag",
				    ptree_nodetype2str(t));
			break;
		default:
			outfl(O_DIE, np->file, np->line,
			    "internal error: check_propnames: "
			    "unexpected type: %d", np->u.name.t);
		}

		if ((dnp = tree_event2np_lut_lookup(lutp, np)) == NULL) {
			outfl(O_ERR, np->file, np->line,
			    "%s statement contains undeclared event",
			    ptree_nodetype2str(t));
		} else
			dnp->u.stmt.flags |= STMT_REF;
		np->u.event.declp = dnp;
	} else if (np->t == T_LIST) {
		check_propnames(t, np->u.expr.left, from, to);
		check_propnames(t, np->u.expr.right, from, to);
	} else if (np->t == T_ARROW) {
		check_propnames(t, np->u.arrow.lhs, 1, to);
		check_propnames(t, np->u.arrow.rhs, from, 1);
	}
}

static struct lut *
record_iterators(struct node *np, struct lut *ex)
{
	if (np == NULL)
		return (ex);

	switch (np->t) {
	case T_ARROW:
		ex = record_iterators(np->u.arrow.lhs, ex);
		ex = record_iterators(np->u.arrow.rhs, ex);
		break;

	case T_LIST:
		ex = record_iterators(np->u.expr.left, ex);
		ex = record_iterators(np->u.expr.right, ex);
		break;

	case T_EVENT:
		ex = record_iterators(np->u.event.epname, ex);
		break;

	case T_NAME:
		if (np->u.name.child && np->u.name.child->t == T_NAME)
			ex = lut_add(ex, (void *) np->u.name.child->u.name.s,
			    (void *) np, NULL);
		ex = record_iterators(np->u.name.next, ex);
		break;

	default:
		outfl(O_DIE, np->file, np->line,
		    "record_iterators: internal error: unexpected type: %s",
		    ptree_nodetype2str(np->t));
	}

	return (ex);
}

void
check_exprscope(struct node *np, struct lut *ex)
{
	if (np == NULL)
		return;

	switch (np->t) {
	case T_EVENT:
		check_exprscope(np->u.event.eexprlist, ex);
		break;

	case T_ARROW:
		check_exprscope(np->u.arrow.lhs, ex);
		check_exprscope(np->u.arrow.rhs, ex);
		break;

	case T_NAME:
		if (np->u.name.child && np->u.name.child->t == T_NAME) {
			if (lut_lookup(ex,
			    (void *) np->u.name.child->u.name.s, NULL) == NULL)
				outfl(O_ERR, np->file, np->line,
				    "constraint contains undefined"
				    " iterator: %s",
				    np->u.name.child->u.name.s);
		}
		check_exprscope(np->u.name.next, ex);
		break;

	case T_QUOTE:
	case T_GLOBID:
		break;

	case T_ASSIGN:
	case T_NE:
	case T_EQ:
	case T_LIST:
	case T_AND:
	case T_OR:
	case T_NOT:
	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
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
	case T_CONDIF:
	case T_CONDELSE:
		check_exprscope(np->u.expr.left, ex);
		check_exprscope(np->u.expr.right, ex);
		break;

	case T_FUNC:
		check_exprscope(np->u.func.arglist, ex);
		break;

	case T_NUM:
	case T_TIMEVAL:
		break;

	default:
		outfl(O_DIE, np->file, np->line,
		    "check_exprscope: internal error: unexpected type: %s",
		    ptree_nodetype2str(np->t));
	}
}

/*
 * check_propscope -- check constraints for out of scope variable refs
 */
void
check_propscope(struct node *np)
{
	struct lut *ex;

	ex = record_iterators(np, NULL);
	check_exprscope(np, ex);
	lut_free(ex, NULL, NULL);
}

/*
 * check_upset_engine -- validate the engine property in an upset statement
 *
 * we do this after the full parse tree has been constructed rather than while
 * building the parse tree because it is inconvenient for the user if we
 * require SERD engines to be declared before used in an upset "engine"
 * property.
 */

/*ARGSUSED*/
void
check_upset_engine(struct node *lhs, struct node *rhs, void *arg)
{
	enum nodetype t = (enum nodetype)arg;
	struct node *engnp;
	struct node *declp;

	ASSERTeq(rhs->t, t, ptree_nodetype2str);

	if ((engnp = tree_s2np_lut_lookup(rhs->u.stmt.lutp, L_engine)) == NULL)
		return;

	ASSERT(engnp->t == T_EVENT);

	if ((declp = tree_event2np_lut_lookup(SERDs, engnp)) == NULL) {
		outfl(O_ERR, engnp->file, engnp->line,
		    "%s %s property contains undeclared name",
		    ptree_nodetype2str(t), L_engine);
		return;
	}
	engnp->u.event.declp = declp;
}

/*
 * check_refcount -- see if declared names are used
 *
 * this is run after the entire parse tree is constructed, so a refcount
 * of zero means the name has been declared but otherwise not used.
 */

void
check_refcount(struct node *lhs, struct node *rhs, void *arg)
{
	enum nodetype t = (enum nodetype)arg;

	ASSERTeq(rhs->t, t, ptree_nodetype2str);

	if (rhs->u.stmt.flags & STMT_REF)
		return;

	outfl(O_WARN|O_NONL, rhs->file, rhs->line,
	    "%s name declared but not used: ", ptree_nodetype2str(t));
	ptree_name(O_WARN|O_NONL, lhs);
	out(O_WARN, NULL);
}

/*
 * set check_cycle_warninglevel only for val >= 0
 */
int
check_cycle_level(long long val)
{
	static int check_cycle_warninglevel = -1;

	if (val == 0)
		check_cycle_warninglevel = 0;
	else if (val > 0)
		check_cycle_warninglevel = 1;

	return (check_cycle_warninglevel);
}

/*
 * check_cycle -- see props from an error have cycles
 *
 * this is run after the entire parse tree is constructed, for
 * each error that has been declared.
 */

/*ARGSUSED*/
void
check_cycle(struct node *lhs, struct node *rhs, void *arg)
{
	struct node *np;

	ASSERTeq(rhs->t, T_ERROR, ptree_nodetype2str);

	if (rhs->u.stmt.flags & STMT_CYCLE)
		return;		/* already reported this cycle */

	if (rhs->u.stmt.flags & STMT_CYMARK) {
#ifdef ESC
		int warninglevel;

		warninglevel = check_cycle_level(-1);
		if (warninglevel <= 0) {
			int olevel = O_ERR;

			if (warninglevel == 0)
				olevel = O_WARN;

			out(olevel|O_NONL, "cycle in propagation tree: ");
			ptree_name(olevel|O_NONL, rhs->u.stmt.np);
			out(olevel, NULL);
		}
#endif /* ESC */

		rhs->u.stmt.flags |= STMT_CYCLE;
	}

	rhs->u.stmt.flags |= STMT_CYMARK;

	/* for each propagation */
	for (np = Props; np; np = np->u.stmt.next)
		check_cycle_lhs(rhs, np->u.stmt.np);

	rhs->u.stmt.flags &= ~STMT_CYMARK;
}

/*
 * check_cycle_lhs -- find the lhs of an arrow for cycle checking
 */

static void
check_cycle_lhs(struct node *stmtnp, struct node *arrow)
{
	struct node *trylhs;
	struct node *tryrhs;

	/* handle cascaded arrows */
	switch (arrow->u.arrow.lhs->t) {
	case T_ARROW:
		/* first recurse left */
		check_cycle_lhs(stmtnp, arrow->u.arrow.lhs);

		/*
		 * return if there's a list of events internal to
		 * cascaded props (which is not allowed)
		 */
		if (arrow->u.arrow.lhs->u.arrow.rhs->t != T_EVENT)
			return;

		/* then try this arrow (thing cascaded *to*) */
		trylhs = arrow->u.arrow.lhs->u.arrow.rhs;
		tryrhs = arrow->u.arrow.rhs;
		break;

	case T_EVENT:
	case T_LIST:
		trylhs = arrow->u.arrow.lhs;
		tryrhs = arrow->u.arrow.rhs;
		break;

	default:
		out(O_DIE, "lhs: unexpected type: %s",
		    ptree_nodetype2str(arrow->u.arrow.lhs->t));
		/*NOTREACHED*/
	}

	check_cycle_lhs_try(stmtnp, trylhs, tryrhs);
}

/*
 * check_cycle_lhs_try -- try matching an event name on lhs of an arrow
 */

static void
check_cycle_lhs_try(struct node *stmtnp, struct node *lhs, struct node *rhs)
{
	if (lhs->t == T_LIST) {
		check_cycle_lhs_try(stmtnp, lhs->u.expr.left, rhs);
		check_cycle_lhs_try(stmtnp, lhs->u.expr.right, rhs);
		return;
	}

	ASSERT(lhs->t == T_EVENT);

	if (tree_eventcmp(stmtnp->u.stmt.np, lhs) != 0)
		return;		/* no match */

	check_cycle_rhs(rhs);
}

/*
 * check_cycle_rhs -- foreach error on rhs, see if we cycle to a marked error
 */

static void
check_cycle_rhs(struct node *rhs)
{
	struct node *dnp;

	if (rhs->t == T_LIST) {
		check_cycle_rhs(rhs->u.expr.left);
		check_cycle_rhs(rhs->u.expr.right);
		return;
	}

	ASSERT(rhs->t == T_EVENT);

	if (rhs->u.event.ename->u.name.t != N_ERROR)
		return;

	if ((dnp = tree_event2np_lut_lookup(Errors, rhs)) == NULL) {
		outfl(O_ERR|O_NONL,
		    rhs->file, rhs->line,
		    "unexpected undeclared event during cycle check");
		ptree_name(O_ERR|O_NONL, rhs);
		out(O_ERR, NULL);
		return;
	}
	check_cycle(NULL, dnp, 0);
}

/*
 * Force iterators to be simple names, expressions, or numbers
 */
void
check_name_iterator(struct node *np)
{
	if (np->u.name.child->t != T_NUM &&
	    np->u.name.child->t != T_NAME &&
	    np->u.name.child->t != T_CONDIF &&
	    np->u.name.child->t != T_SUB &&
	    np->u.name.child->t != T_ADD &&
	    np->u.name.child->t != T_MUL &&
	    np->u.name.child->t != T_DIV &&
	    np->u.name.child->t != T_MOD &&
	    np->u.name.child->t != T_LSHIFT &&
	    np->u.name.child->t != T_RSHIFT) {
		outfl(O_ERR|O_NONL, np->file, np->line,
		"invalid iterator: ");
		ptree_name_iter(O_ERR|O_NONL, np);
		out(O_ERR, NULL);
	}
}

/*
 * Iterators on a declaration may only be implicit
 */
void
check_type_iterator(struct node *np)
{
	while (np != NULL) {
		if (np->t == T_EVENT) {
			np = np->u.event.epname;
		} else if (np->t == T_NAME) {
			if (np->u.name.child != NULL &&
			    np->u.name.child->t != T_NUM) {
				outfl(O_ERR|O_NONL, np->file, np->line,
				    "explicit iterators disallowed "
				    "in declarations: ");
				ptree_name_iter(O_ERR|O_NONL, np);
				out(O_ERR, NULL);
			}
			np = np->u.name.next;
		} else {
			break;
		}
	}
}

void
check_func(struct node *np)
{
	struct node *arglist = np->u.func.arglist;

	ASSERTinfo(np->t == T_FUNC, ptree_nodetype2str(np->t));

	if (np->u.func.s == L_within) {
		switch (arglist->t) {
		case T_NUM:
			if (arglist->u.ull != 0ULL) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "parameter of within must be 0"
				    ", \"infinity\" or a time value.");
			}
			break;

		case T_NAME:
			if (arglist->u.name.s != L_infinity) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "parameter of within must be 0"
				    ", \"infinity\" or a time value.");
			}
			break;

		case T_LIST:
			/*
			 * if two parameters, the left or min must be
			 * either T_NUM or T_TIMEVAL
			 */
			if (arglist->u.expr.left->t != T_NUM &&
			    arglist->u.expr.left->t != T_TIMEVAL) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "first parameter of within must be"
				    " either a time value or zero.");
			}

			/*
			 * if two parameters, the right or max must
			 * be either T_NUM, T_NAME or T_TIMEVAL
			 */
			if (arglist->u.expr.right->t != T_NUM &&
			    arglist->u.expr.right->t != T_TIMEVAL &&
			    arglist->u.expr.right->t != T_NAME) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "second parameter of within must "
				    "be 0, \"infinity\" or time value.");
			}

			/*
			 * if right or left is a T_NUM it must
			 * be zero
			 */
			if ((arglist->u.expr.left->t == T_NUM) &&
			    (arglist->u.expr.left->u.ull != 0ULL)) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "within parameter must be "
				    "0 or a time value.");
			}
			if ((arglist->u.expr.right->t == T_NUM) &&
			    (arglist->u.expr.right->u.ull != 0ULL)) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "within parameter must be "
				    "0 or a time value.");
			}

			/* if right is a T_NAME it must be "infinity" */
			if ((arglist->u.expr.right->t == T_NAME) &&
			    (arglist->u.expr.right->u.name.s != L_infinity)) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "\"infinity\" is the only "
				    "valid name for within parameter.");
			}

			/*
			 * the first parameter [min] must not be greater
			 * than the second parameter [max].
			 */
			if (arglist->u.expr.left->u.ull >
			    arglist->u.expr.right->u.ull) {
				outfl(O_ERR, arglist->file, arglist->line,
				    "the first value (min) of"
				    " within must be less than"
				    " the second (max) value");
			}
			break;

		case T_TIMEVAL:
			break; /* no restrictions on T_TIMEVAL */

		default:
			outfl(O_ERR, arglist->file, arglist->line,
			    "parameter of within must be 0"
			    ", \"infinity\" or a time value.");
		}
	} else if (np->u.func.s == L_call) {
		if (arglist->t != T_QUOTE &&
		    arglist->t != T_LIST &&
		    arglist->t != T_GLOBID &&
		    arglist->t != T_CONDIF &&
		    arglist->t != T_LIST &&
		    arglist->t != T_FUNC)
			outfl(O_ERR, arglist->file, arglist->line,
			    "invalid first argument to call()");
	} else if (np->u.func.s == L_fru) {
		if (arglist->t != T_NAME)
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to fru() must be a path");
	} else if (np->u.func.s == L_asru) {
		if (arglist->t != T_NAME)
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to asru() must be a path");
	} else if (np->u.func.s == L_is_connected ||
	    np->u.func.s == L_is_under) {
		if (arglist->t == T_LIST &&
		    (arglist->u.expr.left->t == T_NAME ||
		    (arglist->u.expr.left->t == T_FUNC &&
		    (arglist->u.expr.left->u.func.s == L_fru ||
		    arglist->u.expr.left->u.func.s == L_asru))) &&
		    (arglist->u.expr.right->t == T_NAME ||
		    (arglist->u.expr.right->t == T_FUNC &&
		    (arglist->u.expr.right->u.func.s == L_fru ||
		    arglist->u.expr.right->u.func.s == L_asru)))) {
			if (arglist->u.expr.left->t == T_FUNC)
				check_func(arglist->u.expr.left);
			if (arglist->u.expr.right->t == T_FUNC)
				check_func(arglist->u.expr.right);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "%s() must have paths or calls to "
			    "fru() and/or asru() as arguments",
			    np->u.func.s);
		}
	} else if (np->u.func.s == L_is_on) {
		if (arglist->t == T_NAME ||
		    (arglist->t == T_FUNC &&
		    (arglist->u.func.s == L_fru ||
		    arglist->u.func.s == L_asru))) {
			if (arglist->t == T_FUNC)
				check_func(arglist);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to is_on() must be a path or a call to "
			    "fru() or asru()");
		}
	} else if (np->u.func.s == L_is_present) {
		if (arglist->t == T_NAME ||
		    (arglist->t == T_FUNC &&
		    (arglist->u.func.s == L_fru ||
		    arglist->u.func.s == L_asru))) {
			if (arglist->t == T_FUNC)
				check_func(arglist);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to is_present() must be a path or a call "
			    "to fru() or asru()");
		}
	} else if (np->u.func.s == L_has_fault) {
		if (arglist->t == T_LIST &&
		    (arglist->u.expr.left->t == T_NAME ||
		    (arglist->u.expr.left->t == T_FUNC &&
		    (arglist->u.expr.left->u.func.s == L_fru ||
		    arglist->u.expr.left->u.func.s == L_asru))) &&
		    arglist->u.expr.right->t == T_QUOTE) {
			if (arglist->u.expr.left->t == T_FUNC)
				check_func(arglist->u.expr.left);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "%s() must have path or call to "
			    "fru() and/or asru() as first argument; "
			    "second argument must be a string", np->u.func.s);
		}
	} else if (np->u.func.s == L_is_type) {
		if (arglist->t == T_NAME ||
		    (arglist->t == T_FUNC &&
		    (arglist->u.func.s == L_fru ||
		    arglist->u.func.s == L_asru))) {
			if (arglist->t == T_FUNC)
				check_func(arglist);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to is_type() must be a path or a call to "
			    "fru() or asru()");
		}
	} else if (np->u.func.s == L_confcall) {
		if (arglist->t != T_QUOTE &&
		    (arglist->t != T_LIST ||
		    arglist->u.expr.left->t != T_QUOTE))
			outfl(O_ERR, arglist->file, arglist->line,
			    "confcall(): first argument must be a string "
			    "(the name of the operation)");
	} else if (np->u.func.s == L_confprop ||
	    np->u.func.s == L_confprop_defined) {
		if (arglist->t == T_LIST &&
		    (arglist->u.expr.left->t == T_NAME ||
		    (arglist->u.expr.left->t == T_FUNC &&
		    (arglist->u.expr.left->u.func.s == L_fru ||
		    arglist->u.expr.left->u.func.s == L_asru))) &&
		    arglist->u.expr.right->t == T_QUOTE) {
			if (arglist->u.expr.left->t == T_FUNC)
				check_func(arglist->u.expr.left);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "%s(): first argument must be a path or a call to "
			    "fru() or asru(); "
			    "second argument must be a string", np->u.func.s);
		}
	} else if (np->u.func.s == L_count) {
		if (arglist->t != T_EVENT) {
			outfl(O_ERR, arglist->file, arglist->line,
			    "count(): argument must be an engine name");
		}
	} else if (np->u.func.s == L_defined) {
		if (arglist->t != T_GLOBID)
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to defined() must be a global");
	} else if (np->u.func.s == L_payloadprop) {
		if (arglist->t != T_QUOTE)
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to payloadprop() must be a string");
	} else if (np->u.func.s == L_payloadprop_contains) {
		if (arglist->t != T_LIST ||
		    arglist->u.expr.left->t != T_QUOTE ||
		    arglist->u.expr.right == NULL)
			outfl(O_ERR, arglist->file, arglist->line,
			    "args to payloadprop_contains(): must be a quoted "
			    "string (property name) and an expression "
			    "(to match)");
	} else if (np->u.func.s == L_payloadprop_defined) {
		if (arglist->t != T_QUOTE)
			outfl(O_ERR, arglist->file, arglist->line,
			    "arg to payloadprop_defined(): must be a quoted "
			    "string");
	} else if (np->u.func.s == L_setpayloadprop) {
		if (arglist->t == T_LIST &&
		    arglist->u.expr.left->t == T_QUOTE) {
			if (arglist->u.expr.right->t == T_FUNC)
				check_func(arglist->u.expr.right);
		} else {
			outfl(O_ERR, arglist->file, arglist->line,
			    "setpayloadprop(): "
			    "first arg must be a string, "
			    "second arg a value");
		}
	} else if (np->u.func.s == L_setserdn || np->u.func.s == L_setserdt ||
	    np->u.func.s == L_setserdsuffix || np->u.func.s ==
	    L_setserdincrement) {
		if (arglist->t == T_FUNC)
			check_func(arglist);
	} else if (np->u.func.s == L_envprop) {
		if (arglist->t != T_QUOTE)
			outfl(O_ERR, arglist->file, arglist->line,
			    "argument to envprop() must be a string");
	} else
		outfl(O_WARN, np->file, np->line,
		    "possible platform-specific function: %s",
		    np->u.func.s);
}

void
check_expr(struct node *np)
{
	ASSERT(np != NULL);

	switch (np->t) {
	case T_ASSIGN:
		ASSERT(np->u.expr.left != NULL);
		if (np->u.expr.left->t != T_GLOBID)
			outfl(O_ERR, np->file, np->line,
			    "assignment only allowed to globals (e.g. $a)");
		break;
	}
}

void
check_event(struct node *np)
{
	ASSERT(np != NULL);
	ASSERTinfo(np->t == T_EVENT, ptree_nodetype2str(np->t));

	if (np->u.event.epname == NULL) {
		outfl(O_ERR|O_NONL, np->file, np->line,
		    "pathless events not allowed: ");
		ptree_name(O_ERR|O_NONL, np->u.event.ename);
		out(O_ERR, NULL);
	}
}

/*
 * check for properties that are required on declarations. This
 * should be done after all declarations since they can be
 * redeclared with a different set of properties.
 */
/*ARGSUSED*/
void
check_required_props(struct node *lhs, struct node *rhs, void *arg)
{
	ASSERTeq(rhs->t, (enum nodetype)arg, ptree_nodetype2str);

	check_stmt_required_properties(rhs);
}

/*
 * check that cascading prop statements do not contain lists internally.
 * the first and last event lists in the cascading prop may be single
 * events or lists of events.
 */
/*ARGSUSED*/
void
check_proplists(enum nodetype t, struct node *np)
{
	ASSERT(np->t == T_ARROW);
	/*
	 * not checking the right hand side of the top level prop
	 * since it is the last part of the propagation and can be
	 * an event or list of events
	 */
	check_proplists_lhs(t, np->u.arrow.lhs);
}

/*ARGSUSED*/
static void
check_proplists_lhs(enum nodetype t, struct node *lhs)
{
	if (lhs->t == T_ARROW) {
		if (lhs->u.arrow.rhs->t == T_LIST) {
			outfl(O_ERR, lhs->file, lhs->line,
			    "lists are not allowed internally on cascading %s",
			    (t == T_PROP) ? "propagations" : "masks");
		}
		check_proplists_lhs(t, lhs->u.arrow.lhs);
	}
}

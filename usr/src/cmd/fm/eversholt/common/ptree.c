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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ptree.c -- routines for printing the prop tree
 *
 * this module contains routines to print portions of the parse tree.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"

int Pchildgen;

#ifdef	FMAPLUGIN

#include "itree.h"
#include "eval.h"
#include "config.h"

static void
cp2num(struct config *cp, int *num)
{
	config_getcompname(cp, NULL, num);
}

#else

/*ARGSUSED*/
static void
cp2num(struct config *cp, int *num)
{
	out(O_DIE, "ptree: non-NULL cp");
}

#endif	/* FMAPLUGIN */

static int
is_stmt(struct node *np)
{
	switch (np->t) {
	case T_FAULT:
	case T_UPSET:
	case T_DEFECT:
	case T_ERROR:
	case T_EREPORT:
	case T_SERD:
	case T_STAT:
	case T_PROP:
	case T_MASK:
	case T_ASRU:
	case T_FRU:
	case T_CONFIG:
		return (1);
		/*NOTREACHED*/
		break;
	default:
		break;
	}

	return (0);
}

void
ptree(int flags, struct node *np, int no_iterators, int fileline)
{
	if (np == NULL)
		return;

	switch (np->t) {
	case T_NOTHING:
		break;
	case T_NAME:
		out(flags|O_NONL, "%s", np->u.name.s);
		if (!no_iterators) {
			if (np->u.name.cp != NULL) {
				int num;
				cp2num(np->u.name.cp, &num);
				out(flags|O_NONL, "%d", num);
			} else if (np->u.name.it == IT_HORIZONTAL) {
				if (np->u.name.child == NULL ||
				    (np->u.name.childgen && !Pchildgen))
					out(flags|O_NONL, "<>");
				else {
					out(flags|O_NONL, "<");
					ptree(flags, np->u.name.child,
					    no_iterators, fileline);
					out(flags|O_NONL, ">");
				}
			} else if (np->u.name.child &&
			    (!np->u.name.childgen || Pchildgen)) {
				if (np->u.name.it != IT_NONE)
					out(flags|O_NONL, "[");
				ptree(flags, np->u.name.child, no_iterators,
				    fileline);
				if (np->u.name.it != IT_NONE)
					out(flags|O_NONL, "]");
			}
		}
		if (np->u.name.next) {
			ASSERT(np->u.name.next->t == T_NAME);
			if (np->u.name.it == IT_ENAME)
				out(flags|O_NONL, ".");
			else
				out(flags|O_NONL, "/");
			ptree(flags, np->u.name.next, no_iterators, fileline);
		}
		break;
	case T_TIMEVAL:
		ptree_timeval(flags, &np->u.ull);
		break;
	case T_NUM:
		out(flags|O_NONL, "%llu", np->u.ull);
		break;
	case T_QUOTE:
		out(flags|O_NONL, "\"%s\"", np->u.quote.s);
		break;
	case T_GLOBID:
		out(flags|O_NONL, "$%s", np->u.globid.s);
		break;
	case T_FUNC:
		out(flags|O_NONL, "%s(", np->u.func.s);
		ptree(flags, np->u.func.arglist, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_NVPAIR:
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "=");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		break;
	case T_EVENT:
		ptree(flags, np->u.event.ename, no_iterators, fileline);
		if (np->u.event.epname) {
			out(flags|O_NONL, "@");
			ptree(flags, np->u.event.epname,
			    no_iterators, fileline);
		}
		if (np->u.event.eexprlist) {
			out(flags|O_NONL, "{");
			ptree(flags, np->u.event.eexprlist,
			    no_iterators, fileline);
			out(flags|O_NONL, "}");
		}
		break;
	case T_ASSIGN:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "=");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_NOT:
		out(flags|O_NONL, "(");
		out(flags|O_NONL, "!");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_AND:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "&&");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_OR:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "||");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_EQ:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "==");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_NE:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "!=");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_SUB:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "-");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_ADD:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "+");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_MUL:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "*");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_DIV:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "/");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_MOD:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "%%");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_LT:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "<");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_LE:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "<=");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_GT:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ">");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_GE:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ">=");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_BITNOT:
		out(flags|O_NONL, "(");
		out(flags|O_NONL, "~");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_BITAND:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "&");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_BITOR:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "|");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_BITXOR:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "^");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_LSHIFT:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "<<");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_RSHIFT:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ">>");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_CONDIF:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, "?");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_CONDELSE:
		out(flags|O_NONL, "(");
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		out(flags|O_NONL, ":");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		out(flags|O_NONL, ")");
		break;
	case T_ARROW:
		ptree(flags, np->u.arrow.lhs, no_iterators, fileline);
		if (np->u.arrow.nnp) {
			out(flags|O_NONL, "(");
			ptree(flags, np->u.arrow.nnp, no_iterators, fileline);
			out(flags|O_NONL, ")");
		}
		out(flags|O_NONL, "->");
		if (np->u.arrow.knp) {
			out(flags|O_NONL, "(");
			ptree(flags, np->u.arrow.knp, no_iterators, fileline);
			out(flags|O_NONL, ")");
		}
		ptree(flags, np->u.arrow.rhs, no_iterators, fileline);
		break;
	case T_LIST:
		ptree(flags, np->u.expr.left, no_iterators, fileline);
		if (np->u.expr.left && np->u.expr.right &&
		    (np->u.expr.left->t != T_LIST ||
		    ! is_stmt(np->u.expr.right)))
			out(flags|O_NONL, ",");
		ptree(flags, np->u.expr.right, no_iterators, fileline);
		break;
	case T_FAULT:
	case T_UPSET:
	case T_DEFECT:
	case T_ERROR:
	case T_EREPORT:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "event ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		if (np->u.stmt.nvpairs) {
			out(flags|O_NONL, " ");
			ptree(flags, np->u.stmt.nvpairs, no_iterators,
			    fileline);
		}
		out(flags, ";");
		break;
	case T_SERD:
	case T_STAT:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "engine ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		if (np->u.stmt.nvpairs) {
			out(flags|O_NONL, " ");
			ptree(flags, np->u.stmt.nvpairs, no_iterators,
			    fileline);
		} else if (np->u.stmt.lutp) {
			struct plut_wlk_data pd;

			pd.flags = flags;
			pd.first = 0;

			lut_walk(np->u.stmt.lutp, ptree_plut, &pd);
		}
		out(flags, ";");
		break;
	case T_ASRU:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "asru ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		if (np->u.stmt.nvpairs) {
			out(flags|O_NONL, " ");
			ptree(flags, np->u.stmt.nvpairs, no_iterators,
			    fileline);
		}
		out(flags, ";");
		break;
	case T_FRU:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "fru ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		if (np->u.stmt.nvpairs) {
			out(flags|O_NONL, " ");
			ptree(flags, np->u.stmt.nvpairs, no_iterators,
			    fileline);
		}
		out(flags, ";");
		break;
	case T_CONFIG:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "config ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		if (np->u.stmt.nvpairs) {
			out(flags|O_NONL, " ");
			ptree(flags, np->u.stmt.nvpairs, no_iterators,
				fileline);
		}
		out(flags, ";");
		break;
	case T_PROP:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "prop ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		out(flags, ";");
		break;
	case T_MASK:
		if (fileline)
			out(flags, "# %d \"%s\"", np->line, np->file);
		out(flags|O_NONL, "mask ");
		ptree(flags, np->u.stmt.np, no_iterators, fileline);
		out(flags, ";");
		break;
	default:
		out(O_DIE,
		    "internal error: ptree unexpected nodetype: %d", np->t);
		/*NOTREACHED*/
	}
}

void
ptree_plut(void *name, void *val, void *arg)
{
	struct plut_wlk_data *pd = (struct plut_wlk_data *)arg;
	int c;
	static int indent;

	indent++;

	if (pd->first == 0)
		out(pd->flags, ",");
	else
		pd->first = 0;

	for (c = indent; c > 0; c--)
		out(pd->flags|O_NONL, "\t");
	out(pd->flags|O_NONL, "%s", (char *)name);

	out(pd->flags|O_NONL, "=");
	ptree(pd->flags, val, 0, 0);

	indent--;
}

void
ptree_name(int flags, struct node *np)
{
	ptree(flags, np, 1, 0);
}

void
ptree_name_iter(int flags, struct node *np)
{
	ptree(flags, np, 0, 0);
}

const char *
ptree_nodetype2str(enum nodetype t)
{
	static char buf[100];

	switch (t) {
	case T_NOTHING: return L_T_NOTHING;
	case T_NAME: return L_T_NAME;
	case T_GLOBID: return L_T_GLOBID;
	case T_EVENT: return L_T_EVENT;
	case T_ENGINE: return L_T_ENGINE;
	case T_ASRU: return L_asru;
	case T_FRU: return L_fru;
	case T_CONFIG: return L_config;
	case T_TIMEVAL: return L_T_TIMEVAL;
	case T_NUM: return L_T_NUM;
	case T_QUOTE: return L_T_QUOTE;
	case T_FUNC: return L_T_FUNC;
	case T_NVPAIR: return L_T_NVPAIR;
	case T_ASSIGN: return L_T_ASSIGN;
	case T_CONDIF: return L_T_CONDIF;
	case T_CONDELSE: return L_T_CONDELSE;
	case T_NOT: return L_T_NOT;
	case T_AND: return L_T_AND;
	case T_OR: return L_T_OR;
	case T_EQ: return L_T_EQ;
	case T_NE: return L_T_NE;
	case T_SUB: return L_T_SUB;
	case T_ADD: return L_T_ADD;
	case T_MUL: return L_T_MUL;
	case T_DIV: return L_T_DIV;
	case T_MOD: return L_T_MOD;
	case T_LT: return L_T_LT;
	case T_LE: return L_T_LE;
	case T_GT: return L_T_GT;
	case T_GE: return L_T_GE;
	case T_BITAND: return L_T_BITAND;
	case T_BITOR: return L_T_BITOR;
	case T_BITXOR: return L_T_BITXOR;
	case T_BITNOT: return L_T_BITNOT;
	case T_LSHIFT: return L_T_LSHIFT;
	case T_RSHIFT: return L_T_RSHIFT;
	case T_ARROW: return L_T_ARROW;
	case T_LIST: return L_T_LIST;
	case T_FAULT: return L_fault;
	case T_UPSET: return L_upset;
	case T_DEFECT: return L_defect;
	case T_ERROR: return L_error;
	case T_EREPORT: return L_ereport;
	case T_SERD: return L_serd;
	case T_STAT: return L_stat;
	case T_PROP: return L_prop;
	case T_MASK: return L_mask;
	default:
		(void) sprintf(buf, "[unexpected nodetype: %d]", t);
		return (buf);
	}
}

const char *
ptree_nametype2str(enum nametype t)
{
	static char buf[100];

	switch (t) {
	case N_UNSPEC: return L_N_UNSPEC;
	case N_FAULT: return L_fault;
	case N_DEFECT: return L_defect;
	case N_UPSET: return L_upset;
	case N_ERROR: return L_error;
	case N_EREPORT: return L_ereport;
	case N_SERD: return L_serd;
	case N_STAT: return L_stat;
	default:
		(void) sprintf(buf, "[unexpected nametype: %d]", t);
		return (buf);
	}
}

struct printer_info {
	enum nodetype t;
	const char *pat;
	int flags;
};

static int
name_pattern_match(struct node *np, const char *pat)
{
	const char *cend;	/* first character not in component in pat */

	if (pat == NULL || *pat == '\0')
		return (1);	/* either no pattern or we've matched it all */

	if (np == NULL)
		return (0);	/* there's more pattern and nothing to match */

	ASSERTeq(np->t, T_NAME, ptree_nodetype2str);

	cend = strchr(pat, '/');
	if (cend == NULL)
		cend = strchr(pat, '.');
	if (cend == NULL)
		cend = &pat[strlen(pat)];

	while (np) {
		const char *s = np->u.name.s;

		while (*s) {
			const char *cstart = pat;

			while (*s && tolower(*s) == tolower(*cstart)) {
				cstart++;
				if (cstart == cend) {
					/* component matched */
					while (*cend == '/')
						cend++;
					return
					    name_pattern_match(np->u.name.next,
					    cend);
				}
				s++;
			}
			if (*s)
				s++;
		}
		np = np->u.name.next;
	}
	return (0);
}

static int
name_pattern_match_in_subtree(struct node *np, const char *pat)
{
	if (pat == NULL || *pat == '\0')
		return (1);

	if (np == NULL)
		return (0);

	if (np->t == T_NAME)
		return (name_pattern_match(np, pat));
	else if (np->t == T_EVENT)
		return (name_pattern_match_in_subtree(np->u.event.ename, pat) ||
		    name_pattern_match_in_subtree(np->u.event.epname, pat) ||
		    name_pattern_match_in_subtree(np->u.event.eexprlist, pat));
	else if (np->t == T_ARROW)
		return (name_pattern_match_in_subtree(np->u.arrow.lhs, pat) ||
		    name_pattern_match_in_subtree(np->u.arrow.rhs, pat));
	else if (np->t == T_ASSIGN ||
			np->t == T_CONDIF ||
			np->t == T_CONDELSE ||
			np->t == T_NOT ||
			np->t == T_AND ||
			np->t == T_OR ||
			np->t == T_EQ ||
			np->t == T_NE ||
			np->t == T_SUB ||
			np->t == T_ADD ||
			np->t == T_MUL ||
			np->t == T_DIV ||
			np->t == T_MOD ||
			np->t == T_LT ||
			np->t == T_LE ||
			np->t == T_GT ||
			np->t == T_GE ||
			np->t == T_BITAND ||
			np->t == T_BITOR ||
			np->t == T_BITXOR ||
			np->t == T_BITNOT ||
			np->t == T_LSHIFT ||
			np->t == T_RSHIFT ||
			np->t == T_LIST) {
		return (name_pattern_match_in_subtree(np->u.expr.left, pat) ||
		    name_pattern_match_in_subtree(np->u.expr.right, pat));
	} else if (np->t == T_FUNC) {
		return (name_pattern_match_in_subtree(np->u.func.arglist, pat));
	}
	return (0);
}

static void
byname_printer(struct node *lhs, struct node *rhs, void *arg)
{
	struct printer_info *infop = (struct printer_info *)arg;

	if (infop->t != T_NOTHING && rhs->t != infop->t)
		return;
	if (!name_pattern_match(lhs, infop->pat))
		return;
	ptree(infop->flags, rhs, 0, 0);
}

static void
ptree_type_pattern(int flags, enum nodetype t, const char *pat)
{
	struct printer_info info;
	struct node *np;

	info.flags = flags;
	info.pat = pat;
	info.t = t;

	switch (t) {
	case T_FAULT:
		lut_walk(Faults, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_UPSET:
		lut_walk(Upsets, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_DEFECT:
		lut_walk(Defects, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_ERROR:
		lut_walk(Errors, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_EREPORT:
		lut_walk(Ereports, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_SERD:
		lut_walk(SERDs, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_STAT:
		lut_walk(STATs, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_ASRU:
		lut_walk(ASRUs, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_FRU:
		lut_walk(FRUs, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_CONFIG:
		lut_walk(Configs, (lut_cb)byname_printer, (void *)&info);
		return;
	case T_PROP:
		for (np = Props; np; np = np->u.stmt.next)
			if (name_pattern_match_in_subtree(np->u.stmt.np, pat))
				ptree(flags, np, 0, 0);
		return;
	case T_MASK:
		for (np = Masks; np; np = np->u.stmt.next)
			if (name_pattern_match_in_subtree(np->u.stmt.np, pat))
				ptree(flags, np, 0, 0);
		return;
	default:
		ptree(flags, tree_root(NULL), 0, 0);
	}
}

void
ptree_all(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_NOTHING, pat);
}

void
ptree_fault(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_FAULT, pat);
}

void
ptree_upset(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_UPSET, pat);
}

void
ptree_defect(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_DEFECT, pat);
}

void
ptree_error(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_ERROR, pat);
}

void
ptree_ereport(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_EREPORT, pat);
}

void
ptree_serd(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_SERD, pat);
}

void
ptree_stat(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_STAT, pat);
}

void
ptree_asru(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_ASRU, pat);
}

void
ptree_fru(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_FRU, pat);
}

void
ptree_prop(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_PROP, pat);
}

void
ptree_mask(int flags, const char *pat)
{
	ptree_type_pattern(flags, T_MASK, pat);
}

void
ptree_timeval(int flags, unsigned long long *ullp)
{
	unsigned long long val;

#define	NOREMAINDER(den, num, val) (((val) = ((den) / (num))) * (num) == (den))
	if (*ullp == 0)
		out(flags|O_NONL, "0us");
	else if (*ullp >= TIMEVAL_EVENTUALLY)
		out(flags|O_NONL, "infinity");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60*60*24*365, val))
		out(flags|O_NONL, "%lluyear%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60*60*24*30, val))
		out(flags|O_NONL, "%llumonth%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60*60*24*7, val))
		out(flags|O_NONL, "%lluweek%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60*60*24, val))
		out(flags|O_NONL, "%lluday%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60*60, val))
		out(flags|O_NONL, "%lluhour%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL*60, val))
		out(flags|O_NONL, "%lluminute%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000000ULL, val))
		out(flags|O_NONL, "%llusecond%s", val, (val == 1) ? "" : "s");
	else if (NOREMAINDER(*ullp, 1000000ULL, val))
		out(flags|O_NONL, "%llums", val);
	else if (NOREMAINDER(*ullp, 1000ULL, val))
		out(flags|O_NONL, "%lluus", val);
	else
		out(flags|O_NONL, "%lluns", *ullp);
}

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
 * tree.c -- routines for manipulating the prop tree
 *
 * the actions in escparse.y call these routines to construct
 * the parse tree.  these routines, in turn, call the check_X()
 * routines for semantic checking.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <alloca.h>
#include "alloc.h"
#include "out.h"
#include "stats.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "tree.h"
#include "check.h"
#include "ptree.h"

static struct node *Root;

static char *Newname;

static struct stats *Faultcount;
static struct stats *Upsetcount;
static struct stats *Defectcount;
static struct stats *Errorcount;
static struct stats *Ereportcount;
static struct stats *SERDcount;
static struct stats *STATcount;
static struct stats *ASRUcount;
static struct stats *FRUcount;
static struct stats *Configcount;
static struct stats *Propcount;
static struct stats *Maskcount;
static struct stats *Nodecount;
static struct stats *Namecount;
static struct stats *Nodesize;

struct lut *Usedprops;

void
tree_init(void)
{
	Faultcount = stats_new_counter("parser.fault", "fault decls", 1);
	Upsetcount = stats_new_counter("parser.upset", "upset decls", 1);
	Defectcount = stats_new_counter("parser.defect", "defect decls", 1);
	Errorcount = stats_new_counter("parser.error", "error decls", 1);
	Ereportcount = stats_new_counter("parser.ereport", "ereport decls", 1);
	SERDcount = stats_new_counter("parser.SERD", "SERD engine decls", 1);
	STATcount = stats_new_counter("parser.STAT", "STAT engine decls", 1);
	ASRUcount = stats_new_counter("parser.ASRU", "ASRU decls", 1);
	FRUcount = stats_new_counter("parser.FRU", "FRU decls", 1);
	Configcount = stats_new_counter("parser.config", "config stmts", 1);
	Propcount = stats_new_counter("parser.prop", "prop stmts", 1);
	Maskcount = stats_new_counter("parser.mask", "mask stmts", 1);
	Nodecount = stats_new_counter("parser.node", "nodes created", 1);
	Namecount = stats_new_counter("parser.name", "names created", 1);
	Nodesize =
	    stats_new_counter("parser.nodesize", "sizeof(struct node)", 1);
	stats_counter_add(Nodesize, sizeof (struct node));
}

void
tree_fini(void)
{
	stats_delete(Faultcount);
	stats_delete(Upsetcount);
	stats_delete(Defectcount);
	stats_delete(Errorcount);
	stats_delete(Ereportcount);
	stats_delete(SERDcount);
	stats_delete(STATcount);
	stats_delete(ASRUcount);
	stats_delete(FRUcount);
	stats_delete(Configcount);
	stats_delete(Propcount);
	stats_delete(Maskcount);
	stats_delete(Nodecount);
	stats_delete(Namecount);
	stats_delete(Nodesize);

	/* free entire parse tree */
	tree_free(Root);

	/* free up the luts we keep for decls */
	lut_free(Faults, NULL, NULL);
	Faults = NULL;
	lut_free(Upsets, NULL, NULL);
	Upsets = NULL;
	lut_free(Defects, NULL, NULL);
	Defects = NULL;
	lut_free(Errors, NULL, NULL);
	Errors = NULL;
	lut_free(Ereports, NULL, NULL);
	Ereports = NULL;
	lut_free(Ereportenames, NULL, NULL);
	Ereportenames = NULL;
	lut_free(Ereportenames_discard, NULL, NULL);
	Ereportenames_discard = NULL;
	lut_free(SERDs, NULL, NULL);
	SERDs = NULL;
	lut_free(STATs, NULL, NULL);
	STATs = NULL;
	lut_free(ASRUs, NULL, NULL);
	ASRUs = NULL;
	lut_free(FRUs, NULL, NULL);
	FRUs = NULL;
	lut_free(Configs, NULL, NULL);
	Configs = NULL;
	lut_free(Usedprops, NULL, NULL);
	Usedprops = NULL;

	Props = Lastprops = NULL;
	Masks = Lastmasks = NULL;
	Problems = Lastproblems = NULL;

	if (Newname != NULL) {
		FREE(Newname);
		Newname = NULL;
	}
}

/*ARGSUSED*/
static int
nodesize(enum nodetype t, struct node *ret)
{
	int size = sizeof (struct node);

	switch (t) {
	case T_NAME:
		size += sizeof (ret->u.name) - sizeof (ret->u);
		break;

	case T_GLOBID:
		size += sizeof (ret->u.globid) - sizeof (ret->u);
		break;

	case T_TIMEVAL:
	case T_NUM:
		size += sizeof (ret->u.ull) - sizeof (ret->u);
		break;

	case T_QUOTE:
		size += sizeof (ret->u.quote) - sizeof (ret->u);
		break;

	case T_FUNC:
		size += sizeof (ret->u.func) - sizeof (ret->u);
		break;

	case T_FAULT:
	case T_UPSET:
	case T_DEFECT:
	case T_ERROR:
	case T_EREPORT:
	case T_ASRU:
	case T_FRU:
	case T_SERD:
	case T_STAT:
	case T_CONFIG:
	case T_PROP:
	case T_MASK:
		size += sizeof (ret->u.stmt) - sizeof (ret->u);
		break;

	case T_EVENT:
		size += sizeof (ret->u.event) - sizeof (ret->u);
		break;

	case T_ARROW:
		size += sizeof (ret->u.arrow) - sizeof (ret->u);
		break;

	default:
		size += sizeof (ret->u.expr) - sizeof (ret->u);
		break;
	}
	return (size);
}

struct node *
newnode(enum nodetype t, const char *file, int line)
{
	struct node *ret = NULL;
	int size = nodesize(t, ret);

	ret = alloc_xmalloc(size);
	stats_counter_bump(Nodecount);
	bzero(ret, size);
	ret->t = t;
	ret->file = (file == NULL) ? "<nofile>" : file;
	ret->line = line;

	return (ret);
}

/*ARGSUSED*/
void
tree_free(struct node *root)
{
	if (root == NULL)
		return;

	switch (root->t) {
	case T_NAME:
		tree_free(root->u.name.child);
		tree_free(root->u.name.next);
		break;
	case T_FUNC:
		tree_free(root->u.func.arglist);
		break;
	case T_AND:
	case T_OR:
	case T_EQ:
	case T_NE:
	case T_ADD:
	case T_DIV:
	case T_MOD:
	case T_MUL:
	case T_SUB:
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
	case T_NVPAIR:
	case T_ASSIGN:
	case T_CONDIF:
	case T_CONDELSE:
	case T_LIST:
		tree_free(root->u.expr.left);
		tree_free(root->u.expr.right);
		break;
	case T_EVENT:
		tree_free(root->u.event.ename);
		tree_free(root->u.event.epname);
		tree_free(root->u.event.eexprlist);
		break;
	case T_NOT:
		tree_free(root->u.expr.left);
		break;
	case T_ARROW:
		tree_free(root->u.arrow.lhs);
		tree_free(root->u.arrow.nnp);
		tree_free(root->u.arrow.knp);
		tree_free(root->u.arrow.rhs);
		break;
	case T_PROP:
	case T_MASK:
		tree_free(root->u.stmt.np);
		break;
	case T_FAULT:
	case T_UPSET:
	case T_DEFECT:
	case T_ERROR:
	case T_EREPORT:
	case T_ASRU:
	case T_FRU:
	case T_SERD:
	case T_STAT:
	case T_CONFIG:
		tree_free(root->u.stmt.np);
		if (root->u.stmt.nvpairs)
			tree_free(root->u.stmt.nvpairs);
		if (root->u.stmt.lutp)
			lut_free(root->u.stmt.lutp, NULL, NULL);
		break;
	case T_TIMEVAL:
	case T_NUM:
	case T_QUOTE:
	case T_GLOBID:
	case T_NOTHING:
		break;
	default:
		out(O_DIE,
		    "internal error: tree_free unexpected nodetype: %d",
		    root->t);
		/*NOTREACHED*/
	}
	alloc_xfree((char *)root, nodesize(root->t, root));
}

static int
tree_treecmp(struct node *np1, struct node *np2, enum nodetype t,
	    lut_cmp cmp_func)
{
	if (np1 == NULL || np2 == NULL)
		return (0);

	if (np1->t != np2->t)
		return (1);

	ASSERT(cmp_func != NULL);

	if (np1->t == t)
		return ((*cmp_func)(np1, np2));

	switch (np1->t) {
	case T_NAME:
		if (tree_treecmp(np1->u.name.child, np2->u.name.child, t,
		    cmp_func))
			return (1);
		return (tree_treecmp(np1->u.name.next, np2->u.name.next, t,
		    cmp_func));
		/*NOTREACHED*/
		break;
	case T_FUNC:
		return (tree_treecmp(np1->u.func.arglist, np2->u.func.arglist,
		    t, cmp_func));
		/*NOTREACHED*/
		break;
	case T_AND:
	case T_OR:
	case T_EQ:
	case T_NE:
	case T_ADD:
	case T_DIV:
	case T_MOD:
	case T_MUL:
	case T_SUB:
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
	case T_NVPAIR:
	case T_ASSIGN:
	case T_CONDIF:
	case T_CONDELSE:
	case T_LIST:
		if (tree_treecmp(np1->u.expr.left, np2->u.expr.left, t,
		    cmp_func))
			return (1);
		return (tree_treecmp(np1->u.expr.right, np2->u.expr.right, t,
		    cmp_func));
		/*NOTREACHED*/
		break;
	case T_EVENT:
		if (tree_treecmp(np1->u.event.ename, np2->u.event.ename, t,
		    cmp_func))
			return (1);
		if (tree_treecmp(np1->u.event.epname, np2->u.event.epname, t,
		    cmp_func))
			return (1);
		return (tree_treecmp(np1->u.event.eexprlist,
		    np2->u.event.eexprlist, t, cmp_func));
		/*NOTREACHED*/
		break;
	case T_NOT:
		return (tree_treecmp(np1->u.expr.left, np2->u.expr.left, t,
		    cmp_func));
		/*NOTREACHED*/
		break;
	case T_ARROW:
		if (tree_treecmp(np1->u.arrow.lhs, np2->u.arrow.lhs, t,
		    cmp_func))
			return (1);
		if (tree_treecmp(np1->u.arrow.nnp, np2->u.arrow.nnp, t,
		    cmp_func))
			return (1);
		if (tree_treecmp(np1->u.arrow.knp, np2->u.arrow.knp, t,
		    cmp_func))
			return (1);
		return (tree_treecmp(np1->u.arrow.rhs, np2->u.arrow.rhs, t,
		    cmp_func));
		/*NOTREACHED*/
		break;
	case T_PROP:
	case T_MASK:
		return (tree_treecmp(np1->u.stmt.np, np2->u.stmt.np, t,
		    cmp_func));
		/*NOTREACHED*/
		break;
	case T_FAULT:
	case T_UPSET:
	case T_DEFECT:
	case T_ERROR:
	case T_EREPORT:
	case T_ASRU:
	case T_FRU:
	case T_SERD:
	case T_STAT:
		if (tree_treecmp(np1->u.stmt.np, np2->u.stmt.np, t, cmp_func))
			return (1);
		return (tree_treecmp(np1->u.stmt.nvpairs, np2->u.stmt.nvpairs,
		    t, cmp_func));
		/*NOTREACHED*/
		break;
	case T_TIMEVAL:
	case T_NUM:
	case T_QUOTE:
	case T_GLOBID:
	case T_NOTHING:
		break;
	default:
		out(O_DIE,
		    "internal error: tree_treecmp unexpected nodetype: %d",
		    np1->t);
		/*NOTREACHED*/
		break;
	}

	return (0);
}

struct node *
tree_root(struct node *np)
{
	if (np)
		Root = np;
	return (Root);
}

struct node *
tree_nothing(void)
{
	return (newnode(T_NOTHING, L_nofile, 0));
}

struct node *
tree_expr(enum nodetype t, struct node *left, struct node *right)
{
	struct node *ret;

	ASSERTinfo(left != NULL || right != NULL, ptree_nodetype2str(t));

	ret = newnode(t,
	    (left) ? left->file : right->file,
	    (left) ? left->line : right->line);

	ret->u.expr.left = left;
	ret->u.expr.right = right;

	check_expr(ret);

	return (ret);
}

/*
 * ename_compress -- convert event class name in to more space-efficient form
 *
 * this routine is called after the parser has completed an "ename", which
 * is that part of an event that contains the class name (like ereport.x.y.z).
 * after this routine gets done with the ename, two things are true:
 *   1. the ename uses only a single struct node
 *   2. ename->u.name.s contains the *complete* class name, dots and all,
 *      entered into the string table.
 *
 * so in addition to saving space by using fewer struct nodes, this routine
 * allows consumers of the fault tree to assume the ename is a single
 * string, rather than a linked list of strings.
 */
static struct node *
ename_compress(struct node *ename)
{
	char *buf;
	char *cp;
	int len = 0;
	struct node *np;

	if (ename == NULL)
		return (ename);

	ASSERT(ename->t == T_NAME);

	if (ename->u.name.next == NULL)
		return (ename);	/* no compression to be applied here */

	for (np = ename; np != NULL; np = np->u.name.next) {
		ASSERT(np->t == T_NAME);
		len++;	/* room for '.' and final '\0' */
		len += strlen(np->u.name.s);
	}
	cp = buf = alloca(len);
	for (np = ename; np != NULL; np = np->u.name.next) {
		ASSERT(np->t == T_NAME);
		if (np != ename)
			*cp++ = '.';
		(void) strcpy(cp, np->u.name.s);
		cp += strlen(cp);
	}

	ename->u.name.s = stable(buf);
	tree_free(ename->u.name.next);
	ename->u.name.next = NULL;
	ename->u.name.last = ename;
	return (ename);
}

struct node *
tree_event(struct node *ename, struct node *epname, struct node *eexprlist)
{
	struct node *ret;

	ASSERT(ename != NULL);

	ret = newnode(T_EVENT, ename->file, ename->line);

	ret->u.event.ename = ename_compress(ename);
	ret->u.event.epname = epname;
	ret->u.event.eexprlist = eexprlist;

	check_event(ret);

	return (ret);
}

struct node *
tree_name(const char *s, enum itertype it, const char *file, int line)
{
	struct node *ret = newnode(T_NAME, file, line);

	ASSERT(s != NULL);

	stats_counter_bump(Namecount);
	ret->u.name.t = N_UNSPEC;
	ret->u.name.s = stable(s);
	ret->u.name.it = it;
	ret->u.name.last = ret;

	if (it == IT_ENAME) {
		/* PHASE2, possible optimization: convert to table driven */
		if (s == L_fault)
			ret->u.name.t = N_FAULT;
		else if (s == L_upset)
			ret->u.name.t = N_UPSET;
		else if (s == L_defect)
			ret->u.name.t = N_DEFECT;
		else if (s == L_error)
			ret->u.name.t = N_ERROR;
		else if (s == L_ereport)
			ret->u.name.t = N_EREPORT;
		else if (s == L_serd)
			ret->u.name.t = N_SERD;
		else if (s == L_stat)
			ret->u.name.t = N_STAT;
		else
			outfl(O_ERR, file, line, "unknown class: %s", s);
	}
	return (ret);
}

struct node *
tree_iname(const char *s, const char *file, int line)
{
	struct node *ret;
	char *ss;
	char *ptr;

	ASSERT(s != NULL && *s != '\0');

	ss = STRDUP(s);

	ptr = &ss[strlen(ss) - 1];
	if (!isdigit(*ptr)) {
		outfl(O_ERR, file, line,
		    "instanced name expected (i.e. \"x0/y1\")");
		FREE(ss);
		return (tree_name(s, IT_NONE, file, line));
	}
	while (ptr > ss && isdigit(*(ptr - 1)))
		ptr--;

	ret = newnode(T_NAME, file, line);
	stats_counter_bump(Namecount);
	ret->u.name.child = tree_num(ptr, file, line);
	*ptr = '\0';
	ret->u.name.t = N_UNSPEC;
	ret->u.name.s = stable(ss);
	ret->u.name.it = IT_NONE;
	ret->u.name.last = ret;
	FREE(ss);

	return (ret);
}

struct node *
tree_globid(const char *s, const char *file, int line)
{
	struct node *ret = newnode(T_GLOBID, file, line);

	ASSERT(s != NULL);

	ret->u.globid.s = stable(s);

	return (ret);
}

struct node *
tree_name_append(struct node *np1, struct node *np2)
{
	ASSERT(np1 != NULL && np2 != NULL);

	if (np1->t != T_NAME)
		outfl(O_DIE, np1->file, np1->line,
		    "tree_name_append: internal error (np1 type %d)", np1->t);
	if (np2->t != T_NAME)
		outfl(O_DIE, np2->file, np2->line,
		    "tree_name_append: internal error (np2 type %d)", np2->t);

	ASSERT(np1->u.name.last != NULL);

	np1->u.name.last->u.name.next = np2;
	np1->u.name.last = np2;
	return (np1);
}

/*
 * tree_name_repairdash -- repair a class name that contained a dash
 *
 * this routine is called by the parser when a dash is encountered
 * in a class name.  the event protocol allows the dashes but our
 * lexer considers them a separate token (arithmetic minus).  an extra
 * rule in the parser catches this case and calls this routine to fixup
 * the last component of the class name (so far) by constructing the
 * new stable entry for a name including the dash.
 */
struct node *
tree_name_repairdash(struct node *np, const char *s)
{
	int len;
	char *buf;

	ASSERT(np != NULL && s != NULL);

	if (np->t != T_NAME)
		outfl(O_DIE, np->file, np->line,
		    "tree_name_repairdash: internal error (np type %d)",
		    np->t);

	ASSERT(np->u.name.last != NULL);

	len = strlen(np->u.name.last->u.name.s) + 1 + strlen(s) + 1;
	buf = MALLOC(len);
	(void) snprintf(buf, len, "%s-%s", np->u.name.last->u.name.s, s);
	np->u.name.last->u.name.s = stable(buf);
	FREE(buf);
	return (np);
}

struct node *
tree_name_repairdash2(const char *s, struct node *np)
{
	int len;
	char *buf;

	ASSERT(np != NULL && s != NULL);

	if (np->t != T_NAME)
		outfl(O_DIE, np->file, np->line,
		    "tree_name_repairdash: internal error (np type %d)",
		    np->t);

	ASSERT(np->u.name.last != NULL);

	len = strlen(np->u.name.last->u.name.s) + 1 + strlen(s) + 1;
	buf = MALLOC(len);
	(void) snprintf(buf, len, "%s-%s", s, np->u.name.last->u.name.s);
	np->u.name.last->u.name.s = stable(buf);
	FREE(buf);
	return (np);
}

struct node *
tree_name_iterator(struct node *np1, struct node *np2)
{
	ASSERT(np1 != NULL);
	ASSERT(np2 != NULL);
	ASSERTinfo(np1->t == T_NAME, ptree_nodetype2str(np1->t));

	np1->u.name.child = np2;

	check_name_iterator(np1);

	return (np1);
}

struct node *
tree_timeval(const char *s, const char *suffix, const char *file, int line)
{
	struct node *ret = newnode(T_TIMEVAL, file, line);
	const unsigned long long *ullp;

	ASSERT(s != NULL);
	ASSERT(suffix != NULL);

	if ((ullp = lex_s2ullp_lut_lookup(Timesuffixlut, suffix)) == NULL) {
		outfl(O_ERR, file, line,
		    "unrecognized number suffix: %s", suffix);
		/* still construct a valid timeval node so parsing continues */
		ret->u.ull = 1;
	} else {
		ret->u.ull = (unsigned long long)strtoul(s, NULL, 0) * *ullp;
	}

	return (ret);
}

struct node *
tree_num(const char *s, const char *file, int line)
{
	struct node *ret = newnode(T_NUM, file, line);

	ret->u.ull = (unsigned long long)strtoul(s, NULL, 0);
	return (ret);
}

struct node *
tree_quote(const char *s, const char *file, int line)
{
	struct node *ret = newnode(T_QUOTE, file, line);

	ret->u.quote.s = stable(s);
	return (ret);
}

struct node *
tree_func(const char *s, struct node *np, const char *file, int line)
{
	struct node *ret = newnode(T_FUNC, file, line);
	const char *ptr;

	ret->u.func.s = s;
	ret->u.func.arglist = np;

	check_func(ret);

	/*
	 * keep track of the properties we're interested in so we can ignore the
	 * rest
	 */
	if (strcmp(s, L_confprop) == 0 || strcmp(s, L_confprop_defined) == 0) {
		ptr = stable(np->u.expr.right->u.quote.s);
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	} else if (strcmp(s, L_is_connected) == 0) {
		ptr = stable("connected");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
		ptr = stable("CONNECTED");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	} else if (strcmp(s, L_is_type) == 0) {
		ptr = stable("type");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
		ptr = stable("TYPE");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	} else if (strcmp(s, L_is_on) == 0) {
		ptr = stable("on");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
		ptr = stable("ON");
		Usedprops = lut_add(Usedprops, (void *)ptr, (void *)ptr, NULL);
	}

	return (ret);
}

/*
 * given a list from a prop or mask statement or a function argument,
 * convert all iterators to explicit iterators by inventing appropriate
 * iterator names.
 */
static void
make_explicit(struct node *np, int eventonly)
{
	struct node *pnp;	/* component of pathname */
	struct node *pnp2;
	int count;
	static size_t namesz;

	if (Newname == NULL) {
		namesz = 200;
		Newname = MALLOC(namesz);
	}

	if (np == NULL)
		return;		/* all done */

	switch (np->t) {
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
			make_explicit(np->u.expr.left, eventonly);
			make_explicit(np->u.expr.right, eventonly);
			break;

		case T_EVENT:
			make_explicit(np->u.event.epname, 0);
			make_explicit(np->u.event.eexprlist, 1);
			break;

		case T_FUNC:
			make_explicit(np->u.func.arglist, eventonly);
			break;

		case T_NAME:
			if (eventonly)
				return;
			for (pnp = np; pnp != NULL; pnp = pnp->u.name.next)
				if (pnp->u.name.child == NULL) {
					/*
					 * found implicit iterator.  convert
					 * it to an explicit iterator by
					 * using the name of the component
					 * appended with '#' and the number
					 * of times we've seen this same
					 * component name in this path so far.
					 */
					count = 0;
					for (pnp2 = np; pnp2 != NULL;
					    pnp2 = pnp2->u.name.next)
						if (pnp2 == pnp)
							break;
						else if (pnp2->u.name.s ==
						    pnp->u.name.s)
							count++;

					if (namesz < strlen(pnp->u.name.s) +
					    100) {
						namesz = strlen(pnp->u.name.s) +
						    100;
						FREE(Newname);
						Newname = MALLOC(namesz);
					}
					/*
					 * made up interator name is:
					 *	name#ordinal
					 * or
					 *	name##ordinal
					 * the first one is used for vertical
					 * expansion, the second for horizontal.
					 * either way, the '#' embedded in
					 * the name makes it impossible to
					 * collide with an actual iterator
					 * given to us in the eversholt file.
					 */
					(void) snprintf(Newname, namesz,
					    "%s#%s%d", pnp->u.name.s,
					    (pnp->u.name.it == IT_HORIZONTAL) ?
					    "#" : "", count);

					pnp->u.name.child = tree_name(Newname,
					    IT_NONE, pnp->file, pnp->line);
					pnp->u.name.childgen = 1;
				}
			break;
	}
}

struct node *
tree_pname(struct node *np)
{
	make_explicit(np, 0);
	return (np);
}

struct node *
tree_arrow(struct node *lhs, struct node *nnp, struct node *knp,
    struct node *rhs)
{
	struct node *ret;

	ASSERT(lhs != NULL || rhs != NULL);

	ret = newnode(T_ARROW,
	    (lhs) ? lhs->file : rhs->file,
	    (lhs) ? lhs->line : rhs->line);

	ret->u.arrow.lhs = lhs;
	ret->u.arrow.nnp = nnp;
	ret->u.arrow.knp = knp;
	ret->u.arrow.rhs = rhs;

	make_explicit(lhs, 0);
	make_explicit(rhs, 0);

	check_arrow(ret);

	return (ret);
}

static struct lut *
nvpair2lut(struct node *np, struct lut *lutp, enum nodetype t)
{
	if (np) {
		if (np->t == T_NVPAIR) {
			ASSERTeq(np->u.expr.left->t, T_NAME,
			    ptree_nodetype2str);
			check_stmt_allowed_properties(t, np, lutp);
			lutp = tree_s2np_lut_add(lutp,
			    np->u.expr.left->u.name.s, np->u.expr.right);
		} else if (np->t == T_LIST) {
			lutp = nvpair2lut(np->u.expr.left, lutp, t);
			lutp = nvpair2lut(np->u.expr.right, lutp, t);
		} else
			outfl(O_DIE, np->file, np->line,
			    "internal error: nvpair2lut type %s",
			    ptree_nodetype2str(np->t));
	}

	return (lutp);
}

struct lut *
tree_s2np_lut_add(struct lut *root, const char *s, struct node *np)
{
	return (lut_add(root, (void *)s, (void *)np, NULL));
}

struct node *
tree_s2np_lut_lookup(struct lut *root, const char *s)
{
	return (struct node *)lut_lookup(root, (void *)s, NULL);
}

struct lut *
tree_name2np_lut_add(struct lut *root, struct node *namep, struct node *np)
{
	return (lut_add(root, (void *)namep, (void *)np,
	    (lut_cmp)tree_namecmp));
}

struct node *
tree_name2np_lut_lookup(struct lut *root, struct node *namep)
{
	return (struct node *)
	    lut_lookup(root, (void *)namep, (lut_cmp)tree_namecmp);
}

struct node *
tree_name2np_lut_lookup_name(struct lut *root, struct node *namep)
{
	return (struct node *)
	    lut_lookup_lhs(root, (void *)namep, (lut_cmp)tree_namecmp);
}

struct lut *
tree_event2np_lut_add(struct lut *root, struct node *enp, struct node *np)
{
	return (lut_add(root, (void *)enp, (void *)np, (lut_cmp)tree_eventcmp));
}

struct node *
tree_event2np_lut_lookup(struct lut *root, struct node *enp)
{
	return ((struct node *)
	    lut_lookup(root, (void *)enp, (lut_cmp)tree_eventcmp));
}

struct node *
tree_event2np_lut_lookup_event(struct lut *root, struct node *enp)
{
	return ((struct node *)
	    lut_lookup_lhs(root, (void *)enp, (lut_cmp)tree_eventcmp));
}

static struct node *
dodecl(enum nodetype t, const char *file, int line,
    struct node *np, struct node *nvpairs, struct lut **lutpp,
    struct stats *countp, int justpath)
{
	struct node *ret;
	struct node *decl;

	/* allocate parse tree node */
	ret = newnode(t, file, line);
	ret->u.stmt.np = np;
	ret->u.stmt.nvpairs = nvpairs;

	/*
	 * the global lut pointed to by lutpp (Faults, Defects, Upsets,
	 * Errors, Ereports, Serds, FRUs, or ASRUs) keeps the first decl.
	 * if this isn't the first declr, we merge the
	 * nvpairs into the first decl so we have a
	 * merged table to look up properties from.
	 * if this is the first time we've seen this fault,
	 * we add it to the global lut and start lutp
	 * off with any nvpairs from this declaration statement.
	 */
	if (justpath && (decl = tree_name2np_lut_lookup(*lutpp, np)) == NULL) {
		/* this is the first time name is declared */
		stats_counter_bump(countp);
		*lutpp = tree_name2np_lut_add(*lutpp, np, ret);
		ret->u.stmt.lutp = nvpair2lut(nvpairs, NULL, t);
	} else if (!justpath &&
	    (decl = tree_event2np_lut_lookup(*lutpp, np)) == NULL) {
		/* this is the first time event is declared */
		stats_counter_bump(countp);
		*lutpp = tree_event2np_lut_add(*lutpp, np, ret);
		ret->u.stmt.lutp = nvpair2lut(nvpairs, NULL, t);
	} else {
		/* was declared before, just add new nvpairs to its lutp */
		decl->u.stmt.lutp = nvpair2lut(nvpairs, decl->u.stmt.lutp, t);
	}

	return (ret);
}

/*ARGSUSED*/
static void
update_serd_refstmt(void *lhs, void *rhs, void *arg)
{
	struct node *serd;

	ASSERT(rhs != NULL);

	serd = tree_s2np_lut_lookup(((struct node *)rhs)->u.stmt.lutp,
	    L_engine);
	if (serd == NULL)
		return;

	ASSERT(serd->t == T_EVENT);
	if (arg != NULL && tree_eventcmp(serd, (struct node *)arg) != 0)
		return;

	serd = tree_event2np_lut_lookup(SERDs, serd);
	if (serd != NULL)
		serd->u.stmt.flags |= STMT_REF;
}

struct node *
tree_decl(enum nodetype t, struct node *np, struct node *nvpairs,
    const char *file, int line)
{
	struct node *decl;
	struct node *ret;

	ASSERT(np != NULL);

	check_type_iterator(np);

	switch (t) {
	case T_EVENT:
		/* determine the type of event being declared */
		ASSERT(np->u.event.ename->t == T_NAME);
		switch (np->u.event.ename->u.name.t) {
		case N_FAULT:
			ret = dodecl(T_FAULT, file, line, np, nvpairs,
			    &Faults, Faultcount, 0);

			/* increment serd statement reference */
			decl = tree_event2np_lut_lookup(Faults, np);
			update_serd_refstmt(NULL, decl, NULL);
			break;

		case N_UPSET:
			ret = dodecl(T_UPSET, file, line, np, nvpairs,
			    &Upsets, Upsetcount, 0);

			/* increment serd statement reference */
			decl = tree_event2np_lut_lookup(Upsets, np);
			update_serd_refstmt(NULL, decl, NULL);
			break;

		case N_DEFECT:
			ret = dodecl(T_DEFECT, file, line, np, nvpairs,
			    &Defects, Defectcount, 0);

			/* increment serd statement reference */
			decl = tree_event2np_lut_lookup(Defects, np);
			update_serd_refstmt(NULL, decl, NULL);
			break;

		case N_ERROR:
			ret = dodecl(T_ERROR, file, line, np, nvpairs,
			    &Errors, Errorcount, 0);
			break;

		case N_EREPORT:
			ret = dodecl(T_EREPORT, file, line, np, nvpairs,
			    &Ereports, Ereportcount, 0);
			/*
			 * Keep a lut of just the enames, so that the DE
			 * can subscribe to a uniqified list of event
			 * classes.
			 */
			Ereportenames =
			    tree_name2np_lut_add(Ereportenames,
			    np->u.event.ename, np);

			/*
			 * Keep a lut of the enames (event classes) to
			 * silently discard if we can't find a matching
			 * configuration node when an ereport of of a given
			 * class is received.  Such events are declaired
			 * with 'discard_if_config_unknown=1'.
			 */
			if (tree_s2np_lut_lookup(ret->u.stmt.lutp,
			    L_discard_if_config_unknown)) {
				Ereportenames_discard = lut_add(
				    Ereportenames_discard,
				    (void *)np->u.event.ename->u.name.s,
				    (void *)np->u.event.ename->u.name.s, NULL);
			}
			break;

		default:
			outfl(O_ERR, file, line,
			    "tree_decl: internal error, event name type %s",
			    ptree_nametype2str(np->u.event.ename->u.name.t));
		}
		break;

	case T_ENGINE:
		/* determine the type of engine being declared */
		ASSERT(np->u.event.ename->t == T_NAME);
		switch (np->u.event.ename->u.name.t) {
		case N_SERD:
			ret = dodecl(T_SERD, file, line, np, nvpairs,
			    &SERDs, SERDcount, 0);
			lut_walk(Upsets, update_serd_refstmt, np);
			break;

		case N_STAT:
			ret = dodecl(T_STAT, file, line, np, nvpairs,
			    &STATs, STATcount, 0);
			break;

		default:
			outfl(O_ERR, file, line,
			    "tree_decl: internal error, engine name type %s",
			    ptree_nametype2str(np->u.event.ename->u.name.t));
		}
		break;
	case T_ASRU:
		ret = dodecl(T_ASRU, file, line, np, nvpairs,
		    &ASRUs, ASRUcount, 1);
		break;

	case T_FRU:
		ret = dodecl(T_FRU, file, line, np, nvpairs,
		    &FRUs, FRUcount, 1);
		break;

	case T_CONFIG:
		/*
		 * config statements are different from above: they
		 * are not merged at all (until the configuration cache
		 * code does its own style of merging.  and the properties
		 * are a free-for-all -- we don't check for allowed or
		 * required config properties.
		 */
		ret = newnode(T_CONFIG, file, line);
		ret->u.stmt.np = np;
		ret->u.stmt.nvpairs = nvpairs;
		ret->u.stmt.lutp = nvpair2lut(nvpairs, NULL, T_CONFIG);

		if (lut_lookup(Configs, np, (lut_cmp)tree_namecmp) == NULL)
			stats_counter_bump(Configcount);

		Configs = lut_add(Configs, (void *)np, (void *)ret, NULL);
		break;

	default:
		out(O_DIE, "tree_decl: internal error, type %s",
		    ptree_nodetype2str(t));
	}

	return (ret);
}

/* keep backpointers in arrows to the prop they belong to (used for scoping) */
static void
set_arrow_prop(struct node *prop, struct node *np)
{
	if (np == NULL)
		return;

	if (np->t == T_ARROW) {
		np->u.arrow.prop = prop;
		set_arrow_prop(prop, np->u.arrow.lhs);
		/*
		 * no need to recurse right or handle T_LIST since
		 * T_ARROWs always cascade left and are at the top
		 * of the parse tree.  (you can see this in the rule
		 * for "propbody" in escparse.y.)
		 */
	}
}

struct node *
tree_stmt(enum nodetype t, struct node *np, const char *file, int line)
{
	struct node *ret = newnode(t, file, line);
	struct node *pp;
	int inlist = 0;

	ret->u.stmt.np = np;

	switch (t) {
	case T_PROP:
		check_proplists(t, np);
		check_propnames(t, np, 0, 0);
		check_propscope(np);
		set_arrow_prop(ret, np);

		for (pp = Props; pp; pp = pp->u.stmt.next) {
			if (tree_treecmp(pp, ret, T_NAME,
			    (lut_cmp)tree_namecmp) == 0) {
				inlist = 1;
				break;
			}
		}
		if (inlist == 0)
			stats_counter_bump(Propcount);

		/* "Props" is a linked list of all prop statements */
		if (Lastprops)
			Lastprops->u.stmt.next = ret;
		else
			Props = ret;
		Lastprops = ret;
		break;

	case T_MASK:
		check_proplists(t, np);
		check_propnames(t, np, 0, 0);
		check_propscope(np);
		set_arrow_prop(ret, np);

		for (pp = Masks; pp; pp = pp->u.stmt.next) {
			if (tree_treecmp(pp, ret, T_NAME,
			    (lut_cmp)tree_namecmp) == 0) {
				inlist = 1;
				break;
			}
		}
		if (inlist == 0)
			stats_counter_bump(Maskcount);

		/* "Masks" is a linked list of all mask statements */
		if (Lastmasks)
			Lastmasks->u.stmt.next = ret;
		else
			Masks = ret;
		Lastmasks = ret;
		stats_counter_bump(Maskcount);
		break;

	default:
		outfl(O_DIE, np->file, np->line,
		    "tree_stmt: internal error (t %d)", t);
	}

	return (ret);
}

void
tree_report()
{
	/*
	 * The only declarations with required properties
	 * currently are faults and serds. Make sure the
	 * the declarations have the required properties.
	 */
	lut_walk(Faults, (lut_cb)check_required_props, (void *)T_FAULT);
	lut_walk(Upsets, (lut_cb)check_required_props, (void *)T_UPSET);
	lut_walk(Errors, (lut_cb)check_required_props, (void *)T_ERROR);
	lut_walk(Ereports, (lut_cb)check_required_props, (void *)T_EREPORT);
	lut_walk(SERDs, (lut_cb)check_required_props, (void *)T_SERD);
	lut_walk(STATs, (lut_cb)check_required_props, (void *)T_STAT);

	/*
	 * we do this now rather than while building the parse
	 * tree because it is inconvenient for the user if we
	 * require SERD engines to be declared before used in
	 * an upset "engine" property.
	 */
	lut_walk(Faults, (lut_cb)check_refcount, (void *)T_FAULT);
	lut_walk(Faults, (lut_cb)check_upset_engine, (void *)T_FAULT);
	lut_walk(Defects, (lut_cb)check_upset_engine, (void *)T_DEFECT);
	lut_walk(Upsets, (lut_cb)check_upset_engine, (void *)T_UPSET);
	lut_walk(Upsets, (lut_cb)check_refcount, (void *)T_UPSET);
	lut_walk(Errors, (lut_cb)check_refcount, (void *)T_ERROR);
	lut_walk(Ereports, (lut_cb)check_refcount, (void *)T_EREPORT);
	lut_walk(SERDs, (lut_cb)check_refcount, (void *)T_SERD);

	/* check for cycles */
	lut_walk(Errors, (lut_cb)check_cycle, (void *)0);
}

/* compare two T_NAMES by only looking at components, not iterators */
int
tree_namecmp(struct node *np1, struct node *np2)
{
	ASSERT(np1 != NULL);
	ASSERT(np2 != NULL);
	ASSERTinfo(np1->t == T_NAME, ptree_nodetype2str(np1->t));
	ASSERTinfo(np2->t == T_NAME, ptree_nodetype2str(np1->t));

	while (np1 && np2 && np1->u.name.s == np2->u.name.s) {
		np1 = np1->u.name.next;
		np2 = np2->u.name.next;
	}
	if (np1 == NULL)
		if (np2 == NULL)
			return (0);
		else
			return (-1);
	else if (np2 == NULL)
		return (1);
	else
		return (np2->u.name.s - np1->u.name.s);
}

int
tree_eventcmp(struct node *np1, struct node *np2)
{
	int ret;

	ASSERT(np1 != NULL);
	ASSERT(np2 != NULL);
	ASSERTinfo(np1->t == T_EVENT, ptree_nodetype2str(np1->t));
	ASSERTinfo(np2->t == T_EVENT, ptree_nodetype2str(np2->t));

	if ((ret = tree_namecmp(np1->u.event.ename,
	    np2->u.event.ename)) == 0) {
			if (np1->u.event.epname == NULL &&
			    np2->u.event.epname == NULL)
				return (0);
			else if (np1->u.event.epname == NULL)
				return (-1);
			else if (np2->u.event.epname == NULL)
				return (1);
			else
				return tree_namecmp(np1->u.event.epname,
				    np2->u.event.epname);
	} else
	return (ret);
}

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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * itree.c -- instance tree creation and manipulation
 *
 * this module provides the instance tree
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include "alloc.h"
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "ipath.h"
#include "iexpr.h"
#include "eval.h"
#include "config.h"

/*
 * struct info contains the state we keep when expanding a prop statement
 * as part of constructing the instance tree.  state kept in struct info
 * is the non-recursive stuff -- the stuff that doesn't need to be on
 * the stack.  the rest of the state that is passed between all the
 * mutually recursive functions, is required to be on the stack since
 * we need to backtrack and recurse as we do the instance tree construction.
 */
struct info {
	struct lut *lut;
	struct node *anp;	/* arrow np */
	struct lut *ex;		/* dictionary of explicit iterators */
	struct config *croot;
} Ninfo;

/*
 * struct wildcardinfo is used to track wildcarded portions of paths.
 *
 * for example, if the epname of an event is "c/d" and the path "a/b/c/d"
 * exists, the wildcard path ewname is filled in with the path "a/b".  when
 * matching is done, epname is temporarily replaced with the concatenation
 * of ewname and epname.  cpstart is set to the (struct config *)
 * corresponding to component "c".
 *
 * a linked list of these structs is used to track the expansion of each
 * event node as it is processed in vmatch() --> vmatch_event() calls.
 */
struct wildcardinfo {
	struct node *nptop;		/* event node fed to vmatch */
	struct node *oldepname;		/* epname without the wildcard part */
	enum status {
		WC_UNDEFINED,		/* struct is not yet initialized */
		WC_UNDERCONSTRUCTION,	/* wildcard path not yet done */
		WC_COMPLETE		/* wildcard path done and is in use */
	} s;
	struct wildcardpath {
		struct node *ewname;	/* wildcard path */
		struct config *cpstart;	/* starting cp node for oldepname */
		int refcount;		/* number of event nodes using this */
	} *p;
	struct wildcardpath *matchwc;	/* ptr to wc path to be matched */
	struct wildcardinfo *next;
};

static void vmatch(struct info *infop, struct node *np,
    struct node *lnp, struct node *anp, struct wildcardinfo **wcproot);
static void hmatch(struct info *infop, struct node *np, struct node *nextnp);
static void itree_pbubble(int flags, struct bubble *bp);
static void itree_destructor(void *left, void *right, void *arg);
static int itree_set_arrow_traits(struct arrow *ap, struct node *fromev,
    struct node *toev, struct lut *ex);
static void itree_free_arrowlists(struct bubble *bubp, int arrows_too);
static void arrow_add_within(struct arrow *ap, struct node *xpr);
static struct arrow *itree_add_arrow(struct bubble *frombubblep,
    struct bubble *tobubblep, struct node *apnode, struct node *fromevent,
    struct node *toevent, struct lut *ex);
static struct constraintlist *itree_add_constraint(struct arrow *arrowp,
    struct node *c);
static struct bubble *itree_add_bubble(struct event *eventp,
    enum bubbletype btype, int nork, int gen);
static void itree_free_bubble(struct bubble *freeme);
static void itree_free_constraints(struct arrow *ap);

/*
 * the following struct contains the state we build up during
 * vertical and horizontal expansion so that generate()
 * has everything it needs to construct the appropriate arrows.
 * after setting up the state by calling:
 *	generate_arrownp()
 *	generate_nork()
 *	generate_new()
 *	generate_from()
 *	generate_to()
 * the actual arrow generation is done by calling:
 *	generate()
 */
static struct {
	int generation;		/* generation number of arrow set */
	struct node *arrownp;	/* top-level parse tree for arrow */
	int n;			/* n value associated with arrow */
	int k;			/* k value associated with arrow */
	struct node *fromnp;	/* left-hand-side event in parse tree */
	struct node *tonp;	/* right-hand-side event in parse tree */
	struct event *frome;	/* left-hand-side event in instance tree */
	struct event *toe;	/* right-hand-side event in instance tree */
	struct bubble *frombp;	/* bubble arrow comes from */
	struct bubble *tobp;	/* bubble arrow goes to */
} G;

static void
generate_arrownp(struct node *arrownp)
{
	G.arrownp = arrownp;
}

static void
generate_nork(int n, int k)
{
	G.n = n;
	G.k = k;
}

static void
generate_new(void)
{
	G.generation++;
}

static void
generate_from(struct node *fromeventnp, struct event *fromevent)
{
	G.fromnp = fromeventnp;
	G.frome = fromevent;

	out(O_ALTFP|O_VERB3|O_NONL, "from bubble on ");
	ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, G.fromnp);
	out(O_ALTFP|O_VERB3, NULL);

	G.frombp = itree_add_bubble(G.frome, B_FROM, G.n, 0);
}

static void
generate_to(struct node *toeventnp, struct event *toevent)
{
	G.tonp = toeventnp;
	G.toe = toevent;

	out(O_ALTFP|O_VERB3|O_NONL, "to bubble (gen %d) on ", G.generation);
	ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, G.tonp);
	out(O_ALTFP|O_VERB3, NULL);

	G.tobp = itree_add_bubble(G.toe, B_TO, G.k, G.generation);
}

static void
generate(struct lut *ex)
{
	ASSERT(G.arrownp != NULL);
	ASSERT(G.fromnp != NULL);
	ASSERT(G.frome != NULL);
	ASSERT(G.frombp != NULL);
	ASSERT(G.tonp != NULL);
	ASSERT(G.toe != NULL);
	ASSERT(G.tobp != NULL);

	out(O_ALTFP|O_VERB3|O_NONL, "        Arrow \"");
	ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, G.fromnp);
	out(O_ALTFP|O_VERB3|O_NONL, "\" -> \"");
	ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, G.tonp);

	if (itree_add_arrow(G.frombp, G.tobp, G.arrownp,
	    G.fromnp, G.tonp, ex) == NULL) {
		out(O_ALTFP|O_VERB3, "\" (prevented by constraints)");
	} else {
		out(O_ALTFP|O_VERB3, "\"");
	}
}

enum childnode_action {
	CN_NONE,
	CN_INSTANTIZE,
	CN_DUP
};

static struct node *
tname_dup(struct node *namep, enum childnode_action act)
{
	struct node *retp = NULL;
	const char *file;
	int line;

	if (namep == NULL)
		return (NULL);

	file = namep->file;
	line = namep->line;

	for (; namep != NULL; namep = namep->u.name.next) {
		struct node *newnp = newnode(T_NAME, file, line);

		newnp->u.name.t = namep->u.name.t;
		newnp->u.name.s = namep->u.name.s;
		newnp->u.name.last = newnp;
		newnp->u.name.it = namep->u.name.it;
		newnp->u.name.cp = namep->u.name.cp;

		if (act == CN_DUP) {
			struct node *npc;

			npc = namep->u.name.child;
			if (npc != NULL) {
				switch (npc->t) {
				case T_NUM:
					newnp->u.name.child =
						newnode(T_NUM, file, line);
					newnp->u.name.child->u.ull =
						npc->u.ull;
					break;
				case T_NAME:
					newnp->u.name.child =
						tree_name(npc->u.name.s,
							npc->u.name.it,
							file, line);
					break;
				default:
					out(O_DIE, "tname_dup: "
					    "invalid child type %s",
					    ptree_nodetype2str(npc->t));
				}
			}
		} else if (act == CN_INSTANTIZE) {
			newnp->u.name.child = newnode(T_NUM, file, line);

			if (namep->u.name.child == NULL ||
			    namep->u.name.child->t != T_NUM) {
				int inum;

				ASSERT(newnp->u.name.cp != NULL);
				config_getcompname(newnp->u.name.cp,
						    NULL, &inum);
				newnp->u.name.child->u.ull =
					(unsigned long long)inum;
			} else {
				newnp->u.name.child->u.ull =
					namep->u.name.child->u.ull;
			}
		}

		if (retp == NULL) {
			retp = newnp;
		} else {
			retp->u.name.last->u.name.next = newnp;
			retp->u.name.last = newnp;
		}
	}

	return (retp);
}

struct prop_wlk_data {
	struct lut *props;
	struct node *epname;
};

static struct lut *props2instance(struct node *, struct node *);

/*
 * let oldepname be a subset of epname.  return the subsection of epname
 * that ends with oldepname.  make each component in the path explicitly
 * instanced (i.e., with a T_NUM child).
 */
static struct node *
tname_dup_to_epname(struct node *oldepname, struct node *epname)
{
	struct node *npref, *npend, *np1, *np2;
	struct node *ret = NULL;
	int foundmatch = 0;

	if (epname == NULL)
		return (NULL);

	/*
	 * search for the longest path in epname which contains
	 * oldnode->u.event.epname.  set npend to point to just past the
	 * end of this path.
	 */
	npend = NULL;
	for (npref = epname; npref; npref = npref->u.name.next) {
		if (npref->u.name.s == oldepname->u.name.s) {
			for (np1 = npref, np2 = oldepname;
			    np1 != NULL && np2 != NULL;
			    np1 = np1->u.name.next, np2 = np2->u.name.next) {
				if (np1->u.name.s != np2->u.name.s)
					break;
			}
			if (np2 == NULL) {
				foundmatch = 1;
				npend = np1;
				if (np1 == NULL) {
					/* oldepname matched npref up to end */
					break;
				}
			}
		}
	}

	if (foundmatch == 0) {
		/*
		 * if oldepname could not be found in epname, return a
		 * duplicate of the former.  do not try to instantize
		 * oldepname since it might not be a path.
		 */
		return (tname_dup(oldepname, CN_DUP));
	}

	/*
	 * dup (epname -- npend).  all children should be T_NUMs.
	 */
	for (npref = epname;
	    ! (npref == NULL || npref == npend);
	    npref = npref->u.name.next) {
		struct node *newnp = newnode(T_NAME, oldepname->file,
					    oldepname->line);

		newnp->u.name.t = npref->u.name.t;
		newnp->u.name.s = npref->u.name.s;
		newnp->u.name.last = newnp;
		newnp->u.name.it = npref->u.name.it;
		newnp->u.name.cp = npref->u.name.cp;

		newnp->u.name.child = newnode(T_NUM, oldepname->file,
					    oldepname->line);

		if (npref->u.name.child == NULL ||
		    npref->u.name.child->t != T_NUM) {
			int childnum;

			ASSERT(npref->u.name.cp != NULL);
			config_getcompname(npref->u.name.cp, NULL, &childnum);
			newnp->u.name.child->u.ull = childnum;
		} else {
			newnp->u.name.child->u.ull =
				npref->u.name.child->u.ull;
		}

		if (ret == NULL) {
			ret = newnp;
		} else {
			ret->u.name.last->u.name.next = newnp;
			ret->u.name.last = newnp;
		}
	}

	return (ret);
}

/*
 * restriction: oldnode->u.event.epname has to be equivalent to or a subset
 * of epname
 */
static struct node *
tevent_dup_to_epname(struct node *oldnode, struct node *epname)
{
	struct node *ret;

	ret = newnode(T_EVENT, oldnode->file, oldnode->line);
	ret->u.event.ename = tname_dup(oldnode->u.event.ename, CN_NONE);
	ret->u.event.epname = tname_dup_to_epname(oldnode->u.event.epname,
						    epname);
	return (ret);
}

static void
nv_instantiate(void *name, void *val, void *arg)
{
	struct prop_wlk_data *pd = (struct prop_wlk_data *)arg;
	struct node *orhs = (struct node *)val;
	struct node *nrhs;

	/* handle engines by instantizing the entire engine */
	if (name == L_engine) {
		ASSERT(orhs->t == T_EVENT);
		ASSERT(orhs->u.event.ename->u.name.t == N_SERD);

		/* there are only SERD engines for now */

		nrhs = newnode(T_SERD, orhs->file, orhs->line);
		nrhs->u.stmt.np = tevent_dup_to_epname(orhs, pd->epname);
		nrhs->u.stmt.lutp = props2instance(orhs, pd->epname);
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		return;
	}

	switch (orhs->t) {
	case T_NUM:
		nrhs = newnode(T_NUM, orhs->file, orhs->line);
		nrhs->u.ull = orhs->u.ull;
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		break;
	case T_TIMEVAL:
		nrhs = newnode(T_TIMEVAL, orhs->file, orhs->line);
		nrhs->u.ull = orhs->u.ull;
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		break;
	case T_NAME:
		nrhs = tname_dup_to_epname(orhs, pd->epname);
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		break;
	case T_EVENT:
		nrhs = tevent_dup_to_epname(orhs, pd->epname);
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		break;
	case T_GLOBID:
		nrhs = newnode(T_GLOBID, orhs->file, orhs->line);
		nrhs->u.globid.s = orhs->u.globid.s;
		pd->props = lut_add(pd->props, name, nrhs, NULL);
		break;
	case T_FUNC:
		/* for T_FUNC, we don't duplicate it, just point to node */
		pd->props = lut_add(pd->props, name, orhs, NULL);
		break;
	default:
		out(O_DIE, "unexpected nvpair value type %s",
		    ptree_nodetype2str(((struct node *)val)->t));
	}
}

static struct lut *
props2instance(struct node *eventnp, struct node *epname)
{
	struct prop_wlk_data pd;

	pd.props = NULL;
	pd.epname = epname;

	ASSERT(eventnp->u.event.declp != NULL);
	lut_walk(eventnp->u.event.declp->u.stmt.lutp, nv_instantiate, &pd);
	return (pd.props);
}

/*ARGSUSED*/
static void
instances_destructor(void *left, void *right, void *arg)
{
	struct node *dn = (struct node *)right;

	if (dn->t == T_SERD) {
		/* we allocated the lut during itree_create(), so free it */
		lut_free(dn->u.stmt.lutp, instances_destructor, NULL);
		dn->u.stmt.lutp = NULL;
	}
	if (dn->t != T_FUNC)	/* T_FUNC pointed to original node */
		tree_free(dn);
}

/*ARGSUSED*/
static void
payloadprops_destructor(void *left, void *right, void *arg)
{
	FREE(right);
}

/*
 * event_cmp -- used via lut_lookup/lut_add on instance tree lut
 */
static int
event_cmp(struct event *ep1, struct event *ep2)
{
	int diff;

	if ((diff = ep2->enode->u.event.ename->u.name.s -
	    ep1->enode->u.event.ename->u.name.s) != 0)
		return (diff);
	if ((diff = (char *)ep2->ipp - (char *)ep1->ipp) != 0)
		return (diff);
	return (0);

}

struct event *
itree_lookup(struct lut *itp, const char *ename, const struct ipath *ipp)
{
	struct event searchevent;	/* just used for searching */
	struct node searcheventnode;
	struct node searchenamenode;

	searchevent.enode = &searcheventnode;
	searcheventnode.t = T_EVENT;
	searcheventnode.u.event.ename = &searchenamenode;
	searchenamenode.t = T_NAME;
	searchenamenode.u.name.s = ename;
	searchevent.ipp = ipp;
	return (lut_lookup(itp, (void *)&searchevent, (lut_cmp)event_cmp));
}

static struct event *
find_or_add_event(struct info *infop, struct node *np)
{
	struct event *ret;
	struct event searchevent;	/* just used for searching */

	ASSERTeq(np->t, T_EVENT, ptree_nodetype2str);

	searchevent.enode = np;
	searchevent.ipp = ipath(np->u.event.epname);
	if ((ret = lut_lookup(infop->lut, (void *)&searchevent,
	    (lut_cmp)event_cmp)) != NULL)
		return (ret);

	/* wasn't already in tree, allocate it */
	ret = MALLOC(sizeof (*ret));
	bzero(ret, sizeof (*ret));

	ret->t = np->u.event.ename->u.name.t;
	ret->enode = np;
	ret->ipp = searchevent.ipp;
	ret->props = props2instance(np, np->u.event.epname);

	infop->lut = lut_add(infop->lut, (void *)ret, (void *)ret,
	    (lut_cmp)event_cmp);

	return (ret);
}

/*
 * hmatch_event -- perform any appropriate horizontal expansion on an event
 *
 * this routine is used to perform horizontal expansion on both the
 * left-hand-side events in a prop, and the right-hand-side events.
 * when called to handle a left-side event, nextnp point to the right
 * side of the prop that should be passed to hmatch() for each match
 * found by horizontal expansion.   when no horizontal expansion exists,
 * we will still "match" one event for every event found in the list on
 * the left-hand-side of the prop because vmatch() already found that
 * there's at least one match during vertical expansion.
 */
static void
hmatch_event(struct info *infop, struct node *eventnp, struct node *epname,
    struct config *ncp, struct node *nextnp, int rematch)
{
	if (epname == NULL) {
		/*
		 * end of pathname recursion, either we just located
		 * a left-hand-side event and we're ready to move on
		 * to the expanding the right-hand-side events, or
		 * we're further down the recursion and we just located
		 * a right-hand-side event.  the passed-in parameter
		 * "nextnp" tells us whether we're working on the left
		 * side and need to move on to nextnp, or if nextnp is
		 * NULL, we're working on the right side.
		 */
		if (nextnp) {
			/*
			 * finished a left side expansion, move on to right.
			 * tell generate() what event we just matched so
			 * it can be used at the source of any arrows
			 * we generate as we match events on the right side.
			 */
			generate_from(eventnp,
			    find_or_add_event(infop, eventnp));
			hmatch(infop, nextnp, NULL);
		} else {
			/*
			 * finished a right side expansion.  tell generate
			 * the information about the destination and let
			 * it construct the arrows as appropriate.
			 */
			generate_to(eventnp,
			    find_or_add_event(infop, eventnp));
			generate(infop->ex);
		}

		return;
	}

	ASSERTeq(epname->t, T_NAME, ptree_nodetype2str);

	/*
	 * we only get here when eventnp already has a completely
	 * instanced epname in it already.  so we first recurse
	 * down to the end of the name and as the recursion pops
	 * up, we look for opportunities to advance horizontal
	 * expansions on to the next match.  when we do advance
	 * horizontal expansions, we potentially render all cp
	 * pointers on all components to the right as invalid,
	 * so we pass in an "ncp" config handle so matching against
	 * the config can happen.
	 */
	if (rematch) {
		struct config *ocp = epname->u.name.cp;
		char *ncp_s;
		int ncp_num, num;

		for (; ncp; ncp = config_next(ncp)) {
			config_getcompname(ncp, &ncp_s, &ncp_num);

			if (ncp_s == epname->u.name.s) {
				/* found a matching component name */
				config_getcompname(epname->u.name.cp,
				    NULL, &num);

				if (epname->u.name.it != IT_HORIZONTAL &&
				    ncp_num != num)
					continue;

				epname->u.name.cp = ncp;
				hmatch_event(infop, eventnp,
				    epname->u.name.next, config_child(ncp),
				    nextnp, 1);
			}
		}

		epname->u.name.cp = ocp;

		return;		/* no more config to match against */

	} else {
		hmatch_event(infop, eventnp, epname->u.name.next, ncp,
		    nextnp, 0);
	}

	if (epname->u.name.it == IT_HORIZONTAL) {
		struct config *cp;
		struct config *ocp = epname->u.name.cp;
		char *cp_s;
		int cp_num;
		int ocp_num;
		struct iterinfo *iterinfop = NULL;
		const char *iters;

		config_getcompname(ocp, NULL, &ocp_num);

		for (cp = config_next(ocp); cp; cp = config_next(cp)) {
			config_getcompname(cp, &cp_s, &cp_num);

			if (cp_s == epname->u.name.s) {
				ASSERT(epname->u.name.child != NULL);

				iters = epname->u.name.child->u.name.s;
				if ((iterinfop = lut_lookup(infop->ex,
				    (void *)iters, NULL)) == NULL) {
					out(O_DIE,
					    "hmatch_event: internal error: "
					    "iterator \"%s\" undefined", iters);
				} else {
					/* advance dict entry to next match */
					iterinfop->num = cp_num;
				}
				epname->u.name.cp = cp;
				hmatch_event(infop, eventnp,
				    epname->u.name.next, config_child(cp),
				    nextnp, 1);
			}
		}

		if (iterinfop != NULL) {
			/* restore dict entry */
			iterinfop->num = ocp_num;
		}
		epname->u.name.cp = ocp;
	}
}

/*
 * hmatch -- check for horizontal expansion matches
 *
 * np points to the things we're matching (like a T_LIST or a T_EVENT)
 * and if we're working on a left-side of a prop, nextnp points to
 * the other side of the prop that we'll tackle next when this recursion
 * bottoms out.  when all the events in the entire prop arrow have been
 * horizontally expanded, generate() will be called to generate the
 * actualy arrow.
 */
static void
hmatch(struct info *infop, struct node *np, struct node *nextnp)
{
	if (np == NULL)
		return;		/* all done */

	/*
	 * for each item in the list of events (which could just
	 * be a single event, or it could get larger in the loop
	 * below due to horizontal expansion), call hmatch on
	 * the right side and create arrows to each element.
	 */

	switch (np->t) {
	case T_LIST:
		/* loop through the list */
		if (np->u.expr.left)
			hmatch(infop, np->u.expr.left, nextnp);
		if (np->u.expr.right)
			hmatch(infop, np->u.expr.right, nextnp);
		break;

	case T_EVENT:
		hmatch_event(infop, np, np->u.event.epname,
		    NULL, nextnp, 0);
		break;

	default:
		outfl(O_DIE, np->file, np->line,
		    "hmatch: unexpected type: %s",
		    ptree_nodetype2str(np->t));
	}
}

static int
itree_np2nork(struct node *norknp)
{
	if (norknp == NULL)
		return (1);
	else if (norknp->t == T_NAME && norknp->u.name.s == L_A)
		return (-1);	/* our internal version of "all" */
	else if (norknp->t == T_NUM)
		return ((int)norknp->u.ull);
	else
		out(O_DIE, norknp->file, norknp->line,
		    "itree_np2nork: internal error type %s",
		    ptree_nodetype2str(norknp->t));
	/*NOTREACHED*/
	return (1);
}

static struct iterinfo *
newiterinfo(int num, struct node *np)
{
	struct iterinfo *ret = MALLOC(sizeof (*ret));

	ret->num = num;
	ret->np = np;

	return (ret);
}

/*ARGSUSED*/
static void
iterinfo_destructor(void *left, void *right, void *arg)
{
	struct iterinfo *iterinfop = (struct iterinfo *)right;

	bzero(iterinfop, sizeof (*iterinfop));
	FREE(iterinfop);
}

/*
 * return 1 if wildcard path for wcp matches another wildcard path;
 * return 0 if otherwise.
 */
static int
wc_paths_match(struct wildcardinfo *wcp)
{
	struct node *np1, *np2;

	ASSERT(wcp->matchwc != NULL);

	for (np1 = wcp->p->ewname, np2 = wcp->matchwc->ewname;
	    np1 != NULL && np2 != NULL;
	    np1 = np1->u.name.next, np2 = np2->u.name.next) {
		/*
		 * names must match
		 */
		if (np1->u.name.s != np2->u.name.s)
			return (0);

		/*
		 * children must exist and have the same numerical value
		 */
		if (np1->u.name.child == NULL || np2->u.name.child == NULL)
			return (0);

		if (np1->u.name.child->t != T_NUM ||
		    np2->u.name.child->t != T_NUM)
			return (0);

		if (np1->u.name.child->u.ull != np2->u.name.child->u.ull)
			return (0);
	}

	/*
	 * return true only if we have matches for all entries of n1 and
	 * n2.  note that NULL wildcard paths (i.e., both wcp->p->ewname
	 * and wcp->matchwc->ewname are NULL) will be considered as
	 * matching paths.
	 */
	if (np1 == NULL && np2 == NULL)
		return (1);

	return (0);
}

/*
 * update epname to include the wildcarded portion
 */
static void
create_wildcardedpath(struct wildcardinfo **wcproot)
{
	struct wildcardinfo *wcp;
	struct node *nptop;

	wcp = *wcproot;

	if (wcp->s == WC_UNDERCONSTRUCTION) {
		ASSERT(wcp->p->refcount == 1);
		wcp->s = WC_COMPLETE;
	}

	/* path has no wildcard */
	if (wcp->p->ewname == NULL)
		return;

	/*
	 * get to this point if a wildcard portion of the path exists.
	 *
	 * first set oldepname to the start of the existing epname for use
	 * in future comparisons, then update epname to include the
	 * wildcard portion.
	 */
	nptop = wcp->nptop;

	ASSERT(wcp->oldepname == nptop->u.event.epname);

	nptop->u.event.epname =	tname_dup(wcp->p->ewname, CN_DUP);
	nptop->u.event.epname = tree_name_append(nptop->u.event.epname,
					tname_dup(wcp->oldepname, CN_DUP));
}

/*
 * restore epname to its former (nonwildcarded) state
 */
static void
undo_wildcardedpath(struct wildcardinfo **wcproot)
{
	struct wildcardinfo *wcp;

	wcp = *wcproot;

	if (wcp->s == WC_COMPLETE) {
		ASSERT(wcp->p->refcount == 1);
		wcp->s = WC_UNDERCONSTRUCTION;
	}

	/* path has no wildcard */
	if (wcp->p->ewname == NULL)
		return;

	ASSERT(wcp->oldepname != NULL);

	tree_free(wcp->nptop->u.event.epname);
	wcp->nptop->u.event.epname = wcp->oldepname;
}

enum wildcard_action {
	WA_NONE,	/* do not do any wildcards */
	WA_SINGLE,	/* do wildcard only for current cp node */
	WA_ALL		/* do wildcards for all cp nodes */
};

static void
vmatch_event(struct info *infop, struct config *cp, struct node *np,
	    struct node *lnp, struct node *anp,
	    struct wildcardinfo **wcproot, enum wildcard_action dowildcard)
{
	struct wildcardinfo *wcp;
	char *cp_s;
	int cp_num;

	wcp = *wcproot;

	if ((np == NULL && wcp->oldepname != NULL) ||
	    (cp == NULL && wcp->oldepname == NULL)) {
		/*
		 * get to this point if the pathname matched the config
		 * (but not necessarily a match at the end).  first check
		 * for any matching wildcard paths.
		 */
		if (wcp->matchwc != NULL && wc_paths_match(wcp) == 0)
			return;

		create_wildcardedpath(wcproot);
		vmatch(infop, np, lnp, anp, wcproot);
		undo_wildcardedpath(wcproot);

		return;
	}

	if (cp == NULL)
		return;	/* no more config to match against */

	for (; cp; cp = config_next(cp)) {
		config_getcompname(cp, &cp_s, &cp_num);

		if (cp_s == np->u.name.s &&
		    ! (wcp->s == WC_UNDERCONSTRUCTION &&
		    dowildcard == WA_SINGLE)) {
			/* found a matching component name */
			if (np->u.name.child &&
			    np->u.name.child->t == T_NUM) {
				/*
				 * an explicit instance number was given
				 * in the source.  so only consider this
				 * a configuration match if the number
				 * also matches.
				 */
				if (cp_num != np->u.name.child->u.ull)
					continue;

				np->u.name.cp = cp;
			} else {
				struct iterinfo *iterinfop;
				const char *iters;

				/*
				 * vertical iterator.  look it up in
				 * the appropriate lut and if we get
				 * back a value it is either one that we
				 * set earlier, in which case we record
				 * the new value for this iteration and
				 * keep matching, or it is one that was
				 * set by an earlier reference to the
				 * iterator, in which case we only consider
				 * this a configuration match if the number
				 * matches cp_num.
				 */

				ASSERT(np->u.name.child != NULL);
				ASSERT(np->u.name.child->t == T_NAME);
				iters = np->u.name.child->u.name.s;

				if ((iterinfop = lut_lookup(infop->ex,
				    (void *)iters, NULL)) == NULL) {
					/* we're the first use, record our np */
					infop->ex = lut_add(infop->ex,
					    (void *)iters,
					    newiterinfo(cp_num, np), NULL);
				} else if (np == iterinfop->np) {
					/*
					 * we're the first use, back again
					 * for another iteration.  so update
					 * the num bound to this iterator in
					 * the lut.
					 */
					iterinfop->num = cp_num;
				} else if (cp_num != iterinfop->num) {
					/*
					 * an earlier reference to this
					 * iterator bound it to a different
					 * instance number, so there's no
					 * match here after all.
					 *
					 * however, it's possible that this
					 * component should really be part of
					 * the wildcard.  we explore this by
					 * forcing this component into the
					 * wildcarded section.
					 *
					 * for an more details of what's
					 * going to happen now, see
					 * comments block below entitled
					 * "forcing components into
					 * wildcard path".
					 */
					if (dowildcard == WA_ALL &&
					    wcp->s == WC_UNDERCONSTRUCTION) {
						vmatch_event(infop, cp, np,
							    lnp, anp, wcproot,
							    WA_SINGLE);
					}
					continue;
				}
				np->u.name.cp = cp;
			}

			/*
			 * if wildcarding was done in a call earlier in the
			 * stack, record the current cp as the first
			 * matching and nonwildcarded cp.
			 */
			if (dowildcard == WA_ALL &&
			    wcp->s == WC_UNDERCONSTRUCTION)
				wcp->p->cpstart = cp;

			/*
			 * if this was an IT_HORIZONTAL name,
			 * hmatch() will use the cp to expand
			 * all matches horizontally into a list.
			 * we know the list will contain at least
			 * one element (the one we just matched),
			 * so we just store cp and let hmatch_event()
			 * do the rest.
			 *
			 * recurse on to next component.  note that
			 * wildcarding is now turned off.
			 */
			vmatch_event(infop, config_child(cp), np->u.name.next,
				    lnp, anp, wcproot, WA_NONE);

			/*
			 * forcing components into wildcard path:
			 *
			 * if this component is the first match, force it
			 * to be part of the wildcarded path and see if we
			 * can get additional matches.  repeat call to
			 * vmatch_event() with the same np, making sure
			 * wildcarding is forced for this component alone
			 * and not its peers by specifying vmatch_event(
			 * ..., WA_SINGLE).  in other words, in the call to
			 * vmatch_event() below, there should be no loop
			 * over cp's peers since that is being done in the
			 * current loop [i.e., the loop we're in now].
			 *
			 * here's an example.  suppose we have the
			 * definition
			 *	event foo@x/y
			 * and configuration
			 *	a0/x0/y0/a1/x1/y1
			 *
			 * the code up to this point will treat "a0" as the
			 * wildcarded part of the path and "x0/y0" as the
			 * nonwildcarded part, resulting in the instanced
			 * event
			 *	foo@a0/x0/y0
			 *
			 * in order to discover the next match (.../x1/y1)
			 * in the configuration we have to force "x0" into
			 * the wildcarded part of the path.  the following
			 * call to vmatch_event(..., WA_SINGLE) does this.
			 * by doing so, we discover the wildcarded part
			 * "a0/x0/y0/a1" and the nonwildcarded part "x1/y1"
			 *
			 * the following call to vmatch_event() is also
			 * needed to properly handle the configuration
			 *	b0/x0/b1/x1/y1
			 *
			 * the recursions into vmatch_event() will start
			 * off uncovering "b0" as the wildcarded part and
			 * "x0" as the start of the nonwildcarded path.
			 * however, the next recursion will not result in a
			 * match since there is no "y" following "x0".  the
			 * subsequent match of (wildcard = "b0/x0/b1" and
			 * nonwildcard = "x1/y1") will be discovered only
			 * if "x0" is forced to be a part of the wildcarded
			 * path.
			 */
			if (dowildcard == WA_ALL &&
			    wcp->s == WC_UNDERCONSTRUCTION) {
				vmatch_event(infop, cp, np, lnp, anp,
					    wcproot, WA_SINGLE);
			}

			if (np->u.name.it == IT_HORIZONTAL) {
				/*
				 * hmatch() finished iterating through
				 * the configuration as described above, so
				 * don't continue iterating here.
				 */
				return;
			}

		} else if ((dowildcard == WA_SINGLE || dowildcard == WA_ALL) &&
			    wcp->s == WC_UNDERCONSTRUCTION) {
			/*
			 * no matching cp, and we are constructing our own
			 * wildcard path.  (in other words, we are not
			 * referencing a wildcard path created for an
			 * earlier event.)
			 *
			 * add wildcard entry, then recurse on to config
			 * child
			 */
			struct node *cpnode, *prevlast;

			cpnode = tree_name(cp_s, IT_NONE, NULL, 0);
			cpnode->u.name.child = newnode(T_NUM, NULL, 0);
			cpnode->u.name.child->u.ull = cp_num;
			cpnode->u.name.cp = cp;

			if (wcp->p->ewname == NULL) {
				prevlast = NULL;
				wcp->p->ewname = cpnode;
			} else {
				prevlast = wcp->p->ewname->u.name.last;
				wcp->p->ewname =
					tree_name_append(wcp->p->ewname,
							    cpnode);
			}

			vmatch_event(infop, config_child(cp), np, lnp, anp,
				    wcproot, WA_ALL);

			/*
			 * back out last addition to ewname and continue
			 * with loop
			 */
			tree_free(cpnode);
			if (prevlast == NULL) {
				wcp->p->ewname = NULL;
			} else {
				prevlast->u.name.next = NULL;
				wcp->p->ewname->u.name.last = prevlast;
			}

			/*
			 * return if wildcarding is done only for this cp
			 */
			if (dowildcard == WA_SINGLE)
				return;
		}
	}
}

/*
 * for the event node np, which will be subjected to pathname
 * expansion/matching, create a (struct wildcardinfo) to hold wildcard
 * information.  this struct will be inserted into the first location in
 * the list that starts with *wcproot.
 *
 * cp is the starting node of the configuration; cpstart, which is output,
 * is the starting node of the nonwildcarded portion of the path.
 */
static void
add_wildcardentry(struct wildcardinfo **wcproot, struct config *cp,
		struct node *np)
{
	struct wildcardinfo *wcpnew, *wcp;
	struct node *np1, *np2;

	/*
	 * create entry for np
	 */
	wcpnew = MALLOC(sizeof (struct wildcardinfo));
	bzero(wcpnew, sizeof (struct wildcardinfo));
	wcpnew->nptop = np;
	wcpnew->oldepname = np->u.event.epname;
	wcpnew->s = WC_UNDERCONSTRUCTION;

	wcpnew->p = MALLOC(sizeof (struct wildcardpath));
	bzero(wcpnew->p, sizeof (struct wildcardpath));
	wcpnew->p->cpstart = cp;
	wcpnew->p->refcount = 1;

	/*
	 * search all completed entries for an epname whose first entry
	 * matches.  note that NULL epnames are considered valid and can be
	 * matched.
	 */
	np2 = wcpnew->oldepname;
	for (wcp = *wcproot; wcp; wcp = wcp->next) {
		ASSERT(wcp->s == WC_COMPLETE);

		np1 = wcp->oldepname;
		if ((np1 && np2 && np1->u.name.s == np2->u.name.s) ||
		    (np1 == NULL && np2 == NULL)) {
			/*
			 * if we find a match in a completed entry, set
			 * matchwc to indicate that we would like to match
			 * it.  it is necessary to do this since wildcards
			 * for each event are constructed independently.
			 */
			wcpnew->matchwc = wcp->p;

			wcp->p->refcount++;
			break;
		}
	}

	wcpnew->next = *wcproot;
	*wcproot = wcpnew;
}

static void
delete_wildcardentry(struct wildcardinfo **wcproot)
{
	struct wildcardinfo *wcp;

	wcp = *wcproot;
	*wcproot = wcp->next;

	switch (wcp->s) {
	case WC_UNDERCONSTRUCTION:
	case WC_COMPLETE:
		if (wcp->matchwc != NULL)
			wcp->matchwc->refcount--;

		ASSERT(wcp->p->refcount == 1);
		tree_free(wcp->p->ewname);
		FREE(wcp->p);
		break;

	default:
		out(O_DIE, "deletewc: invalid status");
		break;
	}

	FREE(wcp);
}

/*
 * vmatch -- find the next vertical expansion match in the config database
 *
 * this routine is called with three node pointers:
 *	 np -- the parse we're matching
 *	lnp -- the rest of the list we're currently working on
 *	anp -- the rest of the arrow we're currently working on
 *
 * the expansion matching happens via three types of recursion:
 *
 *	- when given an arrow, handle the left-side and then recursively
 *	  handle the right side (which might be another cascaded arrow).
 *
 *	- when handling one side of an arrow, recurse through the T_LIST
 *	  to get to each event (or just move on to the event if there
 *	  is a single event instead of a list)  since the arrow parse
 *	  trees recurse left, we actually start with the right-most
 *	  event list in the prop statement and work our way towards
 *	  the left-most event list.
 *
 *	- when handling an event, recurse down each component of the
 *	  pathname, matching in the config database and recording the
 *	  matches in the explicit iterator dictionary as we go.
 *
 * when the bottom of this matching recursion is met, meaning we have
 * set the "cp" pointers on all the names in the entire statement,
 * we call hmatch() which does it's own recursion to handle horizontal
 * expandsion and then call generate() to generate nodes, bubbles, and
 * arrows in the instance tree.  generate() looks at the cp pointers to
 * see what instance numbers were matched in the configuration database.
 *
 * when horizontal expansion appears, vmatch() finds only the first match
 * and hmatch() then takes the horizontal expansion through all the other
 * matches when generating the arrows in the instance tree.
 *
 * the "infop" passed down through the recursion contains a dictionary
 * of the explicit iterators (all the implicit iterators have been converted
 * to explicit iterators when the parse tree was created by tree.c), which
 * allows things like this to work correctly:
 *
 *	prop error.a@x[n]/y/z -> error.b@x/y[n]/z -> error.c@x/y/z[n];
 *
 * during the top level call, the explicit iterator "n" will match an
 * instance number in the config database, and the result will be recorded
 * in the explicit iterator dictionary and passed down via "infop".  so
 * when the recursive call tries to match y[n] in the config database, it
 * will only match the same instance number as x[n] did since the dictionary
 * is consulted to see if "n" took on a value already.
 *
 * at any point during the recursion, match*() can return to indicate
 * a match was not found in the config database and that the caller should
 * move on to the next potential match, if any.
 *
 * constraints are completely ignored by match(), so the statement:
 *
 *	prop error.a@x[n] -> error.b@x[n] {n != 0};
 *
 * might very well match x[0] if it appears in the config database.  it
 * is the generate() routine that takes that match and then decides what
 * arrow, if any, should be generated in the instance tree.  generate()
 * looks at the explicit iterator dictionary to get values like "n" in
 * the above example so that it can evaluate constraints.
 *
 */
static void
vmatch(struct info *infop, struct node *np, struct node *lnp,
    struct node *anp, struct wildcardinfo **wcproot)
{
	if (np == NULL) {
		if (lnp)
			vmatch(infop, lnp, NULL, anp, wcproot);
		else if (anp)
			vmatch(infop, anp, NULL, NULL, wcproot);
		else {
			struct node *src;
			struct node *dst;

			/* end of vertical match recursion */
			outfl(O_ALTFP|O_VERB3|O_NONL,
			    infop->anp->file, infop->anp->line, "vmatch: ");
			ptree_name_iter(O_ALTFP|O_VERB3|O_NONL, infop->anp);
			out(O_ALTFP|O_VERB3, NULL);

			generate_nork(
			    itree_np2nork(infop->anp->u.arrow.nnp),
			    itree_np2nork(infop->anp->u.arrow.knp));
			dst = infop->anp->u.arrow.rhs;
			src = infop->anp->u.arrow.lhs;
			for (;;) {
				generate_new();	/* new set of arrows */
				if (src->t == T_ARROW) {
					hmatch(infop, src->u.arrow.rhs, dst);
					generate_nork(
					    itree_np2nork(src->u.arrow.nnp),
					    itree_np2nork(src->u.arrow.knp));
					dst = src->u.arrow.rhs;
					src = src->u.arrow.lhs;
				} else {
					hmatch(infop, src, dst);
					break;
				}
			}
		}
		return;
	}

	switch (np->t) {
	case T_EVENT: {
		add_wildcardentry(wcproot, config_child(infop->croot), np);
		vmatch_event(infop, config_child(infop->croot),
			    np->u.event.epname, lnp, anp, wcproot, WA_ALL);
		delete_wildcardentry(wcproot);
		break;
	}
	case T_LIST:
		ASSERT(lnp == NULL);
		vmatch(infop, np->u.expr.right, np->u.expr.left, anp, wcproot);
		break;

	case T_ARROW:
		ASSERT(lnp == NULL && anp == NULL);
		vmatch(infop, np->u.arrow.rhs, NULL, np->u.arrow.lhs, wcproot);
		break;

	default:
		outfl(O_DIE, np->file, np->line,
		    "vmatch: unexpected type: %s",
		    ptree_nodetype2str(np->t));
	}
}

static void
cp_reset(struct node *np)
{
	if (np == NULL)
		return;
	switch (np->t) {
	case T_NAME:
		np->u.name.cp = NULL;
		cp_reset(np->u.name.next);
		break;

	case T_LIST:
		cp_reset(np->u.expr.left);
		cp_reset(np->u.expr.right);
		break;

	case T_ARROW:
		cp_reset(np->u.arrow.lhs);
		cp_reset(np->u.arrow.rhs);
		break;

	case T_EVENT:
		cp_reset(np->u.event.epname);
		break;
	}
}

/*
 * itree_create -- apply the current config to the current parse tree
 *
 * returns a lut mapping fully-instance-qualified names to struct events.
 *
 */
struct lut *
itree_create(struct config *croot)
{
	struct lut *retval;
	struct node *propnp;

	Ninfo.lut = NULL;
	Ninfo.croot = croot;
	for (propnp = Props; propnp; propnp = propnp->u.stmt.next) {
		struct node *anp = propnp->u.stmt.np;
		struct wildcardinfo *wcproot = NULL;

		ASSERTeq(anp->t, T_ARROW, ptree_nodetype2str);

		Ninfo.anp = anp;
		Ninfo.ex = NULL;

		generate_arrownp(anp);
		vmatch(&Ninfo, anp, NULL, NULL, &wcproot);

		if (Ninfo.ex) {
			lut_free(Ninfo.ex, iterinfo_destructor, NULL);
			Ninfo.ex = NULL;
		}
		ASSERT(wcproot == NULL);
		cp_reset(anp);
	}

	retval = Ninfo.lut;
	Ninfo.lut = NULL;
	return (retval);
}

void
itree_free(struct lut *lutp)
{
	lut_free(lutp, itree_destructor, NULL);
}

int
itree_nameinstancecmp(struct node *np1, struct node *np2)
{
	int np1type = (int)np1->u.name.t;
	int np2type = (int)np2->u.name.t;
	int num1;
	int num2;

	while (np1 && np2 && np1->u.name.s == np2->u.name.s) {
		if (np1->u.name.next != NULL && np2->u.name.next != NULL) {
			if (np1->u.name.cp != NULL) {
				config_getcompname(np1->u.name.cp, NULL, &num1);
			} else {
				ASSERT(np1->u.name.child != NULL);
				ASSERT(np1->u.name.child->t == T_NUM);
				num1 = (int)np1->u.name.child->u.ull;
			}

			if (np2->u.name.cp != NULL) {
				config_getcompname(np2->u.name.cp, NULL, &num2);
			} else {
				ASSERT(np2->u.name.child != NULL);
				ASSERT(np2->u.name.child->t == T_NUM);
				num2 = (int)np2->u.name.child->u.ull;
			}

			if (num1 != num2)
				return (num1 - num2);
		}

		np1 = np1->u.name.next;
		np2 = np2->u.name.next;
	}
	if (np1 == NULL)
		if (np2 == NULL)
			return (np1type - np2type);
		else
			return (-1);
	else if (np2 == NULL)
		return (1);
	else
		return (strcmp(np1->u.name.s, np2->u.name.s));
}

void
itree_pevent_brief(int flags, struct event *ep)
{
	ASSERT(ep != NULL);
	ASSERT(ep->enode != NULL);
	ASSERT(ep->ipp != NULL);

	ipath_print(flags, ep->enode->u.event.ename->u.name.s, ep->ipp);
}

/*ARGSUSED*/
static void
itree_pevent(struct event *lhs, struct event *ep, void *arg)
{
	struct plut_wlk_data propd;
	struct bubble *bp;
	int flags = (int)arg;

	itree_pevent_brief(flags, ep);
	if (ep->t == N_EREPORT)
		out(flags, " (count %d)", ep->count);
	else
		out(flags, NULL);

	if (ep->props) {
		propd.flags = flags;
		propd.first = 1;
		out(flags, "Properties:");
		lut_walk(ep->props, ptree_plut, (void *)&propd);
	}

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		/* Print only TO bubbles in this loop */
		if (bp->t != B_TO)
			continue;
		itree_pbubble(flags, bp);
	}

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		/* Print only INHIBIT bubbles in this loop */
		if (bp->t != B_INHIBIT)
			continue;
		itree_pbubble(flags, bp);
	}

	for (bp = itree_next_bubble(ep, NULL); bp;
	    bp = itree_next_bubble(ep, bp)) {
		/* Print only FROM bubbles in this loop */
		if (bp->t != B_FROM)
			continue;
		itree_pbubble(flags, bp);
	}
}

static void
itree_pbubble(int flags, struct bubble *bp)
{
	struct constraintlist *cp;
	struct arrowlist *ap;

	ASSERT(bp != NULL);

	out(flags|O_NONL, "   ");
	if (bp->mark)
		out(flags|O_NONL, "*");
	else
		out(flags|O_NONL, " ");
	if (bp->t == B_FROM)
		out(flags|O_NONL, "N=%d to:", bp->nork);
	else if (bp->t == B_TO)
		out(flags|O_NONL, "K=%d from:", bp->nork);
	else
		out(flags|O_NONL, "K=%d masked from:", bp->nork);

	if (bp->t == B_TO || bp->t == B_INHIBIT) {
		for (ap = itree_next_arrow(bp, NULL); ap;
		    ap = itree_next_arrow(bp, ap)) {
			ASSERT(ap->arrowp->head == bp);
			ASSERT(ap->arrowp->tail != NULL);
			ASSERT(ap->arrowp->tail->myevent != NULL);
			out(flags|O_NONL, " ");
			itree_pevent_brief(flags, ap->arrowp->tail->myevent);
		}
		out(flags, NULL);
		return;
	}

	for (ap = itree_next_arrow(bp, NULL); ap;
	    ap = itree_next_arrow(bp, ap)) {
		ASSERT(ap->arrowp->tail == bp);
		ASSERT(ap->arrowp->head != NULL);
		ASSERT(ap->arrowp->head->myevent != NULL);

		out(flags|O_NONL, " ");
		itree_pevent_brief(flags, ap->arrowp->head->myevent);

		out(flags|O_NONL, " ");
		ptree_timeval(flags, &ap->arrowp->mindelay);
		out(flags|O_NONL, ",");
		ptree_timeval(flags, &ap->arrowp->maxdelay);

		/* Display anything from the propogation node? */
		out(O_VERB3|O_NONL, " <%s:%d>",
		    ap->arrowp->pnode->file, ap->arrowp->pnode->line);

		if (itree_next_constraint(ap->arrowp, NULL))
			out(flags|O_NONL, " {");

		for (cp = itree_next_constraint(ap->arrowp, NULL); cp;
		    cp = itree_next_constraint(ap->arrowp, cp)) {
			ptree(flags, cp->cnode, 1, 0);
			if (itree_next_constraint(ap->arrowp, cp))
				out(flags|O_NONL, ", ");
		}

		if (itree_next_constraint(ap->arrowp, NULL))
			out(flags|O_NONL, "}");
	}
	out(flags, NULL);
}

void
itree_ptree(int flags, struct lut *itp)
{
	lut_walk(itp, (lut_cb)itree_pevent, (void *)flags);
}

/*ARGSUSED*/
static void
itree_destructor(void *left, void *right, void *arg)
{
	struct event *ep = (struct event *)right;
	struct bubble *nextbub, *bub;

	/* Free the properties */
	lut_free(ep->props, instances_destructor, NULL);

	/* Free the payload properties */
	lut_free(ep->payloadprops, payloadprops_destructor, NULL);

	/* Free my bubbles */
	for (bub = ep->bubbles; bub != NULL; ) {
		nextbub = bub->next;
		/*
		 * Free arrows if they are FROM me.  Free arrowlists on
		 * other types of bubbles (but not the attached arrows,
		 * which will be freed when we free the originating
		 * bubble.
		 */
		if (bub->t == B_FROM)
			itree_free_arrowlists(bub, 1);
		else
			itree_free_arrowlists(bub, 0);
		itree_free_bubble(bub);
		bub = nextbub;
	}

	if (ep->nvp != NULL)
		nvlist_free(ep->nvp);
	bzero(ep, sizeof (*ep));
	FREE(ep);
}

static void
itree_free_bubble(struct bubble *freeme)
{
	bzero(freeme, sizeof (*freeme));
	FREE(freeme);
}

static struct bubble *
itree_add_bubble(struct event *eventp, enum bubbletype btype, int nork, int gen)
{
	struct bubble *prev = NULL;
	struct bubble *curr;
	struct bubble *newb;

	/* Use existing bubbles as appropriate when possible */
	for (curr = eventp->bubbles;
	    curr != NULL;
	    prev = curr, curr = curr->next) {
		if (btype == B_TO && curr->t == B_TO) {
			/* see if an existing "to" bubble works for us */
			if (gen == curr->gen)
				return (curr);	/* matched gen number */
			else if (nork == 1 && curr->nork == 1) {
				curr->gen = gen;
				return (curr);	/* coalesce K==1 bubbles */
			}
		} else if (btype == B_FROM && curr->t == B_FROM) {
			/* see if an existing "from" bubble works for us */
			if ((nork == N_IS_ALL && curr->nork == N_IS_ALL) ||
			    (nork == 0 && curr->nork == 0))
				return (curr);
		}
	}

	newb = MALLOC(sizeof (struct bubble));
	newb->next = NULL;
	newb->t = btype;
	newb->myevent = eventp;
	newb->nork = nork;
	newb->mark = 0;
	newb->gen = gen;
	newb->arrows = NULL;

	if (prev == NULL)
		eventp->bubbles = newb;
	else
		prev->next = newb;

	return (newb);
}

struct bubble *
itree_next_bubble(struct event *eventp, struct bubble *last)
{
	struct bubble *next;

	for (;;) {
		if (last != NULL)
			next = last->next;
		else
			next = eventp->bubbles;

		if (next == NULL || next->arrows != NULL)
			return (next);

		/* bubble was empty, skip it */
		last = next;
	}
}

static void
add_arrow(struct bubble *bp, struct arrow *ap)
{
	struct arrowlist *prev = NULL;
	struct arrowlist *curr;
	struct arrowlist *newal;

	newal = MALLOC(sizeof (struct arrowlist));
	bzero(newal, sizeof (struct arrowlist));
	newal->arrowp = ap;

	curr = itree_next_arrow(bp, NULL);
	while (curr != NULL) {
		prev = curr;
		curr = itree_next_arrow(bp, curr);
	}

	if (prev == NULL)
		bp->arrows = newal;
	else
		prev->next = newal;
}

static struct arrow *
itree_add_arrow(struct bubble *frombubblep, struct bubble *tobubblep,
    struct node *apnode, struct node *fromevent, struct node *toevent,
    struct lut *ex)
{
	struct arrow *newa;

	ASSERTeq(frombubblep->t, B_FROM, itree_bubbletype2str);
	ASSERTinfo(tobubblep->t == B_TO || tobubblep->t == B_INHIBIT,
	    itree_bubbletype2str(tobubblep->t));
	newa = MALLOC(sizeof (struct arrow));
	bzero(newa, sizeof (struct arrow));
	newa->tail = frombubblep;
	newa->head = tobubblep;
	newa->pnode = apnode;
	newa->constraints = NULL;

	/*
	 *  Set default delays, then try to re-set them from
	 *  any within() constraints.
	 */
	newa->mindelay = newa->maxdelay = 0ULL;
	if (itree_set_arrow_traits(newa, fromevent, toevent, ex) == 0) {
		FREE(newa);
		return (NULL);
	}

	add_arrow(frombubblep, newa);
	add_arrow(tobubblep, newa);
	return (newa);
}

/* returns false if traits show that arrow should not be added after all */
static int
itree_set_arrow_traits(struct arrow *ap, struct node *fromev,
    struct node *toev, struct lut *ex)
{
	struct node *epnames[] = { NULL, NULL, NULL };
	struct node *newc = NULL;

	ASSERTeq(fromev->t, T_EVENT, ptree_nodetype2str);
	ASSERTeq(toev->t, T_EVENT, ptree_nodetype2str);

	/*
	 * search for the within values first on the declaration of
	 * the destination event, and then on the prop.  this allows
	 * one to specify a "default" within by putting it on the
	 * declaration,  but then allow overriding on the prop statement.
	 */
	arrow_add_within(ap, toev->u.event.declp->u.stmt.np->u.event.eexprlist);
	arrow_add_within(ap, toev->u.event.eexprlist);

	/*
	 * handle any global constraints inherited from the
	 * "fromev" event's declaration
	 */
	ASSERT(fromev->u.event.declp != NULL);
	ASSERT(fromev->u.event.declp->u.stmt.np != NULL);

#ifdef	notdef
	/* XXX not quite ready to evaluate constraints from decls yet */
	if (fromev->u.event.declp->u.stmt.np->u.event.eexprlist)
		(void) itree_add_constraint(ap,
		    fromev->u.event.declp->u.stmt.np->u.event.eexprlist);
#endif	/* notdef */

	/* handle constraints on the from event in the prop statement */
	epnames[0] = fromev->u.event.epname;
	epnames[1] = toev->u.event.epname;
	if (eval_potential(fromev->u.event.eexprlist, ex, epnames, &newc) == 0)
		return (0);		/* constraint disallows arrow */

	/*
	 * handle any global constraints inherited from the
	 * "toev" event's declaration
	 */
	ASSERT(toev->u.event.declp != NULL);
	ASSERT(toev->u.event.declp->u.stmt.np != NULL);

#ifdef	notdef
	/* XXX not quite ready to evaluate constraints from decls yet */
	if (toev->u.event.declp->u.stmt.np->u.event.eexprlist)
		(void) itree_add_constraint(ap,
		    toev->u.event.declp->u.stmt.np->u.event.eexprlist);
#endif	/* notdef */

	/* handle constraints on the to event in the prop statement */
	epnames[0] = toev->u.event.epname;
	epnames[1] = fromev->u.event.epname;
	if (eval_potential(toev->u.event.eexprlist, ex, epnames, &newc) == 0)
		return (0);		/* constraint disallows arrow */

	/* if we came up with any deferred constraints, add them to arrow */
	if (newc != NULL)
		(void) itree_add_constraint(ap, iexpr(newc));

	return (1);	/* constraints allow arrow */
}

/*
 * Set within() constraint.  If the constraint were set multiple times,
 * the last one would "win".
 */
static void
arrow_add_within(struct arrow *ap, struct node *xpr)
{
	struct node *arglist;

	/* end of expressions list */
	if (xpr == NULL)
		return;

	switch (xpr->t) {
	case T_LIST:
		arrow_add_within(ap, xpr->u.expr.left);
		arrow_add_within(ap, xpr->u.expr.right);
		return;
	case T_FUNC:
		if (xpr->u.func.s != L_within)
			return;
		arglist = xpr->u.func.arglist;
		switch (arglist->t) {
		case T_TIMEVAL:
			ap->mindelay = 0;
			ap->maxdelay = arglist->u.ull;
			break;
		case T_NAME:
			ASSERT(arglist->u.name.s == L_infinity);
			ap->mindelay = 0;
			ap->maxdelay = TIMEVAL_EVENTUALLY;
			break;
		case T_LIST:
			ASSERT(arglist->u.expr.left->t == T_TIMEVAL);
			ap->mindelay = arglist->u.expr.left->u.ull;
			switch (arglist->u.expr.right->t) {
			case T_TIMEVAL:
				ap->maxdelay = arglist->u.ull;
				break;
			case T_NAME:
				ASSERT(arglist->u.expr.right->u.name.s ==
				    L_infinity);
				ap->maxdelay = TIMEVAL_EVENTUALLY;
				break;
			default:
				out(O_DIE, "within: unexpected 2nd arg type");
			}
			break;
		default:
			out(O_DIE, "within: unexpected 1st arg type");
		}
		break;
	default:
		return;
	}
}

static void
itree_free_arrowlists(struct bubble *bubp, int arrows_too)
{
	struct arrowlist *al, *nal;

	al = bubp->arrows;
	while (al != NULL) {
		nal = al->next;
		if (arrows_too) {
			itree_free_constraints(al->arrowp);
			bzero(al->arrowp, sizeof (struct arrow));
			FREE(al->arrowp);
		}
		bzero(al, sizeof (*al));
		FREE(al);
		al = nal;
	}
}

struct arrowlist *
itree_next_arrow(struct bubble *bubble, struct arrowlist *last)
{
	struct arrowlist *next;

	if (last != NULL)
		next = last->next;
	else
		next = bubble->arrows;
	return (next);
}

static struct constraintlist *
itree_add_constraint(struct arrow *arrowp, struct node *c)
{
	struct constraintlist *prev = NULL;
	struct constraintlist *curr;
	struct constraintlist *newc;

	for (curr = arrowp->constraints;
	    curr != NULL;
	    prev = curr, curr = curr->next);

	newc = MALLOC(sizeof (struct constraintlist));
	newc->next = NULL;
	newc->cnode = c;

	if (prev == NULL)
		arrowp->constraints = newc;
	else
		prev->next = newc;

	return (newc);
}

struct constraintlist *
itree_next_constraint(struct arrow *arrowp, struct constraintlist *last)
{
	struct constraintlist *next;

	if (last != NULL)
		next = last->next;
	else
		next = arrowp->constraints;
	return (next);
}

static void
itree_free_constraints(struct arrow *ap)
{
	struct constraintlist *cl, *ncl;

	cl = ap->constraints;
	while (cl != NULL) {
		ncl = cl->next;
		ASSERT(cl->cnode != NULL);
		if (!iexpr_cached(cl->cnode))
			tree_free(cl->cnode);
		bzero(cl, sizeof (*cl));
		FREE(cl);
		cl = ncl;
	}
}

const char *
itree_bubbletype2str(enum bubbletype t)
{
	static char buf[100];

	switch (t) {
	case B_FROM:	return L_from;
	case B_TO:	return L_to;
	case B_INHIBIT:	return L_inhibit;
	default:
		(void) sprintf(buf, "[unexpected bubbletype: %d]", t);
		return (buf);
	}
}

/*
 * itree_fini -- clean up any half-built itrees
 */
void
itree_fini(void)
{
	if (Ninfo.lut != NULL) {
		itree_free(Ninfo.lut);
		Ninfo.lut = NULL;
	}
	if (Ninfo.ex) {
		lut_free(Ninfo.ex, iterinfo_destructor, NULL);
		Ninfo.ex = NULL;
	}
}

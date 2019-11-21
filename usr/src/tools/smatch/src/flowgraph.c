// SPDX-License-Identifier: MIT
//
// Various utilities for flowgraphs.
//
// Copyright (c) 2017 Luc Van Oostenryck.
//

#include "flowgraph.h"
#include "linearize.h"
#include "flow.h"			// for bb_generation
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>


struct cfg_info {
	struct basic_block_list *list;
	unsigned long gen;
	unsigned int nr;
};


static void label_postorder(struct basic_block *bb, struct cfg_info *info)
{
	struct basic_block *child;

	if (bb->generation == info->gen)
		return;

	bb->generation = info->gen;
	FOR_EACH_PTR_REVERSE(bb->children, child) {
		label_postorder(child, info);
	} END_FOR_EACH_PTR_REVERSE(child);

	bb->postorder_nr = info->nr++;
	add_bb(&info->list, bb);
}

static void reverse_bbs(struct basic_block_list **dst, struct basic_block_list *src)
{
	struct basic_block *bb;
	FOR_EACH_PTR_REVERSE(src, bb) {
		add_bb(dst, bb);
	} END_FOR_EACH_PTR_REVERSE(bb);
}

static void debug_postorder(struct entrypoint *ep)
{
	struct basic_block *bb;

	printf("%s's reverse postorder:\n", show_ident(ep->name->ident));
	FOR_EACH_PTR(ep->bbs, bb) {
		printf("\t.L%u: %u\n", bb->nr, bb->postorder_nr);
	} END_FOR_EACH_PTR(bb);
}

//
// cfg_postorder - Set the BB's reverse postorder links
//
// Do a postorder DFS walk and set the links
// (which will do the reverse part).
//
int cfg_postorder(struct entrypoint *ep)
{
	struct cfg_info info = {
		.gen = ++bb_generation,
	};

	label_postorder(ep->entry->bb, &info);

	// OK, now info.list contains the node in postorder
	// Reuse ep->bbs for the reverse postorder.
	free_ptr_list(&ep->bbs);
	ep->bbs = NULL;
	reverse_bbs(&ep->bbs, info.list);
	free_ptr_list(&info.list);
	if (dbg_postorder)
		debug_postorder(ep);
	return info.nr;
}

//
// Calculate the dominance tree following:
//	"A simple, fast dominance algorithm"
//	by K. D. Cooper, T. J. Harvey, and K. Kennedy.
//	cfr. http://www.cs.rice.edu/∼keith/EMBED/dom.pdf
//
static struct basic_block *intersect_dom(struct basic_block *doms[],
		struct basic_block *b1, struct basic_block *b2)
{
	int f1 = b1->postorder_nr, f2 = b2->postorder_nr;
	while (f1 != f2) {
		while (f1 < f2) {
			b1 = doms[f1];
			f1 = b1->postorder_nr;
		}
		while (f2 < f1) {
			b2 = doms[f2];
			f2 = b2->postorder_nr;
		}
	}
	return b1;
}

static void debug_domtree(struct entrypoint *ep)
{
	struct basic_block *bb = ep->entry->bb;

	printf("%s's idoms:\n", show_ident(ep->name->ident));
	FOR_EACH_PTR(ep->bbs, bb) {
		if (bb == ep->entry->bb)
			continue;	// entry node has no idom
		printf("\t%s	<- %s\n", show_label(bb), show_label(bb->idom));
	} END_FOR_EACH_PTR(bb);
}

void domtree_build(struct entrypoint *ep)
{
	struct basic_block *entry = ep->entry->bb;
	struct basic_block **doms;
	struct basic_block *bb;
	unsigned int size;
	int max_level = 0;
	int changed;

	// First calculate the (reverse) postorder.
	// This will give use us:
	//	- the links to do a reverse postorder traversal
	//	- the order number for each block
	size = cfg_postorder(ep);

	// initialize the dominators array
	doms = calloc(size, sizeof(*doms));
	assert(entry->postorder_nr == size-1);
	doms[size-1] = entry;

	do {
		struct basic_block *b;

		changed = 0;
		FOR_EACH_PTR(ep->bbs, b) {
			struct basic_block *p;
			int bnr = b->postorder_nr;
			struct basic_block *new_idom = NULL;

			if (b == entry)
				continue;	// ignore entry node

			FOR_EACH_PTR(b->parents, p) {
				unsigned int pnr = p->postorder_nr;
				if (!doms[pnr])
					continue;
				if (!new_idom) {
					new_idom = p;
					continue;
				}

				new_idom = intersect_dom(doms, p, new_idom);
			} END_FOR_EACH_PTR(p);

			assert(new_idom);
			if (doms[bnr] != new_idom) {
				doms[bnr] = new_idom;
				changed = 1;
			}
		} END_FOR_EACH_PTR(b);
	} while (changed);

	// set the idom links
	FOR_EACH_PTR(ep->bbs, bb) {
		struct basic_block *idom = doms[bb->postorder_nr];

		if (bb == entry)
			continue;	// ignore entry node

		bb->idom = idom;
		add_bb(&idom->doms, bb);
	} END_FOR_EACH_PTR(bb);
	entry->idom = NULL;

	// set the dominance levels
	FOR_EACH_PTR(ep->bbs, bb) {
		struct basic_block *idom = bb->idom;
		int level = idom ? idom->dom_level + 1 : 0;

		bb->dom_level = level;
		if (max_level < level)
			max_level = level;
	} END_FOR_EACH_PTR(bb);
	ep->dom_levels = max_level + 1;

	free(doms);
	if (dbg_domtree)
		debug_domtree(ep);
}

// dt_dominates - does BB a dominates BB b?
bool domtree_dominates(struct basic_block *a, struct basic_block *b)
{
	if (a == b)			// dominance is reflexive
		return true;
	if (a == b->idom)
		return true;
	if (b == a->idom)
		return false;

	// can't dominate if deeper in the DT
	if (a->dom_level >= b->dom_level)
		return false;

	// FIXME: can be faster if we have the DFS in-out numbers

	// walk up the dominator tree
	for (b = b->idom; b; b = b->idom) {
		if (b == a)
			return true;
	}
	return false;
}

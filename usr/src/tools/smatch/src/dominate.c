// SPDX-License-Identifier: MIT
//
// dominate.c - compute the (iterated) dominance frontier of (a set of) nodes.
//
// Copyright (C) 2017 - Luc Van Oostenryck
//
// The algorithm used is the one described in:
//	"A Linear Time Algorithm for Placing phi-nodes"
//	by Vugranam C. Sreedhar and Guang R. Gao
//

#include "dominate.h"
#include "flowgraph.h"
#include "linearize.h"
#include "flow.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>


struct piggy {
	unsigned int max;
	struct basic_block_list *lists[0];
};

static struct piggy *bank_init(unsigned levels)
{
	struct piggy *bank;
	bank = calloc(1, sizeof(*bank) + levels * sizeof(bank->lists[0]));
	bank->max = levels - 1;
	return bank;
}

static void bank_free(struct piggy *bank, unsigned int levels)
{
	for (; levels-- ;)
		free_ptr_list(&bank->lists[levels]);
	free(bank);
}

static void bank_put(struct piggy *bank, struct basic_block *bb)
{
	unsigned int level = bb->dom_level;
	assert(level <= bank->max);
	add_bb(&bank->lists[level], bb);
}

static inline struct basic_block *pop_bb(struct basic_block_list **list)
{
	return delete_ptr_list_last((struct ptr_list **)list);
}

static struct basic_block *bank_get(struct piggy *bank)
{
	int level = bank->max;
	do {
		struct basic_block *bb = pop_bb(&bank->lists[level]);
		if (bb)
			return bb;
		if (!level)
			return NULL;
		bank->max = --level;
	} while (1);
}


#define	VISITED	0x1
#define	INPHI	0x2
#define	ALPHA	0x4
#define	FLAGS	0x7

static void visit(struct piggy *bank, struct basic_block_list **idf, struct basic_block *x, int curr_level)
{
	struct basic_block *y;

	x->generation |= 1;
	FOR_EACH_PTR(x->children, y) {
		unsigned flags = y->generation & FLAGS;
		if (y->idom == x)	// J-edges will be processed later
			continue;
		if (y->dom_level > curr_level)
			continue;
		if (flags & INPHI)
			continue;
		y->generation |= INPHI;
		add_bb(idf, y);
		if (flags & ALPHA)
			continue;
		bank_put(bank, y);
	} END_FOR_EACH_PTR(y);

	FOR_EACH_PTR(x->doms, y) {
		if (y->generation & VISITED)
			continue;
		visit(bank, idf, y, curr_level);
	} END_FOR_EACH_PTR(y);
}

void idf_compute(struct entrypoint *ep, struct basic_block_list **idf, struct basic_block_list *alpha)
{
	int levels = ep->dom_levels;
	struct piggy *bank = bank_init(levels);
	struct basic_block *bb;
	unsigned long generation = bb_generation;

	generation = bb_generation;
	generation += -generation & FLAGS;
	bb_generation = generation + (FLAGS + 1);

	// init all the nodes
	FOR_EACH_PTR(ep->bbs, bb) {
		// FIXME: this should be removed and the tests for
		//	  visited/in_phi/alpha should use a sparse set
		bb->generation = generation;
	} END_FOR_EACH_PTR(bb);

	FOR_EACH_PTR(alpha, bb) {
		bb->generation = generation | ALPHA;
		bank_put(bank, bb);
	} END_FOR_EACH_PTR(bb);

	while ((bb = bank_get(bank))) {
		visit(bank, idf, bb, bb->dom_level);
	}

	bank_free(bank, levels);
}

void idf_dump(struct entrypoint *ep)
{
	struct basic_block *bb;

	domtree_build(ep);

	printf("%s's IDF:\n", show_ident(ep->name->ident));
	FOR_EACH_PTR(ep->bbs, bb) {
		struct basic_block_list *alpha = NULL;
		struct basic_block_list *idf = NULL;
		struct basic_block *df;

		add_bb(&alpha, bb);
		idf_compute(ep, &idf, alpha);

		printf("\t%s\t<-", show_label(bb));
		FOR_EACH_PTR(idf, df) {
			printf(" %s", show_label(df));
		} END_FOR_EACH_PTR(df);
		printf("\n");

		free_ptr_list(&idf);
		free_ptr_list(&alpha);
	} END_FOR_EACH_PTR(bb);
}

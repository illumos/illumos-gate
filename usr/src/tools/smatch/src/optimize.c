// SPDX-License-Identifier: MIT
//
// optimize.c - main optimization loop
//
// Copyright (C) 2004 Linus Torvalds
// Copyright (C) 2004 Christopher Li

#include <assert.h>
#include "optimize.h"
#include "flowgraph.h"
#include "linearize.h"
#include "liveness.h"
#include "flow.h"
#include "cse.h"
#include "ir.h"
#include "ssa.h"

int repeat_phase;

static void clear_symbol_pseudos(struct entrypoint *ep)
{
	pseudo_t pseudo;

	FOR_EACH_PTR(ep->accesses, pseudo) {
		pseudo->sym->pseudo = NULL;
	} END_FOR_EACH_PTR(pseudo);
}


static void clean_up_insns(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR(bb->insns, insn) {
			repeat_phase |= simplify_instruction(insn);
			if (!insn->bb)
				continue;
			assert(insn->bb == bb);
			cse_collect(insn);
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);
}

void optimize(struct entrypoint *ep)
{
	if (fdump_ir & PASS_LINEARIZE)
		show_entry(ep);

	/*
	 * Do trivial flow simplification - branches to
	 * branches, kill dead basicblocks etc
	 */
	kill_unreachable_bbs(ep);
	ir_validate(ep);

	domtree_build(ep);

	/*
	 * Turn symbols into pseudos
	 */
	if (fpasses & PASS_MEM2REG)
		ssa_convert(ep);
	ir_validate(ep);
	if (fdump_ir & PASS_MEM2REG)
		show_entry(ep);

	if (!(fpasses & PASS_OPTIM))
		return;
repeat:
	/*
	 * Remove trivial instructions, and try to CSE
	 * the rest.
	 */
	do {
		simplify_memops(ep);
		//ir_validate(ep);
		do {
			repeat_phase = 0;
			clean_up_insns(ep);
			if (repeat_phase & REPEAT_CFG_CLEANUP)
				kill_unreachable_bbs(ep);

			cse_eliminate(ep);

			if (repeat_phase & REPEAT_SYMBOL_CLEANUP)
				simplify_memops(ep);
			//ir_validate(ep);
		} while (repeat_phase);
		pack_basic_blocks(ep);
		//ir_validate(ep);
		if (repeat_phase & REPEAT_CFG_CLEANUP)
			kill_unreachable_bbs(ep);
		//ir_validate(ep);
	} while (repeat_phase);
	//ir_validate(ep);

	vrfy_flow(ep);

	/* Cleanup */
	clear_symbol_pseudos(ep);

	/* And track pseudo register usage */
	track_pseudo_liveness(ep);

	/*
	 * Some flow optimizations can only effectively
	 * be done when we've done liveness analysis. But
	 * if they trigger, we need to start all over
	 * again
	 */
	if (simplify_flow(ep)) {
		//ir_validate(ep);
		clear_liveness(ep);
		if (repeat_phase & REPEAT_CFG_CLEANUP)
			kill_unreachable_bbs(ep);
		goto repeat;
	}
	//ir_validate(ep);

	/* Finally, add deathnotes to pseudos now that we have them */
	if (dbg_dead)
		track_pseudo_death(ep);
}

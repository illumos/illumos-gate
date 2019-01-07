/*
 * UnSSA - translate the SSA back to normal form.
 *
 * For now it's done by replacing to set of copies:
 * 1) For each phi-node, replace all their phisrc by copies to a common
 *    temporary.
 * 2) Replace all the phi-nodes by copies of the temporaries to the phi-node target.
 *    This is node to preserve the semantic of the phi-node (they should all "execute"
 *    simultaneously on entry in the basic block in which they belong).
 *
 * This is similar to the "Sreedhar method I" except that the copies to the
 * temporaries are not placed at the end of the predecessor basic blocks, but
 * at the place where the phi-node operands are defined.
 * This is particulary easy since these copies are essentialy already present
 * as the corresponding OP_PHISOURCE.
 *
 * While very simple this method create a lot more copies that really necessary.
 * We eliminate some of these copies but most probably most of them are still
 * useless.
 * Ideally, "Sreedhar method III" should be used:
 * "Translating Out of Static Single Assignment Form", V. C. Sreedhar, R. D.-C. Ju,
 * D. M. Gillies and V. Santhanam.  SAS'99, Vol. 1694 of Lecture Notes in Computer
 * Science, Springer-Verlag, pp. 194-210, 1999.
 * But for this we need precise liveness, on each %phi and not only on OP_PHI's
 * target pseudos.
 *
 * Copyright (C) 2005 Luc Van Oostenryck
 */

#include "lib.h"
#include "linearize.h"
#include "allocate.h"
#include "flow.h"
#include <assert.h>


static inline int nbr_pseudo_users(pseudo_t p)
{
	return ptr_list_size((struct ptr_list *)p->users);
}

static int simplify_phi_node(struct instruction *phi, pseudo_t tmp)
{
	pseudo_t target = phi->target;
	struct pseudo_user *pu;
	pseudo_t src;

	// verify if this phi can be simplified
	FOR_EACH_PTR(phi->phi_list, src) {
		struct instruction *def = src->def;

		if (!def)
			continue;
		if (def->bb == phi->bb)
			return 0;
	} END_FOR_EACH_PTR(src);

	// no need to make a copy of this one
	// -> replace the target pseudo by the tmp
	FOR_EACH_PTR(target->users, pu) {
		use_pseudo(pu->insn, tmp, pu->userp);
	} END_FOR_EACH_PTR(pu);

	phi->bb = NULL;
	return 1;
}

static void replace_phi_node(struct instruction *phi)
{
	pseudo_t tmp;
	pseudo_t p;

	tmp = alloc_pseudo(NULL);
	tmp->type = phi->target->type;
	tmp->ident = phi->target->ident;
	tmp->def = NULL;		// defined by all the phisrc

	// can we avoid to make of copy?
	simplify_phi_node(phi, tmp);

	// rewrite all it's phi_src to copy to a new tmp
	FOR_EACH_PTR(phi->phi_list, p) {
		struct instruction *def = p->def;
		pseudo_t src;

		if (p == VOID)
			continue;

		assert(def->opcode == OP_PHISOURCE);

		def->opcode = OP_COPY;
		def->target = tmp;

		// can we eliminate the copy?
		src = def->phi_src;
		if (src->type != PSEUDO_REG)
			continue;
		switch (nbr_pseudo_users(src)) {
			struct instruction *insn;
		case 1:
			insn = src->def;
			if (!insn)
				break;
			insn->target = tmp;
		case 0:
			kill_instruction(def);
			def->bb = NULL;
		}
	} END_FOR_EACH_PTR(p);

	if (!phi->bb)
		return;

	// rewrite the phi node:
	//	phi	%rt, ...
	// to:
	//	copy	%rt, %tmp
	phi->opcode = OP_COPY;
	use_pseudo(phi, tmp, &phi->src);
}

static void rewrite_phi_bb(struct basic_block *bb)
{
	struct instruction *insn;

	// Replace all the phi-nodes by copies of a temporary
	// (which represent the set of all the %phi that feed them).
	// The target pseudo doesn't change.
	FOR_EACH_PTR(bb->insns, insn) {
		if (!insn->bb)
			continue;
		if (insn->opcode != OP_PHI)
			continue;
		replace_phi_node(insn);
	} END_FOR_EACH_PTR(insn);
}

int unssa(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		rewrite_phi_bb(bb);
	} END_FOR_EACH_PTR(bb);

	return 0;
}

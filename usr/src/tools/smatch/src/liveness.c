/*
 * Register - track pseudo usage, maybe eventually try to do register
 * allocation.
 *
 * Copyright (C) 2004 Linus Torvalds
 */

#include <assert.h>

#include "liveness.h"
#include "parse.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"

static void phi_defines(struct instruction * phi_node, pseudo_t target,
	void (*defines)(struct basic_block *, pseudo_t))
{
	pseudo_t phi;
	FOR_EACH_PTR(phi_node->phi_list, phi) {
		struct instruction *def;
		if (phi == VOID)
			continue;
		def = phi->def;
		if (!def || !def->bb)
			continue;
		defines(def->bb, target);
	} END_FOR_EACH_PTR(phi);
}

static void asm_liveness(struct basic_block *bb, struct instruction *insn,
	void (*def)(struct basic_block *, pseudo_t),
	void (*use)(struct basic_block *, pseudo_t))
{
	struct asm_constraint *entry;

	FOR_EACH_PTR(insn->asm_rules->inputs, entry) {
		use(bb, entry->pseudo);
	} END_FOR_EACH_PTR(entry);
		
	FOR_EACH_PTR(insn->asm_rules->outputs, entry) {
		def(bb, entry->pseudo);
	} END_FOR_EACH_PTR(entry);
}

static void track_instruction_usage(struct basic_block *bb, struct instruction *insn,
	void (*def)(struct basic_block *, pseudo_t),
	void (*use)(struct basic_block *, pseudo_t))
{
	pseudo_t pseudo;

	#define USES(x)		use(bb, insn->x)
	#define DEFINES(x)	def(bb, insn->x)

	switch (insn->opcode) {
	case OP_RET:
	case OP_COMPUTEDGOTO:
		USES(src);
		break;

	case OP_CBR:
	case OP_SWITCH:
		USES(cond);
		break;

	/* Binary */
	case OP_BINARY ... OP_BINARY_END:
	case OP_FPCMP ... OP_FPCMP_END:
	case OP_BINCMP ... OP_BINCMP_END:
		USES(src1); USES(src2); DEFINES(target);
		break;

	/* Uni */
	case OP_UNOP ... OP_UNOP_END:
	case OP_SYMADDR:
		USES(src1); DEFINES(target);
		break;

	case OP_SEL:
		USES(src1); USES(src2); USES(src3); DEFINES(target);
		break;
	
	/* Memory */
	case OP_LOAD:
		USES(src); DEFINES(target);
		break;

	case OP_STORE:
		USES(src); USES(target);
		break;

	case OP_SETVAL:
	case OP_SETFVAL:
		DEFINES(target);
		break;

	/* Other */
	case OP_PHI:
		/* Phi-nodes are "backwards" nodes. Their def doesn't matter */
		phi_defines(insn, insn->target, def);
		break;

	case OP_PHISOURCE:
		/*
		 * We don't care about the phi-source define, they get set
		 * up and expanded by the OP_PHI
		 */
		USES(phi_src);
		break;

	case OP_CALL:
		USES(func);
		if (insn->target != VOID)
			DEFINES(target);
		FOR_EACH_PTR(insn->arguments, pseudo) {
			use(bb, pseudo);
		} END_FOR_EACH_PTR(pseudo);
		break;

	case OP_SLICE:
		USES(base); DEFINES(target);
		break;

	case OP_ASM:
		asm_liveness(bb, insn, def, use);
		break;

	case OP_RANGE:
		USES(src1); USES(src2); USES(src3);
		break;

	case OP_BADOP:
	case OP_NOP:
	case OP_CONTEXT:
		break;
	}
}


static int liveness_changed;

static void add_pseudo_exclusive(struct pseudo_list **list, pseudo_t pseudo)
{
	if (!pseudo_in_list(*list, pseudo)) {
		liveness_changed = 1;
		add_pseudo(list, pseudo);
	}
}

static inline int trackable_pseudo(pseudo_t pseudo)
{
	return pseudo && (pseudo->type == PSEUDO_REG || pseudo->type == PSEUDO_ARG);
}

static void insn_uses(struct basic_block *bb, pseudo_t pseudo)
{
	if (trackable_pseudo(pseudo)) {
		struct instruction *def = pseudo->def;
		if (pseudo->type != PSEUDO_REG || def->bb != bb || def->opcode == OP_PHI)
			add_pseudo_exclusive(&bb->needs, pseudo);
	}
}

static void insn_defines(struct basic_block *bb, pseudo_t pseudo)
{
	assert(trackable_pseudo(pseudo));
	add_pseudo(&bb->defines, pseudo);
}

static void track_bb_liveness(struct basic_block *bb)
{
	pseudo_t needs;

	FOR_EACH_PTR(bb->needs, needs) {
		struct basic_block *parent;
		FOR_EACH_PTR(bb->parents, parent) {
			if (!pseudo_in_list(parent->defines, needs)) {
				add_pseudo_exclusive(&parent->needs, needs);
			}
		} END_FOR_EACH_PTR(parent);
	} END_FOR_EACH_PTR(needs);
}

/*
 * We need to clear the liveness information if we 
 * are going to re-run it.
 */
void clear_liveness(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		free_ptr_list(&bb->needs);
		free_ptr_list(&bb->defines);
	} END_FOR_EACH_PTR(bb);
}

/*
 * Track inter-bb pseudo liveness. The intra-bb case
 * is purely local information.
 */
void track_pseudo_liveness(struct entrypoint *ep)
{
	struct basic_block *bb;

	/* Add all the bb pseudo usage */
	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR(bb->insns, insn) {
			if (!insn->bb)
				continue;
			assert(insn->bb == bb);
			track_instruction_usage(bb, insn, insn_defines, insn_uses);
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);

	/* Calculate liveness.. */
	do {
		liveness_changed = 0;
		FOR_EACH_PTR_REVERSE(ep->bbs, bb) {
			track_bb_liveness(bb);
		} END_FOR_EACH_PTR_REVERSE(bb);
	} while (liveness_changed);

	/* Remove the pseudos from the "defines" list that are used internally */
	FOR_EACH_PTR(ep->bbs, bb) {
		pseudo_t def;
		FOR_EACH_PTR(bb->defines, def) {
			struct basic_block *child;
			FOR_EACH_PTR(bb->children, child) {
				if (pseudo_in_list(child->needs, def))
					goto is_used;
			} END_FOR_EACH_PTR(child);
			DELETE_CURRENT_PTR(def);
is_used:
		;
		} END_FOR_EACH_PTR(def);
		PACK_PTR_LIST(&bb->defines);
	} END_FOR_EACH_PTR(bb);
}

static void merge_pseudo_list(struct pseudo_list *src, struct pseudo_list **dest)
{
	pseudo_t pseudo;
	FOR_EACH_PTR(src, pseudo) {
		add_pseudo_exclusive(dest, pseudo);
	} END_FOR_EACH_PTR(pseudo);
}

static void track_phi_uses(struct instruction *insn)
{
	pseudo_t phi;
	FOR_EACH_PTR(insn->phi_list, phi) {
		struct instruction *def;
		if (phi == VOID || !phi->def)
			continue;
		def = phi->def;
		assert(def->opcode == OP_PHISOURCE);
		add_ptr_list(&def->phi_users, insn);
	} END_FOR_EACH_PTR(phi);
}

static void track_bb_phi_uses(struct basic_block *bb)
{
	struct instruction *insn;
	FOR_EACH_PTR(bb->insns, insn) {
		if (insn->bb && insn->opcode == OP_PHI)
			track_phi_uses(insn);
	} END_FOR_EACH_PTR(insn);
}

static struct pseudo_list **live_list;
static struct pseudo_list *dead_list;

static void death_def(struct basic_block *bb, pseudo_t pseudo)
{
}

static void death_use(struct basic_block *bb, pseudo_t pseudo)
{
	if (trackable_pseudo(pseudo) && !pseudo_in_list(*live_list, pseudo)) {
		add_pseudo(&dead_list, pseudo);
		add_pseudo(live_list, pseudo);
	}
}

static void track_pseudo_death_bb(struct basic_block *bb)
{
	struct pseudo_list *live = NULL;
	struct basic_block *child;
	struct instruction *insn;

	FOR_EACH_PTR(bb->children, child) {
		merge_pseudo_list(child->needs, &live);
	} END_FOR_EACH_PTR(child);

	live_list = &live;
	FOR_EACH_PTR_REVERSE(bb->insns, insn) {
		if (!insn->bb)
			continue;

		dead_list = NULL;
		track_instruction_usage(bb, insn, death_def, death_use);
		if (dead_list) {
			pseudo_t dead;
			FOR_EACH_PTR(dead_list, dead) {
				struct instruction *deathnote = __alloc_instruction(0);
				deathnote->bb = bb;
				deathnote->opcode = OP_DEATHNOTE;
				deathnote->target = dead;
				INSERT_CURRENT(deathnote, insn);
			} END_FOR_EACH_PTR(dead);
			free_ptr_list(&dead_list);
		}
	} END_FOR_EACH_PTR_REVERSE(insn);
	free_ptr_list(&live);
}

void track_pseudo_death(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		track_bb_phi_uses(bb);
	} END_FOR_EACH_PTR(bb);

	FOR_EACH_PTR(ep->bbs, bb) {
		track_pseudo_death_bb(bb);
	} END_FOR_EACH_PTR(bb);
}

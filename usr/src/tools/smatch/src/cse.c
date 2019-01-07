/*
 * CSE - walk the linearized instruction flow, and
 * see if we can simplify it and apply CSE on it.
 *
 * Copyright (C) 2004 Linus Torvalds
 */

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>

#include "parse.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"

#define INSN_HASH_SIZE 256
static struct instruction_list *insn_hash_table[INSN_HASH_SIZE];

int repeat_phase;

static int phi_compare(pseudo_t phi1, pseudo_t phi2)
{
	const struct instruction *def1 = phi1->def;
	const struct instruction *def2 = phi2->def;

	if (def1->src1 != def2->src1)
		return def1->src1 < def2->src1 ? -1 : 1;
	if (def1->bb != def2->bb)
		return def1->bb < def2->bb ? -1 : 1;
	return 0;
}


static void clean_up_one_instruction(struct basic_block *bb, struct instruction *insn)
{
	unsigned long hash;

	if (!insn->bb)
		return;
	assert(insn->bb == bb);
	repeat_phase |= simplify_instruction(insn);
	if (!insn->bb)
		return;
	hash = (insn->opcode << 3) + (insn->size >> 3);
	switch (insn->opcode) {
	case OP_SEL:
		hash += hashval(insn->src3);
		/* Fall through */	

	/* Binary arithmetic */
	case OP_ADD: case OP_SUB:
	case OP_MULU: case OP_MULS:
	case OP_DIVU: case OP_DIVS:
	case OP_MODU: case OP_MODS:
	case OP_SHL:
	case OP_LSR: case OP_ASR:
	case OP_AND: case OP_OR:

	/* Binary logical */
	case OP_XOR: case OP_AND_BOOL:
	case OP_OR_BOOL:

	/* Binary comparison */
	case OP_SET_EQ: case OP_SET_NE:
	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_LT: case OP_SET_GT:
	case OP_SET_B:  case OP_SET_A:
	case OP_SET_BE: case OP_SET_AE:
		hash += hashval(insn->src2);
		/* Fall through */
	
	/* Unary */
	case OP_NOT: case OP_NEG:
		hash += hashval(insn->src1);
		break;

	case OP_SETVAL:
		hash += hashval(insn->val);
		break;

	case OP_SYMADDR:
		hash += hashval(insn->symbol);
		break;

	case OP_CAST:
	case OP_SCAST:
	case OP_PTRCAST:
		/*
		 * This is crap! Many "orig_types" are the
		 * same as far as casts go, we should generate
		 * some kind of "type hash" that is identical
		 * for identical casts
		 */
		hash += hashval(insn->orig_type);
		hash += hashval(insn->src);
		break;

	/* Other */
	case OP_PHI: {
		pseudo_t phi;
		FOR_EACH_PTR(insn->phi_list, phi) {
			struct instruction *def;
			if (phi == VOID || !phi->def)
				continue;
			def = phi->def;
			hash += hashval(def->src1);
			hash += hashval(def->bb);
		} END_FOR_EACH_PTR(phi);
		break;
	}

	default:
		/*
		 * Nothing to do, don't even bother hashing them,
		 * we're not going to try to CSE them
		 */
		return;
	}
	hash += hash >> 16;
	hash &= INSN_HASH_SIZE-1;
	add_instruction(insn_hash_table + hash, insn);
}

static void clean_up_insns(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR(bb->insns, insn) {
			clean_up_one_instruction(bb, insn);
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);
}

/* Compare two (sorted) phi-lists */
static int phi_list_compare(struct pseudo_list *l1, struct pseudo_list *l2)
{
	pseudo_t phi1, phi2;

	PREPARE_PTR_LIST(l1, phi1);
	PREPARE_PTR_LIST(l2, phi2);
	for (;;) {
		int cmp;

		while (phi1 && (phi1 == VOID || !phi1->def))
			NEXT_PTR_LIST(phi1);
		while (phi2 && (phi2 == VOID || !phi2->def))
			NEXT_PTR_LIST(phi2);

		if (!phi1)
			return phi2 ? -1 : 0;
		if (!phi2)
			return phi1 ? 1 : 0;
		cmp = phi_compare(phi1, phi2);
		if (cmp)
			return cmp;
		NEXT_PTR_LIST(phi1);
		NEXT_PTR_LIST(phi2);
	}
	/* Not reached, but we need to make the nesting come out right */
	FINISH_PTR_LIST(phi2);
	FINISH_PTR_LIST(phi1);
}

static int insn_compare(const void *_i1, const void *_i2)
{
	const struct instruction *i1 = _i1;
	const struct instruction *i2 = _i2;

	if (i1->opcode != i2->opcode)
		return i1->opcode < i2->opcode ? -1 : 1;

	switch (i1->opcode) {

	/* commutative binop */
	case OP_ADD:
	case OP_MULU: case OP_MULS:
	case OP_AND_BOOL: case OP_OR_BOOL:
	case OP_AND: case OP_OR:
	case OP_XOR:
	case OP_SET_EQ: case OP_SET_NE:
		if (i1->src1 == i2->src2 && i1->src2 == i2->src1)
			return 0;
		goto case_binops;

	case OP_SEL:
		if (i1->src3 != i2->src3)
			return i1->src3 < i2->src3 ? -1 : 1;
		/* Fall-through to binops */

	/* Binary arithmetic */
	case OP_SUB:
	case OP_DIVU: case OP_DIVS:
	case OP_MODU: case OP_MODS:
	case OP_SHL:
	case OP_LSR: case OP_ASR:

	/* Binary comparison */
	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_LT: case OP_SET_GT:
	case OP_SET_B:  case OP_SET_A:
	case OP_SET_BE: case OP_SET_AE:
	case_binops:
		if (i1->src2 != i2->src2)
			return i1->src2 < i2->src2 ? -1 : 1;
		/* Fall through to unops */

	/* Unary */
	case OP_NOT: case OP_NEG:
		if (i1->src1 != i2->src1)
			return i1->src1 < i2->src1 ? -1 : 1;
		break;

	case OP_SYMADDR:
		if (i1->symbol != i2->symbol)
			return i1->symbol < i2->symbol ? -1 : 1;
		break;

	case OP_SETVAL:
		if (i1->val != i2->val)
			return i1->val < i2->val ? -1 : 1;
		break;

	/* Other */
	case OP_PHI:
		return phi_list_compare(i1->phi_list, i2->phi_list);

	case OP_CAST:
	case OP_SCAST:
	case OP_PTRCAST:
		/*
		 * This is crap! See the comments on hashing.
		 */
		if (i1->orig_type != i2->orig_type)
			return i1->orig_type < i2->orig_type ? -1 : 1;
		if (i1->src != i2->src)
			return i1->src < i2->src ? -1 : 1;
		break;

	default:
		warning(i1->pos, "bad instruction on hash chain");
	}
	if (i1->size != i2->size)
		return i1->size < i2->size ? -1 : 1;
	return 0;
}

static void sort_instruction_list(struct instruction_list **list)
{
	sort_list((struct ptr_list **)list , insn_compare);
}

static struct instruction * cse_one_instruction(struct instruction *insn, struct instruction *def)
{
	convert_instruction_target(insn, def->target);

	kill_instruction(insn);
	repeat_phase |= REPEAT_CSE;
	return def;
}

/*
 * Does "bb1" dominate "bb2"?
 */
static int bb_dominates(struct entrypoint *ep, struct basic_block *bb1, struct basic_block *bb2, unsigned long generation)
{
	struct basic_block *parent;

	/* Nothing dominates the entrypoint.. */
	if (bb2 == ep->entry->bb)
		return 0;
	FOR_EACH_PTR(bb2->parents, parent) {
		if (parent == bb1)
			continue;
		if (parent->generation == generation)
			continue;
		parent->generation = generation;
		if (!bb_dominates(ep, bb1, parent, generation))
			return 0;
	} END_FOR_EACH_PTR(parent);
	return 1;
}

static struct basic_block *trivial_common_parent(struct basic_block *bb1, struct basic_block *bb2)
{
	struct basic_block *parent;

	if (bb_list_size(bb1->parents) != 1)
		return NULL;
	parent = first_basic_block(bb1->parents);
	if (bb_list_size(bb2->parents) != 1)
		return NULL;
	if (first_basic_block(bb2->parents) != parent)
		return NULL;
	return parent;
}

static inline void remove_instruction(struct instruction_list **list, struct instruction *insn, int count)
{
	delete_ptr_list_entry((struct ptr_list **)list, insn, count);
}

static void add_instruction_to_end(struct instruction *insn, struct basic_block *bb)
{
	struct instruction *br = delete_last_instruction(&bb->insns);
	insn->bb = bb;
	add_instruction(&bb->insns, insn);
	add_instruction(&bb->insns, br);
}

static struct instruction * try_to_cse(struct entrypoint *ep, struct instruction *i1, struct instruction *i2)
{
	struct basic_block *b1, *b2, *common;

	/*
	 * OK, i1 and i2 are the same instruction, modulo "target".
	 * We should now see if we can combine them.
	 */
	b1 = i1->bb;
	b2 = i2->bb;

	/*
	 * Currently we only handle the uninteresting degenerate case where
	 * the CSE is inside one basic-block.
	 */
	if (b1 == b2) {
		struct instruction *insn;
		FOR_EACH_PTR(b1->insns, insn) {
			if (insn == i1)
				return cse_one_instruction(i2, i1);
			if (insn == i2)
				return cse_one_instruction(i1, i2);
		} END_FOR_EACH_PTR(insn);
		warning(b1->pos, "Whaa? unable to find CSE instructions");
		return i1;
	}
	if (bb_dominates(ep, b1, b2, ++bb_generation))
		return cse_one_instruction(i2, i1);

	if (bb_dominates(ep, b2, b1, ++bb_generation))
		return cse_one_instruction(i1, i2);

	/* No direct dominance - but we could try to find a common ancestor.. */
	common = trivial_common_parent(b1, b2);
	if (common) {
		i1 = cse_one_instruction(i2, i1);
		remove_instruction(&b1->insns, i1, 1);
		add_instruction_to_end(i1, common);
	}

	return i1;
}

void cleanup_and_cse(struct entrypoint *ep)
{
	int i;

	simplify_memops(ep);
repeat:
	repeat_phase = 0;
	clean_up_insns(ep);
	if (repeat_phase & REPEAT_CFG_CLEANUP)
		kill_unreachable_bbs(ep);
	for (i = 0; i < INSN_HASH_SIZE; i++) {
		struct instruction_list **list = insn_hash_table + i;
		if (*list) {
			if (instruction_list_size(*list) > 1) {
				struct instruction *insn, *last;

				sort_instruction_list(list);

				last = NULL;
				FOR_EACH_PTR(*list, insn) {
					if (!insn->bb)
						continue;
					if (last) {
						if (!insn_compare(last, insn))
							insn = try_to_cse(ep, last, insn);
					}
					last = insn;
				} END_FOR_EACH_PTR(insn);
			}
			free_ptr_list((struct ptr_list **)list);
		}
	}

	if (repeat_phase & REPEAT_SYMBOL_CLEANUP)
		simplify_memops(ep);

	if (repeat_phase & REPEAT_CSE)
		goto repeat;
}

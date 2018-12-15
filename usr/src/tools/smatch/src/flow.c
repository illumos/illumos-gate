/*
 * Flow - walk the linearized flowgraph, simplifying it as we
 * go along.
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
#include "target.h"

unsigned long bb_generation;

/*
 * Dammit, if we have a phi-node followed by a conditional
 * branch on that phi-node, we should damn well be able to
 * do something about the source. Maybe.
 */
static int rewrite_branch(struct basic_block *bb,
	struct basic_block **ptr,
	struct basic_block *old,
	struct basic_block *new)
{
	if (*ptr != old || new == old || !bb->ep)
		return 0;

	/* We might find new if-conversions or non-dominating CSEs */
	/* we may also create new dead cycles */
	repeat_phase |= REPEAT_CSE | REPEAT_CFG_CLEANUP;
	*ptr = new;
	replace_bb_in_list(&bb->children, old, new, 1);
	remove_bb_from_list(&old->parents, bb, 1);
	add_bb(&new->parents, bb);
	return 1;
}

/*
 * Return the known truth value of a pseudo, or -1 if
 * it's not known.
 */
static int pseudo_truth_value(pseudo_t pseudo)
{
	switch (pseudo->type) {
	case PSEUDO_VAL:
		return !!pseudo->value;

	case PSEUDO_REG: {
		struct instruction *insn = pseudo->def;

		/* A symbol address is always considered true.. */
		if (insn->opcode == OP_SYMADDR && insn->target == pseudo)
			return 1;
	}
		/* Fall through */
	default:
		return -1;
	}
}

/*
 * Does a basic block depend on the pseudos that "src" defines?
 */
static int bb_depends_on(struct basic_block *target, struct basic_block *src)
{
	pseudo_t pseudo;

	FOR_EACH_PTR(src->defines, pseudo) {
		if (pseudo_in_list(target->needs, pseudo))
			return 1;
	} END_FOR_EACH_PTR(pseudo);
	return 0;
}

/*
 * This really should be handled by bb_depends_on()
 * which efficiently check the dependence using the
 * defines - needs liveness info. Problem is that
 * there is no liveness done on OP_PHI & OP_PHISRC.
 *
 * This function add the missing dependency checks.
 */
static int bb_depends_on_phi(struct basic_block *target, struct basic_block *src)
{
	struct instruction *insn;
	FOR_EACH_PTR(src->insns, insn) {
		if (!insn->bb)
			continue;
		if (insn->opcode != OP_PHI)
			continue;
		if (pseudo_in_list(target->needs, insn->target))
			return 1;
	} END_FOR_EACH_PTR(insn);
	return 0;
}

/*
 * When we reach here, we have:
 *  - a basic block that ends in a conditional branch and
 *    that has no side effects apart from the pseudos it
 *    may change.
 *  - the phi-node that the conditional branch depends on
 *  - full pseudo liveness information
 *
 * We need to check if any of the _sources_ of the phi-node
 * may be constant, and not actually need this block at all.
 */
static int try_to_simplify_bb(struct basic_block *bb, struct instruction *first, struct instruction *second)
{
	int changed = 0;
	pseudo_t phi;
	int bogus;

	/*
	 * This a due to improper dominance tracking during
	 * simplify_symbol_usage()/conversion to SSA form.
	 * No sane simplification can be done when we have this.
	 */
	bogus = bb_list_size(bb->parents) != pseudo_list_size(first->phi_list);

	FOR_EACH_PTR(first->phi_list, phi) {
		struct instruction *def = phi->def;
		struct basic_block *source, *target;
		pseudo_t pseudo;
		struct instruction *br;
		int true;

		if (!def)
			continue;
		source = def->bb;
		pseudo = def->src1;
		if (!pseudo || !source)
			continue;
		br = last_instruction(source->insns);
		if (!br)
			continue;
		if (br->opcode != OP_CBR && br->opcode != OP_BR)
			continue;
		true = pseudo_truth_value(pseudo);
		if (true < 0)
			continue;
		target = true ? second->bb_true : second->bb_false;
		if (bb_depends_on(target, bb))
			continue;
		if (bb_depends_on_phi(target, bb))
			continue;
		changed |= rewrite_branch(source, &br->bb_true, bb, target);
		changed |= rewrite_branch(source, &br->bb_false, bb, target);
		if (changed && !bogus)
			kill_use(THIS_ADDRESS(phi));
	} END_FOR_EACH_PTR(phi);
	return changed;
}

static int bb_has_side_effects(struct basic_block *bb)
{
	struct instruction *insn;
	FOR_EACH_PTR(bb->insns, insn) {
		switch (insn->opcode) {
		case OP_CALL:
			/* FIXME! This should take "const" etc into account */
			return 1;

		case OP_STORE:
		case OP_CONTEXT:
			return 1;

		case OP_ASM:
			/* FIXME! This should take "volatile" etc into account */
			return 1;

		default:
			continue;
		}
	} END_FOR_EACH_PTR(insn);
	return 0;
}

static int simplify_phi_branch(struct basic_block *bb, struct instruction *br)
{
	pseudo_t cond = br->cond;
	struct instruction *def;

	if (cond->type != PSEUDO_REG)
		return 0;
	def = cond->def;
	if (def->bb != bb || def->opcode != OP_PHI)
		return 0;
	if (bb_has_side_effects(bb))
		return 0;
	return try_to_simplify_bb(bb, def, br);
}

static int simplify_branch_branch(struct basic_block *bb, struct instruction *br,
	struct basic_block **target_p, int true)
{
	struct basic_block *target = *target_p, *final;
	struct instruction *insn;
	int retval;

	if (target == bb)
		return 0;
	insn = last_instruction(target->insns);
	if (!insn || insn->opcode != OP_CBR || insn->cond != br->cond)
		return 0;
	/*
	 * Ahhah! We've found a branch to a branch on the same conditional!
	 * Now we just need to see if we can rewrite the branch..
	 */
	retval = 0;
	final = true ? insn->bb_true : insn->bb_false;
	if (bb_has_side_effects(target))
		goto try_to_rewrite_target;
	if (bb_depends_on(final, target))
		goto try_to_rewrite_target;
	if (bb_depends_on_phi(final, target))
		return 0;
	return rewrite_branch(bb, target_p, target, final);

try_to_rewrite_target:
	/*
	 * If we're the only parent, at least we can rewrite the
	 * now-known second branch.
	 */
	if (bb_list_size(target->parents) != 1)
		return retval;
	insert_branch(target, insn, final);
	return 1;
}

static int simplify_one_branch(struct basic_block *bb, struct instruction *br)
{
	if (simplify_phi_branch(bb, br))
		return 1;
	return simplify_branch_branch(bb, br, &br->bb_true, 1) |
	       simplify_branch_branch(bb, br, &br->bb_false, 0);
}

static int simplify_branch_nodes(struct entrypoint *ep)
{
	int changed = 0;
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *br = last_instruction(bb->insns);

		if (!br || br->opcode != OP_CBR)
			continue;
		changed |= simplify_one_branch(bb, br);
	} END_FOR_EACH_PTR(bb);
	return changed;
}

/*
 * This is called late - when we have intra-bb liveness information..
 */
int simplify_flow(struct entrypoint *ep)
{
	return simplify_branch_nodes(ep);
}

static inline void concat_user_list(struct pseudo_user_list *src, struct pseudo_user_list **dst)
{
	concat_ptr_list((struct ptr_list *)src, (struct ptr_list **)dst);
}

void convert_instruction_target(struct instruction *insn, pseudo_t src)
{
	pseudo_t target;
	struct pseudo_user *pu;
	/*
	 * Go through the "insn->users" list and replace them all..
	 */
	target = insn->target;
	if (target == src)
		return;
	FOR_EACH_PTR(target->users, pu) {
		if (*pu->userp != VOID) {
			assert(*pu->userp == target);
			*pu->userp = src;
		}
	} END_FOR_EACH_PTR(pu);
	if (has_use_list(src))
		concat_user_list(target->users, &src->users);
	target->users = NULL;
}

void convert_load_instruction(struct instruction *insn, pseudo_t src)
{
	convert_instruction_target(insn, src);
	/* Turn the load into a no-op */
	insn->opcode = OP_LNOP;
	insn->bb = NULL;
}

static int overlapping_memop(struct instruction *a, struct instruction *b)
{
	unsigned int a_start = bytes_to_bits(a->offset);
	unsigned int b_start = bytes_to_bits(b->offset);
	unsigned int a_size = a->size;
	unsigned int b_size = b->size;

	if (a_size + a_start <= b_start)
		return 0;
	if (b_size + b_start <= a_start)
		return 0;
	return 1;
}

static inline int same_memop(struct instruction *a, struct instruction *b)
{
	return	a->offset == b->offset && a->size == b->size;
}

static inline int distinct_symbols(pseudo_t a, pseudo_t b)
{
	if (a->type != PSEUDO_SYM)
		return 0;
	if (b->type != PSEUDO_SYM)
		return 0;
	return a->sym != b->sym;
}

/*
 * Return 1 if "dom" dominates the access to "pseudo"
 * in "insn".
 *
 * Return 0 if it doesn't, and -1 if you don't know.
 */
int dominates(pseudo_t pseudo, struct instruction *insn, struct instruction *dom, int local)
{
	int opcode = dom->opcode;

	if (opcode == OP_CALL || opcode == OP_ENTRY)
		return local ? 0 : -1;
	if (opcode != OP_LOAD && opcode != OP_STORE)
		return 0;
	if (dom->src != pseudo) {
		if (local)
			return 0;
		/* We don't think two explicitly different symbols ever alias */
		if (distinct_symbols(insn->src, dom->src))
			return 0;
		/* We could try to do some alias analysis here */
		return -1;
	}
	if (!same_memop(insn, dom)) {
		if (dom->opcode == OP_LOAD)
			return 0;
		if (!overlapping_memop(insn, dom))
			return 0;
		return -1;
	}
	return 1;
}

static int phisrc_in_bb(struct pseudo_list *list, struct basic_block *bb)
{
	pseudo_t p;
	FOR_EACH_PTR(list, p) {
		if (p->def->bb == bb)
			return 1;
	} END_FOR_EACH_PTR(p);

	return 0;
}

static int find_dominating_parents(pseudo_t pseudo, struct instruction *insn,
	struct basic_block *bb, unsigned long generation, struct pseudo_list **dominators,
	int local)
{
	struct basic_block *parent;

	if (!bb->parents)
		return !!local;

	FOR_EACH_PTR(bb->parents, parent) {
		struct instruction *one;
		struct instruction *br;
		pseudo_t phi;

		FOR_EACH_PTR_REVERSE(parent->insns, one) {
			int dominance;
			if (one == insn)
				goto no_dominance;
			dominance = dominates(pseudo, insn, one, local);
			if (dominance < 0) {
				if (one->opcode == OP_LOAD)
					continue;
				return 0;
			}
			if (!dominance)
				continue;
			goto found_dominator;
		} END_FOR_EACH_PTR_REVERSE(one);
no_dominance:
		if (parent->generation == generation)
			continue;
		parent->generation = generation;

		if (!find_dominating_parents(pseudo, insn, parent, generation, dominators, local))
			return 0;
		continue;

found_dominator:
		if (dominators && phisrc_in_bb(*dominators, parent))
			continue;
		br = delete_last_instruction(&parent->insns);
		phi = alloc_phi(parent, one->target, one->size);
		phi->ident = phi->ident ? : pseudo->ident;
		add_instruction(&parent->insns, br);
		use_pseudo(insn, phi, add_pseudo(dominators, phi));
	} END_FOR_EACH_PTR(parent);
	return 1;
}		

/*
 * We should probably sort the phi list just to make it easier to compare
 * later for equality. 
 */
void rewrite_load_instruction(struct instruction *insn, struct pseudo_list *dominators)
{
	pseudo_t new, phi;

	/*
	 * Check for somewhat common case of duplicate
	 * phi nodes.
	 */
	new = first_pseudo(dominators)->def->src1;
	FOR_EACH_PTR(dominators, phi) {
		if (new != phi->def->src1)
			goto complex_phi;
		new->ident = new->ident ? : phi->ident;
	} END_FOR_EACH_PTR(phi);

	/*
	 * All the same pseudo - mark the phi-nodes unused
	 * and convert the load into a LNOP and replace the
	 * pseudo.
	 */
	FOR_EACH_PTR(dominators, phi) {
		kill_instruction(phi->def);
	} END_FOR_EACH_PTR(phi);
	convert_load_instruction(insn, new);
	return;

complex_phi:
	/* We leave symbol pseudos with a bogus usage list here */
	if (insn->src->type != PSEUDO_SYM)
		kill_use(&insn->src);
	insn->opcode = OP_PHI;
	insn->phi_list = dominators;
}

static int find_dominating_stores(pseudo_t pseudo, struct instruction *insn,
	unsigned long generation, int local)
{
	struct basic_block *bb = insn->bb;
	struct instruction *one, *dom = NULL;
	struct pseudo_list *dominators;
	int partial;

	/* Unreachable load? Undo it */
	if (!bb) {
		insn->opcode = OP_LNOP;
		return 1;
	}

	partial = 0;
	FOR_EACH_PTR(bb->insns, one) {
		int dominance;
		if (one == insn)
			goto found;
		dominance = dominates(pseudo, insn, one, local);
		if (dominance < 0) {
			/* Ignore partial load dominators */
			if (one->opcode == OP_LOAD)
				continue;
			dom = NULL;
			partial = 1;
			continue;
		}
		if (!dominance)
			continue;
		dom = one;
		partial = 0;
	} END_FOR_EACH_PTR(one);
	/* Whaa? */
	warning(pseudo->sym->pos, "unable to find symbol read");
	return 0;
found:
	if (partial)
		return 0;

	if (dom) {
		convert_load_instruction(insn, dom->target);
		return 1;
	}

	/* OK, go find the parents */
	bb->generation = generation;

	dominators = NULL;
	if (!find_dominating_parents(pseudo, insn, bb, generation, &dominators, local))
		return 0;

	/* This happens with initial assignments to structures etc.. */
	if (!dominators) {
		if (!local)
			return 0;
		check_access(insn);
		convert_load_instruction(insn, value_pseudo(insn->type, 0));
		return 1;
	}

	/*
	 * If we find just one dominating instruction, we
	 * can turn it into a direct thing. Otherwise we'll
	 * have to turn the load into a phi-node of the
	 * dominators.
	 */
	rewrite_load_instruction(insn, dominators);
	return 1;
}

static void kill_store(struct instruction *insn)
{
	if (insn) {
		insn->bb = NULL;
		insn->opcode = OP_SNOP;
		kill_use(&insn->target);
	}
}

/* Kill a pseudo that is dead on exit from the bb */
static void kill_dead_stores(pseudo_t pseudo, unsigned long generation, struct basic_block *bb, int local)
{
	struct instruction *insn;
	struct basic_block *parent;

	if (bb->generation == generation)
		return;
	bb->generation = generation;
	FOR_EACH_PTR_REVERSE(bb->insns, insn) {
		int opcode = insn->opcode;

		if (opcode != OP_LOAD && opcode != OP_STORE) {
			if (local)
				continue;
			if (opcode == OP_CALL)
				return;
			continue;
		}
		if (insn->src == pseudo) {
			if (opcode == OP_LOAD)
				return;
			kill_store(insn);
			continue;
		}
		if (local)
			continue;
		if (insn->src->type != PSEUDO_SYM)
			return;
	} END_FOR_EACH_PTR_REVERSE(insn);

	FOR_EACH_PTR(bb->parents, parent) {
		struct basic_block *child;
		FOR_EACH_PTR(parent->children, child) {
			if (child && child != bb)
				return;
		} END_FOR_EACH_PTR(child);
		kill_dead_stores(pseudo, generation, parent, local);
	} END_FOR_EACH_PTR(parent);
}

/*
 * This should see if the "insn" trivially dominates some previous store, and kill the
 * store if unnecessary.
 */
static void kill_dominated_stores(pseudo_t pseudo, struct instruction *insn, 
	unsigned long generation, struct basic_block *bb, int local, int found)
{
	struct instruction *one;
	struct basic_block *parent;

	/* Unreachable store? Undo it */
	if (!bb) {
		kill_store(insn);
		return;
	}
	if (bb->generation == generation)
		return;
	bb->generation = generation;
	FOR_EACH_PTR_REVERSE(bb->insns, one) {
		int dominance;
		if (!found) {
			if (one != insn)
				continue;
			found = 1;
			continue;
		}
		dominance = dominates(pseudo, insn, one, local);
		if (!dominance)
			continue;
		if (dominance < 0)
			return;
		if (one->opcode == OP_LOAD)
			return;
		kill_store(one);
	} END_FOR_EACH_PTR_REVERSE(one);

	if (!found) {
		warning(bb->pos, "Unable to find instruction");
		return;
	}

	FOR_EACH_PTR(bb->parents, parent) {
		struct basic_block *child;
		FOR_EACH_PTR(parent->children, child) {
			if (child && child != bb)
				return;
		} END_FOR_EACH_PTR(child);
		kill_dominated_stores(pseudo, insn, generation, parent, local, found);
	} END_FOR_EACH_PTR(parent);
}

void check_access(struct instruction *insn)
{
	pseudo_t pseudo = insn->src;

	if (insn->bb && pseudo->type == PSEUDO_SYM) {
		int offset = insn->offset, bit = bytes_to_bits(offset) + insn->size;
		struct symbol *sym = pseudo->sym;

		if (sym->bit_size > 0 && (offset < 0 || bit > sym->bit_size))
			warning(insn->pos, "invalid access %s '%s' (%d %d)",
				offset < 0 ? "below" : "past the end of",
				show_ident(sym->ident), offset,
				bits_to_bytes(sym->bit_size));
	}
}

static void simplify_one_symbol(struct entrypoint *ep, struct symbol *sym)
{
	pseudo_t pseudo;
	struct pseudo_user *pu;
	unsigned long mod;
	int all;

	/* Never used as a symbol? */
	pseudo = sym->pseudo;
	if (!pseudo)
		return;

	/* We don't do coverage analysis of volatiles.. */
	if (sym->ctype.modifiers & MOD_VOLATILE)
		return;

	/* ..and symbols with external visibility need more care */
	mod = sym->ctype.modifiers & (MOD_NONLOCAL | MOD_STATIC | MOD_ADDRESSABLE);
	if (mod)
		goto external_visibility;

	FOR_EACH_PTR(pseudo->users, pu) {
		/* We know that the symbol-pseudo use is the "src" in the instruction */
		struct instruction *insn = pu->insn;

		switch (insn->opcode) {
		case OP_STORE:
			break;
		case OP_LOAD:
			break;
		case OP_SYMADDR:
			if (!insn->bb)
				continue;
			mod |= MOD_ADDRESSABLE;
			goto external_visibility;
		case OP_NOP:
		case OP_SNOP:
		case OP_LNOP:
		case OP_PHI:
			continue;
		default:
			warning(sym->pos, "symbol '%s' pseudo used in unexpected way", show_ident(sym->ident));
		}
	} END_FOR_EACH_PTR(pu);

external_visibility:
	all = 1;
	FOR_EACH_PTR_REVERSE(pseudo->users, pu) {
		struct instruction *insn = pu->insn;
		if (insn->opcode == OP_LOAD)
			all &= find_dominating_stores(pseudo, insn, ++bb_generation, !mod);
	} END_FOR_EACH_PTR_REVERSE(pu);

	/* If we converted all the loads, remove the stores. They are dead */
	if (all && !mod) {
		FOR_EACH_PTR(pseudo->users, pu) {
			struct instruction *insn = pu->insn;
			if (insn->opcode == OP_STORE)
				kill_store(insn);
		} END_FOR_EACH_PTR(pu);
	} else {
		/*
		 * If we couldn't take the shortcut, see if we can at least kill some
		 * of them..
		 */
		FOR_EACH_PTR(pseudo->users, pu) {
			struct instruction *insn = pu->insn;
			if (insn->opcode == OP_STORE)
				kill_dominated_stores(pseudo, insn, ++bb_generation, insn->bb, !mod, 0);
		} END_FOR_EACH_PTR(pu);

		if (!(mod & (MOD_NONLOCAL | MOD_STATIC))) {
			struct basic_block *bb;
			FOR_EACH_PTR(ep->bbs, bb) {
				if (!bb->children)
					kill_dead_stores(pseudo, ++bb_generation, bb, !mod);
			} END_FOR_EACH_PTR(bb);
		}
	}
			
	return;
}

void simplify_symbol_usage(struct entrypoint *ep)
{
	pseudo_t pseudo;

	FOR_EACH_PTR(ep->accesses, pseudo) {
		simplify_one_symbol(ep, pseudo->sym);
	} END_FOR_EACH_PTR(pseudo);
}

static void mark_bb_reachable(struct basic_block *bb, unsigned long generation)
{
	struct basic_block *child;

	if (bb->generation == generation)
		return;
	bb->generation = generation;
	FOR_EACH_PTR(bb->children, child) {
		mark_bb_reachable(child, generation);
	} END_FOR_EACH_PTR(child);
}

static void kill_defs(struct instruction *insn)
{
	pseudo_t target = insn->target;

	if (!has_use_list(target))
		return;
	if (target->def != insn)
		return;

	convert_instruction_target(insn, VOID);
}

void kill_bb(struct basic_block *bb)
{
	struct instruction *insn;
	struct basic_block *child, *parent;

	FOR_EACH_PTR(bb->insns, insn) {
		kill_instruction_force(insn);
		kill_defs(insn);
		/*
		 * We kill unreachable instructions even if they
		 * otherwise aren't "killable" (e.g. volatile loads)
		 */
	} END_FOR_EACH_PTR(insn);
	bb->insns = NULL;

	FOR_EACH_PTR(bb->children, child) {
		remove_bb_from_list(&child->parents, bb, 0);
	} END_FOR_EACH_PTR(child);
	bb->children = NULL;

	FOR_EACH_PTR(bb->parents, parent) {
		remove_bb_from_list(&parent->children, bb, 0);
	} END_FOR_EACH_PTR(parent);
	bb->parents = NULL;
}

void kill_unreachable_bbs(struct entrypoint *ep)
{
	struct basic_block *bb;
	unsigned long generation = ++bb_generation;

	mark_bb_reachable(ep->entry->bb, generation);
	FOR_EACH_PTR(ep->bbs, bb) {
		if (bb->generation == generation)
			continue;
		/* Mark it as being dead */
		kill_bb(bb);
		bb->ep = NULL;
		DELETE_CURRENT_PTR(bb);
	} END_FOR_EACH_PTR(bb);
	PACK_PTR_LIST(&ep->bbs);
}

static int rewrite_parent_branch(struct basic_block *bb, struct basic_block *old, struct basic_block *new)
{
	int changed = 0;
	struct instruction *insn = last_instruction(bb->insns);

	if (!insn)
		return 0;

	/* Infinite loops: let's not "optimize" them.. */
	if (old == new)
		return 0;

	switch (insn->opcode) {
	case OP_CBR:
		changed |= rewrite_branch(bb, &insn->bb_false, old, new);
		/* fall through */
	case OP_BR:
		changed |= rewrite_branch(bb, &insn->bb_true, old, new);
		assert(changed);
		return changed;
	case OP_SWITCH: {
		struct multijmp *jmp;
		FOR_EACH_PTR(insn->multijmp_list, jmp) {
			changed |= rewrite_branch(bb, &jmp->target, old, new);
		} END_FOR_EACH_PTR(jmp);
		assert(changed);
		return changed;
	}
	default:
		return 0;
	}
}

static struct basic_block * rewrite_branch_bb(struct basic_block *bb, struct instruction *br)
{
	struct basic_block *parent;
	struct basic_block *target = br->bb_true;
	struct basic_block *false = br->bb_false;

	if (br->opcode == OP_CBR) {
		pseudo_t cond = br->cond;
		if (cond->type != PSEUDO_VAL)
			return NULL;
		target = cond->value ? target : false;
	}

	/*
	 * We can't do FOR_EACH_PTR() here, because the parent list
	 * may change when we rewrite the parent.
	 */
	while ((parent = first_basic_block(bb->parents)) != NULL) {
		if (!rewrite_parent_branch(parent, bb, target))
			return NULL;
	}
	return target;
}

static void vrfy_bb_in_list(struct basic_block *bb, struct basic_block_list *list)
{
	if (bb) {
		struct basic_block *tmp;
		int no_bb_in_list = 0;

		FOR_EACH_PTR(list, tmp) {
			if (bb == tmp)
				return;
		} END_FOR_EACH_PTR(tmp);
		assert(no_bb_in_list);
	}
}

static void vrfy_parents(struct basic_block *bb)
{
	struct basic_block *tmp;
	FOR_EACH_PTR(bb->parents, tmp) {
		vrfy_bb_in_list(bb, tmp->children);
	} END_FOR_EACH_PTR(tmp);
}

static void vrfy_children(struct basic_block *bb)
{
	struct basic_block *tmp;
	struct instruction *br = last_instruction(bb->insns);

	if (!br) {
		assert(!bb->children);
		return;
	}
	switch (br->opcode) {
		struct multijmp *jmp;
	case OP_CBR:
		vrfy_bb_in_list(br->bb_false, bb->children);
		/* fall through */
	case OP_BR:
		vrfy_bb_in_list(br->bb_true, bb->children);
		break;
	case OP_SWITCH:
	case OP_COMPUTEDGOTO:
		FOR_EACH_PTR(br->multijmp_list, jmp) {
			vrfy_bb_in_list(jmp->target, bb->children);
		} END_FOR_EACH_PTR(jmp);
		break;
	default:
		break;
	}
		
	FOR_EACH_PTR(bb->children, tmp) {
		vrfy_bb_in_list(bb, tmp->parents);
	} END_FOR_EACH_PTR(tmp);
}

static void vrfy_bb_flow(struct basic_block *bb)
{
	vrfy_children(bb);
	vrfy_parents(bb);
}

void vrfy_flow(struct entrypoint *ep)
{
	struct basic_block *bb;
	struct basic_block *entry = ep->entry->bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		if (bb == entry)
			entry = NULL;
		vrfy_bb_flow(bb);
	} END_FOR_EACH_PTR(bb);
	assert(!entry);
}

void pack_basic_blocks(struct entrypoint *ep)
{
	struct basic_block *bb;

	/* See if we can merge a bb into another one.. */
	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *first, *insn;
		struct basic_block *parent, *child, *last;

		if (!bb_reachable(bb))
			continue;

		/*
		 * Just a branch?
		 */
		FOR_EACH_PTR(bb->insns, first) {
			if (!first->bb)
				continue;
			switch (first->opcode) {
			case OP_NOP: case OP_LNOP: case OP_SNOP:
				continue;
			case OP_CBR:
			case OP_BR: {
				struct basic_block *replace;
				replace = rewrite_branch_bb(bb, first);
				if (replace) {
					kill_bb(bb);
					goto no_merge;
				}
			}
			/* fallthrough */
			default:
				goto out;
			}
		} END_FOR_EACH_PTR(first);

out:
		/*
		 * See if we only have one parent..
		 */
		last = NULL;
		FOR_EACH_PTR(bb->parents, parent) {
			if (last) {
				if (last != parent)
					goto no_merge;
				continue;
			}
			last = parent;
		} END_FOR_EACH_PTR(parent);

		parent = last;
		if (!parent || parent == bb)
			continue;

		/*
		 * Goodie. See if the parent can merge..
		 */
		FOR_EACH_PTR(parent->children, child) {
			if (child != bb)
				goto no_merge;
		} END_FOR_EACH_PTR(child);

		/*
		 * Merge the two.
		 */
		repeat_phase |= REPEAT_CSE;

		parent->children = bb->children;
		bb->children = NULL;
		bb->parents = NULL;

		FOR_EACH_PTR(parent->children, child) {
			replace_bb_in_list(&child->parents, bb, parent, 0);
		} END_FOR_EACH_PTR(child);

		kill_instruction(delete_last_instruction(&parent->insns));
		FOR_EACH_PTR(bb->insns, insn) {
			if (insn->bb) {
				assert(insn->bb == bb);
				insn->bb = parent;
			}
			add_instruction(&parent->insns, insn);
		} END_FOR_EACH_PTR(insn);
		bb->insns = NULL;

	no_merge:
		/* nothing to do */;
	} END_FOR_EACH_PTR(bb);
}



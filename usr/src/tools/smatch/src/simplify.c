/*
 * Simplify - do instruction simplification before CSE
 *
 * Copyright (C) 2004 Linus Torvalds
 */

#include <assert.h>

#include "parse.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"
#include "symbol.h"

/* Find the trivial parent for a phi-source */
static struct basic_block *phi_parent(struct basic_block *source, pseudo_t pseudo)
{
	/* Can't go upwards if the pseudo is defined in the bb it came from.. */
	if (pseudo->type == PSEUDO_REG) {
		struct instruction *def = pseudo->def;
		if (def->bb == source)
			return source;
	}
	if (bb_list_size(source->children) != 1 || bb_list_size(source->parents) != 1)
		return source;
	return first_basic_block(source->parents);
}

/*
 * Copy the phi-node's phisrcs into to given array.
 * Returns 0 if the the list contained the expected
 * number of element, a positive number if there was
 * more than expected and a negative one if less.
 *
 * Note: we can't reuse a function like linearize_ptr_list()
 * because any VOIDs in the phi-list must be ignored here
 * as in this context they mean 'entry has been removed'.
 */
static int get_phisources(struct instruction *sources[], int nbr, struct instruction *insn)
{
	pseudo_t phi;
	int i = 0;

	assert(insn->opcode == OP_PHI);
	FOR_EACH_PTR(insn->phi_list, phi) {
		struct instruction *def;
		if (phi == VOID)
			continue;
		if (i >= nbr)
			return 1;
		def = phi->def;
		assert(def->opcode == OP_PHISOURCE);
		sources[i++] = def;
	} END_FOR_EACH_PTR(phi);
	return i - nbr;
}

static int if_convert_phi(struct instruction *insn)
{
	struct instruction *array[2];
	struct basic_block *parents[3];
	struct basic_block *bb, *bb1, *bb2, *source;
	struct instruction *br;
	pseudo_t p1, p2;

	bb = insn->bb;
	if (get_phisources(array, 2, insn))
		return 0;
	if (linearize_ptr_list((struct ptr_list *)bb->parents, (void **)parents, 3) != 2)
		return 0;
	p1 = array[0]->src1;
	bb1 = array[0]->bb;
	p2 = array[1]->src1;
	bb2 = array[1]->bb;

	/* Only try the simple "direct parents" case */
	if ((bb1 != parents[0] || bb2 != parents[1]) &&
	    (bb1 != parents[1] || bb2 != parents[0]))
		return 0;

	/*
	 * See if we can find a common source for this..
	 */
	source = phi_parent(bb1, p1);
	if (source != phi_parent(bb2, p2))
		return 0;

	/*
	 * Cool. We now know that 'source' is the exclusive
	 * parent of both phi-nodes, so the exit at the
	 * end of it fully determines which one it is, and
	 * we can turn it into a select.
	 *
	 * HOWEVER, right now we only handle regular
	 * conditional branches. No multijumps or computed
	 * stuff. Verify that here.
	 */
	br = last_instruction(source->insns);
	if (!br || br->opcode != OP_CBR)
		return 0;

	assert(br->cond);
	assert(br->bb_false);

	/*
	 * We're in business. Match up true/false with p1/p2.
	 */
	if (br->bb_true == bb2 || br->bb_false == bb1) {
		pseudo_t p = p1;
		p1 = p2;
		p2 = p;
	}

	/*
	 * OK, we can now replace that last
	 *
	 *	br cond, a, b
	 *
	 * with the sequence
	 *
	 *	setcc cond
	 *	select pseudo, p1, p2
	 *	br cond, a, b
	 *
	 * and remove the phi-node. If it then
	 * turns out that 'a' or 'b' is entirely
	 * empty (common case), and now no longer
	 * a phi-source, we'll be able to simplify
	 * the conditional branch too.
	 */
	insert_select(source, br, insn, p1, p2);
	kill_instruction(insn);
	return REPEAT_CSE;
}

static int clean_up_phi(struct instruction *insn)
{
	pseudo_t phi;
	struct instruction *last;
	int same;

	last = NULL;
	same = 1;
	FOR_EACH_PTR(insn->phi_list, phi) {
		struct instruction *def;
		if (phi == VOID)
			continue;
		def = phi->def;
		if (def->src1 == VOID || !def->bb)
			continue;
		if (last) {
			if (last->src1 != def->src1)
				same = 0;
			continue;
		}
		last = def;
	} END_FOR_EACH_PTR(phi);

	if (same) {
		pseudo_t pseudo = last ? last->src1 : VOID;
		convert_instruction_target(insn, pseudo);
		kill_instruction(insn);
		return REPEAT_CSE;
	}

	return if_convert_phi(insn);
}

static int delete_pseudo_user_list_entry(struct pseudo_user_list **list, pseudo_t *entry, int count)
{
	struct pseudo_user *pu;

	FOR_EACH_PTR(*list, pu) {
		if (pu->userp == entry) {
			MARK_CURRENT_DELETED(pu);
			if (!--count)
				goto out;
		}
	} END_FOR_EACH_PTR(pu);
	assert(count <= 0);
out:
	if (ptr_list_size((struct ptr_list *) *list) == 0)
		*list = NULL;
	return count;
}

static inline void remove_usage(pseudo_t p, pseudo_t *usep)
{
	if (has_use_list(p)) {
		delete_pseudo_user_list_entry(&p->users, usep, 1);
		if (!p->users)
			kill_instruction(p->def);
	}
}

void kill_use(pseudo_t *usep)
{
	if (usep) {
		pseudo_t p = *usep;
		*usep = VOID;
		remove_usage(p, usep);
	}
}

static void kill_use_list(struct pseudo_list *list)
{
	pseudo_t p;
	FOR_EACH_PTR(list, p) {
		if (p == VOID)
			continue;
		kill_use(THIS_ADDRESS(p));
	} END_FOR_EACH_PTR(p);
}

/*
 * kill an instruction:
 * - remove it from its bb
 * - remove the usage of all its operands
 * If forse is zero, the normal case, the function only for
 * instructions free of (possible) side-effects. Otherwise
 * the function does that unconditionally (must only be used
 * for unreachable instructions.
 */
void kill_insn(struct instruction *insn, int force)
{
	if (!insn || !insn->bb)
		return;

	switch (insn->opcode) {
	case OP_SEL:
	case OP_RANGE:
		kill_use(&insn->src3);
		/* fall through */

	case OP_BINARY ... OP_BINCMP_END:
		kill_use(&insn->src2);
		/* fall through */

	case OP_CAST:
	case OP_SCAST:
	case OP_FPCAST:
	case OP_PTRCAST:
	case OP_SETVAL:
	case OP_NOT: case OP_NEG:
	case OP_SLICE:
		kill_use(&insn->src1);
		break;

	case OP_PHI:
		kill_use_list(insn->phi_list);
		break;
	case OP_PHISOURCE:
		kill_use(&insn->phi_src);
		break;

	case OP_SYMADDR:
		repeat_phase |= REPEAT_SYMBOL_CLEANUP;
		break;

	case OP_CBR:
	case OP_COMPUTEDGOTO:
		kill_use(&insn->cond);
		break;

	case OP_CALL:
		if (!force) {
			/* a "pure" function can be killed too */
			if (!(insn->func->type == PSEUDO_SYM))
				return;
			if (!(insn->func->sym->ctype.modifiers & MOD_PURE))
				return;
		}
		kill_use_list(insn->arguments);
		if (insn->func->type == PSEUDO_REG)
			kill_use(&insn->func);
		break;

	case OP_LOAD:
		if (!force && insn->type->ctype.modifiers & MOD_VOLATILE)
			return;
		kill_use(&insn->src);
		break;

	case OP_STORE:
		if (!force)
			return;
		kill_use(&insn->src);
		kill_use(&insn->target);
		break;

	case OP_ENTRY:
		/* ignore */
		return;

	case OP_BR:
	default:
		break;
	}

	insn->bb = NULL;
	repeat_phase |= REPEAT_CSE;
	return;
}

/*
 * Kill trivially dead instructions
 */
static int dead_insn(struct instruction *insn, pseudo_t *src1, pseudo_t *src2, pseudo_t *src3)
{
	struct pseudo_user *pu;
	FOR_EACH_PTR(insn->target->users, pu) {
		if (*pu->userp != VOID)
			return 0;
	} END_FOR_EACH_PTR(pu);

	insn->bb = NULL;
	kill_use(src1);
	kill_use(src2);
	kill_use(src3);
	return REPEAT_CSE;
}

static inline int constant(pseudo_t pseudo)
{
	return pseudo->type == PSEUDO_VAL;
}

static int replace_with_pseudo(struct instruction *insn, pseudo_t pseudo)
{
	convert_instruction_target(insn, pseudo);

	switch (insn->opcode) {
	case OP_SEL:
	case OP_RANGE:
		kill_use(&insn->src3);
	case OP_BINARY ... OP_BINCMP_END:
		kill_use(&insn->src2);
	case OP_NOT:
	case OP_NEG:
	case OP_SYMADDR:
	case OP_CAST:
	case OP_SCAST:
	case OP_FPCAST:
	case OP_PTRCAST:
		kill_use(&insn->src1);
		break;

	default:
		assert(0);
	}
	insn->bb = NULL;
	return REPEAT_CSE;
}

unsigned int value_size(long long value)
{
	value >>= 8;
	if (!value)
		return 8;
	value >>= 8;
	if (!value)
		return 16;
	value >>= 16;
	if (!value)
		return 32;
	return 64;
}

/*
 * Try to determine the maximum size of bits in a pseudo.
 *
 * Right now this only follow casts and constant values, but we
 * could look at things like logical 'and' instructions etc.
 */
static unsigned int operand_size(struct instruction *insn, pseudo_t pseudo)
{
	unsigned int size = insn->size;

	if (pseudo->type == PSEUDO_REG) {
		struct instruction *src = pseudo->def;
		if (src && src->opcode == OP_CAST && src->orig_type) {
			unsigned int orig_size = src->orig_type->bit_size;
			if (orig_size < size)
				size = orig_size;
		}
	}
	if (pseudo->type == PSEUDO_VAL) {
		unsigned int orig_size = value_size(pseudo->value);
		if (orig_size < size)
			size = orig_size;
	}
	return size;
}

static int simplify_asr(struct instruction *insn, pseudo_t pseudo, long long value)
{
	unsigned int size = operand_size(insn, pseudo);

	if (value >= size) {
		warning(insn->pos, "right shift by bigger than source value");
		return replace_with_pseudo(insn, value_pseudo(insn->type, 0));
	}
	if (!value)
		return replace_with_pseudo(insn, pseudo);
	return 0;
}

static int simplify_mul_div(struct instruction *insn, long long value)
{
	unsigned long long sbit = 1ULL << (insn->size - 1);
	unsigned long long bits = sbit | (sbit - 1);

	if (value == 1)
		return replace_with_pseudo(insn, insn->src1);

	switch (insn->opcode) {
	case OP_MULS:
	case OP_MULU:
		if (value == 0)
			return replace_with_pseudo(insn, insn->src2);
	/* Fall through */
	case OP_DIVS:
		if (!(value & sbit))	// positive
			break;

		value |= ~bits;
		if (value == -1) {
			insn->opcode = OP_NEG;
			return REPEAT_CSE;
		}
	}

	return 0;
}

static int compare_opcode(int opcode, int inverse)
{
	if (!inverse)
		return opcode;

	switch (opcode) {
	case OP_SET_EQ:	return OP_SET_NE;
	case OP_SET_NE:	return OP_SET_EQ;

	case OP_SET_LT:	return OP_SET_GE;
	case OP_SET_LE:	return OP_SET_GT;
	case OP_SET_GT:	return OP_SET_LE;
	case OP_SET_GE:	return OP_SET_LT;

	case OP_SET_A:	return OP_SET_BE;
	case OP_SET_AE:	return OP_SET_B;
	case OP_SET_B:	return OP_SET_AE;
	case OP_SET_BE:	return OP_SET_A;

	default:
		return opcode;
	}
}

static int simplify_seteq_setne(struct instruction *insn, long long value)
{
	pseudo_t old = insn->src1;
	struct instruction *def = old->def;
	pseudo_t src1, src2;
	int inverse;
	int opcode;

	if (value != 0 && value != 1)
		return 0;

	if (!def)
		return 0;

	inverse = (insn->opcode == OP_SET_NE) == value;
	opcode = def->opcode;
	switch (opcode) {
	case OP_BINCMP ... OP_BINCMP_END:
		// Convert:
		//	setcc.n	%t <- %a, %b
		//	setne.m %r <- %t, $0
		// into:
		//	setcc.n	%t <- %a, %b
		//	setcc.m %r <- %a, $b
		// and similar for setne/eq ... 0/1
		src1 = def->src1;
		src2 = def->src2;
		insn->opcode = compare_opcode(opcode, inverse);
		use_pseudo(insn, src1, &insn->src1);
		use_pseudo(insn, src2, &insn->src2);
		remove_usage(old, &insn->src1);
		return REPEAT_CSE;

	default:
		return 0;
	}
}

static int simplify_constant_rightside(struct instruction *insn)
{
	long long value = insn->src2->value;

	switch (insn->opcode) {
	case OP_OR_BOOL:
		if (value == 1)
			return replace_with_pseudo(insn, insn->src2);
		goto case_neutral_zero;

	case OP_SUB:
		if (value) {
			insn->opcode = OP_ADD;
			insn->src2 = value_pseudo(insn->type, -value);
			return REPEAT_CSE;
		}
	/* Fall through */
	case OP_ADD:
	case OP_OR: case OP_XOR:
	case OP_SHL:
	case OP_LSR:
	case_neutral_zero:
		if (!value)
			return replace_with_pseudo(insn, insn->src1);
		return 0;
	case OP_ASR:
		return simplify_asr(insn, insn->src1, value);

	case OP_MODU: case OP_MODS:
		if (value == 1)
			return replace_with_pseudo(insn, value_pseudo(insn->type, 0));
		return 0;

	case OP_DIVU: case OP_DIVS:
	case OP_MULU: case OP_MULS:
		return simplify_mul_div(insn, value);

	case OP_AND_BOOL:
		if (value == 1)
			return replace_with_pseudo(insn, insn->src1);
	/* Fall through */
	case OP_AND:
		if (!value)
			return replace_with_pseudo(insn, insn->src2);
		return 0;

	case OP_SET_NE:
	case OP_SET_EQ:
		return simplify_seteq_setne(insn, value);
	}
	return 0;
}

static int simplify_constant_leftside(struct instruction *insn)
{
	long long value = insn->src1->value;

	switch (insn->opcode) {
	case OP_ADD: case OP_OR: case OP_XOR:
		if (!value)
			return replace_with_pseudo(insn, insn->src2);
		return 0;

	case OP_SHL:
	case OP_LSR: case OP_ASR:
	case OP_AND:
	case OP_MULU: case OP_MULS:
		if (!value)
			return replace_with_pseudo(insn, insn->src1);
		return 0;
	}
	return 0;
}

static int simplify_constant_binop(struct instruction *insn)
{
	/* FIXME! Verify signs and sizes!! */
	long long left = insn->src1->value;
	long long right = insn->src2->value;
	unsigned long long ul, ur;
	long long res, mask, bits;

	mask = 1ULL << (insn->size-1);
	bits = mask | (mask-1);

	if (left & mask)
		left |= ~bits;
	if (right & mask)
		right |= ~bits;
	ul = left & bits;
	ur = right & bits;

	switch (insn->opcode) {
	case OP_ADD:
		res = left + right;
		break;
	case OP_SUB:
		res = left - right;
		break;
	case OP_MULU:
		res = ul * ur;
		break;
	case OP_MULS:
		res = left * right;
		break;
	case OP_DIVU:
		if (!ur)
			return 0;
		res = ul / ur;
		break;
	case OP_DIVS:
		if (!right)
			return 0;
		if (left == mask && right == -1)
			return 0;
		res = left / right;
		break;
	case OP_MODU:
		if (!ur)
			return 0;
		res = ul % ur;
		break;
	case OP_MODS:
		if (!right)
			return 0;
		if (left == mask && right == -1)
			return 0;
		res = left % right;
		break;
	case OP_SHL:
		res = left << right;
		break;
	case OP_LSR:
		res = ul >> ur;
		break;
	case OP_ASR:
		res = left >> right;
		break;
       /* Logical */
	case OP_AND:
		res = left & right;
		break;
	case OP_OR:
		res = left | right;
		break;
	case OP_XOR:
		res = left ^ right;
		break;
	case OP_AND_BOOL:
		res = left && right;
		break;
	case OP_OR_BOOL:
		res = left || right;
		break;
			       
	/* Binary comparison */
	case OP_SET_EQ:
		res = left == right;
		break;
	case OP_SET_NE:
		res = left != right;
		break;
	case OP_SET_LE:
		res = left <= right;
		break;
	case OP_SET_GE:
		res = left >= right;
		break;
	case OP_SET_LT:
		res = left < right;
		break;
	case OP_SET_GT:
		res = left > right;
		break;
	case OP_SET_B:
		res = ul < ur;
		break;
	case OP_SET_A:
		res = ul > ur;
		break;
	case OP_SET_BE:
		res = ul <= ur;
		break;
	case OP_SET_AE:
		res = ul >= ur;
		break;
	default:
		return 0;
	}
	res &= bits;

	replace_with_pseudo(insn, value_pseudo(insn->type, res));
	return REPEAT_CSE;
}

static int simplify_binop_same_args(struct instruction *insn, pseudo_t arg)
{
	switch (insn->opcode) {
	case OP_SET_NE:
	case OP_SET_LT: case OP_SET_GT:
	case OP_SET_B:  case OP_SET_A:
		if (Wtautological_compare)
			warning(insn->pos, "self-comparison always evaluates to false");
	case OP_SUB:
	case OP_XOR:
		return replace_with_pseudo(insn, value_pseudo(insn->type, 0));

	case OP_SET_EQ:
	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_BE: case OP_SET_AE:
		if (Wtautological_compare)
			warning(insn->pos, "self-comparison always evaluates to true");
		return replace_with_pseudo(insn, value_pseudo(insn->type, 1));

	case OP_AND:
	case OP_OR:
		return replace_with_pseudo(insn, arg);

	case OP_AND_BOOL:
	case OP_OR_BOOL:
		remove_usage(arg, &insn->src2);
		insn->src2 = value_pseudo(insn->type, 0);
		insn->opcode = OP_SET_NE;
		return REPEAT_CSE;

	default:
		break;
	}

	return 0;
}

static int simplify_binop(struct instruction *insn)
{
	if (dead_insn(insn, &insn->src1, &insn->src2, NULL))
		return REPEAT_CSE;
	if (constant(insn->src1)) {
		if (constant(insn->src2))
			return simplify_constant_binop(insn);
		return simplify_constant_leftside(insn);
	}
	if (constant(insn->src2))
		return simplify_constant_rightside(insn);
	if (insn->src1 == insn->src2)
		return simplify_binop_same_args(insn, insn->src1);
	return 0;
}

static void switch_pseudo(struct instruction *insn1, pseudo_t *pp1, struct instruction *insn2, pseudo_t *pp2)
{
	pseudo_t p1 = *pp1, p2 = *pp2;

	use_pseudo(insn1, p2, pp1);
	use_pseudo(insn2, p1, pp2);
	remove_usage(p1, pp1);
	remove_usage(p2, pp2);
}

static int canonical_order(pseudo_t p1, pseudo_t p2)
{
	/* symbol/constants on the right */
	if (p1->type == PSEUDO_VAL)
		return p2->type == PSEUDO_VAL;

	if (p1->type == PSEUDO_SYM)
		return p2->type == PSEUDO_SYM || p2->type == PSEUDO_VAL;

	return 1;
}

static int simplify_commutative_binop(struct instruction *insn)
{
	if (!canonical_order(insn->src1, insn->src2)) {
		switch_pseudo(insn, &insn->src1, insn, &insn->src2);
		return REPEAT_CSE;
	}
	return 0;
}

static inline int simple_pseudo(pseudo_t pseudo)
{
	return pseudo->type == PSEUDO_VAL || pseudo->type == PSEUDO_SYM;
}

static int simplify_associative_binop(struct instruction *insn)
{
	struct instruction *def;
	pseudo_t pseudo = insn->src1;

	if (!simple_pseudo(insn->src2))
		return 0;
	if (pseudo->type != PSEUDO_REG)
		return 0;
	def = pseudo->def;
	if (def == insn)
		return 0;
	if (def->opcode != insn->opcode)
		return 0;
	if (!simple_pseudo(def->src2))
		return 0;
	if (ptr_list_size((struct ptr_list *)def->target->users) != 1)
		return 0;
	switch_pseudo(def, &def->src1, insn, &insn->src2);
	return REPEAT_CSE;
}

static int simplify_constant_unop(struct instruction *insn)
{
	long long val = insn->src1->value;
	long long res, mask;

	switch (insn->opcode) {
	case OP_NOT:
		res = ~val;
		break;
	case OP_NEG:
		res = -val;
		break;
	default:
		return 0;
	}
	mask = 1ULL << (insn->size-1);
	res &= mask | (mask-1);
	
	replace_with_pseudo(insn, value_pseudo(insn->type, res));
	return REPEAT_CSE;
}

static int simplify_unop(struct instruction *insn)
{
	if (dead_insn(insn, &insn->src1, NULL, NULL))
		return REPEAT_CSE;
	if (constant(insn->src1))
		return simplify_constant_unop(insn);

	switch (insn->opcode) {
		struct instruction *def;

	case OP_NOT:
		def = insn->src->def;
		if (def && def->opcode == OP_NOT)
			return replace_with_pseudo(insn, def->src);
		break;
	case OP_NEG:
		def = insn->src->def;
		if (def && def->opcode == OP_NEG)
			return replace_with_pseudo(insn, def->src);
		break;
	default:
		return 0;
	}
	return 0;
}

static int simplify_one_memop(struct instruction *insn, pseudo_t orig)
{
	pseudo_t addr = insn->src;
	pseudo_t new, off;

	if (addr->type == PSEUDO_REG) {
		struct instruction *def = addr->def;
		if (def->opcode == OP_SYMADDR && def->src) {
			kill_use(&insn->src);
			use_pseudo(insn, def->src, &insn->src);
			return REPEAT_CSE | REPEAT_SYMBOL_CLEANUP;
		}
		if (def->opcode == OP_ADD) {
			new = def->src1;
			off = def->src2;
			if (constant(off))
				goto offset;
			new = off;
			off = def->src1;
			if (constant(off))
				goto offset;
			return 0;
		}
	}
	return 0;

offset:
	/* Invalid code */
	if (new == orig) {
		if (new == VOID)
			return 0;
		/*
		 * If some BB have been removed it is possible that this
		 * memop is in fact part of a dead BB. In this case
		 * we must not warn since nothing is wrong.
		 * If not part of a dead BB this will be redone after
		 * the BBs have been cleaned up.
		 */
		if (repeat_phase & REPEAT_CFG_CLEANUP)
			return 0;
		new = VOID;
		warning(insn->pos, "crazy programmer");
	}
	insn->offset += off->value;
	use_pseudo(insn, new, &insn->src);
	remove_usage(addr, &insn->src);
	return REPEAT_CSE | REPEAT_SYMBOL_CLEANUP;
}

/*
 * We walk the whole chain of adds/subs backwards. That's not
 * only more efficient, but it allows us to find loops.
 */
static int simplify_memop(struct instruction *insn)
{
	int one, ret = 0;
	pseudo_t orig = insn->src;

	do {
		one = simplify_one_memop(insn, orig);
		ret |= one;
	} while (one);
	return ret;
}

static long long get_cast_value(long long val, int old_size, int new_size, int sign)
{
	long long mask;

	if (sign && new_size > old_size) {
		mask = 1 << (old_size-1);
		if (val & mask)
			val |= ~(mask | (mask-1));
	}
	mask = 1 << (new_size-1);
	return val & (mask | (mask-1));
}

static int simplify_cast(struct instruction *insn)
{
	struct symbol *orig_type;
	int orig_size, size;
	pseudo_t src;

	if (dead_insn(insn, &insn->src, NULL, NULL))
		return REPEAT_CSE;

	orig_type = insn->orig_type;
	if (!orig_type)
		return 0;

	/* Keep casts with pointer on either side (not only case of OP_PTRCAST) */
	if (is_ptr_type(orig_type) || is_ptr_type(insn->type))
		return 0;

	orig_size = orig_type->bit_size;
	size = insn->size;
	src = insn->src;

	/* A cast of a constant? */
	if (constant(src)) {
		int sign = orig_type->ctype.modifiers & MOD_SIGNED;
		long long val = get_cast_value(src->value, orig_size, size, sign);
		src = value_pseudo(orig_type, val);
		goto simplify;
	}

	/* A cast of a "and" might be a no-op.. */
	if (src->type == PSEUDO_REG) {
		struct instruction *def = src->def;
		if (def->opcode == OP_AND && def->size >= size) {
			pseudo_t val = def->src2;
			if (val->type == PSEUDO_VAL) {
				unsigned long long value = val->value;
				if (!(value >> (size-1)))
					goto simplify;
			}
		}
	}

	if (size == orig_size) {
		int op = (orig_type->ctype.modifiers & MOD_SIGNED) ? OP_SCAST : OP_CAST;
		if (insn->opcode == op)
			goto simplify;
		if (insn->opcode == OP_FPCAST && is_float_type(orig_type))
			goto simplify;
	}

	return 0;

simplify:
	return replace_with_pseudo(insn, src);
}

static int simplify_select(struct instruction *insn)
{
	pseudo_t cond, src1, src2;

	if (dead_insn(insn, &insn->src1, &insn->src2, &insn->src3))
		return REPEAT_CSE;

	cond = insn->src1;
	src1 = insn->src2;
	src2 = insn->src3;
	if (constant(cond) || src1 == src2) {
		pseudo_t *kill, take;
		kill_use(&insn->src1);
		take = cond->value ? src1 : src2;
		kill = cond->value ? &insn->src3 : &insn->src2;
		kill_use(kill);
		replace_with_pseudo(insn, take);
		return REPEAT_CSE;
	}
	if (constant(src1) && constant(src2)) {
		long long val1 = src1->value;
		long long val2 = src2->value;

		/* The pair 0/1 is special - replace with SETNE/SETEQ */
		if ((val1 | val2) == 1) {
			int opcode = OP_SET_EQ;
			if (val1) {
				src1 = src2;
				opcode = OP_SET_NE;
			}
			insn->opcode = opcode;
			/* insn->src1 is already cond */
			insn->src2 = src1; /* Zero */
			return REPEAT_CSE;
		}
	}
	return 0;
}

static int is_in_range(pseudo_t src, long long low, long long high)
{
	long long value;

	switch (src->type) {
	case PSEUDO_VAL:
		value = src->value;
		return value >= low && value <= high;
	default:
		return 0;
	}
}

static int simplify_range(struct instruction *insn)
{
	pseudo_t src1, src2, src3;

	src1 = insn->src1;
	src2 = insn->src2;
	src3 = insn->src3;
	if (src2->type != PSEUDO_VAL || src3->type != PSEUDO_VAL)
		return 0;
	if (is_in_range(src1, src2->value, src3->value)) {
		kill_instruction(insn);
		return REPEAT_CSE;
	}
	return 0;
}

/*
 * Simplify "set_ne/eq $0 + br"
 */
static int simplify_cond_branch(struct instruction *br, pseudo_t cond, struct instruction *def, pseudo_t *pp)
{
	use_pseudo(br, *pp, &br->cond);
	remove_usage(cond, &br->cond);
	if (def->opcode == OP_SET_EQ) {
		struct basic_block *true = br->bb_true;
		struct basic_block *false = br->bb_false;
		br->bb_false = true;
		br->bb_true = false;
	}
	return REPEAT_CSE;
}

static int simplify_branch(struct instruction *insn)
{
	pseudo_t cond = insn->cond;

	/* Constant conditional */
	if (constant(cond)) {
		insert_branch(insn->bb, insn, cond->value ? insn->bb_true : insn->bb_false);
		return REPEAT_CSE;
	}

	/* Same target? */
	if (insn->bb_true == insn->bb_false) {
		struct basic_block *bb = insn->bb;
		struct basic_block *target = insn->bb_false;
		remove_bb_from_list(&target->parents, bb, 1);
		remove_bb_from_list(&bb->children, target, 1);
		insn->bb_false = NULL;
		kill_use(&insn->cond);
		insn->cond = NULL;
		insn->opcode = OP_BR;
		return REPEAT_CSE;
	}

	/* Conditional on a SETNE $0 or SETEQ $0 */
	if (cond->type == PSEUDO_REG) {
		struct instruction *def = cond->def;

		if (def->opcode == OP_SET_NE || def->opcode == OP_SET_EQ) {
			if (constant(def->src1) && !def->src1->value)
				return simplify_cond_branch(insn, cond, def, &def->src2);
			if (constant(def->src2) && !def->src2->value)
				return simplify_cond_branch(insn, cond, def, &def->src1);
		}
		if (def->opcode == OP_SEL) {
			if (constant(def->src2) && constant(def->src3)) {
				long long val1 = def->src2->value;
				long long val2 = def->src3->value;
				if (!val1 && !val2) {
					insert_branch(insn->bb, insn, insn->bb_false);
					return REPEAT_CSE;
				}
				if (val1 && val2) {
					insert_branch(insn->bb, insn, insn->bb_true);
					return REPEAT_CSE;
				}
				if (val2) {
					struct basic_block *true = insn->bb_true;
					struct basic_block *false = insn->bb_false;
					insn->bb_false = true;
					insn->bb_true = false;
				}
				use_pseudo(insn, def->src1, &insn->cond);
				remove_usage(cond, &insn->cond);
				return REPEAT_CSE;
			}
		}
		if (def->opcode == OP_CAST || def->opcode == OP_SCAST) {
			int orig_size = def->orig_type ? def->orig_type->bit_size : 0;
			if (def->size > orig_size) {
				use_pseudo(insn, def->src, &insn->cond);
				remove_usage(cond, &insn->cond);
				return REPEAT_CSE;
			}
		}
	}
	return 0;
}

static int simplify_switch(struct instruction *insn)
{
	pseudo_t cond = insn->cond;
	long long val;
	struct multijmp *jmp;

	if (!constant(cond))
		return 0;
	val = insn->cond->value;

	FOR_EACH_PTR(insn->multijmp_list, jmp) {
		/* Default case */
		if (jmp->begin > jmp->end)
			goto found;
		if (val >= jmp->begin && val <= jmp->end)
			goto found;
	} END_FOR_EACH_PTR(jmp);
	warning(insn->pos, "Impossible case statement");
	return 0;

found:
	insert_branch(insn->bb, insn, jmp->target);
	return REPEAT_CSE;
}

int simplify_instruction(struct instruction *insn)
{
	if (!insn->bb)
		return 0;
	switch (insn->opcode) {
	case OP_ADD: case OP_MULS:
	case OP_AND: case OP_OR: case OP_XOR:
	case OP_AND_BOOL: case OP_OR_BOOL:
		if (simplify_binop(insn))
			return REPEAT_CSE;
		if (simplify_commutative_binop(insn))
			return REPEAT_CSE;
		return simplify_associative_binop(insn);

	case OP_MULU:
	case OP_SET_EQ: case OP_SET_NE:
		if (simplify_binop(insn))
			return REPEAT_CSE;
		return simplify_commutative_binop(insn);

	case OP_SUB:
	case OP_DIVU: case OP_DIVS:
	case OP_MODU: case OP_MODS:
	case OP_SHL:
	case OP_LSR: case OP_ASR:
	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_LT: case OP_SET_GT:
	case OP_SET_B:  case OP_SET_A:
	case OP_SET_BE: case OP_SET_AE:
		return simplify_binop(insn);

	case OP_NOT: case OP_NEG:
		return simplify_unop(insn);
	case OP_LOAD: case OP_STORE:
		return simplify_memop(insn);
	case OP_SYMADDR:
		if (dead_insn(insn, NULL, NULL, NULL))
			return REPEAT_CSE | REPEAT_SYMBOL_CLEANUP;
		return replace_with_pseudo(insn, insn->symbol);
	case OP_CAST:
	case OP_SCAST:
	case OP_FPCAST:
	case OP_PTRCAST:
		return simplify_cast(insn);
	case OP_PHI:
		if (dead_insn(insn, NULL, NULL, NULL)) {
			kill_use_list(insn->phi_list);
			return REPEAT_CSE;
		}
		return clean_up_phi(insn);
	case OP_PHISOURCE:
		if (dead_insn(insn, &insn->phi_src, NULL, NULL))
			return REPEAT_CSE;
		break;
	case OP_SEL:
		return simplify_select(insn);
	case OP_CBR:
		return simplify_branch(insn);
	case OP_SWITCH:
		return simplify_switch(insn);
	case OP_RANGE:
		return simplify_range(insn);
	}
	return 0;
}

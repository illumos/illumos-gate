/*
 * Simplify - do instruction simplification before CSE
 *
 * Copyright (C) 2004 Linus Torvalds
 */

///
// Instruction simplification
// --------------------------
//
// Notation
// ^^^^^^^^
// The following conventions are used to describe the simplications:
// * Uppercase letters are reserved for constants:
//   * `M` for a constant mask,
//   * `S` for a constant shift,
//   * `N` for a constant number of bits (usually other than a shift),
//   * `C` or 'K' for others constants.
// * Lowercase letters `a`, `b`, `x`, `y`, ... are used for non-constants
//   or when it doesn't matter if the pseudo is a constant or not.
// * Primes are used if needed to distinguish symbols (`M`, `M'`, ...).
// * Expressions or sub-expressions involving only constants are
//   understood to be evaluated.
// * `$mask(N)` is used for `((1 << N) -1)`
// * `$trunc(x, N)` is used for `(x & $mask(N))`
// * Expressions like `(-1 << S)`, `(-1 >> S)` and others formulae are
//   understood to be truncated to the size of the current instruction
//   (needed, since in general this size is not the same as the one used
//   by sparse for the evaluation of arithmetic operations).
// * `TRUNC(x, N)` is used for a truncation *to* a size of `N` bits
// * `ZEXT(x, N)` is used for a zero-extension *from* a size of `N` bits
// * `OP(x, C)` is used to represent some generic operation using a constant,
//   including when the constant is implicit (e.g. `TRUNC(x, N)`).
// * `MASK(x, M)` is used to respresent a 'masking' instruction:
//   - `AND(x, M)`
//   - `LSR(x, S)`, with `M` = (-1 << S)
//   - `SHL(x, S)`, with `M` = (-1 >> S)
//   - `TRUNC(x, N)`, with `M` = $mask(N)
//   - `ZEXT(x, N)`, with `M` = $mask(N)
// * `SHIFT(x, S)` is used for `LSR(x, S)` or `SHL(x, S)`.

#include <assert.h>

#include "parse.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"
#include "symbol.h"

///
// Utilities
// ^^^^^^^^^

///
// find the trivial parent for a phi-source
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

///
// copy the phi-node's phisrcs into to given array
// @return: 0 if the the list contained the expected
//	number of element, a positive number if there was
//	more than expected and a negative one if less.
//
// :note: we can't reuse a function like linearize_ptr_list()
//	because any VOIDs in the phi-list must be ignored here
//	as in this context they mean 'entry has been removed'.
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
	p1 = array[0]->phi_src;
	bb1 = array[0]->bb;
	p2 = array[1]->phi_src;
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

///
// detect trivial phi-nodes
// @insn: the phi-node
// @pseudo: the candidate resulting pseudo (NULL when starting)
// @return: the unique result if the phi-node is trivial, NULL otherwise
//
// A phi-node is trivial if it has a single possible result:
//	* all operands are the same
//	* the operands are themselves defined by a chain or cycle of phi-nodes
//		and the set of all operands involved contains a single value
//		not defined by these phi-nodes
//
// Since the result is unique, these phi-nodes can be removed.
static pseudo_t trivial_phi(pseudo_t pseudo, struct instruction *insn, struct pseudo_list **list)
{
	pseudo_t target = insn->target;
	pseudo_t phi;

	add_pseudo(list, target);

	FOR_EACH_PTR(insn->phi_list, phi) {
		struct instruction *def;
		pseudo_t src;

		if (phi == VOID)
			continue;
		def = phi->def;
		if (!def->bb)
			continue;
		src = def->phi_src; // bypass OP_PHISRC & get the real source
		if (src == VOID)
			continue;
		if (!pseudo) {
			pseudo = src;
			continue;
		}
		if (src == pseudo)
			continue;
		if (src == target)
			continue;
		if (DEF_OPCODE(def, src) == OP_PHI) {
			if (pseudo_in_list(*list, src))
				continue;
			if ((pseudo = trivial_phi(pseudo, def, list)))
				continue;
		}
		return NULL;
	} END_FOR_EACH_PTR(phi);

	return pseudo ? pseudo : VOID;
}

static int clean_up_phi(struct instruction *insn)
{
	struct pseudo_list *list = NULL;
	pseudo_t pseudo;

	if ((pseudo = trivial_phi(NULL, insn, &list))) {
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
	if (pseudo_user_list_empty(*list))
		*list = NULL;
	return count;
}

static inline void rem_usage(pseudo_t p, pseudo_t *usep, int kill)
{
	if (has_use_list(p)) {
		if (p->type == PSEUDO_SYM)
			repeat_phase |= REPEAT_SYMBOL_CLEANUP;
		delete_pseudo_user_list_entry(&p->users, usep, 1);
		if (kill && !p->users)
			kill_instruction(p->def);
	}
}

static inline void remove_usage(pseudo_t p, pseudo_t *usep)
{
	rem_usage(p, usep, 1);
}

void kill_use(pseudo_t *usep)
{
	if (usep) {
		pseudo_t p = *usep;
		*usep = VOID;
		rem_usage(p, usep, 1);
	}
}

// Like kill_use() but do not (recursively) kill dead instructions
void remove_use(pseudo_t *usep)
{
	pseudo_t p = *usep;
	*usep = VOID;
	rem_usage(p, usep, 0);
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

///
// kill an instruction
// @insn: the instruction to be killed
// @force: if unset, the normal case, the instruction is not killed
//	if not free of possible side-effect; if set the instruction
//	is unconditionally killed.
//
// The killed instruction is removed from its BB and the usage
// of all its operands are removed. The instruction is also
// marked as killed by setting its ->bb to NULL.
int kill_insn(struct instruction *insn, int force)
{
	if (!insn || !insn->bb)
		return 0;

	switch (insn->opcode) {
	case OP_SEL:
	case OP_RANGE:
		kill_use(&insn->src3);
		/* fall through */

	case OP_BINARY ... OP_BINCMP_END:
		kill_use(&insn->src2);
		/* fall through */

	case OP_UNOP ... OP_UNOP_END:
	case OP_SETVAL:
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
		kill_use(&insn->src);
		repeat_phase |= REPEAT_SYMBOL_CLEANUP;
		break;

	case OP_CBR:
	case OP_SWITCH:
	case OP_COMPUTEDGOTO:
		kill_use(&insn->cond);
		break;

	case OP_CALL:
		if (!force) {
			/* a "pure" function can be killed too */
			if (!(insn->func->type == PSEUDO_SYM))
				return 0;
			if (!(insn->func->sym->ctype.modifiers & MOD_PURE))
				return 0;
		}
		kill_use_list(insn->arguments);
		if (insn->func->type == PSEUDO_REG)
			kill_use(&insn->func);
		break;

	case OP_LOAD:
		if (!force && insn->is_volatile)
			return 0;
		kill_use(&insn->src);
		break;

	case OP_STORE:
		if (!force)
			return 0;
		kill_use(&insn->src);
		kill_use(&insn->target);
		break;

	case OP_ENTRY:
		/* ignore */
		return 0;

	case OP_BR:
	case OP_SETFVAL:
	default:
		break;
	}

	insn->bb = NULL;
	return repeat_phase |= REPEAT_CSE;
}

///
// kill trivially dead instructions
static int dead_insn(struct instruction *insn, pseudo_t *src1, pseudo_t *src2, pseudo_t *src3)
{
	if (has_users(insn->target))
		return 0;

	insn->bb = NULL;
	kill_use(src1);
	kill_use(src2);
	kill_use(src3);
	return REPEAT_CSE;
}

static inline bool has_target(struct instruction *insn)
{
	return opcode_table[insn->opcode].flags & OPF_TARGET;
}

void remove_dead_insns(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR_REVERSE(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR_REVERSE(bb->insns, insn) {
			if (!insn->bb)
				continue;
			if (!has_target(insn))
				continue;
			if (!has_users(insn->target))
				kill_instruction(insn);
		} END_FOR_EACH_PTR_REVERSE(insn);
	} END_FOR_EACH_PTR_REVERSE(bb);
}

static inline int constant(pseudo_t pseudo)
{
	return pseudo->type == PSEUDO_VAL;
}

///
// replace the operand of an instruction
// @insn: the instruction
// @pp: the address of the instruction's operand
// @new: the new value for the operand
// @return: REPEAT_CSE.
static inline int replace_pseudo(struct instruction *insn, pseudo_t *pp, pseudo_t new)
{
	pseudo_t old = *pp;
	use_pseudo(insn, new, pp);
	remove_usage(old, pp);
	return REPEAT_CSE;
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
	case OP_UNOP ... OP_UNOP_END:
	case OP_SYMADDR:
		kill_use(&insn->src1);
		break;

	default:
		assert(0);
	}
	insn->bb = NULL;
	return REPEAT_CSE;
}

static inline int def_opcode(pseudo_t p)
{
	if (p->type != PSEUDO_REG)
		return OP_BADOP;
	return p->def->opcode;
}

static unsigned int value_size(long long value)
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

///
// try to determine the maximum size of bits in a pseudo
//
// Right now this only follow casts and constant values, but we
// could look at things like AND instructions, etc.
static unsigned int operand_size(struct instruction *insn, pseudo_t pseudo)
{
	unsigned int size = insn->size;

	if (pseudo->type == PSEUDO_REG) {
		struct instruction *src = pseudo->def;
		if (src && src->opcode == OP_ZEXT && src->orig_type) {
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

static pseudo_t eval_insn(struct instruction *insn)
{
	/* FIXME! Verify signs and sizes!! */
	unsigned int size = insn->size;
	long long left = insn->src1->value;
	long long right = insn->src2->value;
	unsigned long long ul, ur;
	long long res, mask, bits;

	mask = 1ULL << (size-1);
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
	case OP_MUL:
		res = ul * ur;
		break;
	case OP_DIVU:
		if (!ur)
			goto undef;
		res = ul / ur;
		break;
	case OP_DIVS:
		if (!right)
			goto undef;
		if (left == mask && right == -1)
			goto undef;
		res = left / right;
		break;
	case OP_MODU:
		if (!ur)
			goto undef;
		res = ul % ur;
		break;
	case OP_MODS:
		if (!right)
			goto undef;
		if (left == mask && right == -1)
			goto undef;
		res = left % right;
		break;
	case OP_SHL:
		if (ur >= size)
			goto undef;
		res = left << right;
		break;
	case OP_LSR:
		if (ur >= size)
			goto undef;
		res = ul >> ur;
		break;
	case OP_ASR:
		if (ur >= size)
			goto undef;
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
		return NULL;
	}
	res &= bits;

	return value_pseudo(res);

undef:
	return NULL;
}

///
// Simplifications
// ^^^^^^^^^^^^^^^

///
// try to simplify MASK(OR(AND(x, M'), b), M)
// @insn: the masking instruction
// @mask: the associated mask (M)
// @ora: one of the OR's operands, guaranteed to be PSEUDO_REG
// @orb: the other OR's operand
// @return: 0 if no changes have been made, one or more REPEAT_* flags otherwise.
static int simplify_mask_or_and(struct instruction *insn, unsigned long long mask,
	pseudo_t ora, pseudo_t orb)
{
	unsigned long long omask, nmask;
	struct instruction *and = ora->def;
	pseudo_t src2 = and->src2;

	if (and->opcode != OP_AND)
		return 0;
	if (!constant(src2))
		return 0;
	omask = src2->value;
	nmask = omask & mask;
	if (nmask == 0) {
		// if (M' & M) == 0: ((a & M') | b) -> b
		return replace_pseudo(insn, &insn->src1, orb);
	}
	if (multi_users(insn->src1))
		return 0;	// can't modify anything inside the OR
	if (nmask == mask) {
		struct instruction *or = insn->src1->def;
		pseudo_t *arg = (ora == or->src1) ? &or->src1 : &or->src2;
		// if (M' & M) == M: ((a & M') | b) -> (a | b)
		return replace_pseudo(or, arg, and->src1);
	}
	if (nmask != omask && !multi_users(ora)) {
		// if (M' & M) != M': AND(a, M') -> AND(a, (M' & M))
		and->src2 = value_pseudo(nmask);
		return REPEAT_CSE;
	}
	return 0;
}

///
// try to simplify MASK(OR(a, b), M)
// @insn: the masking instruction
// @mask: the associated mask (M)
// @or: the OR instruction
// @return: 0 if no changes have been made, one or more REPEAT_* flags otherwise.
static int simplify_mask_or(struct instruction *insn, unsigned long long mask, struct instruction *or)
{
	pseudo_t src1 = or->src1;
	pseudo_t src2 = or->src2;
	int rc;

	if (src1->type == PSEUDO_REG) {
		if ((rc = simplify_mask_or_and(insn, mask, src1, src2)))
			return rc;
	}
	if (src2->type == PSEUDO_REG) {
		if ((rc = simplify_mask_or_and(insn, mask, src2, src1)))
			return rc;
	} else if (src2->type == PSEUDO_VAL) {
		unsigned long long oval = src2->value;
		unsigned long long nval = oval & mask;
		// Try to simplify:
		//	MASK(OR(x, C), M)
		if (nval == 0) {
			// if (C & M) == 0: OR(x, C) -> x
			return replace_pseudo(insn, &insn->src1, src1);
		}
		if (nval == mask) {
			// if (C & M) == M: OR(x, C) -> M
			return replace_pseudo(insn, &insn->src1, value_pseudo(mask));
		}
		if (nval != oval && !multi_users(or->target)) {
			// if (C & M) != C: OR(x, C) -> OR(x, (C & M))
			return replace_pseudo(or, &or->src2, value_pseudo(nval));
		}
	}
	return 0;
}

///
// try to simplify MASK(SHIFT(OR(a, b), S), M)
// @sh: the shift instruction
// @or: the OR instruction
// @mask: the mask associated to MASK (M):
// @return: 0 if no changes have been made, one or more REPEAT_* flags otherwise.
static int simplify_mask_shift_or(struct instruction *sh, struct instruction *or, unsigned long long mask)
{
	unsigned long long smask = bits_mask(sh->size);
	int shift = sh->src2->value;

	if (sh->opcode == OP_LSR)
		mask <<= shift;
	else
		mask >>= shift;
	return simplify_mask_or(sh, smask & mask, or);
}

static int simplify_mask_shift(struct instruction *sh, unsigned long long mask)
{
	struct instruction *inner;

	if (!constant(sh->src2) || sh->tainted)
		return 0;
	switch (DEF_OPCODE(inner, sh->src1)) {
	case OP_OR:
		if (!multi_users(sh->target))
			return simplify_mask_shift_or(sh, inner, mask);
		break;
	}
	return 0;
}

static long long check_shift_count(struct instruction *insn, unsigned long long uval)
{
	unsigned int size = insn->size;
	long long sval = uval;

	if (uval < size)
		return uval;

	sval = sign_extend_safe(sval, size);
	sval = sign_extend_safe(sval, bits_in_int);
	if (sval < 0)
		insn->src2 = value_pseudo(sval);
	if (insn->tainted)
		return sval;

	if (sval < 0 && Wshift_count_negative)
		warning(insn->pos, "shift count is negative (%lld)", sval);
	if (sval > 0 && Wshift_count_overflow) {
		struct symbol *ctype = insn->type;
		const char *tname;
		if (ctype->type == SYM_NODE)
			ctype = ctype->ctype.base_type;
		tname = show_typename(ctype);
		warning(insn->pos, "shift too big (%llu) for type %s", sval, tname);
	}
	insn->tainted = 1;
	return sval;
}

static int simplify_shift(struct instruction *insn, pseudo_t pseudo, long long value)
{
	struct instruction *def;
	unsigned long long mask, omask, nmask;
	unsigned long long nval;
	unsigned int size;
	pseudo_t src2;

	if (!value)
		return replace_with_pseudo(insn, pseudo);
	value = check_shift_count(insn, value);
	if (value < 0)
		return 0;

	size = insn->size;
	switch (insn->opcode) {
	case OP_ASR:
		if (value >= size)
			return 0;
		if (pseudo->type != PSEUDO_REG)
			break;
		def = pseudo->def;
		switch (def->opcode) {
		case OP_LSR:
		case OP_ASR:
			if (def == insn)	// cyclic DAG!
				break;
			src2 = def->src2;
			if (src2->type != PSEUDO_VAL)
				break;
			nval = src2->value;
			if (nval > insn->size || nval == 0)
				break;
			value += nval;
			if (def->opcode == OP_LSR)
				insn->opcode = OP_LSR;
			else if (value >= size)
				value = size - 1;
			goto new_value;

		case OP_ZEXT:
			// transform:
			//	zext.N	%t <- (O) %a
			//	asr.N	%r <- %t, C
			// into
			//	zext.N	%t <- (O) %a
			//	lsr.N	%r <- %t, C
			insn->opcode = OP_LSR;
			return REPEAT_CSE;
		}
		break;
	case OP_LSR:
		size = operand_size(insn, pseudo);
		if (value >= size)
			goto zero;
		switch(DEF_OPCODE(def, pseudo)) {
		case OP_AND:
			// replace (A & M) >> S
			// by      (A >> S) & (M >> S)
			if (!constant(def->src2))
				break;
			mask = bits_mask(insn->size - value) << value;
			omask = def->src2->value;
			nmask = omask & mask;
			if (nmask == 0)
				return replace_with_pseudo(insn, value_pseudo(0));
			if (nmask == mask)
				return replace_pseudo(insn, &insn->src1, def->src1);
			if (nbr_users(pseudo) > 1)
				break;
			def->opcode = OP_LSR;
			def->src2 = insn->src2;
			insn->opcode = OP_AND;
			insn->src2 = value_pseudo(omask >> value);
			return REPEAT_CSE;
		case OP_LSR:
			goto case_shift_shift;
		case OP_OR:
			mask = bits_mask(size);
			return simplify_mask_shift_or(insn, def, mask);
		case OP_SHL:
			// replace ((x << S) >> S)
			// by      (x & (-1 >> S))
			if (def->src2 != insn->src2)
				break;
			mask = bits_mask(insn->size - value);
			goto replace_mask;
		}
		break;
	case OP_SHL:
		if (value >= size)
			goto zero;
		switch(DEF_OPCODE(def, pseudo)) {
		case OP_AND:
			// simplify (A & M) << S
			if (!constant(def->src2))
				break;
			mask = bits_mask(insn->size) >> value;
			omask = def->src2->value;
			nmask = omask & mask;
			if (nmask == 0)
				return replace_with_pseudo(insn, value_pseudo(0));
			if (nmask == mask)
				return replace_pseudo(insn, &insn->src1, def->src1);
			// do not simplify into ((A << S) & (M << S))
			break;
		case OP_LSR:
			// replace ((x >> S) << S)
			// by      (x & (-1 << S))
			if (def->src2 != insn->src2)
				break;
			mask = bits_mask(insn->size - value) << value;
			goto replace_mask;
		case OP_OR:
			mask = bits_mask(size);
			return simplify_mask_shift_or(insn, def, mask);
		case OP_SHL:
		case_shift_shift:		// also for LSR - LSR
			if (def == insn)	// cyclic DAG!
				break;
			src2 = def->src2;
			if (src2->type != PSEUDO_VAL)
				break;
			nval = src2->value;
			if (nval > insn->size)
				break;
			value += nval;
			goto new_value;
		}
		break;
	}
	return 0;

new_value:
	if (value < size) {
		insn->src2 = value_pseudo(value);
		return replace_pseudo(insn, &insn->src1, pseudo->def->src1);
	}
zero:
	return replace_with_pseudo(insn, value_pseudo(0));
replace_mask:
	insn->opcode = OP_AND;
	insn->src2 = value_pseudo(mask);
	return replace_pseudo(insn, &insn->src1, def->src1);
}

static int simplify_mul_div(struct instruction *insn, long long value)
{
	unsigned long long sbit = 1ULL << (insn->size - 1);
	unsigned long long bits = sbit | (sbit - 1);

	if (value == 1)
		return replace_with_pseudo(insn, insn->src1);

	switch (insn->opcode) {
	case OP_MUL:
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

static int simplify_seteq_setne(struct instruction *insn, long long value)
{
	pseudo_t old = insn->src1;
	struct instruction *def;
	unsigned osize;
	int inverse;
	int opcode;

	if (value != 0 && value != 1)
		return 0;

	if (old->type != PSEUDO_REG)
		return 0;
	def = old->def;
	if (!def)
		return 0;

	inverse = (insn->opcode == OP_SET_NE) == value;
	if (!inverse && def->size == 1 && insn->size == 1) {
		// Replace:
		//	setne   %r <- %s, $0
		// or:
		//	seteq   %r <- %s, $1
		// by %s when boolean
		return replace_with_pseudo(insn, old);
	}
	opcode = def->opcode;
	switch (opcode) {
	case OP_AND:
		if (inverse)
			break;
		if (def->size != insn->size)
			break;
		if (def->src2->type != PSEUDO_VAL)
			break;
		if (def->src2->value != 1)
			break;
		return replace_with_pseudo(insn, old);
	case OP_FPCMP ... OP_BINCMP_END:
		// Convert:
		//	setcc.n	%t <- %a, %b
		//	setne.m %r <- %t, $0
		// into:
		//	setcc.n	%t <- %a, %b
		//	setcc.m %r <- %a, $b
		// and similar for setne/eq ... 0/1
		insn->opcode = inverse ? opcode_table[opcode].negate : opcode;
		use_pseudo(insn, def->src1, &insn->src1);
		use_pseudo(insn, def->src2, &insn->src2);
		remove_usage(old, &insn->src1);
		return REPEAT_CSE;

	case OP_SEXT:
		if (value && (def->orig_type->bit_size == 1))
			break;
		/* Fall through */
	case OP_ZEXT:
		// Convert:
		//	*ext.m	%s <- (1) %a
		//	setne.1 %r <- %s, $0
		// into:
		//	setne.1 %s <- %a, $0
		// and same for setne/eq ... 0/1
		return replace_pseudo(insn, &insn->src1, def->src);
	case OP_TRUNC:
		if (multi_users(old))
			break;
		// convert
		//	trunc.n	%s <- (o) %a
		//	setne.m %r <- %s, $0
		// into:
		//	and.o	%s <- %a, $((1 << o) - 1)
		//	setne.m %r <- %s, $0
		// and same for setne/eq ... 0/1
		osize = def->size;
		def->opcode = OP_AND;
		def->type = def->orig_type;
		def->size = def->type->bit_size;
		def->src2 = value_pseudo(bits_mask(osize));
		return REPEAT_CSE;
	}
	return 0;
}

static int simplify_constant_mask(struct instruction *insn, unsigned long long mask)
{
	pseudo_t old = insn->src1;
	unsigned long long omask;
	unsigned long long nmask;
	struct instruction *def;
	int osize;

	switch (DEF_OPCODE(def, old)) {
	case OP_FPCMP ... OP_BINCMP_END:
		osize = 1;
		goto oldsize;
	case OP_OR:
		return simplify_mask_or(insn, mask, def);
	case OP_LSR:
	case OP_SHL:
		return simplify_mask_shift(def, mask);
	case OP_ZEXT:
		osize = def->orig_type->bit_size;
		/* fall through */
	oldsize:
		omask = (1ULL << osize) - 1;
		nmask = mask & omask;
		if (nmask == omask)
			// the AND mask is redundant
			return replace_with_pseudo(insn, old);
		if (nmask != mask) {
			// can use a smaller mask
			insn->src2 = value_pseudo(nmask);
			return REPEAT_CSE;
		}
		break;
	}
	return 0;
}

static int simplify_constant_rightside(struct instruction *insn)
{
	long long value = insn->src2->value;
	long long sbit = 1ULL << (insn->size - 1);
	long long bits = sbit | (sbit - 1);

	switch (insn->opcode) {
	case OP_OR:
		if ((value & bits) == bits)
			return replace_with_pseudo(insn, insn->src2);
		goto case_neutral_zero;

	case OP_XOR:
		if ((value & bits) == bits) {
			insn->opcode = OP_NOT;
			return REPEAT_CSE;
		}
		goto case_neutral_zero;

	case OP_SUB:
		if (value) {
			insn->opcode = OP_ADD;
			insn->src2 = value_pseudo(-value);
			return REPEAT_CSE;
		}
	/* Fall through */
	case OP_ADD:
	case_neutral_zero:
		if (!value)
			return replace_with_pseudo(insn, insn->src1);
		return 0;
	case OP_ASR:
	case OP_SHL:
	case OP_LSR:
		return simplify_shift(insn, insn->src1, value);

	case OP_MODU: case OP_MODS:
		if (value == 1)
			return replace_with_pseudo(insn, value_pseudo(0));
		return 0;

	case OP_DIVU: case OP_DIVS:
	case OP_MUL:
		return simplify_mul_div(insn, value);

	case OP_AND:
		if (!value)
			return replace_with_pseudo(insn, insn->src2);
		if ((value & bits) == bits)
			return replace_with_pseudo(insn, insn->src1);
		return simplify_constant_mask(insn, value);

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
	case OP_MUL:
		if (!value)
			return replace_with_pseudo(insn, insn->src1);
		return 0;
	}
	return 0;
}

static int simplify_constant_binop(struct instruction *insn)
{
	pseudo_t res = eval_insn(insn);

	if (!res)
		return 0;

	replace_with_pseudo(insn, res);
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
		return replace_with_pseudo(insn, value_pseudo(0));

	case OP_SET_EQ:
	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_BE: case OP_SET_AE:
		if (Wtautological_compare)
			warning(insn->pos, "self-comparison always evaluates to true");
		return replace_with_pseudo(insn, value_pseudo(1));

	case OP_AND:
	case OP_OR:
		return replace_with_pseudo(insn, arg);

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

static int canonicalize_commutative(struct instruction *insn)
{
	if (canonical_order(insn->src1, insn->src2))
		return 0;

	switch_pseudo(insn, &insn->src1, insn, &insn->src2);
	return repeat_phase |= REPEAT_CSE;
}

static int canonicalize_compare(struct instruction *insn)
{
	if (canonical_order(insn->src1, insn->src2))
		return 0;

	switch_pseudo(insn, &insn->src1, insn, &insn->src2);
	insn->opcode = opcode_table[insn->opcode].swap;
	return repeat_phase |= REPEAT_CSE;
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
	if (multi_users(def->target))
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
	case OP_SEXT:
		mask = 1ULL << (insn->orig_type->bit_size-1);
		if (val & mask)
			val |= ~(mask | (mask-1));
		/* fall through */
	case OP_ZEXT:
	case OP_TRUNC:
		res = val;
		break;
	default:
		return 0;
	}
	mask = 1ULL << (insn->size-1);
	res &= mask | (mask-1);
	
	replace_with_pseudo(insn, value_pseudo(res));
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
	if (new == orig || new == addr) {
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
		warning(insn->pos, "crazy programmer");
		replace_pseudo(insn, &insn->src, VOID);
		return 0;
	}
	insn->offset += off->value;
	replace_pseudo(insn, &insn->src, new);
	return REPEAT_CSE | REPEAT_SYMBOL_CLEANUP;
}

///
// simplify memops instructions
//
// :note: We walk the whole chain of adds/subs backwards.
//	That's not only more efficient, but it allows us to find loops.
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

static int simplify_cast(struct instruction *insn)
{
	unsigned long long mask;
	struct instruction *def;
	pseudo_t src;
	pseudo_t val;
	int osize;
	int size;

	if (dead_insn(insn, &insn->src, NULL, NULL))
		return REPEAT_CSE;

	src = insn->src;

	/* A cast of a constant? */
	if (constant(src))
		return simplify_constant_unop(insn);

	// can merge with the previous instruction?
	size = insn->size;
	def = src->def;
	switch (def_opcode(src)) {
	case OP_AND:
		val = def->src2;
		if (val->type != PSEUDO_VAL)
			break;
		/* A cast of a AND might be a no-op.. */
		switch (insn->opcode) {
		case OP_TRUNC:
			if (multi_users(src))
				break;
			def->opcode = OP_TRUNC;
			def->orig_type = def->type;
			def->type = insn->type;
			def->size = size;

			insn->opcode = OP_AND;
			mask = val->value;
			mask &= (1ULL << size) - 1;
			insn->src2 = value_pseudo(mask);
			return REPEAT_CSE;

		case OP_SEXT:
			if (val->value & (1 << (def->size - 1)))
				break;
			// OK, sign bit is 0
		case OP_ZEXT:
			if (multi_users(src))
				break;
			// transform:
			//	and.n	%b <- %a, M
			//	*ext.m	%c <- (n) %b
			// into:
			//	zext.m	%b <- %a
			//	and.m	%c <- %b, M
			// For ZEXT, the mask will always be small
			// enough. For SEXT, it can only be done if
			// the mask force the sign bit to 0.
			def->opcode = OP_ZEXT;
			def->orig_type = insn->orig_type;
			def->type = insn->type;
			def->size = insn->size;
			insn->opcode = OP_AND;
			insn->src2 = val;
			return REPEAT_CSE;
		}
		break;
	case OP_FPCMP ... OP_BINCMP_END:
		switch (insn->opcode) {
		case OP_SEXT:
			if (insn->size == 1)
				break;
			/* fall through */
		case OP_ZEXT:
		case OP_TRUNC:
			// simplify:
			//	setcc.n	%t <- %a, %b
			//	zext.m	%r <- (n) %t
			// into:
			//	setcc.m	%r <- %a, %b
			// and same for s/zext/trunc/
			insn->opcode = def->opcode;
			use_pseudo(insn, def->src2, &insn->src2);
			return replace_pseudo(insn, &insn->src1, def->src1);
		}
		break;
	case OP_OR:
		switch (insn->opcode) {
		case OP_TRUNC:
			mask = bits_mask(insn->size);
			return simplify_mask_or(insn, mask, def);
		}
		break;
	case OP_LSR:
	case OP_SHL:
		if (insn->opcode != OP_TRUNC)
			break;
		mask = bits_mask(insn->size);
		return simplify_mask_shift(def, mask);
	case OP_TRUNC:
		switch (insn->opcode) {
		case OP_TRUNC:
			insn->orig_type = def->orig_type;
			return replace_pseudo(insn, &insn->src1, def->src);
		case OP_ZEXT:
			if (size != def->orig_type->bit_size)
				break;
			insn->opcode = OP_AND;
			insn->src2 = value_pseudo((1ULL << def->size) - 1);
			return replace_pseudo(insn, &insn->src1, def->src);
		}
		break;
	case OP_ZEXT:
		switch (insn->opcode) {
		case OP_SEXT:
			insn->opcode = OP_ZEXT;
			/* fall through */
		case OP_ZEXT:
			insn->orig_type = def->orig_type;
			return replace_pseudo(insn, &insn->src, def->src);
		}
		/* fall through */
	case OP_SEXT:
		switch (insn->opcode) {
		case OP_TRUNC:
			osize = def->orig_type->bit_size;
			if (size == osize)
				return replace_with_pseudo(insn, def->src);
			if (size > osize)
				insn->opcode = def->opcode;
			insn->orig_type = def->orig_type;
			return replace_pseudo(insn, &insn->src, def->src);
		}
		switch (insn->opcode) {
		case OP_SEXT:
			insn->orig_type = def->orig_type;
			return replace_pseudo(insn, &insn->src, def->src);
		}
		break;
	}

	return 0;
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
	if (cond == src2 && is_zero(src1)) {
		kill_use(&insn->src1);
		kill_use(&insn->src3);
		replace_with_pseudo(insn, value_pseudo(0));
		return REPEAT_CSE;
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

///
// simplify SET_NE/EQ $0 + BR
static int simplify_cond_branch(struct instruction *br, struct instruction *def, pseudo_t newcond)
{
	replace_pseudo(br, &br->cond, newcond);
	if (def->opcode == OP_SET_EQ) {
		struct basic_block *tmp = br->bb_true;
		br->bb_true = br->bb_false;
		br->bb_false = tmp;
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
				return simplify_cond_branch(insn, def, def->src2);
			if (constant(def->src2) && !def->src2->value)
				return simplify_cond_branch(insn, def, def->src1);
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
					struct basic_block *tmp = insn->bb_true;
					insn->bb_true = insn->bb_false;
					insn->bb_false = tmp;
				}
				return replace_pseudo(insn, &insn->cond, def->src1);
			}
		}
		if (def->opcode == OP_SEXT || def->opcode == OP_ZEXT)
			return replace_pseudo(insn, &insn->cond, def->src);
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
	case OP_ADD: case OP_MUL:
	case OP_AND: case OP_OR: case OP_XOR:
		canonicalize_commutative(insn);
		if (simplify_binop(insn))
			return REPEAT_CSE;
		return simplify_associative_binop(insn);

	case OP_SET_EQ: case OP_SET_NE:
		canonicalize_commutative(insn);
		return simplify_binop(insn);

	case OP_SET_LE: case OP_SET_GE:
	case OP_SET_LT: case OP_SET_GT:
	case OP_SET_B:  case OP_SET_A:
	case OP_SET_BE: case OP_SET_AE:
		canonicalize_compare(insn);
		/* fall through */
	case OP_SUB:
	case OP_DIVU: case OP_DIVS:
	case OP_MODU: case OP_MODS:
	case OP_SHL:
	case OP_LSR: case OP_ASR:
		return simplify_binop(insn);

	case OP_NOT: case OP_NEG: case OP_FNEG:
		return simplify_unop(insn);
	case OP_LOAD:
		if (!has_users(insn->target))
			return kill_instruction(insn);
		/* fall-through */
	case OP_STORE:
		return simplify_memop(insn);
	case OP_SYMADDR:
		if (dead_insn(insn, &insn->src, NULL, NULL))
			return REPEAT_CSE | REPEAT_SYMBOL_CLEANUP;
		return replace_with_pseudo(insn, insn->src);
	case OP_SEXT: case OP_ZEXT:
	case OP_TRUNC:
		return simplify_cast(insn);
	case OP_FCVTU: case OP_FCVTS:
	case OP_UCVTF: case OP_SCVTF:
	case OP_FCVTF:
	case OP_PTRCAST:
		if (dead_insn(insn, &insn->src, NULL, NULL))
			return REPEAT_CSE;
		break;
	case OP_UTPTR:
	case OP_PTRTU:
		return replace_with_pseudo(insn, insn->src);
	case OP_SLICE:
		if (dead_insn(insn, &insn->src, NULL, NULL))
			return REPEAT_CSE;
		break;
	case OP_SETVAL:
	case OP_SETFVAL:
		if (dead_insn(insn, NULL, NULL, NULL))
			return REPEAT_CSE;
		break;
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
	case OP_FADD:
	case OP_FSUB:
	case OP_FMUL:
	case OP_FDIV:
		if (dead_insn(insn, &insn->src1, &insn->src2, NULL))
			return REPEAT_CSE;
		break;
	}
	return 0;
}

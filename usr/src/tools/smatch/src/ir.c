// SPDX-License-Identifier: MIT

#include "ir.h"
#include "linearize.h"
#include <stdlib.h>
#include <assert.h>


static int nbr_phi_operands(struct instruction *insn)
{
	pseudo_t p;
	int nbr = 0;

	if (!insn->phi_list)
		return 0;

	FOR_EACH_PTR(insn->phi_list, p) {
		if (p == VOID)
			continue;
		nbr++;
	} END_FOR_EACH_PTR(p);

	return nbr;
}

static int check_phi_node(struct instruction *insn)
{
	struct basic_block *par;
	pseudo_t phi;
	int err = 0;

	if (!has_users(insn->target))
		return err;

	if (bb_list_size(insn->bb->parents) != nbr_phi_operands(insn)) {
		sparse_error(insn->pos, "bad number of phi operands in:\n\t%s",
			show_instruction(insn));
		info(insn->pos, "parents: %d", bb_list_size(insn->bb->parents));
		info(insn->pos, "phisrcs: %d", nbr_phi_operands(insn));
		return 1;
	}

	PREPARE_PTR_LIST(insn->bb->parents, par);
	FOR_EACH_PTR(insn->phi_list, phi) {
		struct instruction *src;
		if (phi == VOID)
			continue;
		assert(phi->type == PSEUDO_PHI);
		src = phi->def;
		if (src->bb != par) {
			sparse_error(src->pos, "wrong BB for %s:", show_instruction(src));
			info(src->pos, "expected: %s", show_label(par));
			info(src->pos, "     got: %s", show_label(src->bb));
			err++;
		}
		NEXT_PTR_LIST(par);
	} END_FOR_EACH_PTR(phi);
	FINISH_PTR_LIST(par);
	return err;
}

static int check_user(struct instruction *insn, pseudo_t pseudo)
{
	struct instruction *def;

	if (!pseudo) {
		show_entry(insn->bb->ep);
		sparse_error(insn->pos, "null pseudo in %s", show_instruction(insn));
		return 1;
	}
	switch (pseudo->type) {
	case PSEUDO_PHI:
	case PSEUDO_REG:
		def = pseudo->def;
		if (def && def->bb)
			break;
		show_entry(insn->bb->ep);
		sparse_error(insn->pos, "wrong usage for %s in %s", show_pseudo(pseudo),
			show_instruction(insn));
		return 1;

	default:
		break;
	}
	return 0;
}

static int check_branch(struct entrypoint *ep, struct instruction *insn, struct basic_block *bb)
{
	if (bb->ep && lookup_bb(ep->bbs, bb))
		return 0;
	sparse_error(insn->pos, "branch to dead BB: %s", show_instruction(insn));
	return 1;
}

static int check_switch(struct entrypoint *ep, struct instruction *insn)
{
	struct multijmp *jmp;
	int err = 0;

	FOR_EACH_PTR(insn->multijmp_list, jmp) {
		err = check_branch(ep, insn, jmp->target);
		if (err)
			return err;
	} END_FOR_EACH_PTR(jmp);

	return err;
}

static int check_return(struct instruction *insn)
{
	struct symbol *ctype = insn->type;

	if (ctype && ctype->bit_size > 0 && insn->src == VOID) {
		sparse_error(insn->pos, "return without value");
		return 1;
	}
	return 0;
}

static int validate_insn(struct entrypoint *ep, struct instruction *insn)
{
	int err = 0;

	switch (insn->opcode) {
	case OP_SEL:
	case OP_RANGE:
		err += check_user(insn, insn->src3);
		/* fall through */

	case OP_BINARY ... OP_BINCMP_END:
		err += check_user(insn, insn->src2);
		/* fall through */

	case OP_UNOP ... OP_UNOP_END:
	case OP_SLICE:
	case OP_SYMADDR:
	case OP_PHISOURCE:
		err += check_user(insn, insn->src1);
		break;

	case OP_CBR:
		err += check_branch(ep, insn, insn->bb_true);
		err += check_branch(ep, insn, insn->bb_false);
		/* fall through */
	case OP_COMPUTEDGOTO:
		err += check_user(insn, insn->cond);
		break;

	case OP_PHI:
		err += check_phi_node(insn);
		break;

	case OP_CALL:
		// FIXME: ignore for now
		break;

	case OP_STORE:
		err += check_user(insn, insn->target);
		/* fall through */

	case OP_LOAD:
		err += check_user(insn, insn->src);
		break;

	case OP_RET:
		err += check_return(insn);
		break;

	case OP_BR:
		err += check_branch(ep, insn, insn->bb_true);
		break;
	case OP_SWITCH:
		err += check_switch(ep, insn);
		break;

	case OP_ENTRY:
	case OP_SETVAL:
	default:
		break;
	}

	return err;
}

int ir_validate(struct entrypoint *ep)
{
	struct basic_block *bb;
	int err = 0;

	if (!dbg_ir || has_error)
		return 0;

	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR(bb->insns, insn) {
			if (!insn->bb)
				continue;
			err += validate_insn(ep, insn);
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);

	if (err)
		abort();
	return err;
}

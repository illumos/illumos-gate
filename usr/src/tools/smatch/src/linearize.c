/*
 * Linearize - walk the statement tree (but _not_ the expressions)
 * to generate a linear version of it and the basic blocks. 
 *
 * NOTE! We're not interested in the actual sub-expressions yet,
 * even though they can generate conditional branches and
 * subroutine calls. That's all "local" behaviour.
 *
 * Copyright (C) 2004 Linus Torvalds
 * Copyright (C) 2004 Christopher Li
 */

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "parse.h"
#include "expression.h"
#include "linearize.h"
#include "optimize.h"
#include "flow.h"
#include "target.h"

static pseudo_t linearize_statement(struct entrypoint *ep, struct statement *stmt);
static pseudo_t linearize_expression(struct entrypoint *ep, struct expression *expr);

static pseudo_t add_cast(struct entrypoint *ep, struct symbol *to, struct symbol *from, int op, pseudo_t src);
static pseudo_t add_binary_op(struct entrypoint *ep, struct symbol *ctype, int op, pseudo_t left, pseudo_t right);
static pseudo_t add_setval(struct entrypoint *ep, struct symbol *ctype, struct expression *val);
static pseudo_t linearize_one_symbol(struct entrypoint *ep, struct symbol *sym);

struct access_data;
static pseudo_t add_load(struct entrypoint *ep, struct access_data *);
static pseudo_t linearize_initializer(struct entrypoint *ep, struct expression *initializer, struct access_data *);
static pseudo_t cast_pseudo(struct entrypoint *ep, pseudo_t src, struct symbol *from, struct symbol *to);

struct pseudo void_pseudo = {};

static struct position current_pos;

ALLOCATOR(pseudo_user, "pseudo_user");

static struct instruction *alloc_instruction(int opcode, int size)
{
	struct instruction * insn = __alloc_instruction(0);
	insn->opcode = opcode;
	insn->size = size;
	insn->pos = current_pos;
	return insn;
}

static inline int type_size(struct symbol *type)
{
	return type ? type->bit_size > 0 ? type->bit_size : 0 : 0;
}

static struct instruction *alloc_typed_instruction(int opcode, struct symbol *type)
{
	struct instruction *insn = alloc_instruction(opcode, type_size(type));
	insn->type = type;
	return insn;
}

static struct entrypoint *alloc_entrypoint(void)
{
	return __alloc_entrypoint(0);
}

static struct basic_block *alloc_basic_block(struct entrypoint *ep, struct position pos)
{
	static int nr;
	struct basic_block *bb = __alloc_basic_block(0);
	bb->pos = pos;
	bb->ep = ep;
	bb->nr = nr++;
	return bb;
}

static struct multijmp *alloc_multijmp(struct basic_block *target, long long begin, long long end)
{
	struct multijmp *multijmp = __alloc_multijmp(0);
	multijmp->target = target;
	multijmp->begin = begin;
	multijmp->end = end;
	return multijmp;
}

const char *show_label(struct basic_block *bb)
{
	static int n;
	static char buffer[4][16];
	char *buf = buffer[3 & ++n];

	if (!bb)
		return ".L???";
	snprintf(buf, 64, ".L%u", bb->nr);
	return buf;
}

const char *show_pseudo(pseudo_t pseudo)
{
	static int n;
	static char buffer[4][64];
	char *buf;
	int i;

	if (!pseudo)
		return "no pseudo";
	if (pseudo == VOID)
		return "VOID";
	buf = buffer[3 & ++n];
	switch(pseudo->type) {
	case PSEUDO_SYM: {
		struct symbol *sym = pseudo->sym;
		struct expression *expr;

		if (!sym) {
			snprintf(buf, 64, "<bad symbol>");
			break;
		}
		if (sym->bb_target) {
			snprintf(buf, 64, "%s", show_label(sym->bb_target));
			break;
		}
		if (sym->ident) {
			snprintf(buf, 64, "%s", show_ident(sym->ident));
			break;
		}
		expr = sym->initializer;
		snprintf(buf, 64, "<anon symbol:%p>", verbose ? sym : NULL);
		if (expr) {
			switch (expr->type) {
			case EXPR_VALUE:
				snprintf(buf, 64, "<symbol value: %lld>", expr->value);
				break;
			case EXPR_STRING:
				return show_string(expr->string);
			default:
				break;
			}
		}
		break;
	}
	case PSEUDO_REG:
		i = snprintf(buf, 64, "%%r%d", pseudo->nr);
		if (pseudo->ident)
			sprintf(buf+i, "(%s)", show_ident(pseudo->ident));
		break;
	case PSEUDO_VAL: {
		long long value = pseudo->value;
		if (value > 1000 || value < -1000)
			snprintf(buf, 64, "$%#llx", value);
		else
			snprintf(buf, 64, "$%lld", value);
		break;
	}
	case PSEUDO_ARG:
		snprintf(buf, 64, "%%arg%d", pseudo->nr);
		break;
	case PSEUDO_PHI:
		i = snprintf(buf, 64, "%%phi%d", pseudo->nr);
		if (pseudo->ident)
			sprintf(buf+i, "(%s)", show_ident(pseudo->ident));
		break;
	case PSEUDO_UNDEF:
		return "UNDEF";
	default:
		snprintf(buf, 64, "<bad pseudo type %d>", pseudo->type);
	}
	return buf;
}

static const char *opcodes[] = {
	[OP_BADOP] = "bad_op",

	/* Fn entrypoint */
	[OP_ENTRY] = "<entry-point>",

	/* Terminator */
	[OP_RET] = "ret",
	[OP_BR] = "br",
	[OP_CBR] = "cbr",
	[OP_SWITCH] = "switch",
	[OP_COMPUTEDGOTO] = "jmp *",
	
	/* Binary */
	[OP_ADD] = "add",
	[OP_SUB] = "sub",
	[OP_MUL] = "mul",
	[OP_DIVU] = "divu",
	[OP_DIVS] = "divs",
	[OP_MODU] = "modu",
	[OP_MODS] = "mods",
	[OP_SHL] = "shl",
	[OP_LSR] = "lsr",
	[OP_ASR] = "asr",
	
	/* Floating-point Binary */
	[OP_FADD] = "fadd",
	[OP_FSUB] = "fsub",
	[OP_FMUL] = "fmul",
	[OP_FDIV] = "fdiv",

	/* Logical */
	[OP_AND] = "and",
	[OP_OR] = "or",
	[OP_XOR] = "xor",

	/* Binary comparison */
	[OP_SET_EQ] = "seteq",
	[OP_SET_NE] = "setne",
	[OP_SET_LE] = "setle",
	[OP_SET_GE] = "setge",
	[OP_SET_LT] = "setlt",
	[OP_SET_GT] = "setgt",
	[OP_SET_B] = "setb",
	[OP_SET_A] = "seta",
	[OP_SET_BE] = "setbe",
	[OP_SET_AE] = "setae",

	/* floating-point comparison */
	[OP_FCMP_ORD] = "fcmpord",
	[OP_FCMP_OEQ] = "fcmpoeq",
	[OP_FCMP_ONE] = "fcmpone",
	[OP_FCMP_OLE] = "fcmpole",
	[OP_FCMP_OGE] = "fcmpoge",
	[OP_FCMP_OLT] = "fcmpolt",
	[OP_FCMP_OGT] = "fcmpogt",
	[OP_FCMP_UEQ] = "fcmpueq",
	[OP_FCMP_UNE] = "fcmpune",
	[OP_FCMP_ULE] = "fcmpule",
	[OP_FCMP_UGE] = "fcmpuge",
	[OP_FCMP_ULT] = "fcmpult",
	[OP_FCMP_UGT] = "fcmpugt",
	[OP_FCMP_UNO] = "fcmpuno",

	/* Uni */
	[OP_NOT] = "not",
	[OP_NEG] = "neg",
	[OP_FNEG] = "fneg",

	/* Special three-input */
	[OP_SEL] = "select",
	
	/* Memory */
	[OP_LOAD] = "load",
	[OP_STORE] = "store",
	[OP_SETVAL] = "set",
	[OP_SETFVAL] = "setfval",
	[OP_SYMADDR] = "symaddr",

	/* Other */
	[OP_PHI] = "phi",
	[OP_PHISOURCE] = "phisrc",
	[OP_SEXT] = "sext",
	[OP_ZEXT] = "zext",
	[OP_TRUNC] = "trunc",
	[OP_FCVTU] = "fcvtu",
	[OP_FCVTS] = "fcvts",
	[OP_UCVTF] = "ucvtf",
	[OP_SCVTF] = "scvtf",
	[OP_FCVTF] = "fcvtf",
	[OP_UTPTR] = "utptr",
	[OP_PTRTU] = "ptrtu",
	[OP_PTRCAST] = "ptrcast",
	[OP_INLINED_CALL] = "# call",
	[OP_CALL] = "call",
	[OP_SLICE] = "slice",
	[OP_NOP] = "nop",
	[OP_DEATHNOTE] = "dead",
	[OP_ASM] = "asm",

	/* Sparse tagging (line numbers, context, whatever) */
	[OP_CONTEXT] = "context",
	[OP_RANGE] = "range-check",

	[OP_COPY] = "copy",
};

static char *show_asm_constraints(char *buf, const char *sep, struct asm_constraint_list *list)
{
	struct asm_constraint *entry;

	FOR_EACH_PTR(list, entry) {
		buf += sprintf(buf, "%s\"%s\"", sep, entry->constraint);
		if (entry->pseudo)
			buf += sprintf(buf, " (%s)", show_pseudo(entry->pseudo));
		if (entry->ident)
			buf += sprintf(buf, " [%s]", show_ident(entry->ident));
		sep = ", ";		
	} END_FOR_EACH_PTR(entry);
	return buf;
}

static char *show_asm(char *buf, struct instruction *insn)
{
	struct asm_rules *rules = insn->asm_rules;

	buf += sprintf(buf, "\"%s\"", insn->string);
	buf = show_asm_constraints(buf, "\n\t\tout: ", rules->outputs);
	buf = show_asm_constraints(buf, "\n\t\tin: ", rules->inputs);
	buf = show_asm_constraints(buf, "\n\t\tclobber: ", rules->clobbers);
	return buf;
}

const char *show_instruction(struct instruction *insn)
{
	int opcode = insn->opcode;
	static char buffer[4096];
	char *buf;

	buf = buffer;
	if (!insn->bb)
		buf += sprintf(buf, "# ");

	if (opcode < ARRAY_SIZE(opcodes)) {
		const char *op = opcodes[opcode];
		if (!op)
			buf += sprintf(buf, "opcode:%d", opcode);
		else
			buf += sprintf(buf, "%s", op);
		if (insn->size)
			buf += sprintf(buf, ".%d", insn->size);
		memset(buf, ' ', 20);
		buf++;
	}

	if (buf < buffer + 12)
		buf = buffer + 12;
	switch (opcode) {
	case OP_RET:
		if (insn->src && insn->src != VOID)
			buf += sprintf(buf, "%s", show_pseudo(insn->src));
		break;

	case OP_CBR:
		buf += sprintf(buf, "%s, %s, %s", show_pseudo(insn->cond), show_label(insn->bb_true), show_label(insn->bb_false));
		break;

	case OP_BR:
		buf += sprintf(buf, "%s", show_label(insn->bb_true));
		break;

	case OP_SETVAL: {
		struct expression *expr = insn->val;
		buf += sprintf(buf, "%s <- ", show_pseudo(insn->target));

		if (!expr) {
			buf += sprintf(buf, "%s", "<none>");
			break;
		}
			
		switch (expr->type) {
		case EXPR_VALUE:
			buf += sprintf(buf, "%lld", expr->value);
			break;
		case EXPR_FVALUE:
			buf += sprintf(buf, "%Le", expr->fvalue);
			break;
		case EXPR_STRING:
			buf += sprintf(buf, "%.40s", show_string(expr->string));
			break;
		case EXPR_SYMBOL:
			buf += sprintf(buf, "%s", show_ident(expr->symbol->ident));
			break;
		case EXPR_LABEL:
			buf += sprintf(buf, "%s", show_label(expr->symbol->bb_target));
			break;
		default:
			buf += sprintf(buf, "SETVAL EXPR TYPE %d", expr->type);
		}
		break;
	}
	case OP_SETFVAL:
		buf += sprintf(buf, "%s <- ", show_pseudo(insn->target));
		buf += sprintf(buf, "%Le", insn->fvalue);
		break;

	case OP_SWITCH: {
		struct multijmp *jmp;
		buf += sprintf(buf, "%s", show_pseudo(insn->cond));
		FOR_EACH_PTR(insn->multijmp_list, jmp) {
			if (jmp->begin == jmp->end)
				buf += sprintf(buf, ", %lld -> %s", jmp->begin, show_label(jmp->target));
			else if (jmp->begin < jmp->end)
				buf += sprintf(buf, ", %lld ... %lld -> %s", jmp->begin, jmp->end, show_label(jmp->target));
			else
				buf += sprintf(buf, ", default -> %s", show_label(jmp->target));
		} END_FOR_EACH_PTR(jmp);
		break;
	}
	case OP_COMPUTEDGOTO: {
		struct multijmp *jmp;
		buf += sprintf(buf, "%s", show_pseudo(insn->src));
		FOR_EACH_PTR(insn->multijmp_list, jmp) {
			buf += sprintf(buf, ", %s", show_label(jmp->target));
		} END_FOR_EACH_PTR(jmp);
		break;
	}

	case OP_PHISOURCE: {
		struct instruction *phi;
		buf += sprintf(buf, "%s <- %s    ", show_pseudo(insn->target), show_pseudo(insn->phi_src));
		FOR_EACH_PTR(insn->phi_users, phi) {
			buf += sprintf(buf, " (%s)", show_pseudo(phi->target));
		} END_FOR_EACH_PTR(phi);
		break;
	}

	case OP_PHI: {
		pseudo_t phi;
		const char *s = " <-";
		buf += sprintf(buf, "%s", show_pseudo(insn->target));
		FOR_EACH_PTR(insn->phi_list, phi) {
			if (phi == VOID && !verbose)
				continue;
			buf += sprintf(buf, "%s %s", s, show_pseudo(phi));
			s = ",";
		} END_FOR_EACH_PTR(phi);
		break;
	}	
	case OP_LOAD:
		buf += sprintf(buf, "%s <- %d[%s]", show_pseudo(insn->target), insn->offset, show_pseudo(insn->src));
		break;
	case OP_STORE:
		buf += sprintf(buf, "%s -> %d[%s]", show_pseudo(insn->target), insn->offset, show_pseudo(insn->src));
		break;
	case OP_INLINED_CALL:
	case OP_CALL: {
		struct pseudo *arg;
		if (insn->target && insn->target != VOID)
			buf += sprintf(buf, "%s <- ", show_pseudo(insn->target));
		buf += sprintf(buf, "%s", show_pseudo(insn->func));
		FOR_EACH_PTR(insn->arguments, arg) {
			buf += sprintf(buf, ", %s", show_pseudo(arg));
		} END_FOR_EACH_PTR(arg);
		break;
	}
	case OP_SEXT: case OP_ZEXT:
	case OP_TRUNC:
	case OP_FCVTU: case OP_FCVTS:
	case OP_UCVTF: case OP_SCVTF:
	case OP_FCVTF:
	case OP_UTPTR:
	case OP_PTRTU:
	case OP_PTRCAST:
		buf += sprintf(buf, "%s <- (%d) %s",
			show_pseudo(insn->target),
			type_size(insn->orig_type),
			show_pseudo(insn->src));
		break;
	case OP_BINARY ... OP_BINARY_END:
	case OP_FPCMP ... OP_FPCMP_END:
	case OP_BINCMP ... OP_BINCMP_END:
		buf += sprintf(buf, "%s <- %s, %s", show_pseudo(insn->target), show_pseudo(insn->src1), show_pseudo(insn->src2));
		break;

	case OP_SEL:
		buf += sprintf(buf, "%s <- %s, %s, %s", show_pseudo(insn->target),
			show_pseudo(insn->src1), show_pseudo(insn->src2), show_pseudo(insn->src3));
		break;

	case OP_SLICE:
		buf += sprintf(buf, "%s <- %s, %d, %d", show_pseudo(insn->target), show_pseudo(insn->base), insn->from, insn->len);
		break;

	case OP_NOT: case OP_NEG:
	case OP_FNEG:
	case OP_SYMADDR:
		buf += sprintf(buf, "%s <- %s", show_pseudo(insn->target), show_pseudo(insn->src1));
		break;

	case OP_CONTEXT:
		buf += sprintf(buf, "%s%d", insn->check ? "check: " : "", insn->increment);
		break;
	case OP_RANGE:
		buf += sprintf(buf, "%s between %s..%s", show_pseudo(insn->src1), show_pseudo(insn->src2), show_pseudo(insn->src3));
		break;
	case OP_NOP:
		buf += sprintf(buf, "%s <- %s", show_pseudo(insn->target), show_pseudo(insn->src1));
		break;
	case OP_DEATHNOTE:
		buf += sprintf(buf, "%s", show_pseudo(insn->target));
		break;
	case OP_ASM:
		buf = show_asm(buf, insn);
		break;
	case OP_COPY:
		buf += sprintf(buf, "%s <- %s", show_pseudo(insn->target), show_pseudo(insn->src));
		break;
	default:
		break;
	}

	if (buf >= buffer + sizeof(buffer))
		die("instruction buffer overflowed %td\n", buf - buffer);
	do { --buf; } while (*buf == ' ');
	*++buf = 0;
	return buffer;
}

void show_bb(struct basic_block *bb)
{
	struct instruction *insn;

	printf("%s:\n", show_label(bb));
	if (verbose) {
		pseudo_t needs, defines;
		printf("%s:%d\n", stream_name(bb->pos.stream), bb->pos.line);

		FOR_EACH_PTR(bb->needs, needs) {
			struct instruction *def = needs->def;
			if (def->opcode != OP_PHI) {
				printf("  **uses %s (from %s)**\n", show_pseudo(needs), show_label(def->bb));
			} else {
				pseudo_t phi;
				const char *sep = " ";
				printf("  **uses %s (from", show_pseudo(needs));
				FOR_EACH_PTR(def->phi_list, phi) {
					if (phi == VOID)
						continue;
					printf("%s(%s:%s)", sep, show_pseudo(phi), show_label(phi->def->bb));
					sep = ", ";
				} END_FOR_EACH_PTR(phi);		
				printf(")**\n");
			}
		} END_FOR_EACH_PTR(needs);

		FOR_EACH_PTR(bb->defines, defines) {
			printf("  **defines %s **\n", show_pseudo(defines));
		} END_FOR_EACH_PTR(defines);

		if (bb->parents) {
			struct basic_block *from;
			FOR_EACH_PTR(bb->parents, from) {
				printf("  **from %s (%s:%d:%d)**\n", show_label(from),
					stream_name(from->pos.stream), from->pos.line, from->pos.pos);
			} END_FOR_EACH_PTR(from);
		}

		if (bb->children) {
			struct basic_block *to;
			FOR_EACH_PTR(bb->children, to) {
				printf("  **to %s (%s:%d:%d)**\n", show_label(to),
					stream_name(to->pos.stream), to->pos.line, to->pos.pos);
			} END_FOR_EACH_PTR(to);
		}
	}

	FOR_EACH_PTR(bb->insns, insn) {
		if (!insn->bb && verbose < 2)
			continue;
		printf("\t%s\n", show_instruction(insn));
	} END_FOR_EACH_PTR(insn);
	if (!bb_terminated(bb))
		printf("\tEND\n");
}

static void show_symbol_usage(pseudo_t pseudo)
{
	struct pseudo_user *pu;

	if (pseudo) {
		FOR_EACH_PTR(pseudo->users, pu) {
			printf("\t%s\n", show_instruction(pu->insn));
		} END_FOR_EACH_PTR(pu);
	}
}

void show_entry(struct entrypoint *ep)
{
	struct symbol *sym;
	struct basic_block *bb;

	printf("%s:\n", show_ident(ep->name->ident));

	if (verbose) {
		printf("ep %p: %s\n", ep, show_ident(ep->name->ident));

		FOR_EACH_PTR(ep->syms, sym) {
			if (!sym->pseudo)
				continue;
			if (!sym->pseudo->users)
				continue;
			printf("   sym: %p %s\n", sym, show_ident(sym->ident));
			if (sym->ctype.modifiers & (MOD_EXTERN | MOD_STATIC | MOD_ADDRESSABLE))
				printf("\texternal visibility\n");
			show_symbol_usage(sym->pseudo);
		} END_FOR_EACH_PTR(sym);

		printf("\n");
	}

	FOR_EACH_PTR(ep->bbs, bb) {
		if (!bb)
			continue;
		if (!bb->parents && !bb->children && !bb->insns && verbose < 2)
			continue;
		show_bb(bb);
		printf("\n");
	} END_FOR_EACH_PTR(bb);

	printf("\n");
}

static void bind_label(struct symbol *label, struct basic_block *bb, struct position pos)
{
	if (label->bb_target)
		warning(pos, "label '%s' already bound", show_ident(label->ident));
	label->bb_target = bb;
}

static struct basic_block * get_bound_block(struct entrypoint *ep, struct symbol *label)
{
	struct basic_block *bb = label->bb_target;

	if (!bb) {
		bb = alloc_basic_block(ep, label->pos);
		label->bb_target = bb;
	}
	return bb;
}

static void finish_block(struct entrypoint *ep)
{
	struct basic_block *src = ep->active;
	if (bb_reachable(src))
		ep->active = NULL;
}

static void add_goto(struct entrypoint *ep, struct basic_block *dst)
{
	struct basic_block *src = ep->active;
	if (bb_reachable(src)) {
		struct instruction *br = alloc_instruction(OP_BR, 0);
		br->bb_true = dst;
		add_bb(&dst->parents, src);
		add_bb(&src->children, dst);
		br->bb = src;
		add_instruction(&src->insns, br);
		ep->active = NULL;
	}
}

static void add_one_insn(struct entrypoint *ep, struct instruction *insn)
{
	struct basic_block *bb = ep->active;    

	if (bb_reachable(bb)) {
		insn->bb = bb;
		add_instruction(&bb->insns, insn);
	}
}

static void set_activeblock(struct entrypoint *ep, struct basic_block *bb)
{
	if (!bb_terminated(ep->active))
		add_goto(ep, bb);

	ep->active = bb;
	if (bb_reachable(bb))
		add_bb(&ep->bbs, bb);
}

static void remove_parent(struct basic_block *child, struct basic_block *parent)
{
	remove_bb_from_list(&child->parents, parent, 1);
	if (!child->parents)
		repeat_phase |= REPEAT_CFG_CLEANUP;
}

/* Change a "switch" or a conditional branch into a branch */
void insert_branch(struct basic_block *bb, struct instruction *jmp, struct basic_block *target)
{
	struct instruction *br, *old;
	struct basic_block *child;

	/* Remove the switch */
	old = delete_last_instruction(&bb->insns);
	assert(old == jmp);
	kill_instruction(old);

	br = alloc_instruction(OP_BR, 0);
	br->bb = bb;
	br->bb_true = target;
	add_instruction(&bb->insns, br);

	FOR_EACH_PTR(bb->children, child) {
		if (child == target) {
			target = NULL;	/* Trigger just once */
			continue;
		}
		DELETE_CURRENT_PTR(child);
		remove_parent(child, bb);
	} END_FOR_EACH_PTR(child);
	PACK_PTR_LIST(&bb->children);
}
	

void insert_select(struct basic_block *bb, struct instruction *br, struct instruction *phi_node, pseudo_t if_true, pseudo_t if_false)
{
	pseudo_t target;
	struct instruction *select;

	/* Remove the 'br' */
	delete_last_instruction(&bb->insns);

	select = alloc_typed_instruction(OP_SEL, phi_node->type);
	select->bb = bb;

	assert(br->cond);
	use_pseudo(select, br->cond, &select->src1);

	target = phi_node->target;
	assert(target->def == phi_node);
	select->target = target;
	target->def = select;

	use_pseudo(select, if_true, &select->src2);
	use_pseudo(select, if_false, &select->src3);

	add_instruction(&bb->insns, select);
	add_instruction(&bb->insns, br);
}

static inline int bb_empty(struct basic_block *bb)
{
	return !bb->insns;
}

/* Add a label to the currently active block, return new active block */
static struct basic_block * add_label(struct entrypoint *ep, struct symbol *label)
{
	struct basic_block *bb = label->bb_target;

	if (bb) {
		set_activeblock(ep, bb);
		return bb;
	}
	bb = ep->active;
	if (!bb_reachable(bb) || !bb_empty(bb)) {
		bb = alloc_basic_block(ep, label->pos);
		set_activeblock(ep, bb);
	}
	label->bb_target = bb;
	return bb;
}

static void add_branch(struct entrypoint *ep, pseudo_t cond, struct basic_block *bb_true, struct basic_block *bb_false)
{
	struct basic_block *bb = ep->active;
	struct instruction *br;

	if (bb_reachable(bb)) {
		br = alloc_instruction(OP_CBR, 0);
		use_pseudo(br, cond, &br->cond);
		br->bb_true = bb_true;
		br->bb_false = bb_false;
		add_bb(&bb_true->parents, bb);
		add_bb(&bb_false->parents, bb);
		add_bb(&bb->children, bb_true);
		add_bb(&bb->children, bb_false);
		add_one_insn(ep, br);
	}
}

pseudo_t alloc_pseudo(struct instruction *def)
{
	static int nr = 0;
	struct pseudo * pseudo = __alloc_pseudo(0);
	pseudo->type = PSEUDO_REG;
	pseudo->nr = ++nr;
	pseudo->def = def;
	return pseudo;
}

static pseudo_t symbol_pseudo(struct entrypoint *ep, struct symbol *sym)
{
	pseudo_t pseudo;

	if (!sym)
		return VOID;

	pseudo = sym->pseudo;
	if (!pseudo) {
		pseudo = __alloc_pseudo(0);
		pseudo->nr = -1;
		pseudo->type = PSEUDO_SYM;
		pseudo->sym = sym;
		pseudo->ident = sym->ident;
		sym->pseudo = pseudo;
		add_pseudo(&ep->accesses, pseudo);
	}
	/* Symbol pseudos have neither nr nor def */
	return pseudo;
}

pseudo_t value_pseudo(long long val)
{
#define MAX_VAL_HASH 64
	static struct pseudo_list *prev[MAX_VAL_HASH];
	int hash = val & (MAX_VAL_HASH-1);
	struct pseudo_list **list = prev + hash;
	pseudo_t pseudo;

	FOR_EACH_PTR(*list, pseudo) {
		if (pseudo->value == val)
			return pseudo;
	} END_FOR_EACH_PTR(pseudo);

	pseudo = __alloc_pseudo(0);
	pseudo->type = PSEUDO_VAL;
	pseudo->value = val;
	add_pseudo(list, pseudo);

	/* Value pseudos have neither nr, usage nor def */
	return pseudo;
}

pseudo_t undef_pseudo(void)
{
	pseudo_t pseudo = __alloc_pseudo(0);
	pseudo->type = PSEUDO_UNDEF;
	return pseudo;
}

static pseudo_t argument_pseudo(struct entrypoint *ep, int nr)
{
	pseudo_t pseudo = __alloc_pseudo(0);
	struct instruction *entry = ep->entry;

	pseudo->type = PSEUDO_ARG;
	pseudo->nr = nr;
	pseudo->def = entry;
	add_pseudo(&entry->arg_list, pseudo);

	/* Argument pseudos have neither usage nor def */
	return pseudo;
}

struct instruction *alloc_phisrc(pseudo_t pseudo, struct symbol *type)
{
	struct instruction *insn = alloc_typed_instruction(OP_PHISOURCE, type);
	pseudo_t phi = __alloc_pseudo(0);
	static int nr = 0;

	phi->type = PSEUDO_PHI;
	phi->nr = ++nr;
	phi->def = insn;

	use_pseudo(insn, pseudo, &insn->phi_src);
	insn->target = phi;
	return insn;
}

pseudo_t alloc_phi(struct basic_block *source, pseudo_t pseudo, struct symbol *type)
{
	struct instruction *insn;

	if (!source)
		return VOID;

	insn = alloc_phisrc(pseudo, type);
	insn->bb = source;
	add_instruction(&source->insns, insn);
	return insn->target;
}

struct instruction *alloc_phi_node(struct basic_block *bb, struct symbol *type, struct ident *ident)
{
	struct instruction *phi_node = alloc_typed_instruction(OP_PHI, type);
	pseudo_t phi;

	phi = alloc_pseudo(phi_node);
	phi->ident = ident;
	phi->def = phi_node;
	phi_node->target = phi;
	phi_node->bb = bb;
	return phi_node;
}

void add_phi_node(struct basic_block *bb, struct instruction *phi_node)
{
	struct instruction *insn;

	FOR_EACH_PTR(bb->insns, insn) {
		enum opcode op = insn->opcode;
		if (op == OP_PHI)
			continue;
		INSERT_CURRENT(phi_node, insn);
		return;
	} END_FOR_EACH_PTR(insn);

	// FIXME
	add_instruction(&bb->insns, phi_node);
}

struct instruction *insert_phi_node(struct basic_block *bb, struct symbol *var)
{
	struct instruction *phi_node = alloc_phi_node(bb, var, var->ident);
	add_phi_node(bb, phi_node);
	return phi_node;
}

/*
 * We carry the "access_data" structure around for any accesses,
 * which simplifies things a lot. It contains all the access
 * information in one place.
 */
struct access_data {
	struct symbol *type;		// ctype
	struct symbol *btype;		// base type of bitfields
	pseudo_t address;		// pseudo containing address ..
	unsigned int offset;		// byte offset
};

static int linearize_simple_address(struct entrypoint *ep,
	struct expression *addr,
	struct access_data *ad)
{
	if (addr->type == EXPR_SYMBOL) {
		linearize_one_symbol(ep, addr->symbol);
		ad->address = symbol_pseudo(ep, addr->symbol);
		return 1;
	}
	if (addr->type == EXPR_BINOP) {
		if (addr->right->type == EXPR_VALUE) {
			if (addr->op == '+') {
				ad->offset += get_expression_value(addr->right);
				return linearize_simple_address(ep, addr->left, ad);
			}
		}
	}
	ad->address = linearize_expression(ep, addr);
	return 1;
}

static struct symbol *bitfield_base_type(struct symbol *sym)
{
	struct symbol *base = sym;

	if (sym) {
		if (sym->type == SYM_NODE)
			base = base->ctype.base_type;
		if (base->type == SYM_BITFIELD)
			return base->ctype.base_type;
	}
	return sym;
}

static int linearize_address_gen(struct entrypoint *ep,
	struct expression *expr,
	struct access_data *ad)
{
	struct symbol *ctype = expr->ctype;

	if (!ctype)
		return 0;
	ad->type = ctype;
	if (expr->type == EXPR_PREOP && expr->op == '*')
		return linearize_simple_address(ep, expr->unop, ad);

	warning(expr->pos, "generating address of non-lvalue (%d)", expr->type);
	return 0;
}

static pseudo_t add_load(struct entrypoint *ep, struct access_data *ad)
{
	struct instruction *insn;
	pseudo_t new;

	if (!ep->active)
		return VOID;

	insn = alloc_typed_instruction(OP_LOAD, ad->btype);
	new = alloc_pseudo(insn);

	insn->target = new;
	insn->offset = ad->offset;
	insn->is_volatile = ad->type && (ad->type->ctype.modifiers & MOD_VOLATILE);
	use_pseudo(insn, ad->address, &insn->src);
	add_one_insn(ep, insn);
	return new;
}

static void add_store(struct entrypoint *ep, struct access_data *ad, pseudo_t value)
{
	struct basic_block *bb = ep->active;
	struct instruction *store;

	if (!bb)
		return;

	store = alloc_typed_instruction(OP_STORE, ad->btype);
	store->offset = ad->offset;
	store->is_volatile = ad->type && (ad->type->ctype.modifiers & MOD_VOLATILE);
	use_pseudo(store, value, &store->target);
	use_pseudo(store, ad->address, &store->src);
	add_one_insn(ep, store);
}

static pseudo_t linearize_bitfield_insert(struct entrypoint *ep,
	pseudo_t ori, pseudo_t val, struct symbol *ctype, struct symbol *btype)
{
	unsigned int shift = ctype->bit_offset;
	unsigned int size = ctype->bit_size;
	unsigned long long mask = ((1ULL << size) - 1);
	unsigned long long smask= bits_mask(btype->bit_size);

	val = add_cast(ep, btype, ctype, OP_ZEXT, val);
	if (shift) {
		val = add_binary_op(ep, btype, OP_SHL, val, value_pseudo(shift));
		mask <<= shift;
	}
	ori = add_binary_op(ep, btype, OP_AND, ori, value_pseudo(~mask & smask));
	val = add_binary_op(ep, btype, OP_OR, ori, val);

	return val;
}

static pseudo_t linearize_store_gen(struct entrypoint *ep,
		pseudo_t value,
		struct access_data *ad)
{
	struct symbol *ctype = ad->type;
	struct symbol *btype;
	pseudo_t store = value;

	if (!ep->active)
		return VOID;

	btype = ad->btype = bitfield_base_type(ctype);
	if (type_size(btype) != type_size(ctype)) {
		pseudo_t orig = add_load(ep, ad);
		store = linearize_bitfield_insert(ep, orig, value, ctype, btype);
	}
	add_store(ep, ad, store);
	return value;
}

static void taint_undefined_behaviour(struct instruction *insn)
{
	pseudo_t src2;

	switch (insn->opcode) {
	case OP_LSR:
	case OP_ASR:
	case OP_SHL:
		src2 = insn->src2;
		if (src2->type != PSEUDO_VAL)
			break;
		if ((unsigned long long)src2->value >= insn->size)
			insn->tainted = 1;
		break;
	}
}

static pseudo_t add_binary_op(struct entrypoint *ep, struct symbol *ctype, int op, pseudo_t left, pseudo_t right)
{
	struct instruction *insn = alloc_typed_instruction(op, ctype);
	pseudo_t target = alloc_pseudo(insn);
	insn->target = target;
	use_pseudo(insn, left, &insn->src1);
	use_pseudo(insn, right, &insn->src2);
	add_one_insn(ep, insn);
	return target;
}

static pseudo_t add_setval(struct entrypoint *ep, struct symbol *ctype, struct expression *val)
{
	struct instruction *insn = alloc_typed_instruction(OP_SETVAL, ctype);
	pseudo_t target = alloc_pseudo(insn);
	insn->target = target;
	insn->val = val;
	add_one_insn(ep, insn);
	return target;
}

static pseudo_t add_setfval(struct entrypoint *ep, struct symbol *ctype, long double fval)
{
	struct instruction *insn = alloc_typed_instruction(OP_SETFVAL, ctype);
	pseudo_t target = alloc_pseudo(insn);
	insn->target = target;
	insn->fvalue = fval;
	add_one_insn(ep, insn);
	return target;
}

static pseudo_t add_symbol_address(struct entrypoint *ep, struct symbol *sym)
{
	struct instruction *insn = alloc_instruction(OP_SYMADDR, bits_in_pointer);
	pseudo_t target = alloc_pseudo(insn);

	insn->target = target;
	use_pseudo(insn, symbol_pseudo(ep, sym), &insn->src);
	add_one_insn(ep, insn);
	return target;
}

static pseudo_t linearize_bitfield_extract(struct entrypoint *ep,
		pseudo_t val, struct symbol *ctype, struct symbol *btype)
{
	unsigned int off = ctype->bit_offset;

	if (off) {
		pseudo_t shift = value_pseudo(off);
		val = add_binary_op(ep, btype, OP_LSR, val, shift);
	}
	val = cast_pseudo(ep, val, btype, ctype);
	return val;
}

static pseudo_t linearize_load_gen(struct entrypoint *ep, struct access_data *ad)
{
	struct symbol *ctype = ad->type;
	struct symbol *btype;
	pseudo_t new;

	if (!ep->active)
		return VOID;

	btype = ad->btype = bitfield_base_type(ctype);
	new = add_load(ep, ad);
	if (ctype->bit_size != type_size(btype))
		new = linearize_bitfield_extract(ep, new, ctype, btype);
	return new;
}

static pseudo_t linearize_access(struct entrypoint *ep, struct expression *expr)
{
	struct access_data ad = { NULL, };
	pseudo_t value;

	if (!linearize_address_gen(ep, expr, &ad))
		return VOID;
	value = linearize_load_gen(ep, &ad);
	return value;
}

static pseudo_t linearize_inc_dec(struct entrypoint *ep, struct expression *expr, int postop)
{
	struct access_data ad = { NULL, };
	pseudo_t old, new, one;
	int op = expr->op == SPECIAL_INCREMENT ? OP_ADD : OP_SUB;

	if (!linearize_address_gen(ep, expr->unop, &ad))
		return VOID;

	old = linearize_load_gen(ep, &ad);
	op = opcode_float(op, expr->ctype);
	if (is_float_type(expr->ctype))
		one = add_setfval(ep, expr->ctype, expr->op_value);
	else
		one = value_pseudo(expr->op_value);
	if (ad.btype != ad.type)
		old = cast_pseudo(ep, old, ad.type, ad.btype);
	new = add_binary_op(ep, ad.btype, op, old, one);
	if (ad.btype != ad.type)
		new = cast_pseudo(ep, new, ad.btype, ad.type);
	linearize_store_gen(ep, new, &ad);
	return postop ? old : new;
}

static pseudo_t add_unop(struct entrypoint *ep, struct symbol *ctype, int op, pseudo_t src)
{
	struct instruction *insn = alloc_typed_instruction(op, ctype);
	pseudo_t new = alloc_pseudo(insn);

	insn->target = new;
	use_pseudo(insn, src, &insn->src1);
	add_one_insn(ep, insn);
	return new;
}

static pseudo_t add_cast(struct entrypoint *ep, struct symbol *to,
			 struct symbol *from, int op, pseudo_t src)
{
	pseudo_t new = add_unop(ep, to, op, src);
	new->def->orig_type = from;
	return new;
}

static pseudo_t linearize_slice(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t pre = linearize_expression(ep, expr->base);
	struct instruction *insn = alloc_typed_instruction(OP_SLICE, expr->ctype);
	pseudo_t new = alloc_pseudo(insn);

	insn->target = new;
	insn->from = expr->r_bitpos;
	insn->len = expr->r_nrbits;
	use_pseudo(insn, pre, &insn->base);
	add_one_insn(ep, insn);
	return new;
}

static pseudo_t linearize_regular_preop(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t pre = linearize_expression(ep, expr->unop);
	struct symbol *ctype = expr->ctype;
	switch (expr->op) {
	case '+':
		return pre;
	case '!': {
		pseudo_t zero = value_pseudo(0);
		return add_binary_op(ep, ctype, OP_SET_EQ, pre, zero);
	}
	case '~':
		return add_unop(ep, ctype, OP_NOT, pre);
	case '-':
		return add_unop(ep, ctype, opcode_float(OP_NEG, ctype), pre);
	}
	return VOID;
}

static pseudo_t linearize_preop(struct entrypoint *ep, struct expression *expr)
{
	/*
	 * '*' is an lvalue access, and is fundamentally different
	 * from an arithmetic operation. Maybe it should have an
	 * expression type of its own..
	 */
	if (expr->op == '*')
		return linearize_access(ep, expr);
	if (expr->op == SPECIAL_INCREMENT || expr->op == SPECIAL_DECREMENT)
		return linearize_inc_dec(ep, expr, 0);
	return linearize_regular_preop(ep, expr);
}

static pseudo_t linearize_postop(struct entrypoint *ep, struct expression *expr)
{
	return linearize_inc_dec(ep, expr, 1);
}	

/*
 * Casts to pointers are "less safe" than other casts, since
 * they imply type-unsafe accesses. "void *" is a special
 * case, since you can't access through it anyway without another
 * cast.
 */
enum mtype {
	MTYPE_UINT,
	MTYPE_SINT,
	MTYPE_PTR,
	MTYPE_VPTR,	// TODO: must be removed ?
	MTYPE_FLOAT,
	MTYPE_BAD,
};

static enum mtype get_mtype(struct symbol *s)
{
	int sign = (s->ctype.modifiers & MOD_SIGNED) ? 1 : 0;

retry:	switch (s->type) {
	case SYM_NODE:
		s = s->ctype.base_type;
		goto retry;
	case SYM_PTR:
		if (s->ctype.base_type == &void_ctype)
			return MTYPE_VPTR;
		return MTYPE_PTR;
	case SYM_BITFIELD:
	case SYM_RESTRICT:
	case SYM_FOULED:
	case SYM_ENUM:
		s = s->ctype.base_type;
		/* fall-through */
	case_int:
		return sign ? MTYPE_SINT : MTYPE_UINT;
	case SYM_BASETYPE:
		if (s->ctype.base_type == &fp_type)
			return MTYPE_FLOAT;
		if (s->ctype.base_type == &int_type)
			goto case_int;
		/* fall-through */
	default:
		return MTYPE_BAD;
	}
}

static int get_cast_opcode(struct symbol *dst, struct symbol *src)
{
	enum mtype stype = get_mtype(src);
	enum mtype dtype = get_mtype(dst);

	switch (dtype) {
	case MTYPE_FLOAT:
		switch (stype) {
		case MTYPE_FLOAT:
			if (dst->bit_size == src->bit_size)
				return OP_NOP;
			return OP_FCVTF;
		case MTYPE_UINT:
			return OP_UCVTF;
		case MTYPE_SINT:
			return OP_SCVTF;
		default:
			return OP_BADOP;
		}
	case MTYPE_PTR:
		switch (stype) {
		case MTYPE_UINT:
		case MTYPE_SINT:
			return OP_UTPTR;
		case MTYPE_PTR:
		case MTYPE_VPTR:
			return OP_PTRCAST;
		default:
			return OP_BADOP;
		}
	case MTYPE_VPTR:
		switch (stype) {
		case MTYPE_PTR:
		case MTYPE_VPTR:
		case MTYPE_UINT:
			stype = MTYPE_UINT;
			/* fall through */
		case MTYPE_SINT:
			break;
		default:
			return OP_BADOP;
		}
		/* fall through */
	case MTYPE_UINT:
	case MTYPE_SINT:
		switch (stype) {
		case MTYPE_FLOAT:
			return dtype == MTYPE_UINT ? OP_FCVTU : OP_FCVTS;
		case MTYPE_PTR:
			return OP_PTRTU;
		case MTYPE_VPTR:
		case MTYPE_UINT:
		case MTYPE_SINT:
			if (dst->bit_size ==src->bit_size)
				return OP_NOP;
			if (dst->bit_size  < src->bit_size)
				return OP_TRUNC;
			return stype == MTYPE_SINT ? OP_SEXT : OP_ZEXT;
		default:
			return OP_BADOP;
		}
		/* fall through */
	default:
		if (src->type == SYM_NODE)
			src = src->ctype.base_type;
		if (dst->type == SYM_NODE)
			dst = dst->ctype.base_type;
		if (src == dst)
			return OP_NOP;
		return OP_BADOP;
	}
}

static pseudo_t cast_pseudo(struct entrypoint *ep, pseudo_t src, struct symbol *from, struct symbol *to)
{
	const struct position pos = current_pos;
	pseudo_t result;
	struct instruction *insn;
	int opcode;

	if (src == VOID)
		return VOID;
	if (!from || !to)
		return VOID;
	if (from->bit_size < 0 || to->bit_size < 0)
		return VOID;
	opcode = get_cast_opcode(to, from);
	switch (opcode) {
	case OP_NOP:
		return src;
	case OP_UTPTR:
		if (from->bit_size == to->bit_size)
			break;
		if (src == value_pseudo(0))
			break;
		if (Wint_to_pointer_cast)
			warning(pos, "non size-preserving integer to pointer cast");
		src = cast_pseudo(ep, src, from, size_t_ctype);
		from = size_t_ctype;
		break;
	case OP_PTRTU:
		if (from->bit_size == to->bit_size)
			break;
		if (Wpointer_to_int_cast)
			warning(pos, "non size-preserving pointer to integer cast");
		src = cast_pseudo(ep, src, from, size_t_ctype);
		return cast_pseudo(ep, src, size_t_ctype, to);
	case OP_BADOP:
		return VOID;
	default:
		break;
	}
	insn = alloc_typed_instruction(opcode, to);
	result = alloc_pseudo(insn);
	insn->target = result;
	insn->orig_type = from;
	use_pseudo(insn, src, &insn->src);
	add_one_insn(ep, insn);
	return result;
}

static int map_opcode(int opcode, struct symbol *ctype)
{
	if (ctype && is_float_type(ctype))
		return opcode_table[opcode].to_float;
	if (ctype && (ctype->ctype.modifiers & MOD_SIGNED)) {
		switch(opcode) {
		case OP_DIVU: case OP_MODU: case OP_LSR:
			opcode++;
		}
	}
	return opcode;
}

static inline pseudo_t add_convert_to_bool(struct entrypoint *ep, pseudo_t src, struct symbol *type)
{
	pseudo_t zero;
	int op;

	if (!type || src == VOID)
		return VOID;
	if (is_bool_type(type))
		return src;
	if (src->type == PSEUDO_VAL && (src->value == 0 || src->value == 1))
		return src;
	if (is_float_type(type)) {
		zero = add_setfval(ep, type, 0.0);
		op = map_opcode(OP_SET_NE, type);
	} else {
		zero = value_pseudo(0);
		op = OP_SET_NE;
	}
	return add_binary_op(ep, &bool_ctype, op, src, zero);
}

static pseudo_t linearize_expression_to_bool(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t dst;
	dst = linearize_expression(ep, expr);
	dst = add_convert_to_bool(ep, dst, expr->ctype);
	return dst;
}

static pseudo_t linearize_assignment(struct entrypoint *ep, struct expression *expr)
{
	struct access_data ad = { NULL, };
	struct expression *target = expr->left;
	struct expression *src = expr->right;
	struct symbol *ctype;
	pseudo_t value;

	value = linearize_expression(ep, src);
	if (!target || !linearize_address_gen(ep, target, &ad))
		return value;
	if (expr->op != '=') {
		pseudo_t oldvalue = linearize_load_gen(ep, &ad);
		pseudo_t dst;
		static const int op_trans[] = {
			[SPECIAL_ADD_ASSIGN - SPECIAL_BASE] = OP_ADD,
			[SPECIAL_SUB_ASSIGN - SPECIAL_BASE] = OP_SUB,
			[SPECIAL_MUL_ASSIGN - SPECIAL_BASE] = OP_MUL,
			[SPECIAL_DIV_ASSIGN - SPECIAL_BASE] = OP_DIVU,
			[SPECIAL_MOD_ASSIGN - SPECIAL_BASE] = OP_MODU,
			[SPECIAL_SHL_ASSIGN - SPECIAL_BASE] = OP_SHL,
			[SPECIAL_SHR_ASSIGN - SPECIAL_BASE] = OP_LSR,
			[SPECIAL_AND_ASSIGN - SPECIAL_BASE] = OP_AND,
			[SPECIAL_OR_ASSIGN  - SPECIAL_BASE] = OP_OR,
			[SPECIAL_XOR_ASSIGN - SPECIAL_BASE] = OP_XOR
		};
		int opcode;

		if (!src)
			return VOID;

		ctype = src->ctype;
		oldvalue = cast_pseudo(ep, oldvalue, target->ctype, ctype);
		opcode = map_opcode(op_trans[expr->op - SPECIAL_BASE], ctype);
		dst = add_binary_op(ep, ctype, opcode, oldvalue, value);
		taint_undefined_behaviour(dst->def);
		value = cast_pseudo(ep, dst, ctype, expr->ctype);
	}
	value = linearize_store_gen(ep, value, &ad);
	return value;
}

static pseudo_t linearize_call_expression(struct entrypoint *ep, struct expression *expr)
{
	struct expression *arg, *fn;
	struct instruction *insn = alloc_typed_instruction(OP_CALL, expr->ctype);
	pseudo_t retval, call;
	struct ctype *ctype = NULL;
	struct symbol *fntype;
	struct context *context;

	if (!expr->ctype)
		return VOID;

	fn = expr->fn;
	fntype = fn->ctype;
	ctype = &fntype->ctype;
	if (fntype->type == SYM_NODE)
		fntype = fntype->ctype.base_type;

	add_symbol(&insn->fntypes, fntype);
	FOR_EACH_PTR(expr->args, arg) {
		pseudo_t new = linearize_expression(ep, arg);
		use_pseudo(insn, new, add_pseudo(&insn->arguments, new));
		add_symbol(&insn->fntypes, arg->ctype);
	} END_FOR_EACH_PTR(arg);

	if (fn->type == EXPR_PREOP && fn->op == '*' && is_func_type(fn->ctype))
		fn = fn->unop;

	if (fn->type == EXPR_SYMBOL) {
		call = symbol_pseudo(ep, fn->symbol);
	} else {
		call = linearize_expression(ep, fn);
	}
	use_pseudo(insn, call, &insn->func);
	retval = VOID;
	if (expr->ctype != &void_ctype)
		retval = alloc_pseudo(insn);
	insn->target = retval;
	add_one_insn(ep, insn);

	if (ctype) {
		FOR_EACH_PTR(ctype->contexts, context) {
			int in = context->in;
			int out = context->out;
			int check = 0;
			int context_diff;
			if (in < 0) {
				check = 1;
				in = 0;
			}
			if (out < 0) {
				check = 0;
				out = 0;
			}
			context_diff = out - in;
			if (check || context_diff) {
				insn = alloc_instruction(OP_CONTEXT, 0);
				insn->increment = context_diff;
				insn->check = check;
				insn->context_expr = context->context;
				add_one_insn(ep, insn);
			}
		} END_FOR_EACH_PTR(context);
	}

	return retval;
}

static pseudo_t linearize_binop_bool(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t src1, src2, dst;
	int op = (expr->op == SPECIAL_LOGICAL_OR) ? OP_OR : OP_AND;

	src1 = linearize_expression_to_bool(ep, expr->left);
	src2 = linearize_expression_to_bool(ep, expr->right);
	dst = add_binary_op(ep, &bool_ctype, op, src1, src2);
	if (expr->ctype != &bool_ctype)
		dst = cast_pseudo(ep, dst, &bool_ctype, expr->ctype);
	return dst;
}

static pseudo_t linearize_binop(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t src1, src2, dst;
	static const int opcode[] = {
		['+'] = OP_ADD, ['-'] = OP_SUB,
		['*'] = OP_MUL, ['/'] = OP_DIVU,
		['%'] = OP_MODU, ['&'] = OP_AND,
		['|'] = OP_OR,  ['^'] = OP_XOR,
		[SPECIAL_LEFTSHIFT] = OP_SHL,
		[SPECIAL_RIGHTSHIFT] = OP_LSR,
	};
	int op;

	src1 = linearize_expression(ep, expr->left);
	src2 = linearize_expression(ep, expr->right);
	op = map_opcode(opcode[expr->op], expr->ctype);
	dst = add_binary_op(ep, expr->ctype, op, src1, src2);
	taint_undefined_behaviour(dst->def);
	return dst;
}

static pseudo_t linearize_logical_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false);

static pseudo_t linearize_cond_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false);

static pseudo_t linearize_select(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t cond, valt, valf, res;
	struct instruction *insn;

	valt = linearize_expression(ep, expr->cond_true);
	valf = linearize_expression(ep, expr->cond_false);
	cond = linearize_expression(ep, expr->conditional);

	insn = alloc_typed_instruction(OP_SEL, expr->ctype);
	if (!expr->cond_true)
		valt = cond;
	use_pseudo(insn, cond, &insn->src1);
	use_pseudo(insn, valt, &insn->src2);
	use_pseudo(insn, valf, &insn->src3);

	res = alloc_pseudo(insn);
	insn->target = res;
	add_one_insn(ep, insn);
	return res;
}

static pseudo_t add_join_conditional(struct entrypoint *ep, struct expression *expr,
				     pseudo_t phi1, pseudo_t phi2)
{
	pseudo_t target;
	struct instruction *phi_node;

	if (phi1 == VOID)
		return phi2;
	if (phi2 == VOID)
		return phi1;

	phi_node = alloc_typed_instruction(OP_PHI, expr->ctype);
	use_pseudo(phi_node, phi1, add_pseudo(&phi_node->phi_list, phi1));
	use_pseudo(phi_node, phi2, add_pseudo(&phi_node->phi_list, phi2));
	phi_node->target = target = alloc_pseudo(phi_node);
	add_one_insn(ep, phi_node);
	return target;
}	

static pseudo_t linearize_short_conditional(struct entrypoint *ep, struct expression *expr,
					    struct expression *cond,
					    struct expression *expr_false)
{
	pseudo_t src1, src2;
	struct basic_block *bb_false;
	struct basic_block *merge;
	pseudo_t phi1, phi2;

	if (!expr_false || !ep->active)
		return VOID;

	bb_false = alloc_basic_block(ep, expr_false->pos);
	merge = alloc_basic_block(ep, expr->pos);

	src1 = linearize_expression(ep, cond);
	phi1 = alloc_phi(ep->active, src1, expr->ctype);
	add_branch(ep, src1, merge, bb_false);

	set_activeblock(ep, bb_false);
	src2 = linearize_expression(ep, expr_false);
	phi2 = alloc_phi(ep->active, src2, expr->ctype);
	set_activeblock(ep, merge);

	return add_join_conditional(ep, expr, phi1, phi2);
}

static pseudo_t linearize_conditional(struct entrypoint *ep, struct expression *expr,
				      struct expression *cond,
				      struct expression *expr_true,
				      struct expression *expr_false)
{
	pseudo_t src1, src2;
	pseudo_t phi1, phi2;
	struct basic_block *bb_true, *bb_false, *merge;

	if (!cond || !expr_true || !expr_false || !ep->active)
		return VOID;
	bb_true = alloc_basic_block(ep, expr_true->pos);
	bb_false = alloc_basic_block(ep, expr_false->pos);
	merge = alloc_basic_block(ep, expr->pos);

	linearize_cond_branch(ep, cond, bb_true, bb_false);

	set_activeblock(ep, bb_true);
	src1 = linearize_expression(ep, expr_true);
	phi1 = alloc_phi(ep->active, src1, expr->ctype);
	add_goto(ep, merge); 

	set_activeblock(ep, bb_false);
	src2 = linearize_expression(ep, expr_false);
	phi2 = alloc_phi(ep->active, src2, expr->ctype);
	set_activeblock(ep, merge);

	return add_join_conditional(ep, expr, phi1, phi2);
}

static void insert_phis(struct basic_block *bb, pseudo_t src, struct symbol *ctype,
	struct instruction *node)
{
	struct basic_block *parent;

	FOR_EACH_PTR(bb->parents, parent) {
		struct instruction *br = delete_last_instruction(&parent->insns);
		pseudo_t phi = alloc_phi(parent, src, ctype);
		add_instruction(&parent->insns, br);
		use_pseudo(node, phi, add_pseudo(&node->phi_list, phi));
	} END_FOR_EACH_PTR(parent);
}

static pseudo_t linearize_logical(struct entrypoint *ep, struct expression *expr)
{
	struct symbol *ctype = expr->ctype;
	struct basic_block *other, *merge;
	struct instruction *node;
	pseudo_t src1, src2, phi2;

	if (!ep->active || !expr->left || !expr->right)
		return VOID;

	other = alloc_basic_block(ep, expr->right->pos);
	merge = alloc_basic_block(ep, expr->pos);
	node = alloc_phi_node(merge, ctype, NULL);

	// LHS and its shortcut
	if (expr->op == SPECIAL_LOGICAL_OR) {
		linearize_cond_branch(ep, expr->left, merge, other);
		src1 = value_pseudo(1);
	} else {
		linearize_cond_branch(ep, expr->left, other, merge);
		src1 = value_pseudo(0);
	}
	insert_phis(merge, src1, ctype, node);

	// RHS
	set_activeblock(ep, other);
	src2 = linearize_expression_to_bool(ep, expr->right);
	src2 = cast_pseudo(ep, src2, &bool_ctype, ctype);
	phi2 = alloc_phi(ep->active, src2, ctype);
	use_pseudo(node, phi2, add_pseudo(&node->phi_list, phi2));

	// join
	set_activeblock(ep, merge);
	add_instruction(&merge->insns, node);
	return node->target;
}

static pseudo_t linearize_compare(struct entrypoint *ep, struct expression *expr)
{
	static const int cmpop[] = {
		['>'] = OP_SET_GT, ['<'] = OP_SET_LT,
		[SPECIAL_EQUAL] = OP_SET_EQ,
		[SPECIAL_NOTEQUAL] = OP_SET_NE,
		[SPECIAL_GTE] = OP_SET_GE,
		[SPECIAL_LTE] = OP_SET_LE,
		[SPECIAL_UNSIGNED_LT] = OP_SET_B,
		[SPECIAL_UNSIGNED_GT] = OP_SET_A,
		[SPECIAL_UNSIGNED_LTE] = OP_SET_BE,
		[SPECIAL_UNSIGNED_GTE] = OP_SET_AE,
	};
	int op = opcode_float(cmpop[expr->op], expr->right->ctype);
	pseudo_t src1 = linearize_expression(ep, expr->left);
	pseudo_t src2 = linearize_expression(ep, expr->right);
	pseudo_t dst = add_binary_op(ep, expr->ctype, op, src1, src2);
	return dst;
}


static pseudo_t linearize_cond_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false)
{
	pseudo_t cond;

	if (!expr || !bb_reachable(ep->active))
		return VOID;

	switch (expr->type) {

	case EXPR_STRING:
	case EXPR_VALUE:
		add_goto(ep, expr->value ? bb_true : bb_false);
		return VOID;

	case EXPR_FVALUE:
		add_goto(ep, expr->fvalue ? bb_true : bb_false);
		return VOID;
		
	case EXPR_LOGICAL:
		linearize_logical_branch(ep, expr, bb_true, bb_false);
		return VOID;

	case EXPR_COMPARE:
		cond = linearize_compare(ep, expr);
		add_branch(ep, cond, bb_true, bb_false);
		break;
		
	case EXPR_PREOP:
		if (expr->op == '!')
			return linearize_cond_branch(ep, expr->unop, bb_false, bb_true);
		/* fall through */
	default: {
		cond = linearize_expression_to_bool(ep, expr);
		add_branch(ep, cond, bb_true, bb_false);

		return VOID;
	}
	}
	return VOID;
}


	
static pseudo_t linearize_logical_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false)
{
	struct basic_block *next = alloc_basic_block(ep, expr->pos);

	if (expr->op == SPECIAL_LOGICAL_OR)
		linearize_cond_branch(ep, expr->left, bb_true, next);
	else
		linearize_cond_branch(ep, expr->left, next, bb_false);
	set_activeblock(ep, next);
	linearize_cond_branch(ep, expr->right, bb_true, bb_false);
	return VOID;
}

static pseudo_t linearize_cast(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t src;
	struct expression *orig = expr->cast_expression;

	if (!orig)
		return VOID;

	src = linearize_expression(ep, orig);
	return cast_pseudo(ep, src, orig->ctype, expr->ctype);
}

static pseudo_t linearize_initializer(struct entrypoint *ep, struct expression *initializer, struct access_data *ad)
{
	switch (initializer->type) {
	case EXPR_INITIALIZER: {
		struct expression *expr;
		FOR_EACH_PTR(initializer->expr_list, expr) {
			linearize_initializer(ep, expr, ad);
		} END_FOR_EACH_PTR(expr);
		break;
	}
	case EXPR_POS:
		ad->offset = initializer->init_offset;
		linearize_initializer(ep, initializer->init_expr, ad);
		break;
	default: {
		pseudo_t value = linearize_expression(ep, initializer);
		ad->type = initializer->ctype;
		linearize_store_gen(ep, value, ad);
		return value;
	}
	}

	return VOID;
}

static void linearize_argument(struct entrypoint *ep, struct symbol *arg, int nr)
{
	struct access_data ad = { NULL, };

	ad.type = arg;
	ad.address = symbol_pseudo(ep, arg);
	linearize_store_gen(ep, argument_pseudo(ep, nr), &ad);
}

static pseudo_t linearize_expression(struct entrypoint *ep, struct expression *expr)
{
	if (!expr)
		return VOID;

	current_pos = expr->pos;
	switch (expr->type) {
	case EXPR_SYMBOL:
		linearize_one_symbol(ep, expr->symbol);
		return add_symbol_address(ep, expr->symbol);

	case EXPR_VALUE:
		return value_pseudo(expr->value);

	case EXPR_STRING:
	case EXPR_LABEL:
		return add_setval(ep, expr->ctype, expr);

	case EXPR_FVALUE:
		return add_setfval(ep, expr->ctype, expr->fvalue);

	case EXPR_STATEMENT:
		return linearize_statement(ep, expr->statement);

	case EXPR_CALL:
		return linearize_call_expression(ep, expr);

	case EXPR_BINOP:
		if (expr->op == SPECIAL_LOGICAL_AND || expr->op == SPECIAL_LOGICAL_OR)
			return linearize_binop_bool(ep, expr);
		return linearize_binop(ep, expr);

	case EXPR_LOGICAL:
		return linearize_logical(ep, expr);

	case EXPR_COMPARE:
		return  linearize_compare(ep, expr);

	case EXPR_SELECT:
		return	linearize_select(ep, expr);

	case EXPR_CONDITIONAL:
		if (!expr->cond_true)
			return linearize_short_conditional(ep, expr, expr->conditional, expr->cond_false);

		return  linearize_conditional(ep, expr, expr->conditional,
					      expr->cond_true, expr->cond_false);

	case EXPR_COMMA:
		linearize_expression(ep, expr->left);
		return linearize_expression(ep, expr->right);

	case EXPR_ASSIGNMENT:
		return linearize_assignment(ep, expr);

	case EXPR_PREOP:
		return linearize_preop(ep, expr);

	case EXPR_POSTOP:
		return linearize_postop(ep, expr);

	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		return linearize_cast(ep, expr);
	
	case EXPR_SLICE:
		return linearize_slice(ep, expr);

	case EXPR_INITIALIZER:
	case EXPR_POS:
		warning(expr->pos, "unexpected initializer expression (%d %d)", expr->type, expr->op);
		return VOID;
	default: 
		warning(expr->pos, "unknown expression (%d %d)", expr->type, expr->op);
		return VOID;
	}
	return VOID;
}

static pseudo_t linearize_one_symbol(struct entrypoint *ep, struct symbol *sym)
{
	struct access_data ad = { NULL, };
	pseudo_t value;

	if (!sym || !sym->initializer || sym->initialized)
		return VOID;

	/* We need to output these puppies some day too.. */
	if (sym->ctype.modifiers & (MOD_STATIC | MOD_TOPLEVEL))
		return VOID;

	sym->initialized = 1;
	ad.address = symbol_pseudo(ep, sym);

	if (sym->initializer && !is_scalar_type(sym)) {
		// default zero initialization [6.7.9.21]
		// FIXME: this init the whole aggregate while
		// only the existing fields need to be initialized.
		// FIXME: this init the whole aggregate even if
		// all fields arelater  explicitely initialized.
		ad.type = sym;
		ad.address = symbol_pseudo(ep, sym);
		linearize_store_gen(ep, value_pseudo(0), &ad);
	}

	value = linearize_initializer(ep, sym->initializer, &ad);
	return value;
}

static pseudo_t linearize_compound_statement(struct entrypoint *ep, struct statement *stmt)
{
	pseudo_t pseudo;
	struct statement *s;

	pseudo = VOID;
	FOR_EACH_PTR(stmt->stmts, s) {
		pseudo = linearize_statement(ep, s);
	} END_FOR_EACH_PTR(s);

	return pseudo;
}

static void add_return(struct entrypoint *ep, struct basic_block *bb, struct symbol *ctype, pseudo_t src)
{
	struct instruction *phi_node = first_instruction(bb->insns);
	pseudo_t phi;
	if (!phi_node) {
		phi_node = alloc_typed_instruction(OP_PHI, ctype);
		phi_node->target = alloc_pseudo(phi_node);
		phi_node->bb = bb;
		add_instruction(&bb->insns, phi_node);
	}
	phi = alloc_phi(ep->active, src, ctype);
	phi->ident = &return_ident;
	use_pseudo(phi_node, phi, add_pseudo(&phi_node->phi_list, phi));
}

static pseudo_t linearize_fn_statement(struct entrypoint *ep, struct statement *stmt)
{
	struct instruction *phi_node;
	struct basic_block *bb;
	pseudo_t pseudo;

	pseudo = linearize_compound_statement(ep, stmt);
	if (!is_void_type(stmt->ret)) {			// non-void function
		struct basic_block *active = ep->active;
		if (active && !bb_terminated(active)) {	// missing return
			struct basic_block *bb_ret;
			bb_ret = get_bound_block(ep, stmt->ret);
			add_return(ep, bb_ret, stmt->ret, undef_pseudo());
		}
	}
	bb = add_label(ep, stmt->ret);
	phi_node = first_instruction(bb->insns);
	if (phi_node)
		pseudo = phi_node->target;
	return pseudo;
}

static pseudo_t linearize_inlined_call(struct entrypoint *ep, struct statement *stmt)
{
	struct instruction *insn = alloc_instruction(OP_INLINED_CALL, 0);
	struct statement *args = stmt->args;
	struct basic_block *bb;
	pseudo_t pseudo;

	if (args) {
		struct symbol *sym;

		concat_symbol_list(args->declaration, &ep->syms);
		FOR_EACH_PTR(args->declaration, sym) {
			pseudo_t value = linearize_one_symbol(ep, sym);
			add_pseudo(&insn->arguments, value);
		} END_FOR_EACH_PTR(sym);
	}

	pseudo = linearize_fn_statement(ep, stmt);
	insn->target = pseudo;

	use_pseudo(insn, symbol_pseudo(ep, stmt->inline_fn), &insn->func);
	bb = ep->active;
	if (!bb->insns)
		bb->pos = stmt->pos;
	add_one_insn(ep, insn);
	return pseudo;
}

static pseudo_t linearize_context(struct entrypoint *ep, struct statement *stmt)
{
	struct instruction *insn = alloc_instruction(OP_CONTEXT, 0);
	struct expression *expr = stmt->expression;

	insn->increment = get_expression_value(expr);
	insn->context_expr = stmt->context;
	add_one_insn(ep, insn);
	return VOID;
}

static pseudo_t linearize_range(struct entrypoint *ep, struct statement *stmt)
{
	struct instruction *insn = alloc_instruction(OP_RANGE, 0);

	use_pseudo(insn, linearize_expression(ep, stmt->range_expression), &insn->src1);
	use_pseudo(insn, linearize_expression(ep, stmt->range_low), &insn->src2);
	use_pseudo(insn, linearize_expression(ep, stmt->range_high), &insn->src3);
	add_one_insn(ep, insn);
	return VOID;
}

ALLOCATOR(asm_rules, "asm rules");
ALLOCATOR(asm_constraint, "asm constraints");

static void add_asm_input(struct entrypoint *ep, struct instruction *insn, struct expression *expr,
	const char *constraint, const struct ident *ident)
{
	pseudo_t pseudo = linearize_expression(ep, expr);
	struct asm_constraint *rule = __alloc_asm_constraint(0);

	rule->ident = ident;
	rule->constraint = constraint;
	use_pseudo(insn, pseudo, &rule->pseudo);
	add_ptr_list(&insn->asm_rules->inputs, rule);
}

static void add_asm_output(struct entrypoint *ep, struct instruction *insn, struct expression *expr,
	const char *constraint, const struct ident *ident)
{
	struct access_data ad = { NULL, };
	pseudo_t pseudo = alloc_pseudo(insn);
	struct asm_constraint *rule;

	if (!expr || !linearize_address_gen(ep, expr, &ad))
		return;
	linearize_store_gen(ep, pseudo, &ad);
	rule = __alloc_asm_constraint(0);
	rule->ident = ident;
	rule->constraint = constraint;
	use_pseudo(insn, pseudo, &rule->pseudo);
	add_ptr_list(&insn->asm_rules->outputs, rule);
}

static pseudo_t linearize_asm_statement(struct entrypoint *ep, struct statement *stmt)
{
	struct expression *expr;
	struct instruction *insn;
	struct asm_rules *rules;
	const char *constraint;

	insn = alloc_instruction(OP_ASM, 0);
	expr = stmt->asm_string;
	if (!expr || expr->type != EXPR_STRING) {
		warning(stmt->pos, "expected string in inline asm");
		return VOID;
	}
	insn->string = expr->string->data;

	rules = __alloc_asm_rules(0);
	insn->asm_rules = rules;

	/* Gather the inputs.. */
	FOR_EACH_PTR(stmt->asm_inputs, expr) {
		constraint = expr->constraint ? expr->constraint->string->data : "";
		add_asm_input(ep, insn, expr->expr, constraint, expr->name);
	} END_FOR_EACH_PTR(expr);

	add_one_insn(ep, insn);

	/* Assign the outputs */
	FOR_EACH_PTR(stmt->asm_outputs, expr) {
		constraint = expr->constraint ? expr->constraint->string->data : "";
		add_asm_output(ep, insn, expr->expr, constraint, expr->name);
	} END_FOR_EACH_PTR(expr);

	return VOID;
}

static int multijmp_cmp(const void *_a, const void *_b)
{
	const struct multijmp *a = _a;
	const struct multijmp *b = _b;

	// "default" case?
	if (a->begin > a->end) {
		if (b->begin > b->end)
			return 0;
		return 1;
	}
	if (b->begin > b->end)
		return -1;
	if (a->begin == b->begin) {
		if (a->end == b->end)
			return 0;
		return (a->end < b->end) ? -1 : 1;
	}
	return a->begin < b->begin ? -1 : 1;
}

static void sort_switch_cases(struct instruction *insn)
{
	sort_list((struct ptr_list **)&insn->multijmp_list, multijmp_cmp);
}

static pseudo_t linearize_declaration(struct entrypoint *ep, struct statement *stmt)
{
	struct symbol *sym;

	concat_symbol_list(stmt->declaration, &ep->syms);

	FOR_EACH_PTR(stmt->declaration, sym) {
		linearize_one_symbol(ep, sym);
	} END_FOR_EACH_PTR(sym);
	return VOID;
}

static pseudo_t linearize_return(struct entrypoint *ep, struct statement *stmt)
{
	struct expression *expr = stmt->expression;
	struct symbol *ret = stmt->ret_target;
	struct basic_block *bb_return = get_bound_block(ep, ret);
	struct basic_block *active;
	pseudo_t src = linearize_expression(ep, expr);
	active = ep->active;
	if (active && !is_void_type(ret)) {
		add_return(ep, bb_return, ret, src);
	}
	add_goto(ep, bb_return);
	return VOID;
}

static pseudo_t linearize_switch(struct entrypoint *ep, struct statement *stmt)
{
	struct symbol *sym;
	struct instruction *switch_ins;
	struct basic_block *switch_end = alloc_basic_block(ep, stmt->pos);
	struct basic_block *active, *default_case;
	struct expression *expr = stmt->switch_expression;
	struct multijmp *jmp;
	pseudo_t pseudo;

	if (!expr || !expr->ctype)
		return VOID;
	pseudo = linearize_expression(ep, expr);
	active = ep->active;
	if (!active) {
		active = alloc_basic_block(ep, stmt->pos);
		set_activeblock(ep, active);
	}

	switch_ins = alloc_typed_instruction(OP_SWITCH, expr->ctype);
	use_pseudo(switch_ins, pseudo, &switch_ins->cond);
	add_one_insn(ep, switch_ins);
	finish_block(ep);

	default_case = NULL;
	FOR_EACH_PTR(stmt->switch_case->symbol_list, sym) {
		struct statement *case_stmt = sym->stmt;
		struct basic_block *bb_case = get_bound_block(ep, sym);

		if (!case_stmt->case_expression) {
			default_case = bb_case;
			continue;
		} else if (case_stmt->case_expression->type != EXPR_VALUE) {
			continue;
		} else {
			struct expression *case_to = case_stmt->case_to;
			long long begin, end;

			begin = end = case_stmt->case_expression->value;
			if (case_to && case_to->type == EXPR_VALUE)
				end = case_to->value;
			if (begin > end)
				jmp = alloc_multijmp(bb_case, end, begin);
			else
				jmp = alloc_multijmp(bb_case, begin, end);

		}
		add_multijmp(&switch_ins->multijmp_list, jmp);
		add_bb(&bb_case->parents, active);
		add_bb(&active->children, bb_case);
	} END_FOR_EACH_PTR(sym);

	bind_label(stmt->switch_break, switch_end, stmt->pos);

	/* And linearize the actual statement */
	linearize_statement(ep, stmt->switch_statement);
	set_activeblock(ep, switch_end);

	if (!default_case)
		default_case = switch_end;

	jmp = alloc_multijmp(default_case, 1, 0);
	add_multijmp(&switch_ins->multijmp_list, jmp);
	add_bb(&default_case->parents, active);
	add_bb(&active->children, default_case);
	sort_switch_cases(switch_ins);

	return VOID;
}

static pseudo_t linearize_iterator(struct entrypoint *ep, struct statement *stmt)
{
	struct statement  *pre_statement = stmt->iterator_pre_statement;
	struct expression *pre_condition = stmt->iterator_pre_condition;
	struct statement  *statement = stmt->iterator_statement;
	struct statement  *post_statement = stmt->iterator_post_statement;
	struct expression *post_condition = stmt->iterator_post_condition;
	struct basic_block *loop_top, *loop_body, *loop_continue, *loop_end;
	struct symbol *sym;

	FOR_EACH_PTR(stmt->iterator_syms, sym) {
		linearize_one_symbol(ep, sym);
	} END_FOR_EACH_PTR(sym);
	concat_symbol_list(stmt->iterator_syms, &ep->syms);
	linearize_statement(ep, pre_statement);

	loop_body = loop_top = alloc_basic_block(ep, stmt->pos);
	loop_continue = alloc_basic_block(ep, stmt->pos);
	loop_end = alloc_basic_block(ep, stmt->pos);

	/* An empty post-condition means that it's the same as the pre-condition */
	if (!post_condition) {
		loop_top = alloc_basic_block(ep, stmt->pos);
		set_activeblock(ep, loop_top);
	}

	if (pre_condition)
			linearize_cond_branch(ep, pre_condition, loop_body, loop_end);

	bind_label(stmt->iterator_continue, loop_continue, stmt->pos);
	bind_label(stmt->iterator_break, loop_end, stmt->pos);

	set_activeblock(ep, loop_body);
	linearize_statement(ep, statement);
	add_goto(ep, loop_continue);

	set_activeblock(ep, loop_continue);
	linearize_statement(ep, post_statement);
	if (!post_condition)
		add_goto(ep, loop_top);
	else
		linearize_cond_branch(ep, post_condition, loop_top, loop_end);
	set_activeblock(ep, loop_end);

	return VOID;
}

static pseudo_t linearize_statement(struct entrypoint *ep, struct statement *stmt)
{
	struct basic_block *bb;

	if (!stmt)
		return VOID;

	bb = ep->active;
	if (bb && !bb->insns)
		bb->pos = stmt->pos;
	current_pos = stmt->pos;

	switch (stmt->type) {
	case STMT_NONE:
		break;

	case STMT_DECLARATION:
		return linearize_declaration(ep, stmt);

	case STMT_CONTEXT:
		return linearize_context(ep, stmt);

	case STMT_RANGE:
		return linearize_range(ep, stmt);

	case STMT_EXPRESSION:
		return linearize_expression(ep, stmt->expression);

	case STMT_ASM:
		return linearize_asm_statement(ep, stmt);

	case STMT_RETURN:
		return linearize_return(ep, stmt);

	case STMT_CASE: {
		add_label(ep, stmt->case_label);
		linearize_statement(ep, stmt->case_statement);
		break;
	}

	case STMT_LABEL: {
		struct symbol *label = stmt->label_identifier;

		if (label->used) {
			add_label(ep, label);
		}
		return linearize_statement(ep, stmt->label_statement);
	}

	case STMT_GOTO: {
		struct symbol *sym;
		struct expression *expr;
		struct instruction *goto_ins;
		struct basic_block *active;
		pseudo_t pseudo;

		active = ep->active;
		if (!bb_reachable(active))
			break;

		if (stmt->goto_label) {
			add_goto(ep, get_bound_block(ep, stmt->goto_label));
			break;
		}

		expr = stmt->goto_expression;
		if (!expr)
			break;

		/* This can happen as part of simplification */
		if (expr->type == EXPR_LABEL) {
			add_goto(ep, get_bound_block(ep, expr->label_symbol));
			break;
		}

		pseudo = linearize_expression(ep, expr);
		goto_ins = alloc_instruction(OP_COMPUTEDGOTO, 0);
		use_pseudo(goto_ins, pseudo, &goto_ins->src);
		add_one_insn(ep, goto_ins);

		FOR_EACH_PTR(stmt->target_list, sym) {
			struct basic_block *bb_computed = get_bound_block(ep, sym);
			struct multijmp *jmp = alloc_multijmp(bb_computed, 1, 0);
			add_multijmp(&goto_ins->multijmp_list, jmp);
			add_bb(&bb_computed->parents, ep->active);
			add_bb(&active->children, bb_computed);
		} END_FOR_EACH_PTR(sym);

		finish_block(ep);
		break;
	}

	case STMT_COMPOUND:
		if (stmt->inline_fn)
			return linearize_inlined_call(ep, stmt);
		return linearize_compound_statement(ep, stmt);

	/*
	 * This could take 'likely/unlikely' into account, and
	 * switch the arms around appropriately..
	 */
	case STMT_IF: {
		struct basic_block *bb_true, *bb_false, *endif;
 		struct expression *cond = stmt->if_conditional;

		bb_true = alloc_basic_block(ep, stmt->pos);
		bb_false = endif = alloc_basic_block(ep, stmt->pos);

 		linearize_cond_branch(ep, cond, bb_true, bb_false);

		set_activeblock(ep, bb_true);
 		linearize_statement(ep, stmt->if_true);
 
 		if (stmt->if_false) {
			endif = alloc_basic_block(ep, stmt->pos);
			add_goto(ep, endif);
			set_activeblock(ep, bb_false);
 			linearize_statement(ep, stmt->if_false);
		}
		set_activeblock(ep, endif);
		break;
	}

	case STMT_SWITCH:
		return linearize_switch(ep, stmt);

	case STMT_ITERATOR:
		return linearize_iterator(ep, stmt);

	default:
		break;
	}
	return VOID;
}

static struct entrypoint *linearize_fn(struct symbol *sym, struct symbol *base_type)
{
	struct statement *stmt = base_type->stmt;
	struct entrypoint *ep;
	struct basic_block *bb;
	struct symbol *ret_type;
	struct symbol *arg;
	struct instruction *entry;
	struct instruction *ret;
	pseudo_t result;
	int i;

	if (!stmt)
		return NULL;

	ep = alloc_entrypoint();
	ep->name = sym;
	sym->ep = ep;
	bb = alloc_basic_block(ep, sym->pos);
	set_activeblock(ep, bb);

	if (stmt->type == STMT_ASM) {	// top-level asm
		linearize_asm_statement(ep, stmt);
		return ep;
	}

	entry = alloc_instruction(OP_ENTRY, 0);
	add_one_insn(ep, entry);
	ep->entry = entry;

	concat_symbol_list(base_type->arguments, &ep->syms);

	/* FIXME!! We should do something else about varargs.. */
	i = 0;
	FOR_EACH_PTR(base_type->arguments, arg) {
		linearize_argument(ep, arg, ++i);
	} END_FOR_EACH_PTR(arg);

	result = linearize_fn_statement(ep, stmt);
	ret_type = base_type->ctype.base_type;
	ret = alloc_typed_instruction(OP_RET, ret_type);
	if (type_size(ret_type) > 0)
		use_pseudo(ret, result, &ret->src);
	add_one_insn(ep, ret);

	optimize(ep);
	return ep;
}

struct entrypoint *linearize_symbol(struct symbol *sym)
{
	struct symbol *base_type;

	if (!sym)
		return NULL;
	current_pos = sym->pos;
	base_type = sym->ctype.base_type;
	if (!base_type)
		return NULL;
	if (base_type->type == SYM_FN)
		return linearize_fn(sym, base_type);
	return NULL;
}

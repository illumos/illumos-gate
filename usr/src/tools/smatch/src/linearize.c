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
#include "flow.h"
#include "target.h"

pseudo_t linearize_statement(struct entrypoint *ep, struct statement *stmt);
pseudo_t linearize_expression(struct entrypoint *ep, struct expression *expr);

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
	bb->context = -1;
	bb->pos = pos;
	bb->ep = ep;
	bb->nr = nr++;
	return bb;
}

static struct multijmp *alloc_multijmp(struct basic_block *target, int begin, int end)
{
	struct multijmp *multijmp = __alloc_multijmp(0);
	multijmp->target = target;
	multijmp->begin = begin;
	multijmp->end = end;
	return multijmp;
}

static inline int regno(pseudo_t n)
{
	int retval = -1;
	if (n && n->type == PSEUDO_REG)
		retval = n->nr;
	return retval;
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

		if (sym->bb_target) {
			snprintf(buf, 64, ".L%u", sym->bb_target->nr);
			break;
		}
		if (sym->ident) {
			snprintf(buf, 64, "%s", show_ident(sym->ident));
			break;
		}
		expr = sym->initializer;
		snprintf(buf, 64, "<anon symbol:%p>", sym);
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
	[OP_INVOKE] = "invoke",
	[OP_COMPUTEDGOTO] = "jmp *",
	[OP_UNWIND] = "unwind",
	
	/* Binary */
	[OP_ADD] = "add",
	[OP_SUB] = "sub",
	[OP_MULU] = "mulu",
	[OP_MULS] = "muls",
	[OP_DIVU] = "divu",
	[OP_DIVS] = "divs",
	[OP_MODU] = "modu",
	[OP_MODS] = "mods",
	[OP_SHL] = "shl",
	[OP_LSR] = "lsr",
	[OP_ASR] = "asr",
	
	/* Logical */
	[OP_AND] = "and",
	[OP_OR] = "or",
	[OP_XOR] = "xor",
	[OP_AND_BOOL] = "and-bool",
	[OP_OR_BOOL] = "or-bool",

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

	/* Uni */
	[OP_NOT] = "not",
	[OP_NEG] = "neg",

	/* Special three-input */
	[OP_SEL] = "select",
	
	/* Memory */
	[OP_MALLOC] = "malloc",
	[OP_FREE] = "free",
	[OP_ALLOCA] = "alloca",
	[OP_LOAD] = "load",
	[OP_STORE] = "store",
	[OP_SETVAL] = "set",
	[OP_SYMADDR] = "symaddr",
	[OP_GET_ELEMENT_PTR] = "getelem",

	/* Other */
	[OP_PHI] = "phi",
	[OP_PHISOURCE] = "phisrc",
	[OP_CAST] = "cast",
	[OP_SCAST] = "scast",
	[OP_FPCAST] = "fpcast",
	[OP_PTRCAST] = "ptrcast",
	[OP_INLINED_CALL] = "# call",
	[OP_CALL] = "call",
	[OP_VANEXT] = "va_next",
	[OP_VAARG] = "va_arg",
	[OP_SLICE] = "slice",
	[OP_SNOP] = "snop",
	[OP_LNOP] = "lnop",
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
		buf += sprintf(buf, "%s, .L%u, .L%u", show_pseudo(insn->cond), insn->bb_true->nr, insn->bb_false->nr);
		break;

	case OP_BR:
		buf += sprintf(buf, ".L%u", insn->bb_true->nr);
		break;

	case OP_SYMADDR: {
		struct symbol *sym = insn->symbol->sym;
		buf += sprintf(buf, "%s <- ", show_pseudo(insn->target));

		if (!insn->bb && !sym)
			break;
		if (sym->bb_target) {
			buf += sprintf(buf, ".L%u", sym->bb_target->nr);
			break;
		}
		if (sym->ident) {
			buf += sprintf(buf, "%s", show_ident(sym->ident));
			break;
		}
		buf += sprintf(buf, "<anon symbol:%p>", sym);
		break;
	}
		
	case OP_SETVAL: {
		struct expression *expr = insn->val;
		struct symbol *sym;
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
			buf += sprintf(buf, "%Lf", expr->fvalue);
			break;
		case EXPR_STRING:
			buf += sprintf(buf, "%.40s", show_string(expr->string));
			break;
		case EXPR_SYMBOL:
			buf += sprintf(buf, "%s", show_ident(expr->symbol->ident));
			break;
		case EXPR_LABEL:
			sym = expr->symbol;
			if (sym->bb_target)
				buf += sprintf(buf, ".L%u", sym->bb_target->nr);
			break;
		default:
			buf += sprintf(buf, "SETVAL EXPR TYPE %d", expr->type);
		}
		break;
	}
	case OP_SWITCH: {
		struct multijmp *jmp;
		buf += sprintf(buf, "%s", show_pseudo(insn->cond));
		FOR_EACH_PTR(insn->multijmp_list, jmp) {
			if (jmp->begin == jmp->end)
				buf += sprintf(buf, ", %d -> .L%u", jmp->begin, jmp->target->nr);
			else if (jmp->begin < jmp->end)
				buf += sprintf(buf, ", %d ... %d -> .L%u", jmp->begin, jmp->end, jmp->target->nr);
			else
				buf += sprintf(buf, ", default -> .L%u", jmp->target->nr);
		} END_FOR_EACH_PTR(jmp);
		break;
	}
	case OP_COMPUTEDGOTO: {
		struct multijmp *jmp;
		buf += sprintf(buf, "%s", show_pseudo(insn->target));
		FOR_EACH_PTR(insn->multijmp_list, jmp) {
			buf += sprintf(buf, ", .L%u", jmp->target->nr);
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
			buf += sprintf(buf, "%s %s", s, show_pseudo(phi));
			s = ",";
		} END_FOR_EACH_PTR(phi);
		break;
	}	
	case OP_LOAD: case OP_LNOP:
		buf += sprintf(buf, "%s <- %d[%s]", show_pseudo(insn->target), insn->offset, show_pseudo(insn->src));
		break;
	case OP_STORE: case OP_SNOP:
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
	case OP_CAST:
	case OP_SCAST:
	case OP_FPCAST:
	case OP_PTRCAST:
		buf += sprintf(buf, "%s <- (%d) %s",
			show_pseudo(insn->target),
			type_size(insn->orig_type),
			show_pseudo(insn->src));
		break;
	case OP_BINARY ... OP_BINARY_END:
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

	printf(".L%u:\n", bb->nr);
	if (verbose) {
		pseudo_t needs, defines;
		printf("%s:%d\n", stream_name(bb->pos.stream), bb->pos.line);

		FOR_EACH_PTR(bb->needs, needs) {
			struct instruction *def = needs->def;
			if (def->opcode != OP_PHI) {
				printf("  **uses %s (from .L%u)**\n", show_pseudo(needs), def->bb->nr);
			} else {
				pseudo_t phi;
				const char *sep = " ";
				printf("  **uses %s (from", show_pseudo(needs));
				FOR_EACH_PTR(def->phi_list, phi) {
					if (phi == VOID)
						continue;
					printf("%s(%s:.L%u)", sep, show_pseudo(phi), phi->def->bb->nr);
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
				printf("  **from .L%u (%s:%d:%d)**\n", from->nr,
					stream_name(from->pos.stream), from->pos.line, from->pos.pos);
			} END_FOR_EACH_PTR(from);
		}

		if (bb->children) {
			struct basic_block *to;
			FOR_EACH_PTR(bb->children, to) {
				printf("  **to .L%u (%s:%d:%d)**\n", to->nr,
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

	select = alloc_instruction(OP_SEL, phi_node->size);
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

static void add_branch(struct entrypoint *ep, struct expression *expr, pseudo_t cond, struct basic_block *bb_true, struct basic_block *bb_false)
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

/* Dummy pseudo allocator */
pseudo_t alloc_pseudo(struct instruction *def)
{
	static int nr = 0;
	struct pseudo * pseudo = __alloc_pseudo(0);
	pseudo->type = PSEUDO_REG;
	pseudo->nr = ++nr;
	pseudo->def = def;
	return pseudo;
}

static void clear_symbol_pseudos(struct entrypoint *ep)
{
	pseudo_t pseudo;

	FOR_EACH_PTR(ep->accesses, pseudo) {
		pseudo->sym->pseudo = NULL;
	} END_FOR_EACH_PTR(pseudo);
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
	/* Symbol pseudos have neither nr, usage nor def */
	return pseudo;
}

pseudo_t value_pseudo(struct symbol *type, long long val)
{
#define MAX_VAL_HASH 64
	static struct pseudo_list *prev[MAX_VAL_HASH];
	int hash = val & (MAX_VAL_HASH-1);
	struct pseudo_list **list = prev + hash;
	int size = type ? type->bit_size : value_size(val);
	pseudo_t pseudo;


	FOR_EACH_PTR(*list, pseudo) {
		if (pseudo->value == val && pseudo->size == size)
			return pseudo;
	} END_FOR_EACH_PTR(pseudo);

	pseudo = __alloc_pseudo(0);
	pseudo->type = PSEUDO_VAL;
	pseudo->value = val;
	pseudo->size = size;
	add_pseudo(list, pseudo);

	/* Value pseudos have neither nr, usage nor def */
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

pseudo_t alloc_phi(struct basic_block *source, pseudo_t pseudo, int size)
{
	struct instruction *insn;
	pseudo_t phi;
	static int nr = 0;

	if (!source)
		return VOID;

	insn = alloc_instruction(OP_PHISOURCE, size);
	phi = __alloc_pseudo(0);
	phi->type = PSEUDO_PHI;
	phi->nr = ++nr;
	phi->def = insn;

	use_pseudo(insn, pseudo, &insn->phi_src);
	insn->bb = source;
	insn->target = phi;
	add_instruction(&source->insns, insn);
	return phi;
}

/*
 * We carry the "access_data" structure around for any accesses,
 * which simplifies things a lot. It contains all the access
 * information in one place.
 */
struct access_data {
	struct symbol *result_type;	// result ctype
	struct symbol *source_type;	// source ctype
	pseudo_t address;		// pseudo containing address ..
	unsigned int offset;		// byte offset
	struct position pos;
};

static void finish_address_gen(struct entrypoint *ep, struct access_data *ad)
{
}

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

static struct symbol *base_type(struct symbol *sym)
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
	ad->pos = expr->pos;
	ad->result_type = ctype;
	ad->source_type = base_type(ctype);
	if (expr->type == EXPR_PREOP && expr->op == '*')
		return linearize_simple_address(ep, expr->unop, ad);

	warning(expr->pos, "generating address of non-lvalue (%d)", expr->type);
	return 0;
}

static pseudo_t add_load(struct entrypoint *ep, struct access_data *ad)
{
	struct instruction *insn;
	pseudo_t new;

	insn = alloc_typed_instruction(OP_LOAD, ad->source_type);
	new = alloc_pseudo(insn);

	insn->target = new;
	insn->offset = ad->offset;
	use_pseudo(insn, ad->address, &insn->src);
	add_one_insn(ep, insn);
	return new;
}

static void add_store(struct entrypoint *ep, struct access_data *ad, pseudo_t value)
{
	struct basic_block *bb = ep->active;

	if (bb_reachable(bb)) {
		struct instruction *store = alloc_typed_instruction(OP_STORE, ad->source_type);
		store->offset = ad->offset;
		use_pseudo(store, value, &store->target);
		use_pseudo(store, ad->address, &store->src);
		add_one_insn(ep, store);
	}
}

static pseudo_t linearize_store_gen(struct entrypoint *ep,
		pseudo_t value,
		struct access_data *ad)
{
	pseudo_t store = value;

	if (type_size(ad->source_type) != type_size(ad->result_type)) {
		struct symbol *ctype = ad->result_type;
		unsigned int shift = ctype->bit_offset;
		unsigned int size = ctype->bit_size;
		pseudo_t orig = add_load(ep, ad);
		unsigned long long mask = (1ULL << size) - 1;

		if (shift) {
			store = add_binary_op(ep, ad->source_type, OP_SHL, value, value_pseudo(ctype, shift));
			mask <<= shift;
		}
		orig = add_binary_op(ep, ad->source_type, OP_AND, orig, value_pseudo(ctype, ~mask));
		store = add_binary_op(ep, ad->source_type, OP_OR, orig, store);
	}
	add_store(ep, ad, store);
	return value;
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

static pseudo_t add_symbol_address(struct entrypoint *ep, struct symbol *sym)
{
	struct instruction *insn = alloc_instruction(OP_SYMADDR, bits_in_pointer);
	pseudo_t target = alloc_pseudo(insn);

	insn->target = target;
	use_pseudo(insn, symbol_pseudo(ep, sym), &insn->symbol);
	add_one_insn(ep, insn);
	return target;
}

static pseudo_t linearize_load_gen(struct entrypoint *ep, struct access_data *ad)
{
	struct symbol *ctype = ad->result_type;
	pseudo_t new = add_load(ep, ad);

	if (ctype->bit_offset) {
		pseudo_t shift = value_pseudo(ctype, ctype->bit_offset);
		pseudo_t newval = add_binary_op(ep, ad->source_type, OP_LSR, new, shift);
		new = newval;
	}
	if (ctype->bit_size != type_size(ad->source_type))
		new = cast_pseudo(ep, new, ad->source_type, ad->result_type);
	return new;
}

static pseudo_t linearize_access(struct entrypoint *ep, struct expression *expr)
{
	struct access_data ad = { NULL, };
	pseudo_t value;

	if (!linearize_address_gen(ep, expr, &ad))
		return VOID;
	value = linearize_load_gen(ep, &ad);
	finish_address_gen(ep, &ad);
	return value;
}

/* FIXME: FP */
static pseudo_t linearize_inc_dec(struct entrypoint *ep, struct expression *expr, int postop)
{
	struct access_data ad = { NULL, };
		pseudo_t old, new, one;
	int op = expr->op == SPECIAL_INCREMENT ? OP_ADD : OP_SUB;

	if (!linearize_address_gen(ep, expr->unop, &ad))
		return VOID;

	old = linearize_load_gen(ep, &ad);
	one = value_pseudo(expr->ctype, expr->op_value);
	new = add_binary_op(ep, expr->ctype, op, old, one);
	linearize_store_gen(ep, new, &ad);
	finish_address_gen(ep, &ad);
	return postop ? old : new;
}

static pseudo_t add_uniop(struct entrypoint *ep, struct expression *expr, int op, pseudo_t src)
{
	struct instruction *insn = alloc_typed_instruction(op, expr->ctype);
	pseudo_t new = alloc_pseudo(insn);

	insn->target = new;
	use_pseudo(insn, src, &insn->src1);
	add_one_insn(ep, insn);
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
	switch (expr->op) {
	case '+':
		return pre;
	case '!': {
		pseudo_t zero = value_pseudo(expr->ctype, 0);
		return add_binary_op(ep, expr->ctype, OP_SET_EQ, pre, zero);
	}
	case '~':
		return add_uniop(ep, expr, OP_NOT, pre);
	case '-':
		return add_uniop(ep, expr, OP_NEG, pre);
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
static struct instruction *alloc_cast_instruction(struct symbol *src, struct symbol *ctype)
{
	int opcode = OP_CAST;
	struct symbol *base = ctype;

	if (src->ctype.modifiers & MOD_SIGNED)
		opcode = OP_SCAST;
	if (base->type == SYM_NODE)
		base = base->ctype.base_type;
	if (base->type == SYM_PTR) {
		base = base->ctype.base_type;
		if (base != &void_ctype)
			opcode = OP_PTRCAST;
	} else if (base->ctype.base_type == &fp_type)
		opcode = OP_FPCAST;
	return alloc_typed_instruction(opcode, ctype);
}

static pseudo_t cast_pseudo(struct entrypoint *ep, pseudo_t src, struct symbol *from, struct symbol *to)
{
	pseudo_t result;
	struct instruction *insn;

	if (src == VOID)
		return VOID;
	if (!from || !to)
		return VOID;
	if (from->bit_size < 0 || to->bit_size < 0)
		return VOID;
	insn = alloc_cast_instruction(from, to);
	result = alloc_pseudo(insn);
	insn->target = result;
	insn->orig_type = from;
	use_pseudo(insn, src, &insn->src);
	add_one_insn(ep, insn);
	return result;
}

static int opcode_sign(int opcode, struct symbol *ctype)
{
	if (ctype && (ctype->ctype.modifiers & MOD_SIGNED)) {
		switch(opcode) {
		case OP_MULU: case OP_DIVU: case OP_MODU: case OP_LSR:
			opcode++;
		}
	}
	return opcode;
}

static inline pseudo_t add_convert_to_bool(struct entrypoint *ep, pseudo_t src, struct symbol *type)
{
	pseudo_t zero;
	int op;

	if (is_bool_type(type))
		return src;
	zero = value_pseudo(type, 0);
	op = OP_SET_NE;
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
			[SPECIAL_MUL_ASSIGN - SPECIAL_BASE] = OP_MULU,
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
		opcode = opcode_sign(op_trans[expr->op - SPECIAL_BASE], ctype);
		dst = add_binary_op(ep, ctype, opcode, oldvalue, value);
		value = cast_pseudo(ep, dst, ctype, expr->ctype);
	}
	value = linearize_store_gen(ep, value, &ad);
	finish_address_gen(ep, &ad);
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

	if (!expr->ctype) {
		warning(expr->pos, "call with no type!");
		return VOID;
	}

	FOR_EACH_PTR(expr->args, arg) {
		pseudo_t new = linearize_expression(ep, arg);
		use_pseudo(insn, new, add_pseudo(&insn->arguments, new));
	} END_FOR_EACH_PTR(arg);

	fn = expr->fn;

	if (fn->ctype)
		ctype = &fn->ctype->ctype;

	fntype = fn->ctype;
	if (fntype) {
		if (fntype->type == SYM_NODE)
			fntype = fntype->ctype.base_type;
	}
	insn->fntype = fntype;

	if (fn->type == EXPR_PREOP) {
		if (fn->unop->type == EXPR_SYMBOL) {
			struct symbol *sym = fn->unop->symbol;
			if (sym->ctype.base_type->type == SYM_FN)
				fn = fn->unop;
		}
	}
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
	int op = (expr->op == SPECIAL_LOGICAL_OR) ? OP_OR_BOOL : OP_AND_BOOL;

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
		['*'] = OP_MULU, ['/'] = OP_DIVU,
		['%'] = OP_MODU, ['&'] = OP_AND,
		['|'] = OP_OR,  ['^'] = OP_XOR,
		[SPECIAL_LEFTSHIFT] = OP_SHL,
		[SPECIAL_RIGHTSHIFT] = OP_LSR,
	};
	int op;

	src1 = linearize_expression(ep, expr->left);
	src2 = linearize_expression(ep, expr->right);
	op = opcode_sign(opcode[expr->op], expr->ctype);
	dst = add_binary_op(ep, expr->ctype, op, src1, src2);
	return dst;
}

static pseudo_t linearize_logical_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false);

pseudo_t linearize_cond_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false);

static pseudo_t linearize_select(struct entrypoint *ep, struct expression *expr)
{
	pseudo_t cond, true, false, res;
	struct instruction *insn;

	true = linearize_expression(ep, expr->cond_true);
	false = linearize_expression(ep, expr->cond_false);
	cond = linearize_expression(ep, expr->conditional);

	insn = alloc_typed_instruction(OP_SEL, expr->ctype);
	if (!expr->cond_true)
		true = cond;
	use_pseudo(insn, cond, &insn->src1);
	use_pseudo(insn, true, &insn->src2);
	use_pseudo(insn, false, &insn->src3);

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
	struct basic_block *merge = alloc_basic_block(ep, expr->pos);
	pseudo_t phi1, phi2;
	int size = type_size(expr->ctype);

	if (!expr_false || !ep->active)
		return VOID;

	bb_false = alloc_basic_block(ep, expr_false->pos);
	src1 = linearize_expression(ep, cond);
	phi1 = alloc_phi(ep->active, src1, size);
	add_branch(ep, expr, src1, merge, bb_false);

	set_activeblock(ep, bb_false);
	src2 = linearize_expression(ep, expr_false);
	phi2 = alloc_phi(ep->active, src2, size);
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
	int size = type_size(expr->ctype);

	if (!cond || !expr_true || !expr_false || !ep->active)
		return VOID;
	bb_true = alloc_basic_block(ep, expr_true->pos);
	bb_false = alloc_basic_block(ep, expr_false->pos);
	merge = alloc_basic_block(ep, expr->pos);

	linearize_cond_branch(ep, cond, bb_true, bb_false);

	set_activeblock(ep, bb_true);
	src1 = linearize_expression(ep, expr_true);
	phi1 = alloc_phi(ep->active, src1, size);
	add_goto(ep, merge); 

	set_activeblock(ep, bb_false);
	src2 = linearize_expression(ep, expr_false);
	phi2 = alloc_phi(ep->active, src2, size);
	set_activeblock(ep, merge);

	return add_join_conditional(ep, expr, phi1, phi2);
}

static pseudo_t linearize_logical(struct entrypoint *ep, struct expression *expr)
{
	struct expression *shortcut;

	shortcut = alloc_const_expression(expr->pos, expr->op == SPECIAL_LOGICAL_OR);
	shortcut->ctype = expr->ctype;
	if (expr->op == SPECIAL_LOGICAL_OR)
		return linearize_conditional(ep, expr, expr->left, shortcut, expr->right);
	return linearize_conditional(ep, expr, expr->left, expr->right, shortcut);
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

	pseudo_t src1 = linearize_expression(ep, expr->left);
	pseudo_t src2 = linearize_expression(ep, expr->right);
	pseudo_t dst = add_binary_op(ep, expr->ctype, cmpop[expr->op], src1, src2);
	return dst;
}


pseudo_t linearize_cond_branch(struct entrypoint *ep, struct expression *expr, struct basic_block *bb_true, struct basic_block *bb_false)
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
		add_branch(ep, expr, cond, bb_true, bb_false);
		break;
		
	case EXPR_PREOP:
		if (expr->op == '!')
			return linearize_cond_branch(ep, expr->unop, bb_false, bb_true);
		/* fall through */
	default: {
		cond = linearize_expression(ep, expr);
		add_branch(ep, expr, cond, bb_true, bb_false);

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

static pseudo_t linearize_position(struct entrypoint *ep, struct expression *pos, struct access_data *ad)
{
	struct expression *init_expr = pos->init_expr;

	ad->offset = pos->init_offset;
	ad->source_type = base_type(init_expr->ctype);
	ad->result_type = init_expr->ctype;
	return linearize_initializer(ep, init_expr, ad);
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
		linearize_position(ep, initializer, ad);
		break;
	default: {
		pseudo_t value = linearize_expression(ep, initializer);
		ad->source_type = base_type(initializer->ctype);
		ad->result_type = initializer->ctype;
		linearize_store_gen(ep, value, ad);
		return value;
	}
	}

	return VOID;
}

static void linearize_argument(struct entrypoint *ep, struct symbol *arg, int nr)
{
	struct access_data ad = { NULL, };

	ad.source_type = arg;
	ad.result_type = arg;
	ad.address = symbol_pseudo(ep, arg);
	linearize_store_gen(ep, argument_pseudo(ep, nr), &ad);
	finish_address_gen(ep, &ad);
}

pseudo_t linearize_expression(struct entrypoint *ep, struct expression *expr)
{
	if (!expr)
		return VOID;

	current_pos = expr->pos;
	switch (expr->type) {
	case EXPR_SYMBOL:
		linearize_one_symbol(ep, expr->symbol);
		return add_symbol_address(ep, expr->symbol);

	case EXPR_VALUE:
		return value_pseudo(expr->ctype, expr->value);

	case EXPR_STRING: case EXPR_FVALUE: case EXPR_LABEL:
		return add_setval(ep, expr->ctype, expr);

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
		struct expression *expr = sym->initializer;
		ad.pos = expr->pos;
		ad.result_type = sym;
		ad.source_type = base_type(sym);
		ad.address = symbol_pseudo(ep, sym);
		linearize_store_gen(ep, value_pseudo(sym, 0), &ad);
	}

	value = linearize_initializer(ep, sym->initializer, &ad);
	finish_address_gen(ep, &ad);
	return value;
}

static pseudo_t linearize_compound_statement(struct entrypoint *ep, struct statement *stmt)
{
	pseudo_t pseudo;
	struct statement *s;
	struct symbol *ret = stmt->ret;

	pseudo = VOID;
	FOR_EACH_PTR(stmt->stmts, s) {
		pseudo = linearize_statement(ep, s);
	} END_FOR_EACH_PTR(s);

	if (ret) {
		struct basic_block *bb = add_label(ep, ret);
		struct instruction *phi_node = first_instruction(bb->insns);

		if (!phi_node)
			return pseudo;

		if (pseudo_list_size(phi_node->phi_list)==1) {
			pseudo = first_pseudo(phi_node->phi_list);
			assert(pseudo->type == PSEUDO_PHI);
			return pseudo->def->src1;
		}
		return phi_node->target;
	}

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
			use_pseudo(insn, value, add_pseudo(&insn->arguments, value));
		} END_FOR_EACH_PTR(sym);
	}

	insn->target = pseudo = linearize_compound_statement(ep, stmt);
	use_pseudo(insn, symbol_pseudo(ep, stmt->inline_fn), &insn->func);
	bb = ep->active;
	if (bb && !bb->insns)
		bb->pos = stmt->pos;
	add_one_insn(ep, insn);
	return pseudo;
}

static pseudo_t linearize_context(struct entrypoint *ep, struct statement *stmt)
{
	struct instruction *insn = alloc_instruction(OP_CONTEXT, 0);
	struct expression *expr = stmt->expression;
	int value = 0;

	if (expr->type == EXPR_VALUE)
		value = expr->value;

	insn->increment = value;
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
	finish_address_gen(ep, &ad);
	rule = __alloc_asm_constraint(0);
	rule->ident = ident;
	rule->constraint = constraint;
	use_pseudo(insn, pseudo, &rule->pseudo);
	add_ptr_list(&insn->asm_rules->outputs, rule);
}

static pseudo_t linearize_asm_statement(struct entrypoint *ep, struct statement *stmt)
{
	int state;
	struct expression *expr;
	struct instruction *insn;
	struct asm_rules *rules;
	const char *constraint;
	struct ident *ident;

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
	state = 0;
	ident = NULL;
	constraint = NULL;
	FOR_EACH_PTR(stmt->asm_inputs, expr) {
		switch (state) {
		case 0:	/* Identifier */
			state = 1;
			ident = (struct ident *)expr;
			continue;

		case 1:	/* Constraint */
			state = 2;
			constraint = expr ? expr->string->data : "";
			continue;

		case 2:	/* Expression */
			state = 0;
			add_asm_input(ep, insn, expr, constraint, ident);
		}
	} END_FOR_EACH_PTR(expr);

	add_one_insn(ep, insn);

	/* Assign the outputs */
	state = 0;
	ident = NULL;
	constraint = NULL;
	FOR_EACH_PTR(stmt->asm_outputs, expr) {
		switch (state) {
		case 0:	/* Identifier */
			state = 1;
			ident = (struct ident *)expr;
			continue;

		case 1:	/* Constraint */
			state = 2;
			constraint = expr ? expr->string->data : "";
			continue;

		case 2:
			state = 0;
			add_asm_output(ep, insn, expr, constraint, ident);
		}
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
	struct basic_block *bb_return = get_bound_block(ep, stmt->ret_target);
	struct basic_block *active;
	pseudo_t src = linearize_expression(ep, expr);
	active = ep->active;
	if (active && src != VOID) {
		struct instruction *phi_node = first_instruction(bb_return->insns);
		pseudo_t phi;
		if (!phi_node) {
			phi_node = alloc_typed_instruction(OP_PHI, expr->ctype);
			phi_node->target = alloc_pseudo(phi_node);
			phi_node->bb = bb_return;
			add_instruction(&bb_return->insns, phi_node);
		}
		phi = alloc_phi(active, src, type_size(expr->ctype));
		phi->ident = &return_ident;
		use_pseudo(phi_node, phi, add_pseudo(&phi_node->phi_list, phi));
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
	struct multijmp *jmp;
	pseudo_t pseudo;

	pseudo = linearize_expression(ep, stmt->switch_expression);

	active = ep->active;
	if (!bb_reachable(active))
		return VOID;

	switch_ins = alloc_instruction(OP_SWITCH, 0);
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
		} else {
			int begin, end;

			begin = end = case_stmt->case_expression->value;
			if (case_stmt->case_to)
				end = case_stmt->case_to->value;
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

pseudo_t linearize_statement(struct entrypoint *ep, struct statement *stmt)
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
		use_pseudo(goto_ins, pseudo, &goto_ins->target);
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
	struct entrypoint *ep;
	struct basic_block *bb;
	struct symbol *arg;
	struct instruction *entry;
	pseudo_t result;
	int i;

	if (!base_type->stmt)
		return NULL;

	ep = alloc_entrypoint();
	bb = alloc_basic_block(ep, sym->pos);
	
	ep->name = sym;
	sym->ep = ep;
	set_activeblock(ep, bb);

	entry = alloc_instruction(OP_ENTRY, 0);
	add_one_insn(ep, entry);
	ep->entry = entry;

	concat_symbol_list(base_type->arguments, &ep->syms);

	/* FIXME!! We should do something else about varargs.. */
	i = 0;
	FOR_EACH_PTR(base_type->arguments, arg) {
		linearize_argument(ep, arg, ++i);
	} END_FOR_EACH_PTR(arg);

	result = linearize_statement(ep, base_type->stmt);
	if (bb_reachable(ep->active) && !bb_terminated(ep->active)) {
		struct symbol *ret_type = base_type->ctype.base_type;
		struct instruction *insn = alloc_typed_instruction(OP_RET, ret_type);

		if (type_size(ret_type) > 0)
			use_pseudo(insn, result, &insn->src);
		add_one_insn(ep, insn);
	}

	if (fdump_linearize) {
		if (fdump_linearize == 2)
			return ep;
		show_entry(ep);
	}

	/*
	 * Do trivial flow simplification - branches to
	 * branches, kill dead basicblocks etc
	 */
	kill_unreachable_bbs(ep);

	/*
	 * Turn symbols into pseudos
	 */
	simplify_symbol_usage(ep);

repeat:
	/*
	 * Remove trivial instructions, and try to CSE
	 * the rest.
	 */
	do {
		cleanup_and_cse(ep);
		pack_basic_blocks(ep);
	} while (repeat_phase & REPEAT_CSE);

	kill_unreachable_bbs(ep);
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
		clear_liveness(ep);
		goto repeat;
	}

	/* Finally, add deathnotes to pseudos now that we have them */
	if (dbg_dead)
		track_pseudo_death(ep);

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

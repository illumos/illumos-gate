#ifndef LINEARIZE_H
#define LINEARIZE_H

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"

struct instruction;
DECLARE_PTR_LIST(pseudo_ptr_list, pseudo_t);

struct pseudo_user {
	struct instruction *insn;
	pseudo_t *userp;
};

DECLARE_ALLOCATOR(pseudo_user);
DECLARE_PTR_LIST(pseudo_user_list, struct pseudo_user);


enum pseudo_type {
	PSEUDO_VOID,
	PSEUDO_REG,
	PSEUDO_SYM,
	PSEUDO_VAL,
	PSEUDO_ARG,
	PSEUDO_PHI,
};

struct pseudo {
	int nr;
	int size:16;	/* OP_SETVAL only */
	enum pseudo_type type:8;
	struct pseudo_user_list *users;
	struct ident *ident;
	union {
		struct symbol *sym;
		struct instruction *def;
		long long value;
	};
	void *priv;
};

extern struct pseudo void_pseudo;

#define VOID (&void_pseudo)

struct multijmp {
	struct basic_block *target;
	int begin, end;
};

struct asm_constraint {
	pseudo_t pseudo;
	const char *constraint;
	const struct ident *ident;
};

DECLARE_ALLOCATOR(asm_constraint);
DECLARE_PTR_LIST(asm_constraint_list, struct asm_constraint);

struct asm_rules {
	struct asm_constraint_list *inputs;
	struct asm_constraint_list *outputs;
	struct asm_constraint_list *clobbers;
};

DECLARE_ALLOCATOR(asm_rules);

struct instruction {
	unsigned opcode:8,
		 size:24;
	struct basic_block *bb;
	struct position pos;
	struct symbol *type;
	union {
		pseudo_t target;
		pseudo_t cond;		/* for branch and switch */
	};
	union {
		struct /* entrypoint */ {
			struct pseudo_list *arg_list;
		};
		struct /* branch */ {
			struct basic_block *bb_true, *bb_false;
		};
		struct /* switch */ {
			struct multijmp_list *multijmp_list;
		};
		struct /* phi_node */ {
			struct pseudo_list *phi_list;
		};
		struct /* phi source */ {
			pseudo_t phi_src;
			struct instruction_list *phi_users;
		};
		struct /* unops */ {
			pseudo_t src;
			struct symbol *orig_type;	/* casts */
			unsigned int offset;		/* memops */
		};
		struct /* binops and sel */ {
			pseudo_t src1, src2, src3;
		};
		struct /* slice */ {
			pseudo_t base;
			unsigned from, len;
		};
		struct /* setval */ {
			pseudo_t symbol;		/* Subtle: same offset as "src" !! */
			struct expression *val;
		};
		struct /* call */ {
			pseudo_t func;
			struct pseudo_list *arguments;
			struct symbol *fntype;
		};
		struct /* context */ {
			int increment;
			int check;
			struct expression *context_expr;
		};
		struct /* asm */ {
			const char *string;
			struct asm_rules *asm_rules;
		};
	};
};

enum opcode {
	OP_BADOP,

	/* Entry */
	OP_ENTRY,

	/* Terminator */
	OP_TERMINATOR,
	OP_RET = OP_TERMINATOR,
	OP_BR,
	OP_CBR,
	OP_SWITCH,
	OP_INVOKE,
	OP_COMPUTEDGOTO,
	OP_UNWIND,
	OP_TERMINATOR_END = OP_UNWIND,
	
	/* Binary */
	OP_BINARY,
	OP_ADD = OP_BINARY,
	OP_SUB,
	OP_MULU, OP_MULS,
	OP_DIVU, OP_DIVS,
	OP_MODU, OP_MODS,
	OP_SHL,
	OP_LSR, OP_ASR,
	
	/* Logical */
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_AND_BOOL,
	OP_OR_BOOL,
	OP_BINARY_END = OP_OR_BOOL,

	/* Binary comparison */
	OP_BINCMP,
	OP_SET_EQ = OP_BINCMP,
	OP_SET_NE,
	OP_SET_LE,
	OP_SET_GE,
	OP_SET_LT,
	OP_SET_GT,
	OP_SET_B,
	OP_SET_A,
	OP_SET_BE,
	OP_SET_AE,
	OP_BINCMP_END = OP_SET_AE,

	/* Uni */
	OP_NOT,
	OP_NEG,

	/* Select - three input values */
	OP_SEL,
	
	/* Memory */
	OP_MALLOC,
	OP_FREE,
	OP_ALLOCA,
	OP_LOAD,
	OP_STORE,
	OP_SETVAL,
	OP_SYMADDR,
	OP_GET_ELEMENT_PTR,

	/* Other */
	OP_PHI,
	OP_PHISOURCE,
	OP_CAST,
	OP_SCAST,
	OP_FPCAST,
	OP_PTRCAST,
	OP_INLINED_CALL,
	OP_CALL,
	OP_VANEXT,
	OP_VAARG,
	OP_SLICE,
	OP_SNOP,
	OP_LNOP,
	OP_NOP,
	OP_DEATHNOTE,
	OP_ASM,

	/* Sparse tagging (line numbers, context, whatever) */
	OP_CONTEXT,
	OP_RANGE,

	/* Needed to translate SSA back to normal form */
	OP_COPY,
};

struct basic_block_list;
struct instruction_list;

struct basic_block {
	struct position pos;
	unsigned long generation;
	int context;
	struct entrypoint *ep;
	struct basic_block_list *parents; /* sources */
	struct basic_block_list *children; /* destinations */
	struct instruction_list *insns;	/* Linear list of instructions */
	struct pseudo_list *needs, *defines;
	union {
		unsigned int nr;	/* unique id for label's names */
		void *priv;
	};
};


static inline void add_bb(struct basic_block_list **list, struct basic_block *bb)
{
	add_ptr_list(list, bb);
}

static inline void add_instruction(struct instruction_list **list, struct instruction *insn)
{
	add_ptr_list(list, insn);
}

static inline void add_multijmp(struct multijmp_list **list, struct multijmp *multijmp)
{
	add_ptr_list(list, multijmp);
}

static inline pseudo_t *add_pseudo(struct pseudo_list **list, pseudo_t pseudo)
{
	return add_ptr_list(list, pseudo);
}

static inline int remove_pseudo(struct pseudo_list **list, pseudo_t pseudo)
{
	return delete_ptr_list_entry((struct ptr_list **)list, pseudo, 0) != 0;
}

static inline int bb_terminated(struct basic_block *bb)
{
	struct instruction *insn;
	if (!bb)
		return 0;
	insn = last_instruction(bb->insns);
	return insn && insn->opcode >= OP_TERMINATOR
	            && insn->opcode <= OP_TERMINATOR_END;
}

static inline int bb_reachable(struct basic_block *bb)
{
	return bb != NULL;
}

static inline void add_pseudo_ptr(pseudo_t *ptr, struct pseudo_ptr_list **list)
{
	add_ptr_list(list, ptr);
}

static inline void add_pseudo_user_ptr(struct pseudo_user *user, struct pseudo_user_list **list)
{
	add_ptr_list(list, user);
}

static inline int has_use_list(pseudo_t p)
{
	return (p && p->type != PSEUDO_VOID && p->type != PSEUDO_VAL);
}

static inline struct pseudo_user *alloc_pseudo_user(struct instruction *insn, pseudo_t *pp)
{
	struct pseudo_user *user = __alloc_pseudo_user(0);
	user->userp = pp;
	user->insn = insn;
	return user;
}

static inline void use_pseudo(struct instruction *insn, pseudo_t p, pseudo_t *pp)
{
	*pp = p;
	if (has_use_list(p))
		add_pseudo_user_ptr(alloc_pseudo_user(insn, pp), &p->users);
}

static inline void remove_bb_from_list(struct basic_block_list **list, struct basic_block *entry, int count)
{
	delete_ptr_list_entry((struct ptr_list **)list, entry, count);
}

static inline void replace_bb_in_list(struct basic_block_list **list,
	struct basic_block *old, struct basic_block *new, int count)
{
	replace_ptr_list_entry((struct ptr_list **)list, old, new, count);
}

struct entrypoint {
	struct symbol *name;
	struct symbol_list *syms;
	struct pseudo_list *accesses;
	struct basic_block_list *bbs;
	struct basic_block *active;
	struct instruction *entry;
};

extern void insert_select(struct basic_block *bb, struct instruction *br, struct instruction *phi, pseudo_t if_true, pseudo_t if_false);
extern void insert_branch(struct basic_block *bb, struct instruction *br, struct basic_block *target);

pseudo_t alloc_phi(struct basic_block *source, pseudo_t pseudo, int size);
pseudo_t alloc_pseudo(struct instruction *def);
pseudo_t value_pseudo(struct symbol *type, long long val);
unsigned int value_size(long long value);

struct entrypoint *linearize_symbol(struct symbol *sym);
int unssa(struct entrypoint *ep);
void show_entry(struct entrypoint *ep);
const char *show_pseudo(pseudo_t pseudo);
void show_bb(struct basic_block *bb);
const char *show_instruction(struct instruction *insn);

#endif /* LINEARIZE_H */


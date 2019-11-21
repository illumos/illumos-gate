#ifndef LINEARIZE_H
#define LINEARIZE_H

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "opcode.h"
#include "parse.h"
#include "symbol.h"
#include "ptrmap.h"

struct instruction;

struct pseudo_user {
	struct instruction *insn;
	pseudo_t *userp;
};

DECLARE_ALLOCATOR(pseudo_user);
DECLARE_PTR_LIST(pseudo_user_list, struct pseudo_user);
DECLARE_PTRMAP(phi_map, struct symbol *, pseudo_t);


enum pseudo_type {
	PSEUDO_VOID,
	PSEUDO_UNDEF,
	PSEUDO_REG,
	PSEUDO_SYM,
	PSEUDO_VAL,
	PSEUDO_ARG,
	PSEUDO_PHI,
};

struct pseudo {
	int nr;
	enum pseudo_type type;
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

static inline bool is_zero(pseudo_t pseudo)
{
	return pseudo->type == PSEUDO_VAL && pseudo->value == 0;
}

static inline bool is_nonzero(pseudo_t pseudo)
{
	return pseudo->type == PSEUDO_VAL && pseudo->value != 0;
}


struct multijmp {
	struct basic_block *target;
	long long begin, end;
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
	unsigned opcode:7,
		 tainted:1,
		 size:24;
	struct basic_block *bb;
	struct position pos;
	struct symbol *type;
	pseudo_t target;
	union {
		struct /* entrypoint */ {
			struct pseudo_list *arg_list;
		};
		struct /* branch */ {
			pseudo_t cond;
			struct basic_block *bb_true, *bb_false;
		};
		struct /* switch */ {
			pseudo_t _cond;
			struct multijmp_list *multijmp_list;
		};
		struct /* phi_node */ {
			pseudo_t phi_var;		// used for SSA conversion
			struct pseudo_list *phi_list;
			unsigned int used:1;
		};
		struct /* phi source */ {
			pseudo_t phi_src;
			struct instruction_list *phi_users;
		};
		struct /* unops */ {
			pseudo_t src;
			struct symbol *orig_type;	/* casts */
		};
		struct /* memops */ {
			pseudo_t addr;			/* alias .src */
			unsigned int offset;
			unsigned int is_volatile:1;
		};
		struct /* binops and sel */ {
			pseudo_t src1, src2, src3;
		};
		struct /* slice */ {
			pseudo_t base;
			unsigned from, len;
		};
		struct /* setval */ {
			struct expression *val;
		};
		struct /* setfval */ {
			long double fvalue;
		};
		struct /* call */ {
			pseudo_t func;
			struct pseudo_list *arguments;
			struct symbol_list *fntypes;
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

struct basic_block_list;
struct instruction_list;

struct basic_block {
	struct position pos;
	unsigned long generation;
	union {
		int context;
		int postorder_nr;	/* postorder number */
		int dom_level;		/* level in the dominance tree */
	};
	struct entrypoint *ep;
	struct basic_block_list *parents; /* sources */
	struct basic_block_list *children; /* destinations */
	struct instruction_list *insns;	/* Linear list of instructions */
	struct basic_block *idom;	/* link to the immediate dominator */
	struct basic_block_list *doms;	/* list of BB idominated by this one */
	struct phi_map *phi_map;
	struct pseudo_list *needs, *defines;
	union {
		unsigned int nr;	/* unique id for label's names */
		void *priv;
	};
};


//
// return the opcode of the instruction defining ``SRC`` if existing
// and OP_BADOP if not. It also assigns the defining instruction
// to ``DEF``.
#define DEF_OPCODE(DEF, SRC)	\
	(((SRC)->type == PSEUDO_REG && (DEF = (SRC)->def)) ? DEF->opcode : OP_BADOP)


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

static inline int pseudo_in_list(struct pseudo_list *list, pseudo_t pseudo)
{
	return lookup_ptr_list_entry((struct ptr_list *)list, pseudo);
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

static inline int lookup_bb(struct basic_block_list *list, struct basic_block *bb)
{
	return lookup_ptr_list_entry((struct ptr_list *)list, bb);
}


static inline void add_pseudo_user_ptr(struct pseudo_user *user, struct pseudo_user_list **list)
{
	add_ptr_list(list, user);
}

static inline int has_use_list(pseudo_t p)
{
	return (p && p->type != PSEUDO_VOID && p->type != PSEUDO_UNDEF && p->type != PSEUDO_VAL);
}

static inline int pseudo_user_list_size(struct pseudo_user_list *list)
{
	return ptr_list_size((struct ptr_list *)list);
}

static inline bool pseudo_user_list_empty(struct pseudo_user_list *list)
{
	return ptr_list_empty((struct ptr_list *)list);
}

static inline int has_users(pseudo_t p)
{
	return !pseudo_user_list_empty(p->users);
}

static inline bool multi_users(pseudo_t p)
{
	return ptr_list_multiple((struct ptr_list *)(p->users));
}

static inline int nbr_users(pseudo_t p)
{
	return pseudo_user_list_size(p->users);
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
	unsigned int dom_levels;	/* max levels in the dom tree */
};

extern void insert_select(struct basic_block *bb, struct instruction *br, struct instruction *phi, pseudo_t if_true, pseudo_t if_false);
extern void insert_branch(struct basic_block *bb, struct instruction *br, struct basic_block *target);

struct instruction *alloc_phisrc(pseudo_t pseudo, struct symbol *type);
struct instruction *alloc_phi_node(struct basic_block *bb, struct symbol *type, struct ident *ident);
struct instruction *insert_phi_node(struct basic_block *bb, struct symbol *var);
void add_phi_node(struct basic_block *bb, struct instruction *phi_node);

pseudo_t alloc_phi(struct basic_block *source, pseudo_t pseudo, struct symbol *type);
pseudo_t alloc_pseudo(struct instruction *def);
pseudo_t value_pseudo(long long val);
pseudo_t undef_pseudo(void);

struct entrypoint *linearize_symbol(struct symbol *sym);
int unssa(struct entrypoint *ep);
void show_entry(struct entrypoint *ep);
const char *show_pseudo(pseudo_t pseudo);
void show_bb(struct basic_block *bb);
const char *show_instruction(struct instruction *insn);
const char *show_label(struct basic_block *bb);

#endif /* LINEARIZE_H */


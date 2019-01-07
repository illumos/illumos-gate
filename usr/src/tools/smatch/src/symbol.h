#ifndef SYMBOL_H
#define SYMBOL_H
/*
 * Basic symbol and namespace definitions.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003 Linus Torvalds
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "token.h"
#include "target.h"

/*
 * An identifier with semantic meaning is a "symbol".
 *
 * There's a 1:n relationship: each symbol is always
 * associated with one identifier, while each identifier
 * can have one or more semantic meanings due to C scope
 * rules.
 *
 * The progression is symbol -> token -> identifier. The
 * token contains the information on where the symbol was
 * declared.
 */
enum namespace {
	NS_NONE = 0,
	NS_MACRO = 1,
	NS_TYPEDEF = 2,
	NS_STRUCT = 4,  // Also used for unions and enums.
	NS_LABEL = 8,
	NS_SYMBOL = 16,
	NS_ITERATOR = 32,
	NS_PREPROCESSOR = 64,
	NS_UNDEF = 128,
	NS_KEYWORD = 256,
};

enum type {
	SYM_UNINITIALIZED,
	SYM_PREPROCESSOR,
	SYM_BASETYPE,
	SYM_NODE,
	SYM_PTR,
	SYM_FN,
	SYM_ARRAY,
	SYM_STRUCT,
	SYM_UNION,
	SYM_ENUM,
	SYM_TYPEDEF,
	SYM_TYPEOF,
	SYM_MEMBER,
	SYM_BITFIELD,
	SYM_LABEL,
	SYM_RESTRICT,
	SYM_FOULED,
	SYM_KEYWORD,
	SYM_BAD,
};

enum keyword {
	KW_SPECIFIER 	= 1 << 0,
	KW_MODIFIER	= 1 << 1,
	KW_QUALIFIER	= 1 << 2,
	KW_ATTRIBUTE	= 1 << 3,
	KW_STATEMENT	= 1 << 4,
	KW_ASM		= 1 << 5,
	KW_MODE		= 1 << 6,
	KW_SHORT	= 1 << 7,
	KW_LONG		= 1 << 8,
	KW_EXACT	= 1 << 9,
};

struct context {
	struct expression *context;
	unsigned int in, out;
};

extern struct context *alloc_context(void);

DECLARE_PTR_LIST(context_list, struct context);

struct ctype {
	unsigned long modifiers;
	unsigned long alignment;
	struct context_list *contexts;
	unsigned int as;
	struct symbol *base_type;
};

struct decl_state {
	struct ctype ctype;
	struct ident **ident;
	struct symbol_op *mode;
	unsigned char prefer_abstract, is_inline, storage_class, is_tls;
};

struct symbol_op {
	enum keyword type;
	int (*evaluate)(struct expression *);
	int (*expand)(struct expression *, int);
	int (*args)(struct expression *);

	/* keywords */
	struct token *(*declarator)(struct token *token, struct decl_state *ctx);
	struct token *(*statement)(struct token *token, struct statement *stmt);
	struct token *(*toplevel)(struct token *token, struct symbol_list **list);
	struct token *(*attribute)(struct token *token, struct symbol *attr, struct decl_state *ctx);
	struct symbol *(*to_mode)(struct symbol *);

	int test, set, class;
};


#define SYM_ATTR_WEAK		0
#define SYM_ATTR_NORMAL		1
#define SYM_ATTR_STRONG		2

struct symbol {
	enum type type:8;
	enum namespace namespace:9;
	unsigned char used:1, attr:2, enum_member:1, bound:1;
	struct position pos;		/* Where this symbol was declared */
	struct position endpos;		/* Where this symbol ends*/
	struct ident *ident;		/* What identifier this symbol is associated with */
	struct symbol *next_id;		/* Next semantic symbol that shares this identifier */
	struct symbol	*replace;	/* What is this symbol shadowed by in copy-expression */
	struct scope	*scope;
	union {
		struct symbol	*same_symbol;
		struct symbol	*next_subobject;
	};

	struct symbol_op *op;

	union {
		struct /* NS_MACRO */ {
			struct token *expansion;
			struct token *arglist;
			struct scope *used_in;
		};
		struct /* NS_PREPROCESSOR */ {
			int (*handler)(struct stream *, struct token **, struct token *);
			int normal;
		};
		struct /* NS_SYMBOL */ {
			unsigned long	offset;
			int		bit_size;
			unsigned int	bit_offset:8,
					arg_count:10,
					variadic:1,
					initialized:1,
					examined:1,
					expanding:1,
					evaluated:1,
					string:1,
					designated_init:1,
					forced_arg:1,
					transparent_union:1;
			struct expression *array_size;
			struct ctype ctype;
			struct symbol_list *arguments;
			struct statement *stmt;
			struct symbol_list *symbol_list;
			struct statement *inline_stmt;
			struct symbol_list *inline_symbol_list;
			struct expression *initializer;
			struct entrypoint *ep;
			long long value;		/* Initial value */
			struct symbol *definition;
		};
	};
	union /* backend */ {
		struct basic_block *bb_target;	/* label */
		void *aux;			/* Auxiliary info, e.g. backend information */
		struct {			/* sparse ctags */
			char kind;
			unsigned char visited:1;
		};
	};
	pseudo_t pseudo;
};

/* Modifiers */
#define MOD_AUTO	0x0001
#define MOD_REGISTER	0x0002
#define MOD_STATIC	0x0004
#define MOD_EXTERN	0x0008

#define MOD_CONST	0x0010
#define MOD_VOLATILE	0x0020
#define MOD_SIGNED	0x0040
#define MOD_UNSIGNED	0x0080

#define MOD_CHAR	0x0100
#define MOD_SHORT	0x0200
#define MOD_LONG	0x0400
#define MOD_LONGLONG	0x0800
#define MOD_LONGLONGLONG	0x1000
#define MOD_PURE	0x2000

#define MOD_TYPEDEF	0x10000

#define MOD_TLS		0x20000
#define MOD_INLINE	0x40000
#define MOD_ADDRESSABLE	0x80000

#define MOD_NOCAST	0x100000
#define MOD_NODEREF	0x200000
#define MOD_ACCESSED	0x400000
#define MOD_TOPLEVEL	0x800000	// scoping..

#define MOD_ASSIGNED	0x2000000
#define MOD_TYPE	0x4000000
#define MOD_SAFE	0x8000000	// non-null/non-trapping pointer

#define MOD_USERTYPE	0x10000000
#define MOD_NORETURN	0x20000000
#define MOD_EXPLICITLY_SIGNED	0x40000000
#define MOD_BITWISE	0x80000000


#define MOD_NONLOCAL	(MOD_EXTERN | MOD_TOPLEVEL)
#define MOD_STORAGE	(MOD_AUTO | MOD_REGISTER | MOD_STATIC | MOD_EXTERN | MOD_INLINE | MOD_TOPLEVEL)
#define MOD_SIGNEDNESS	(MOD_SIGNED | MOD_UNSIGNED | MOD_EXPLICITLY_SIGNED)
#define MOD_LONG_ALL	(MOD_LONG | MOD_LONGLONG | MOD_LONGLONGLONG)
#define MOD_SPECIFIER	(MOD_CHAR | MOD_SHORT | MOD_LONG_ALL | MOD_SIGNEDNESS)
#define MOD_SIZE	(MOD_CHAR | MOD_SHORT | MOD_LONG_ALL)
#define MOD_IGNORE (MOD_TOPLEVEL | MOD_STORAGE | MOD_ADDRESSABLE |	\
	MOD_ASSIGNED | MOD_USERTYPE | MOD_ACCESSED | MOD_EXPLICITLY_SIGNED)
#define MOD_PTRINHERIT (MOD_VOLATILE | MOD_CONST | MOD_NODEREF | MOD_NORETURN | MOD_NOCAST)
/* modifiers preserved by typeof() operator */
#define MOD_TYPEOF	(MOD_VOLATILE | MOD_CONST | MOD_NOCAST | MOD_SPECIFIER)


/* Current parsing/evaluation function */
extern struct symbol *current_fn;

/* Abstract types */
extern struct symbol	int_type,
			fp_type;

/* C types */
extern struct symbol	bool_ctype, void_ctype, type_ctype,
			char_ctype, schar_ctype, uchar_ctype,
			short_ctype, sshort_ctype, ushort_ctype,
			int_ctype, sint_ctype, uint_ctype,
			long_ctype, slong_ctype, ulong_ctype,
			llong_ctype, sllong_ctype, ullong_ctype,
			lllong_ctype, slllong_ctype, ulllong_ctype,
			float_ctype, double_ctype, ldouble_ctype,
			string_ctype, ptr_ctype, lazy_ptr_ctype,
			incomplete_ctype, label_ctype, bad_ctype,
			null_ctype;

/* Special internal symbols */
extern struct symbol	zero_int;

#define __IDENT(n,str,res) \
	extern struct ident n
#include "ident-list.h"

#define symbol_is_typename(sym) ((sym)->type == SYM_TYPE)

extern struct symbol_list *translation_unit_used_list;

extern void access_symbol(struct symbol *);

extern const char * type_difference(struct ctype *c1, struct ctype *c2,
	unsigned long mod1, unsigned long mod2);

extern struct symbol *lookup_symbol(struct ident *, enum namespace);
extern struct symbol *create_symbol(int stream, const char *name, int type, int namespace);
extern void init_symbols(void);
extern void init_builtins(int stream);
extern void init_ctype(void);
extern struct symbol *alloc_symbol(struct position, int type);
extern void show_type(struct symbol *);
extern const char *modifier_string(unsigned long mod);
extern void show_symbol(struct symbol *);
extern int show_symbol_expr_init(struct symbol *sym);
extern void show_type_list(struct symbol *);
extern void show_symbol_list(struct symbol_list *, const char *);
extern void add_symbol(struct symbol_list **, struct symbol *);
extern void bind_symbol(struct symbol *, struct ident *, enum namespace);

extern struct symbol *examine_symbol_type(struct symbol *);
extern struct symbol *examine_pointer_target(struct symbol *);
extern void examine_simple_symbol_type(struct symbol *);
extern const char *show_typename(struct symbol *sym);
extern const char *builtin_typename(struct symbol *sym);
extern const char *builtin_ctypename(struct ctype *ctype);
extern const char* get_type_name(enum type type);

extern void debug_symbol(struct symbol *);
extern void merge_type(struct symbol *sym, struct symbol *base_type);
extern void check_declaration(struct symbol *sym);

static inline struct symbol *get_base_type(const struct symbol *sym)
{
	return examine_symbol_type(sym->ctype.base_type);
}

static inline int is_int_type(const struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	if (type->type == SYM_ENUM)
		type = type->ctype.base_type;
	return type->type == SYM_BITFIELD ||
	       type->ctype.base_type == &int_type;
}

static inline int is_enum_type(const struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return (type->type == SYM_ENUM);
}

static inline int is_type_type(struct symbol *type)
{
	return (type->ctype.modifiers & MOD_TYPE) != 0;
}

static inline int is_ptr_type(struct symbol *type)
{
	if (!type)
		return 0;
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type->type == SYM_PTR || type->type == SYM_ARRAY || type->type == SYM_FN;
}

static inline int is_func_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type->type == SYM_FN;
}

static inline int is_array_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type->type == SYM_ARRAY;
}

static inline int is_float_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type->ctype.base_type == &fp_type;
}

static inline int is_byte_type(struct symbol *type)
{
	return type->bit_size == bits_in_char && type->type != SYM_BITFIELD;
}

static inline int is_void_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type == &void_ctype;
}

static inline int is_bool_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type == &bool_ctype;
}

static inline int is_scalar_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	switch (type->type) {
	case SYM_ENUM:
	case SYM_BITFIELD:
	case SYM_PTR:
	case SYM_RESTRICT:	// OK, always integer types
		return 1;
	default:
		break;
	}
	if (type->ctype.base_type == &int_type)
		return 1;
	if (type->ctype.base_type == &fp_type)
		return 1;
	return 0;
}

static inline int is_function(struct symbol *type)
{
	return type && type->type == SYM_FN;
}

static inline int is_extern_inline(struct symbol *sym)
{
	return (sym->ctype.modifiers & MOD_EXTERN) &&
		(sym->ctype.modifiers & MOD_INLINE) &&
		is_function(sym->ctype.base_type);
}

static inline int get_sym_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	if (type->type == SYM_ENUM)
		type = type->ctype.base_type;
	return type->type;
}

static inline struct symbol *lookup_keyword(struct ident *ident, enum namespace ns)
{
	if (!ident->keyword)
		return NULL;
	return lookup_symbol(ident, ns);
}

#define is_restricted_type(type) (get_sym_type(type) == SYM_RESTRICT)
#define is_fouled_type(type) (get_sym_type(type) == SYM_FOULED)
#define is_bitfield_type(type)   (get_sym_type(type) == SYM_BITFIELD)
extern int is_ptr_type(struct symbol *);

void create_fouled(struct symbol *type);
struct symbol *befoul(struct symbol *type);

#endif /* SYMBOL_H */

#ifndef EXPRESSION_H
#define EXPRESSION_H
/*
 * sparse/expression.h
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
 *
 * Declarations and helper functions for expression parsing.
 */

#include "allocate.h"
#include "lib.h"
#include "symbol.h"

struct expression_list;

enum expression_type {
	EXPR_VALUE = 1,
	EXPR_STRING,
	EXPR_SYMBOL,
	EXPR_TYPE,
	EXPR_BINOP,
	EXPR_ASSIGNMENT,
	EXPR_LOGICAL,
	EXPR_DEREF,
	EXPR_PREOP,
	EXPR_POSTOP,
	EXPR_CAST,
	EXPR_FORCE_CAST,
	EXPR_IMPLIED_CAST,
	EXPR_SIZEOF,
	EXPR_ALIGNOF,
	EXPR_PTRSIZEOF,
	EXPR_CONDITIONAL,
	EXPR_SELECT,		// a "safe" conditional expression
	EXPR_STATEMENT,
	EXPR_CALL,
	EXPR_COMMA,
	EXPR_COMPARE,
	EXPR_LABEL,
	EXPR_INITIALIZER,	// initializer list
	EXPR_IDENTIFIER,	// identifier in initializer
	EXPR_INDEX,		// index in initializer
	EXPR_POS,		// position in initializer
	EXPR_FVALUE,
	EXPR_SLICE,
	EXPR_OFFSETOF,
};


/*
 * Flags for tracking the promotion of constness related attributes
 * from subexpressions to their parents.
 *
 * The flags are not independent as one might imply another.
 * The implications are as follows:
 * - CEF_INT, CEF_ENUM and
 *   CEF_CHAR imply CEF_ICE.
 *
 * Use the CEF_*_SET_MASK and CEF_*_CLEAR_MASK
 * helper macros defined below to set or clear one of these flags.
 */
enum constexpr_flag {
	CEF_NONE = 0,
	/*
	 * A constant in the sense of [6.4.4]:
	 * - Integer constant [6.4.4.1]
	 * - Floating point constant [6.4.4.2]
	 * - Enumeration constant [6.4.4.3]
	 * - Character constant [6.4.4.4]
	 */
	CEF_INT = (1 << 0),
	CEF_FLOAT = (1 << 1),
	CEF_ENUM = (1 << 2),
	CEF_CHAR = (1 << 3),

	/*
	 * A constant expression in the sense of [6.6]:
	 * - integer constant expression [6.6(6)]
	 * - arithmetic constant expression [6.6(8)]
	 * - address constant [6.6(9)]
	 */
	CEF_ICE = (1 << 4),
	CEF_ACE = (1 << 5),
	CEF_ADDR = (1 << 6),

	/* integer constant expression => arithmetic constant expression */
	CEF_SET_ICE = (CEF_ICE | CEF_ACE),

	/* integer constant => integer constant expression */
	CEF_SET_INT = (CEF_INT | CEF_SET_ICE),

	/* floating point constant => arithmetic constant expression */
	CEF_SET_FLOAT = (CEF_FLOAT | CEF_ACE),

	/* enumeration constant => integer constant expression */
	CEF_SET_ENUM = (CEF_ENUM | CEF_SET_ICE),

	/* character constant => integer constant expression */
	CEF_SET_CHAR = (CEF_CHAR | CEF_SET_ICE),

	/*
	 * Remove any "Constant" [6.4.4] flag, but retain the "constant
	 * expression" [6.6] flags.
	 */
	CEF_CONST_MASK = (CEF_INT | CEF_FLOAT | CEF_CHAR),

	/*
	 * not an integer constant expression => neither of integer,
	 * enumeration and character constant
	 */
	CEF_CLR_ICE = (CEF_ICE | CEF_INT | CEF_ENUM | CEF_CHAR),
};

enum {
	Handled = 1 << 0,
	Fake	= 1 << 1,
}; /* for expr->flags */

enum {
	Taint_comma = 1,
}; /* for expr->taint */

struct expression {
	enum expression_type type:8;
	unsigned flags:8;
	unsigned smatch_flags:16;
	int op;
	struct position pos;
	struct symbol *ctype;
	unsigned long parent;
	union {
		// EXPR_VALUE
		struct {
			unsigned long long value;
			unsigned taint;
		};

		// EXPR_FVALUE
		long double fvalue;

		// EXPR_STRING
		struct {
			int wide;
			struct string *string;
		};

		// EXPR_UNOP, EXPR_PREOP and EXPR_POSTOP
		struct /* unop */ {
			struct expression *unop;
			unsigned long op_value;
		};

		// EXPR_SYMBOL, EXPR_TYPE
		struct /* symbol_arg */ {
			struct symbol *symbol;
			struct ident *symbol_name;
		};

		// EXPR_STATEMENT
		struct statement *statement;

		// EXPR_BINOP, EXPR_COMMA, EXPR_COMPARE, EXPR_LOGICAL and EXPR_ASSIGNMENT
		struct /* binop_arg */ {
			struct expression *left, *right;
		};
		// EXPR_DEREF
		struct /* deref_arg */ {
			struct expression *deref;
			struct ident *member;
			int member_offset;
		};
		// EXPR_SLICE
		struct /* slice */ {
			struct expression *base;
			unsigned r_bitpos, r_nrbits;
		};
		// EXPR_CAST and EXPR_SIZEOF
		struct /* cast_arg */ {
			struct symbol *cast_type;
			struct expression *cast_expression;
		};
		// EXPR_CONDITIONAL
		// EXPR_SELECT
		struct /* conditional_expr */ {
			struct expression *conditional, *cond_true, *cond_false;
		};
		// EXPR_CALL
		struct /* call_expr */ {
			struct expression *fn;
			struct expression_list *args;
		};
		// EXPR_LABEL
		struct /* label_expr */ {
			struct symbol *label_symbol;
		};
		// EXPR_INITIALIZER
		struct expression_list *expr_list;
		// EXPR_IDENTIFIER
		struct /* ident_expr */ {
			int offset;
			struct ident *expr_ident;
			struct symbol *field;
			struct expression *ident_expression;
		};
		// EXPR_INDEX
		struct /* index_expr */ {
			unsigned int idx_from, idx_to;
			struct expression *idx_expression;
		};
		// EXPR_POS
		struct /* initpos_expr */ {
			unsigned int init_offset, init_nr;
			struct expression *init_expr;
		};
		// EXPR_OFFSETOF
		struct {
			struct symbol *in;
			struct expression *down;
			union {
				struct ident *ident;
				struct expression *index;
			};
		};
	};
};

/* Constant expression values */
int is_zero_constant(struct expression *);
int expr_truth_value(struct expression *expr);
long long get_expression_value(struct expression *);
long long const_expression_value(struct expression *);
long long get_expression_value_silent(struct expression *expr);

/* Expression parsing */
struct token *parse_expression(struct token *token, struct expression **tree);
struct token *conditional_expression(struct token *token, struct expression **tree);
struct token *primary_expression(struct token *token, struct expression **tree);
struct token *parens_expression(struct token *token, struct expression **expr, const char *where);
struct token *assignment_expression(struct token *token, struct expression **tree);

extern void evaluate_symbol_list(struct symbol_list *list);
extern struct symbol *evaluate_statement(struct statement *stmt);
extern struct symbol *evaluate_expression(struct expression *);

extern int expand_symbol(struct symbol *);

static inline struct expression *alloc_expression(struct position pos, int type)
{
	struct expression *expr = __alloc_expression(0);
	expr->type = type;
	expr->pos = pos;
	expr->flags = CEF_NONE;
	return expr;
}

static inline struct expression *alloc_const_expression(struct position pos, int value)
{
	struct expression *expr = __alloc_expression(0);
	expr->type = EXPR_VALUE;
	expr->pos = pos;
	expr->value = value;
	expr->ctype = &int_ctype;
	expr->flags = CEF_SET_INT;
	return expr;
}

/* Type name parsing */
struct token *typename(struct token *, struct symbol **, int *);

static inline int lookup_type(struct token *token)
{
	if (token->pos.type == TOKEN_IDENT) {
		struct symbol *sym = lookup_symbol(token->ident, NS_SYMBOL | NS_TYPEDEF);
		return sym && (sym->namespace & NS_TYPEDEF);
	}
	return 0;
}

/* Statement parsing */
struct statement *alloc_statement(struct position pos, int type);
struct token *initializer(struct expression **tree, struct token *token);
struct token *compound_statement(struct token *, struct statement *);

/* The preprocessor calls this 'constant_expression()' */
#define constant_expression(token,tree) conditional_expression(token, tree)

/* Cast folding of constant values.. */
void cast_value(struct expression *expr, struct symbol *newtype,
	struct expression *old, struct symbol *oldtype);

#endif

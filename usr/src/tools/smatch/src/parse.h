#ifndef PARSE_H
#define PARSE_H
/*
 * Basic parsing data structures. Statements and symbols.
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

#include "symbol.h"

enum statement_type {
	STMT_NONE,
	STMT_DECLARATION,
	STMT_EXPRESSION,
	STMT_COMPOUND,
	STMT_IF,
	STMT_RETURN,
	STMT_CASE,
	STMT_SWITCH,
	STMT_ITERATOR,
	STMT_LABEL,
	STMT_GOTO,
	STMT_ASM,
	STMT_CONTEXT,
	STMT_RANGE,
};

struct statement {
	enum statement_type type;
	struct position pos;
	struct statement *parent;
	union {
		struct /* declaration */ {
			struct symbol_list *declaration;
		};
		struct /* context */ {
			struct expression *expression;
			struct expression *context;
		};
		struct /* return_statement */ {
			struct expression *ret_value;
			struct symbol *ret_target;
		};
		struct /* if_statement */ {
			struct expression *if_conditional;
			struct statement *if_true;
			struct statement *if_false;
		};
		struct /* compound_struct */ {
			struct statement_list *stmts;
			struct symbol *ret;
			struct symbol *inline_fn;
			struct statement *args;
		};
		struct /* labeled_struct */ {
			struct symbol *label_identifier;
			struct statement *label_statement;
		};
		struct /* case_struct */ {
			struct expression *case_expression;
			struct expression *case_to;
			struct statement *case_statement;
			struct symbol *case_label;
		};
		struct /* switch_struct */ {
			struct expression *switch_expression;
			struct statement *switch_statement;
			struct symbol *switch_break, *switch_case;
		};
		struct /* iterator_struct */ {
			struct symbol *iterator_break;
			struct symbol *iterator_continue;
			struct symbol_list *iterator_syms;
			struct statement  *iterator_pre_statement;
			struct expression *iterator_pre_condition;

			struct statement  *iterator_statement;

			struct statement  *iterator_post_statement;
			struct expression *iterator_post_condition;
		};
		struct /* goto_struct */ {
			struct symbol *goto_label;

			/* computed gotos have these: */
			struct expression *goto_expression;
			struct symbol_list *target_list;
		};
		struct /* asm */ {
			struct expression *asm_string;
			struct expression_list *asm_outputs;
			struct expression_list *asm_inputs;
			struct expression_list *asm_clobbers;
			struct symbol_list *asm_labels;
		};
		struct /* range */ {
			struct expression *range_expression;
			struct expression *range_low;
			struct expression *range_high;
		};
	};
};

extern struct symbol_list *function_computed_target_list;
extern struct statement_list *function_computed_goto_list;

extern struct token *parse_expression(struct token *, struct expression **);
extern struct symbol *label_symbol(struct token *token);

extern int show_statement(struct statement *);
extern void show_statement_list(struct statement_list *, const char *);
extern int show_expression(struct expression *);

typedef void (*validate_decl_t)(struct symbol *decl);
extern struct token *external_declaration(struct token *, struct symbol_list **, validate_decl_t);

extern struct symbol *ctype_integer(int size, int want_unsigned);

extern int inline_function(struct expression *expr, struct symbol *sym);
extern void uninline(struct symbol *sym);
extern void init_parser(int);

static inline void stmt_set_parent_stmt(struct statement *stmt, struct statement *parent)
{
	if (!stmt)
		return;
	stmt->parent = parent;
}

static inline struct statement *stmt_get_parent_stmt(struct statement *stmt)
{
	return stmt->parent;
}

#endif /* PARSE_H */

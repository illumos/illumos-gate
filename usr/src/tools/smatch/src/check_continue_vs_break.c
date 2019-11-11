/*
 * Copyright (C) 2015 Oracle.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

/*
 * If you have code like:
 * do {
 *    if (xxx)
 *        continue;
 * while (0);
 *
 * Then the continue is equivalent of a break.  So what was really intended?
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

static struct statement_list *iterator_stack;

static int is_do_while_zero(struct statement *stmt)
{
	if (!stmt->iterator_post_condition)
		return 0;
	if (!expr_is_zero(stmt->iterator_post_condition))
		return 0;
	return 1;
}

static void push_statement(struct statement_list **stack, struct statement *stmt)
{
	add_ptr_list(stack, stmt);
}

static void pop_statement(struct statement_list **stack)
{
	delete_ptr_list_last((struct ptr_list **)stack);
}

static int inside_do_while_zero(void)
{
	struct statement *stmt;

	stmt = last_ptr_list((struct ptr_list *)iterator_stack);
	return !!stmt;
}

static int loop_is_macro(void)
{
	struct statement *stmt;

	stmt = last_ptr_list((struct ptr_list *)iterator_stack);
	if (!stmt)
		return 0;
	if (get_macro_name(stmt->iterator_post_condition->pos))
		return 1;
	return 0;
}

static void match_stmt(struct statement *stmt)
{
	if (stmt->type != STMT_ITERATOR)
		return;

	if (is_do_while_zero(stmt)) {
		push_statement(&iterator_stack, stmt);
	} else
		push_statement(&iterator_stack, NULL);
}

static void match_stmt_after(struct statement *stmt)
{
	if (stmt->type != STMT_ITERATOR)
		return;

	pop_statement(&iterator_stack);
}

static void match_inline_start(struct expression *expr)
{
	push_statement(&iterator_stack, NULL);
}

static void match_inline_end(struct expression *expr)
{
	pop_statement(&iterator_stack);
}

static void match_continue(struct statement *stmt)
{
	if (stmt->type != STMT_GOTO)
		return;

	if (!stmt->goto_label || stmt->goto_label->type != SYM_NODE)
		return;
	if (strcmp(stmt->goto_label->ident->name, "continue") != 0)
		return;
	if (!inside_do_while_zero())
		return;
	if (loop_is_macro())
		return;
	sm_warning("continue to end of do { ... } while(0); loop");
}

void check_continue_vs_break(int id)
{
	my_id = id;
	add_hook(&match_stmt, STMT_HOOK);
	add_hook(&match_stmt_after, STMT_HOOK_AFTER);
	add_hook(&match_inline_start, INLINE_FN_START);
	add_hook(&match_inline_end, INLINE_FN_END);

	add_hook(&match_continue, STMT_HOOK);
}

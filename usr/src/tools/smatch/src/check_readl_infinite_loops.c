/*
 * Copyright (C) 2014 Oracle.
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

#include "smatch.h"
#include "smatch_extra.h"

static int my_id;

STATE(readl);
STATE(readl_ff);
STATE(readl_00);

DECLARE_PTR_LIST(state_stack, struct smatch_state);
struct state_stack *state_at_start;

static int readl_has_been_called;
static int returned;

static int is_readl_call(struct expression *expr)
{
	struct symbol *sym;

	expr = strip_expr(expr);
	if (expr->type != EXPR_CALL)
		return 0;
	if (expr->fn->type != EXPR_SYMBOL)
		return 0;
	sym = expr->fn->symbol;
	if (!sym || !sym->ident)
		return 0;
	if (strcmp(sym->ident->name, "readl") != 0)
		return 0;
	return 1;
}

static int is_readl(struct expression *expr)
{
	if (is_readl_call(expr))
		return 1;
	if (get_state_expr(my_id, expr) == &readl)
		return 1;
	return 0;
}

static void match_assign(struct expression *expr)
{
	if (is_readl(expr->right))
		set_state_expr(my_id, expr->left, &readl);
	else if (get_state_expr(my_id, expr->left))
		set_state_expr(my_id, expr->left, &undefined);
}

static int condition_depends_on_readl(struct expression *expr)
{
	if (expr->type == EXPR_BINOP) {
		if (condition_depends_on_readl(expr->left))
			return 1;
		if (condition_depends_on_readl(expr->right))
			return 1;
		return 0;
	}
	if (is_readl(expr))
		return 1;
	return 0;
}

static void check_condition(struct expression *expr)
{
	if (expr->op != '&')
		return;
	if (!condition_depends_on_readl(expr))
		return;
	readl_has_been_called = 1;
	set_true_false_states(my_id, "depends on", NULL, &readl_ff, &readl_00);
}

static void match_return(struct expression *expr)
{

	if (__inline_fn)
		return;
	returned = 1;
#if 0
	struct smatch_state *tmp;

	if (!readl_has_been_called)
		return;

	FOR_EACH_PTR(state_at_start, tmp) {
		REPLACE_CURRENT_PTR(tmp, NULL);
	}
#endif
}

static void push_state_at_start(struct smatch_state *state)
{
	add_ptr_list(&state_at_start, state);
}

static struct smatch_state *pop_state_at_start(void)
{
	struct smatch_state *state;

	state = last_ptr_list((struct ptr_list *)state_at_start);
	delete_ptr_list_last((struct ptr_list **)&state_at_start);
	return state;
}

static void before_loop(struct statement *stmt)
{
	struct smatch_state *state;

	if (!stmt || stmt->type != STMT_ITERATOR)
		return;
	if (ptr_list_empty((struct ptr_list *)state_at_start))
		returned = 0;
	state = get_state(my_id, "depends on", NULL);
	push_state_at_start(state);
}

static void after_loop(struct statement *stmt)
{
	struct smatch_state *old_state;

	if (!stmt || stmt->type != STMT_ITERATOR)
		return;
	old_state = pop_state_at_start();
	if (old_state == &readl_00)
		return;
	if (returned)
		return;
	if (get_state(my_id, "depends on", NULL) != &readl_00)
		return;
	sm_warning("this loop depends on readl() succeeding");
}

void check_readl_infinite_loops(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;

	add_hook(match_assign, ASSIGNMENT_HOOK);
	add_hook(check_condition, CONDITION_HOOK);

	add_hook(&match_return, RETURN_HOOK);

	add_hook(before_loop, STMT_HOOK);
	add_hook(after_loop, STMT_HOOK_AFTER);
}

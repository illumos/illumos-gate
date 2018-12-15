/*
 * Copyright (C) 2013 Oracle.
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
 * The way I'm detecting missing breaks is if there is an assignment inside a
 * switch statement which is over written.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;
static struct expression *skip_this;

/*
 * It goes like this:
 * - Allocate a state which stores the switch expression.  I wanted to
 *   just have a state &assigned but we need to know the switch statement where
 *   it was assigned.
 * - If it gets used then we change it to &used.
 * - For unmatched states we use &used (because of cleanness, not because we need
 *   to).
 * - If we merge inside a case statement and one of the states is &assigned (or
 *   if it is &nobreak) then &nobreak is used.
 *
 * We print an error when we assign something to a &no_break symbol.
 *
 */

STATE(used);
STATE(no_break);

static int in_switch_stmt;

static struct smatch_state *alloc_my_state(struct expression *expr)
{
	struct smatch_state *state;
	char *name;

	state = __alloc_smatch_state(0);
	expr = strip_expr(expr);
	name = expr_to_str(expr);
	if (!name)
		name = alloc_string("");
	state->name = alloc_sname(name);
	free_string(name);
	state->data = expr;
	return state;
}

struct expression *last_print_expr;
static void print_missing_break(struct expression *expr)
{
	char *name;

	if (get_switch_expr() == last_print_expr)
		return;
	last_print_expr = get_switch_expr();

	name = expr_to_var(expr);
	sm_warning("missing break? reassigning '%s'", name);
	free_string(name);
}

static void match_assign(struct expression *expr)
{
	struct expression *left;

	if (expr->op != '=')
		return;
	if (!get_switch_expr())
		return;
	left = strip_expr(expr->left);
	if (get_state_expr(my_id, left) == &no_break)
		print_missing_break(left);

	set_state_expr(my_id, left, alloc_my_state(get_switch_expr()));
	skip_this = left;
}

static void match_symbol(struct expression *expr)
{
	if (outside_of_function())
		return;
	if (!get_switch_expr())
		return;

	expr = strip_expr(expr);
	if (expr == skip_this)
		return;
	set_state_expr(my_id, expr, &used);
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	return &used;
}

static int in_case;
static struct smatch_state *merge_hook(struct smatch_state *s1, struct smatch_state *s2)
{
	struct expression *switch_expr;

	if (s1 == &no_break || s2 == &no_break)
		return &no_break;
	if (!in_case)
		return &used;
	switch_expr = get_switch_expr();
	if (s1->data == switch_expr || s2->data == switch_expr)
		return &no_break;
	return &used;
}

static void match_stmt(struct statement *stmt)
{
	if (stmt->type == STMT_CASE)
		in_case = 1;
	else
		in_case = 0;
}

static void match_switch(struct statement *stmt)
{
	if (stmt->type != STMT_SWITCH)
		return;

	in_switch_stmt++;
}

static void delete_my_states(int owner)
{
	struct state_list *slist = NULL;
	struct sm_state *sm;

	FOR_EACH_MY_SM(owner, __get_cur_stree(), sm) {
		add_ptr_list(&slist, sm);
	} END_FOR_EACH_SM(sm);

	FOR_EACH_PTR(slist, sm) {
		delete_state(sm->owner, sm->name, sm->sym);
	} END_FOR_EACH_PTR(sm);

	free_slist(&slist);
}

static void match_switch_end(struct statement *stmt)
{

	if (stmt->type != STMT_SWITCH)
		return;

	in_switch_stmt--;

	if (!in_switch_stmt)
		delete_my_states(my_id);
}

void check_missing_break(int id)
{
	my_id = id;

	if (!option_spammy)
		return;

	add_unmatched_state_hook(my_id, &unmatched_state);
	add_merge_hook(my_id, &merge_hook);

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_symbol, SYM_HOOK);
	add_hook(&match_stmt, STMT_HOOK);
	add_hook(&match_switch, STMT_HOOK);
	add_hook(&match_switch_end, STMT_HOOK_AFTER);
}

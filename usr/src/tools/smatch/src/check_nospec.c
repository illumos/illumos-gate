/*
 * Copyright (C) 2018 Oracle.
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

#include <stdlib.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static int barrier_id;

STATE(nospec);

static bool in_nospec_stmt;

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct range_list *rl;

	if (__in_function_def && !get_user_rl_var_sym(sm->name, sm->sym, &rl))
		return &nospec;
	return &undefined;
}

bool is_nospec(struct expression *expr)
{
	char *macro;

	if (in_nospec_stmt)
		return true;
	if (!expr)
		return false;
	if (get_state_expr(my_id, expr) == &nospec)
		return true;
	macro = get_macro_name(expr->pos);
	if (macro && strcmp(macro, "array_index_nospec") == 0)
		return true;
	return false;
}

static void nospec_assign(struct expression *expr)
{
	if (is_nospec(expr->right))
		set_state_expr(my_id, expr->left, &nospec);
}

static void set_param_nospec(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	set_state(my_id, fullname, sym, &nospec);
}

static void match_call_info(struct expression *expr)
{
	struct expression *arg;
	int i = 0;

	FOR_EACH_PTR(expr->args, arg) {
		if (get_state_expr(my_id, arg) == &nospec)
			sql_insert_caller_info(expr, NOSPEC, i, "$", "");
		i++;
	} END_FOR_EACH_PTR(arg);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	struct range_list *rl;

	if (!get_user_rl_var_sym(sm->name, sm->sym, &rl))
		return;
	sql_insert_caller_info(call, NOSPEC, param, printed_name, "");
}

static void returned_struct_members(int return_id, char *return_ranges, struct expression *expr)
{
	struct stree *start_states = get_start_states();
	struct symbol *returned_sym;
	struct sm_state *sm;
	const char *param_name;
	struct range_list *rl;
	int param;

	returned_sym = expr_to_sym(expr);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (get_state_stree(start_states, my_id, sm->name, sm->sym) == sm->state)
			continue;
		param = get_param_num_from_sym(sm->sym);
		if (param < 0) {
			if (!returned_sym || returned_sym != sm->sym)
				continue;
			param = -1;
		}

		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		if (param != -1 && strcmp(param_name, "$") == 0)
			continue;

		if (!get_user_rl_var_sym(sm->name, sm->sym, &rl))
			continue;

		sql_insert_return_states(return_id, return_ranges, NOSPEC, param, param_name, "");
	} END_FOR_EACH_SM(sm);

	if (is_nospec(expr) && get_user_rl(expr, &rl))
		sql_insert_return_states(return_id, return_ranges, NOSPEC, -1, "$", "");

	if (get_state(barrier_id, "barrier", NULL) == &nospec)
		sql_insert_return_states(return_id, return_ranges, NOSPEC_WB, -1, "", "");
}

static int is_return_statement(void)
{
	if (__cur_stmt && __cur_stmt->type == STMT_RETURN)
		return 1;
	return 0;
}

static void db_returns_nospec(struct expression *expr, int param, char *key, char *value)
{
	struct expression *call;
	struct expression *arg;
	char *name;
	struct symbol *sym;

	call = expr;
	while (call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (call->type != EXPR_CALL)
		return;

	if (param == -1 && expr->type == EXPR_ASSIGNMENT) {
		name = get_variable_from_key(expr->left, key, &sym);
	} else if (param == -1 && is_return_statement()) {
		in_nospec_stmt = true;
		return;
	} else {
		arg = get_argument_from_call_expr(call->args, param);
		if (!arg)
			return;
		name = get_variable_from_key(arg, key, &sym);
	}
	if (!name || !sym)
		goto free;

	set_state(my_id, name, sym, &nospec);
free:
	free_string(name);
}

static int is_nospec_asm(struct statement *stmt)
{
	char *macro;

	if (!stmt || stmt->type != STMT_ASM)
		return 0;
	macro = get_macro_name(stmt->asm_string->pos);
	if (!macro || strcmp(macro, "CALL_NOSPEC") != 0)
		return 0;
	return 1;
}

static void match_asm(struct statement *stmt)
{
	if (is_nospec_asm(stmt))
		in_nospec_stmt = true;
}

static void match_after_nospec_asm(struct statement *stmt)
{
	in_nospec_stmt = false;
}

static void mark_user_data_as_nospec(void)
{
	struct stree *stree;
	struct symbol *type;
	struct sm_state *sm;

	stree = get_user_stree();
	FOR_EACH_SM(stree, sm) {
		if (is_whole_rl(estate_rl(sm->state)))
			continue;
		type = estate_type(sm->state);
		if (!type || type->type != SYM_BASETYPE)
			continue;
		if (!is_capped_var_sym(sm->name, sm->sym))
			continue;
		set_state(my_id, sm->name, sm->sym, &nospec);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);
}

static void match_barrier(struct statement *stmt)
{
	char *macro;

	macro = get_macro_name(stmt->pos);
	if (!macro)
		return;
	if (strcmp(macro, "rmb") != 0 &&
	    strcmp(macro, "smp_rmb") != 0 &&
	    strcmp(macro, "barrier_nospec") != 0 &&
	    strcmp(macro, "preempt_disable") != 0)
		return;

	set_state(barrier_id, "barrier", NULL, &nospec);
	mark_user_data_as_nospec();
}

static void db_returns_barrier(struct expression *expr, int param, char *key, char *value)
{
	mark_user_data_as_nospec();
}

static void select_return_stmt_cnt(struct expression *expr, int param, char *key, char *value)
{
	int cnt;

	cnt = atoi(value);
	if (cnt > 400)
		mark_user_data_as_nospec();
}

void check_nospec(int id)
{
	my_id = id;

	add_hook(&nospec_assign, ASSIGNMENT_HOOK);

	select_caller_info_hook(set_param_nospec, NOSPEC);
	add_unmatched_state_hook(my_id, &unmatched_state);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	add_split_return_callback(&returned_struct_members);
	select_return_states_hook(NOSPEC, &db_returns_nospec);
	select_return_states_hook(NOSPEC_WB, &db_returns_barrier);
	select_return_states_hook(STMT_CNT, &select_return_stmt_cnt);

	add_hook(&match_asm, ASM_HOOK);
	add_hook(&match_after_nospec_asm, STMT_HOOK_AFTER);
}

void check_nospec_barrier(int id)
{
	barrier_id = id;

	add_hook(&match_barrier, ASM_HOOK);
}

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

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;
static int param_set_id;

STATE(terminated);
STATE(unterminated);
STATE(set);

static void set_terminated_var_sym(const char *name, struct symbol *sym, struct smatch_state *state)
{
	if (get_param_num_from_sym(sym) >= 0)
		set_state(param_set_id, name, sym, &set);
	set_state(my_id, name, sym, state);
}

static void set_terminated(struct expression *expr, struct smatch_state *state)
{
	struct symbol *sym;
	char *name;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		return;
	set_terminated_var_sym(name, sym, state);
	free_string(name);
}

static void match_nul_assign(struct expression *expr)
{
	struct expression *array;
	struct symbol *type;
	sval_t sval;

	if (expr->op != '=')
		return;

	if (!get_value(expr->right, &sval) || sval.value != 0)
		return;

	array = get_array_base(expr->left);
	if (!array)
		return;

	type = get_type(array);
	if (!type)
		return;
	type = get_real_base_type(type);
	if (type != &char_ctype)
		return;
	set_terminated(array, &terminated);
}

static struct smatch_state *get_terminated_state(struct expression *expr)
{
	struct sm_state *sm, *tmp;

	if (!expr)
		return NULL;
	if (expr->type == EXPR_STRING)
		return &terminated;
	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return NULL;
	if (sm->state == &terminated || sm->state == &unterminated)
		return sm->state;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &unterminated)
			return &unterminated;
	} END_FOR_EACH_PTR(tmp);

	return NULL;
}

static void match_string_assign(struct expression *expr)
{
	struct smatch_state *state;

	if (expr->op != '=')
		return;
	state = get_terminated_state(expr->right);
	if (!state)
		return;
	set_terminated(expr->left, state);
}

static int sm_to_term(struct sm_state *sm)
{
	struct sm_state *tmp;

	if (!sm)
		return -1;
	if (sm->state == &terminated)
		return 1;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &unterminated)
			return 0;
	} END_FOR_EACH_PTR(tmp);

	return -1;
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	int term;

	term = sm_to_term(sm);
	if (term < 0)
		return;

	sql_insert_caller_info(call, TERMINATED, param, printed_name, term ? "1" : "0");
}

static void match_call_info(struct expression *expr)
{
	struct smatch_state *state;
	struct expression *arg;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;

		state = get_terminated_state(arg);
		if (!state)
			continue;
		sql_insert_caller_info(expr, TERMINATED, i, "$",
				       (state == &terminated) ? "1" : "0");
	} END_FOR_EACH_PTR(arg);
}

static void caller_info_terminated(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	set_state(my_id, fullname, sym, (*value == '1') ? &terminated : &unterminated);
}

static void split_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct symbol *returned_sym;
	struct sm_state *tmp, *sm;
	const char *param_name;
	int param;
	int term;

	FOR_EACH_MY_SM(param_set_id, __get_cur_stree(), tmp) {
		sm = get_sm_state(my_id, tmp->name, tmp->sym);
		if (!sm)
			continue;
		term = sm_to_term(sm);
		if (term < 0)
			continue;
		param = get_param_num_from_sym(tmp->sym);
		if (param < 0)
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		if (strcmp(param_name, "$") == 0)
			continue;

		sql_insert_return_states(return_id, return_ranges, TERMINATED,
					 param, param_name, term ? "1" : "0");
	} END_FOR_EACH_SM(tmp);

	returned_sym = expr_to_sym(expr);
	if (!returned_sym)
		return;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->sym != returned_sym)
			continue;
		term = sm_to_term(sm);
		if (term < 0)
			continue;
		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		sql_insert_return_states(return_id, return_ranges, TERMINATED,
					 -1, param_name, term ? "1" : "0");
	} END_FOR_EACH_SM(sm);
}

static void return_info_terminated(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;

	if (param == -1) {
		arg = expr->left;
	} else {
		struct expression *call = expr;

		while (call->type == EXPR_ASSIGNMENT)
			call = strip_expr(call->right);
		if (call->type != EXPR_CALL)
			return;

		arg = get_argument_from_call_expr(call->args, param);
		if (!arg)
			return;
	}

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	set_terminated_var_sym(name, sym, (*value == '1') ? &terminated : &unterminated);
free:
	free_string(name);
}

bool is_nul_terminated(struct expression *expr)
{
	if (get_terminated_state(expr) == &terminated)
		return 1;
	return 0;
}

void register_nul_terminator(int id)
{
	my_id = id;

	add_hook(&match_nul_assign, ASSIGNMENT_HOOK);
	add_hook(&match_string_assign, ASSIGNMENT_HOOK);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	add_split_return_callback(&split_return_info);

	select_caller_info_hook(caller_info_terminated, TERMINATED);
	select_return_states_hook(TERMINATED, return_info_terminated);
}

void register_nul_terminator_param_set(int id)
{
	param_set_id = id;
}

/*
 * Copyright (C) 2011 Oracle.  All rights reserved.
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
 * This is trying to make a list of the variables which
 * have capped values.  Sometimes we don't know what the
 * cap is, for example if we are comparing variables but
 * we don't know the values of the variables.  In that
 * case we only know that our variable is capped and we
 * sort that information here.
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(capped);
STATE(uncapped);

static void set_uncapped(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &uncapped);
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct smatch_state *state;

	state = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (state && !estate_is_whole(state))
		return &capped;
	return &uncapped;
}

static int is_capped_macro(struct expression *expr)
{
	char *name;

	name = get_macro_name(expr->pos);
	if (!name)
		return 0;

	if (strcmp(name, "min") == 0)
		return 1;
	if (strcmp(name, "MIN") == 0)
		return 1;
	if (strcmp(name, "min_t") == 0)
		return 1;

	return 0;
}

int is_capped(struct expression *expr)
{
	sval_t dummy;

	expr = strip_expr(expr);
	while (expr && expr->type == EXPR_POSTOP) {
		expr = strip_expr(expr->unop);
	}
	if (!expr)
		return 0;

	if (get_hard_max(expr, &dummy))
		return 1;

	if (is_capped_macro(expr))
		return 1;

	if (expr->type == EXPR_BINOP) {
		struct range_list *left_rl, *right_rl;

		if (expr->op == '&')
			return 1;
		if (expr->op == SPECIAL_RIGHTSHIFT)
			return 1;
		if (expr->op == '%')
			return is_capped(expr->right);
		if (!is_capped(expr->left))
			return 0;
		if (expr->op == '/')
			return 1;
		if (!is_capped(expr->right))
			return 0;
		if (expr->op == '*') {
			get_absolute_rl(expr->left, &left_rl);
			get_absolute_rl(expr->right, &right_rl);
			if (sval_is_negative(rl_min(left_rl)) ||
			    sval_is_negative(rl_min(right_rl)))
				return 0;
		}
		return 1;
	}
	if (get_state_expr(my_id, expr) == &capped)
		return 1;
	return 0;
}

int is_capped_var_sym(const char *name, struct symbol *sym)
{
	if (get_state(my_id, name, sym) == &capped)
		return 1;
	return 0;
}

void set_param_capped_data(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];

	if (strncmp(key, "$", 1))
		return;
	snprintf(fullname, 256, "%s%s", name, key + 1);
	set_state(my_id, fullname, sym, &capped);
}

static void match_condition(struct expression *expr)
{
	struct smatch_state *left_true = NULL;
	struct smatch_state *left_false = NULL;
	struct smatch_state *right_true = NULL;
	struct smatch_state *right_false = NULL;


	if (expr->type != EXPR_COMPARE)
		return;

	switch (expr->op) {
	case '<':
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_UNSIGNED_LTE:
		left_true = &capped;
		right_false = &capped;
		break;
	case '>':
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_UNSIGNED_GTE:
		left_false = &capped;
		right_true = &capped;
		break;
	case SPECIAL_EQUAL:
		left_true = &capped;
		right_true = &capped;
		break;
	case SPECIAL_NOTEQUAL:
		left_false = &capped;
		right_false = &capped;
		break;

	default:
		return;
	}

	set_true_false_states_expr(my_id, expr->left, left_true, left_false);
	set_true_false_states_expr(my_id, expr->right, right_true, right_false);
}

static void match_assign(struct expression *expr)
{
	if (is_capped(expr->right)) {
		set_state_expr(my_id, expr->left, &capped);
	} else {
		if (get_state_expr(my_id, expr->left))
			set_state_expr(my_id, expr->left, &uncapped);
	}
}

static void match_caller_info(struct expression *expr)
{
	struct expression *tmp;
	sval_t sval;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, tmp) {
		i++;
		if (get_implied_value(tmp, &sval))
			continue;
		if (!is_capped(tmp))
			continue;
		sql_insert_caller_info(expr, CAPPED_DATA, i, "$", "1");
	} END_FOR_EACH_PTR(tmp);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	struct smatch_state *estate;
	sval_t sval;

	if (sm->state != &capped)
		return;
	estate = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (estate_get_single_value(estate, &sval))
		return;
	sql_insert_caller_info(call, CAPPED_DATA, param, printed_name, "1");
}

static void print_return_implies_capped(int return_id, char *return_ranges, struct expression *expr)
{
	struct smatch_state *orig, *estate;
	struct sm_state *sm;
	struct symbol *ret_sym;
	const char *param_name;
	char *return_str;
	int param;
	sval_t sval;
	bool return_found = false;

	expr = strip_expr(expr);
	return_str = expr_to_str(expr);
	ret_sym = expr_to_sym(expr);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state != &capped)
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;

		estate = get_state(SMATCH_EXTRA, sm->name, sm->sym);
		if (estate_get_single_value(estate, &sval))
			continue;

		orig = get_state_stree(get_start_states(), my_id, sm->name, sm->sym);
		if (orig == &capped)
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;

		sql_insert_return_states(return_id, return_ranges, CAPPED_DATA,
					 param, param_name, "1");
	} END_FOR_EACH_SM(sm);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (!ret_sym)
			break;
		if (ret_sym != sm->sym)
			continue;

		param_name = state_name_to_param_name(sm->name, return_str);
		if (!param_name)
			continue;
		if (strcmp(param_name, "$") == 0)
			return_found = true;
		sql_insert_return_states(return_id, return_ranges, CAPPED_DATA,
					 -1, param_name, "1");
	} END_FOR_EACH_SM(sm);

	if (return_found)
		goto free_string;

	if (option_project == PROJ_KERNEL && get_function() &&
	    strstr(get_function(), "nla_get_"))
		sql_insert_return_states(return_id, return_ranges, CAPPED_DATA,
					 -1, "$", "1");

free_string:
	free_string(return_str);
}

static void db_return_states_capped(struct expression *expr, int param, char *key, char *value)
{
	char *name;
	struct symbol *sym;

	name = return_state_to_var_sym(expr, param, key, &sym);
	if (!name || !sym)
		goto free;

	set_state(my_id, name, sym, &capped);
free:
	free_string(name);
}

void register_capped(int id)
{
	my_id = id;

	add_unmatched_state_hook(my_id, &unmatched_state);
	select_caller_info_hook(set_param_capped_data, CAPPED_DATA);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_modification_hook(my_id, &set_uncapped);

	add_hook(&match_caller_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);

	add_split_return_callback(print_return_implies_capped);
	select_return_states_hook(CAPPED_DATA, &db_return_states_capped);
}

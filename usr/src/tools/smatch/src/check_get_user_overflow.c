/*
 * Copyright (C) 2010 Dan Carpenter.
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
 * Looks for integers that we get from the user which can be attacked
 * with an integer overflow.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_max_id;
static int my_min_id;

STATE(capped);
STATE(user_data);

static void match_condition(struct expression *expr)
{
	struct smatch_state *left_max_true = NULL;
	struct smatch_state *left_max_false = NULL;
	struct smatch_state *right_max_true = NULL;
	struct smatch_state *right_max_false = NULL;

	struct smatch_state *left_min_true = NULL;
	struct smatch_state *left_min_false = NULL;
	struct smatch_state *right_min_true = NULL;
	struct smatch_state *right_min_false = NULL;

	if (expr->type != EXPR_COMPARE)
		return;

	switch (expr->op) {
	case '<':
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_UNSIGNED_LTE:
		left_max_true = &capped;
		right_max_false = &capped;
		right_min_true = &capped;
		left_min_false = &capped;
		break;
	case '>':
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_UNSIGNED_GTE:
		left_max_false = &capped;
		right_max_true = &capped;
		left_min_true = &capped;
		right_min_false = &capped;
		break;
	case SPECIAL_EQUAL:
		left_max_true = &capped;
		right_max_true = &capped;
		left_min_true = &capped;
		right_min_true = &capped;
		break;
	case SPECIAL_NOTEQUAL:
		left_max_false = &capped;
		right_max_false = &capped;
		left_min_false = &capped;
		right_min_false = &capped;
		break;
	default:
		return;
	}

	if (get_state_expr(my_max_id, expr->left)) {
		set_true_false_states_expr(my_max_id, expr->left, left_max_true, left_max_false);
		set_true_false_states_expr(my_min_id, expr->left, left_min_true, left_min_false);
	}
	if (get_state_expr(my_max_id, expr->right)) {
		set_true_false_states_expr(my_max_id, expr->right, right_max_true, right_max_false);
		set_true_false_states_expr(my_min_id, expr->right, right_min_true, right_min_false);
	}
}

static void match_normal_assign(struct expression *expr)
{
	if (get_state_expr(my_max_id, expr->left)) {
		set_state_expr(my_max_id, expr->left, &capped);
		set_state_expr(my_min_id, expr->left, &capped);
	}
}

static void match_assign(struct expression *expr)
{
	char *name;

	name = get_macro_name(expr->pos);
	if (!name || strcmp(name, "get_user") != 0) {
		match_normal_assign(expr);
		return;
	}
	name = expr_to_var(expr->right);
	if (!name || (strcmp(name, "__val_gu") != 0 && strcmp(name, "__gu_val")))
		goto free;
	set_state_expr(my_max_id, expr->left, &user_data);
	set_state_expr(my_min_id, expr->left, &user_data);
free:
	free_string(name);
}

static void check_expr(struct expression *expr)
{
	struct sm_state *sm;
	sval_t max;
	sval_t sval;
	char *name;
	int overflow = 0;
	int underflow = 0;

	sm = get_sm_state_expr(my_max_id, expr);
	if (sm && slist_has_state(sm->possible, &user_data)) {
		get_absolute_max(expr, &max);
		if (sval_cmp_val(max, 20000) > 0)
			overflow = 1;
	}

	sm = get_sm_state_expr(my_min_id, expr);
	if (sm && slist_has_state(sm->possible, &user_data)) {
		get_absolute_min(expr, &sval);
		if (sval_is_negative(sval) && sval_cmp_val(sval, -20000) < 0)
			underflow = 1;
	}

	if (!overflow && !underflow)
		return;

	name = expr_to_var_sym(expr, NULL);
	if (overflow && underflow)
		sm_warning("check for integer over/underflow '%s'", name);
	else if (underflow)
		sm_warning("check for integer underflow '%s'", name);
	else
		sm_warning("check for integer overflow '%s'", name);
	free_string(name);

	set_state_expr(my_max_id, expr, &capped);
	set_state_expr(my_min_id, expr, &capped);
}

static void match_binop(struct expression *expr)
{
	if (expr->op == '^')
		return;
	if (expr->op == '&')
		return;
	if (expr->op == '|')
		return;
	if (expr->op == SPECIAL_RIGHTSHIFT)
		return;
	if (expr->op == SPECIAL_LEFTSHIFT)
		return;

	check_expr(expr->left);
	check_expr(expr->right);
}

void check_get_user_overflow(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_max_id = id;
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_binop, BINOP_HOOK);
}

void check_get_user_overflow2(int id)
{
	my_min_id = id;
}

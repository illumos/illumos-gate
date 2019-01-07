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

/*
 * Looks for integers that we get from the user which can be attacked
 * with an integer overflow.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

static void match_condition(struct expression *expr)
{
	struct expression *left, *right;
	struct symbol *type;
	char *right_name;
	char *left_name;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != '<')
		return;

	type = get_type(expr);
	if (!type_signed(type))
		return;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (left->type != EXPR_BINOP) {
		left = get_assigned_expr(left);
		left = strip_expr(left);
		if (!left || left->type != EXPR_BINOP)
			return;
	}

	if (left->op != '+' && left->op != '*' && left->op != SPECIAL_LEFTSHIFT)
		return;

	if (has_variable(left, right) == 1) {
		left_name = expr_to_str(left);
		right_name = expr_to_str(right);
		sm_warning("signed overflow undefined. '%s %s %s'", left_name, show_special(expr->op), right_name);
		free_string(left_name);
		free_string(right_name);
	}
}

static void match_binop(struct expression *expr)
{
	sval_t left_val, right_min;
	char *str;

	if (expr->op != '-')
		return;

	if (!get_value(expr->left, &left_val))
		return;

	switch (left_val.uvalue) {
	case SHRT_MAX:
	case USHRT_MAX:
	case INT_MAX:
	case UINT_MAX:
	case LLONG_MAX:
	case ULLONG_MAX:
		break;
	default:
		return;
	}

	get_absolute_min(expr->right, &right_min);
	if (!sval_is_negative(right_min))
		return;

	str = expr_to_str(expr);
	sm_warning("potential negative subtraction from max '%s'", str);
	free_string(str);
}

void check_signed_integer_overflow_check(int id)
{
	my_id = id;

	if (option_project == PROJ_KERNEL) {
		/* The kernel uses -fno-strict-overflow so it's fine */
		return;
	}

	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_binop, BINOP_HOOK);
}


/*
 * Copyright (C) 2012 Oracle.
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
#include "smatch_function_hashtable.h"

static int my_id;

DEFINE_STRING_HASHTABLE_STATIC(unconstant_macros);

static int does_inc_dec(struct expression *expr)
{
	if (expr->type == EXPR_PREOP || expr->type == EXPR_POSTOP) {
		if (expr->op == SPECIAL_INCREMENT || expr->op == SPECIAL_DECREMENT)
			return 1;
		return does_inc_dec(expr->unop);
	}
	return 0;
}

static int expr_equiv_no_inc_dec(struct expression *one, struct expression *two)
{
	if (does_inc_dec(one) || does_inc_dec(two))
		return 0;
	return expr_equiv(one, two);
}

static int inconsistent_check(struct expression *left, struct expression *right)
{
	sval_t sval;

	if (get_value(left->left, &sval)) {
		if (get_value(right->left, &sval))
			return expr_equiv_no_inc_dec(left->right, right->right);
		if (get_value(right->right, &sval))
			return expr_equiv_no_inc_dec(left->right, right->left);
		return 0;
	}
	if (get_value(left->right, &sval)) {
		if (get_value(right->left, &sval))
			return expr_equiv_no_inc_dec(left->left, right->right);
		if (get_value(right->right, &sval))
			return expr_equiv_no_inc_dec(left->left, right->left);
		return 0;
	}

	return 0;
}

static void check_or(struct expression *expr)
{
	struct expression *left, *right;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (left->type != EXPR_COMPARE || left->op != SPECIAL_NOTEQUAL)
		return;
	if (right->type != EXPR_COMPARE || right->op != SPECIAL_NOTEQUAL)
		return;
	if (!inconsistent_check(left, right))
		return;

	sm_warning("was && intended here instead of ||?");
}

static int is_kernel_min_macro(struct expression *expr)
{
	char *macro;

	if (option_project != PROJ_KERNEL)
		return 0;
	macro = get_macro_name(expr->pos);
	if (!macro)
		return 0;
	if (strcmp(macro, "min") == 0 ||
	    strcmp(macro, "min_t") == 0 ||
	    strcmp(macro, "max") == 0 ||
	    strcmp(macro, "max_t") == 0)
		return 1;
	return 0;
}

static void check_and(struct expression *expr)
{
	struct expression *left, *right;

	if (is_kernel_min_macro(expr))
		return;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (left->type != EXPR_COMPARE || left->op != SPECIAL_EQUAL)
		return;
	if (right->type != EXPR_COMPARE || right->op != SPECIAL_EQUAL)
		return;
	if (!inconsistent_check(left, right))
		return;

	sm_warning("was || intended here instead of &&?");
}

static void match_logic(struct expression *expr)
{
	if (expr->type != EXPR_LOGICAL)
		return;

	if (expr->op == SPECIAL_LOGICAL_OR)
		check_or(expr);
	if (expr->op == SPECIAL_LOGICAL_AND)
		check_and(expr);
}

static int is_unconstant_macro(struct expression *expr)
{
	char *macro;

	macro = get_macro_name(expr->pos);
	if (!macro)
		return 0;
	if (search_unconstant_macros(unconstant_macros, macro))
		return 1;
	return 0;
}

static void match_condition(struct expression *expr)
{
	sval_t sval;

	if (expr->type != EXPR_BINOP)
		return;
	if (expr->op == '|') {
		if (get_value(expr->left, &sval) || get_value(expr->right, &sval))
			sm_warning("suspicious bitop condition");
		return;
	}

	if (expr->op != '&')
		return;

	if (get_macro_name(expr->pos))
		return;
	if (is_unconstant_macro(expr->left) || is_unconstant_macro(expr->right))
		return;

	if ((get_value(expr->left, &sval) && sval.value == 0) ||
	    (get_value(expr->right, &sval) && sval.value == 0))
		sm_warning("bitwise AND condition is false here");
}

static void match_binop(struct expression *expr)
{
	sval_t left, right, sval;

	if (expr->op != '&')
		return;
	if (!get_value(expr, &sval) || sval.value != 0)
		return;
	if (get_macro_name(expr->pos))
		return;
	if (!get_value(expr->left, &left) || !get_value(expr->right, &right))
		return;
	sm_warning("odd binop '0x%llx & 0x%llx'", left.uvalue, right.uvalue);
}

void check_or_vs_and(int id)
{
	my_id = id;

	unconstant_macros = create_function_hashtable(100);
	load_strings("unconstant_macros", unconstant_macros);

	add_hook(&match_logic, LOGIC_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	if (option_spammy)
		add_hook(&match_binop, BINOP_HOOK);
}

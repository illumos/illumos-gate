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

static int my_id;

#if 0
static unsigned long long find_possible_bits(struct expression *expr)
{
	sval_t sval;
	unsigned long long ret;
	int set;
	int i;

	expr = strip_expr(expr);

	if (get_implied_value(expr, &sval))
		return sval.uvalue;

	if (expr->type == EXPR_BINOP && (expr->op == '&' || expr->op == '|')) {
		unsigned long long left, right;

		left = find_possible_bits(expr->left);
		if (!left)
			return 0;
		right = find_possible_bits(expr->right);
		if (!right)
			return 0;

		if (expr->op == '&')
			return left & right;
		return left | right;
	}

	get_absolute_max(expr, &sval);
	ret = sval.value;

	set = false;
	for (i = 63; i >= 0; i--) {
		if (ret & 1 << i)
			set = true;
		if (set)
			ret |= 1 << i;
	}
	return ret;
}
#endif

static unsigned long long get_possible_bits(struct expression *expr)
{
	sval_t sval;

	expr = strip_expr(expr);
	if (expr->type != EXPR_BINOP)
		return 0;
	if (expr->op != '&')
		return 0;
	if (!get_implied_value(expr->right, &sval))
		return 0;

	return sval.uvalue;
}

static void match_condition(struct expression *expr)
{
	struct symbol *type;
	sval_t sval;
	unsigned long long left_mask, right_mask;
	char *str;

	type = get_type(expr);
	if (!type)
		type = &int_ctype;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != SPECIAL_EQUAL && expr->op != SPECIAL_NOTEQUAL)
		return;

	if (!get_value(expr->right, &sval))
		return;
	right_mask = sval.uvalue;

	left_mask = get_possible_bits(expr->left);
	if (!left_mask)
		return;

	if (type_bits(type) < 64) {
		left_mask &= (1ULL << type_bits(type)) - 1;
		right_mask &= (1ULL << type_bits(type)) - 1;
	}

	if ((left_mask & right_mask) == right_mask)
		return;

	str = expr_to_str(expr);
	sm_warning("masked condition '%s' is always %s.", str,
	       expr->op == SPECIAL_EQUAL ? "false" : "true");
	free_string(str);
}

void check_impossible_mask(int id)
{
	my_id = id;

	add_hook(&match_condition, CONDITION_HOOK);
}

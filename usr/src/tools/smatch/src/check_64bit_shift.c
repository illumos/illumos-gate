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
#include "smatch_extra.h"

static int my_id;

static void match_shift_mask(struct expression *expr)
{
	struct expression *right, *shifter;
	struct range_list *rl;
	char *str;

	expr = strip_expr(expr);
	if (expr->type != EXPR_BINOP || expr->op != '&')
		return;

	if (get_type(expr->left) != &ullong_ctype)
		return;

	if (type_bits(get_type(expr->right)) == 64)
		return;

	right = strip_expr(expr->right);
	if (right->type != EXPR_BINOP || right->op != SPECIAL_LEFTSHIFT)
		return;

	shifter = strip_expr(right->right);
	get_real_absolute_rl(shifter, &rl);
	if (rl_max(rl).uvalue < 32)
		return;

	str = expr_to_str(expr->right);
	sm_warning("should '%s' be a 64 bit type?", str);
	free_string(str);
}

static void match_shift_assignment(struct expression *expr)
{
	struct symbol *left_type, *right_type;
	struct expression *right;
	sval_t sval;
	sval_t bits, shifter;
	char *name;

	right = strip_expr(expr->right);
	if (right->type != EXPR_BINOP || right->op != SPECIAL_LEFTSHIFT)
		return;

	left_type = get_type(expr->left);
	if (left_type != &llong_ctype && left_type != &ullong_ctype)
		return;

	right_type = get_type(expr->right);

	if (type_bits(right_type) == 64)
		return;

	if (get_value(right, &sval))
		return;

	get_absolute_max(right->left, &bits);
	get_absolute_max(right->right, &shifter);

	bits = sval_cast(&ullong_ctype, bits);
	if (sval_cmp_val(shifter, 32) < 0) {
		sval = sval_binop(bits, SPECIAL_LEFTSHIFT, shifter);
		if (sval_cmp_val(sval, UINT_MAX) < 0)
			return;
	}

	name = expr_to_str_sym(right, NULL);
	sm_warning("should '%s' be a 64 bit type?", name);
	free_string(name);
}

void check_64bit_shift(int id)
{
	my_id = id;

	add_hook(&match_shift_assignment, ASSIGNMENT_HOOK);
	add_hook(&match_shift_mask, BINOP_HOOK);
}

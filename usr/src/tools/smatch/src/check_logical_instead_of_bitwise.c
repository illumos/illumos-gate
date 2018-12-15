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

static int is_bitshift(struct expression *expr)
{
	expr = strip_expr(expr);

	if (expr->type != EXPR_BINOP)
		return 0;
	if (expr->op == SPECIAL_LEFTSHIFT)
		return 1;
	return 0;
}

static void match_logic(struct expression *expr)
{
	sval_t sval;

	if (expr->type != EXPR_LOGICAL)
		return;

	if (get_macro_name(expr->pos))
		return;

	if (!get_value(expr->right, &sval)) {
		if (!get_value(expr->left, &sval))
			return;
	}

	if (sval.value == 0 || sval.value == 1)
		return;

	sm_warning("should this be a bitwise op?");
}

static void match_assign(struct expression *expr)
{
	struct expression *right;

	right = strip_expr(expr->right);
	if (right->type != EXPR_LOGICAL)
		return;
	if (is_bitshift(right->left) || is_bitshift(right->right))
		sm_warning("should this be a bitwise op?");
}

void check_logical_instead_of_bitwise(int id)
{
	my_id = id;

	add_hook(&match_logic, LOGIC_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
}

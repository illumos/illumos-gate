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

#include "smatch.h"

static int my_id;

static void match_inside(struct expression *expr, struct position pos)
{
	char *name;
	int matched = 0;

	if (positions_eq(expr->pos, pos))
		matched++;
	if (positions_eq(expr->unop->pos, pos))
		matched++;
	if (matched != 1)
		return;
	name = get_macro_name(pos);
	if (!name)
		return;
	sm_warning("the '%s' macro might need parens", name);
}

static void match_one_side(struct expression *expr, struct position pos, int op)
{
	char *name;
	int matched = 0;

	if ((op == '+' || op == '*' || op == '|' || op == '&') && expr->op == op)
		return;
	if (positions_eq(expr->right->pos, pos))
		matched++;
	if (positions_eq(expr->left->pos, pos))
		matched++;
	if (matched != 1)
		return;
	name = get_macro_name(pos);
	if (!name)
		return;
	if (option_project == PROJ_WINE && !strcmp("BEGIN", name))
		return;
	sm_warning("the '%s' macro might need parens", name);
}

static void match_join(struct expression *expr)
{
	if (expr->left->type == EXPR_PREOP)
		match_inside(expr->left, expr->pos);
	if (expr->right->type == EXPR_POSTOP)
		match_inside(expr->right, expr->pos);

	if (expr->left->type == EXPR_BINOP)
		match_one_side(expr->left, expr->pos, expr->op);
	if (expr->right->type == EXPR_BINOP)
		match_one_side(expr->right, expr->pos, expr->op);
}

void check_macros(int id)
{
	my_id = id;
	add_hook(&match_join, BINOP_HOOK);
	add_hook(&match_join, LOGIC_HOOK);
}

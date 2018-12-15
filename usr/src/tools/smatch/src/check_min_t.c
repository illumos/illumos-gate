/*
 * Copyright (C) 2011 Dan Carpenter.
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

static void match_assign(struct expression *expr)
{
	const char *macro;
	sval_t max_left, max_right;
	char *name;

	if (expr->op != '=')
		return;

	macro = get_macro_name(expr->pos);
	if (!macro)
		return;
	if (strcmp(macro, "min_t"))
		return;

	if (!get_absolute_max(expr->left, &max_left))
		return;
	if (!get_absolute_max(expr->right, &max_right))
		return;

	if (sval_cmp(max_left, max_right) >= 0)
		return;

	name = expr_to_str(expr->right);
	sm_warning("min_t truncates here '%s' (%s vs %s)", name, sval_to_str(max_left), sval_to_str(max_right));
	free_string(name);
}

void check_min_t(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;
	add_hook(&match_assign, ASSIGNMENT_HOOK);
}

/*
 * Copyright (C) 2011 Oracle.
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

static void match_wait_for_common(const char *fn, struct expression *expr, void *unused)
{
	char *name;

	if (!expr_unsigned(expr->left))
		return;
	name = expr_to_str(expr->left);
	sm_error("'%s()' returns negative and '%s' is unsigned", fn, name);
	free_string(name);
}

void check_wait_for_common(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;
	add_function_assign_hook("wait_for_common", &match_wait_for_common, NULL);
	add_function_assign_hook("wait_for_completion_interruptible_timeout", &match_wait_for_common, NULL);
}

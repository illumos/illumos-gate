/*
 * Copyright (C) 2009 Dan Carpenter.
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

static void match_call(struct expression *expr)
{
	char *fn_name;

	fn_name = expr_to_var(expr->fn);
	if (!fn_name)
		return;
	sm_prefix();
	sm_printf("info: func_call (");
	print_held_locks();
	sm_printf(") %s\n", fn_name);
	free_string(fn_name);
}

void check_call_tree(int id)
{
	if (!option_call_tree)
		return;
	my_id = id;
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}

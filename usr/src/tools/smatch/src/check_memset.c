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

static void match_memset(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg_expr;
	sval_t sval;

	arg_expr = get_argument_from_call_expr(expr->args, 2);

	if (arg_expr->type != EXPR_VALUE)
		return;
	if (!get_value(arg_expr, &sval))
		return;
	if (sval.value != 0)
		return;
	sm_error("calling memset(x, y, 0);");
}

void check_memset(int id)
{
	my_id = id;
	add_function_hook("memset", &match_memset, NULL);
	add_function_hook("__builtin_memset", &match_memset, NULL);
}

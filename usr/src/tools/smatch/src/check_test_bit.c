/*
 * Copyright (C) 2015 Oracle.
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
#include "smatch_slist.h"

static int my_id;

static void match_test_bit(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;
	char *macro;

	arg = get_argument_from_call_expr(expr->args, 0);
	arg = strip_expr(arg);

	if (!arg || arg->type != EXPR_BINOP)
		return;
	if (arg->op != '|' && arg->op != SPECIAL_LEFTSHIFT)
		return;
	macro = get_macro_name(arg->pos);
	if (macro && strstr(macro, "cpu_has"))
		return;
	sm_warning("test_bit() takes a bit number");
}

void check_test_bit(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	add_function_hook("test_bit", &match_test_bit, NULL);
	add_function_hook("variable_test_bit", &match_test_bit, NULL);
	add_function_hook("set_bit", &match_test_bit, NULL);
	add_function_hook("clear_bit", &match_test_bit, NULL);
	add_function_hook("test_and_clear_bit", &match_test_bit, NULL);
	add_function_hook("test_and_set_bit", &match_test_bit, NULL);
}

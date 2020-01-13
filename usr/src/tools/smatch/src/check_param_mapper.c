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

/*
 * The idea behind this test is that if we have:
 * void foo(int bar)
 * {
 *         baz(1, bar);
 * }
 *
 * Passing "bar" to foo() really means passing "bar" to baz();
 *
 * In this case it would print:
 * info: param_mapper 0 => bar 1
 *
 */

#include "smatch.h"

static int my_id;

static void match_call(struct expression *expr)
{
	struct expression *tmp;
	char *func;
	int arg_num;
	int i;

	if (expr->fn->type != EXPR_SYMBOL)
		return;

	func = expr->fn->symbol_name->name;

	i = -1;
	FOR_EACH_PTR(expr->args, tmp) {
		i++;
		tmp = strip_expr(tmp);
		if (tmp->type != EXPR_SYMBOL)
			continue;
		if (param_was_set(tmp))
			continue;
		arg_num = get_param_num_from_sym(tmp->symbol);
		if (arg_num < 0)
			continue;
		sm_msg("info: param_mapper %d => %s %d", arg_num, func, i);
	} END_FOR_EACH_PTR(tmp);
}

void check_param_mapper(int id)
{
	if (!option_info)
		return;
	my_id = id;
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}

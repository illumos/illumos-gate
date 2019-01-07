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

static void match_irqrestore(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg_expr;
	sval_t tmp;

	arg_expr = get_argument_from_call_expr(expr->args, 1);
	if (!get_implied_value(arg_expr, &tmp))
		return;
	sm_error("calling '%s()' with bogus flags", fn);
}

void check_bogus_irqrestore(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_hook("spin_unlock_irqrestore", &match_irqrestore, NULL);
}

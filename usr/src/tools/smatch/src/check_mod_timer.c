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
#include "smatch_slist.h"

static int my_id;

static void match_mod_timer(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 1);
	if (!get_value(arg, &sval) || sval.value == 0)
		return;
	sm_warning("mod_timer() takes an absolute time not an offset.");
}

void check_mod_timer(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_hook("mod_timer", &match_mod_timer, NULL);
}

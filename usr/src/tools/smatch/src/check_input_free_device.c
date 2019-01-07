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

/*
 * Don't call input_free_device() after calling
 * input_unregister_device()
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

STATE(no_free);
STATE(ok);

static int my_id;

static void match_assign(struct expression *expr)
{
	if (get_state_expr(my_id, expr->left)) {
		set_state_expr(my_id, expr->left, &ok);
	}
}

static void match_input_unregister(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, 0);
	set_state_expr(my_id, arg, &no_free);
}

static void match_input_free(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;
	struct sm_state *sm;

	arg = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(my_id, arg);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &no_free))
		return;
	sm_error("don't call input_free_device() after input_unregister_device()");
}

void check_input_free_device(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_function_hook("input_unregister_device", &match_input_unregister, NULL);
	add_function_hook("input_free_device", &match_input_free, NULL);
}

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
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

#define MAX_ERRNO 4095

STATE(added);
STATE(not_added);

static void match_added(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(call_expr->args, 0);
	set_state_expr(my_id, arg_expr, &added);
}

static void match_not_added(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(call_expr->args, 0);
	set_state_expr(my_id, arg_expr, &not_added);
}

static void match_platform_device_del(const char *fn, struct expression *expr, void *unused)
{
	struct expression *arg_expr;
	struct sm_state *sm;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(my_id, arg_expr);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &not_added))
		return;
	sm_warning("perhaps platform_device_put() was intended here?");
}

void check_platform_device_put(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;

	return_implies_state("platform_device_add", 0, 0, &match_added, NULL);
	return_implies_state("platform_device_add", -MAX_ERRNO, -1, &match_not_added, NULL);
	add_function_hook("platform_device_del", &match_platform_device_del, NULL);
}

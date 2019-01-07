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

STATE(no_unmap);

extern int check_assigned_expr_id;
static int my_id;

static void check_assignment(void *data)
{
	struct expression *expr = (struct expression *)data;
	char *fn;

	if (!expr)
		return;
	if (expr->type != EXPR_CALL)
		return;
	fn = expr_to_var(expr->fn);
	if (!fn)
		return;
	if (!strcmp(fn, "kmap"))
		sm_warning("passing the wrong variable to kunmap()");
	free_string(fn);
}

static void match_kmap_atomic(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, 0);
	set_state_expr(my_id, arg, &no_unmap);
}

static void match_kunmap_atomic(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;
	struct sm_state *sm;

	arg = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(my_id, arg);
	if (!sm)
		return;
	if (slist_has_state(sm->possible, &no_unmap))
		sm_warning("passing the wrong variable to kmap_atomic()");
}

static void match_kunmap(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg;
	struct sm_state *sm;
	struct sm_state *tmp;

	arg = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(check_assigned_expr_id, arg);
	if (!sm)
		return;
	FOR_EACH_PTR(sm->possible, tmp) {
		check_assignment(tmp->state->data);
	} END_FOR_EACH_PTR(tmp);
}

void check_kunmap(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;
	add_function_hook("kunmap", &match_kunmap, NULL);
	add_function_hook("kmap_atomic", &match_kmap_atomic, NULL);
	add_function_hook("kunmap_atomic", &match_kunmap_atomic, NULL);
}

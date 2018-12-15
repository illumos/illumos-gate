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
 * Some macros don't return NULL pointers.  Complain if people
 * check the results for NULL because obviously the programmers
 * don't know what the pants they're doing.
 */

#include "smatch.h"

static int my_id;

STATE(non_null);

static void is_ok(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &undefined);
}

static void match_non_null(const char *fn, struct expression *expr, void *unused)
{
	set_state_expr(my_id, expr->left, &non_null);
}

static void match_condition(struct expression *expr)
{
	if (__in_pre_condition)
		return;

	if (get_macro_name(expr->pos))
		return;

	if (get_state_expr(my_id, expr) == &non_null) {
		char *name;

		name = expr_to_var(expr);
		sm_warning("can '%s' even be NULL?", name);
		set_state_expr(my_id, expr, &undefined);
		free_string(name);
	}
}

void check_container_of(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_macro_assign_hook("container_of", &match_non_null, NULL);
	add_macro_assign_hook("list_first_entry", &match_non_null, NULL);
	add_function_assign_hook("nla_data", &match_non_null, NULL);
	add_modification_hook(my_id, &is_ok);
	add_hook(&match_condition, CONDITION_HOOK);
}

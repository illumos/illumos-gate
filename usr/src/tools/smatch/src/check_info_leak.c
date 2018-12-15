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

STATE(alloced);
STATE(string);

static char *my_get_variable(struct expression *expr, struct symbol **sym)
{
	char *name;

	name = expr_to_var_sym(expr, sym);
	free_string(name);
	if (!name || !*sym)
		return NULL;

	return (*sym)->ident->name;
}

static void match_kmalloc(const char *fn, struct expression *expr, void *unused)
{
	char *name;
	struct symbol *sym;

	name = my_get_variable(expr->left, &sym);
	if (!name)
		return;
	set_state(my_id, name, sym, &alloced);
}

static void match_strcpy(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	char *name;
	struct symbol *sym;

	dest = get_argument_from_call_expr(expr->args, 0);
	name = my_get_variable(dest, &sym);
	if (!name || !sym)
		return;
	if (!get_state(my_id, name, sym))
		return;
	set_state(my_id, name, sym, &string);
}

static void match_copy_to_user(const char *fn, struct expression *expr, void *unused)
{
	struct expression *src;
	char *name;
	struct symbol *sym;
	struct sm_state *sm;

	src = get_argument_from_call_expr(expr->args, 1);
	name = my_get_variable(src, &sym);
	if (!name || !sym)
		return;
	sm = get_sm_state(my_id, name, sym);
	if (!sm || !slist_has_state(sm->possible, &string))
		return;
	name = expr_to_var(src);
	sm_warning("possible info leak '%s'", name);
	free_string(name);
}

void check_info_leak(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;
	add_function_assign_hook("kmalloc", &match_kmalloc, NULL);
	add_function_hook("strcpy", &match_strcpy, NULL);
	add_function_hook("strlcpy", &match_strcpy, NULL);
	add_function_hook("strlcat", &match_strcpy, NULL);
	add_function_hook("strncpy", &match_strcpy, NULL);
	add_function_hook("copy_to_user", &match_copy_to_user, NULL);
}

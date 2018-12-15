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
 * I found a bug where someone released the wrong resource and wanted to 
 * prevent that from happening again.
 *
 */

#include "smatch.h"

static int my_id;

static struct tracker_list *resource_list;

static void match_request(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);
	char *name;
	struct symbol *sym;

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	arg_expr = strip_expr(arg_expr);

	name = expr_to_var_sym(arg_expr, &sym);
	if (!name || !sym)
		goto free;
	add_tracker(&resource_list, my_id, name, sym);
free:
	free_string(name);
}

static void match_release(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);
	char *name;
	struct symbol *sym;

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	arg_expr = strip_expr(arg_expr);

	if (!resource_list)
		return;

	name = expr_to_var_sym(arg_expr, &sym);
	if (!name || !sym)
		goto free;
	if (in_tracker_list(resource_list, my_id, name, sym))
		goto free;
	sm_warning("'%s' was not one of the resources you requested", name);
free:
	free_string(name);
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	free_trackers_and_list(&resource_list);
}

void check_release_resource(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	add_function_hook("request_resource", &match_request, (void *)1);
	add_function_hook("release_resource", &match_release, (void *)0);
	add_function_hook("request_mem_resource", &match_request, (void *)0);
	add_function_hook("release_mem_resource", &match_release, (void *)0);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

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

static int my_id;

static struct {
	int name_param;
	int mode_param;
} param_index[] = {
	{.name_param = 0, .mode_param = 1},
	{.name_param = 1, .mode_param = 2},
};

#define S_IWOTH 00002

static void match_create(const char *fn, struct expression *expr, void *_param_type)
{
	struct expression *arg_expr;
	sval_t sval;
	char *name;
	int idx = PTR_INT(_param_type);

	arg_expr = get_argument_from_call_expr(expr->args, param_index[idx].mode_param);
	if (!get_implied_value(arg_expr, &sval))
		return;
	if (!(sval.uvalue & S_IWOTH))
		return;
	arg_expr = get_argument_from_call_expr(expr->args, param_index[idx].name_param);
	name = expr_to_var(arg_expr);
	sm_warning("proc file '%s' is world writable", name);
	free_string(name);
}

void check_proc_create(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;

	add_function_hook("proc_create", &match_create, INT_PTR(0));
	add_function_hook("create_proc_entry", &match_create, INT_PTR(0));
	add_function_hook("proc_create_data", &match_create, INT_PTR(0));
	add_function_hook("proc_net_fops_create", match_create, INT_PTR(1));
}

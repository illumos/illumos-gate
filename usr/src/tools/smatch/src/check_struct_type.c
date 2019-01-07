/*
 * Copyright (C) 2013 Oracle.
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

static void match_assign(const char *fn, struct expression *expr, void *_size_arg)
{
	int size_arg = PTR_INT(_size_arg);
	struct expression *left;
	struct expression *call;
	struct expression *arg;
	struct symbol *left_type;
	struct symbol *size_type;

	left = strip_expr(expr->left);
	left_type = get_type(left);
	if (!left_type || left_type->type != SYM_PTR)
		return;
	left_type = get_real_base_type(left_type);
	if (!left_type || left_type->type != SYM_STRUCT)
		return;

	call = strip_expr(expr->right);
	arg = get_argument_from_call_expr(call->args, size_arg);
	if (!arg || arg->type != EXPR_SIZEOF || !arg->cast_type)
		return;
	size_type = arg->cast_type;
	if (size_type->type != SYM_NODE)
		return;
	size_type = get_real_base_type(size_type);
	if (size_type->type != SYM_STRUCT)
		return;
	if (strcmp(left_type->ident->name, size_type->ident->name) == 0)
		return;
	sm_warning("struct type mismatch '%s vs %s'", left_type->ident->name,
	       size_type->ident->name);

}

void check_struct_type(int id)
{
	my_id = id;

	if (option_project == PROJ_KERNEL) {
		add_function_assign_hook("kmalloc", &match_assign, INT_PTR(0));
		add_function_assign_hook("kzalloc", &match_assign, INT_PTR(0));
	}
}

/*
 * Copyright (C) 2011 Dan Carpenter.
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

static int get_data_size(struct expression *ptr)
{
	struct symbol *type;

	type = get_type(ptr);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_base_type(type);
	if (!type)
		return 0;
	return type_bytes(type);
}

static void check_size_matches(int data_size, struct expression *size_expr)
{
	sval_t sval;

	if (data_size == 1)  /* this is generic a buffer */
		return;

	if (!get_implied_value(size_expr, &sval))
		return;
	if (sval_cmp_val(sval, data_size) != 0)
		sm_warning("double check that we're allocating correct size: %d vs %s", data_size, sval_to_str(sval));
}

static void match_alloc(const char *fn, struct expression *expr, void *unused)
{
	struct expression *call = strip_expr(expr->right);
	struct expression *arg;
	int ptr_size;

	ptr_size = get_data_size(expr->left);
	if (!ptr_size)
		return;

	arg = get_argument_from_call_expr(call->args, 0);
	arg = strip_expr(arg);
	if (!arg || arg->type != EXPR_BINOP || arg->op != '*')
		return;
	if (expr->left->type == EXPR_SIZEOF)
		check_size_matches(ptr_size, arg->left);
	if (expr->right->type == EXPR_SIZEOF)
		check_size_matches(ptr_size, arg->right);
}

static void match_calloc(const char *fn, struct expression *expr, void *_arg_nr)
{
	int arg_nr = PTR_INT(_arg_nr);
	struct expression *call = strip_expr(expr->right);
	struct expression *arg;
	int ptr_size;

	ptr_size = get_data_size(expr->left);
	if (!ptr_size)
		return;

	arg = get_argument_from_call_expr(call->args, arg_nr);
	check_size_matches(ptr_size, arg);
}

void check_kmalloc_wrong_size(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL) {
		add_function_assign_hook("malloc", &match_alloc, NULL);
		add_function_assign_hook("calloc", &match_calloc, INT_PTR(1));
		return;
	}

	add_function_assign_hook("kmalloc", &match_alloc, NULL);
	add_function_assign_hook("kcalloc", &match_calloc, INT_PTR(1));
}

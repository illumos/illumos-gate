/*
 * Copyright (C) 2012 Oracle.
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

STATE(size_in_bytes);

static void set_undefined(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state == &size_in_bytes)
		set_state(my_id, sm->name, sm->sym, &undefined);
}

static int is_sizeof(struct expression *expr)
{
	return (expr->type == EXPR_SIZEOF);
}

static int is_macro(struct expression *expr, const char *macro_name)
{
	char *name;
	struct expression *outside_expr;

	/* check that we aren't inside the macro itself */
	outside_expr = last_ptr_list((struct ptr_list *)big_expression_stack);
	if (outside_expr && positions_eq(expr->pos, outside_expr->pos))
		return 0;

	name = get_macro_name(expr->pos);
	if (name && strcmp(name, macro_name) == 0)
		return 1;
	return 0;
}

static int is_size_in_bytes(struct expression *expr)
{
	if (is_sizeof(expr))
		return 1;

	if (is_macro(expr, "offsetof"))
		return 1;
	if (is_macro(expr, "PAGE_SIZE"))
		return 1;

	if (get_state_expr(my_id, expr) == &size_in_bytes)
		return 1;

	return 0;
}

static void match_binop(struct expression *expr)
{
	struct symbol *type;
	char *name;
	int size;

	if (expr->op != '+')
		return;
	type = get_pointer_type(expr->left);
	if (!type)
		return;
	if (type_bits(type) <= 8) /* ignore void, bool and char pointers*/
		return;
	if (!is_size_in_bytes(expr->right))
		return;

	/* if we know it's within bounds then don't complain */
	size = get_array_size(expr->left);
	if (size) {
		sval_t max;

		get_absolute_max(expr->right, &max);
		if (max.uvalue < size)
			return;
	}

	name = expr_to_str(expr->left);
	sm_warning("potential pointer math issue ('%s' is a %d bit pointer)",
	       name, type_bits(type));
	free_string(name);
}

static void match_assign(struct expression *expr)
{
	if (expr->op != '=')
		return;

	if (!is_size_in_bytes(expr->right))
		return;
	set_state_expr(my_id, expr->left, &size_in_bytes);
}

static void check_assign(struct expression *expr)
{
	struct symbol *type;
	char *name;

	if (expr->op != SPECIAL_ADD_ASSIGN && expr->op != SPECIAL_SUB_ASSIGN)
		return;

	type = get_pointer_type(expr->left);
	if (!type)
		return;
	if (type_bits(type) == 8 || type_bits(type) == -1)
		return;
	if (!is_size_in_bytes(expr->right))
		return;
	name = expr_to_var(expr->left);
	sm_warning("potential pointer math issue ('%s' is a %d bit pointer)",
	       name, type_bits(type));
	free_string(name);
}

void check_pointer_math(int id)
{
	my_id = id;
	add_hook(&match_binop, BINOP_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&check_assign, ASSIGNMENT_HOOK);
	add_modification_hook(my_id, &set_undefined);
}

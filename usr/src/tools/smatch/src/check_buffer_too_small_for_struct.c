/*
 * Copyright (C) 2014 Oracle.
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

STATE(too_small);

static void match_assign(struct expression *expr)
{
	struct symbol *left_type, *right_type;
	struct expression *size_expr;
	sval_t min_size;

	left_type = get_type(expr->left);
	if (!left_type || left_type->type != SYM_PTR)
		return;
	left_type = get_real_base_type(left_type);
	if (!left_type || left_type->type != SYM_STRUCT)
		return;

	right_type = get_type(expr->right);
	if (!right_type || right_type->type != SYM_PTR)
		return;
	right_type = get_real_base_type(right_type);
	if (!right_type)
		return;
	if (right_type != &void_ctype && type_bits(right_type) != 8)
		return;

	size_expr = get_size_variable(expr->right);
	if (!size_expr)
		return;

	get_absolute_min(size_expr, &min_size);
	if (min_size.value >= type_bytes(left_type))
		return;

	set_state_expr(my_id, expr->left, &too_small);
}

static void match_dereferences(struct expression *expr)
{
	struct symbol *left_type;
	struct expression *right;
	struct smatch_state *state;
	char *name;
	struct expression *size_expr;
	sval_t min_size;

	if (expr->type != EXPR_PREOP)
		return;

	expr = strip_expr(expr->unop);
	state = get_state_expr(my_id, expr);
	if (state != &too_small)
		return;

	left_type = get_type(expr);
	if (!left_type || left_type->type != SYM_PTR)
		return;
	left_type = get_real_base_type(left_type);
	if (!left_type || left_type->type != SYM_STRUCT)
		return;

	right = get_assigned_expr(expr);
	size_expr = get_size_variable(right);
	if (!size_expr)
		return;

	get_absolute_min(size_expr, &min_size);
	if (min_size.value >= type_bytes(left_type))
		return;

	name = expr_to_str(right);
	sm_warning("is '%s' large enough for 'struct %s'? %s", name, left_type->ident ? left_type->ident->name : "<anon>", sval_to_str(min_size));
	free_string(name);
	set_state_expr(my_id, expr, &undefined);
}

void check_buffer_too_small_for_struct(int id)
{
	my_id = id;

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_dereferences, DEREF_HOOK);
}

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
extern int check_assigned_expr_id;

static int is_probably_ok(struct expression *expr)
{
	expr = strip_expr(expr);

	if (expr->type == EXPR_BINOP)
		return 1;
	if (expr->type == EXPR_SIZEOF)
		return 1;

	return 0;
}

static void verify_size_expr(struct expression *expr)
{
	if (expr->type != EXPR_BINOP)
		return;
	if (expr->op != '-')
		return;
	if (is_probably_ok(expr->left))
		return;
	if (is_probably_ok(expr->right))
		return;
	sm_warning("consider using resource_size() here");
}

static void handle_assigned_expr(struct expression *expr)
{
	struct smatch_state *state;

	state = get_state_expr(check_assigned_expr_id, expr);
	if (!state || !state->data)
		return;
	expr = (struct expression *)state->data;
	verify_size_expr(expr);
}

static void match_resource(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	arg_expr = strip_expr(arg_expr);
	if (!arg_expr)
		return;

	if (arg_expr->type == EXPR_SYMBOL) {
		handle_assigned_expr(arg_expr);
		return;
	}
	verify_size_expr(arg_expr);
}

void check_resource_size(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	add_function_hook("ioremap_nocache", &match_resource, (void *)1);
	add_function_hook("ioremap", &match_resource, (void *)1);
	add_function_hook("__request_region", &match_resource, (void *)2);
	add_function_hook("__release_region", &match_resource, (void *)2);
	add_function_hook("__devm_request_region", &match_resource, (void *)3);
	add_function_hook("__devm_release_region", &match_resource, (void *)3);
}

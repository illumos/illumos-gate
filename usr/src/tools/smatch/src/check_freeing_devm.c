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

STATE(devm);

static int my_id;

static void match_assign(const char *fn, struct expression *expr, void *unused)
{
	set_state_expr(my_id, expr->left, &devm);
}

static void match_free_func(const char *fn, struct expression *expr, void *_arg)
{
	struct expression *arg_expr;
	int arg = PTR_INT(_arg);
	char *name;

	arg_expr = get_argument_from_call_expr(expr->args, arg);
	if (!get_state_expr(my_id, arg_expr))
		return;
	name = expr_to_str(arg_expr);
	sm_warning("passing devm_ allocated variable to kfree. '%s'", name);
	free_string(name);
}

static void register_funcs_from_file(void)
{
	struct token *token;
	const char *func;
	int arg;

	token = get_tokens_file("kernel.frees_argument");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		arg = atoi(token->number);
		add_function_hook(func, &match_free_func, INT_PTR(arg));
		token = token->next;
	}
	clear_token_alloc();
}

void check_freeing_devm(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;

	add_function_assign_hook("devm_kmalloc", &match_assign, NULL);
	add_function_assign_hook("devm_kzalloc", &match_assign, NULL);
	add_function_assign_hook("devm_kcalloc", &match_assign, NULL);
	add_function_assign_hook("devm_kmalloc_array", &match_assign, NULL);


	add_function_hook("kfree", &match_free_func, INT_PTR(0));
	add_function_hook("krealloc", &match_free_func, INT_PTR(0));
	register_funcs_from_file();
}

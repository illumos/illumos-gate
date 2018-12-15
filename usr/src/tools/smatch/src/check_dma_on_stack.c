/*
 * Copyright (C) 2009 Dan Carpenter.
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

static void match_dma_func(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg;
	struct symbol *sym;
	char *name;

	arg = get_argument_from_call_expr(expr->args, PTR_INT(param));
	arg = strip_expr(arg);
	if (!arg)
		return;
	if (arg->type == EXPR_PREOP && arg->op == '&') {
		if (arg->unop->type != EXPR_SYMBOL)
			return;
		name = expr_to_str(arg);
		sm_error("doing dma on the stack (%s)", name);
		free_string(name);
		return;
	}
	if (arg->type != EXPR_SYMBOL)
		return;
	sym = get_type(arg);
	if (!sym || sym->type != SYM_ARRAY)
		return;
	if (get_param_num(arg) >= 0)
		return;
	name = expr_to_var(arg);
	sm_error("doing dma on the stack (%s)", name);
	free_string(name);
}

static void register_funcs_from_file(void)
{
	struct token *token;
	const char *func;
	int arg;

	token = get_tokens_file("kernel.dma_funcs");
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
		add_function_hook(func, &match_dma_func, INT_PTR(arg));
		token = token->next;
	}
	clear_token_alloc();
}

void check_dma_on_stack(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;
	register_funcs_from_file();
}

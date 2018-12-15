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

static void match_parameter(const char *fn, struct expression *expr, void *_param)
{
	int param = PTR_INT(_param);
	struct expression *arg;
	char *name;

	arg = get_argument_from_call_expr(expr->args, param);
	arg = strip_expr(arg);
	if (!arg)
		return;
	if (arg->type != EXPR_COMPARE)
		return;

	name = expr_to_str_sym(arg, NULL);
	sm_warning("expected a buffer size but got a comparison '%s'", name);
	free_string(name);
}

static void register_funcs_from_file(void)
{
	char name[256];
	struct token *token;
	const char *func;
	char prev_func[256];
	int size;

	memset(prev_func, 0, sizeof(prev_func));
	snprintf(name, 256, "%s.sizeof_param", option_project_str);
	name[255] = '\0';
	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			break;
		func = show_ident(token->ident);

		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			break;
		size = atoi(token->number);

		token = token->next;
		if (token_type(token) == TOKEN_SPECIAL) {
			if (token->special != '-')
				break;
			token = token->next;
		}
		if (token_type(token) != TOKEN_NUMBER)
			break;
		/* we don't care which argument hold the buf pointer */
		token = token->next;

		if (strcmp(func, prev_func) == 0)
			continue;
		strncpy(prev_func, func, 255);

		add_function_hook(func, &match_parameter, INT_PTR(size));

	}
	if (token_type(token) != TOKEN_STREAMEND)
		sm_perror("problem parsing '%s'", name);
	clear_token_alloc();
}

void check_wrong_size_arg(int id)
{
	my_id = id;
	register_funcs_from_file();
}

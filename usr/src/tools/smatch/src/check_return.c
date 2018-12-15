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
#include "smatch_slist.h"

static int my_id;

static void must_check(const char *fn, struct expression *expr, void *data)
{
	struct statement *stmt;

	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);
	if (stmt->type == STMT_EXPRESSION && stmt->expression == expr)
		sm_warning("unchecked '%s'", fn);
}

static void register_must_check_funcs(void)
{
	struct token *token;
	const char *func;
	static char name[256];


	snprintf(name, 256, "%s.must_check_funcs", option_project_str);
	name[255] = '\0';
	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		add_function_hook(func, &must_check, NULL);
		token = token->next;
	}
	clear_token_alloc();
}

void check_return(int id)
{
	my_id = id;
	register_must_check_funcs();
}

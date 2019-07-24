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
#include "smatch_slist.h"

STATE(ignore);
static struct stree *ignored;
static struct stree *ignored_from_file;

void add_ignore(int owner, const char *name, struct symbol *sym)
{
	set_state_stree(&ignored, owner, name, sym, &ignore);
}

int is_ignored(int owner, const char *name, struct symbol *sym)
{
	return !!get_state_stree(ignored, owner, name, sym);
}

void add_ignore_expr(int owner, struct expression *expr)
{
	struct symbol *sym;
	char *name;

	name = expr_to_str_sym(expr, &sym);
	if (!name || !sym)
		return;
	add_ignore(owner, name, sym);
	free_string(name);
}

int is_ignored_expr(int owner, struct expression *expr)
{
	struct symbol *sym;
	char *name;
	int ret;

	name = expr_to_str_sym(expr, &sym);
	if (!name && !sym)
		return 0;
	ret = is_ignored(owner, name, sym);
	free_string(name);
	if (ret)
		return true;

	name = get_macro_name(expr->pos);
	if (name && get_state_stree(ignored_from_file, owner, name, NULL))
		return true;

	name = get_function();
	if (name && get_state_stree(ignored_from_file, owner, name, NULL))
		return true;

	return false;
}

static void clear_ignores(void)
{
	if (__inline_fn)
		return;
	free_stree(&ignored);
}

static void load_ignores(void)
{
	struct token *token;
	const char *name, *str;
	int owner;
	char buf[64];

	snprintf(buf, sizeof(buf), "%s.ignored_warnings", option_project_str);
	token = get_tokens_file(buf);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			break;
		name = show_ident(token->ident);
		token = token->next;
		owner = id_from_name(name);

		if (token_type(token) != TOKEN_IDENT)
			break;
		str = show_ident(token->ident);
		token = token->next;

		set_state_stree_perm(&ignored_from_file, owner, str, NULL, &ignore);
	}
	clear_token_alloc();
}

void register_smatch_ignore(int id)
{
	add_hook(&clear_ignores, AFTER_FUNC_HOOK);
	load_ignores();
}

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
	return ret;
}

static void clear_ignores(void)
{
	if (__inline_fn)
		return;
	free_stree(&ignored);
}

void register_smatch_ignore(int id)
{
	add_hook(&clear_ignores, AFTER_FUNC_HOOK);
}

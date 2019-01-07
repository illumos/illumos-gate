/*
 * Copyright (C) 2016 Oracle.
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

static struct statement_list *stmt_list;

static int end_of_function(struct statement *stmt)
{
	struct symbol *fn = get_base_type(cur_func_sym);

	/* err on the conservative side of things */
	if (!fn)
		return 1;
	if (stmt == fn->stmt || stmt == fn->inline_stmt)
		return 1;
	return 0;
}

/*
 * We're wasting a lot of time worrying about out of scope variables.
 * When we come to the end of a scope then just delete them all the out of
 * scope states.
 */
static void match_end_of_block(struct statement *stmt)
{
	struct statement *tmp;
	struct symbol *sym;

	if (end_of_function(stmt))
		return;

	FOR_EACH_PTR(stmt->stmts, tmp) {
		if (tmp->type != STMT_DECLARATION)
			return;

		FOR_EACH_PTR(tmp->declaration, sym) {
			if (!sym->ident)
				continue;
			__delete_all_states_sym(sym);
		} END_FOR_EACH_PTR(sym);
	} END_FOR_EACH_PTR(tmp);
}

static int is_outer_stmt(struct statement *stmt)
{
	struct symbol *fn;

	if (!cur_func_sym)
		return 0;
	fn = get_base_type(cur_func_sym);
	if (!fn)
		return 0;
	/*
	 * There are times when ->parent is not set but it's set for
	 * the outer statement so ignoring NULLs works as a work-around.
	 */
	if (!stmt->parent)
		return 0;
	if (stmt->parent == fn->stmt ||
	    stmt->parent == fn->inline_stmt)
		return 1;
	return 0;
}

static void match_stmt(struct statement *stmt)
{
	struct statement *tmp;

	if (__inline_fn)
		return;

	if (stmt->type == STMT_COMPOUND)
		add_ptr_list(&stmt_list, stmt);

	if (!is_outer_stmt(stmt))
		return;

	FOR_EACH_PTR(stmt_list, tmp) {
		match_end_of_block(tmp);
	} END_FOR_EACH_PTR(tmp);
	free_ptr_list(&stmt_list);
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	free_ptr_list(&stmt_list);
}

void register_scope(int id)
{
	add_hook(&match_stmt, STMT_HOOK_AFTER);
	add_hook(&match_end_func, AFTER_FUNC_HOOK);
}

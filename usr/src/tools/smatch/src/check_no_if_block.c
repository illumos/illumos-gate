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

static void match_if_stmt(struct statement *stmt)
{
	if (__inline_fn)
		return;
	if (stmt->type != STMT_IF)
		return;
	if (stmt->if_true->type == STMT_COMPOUND)
		return;
	if (get_macro_name(stmt->pos))
		return;
	if (stmt->pos.pos != stmt->if_true->pos.pos)
		return;
	sm_warning("if statement not indented");
}

static void match_for_stmt(struct statement *stmt)
{
	if (__inline_fn)
		return;
	if (stmt->type != STMT_ITERATOR)
		return;
	if (stmt->iterator_statement->type == STMT_COMPOUND)
		return;
	if (get_macro_name(stmt->pos))
		return;
	if (stmt->pos.pos != stmt->iterator_statement->pos.pos)
		return;
	sm_warning("for statement not indented");
}

void check_no_if_block(int id)
{
	my_id = id;

	add_hook(&match_if_stmt, STMT_HOOK);
	add_hook(&match_for_stmt, STMT_HOOK);
}

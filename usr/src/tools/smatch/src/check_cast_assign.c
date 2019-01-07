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
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

static struct symbol *get_cast_type(struct expression *expr)
{
	if (!expr || expr->type != EXPR_PREOP || expr->op != '*')
		return NULL;
	expr = strip_parens(expr->unop);
	if (expr->type != EXPR_CAST)
		return NULL;
	return get_pointer_type(expr);
}

static void match_overflow(struct expression *expr)
{
	struct expression *ptr;
	struct symbol *type;
	int cast_size;
	int data_size;

	type = get_cast_type(expr->left);
	if (!type)
		return;
	cast_size = type_bytes(type);

	ptr = strip_expr(expr->left->unop);
	data_size = get_array_size_bytes_min(ptr);
	if (data_size <= 0)
		return;
	if (data_size >= cast_size)
		return;
	sm_warning("potential memory corrupting cast %d vs %d bytes",
	       cast_size, data_size);
}

void check_cast_assign(int id)
{
	my_id = id;
	add_hook(&match_overflow, ASSIGNMENT_HOOK);
}


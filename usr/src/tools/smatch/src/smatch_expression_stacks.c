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
#include "smatch_expression_stacks.h"

void push_expression(struct expression_list **estack, struct expression *expr)
{
	add_ptr_list(estack, expr);
}

struct expression *pop_expression(struct expression_list **estack)
{
	struct expression *expr;

	expr = last_ptr_list((struct ptr_list *)*estack);
	delete_ptr_list_last((struct ptr_list **)estack);
	return expr;
}

struct expression *top_expression(struct expression_list *estack)
{
	struct expression *expr;

	expr = last_ptr_list((struct ptr_list *)estack);
	return expr;
}

void free_expression_stack(struct expression_list **estack)
{
	__free_ptr_list((struct ptr_list **)estack);
}

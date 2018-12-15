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

static void db_returns_buf_size(struct expression *expr, int param, char *unused, char *math)
{
	struct expression *call;
	struct symbol *left_type, *right_type;
	int bytes;
	sval_t sval;

	if (expr->type != EXPR_ASSIGNMENT)
		return;
	right_type = get_pointer_type(expr->right);
	if (!right_type || type_bits(right_type) != -1)
		return;

	call = strip_expr(expr->right);
	left_type = get_pointer_type(expr->left);

	if (!parse_call_math(call, math, &sval) || sval.value == 0)
		return;
	if (!left_type)
		return;
	bytes = type_bytes(left_type);
	if (bytes <= 0)
		return;
	if (sval.uvalue >= bytes)
		return;
	sm_error("not allocating enough data %d vs %s", bytes, sval_to_str(sval));
}

void check_allocating_enough_data(int id)
{
	select_return_states_hook(BUF_SIZE, &db_returns_buf_size);
}

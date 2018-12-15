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

/*
 * The situation here is that we often need to fake an assignment but we don't
 * know anything about the right hand side of the assignment.  We use a fake
 * function call of &llong_ctype.  The reason for using a function call instead
 * of a value is so we don't start storing the equivalence.
 *
 */

#include "smatch.h"

struct ident fake_assign = {
	.len = sizeof("fake assign"),
	.name = "fake assign",
};

static struct symbol fake_fn_symbol = {
	.type = SYM_FN,
	.ident = &fake_assign,
};

static struct symbol fake_node_symbol = {
	.type = SYM_NODE,
	.ident = &fake_assign,
};

static struct expression fake_fn_expr = {
	.type = EXPR_SYMBOL,
	.ctype = &llong_ctype,
};

static struct expression fake_call = {
	.type = EXPR_CALL,
	.ctype = &llong_ctype,
};

static void __attribute__((constructor)) initialize_local_variables(void)
{
	fake_fn_symbol.ctype.base_type = &llong_ctype;
	fake_node_symbol.ctype.base_type = &fake_fn_symbol;
	fake_fn_expr.symbol = &fake_node_symbol;
	fake_fn_expr.symbol_name = &fake_assign;
	fake_call.fn = &fake_fn_expr;
}

struct expression *unknown_value_expression(struct expression *expr)
{
	fake_fn_expr.parent = 0;
	fake_call.parent = 0;
	return &fake_call;
}

int is_fake_call(struct expression *expr)
{
	return expr == &fake_call;
}

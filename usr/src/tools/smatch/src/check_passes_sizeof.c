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

#define NOBUF -2

static int my_id;

static struct expression *get_returned_expr(struct expression *expr)
{
	struct statement *stmt;

	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);
	if (!stmt || stmt->type != STMT_EXPRESSION || !stmt->expression)
		return NULL;
	if (stmt->expression->type != EXPR_ASSIGNMENT)
		return NULL;
	if (stmt->expression->right != expr)
		return NULL;
	return stmt->expression->left;
}

static struct expression *remove_dereference(struct expression *expr)
{
	if (!expr || expr->type != EXPR_PREOP || expr->op != '*')
		return expr;
	expr = expr->unop;
	if (!expr || expr->type != EXPR_PREOP || expr->op != '*')
		return expr;
	return expr->unop;
}

static int get_buf_number(struct expression *call, struct expression *size_arg)
{
	struct expression *arg;
	int idx = -1;

	size_arg = strip_expr(size_arg->cast_expression);
	size_arg = remove_dereference(size_arg);

	arg = get_returned_expr(call);
	if (arg && expr_equiv(arg, size_arg))
		return idx;

	FOR_EACH_PTR(call->args, arg) {
		idx++;
		if (expr_equiv(arg, size_arg))
			return idx;
	} END_FOR_EACH_PTR(arg);

	return NOBUF;
}

static void match_call(struct expression *call)
{
	struct expression *arg;
	char *name;
	int buf_nr;
	int i = -1;

	if (call->fn->type != EXPR_SYMBOL)
		return;

	name = expr_to_var(call->fn);
	FOR_EACH_PTR(call->args, arg) {
		i++;
		if (arg->type != EXPR_SIZEOF)
			continue;
		buf_nr = get_buf_number(call, arg);
		if (buf_nr == NOBUF)
			sm_msg("info: sizeof_param '%s' %d", name, i);
		else
			sm_msg("info: sizeof_param '%s' %d %d", name, i, buf_nr);
	} END_FOR_EACH_PTR(arg);
	free_string(name);
}

void check_passes_sizeof(int id)
{
	if (!option_info)
		return;

	my_id = id;
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}

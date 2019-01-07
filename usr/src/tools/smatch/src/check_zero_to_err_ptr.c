/*
 * Copyright (C) 2013 Oracle.
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

static int is_comparison_call(struct expression *expr)
{
	expr = expr_get_parent_expr(expr);
	if (!expr || expr->type != EXPR_COMPARE)
		return 0;
	if (expr->op != SPECIAL_EQUAL && expr->op != SPECIAL_NOTEQUAL)
		return 0;
	return 1;
}

static int next_line_is_if(struct expression *expr)
{
	struct expression *next;

	if (!__next_stmt || __next_stmt->type != STMT_IF)
		return 0;

	next = strip_expr(__next_stmt->if_conditional);
	while (next->type == EXPR_PREOP && next->op == '!')
		next = strip_expr(next->unop);
	if (expr_equiv(expr, next))
		return 1;
	return 0;
}

static int next_line_checks_IS_ERR(struct expression *call, struct expression *arg)
{
	struct expression *next;
	struct expression *tmp;

	tmp = expr_get_parent_expr(call);
	if (tmp && tmp->type == EXPR_ASSIGNMENT) {
		if (next_line_checks_IS_ERR(NULL, tmp->left))
			return 1;
	}

	if (!__next_stmt || __next_stmt->type != STMT_IF)
		return 0;

	next = strip_expr(__next_stmt->if_conditional);
	while (next->type == EXPR_PREOP && next->op == '!')
		next = strip_expr(next->unop);
	if (!next || next->type != EXPR_CALL)
		return 0;
	if (next->fn->type != EXPR_SYMBOL || !next->fn->symbol ||
	    !next->fn->symbol->ident ||
	    (strcmp(next->fn->symbol->ident->name, "IS_ERR") != 0 &&
	     strcmp(next->fn->symbol->ident->name, "IS_ERR_OR_NULL") != 0))
		return 0;
	next = get_argument_from_call_expr(next->args, 0);
	return expr_equiv(next, arg);
}

static int is_valid_ptr(sval_t sval)
{
	if (sval.type == &int_ctype &&
	    (sval.value == INT_MIN || sval.value == INT_MAX))
		return 0;

	if (sval_cmp(valid_ptr_min_sval, sval) <= 0 &&
	    sval_cmp(valid_ptr_max_sval, sval) >= 0)
		return 1;
	return 0;
}

static void match_err_ptr(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg_expr;
	struct sm_state *sm, *tmp;
	sval_t sval;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(SMATCH_EXTRA, arg_expr);
	if (!sm)
		return;

	if (is_comparison_call(expr))
		return;

	if (next_line_checks_IS_ERR(expr, arg_expr))
		return;
	if (strcmp(fn, "ERR_PTR") == 0 &&
	    next_line_is_if(arg_expr))
		return;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!estate_rl(tmp->state))
			continue;
		if (is_valid_ptr(estate_min(tmp->state)) &&
		    is_valid_ptr(estate_max(tmp->state))) {
			sm_warning("passing a valid pointer to '%s'", fn);
			return;
		}
		if (!rl_to_sval(estate_rl(tmp->state), &sval))
			continue;
		if (sval.value != 0)
			continue;
		sm_warning("passing zero to '%s'", fn);
		return;
	} END_FOR_EACH_PTR(tmp);
}

void check_zero_to_err_ptr(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_hook("ERR_PTR", &match_err_ptr, NULL);
	add_function_hook("ERR_CAST", &match_err_ptr, NULL);
	add_function_hook("PTR_ERR", &match_err_ptr, NULL);
}

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

/*
 * This check is supposed to find bugs in reference counting using dev_hold()
 * and dev_put().
 *
 * When a device is first held, if an error happens later in the function
 * it needs to be released on all the error paths.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(held);
STATE(released);

static void match_dev_hold(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	set_state_expr(my_id, arg_expr, &held);
}

static void match_dev_put(const char *fn, struct expression *expr, void *data)
{
	struct expression *arg_expr;

	arg_expr = get_argument_from_call_expr(expr->args, 0);
	set_state_expr(my_id, arg_expr, &released);
}

static void match_returns_held(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	if (assign_expr)
		set_state_expr(my_id, assign_expr->left, &held);
}

static void match_returns_null(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	if (assign_expr)
		set_state_expr(my_id, assign_expr->left, &released);
}

static void check_for_held(void)
{
	struct stree *stree;
	struct sm_state *tmp;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, tmp) {
		if (slist_has_state(tmp->possible, &held)) {
			sm_warning("'%s' held on error path.",
				tmp->name);
		}
	} END_FOR_EACH_SM(tmp);
}

static void print_returns_held(struct expression *expr)
{
	struct sm_state *sm;

	if (!option_info)
		return;
	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;
	if (slist_has_state(sm->possible, &held))
		sm_info("returned dev is held.");
}

static void match_return(struct expression *ret_value)
{
	print_returns_held(ret_value);
	if (!is_error_return(ret_value))
		return;
	check_for_held();
}

static void register_returns_held_funcs(void)
{
	struct token *token;
	const char *func;

	token = get_tokens_file("kernel.returns_held_funcs");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		return_implies_state_sval(func, valid_ptr_min_sval, valid_ptr_max_sval,
				     &match_returns_held, NULL);
		return_implies_state(func, 0, 0, &match_returns_null,
					 NULL);
		token = token->next;
	}
	clear_token_alloc();
}

void check_held_dev(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_hook("dev_hold", &match_dev_hold, NULL);
	add_function_hook("dev_put", &match_dev_put, NULL);
	register_returns_held_funcs();
	add_hook(&match_return, RETURN_HOOK);
}

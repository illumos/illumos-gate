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

/*
 * This tries to find places which should probably return -EFAULT
 * but return the number of bytes to copy instead.
 */

#include <string.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(remaining);
STATE(ok);

static void ok_to_use(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state != &ok)
		set_state(my_id, sm->name, sm->sym, &ok);
}

static void match_copy(const char *fn, struct expression *expr, void *unused)
{
	if (expr->op == SPECIAL_SUB_ASSIGN)
		return;
	set_state_expr(my_id, expr->left, &remaining);
}

static void match_condition(struct expression *expr)
{
	if (!get_state_expr(my_id, expr))
		return;
	/* If the variable is zero that's ok */
	set_true_false_states_expr(my_id, expr, NULL, &ok);
}

/*
 * This function is biased in favour of print out errors.
 * The heuristic to print is:
 *    If we have a potentially positive return from copy_to_user
 *    and there is a possibility that we return negative as well
 *    then complain.
 */
static void match_return_var(struct expression *ret_value)
{
	struct smatch_state *state;
	struct sm_state *sm;
	sval_t min;

	sm = get_sm_state_expr(my_id, ret_value);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &remaining))
		return;
	state = get_state_expr(SMATCH_EXTRA, ret_value);
	if (!state)
		return;
	if (!get_absolute_min(ret_value, &min))
		return;
	if (min.value == 0)
		return;
	sm_warning("maybe return -EFAULT instead of the bytes remaining?");
}

static void match_return_call(struct expression *ret_value)
{
	struct expression *fn;
	struct range_list *rl;
	const char *fn_name;
	char *cur_func;

	if (!ret_value || ret_value->type != EXPR_CALL)
		return;
	cur_func = get_function();
	if (!cur_func)
		return;
	if (strstr(cur_func, "_to_user") ||
	    strstr(cur_func, "_from_user"))
		return;

	fn = strip_expr(ret_value->fn);
	if (fn->type != EXPR_SYMBOL)
		return;
	fn_name = fn->symbol_name->name;
	if (strcmp(fn_name, "copy_to_user") != 0 &&
	    strcmp(fn_name, "__copy_to_user") != 0 &&
	    strcmp(fn_name, "copy_from_user") != 0 &&
	    strcmp(fn_name, "__copy_from_user"))
		return;

	rl = db_return_vals_from_str(get_function());
	if (!rl)
		return;

	if (!sval_is_negative(rl_min(rl)))
		return;
	sm_warning("maybe return -EFAULT instead of the bytes remaining?");
}

void check_return_efault(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_assign_hook("copy_to_user", &match_copy, NULL);
	add_function_assign_hook("__copy_to_user", &match_copy, NULL);
	add_function_assign_hook("copy_from_user", &match_copy, NULL);
	add_function_assign_hook("__copy_from_user", &match_copy, NULL);
	add_function_assign_hook("clear_user", &match_copy, NULL);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_return_var, RETURN_HOOK);
	add_hook(&match_return_call, RETURN_HOOK);
	add_modification_hook(my_id, &ok_to_use);
}

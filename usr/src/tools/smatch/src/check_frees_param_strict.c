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
 * This file is sort of like check_dereferences_param.c.  In theory the one
 * difference should be that the param is NULL it should still be counted as a
 * free.  But for now I don't handle that case.
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(freed);
STATE(ignore);

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	if (sm->state != &freed)
		return &undefined;
	if (parent_is_null_var_sym(sm->name, sm->sym))
		return &freed;
	return &undefined;
}

static void set_ignore(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &ignore);
}

static int counter_was_inced(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	char buf[256];
	int ret = 0;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	snprintf(buf, sizeof(buf), "%s->users.counter", name);
	ret = was_inced(buf, sym);
free:
	free_string(name);
	return ret;
}

static void match_free(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg, *tmp;
	int cnt = 0;

	arg = get_argument_from_call_expr(expr->args, PTR_INT(param));
	if (!arg)
		return;
	while ((tmp = get_assigned_expr(arg))) {
		arg = strip_expr(tmp);
		if (cnt++ > 5)
			break;
	}

	if (get_param_num(arg) < 0)
		return;
	if (param_was_set(arg))
		return;
	if (strcmp(fn, "kfree_skb") == 0 && counter_was_inced(arg))
		return;

	set_state_expr(my_id, arg, &freed);
}

static void set_param_freed(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;
	if (get_param_num_from_sym(sym) < 0)
		goto free;

	if (param_was_set_var_sym(name, sym))
		goto free;

	set_state(my_id, name, sym, &freed);
free:
	free_string(name);
}

static void param_freed_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	int param;
	const char *param_name;

	if (on_atomic_dec_path())
		return;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state != &freed)
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;

		sql_insert_return_states(return_id, return_ranges, PARAM_FREED,
					 param, param_name, "");
	} END_FOR_EACH_SM(sm);
}

void check_frees_param_strict(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	add_function_hook("kfree", &match_free, INT_PTR(0));
	add_function_hook("kmem_cache_free", &match_free, INT_PTR(1));
	add_function_hook("kfree_skb", &match_free, INT_PTR(0));
	add_function_hook("kfree_skbmem", &match_free, INT_PTR(0));
	add_function_hook("dma_pool_free", &match_free, INT_PTR(1));
	add_function_hook("spi_unregister_controller", &match_free, INT_PTR(0));

	select_return_states_hook(PARAM_FREED, &set_param_freed);
	add_modification_hook(my_id, &set_ignore);
	add_split_return_callback(&param_freed_info);

	add_unmatched_state_hook(my_id, &unmatched_state);
}

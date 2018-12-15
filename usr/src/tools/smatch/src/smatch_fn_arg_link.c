/*
 * Copyright (C) 2016 Oracle.
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
 * What we're trying to do here is record links between function pointers and
 * function data.  If you have foo->function(foo->data); that's very easy.  But
 * the problem is maybe when you pass the function and the data as parameters.
 *
 */

#include "smatch.h"
#include <ctype.h>

static int my_id;

static void save_in_fn_ptr_data_link_table(struct expression *fn, struct expression *arg)
{
	struct symbol *fn_sym, *arg_sym;
	struct symbol *type;
	char *fn_name, *arg_name;
	int sym_len;
	char fn_buf[128];
	char arg_buf[128];

	fn_name = expr_to_var_sym(fn, &fn_sym);
	arg_name = expr_to_var_sym(arg, &arg_sym);
	if (!fn_sym || !fn_sym->ident || !arg_sym || !fn_name || !arg_name)
		goto free;
	if (fn_sym != arg_sym)
		goto free;

	sym_len = fn_sym->ident->len;

	/* This is ignoring
	 * net/mac80211/driver-ops.h:482 drv_sta_remove() FN: local->ops->sta_remove ARG: &local->hw
	 * but ideally the restriction can be removed later.
	 */
	if (strncmp(fn_name, arg_name, sym_len) != 0)
		goto free;

	type = get_real_base_type(fn_sym);
	if (!type)
		goto free;
	if (type->type != SYM_PTR)
		goto free;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_STRUCT || !type->ident)
		goto free;

	snprintf(fn_buf, sizeof(fn_buf), "(struct %s)%s", type->ident->name,
		 fn_name + sym_len);

	snprintf(arg_buf, sizeof(arg_buf), "(struct %s)%s", type->ident->name,
		 arg_name + sym_len);

	sql_insert_fn_ptr_data_link(fn_buf, arg_buf);
free:
	free_string(arg_name);
	free_string(fn_name);
}

static int print_calls_parameter(struct expression *call)
{
	struct expression *arg;
	int fn_param, arg_param;
	char buf[32];

	fn_param = get_param_num(call->fn);
	if (fn_param < 0)
		return 0;

	arg = get_argument_from_call_expr(call->args, 0);
	if (!arg)
		return 0;

	arg_param = get_param_num(arg);
	if (arg_param < 0)
		return 0;

	snprintf(buf, sizeof(buf), "%d", arg_param);
	sql_insert_return_implies(FN_ARG_LINK, fn_param, "$", buf);
	return 0;
}

static int print_call_is_linked(struct expression *call)
{
	struct expression *fn, *tmp;
	struct expression *arg;
	struct symbol *fn_sym;
	struct symbol *arg_sym = NULL;
	int i;

	fn = strip_expr(call->fn);
	tmp = get_assigned_expr(fn);
	if (tmp)
		fn = tmp;
	if (fn->type != EXPR_DEREF || !fn->member)
		return 0;

	fn_sym = expr_to_sym(fn);
	if (!fn_sym)
		return 0;

	i = -1;
	FOR_EACH_PTR(call->args, arg) {
		i++;
		tmp = get_assigned_expr(arg);
		if (tmp)
			arg = tmp;
		arg_sym = expr_to_sym(arg);
		if (arg_sym == fn_sym) {
			save_in_fn_ptr_data_link_table(fn, arg);
			return 1;
		}
	} END_FOR_EACH_PTR(arg);

	return 0;
}

static int is_recursive_call(struct expression *call)
{
	if (call->fn->type != EXPR_SYMBOL)
		return 0;
	if (call->fn->symbol == cur_func_sym)
		return 1;
	return 0;
}

static void check_passes_fn_and_data(struct expression *call, struct expression *fn, char *key, char *value)
{
	struct expression *arg;
	struct expression *tmp;
	struct symbol *fn_sym, *arg_sym;
	struct symbol *type;
	int data_nr;
	int fn_param, arg_param;

	if (is_recursive_call(call))
		return;

	type = get_type(fn);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_FN)
		return;
	tmp = get_assigned_expr(fn);
	if (tmp)
		fn = tmp;

	if (!isdigit(value[0]))
		return;
	data_nr = atoi(value);
	arg = get_argument_from_call_expr(call->args, data_nr);
	if (!arg)
		return;
	tmp = get_assigned_expr(arg);
	if (tmp)
		arg = tmp;

	fn_param = get_param_num(fn);
	arg_param = get_param_num(arg);
	if (fn_param >= 0 && arg_param >= 0) {
		char buf[32];

		snprintf(buf, sizeof(buf), "%d", arg_param);
		sql_insert_return_implies(FN_ARG_LINK, fn_param, "$", buf);
		return;
	}

	fn_sym = expr_to_sym(fn);
	if (!fn_sym)
		return;
	arg_sym = expr_to_sym(arg);
	if (arg_sym != fn_sym)
		return;
	save_in_fn_ptr_data_link_table(fn, tmp);
}

static void match_call_info(struct expression *call)
{
	if (print_calls_parameter(call))
		return;
	if (print_call_is_linked(call))
		return;
}

void register_fn_arg_link(int id)
{
	my_id = id;

	if (!option_info)
		return;

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	select_return_implies_hook(FN_ARG_LINK, &check_passes_fn_and_data);
}


/*
 * Copyright (C) 2017 Oracle.
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
 * Say you have assign a function to a function pointer and you assign a
 * pointer to the data argument then we want to record some information about
 * the argument.  Right now what I mainly want to record is the type of it, I
 * guess.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"
#include <ctype.h>

static int my_id;

static int assigns_parameters(struct expression *fn, struct expression *arg)
{
	int fn_param, arg_param;
	char buf[32];

	fn_param = get_param_num(fn);
	if (fn_param < 0)
		return 0;

	arg_param = get_param_num(arg);
	if (arg_param < 0)
		return 0;

	snprintf(buf, sizeof(buf), "%d", arg_param);
	sql_insert_return_implies(FN_ARG_LINK, fn_param, "$", buf);
	return 1;
}

static void link_function_arg(struct expression *fn, int param, struct expression *arg)
{
	struct symbol *type;

	if (!fn || !arg)
		return;
	if (assigns_parameters(fn, arg))
		return;

	type = get_type(arg);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type)
		return;
	// FIXME: param shouldn't always be 0?
	sql_insert_fn_data_link(fn, PASSES_TYPE, param, "$", type_to_str(type));
}

char *next_param_name;
struct symbol *next_param_sym;
struct expression *next_fn;
static void match_assign_param(struct expression *expr)
{
	struct symbol *sym;
	char *name;

	if (!next_param_name)
		return;

	name = expr_to_var_sym(expr->left, &sym);
	if (!name || !sym) {
		free_string(name);
		return;
	}

	if (sym != next_param_sym ||
	    strcmp(name, next_param_name) != 0)
		return;

	link_function_arg(next_fn, 0, strip_expr(expr->right));

	next_param_name = 0;
	next_param_sym = NULL;
	next_fn = NULL;
}

static int get_arg_ptr(void *_arg_ptr, int argc, char **argv, char **azColName)
{
	char **arg_ptr = _arg_ptr;

	*arg_ptr = NULL;
	if (argc != 1)
		return 0;
	*arg_ptr = alloc_string(argv[0]);
	return 0;
}

static char *get_data_member(char *fn_member, struct expression *expr, struct symbol **sym)
{
	struct symbol *tmp_sym;
	char *fn_str;
	char *arg_ptr = NULL;
	char *end_type;
	int len_ptr, len_str;
	char buf[128];

	*sym = NULL;
	run_sql(get_arg_ptr, &arg_ptr,
		"select data from fn_ptr_data_link where fn_ptr = '%s';", fn_member);
	if (!arg_ptr)
		return NULL;
	end_type = strchr(arg_ptr, '>');
	if (!end_type)
		return NULL;
	end_type++;
	fn_str = expr_to_var_sym(expr, &tmp_sym);
	if (!fn_str || !tmp_sym)
		return NULL;
	len_ptr = strlen(fn_member);
	len_str = strlen(fn_str);
	while (len_str > 0 && len_ptr > 0) {
		if (fn_str[len_str - 1] != fn_member[len_ptr - 1])
			break;
		if (fn_str[len_str - 1] == '>')
			break;
		len_str--;
		len_ptr--;
	}

	strncpy(buf, fn_str, sizeof(buf));
	snprintf(buf + len_str, sizeof(buf) - len_str, end_type);
	*sym = tmp_sym;
	return alloc_string(buf);
}

static void match_assign_function(struct expression *expr)
{
	struct expression *right, *arg;
	struct symbol *sym;
	char *data_member;
	struct symbol *type;
	char *member_name;

	right = strip_expr(expr->right);
	if (right->type == EXPR_PREOP && right->op == '&')
		right = strip_expr(right->unop);

	type = get_type(right);
	if (type && type->type == SYM_PTR)
		type = get_real_base_type(type);
	if (!type || type->type != SYM_FN)
		return;

	member_name = get_member_name(expr->left);
	if (!member_name)
		return;

	data_member = get_data_member(member_name, expr->left, &sym);
	if (!data_member || !sym) {
		free_string(data_member);
		data_member = NULL;
	}

	arg = get_assigned_expr_name_sym(data_member, sym);
	if (arg) {
		link_function_arg(right, 0, arg);
	} else {
		next_param_name = data_member;
		next_param_sym = sym;
		next_fn = right;
	}
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
	struct symbol *type;
	int data_nr;

	if (is_recursive_call(call))
		return;

	type = get_type(fn);
	if (!type || type->type != SYM_FN)
		return;

	if (!isdigit(value[0]))
		return;
	data_nr = atoi(value);
	arg = get_argument_from_call_expr(call->args, data_nr);
	if (!arg)
		return;
	link_function_arg(fn, 0, arg);
}

static void match_end_func(struct symbol *sym)
{
	next_param_sym = NULL;
	next_fn = NULL;
}

void register_about_fn_ptr_arg(int id)
{
	my_id = id;

	if (0 && !option_info)
		return;
	add_hook(match_assign_param, ASSIGNMENT_HOOK);
	add_hook(match_assign_function, ASSIGNMENT_HOOK);
	select_return_implies_hook(FN_ARG_LINK, &check_passes_fn_and_data);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

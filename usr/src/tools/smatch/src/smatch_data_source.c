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
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static char *get_source_parameter(struct expression *expr)
{
	struct expression *tmp;
	const char *param_name;
	struct symbol *sym;
	char *name;
	int param;
	char *ret = NULL;
	char buf[32];
	int cnt = 0;
	bool modified = false;

	tmp = expr;
	while ((tmp = get_assigned_expr(tmp))) {
		expr = tmp;
		if (cnt++ > 3)
			break;
	}

	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL)
		return NULL;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	param = get_param_num_from_sym(sym);
	if (param < 0)
		goto free;
	param_name = get_param_name_var_sym(name, sym);
	if (!param_name)
		goto free;
	if (param_was_set_var_sym(name, sym))
		modified = true;

	snprintf(buf, sizeof(buf), "$%d%s%s", param, param_name + 1,
		 modified ? " [m]" : "");
	ret = alloc_string(buf);

free:
	free_string(name);
	return ret;
}

static char *get_source_assignment(struct expression *expr)
{
	struct expression *right;
	char *name;
	char buf[64];
	char *ret;

	right = get_assigned_expr(expr);
	right = strip_expr(right);
	if (!right)
		return NULL;
	if (right->type != EXPR_CALL || right->fn->type != EXPR_SYMBOL)
		return NULL;
	if (is_fake_call(right))
		return NULL;
	name = expr_to_str(right->fn);
	if (!name)
		return NULL;
	snprintf(buf, sizeof(buf), "r %s", name);
	ret = alloc_string(buf);
	free_string(name);
	return ret;
}

static char *get_source_str(struct expression *arg)
{
	char *source;

	source = get_source_parameter(arg);
	if (source)
		return source;
	return get_source_assignment(arg);
}

static void match_caller_info(struct expression *expr)
{
	struct expression *arg;
	char *source;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		source = get_source_str(arg);
		if (!source)
			continue;
		sql_insert_caller_info(expr, DATA_SOURCE, i, "$", source);
		free_string(source);
	} END_FOR_EACH_PTR(arg);
}

void register_data_source(int id)
{
//	if (!option_info)
//		return;
	my_id = id;
	add_hook(&match_caller_info, FUNCTION_CALL_HOOK);
}

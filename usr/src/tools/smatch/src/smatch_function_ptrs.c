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

/*
 * Track how functions are saved as various struct members or passed as
 * parameters.
 *
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

static char *get_from__symbol_get(struct expression *expr)
{
	struct expression *arg;

	/*
	 * typeof(&dib0070_attach) __a =
	 * ((((typeof(&dib0070_attach)) (__symbol_get("dib0070_attach")))) ?:
	 *  (__request_module(true, "symbol:" "dib0070_attach"), (((typeof(&dib0070_attach))(__symbol_get("dib0070_attach"))))));
	 */

	expr = strip_expr(expr);

	if (expr->type != EXPR_CALL)
		return NULL;
	if (!sym_name_is("__symbol_get", expr->fn))
		return NULL;
	arg = get_argument_from_call_expr(expr->args, 0);
	if (!arg || arg->type != EXPR_STRING)
		return NULL;

	return alloc_string(arg->string->data);
}

static char *get_array_ptr(struct expression *expr)
{
	struct expression *array;
	struct symbol *type;
	char *name;
	char buf[256];

	array = get_array_base(expr);

	if (array) {
		name = get_member_name(array);
		if (name)
			return name;
	}

	/* FIXME:  is_array() should probably be is_array_element() */
	type = get_type(expr);
	if (!array && type && type->type == SYM_ARRAY)
		array = expr;
	if (array) {
		name = expr_to_var(array);
		if (!name)
			return NULL;
		snprintf(buf, sizeof(buf), "%s[]", name);
		return alloc_string(buf);
	}

	expr = get_assigned_expr(expr);
	array = get_array_base(expr);
	if (!array)
		return NULL;
	name = expr_to_var(array);
	if (!name)
		return NULL;
	snprintf(buf, sizeof(buf), "%s[]", name);
	free_string(name);
	return alloc_string(buf);
}

static int is_local_symbol(struct symbol *sym)
{
	if (!sym ||
	    !(sym->ctype.modifiers & MOD_TOPLEVEL))
		return 1;
	return 0;
}

static char *ptr_prefix(struct symbol *sym)
{
	static char buf[128];


	if (is_local_symbol(sym))
		snprintf(buf, sizeof(buf), "%s ptr", get_function());
	else if (sym && toplevel(sym->scope))
		snprintf(buf, sizeof(buf), "%s ptr", get_base_file());
	else
		snprintf(buf, sizeof(buf), "ptr");

	return buf;
}

char *get_returned_ptr(struct expression *expr)
{
	struct symbol *type;
	char *name;
	char buf[256];

	if (expr->type != EXPR_CALL)
		return NULL;
	if (!expr->fn || expr->fn->type != EXPR_SYMBOL)
		return NULL;

	type = get_type(expr);
	if (type && type->type == SYM_PTR)
		type = get_real_base_type(type);
	if (!type || type->type != SYM_FN)
		return NULL;

	name = expr_to_var(expr->fn);
	if (!name)
		return NULL;
	snprintf(buf, sizeof(buf), "r %s()", name);
	free_string(name);
	return alloc_string(buf);
}

char *get_fnptr_name(struct expression *expr)
{
	char *name;

	expr = strip_expr(expr);

	/* (*ptrs[0])(a, b, c) is the same as ptrs[0](a, b, c); */
	if (expr->type == EXPR_PREOP && expr->op == '*')
		expr = strip_expr(expr->unop);

	name = get_from__symbol_get(expr);
	if (name)
		return name;

	name = get_array_ptr(expr);
	if (name)
		return name;

	name = get_returned_ptr(expr);
	if (name)
		return name;

	name = get_member_name(expr);
	if (name)
		return name;

	if (expr->type == EXPR_SYMBOL) {
		int param;
		char buf[256];
		struct symbol *sym;
		struct symbol *type;

		param = get_param_num_from_sym(expr->symbol);
		if (param >= 0) {
			snprintf(buf, sizeof(buf), "%s param %d", get_function(), param);
			return alloc_string(buf);
		}

		name =  expr_to_var_sym(expr, &sym);
		if (!name)
			return NULL;
		type = get_type(expr);
		if (type && type->type == SYM_PTR) {
			snprintf(buf, sizeof(buf), "%s %s", ptr_prefix(sym), name);
			free_string(name);
			return alloc_string(buf);
		}
		return name;
	}
	return expr_to_var(expr);
}

static void match_passes_function_pointer(struct expression *expr)
{
	struct expression *arg, *tmp;
	struct symbol *type;
	char *called_name;
	char *fn_name;
	char ptr_name[256];
	int i;


	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;

		tmp = strip_expr(arg);
		if (tmp->type == EXPR_PREOP && tmp->op == '&')
			tmp = strip_expr(tmp->unop);

		type = get_type(tmp);
		if (type && type->type == SYM_PTR)
			type = get_real_base_type(type);
		if (!type || type->type != SYM_FN)
			continue;

		called_name = expr_to_var(expr->fn);
		if (!called_name)
			return;
		fn_name = get_fnptr_name(tmp);
		if (!fn_name)
			goto free;

		snprintf(ptr_name, sizeof(ptr_name), "%s param %d", called_name, i);
		sql_insert_function_ptr(fn_name, ptr_name);
free:
		free_string(fn_name);
		free_string(called_name);
	} END_FOR_EACH_PTR(arg);

}

static int get_row_count(void *_row_count, int argc, char **argv, char **azColName)
{
	int *row_count = _row_count;

	*row_count = 0;
	if (argc != 1)
		return 0;
	*row_count = atoi(argv[0]);
	return 0;
}

static int can_hold_function_ptr(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return 0;
	if (type->type == SYM_PTR || type->type == SYM_ARRAY) {
		type = get_real_base_type(type);
		if (!type)
			return 0;
	}
	if (type->type == SYM_FN)
		return 1;
	if (type == &ulong_ctype && expr->type == EXPR_DEREF)
		return 1;
	if (type == &void_ctype)
		return 1;
	return 0;
}

static void match_function_assign(struct expression *expr)
{
	struct expression *right;
	struct symbol *type;
	char *fn_name;
	char *ptr_name;

	if (__in_fake_assign)
		return;

	right = strip_expr(expr->right);
	if (right->type == EXPR_PREOP && right->op == '&')
		right = strip_expr(right->unop);

	if (right->type != EXPR_SYMBOL &&
	    right->type != EXPR_DEREF)
		return;

	if (!can_hold_function_ptr(right) ||
	    !can_hold_function_ptr(expr->left))
		return;

	fn_name = get_fnptr_name(right);
	ptr_name = get_fnptr_name(expr->left);
	if (!fn_name || !ptr_name)
		goto free;
	if (strcmp(fn_name, ptr_name) == 0)
		goto free;


	type = get_type(right);
	if (!type)
		return;
	if (type->type == SYM_PTR || type->type == SYM_ARRAY) {
		type = get_real_base_type(type);
		if (!type)
			return;
	}
	if (type->type != SYM_FN) {
		int count = 0;

		/* look it up in function_ptr */
		run_sql(get_row_count, &count,
			"select count(*) from function_ptr where ptr = '%s'",
			fn_name);
		if (count == 0)
			goto free;
	}

	sql_insert_function_ptr(fn_name, ptr_name);
free:
	free_string(fn_name);
	free_string(ptr_name);
}

static void match_returns_function_pointer(struct expression *expr)
{
	struct symbol *type;
	char *fn_name;
	char ptr_name[256];

	if (__inline_fn)
		return;

	type = get_real_base_type(cur_func_sym);
	if (!type || type->type != SYM_FN)
		return;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_FN)
		return;

	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_expr(expr->unop);

	fn_name = get_fnptr_name(expr);
	if (!fn_name)
		return;
	snprintf(ptr_name, sizeof(ptr_name), "r %s()", get_function());
	sql_insert_function_ptr(fn_name, ptr_name);
}

void register_function_ptrs(int id)
{
	my_id = id;

	if (!option_info)
		return;

	add_hook(&match_passes_function_pointer, FUNCTION_CALL_HOOK);
	add_hook(&match_returns_function_pointer, RETURN_HOOK);
	add_hook(&match_function_assign, ASSIGNMENT_HOOK);
	add_hook(&match_function_assign, GLOBAL_ASSIGNMENT_HOOK);
}

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

#include "smatch.h"
#include "smatch_extra.h"

static int my_id;

struct allocator {
	const char *func;
	int param;
	int param2;
};

static struct allocator generic_allocator_table[] = {
	{"malloc", 0},
	{"memdup", 1},
	{"realloc", 1},
};

static struct allocator kernel_allocator_table[] = {
	{"kmalloc", 0},
	{"kzalloc", 0},
	{"vmalloc", 0},
	{"__vmalloc", 0},
	{"vzalloc", 0},
	{"sock_kmalloc", 1},
	{"kmemdup", 1},
	{"kmemdup_user", 1},
	{"dma_alloc_attrs", 1},
	{"pci_alloc_consistent", 1},
	{"pci_alloc_coherent", 1},
	{"devm_kmalloc", 1},
	{"devm_kzalloc", 1},
	{"krealloc", 1},
};

static struct allocator calloc_table[] = {
	{"calloc", 0, 1},
	{"kcalloc", 0, 1},
	{"kmalloc_array", 0, 1},
	{"devm_kcalloc", 1, 2},
};

static int bytes_per_element(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return 0;

	if (type->type != SYM_PTR && type->type != SYM_ARRAY)
		return 0;

	type = get_base_type(type);
	return type_bytes(type);
}

static void save_constraint_required(struct expression *pointer, int op, struct expression *constraint)
{
	char *data, *limit;

	data = get_constraint_str(pointer);
	if (!data)
		return;

	limit = get_constraint_str(constraint);
	if (!limit) {
		// FIXME deal with <= also
		if (op == '<')
			set_state_expr(my_id, constraint, alloc_state_expr(pointer));
		goto free_data;
	}

	sql_save_constraint_required(data, op, limit);

	free_string(limit);
free_data:
	free_string(data);
}

static int handle_zero_size_arrays(struct expression *pointer, struct expression *size)
{
	struct expression *left, *right;
	struct symbol *type, *array, *array_type;
	sval_t struct_size;
	char *limit;
	char data[128];

	if (size->type != EXPR_BINOP || size->op != '+')
		return 0;

	type = get_type(pointer);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (!type || !type->ident || type->type != SYM_STRUCT)
		return 0;
	if (!last_member_is_resizable(type))
		return 0;
	array = last_ptr_list((struct ptr_list *)type->symbol_list);
	if (!array || !array->ident)
		return 0;
	array_type = get_real_base_type(array);
	if (!array_type || array_type->type != SYM_ARRAY)
		return 0;
	array_type = get_real_base_type(array_type);

	left = strip_expr(size->left);
	right = strip_expr(size->right);

	if (!get_implied_value(left, &struct_size))
		return 0;
	if (struct_size.value != type_bytes(type))
		return 0;

	if (right->type == EXPR_BINOP && right->op == '*') {
		struct expression *mult_left, *mult_right;
		sval_t sval;

		mult_left = strip_expr(right->left);
		mult_right = strip_expr(right->right);

		if (get_implied_value(mult_left, &sval) &&
		    sval.value == type_bytes(array_type))
			size = mult_right;
		else if (get_implied_value(mult_right, &sval) &&
		    sval.value == type_bytes(array_type))
			size = mult_left;
		else
			return 0;
	}

	snprintf(data, sizeof(data), "(struct %s)->%s", type->ident->name, array->ident->name);
	limit = get_constraint_str(size);
	if (!limit) {
		set_state_expr(my_id, size, alloc_state_expr(
			       member_expression(deref_expression(pointer), '*', array->ident)));
		return 1;
	}

	sql_save_constraint_required(data, '<', limit);

	free_string(limit);
	return 1;
}

static void match_alloc_helper(struct expression *pointer, struct expression *size, int recurse)
{
	struct expression *size_orig, *tmp;
	sval_t sval;
	int cnt = 0;

	pointer = strip_expr(pointer);
	size = strip_expr(size);
	if (!size || !pointer)
		return;

	size_orig = size;
	if (recurse) {
		while ((tmp = get_assigned_expr(size))) {
			size = strip_expr(tmp);
			if (cnt++ > 5)
				break;
		}
		if (size != size_orig) {
			match_alloc_helper(pointer, size, 0);
			size = size_orig;
		}
	}

	if (handle_zero_size_arrays(pointer, size))
		return;

	if (size->type == EXPR_BINOP && size->op == '*') {
		struct expression *mult_left, *mult_right;

		mult_left = strip_expr(size->left);
		mult_right = strip_expr(size->right);

		if (get_implied_value(mult_left, &sval) &&
		    sval.value == bytes_per_element(pointer))
			size = mult_right;
		else if (get_implied_value(mult_right, &sval) &&
		    sval.value == bytes_per_element(pointer))
			size = mult_left;
		else
			return;
	}

	if (size->type == EXPR_BINOP && size->op == '+' &&
	    get_implied_value(size->right, &sval) &&
	    sval.value == 1)
		save_constraint_required(pointer, SPECIAL_LTE, size->left);
	else
		save_constraint_required(pointer, '<', size);
}

static void match_alloc(const char *fn, struct expression *expr, void *_size_arg)
{
	int size_arg = PTR_INT(_size_arg);
	struct expression *call, *arg;

	call = strip_expr(expr->right);
	arg = get_argument_from_call_expr(call->args, size_arg);

	match_alloc_helper(expr->left, arg, 1);
}

static void match_calloc(const char *fn, struct expression *expr, void *_start_arg)
{
	struct expression *pointer, *call, *size;
	struct expression *count = NULL;
	int start_arg = PTR_INT(_start_arg);
	sval_t sval;

	pointer = strip_expr(expr->left);
	call = strip_expr(expr->right);

	size = get_argument_from_call_expr(call->args, start_arg);
	if (get_implied_value(size, &sval) &&
	    sval.value == bytes_per_element(pointer))
		count = get_argument_from_call_expr(call->args, start_arg + 1);
	else {
		size = get_argument_from_call_expr(call->args, start_arg + 1);
		if (get_implied_value(size, &sval) &&
		    sval.value == bytes_per_element(pointer))
			count = get_argument_from_call_expr(call->args, start_arg);
	}

	if (!count)
		return;

	save_constraint_required(pointer, '<', count);
}

static void add_allocation_function(const char *func, void *call_back, int param)
{
	add_function_assign_hook(func, call_back, INT_PTR(param));
}

static void match_assign_size(struct expression *expr)
{
	struct smatch_state *state;
	char *data, *limit;

	state = get_state_expr(my_id, expr->right);
	if (!state || !state->data)
		return;

	data = get_constraint_str(state->data);
	if (!data)
		return;

	limit = get_constraint_str(expr->left);
	if (!limit)
		goto free_data;

	sql_save_constraint_required(data, '<', limit);

	free_string(limit);
free_data:
	free_string(data);
}

static void match_assign_has_buf_comparison(struct expression *expr)
{
	struct expression *size;
	int limit_type;

	if (expr->op != '=')
		return;
	if (expr->right->type == EXPR_CALL)
		return;
	size = get_size_variable(expr->right, &limit_type);
	if (!size)
		return;
	if (limit_type != ELEM_COUNT)
		return;
	match_alloc_helper(expr->left, size, 1);
}

static void match_assign_data(struct expression *expr)
{
	struct expression *right, *arg, *tmp;
	int i;
	int size_arg;
	int size_arg2 = -1;

	if (expr->op != '=')
		return;

	/* Direct calls are handled else where (for now at least) */
	tmp = get_assigned_expr(expr->right);
	if (!tmp)
		return;

	right = strip_expr(tmp);
	if (right->type != EXPR_CALL)
		return;

	if (right->fn->type != EXPR_SYMBOL ||
	    !right->fn->symbol ||
	    !right->fn->symbol->ident)
		return;

	for (i = 0; i < ARRAY_SIZE(generic_allocator_table); i++) {
		if (strcmp(right->fn->symbol->ident->name,
			   generic_allocator_table[i].func) == 0) {
			size_arg = generic_allocator_table[i].param;
			goto found;
		}
	}

	if (option_project != PROJ_KERNEL)
		return;

	for (i = 0; i < ARRAY_SIZE(kernel_allocator_table); i++) {
		if (strcmp(right->fn->symbol->ident->name,
			   kernel_allocator_table[i].func) == 0) {
			size_arg = kernel_allocator_table[i].param;
			goto found;
		}
	}

	for (i = 0; i < ARRAY_SIZE(calloc_table); i++) {
		if (strcmp(right->fn->symbol->ident->name,
			   calloc_table[i].func) == 0) {
			size_arg = calloc_table[i].param;
			size_arg2 = calloc_table[i].param2;
			goto found;
		}
	}

	return;

found:
	arg = get_argument_from_call_expr(right->args, size_arg);
	match_alloc_helper(expr->left, arg, 1);
	if (size_arg2 == -1)
		return;
	arg = get_argument_from_call_expr(right->args, size_arg2);
	match_alloc_helper(expr->left, arg, 1);
}

static void match_assign_ARRAY_SIZE(struct expression *expr)
{
	struct expression *array;
	char *data, *limit;
	const char *macro;

	macro = get_macro_name(expr->right->pos);
	if (!macro || strcmp(macro, "ARRAY_SIZE") != 0)
		return;
	array = strip_expr(expr->right);
	if (array->type != EXPR_BINOP || array->op != '+')
		return;
	array = strip_expr(array->left);
	if (array->type != EXPR_BINOP || array->op != '/')
		return;
	array = strip_expr(array->left);
	if (array->type != EXPR_SIZEOF)
		return;
	array = strip_expr(array->cast_expression);
	if (array->type != EXPR_PREOP || array->op != '*')
		return;
	array = strip_expr(array->unop);

	data = get_constraint_str(array);
	limit = get_constraint_str(expr->left);
	if (!data || !limit)
		goto free;

	sql_save_constraint_required(data, '<', limit);

free:
	free_string(data);
	free_string(limit);
}

static void match_assign_buf_comparison(struct expression *expr)
{
	struct expression *pointer;

	if (expr->op != '=')
		return;
	pointer = get_array_variable(expr->right);
	if (!pointer)
		return;

	match_alloc_helper(pointer, expr->right, 1);
}

static int constraint_found(void *_found, int argc, char **argv, char **azColName)
{
	int *found = _found;

	*found = 1;
	return 0;
}

static int has_constraint(struct expression *expr, const char *constraint)
{
	int found = 0;

	if (get_state_expr(my_id, expr))
		return 1;

	run_sql(constraint_found, &found,
		"select data from constraints_required where bound = '%q' limit 1",
		escape_newlines(constraint));

	return found;
}

static void match_assign_constraint(struct expression *expr)
{
	struct symbol *type;
	char *left, *right;

	if (expr->op != '=')
		return;

	type = get_type(expr->left);
	if (!type || type->type != SYM_BASETYPE)
		return;

	left = get_constraint_str(expr->left);
	if (!left)
		return;
	right = get_constraint_str(expr->right);
	if (!right)
		goto free;
	if (!has_constraint(expr->right, right))
		return;
	sql_copy_constraint_required(left, right);
free:
	free_string(right);
	free_string(left);
}

void register_constraints_required(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_hook(&match_assign_size, ASSIGNMENT_HOOK);
	add_hook(&match_assign_data, ASSIGNMENT_HOOK);
	add_hook(&match_assign_has_buf_comparison, ASSIGNMENT_HOOK);

	add_hook(&match_assign_ARRAY_SIZE, ASSIGNMENT_HOOK);
	add_hook(&match_assign_ARRAY_SIZE, GLOBAL_ASSIGNMENT_HOOK);
	add_hook(&match_assign_buf_comparison, ASSIGNMENT_HOOK);
	add_hook(&match_assign_constraint, ASSIGNMENT_HOOK);

	add_allocation_function("malloc", &match_alloc, 0);
	add_allocation_function("memdup", &match_alloc, 1);
	add_allocation_function("realloc", &match_alloc, 1);
	add_allocation_function("realloc", &match_calloc, 0);
	if (option_project == PROJ_KERNEL) {
		add_allocation_function("kmalloc", &match_alloc, 0);
		add_allocation_function("kzalloc", &match_alloc, 0);
		add_allocation_function("vmalloc", &match_alloc, 0);
		add_allocation_function("__vmalloc", &match_alloc, 0);
		add_allocation_function("vzalloc", &match_alloc, 0);
		add_allocation_function("sock_kmalloc", &match_alloc, 1);
		add_allocation_function("kmemdup", &match_alloc, 1);
		add_allocation_function("kmemdup_user", &match_alloc, 1);
		add_allocation_function("dma_alloc_attrs", &match_alloc, 1);
		add_allocation_function("pci_alloc_consistent", &match_alloc, 1);
		add_allocation_function("pci_alloc_coherent", &match_alloc, 1);
		add_allocation_function("devm_kmalloc", &match_alloc, 1);
		add_allocation_function("devm_kzalloc", &match_alloc, 1);
		add_allocation_function("kcalloc", &match_calloc, 0);
		add_allocation_function("kmalloc_array", &match_calloc, 0);
		add_allocation_function("devm_kcalloc", &match_calloc, 1);
		add_allocation_function("krealloc", &match_alloc, 1);
	}
}

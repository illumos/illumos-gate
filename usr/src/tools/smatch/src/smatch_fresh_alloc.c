/*
 * Copyright (C) 2019 Oracle.
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
 * There are a bunch of allocation functions where we allocate some memory,
 * set up some struct members and then return the allocated memory.  One
 * nice thing about this is that we just one pointer to the allocated memory
 * so what we can do is we can generate a mtag alias for it in the caller.
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(fresh);

struct alloc_info *alloc_funcs;

struct alloc_info kernel_allocation_funcs[] = {
	{"kmalloc", 0},
	{"kmalloc_node", 0},
	{"kzalloc", 0},
	{"kzalloc_node", 0},
	{"vmalloc", 0},
	{"__vmalloc", 0},
	{"kvmalloc", 0},
	{"kcalloc", 0, 1},
	{"kmalloc_array", 0, 1},
	{"sock_kmalloc", 1},
	{"kmemdup", 1},
	{"kmemdup_user", 1},
	{"dma_alloc_attrs", 1},
	{"pci_alloc_consistent", 1},
	{"pci_alloc_coherent", 1},
	{"devm_kmalloc", 1},
	{"devm_kzalloc", 1},
	{"krealloc", 1},
	{"__alloc_bootmem", 0},
	{"alloc_bootmem", 0},
	{"dma_alloc_contiguous", 1},
	{"dma_alloc_coherent", 1},
	{},
};

struct alloc_info general_allocation_funcs[] = {
	{"malloc", 0},
	{"calloc", 0, 1},
	{"memdup", 1},
	{"realloc", 1},
	{},
};

static int fresh_callback(void *fresh, int argc, char **argv, char **azColName)
{
	*(int *)fresh = 1;
	return 0;
}

static int fresh_from_db(struct expression *call)
{
	int fresh = 0;

	/* for function pointers assume everything is used */
	if (call->fn->type != EXPR_SYMBOL)
		return 0;

	run_sql(&fresh_callback, &fresh,
		"select * from return_states where %s and type = %d and parameter = -1 and key = '$' limit 1;",
		get_static_filter(call->fn->symbol), FRESH_ALLOC);
	return fresh;
}

bool is_fresh_alloc_var_sym(const char *var, struct symbol *sym)
{
	return get_state(my_id, var, sym) == &fresh;
}

bool is_fresh_alloc(struct expression *expr)
{
	sval_t sval;
	int i;

	if (!expr)
		return false;

	if (get_implied_value_fast(expr, &sval) && sval.value == 0)
		return false;

	if (get_state_expr(my_id, expr) == &fresh)
		return true;

	if (expr->type != EXPR_CALL)
		return false;
	if (fresh_from_db(expr))
		return true;
	i = -1;
	while (alloc_funcs[++i].fn) {
		if (sym_name_is(kernel_allocation_funcs[i].fn, expr->fn))
			return true;
	}
	return false;
}

static void record_alloc_func(int return_id, char *return_ranges, struct expression *expr)
{
	if (!is_fresh_alloc(expr))
		return;
	sql_insert_return_states(return_id, return_ranges, FRESH_ALLOC, -1, "$", "");
}

static void set_unfresh(struct expression *expr)
{
	struct sm_state *sm;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &fresh))
		return;
	// TODO call unfresh hooks
	set_state_expr(my_id, expr, &undefined);
}

static void match_assign(struct expression *expr)
{
	set_unfresh(expr->right);
}

static void match_call(struct expression *expr)
{
	struct expression *arg;

	FOR_EACH_PTR(expr->args, arg) {
		set_unfresh(arg);
	} END_FOR_EACH_PTR(arg);
}

static void set_fresh(struct expression *expr)
{
	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL)
		return;
	set_state_expr(my_id, expr, &fresh);
}

static void returns_fresh_alloc(struct expression *expr, int param, char *key, char *value)
{
	if (param != -1 || !key || strcmp(key, "$") != 0)
		return;
	if (expr->type != EXPR_ASSIGNMENT)
		return;

	set_fresh(expr->left);
}

static void match_alloc(const char *fn, struct expression *expr, void *_size_arg)
{
	set_fresh(expr->left);
}

void register_fresh_alloc(int id)
{
	int i;

	my_id = id;

	if (option_project == PROJ_KERNEL)
		alloc_funcs = kernel_allocation_funcs;
	else
		alloc_funcs = general_allocation_funcs;

	i = -1;
	while (alloc_funcs[++i].fn)
		add_function_assign_hook(alloc_funcs[i].fn, &match_alloc, 0);

	add_split_return_callback(&record_alloc_func);
	select_return_states_hook(FRESH_ALLOC, &returns_fresh_alloc);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}

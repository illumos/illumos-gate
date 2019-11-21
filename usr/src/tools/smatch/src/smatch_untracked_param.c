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
 * Sometimes we aren't able to track a variable through a function call.  This
 * usually happens because a function changes too many variables so we give up.
 * Another reason this happens is because we call a function pointer and there
 * are too many functions which implement that function pointer so we give up.
 * Also maybe we don't have the database enabled.
 *
 * The goal here is to make a call back so what if we call:
 *
 * 	frob(&foo);
 *
 * but we're not able to say what happens to "foo", then let's assume that we
 * don't know anything about "foo" if it's an untracked call.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static int tracked;

STATE(untracked);
STATE(lost);

typedef void (untracked_hook)(struct expression *call, int param);
DECLARE_PTR_LIST(untracked_hook_list, untracked_hook *);
static struct untracked_hook_list *untracked_hooks;
static struct untracked_hook_list *lost_hooks;

struct int_stack *tracked_stack;

void add_untracked_param_hook(void (func)(struct expression *call, int param))
{
	untracked_hook **p = malloc(sizeof(untracked_hook *));
	*p = func;
	add_ptr_list(&untracked_hooks, p);
}

static void call_untracked_callbacks(struct expression *expr, int param)
{
	untracked_hook **fn;

	FOR_EACH_PTR(untracked_hooks, fn) {
		(*fn)(expr, param);
	} END_FOR_EACH_PTR(fn);
}

void add_lost_param_hook(void (func)(struct expression *call, int param))
{
	untracked_hook **p = malloc(sizeof(untracked_hook *));
	*p = func;
	add_ptr_list(&lost_hooks, p);
}

static void call_lost_callbacks(struct expression *expr, int param)
{
	untracked_hook **fn;

	FOR_EACH_PTR(lost_hooks, fn) {
		(*fn)(expr, param);
	} END_FOR_EACH_PTR(fn);
}

static void assume_tracked(struct expression *call_expr, int param, char *key, char *value)
{
	tracked = 1;
}

static char *get_array_from_key(struct expression *expr, int param, const char *key, struct symbol **sym)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return NULL;
	if (arg->type != EXPR_PREOP || arg->op != '&')
		return NULL;
	arg = arg->unop;
	if (!is_array(arg))
		return NULL;
	arg = get_array_base(arg);

	return expr_to_var_sym(arg, sym);
}

static void mark_untracked_lost(struct expression *expr, int param, const char *key, int type)
{
	char *name;
	struct symbol *sym;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	name = return_state_to_var_sym(expr, param, key, &sym);
	if (!name || !sym) {
		name = get_array_from_key(expr, param, key, &sym);
		if (!name || !sym)
			goto free;
	}

	if (type == LOST_PARAM)
		call_lost_callbacks(expr, param);
	call_untracked_callbacks(expr, param);
	set_state(my_id, name, sym, &untracked);
free:
	free_string(name);

}

void mark_untracked(struct expression *expr, int param, const char *key, const char *value)
{
	mark_untracked_lost(expr, param, key, UNTRACKED_PARAM);
}

void mark_lost(struct expression *expr, int param, const char *key, const char *value)
{
	mark_untracked_lost(expr, param, key, LOST_PARAM);
}

static int lost_in_va_args(struct expression *expr)
{
	struct symbol *fn;
	char *name;
	int is_lost;

	fn = get_type(expr->fn);
	if (!fn || !fn->variadic)
		return 0;

	is_lost = 1;
	name = expr_to_var(expr->fn);
	if (name && strstr(name, "print"))
		is_lost = 0;
	free_string(name);

	return is_lost;
}

static void match_after_call(struct expression *expr)
{
	struct expression *arg;
	struct symbol *type;
	int i;

	if (lost_in_va_args(expr))
		tracked = 0;

	if (tracked) {
		tracked = 0;
		return;
	}

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;

		type = get_type(arg);
		if (!type || type->type != SYM_PTR)
			continue;

		call_untracked_callbacks(expr, i);
		set_state_expr(my_id, arg, &untracked);
	} END_FOR_EACH_PTR(arg);
}


static void mark_all_params(int return_id, char *return_ranges, int type)
{
	struct symbol *arg;
	int param;

	param = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		param++;

		if (!arg->ident)
			continue;
		sql_insert_return_states(return_id, return_ranges,
					 type, param, "$", "");
	} END_FOR_EACH_PTR(arg);
}


void mark_all_params_untracked(int return_id, char *return_ranges, struct expression *expr)
{
	mark_all_params(return_id, return_ranges, UNTRACKED_PARAM);
}

void mark_all_params_lost(int return_id, char *return_ranges, struct expression *expr)
{
	mark_all_params(return_id, return_ranges, LOST_PARAM);
}

static void print_untracked_params(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	struct symbol *arg;
	int param;
	int type;

	param = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		param++;

		if (!arg->ident)
			continue;

		if (__bail_on_rest_of_function) {
			/* hairy functions are lost */
			type = LOST_PARAM;
		} else if ((sm = get_sm_state(my_id, arg->ident->name, arg))) {
			if (slist_has_state(sm->possible, &lost))
				type = LOST_PARAM;
			else
				type = UNTRACKED_PARAM;
		} else {
			continue;
		}

		sql_insert_return_states(return_id, return_ranges,
					 type, param, "$", "");
	} END_FOR_EACH_PTR(arg);
}

static void match_param_assign(struct expression *expr)
{
	struct expression *right;
	struct symbol *type;
	int param;

	if (__in_fake_assign)
		return;

	right = strip_expr(expr->right);
	type = get_type(right);
	if (!type || type->type != SYM_PTR)
		return;

	param = get_param_num(right);
	if (param < 0)
		return;

	set_state_expr(my_id, right, &untracked);
}


static void match_param_assign_in_asm(struct statement *stmt)
{

	struct expression *tmp, *expr;
	struct symbol *type;
	int param;

	FOR_EACH_PTR(stmt->asm_inputs, tmp) {
		expr = strip_expr(tmp->expr);
		type = get_type(expr);
		if (!type || type->type != SYM_PTR)
			continue;
		param = get_param_num(expr);
		if (param < 0)
			continue;
		set_state_expr(my_id, expr, &untracked);
	} END_FOR_EACH_PTR(tmp);
}

static void match_inline_start(struct expression *expr)
{
	push_int(&tracked_stack, tracked);
}

static void match_inline_end(struct expression *expr)
{
	tracked = pop_int(&tracked_stack);
}

void register_untracked_param(int id)
{
	my_id = id;

	select_return_states_hook(INTERNAL, &assume_tracked);
	select_return_states_hook(UNTRACKED_PARAM, &mark_untracked);
	select_return_states_hook(LOST_PARAM, &mark_lost);
	add_hook(&match_after_call, FUNCTION_CALL_HOOK_AFTER_DB);

	add_split_return_callback(&print_untracked_params);

	add_hook(&match_param_assign, ASSIGNMENT_HOOK);
	add_hook(&match_param_assign_in_asm, ASM_HOOK);

	add_hook(&match_inline_start, INLINE_FN_START);
	add_hook(&match_inline_end, INLINE_FN_END);
}

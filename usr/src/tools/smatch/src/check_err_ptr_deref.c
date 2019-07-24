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

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(err_ptr);
STATE(checked);

static sval_t err_ptr_min = {
	.type = &int_ctype,
	{.value = -4095},
};

static sval_t err_ptr_max = {
	.type = &int_ctype,
	{.value = -1},
};

struct range_list *err_ptr_rl;

static void ok_to_use(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state != &checked)
		set_state(my_id, sm->name, sm->sym, &checked);
}

static void check_is_err_ptr(struct expression *expr)
{
	struct sm_state *sm;
	struct range_list *rl;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;

	if (!slist_has_state(sm->possible, &err_ptr))
		return;

	get_absolute_rl(expr, &rl);
	if (!possibly_true_rl(rl, SPECIAL_EQUAL, err_ptr_rl))
		return;

	sm_error("'%s' dereferencing possible ERR_PTR()", sm->name);
	set_state(my_id, sm->name, sm->sym, &checked);
}

static void match_returns_err_ptr(const char *fn, struct expression *expr,
				void *info)
{
	set_state_expr(my_id, expr->left, &err_ptr);
}

static void set_param_dereferenced(struct expression *call, struct expression *arg, char *key, char *unused)
{
	struct sm_state *sm;
	struct smatch_state *estate;
	struct symbol *sym;
	char *name;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	sm = get_sm_state(my_id, name, sym);
	if (!sm)
		goto free;

	if (!slist_has_state(sm->possible, &err_ptr))
		goto free;

	estate = get_state(SMATCH_EXTRA, name, sym);
	if (!estate || !possibly_true_rl(estate_rl(estate), SPECIAL_EQUAL, err_ptr_rl))
		goto free;

	sm_error("'%s' dereferencing possible ERR_PTR()", sm->name);
	set_state(my_id, sm->name, sm->sym, &checked);

free:
	free_string(name);
}

static void match_checked(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(call_expr->args, 0);
	arg = strip_expr(arg);
	while (arg->type == EXPR_ASSIGNMENT)
		arg = strip_expr(arg->left);
	set_state_expr(my_id, arg, &checked);
}

static void match_err(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(call_expr->args, 0);
	arg = strip_expr(arg);
	while (arg->type == EXPR_ASSIGNMENT)
		arg = strip_expr(arg->left);
	set_state_expr(my_id, arg, &err_ptr);
}

static void match_dereferences(struct expression *expr)
{
	if (expr->type != EXPR_PREOP)
		return;
	check_is_err_ptr(expr->unop);
}

static void match_kfree(const char *fn, struct expression *expr, void *_arg_nr)
{
	int arg_nr = PTR_INT(_arg_nr);
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, arg_nr);
	check_is_err_ptr(arg);
}

static void match_condition(struct expression *expr)
{
	if (expr->type == EXPR_ASSIGNMENT) {
		match_condition(expr->right);
		match_condition(expr->left);
	}
	if (!get_state_expr(my_id, expr))
		return;
	/* If we know the variable is zero that means it's not an ERR_PTR */
	set_true_false_states_expr(my_id, expr, NULL, &checked);
}

static void register_err_ptr_funcs(void)
{
	struct token *token;
	const char *func;

	token = get_tokens_file("kernel.returns_err_ptr");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		add_function_assign_hook(func, &match_returns_err_ptr, NULL);
		token = token->next;
	}
	clear_token_alloc();
}

static void match_err_ptr_positive_const(const char *fn, struct expression *expr, void *unused)
{
	struct expression *arg;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 0);

	if (!get_value(arg, &sval))
		return;
	if (sval_is_positive(sval) && sval_cmp_val(sval, 0) != 0)
		sm_error("passing non negative %s to ERR_PTR", sval_to_str(sval));
}

static void match_err_ptr(const char *fn, struct expression *expr, void *unused)
{
	struct expression *arg;
	struct sm_state *sm;
	struct sm_state *tmp;
	sval_t tmp_min;
	sval_t tmp_max;
	sval_t min = sval_type_max(&llong_ctype);
	sval_t max = sval_type_min(&llong_ctype);

	arg = get_argument_from_call_expr(expr->args, 0);
	sm = get_sm_state_expr(SMATCH_EXTRA, arg);
	if (!sm)
		return;
	FOR_EACH_PTR(sm->possible, tmp) {
		tmp_min = estate_min(tmp->state);
		if (!sval_is_a_min(tmp_min) && sval_cmp(tmp_min, min) < 0)
			min = tmp_min;
		tmp_max = estate_max(tmp->state);
		if (!sval_is_a_max(tmp_max) && sval_cmp(tmp_max, max) > 0)
			max = tmp_max;
	} END_FOR_EACH_PTR(tmp);
	if (sval_is_negative(min) && sval_cmp_val(min, -4095) < 0)
		sm_error("%s too low for ERR_PTR", sval_to_str(min));
	if (sval_is_positive(max) && sval_cmp_val(max, 0) != 0)
		sm_error("passing non negative %s to ERR_PTR", sval_to_str(max));
}

void check_err_ptr_deref(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	return_implies_state("IS_ERR", 0, 0, &match_checked, NULL);
	return_implies_state("IS_ERR", 1, 1, &match_err, NULL);
	return_implies_state("IS_ERR_OR_NULL", 0, 0, &match_checked, NULL);
	return_implies_state("IS_ERR_OR_NULL", 1, 1, &match_err, NULL);
	return_implies_state("PTR_RET", 0, 0, &match_checked, NULL);
	return_implies_state("PTR_RET", -4095, -1, &match_err, NULL);
	register_err_ptr_funcs();
	add_hook(&match_dereferences, DEREF_HOOK);
	add_function_hook("ERR_PTR", &match_err_ptr_positive_const, NULL);
	add_function_hook("ERR_PTR", &match_err_ptr, NULL);
	add_hook(&match_condition, CONDITION_HOOK);
	add_modification_hook(my_id, &ok_to_use);
	add_function_hook("kfree", &match_kfree, INT_PTR(0));
	add_function_hook("brelse", &match_kfree, INT_PTR(0));
	add_function_hook("kmem_cache_free", &match_kfree, INT_PTR(1));
	add_function_hook("vfree", &match_kfree, INT_PTR(0));

	err_ptr_rl = clone_rl_permanent(alloc_rl(err_ptr_min, err_ptr_max));

	select_return_implies_hook(DEREFERENCE, &set_param_dereferenced);
}


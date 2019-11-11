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
 * This is a kernel check to make sure we unwind everything on
 * on errors.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

#define EBUSY 16
#define MAX_ERRNO 4095

static int my_id;

STATE(allocated);
STATE(unallocated);

/* state of unwind function */
STATE(called);

static int was_passed_as_param(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct symbol *arg;

	name = expr_to_var_sym(expr, &sym);
	if (!name)
		return 0;
	free_string(name);

	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		if (arg == sym)
			return 1;
	} END_FOR_EACH_PTR(arg);
	return 0;
}

static void print_unwind_functions(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);
	static struct symbol *last_printed = NULL;

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	if (!was_passed_as_param(arg_expr))
		return;
	if (last_printed == cur_func_sym)
		return;
	last_printed = cur_func_sym;
	sm_msg("info: is unwind function");
}

static void request_granted(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);

	if (arg_no == -1) {
		if (!assign_expr)
			return;
		arg_expr = assign_expr->left;
	} else {
		arg_expr = get_argument_from_call_expr(call_expr->args, arg_no);
	}
	set_state_expr(my_id, arg_expr, &allocated);
}

static void request_denied(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);

	if (arg_no == -1) {
		if (!assign_expr)
			return;
		arg_expr = assign_expr->left;
	} else {
		arg_expr = get_argument_from_call_expr(call_expr->args, arg_no);
	}
	set_state_expr(my_id, arg_expr, &unallocated);
}

static void match_release(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	if (get_state_expr(my_id, arg_expr))
		set_state_expr(my_id, arg_expr, &unallocated);
	set_equiv_state_expr(my_id, arg_expr, &unallocated);
}

static void match_unwind_function(const char *fn, struct expression *expr, void *unused)
{
	set_state(my_id, "unwind_function", NULL, &called);
}

static int func_returns_int(void)
{
	struct symbol *type;

	type = get_base_type(cur_func_sym);
	if (!type || type->type != SYM_FN)
		return 0;
	type = get_base_type(type);
	if (type && type->ctype.base_type == &int_type) {
		return 1;
	}
	return 0;
}

static void match_return(struct expression *ret_value)
{
	struct stree *stree;
	struct sm_state *tmp;
	sval_t sval;

	if (!func_returns_int())
		return;
	if (get_value(ret_value, &sval) && sval_cmp_val(sval, 0) >= 0)
		return;
	if (!implied_not_equal(ret_value, 0))
		return;
	if (get_state(my_id, "unwind_function", NULL) == &called)
		return;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, tmp) {
		if (slist_has_state(tmp->possible, &allocated))
			sm_warning("'%s' was not released on error", tmp->name);
	} END_FOR_EACH_SM(tmp);
}

static void register_unwind_functions(void)
{
	struct token *token;
	const char *func;

	token = get_tokens_file("kernel.unwind_functions");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		add_function_hook(func, &match_unwind_function, NULL);
		token = token->next;
	}
	clear_token_alloc();
}

static void release_function_indicator(const char *name)
{
	if (!option_info)
		return;
	add_function_hook(name, &print_unwind_functions, INT_PTR(0));
}

void check_unwind(int id)
{
	if (option_project != PROJ_KERNEL || !option_spammy)
		return;
	my_id = id;

	register_unwind_functions();

	return_implies_state("request_resource", 0, 0, &request_granted, INT_PTR(1));
	return_implies_state("request_resource", -EBUSY, -EBUSY, &request_denied, INT_PTR(1));
	add_function_hook("release_resource", &match_release, INT_PTR(0));
	release_function_indicator("release_resource");

	return_implies_state_sval("__request_region", valid_ptr_min_sval, valid_ptr_max_sval, &request_granted, INT_PTR(1));
	return_implies_state("__request_region", 0, 0, &request_denied, INT_PTR(1));
	add_function_hook("__release_region", &match_release, INT_PTR(1));
	release_function_indicator("__release_region");

	return_implies_state_sval("ioremap", valid_ptr_min_sval, valid_ptr_max_sval, &request_granted, INT_PTR(-1));
	return_implies_state("ioremap", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("iounmap", &match_release, INT_PTR(0));

	return_implies_state_sval("pci_iomap", valid_ptr_min_sval, valid_ptr_max_sval, &request_granted, INT_PTR(-1));
	return_implies_state("pci_iomap", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("pci_iounmap", &match_release, INT_PTR(1));
	release_function_indicator("pci_iounmap");

	return_implies_state_sval("__create_workqueue_key", valid_ptr_min_sval, valid_ptr_max_sval, &request_granted,
			INT_PTR(-1));
	return_implies_state("__create_workqueue_key", 0, 0, &request_denied, INT_PTR(-1));
	add_function_hook("destroy_workqueue", &match_release, INT_PTR(0));

	return_implies_state("request_irq", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("request_irq", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("free_irq", &match_release, INT_PTR(0));
	release_function_indicator("free_irq");

	return_implies_state("register_netdev", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("register_netdev", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("unregister_netdev", &match_release, INT_PTR(0));
	release_function_indicator("unregister_netdev");

	return_implies_state("misc_register", 0, 0, &request_granted, INT_PTR(0));
	return_implies_state("misc_register", -MAX_ERRNO, -1, &request_denied, INT_PTR(0));
	add_function_hook("misc_deregister", &match_release, INT_PTR(0));
	release_function_indicator("misc_deregister");

	add_hook(&match_return, RETURN_HOOK);
}

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
 * There was a previous null dereference test but it was too confusing and
 * difficult to debug.  This test is much simpler in its goals and scope.
 *
 * This test only complains about:
 * 1) dereferencing uninitialized variables
 * 2) dereferencing variables which were assigned as null.
 * 3) dereferencing variables which were assigned a function the returns 
 *    null.
 *
 * If we dereference something then we complain if any of those three
 * are possible.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

#define __GFP_NOFAIL 0x800

STATE(null);
STATE(ok);
STATE(uninitialized);

static struct smatch_state *alloc_my_state(const char *name)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->name = name;
	return state;
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	return &ok;
}

static void is_ok(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &ok);
}

static void check_dereference(struct expression *expr)
{
	struct sm_state *sm;
	struct sm_state *tmp;

	expr = strip_expr(expr);
	if (is_static(expr))
		return;
	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;
	if (is_ignored(my_id, sm->name, sm->sym))
		return;
	if (implied_not_equal(expr, 0))
		return;
	if (is_impossible_path())
		return;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &merged)
			continue;
		if (tmp->state == &ok)
			continue;
		add_ignore(my_id, sm->name, sm->sym);
		if (tmp->state == &null) {
			if (option_spammy)
				sm_error("potential NULL dereference '%s'.", tmp->name);
			return;
		}
		if (tmp->state == &uninitialized) {
			if (option_spammy)
				sm_error("potentially dereferencing uninitialized '%s'.", tmp->name);
			return;
		}
		sm_error("potential null dereference '%s'.  (%s returns null)",
			tmp->name, tmp->state->name);
		return;
	} END_FOR_EACH_PTR(tmp);
}

static void check_dereference_name_sym(char *name, struct symbol *sym)
{
	struct sm_state *sm;
	struct sm_state *tmp;

	sm = get_sm_state(my_id, name, sym);
	if (!sm)
		return;
	if (is_ignored(my_id, sm->name, sm->sym))
		return;
	if (implied_not_equal_name_sym(name, sym, 0))
		return;
	if (is_impossible_path())
		return;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &merged)
			continue;
		if (tmp->state == &ok)
			continue;
		add_ignore(my_id, sm->name, sm->sym);
		if (tmp->state == &null) {
			if (option_spammy)
				sm_error("potential NULL dereference '%s'.", tmp->name);
			return;
		}
		if (tmp->state == &uninitialized) {
			if (option_spammy)
				sm_error("potentially dereferencing uninitialized '%s'.", tmp->name);
			return;
		}
		sm_error("potential null dereference '%s'.  (%s returns null)",
			tmp->name, tmp->state->name);
		return;
	} END_FOR_EACH_PTR(tmp);
}

static void match_dereferences(struct expression *expr)
{
	if (expr->type != EXPR_PREOP)
		return;
	check_dereference(expr->unop);
}

static void match_pointer_as_array(struct expression *expr)
{
	if (!is_array(expr))
		return;
	check_dereference(get_array_base(expr));
}

static void set_param_dereferenced(struct expression *call, struct expression *arg, char *key, char *unused)
{
	struct symbol *sym;
	char *name;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	check_dereference_name_sym(name, sym);
free:
	free_string(name);
}

static void match_declarations(struct symbol *sym)
{
	const char *name;

	if ((get_base_type(sym))->type == SYM_ARRAY)
		return;

	if (!sym->ident)
		return;
	name = sym->ident->name;
	if (!sym->initializer) {
		set_state(my_id, name, sym, &uninitialized);
		scoped_state(my_id, name, sym);
	}
}

static void match_assign(struct expression *expr)
{
	struct statement *stmt;

	if (!is_zero(expr->right))
		return;

	if (__in_fake_assign)
		return;

	FOR_EACH_PTR_REVERSE(big_statement_stack, stmt) {
		if (stmt->type == STMT_DECLARATION)
			return;
		break;
	} END_FOR_EACH_PTR_REVERSE(stmt);

	set_state_expr(my_id, expr->left, &null);
}

static void match_assigns_address(struct expression *expr)
{
	struct expression *right;

	right = strip_expr(expr->right);
	if (right->type != EXPR_PREOP || right->op != '&')
		return;
	set_state_expr(my_id, right, &ok);
}

static void match_condition(struct expression *expr)
{
	if (expr->type == EXPR_ASSIGNMENT) {
		match_condition(expr->right);
		match_condition(expr->left);
	}
	if (!get_state_expr(my_id, expr))
		return;
	set_true_false_states_expr(my_id, expr, &ok, NULL);
}

static int called_with_no_fail(struct expression *call, int param)
{
	struct expression *arg;
	sval_t sval;

	if (param == -1)
		return 0;
	call = strip_expr(call);
	if (call->type != EXPR_CALL)
		return 0;
	arg = get_argument_from_call_expr(call->args, param);
	if (get_value(arg, &sval) && (sval.uvalue & __GFP_NOFAIL))
		return 1;
	return 0;
}

static void match_assign_returns_null(const char *fn, struct expression *expr, void *_gfp)
{
	struct smatch_state *state;
	int gfp_param = PTR_INT(_gfp);

	if (called_with_no_fail(expr->right, gfp_param))
		return;
	state = alloc_my_state(fn);
	set_state_expr(my_id, expr->left, state);
}

static void register_allocation_funcs(void)
{
	struct token *token;
	const char *func;
	int arg;

	token = get_tokens_file("kernel.allocation_funcs_gfp");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		token = token->next;
		if (token_type(token) == TOKEN_IDENT)
			arg = -1;
		else if (token_type(token) == TOKEN_NUMBER)
			arg = atoi(token->number);
		else
			return;
		add_function_assign_hook(func, &match_assign_returns_null, INT_PTR(arg));
		token = token->next;
	}
	clear_token_alloc();
}

void check_deref(int id)
{
	my_id = id;

	add_unmatched_state_hook(my_id, &unmatched_state);
	add_modification_hook(my_id, &is_ok);
	add_hook(&match_dereferences, DEREF_HOOK);
	add_hook(&match_pointer_as_array, OP_HOOK);
	select_return_implies_hook(DEREFERENCE, &set_param_dereferenced);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_declarations, DECLARATION_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_assigns_address, ASSIGNMENT_HOOK);
	if (option_project == PROJ_KERNEL)
		register_allocation_funcs();
}

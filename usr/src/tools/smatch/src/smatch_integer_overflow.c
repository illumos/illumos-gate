/*
 * Copyright (C) 2015 Oracle.
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
static int link_id;

static struct smatch_state *safe_state(struct expression *expr)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	expr = strip_expr(expr);
	state->name = alloc_sname("safe");
	state->data = expr;
	return state;
}

static char *save_links(struct expression *expr, struct symbol **sym, struct var_sym_list **vsl)
{
	struct var_sym *vs;
	char *name;

	name = expr_to_chunk_sym_vsl(expr, sym, vsl);
	if (!name || !*vsl) {
		free_string(name);
		return NULL;
	}

	FOR_EACH_PTR(*vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, *sym);
	} END_FOR_EACH_PTR(vs);

	return name;
}

static void match_divide(struct expression *expr)
{
	struct expression *left, *right, *binop;
	struct symbol *type;
	char *name;
	struct symbol *sym;
	struct var_sym_list *vsl;
	sval_t max;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != '>' && expr->op != SPECIAL_UNSIGNED_GT &&
	    expr->op != SPECIAL_GTE && expr->op != SPECIAL_UNSIGNED_GTE)
		return;

	left = strip_parens(expr->left);
	right = strip_parens(expr->right);

	if (right->type != EXPR_BINOP || right->op != '/')
		return;
	if (!get_value(right->left, &max))
		return;
	if (max.value != INT_MAX && max.value != UINT_MAX &&
	    max.value != LLONG_MAX && max.uvalue != ULLONG_MAX)
		return;

	type = get_type(expr);
	if (!type)
		return;
	if (type_bits(type) != 32 && type_bits(type) != 64)
		return;


	binop = binop_expression(left, '*', right->right);

	name = save_links(binop, &sym, &vsl);
	if (!name)
		return;
	set_true_false_states(my_id, name, sym, NULL, safe_state(binop));
	free_string(name);
}

static void match_overflow_to_less_than(struct expression *expr)
{
	struct expression *left, *right;
	struct symbol *type;
	char *name;
	struct symbol *sym;
	struct var_sym_list *vsl;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != '<' && expr->op != SPECIAL_UNSIGNED_LT)
		return;

	left = strip_parens(expr->left);
	right = strip_parens(expr->right);

	if (left->op != '+')
		return;

	type = get_type(expr);
	if (!type)
		return;
	if (type_bits(type) != 32 && type_bits(type) != 64)
		return;

	if (!expr_equiv(left->left, right) && !expr_equiv(left->right, right))
		return;

	name = save_links(left, &sym, &vsl);
	if (!name)
		return;
	set_true_false_states(my_id, name, sym, NULL, safe_state(left));
	free_string(name);
}

static void match_condition(struct expression *expr)
{
	match_overflow_to_less_than(expr);
	match_divide(expr);
}

int can_integer_overflow(struct symbol *type, struct expression *expr)
{
	int op;
	sval_t lmax, rmax, res;

	if (!type)
		type = &int_ctype;

	expr = strip_expr(expr);

	if (expr->type == EXPR_ASSIGNMENT) {
		switch(expr->op) {
		case SPECIAL_MUL_ASSIGN:
			op = '*';
			break;
		case SPECIAL_ADD_ASSIGN:
			op = '+';
			break;
		case SPECIAL_SHL_ASSIGN:
			op = SPECIAL_LEFTSHIFT;
			break;
		default:
			return 0;
		}
	} else if (expr->type == EXPR_BINOP) {
		if (expr->op != '*' && expr->op != '+' && expr->op != SPECIAL_LEFTSHIFT)
			return 0;
		op = expr->op;
	} else {
		return 0;
	}

	get_absolute_max(expr->left, &lmax);
	get_absolute_max(expr->right, &rmax);

	if (sval_binop_overflows(lmax, op, rmax))
		return 1;

	res = sval_binop(lmax, op, rmax);
	if (sval_cmp(res, sval_type_max(type)) > 0)
		return 1;
	return 0;
}

int can_integer_overflow_expr(struct expression *expr)
{
	struct symbol *type;
	struct smatch_state *state;
	char *name;
	struct symbol *sym;
	int ret;

	type = get_type(expr);
	if (!type)
		return 0;

	if (!can_integer_overflow(type, expr))
		return 0;

	name = expr_to_known_chunk_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	state = get_state(my_id, name, sym);
	if (state && state->data)
		ret = 0;
free:
	free_string(name);
	return ret;
}

static int get_arg_nr(struct expression *call, struct expression *expr)
{
	struct expression *arg;
	int i;

	i = -1;
	FOR_EACH_PTR(call->args, arg) {
		i++;
		if (expr_equiv(arg, expr))
			return i;
	} END_FOR_EACH_PTR(arg);

	return -1;
}

static void check_links(struct expression *call, struct expression *arg, int nr, struct sm_state *sm, void *_vsl)
{
	struct var_sym_list *vsl = _vsl;
	struct var_sym *vs;
	struct smatch_state *state;
	struct expression *expr;
	int left = -1;
	int right = -1;

	FOR_EACH_PTR(vsl, vs) {
		state = get_state(my_id, vs->var, vs->sym);
		if (!state || !state->data)
			continue;

		expr = state->data;

		if (expr_equiv(arg, expr->left)) {
			left = nr;
			right = get_arg_nr(call, expr->right);
		} else if (expr_equiv(arg, expr->right)) {
			left = get_arg_nr(call, expr->left);
			right = nr;
		}

		if (left == -1 || right == -1)
			continue;

		left = -1;
		right = -1;
	} END_FOR_EACH_PTR(vs);
}

static void match_call_info(struct expression *call)
{
	struct expression *arg;
	struct sm_state *link;
	struct stree *done = NULL;
	int i;

	i = -1;
	FOR_EACH_PTR(call->args, arg) {
		i++;

		link = get_sm_state_expr(link_id, arg);
		if (!link)
			continue;

		if (get_state_stree(done, my_id, link->state->name, NULL))
			continue;
//		set_state_stree(&done, my_id, link->state->name, NULL, &undefined);

		check_links(call, arg, i, link, link->state->data);
	} END_FOR_EACH_PTR(arg);

	free_stree(&done);
}

void register_integer_overflow(int id)
{
	my_id = id;
	set_dynamic_states(my_id);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
}

void register_integer_overflow_links(int id)
{
	link_id = id;
	set_up_link_functions(my_id, link_id);
}

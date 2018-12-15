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

#include "symbol.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static struct range_list *_get_rl(struct expression *expr, int implied, int *recurse_cnt);
static struct range_list *handle_variable(struct expression *expr, int implied, int *recurse_cnt);
static struct range_list *(*custom_handle_variable)(struct expression *expr);

static int get_implied_value_internal(struct expression *expr, sval_t *sval, int *recurse_cnt);
static int get_absolute_rl_internal(struct expression *expr, struct range_list **rl, int *recurse_cnt);

static sval_t zero  = {.type = &int_ctype, {.value = 0} };
static sval_t one   = {.type = &int_ctype, {.value = 1} };

struct range_list *rl_zero(void)
{
	static struct range_list *zero_perm;

	if (!zero_perm)
		zero_perm = clone_rl_permanent(alloc_rl(zero, zero));
	return zero_perm;
}

struct range_list *rl_one(void)
{
	static struct range_list *one_perm;

	if (!one_perm)
		one_perm = clone_rl_permanent(alloc_rl(one, one));

	return one_perm;
}

enum {
	RL_EXACT,
	RL_HARD,
	RL_FUZZY,
	RL_IMPLIED,
	RL_ABSOLUTE,
	RL_REAL_ABSOLUTE,
};

static struct range_list *last_stmt_rl(struct statement *stmt, int implied, int *recurse_cnt)
{
	struct expression *expr;

	if (!stmt)
		return NULL;

	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt->type == STMT_LABEL) {
		if (stmt->label_statement &&
		    stmt->label_statement->type == STMT_EXPRESSION)
			expr = stmt->label_statement->expression;
		else
			return NULL;
	} else if (stmt->type == STMT_EXPRESSION) {
		expr = stmt->expression;
	} else {
		return NULL;
	}
	return _get_rl(expr, implied, recurse_cnt);
}

static struct range_list *handle_expression_statement_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	return last_stmt_rl(get_expression_statement(expr), implied, recurse_cnt);
}

static struct range_list *handle_ampersand_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	sval_t sval;

	if (implied == RL_EXACT || implied == RL_HARD)
		return NULL;
	if (get_mtag_sval(expr, &sval))
		return alloc_rl(sval, sval);
	if (get_address_rl(expr, &rl))
		return rl;
	return alloc_rl(valid_ptr_min_sval, valid_ptr_max_sval);
}

static struct range_list *handle_negate_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	if (known_condition_true(expr->unop))
		return rl_zero();
	if (known_condition_false(expr->unop))
		return rl_one();

	if (implied == RL_EXACT)
		return NULL;

	if (implied_condition_true(expr->unop))
		return rl_zero();
	if (implied_condition_false(expr->unop))
		return rl_one();
	return alloc_rl(zero, one);
}

static struct range_list *handle_bitwise_negate(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	sval_t sval;

	rl = _get_rl(expr->unop, implied, recurse_cnt);
	if (!rl_to_sval(rl, &sval))
		return NULL;
	sval = sval_preop(sval, '~');
	sval_cast(get_type(expr->unop), sval);
	return alloc_rl(sval, sval);
}

static struct range_list *handle_minus_preop(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	sval_t min, max;

	rl = _get_rl(expr->unop, implied, recurse_cnt);
	min = sval_preop(rl_max(rl), '-');
	max = sval_preop(rl_min(rl), '-');
	return alloc_rl(min, max);
}

static struct range_list *handle_preop_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	switch (expr->op) {
	case '&':
		return handle_ampersand_rl(expr, implied, recurse_cnt);
	case '!':
		return handle_negate_rl(expr, implied, recurse_cnt);
	case '~':
		return handle_bitwise_negate(expr, implied, recurse_cnt);
	case '-':
		return handle_minus_preop(expr, implied, recurse_cnt);
	case '*':
		return handle_variable(expr, implied, recurse_cnt);
	case '(':
		return handle_expression_statement_rl(expr, implied, recurse_cnt);
	default:
		return NULL;
	}
}

static struct range_list *handle_divide_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *left_rl, *right_rl;
	struct symbol *type;

	type = get_type(expr);

	left_rl = _get_rl(expr->left, implied, recurse_cnt);
	left_rl = cast_rl(type, left_rl);
	right_rl = _get_rl(expr->right, implied, recurse_cnt);
	right_rl = cast_rl(type, right_rl);

	if (!left_rl || !right_rl)
		return NULL;

	if (implied != RL_REAL_ABSOLUTE) {
		if (is_whole_rl(left_rl) || is_whole_rl(right_rl))
			return NULL;
	}

	return rl_binop(left_rl, '/', right_rl);
}

static int handle_offset_subtraction(struct expression *expr)
{
	struct expression *left, *right;
	struct symbol *left_sym, *right_sym;
	struct symbol *type;
	int left_offset, right_offset;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return -1;
	type = get_real_base_type(type);
	if (!type || (type_bits(type) != 8 && (type != &void_ctype)))
		return -1;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (left->type != EXPR_PREOP || left->op != '&')
		return -1;
	left = strip_expr(left->unop);

	left_sym = expr_to_sym(left);
	right_sym = expr_to_sym(right);
	if (!left_sym || left_sym != right_sym)
		return -1;

	left_offset = get_member_offset_from_deref(left);
	if (right->type == EXPR_SYMBOL)
		right_offset = 0;
	else {
		if (right->type != EXPR_PREOP || right->op != '&')
			return -1;
		right = strip_expr(right->unop);
		right_offset = get_member_offset_from_deref(right);
	}
	if (left_offset < 0 || right_offset < 0)
		return -1;

	return left_offset - right_offset;
}

static struct range_list *handle_subtract_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct symbol *type;
	struct range_list *left_orig, *right_orig;
	struct range_list *left_rl, *right_rl;
	sval_t max, min, tmp;
	int comparison;
	int offset;

	type = get_type(expr);

	offset = handle_offset_subtraction(expr);
	if (offset >= 0) {
		tmp.type = type;
		tmp.value = offset;

		return alloc_rl(tmp, tmp);
	}

	comparison = get_comparison(expr->left, expr->right);

	left_orig = _get_rl(expr->left, implied, recurse_cnt);
	left_rl = cast_rl(type, left_orig);
	right_orig = _get_rl(expr->right, implied, recurse_cnt);
	right_rl = cast_rl(type, right_orig);

	if ((!left_rl || !right_rl) &&
	    (implied == RL_EXACT || implied == RL_HARD || implied == RL_FUZZY))
		return NULL;

	if (!left_rl)
		left_rl = alloc_whole_rl(type);
	if (!right_rl)
		right_rl = alloc_whole_rl(type);

	/* negative values complicate everything fix this later */
	if (sval_is_negative(rl_min(right_rl)))
		return NULL;
	max = rl_max(left_rl);
	min = sval_type_min(type);

	switch (comparison) {
	case '>':
	case SPECIAL_UNSIGNED_GT:
		min = sval_type_val(type, 1);
		max = rl_max(left_rl);
		break;
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		min = sval_type_val(type, 0);
		max = rl_max(left_rl);
		break;
	case SPECIAL_EQUAL:
		min = sval_type_val(type, 0);
		max = sval_type_val(type, 0);
		break;
	case '<':
	case SPECIAL_UNSIGNED_LT:
		max = sval_type_val(type, -1);
		break;
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		max = sval_type_val(type, 0);
		break;
	default:
		if (!left_orig || !right_orig)
			return NULL;
		return rl_binop(left_rl, '-', right_rl);
	}

	if (!sval_binop_overflows(rl_min(left_rl), '-', rl_max(right_rl))) {
		tmp = sval_binop(rl_min(left_rl), '-', rl_max(right_rl));
		if (sval_cmp(tmp, min) > 0)
			min = tmp;
	}

	if (!sval_is_max(rl_max(left_rl))) {
		tmp = sval_binop(rl_max(left_rl), '-', rl_min(right_rl));
		if (sval_cmp(tmp, max) < 0)
			max = tmp;
	}

	if (sval_is_min(min) && sval_is_max(max))
		return NULL;

	return cast_rl(type, alloc_rl(min, max));
}

static struct range_list *handle_mod_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	sval_t left, right, sval;

	if (implied == RL_EXACT) {
		if (!get_implied_value(expr->right, &right))
			return NULL;
		if (!get_implied_value(expr->left, &left))
			return NULL;
		sval = sval_binop(left, '%', right);
		return alloc_rl(sval, sval);
	}
	/* if we can't figure out the right side it's probably hopeless */
	if (!get_implied_value_internal(expr->right, &right, recurse_cnt))
		return NULL;

	right = sval_cast(get_type(expr), right);
	right.value--;

	rl = _get_rl(expr->left, implied, recurse_cnt);
	if (rl && rl_max(rl).uvalue < right.uvalue)
		right.uvalue = rl_max(rl).uvalue;

	return alloc_rl(sval_cast(right.type, zero), right);
}

static sval_t sval_lowest_set_bit(sval_t sval)
{
	int i;
	int found = 0;

	for (i = 0; i < 64; i++) {
		if (sval.uvalue & 1ULL << i) {
			if (!found++)
				continue;
			sval.uvalue &= ~(1ULL << i);
		}
	}
	return sval;
}

static struct range_list *handle_bitwise_AND(struct expression *expr, int implied, int *recurse_cnt)
{
	struct symbol *type;
	struct range_list *left_rl, *right_rl;
	sval_t known;
	int new_recurse;

	if (implied != RL_IMPLIED && implied != RL_ABSOLUTE && implied != RL_REAL_ABSOLUTE)
		return NULL;

	type = get_type(expr);

	if (get_implied_value_internal(expr->left, &known, recurse_cnt)) {
		sval_t min;

		min = sval_lowest_set_bit(known);
		left_rl = alloc_rl(min, known);
		left_rl = cast_rl(type, left_rl);
		add_range(&left_rl, sval_type_val(type, 0), sval_type_val(type, 0));
	} else {
		left_rl = _get_rl(expr->left, implied, recurse_cnt);
		if (left_rl) {
			left_rl = cast_rl(type, left_rl);
			left_rl = alloc_rl(sval_type_val(type, 0), rl_max(left_rl));
		} else {
			if (implied == RL_HARD)
				return NULL;
			left_rl = alloc_whole_rl(type);
		}
	}

	new_recurse = *recurse_cnt;
	if (*recurse_cnt >= 200)
		new_recurse = 100;  /* Let's try super hard to get the mask */
	if (get_implied_value_internal(expr->right, &known, &new_recurse)) {
		sval_t min, left_max, mod;

		*recurse_cnt = new_recurse;

		min = sval_lowest_set_bit(known);
		right_rl = alloc_rl(min, known);
		right_rl = cast_rl(type, right_rl);
		add_range(&right_rl, sval_type_val(type, 0), sval_type_val(type, 0));

		if (min.value != 0) {
			left_max = rl_max(left_rl);
			mod = sval_binop(left_max, '%', min);
			if (mod.value) {
				left_max = sval_binop(left_max, '-', mod);
				left_max.value++;
				if (left_max.value > 0 && sval_cmp(left_max, rl_max(left_rl)) < 0)
					left_rl = remove_range(left_rl, left_max, rl_max(left_rl));
			}
		}
	} else {
		right_rl = _get_rl(expr->right, implied, recurse_cnt);
		if (right_rl) {
			right_rl = cast_rl(type, right_rl);
			right_rl = alloc_rl(sval_type_val(type, 0), rl_max(right_rl));
		} else {
			if (implied == RL_HARD)
				return NULL;
			right_rl = alloc_whole_rl(type);
		}
	}

	return rl_intersection(left_rl, right_rl);
}

static struct range_list *use_rl_binop(struct expression *expr, int implied, int *recurse_cnt)
{
	struct symbol *type;
	struct range_list *left_rl, *right_rl;

	if (implied != RL_IMPLIED && implied != RL_ABSOLUTE && implied != RL_REAL_ABSOLUTE)
		return NULL;

	type = get_type(expr);

	get_absolute_rl_internal(expr->left, &left_rl, recurse_cnt);
	get_absolute_rl_internal(expr->right, &right_rl, recurse_cnt);
	left_rl = cast_rl(type, left_rl);
	right_rl = cast_rl(type, right_rl);
	if (!left_rl || !right_rl)
		return NULL;

	return rl_binop(left_rl, expr->op, right_rl);
}

static struct range_list *handle_right_shift(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *left_rl;
	sval_t right;
	sval_t min, max;

	if (implied == RL_EXACT || implied == RL_HARD)
		return NULL;

	left_rl = _get_rl(expr->left, implied, recurse_cnt);
	if (left_rl) {
		max = rl_max(left_rl);
		min = rl_min(left_rl);
	} else {
		if (implied == RL_FUZZY)
			return NULL;
		max = sval_type_max(get_type(expr->left));
		min = sval_type_val(get_type(expr->left), 0);
	}

	if (get_implied_value_internal(expr->right, &right, recurse_cnt)) {
		min = sval_binop(min, SPECIAL_RIGHTSHIFT, right);
		max = sval_binop(max, SPECIAL_RIGHTSHIFT, right);
	} else if (!sval_is_negative(min)) {
		min.value = 0;
		max = sval_type_max(max.type);
	} else {
		return NULL;
	}

	return alloc_rl(min, max);
}

static struct range_list *handle_left_shift(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *left_rl, *res;
	sval_t right;
	sval_t min, max;
	int add_zero = 0;

	if (implied == RL_EXACT || implied == RL_HARD)
		return NULL;
	/* this is hopeless without the right side */
	if (!get_implied_value_internal(expr->right, &right, recurse_cnt))
		return NULL;
	left_rl = _get_rl(expr->left, implied, recurse_cnt);
	if (left_rl) {
		max = rl_max(left_rl);
		min = rl_min(left_rl);
		if (min.value == 0) {
			min.value = 1;
			add_zero = 1;
		}
	} else {
		if (implied == RL_FUZZY)
			return NULL;
		max = sval_type_max(get_type(expr->left));
		min = sval_type_val(get_type(expr->left), 1);
		add_zero = 1;
	}

	max = sval_binop(max, SPECIAL_LEFTSHIFT, right);
	min = sval_binop(min, SPECIAL_LEFTSHIFT, right);
	res = alloc_rl(min, max);
	if (add_zero)
		res = rl_union(res, rl_zero());
	return res;
}

static struct range_list *handle_known_binop(struct expression *expr)
{
	sval_t left, right;

	if (!get_value(expr->left, &left))
		return NULL;
	if (!get_value(expr->right, &right))
		return NULL;
	left = sval_binop(left, expr->op, right);
	return alloc_rl(left, left);
}

static int has_actual_ranges(struct range_list *rl)
{
	struct data_range *tmp;

	FOR_EACH_PTR(rl, tmp) {
		if (sval_cmp(tmp->min, tmp->max) != 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static struct range_list *handle_implied_binop(struct range_list *left_rl, int op, struct range_list *right_rl)
{
	struct range_list *res_rl;
	struct data_range *left_drange, *right_drange;
	sval_t res;

	if (!left_rl || !right_rl)
		return NULL;
	if (has_actual_ranges(left_rl))
		return NULL;
	if (has_actual_ranges(right_rl))
		return NULL;

	if (ptr_list_size((struct ptr_list *)left_rl) * ptr_list_size((struct ptr_list *)right_rl) > 20)
		return NULL;

	res_rl = NULL;

	FOR_EACH_PTR(left_rl, left_drange) {
		FOR_EACH_PTR(right_rl, right_drange) {
			if ((op == '%' || op == '/') &&
			    right_drange->min.value == 0)
				return NULL;
			res = sval_binop(left_drange->min, op, right_drange->min);
			add_range(&res_rl, res, res);
		} END_FOR_EACH_PTR(right_drange);
	} END_FOR_EACH_PTR(left_drange);

	return res_rl;
}

static struct range_list *handle_binop_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct smatch_state *state;
	struct symbol *type;
	struct range_list *left_rl, *right_rl, *rl;
	sval_t min, max;

	rl = handle_known_binop(expr);
	if (rl)
		return rl;
	if (implied == RL_EXACT)
		return NULL;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl)
			return rl;
	}

	state = get_extra_state(expr);
	if (state && !is_whole_rl(estate_rl(state))) {
		if (implied != RL_HARD || estate_has_hard_max(state))
			return clone_rl(estate_rl(state));
	}

	type = get_type(expr);
	left_rl = _get_rl(expr->left, implied, recurse_cnt);
	left_rl = cast_rl(type, left_rl);
	right_rl = _get_rl(expr->right, implied, recurse_cnt);
	right_rl = cast_rl(type, right_rl);

	if (!left_rl && !right_rl)
		return NULL;

	rl = handle_implied_binop(left_rl, expr->op, right_rl);
	if (rl)
		return rl;

	switch (expr->op) {
	case '%':
		return handle_mod_rl(expr, implied, recurse_cnt);
	case '&':
		return handle_bitwise_AND(expr, implied, recurse_cnt);
	case '|':
	case '^':
		return use_rl_binop(expr, implied, recurse_cnt);
	case SPECIAL_RIGHTSHIFT:
		return handle_right_shift(expr, implied, recurse_cnt);
	case SPECIAL_LEFTSHIFT:
		return handle_left_shift(expr, implied, recurse_cnt);
	case '-':
		return handle_subtract_rl(expr, implied, recurse_cnt);
	case '/':
		return handle_divide_rl(expr, implied, recurse_cnt);
	}

	if (!left_rl || !right_rl)
		return NULL;

	if (sval_binop_overflows(rl_min(left_rl), expr->op, rl_min(right_rl)))
		return NULL;
	if (sval_binop_overflows(rl_max(left_rl), expr->op, rl_max(right_rl)))
		return NULL;

	min = sval_binop(rl_min(left_rl), expr->op, rl_min(right_rl));
	max = sval_binop(rl_max(left_rl), expr->op, rl_max(right_rl));

	return alloc_rl(min, max);
}

static int do_comparison(struct expression *expr)
{
	struct range_list *left_ranges = NULL;
	struct range_list *right_ranges = NULL;
	int poss_true, poss_false;
	struct symbol *type;

	type = get_type(expr);
	get_absolute_rl(expr->left, &left_ranges);
	get_absolute_rl(expr->right, &right_ranges);

	left_ranges = cast_rl(type, left_ranges);
	right_ranges = cast_rl(type, right_ranges);

	poss_true = possibly_true_rl(left_ranges, expr->op, right_ranges);
	poss_false = possibly_false_rl(left_ranges, expr->op, right_ranges);

	if (!poss_true && !poss_false)
		return 0x0;
	if (poss_true && !poss_false)
		return 0x1;
	if (!poss_true && poss_false)
		return 0x2;
	return 0x3;
}

static struct range_list *handle_comparison_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	sval_t left, right;
	int res;

	if (expr->op == SPECIAL_EQUAL && expr->left->type == EXPR_TYPE) {
		struct symbol *left, *right;

		left = get_real_base_type(expr->left->symbol);
		right = get_real_base_type(expr->left->symbol);
		if (left == right)
			return rl_one();
		return rl_zero();
	}

	if (get_value(expr->left, &left) && get_value(expr->right, &right)) {
		struct data_range tmp_left, tmp_right;

		tmp_left.min = left;
		tmp_left.max = left;
		tmp_right.min = right;
		tmp_right.max = right;
		if (true_comparison_range(&tmp_left, expr->op, &tmp_right))
			return rl_one();
		return rl_zero();
	}

	if (implied == RL_EXACT)
		return NULL;

	res = do_comparison(expr);
	if (res == 1)
		return rl_one();
	if (res == 2)
		return rl_zero();

	return alloc_rl(zero, one);
}

static struct range_list *handle_logical_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	sval_t left, right;
	int left_known = 0;
	int right_known = 0;

	if (implied == RL_EXACT) {
		if (get_value(expr->left, &left))
			left_known = 1;
		if (get_value(expr->right, &right))
			right_known = 1;
	} else {
		if (get_implied_value_internal(expr->left, &left, recurse_cnt))
			left_known = 1;
		if (get_implied_value_internal(expr->right, &right, recurse_cnt))
			right_known = 1;
	}

	switch (expr->op) {
	case SPECIAL_LOGICAL_OR:
		if (left_known && left.value)
			return rl_one();
		if (right_known && right.value)
			return rl_one();
		if (left_known && right_known)
			return rl_zero();
		break;
	case SPECIAL_LOGICAL_AND:
		if (left_known && right_known) {
			if (left.value && right.value)
				return rl_one();
			return rl_zero();
		}
		break;
	default:
		return NULL;
	}

	if (implied == RL_EXACT)
		return NULL;

	return alloc_rl(zero, one);
}

static struct range_list *handle_conditional_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct expression *cond_true;
	struct range_list *true_rl, *false_rl;
	struct symbol *type;
	int final_pass_orig = final_pass;

	cond_true = expr->cond_true;
	if (!cond_true)
		cond_true = expr->conditional;

	if (known_condition_true(expr->conditional))
		return _get_rl(cond_true, implied, recurse_cnt);
	if (known_condition_false(expr->conditional))
		return _get_rl(expr->cond_false, implied, recurse_cnt);

	if (implied == RL_EXACT)
		return NULL;

	if (implied_condition_true(expr->conditional))
		return _get_rl(cond_true, implied, recurse_cnt);
	if (implied_condition_false(expr->conditional))
		return _get_rl(expr->cond_false, implied, recurse_cnt);


	/* this becomes a problem with deeply nested conditional statements */
	if (low_on_memory())
		return NULL;

	type = get_type(expr);

	__push_fake_cur_stree();
	final_pass = 0;
	__split_whole_condition(expr->conditional);
	true_rl = _get_rl(cond_true, implied, recurse_cnt);
	__push_true_states();
	__use_false_states();
	false_rl = _get_rl(expr->cond_false, implied, recurse_cnt);
	__merge_true_states();
	__free_fake_cur_stree();
	final_pass = final_pass_orig;

	if (!true_rl || !false_rl)
		return NULL;
	true_rl = cast_rl(type, true_rl);
	false_rl = cast_rl(type, false_rl);

	return rl_union(true_rl, false_rl);
}

static int get_fuzzy_max_helper(struct expression *expr, sval_t *max)
{
	struct smatch_state *state;
	sval_t sval;

	if (get_hard_max(expr, &sval)) {
		*max = sval;
		return 1;
	}

	state = get_extra_state(expr);
	if (!state || !estate_has_fuzzy_max(state))
		return 0;
	*max = sval_cast(get_type(expr), estate_get_fuzzy_max(state));
	return 1;
}

static int get_fuzzy_min_helper(struct expression *expr, sval_t *min)
{
	struct smatch_state *state;
	sval_t sval;

	state = get_extra_state(expr);
	if (!state || !estate_rl(state))
		return 0;

	sval = estate_min(state);
	if (sval_is_negative(sval) && sval_is_min(sval))
		return 0;

	if (sval_is_max(sval))
		return 0;

	*min = sval_cast(get_type(expr), sval);
	return 1;
}

int get_const_value(struct expression *expr, sval_t *sval)
{
	struct symbol *sym;
	sval_t right;

	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	sym = expr->symbol;
	if (!(sym->ctype.modifiers & MOD_CONST))
		return 0;
	if (get_value(sym->initializer, &right)) {
		*sval = sval_cast(get_type(expr), right);
		return 1;
	}
	return 0;
}

struct range_list *var_to_absolute_rl(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;

	state = get_extra_state(expr);
	if (!state || is_whole_rl(estate_rl(state))) {
		state = get_real_absolute_state(expr);
		if (state && state->data && !estate_is_whole(state))
			return clone_rl(estate_rl(state));
		if (get_local_rl(expr, &rl) && !is_whole_rl(rl))
			return rl;
		if (get_mtag_rl(expr, &rl))
			return rl;
		if (get_db_type_rl(expr, &rl) && !is_whole_rl(rl))
			return rl;
		return alloc_whole_rl(get_type(expr));
	}
	/* err on the side of saying things are possible */
	if (!estate_rl(state))
		return alloc_whole_rl(get_type(expr));
	return clone_rl(estate_rl(state));
}

static struct range_list *handle_variable(struct expression *expr, int implied, int *recurse_cnt)
{
	struct smatch_state *state;
	struct range_list *rl;
	sval_t sval, min, max;
	struct symbol *type;

	if (get_const_value(expr, &sval))
		return alloc_rl(sval, sval);

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (!rl)
			return var_to_absolute_rl(expr);
		return rl;
	}

	if (implied == RL_EXACT)
		return NULL;

	if (get_mtag_sval(expr, &sval))
		return alloc_rl(sval, sval);

	type = get_type(expr);
	if (type && type->type == SYM_FN)
		return alloc_rl(fn_ptr_min, fn_ptr_max);

	switch (implied) {
	case RL_HARD:
	case RL_IMPLIED:
	case RL_ABSOLUTE:
		state = get_extra_state(expr);
		if (!state || !state->data) {
			if (implied == RL_HARD)
				return NULL;
			if (get_local_rl(expr, &rl))
				return rl;
			if (get_mtag_rl(expr, &rl))
				return rl;
			if (get_db_type_rl(expr, &rl))
				return rl;
			if (is_array(expr) && get_array_rl(expr, &rl))
				return rl;
			return NULL;
		}
		if (implied == RL_HARD && !estate_has_hard_max(state))
			return NULL;
		return clone_rl(estate_rl(state));
	case RL_REAL_ABSOLUTE: {
		struct smatch_state *abs_state;

		state = get_extra_state(expr);
		abs_state = get_real_absolute_state(expr);

		if (estate_rl(state) && estate_rl(abs_state)) {
			return clone_rl(rl_intersection(estate_rl(state),
							estate_rl(abs_state)));
		} else if (estate_rl(state)) {
			return clone_rl(estate_rl(state));
		} else if (estate_is_empty(state)) {
			/*
			 * FIXME: we don't handle empty extra states correctly.
			 *
			 * The real abs rl is supposed to be filtered by the
			 * extra state if there is one.  We don't bother keeping
			 * the abs state in sync all the time because we know it
			 * will be filtered later.
			 *
			 * It's not totally obvious to me how they should be
			 * handled.  Perhaps we should take the whole rl and
			 * filter by the imaginary states.  Perhaps we should
			 * just go with the empty state.
			 *
			 * Anyway what we currently do is return NULL here and
			 * that gets translated into the whole range in
			 * get_real_absolute_rl().
			 *
			 */
			return NULL;
		} else if (estate_rl(abs_state)) {
			return clone_rl(estate_rl(abs_state));
		}

		if (get_local_rl(expr, &rl))
			return rl;
		if (get_mtag_rl(expr, &rl))
			return rl;
		if (get_db_type_rl(expr, &rl))
			return rl;
		if (is_array(expr) && get_array_rl(expr, &rl))
			return rl;
		return NULL;
	}
	case RL_FUZZY:
		if (!get_fuzzy_min_helper(expr, &min))
			min = sval_type_min(get_type(expr));
		if (!get_fuzzy_max_helper(expr, &max))
			return NULL;
		/* fuzzy ranges are often inverted */
		if (sval_cmp(min, max) > 0) {
			sval = min;
			min = max;
			max = sval;
		}
		return alloc_rl(min, max);
	}
	return NULL;
}

static sval_t handle_sizeof(struct expression *expr)
{
	struct symbol *sym;
	sval_t ret;

	ret = sval_blank(expr);
	sym = expr->cast_type;
	if (!sym) {
		sym = evaluate_expression(expr->cast_expression);
		if (!sym) {
			__silence_warnings_for_stmt = true;
			sym = &int_ctype;
		}
#if 0
		/*
		 * Expressions of restricted types will possibly get
		 * promoted - check that here.  I'm not sure how this works,
		 * the problem is that sizeof(le16) shouldn't be promoted and
		 * the original code did that...  Let's if zero this out and
		 * see what breaks.
		 */

		if (is_restricted_type(sym)) {
			if (type_bits(sym) < bits_in_int)
				sym = &int_ctype;
		}
#endif
		if (is_fouled_type(sym))
			sym = &int_ctype;
	}
	examine_symbol_type(sym);

	ret.type = size_t_ctype;
	if (type_bits(sym) <= 0) /* sizeof(void) */ {
		if (get_real_base_type(sym) == &void_ctype)
			ret.value = 1;
		else
			ret.value = 0;
	} else
		ret.value = type_bytes(sym);

	return ret;
}

static struct range_list *handle_strlen(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	struct expression *arg, *tmp;
	sval_t tag;
	sval_t ret = { .type = &ulong_ctype };

	if (implied == RL_EXACT)
		return NULL;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!arg)
		return NULL;
	if (arg->type == EXPR_STRING) {
		ret.value = arg->string->length - 1;
		return alloc_rl(ret, ret);
	}
	if (get_implied_value(arg, &tag) &&
	    (tmp = fake_string_from_mtag(tag.uvalue))) {
		ret.value = tmp->string->length - 1;
		return alloc_rl(ret, ret);
	}

	if (implied == RL_HARD || implied == RL_FUZZY)
		return NULL;

	if (get_implied_return(expr, &rl))
		return rl;

	return NULL;
}

static struct range_list *handle_builtin_constant_p(struct expression *expr, int implied, int *recurse_cnt)
{
	struct expression *arg;
	struct range_list *rl;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 0);
	rl = _get_rl(arg, RL_EXACT, recurse_cnt);
	if (rl_to_sval(rl, &sval))
		return rl_one();
	return rl_zero();
}

static struct range_list *handle__builtin_choose_expr(struct expression *expr, int implied, int *recurse_cnt)
{
	struct expression *const_expr, *expr1, *expr2;
	sval_t sval;

	const_expr = get_argument_from_call_expr(expr->args, 0);
	expr1 = get_argument_from_call_expr(expr->args, 1);
	expr2 = get_argument_from_call_expr(expr->args, 2);

	if (!get_value(const_expr, &sval) || !expr1 || !expr2)
		return NULL;
	if (sval.value)
		return _get_rl(expr1, implied, recurse_cnt);
	return _get_rl(expr2, implied, recurse_cnt);
}

static struct range_list *handle_call_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;

	if (sym_name_is("__builtin_constant_p", expr->fn))
		return handle_builtin_constant_p(expr, implied, recurse_cnt);

	if (sym_name_is("__builtin_choose_expr", expr->fn))
		return handle__builtin_choose_expr(expr, implied, recurse_cnt);

	if (sym_name_is("__builtin_expect", expr->fn) ||
	    sym_name_is("__builtin_bswap16", expr->fn) ||
	    sym_name_is("__builtin_bswap32", expr->fn) ||
	    sym_name_is("__builtin_bswap64", expr->fn)) {
		struct expression *arg;

		arg = get_argument_from_call_expr(expr->args, 0);
		return _get_rl(arg, implied, recurse_cnt);
	}

	if (sym_name_is("strlen", expr->fn))
		return handle_strlen(expr, implied, recurse_cnt);

	if (implied == RL_EXACT || implied == RL_HARD || implied == RL_FUZZY)
		return NULL;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl)
			return rl;
	}

	if (get_implied_return(expr, &rl))
		return rl;
	return db_return_vals(expr);
}

static struct range_list *handle_cast(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	struct symbol *type;

	type = get_type(expr);
	rl = _get_rl(expr->cast_expression, implied, recurse_cnt);
	if (rl)
		return cast_rl(type, rl);
	if (implied == RL_ABSOLUTE || implied == RL_REAL_ABSOLUTE)
		return alloc_whole_rl(type);
	if (implied == RL_IMPLIED && type &&
	    type_bits(type) > 0 && type_bits(type) < 32)
		return alloc_whole_rl(type);
	return NULL;
}

static struct range_list *_get_rl(struct expression *expr, int implied, int *recurse_cnt)
{
	struct range_list *rl;
	struct symbol *type;
	sval_t sval;

	type = get_type(expr);
	expr = strip_parens(expr);
	if (!expr)
		return NULL;

	if (++(*recurse_cnt) >= 200)
		return NULL;

	switch(expr->type) {
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		rl = handle_cast(expr, implied, recurse_cnt);
		goto out_cast;
	}

	expr = strip_expr(expr);
	if (!expr)
		return NULL;

	switch (expr->type) {
	case EXPR_VALUE:
		sval = sval_from_val(expr, expr->value);
		rl = alloc_rl(sval, sval);
		break;
	case EXPR_PREOP:
		rl = handle_preop_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_POSTOP:
		rl = _get_rl(expr->unop, implied, recurse_cnt);
		break;
	case EXPR_BINOP:
		rl = handle_binop_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_COMPARE:
		rl = handle_comparison_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_LOGICAL:
		rl = handle_logical_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_PTRSIZEOF:
	case EXPR_SIZEOF:
		sval = handle_sizeof(expr);
		rl = alloc_rl(sval, sval);
		break;
	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		rl = handle_conditional_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_CALL:
		rl = handle_call_rl(expr, implied, recurse_cnt);
		break;
	case EXPR_STRING:
		rl = NULL;
		if (get_mtag_sval(expr, &sval))
			rl = alloc_rl(sval, sval);
		break;
	default:
		rl = handle_variable(expr, implied, recurse_cnt);
	}

out_cast:
	if (rl)
		return rl;
	if (type && (implied == RL_ABSOLUTE || implied == RL_REAL_ABSOLUTE))
		return alloc_whole_rl(type);
	return NULL;
}

struct {
	struct expression *expr;
	struct range_list *rl;
} cached_results[24];
static int cache_idx;

void clear_math_cache(void)
{
	memset(cached_results, 0, sizeof(cached_results));
}

/* returns 1 if it can get a value literal or else returns 0 */
int get_value(struct expression *expr, sval_t *sval)
{
	struct range_list *(*orig_custom_fn)(struct expression *expr);
	struct range_list *rl;
	int recurse_cnt = 0;
	sval_t tmp;
	int i;

	/*
	 * This only handles RL_EXACT because other expr statements can be
	 * different at different points.  Like the list iterator, for example.
	 */
	for (i = 0; i < ARRAY_SIZE(cached_results); i++) {
		if (expr == cached_results[i].expr)
			return rl_to_sval(cached_results[i].rl, sval);
	}

	orig_custom_fn = custom_handle_variable;
	custom_handle_variable = NULL;
	rl = _get_rl(expr, RL_EXACT, &recurse_cnt);
	if (!rl_to_sval(rl, &tmp))
		rl = NULL;
	custom_handle_variable = orig_custom_fn;

	cached_results[cache_idx].expr = expr;
	cached_results[cache_idx].rl = rl;
	cache_idx = (cache_idx + 1) % ARRAY_SIZE(cached_results);

	if (!rl)
		return 0;

	*sval = tmp;
	return 1;
}

static int get_implied_value_internal(struct expression *expr, sval_t *sval, int *recurse_cnt)
{
	struct range_list *rl;

	rl =  _get_rl(expr, RL_IMPLIED, recurse_cnt);
	if (!rl_to_sval(rl, sval))
		return 0;
	return 1;
}

int get_implied_value(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_IMPLIED, &recurse_cnt);
	if (!rl_to_sval(rl, sval))
		return 0;
	return 1;
}

int get_implied_min(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_IMPLIED, &recurse_cnt);
	if (!rl)
		return 0;
	*sval = rl_min(rl);
	return 1;
}

int get_implied_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_IMPLIED, &recurse_cnt);
	if (!rl)
		return 0;
	*sval = rl_max(rl);
	return 1;
}

int get_implied_rl(struct expression *expr, struct range_list **rl)
{
	int recurse_cnt = 0;

	*rl = _get_rl(expr, RL_IMPLIED, &recurse_cnt);
	if (*rl)
		return 1;
	return 0;
}

static int get_absolute_rl_internal(struct expression *expr, struct range_list **rl, int *recurse_cnt)
{
	*rl = _get_rl(expr, RL_ABSOLUTE, recurse_cnt);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int get_absolute_rl(struct expression *expr, struct range_list **rl)
{
	int recurse_cnt = 0;

	*rl = _get_rl(expr, RL_ABSOLUTE, &recurse_cnt);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int get_real_absolute_rl(struct expression *expr, struct range_list **rl)
{
	int recurse_cnt = 0;

	*rl = _get_rl(expr, RL_REAL_ABSOLUTE, &recurse_cnt);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int custom_get_absolute_rl(struct expression *expr,
			   struct range_list *(*fn)(struct expression *expr),
			   struct range_list **rl)
{
	int recurse_cnt = 0;

	*rl = NULL;
	custom_handle_variable = fn;
	*rl = _get_rl(expr, RL_REAL_ABSOLUTE, &recurse_cnt);
	custom_handle_variable = NULL;
	return 1;
}

int get_implied_rl_var_sym(const char *var, struct symbol *sym, struct range_list **rl)
{
	struct smatch_state *state;

	state = get_state(SMATCH_EXTRA, var, sym);
	*rl = estate_rl(state);
	if (*rl)
		return 1;
	return 0;
}

int get_hard_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_HARD, &recurse_cnt);
	if (!rl)
		return 0;
	*sval = rl_max(rl);
	return 1;
}

int get_fuzzy_min(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	sval_t tmp;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_FUZZY, &recurse_cnt);
	if (!rl)
		return 0;
	tmp = rl_min(rl);
	if (sval_is_negative(tmp) && sval_is_min(tmp))
		return 0;
	*sval = tmp;
	return 1;
}

int get_fuzzy_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	sval_t max;
	int recurse_cnt = 0;

	rl =  _get_rl(expr, RL_FUZZY, &recurse_cnt);
	if (!rl)
		return 0;
	max = rl_max(rl);
	if (max.uvalue > INT_MAX - 10000)
		return 0;
	*sval = max;
	return 1;
}

int get_absolute_min(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	struct symbol *type;
	int recurse_cnt = 0;

	type = get_type(expr);
	if (!type)
		type = &llong_ctype;  // FIXME: this is wrong but places assume get type can't fail.
	rl = _get_rl(expr, RL_REAL_ABSOLUTE, &recurse_cnt);
	if (rl)
		*sval = rl_min(rl);
	else
		*sval = sval_type_min(type);

	if (sval_cmp(*sval, sval_type_min(type)) < 0)
		*sval = sval_type_min(type);
	return 1;
}

int get_absolute_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	struct symbol *type;
	int recurse_cnt = 0;

	type = get_type(expr);
	if (!type)
		type = &llong_ctype;
	rl = _get_rl(expr, RL_REAL_ABSOLUTE, &recurse_cnt);
	if (rl)
		*sval = rl_max(rl);
	else
		*sval = sval_type_max(type);

	if (sval_cmp(sval_type_max(type), *sval) < 0)
		*sval = sval_type_max(type);
	return 1;
}

int known_condition_true(struct expression *expr)
{
	sval_t tmp;

	if (!expr)
		return 0;

	if (get_value(expr, &tmp) && tmp.value)
		return 1;

	return 0;
}

int known_condition_false(struct expression *expr)
{
	if (!expr)
		return 0;

	if (is_zero(expr))
		return 1;

	return 0;
}

int implied_condition_true(struct expression *expr)
{
	sval_t tmp;

	if (!expr)
		return 0;

	if (known_condition_true(expr))
		return 1;
	if (get_implied_value(expr, &tmp) && tmp.value)
		return 1;

	if (expr->type == EXPR_POSTOP)
		return implied_condition_true(expr->unop);

	if (expr->type == EXPR_PREOP && expr->op == SPECIAL_DECREMENT)
		return implied_not_equal(expr->unop, 1);
	if (expr->type == EXPR_PREOP && expr->op == SPECIAL_INCREMENT)
		return implied_not_equal(expr->unop, -1);

	expr = strip_expr(expr);
	switch (expr->type) {
	case EXPR_COMPARE:
		if (do_comparison(expr) == 1)
			return 1;
		break;
	case EXPR_PREOP:
		if (expr->op == '!') {
			if (implied_condition_false(expr->unop))
				return 1;
			break;
		}
		break;
	default:
		if (implied_not_equal(expr, 0) == 1)
			return 1;
		break;
	}
	return 0;
}

int implied_condition_false(struct expression *expr)
{
	struct expression *tmp;
	sval_t sval;

	if (!expr)
		return 0;

	if (known_condition_false(expr))
		return 1;

	switch (expr->type) {
	case EXPR_COMPARE:
		if (do_comparison(expr) == 2)
			return 1;
	case EXPR_PREOP:
		if (expr->op == '!') {
			if (implied_condition_true(expr->unop))
				return 1;
			break;
		}
		tmp = strip_expr(expr);
		if (tmp != expr)
			return implied_condition_false(tmp);
		break;
	default:
		if (get_implied_value(expr, &sval) && sval.value == 0)
			return 1;
		break;
	}
	return 0;
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

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

static bool get_rl_sval(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *sval_res);
static bool get_rl_internal(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res);
static bool handle_variable(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval);
static struct range_list *(*custom_handle_variable)(struct expression *expr);

static bool get_implied_value_internal(struct expression *expr, int *recurse_cnt, sval_t *res_sval);
static int get_absolute_rl_internal(struct expression *expr, struct range_list **rl, int *recurse_cnt);

static sval_t zero  = {.type = &int_ctype, {.value = 0} };
static sval_t one   = {.type = &int_ctype, {.value = 1} };

static int fast_math_only;

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

static bool last_stmt_rl(struct statement *stmt, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct expression *expr;

	if (!stmt)
		return false;

	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt->type == STMT_LABEL) {
		if (stmt->label_statement &&
		    stmt->label_statement->type == STMT_EXPRESSION)
			expr = stmt->label_statement->expression;
		else
			return false;
	} else if (stmt->type == STMT_EXPRESSION) {
		expr = stmt->expression;
	} else {
		return false;
	}
	return get_rl_sval(expr, implied, recurse_cnt, res, res_sval);
}

static bool handle_expression_statement_rl(struct expression *expr, int implied,
		int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	return last_stmt_rl(get_expression_statement(expr), implied, recurse_cnt, res, res_sval);
}

static bool handle_address(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct range_list *rl;
	static int recursed;
	sval_t sval;

	if (recursed > 10)
		return false;
	if (implied == RL_EXACT)
		return false;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl) {
			*res = rl;
			return true;
		}
	}

	recursed++;
	if (get_mtag_sval(expr, &sval)) {
		recursed--;
		*res_sval = sval;
		return true;
	}

	if (get_address_rl(expr, res)) {
		recursed--;
		return true;
	}
	recursed--;
	return 0;
}

static bool handle_ampersand_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	return handle_address(expr, implied, recurse_cnt, res, res_sval);
}

static bool handle_negate_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	if (known_condition_true(expr->unop)) {
		*res_sval = zero;
		return true;
	}
	if (known_condition_false(expr->unop)) {
		*res_sval = one;
		return true;
	}

	if (implied == RL_EXACT)
		return false;

	if (implied_condition_true(expr->unop)) {
		*res_sval = zero;
		return true;
	}
	if (implied_condition_false(expr->unop)) {
		*res_sval = one;
		return true;
	}

	*res = alloc_rl(zero, one);
	return true;
}

static bool handle_bitwise_negate(struct expression *expr, int implied, int *recurse_cnt, sval_t *res_sval)
{
	struct range_list *rl;
	sval_t sval = {};

	if (!get_rl_sval(expr->unop, implied, recurse_cnt, &rl, &sval))
		return false;
	if (!sval.type && !rl_to_sval(rl, &sval))
		return false;
	sval = sval_preop(sval, '~');
	sval_cast(get_type(expr->unop), sval);
	*res_sval = sval;
	return true;
}

static bool untrusted_type_min(struct expression *expr)
{
	struct range_list *rl;

	rl = var_user_rl(expr);
	return rl && sval_is_min(rl_min(rl));
}

static bool handle_minus_preop(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct range_list *rl;
	struct range_list *ret = NULL;
	struct symbol *type;
	sval_t neg_one = { 0 };
	sval_t zero = { 0 };
	sval_t sval = {};

	neg_one.value = -1;
	zero.value = 0;

	if (!get_rl_sval(expr->unop, implied, recurse_cnt, &rl, &sval))
		return false;
	if (sval.type) {
		*res_sval = sval_preop(sval, '-');
		return true;
	}
	/*
	 * One complication is that -INT_MIN is still INT_MIN because of integer
	 * overflows...  But how many times do we set a time out to INT_MIN?
	 * So normally when we call abs() then it does return a positive value.
	 *
	 */
	type = rl_type(rl);
	neg_one.type = zero.type = type;

	if (sval_is_negative(rl_min(rl))) {
		struct range_list *neg;
		struct data_range *drange;
		sval_t new_min, new_max;

		neg = alloc_rl(sval_type_min(type), neg_one);
		neg = rl_intersection(rl, neg);

		if (sval_is_min(rl_min(neg)) && !sval_is_min(rl_max(neg)))
			neg = remove_range(neg, sval_type_min(type), sval_type_min(type));

		FOR_EACH_PTR(neg, drange) {
			new_min = drange->max;
			new_min.value = -new_min.value;
			new_max = drange->min;
			new_max.value = -new_max.value;
			add_range(&ret, new_min, new_max);
		} END_FOR_EACH_PTR(drange);

		if (untrusted_type_min(expr))
			add_range(&ret, sval_type_min(type), sval_type_min(type));
	}

	if (!sval_is_negative(rl_max(rl))) {
		struct range_list *pos;
		struct data_range *drange;
		sval_t new_min, new_max;

		pos = alloc_rl(zero, sval_type_max(type));
		pos = rl_intersection(rl, pos);

		FOR_EACH_PTR(pos, drange) {
			new_min = drange->max;
			new_min.value = -new_min.value;
			new_max = drange->min;
			new_max.value = -new_max.value;
			add_range(&ret, new_min, new_max);
		} END_FOR_EACH_PTR(drange);
	}

	*res = ret;
	return true;
}

static bool handle_preop_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	switch (expr->op) {
	case '&':
		return handle_ampersand_rl(expr, implied, recurse_cnt, res, res_sval);
	case '!':
		return handle_negate_rl(expr, implied, recurse_cnt, res, res_sval);
	case '~':
		return handle_bitwise_negate(expr, implied, recurse_cnt, res_sval);
	case '-':
		return handle_minus_preop(expr, implied, recurse_cnt, res, res_sval);
	case '*':
		return handle_variable(expr, implied, recurse_cnt, res, res_sval);
	case '(':
		return handle_expression_statement_rl(expr, implied, recurse_cnt, res, res_sval);
	default:
		return false;
	}
}

static bool handle_divide_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct range_list *left_rl = NULL;
	struct range_list *right_rl = NULL;
	struct symbol *type;

	type = get_type(expr);

	get_rl_internal(expr->left, implied, recurse_cnt, &left_rl);
	left_rl = cast_rl(type, left_rl);
	get_rl_internal(expr->right, implied, recurse_cnt, &right_rl);
	right_rl = cast_rl(type, right_rl);

	if (!left_rl || !right_rl)
		return false;

	if (implied != RL_REAL_ABSOLUTE) {
		if (is_whole_rl(left_rl) || is_whole_rl(right_rl))
			return false;
	}

	*res = rl_binop(left_rl, '/', right_rl);
	return true;
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

static bool handle_subtract_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct symbol *type;
	struct range_list *left_orig, *right_orig;
	struct range_list *left_rl, *right_rl;
	sval_t min, max, tmp;
	int comparison;
	int offset;

	type = get_type(expr);

	offset = handle_offset_subtraction(expr);
	if (offset >= 0) {
		tmp.type = type;
		tmp.value = offset;

		*res = alloc_rl(tmp, tmp);
		return true;
	}

	comparison = get_comparison(expr->left, expr->right);

	left_orig = NULL;
	get_rl_internal(expr->left, implied, recurse_cnt, &left_orig);
	left_rl = cast_rl(type, left_orig);
	right_orig = NULL;
	get_rl_internal(expr->right, implied, recurse_cnt, &right_orig);
	right_rl = cast_rl(type, right_orig);

	if ((!left_rl || !right_rl) &&
	    (implied == RL_EXACT || implied == RL_HARD || implied == RL_FUZZY))
		return false;

	if (!left_rl)
		left_rl = alloc_whole_rl(type);
	if (!right_rl)
		right_rl = alloc_whole_rl(type);

	/* negative values complicate everything fix this later */
	if (sval_is_negative(rl_min(right_rl)))
		return false;
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
			return false;
		*res = rl_binop(left_rl, '-', right_rl);
		return true;
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
		return false;

	*res = cast_rl(type, alloc_rl(min, max));
	return true;
}

static bool handle_mod_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct range_list *rl;
	sval_t left, right, sval;

	if (implied == RL_EXACT) {
		if (!get_implied_value(expr->right, &right))
			return false;
		if (!get_implied_value(expr->left, &left))
			return false;
		sval = sval_binop(left, '%', right);
		*res = alloc_rl(sval, sval);
		return true;
	}
	/* if we can't figure out the right side it's probably hopeless */
	if (!get_implied_value_internal(expr->right, recurse_cnt, &right))
		return false;

	right = sval_cast(get_type(expr), right);
	right.value--;

	if (get_rl_internal(expr->left, implied, recurse_cnt, &rl) && rl &&
	    rl_max(rl).uvalue < right.uvalue)
		right.uvalue = rl_max(rl).uvalue;

	*res = alloc_rl(sval_cast(right.type, zero), right);
	return true;
}

static bool handle_bitwise_AND(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct symbol *type;
	struct range_list *left_rl, *right_rl;
	int new_recurse;

	if (implied != RL_IMPLIED && implied != RL_ABSOLUTE && implied != RL_REAL_ABSOLUTE)
		return false;

	type = get_type(expr);

	if (!get_rl_internal(expr->left, implied, recurse_cnt, &left_rl))
		left_rl = alloc_whole_rl(type);
	left_rl = cast_rl(type, left_rl);

	new_recurse = *recurse_cnt;
	if (*recurse_cnt >= 200)
		new_recurse = 100;  /* Let's try super hard to get the mask */
	if (!get_rl_internal(expr->right, implied, &new_recurse, &right_rl))
		right_rl = alloc_whole_rl(type);
	right_rl = cast_rl(type, right_rl);
	*recurse_cnt = new_recurse;

	*res = rl_binop(left_rl, '&', right_rl);
	return true;
}

static bool use_rl_binop(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct symbol *type;
	struct range_list *left_rl, *right_rl;

	if (implied != RL_IMPLIED && implied != RL_ABSOLUTE && implied != RL_REAL_ABSOLUTE)
		return false;

	type = get_type(expr);

	get_absolute_rl_internal(expr->left, &left_rl, recurse_cnt);
	get_absolute_rl_internal(expr->right, &right_rl, recurse_cnt);
	left_rl = cast_rl(type, left_rl);
	right_rl = cast_rl(type, right_rl);
	if (!left_rl || !right_rl)
		return false;

	*res = rl_binop(left_rl, expr->op, right_rl);
	return true;
}

static bool handle_right_shift(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct range_list *left_rl, *right_rl;
	sval_t min, max;

	if (implied == RL_EXACT || implied == RL_HARD)
		return false;

	if (get_rl_internal(expr->left, implied, recurse_cnt, &left_rl)) {
		max = rl_max(left_rl);
		min = rl_min(left_rl);
	} else {
		if (implied == RL_FUZZY)
			return false;
		max = sval_type_max(get_type(expr->left));
		min = sval_type_val(get_type(expr->left), 0);
	}

	if (get_rl_internal(expr->right, implied, recurse_cnt, &right_rl) &&
	    !sval_is_negative(rl_min(right_rl))) {
		min = sval_binop(min, SPECIAL_RIGHTSHIFT, rl_max(right_rl));
		max = sval_binop(max, SPECIAL_RIGHTSHIFT, rl_min(right_rl));
	} else if (!sval_is_negative(min)) {
		min.value = 0;
		max = sval_type_max(max.type);
	} else {
		return false;
	}

	*res = alloc_rl(min, max);
	return true;
}

static bool handle_left_shift(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct range_list *left_rl, *rl;
	sval_t right;

	if (implied == RL_EXACT || implied == RL_HARD)
		return false;
	/* this is hopeless without the right side */
	if (!get_implied_value_internal(expr->right, recurse_cnt, &right))
		return false;
	if (!get_rl_internal(expr->left, implied, recurse_cnt, &left_rl)) {
		if (implied == RL_FUZZY)
			return false;
		left_rl = alloc_whole_rl(get_type(expr->left));
	}

	rl = rl_binop(left_rl, SPECIAL_LEFTSHIFT, alloc_rl(right, right));
	if (!rl)
		return false;
	*res = rl;
	return true;
}

static bool handle_known_binop(struct expression *expr, sval_t *res)
{
	sval_t left, right;

	if (!get_value(expr->left, &left))
		return false;
	if (!get_value(expr->right, &right))
		return false;
	*res = sval_binop(left, expr->op, right);
	return true;
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

static bool handle_binop_rl_helper(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct symbol *type;
	struct range_list *left_rl = NULL;
	struct range_list *right_rl = NULL;
	struct range_list *rl;
	sval_t min, max;

	type = get_promoted_type(get_type(expr->left), get_type(expr->right));
	get_rl_internal(expr->left, implied, recurse_cnt, &left_rl);
	left_rl = cast_rl(type, left_rl);
	get_rl_internal(expr->right, implied, recurse_cnt, &right_rl);
	right_rl = cast_rl(type, right_rl);
	if (!left_rl && !right_rl)
		return false;

	rl = handle_implied_binop(left_rl, expr->op, right_rl);
	if (rl) {
		*res = rl;
		return true;
	}

	switch (expr->op) {
	case '%':
		return handle_mod_rl(expr, implied, recurse_cnt, res);
	case '&':
		return handle_bitwise_AND(expr, implied, recurse_cnt, res);
	case '|':
	case '^':
		return use_rl_binop(expr, implied, recurse_cnt, res);
	case SPECIAL_RIGHTSHIFT:
		return handle_right_shift(expr, implied, recurse_cnt, res);
	case SPECIAL_LEFTSHIFT:
		return handle_left_shift(expr, implied, recurse_cnt, res);
	case '-':
		return handle_subtract_rl(expr, implied, recurse_cnt, res);
	case '/':
		return handle_divide_rl(expr, implied, recurse_cnt, res);
	}

	if (!left_rl || !right_rl)
		return false;

	if (sval_binop_overflows(rl_min(left_rl), expr->op, rl_min(right_rl)))
		return false;
	if (sval_binop_overflows(rl_max(left_rl), expr->op, rl_max(right_rl)))
		return false;

	min = sval_binop(rl_min(left_rl), expr->op, rl_min(right_rl));
	max = sval_binop(rl_max(left_rl), expr->op, rl_max(right_rl));

	*res = alloc_rl(min, max);
	return true;

}

static bool handle_binop_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct smatch_state *state;
	struct range_list *rl;
	sval_t val;

	if (handle_known_binop(expr, &val)) {
		*res_sval = val;
		return true;
	}
	if (implied == RL_EXACT)
		return false;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl) {
			*res = rl;
			return true;
		}
	}

	state = get_extra_state(expr);
	if (state && !is_whole_rl(estate_rl(state))) {
		if (implied != RL_HARD || estate_has_hard_max(state)) {
			*res = clone_rl(estate_rl(state));
			return true;
		}
	}

	return handle_binop_rl_helper(expr, implied, recurse_cnt, res, res_sval);
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

static bool handle_comparison_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	sval_t left, right;
	int cmp;

	if (expr->op == SPECIAL_EQUAL && expr->left->type == EXPR_TYPE) {
		struct symbol *left, *right;

		if (expr->right->type != EXPR_TYPE)
			return false;

		left = get_real_base_type(expr->left->symbol);
		right = get_real_base_type(expr->right->symbol);
		if (type_bits(left) == type_bits(right) &&
		    type_positive_bits(left) == type_positive_bits(right))
			*res_sval = one;
		else
			*res_sval = zero;
		return true;
	}

	if (get_value(expr->left, &left) && get_value(expr->right, &right)) {
		struct data_range tmp_left, tmp_right;

		tmp_left.min = left;
		tmp_left.max = left;
		tmp_right.min = right;
		tmp_right.max = right;
		if (true_comparison_range(&tmp_left, expr->op, &tmp_right))
			*res_sval = one;
		else
			*res_sval = zero;
		return true;
	}

	if (implied == RL_EXACT)
		return false;

	cmp = do_comparison(expr);
	if (cmp == 1) {
		*res_sval = one;
		return true;
	}
	if (cmp == 2) {
		*res_sval = zero;
		return true;
	}

	*res = alloc_rl(zero, one);
	return true;
}

static bool handle_logical_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
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
		if (get_implied_value_internal(expr->left, recurse_cnt, &left))
			left_known = 1;
		if (get_implied_value_internal(expr->right, recurse_cnt, &right))
			right_known = 1;
	}

	switch (expr->op) {
	case SPECIAL_LOGICAL_OR:
		if (left_known && left.value)
			goto one;
		if (right_known && right.value)
			goto one;
		if (left_known && right_known)
			goto zero;
		break;
	case SPECIAL_LOGICAL_AND:
		if (left_known && right_known) {
			if (left.value && right.value)
				goto one;
			goto zero;
		}
		break;
	default:
		return false;
	}

	if (implied == RL_EXACT)
		return false;

	*res = alloc_rl(zero, one);
	return true;

zero:
	*res_sval = zero;
	return true;
one:
	*res_sval = one;
	return true;
}

static bool handle_conditional_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct expression *cond_true;
	struct range_list *true_rl, *false_rl;
	struct symbol *type;
	int final_pass_orig = final_pass;

	cond_true = expr->cond_true;
	if (!cond_true)
		cond_true = expr->conditional;

	if (known_condition_true(expr->conditional))
		return get_rl_sval(cond_true, implied, recurse_cnt, res, res_sval);
	if (known_condition_false(expr->conditional))
		return get_rl_sval(expr->cond_false, implied, recurse_cnt, res, res_sval);

	if (implied == RL_EXACT)
		return false;

	if (implied_condition_true(expr->conditional))
		return get_rl_sval(cond_true, implied, recurse_cnt, res, res_sval);
	if (implied_condition_false(expr->conditional))
		return get_rl_sval(expr->cond_false, implied, recurse_cnt, res, res_sval);

	/* this becomes a problem with deeply nested conditional statements */
	if (fast_math_only || low_on_memory())
		return false;

	type = get_type(expr);

	__push_fake_cur_stree();
	final_pass = 0;
	__split_whole_condition(expr->conditional);
	true_rl = NULL;
	get_rl_internal(cond_true, implied, recurse_cnt, &true_rl);
	__push_true_states();
	__use_false_states();
	false_rl = NULL;
	get_rl_internal(expr->cond_false, implied, recurse_cnt, &false_rl);
	__merge_true_states();
	__free_fake_cur_stree();
	final_pass = final_pass_orig;

	if (!true_rl || !false_rl)
		return false;
	true_rl = cast_rl(type, true_rl);
	false_rl = cast_rl(type, false_rl);

	*res = rl_union(true_rl, false_rl);
	return true;
}

static bool get_fuzzy_max_helper(struct expression *expr, sval_t *max)
{
	struct smatch_state *state;
	sval_t sval;

	if (get_hard_max(expr, &sval)) {
		*max = sval;
		return true;
	}

	state = get_extra_state(expr);
	if (!state || !estate_has_fuzzy_max(state))
		return false;
	*max = sval_cast(get_type(expr), estate_get_fuzzy_max(state));
	return true;
}

static bool get_fuzzy_min_helper(struct expression *expr, sval_t *min)
{
	struct smatch_state *state;
	sval_t sval;

	state = get_extra_state(expr);
	if (!state || !estate_rl(state))
		return false;

	sval = estate_min(state);
	if (sval_is_negative(sval) && sval_is_min(sval))
		return false;

	if (sval_is_max(sval))
		return false;

	*min = sval_cast(get_type(expr), sval);
	return true;
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

static bool handle_variable(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct smatch_state *state;
	struct range_list *rl;
	sval_t sval, min, max;
	struct symbol *type;

	if (get_const_value(expr, &sval)) {
		*res_sval = sval;
		return true;
	}

	if (implied == RL_EXACT)
		return false;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl) {
			if (!rl_to_sval(rl, res_sval))
				*res = rl;
		} else {
			*res = var_to_absolute_rl(expr);
		}
		return true;
	}

	if (get_mtag_sval(expr, &sval)) {
		*res_sval = sval;
		return true;
	}

	type = get_type(expr);
	if (type &&
	    (type->type == SYM_ARRAY ||
	     type->type == SYM_FN))
		return handle_address(expr, implied, recurse_cnt, res, res_sval);

	/* FIXME: call rl_to_sval() on the results */

	switch (implied) {
	case RL_HARD:
	case RL_IMPLIED:
	case RL_ABSOLUTE:
		state = get_extra_state(expr);
		if (!state) {
			if (implied == RL_HARD)
				return false;
			if (get_mtag_rl(expr, res))
				return true;
			if (get_db_type_rl(expr, res))
				return true;
			if (is_array(expr) && get_array_rl(expr, res))
				return true;
			return false;
		}
		if (implied == RL_HARD && !estate_has_hard_max(state))
			return false;
		*res = clone_rl(estate_rl(state));
		return true;
	case RL_REAL_ABSOLUTE: {
		struct smatch_state *abs_state;

		state = get_extra_state(expr);
		abs_state = get_real_absolute_state(expr);

		if (estate_rl(state) && estate_rl(abs_state)) {
			*res = clone_rl(rl_intersection(estate_rl(state),
							estate_rl(abs_state)));
			return true;
		} else if (estate_rl(state)) {
			*res = clone_rl(estate_rl(state));
			return true;
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
			return false;
		} else if (estate_rl(abs_state)) {
			*res = clone_rl(estate_rl(abs_state));
			return true;
		}

		if (get_mtag_rl(expr, res))
			return true;
		if (get_db_type_rl(expr, res))
			return true;
		if (is_array(expr) && get_array_rl(expr, res))
			return true;
		return false;
	}
	case RL_FUZZY:
		if (!get_fuzzy_min_helper(expr, &min))
			min = sval_type_min(get_type(expr));
		if (!get_fuzzy_max_helper(expr, &max))
			return false;
		/* fuzzy ranges are often inverted */
		if (sval_cmp(min, max) > 0) {
			sval = min;
			min = max;
			max = sval;
		}
		*res = alloc_rl(min, max);
		return true;
	}
	return false;
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

static bool handle_strlen(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct expression *arg, *tmp;
	sval_t tag;
	sval_t ret = { .type = &ulong_ctype };
	struct range_list *rl;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!arg)
		return false;
	if (arg->type == EXPR_STRING) {
		ret.value = arg->string->length - 1;
		*res_sval = ret;
		return true;
	}
	if (implied == RL_EXACT)
		return false;
	if (get_implied_value(arg, &tag) &&
	    (tmp = fake_string_from_mtag(tag.uvalue))) {
		ret.value = tmp->string->length - 1;
		*res_sval = ret;
		return true;
	}

	if (implied == RL_HARD || implied == RL_FUZZY)
		return false;

	if (get_implied_return(expr, &rl)) {
		*res = rl;
		return true;
	}

	return false;
}

static bool handle_builtin_constant_p(struct expression *expr, int implied, int *recurse_cnt, sval_t *res_sval)
{
	struct expression *arg;
	struct range_list *rl;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (get_rl_internal(arg, RL_EXACT, recurse_cnt, &rl))
		*res_sval = one;
	else
		*res_sval = zero;
	return true;
}

static bool handle__builtin_choose_expr(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct expression *const_expr, *expr1, *expr2;
	sval_t sval;

	const_expr = get_argument_from_call_expr(expr->args, 0);
	expr1 = get_argument_from_call_expr(expr->args, 1);
	expr2 = get_argument_from_call_expr(expr->args, 2);

	if (!get_value(const_expr, &sval) || !expr1 || !expr2)
		return false;
	if (sval.value)
		return get_rl_sval(expr1, implied, recurse_cnt, res, res_sval);
	else
		return get_rl_sval(expr2, implied, recurse_cnt, res, res_sval);
}

static bool handle_call_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct range_list *rl;

	if (sym_name_is("__builtin_constant_p", expr->fn))
		return handle_builtin_constant_p(expr, implied, recurse_cnt, res_sval);

	if (sym_name_is("__builtin_choose_expr", expr->fn))
		return handle__builtin_choose_expr(expr, implied, recurse_cnt, res, res_sval);

	if (sym_name_is("__builtin_expect", expr->fn) ||
	    sym_name_is("__builtin_bswap16", expr->fn) ||
	    sym_name_is("__builtin_bswap32", expr->fn) ||
	    sym_name_is("__builtin_bswap64", expr->fn)) {
		struct expression *arg;

		arg = get_argument_from_call_expr(expr->args, 0);
		return get_rl_sval(arg, implied, recurse_cnt, res, res_sval);
	}

	if (sym_name_is("strlen", expr->fn))
		return handle_strlen(expr, implied, recurse_cnt, res, res_sval);

	if (implied == RL_EXACT || implied == RL_HARD || implied == RL_FUZZY)
		return false;

	if (custom_handle_variable) {
		rl = custom_handle_variable(expr);
		if (rl) {
			*res = rl;
			return true;
		}
	}

	/* Ugh...  get_implied_return() sets *rl to NULL on failure */
	if (get_implied_return(expr, &rl)) {
		*res = rl;
		return true;
	}
	rl = db_return_vals(expr);
	if (rl) {
		*res = rl;
		return true;
	}
	return false;
}

static bool handle_cast(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct range_list *rl;
	struct symbol *type;
	sval_t sval = {};

	type = get_type(expr);
	if (get_rl_sval(expr->cast_expression, implied, recurse_cnt, &rl, &sval)) {
		if (sval.type)
			*res_sval = sval_cast(type, sval);
		else
			*res = cast_rl(type, rl);
		return true;
	}
	if (implied == RL_ABSOLUTE || implied == RL_REAL_ABSOLUTE) {
		*res = alloc_whole_rl(type);
		return true;
	}
	if (implied == RL_IMPLIED && type &&
	    type_bits(type) > 0 && type_bits(type) < 32) {
		*res = alloc_whole_rl(type);
		return true;
	}
	return false;
}

static bool get_offset_from_down(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct expression *index;
	struct symbol *type = expr->in;
	struct range_list *rl;
	struct symbol *field;
	int offset = 0;
	sval_t sval = { .type = ssize_t_ctype };
	sval_t tmp_sval = {};

	/*
	 * FIXME:  I don't really know what I'm doing here.  I wish that I
	 * could just get rid of the __builtin_offset() function and use:
	 * "&((struct bpf_prog *)NULL)->insns[fprog->len]" instead...
	 * Anyway, I have done the minimum ammount of work to get that
	 * expression to work.
	 *
	 */

	if (expr->op != '.' || !expr->down ||
	    expr->down->type != EXPR_OFFSETOF ||
	    expr->down->op != '[' ||
	    !expr->down->index)
		return false;

	index = expr->down->index;

	examine_symbol_type(type);
	type = get_real_base_type(type);
	if (!type)
		return false;
	field = find_identifier(expr->ident, type->symbol_list, &offset);
	if (!field)
		return false;

	type = get_real_base_type(field);
	if (!type || type->type != SYM_ARRAY)
		return false;
	type = get_real_base_type(type);

	if (get_implied_value_internal(index, recurse_cnt, &sval)) {
		res_sval->type = ssize_t_ctype;
		res_sval->value = offset + sval.value * type_bytes(type);
		return true;
	}

	if (!get_rl_sval(index, implied, recurse_cnt, &rl, &tmp_sval))
		return false;

	/*
	 * I'm not sure why get_rl_sval() would return an sval when
	 * get_implied_value_internal() failed but it does when I
	 * parse drivers/net/ethernet/mellanox/mlx5/core/en/monitor_stats.c
	 *
	 */
	if (tmp_sval.type) {
		res_sval->type = ssize_t_ctype;
		res_sval->value = offset + sval.value * type_bytes(type);
		return true;
	}

	sval.value = type_bytes(type);
	rl = rl_binop(rl, '*', alloc_rl(sval, sval));
	sval.value = offset;
	*res = rl_binop(rl, '+', alloc_rl(sval, sval));
	return true;
}

static bool get_offset_from_in(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	struct symbol *type = get_real_base_type(expr->in);
	struct symbol *field;
	int offset = 0;

	if (expr->op != '.' || !type || !expr->ident)
		return false;

	field = find_identifier(expr->ident, type->symbol_list, &offset);
	if (!field)
		return false;

	res_sval->type = size_t_ctype;
	res_sval->value = offset;

	return true;
}

static bool handle_offsetof_rl(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *res_sval)
{
	if (get_offset_from_down(expr, implied, recurse_cnt, res, res_sval))
		return true;

	if (get_offset_from_in(expr, implied, recurse_cnt, res, res_sval))
		return true;

	evaluate_expression(expr);
	if (expr->type == EXPR_VALUE) {
		*res_sval = sval_from_val(expr, expr->value);
		return true;
	}
	return false;
}

static bool get_rl_sval(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res, sval_t *sval_res)
{
	struct range_list *rl = (void *)-1UL;
	struct symbol *type;
	sval_t sval = {};

	type = get_type(expr);
	expr = strip_parens(expr);
	if (!expr)
		return false;

	if (++(*recurse_cnt) >= 200)
		return false;

	switch(expr->type) {
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		handle_cast(expr, implied, recurse_cnt, &rl, &sval);
		goto out_cast;
	}

	expr = strip_expr(expr);
	if (!expr)
		return false;

	switch (expr->type) {
	case EXPR_VALUE:
		sval = sval_from_val(expr, expr->value);
		break;
	case EXPR_PREOP:
		handle_preop_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_POSTOP:
		get_rl_sval(expr->unop, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_BINOP:
		handle_binop_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_COMPARE:
		handle_comparison_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_LOGICAL:
		handle_logical_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_PTRSIZEOF:
	case EXPR_SIZEOF:
		sval = handle_sizeof(expr);
		break;
	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		handle_conditional_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_CALL:
		handle_call_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_STRING:
		if (get_mtag_sval(expr, &sval))
			break;
		if (implied == RL_EXACT)
			break;
		rl = alloc_rl(valid_ptr_min_sval, valid_ptr_max_sval);
		break;
	case EXPR_OFFSETOF:
		handle_offsetof_rl(expr, implied, recurse_cnt, &rl, &sval);
		break;
	case EXPR_ALIGNOF:
		evaluate_expression(expr);
		if (expr->type == EXPR_VALUE)
			sval = sval_from_val(expr, expr->value);
		break;
	default:
		handle_variable(expr, implied, recurse_cnt, &rl, &sval);
	}

out_cast:
	if (rl == (void *)-1UL)
		rl = NULL;

	if (sval.type || (rl && rl_to_sval(rl, &sval))) {
		*sval_res = sval;
		return true;
	}
	if (implied == RL_EXACT)
		return false;

	if (rl) {
		*res = rl;
		return true;
	}
	if (type && (implied == RL_ABSOLUTE || implied == RL_REAL_ABSOLUTE)) {
		*res = alloc_whole_rl(type);
		return true;
	}
	return false;
}

static bool get_rl_internal(struct expression *expr, int implied, int *recurse_cnt, struct range_list **res)
{
	struct range_list *rl = NULL;
	sval_t sval = {};

	if (!get_rl_sval(expr, implied, recurse_cnt, &rl, &sval))
		return false;

	if (sval.type)
		*res = alloc_rl(sval, sval);
	else
		*res = rl;
	return true;
}

static bool get_rl_helper(struct expression *expr, int implied, struct range_list **res)
{
	struct range_list *rl = NULL;
	sval_t sval = {};
	int recurse_cnt = 0;

	if (get_value(expr, &sval)) {
		*res = alloc_rl(sval, sval);
		return true;
	}

	if (!get_rl_sval(expr, implied, &recurse_cnt, &rl, &sval))
		return false;

	if (sval.type)
		*res = alloc_rl(sval, sval);
	else
		*res = rl;
	return true;
}

struct {
	struct expression *expr;
	sval_t sval;
} cached_results[24];
static int cache_idx;

void clear_math_cache(void)
{
	memset(cached_results, 0, sizeof(cached_results));
}

void set_fast_math_only(void)
{
	fast_math_only++;
}

void clear_fast_math_only(void)
{
	fast_math_only--;
}

/*
 * Don't cache EXPR_VALUE because values are fast already.
 *
 */
static bool get_value_literal(struct expression *expr, sval_t *res_sval)
{
	struct expression *tmp;
	int recurse_cnt = 0;

	tmp = strip_expr(expr);
	if (!tmp || tmp->type != EXPR_VALUE)
		return false;

	return get_rl_sval(expr, RL_EXACT, &recurse_cnt, NULL, res_sval);
}

/* returns 1 if it can get a value literal or else returns 0 */
int get_value(struct expression *expr, sval_t *res_sval)
{
	struct range_list *(*orig_custom_fn)(struct expression *expr);
	int recurse_cnt = 0;
	sval_t sval = {};
	int i;

	if (get_value_literal(expr, res_sval))
		return 1;

	/*
	 * This only handles RL_EXACT because other expr statements can be
	 * different at different points.  Like the list iterator, for example.
	 */
	for (i = 0; i < ARRAY_SIZE(cached_results); i++) {
		if (expr == cached_results[i].expr) {
			if (cached_results[i].sval.type) {
				*res_sval = cached_results[i].sval;
				return true;
			}
			return false;
		}
	}

	orig_custom_fn = custom_handle_variable;
	custom_handle_variable = NULL;
	get_rl_sval(expr, RL_EXACT, &recurse_cnt, NULL, &sval);

	custom_handle_variable = orig_custom_fn;

	cached_results[cache_idx].expr = expr;
	cached_results[cache_idx].sval = sval;
	cache_idx = (cache_idx + 1) % ARRAY_SIZE(cached_results);

	if (!sval.type)
		return 0;

	*res_sval = sval;
	return 1;
}

static bool get_implied_value_internal(struct expression *expr, int *recurse_cnt, sval_t *res_sval)
{
	struct range_list *rl;

	res_sval->type = NULL;

	if (!get_rl_sval(expr, RL_IMPLIED, recurse_cnt, &rl, res_sval))
		return false;
	if (!res_sval->type && !rl_to_sval(rl, res_sval))
		return false;
	return true;
}

int get_implied_value(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (!get_rl_helper(expr, RL_IMPLIED, &rl) ||
	    !rl_to_sval(rl, sval))
		return 0;
	return 1;
}

int get_implied_min(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (!get_rl_helper(expr, RL_IMPLIED, &rl) || !rl)
		return 0;
	*sval = rl_min(rl);
	return 1;
}

int get_implied_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (!get_rl_helper(expr, RL_IMPLIED, &rl) || !rl)
		return 0;
	*sval = rl_max(rl);
	return 1;
}

int get_implied_rl(struct expression *expr, struct range_list **rl)
{
	if (!get_rl_helper(expr, RL_IMPLIED, rl) || !*rl)
		return 0;
	return 1;
}

static int get_absolute_rl_internal(struct expression *expr, struct range_list **rl, int *recurse_cnt)
{
	*rl = NULL;
	get_rl_internal(expr, RL_ABSOLUTE, recurse_cnt, rl);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int get_absolute_rl(struct expression *expr, struct range_list **rl)
{
	*rl = NULL;
	 get_rl_helper(expr, RL_ABSOLUTE, rl);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int get_real_absolute_rl(struct expression *expr, struct range_list **rl)
{
	*rl = NULL;
	get_rl_helper(expr, RL_REAL_ABSOLUTE, rl);
	if (!*rl)
		*rl = alloc_whole_rl(get_type(expr));
	return 1;
}

int custom_get_absolute_rl(struct expression *expr,
			   struct range_list *(*fn)(struct expression *expr),
			   struct range_list **rl)
{
	int ret;

	*rl = NULL;
	custom_handle_variable = fn;
	ret = get_rl_helper(expr, RL_REAL_ABSOLUTE, rl);
	custom_handle_variable = NULL;
	return ret;
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

	if (!get_rl_helper(expr, RL_HARD, &rl) || !rl)
		return 0;
	*sval = rl_max(rl);
	return 1;
}

int get_fuzzy_min(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;
	sval_t tmp;

	if (!get_rl_helper(expr, RL_FUZZY, &rl) || !rl)
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

	if (!get_rl_helper(expr, RL_FUZZY, &rl) || !rl)
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

	type = get_type(expr);
	if (!type)
		type = &llong_ctype;  // FIXME: this is wrong but places assume get type can't fail.
	rl = NULL;
	get_rl_helper(expr, RL_REAL_ABSOLUTE, &rl);
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

	type = get_type(expr);
	if (!type)
		type = &llong_ctype;
	rl = NULL;
	get_rl_helper(expr, RL_REAL_ABSOLUTE, &rl);
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

	if (__inline_fn && get_param_num(expr) >= 0) {
		if (get_implied_value(expr, &tmp) && tmp.value)
			return 1;
		return 0;
	}

	if (get_value(expr, &tmp) && tmp.value)
		return 1;

	return 0;
}

int known_condition_false(struct expression *expr)
{
	sval_t tmp;

	if (!expr)
		return 0;

	if (__inline_fn && get_param_num(expr) >= 0) {
		if (get_implied_value(expr, &tmp) && tmp.value == 0)
			return 1;
		return 0;
	}

	if (expr_is_zero(expr))
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



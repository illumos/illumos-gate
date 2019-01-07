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

/*
 * Check for things which are signed but probably should be unsigned.
 *
 * Hm...  It seems like at this point in the processing, sparse makes all
 * bitfields unsigned.  Which is logical but not what GCC does.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"

static int my_id;

#define VAR_ON_RIGHT 0
#define VAR_ON_LEFT 1

static void match_assign(struct expression *expr)
{
	struct symbol *sym;
	sval_t sval;
	sval_t max;
	sval_t min;
	char *left_name, *right_name;

	if (__in_fake_assign)
		return;
	if (expr->op == SPECIAL_AND_ASSIGN || expr->op == SPECIAL_OR_ASSIGN)
		return;

	sym = get_type(expr->left);
	if (!sym || sym->type != SYM_BASETYPE) {
		//sm_msg("could not get type");
		return;
	}
	if (type_bits(sym) < 0 || type_bits(sym) >= 32) /* max_val limits this */
		return;
	if (!get_implied_value(expr->right, &sval))
		return;
	max = sval_type_max(sym);
	if (sym != &bool_ctype && sym != &uchar_ctype &&
	    sval_cmp(max, sval) < 0 &&
	    !(sval.value < 256 && max.value == 127)) {
		left_name = expr_to_str(expr->left);
		right_name = expr_to_str(expr->right);
		sm_warning("'%s' %s can't fit into %s '%s'",
		       right_name, sval_to_numstr(sval), sval_to_numstr(max), left_name);
		free_string(left_name);
	}
	min = sval_type_min(sym);
	if (sval_cmp_t(&llong_ctype, min, sval) > 0) {
		if (min.value == 0 && sval.value == -1) /* assigning -1 to unsigned variables is idiomatic */
			return;
		if (expr->right->type == EXPR_PREOP && expr->right->op == '~')
			return;
		if (expr->op == SPECIAL_SUB_ASSIGN || expr->op == SPECIAL_ADD_ASSIGN)
			return;
		if (sval_positive_bits(sval) == 7)
			return;
		left_name = expr_to_str(expr->left);
		if (min.value == 0) {
			sm_warning("assigning %s to unsigned variable '%s'",
			       sval_to_str(sval), left_name);
		} else {
			sm_warning("value %s can't fit into %s '%s'",
			       sval_to_str(sval), sval_to_str(min), left_name);
		}
		free_string(left_name);
	}
}

static int cap_gt_zero_and_lt(struct expression *expr)
{

	struct expression *var = expr->left;
	struct expression *tmp;
	char *name1 = NULL;
	char *name2 = NULL;
	sval_t known;
	int ret = 0;
	int i;

	if (!get_value(expr->right, &known) || known.value != 0)
		return 0;

	i = 0;
	FOR_EACH_PTR_REVERSE(big_expression_stack, tmp) {
		if (!i++)
			continue;
		if (tmp->op == SPECIAL_LOGICAL_AND) {
			struct expression *right = strip_expr(tmp->right);

			if (right->op != '<' &&
			    right->op != SPECIAL_UNSIGNED_LT &&
			    right->op != SPECIAL_LTE &&
			    right->op != SPECIAL_UNSIGNED_LTE)
				return 0;

			name1 = expr_to_str(var);
			if (!name1)
				goto free;

			name2 = expr_to_str(right->left);
			if (!name2)
				goto free;
			if (!strcmp(name1, name2))
				ret = 1;
			goto free;

		}
		return 0;
	} END_FOR_EACH_PTR_REVERSE(tmp);

free:
	free_string(name1);
	free_string(name2);
	return ret;
}

static int cap_lt_zero_or_gt(struct expression *expr)
{

	struct expression *var = expr->left;
	struct expression *tmp;
	char *name1 = NULL;
	char *name2 = NULL;
	sval_t known;
	int ret = 0;
	int i;

	if (!get_value(expr->right, &known) || known.value != 0)
		return 0;

	i = 0;
	FOR_EACH_PTR_REVERSE(big_expression_stack, tmp) {
		if (!i++)
			continue;
		if (tmp->op == SPECIAL_LOGICAL_OR) {
			struct expression *right = strip_expr(tmp->right);

			if (right->op != '>' &&
			    right->op != SPECIAL_UNSIGNED_GT &&
			    right->op != SPECIAL_GTE &&
			    right->op != SPECIAL_UNSIGNED_GTE)
				return 0;

			name1 = expr_to_str(var);
			if (!name1)
				goto free;

			name2 = expr_to_str(right->left);
			if (!name2)
				goto free;
			if (!strcmp(name1, name2))
				ret = 1;
			goto free;

		}
		return 0;
	} END_FOR_EACH_PTR_REVERSE(tmp);

free:
	free_string(name1);
	free_string(name2);
	return ret;
}

static int cap_both_sides(struct expression *expr)
{
	switch (expr->op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		return cap_lt_zero_or_gt(expr);
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		return cap_gt_zero_and_lt(expr);
	}
	return 0;
}

static int compare_against_macro(struct expression *expr)
{
	sval_t known;

	if (expr->op != SPECIAL_UNSIGNED_LT)
		return 0;

	if (!get_value(expr->right, &known) || known.value != 0)
		return 0;
	return !!get_macro_name(expr->right->pos);
}

static int print_unsigned_never_less_than_zero(struct expression *expr)
{
	sval_t known;
	char *name;

	if (expr->op != SPECIAL_UNSIGNED_LT)
		return 0;

	if (!get_value(expr->right, &known) || known.value != 0)
		return 0;

	name = expr_to_str(expr->left);
	sm_warning("unsigned '%s' is never less than zero.", name);
	free_string(name);
	return 1;
}

static void match_condition(struct expression *expr)
{
	struct symbol *type;
	sval_t known;
	sval_t min, max;
	struct range_list *rl_left_orig, *rl_right_orig;
	struct range_list *rl_left, *rl_right;

	if (expr->type != EXPR_COMPARE)
		return;

	type = get_type(expr);
	if (!type)
		return;

	/* screw it.  I am writing this to mark yoda code as buggy.
	 * Valid comparisons between an unsigned and zero are:
	 * 1) inside a macro.
	 * 2) foo < LOWER_BOUND where LOWER_BOUND is a macro.
	 * 3) foo < 0 || foo > X in exactly this format.  No Yoda.
	 * 4) foo >= 0 && foo < X
	 */
	if (get_macro_name(expr->pos))
		return;
	if (compare_against_macro(expr))
		return;
	if (cap_both_sides(expr))
		return;

	/* This is a special case for the common error */
	if (print_unsigned_never_less_than_zero(expr))
		return;

	/* check that one and only one side is known */
	if (get_value(expr->left, &known)) {
		if (get_value(expr->right, &known))
			return;
		rl_left_orig = alloc_rl(known, known);
		rl_left = cast_rl(type, rl_left_orig);

		min = sval_type_min(get_type(expr->right));
		max = sval_type_max(get_type(expr->right));
		rl_right_orig = alloc_rl(min, max);
		rl_right = cast_rl(type, rl_right_orig);
	} else if (get_value(expr->right, &known)) {
		rl_right_orig = alloc_rl(known, known);
		rl_right = cast_rl(type, rl_right_orig);

		min = sval_type_min(get_type(expr->left));
		max = sval_type_max(get_type(expr->left));
		rl_left_orig = alloc_rl(min, max);
		rl_left = cast_rl(type, rl_left_orig);
	} else {
		return;
	}

	if (!possibly_true_rl(rl_left, expr->op, rl_right)) {
		char *name = expr_to_str(expr);

		sm_warning("impossible condition '(%s) => (%s %s %s)'", name,
		       show_rl(rl_left), show_special(expr->op),
		       show_rl(rl_right));
		free_string(name);
	}

	if (!possibly_false_rl(rl_left, expr->op, rl_right)) {
		char *name = expr_to_str(expr);

		sm_warning("always true condition '(%s) => (%s %s %s)'", name,
		       show_rl(rl_left_orig), show_special(expr->op),
		       show_rl(rl_right_orig));
		free_string(name);
	}
}

void check_signed(int id)
{
	my_id = id;

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
}

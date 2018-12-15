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

#include <stdlib.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int loop_id;

STATE(loop_end);

static int definitely_just_used_as_limiter(struct expression *array, struct expression *offset)
{
	sval_t sval;
	struct expression *tmp;

	if (!get_implied_value(offset, &sval))
		return 0;
	if (get_array_size(array) != sval.value)
		return 0;

	tmp = array;
	while ((tmp = expr_get_parent_expr(tmp))) {
		if (tmp->type == EXPR_PREOP && tmp->op == '&')
			return 1;
	}

	return 0;
}

static int fake_get_hard_max(struct expression *expr, sval_t *sval)
{
	struct range_list *implied_rl;

	if (!get_hard_max(expr, sval))
		return 0;

	/*
	 * The problem is that hard_max doesn't care about minimums
	 * properly.  So if you give it thing like:
	 *	err = (-10)-(-1)
	 *	__smatch_hard_max(-err);
	 *
	 * Then it returns s32max instead of 10.
	 */

	if (get_implied_rl(expr, &implied_rl) &&
	    sval_cmp(rl_max(implied_rl), *sval) < 0)
		*sval = rl_max(implied_rl);
	return 1;
}

static int get_the_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (get_hard_max(expr, sval)) {
		struct range_list *implied_rl;

		/*
		 * The problem is that hard_max doesn't care about minimums
		 * properly.  So if you give it thing like:
		 *	err = (-10)-(-1)
		 *	__smatch_hard_max(-err);
		 *
		 * Then it returns s32max instead of 10.
		 */

		if (get_implied_rl(expr, &implied_rl) &&
		    sval_cmp(rl_max(implied_rl), *sval) < 0)
			*sval = rl_max(implied_rl);
		return 1;
	}
	if (!option_spammy)
		return 0;

	/* Fixme:  use fuzzy max */

	if (!get_user_rl(expr, &rl))
		return 0;
	if (rl_max(rl).uvalue > sval_type_max(rl_type(rl)).uvalue - 4 &&
	    is_capped(expr))
		return 0;

	*sval = rl_max(rl);
	return 1;
}

static int common_false_positives(struct expression *array, sval_t max)
{
	char *name;
	int ret;

	name = expr_to_str(array);

	/* Smatch can't figure out glibc's strcmp __strcmp_cg()
	 * so it prints an error every time you compare to a string
	 * literal array with 4 or less chars.
	 */
	if (name &&
	    (strcmp(name, "__s1") == 0 || strcmp(name, "__s2") == 0)) {
		ret = 1;
		goto free;
	}

	/* Ugh... People are saying that Smatch still barfs on glibc strcmp()
	 * functions.
	 */
	if (array) {
		char *macro;

		/* why is this again??? */
		if (array->type == EXPR_STRING &&
		    max.value == array->string->length) {
			ret = 1;
			goto free;
		}

		macro = get_macro_name(array->pos);
		if (macro && max.uvalue < 4 &&
		    (strcmp(macro, "strcmp")  == 0 ||
		     strcmp(macro, "strncmp") == 0 ||
		     strcmp(macro, "streq")   == 0 ||
		     strcmp(macro, "strneq")  == 0 ||
		     strcmp(macro, "strsep")  == 0)) {
			ret = 1;
			goto free;
		}
	}

	/*
	 * passing WORK_CPU_UNBOUND is idiomatic but Smatch doesn't understand
	 * how it's used so it causes a bunch of false positives.
	 */
	if (option_project == PROJ_KERNEL && name &&
	    strcmp(name, "__per_cpu_offset") == 0) {
		ret = 1;
		goto free;
	}
	ret = 0;

free:
	free_string(name);
	return ret;
}

static int is_subtract(struct expression *expr)
{
	struct expression *tmp;
	int cnt = 0;

	expr = strip_expr(expr);
	while ((tmp = get_assigned_expr(expr))) {
		expr = strip_expr(tmp);
		if (++cnt > 5)
			break;
	}

	if (expr->type == EXPR_BINOP && expr->op == '-')
		return 1;
	return 0;
}

static int constraint_met(struct expression *array_expr, struct expression *offset)
{
	char *data_str, *required, *unmet;
	int ret = 0;

	data_str = get_constraint_str(array_expr);
	if (!data_str)
		return 0;

	required = get_required_constraint(data_str);
	if (!required)
		goto free_data_str;

	unmet = unmet_constraint(array_expr, offset);
	if (!unmet)
		ret = 1;
	free_string(unmet);
	free_string(required);

free_data_str:
	free_string(data_str);
	return ret;
}


static int should_warn(struct expression *expr)
{
	struct expression *array_expr;
	struct range_list *abs_rl;
	sval_t hard_max = { .type = &int_ctype, };
	sval_t fuzzy_max = { .type = &int_ctype, };
	int array_size;
	struct expression *offset;
	sval_t max;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return 0;

	if (is_impossible_path())
		return 0;
	array_expr = get_array_base(expr);
	array_size = get_array_size(array_expr);
	if (!array_size || array_size == 1)
		return 0;

	offset = get_array_offset(expr);
	get_absolute_rl(offset, &abs_rl);
	fake_get_hard_max(offset, &hard_max);
	get_fuzzy_max(offset, &fuzzy_max);

	if (!get_the_max(offset, &max))
		return 0;
	if (array_size > max.value)
		return 0;
	if (constraint_met(array_expr, offset))
		return 0;

	if (array_size > rl_max(abs_rl).uvalue)
		return 0;

	if (definitely_just_used_as_limiter(array_expr, offset))
		return 0;

	array_expr = strip_expr(array_expr);
	if (common_false_positives(array_expr, max))
		return 0;

	if (impossibly_high_comparison(offset))
		return 0;

	return 1;

}

static int is_because_of_no_break(struct expression *offset)
{
	if (get_state_expr(loop_id, offset) == &loop_end)
		return 1;
	return 0;
}

static void array_check(struct expression *expr)
{
	struct expression *array_expr;
	struct range_list *abs_rl;
	struct range_list *user_rl = NULL;
	sval_t hard_max = { .type = &int_ctype, };
	sval_t fuzzy_max = { .type = &int_ctype, };
	int array_size;
	struct expression *array_size_value, *comparison;
	struct expression *offset;
	sval_t max;
	char *name;
	int no_break = 0;

	if (!should_warn(expr))
		return;

	expr = strip_expr(expr);
	array_expr = get_array_base(expr);
	array_size = get_array_size(array_expr);
	offset = get_array_offset(expr);

	/*
	 * Perhaps if the offset is out of bounds that means a constraint
	 * applies or maybe it means we are on an impossible path.  So test
	 * again based on that assumption.
	 *
	 */
	array_size_value = value_expr(array_size);
	comparison = compare_expression(offset, SPECIAL_GTE, array_size_value);
	if (assume(comparison)) {
		if (!should_warn(expr)) {
			end_assume();
			return;
		}
		no_break = is_because_of_no_break(offset);
		end_assume();
	}

	get_absolute_rl(offset, &abs_rl);
	get_user_rl(offset, &user_rl);
	fake_get_hard_max(offset, &hard_max);
	get_fuzzy_max(offset, &fuzzy_max);

	array_expr = strip_expr(array_expr);
	name = expr_to_str(array_expr);

	if (user_rl)
		max = rl_max(user_rl);
	else
		max = rl_max(abs_rl);

	if (!option_spammy && is_subtract(offset))
		return;

	if (no_break) {
		sm_error("buffer overflow '%s' %d <= %s (assuming for loop doesn't break)",
			name, array_size, sval_to_str(max));
	} else if (user_rl) {
		sm_error("buffer overflow '%s' %d <= %s user_rl='%s'%s",
			name, array_size, sval_to_str(max), show_rl(user_rl),
			is_subtract(offset) ? " subtract" : "");
	} else {
		sm_error("buffer overflow '%s' %d <= %s%s",
			name, array_size, sval_to_str(max),
			is_subtract(offset) ? " subtract" : "");
	}

	free_string(name);
}

void check_index_overflow(int id)
{
	add_hook(&array_check, OP_HOOK);
}

static void match_condition(struct expression *expr)
{
	struct statement *stmt;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != '<' && expr->op != SPECIAL_UNSIGNED_LT)
		return;

	stmt = expr_get_parent_stmt(expr);
	if (!stmt || stmt->type != STMT_ITERATOR)
		return;

	set_true_false_states_expr(loop_id, expr->left, NULL, &loop_end);
}

static void set_undefined(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state == &loop_end)
		set_state(loop_id, sm->name, sm->sym, &undefined);
}

void check_index_overflow_loop_marker(int id)
{
	loop_id = id;

	add_hook(&match_condition, CONDITION_HOOK);
	add_modification_hook(loop_id, &set_undefined);
}


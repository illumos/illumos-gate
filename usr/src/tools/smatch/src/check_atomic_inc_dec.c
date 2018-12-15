/*
 * Copyright (C) 2016 Oracle.
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
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(inc);
STATE(orig);
STATE(dec);

static void db_inc_dec(struct expression *expr, int param, const char *key, const char *value, int inc_dec)
{
	struct smatch_state *start_state;
	struct expression *arg;
	char *name;
	struct symbol *sym;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	start_state = get_state(my_id, name, sym);

	if (inc_dec == ATOMIC_INC) {
//		if (start_state == &inc)
//			sm_error("XXX double increment '%s'", name);
		set_state(my_id, name, sym, &inc);
	} else {
//		if (start_state == &dec)
//			sm_error("XXX double decrement '%s'", name);
		if (start_state == &inc)
			set_state(my_id, name, sym, &orig);
		else
			set_state(my_id, name, sym, &dec);
	}

free:
	free_string(name);
}

static void db_inc(struct expression *expr, int param, char *key, char *value)
{
	db_inc_dec(expr, param, key, value, ATOMIC_INC);
}

static void db_dec(struct expression *expr, int param, char *key, char *value)
{
	db_inc_dec(expr, param, key, value, ATOMIC_DEC);
}

static void match_atomic_inc(const char *fn, struct expression *expr, void *_unused)
{
	db_inc_dec(expr, 0, "$->counter", "", ATOMIC_INC);
}

static void match_atomic_dec(const char *fn, struct expression *expr, void *_unused)
{
	db_inc_dec(expr, 0, "$->counter", "", ATOMIC_DEC);
}

static void match_atomic_add(const char *fn, struct expression *expr, void *_unused)
{
	struct expression *amount;
	sval_t sval;

	amount = get_argument_from_call_expr(expr->args, 0);
	if (get_implied_value(amount, &sval) && sval_is_negative(sval)) {
		db_inc_dec(expr, 1, "$->counter", "", ATOMIC_DEC);
		return;
	}

	db_inc_dec(expr, 1, "$->counter", "", ATOMIC_INC);
}

static void match_atomic_sub(const char *fn, struct expression *expr, void *_unused)
{
	db_inc_dec(expr, 1, "$->counter", "", ATOMIC_DEC);
}

static void refcount_inc(const char *fn, struct expression *expr, void *param)
{
	db_inc_dec(expr, PTR_INT(param), "$->ref.counter", "", ATOMIC_INC);
}

static void refcount_dec(const char *fn, struct expression *expr, void *param)
{
	db_inc_dec(expr, PTR_INT(param), "$->ref.counter", "", ATOMIC_DEC);
}

static void match_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state != &inc &&
		    sm->state != &dec)
			continue;
		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;
		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		sql_insert_return_states(return_id, return_ranges,
					 (sm->state == &inc) ? ATOMIC_INC : ATOMIC_DEC,
					 param, param_name, "");
	} END_FOR_EACH_SM(sm);
}

enum {
	NEGATIVE, ZERO, POSITIVE,
};

static int success_fail_positive(struct range_list *rl)
{
	if (!rl)
		return ZERO;

	if (sval_is_negative(rl_min(rl)))
		return NEGATIVE;

	if (rl_min(rl).value == 0)
		return ZERO;

	return POSITIVE;
}

static void check_counter(const char *name, struct symbol *sym)
{
	struct range_list *inc_lines = NULL;
	struct range_list *dec_lines = NULL;
	int inc_buckets[3] = {};
	struct stree *stree;
	struct sm_state *return_sm;
	struct sm_state *sm;
	sval_t line = sval_type_val(&int_ctype, 0);

	FOR_EACH_PTR(get_all_return_strees(), stree) {
		return_sm = get_sm_state_stree(stree, RETURN_ID, "return_ranges", NULL);
		if (!return_sm)
			continue;
		line.value = return_sm->line;

		sm = get_sm_state_stree(stree, my_id, name, sym);
		if (!sm)
			continue;

		if (sm->state != &inc && sm->state != &dec)
			continue;

		if (sm->state == &inc) {
			add_range(&inc_lines, line, line);
			inc_buckets[success_fail_positive(estate_rl(return_sm->state))] = 1;
		}
		if (sm->state == &dec)
			add_range(&dec_lines, line, line);
	} END_FOR_EACH_PTR(stree);

	if (inc_buckets[NEGATIVE] &&
	    inc_buckets[ZERO]) {
		// sm_warning("XXX '%s' not decremented on lines: %s.", name, show_rl(inc_lines));
	}

}

static void match_check_missed(struct symbol *sym)
{
	struct sm_state *sm;

	FOR_EACH_MY_SM(my_id, get_all_return_states(), sm) {
		check_counter(sm->name, sm->sym);
	} END_FOR_EACH_SM(sm);
}

int on_atomic_dec_path(void)
{
	struct sm_state *sm;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state == &dec)
			return 1;
	} END_FOR_EACH_SM(sm);

	return 0;
}

int was_inced(const char *name, struct symbol *sym)
{
	return get_state(my_id, name, sym) == &inc;
}

void check_atomic_inc_dec(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	select_return_states_hook(ATOMIC_INC, &db_inc);
	select_return_states_hook(ATOMIC_DEC, &db_dec);
	add_function_hook("atomic_inc_return", &match_atomic_inc, NULL);
	add_function_hook("atomic_add_return", &match_atomic_add, NULL);
	add_function_hook("atomic_sub_return", &match_atomic_sub, NULL);
	add_function_hook("atomic_sub_and_test", &match_atomic_sub, NULL);
	add_function_hook("atomic_dec_and_test", &match_atomic_dec, NULL);
	add_function_hook("_atomic_dec_and_lock", &match_atomic_dec, NULL);
	add_function_hook("atomic_dec", &match_atomic_dec, NULL);
	add_function_hook("atomic_long_inc", &match_atomic_inc, NULL);
	add_function_hook("atomic_long_dec", &match_atomic_dec, NULL);
	add_function_hook("atomic_inc", &match_atomic_inc, NULL);
	add_function_hook("atomic_sub", &match_atomic_sub, NULL);
	add_split_return_callback(match_return_info);

	add_function_hook("refcount_add_not_zero", &refcount_inc, INT_PTR(1));
	add_function_hook("refcount_inc_not_zero", &refcount_inc, INT_PTR(0));
	add_function_hook("refcount_sub_and_test", &refcount_dec, INT_PTR(1));
	add_function_hook("refcount_dec_and_test", &refcount_dec, INT_PTR(1));

	add_hook(&match_check_missed, END_FUNC_HOOK);
}

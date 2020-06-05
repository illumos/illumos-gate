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

#include <ctype.h>

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(inc);
STATE(orig);
STATE(dec);

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	if (parent_is_gone_var_sym(sm->name, sm->sym))
		return sm->state;
	return &undefined;
}

static struct stree *start_states;
static struct stree_stack *saved_stack;
static void set_start_state(const char *name, struct symbol *sym, struct smatch_state *start)
{
	struct smatch_state *orig;

	orig = get_state_stree(start_states, my_id, name, sym);
	if (!orig)
		set_state_stree(&start_states, my_id, name, sym, start);
	else if (orig != start)
		set_state_stree(&start_states, my_id, name, sym, &undefined);
}

static struct sm_state *get_best_match(const char *key)
{
	struct sm_state *sm;
	struct sm_state *match;
	int cnt = 0;
	int start_pos, state_len, key_len, chunks, i;

	if (strncmp(key, "$->", 3) == 0)
		key += 3;

	key_len = strlen(key);
	chunks = 0;
	for (i = key_len - 1; i > 0; i--) {
		if (key[i] == '>' || key[i] == '.')
			chunks++;
		if (chunks == 2) {
			key += (i + 1);
			key_len = strlen(key);
			break;
		}
	}

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		state_len = strlen(sm->name);
		if (state_len < key_len)
			continue;
		start_pos = state_len - key_len;
		if ((start_pos == 0 || !isalnum(sm->name[start_pos - 1])) &&
		    strcmp(sm->name + start_pos, key) == 0) {
			cnt++;
			match = sm;
		}
	} END_FOR_EACH_SM(sm);

	if (cnt == 1)
		return match;
	return NULL;
}

static void db_inc_dec(struct expression *expr, int param, const char *key, const char *value, int inc_dec)
{
	struct sm_state *start_sm;
	struct expression *arg;
	char *name;
	struct symbol *sym;
	bool free_at_end = true;

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

	start_sm = get_sm_state(my_id, name, sym);
	if (!start_sm && inc_dec == ATOMIC_DEC) {
		start_sm = get_best_match(key);
		if (start_sm) {
			free_string(name);
			free_at_end = false;
			name = (char *)start_sm->name;
			sym = start_sm->sym;
		}
	}

	if (inc_dec == ATOMIC_INC) {
		if (!start_sm)
			set_start_state(name, sym, &dec);
//		set_refcount_inc(name, sym);
		set_state(my_id, name, sym, &inc);
	} else {
//		set_refcount_dec(name, sym);
		if (!start_sm)
			set_start_state(name, sym, &inc);

		if (start_sm && start_sm->state == &inc)
			set_state(my_id, name, sym, &orig);
		else
			set_state(my_id, name, sym, &dec);
	}

free:
	if (free_at_end)
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
		if (parent_is_gone_var_sym(sm->name, sm->sym))
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
	EMPTY, NEGATIVE, ZERO, POSITIVE, NUM_BUCKETS
};

static int success_fail_positive(struct range_list *rl)
{
	if (!rl)
		return EMPTY;

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
	int inc_buckets[NUM_BUCKETS] = {};
	int dec_buckets[NUM_BUCKETS] = {};
	struct stree *stree, *orig_stree;
	struct sm_state *return_sm;
	struct sm_state *sm;
	sval_t line = sval_type_val(&int_ctype, 0);
	int bucket;

	FOR_EACH_PTR(get_all_return_strees(), stree) {
		orig_stree = __swap_cur_stree(stree);

		return_sm = get_sm_state(RETURN_ID, "return_ranges", NULL);
		if (!return_sm)
			goto swap_stree;
		line.value = return_sm->line;

		if (get_state_stree(start_states, my_id, name, sym) == &inc)
			goto swap_stree;

		if (parent_is_gone_var_sym(name, sym))
			goto swap_stree;

		sm = get_sm_state(my_id, name, sym);
		if (!sm)
			goto swap_stree;

		if (sm->state != &inc &&
		    sm->state != &dec &&
		    sm->state != &orig)
			goto swap_stree;

		bucket = success_fail_positive(estate_rl(return_sm->state));

		if (sm->state == &inc) {
			add_range(&inc_lines, line, line);
			inc_buckets[bucket] = true;
		}
		if (sm->state == &dec || sm->state == &orig) {
			add_range(&dec_lines, line, line);
			dec_buckets[bucket] = true;
		}
swap_stree:
		__swap_cur_stree(orig_stree);
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

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, start_states);
	start_states = NULL;
}

static void match_restore_states(struct expression *expr)
{
	start_states = pop_stree(&saved_stack);
}

static void match_after_func(struct symbol *sym)
{
	free_stree(&start_states);
}

void check_atomic_inc_dec(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	add_unmatched_state_hook(my_id, &unmatched_state);

	add_split_return_callback(match_return_info);
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

	add_function_hook("refcount_inc", &refcount_inc, INT_PTR(0));
	add_function_hook("refcount_dec", &refcount_dec, INT_PTR(0));
	add_function_hook("refcount_add", &refcount_inc, INT_PTR(1));
	add_function_hook("refcount_add_not_zero", &refcount_inc, INT_PTR(1));
	add_function_hook("refcount_inc_not_zero", &refcount_inc, INT_PTR(0));
	add_function_hook("refcount_sub_and_test", &refcount_dec, INT_PTR(1));
	add_function_hook("refcount_dec_and_test", &refcount_dec, INT_PTR(0));

	add_hook(&match_check_missed, END_FUNC_HOOK);

	add_hook(&match_after_func, AFTER_FUNC_HOOK);
	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);
}

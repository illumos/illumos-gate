/*
 * Copyright (C) 2012 Oracle.
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
 * This is almost the same as smatch_param_filter.c.  The difference is that
 * this only deals with values passed on the stack and param filter only deals
 * with values changed so that the caller sees the new value.  It other words
 * the key for these should always be "$" and the key for param_filter should
 * never be "$".  Also smatch_param_set() should never use "$" as the key.
 * Param set should work together with param_filter to determine the value that
 * the caller sees at the end.
 *
 * This is for functions like this:
 *
 * int foo(int a)
 * {
 *        if (a >= 0 && a < 10) {
 *                 a = 42;
 *                 return 1;
 *        }
 *        return 0;
 * }
 *
 * If we pass in 5, it returns 1.
 *
 * It's a bit complicated because we can't just consider the final value, we
 * have to always consider the passed in value.
 *
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

static struct stree *start_states;
static struct stree_stack *saved_stack;

static void save_start_states(struct statement *stmt)
{
	start_states = get_all_states_stree(SMATCH_EXTRA);
}

static void free_start_states(void)
{
	free_stree(&start_states);
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct smatch_state *state;

	state = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (state)
		return state;
	return alloc_estate_whole(estate_type(sm->state));
}

struct smatch_state *get_orig_estate(const char *name, struct symbol *sym)
{
	struct smatch_state *state;

	state = get_state(my_id, name, sym);
	if (state)
		return state;

	state = get_state(SMATCH_EXTRA, name, sym);
	if (state)
		return state;
	return alloc_estate_rl(alloc_whole_rl(get_real_base_type(sym)));
}

struct smatch_state *get_orig_estate_type(const char *name, struct symbol *sym, struct symbol *type)
{
	struct smatch_state *state;

	state = get_state(my_id, name, sym);
	if (state)
		return state;

	state = get_state(SMATCH_EXTRA, name, sym);
	if (state)
		return state;
	return alloc_estate_rl(alloc_whole_rl(type));
}

static struct range_list *generify_mtag_range(struct smatch_state *state)
{
	struct range_list *rl;
	struct data_range *drange;

	if (!estate_type(state) || estate_type(state)->type != SYM_PTR)
		return estate_rl(state);

	/*
	 * The problem is that we get too specific on our param limits when we
	 * know exactly what pointers are passed to a function.  It gets to the
	 * point where we say "pointer x will succeed, but everything else will
	 * fail."  And then we introduce a new caller which passes a different
	 * pointer and it's like, "Sorry bro, that's not possible."
	 *
	 */
	rl = rl_intersection(estate_rl(state), valid_ptr_rl);
	if (!rl)
		return estate_rl(state);

	FOR_EACH_PTR(rl, drange) {
		if (drange->min.value != drange->max.value)
			continue;
		if (drange->min.value > -4096 && drange->min.value <= 0)
			continue;
		return rl_union(valid_ptr_rl, rl);
	} END_FOR_EACH_PTR(drange);

	return estate_rl(state);
}

static void print_return_value_param(int return_id, char *return_ranges, struct expression *expr)
{
	struct smatch_state *state, *old;
	struct sm_state *tmp;
	struct range_list *rl;
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(SMATCH_EXTRA, __get_cur_stree(), tmp) {
		param = get_param_num_from_sym(tmp->sym);
		if (param < 0)
			continue;

		param_name = get_param_name(tmp);
		if (!param_name)
			continue;

		state = __get_state(my_id, tmp->name, tmp->sym);
		if (!state)
			state = tmp->state;

		if (estate_is_whole(state) || estate_is_empty(state))
			continue;
		old = get_state_stree(start_states, SMATCH_EXTRA, tmp->name, tmp->sym);
		if (old && rl_equiv(estate_rl(old), estate_rl(state)))
			continue;

		rl = generify_mtag_range(state);
		sql_insert_return_states(return_id, return_ranges, PARAM_LIMIT,
					 param, param_name, show_rl(rl));
	} END_FOR_EACH_SM(tmp);
}

static void extra_mod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	struct smatch_state *orig_vals;
	int param;

	param = get_param_num_from_sym(sym);
	if (param < 0)
		return;

	orig_vals = get_orig_estate_type(name, sym, estate_type(state));
	set_state(my_id, name, sym, orig_vals);
}

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, start_states);
	start_states = NULL;
}

static void match_restore_states(struct expression *expr)
{
	free_stree(&start_states);
	start_states = pop_stree(&saved_stack);
}

void register_param_limit(int id)
{
	my_id = id;

	add_hook(&save_start_states, AFTER_DEF_HOOK);
	add_hook(&free_start_states, AFTER_FUNC_HOOK);

	add_extra_mod_hook(&extra_mod_hook);
	add_unmatched_state_hook(my_id, &unmatched_state);
	add_merge_hook(my_id, &merge_estates);

	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);

	add_split_return_callback(&print_return_value_param);
}


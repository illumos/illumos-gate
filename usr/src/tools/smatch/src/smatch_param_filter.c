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
 * This is for functions like:
 *
 * void foo(int *x)
 * {
 * 	if (*x == 42)
 *		*x = 0;
 * }
 *
 * The final value of *x depends on the input to the function but with *x == 42
 * filtered out.
 *
 */

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

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct smatch_state *state;

	if (parent_is_gone_var_sym(sm->name, sm->sym))
		return alloc_estate_empty();

	state = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (state)
		return state;
	return alloc_estate_whole(estate_type(sm->state));
}

static void pre_merge_hook(struct sm_state *sm)
{
	struct smatch_state *extra, *mine;
	struct range_list *rl;

	if (estate_rl(sm->state))
		return;

	extra = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!extra)
		return;
	mine = get_state(my_id, sm->name, sm->sym);

	rl = rl_intersection(estate_rl(extra), estate_rl(mine));
	if (rl_equiv(rl, estate_rl(mine)))
		return;
	set_state(my_id, sm->name, sm->sym, alloc_estate_rl(clone_rl(rl)));
}

static void extra_mod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	int param;

	if (__in_fake_assign)
		return;

	param = get_param_num_from_sym(sym);
	if (param < 0)
		return;

	/* on stack parameters are handled in smatch_param_limit.c */
	if (sym->ident && strcmp(sym->ident->name, name) == 0)
		return;

	set_state(my_id, name, sym, alloc_estate_empty());
}

/*
 * This relies on the fact that these states are stored so that
 * foo->bar is before foo->bar->baz.
 */
static int parent_set(struct string_list *list, const char *name)
{
	char *tmp;
	int len;
	int ret;

	FOR_EACH_PTR(list, tmp) {
		len = strlen(tmp);
		ret = strncmp(tmp, name, len);
		if (ret < 0)
			continue;
		if (ret > 0)
			return 0;
		if (name[len] == '-')
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static void print_one_mod_param(int return_id, char *return_ranges,
			int param, struct sm_state *sm, struct string_list **totally_filtered)
{
	const char *param_name;

	param_name = get_param_name(sm);
	if (!param_name)
		return;
	if (is_whole_rl(estate_rl(sm->state)))
		return;
	if (!estate_rl(sm->state)) {
		insert_string(totally_filtered, (char *)sm->name);
		return;
	}

	if (is_ignored_kernel_data(param_name)) {
		insert_string(totally_filtered, (char *)sm->name);
		return;
	}

	sql_insert_return_states(return_id, return_ranges, PARAM_FILTER, param,
			param_name, show_rl(estate_rl(sm->state)));
}

static void print_return_value_param(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *tmp;
	struct sm_state *sm;
	struct string_list *totally_filtered = NULL;
	int param;

	FOR_EACH_MY_SM(SMATCH_EXTRA, __get_cur_stree(), tmp) {
		param = get_param_num_from_sym(tmp->sym);
		if (param < 0)
			continue;

		/* on stack parameters are handled in smatch_param_limit.c */
		if (tmp->sym->ident && strcmp(tmp->sym->ident->name, tmp->name) == 0)
			continue;

		if (parent_set(totally_filtered, tmp->name))
			continue;

		sm = get_sm_state(my_id, tmp->name, tmp->sym);
		if (sm)
			print_one_mod_param(return_id, return_ranges, param, sm, &totally_filtered);
	} END_FOR_EACH_SM(tmp);

	free_ptr_list((struct ptr_list **)&totally_filtered);
}

int param_has_filter_data(struct sm_state *sm)
{
	struct smatch_state *state;

	state = get_state(my_id, sm->name, sm->sym);
	if (!state) {
		if (get_assigned_expr_name_sym(sm->name, sm->sym))
			return 0;
		return 1;
	}
	if (estate_rl(state))
		return 1;
	return 0;
}

void register_param_filter(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_hook(&save_start_states, AFTER_DEF_HOOK);
	add_hook(&free_start_states, AFTER_FUNC_HOOK);

	add_extra_mod_hook(&extra_mod_hook);
	add_unmatched_state_hook(my_id, &unmatched_state);
	add_pre_merge_hook(my_id, &pre_merge_hook);
	add_merge_hook(my_id, &merge_estates);

	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);

	add_split_return_callback(&print_return_value_param);
}


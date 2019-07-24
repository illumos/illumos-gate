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

static int my_id;

static struct stree *used_stree;
static struct stree_stack *saved_stack;

STATE(used);

static void get_state_hook(int owner, const char *name, struct symbol *sym)
{
	int arg;

	if (!option_info)
		return;
	if (__in_fake_assign || __in_fake_parameter_assign || __in_function_def)
		return;

	arg = get_param_num_from_sym(sym);
	if (arg >= 0)
		set_state_stree(&used_stree, my_id, name, sym, &used);
}

static void set_param_used(struct expression *call, struct expression *arg, char *key, char *unused)
{
	struct symbol *sym;
	char *name;
	int arg_nr;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	arg_nr = get_param_num_from_sym(sym);
	if (arg_nr >= 0)
		set_state_stree(&used_stree, my_id, name, sym, &used);
free:
	free_string(name);
}

static void process_states(void)
{
	struct sm_state *tmp;
	int arg;
	const char *name;

	FOR_EACH_SM(used_stree, tmp) {
		arg = get_param_num_from_sym(tmp->sym);
		if (arg < 0)
			continue;
		name = get_param_name(tmp);
		if (!name)
			continue;
		if (is_recursive_member(name))
			continue;

		if (is_ignored_kernel_data(name))
			continue;

		sql_insert_return_implies(PARAM_USED, arg, name, "");
	} END_FOR_EACH_SM(tmp);

	free_stree(&used_stree);
}

static void match_function_def(struct symbol *sym)
{
	free_stree(&used_stree);
}

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, used_stree);
	used_stree = NULL;
}

static void match_restore_states(struct expression *expr)
{
	free_stree(&used_stree);
	used_stree = pop_stree(&saved_stack);
}

void register_param_used(int id)
{
	my_id = id;

	add_hook(&match_function_def, FUNC_DEF_HOOK);

	add_get_state_hook(&get_state_hook);

	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);

	select_return_implies_hook(PARAM_USED, &set_param_used);
	all_return_states_hook(&process_states);
}

/*
 * Copyright (C) 2019 Oracle.
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
 * The problem here is something like this:
 *
 * return (blah() || whatever()) ? NULL : some_function();
 *
 * When we are parsing this what happens is that we first parse all the
 * expressions "(blah() || whatever()) ? NULL : some_function();" and then
 * we parse the return statement.
 *
 * When we parse the return statement, we say "Oh, this is a conditional.  Let's
 * get all the implications for true and false."  But because
 * "(blah() || whatever())" is a function pointer, that means there aren't any
 * implications.
 *
 * So what this module does is it ties the implications to the expression
 * pointer so that we can retreive them easily.  It's similar to Smatch stored
 * implications but it doesn't save condition, it saves the pointer.
 *
 * We ignore pre loop conditions which Smatch parses twice.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(true_path);
STATE(false_path);

void record_condition(struct expression *expr)
{
	char name[32];
	sval_t val;

	if (get_value(expr, &val))
		return;

	if (__in_pre_condition)
		return;

	snprintf(name, sizeof(name), "condition %p", expr);
	set_true_false_states(my_id, name, NULL, &true_path, &false_path);
}

void register_parsed_conditions(int id)
{
	my_id = id;
	add_hook(&record_condition, CONDITION_HOOK);
}

static void filter_by_sm(struct sm_state *sm,
		       struct state_list **true_stack,
		       struct state_list **false_stack)
{
	if (!sm)
		return;

	if (sm->state == &true_path)
		add_ptr_list(true_stack, sm);
	else if (sm->state == &false_path)
		add_ptr_list(false_stack, sm);

	if (sm->merged) {
		filter_by_sm(sm->left, true_stack, false_stack);
		filter_by_sm(sm->right, true_stack, false_stack);
	}
}

struct sm_state *parsed_condition_implication_hook(struct expression *expr,
				struct state_list **true_stack,
				struct state_list **false_stack)
{
	struct state_list *tmp_true = NULL;
	struct state_list *tmp_false = NULL;
	struct sm_state *sm, *tmp;
	char name[32];

	snprintf(name, sizeof(name), "condition %p", expr);

	sm = get_sm_state(my_id, name, NULL);
	if (!sm)
		return NULL;
	if (!sm->merged)
		return NULL;

	filter_by_sm(sm, &tmp_true, &tmp_false);
	if (!tmp_true && !tmp_false)
		return NULL;

	FOR_EACH_PTR(tmp_true, tmp) {
		add_ptr_list(true_stack, tmp);
	} END_FOR_EACH_PTR(tmp);

	FOR_EACH_PTR(tmp_false, tmp) {
		add_ptr_list(false_stack, tmp);
	} END_FOR_EACH_PTR(tmp);

	free_slist(&tmp_true);
	free_slist(&tmp_false);

	return sm;
}


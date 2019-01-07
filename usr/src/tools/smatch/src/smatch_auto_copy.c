/*
 * Copyright (C) 2014 Oracle.
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

static int *auto_copy;

void set_auto_copy(int owner)
{
	if (owner <= 1 || owner > num_checks) {
		sm_ierror("bogus set_auto_copy()");
		return;
	}
	auto_copy[owner] = 1;
}

static void match_assign(struct expression *expr)
{
	char *left_name = NULL;
	char *right_name = NULL;
	struct symbol *left_sym, *right_sym;
	struct state_list *slist = NULL;
	struct sm_state *sm;

	left_name = expr_to_var_sym(expr->left, &left_sym);
	if (!left_name || !left_sym)
		goto free;
	right_name = expr_to_var_sym(expr->right, &right_sym);
	if (!right_name || !right_sym)
		goto free;

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (sm->owner <= 1 || sm->owner > num_checks)
			continue;
		if (!auto_copy[sm->owner])
			continue;
		if (right_sym != sm->sym)
			continue;
		if (strcmp(right_name, sm->name) != 0)
			continue;
		add_ptr_list(&slist, sm);
	} END_FOR_EACH_SM(sm);


	FOR_EACH_PTR(slist, sm) {
		set_state(sm->owner, left_name, left_sym, sm->state);
	} END_FOR_EACH_PTR(sm);

free:
	free_slist(&slist);
	free_string(left_name);
	free_string(right_name);
}

void register_auto_copy(int id)
{
	my_id = id;
	auto_copy = malloc((num_checks + 1) * sizeof(*auto_copy));
	memset(auto_copy, 0, (num_checks + 1) * sizeof(*auto_copy));

	add_hook(&match_assign, ASSIGNMENT_HOOK);
}

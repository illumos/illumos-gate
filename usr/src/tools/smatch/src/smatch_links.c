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

/*
 * Some helper functions for managing links.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static struct smatch_state *alloc_link(struct var_sym_list *links)
{
	struct smatch_state *state;
	static char buf[256];
	struct var_sym *tmp;
	int i;

	state = __alloc_smatch_state(0);

	i = 0;
	FOR_EACH_PTR(links, tmp) {
		if (!i++) {
			snprintf(buf, sizeof(buf), "%s", tmp->var);
		} else {
			append(buf, ", ", sizeof(buf));
			append(buf, tmp->var, sizeof(buf));
		}
	} END_FOR_EACH_PTR(tmp);

	state->name = alloc_sname(buf);
	state->data = links;
	return state;
}

struct smatch_state *merge_link_states(struct smatch_state *s1, struct smatch_state *s2)
{
	struct var_sym_list *new_links;

	if (s1 == &undefined)
		return s2;
	if (s2 == &undefined)
		return s1;

	if (var_sym_lists_equiv(s1->data, s2->data))
		return s1;

	new_links = clone_var_sym_list(s1->data);
	merge_var_sym_list(&new_links, s2->data);

	return alloc_link(new_links);
}

void store_link(int link_id, const char *var, struct symbol *sym, const char *link_name, struct symbol *link_sym)
{

	struct smatch_state *old_state;
	struct var_sym_list *links;

	if (!cur_func_sym)
		return;

	old_state = get_state(link_id, var, sym);
	if (old_state)
		links = clone_var_sym_list(old_state->data);
	else
		links = NULL;

	add_var_sym(&links, link_name, link_sym);
	set_state(link_id, var, sym, alloc_link(links));
}

static void match_link_modify(struct sm_state *sm, struct expression *mod_expr)
{
	struct var_sym_list *links;
	struct var_sym *tmp;

	links = sm->state->data;

	FOR_EACH_PTR(links, tmp) {
		set_state(sm->owner - 1, tmp->var, tmp->sym, &undefined);
	} END_FOR_EACH_PTR(tmp);
	set_state(sm->owner, sm->name, sm->sym, &undefined);
}

void set_up_link_functions(int id, int link_id)
{
	if (id + 1 != link_id)
		sm_fatal("FATAL ERROR: links need to be registered directly after the check");

	set_dynamic_states(link_id);
	add_merge_hook(link_id, &merge_link_states);
	add_modification_hook(link_id, &match_link_modify);
	// free link at the end of function
}


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

/*
 * Say you have a condition like:
 *
 *     if (foo < 0)
 *         return foo;
 *
 * But we actually know that foo is zero.  Then in smatch_extra.c we set "foo"
 * to the empty state and then for the return statement we say that "foo" is
 * s32min-s32max because we can't return the empty state.
 *
 * This file is supposed to provide an alternative to say that actually "foo" is
 * less than zero.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static struct smatch_state *empty_state(struct sm_state *sm)
{
	return alloc_estate_empty();
}

struct smatch_state *merge_is_empty(struct smatch_state *s1, struct smatch_state *s2)
{
	return alloc_estate_empty();
}

static void reset(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, alloc_estate_empty());
}

void __save_imaginary_state(struct expression *expr, struct range_list *true_rl, struct range_list *false_rl)
{
	set_true_false_states_expr(my_id, expr, alloc_estate_rl(true_rl), alloc_estate_rl(false_rl));
}

int get_imaginary_absolute(struct expression *expr, struct range_list **rl)
{
	struct smatch_state *state;

	*rl = NULL;

	state = get_state_expr(my_id, expr);
	if (!state || !estate_rl(state))
		return 0;

	*rl = estate_rl(state);
	return 1;
}

void register_imaginary_absolute(int id)
{
	my_id = id;

	add_unmatched_state_hook(my_id, &empty_state);
	add_merge_hook(my_id, &merge_is_empty);
	add_modification_hook(my_id, &reset);
}


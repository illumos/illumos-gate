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
#include "smatch_extra.h"

static int my_id;

STATE(positive);
STATE(ok);

static void ok_to_use(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state != &ok)
		set_state(my_id, sm->name, sm->sym, &ok);
}

static void match_assign(const char *fn, struct expression *expr, void *unused)
{
	struct range_list *rl;

	if (!get_implied_rl(expr->right, &rl))
		return;
	if (rl_max(rl).value != 1)
		return;
	set_state_expr(my_id, expr->left, &positive);
}

static void match_condition(struct expression *expr)
{
	if (!get_state_expr(my_id, expr))
		return;
	/* If the variable is zero that's ok */
	set_true_false_states_expr(my_id, expr, NULL, &ok);
}

static void match_return(struct expression *ret_value)
{
	struct smatch_state *state;
	struct sm_state *sm;
	sval_t min;

	sm = get_sm_state_expr(my_id, ret_value);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &positive))
		return;
	state = get_state_expr(SMATCH_EXTRA, ret_value);
	if (!state)
		return;
	if (!get_absolute_min(ret_value, &min))
		return;
	if (min.value == 0)
		return;
	sm_warning("dma_mapping_error() doesn't return an error code");
}

void check_dma_mapping_error(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_assign_hook("dma_mapping_error", &match_assign, NULL);
	add_function_assign_hook("pci_dma_mapping_error", &match_assign, NULL);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_return, RETURN_HOOK);
	add_modification_hook(my_id, &ok_to_use);
}

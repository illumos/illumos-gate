/*
 * Copyright (C) 2010 Dan Carpenter.
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

static void ok_to_use(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &undefined);
}

static void match_snprintf(const char *fn, struct expression *expr, void *info)
{
	struct expression *call;
	struct expression *arg;
	sval_t buflen;

	call = strip_expr(expr->right);
	arg = get_argument_from_call_expr(call->args, 1);
	if (!get_fuzzy_max(arg, &buflen))
		return;
	set_state_expr(my_id, expr->left, alloc_state_num(buflen.value));
}

static int get_old_buflen(struct sm_state *sm)
{
	struct sm_state *tmp;
	int ret = 0;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (PTR_INT(tmp->state->data) > ret)
			ret = PTR_INT(tmp->state->data);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

static void match_call(struct expression *expr)
{
	struct expression *arg;
	struct sm_state *sm;
	int old_buflen;
	sval_t max;

	FOR_EACH_PTR(expr->args, arg) {
		sm = get_sm_state_expr(my_id, arg);
		if (!sm)
			continue;
		old_buflen = get_old_buflen(sm);
		if (!old_buflen)
			return;
		if (get_absolute_max(arg, &max) && sval_cmp_val(max, old_buflen) > 0)
			sm_warning("'%s' returned from snprintf() might be larger than %d",
				sm->name, old_buflen);
	} END_FOR_EACH_PTR(arg);
}

void check_snprintf(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	if (!option_spammy)
		return;

	my_id = id;
	set_dynamic_states(my_id);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
	add_function_assign_hook("snprintf", &match_snprintf, NULL);
	add_modification_hook(my_id, &ok_to_use);
}


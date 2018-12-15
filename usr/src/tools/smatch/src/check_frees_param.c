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
 * This file is sort of like check_dereferences_param.c.  In theory the one
 * difference should be that the param is NULL it should still be counted as a
 * free.  But for now I don't handle that case.
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(freed);
STATE(ignore);
STATE(param);

static void set_ignore(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &ignore);
}

static void match_function_def(struct symbol *sym)
{
	struct symbol *arg;
	int i;

	i = -1;
	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		i++;
		if (!arg->ident)
			continue;
		set_state(my_id, arg->ident->name, arg, &param);
	} END_FOR_EACH_PTR(arg);
}

static void freed_variable(struct expression *expr)
{
	struct sm_state *sm;

	expr = strip_expr(expr);
	if (get_param_num(expr) < 0)
		return;

	sm = get_sm_state_expr(my_id, expr);
	if (sm && slist_has_state(sm->possible, &ignore))
		return;
	set_state_expr(my_id, expr, &freed);
}

static void match_free(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, PTR_INT(param));
	if (!arg)
		return;
	freed_variable(arg);
}

static void set_param_freed(struct expression *call, struct expression *arg, char *key, char *unused)
{
	/* XXX FIXME: return_implies has been updated with more information */
	if (strcmp(key, "$") != 0)
		return;
	freed_variable(arg);
}

static void process_states(void)
{
	struct sm_state *sm;
	int param;
	const char *param_name;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state != &freed)
			continue;
		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;
		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		sql_insert_return_implies(PARAM_FREED, param, param_name, "1");
	} END_FOR_EACH_SM(sm);

}

void check_frees_param(int id)
{
	my_id = id;

	if (option_project == PROJ_KERNEL) {
		/* The kernel uses check_frees_param_strict.c */
		return;
	}

	add_hook(&match_function_def, FUNC_DEF_HOOK);

	add_function_hook("free", &match_free, INT_PTR(0));

	select_return_implies_hook(PARAM_FREED, &set_param_freed);
	add_modification_hook(my_id, &set_ignore);

	all_return_states_hook(&process_states);
}

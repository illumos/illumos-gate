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
 * This is an --info recipe.  The goal is to print a message for every parameter
 * which we can not avoid dereferencing.  This is maybe a bit restrictive but it
 * avoids some false positives.
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

STATE(derefed);
STATE(ignore);
STATE(param);

static void set_ignore(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state == &derefed)
		return;
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

static void check_deref(struct expression *expr)
{
	struct expression *tmp;
	struct sm_state *sm;

	tmp = get_assigned_expr(expr);
	if (tmp)
		expr = tmp;
	expr = strip_expr(expr);

	if (get_param_num(expr) < 0)
		return;

	if (param_was_set(expr))
		return;

	sm = get_sm_state_expr(my_id, expr);
	if (sm && slist_has_state(sm->possible, &ignore))
		return;
	set_state_expr(my_id, expr, &derefed);
}

static void match_dereference(struct expression *expr)
{
	if (expr->type != EXPR_PREOP)
		return;
	check_deref(expr->unop);
}

static void set_param_dereferenced(struct expression *call, struct expression *arg, char *key, char *unused)
{
	/* XXX FIXME: param_implies has more information now */
	if (strcmp(key, "$") != 0)
		return;
	check_deref(arg);
}

static void process_states(void)
{
	struct sm_state *tmp;
	int arg;
	const char *name;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), tmp) {
		if (tmp->state != &derefed)
			continue;
		arg = get_param_num_from_sym(tmp->sym);
		if (arg < 0)
			continue;
		name = get_param_name(tmp);
		if (!name)
			continue;
		sql_insert_return_implies(DEREFERENCE, arg, name, "1");
	} END_FOR_EACH_SM(tmp);
}

static void match_pointer_as_array(struct expression *expr)
{
	if (!is_array(expr))
		return;
	check_deref(get_array_base(expr));
}

void check_dereferences_param(int id)
{
	my_id = id;

	add_hook(&match_function_def, FUNC_DEF_HOOK);

	add_hook(&match_dereference, DEREF_HOOK);
	add_hook(&match_pointer_as_array, OP_HOOK);
	select_return_implies_hook(DEREFERENCE, &set_param_dereferenced);
	add_modification_hook(my_id, &set_ignore);

	all_return_states_hook(&process_states);
}

/*
 * Copyright (C) 2009 Dan Carpenter.
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
#include "smatch_extra.h"

static int my_id;

STATE(derefed);

static void underef(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &undefined);
}

static void match_dereference(struct expression *expr)
{
	if (__in_fake_assign)
		return;

	if (expr->type != EXPR_PREOP)
		return;
	expr = strip_expr(expr->unop);
	if (!is_pointer(expr))
		return;
	if (implied_not_equal(expr, 0))
		return;

	if (is_impossible_path())
		return;

	set_state_expr(my_id, expr, &derefed);
}

static void set_param_dereferenced(struct expression *call, struct expression *arg, char *key, char *unused)
{
	struct symbol *sym;
	char *name;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	if (implied_not_equal_name_sym(name, sym, 0))
		goto free;
	set_state(my_id, name, sym, &derefed);

free:
	free_string(name);
}

static void match_condition(struct expression *expr)
{
	struct sm_state *sm;
	char *name;

	if (__in_pre_condition)
		return;

	name = get_macro_name(expr->pos);
	if (name &&
	    (strcmp(name, "likely") != 0 && strcmp(name, "unlikely") != 0))
		return;

	if (!is_pointer(expr))
		return;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm || sm->state != &derefed)
		return;

	sm_warning("variable dereferenced before check '%s' (see line %d)", sm->name, sm->line);
	set_state_expr(my_id, expr, &undefined);
}

void check_deref_check(int id)
{
	my_id = id;
	add_hook(&match_dereference, DEREF_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	select_return_implies_hook(DEREFERENCE, &set_param_dereferenced);
	add_modification_hook(my_id, &underef);
}

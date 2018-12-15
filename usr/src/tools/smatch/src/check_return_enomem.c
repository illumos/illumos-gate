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

/*
 * Complains about places that return -1 instead of -ENOMEM
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static void match_return(struct expression *ret_value)
{
	struct expression *expr;
	struct sm_state *sm;
	struct stree *stree;
	sval_t sval;

	if (!ret_value)
		return;
	if (returns_unsigned(cur_func_sym))
		return;
	if (returns_pointer(cur_func_sym))
		return;
	if (!get_value(ret_value, &sval) || sval.value != -1)
		return;
	if (get_macro_name(ret_value->pos))
		return;

	stree = __get_cur_stree();

	FOR_EACH_MY_SM(SMATCH_EXTRA, stree, sm) {
		if (!estate_get_single_value(sm->state, &sval) || sval.value != 0)
			continue;
		expr = get_assigned_expr_name_sym(sm->name, sm->sym);
		if (!expr)
			continue;
		if (expr->type != EXPR_CALL || expr->fn->type != EXPR_SYMBOL)
			continue;
		if (!expr->fn->symbol_name)
			continue;
		/* To be honest the correct check is:
		 * if (strstr(expr->fn->symbol_name->name, "alloc"))
		 * 	complain();
		 * But it generates too many warnings and it's too depressing.
		 */
		if (strcmp(expr->fn->symbol_name->name, "kmalloc") != 0 &&
		    strcmp(expr->fn->symbol_name->name, "kzalloc") != 0)
			continue;

		sm_warning("returning -1 instead of -ENOMEM is sloppy");
		return;

	} END_FOR_EACH_SM(sm);
}

void check_return_enomem(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_hook(&match_return, RETURN_HOOK);
}

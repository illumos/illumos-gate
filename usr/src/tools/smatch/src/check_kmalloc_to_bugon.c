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

static int my_id;

extern int check_assigned_expr_id;

static int is_kmalloc_call(struct expression *expr)
{
	if (expr->type != EXPR_CALL)
		return 0;
	if (expr->fn->type != EXPR_SYMBOL)
		return 0;
	if (!strcmp(expr->fn->symbol_name->name, "kmalloc"))
		return 1;
	if (!strcmp(expr->fn->symbol_name->name, "kzalloc"))
		return 1;
	return 0;
}

static void match_condition(struct expression *expr)
{
	char *macro;
	struct smatch_state *state;
	struct expression *right;
	char *name;

	macro = get_macro_name(expr->pos);
	if (!macro || strcmp(macro, "BUG_ON") != 0)
		return;
	state = get_state_expr(check_assigned_expr_id, expr);
	if (!state || !state->data)
		return;
	right = (struct expression *)state->data;
	if (!is_kmalloc_call(right))
		return;

	name = expr_to_var(expr);
	sm_warning("bug on allocation failure '%s'", name);
	free_string(name);
}

void check_kmalloc_to_bugon(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	if (!option_spammy)
		return;
	my_id = id;
	add_hook(&match_condition, CONDITION_HOOK);
}

/*
 * Copyright (C) 2011 Dan Carpenter.
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

static void match_return(struct expression *ret_value)
{
	struct expression *expr;
	char *macro;

	if (!ret_value)
		return;
	expr = ret_value;
	if (ret_value->type != EXPR_PREOP || ret_value->op != '-')
		return;

	macro = get_macro_name(expr->unop->pos);
	if (macro && !strcmp(macro, "PTR_ERR")) {
		sm_warning("returning -%s()", macro);
		return;
	}

	if (!option_spammy)
		return;

	expr = get_assigned_expr(ret_value->unop);
	if (!expr)
		return;
	if (expr->type != EXPR_CALL)
		return;

	sm_warning("should this return really be negated?");
}

void check_return_negative_var(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_hook(&match_return, RETURN_HOOK);
}

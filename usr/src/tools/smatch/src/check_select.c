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

static int my_id;

static void match_select(struct expression *expr)
{
	if (expr->cond_true)
		return;
	expr = strip_expr(expr->conditional);
	if (expr->type != EXPR_COMPARE)
		return;
	sm_warning("boolean comparison inside select");
}

void check_select(int id)
{
	my_id = id;
	add_hook(&match_select, SELECT_HOOK);
}

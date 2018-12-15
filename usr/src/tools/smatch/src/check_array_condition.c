/*
 * Copyright (C) 2013 Oracle.
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
 * struct foo { char buf[10]; };
 *
 * struct foo *p = something();
 * if (p->buf) { ...
 *
 */

#include "smatch.h"

static int my_id;

static void match_condition(struct expression *expr)
{
	struct symbol *type;
	char *str;

	if (expr->type != EXPR_DEREF)
		return;
	type = get_type(expr);
	if (!type || type->type != SYM_ARRAY)
		return;
	if (get_macro_name(expr->pos))
		return;

	str = expr_to_str(expr);
	sm_warning("this array is probably non-NULL. '%s'", str);
	free_string(str);
}

void check_array_condition(int id)
{
	my_id = id;
	add_hook(&match_condition, CONDITION_HOOK);
}

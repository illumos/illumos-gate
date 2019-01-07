/*
 * Copyright (C) 2017 Oracle.
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

static int find_param_eq(struct expression *expr, int size)
{
	struct expression *arg;
	sval_t val;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		if (!get_implied_value(arg, &val))
			continue;
		if (val.value == size)
			return i;
	} END_FOR_EACH_PTR(arg);

	return -1;
}

static void match_call(struct expression *expr)
{
	struct expression *arg;
	struct symbol *type;
	int size, bytes;
	int i, nr;
	char buf[16];


	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		type = get_type(arg);
		if (!type || (type->type != SYM_PTR && type->type != SYM_ARRAY))
			continue;
		size = get_array_size(arg);
		if (size > 0) {
			nr = find_param_eq(expr, size);
			if (nr >= 0) {
				snprintf(buf, sizeof(buf), "%d", nr);
				sql_insert_caller_info(expr, ARRAYSIZE_ARG, i, buf, "");
				continue;
			}
		}
		bytes = get_array_size_bytes(arg);
		if (bytes > 0) {
			nr = find_param_eq(expr, bytes);
			if (nr >= 0) {
				snprintf(buf, sizeof(buf), "%d", nr);
				sql_insert_caller_info(expr, SIZEOF_ARG, i, buf, "");
				continue;
			}
		}
	} END_FOR_EACH_PTR(arg);
}

void register_passes_array_size(int id)
{
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}


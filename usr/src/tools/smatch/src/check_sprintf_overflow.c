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

static void match_sprintf(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	struct expression *format_string;
	struct expression *data;
	char *data_name = NULL;
	int dest_size;
	char *format;
	int data_size;

	dest = get_argument_from_call_expr(expr->args, 0);
	format_string = get_argument_from_call_expr(expr->args, 1);
	data = get_argument_from_call_expr(expr->args, 2);

	dest_size = get_array_size_bytes(dest);
	if (!dest_size)
		return;
	format = expr_to_var(format_string);
	if (!format)
		return;
	if (strcmp(format, "\"%s\""))
		goto free;
	data_name = expr_to_str(data);
	data_size = get_size_from_strlen(data);
	if (!data_size)
		data_size = get_array_size_bytes(data);
	if (dest_size < data_size)
		sm_error("sprintf() copies too much data from '%s': %d vs %d",
		       data_name, data_size, dest_size);
free:
	free_string(data_name);
	free_string(format);
}

void check_sprintf_overflow(int id)
{
	add_function_hook("sprintf", &match_sprintf, NULL);
}

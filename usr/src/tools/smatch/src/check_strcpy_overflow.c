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

static void match_strcpy(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	struct expression *data;
	char *dest_name = NULL;
	char *data_name = NULL;
	int dest_size;
	int data_size;

	dest = get_argument_from_call_expr(expr->args, 0);
	data = get_argument_from_call_expr(expr->args, 1);
	dest_size = get_array_size_bytes(dest);
	if (!dest_size)
		return;

	data_size = get_size_from_strlen(data);
	if (!data_size)
		data_size = get_array_size_bytes(data);

	/* If the size of both arrays is known and the destination
	 * buffer is larger than the source buffer, we're okay.
	 */
	if (data_size && dest_size >= data_size)
		return;

	dest_name = expr_to_str(dest);
	data_name = expr_to_str(data);

	if (data_size)
		sm_error("%s() '%s' too large for '%s' (%d vs %d)",
			fn, data_name, dest_name, data_size, dest_size);
	else if (option_spammy)
		sm_warning("%s() '%s' of unknown size might be too large for '%s'",
			fn, data_name, dest_name);

	free_string(dest_name);
	free_string(data_name);
}

void check_strcpy_overflow(int id)
{
	add_function_hook("strcpy", &match_strcpy, NULL);
}

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
static int returned;

static void match_return(struct expression *ret_value)
{
	if (__inline_fn)
		return;
	if (is_reachable())
		returned = 1;
}

static void match_func_end(struct symbol *sym)
{
	if (__inline_fn)
		return;
	if (!is_reachable() && !returned)
		sm_info("info: add to no_return_funcs");
	returned = 0;
}

void check_no_return(int id)
{
	if (!option_info)
		return;
	my_id = id;
	add_hook(&match_return, RETURN_HOOK);
	add_hook(&match_func_end, END_FUNC_HOOK);
}

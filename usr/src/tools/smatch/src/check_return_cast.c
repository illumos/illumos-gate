/*
 * Copyright (C) 2012 Oracle.
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

static int my_id;

static void match_return(struct expression *ret_value)
{
	struct symbol *func_type = get_real_base_type(cur_func_sym);
	sval_t sval;

	if (!func_type)
		return;
	if (!type_unsigned(func_type))
		return;
	if (type_bits(func_type) > 16)
		return;
	if (!get_fuzzy_min(ret_value, &sval))
		return;
	if (sval_is_positive(sval) || sval_cmp_val(sval, -1) == 0)
		return;

	sm_warning("signedness bug returning '%s'", sval_to_str(sval));
}

void check_return_cast(int id)
{
	my_id = id;
	add_hook(&match_return, RETURN_HOOK);
}

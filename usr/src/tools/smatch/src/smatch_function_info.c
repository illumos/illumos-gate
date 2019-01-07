/*
 * Copyright (C) 2014 Oracle.
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
 * Record parameter types in the database.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

static void match_def(struct symbol *sym)
{
	struct symbol *arg;
	int i;

	i = -1;
	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		i++;
		sql_insert_function_type(i, type_to_str(get_real_base_type(arg)));
	} END_FOR_EACH_PTR(arg);
}

void register_function_info(int id)
{
	my_id = id;
	add_hook(match_def, FUNC_DEF_HOOK);
}

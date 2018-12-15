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

static void match_def(struct symbol *sym)
{
	struct symbol *param;
	int i;

	if (__inline_fn)
		return;

	i = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, param) {
		i++;
		if (!param->ident)
			continue;
		sql_insert_parameter_name(i, param->ident->name);
	} END_FOR_EACH_PTR(param);
}

void register_parameter_names(int id)
{
	if (!option_info)
		return;

	add_hook(&match_def, FUNC_DEF_HOOK);
}

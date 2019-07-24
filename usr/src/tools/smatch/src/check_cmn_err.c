/*
 * Copyright (C) 2016 Oracle.
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
 *
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Heavily borrowed from check_wine.c: what we're doing here is teaching smatch
 * that cmn_err(CE_PANIC, ...) is noreturn.
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_extra.h"

#define	CE_PANIC (3)

void match_cmn_err(const char *fn, struct expression *expr,
			void *unused)
{
	struct expression *arg;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!get_implied_value(arg, &sval))
		return;

	if (sval.value == CE_PANIC)
		nullify_path();
}


void check_cmn_err(int id)
{
	if (option_project != PROJ_ILLUMOS_KERNEL)
		return;

	add_function_hook("cmn_err", &match_cmn_err, NULL);
}

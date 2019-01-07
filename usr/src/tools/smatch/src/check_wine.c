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
 */

/*
 * This is wine specific stuff for smatch_extra.
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_extra.h"

/* report (R_FATAL, "Can't get OS version."); */
void match_fatal_report(const char *fn, struct expression *expr,
			void *unused)
{
	struct expression *arg;
	sval_t sval;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!get_implied_value(arg, &sval))
		return;

	/* R_FATAL is 9. */
	if (sval.value == 9)
		nullify_path();
}


void check_wine(int id)
{
	if (option_project != PROJ_WINE)
		return;

	add_function_hook("report", &match_fatal_report, NULL);
}

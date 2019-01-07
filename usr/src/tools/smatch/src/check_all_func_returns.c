/*
 * Copyright 2018 Joyent, Inc.
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
 * Like lint of old, check that every return value from every function is used.
 * Casting to (void) will silence this check.
 */

#include "smatch.h"
#include "smatch_slist.h"

static void check_func_return(struct expression *expr)
{
	struct symbol *sym = get_real_base_type(get_type(expr->fn));
	const char *func = expr_to_str(expr->fn);
	struct statement *stmt;

	if (sym == NULL) {
		sm_error("unknown type for func '%s'", func);
		return;
	}

	if (expr->type != EXPR_CALL) {
		sm_error("func '%s' is not a call site", func);
		return;
	}

	/*
	 * There is never any need to check these returns.
	 */
	if (strcmp(func, "memcpy") == 0 ||
	    strcmp(func, "memmove") == 0 ||
	    strcmp(func, "memset") == 0)
		return;

	/*
	 * Closer to a policy here, but there seems very few cases where it's
	 * useful to check the return value of the standard printf() family
	 * outputting to stdout or stderr.
	 */
	if (strcmp(func, "printf") == 0 || strcmp(func, "vprintf") == 0)
		return;

	if (strcmp(func, "fprintf") == 0 || strcmp(func, "vfprintf")) {
		const char *arg0 = expr_to_str(get_argument_from_call_expr(expr->args, 0));

		if (arg0 != NULL &&
		    (strcmp(arg0, "(&__iob[1])") == 0 ||
		    strcmp(arg0, "(&__iob[2])") == 0))
			return;
	}

	/*
	 * Either we got the return type already (direct call),
	 * or we need to go one further (function pointer call)
	 */
	if (sym == &void_ctype || (sym->type == SYM_FN &&
		get_real_base_type(sym) == &void_ctype))
		return;

	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);

	if (stmt->type == STMT_EXPRESSION && stmt->expression == expr)
		sm_error("unchecked function return '%s'", expr_to_str(expr->fn));
}

void check_all_func_returns(int id)
{
	if (option_project != PROJ_ILLUMOS_KERNEL &&
	    option_project != PROJ_ILLUMOS_USER)
		return;

	add_hook(&check_func_return, FUNCTION_CALL_HOOK);
}

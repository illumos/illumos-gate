/*
 * Copyright (C) 2013 Oracle.
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
 * A place to add function annotations for common functions.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"

static int param_caps_return(struct expression *call, void *_arg, struct range_list **res)
{
	int arg = PTR_INT(_arg);
	struct expression *expr;
	struct range_list *rl;

	expr = get_argument_from_call_expr(call->args, arg);
	if (get_implied_rl(expr, &rl) && rl_max(rl).value != 0)
		*res = alloc_rl(sval_type_val(rl_type(rl), 0), rl_max(rl));
	return 1;
}

void register_annotate(int id)
{
	/*
	 * Technically snprintf() returns the number of bytes which *would* have
	 * been printed.  I do try caclulating that in check_snprintf().  But
	 * it probably works better to assume the limitter is accurate.
	 */
	add_implied_return_hook("snprintf", &param_caps_return, INT_PTR(1));

}

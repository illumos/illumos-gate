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

#include "scope.h"
#include "smatch.h"
#include "smatch_extra.h"

static int match_strlen(struct expression *call, void *unused, struct range_list **rl)
{
	struct expression *str;
	unsigned long max;

	str = get_argument_from_call_expr(call->args, 0);
	if (get_implied_strlen(str, rl) && sval_is_positive(rl_min(*rl))) {
		*rl = cast_rl(&ulong_ctype, *rl);
		return 1;
	}
	/* smatch_strlen.c is not very complete */
	max = get_array_size_bytes_max(str);
	if (max == 0) {
		*rl = alloc_rl(sval_type_val(&ulong_ctype, 0),
			       sval_type_val(&ulong_ctype, STRLEN_MAX_RET));
	} else {
		max--;
		*rl = alloc_rl(sval_type_val(&ulong_ctype, 0),
			       sval_type_val(&ulong_ctype, max));
	}
	return 1;
}

static int match_strnlen(struct expression *call, void *unused, struct range_list **rl)
{
	struct expression *limit;
	sval_t fixed;
	sval_t bound;
	sval_t ulong_max = sval_type_val(&ulong_ctype, ULONG_MAX);

	match_strlen(call, NULL, rl);
	limit = get_argument_from_call_expr(call->args, 1);
	if (!get_implied_max(limit, &bound))
		return 1;
	if (sval_cmp(bound, ulong_max) == 0)
		return 1;
	if (rl_to_sval(*rl, &fixed) && sval_cmp(fixed, bound) >= 0) {
		*rl = alloc_rl(bound, bound);
		return 1;
	}

	bound.value++;
	*rl = remove_range(*rl, bound, ulong_max);

	return 1;
}

static int match_sprintf(struct expression *call, void *_arg, struct range_list **rl)
{
	int str_arg = PTR_INT(_arg);
	int min, max;

	min = get_formatted_string_min_size(call, str_arg);
	max = get_formatted_string_size(call, str_arg);
	if (min < 0 || max < 0) {
		*rl = alloc_whole_rl(&ulong_ctype);
	} else {
		*rl = alloc_rl(ll_to_sval(min), ll_to_sval(max));
		*rl = cast_rl(get_type(call), *rl);
	}
	return 1;
}

void register_common_functions(int id)
{
	/*
	 * When you add a new function here, then don't forget to delete it from
	 * the database and smatch_data/.
	 */
	add_implied_return_hook("strlen", &match_strlen, NULL);
	add_implied_return_hook("strnlen", &match_strnlen, NULL);
	add_implied_return_hook("sprintf", &match_sprintf, INT_PTR(1));
	add_implied_return_hook("snprintf", &match_sprintf, INT_PTR(2));
}

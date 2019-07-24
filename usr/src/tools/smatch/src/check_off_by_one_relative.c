/*
 * Copyright (C) 2015 Oracle.
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
 * The point here is to store that a buffer has x bytes even if we don't know
 * the value of x.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static void array_check(struct expression *expr)
{
	struct expression *array;
	struct expression *size;
	struct expression *offset;
	char *array_str, *offset_str;
	int limit_type;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	array = get_array_base(expr);
	size = get_size_variable(array, &limit_type);
	if (!size || limit_type != ELEM_COUNT)
		return;
	offset = get_array_offset(expr);
	if (!possible_comparison(size, SPECIAL_EQUAL, offset))
		return;

	if (buf_comparison_index_ok(expr))
		return;

	array_str = expr_to_str(array);
	offset_str = expr_to_str(offset);
	sm_warning("potentially one past the end of array '%s[%s]'", array_str, offset_str);
	free_string(array_str);
	free_string(offset_str);
}

static int known_access_ok_numbers(struct expression *expr)
{
	struct expression *array;
	struct expression *offset;
	sval_t max;
	int size;

	array = get_array_base(expr);
	offset = get_array_offset(expr);

	size = get_array_size(array);
	if (size <= 0)
		return 0;

	get_absolute_max(offset, &max);
	if (max.uvalue < size)
		return 1;
	return 0;
}

static void array_check_data_info(struct expression *expr)
{
	struct expression *array;
	struct expression *offset;
	struct state_list *slist;
	struct sm_state *sm;
	struct compare_data *comp;
	char *offset_name;
	const char *equal_name = NULL;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	if (known_access_ok_numbers(expr))
		return;
	if (buf_comparison_index_ok(expr))
		return;

	array = get_array_base(expr);
	offset = get_array_offset(expr);
	offset_name = expr_to_var(offset);
	if (!offset_name)
		return;
	slist = get_all_possible_equal_comparisons(offset);
	if (!slist)
		goto free;

	FOR_EACH_PTR(slist, sm) {
		comp = sm->state->data;
		if (strcmp(comp->left_var, offset_name) == 0) {
			if (db_var_is_array_limit(array, comp->right_var, comp->right_vsl)) {
				equal_name = comp->right_var;
				break;
			}
		} else if (strcmp(comp->right_var, offset_name) == 0) {
			if (db_var_is_array_limit(array, comp->left_var, comp->left_vsl)) {
				equal_name = comp->left_var;
				break;
			}
		}
	} END_FOR_EACH_PTR(sm);

	if (equal_name) {
		char *array_name = expr_to_str(array);

		sm_warning("potential off by one '%s[]' limit '%s'", array_name, equal_name);
		free_string(array_name);
	}

free:
	free_slist(&slist);
	free_string(offset_name);
}

void check_off_by_one_relative(int id)
{
	my_id = id;

	add_hook(&array_check, OP_HOOK);
	add_hook(&array_check_data_info, OP_HOOK);
}


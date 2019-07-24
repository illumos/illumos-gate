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

#include <stdlib.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

/*
 * This check has two smatch IDs.
 * my_used_id - keeps a record of array offsets that have been used.
 *              If the code checks that they are within bounds later on,
 *              we complain about using an array offset before checking
 *              that it is within bounds.
 */
static int my_used_id;

static void delete(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_used_id, sm->name, sm->sym, &undefined);
}

static void array_check(struct expression *expr)
{
	struct expression *array_expr;
	int array_size;
	struct expression *offset;
	struct range_list *rl;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	array_expr = get_array_base(expr);
	array_size = get_array_size(array_expr);
	if (!array_size || array_size == 1)
		return;

	offset = get_array_offset(expr);
	get_absolute_rl(offset, &rl);
	if (rl_max(rl).uvalue < array_size)
		return;
	if (buf_comparison_index_ok(expr))
		return;

	if (getting_address())
		return;
	if (is_capped(offset))
		return;
	set_state_expr(my_used_id, offset, alloc_state_num(array_size));
}

static void match_condition(struct expression *expr)
{
	int left;
	sval_t sval;
	struct state_list *slist;
	struct sm_state *tmp;
	int boundary;

	if (!expr || expr->type != EXPR_COMPARE)
		return;
	if (get_macro_name(expr->pos))
		return;
	if (get_implied_value(expr->left, &sval))
		left = 1;
	else if (get_implied_value(expr->right, &sval))
		left = 0;
	else
		return;

	if (left)
		slist = get_possible_states_expr(my_used_id, expr->right);
	else
		slist = get_possible_states_expr(my_used_id, expr->left);
	if (!slist)
		return;
	FOR_EACH_PTR(slist, tmp) {
		if (tmp->state == &merged || tmp->state == &undefined)
			continue;
		boundary = PTR_INT(tmp->state->data);
		boundary -= sval.value;
		if (boundary < 1 && boundary > -1) {
			char *name;

			name = expr_to_var(left ? expr->right : expr->left);
			sm_error("testing array offset '%s' after use.", name);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
}

void check_testing_index_after_use(int id)
{
	my_used_id = id;
	set_dynamic_states(my_used_id);
	add_hook(&array_check, OP_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	add_modification_hook(my_used_id, &delete);
}

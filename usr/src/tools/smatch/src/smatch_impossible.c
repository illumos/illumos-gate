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

#include "smatch.h"
#include "smatch_extra.h"

static int my_id;
static int my_return_id;

STATE(impossible);

int is_impossible_path(void)
{
	if (get_state(my_id, "impossible", NULL) == &impossible)
		return 1;
	return 0;
}

static void handle_compare(struct expression *left, int op, struct expression *right)
{
	int true_impossible = 0;
	int false_impossible = 0;

	left = strip_expr(left);
	while (left && left->type == EXPR_ASSIGNMENT)
		left = strip_expr(left->left);

	if (!possibly_true(left, op, right))
		true_impossible = 1;
	if (!possibly_false(left, op, right))
		false_impossible = 1;

	if (!true_impossible && !false_impossible)
		return;

	set_true_false_states(my_id, "impossible", NULL,
			      true_impossible ? &impossible : NULL,
			      false_impossible ? &impossible : NULL);

	if (inside_loop())
		return;

	set_true_false_states(my_return_id, "impossible", NULL,
			      true_impossible ? &impossible : NULL,
			      false_impossible ? &impossible : NULL);
}

static void match_condition(struct expression *expr)
{
	if (expr->type == EXPR_COMPARE)
		handle_compare(expr->left, expr->op, expr->right);
	else
		handle_compare(expr, SPECIAL_NOTEQUAL, zero_expr());
}

void set_path_impossible(void)
{
	set_state(my_id, "impossible", NULL, &impossible);

	if (inside_loop())
		return;

	set_state(my_return_id, "impossible", NULL, &impossible);
}

static void match_case(struct expression *expr, struct range_list *rl)
{
	if (rl)
		return;
	set_path_impossible();
}

static void print_impossible_return(int return_id, char *return_ranges, struct expression *expr)
{
	if (get_state(my_return_id, "impossible", NULL) == &impossible) {
		if (option_debug)
			sm_msg("impossible return.  return_id = %d return ranges = %s", return_id, return_ranges);
		sql_insert_return_states(return_id, return_ranges, CULL_PATH, -1, "", "");
	}
}

void register_impossible(int id)
{
	my_id = id;

	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_case, CASE_HOOK);
}

void register_impossible_return(int id)
{
	my_return_id = id;

	add_split_return_callback(&print_impossible_return);
}

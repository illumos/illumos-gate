/*
 * Copyright (C) 2011 Dan Carpenter.
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
#include "smatch_slist.h"

static int my_id;

static int right_side_changes(struct expression *expr)
{
	sval_t dummy;

	if (get_value(expr->right, &dummy))
		return 0;
	return 1;
}

static struct expression *get_iterator_set(struct statement *stmt)
{
	struct expression *expr;

	if (!stmt)
		return NULL;
	if (stmt->type != STMT_EXPRESSION)
		return NULL;
	expr = stmt->expression;
	if (expr->type != EXPR_ASSIGNMENT)
		return NULL;
	if (expr->op != '=')
		return NULL;
	if (right_side_changes(expr))
		return NULL;
	return expr->left;
}

static struct expression *get_iterator_tested(struct expression *expr)
{
	if (!expr)
		return NULL;
	if (expr->type != EXPR_COMPARE)
		return NULL;
	return expr->left;
}

static void match_loop(struct statement *stmt)
{
	struct expression *iterator;
	char *iter_set;
	char *iter_tested;

	if (get_macro_name(stmt->pos))
		return;

	iterator = get_iterator_set(stmt->iterator_pre_statement);
	iter_set = expr_to_var(iterator);
	iterator = get_iterator_tested(stmt->iterator_pre_condition);
	iter_tested = expr_to_var(iterator);
	if (!iter_set || !iter_tested)
		goto free;
	if (strcmp(iter_set, iter_tested))
		goto free;

	/* smatch doesn't handle loops correctly so this silences some
	 * false positives.
	 */
	if (right_side_changes(stmt->iterator_pre_condition))
		goto free;

	if (implied_condition_false(stmt->iterator_pre_condition))
		sm_warning("we never enter this loop");

free:
	free_string(iter_set);
	free_string(iter_tested);
}

void check_bogus_loop(int id)
{
	my_id = id;
	add_hook(&match_loop, PRELOOP_HOOK);
}

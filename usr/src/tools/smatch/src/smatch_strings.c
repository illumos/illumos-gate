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

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static int get_str(void *_ret, int argc, char **argv, char **azColName)
{
	char **ret = _ret;

	if (*ret)
		*ret = (void *)-1UL;
	else
		*ret = alloc_sname(argv[0]);

	return 0;
}

static char *get_string_from_mtag(mtag_t tag)
{
	char *str = NULL;

	run_sql(get_str, &str,
		"select value from mtag_data where tag = %lld and offset = 0 and type = %d;",
		tag, STRING_VALUE);

	if ((unsigned long)str == -1UL)
		return NULL;
	return str;
}

struct expression *fake_string_from_mtag(mtag_t tag)
{
	char *str;

	if (!tag)
		return NULL;
	str = get_string_from_mtag(tag);
	if (!str)
		return NULL;
	return string_expression(str);
}

static void match_strcpy(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest, *src;

	dest = get_argument_from_call_expr(expr->args, 0);
	src = get_argument_from_call_expr(expr->args, 1);
	src = strip_expr(src);
	if (src->type == EXPR_STRING)
		set_state_expr(my_id, dest, alloc_state_str(src->string->data));
}

struct state_list *get_strings(struct expression *expr)
{
	struct state_list *ret = NULL;
	struct smatch_state *state;
	struct sm_state *sm;

	expr = strip_expr(expr);
	if (expr->type == EXPR_STRING) {
		state = alloc_state_str(expr->string->data);
		sm = alloc_sm_state(my_id, expr->string->data, NULL, state);
		add_ptr_list(&ret, sm);
		return ret;
	}

	if (expr->type == EXPR_CONDITIONAL ||
	    expr->type == EXPR_SELECT) {
		struct state_list *true_strings = NULL;
		struct state_list *false_strings = NULL;

		if (known_condition_true(expr->conditional))
			return get_strings(expr->cond_true);
		if (known_condition_false(expr->conditional))
			return get_strings(expr->cond_false);

		true_strings = get_strings(expr->cond_true);
		false_strings = get_strings(expr->cond_false);
		concat_ptr_list((struct ptr_list *)true_strings, (struct ptr_list **)&false_strings);
		free_slist(&true_strings);
		return false_strings;
	}

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return NULL;

	return clone_slist(sm->possible);
}

static void match_assignment(struct expression *expr)
{
	struct state_list *slist;
	struct sm_state *sm;

	if (expr->op != '=')
		return;

	slist = get_strings(strip_expr(expr->right));
	if (!slist)
		return;

	if (ptr_list_size((struct ptr_list *)slist) == 1) {
		sm = first_ptr_list((struct ptr_list *)slist);
		set_state_expr(my_id, expr->left, sm->state);
		return;
	}
}

static void match_string(struct expression *expr)
{
	mtag_t tag;

	if (expr->type != EXPR_STRING || !expr->string->data)
		return;
	if (expr->string->length > 255)
		return;

	if (!get_string_mtag(expr, &tag))
		return;

	cache_sql(NULL, NULL, "insert into mtag_data values (%lld, %d, %d, '%q');",
		  tag, 0, STRING_VALUE, escape_newlines(expr->string->data));
}

void register_strings(int id)
{
	my_id = id;

	add_function_hook("strcpy", &match_strcpy, NULL);
	add_function_hook("strlcpy", &match_strcpy, NULL);
	add_function_hook("strncpy", &match_strcpy, NULL);

	add_hook(&match_assignment, ASSIGNMENT_HOOK);
	add_hook(&match_string, STRING_HOOK);

}

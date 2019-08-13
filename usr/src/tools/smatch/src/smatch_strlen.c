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

#include <stdlib.h>
#include <errno.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

#define UNKNOWN_SIZE (-1)

static int my_strlen_id;
/*
 * The trick with the my_equiv_id is that if we have:
 * foo = strlen(bar);
 * We don't know at that point what the strlen() is but we know it's equivalent
 * to "foo" so maybe we can find the value of "foo" later.
 */
static int my_equiv_id;

static struct smatch_state *size_to_estate(int size)
{
	sval_t sval;

	sval.type = &int_ctype;
	sval.value = size;

	return alloc_estate_sval(sval);
}

static struct smatch_state *unmatched_strlen_state(struct sm_state *sm)
{
	return size_to_estate(UNKNOWN_SIZE);
}

static void set_strlen_undefined(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(sm->owner, sm->name, sm->sym, size_to_estate(UNKNOWN_SIZE));
}

static void set_strlen_equiv_undefined(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(sm->owner, sm->name, sm->sym, &undefined);
}

static void match_string_assignment(struct expression *expr)
{
	struct range_list *rl;

	if (expr->op != '=')
		return;
	if (!get_implied_strlen(expr->right, &rl))
		return;
	set_state_expr(my_strlen_id, expr->left, alloc_estate_rl(clone_rl(rl)));
}

static void match_strlen(const char *fn, struct expression *expr, void *unused)
{
	struct expression *right;
	struct expression *str;
	struct expression *len_expr;
	char *len_name;
	struct smatch_state *state;

	right = strip_expr(expr->right);
	str = get_argument_from_call_expr(right->args, 0);
	len_expr = strip_expr(expr->left);

	len_name = expr_to_var(len_expr);
	if (!len_name)
		return;

	state = __alloc_smatch_state(0);
        state->name = len_name;
	state->data = len_expr;

	set_state_expr(my_equiv_id, str, state);
}

static void match_strlen_condition(struct expression *expr)
{
	struct expression *left;
	struct expression *right;
	struct expression *str = NULL;
	int strlen_left = 0;
	int strlen_right = 0;
	sval_t sval;
	struct smatch_state *true_state = NULL;
	struct smatch_state *false_state = NULL;
	int op;

	if (expr->type != EXPR_COMPARE)
		return;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (left->type == EXPR_CALL && sym_name_is("strlen", left->fn)) {
		str = get_argument_from_call_expr(left->args, 0);
		strlen_left = 1;
	}
	if (right->type == EXPR_CALL && sym_name_is("strlen", right->fn)) {
		str = get_argument_from_call_expr(right->args, 0);
		strlen_right = 1;
	}

	if (!strlen_left && !strlen_right)
		return;
	if (strlen_left && strlen_right)
		return;

	op = expr->op;
	if (strlen_left) {
		if (!get_value(right, &sval))
			return;
	} else {
		op = flip_comparison(op);
		if (!get_value(left, &sval))
			return;
	}

	switch (op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		true_state = size_to_estate(sval.value - 1);
		break;
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		true_state = size_to_estate(sval.value);
		break;
	case SPECIAL_EQUAL:
		true_state = size_to_estate(sval.value);
		break;
	case SPECIAL_NOTEQUAL:
		false_state = size_to_estate(sval.value);
		break;
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		false_state = size_to_estate(sval.value - 1);
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
		false_state = size_to_estate(sval.value);
		break;
	}

	set_true_false_states_expr(my_strlen_id, str, true_state, false_state);
}

static void match_snprintf(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	struct expression *dest_size_expr;
	sval_t limit_size;

	dest = get_argument_from_call_expr(expr->args, 0);
	dest_size_expr = get_argument_from_call_expr(expr->args, 1);

	if (!get_implied_value(dest_size_expr, &limit_size))
		return;

	if (limit_size.value <= 0)
		return;

	set_state_expr(my_strlen_id, dest, size_to_estate(limit_size.value - 1));
}

static void match_strlcpycat(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	struct expression *src;
	struct expression *limit_expr;
	int src_len;
	sval_t limit;

	dest = get_argument_from_call_expr(expr->args, 0);
	src = get_argument_from_call_expr(expr->args, 1);
	limit_expr = get_argument_from_call_expr(expr->args, 2);

	src_len = get_size_from_strlen(src);

	if (!get_implied_max(limit_expr, &limit))
		return;
	if (limit.value < 0 || limit.value > INT_MAX)
		return;
	if (src_len != 0 && strcmp(fn, "strcpy") == 0 && src_len < limit.value)
		limit.value = src_len;

	set_state_expr(my_strlen_id, dest, size_to_estate(limit.value - 1));
}

static void match_strcpy(const char *fn, struct expression *expr, void *unused)
{
	struct expression *dest;
	struct expression *src;
	int src_len;

	dest = get_argument_from_call_expr(expr->args, 0);
	src = get_argument_from_call_expr(expr->args, 1);

	src_len = get_size_from_strlen(src);
	if (src_len == 0)
		return;

	set_state_expr(my_strlen_id, dest, size_to_estate(src_len - 1));
}

static int get_strlen_from_string(struct expression *expr, struct range_list **rl)
{
	sval_t sval;
	int len;

	len = expr->string->length;
	sval = sval_type_val(&int_ctype, len - 1);
	*rl = alloc_rl(sval, sval);
	return 1;
}


static int get_strlen_from_state(struct expression *expr, struct range_list **rl)
{
	struct smatch_state *state;

	state = get_state_expr(my_strlen_id, expr);
	if (!state)
		return 0;
	*rl = estate_rl(state);
	return 1;
}

static int get_strlen_from_equiv(struct expression *expr, struct range_list **rl)
{
	struct smatch_state *state;

	state = get_state_expr(my_equiv_id, expr);
	if (!state || !state->data)
		return 0;
	if (!get_implied_rl((struct expression *)state->data, rl))
		return 0;
	return 1;
}

/*
 * This returns the strlen() without the NUL char.
 */
int get_implied_strlen(struct expression *expr, struct range_list **rl)
{

	*rl = NULL;

	expr = strip_expr(expr);
	if (expr->type == EXPR_STRING)
		return get_strlen_from_string(expr, rl);

	if (get_strlen_from_state(expr, rl))
		return 1;
	if (get_strlen_from_equiv(expr, rl))
		return 1;
	return 0;
}

int get_size_from_strlen(struct expression *expr)
{
	struct range_list *rl;
	sval_t max;

	if (!get_implied_strlen(expr, &rl))
		return 0;
	max = rl_max(rl);
	if (sval_is_negative(max) || sval_is_max(max))
		return 0;

	return max.value + 1; /* add one because strlen doesn't include the NULL */
}

void set_param_strlen(const char *name, struct symbol *sym, char *key, char *value)
{
	struct range_list *rl = NULL;
	struct smatch_state *state;
	char fullname[256];

	if (strncmp(key, "$", 1) != 0)
		return;

	snprintf(fullname, 256, "%s%s", name, key + 1);

	str_to_rl(&int_ctype, value, &rl);
	if (!rl || is_whole_rl(rl))
		return;
	state = alloc_estate_rl(rl);
	set_state(my_strlen_id, fullname, sym, state);
}

static void match_call(struct expression *expr)
{
	struct expression *arg;
	struct range_list *rl;
	int i;

	i = 0;
	FOR_EACH_PTR(expr->args, arg) {
		if (!get_implied_strlen(arg, &rl))
			continue;
		if (!is_whole_rl(rl))
			sql_insert_caller_info(expr, STR_LEN, i, "$", show_rl(rl));
		i++;
	} END_FOR_EACH_PTR(arg);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	if (sm->state == &merged)
		return;
	sql_insert_caller_info(call, STR_LEN, param, printed_name, sm->state->name);
}

void register_strlen(int id)
{
	my_strlen_id = id;

	set_dynamic_states(my_strlen_id);

	add_unmatched_state_hook(my_strlen_id, &unmatched_strlen_state);

	select_caller_info_hook(set_param_strlen, STR_LEN);
	add_hook(&match_string_assignment, ASSIGNMENT_HOOK);

	add_modification_hook(my_strlen_id, &set_strlen_undefined);
	add_merge_hook(my_strlen_id, &merge_estates);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_strlen_id, struct_member_callback);
	add_hook(&match_strlen_condition, CONDITION_HOOK);

	add_function_hook("snprintf", &match_snprintf, NULL);

	add_function_hook("strlcpy", &match_strlcpycat, NULL);
	add_function_hook("strlcat", &match_strlcpycat, NULL);
	add_function_hook("strcpy", &match_strcpy, NULL);
}

void register_strlen_equiv(int id)
{
	my_equiv_id = id;
	set_dynamic_states(my_equiv_id);
	add_function_assign_hook("strlen", &match_strlen, NULL);
	add_modification_hook(my_equiv_id, &set_strlen_equiv_undefined);
}


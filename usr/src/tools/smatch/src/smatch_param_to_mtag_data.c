/*
 * Copyright (C) 2017 Oracle.
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
 * Take a look at request_threaded_irq().  It takes thread_fn and dev_id.  Then
 * it does:
 *
 *	action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
 *	action->thread_fn = thread_fn;
 *	action->dev_id = dev_id;
 *
 * It doesn't ever pass action back to the higher levels, but instead registers
 * it with the lower levels.
 *
 * The kzalloc() allocation creates a new mtag.  We don't know at this point
 * what "thread_fn" and "dev_id" are because they come from many different
 * sources.
 *
 * So what we do is we pass the information back to the callers that thread_fn
 * and dev_id are stored as a specific mtag data.  Then when the callers *do*
 * know what values are passed they create an mtag_alias.  An mtag_alias is a
 * many to one relationship.  Then they store that in mtag_data using the
 * mtag_alias.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

struct tag_assign_info {
	mtag_t tag;
	int offset;
};
ALLOCATOR(tag_assign_info, "tag name offset");

static struct smatch_state *alloc_tag_data_state(mtag_t tag, char *name, int offset)
{
	struct smatch_state *state;
	struct tag_assign_info *data;

	data = __alloc_tag_assign_info(0);
	data->tag = tag;
	data->offset = offset;

	state = __alloc_smatch_state(0);
	state->name = alloc_sname(name);
	state->data = data;
	return state;
}

struct smatch_state *merge_tag_info(struct smatch_state *s1, struct smatch_state *s2)
{
	/* Basically ignore undefined states */
	if (s1 == &undefined)
		return s2;
	if (s2 == &undefined)
		return s1;

	return &merged;
}

static void match_assign(struct expression *expr)
{
	struct expression *left;
	struct symbol *right_sym;
	char *name;
	mtag_t tag;
	int offset;
	int param;

	if (expr->op != '=')
		return;
	left = strip_expr(expr->left);
	right_sym = expr_to_sym(expr->right);
	if (!right_sym)
		return;

	param = get_param_num_from_sym(right_sym);
	if (param < 0)
		return;
	// FIXME:  modify param_has_filter_data() to take a name/sym
	if (!expr_to_mtag_offset(left, &tag, &offset))
		return;
	name = expr_to_str(left);
	if (!name)
		return;
	set_state_expr(my_id, expr->right, alloc_tag_data_state(tag, name, offset));
	free_string(name);
}

#if 0
static void save_mtag_to_map(struct expression *expr, mtag_t tag, int offset, int param, char *key, char *value)
{
	struct expression *arg, *gen_expr;
	mtag_t arg_tag;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	gen_expr = gen_expression_from_key(arg, key);
	if (!gen_expr)
		return;

	if (!get_mtag(gen_expr, &arg_tag))
		arg_tag = 0;

	if (local_debug)
		sm_msg("finding mtag for '%s' %lld", expr_to_str(gen_expr), arg_tag);
}
#endif

static void propogate_assignment(struct expression *expr, mtag_t tag, int offset, int param, char *key)
{
	struct expression *arg;
	int orig_param;
	char buf[32];
	char *name;
	struct symbol *sym;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	orig_param = get_param_num_from_sym(sym);
	if (orig_param < 0)
		goto free;

	snprintf(buf, sizeof(buf), "$->[%d]", offset);
	set_state(my_id, name, sym, alloc_tag_data_state(tag, buf, offset));
free:
	free_string(name);
}

static void assign_to_alias(struct expression *expr, int param, mtag_t tag, int offset, char *key)
{
	struct expression *arg, *gen_expr;
	struct range_list *rl;
	mtag_t arg_tag;
	mtag_t alias;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	gen_expr = gen_expression_from_key(arg, key);
	if (!gen_expr)
		return;

	get_absolute_rl(gen_expr, &rl);

	if (!create_mtag_alias(tag, expr, &alias))
		return;

//	insert_mtag_data(alias, offset, rl);

	if (get_mtag(gen_expr, &arg_tag))
		sql_insert_mtag_map(arg_tag, -offset, alias);
}

static void call_does_mtag_assign(struct expression *expr, int param, char *key, char *value)
{
	char *p;
	mtag_t tag;
	int offset;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	tag = strtoul(value, NULL, 10);
	p = strchr(value, '+');
	if (!p)
		return;
	offset = atoi(p + 1);

//	save_mtag_to_map(expr, tag, offset, param, key, value);
	propogate_assignment(expr, tag, offset, param, key);
	assign_to_alias(expr, param, tag, offset, key);
}

static void print_stored_to_mtag(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	struct tag_assign_info *data;
	char buf[256];
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (!sm->state->data)
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;
		param_name = get_param_name(sm);
		if (!param_name)
			continue;

		data = sm->state->data;
		snprintf(buf, sizeof(buf), "%lld+%d", data->tag, data->offset);
		sql_insert_return_states(return_id, return_ranges, MTAG_ASSIGN, param, param_name, buf);
	} END_FOR_EACH_SM(sm);
}

void register_param_to_mtag_data(int id)
{
	my_id = id;

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	select_return_states_hook(MTAG_ASSIGN, &call_does_mtag_assign);
	add_merge_hook(my_id, &merge_tag_info);
	add_split_return_callback(&print_stored_to_mtag);
}


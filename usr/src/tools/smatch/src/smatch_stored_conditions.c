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

/*
 * Keep a record of all the things we have tested for so that we know when we
 * test for it again.  For example, if we have code like this:
 *
 * 	if (foo & FLAG)
 *		lock();
 *
 *	...
 *
 *	if (foo & FLAG)
 *		unlock();
 *
 * That's the end goal at least.  But actually implementing the flow of that
 * requires quite a bit of work because if "foo" changes the condition needs to
 * be retested and smatch_implications.c needs to be updated.
 *
 * For now, I just record the conditions and use it to see if we test for NULL
 * twice.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;
static int link_id;

static struct smatch_state *alloc_link_state(struct expression_list *expr_list)
{
	struct expression *tmp;
	struct smatch_state *state;
	static char buf[256];
	char *name;
	int i;

	state = __alloc_smatch_state(0);

	i = 0;
	FOR_EACH_PTR(expr_list, tmp) {
		name = expr_to_str(tmp);
		if (!i++) {
			snprintf(buf, sizeof(buf), "%s", name);
		} else {
			append(buf, ", ", sizeof(buf));
			append(buf, name, sizeof(buf));
		}
		free_string(name);
	} END_FOR_EACH_PTR(tmp);

	state->name = alloc_sname(buf);
	state->data = expr_list;
	return state;
}

static struct expression_list *clone_expression_list(struct expression_list *list)
{
	struct expression_list *ret = NULL;
	struct expression *expr;

	FOR_EACH_PTR(list, expr) {
		add_ptr_list(&ret, expr);
	} END_FOR_EACH_PTR(expr);

	return ret;
}

static void insert_expression(struct expression_list **list, struct expression *expr)
{
	struct expression *tmp;

	FOR_EACH_PTR(*list, tmp) {
		if (tmp == expr)
			return;
	} END_FOR_EACH_PTR(tmp);

	add_ptr_list(list, expr);
}

static struct smatch_state *merge_links(struct smatch_state *s1, struct smatch_state *s2)
{
	struct expression_list *list, *expr_list;
	struct expression *expr;

	expr_list = clone_expression_list(s1->data);

	list = s2->data;
	FOR_EACH_PTR(list, expr) {
		insert_expression(&expr_list, expr);
	} END_FOR_EACH_PTR(expr);

	return alloc_link_state(expr_list);
}

static void save_link_var_sym(const char *var, struct symbol *sym, struct expression *condition)
{
	struct smatch_state *old_state, *new_state;
	struct expression_list *expr_list;

	old_state = get_state(link_id, var, sym);
	expr_list = clone_expression_list(old_state ? old_state->data : NULL);

	insert_expression(&expr_list, condition);

	new_state = alloc_link_state(expr_list);
	set_state(link_id, var, sym, new_state);
}

static void match_link_modify(struct sm_state *sm, struct expression *mod_expr)
{
	struct expression_list *expr_list;
	struct expression *tmp;
	char *name;

	expr_list = sm->state->data;

	FOR_EACH_PTR(expr_list, tmp) {
		name = expr_to_str(tmp);
		set_state(my_id, name, NULL, &undefined);
		free_string(name);
	} END_FOR_EACH_PTR(tmp);
	set_state(link_id, sm->name, sm->sym, &undefined);
}

static struct smatch_state *alloc_state(struct expression *expr, int is_true)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	if (is_true)
		state->name = alloc_sname("true");
	else
		state->name = alloc_sname("false");
	state->data = expr;
	return state;
}

static void store_all_links(struct expression *expr, struct expression *condition)
{
	char *var;
	struct symbol *sym;

	expr = strip_expr(expr);

	if (is_array(expr)) {
		var = expr_to_known_chunk_sym(expr, &sym);
		if (var)
			save_link_var_sym(var, sym, condition);
	}

	switch (expr->type) {
	case EXPR_COMPARE:
	case EXPR_BINOP:
		store_all_links(expr->left, condition);
		store_all_links(expr->right, condition);
		return;
	case EXPR_VALUE:
		return;
	}

	var = expr_to_var_sym(expr, &sym);
	if (!var || !sym)
		goto free;
	save_link_var_sym(var, sym, condition);
free:
	free_string(var);
}

static int condition_too_complicated(struct expression *expr)
{
	if (get_complication_score(expr) > 2)
		return 1;
	return 0;
}

void __stored_condition(struct expression *expr)
{
	struct smatch_state *true_state, *false_state;
	char *name;
	sval_t val;

	if (get_value(expr, &val))
		return;

	if (condition_too_complicated(expr))
		return;

	name = expr_to_str(expr);
	if (!name)
		return;
	true_state = alloc_state(expr, TRUE);
	false_state = alloc_state(expr, FALSE);
	set_true_false_states(my_id, name, NULL, true_state, false_state);
	store_all_links(expr, expr);
	free_string(name);
}

struct smatch_state *get_stored_condition(struct expression *expr)
{
	struct smatch_state *state;
	char *name;

	name = expr_to_str(expr);
	if (!name)
		return NULL;

	state = get_state(my_id, name, NULL);
	free_string(name);
	return state;
}

struct expression_list *get_conditions(struct expression *expr)
{
	struct smatch_state *state;

	state = get_state_expr(link_id, expr);
	if (!state)
		return NULL;
	return state->data;
}

void register_stored_conditions(int id)
{
	my_id = id;
}

void register_stored_conditions_links(int id)
{
	link_id = id;
	add_merge_hook(link_id, &merge_links);
	add_modification_hook(link_id, &match_link_modify);
}

#define RECURSE_LIMIT 50

static void filter_by_sm(struct sm_state *sm,
		       struct state_list **true_stack,
		       struct state_list **false_stack,
		       int *recurse_cnt)
{
	if (!sm)
		return;

	if ((*recurse_cnt)++ > RECURSE_LIMIT)
		return;

	if (strcmp(sm->state->name, "true") == 0) {
		add_ptr_list(true_stack, sm);
	} else if (strcmp(sm->state->name, "false") == 0) {
		add_ptr_list(false_stack, sm);
	}

	if (sm->merged) {
		filter_by_sm(sm->left, true_stack, false_stack, recurse_cnt);
		filter_by_sm(sm->right, true_stack, false_stack, recurse_cnt);
	}
}

struct sm_state *stored_condition_implication_hook(struct expression *expr,
				struct state_list **true_stack,
				struct state_list **false_stack)
{
	struct sm_state *sm;
	char *name;
	int recurse_cnt = 0;
	struct state_list *tmp_true = NULL;
	struct state_list *tmp_false = NULL;
	struct sm_state *tmp;

	expr = strip_expr(expr);

	name = expr_to_str(expr);
	if (!name)
		return NULL;

	sm = get_sm_state(my_id, name, NULL);
	free_string(name);
	if (!sm)
		return NULL;
	if (!sm->merged)
		return NULL;

	filter_by_sm(sm, &tmp_true, &tmp_false, &recurse_cnt);
	if (!tmp_true && !tmp_false)
		return NULL;
	if (recurse_cnt > RECURSE_LIMIT) {
		sm = NULL;
		goto free;
	}

	FOR_EACH_PTR(tmp_true, tmp) {
		add_ptr_list(true_stack, tmp);
	} END_FOR_EACH_PTR(tmp);

	FOR_EACH_PTR(tmp_false, tmp) {
		add_ptr_list(false_stack, tmp);
	} END_FOR_EACH_PTR(tmp);

free:
	free_slist(&tmp_true);
	free_slist(&tmp_false);
	return sm;
}


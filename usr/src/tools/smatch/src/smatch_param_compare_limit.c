/*
 * Copyright (C) 2016 Oracle.
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
 * The point here is to store the relationships between two variables.
 * Ie:  y > x.
 * To do that we create a state with the two variables in alphabetical order:
 * ->name = "x vs y" and the state would be "<".  On the false path the state
 * would be ">=".
 *
 * Part of the trick of it is that if x or y is modified then we need to reset
 * the state.  We need to keep a list of all the states which depend on x and
 * all the states which depend on y.  The link_id code handles this.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int compare_id;
static int link_id;

static struct smatch_state *alloc_link_state(struct string_list *links)
{
	struct smatch_state *state;
	static char buf[256];
	char *tmp;
	int i;

	state = __alloc_smatch_state(0);

	i = 0;
	FOR_EACH_PTR(links, tmp) {
		if (!i++) {
			snprintf(buf, sizeof(buf), "%s", tmp);
		} else {
			append(buf, ", ", sizeof(buf));
			append(buf, tmp, sizeof(buf));
		}
	} END_FOR_EACH_PTR(tmp);

	state->name = alloc_sname(buf);
	state->data = links;
	return state;
}

static struct smatch_state *merge_links(struct smatch_state *s1, struct smatch_state *s2)
{
	struct smatch_state *ret;
	struct string_list *links;

	links = combine_string_lists(s1->data, s2->data);
	ret = alloc_link_state(links);
	return ret;
}

static void save_link_var_sym(const char *var, struct symbol *sym, const char *link)
{
	struct smatch_state *old_state, *new_state;
	struct string_list *links;
	char *new;

	old_state = get_state(link_id, var, sym);
	if (old_state)
		links = clone_str_list(old_state->data);
	else
		links = NULL;

	new = alloc_sname(link);
	insert_string(&links, new);

	new_state = alloc_link_state(links);
	set_state(link_id, var, sym, new_state);
}

static void add_comparison_var_sym(const char *left_name,
		struct var_sym_list *left_vsl,
		int comparison,
		const char *right_name, struct var_sym_list *right_vsl)
{
	struct smatch_state *state;
	struct var_sym *vs;
	char state_name[256];

	if (strcmp(left_name, right_name) > 0) {
		const char *tmp_name = left_name;
		struct var_sym_list *tmp_vsl = left_vsl;

		left_name = right_name;
		left_vsl = right_vsl;
		right_name = tmp_name;
		right_vsl = tmp_vsl;
		comparison = flip_comparison(comparison);
	}
	snprintf(state_name, sizeof(state_name), "%s vs %s", left_name, right_name);
	state = alloc_compare_state(NULL, left_name, left_vsl, comparison, NULL, right_name, right_vsl);

	set_state(compare_id, state_name, NULL, state);

	FOR_EACH_PTR(left_vsl, vs) {
		save_link_var_sym(vs->var, vs->sym, state_name);
	} END_FOR_EACH_PTR(vs);
	FOR_EACH_PTR(right_vsl, vs) {
		save_link_var_sym(vs->var, vs->sym, state_name);
	} END_FOR_EACH_PTR(vs);
}

/*
 * This is quite a bit more limitted, less ambitious, simpler compared to
 * smatch_camparison.c.
 */
void __compare_param_limit_hook(struct expression *left_expr, struct expression *right_expr,
				const char *state_name,
				struct smatch_state *true_state, struct smatch_state *false_state)
{
	char *left_name = NULL;
	char *right_name = NULL;
	char *tmp_name = NULL;
	struct symbol *left_sym, *right_sym, *tmp_sym;

	left_name = expr_to_var_sym(left_expr, &left_sym);
	if (!left_name || !left_sym)
		goto free;
	right_name = expr_to_var_sym(right_expr, &right_sym);
	if (!right_name || !right_sym)
		goto free;

	if (get_param_num_from_sym(left_sym) < 0 ||
	    get_param_num_from_sym(right_sym) < 0)
		return;

	tmp_name = get_other_name_sym(left_name, left_sym, &tmp_sym);
	if (tmp_name) {
		free_string(left_name);
		left_name = tmp_name;
		left_sym = tmp_sym;
	}

	tmp_name = get_other_name_sym(right_name, right_sym, &tmp_sym);
	if (tmp_name) {
		free_string(right_name);
		right_name = tmp_name;
		right_sym = tmp_sym;
	}

	if (param_was_set_var_sym(left_name, left_sym))
		return;
	if (param_was_set_var_sym(right_name, right_sym))
		return;

	set_true_false_states(compare_id, state_name, NULL, true_state, false_state);
	save_link_var_sym(left_name, left_sym, state_name);
	save_link_var_sym(right_name, right_sym, state_name);
free:
	free_string(left_name);
	free_string(right_name);
}

static void print_return_comparison(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *tmp;
	struct string_list *links;
	char *link;
	struct sm_state *sm;
	struct compare_data *data;
	struct var_sym *left, *right;
	int left_param, right_param;
	static char left_buf[248];
	static char right_buf[248];
	static char info_buf[256];
	const char *tmp_name;

	FOR_EACH_MY_SM(link_id, __get_cur_stree(), tmp) {
		links = tmp->state->data;
		FOR_EACH_PTR(links, link) {
			sm = get_sm_state(compare_id, link, NULL);
			if (!sm)
				continue;
			data = sm->state->data;
			if (!data || !data->comparison)
				continue;
			if (ptr_list_size((struct ptr_list *)data->left_vsl) != 1 ||
			    ptr_list_size((struct ptr_list *)data->right_vsl) != 1)
				continue;
			left = first_ptr_list((struct ptr_list *)data->left_vsl);
			right = first_ptr_list((struct ptr_list *)data->right_vsl);
			if (left->sym == right->sym &&
			    strcmp(left->var, right->var) == 0)
				continue;
			/*
			 * Both parameters link to this comparison so only
			 * record the first one.
			 */
			if (left->sym != tmp->sym ||
			    strcmp(left->var, tmp->name) != 0)
				continue;

			left_param = get_param_num_from_sym(left->sym);
			right_param = get_param_num_from_sym(right->sym);
			if (left_param < 0 || right_param < 0) /* can't happen hopefully */
				continue;

			tmp_name = get_param_name_var_sym(left->var, left->sym);
			if (!tmp_name)
				continue;
			snprintf(left_buf, sizeof(left_buf), "%s", tmp_name);

			tmp_name = get_param_name_var_sym(right->var, right->sym);
			if (!tmp_name || tmp_name[0] != '$')
				continue;
			snprintf(right_buf, sizeof(right_buf), "$%d%s", right_param, tmp_name + 1);

			snprintf(info_buf, sizeof(info_buf), "%s %s", show_special(data->comparison), right_buf);
			sql_insert_return_states(return_id, return_ranges,
					COMPARE_LIMIT, left_param, left_buf, info_buf);
		} END_FOR_EACH_PTR(link);

	} END_FOR_EACH_SM(tmp);
}

static int parse_comparison(char **value, int *op)
{

	*op = **value;

	switch (*op) {
	case '<':
		(*value)++;
		if (**value == '=') {
			(*value)++;
			*op = SPECIAL_LTE;
		}
		break;
	case '=':
		(*value)++;
		(*value)++;
		*op = SPECIAL_EQUAL;
		break;
	case '!':
		(*value)++;
		(*value)++;
		*op = SPECIAL_NOTEQUAL;
		break;
	case '>':
		(*value)++;
		if (**value == '=') {
			(*value)++;
			*op = SPECIAL_GTE;
		}
		break;
	default:
		return 0;
	}

	if (**value != ' ') {
		sm_perror("parsing comparison.  %s", *value);
		return 0;
	}

	(*value)++;
	return 1;
}

static int split_op_param_key(char *value, int *op, int *param, char **key)
{
	static char buf[256];
	char *p;

	if (!parse_comparison(&value, op))
		return 0;

	snprintf(buf, sizeof(buf), "%s", value);

	p = buf;
	if (*p++ != '$')
		return 0;

	*param = atoi(p);
	if (*param < 0 || *param > 99)
		return 0;
	p++;
	if (*param > 9)
		p++;
	p--;
	*p = '$';
	*key = p;

	return 1;
}

static void db_return_comparison(struct expression *expr, int left_param, char *key, char *value)
{
	struct expression *left_arg, *right_arg;
	char *left_name = NULL;
	struct symbol *left_sym;
	char *right_name = NULL;
	struct symbol *right_sym;
	int op;
	int right_param;
	char *right_key;
	struct var_sym_list *left_vsl = NULL, *right_vsl = NULL;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	if (!split_op_param_key(value, &op, &right_param, &right_key))
		return;

	left_arg = get_argument_from_call_expr(expr->args, left_param);
	if (!left_arg)
		return;

	right_arg = get_argument_from_call_expr(expr->args, right_param);
	if (!right_arg)
		return;

	left_name = get_variable_from_key(left_arg, key, &left_sym);
	if (!left_name || !left_sym)
		goto free;
	if (get_param_num_from_sym(left_sym) < 0)
		goto free;

	right_name = get_variable_from_key(right_arg, right_key, &right_sym);
	if (!right_name || !right_sym)
		goto free;
	if (get_param_num_from_sym(right_sym) < 0)
		goto free;

	add_var_sym(&left_vsl, left_name, left_sym);
	add_var_sym(&right_vsl, right_name, right_sym);

	add_comparison_var_sym(left_name, left_vsl, op, right_name, right_vsl);

free:
	free_string(left_name);
	free_string(right_name);
}

void register_param_compare_limit(int id)
{
	compare_id = id;

	set_dynamic_states(compare_id);
	add_merge_hook(compare_id, &merge_compare_states);
	add_split_return_callback(&print_return_comparison);

	select_return_states_hook(COMPARE_LIMIT, &db_return_comparison);
}

void register_param_compare_limit_links(int id)
{
	link_id = id;

	set_dynamic_states(link_id);
	add_merge_hook(link_id, &merge_links);
}


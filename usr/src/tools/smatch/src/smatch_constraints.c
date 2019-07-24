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
 * Basically I see constraints as a way of saying "x <= some_limit".  The
 * problem is that smatch_capped is not granullar enough.
 *
 * This is mostly for finding out of bounds errors.  So there are different
 * types of constraints.  Quite often we have "foo->xxx[i] = 42;" and we want
 * to verify that "i" is less than foo->size.
 *
 * My idea was that we could automatically figure out these constraints.  And we
 * could load them in the DB so that they are the same every time.  As in a
 * constraint could be "< (struct whatever)->size" and give that in ID that
 * would be constant until you completely wiped the DB.  So when you do a normal
 * DB rebuild then the first thing it will do is preserve all the constraints.
 * I guess the reason to do it this way is to save space...  I sometimes suspect
 * that worrying about saving space is premature optimization.
 *
 * The other thing that I want to do a little bit different here is how I merge
 * constraints.  If a constraint is true on both sides, then that's normal.  If
 * we merge constraint 23 and 67 then we get constraint 23|67.  If we merge 23
 * with &undefined then we get &undefined.  We can also have two constraints
 * that are both true so we could have (45&23)|12 which means either both 45 and
 * 23 are true or 12 is true.
 *
 */


#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

ALLOCATOR(constraint, "constraints");

static void add_constraint(struct constraint_list **list, int op, int constraint)
{
	struct constraint *tmp, *new;

	FOR_EACH_PTR(*list, tmp) {
		if (tmp->id < constraint)
			continue;
		if (tmp->id == constraint) {
			if (tmp->op == '<')
				return;
			if (op == SPECIAL_LTE)
				return;

			new = __alloc_constraint(0);
			new->op = op;
			new->id = constraint;
			REPLACE_CURRENT_PTR(tmp, new);
			return;
		}

		new = __alloc_constraint(0);
		new->op = op;
		new->id = constraint;
		INSERT_CURRENT(new, tmp);
		return;
	} END_FOR_EACH_PTR(tmp);

	new = __alloc_constraint(0);
	new->op = op;
	new->id = constraint;
	add_ptr_list(list, new);
}

static struct constraint_list *merge_constraint_lists(struct constraint_list *one, struct constraint_list *two)
{
	struct constraint_list *ret = NULL;
	struct constraint *tmp;

	// FIXME: not || but &&
	FOR_EACH_PTR(one, tmp) {
		add_constraint(&ret, tmp->op, tmp->id);
	} END_FOR_EACH_PTR(tmp);

	FOR_EACH_PTR(two, tmp) {
		add_constraint(&ret, tmp->op, tmp->id);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

static struct constraint_list *clone_constraint_list(struct constraint_list *list)
{
	struct constraint_list *ret = NULL;
	struct constraint *tmp;

	FOR_EACH_PTR(list, tmp) {
		add_constraint(&ret, tmp->op, tmp->id);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

static struct smatch_state *alloc_constraint_state(struct constraint_list *list)
{
	struct smatch_state *state;
	struct constraint *con;
	static char buf[256];
	int cnt = 0;

	FOR_EACH_PTR(list, con) {
		if (cnt != 0)
			cnt += snprintf(buf + cnt, sizeof(buf) - cnt, ", ");
		cnt += snprintf(buf + cnt, sizeof(buf) - cnt, "%s%d",
				show_special(con->op), con->id);
	} END_FOR_EACH_PTR(con);

	state = __alloc_smatch_state(0);
	state->name = alloc_string(buf);
	state->data = list;
	return state;
}

static struct smatch_state *merge_func(struct smatch_state *s1, struct smatch_state *s2)
{
	struct constraint_list *list;

	// FIXME:  use the dead code below instead
	if (strcmp(s1->name, s2->name) == 0)
		return s1;
	return &merged;

	list = merge_constraint_lists(s1->data, s2->data);
	return alloc_constraint_state(list);
}

static int negate_gt(int op)
{
	switch (op) {
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		return negate_comparison(op);
	}
	return op;
}

static char *get_func_constraint(struct expression *expr)
{
	char buf[256];
	char *name;

	if (is_fake_call(expr))
		return NULL;
	name = expr_to_str(expr->fn);
	if (!name)
		return NULL;
	snprintf(buf, sizeof(buf), "%s()", name);
	free_string(name);
	return alloc_string(buf);
}

static char *get_toplevel_name(struct expression *expr)
{
	struct symbol *sym;
	char buf[256];

	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL || !expr->symbol || !expr->symbol->ident)
		return NULL;

	sym = expr->symbol;
	if (!(sym->ctype.modifiers & MOD_TOPLEVEL))
		return NULL;

	if (sym->ctype.modifiers & MOD_STATIC)
		snprintf(buf, sizeof(buf), "%s %s", get_base_file(), sym->ident->name);
	else
		snprintf(buf, sizeof(buf), "extern %s", sym->ident->name);

	return alloc_string(buf);
}

char *get_constraint_str(struct expression *expr)
{
	char *name;

	expr = strip_expr(expr);
	if (!expr)
		return NULL;
	if (expr->type == EXPR_CALL)
		return get_func_constraint(expr);
	if (expr->type == EXPR_BINOP)
		return expr_to_str(expr);
	name = get_toplevel_name(expr);
	if (name)
		return name;
	return get_member_name(expr);
}

static int save_int_callback(void *_p, int argc, char **argv, char **azColName)
{
	int *p = _p;

	*p = atoi(argv[0]);
	return 0;
}

static int constraint_str_to_id(const char *str)
{
	int id = -1;

	run_sql(save_int_callback, &id,
		"select id from constraints where str = '%q'", str);

	return id;
}

static int save_constraint_str(void *_str, int argc, char **argv, char **azColName)
{
	char **str = _str;

	*str = alloc_string(argv[0]);
	return 0;
}

static char *constraint_id_to_str(int id)
{
	char *str = NULL;

	run_sql(save_constraint_str, &str,
		"select str from constraints where id = '%d'", id);

	return str;
}

static int save_op_callback(void *_p, int argc, char **argv, char **azColName)
{
	int *p = _p;

	if (argv[0][0] == '<' && argv[0][1] == '=')
		*p = SPECIAL_LTE;
	else
		*p = '<';
	return 0;
}

static int save_str_callback(void *_p, int argc, char **argv, char **azColName)
{
	char **p = _p;

	if (!*p) {
		*p = alloc_string(argv[0]);
	} else {
		char buf[256];

		snprintf(buf, sizeof(buf), "%s, %s", *p, argv[0]);
		*p = alloc_string(buf);
	}
	return 0;
}

char *get_required_constraint(const char *data_str)
{
	char *required = NULL;

	run_sql(save_str_callback, &required,
		"select bound from constraints_required where data = '%q'", data_str);

	return required;
}

static int get_required_op(char *data_str, char *con_str)
{
	int op = 0;

	run_sql(save_op_callback, &op,
		"select op from constraints_required where data = '%q' and bound = '%q'", data_str, con_str);

	return op;
}

char *unmet_constraint(struct expression *data, struct expression *offset)
{
	struct smatch_state *state;
	struct constraint_list *list;
	struct constraint *con;
	char *data_str;
	char *required;
	int req_op;

	data_str = get_constraint_str(data);
	if (!data_str)
		return NULL;

	required = get_required_constraint(data_str);
	if (!required)
		goto free_data;

	state = get_state_expr(my_id, offset);
	if (!state)
		goto free_data;
	list = state->data;

	/* check the list of bounds on our index against the list that work */
	FOR_EACH_PTR(list, con) {
		char *con_str;

		con_str = constraint_id_to_str(con->id);
		if (!con_str) {
			sm_msg("constraint %d not found", con->id);
			continue;
		}

		req_op = get_required_op(data_str, con_str);
		free_string(con_str);
		if (!req_op)
			continue;
		if (con->op == '<' || con->op == req_op) {
			free_string(required);
			required = NULL;
			goto free_data;
		}
	} END_FOR_EACH_PTR(con);

free_data:
	free_string(data_str);
	return required;
}

struct string_list *saved_constraints;
static void save_new_constraint(const char *con)
{
	if (!insert_string(&saved_constraints, con))
		return;
	sql_save_constraint(con);
}

static void handle_comparison(struct expression *left, int op, struct expression *right)
{
	struct constraint_list *constraints;
	struct smatch_state *state;
	char *constraint;
	int constraint_id;
	int orig_op = op;
	sval_t sval;

	/* known values are handled in smatch extra */
	if (get_value(left, &sval) || get_value(right, &sval))
		return;

	constraint = get_constraint_str(right);
	if (!constraint)
		return;
	constraint_id = constraint_str_to_id(constraint);
	if (constraint_id < 0)
		save_new_constraint(constraint);
	free_string(constraint);
	if (constraint_id < 0)
		return;

	constraints = get_constraints(left);
	constraints = clone_constraint_list(constraints);
	op = negate_gt(orig_op);
	add_constraint(&constraints, remove_unsigned_from_comparison(op), constraint_id);
	state = alloc_constraint_state(constraints);

	if (op == orig_op)
		set_true_false_states_expr(my_id, left,	state, NULL);
	else
		set_true_false_states_expr(my_id, left, NULL, state);
}

static void match_condition(struct expression *expr)
{
	if (expr->type != EXPR_COMPARE)
		return;

	if (expr->op == SPECIAL_EQUAL ||
	    expr->op == SPECIAL_NOTEQUAL)
		return;

	handle_comparison(expr->left, expr->op, expr->right);
	handle_comparison(expr->right, flip_comparison(expr->op), expr->left);
}

struct constraint_list *get_constraints(struct expression *expr)
{
	struct smatch_state *state;

	state = get_state_expr(my_id, expr);
	if (!state)
		return NULL;
	return state->data;
}

static void match_caller_info(struct expression *expr)
{
	struct expression *tmp;
	struct smatch_state *state;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, tmp) {
		i++;
		state = get_state_expr(my_id, tmp);
		if (!state || state == &merged || state == &undefined)
			continue;
		sql_insert_caller_info(expr, CONSTRAINT, i, "$", state->name);
	} END_FOR_EACH_PTR(tmp);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	if (sm->state == &merged || sm->state == &undefined)
		return;
	sql_insert_caller_info(call, CONSTRAINT, param, printed_name, sm->state->name);
}

static struct smatch_state *constraint_str_to_state(char *value)
{
	struct constraint_list *list = NULL;
	char *p = value;
	int op;
	long long id;

	while (true) {
		op = '<';
		if (*p != '<')
			return &undefined;
		p++;
		if (*p == '=') {
			op = SPECIAL_LTE;
			p++;
		}
		id = strtoll(p, &p, 10);
		add_constraint(&list, op, id);
		if (*p != ',')
			break;
		p++;
		if (*p != ' ')
			return &undefined;
	}

	return alloc_constraint_state(list);
}

static void set_param_constrained(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	set_state(my_id, name, sym, constraint_str_to_state(value));
}

static void print_return_implies_constrained(int return_id, char *return_ranges, struct expression *expr)
{
	struct smatch_state *orig;
	struct sm_state *sm;
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state == &merged || sm->state == &undefined)
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;

		orig = get_state_stree(get_start_states(), my_id, sm->name, sm->sym);
		if (orig && strcmp(sm->state->name, orig->name) == 0)
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;

		sql_insert_return_states(return_id, return_ranges, CONSTRAINT,
					 param, param_name, sm->state->name);
	} END_FOR_EACH_SM(sm);
}

static void db_returns_constrained(struct expression *expr, int param, char *key, char *value)
{
	char *name;
	struct symbol *sym;

	name = return_state_to_var_sym(expr, param, key, &sym);
	if (!name || !sym)
		goto free;

	set_state(my_id, name, sym, constraint_str_to_state(value));
free:
	free_string(name);
}

void register_constraints(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_merge_hook(my_id, &merge_func);
	add_hook(&match_condition, CONDITION_HOOK);

	add_hook(&match_caller_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	select_caller_info_hook(&set_param_constrained, CONSTRAINT);

	add_split_return_callback(print_return_implies_constrained);
	select_return_states_hook(CONSTRAINT, &db_returns_constrained);
}

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
 * This is for smatch_extra.c to use.  It sort of like check_assigned_expr.c but
 * more limited.  Say a function returns "64min-s64max[$0->data]" and the caller
 * does "struct whatever *p = get_data(dev);" then we want to record that p is
 * now the same as "dev->data".  Then if we update "p->foo" it means we can
 * update "dev->data->foo" as well.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

extern int check_assigned_expr_id;
static int my_id;
static int link_id;

static struct smatch_state *alloc_my_state(const char *name, struct symbol *sym)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->name = alloc_sname(name);
	state->data = sym;
	return state;
}

static void undef(struct sm_state *sm, struct expression *mod_expr)
{
	if (__in_fake_parameter_assign)
		return;
	set_state(my_id, sm->name, sm->sym, &undefined);
}

char *map_call_to_other_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	struct smatch_state *state;
	int skip;
	char buf[256];

	/* skip 'foo->'.  This was checked in the caller. */
	skip = strlen(sym->ident->name) + 2;

	state = get_state(my_id, sym->ident->name, sym);
	if (!state || !state->data)
		return NULL;

	snprintf(buf, sizeof(buf), "%s->%s", state->name, name + skip);
	*new_sym = state->data;
	return alloc_string(buf);
}

static char *map_my_state_long_to_short(struct sm_state *sm, const char *name, struct symbol *sym, struct symbol **new_sym, bool stack)
{
	int len;
	char buf[256];

	if (sm->state->data != sym)
		return NULL;
	len = strlen(sm->state->name);
	if (strncmp(name, sm->state->name, len) != 0)
		return NULL;

	if (name[len] == '.')
		return NULL;
	if (!stack && name[len] != '-')
		return NULL;
	snprintf(buf, sizeof(buf), "%s%s", sm->name, name + len);
	*new_sym = sm->sym;
	return alloc_string(buf);
}

static char *map_assignment_long_to_short(struct sm_state *sm, const char *name, struct symbol *sym, struct symbol **new_sym, bool stack)
{
	struct expression *orig_expr;
	struct symbol *orig_sym;
	int len;
	char buf[256];

	orig_expr = sm->state->data;
	if (!orig_expr)
		return NULL;

	/*
	 * Say we have an assignment like:
	 *     foo->bar->my_ptr = my_ptr;
	 * We still expect the function to carry on using "my_ptr" as the
	 * shorter name.  That's not a long to short mapping.
	 *
	 */
	if (orig_expr->type == EXPR_SYMBOL)
		return NULL;

	orig_sym = expr_to_sym(orig_expr);
	if (!orig_sym)
		return NULL;
	if (sym != orig_sym)
		return NULL;

	len = strlen(sm->state->name);
	if (strncmp(name, sm->state->name, len) != 0)
		return NULL;

	if (name[len] == '.')
		return NULL;
	if (!stack && name[len] != '-')
		return NULL;
	snprintf(buf, sizeof(buf), "%s%s", sm->name, name + len);
	*new_sym = sm->sym;
	return alloc_string(buf);
}

/*
 * Normally, we expect people to consistently refer to variables by the shortest
 * name.  So they use "b->a" instead of "foo->bar.a" when both point to the
 * same memory location.  However, when we're dealing across function boundaries
 * then sometimes we pass frob(foo) which sets foo->bar.a.  In that case, we
 * translate it to the shorter name.  Smatch extra updates the shorter name,
 * which in turn updates the longer name.
 *
 */
static char *map_long_to_short_name_sym_helper(const char *name, struct symbol *sym, struct symbol **new_sym, bool stack)
{
	char *ret;
	struct sm_state *sm;

	*new_sym = NULL;

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (sm->owner == my_id) {
			ret = map_my_state_long_to_short(sm, name, sym, new_sym, stack);
			if (ret)
				return ret;
			continue;
		}
		if (sm->owner == check_assigned_expr_id) {
			ret = map_assignment_long_to_short(sm, name, sym, new_sym, stack);
			if (ret)
				return ret;
			continue;
		}
	} END_FOR_EACH_SM(sm);

	return NULL;
}

char *map_long_to_short_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	return map_long_to_short_name_sym_helper(name, sym, new_sym, 1);
}

char *map_long_to_short_name_sym_nostack(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	return map_long_to_short_name_sym_helper(name, sym, new_sym, 0);
}

char *map_call_to_param_name_sym(struct expression *expr, struct symbol **sym)
{
	char *name;
	struct symbol *start_sym;
	struct smatch_state *state;

	*sym = NULL;

	name = expr_to_str_sym(expr, &start_sym);
	if (!name)
		return NULL;
	if (expr->type == EXPR_CALL)
		start_sym = expr_to_sym(expr->fn);

	state = get_state(my_id, name, start_sym);
	free_string(name);
	if (!state || !state->data)
		return NULL;

	*sym = state->data;
	return alloc_string(state->name);
}

static void store_mapping_helper(char *left_name, struct symbol *left_sym, struct expression *call, const char *return_string)
{
	const char *p = return_string;
	char *close;
	int param;
	struct expression *arg, *new;
	char *right_name;
	struct symbol *right_sym;
	char buf[256];

	while (*p && *p != '[')
		p++;
	if (!*p)
		return;
	p++;
	if (*p != '$')
		return;

	snprintf(buf, sizeof(buf), "%s", p);
	close = strchr(buf, ']');
	if (!close)
		return;
	*close = '\0';

	param = atoi(buf + 1);
	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;

	new = gen_expression_from_key(arg, buf);
	if (!new)
		return;

	right_name = expr_to_var_sym(new, &right_sym);
	if (!right_name || !right_sym)
		goto free;

	set_state(my_id, left_name, left_sym, alloc_my_state(right_name, right_sym));
	store_link(link_id, right_name, right_sym, left_name, left_sym);

free:
	free_string(right_name);
}

void __add_return_to_param_mapping(struct expression *expr, const char *return_string)
{
	struct expression *call;
	char *left_name = NULL;
	struct symbol *left_sym;

	if (expr->type == EXPR_ASSIGNMENT) {
		left_name = expr_to_var_sym(expr->left, &left_sym);
		if (!left_name || !left_sym)
			goto free;

		call = strip_expr(expr->right);
		if (call->type != EXPR_CALL)
			goto free;

		store_mapping_helper(left_name, left_sym, call, return_string);
		goto free;
	}

	if (expr->type == EXPR_CALL &&
	    expr_get_parent_stmt(expr) &&
	    expr_get_parent_stmt(expr)->type == STMT_RETURN) {
		call = strip_expr(expr);
		left_sym = expr_to_sym(call->fn);
		if (!left_sym)
			return;
		left_name = expr_to_str(call);
		if (!left_name)
			return;

		store_mapping_helper(left_name, left_sym, call, return_string);
		goto free;

	}

free:
	free_string(left_name);
}

void register_return_to_param(int id)
{
	my_id = id;
	add_modification_hook(my_id, &undef);
}

void register_return_to_param_links(int id)
{
	link_id = id;
	set_up_link_functions(my_id, link_id);
}


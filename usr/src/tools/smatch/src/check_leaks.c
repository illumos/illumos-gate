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

/*
 * The point of this check is to look for leaks.
 * foo = malloc();  // <- mark it as allocated.
 * A variable becomes &ok if we:
 * 1) assign it to another variable.
 * 2) pass it to a function.
 *
 * One complication is dealing with stuff like:
 * foo->bar = malloc();
 * foo->baz = malloc();
 * foo = something();
 *
 * The work around is that for now what this check only
 * checks simple expressions and doesn't check whether
 * foo->bar is leaked.
 * 
 */

#include <fcntl.h>
#include <unistd.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(allocated);
STATE(ok);

static void set_parent(struct expression *expr, struct smatch_state *state);

static const char *allocation_funcs[] = {
	"malloc",
	"kmalloc",
	"kzalloc",
	"kmemdup",
};

static char *alloc_parent_str(struct symbol *sym)
{
	static char buf[256];

	if (!sym || !sym->ident)
		return NULL;

	snprintf(buf, 255, "%s", sym->ident->name);
	buf[255] = '\0';
	return alloc_string(buf);
}

static char *get_parent_from_expr(struct expression *expr, struct symbol **sym)
{
	char *name;

	expr = strip_expr(expr);

	name = expr_to_str_sym(expr, sym);
	free_string(name);
	if (!name || !*sym || !(*sym)->ident) {
		*sym = NULL;
		return NULL;
	}
	return alloc_parent_str(*sym);
}

static int is_local(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	int ret = 0;

	name = expr_to_str_sym(expr, &sym);
	if (!name || !sym)
		goto out;
	if (sym->ctype.modifiers & (MOD_NONLOCAL | MOD_STATIC | MOD_ADDRESSABLE))
		goto out;
	ret = 1;
out:
	free_string(name);
	return ret;
}

static int is_param(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct symbol *tmp;
	int ret = 0;

	name = expr_to_str_sym(expr, &sym);
	if (!name || !sym)
		goto out;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, tmp) {
		if (tmp == sym) {
			ret = 1;
			goto out;
		}
	} END_FOR_EACH_PTR(tmp);
out:
	free_string(name);
	return ret;
	
}

static void match_alloc(const char *fn, struct expression *expr, void *unused)
{
	if (!is_local(expr->left))
		return;
	if (is_param(expr->left))
		return;
	if (expr->left->type != EXPR_SYMBOL)
		return;
	set_state_expr(my_id, expr->left, &allocated);
}

static void match_condition(struct expression *expr)
{
	struct sm_state *sm;

	expr = strip_expr(expr);

	switch (expr->type) {
	case EXPR_PREOP:
	case EXPR_SYMBOL:
	case EXPR_DEREF:
		sm = get_sm_state_expr(my_id, expr);
		if (sm && slist_has_state(sm->possible, &allocated))
			set_true_false_states_expr(my_id, expr, NULL, &ok);
		return;
	case EXPR_ASSIGNMENT:
		 /* You have to deal with stuff like if (a = b = c) */
		match_condition(expr->left);
		return;
	default:
		return;
	}
}

static void set_parent(struct expression *expr, struct smatch_state *state)
{
	char *name;
	struct symbol *sym;

	expr = strip_expr(expr);
	if (!expr)
		return;
	if (expr->type == EXPR_CONDITIONAL ||
	    expr->type == EXPR_SELECT) {
		set_parent(expr->cond_true, state);
		set_parent(expr->cond_false, state);
		return;
	}

	name = get_parent_from_expr(expr, &sym);
	if (!name || !sym)
		goto free;
	if (state == &ok && !get_state(my_id, name, sym))
		goto free;
	set_state(my_id, name, sym, state);
free:
	free_string(name);
}

static void match_function_call(struct expression *expr)
{
	struct expression *tmp;

	FOR_EACH_PTR(expr->args, tmp) {
		set_parent(tmp, &ok);
	} END_FOR_EACH_PTR(tmp);
}

static void warn_if_allocated(struct expression *expr)
{
	struct sm_state *sm;
	char *name;
	sval_t sval;

	if (get_implied_value(expr, &sval) && sval.value == 0)
		return;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;
	if (!slist_has_state(sm->possible, &allocated))
		return;

	name = expr_to_var(expr);
	sm_warning("overwrite may leak '%s'", name);
	free_string(name);

	/* silence further warnings */
	set_state_expr(my_id, expr, &ok);
}

static void match_assign(struct expression *expr)
{
	struct expression *right;

	right = expr->right;

	while (right->type == EXPR_ASSIGNMENT)
		right = right->left;

	warn_if_allocated(expr->left);
	set_parent(right, &ok);
}

static void check_for_allocated(void)
{
	struct stree *stree;
	struct sm_state *tmp;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(my_id, stree, tmp) {
		if (!slist_has_state(tmp->possible, &allocated))
			continue;
		sm_warning("possible memory leak of '%s'", tmp->name);
	} END_FOR_EACH_SM(tmp);
}

static void match_return(struct expression *ret_value)
{
	if (__inline_fn)
		return;
	set_parent(ret_value, &ok);
	check_for_allocated();
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	check_for_allocated();
}

void check_leaks(int id)
{
	int i;

	my_id = id;

	for (i = 0; i < ARRAY_SIZE(allocation_funcs); i++)
		add_function_assign_hook(allocation_funcs[i], &match_alloc, NULL);

	add_hook(&match_condition, CONDITION_HOOK);

	add_hook(&match_function_call, FUNCTION_CALL_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);

	add_hook(&match_return, RETURN_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

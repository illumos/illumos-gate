/*
 * Copyright (C) 2009 Dan Carpenter.
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
 * This check is supposed to find places like this:
 * err = foo();
 * err = bar();
 * if (err)
 *         return err;
 * (the first assignment isn't used)
 *
 * How the check works is that every assignment gets an ID.
 * We store that assignment ID in a list of assignments that
 * haven't been used.  We also set the state of 'err' from
 * the example above to be.  Then when we use 'err' we remove
 * it from the list.  At the end of the function we print
 * a list of assignments that still haven't been used.
 *
 * Note that this check only works for assignments to
 * EXPR_SYMBOL.  Maybe it could be modified to cover other
 * assignments later but then you would have to deal with
 * scope issues.
 *
 * Also this state is quite tied to the order the callbacks
 * are called in smatch_flow.c.  (If the order changed it
 * would break).
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_function_hashtable.h"

static int my_id;

struct assignment {
	int assign_id;
	char *name;
	char *function;
	int line;
};
ALLOCATOR(assignment, "assignment id");
DECLARE_PTR_LIST(assignment_list, struct assignment);
static struct assignment_list *assignment_list;

static struct expression *skip_this;
static int assign_id;

static DEFINE_HASHTABLE_INSERT(insert_func, char, int);
static DEFINE_HASHTABLE_SEARCH(search_func, char, int);
static struct hashtable *ignored_funcs;

static const char *kernel_ignored[] = {
	"inb",
	"inl",
	"inw",
	"readb",
	"readl",
	"readw",
};

static char *get_fn_name(struct expression *expr)
{
	if (expr->type != EXPR_CALL)
		return NULL;
	if (expr->fn->type != EXPR_SYMBOL)
		return NULL;
	return expr_to_var(expr->fn);
}

static int ignored_function(struct expression *expr)
{
	char *func;
	int ret = 0;

	func = get_fn_name(expr);
	if (!func)
		return 0;
	if (search_func(ignored_funcs, func))
		ret = 1;
	free_string(func);
	return ret;
}

static void match_assign_call(struct expression *expr)
{
	struct expression *left;
	struct assignment *assign;

	if (final_pass)
		return;
	if (in_condition())
		return;
	if (expr->op != '=')
		return;
	if (unreachable())
		return;
	if (ignored_function(expr->right))
		return;
	left = strip_expr(expr->left);
	if (!left || left->type != EXPR_SYMBOL)
		return;
	if (left->symbol->ctype.modifiers & (MOD_TOPLEVEL | MOD_EXTERN | MOD_STATIC))
		return;

	skip_this = left;

	set_state_expr(my_id, left, alloc_state_num(assign_id));

	assign = __alloc_assignment(0);
	assign->assign_id = assign_id++;
	assign->name = expr_to_var(left);
	assign->function = get_fn_name(expr->right);
	assign->line = get_lineno();
	add_ptr_list(&assignment_list, assign);
}

static void match_assign(struct expression *expr)
{
	struct expression *left;

	if (expr->op != '=')
		return;
	left = strip_expr(expr->left);
	if (!left || left->type != EXPR_SYMBOL)
		return;
	set_state_expr(my_id, left, &undefined);
}

static void delete_used(int assign_id)
{
	struct assignment *tmp;

 	FOR_EACH_PTR(assignment_list, tmp) {
		if (tmp->assign_id == assign_id) {
			DELETE_CURRENT_PTR(tmp);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
}

static void delete_used_symbols(struct state_list *possible)
{
	struct sm_state *tmp;

 	FOR_EACH_PTR(possible, tmp) {
		delete_used(PTR_INT(tmp->state->data));
	} END_FOR_EACH_PTR(tmp);
}

static void match_symbol(struct expression *expr)
{
	struct sm_state *sm;

	expr = strip_expr(expr);
	if (expr == skip_this)
		return;
	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return;
	delete_used_symbols(sm->possible);
	set_state_expr(my_id, expr, &undefined);
}

static void match_end_func(struct symbol *sym)
{
	struct assignment *tmp;

	if (__inline_fn)
		return;
 	FOR_EACH_PTR(assignment_list, tmp) {
		sm_printf("%s:%d %s() ", get_filename(), tmp->line, get_function());
		sm_printf("warn: unused return: %s = %s()\n",
			tmp->name, tmp->function);
	} END_FOR_EACH_PTR(tmp);
}

static void match_after_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	clear_assignment_alloc();
	__free_ptr_list((struct ptr_list **)&assignment_list);
}

void check_unused_ret(int id)
{
	my_id = id;

	/* It turns out that this test is worthless unless you use --two-passes.  */
	if (!option_two_passes)
		return;
	add_hook(&match_assign_call, CALL_ASSIGNMENT_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_symbol, SYM_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
	add_hook(&match_after_func, AFTER_FUNC_HOOK);
	ignored_funcs = create_function_hashtable(100);
	if (option_project == PROJ_KERNEL) {
		int i;

		for (i = 0; i < ARRAY_SIZE(kernel_ignored); i++)
			insert_func(ignored_funcs, (char *)kernel_ignored[i], (int *)1);
	}
}

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
 * This script is for finding functions like hcd_buffer_free() which free
 * their arguments.  After running it, add those functions to check_memory.c
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(putted);

static struct symbol *this_func;
static struct tracker_list *putted_args = NULL;

static void match_function_def(struct symbol *sym)
{
	this_func = sym;
}

static int parent_is_arg(struct symbol *sym)
{
	struct symbol *arg;

	FOR_EACH_PTR(this_func->ctype.base_type->arguments, arg) {
		if (sym == arg)
			return 1;
	} END_FOR_EACH_PTR(arg);
	return 0;
}

static void match_put(const char *fn, struct expression *expr, void *info)
{
	struct expression *tmp;
	struct symbol *sym;
	char *name;

	tmp = get_argument_from_call_expr(expr->args, 0);
	tmp = strip_expr(tmp);
	name = expr_to_var_sym(tmp, &sym);
	free_string(name);
	if (parent_is_arg(sym) && sym->ident)
		set_state(my_id, sym->ident->name, sym, &putted);
}

static int return_count = 0;
static void match_return(struct expression *ret_value)
{
	struct stree *stree;
	struct sm_state *tmp;
	struct tracker *tracker;

	if (__inline_fn)
		return;

	if (!return_count) {
		stree = __get_cur_stree();
		FOR_EACH_MY_SM(my_id, stree, tmp) {
			if (tmp->state == &putted)
				add_tracker(&putted_args, my_id, tmp->name, 
					    tmp->sym);
		} END_FOR_EACH_SM(tmp);
	} else {
		FOR_EACH_PTR(putted_args, tracker) {
			tmp = get_sm_state(my_id, tracker->name, tracker->sym);
			if (tmp && tmp->state != &putted)
				del_tracker(&putted_args, my_id, tracker->name, 
					    tracker->sym);
		} END_FOR_EACH_PTR(tracker);
		
	}
}

static void print_arg(struct symbol *sym)
{
	struct symbol *arg;
	int i = 0;

	FOR_EACH_PTR(this_func->ctype.base_type->arguments, arg) {
		if (sym == arg) {
			sm_info("puts_arg %s %d", get_function(), i);
			return;
		}
		i++;
	} END_FOR_EACH_PTR(arg);
}

static void match_end_func(struct symbol *sym)
{
	struct tracker *tracker;

	if (__inline_fn)
		return;
	if (is_reachable())
		match_return(NULL);

	FOR_EACH_PTR(putted_args, tracker) {
		print_arg(tracker->sym);
	} END_FOR_EACH_PTR(tracker);

	free_trackers_and_list(&putted_args);
	return_count = 0;
}

void check_puts_argument(int id)
{
	if (!option_info || option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_hook(&match_function_def, FUNC_DEF_HOOK);
	add_function_hook("kobject_put", &match_put, NULL);
	add_function_hook("kref_put", &match_put, NULL);
	add_hook(&match_return, RETURN_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

/*
 * Copyright (C) 2011 Oracle.
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

int RETURN_ID;

struct return_states_callback {
	void (*callback)(void);
};
ALLOCATOR(return_states_callback, "return states callbacks");
DECLARE_PTR_LIST(callback_list, struct return_states_callback);
static struct callback_list *callback_list;

DECLARE_PTR_LIST(stree_stack_stack, struct stree_stack);
static void push_stree_stack(struct stree_stack_stack **stack_stack, struct stree_stack *stack)
{
	add_ptr_list(stack_stack, stack);
}

static struct stree_stack *pop_stree_stack(struct stree_stack_stack **stack_stack)
{
	struct stree_stack *stack;

	stack = last_ptr_list((struct ptr_list *)*stack_stack);
	delete_ptr_list_last((struct ptr_list **)stack_stack);
	return stack;
}

static struct stree_stack *return_stree_stack;
static struct stree_stack_stack *saved_stack_stack;
static struct stree *all_return_states;
static struct stree_stack *saved_stack;

void all_return_states_hook(void (*callback)(void))
{
	struct return_states_callback *rs_cb = __alloc_return_states_callback(0);

	rs_cb->callback = callback;
	add_ptr_list(&callback_list, rs_cb);
}

static void call_hooks(void)
{
	struct return_states_callback *rs_cb;
	struct stree *orig;

	orig = __swap_cur_stree(all_return_states);
	FOR_EACH_PTR(callback_list, rs_cb) {
		rs_cb->callback();
	} END_FOR_EACH_PTR(rs_cb);
	__swap_cur_stree(orig);
}

static void match_return(int return_id, char *return_ranges, struct expression *expr)
{
	struct stree *stree;

	stree = clone_stree(__get_cur_stree());
	merge_stree_no_pools(&all_return_states, stree);
	push_stree(&return_stree_stack, stree);
}

static void match_end_func(struct symbol *sym)
{
	/*
	 * FIXME: either this isn't needed or we need to copy a stree into the
	 * return_stree_stack as well.
	 */
	merge_stree(&all_return_states, __get_cur_stree());
	call_hooks();
}

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, all_return_states);
	all_return_states = NULL;

	push_stree_stack(&saved_stack_stack, return_stree_stack);
	return_stree_stack = NULL;
}

static void match_restore_states(struct expression *expr)
{
	/* This free_stree() isn't needed is it?? */
	free_stree(&all_return_states);

	all_return_states = pop_stree(&saved_stack);
	return_stree_stack = pop_stree_stack(&saved_stack_stack);
}

struct stree *get_all_return_states(void)
{
	return all_return_states;
}

struct stree_stack *get_all_return_strees(void)
{
	return return_stree_stack;
}

static void free_resources(struct symbol *sym)
{
	free_stree(&all_return_states);
	free_stack_and_strees(&return_stree_stack);
}

void register_returns_early(int id)
{
	RETURN_ID = id;

	set_dynamic_states(RETURN_ID);
	add_split_return_callback(match_return);
}

void register_returns(int id)
{
	add_hook(&match_end_func, END_FUNC_HOOK);
	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);
	add_hook(&free_resources, AFTER_FUNC_HOOK);
}

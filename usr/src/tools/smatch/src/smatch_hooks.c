/*
 * Copyright (C) 2006 Dan Carpenter.
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

enum data_type {
	NO_DATA,
	EXPR_PTR,
	STMT_PTR,
	SYMBOL_PTR,
	SYM_LIST_PTR,
};

struct hook_container {
	int hook_type;
	int owner;
	void *fn;
};
ALLOCATOR(hook_container, "hook functions");
DECLARE_PTR_LIST(hook_func_list, struct hook_container);

typedef void (expr_func)(struct expression *expr);
typedef void (stmt_func)(struct statement *stmt);
typedef void (sym_func)(struct symbol *sym);
typedef void (sym_list_func)(struct symbol_list *sym_list);

static struct hook_func_list *merge_funcs;
static struct hook_func_list *unmatched_state_funcs;
static struct hook_func_list *hook_array[NUM_HOOKS] = {};
static const enum data_type data_types[NUM_HOOKS] = {
	[EXPR_HOOK] = EXPR_PTR,
	[EXPR_HOOK_AFTER] = EXPR_PTR,
	[STMT_HOOK] = STMT_PTR,
	[STMT_HOOK_AFTER] = STMT_PTR,
	[SYM_HOOK] = EXPR_PTR,
	[STRING_HOOK] = EXPR_PTR,
	[DECLARATION_HOOK] = SYMBOL_PTR,
	[ASSIGNMENT_HOOK] = EXPR_PTR,
	[ASSIGNMENT_HOOK_AFTER] = EXPR_PTR,
	[RAW_ASSIGNMENT_HOOK] = EXPR_PTR,
	[GLOBAL_ASSIGNMENT_HOOK] = EXPR_PTR,
	[CALL_ASSIGNMENT_HOOK] = EXPR_PTR,
	[MACRO_ASSIGNMENT_HOOK] = EXPR_PTR,
	[BINOP_HOOK] = EXPR_PTR,
	[OP_HOOK] = EXPR_PTR,
	[LOGIC_HOOK] = EXPR_PTR,
	[PRELOOP_HOOK] = STMT_PTR,
	[CONDITION_HOOK] = EXPR_PTR,
	[SELECT_HOOK] = EXPR_PTR,
	[WHOLE_CONDITION_HOOK] = EXPR_PTR,
	[FUNCTION_CALL_HOOK] = EXPR_PTR,
	[CALL_HOOK_AFTER_INLINE] = EXPR_PTR,
	[FUNCTION_CALL_HOOK_AFTER_DB] = EXPR_PTR,
	[DEREF_HOOK] = EXPR_PTR,
	[CASE_HOOK] = NO_DATA,
	[ASM_HOOK] = STMT_PTR,
	[CAST_HOOK] = EXPR_PTR,
	[SIZEOF_HOOK] = EXPR_PTR,
	[BASE_HOOK] = SYMBOL_PTR,
	[FUNC_DEF_HOOK] = SYMBOL_PTR,
	[AFTER_DEF_HOOK] = SYMBOL_PTR,
	[END_FUNC_HOOK] = SYMBOL_PTR,
	[AFTER_FUNC_HOOK] = SYMBOL_PTR,
	[RETURN_HOOK] = EXPR_PTR,
	[INLINE_FN_START] = EXPR_PTR,
	[INLINE_FN_END] = EXPR_PTR,
	[END_FILE_HOOK] = SYM_LIST_PTR,
};

void (**pre_merge_hooks)(struct sm_state *cur, struct sm_state *other);

struct scope_container {
	void *fn;
	void *data;
};
ALLOCATOR(scope_container, "scope hook functions");
DECLARE_PTR_LIST(scope_hook_list, struct scope_container);
DECLARE_PTR_LIST(scope_hook_stack, struct scope_hook_list);
static struct scope_hook_stack *scope_hooks;

void add_hook(void *func, enum hook_type type)
{
	struct hook_container *container = __alloc_hook_container(0);

	container->hook_type = type;
	container->fn = func;

	add_ptr_list(&hook_array[type], container);
}

void add_merge_hook(int client_id, merge_func_t *func)
{
	struct hook_container *container = __alloc_hook_container(0);
	container->owner = client_id;
	container->fn = func;
	add_ptr_list(&merge_funcs, container);
}

void add_unmatched_state_hook(int client_id, unmatched_func_t *func)
{
	struct hook_container *container = __alloc_hook_container(0);
	container->owner = client_id;
	container->fn = func;
	add_ptr_list(&unmatched_state_funcs, container);
}

void add_pre_merge_hook(int client_id, void (*hook)(struct sm_state *cur, struct sm_state *other))
{
	pre_merge_hooks[client_id] = hook;
}

static void pass_expr_to_client(void *fn, void *data)
{
	((expr_func *)fn)((struct expression *)data);
}

static void pass_stmt_to_client(void *fn, void *data)
{
	((stmt_func *)fn)((struct statement *)data);
}

static void pass_sym_to_client(void *fn, void *data)
{
	((sym_func *)fn)((struct symbol *)data);
}

static void pass_sym_list_to_client(void *fn, void *data)
{
	((sym_list_func *)fn)((struct symbol_list *)data);
}

void __pass_to_client(void *data, enum hook_type type)
{
	struct hook_container *container;

	FOR_EACH_PTR(hook_array[type], container) {
		switch (data_types[type]) {
		case EXPR_PTR:
			pass_expr_to_client(container->fn, data);
			break;
		case STMT_PTR:
			pass_stmt_to_client(container->fn, data);
			break;
		case SYMBOL_PTR:
			pass_sym_to_client(container->fn, data);
			break;
		case SYM_LIST_PTR:
			pass_sym_list_to_client(container->fn, data);
			break;
		}
	} END_FOR_EACH_PTR(container);
}

void __pass_case_to_client(struct expression *switch_expr,
			   struct range_list *rl)
{
	typedef void (case_func)(struct expression *switch_expr,
				 struct range_list *rl);
	struct hook_container *container;

	FOR_EACH_PTR(hook_array[CASE_HOOK], container) {
		((case_func *)container->fn)(switch_expr, rl);
	} END_FOR_EACH_PTR(container);
}

int __has_merge_function(int client_id)
{
	struct hook_container *tmp;

	FOR_EACH_PTR(merge_funcs, tmp) {
		if (tmp->owner == client_id)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

struct smatch_state *__client_merge_function(int owner,
					     struct smatch_state *s1,
					     struct smatch_state *s2)
{
	struct smatch_state *tmp_state;
	struct hook_container *tmp;

	/* Pass NULL states first and the rest alphabetically by name */
	if (!s2 || (s1 && strcmp(s2->name, s1->name) < 0)) {
		tmp_state = s1;
		s1 = s2;
		s2 = tmp_state;
	}

	FOR_EACH_PTR(merge_funcs, tmp) {
		if (tmp->owner == owner)
			return ((merge_func_t *)tmp->fn)(s1, s2);
	} END_FOR_EACH_PTR(tmp);
	return &undefined;
}

struct smatch_state *__client_unmatched_state_function(struct sm_state *sm)
{
	struct hook_container *tmp;

	FOR_EACH_PTR(unmatched_state_funcs, tmp) {
		if (tmp->owner == sm->owner)
			return ((unmatched_func_t *)tmp->fn)(sm);
	} END_FOR_EACH_PTR(tmp);
	return &undefined;
}

void call_pre_merge_hook(struct sm_state *cur, struct sm_state *other)
{
	if (cur->owner >= num_checks)
		return;

	if (pre_merge_hooks[cur->owner])
		pre_merge_hooks[cur->owner](cur, other);
}

static struct scope_hook_list *pop_scope_hook_list(struct scope_hook_stack **stack)
{
	struct scope_hook_list *hook_list;

	hook_list = last_ptr_list((struct ptr_list *)*stack);
	delete_ptr_list_last((struct ptr_list **)stack);
	return hook_list;
}

static void push_scope_hook_list(struct scope_hook_stack **stack, struct scope_hook_list *l)
{
	add_ptr_list(stack, l);
}

void add_scope_hook(scope_hook *fn, void *data)
{
	struct scope_hook_list *hook_list;
	struct scope_container *new;

	if (!scope_hooks)
		return;
	hook_list = pop_scope_hook_list(&scope_hooks);
	new = __alloc_scope_container(0);
	new->fn = fn;
	new->data = data;
	add_ptr_list(&hook_list, new);
	push_scope_hook_list(&scope_hooks, hook_list);
}

void __push_scope_hooks(void)
{
	push_scope_hook_list(&scope_hooks, NULL);
}

void __call_scope_hooks(void)
{
	struct scope_hook_list *hook_list;
	struct scope_container *tmp;

	if (!scope_hooks)
		return;

	hook_list = pop_scope_hook_list(&scope_hooks);
	FOR_EACH_PTR(hook_list, tmp) {
		((scope_hook *)tmp->fn)(tmp->data);
		__free_scope_container(tmp);
	} END_FOR_EACH_PTR(tmp);
}

void allocate_hook_memory(void)
{
	pre_merge_hooks = malloc(num_checks * sizeof(*pre_merge_hooks));
	memset(pre_merge_hooks, 0, num_checks * sizeof(*pre_merge_hooks));
}


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

/*
 * You have a lists of states.  kernel = locked, foo = NULL, ...
 * When you hit an if {} else {} statement then you swap the list
 * of states for a different list of states.  The lists are stored
 * on stacks.
 *
 * At the beginning of this file there are list of the stacks that
 * we use.  Each function in this file does something to one of
 * of the stacks.
 *
 * So the smatch_flow.c understands code but it doesn't understand states.
 * smatch_flow calls functions in this file.  This file calls functions
 * in smatch_slist.c which just has boring generic plumbing for handling
 * state lists.  But really it's this file where all the magic happens.
 */

#include <stdlib.h>
#include <stdio.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

struct smatch_state undefined = { .name = "undefined" };
struct smatch_state ghost = { .name = "ghost" };
struct smatch_state merged = { .name = "merged" };
struct smatch_state true_state = { .name = "true" };
struct smatch_state false_state = { .name = "false" };

static struct stree *cur_stree; /* current states */
static struct stree *fast_overlay;

static struct stree_stack *true_stack; /* states after a t/f branch */
static struct stree_stack *false_stack;
static struct stree_stack *pre_cond_stack; /* states before a t/f branch */

static struct stree_stack *cond_true_stack; /* states affected by a branch */
static struct stree_stack *cond_false_stack;

static struct stree_stack *fake_cur_stree_stack;
static int read_only;

static struct stree_stack *break_stack;
static struct stree_stack *fake_break_stack;
static struct stree_stack *switch_stack;
static struct range_list_stack *remaining_cases;
static struct stree_stack *default_stack;
static struct stree_stack *continue_stack;

static struct named_stree_stack *goto_stack;

static struct ptr_list *backup;

int option_debug;

void __print_cur_stree(void)
{
	__print_stree(cur_stree);
}

int unreachable(void)
{
	if (!cur_stree)
		return 1;
	return 0;
}

void __set_cur_stree_readonly(void)
{
	read_only++;
}

void __set_cur_stree_writable(void)
{
	read_only--;
}

struct sm_state *set_state(int owner, const char *name, struct symbol *sym, struct smatch_state *state)
{
	struct sm_state *ret;

	if (!name || !state)
		return NULL;

	if (read_only)
		sm_perror("cur_stree is read only.");

	if (option_debug || strcmp(check_name(owner), option_debug_check) == 0) {
		struct smatch_state *s;

		s = __get_state(owner, name, sym);
		if (!s)
			sm_msg("%s new [%s] '%s' %s", __func__,
			       check_name(owner), name, show_state(state));
		else
			sm_msg("%s change [%s] '%s' %s => %s",
				__func__, check_name(owner), name, show_state(s),
				show_state(state));
	}

	if (owner != -1 && unreachable())
		return NULL;

	if (fake_cur_stree_stack)
		set_state_stree_stack(&fake_cur_stree_stack, owner, name, sym, state);

	ret = set_state_stree(&cur_stree, owner, name, sym, state);

	return ret;
}

struct sm_state *set_state_expr(int owner, struct expression *expr, struct smatch_state *state)
{
	char *name;
	struct symbol *sym;
	struct sm_state *ret = NULL;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	ret = set_state(owner, name, sym, state);
free:
	free_string(name);
	return ret;
}

struct stree *__swap_cur_stree(struct stree *stree)
{
	struct stree *orig = cur_stree;

	cur_stree = stree;
	return orig;
}

void __push_fake_cur_stree(void)
{
	push_stree(&fake_cur_stree_stack, NULL);
	__save_pre_cond_states();
}

struct stree *__pop_fake_cur_stree(void)
{
	if (!fake_cur_stree_stack)
		sm_perror("popping too many fake cur strees.");
	__use_pre_cond_states();
	return pop_stree(&fake_cur_stree_stack);
}

void __free_fake_cur_stree(void)
{
	struct stree *stree;

	stree = __pop_fake_cur_stree();
	free_stree(&stree);
}

void __set_fake_cur_stree_fast(struct stree *stree)
{
	if (fast_overlay) {
		sm_perror("cannot nest fast overlay");
		return;
	}
	fast_overlay = stree;
	set_fast_math_only();
}

void __pop_fake_cur_stree_fast(void)
{
	fast_overlay = NULL;
	clear_fast_math_only();
}

void __merge_stree_into_cur(struct stree *stree)
{
	struct sm_state *sm;
	struct sm_state *orig;
	struct sm_state *merged;

	FOR_EACH_SM(stree, sm) {
		orig = get_sm_state(sm->owner, sm->name, sm->sym);
		if (orig)
			merged = merge_sm_states(orig, sm);
		else
			merged = sm;
		__set_sm(merged);
	} END_FOR_EACH_SM(sm);
}

void __set_sm(struct sm_state *sm)
{
	if (read_only)
		sm_perror("cur_stree is read only.");

	if (option_debug ||
	    strcmp(check_name(sm->owner), option_debug_check) == 0) {
		struct smatch_state *s;

		s = __get_state(sm->owner, sm->name, sm->sym);
		if (!s)
			sm_msg("%s new %s", __func__, show_sm(sm));
		else
			sm_msg("%s change %s (was %s)",	__func__, show_sm(sm),
			       show_state(s));
	}

	if (unreachable())
		return;

	if (fake_cur_stree_stack)
		overwrite_sm_state_stree_stack(&fake_cur_stree_stack, sm);

	overwrite_sm_state_stree(&cur_stree, sm);
}

void __set_sm_cur_stree(struct sm_state *sm)
{
	if (read_only)
		sm_perror("cur_stree is read only.");

	if (option_debug ||
	    strcmp(check_name(sm->owner), option_debug_check) == 0) {
		struct smatch_state *s;

		s = __get_state(sm->owner, sm->name, sm->sym);
		if (!s)
			sm_msg("%s new %s", __func__, show_sm(sm));
		else
			sm_msg("%s change %s (was %s)",
				__func__, show_sm(sm), show_state(s));
	}

	if (unreachable())
		return;

	overwrite_sm_state_stree(&cur_stree, sm);
}

void __set_sm_fake_stree(struct sm_state *sm)
{
	if (read_only)
		sm_perror("cur_stree is read only.");

	if (option_debug ||
	    strcmp(check_name(sm->owner), option_debug_check) == 0) {
		struct smatch_state *s;

		s = __get_state(sm->owner, sm->name, sm->sym);
		if (!s)
			sm_msg("%s new %s", __func__, show_sm(sm));
		else
			sm_msg("%s change %s (was %s)",
				__func__, show_sm(sm), show_state(s));
	}

	if (unreachable())
		return;

	overwrite_sm_state_stree_stack(&fake_cur_stree_stack, sm);
}


typedef void (get_state_hook)(int owner, const char *name, struct symbol *sym);
DECLARE_PTR_LIST(fn_list, get_state_hook *);
static struct fn_list *get_state_hooks;

void add_get_state_hook(get_state_hook *fn)
{
	get_state_hook **p = malloc(sizeof(get_state_hook *));
	*p = fn;
	add_ptr_list(&get_state_hooks, p);
}

static void call_get_state_hooks(int owner, const char *name, struct symbol *sym)
{
	static int recursion;
	get_state_hook **fn;

	if (recursion)
		return;
	recursion = 1;

	FOR_EACH_PTR(get_state_hooks, fn) {
		(*fn)(owner, name, sym);
	} END_FOR_EACH_PTR(fn);

	recursion = 0;
}

struct smatch_state *__get_state(int owner, const char *name, struct symbol *sym)
{
	struct sm_state *sm;

	sm = get_sm_state(owner, name, sym);
	if (!sm)
		return NULL;
	return sm->state;
}

struct smatch_state *get_state(int owner, const char *name, struct symbol *sym)
{
	call_get_state_hooks(owner, name, sym);

	return __get_state(owner, name, sym);
}

struct smatch_state *get_state_expr(int owner, struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct smatch_state *ret = NULL;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	ret = get_state(owner, name, sym);
free:
	free_string(name);
	return ret;
}

struct state_list *get_possible_states(int owner, const char *name, struct symbol *sym)
{
	struct sm_state *sms;

	sms = get_sm_state_stree(cur_stree, owner, name, sym);
	if (sms)
		return sms->possible;
	return NULL;
}

struct state_list *get_possible_states_expr(int owner, struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct state_list *ret = NULL;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	ret = get_possible_states(owner, name, sym);
free:
	free_string(name);
	return ret;
}

struct sm_state *get_sm_state(int owner, const char *name, struct symbol *sym)
{
	struct sm_state *ret;

	ret = get_sm_state_stree(fast_overlay, owner, name, sym);
	if (ret)
		return ret;

	return get_sm_state_stree(cur_stree, owner, name, sym);
}

struct sm_state *get_sm_state_expr(int owner, struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct sm_state *ret = NULL;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	ret = get_sm_state(owner, name, sym);
free:
	free_string(name);
	return ret;
}

void delete_state(int owner, const char *name, struct symbol *sym)
{
	delete_state_stree(&cur_stree, owner, name, sym);
	if (cond_true_stack) {
		delete_state_stree_stack(&pre_cond_stack, owner, name, sym);
		delete_state_stree_stack(&cond_true_stack, owner, name, sym);
		delete_state_stree_stack(&cond_false_stack, owner, name, sym);
	}
}

void delete_state_expr(int owner, struct expression *expr)
{
	char *name;
	struct symbol *sym;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	delete_state(owner, name, sym);
free:
	free_string(name);
}

static void delete_all_states_stree_sym(struct stree **stree, struct symbol *sym)
{
	struct state_list *slist = NULL;
	struct sm_state *sm;

	FOR_EACH_SM(*stree, sm) {
		if (sm->sym == sym)
			add_ptr_list(&slist, sm);
	} END_FOR_EACH_SM(sm);

	FOR_EACH_PTR(slist, sm) {
		delete_state_stree(stree, sm->owner, sm->name, sm->sym);
	} END_FOR_EACH_PTR(sm);

	free_slist(&slist);
}

static void delete_all_states_stree_stack_sym(struct stree_stack **stack, struct symbol *sym)
{
	struct stree *stree;

	if (!*stack)
		return;

	stree = pop_stree(stack);
	delete_all_states_stree_sym(&stree, sym);
	push_stree(stack, stree);
}

void __delete_all_states_sym(struct symbol *sym)
{
	delete_all_states_stree_sym(&cur_stree, sym);

	delete_all_states_stree_stack_sym(&true_stack, sym);
	delete_all_states_stree_stack_sym(&true_stack, sym);
	delete_all_states_stree_stack_sym(&false_stack, sym);
	delete_all_states_stree_stack_sym(&pre_cond_stack, sym);
	delete_all_states_stree_stack_sym(&cond_true_stack, sym);
	delete_all_states_stree_stack_sym(&cond_false_stack, sym);
	delete_all_states_stree_stack_sym(&fake_cur_stree_stack, sym);
	delete_all_states_stree_stack_sym(&break_stack, sym);
	delete_all_states_stree_stack_sym(&fake_break_stack, sym);
	delete_all_states_stree_stack_sym(&switch_stack, sym);
	delete_all_states_stree_stack_sym(&continue_stack, sym);

	/*
	 * deleting from the goto stack is problematic because we don't know
	 * if the label is in scope and also we need the value for --two-passes.
	 */
}

struct stree *get_all_states_from_stree(int owner, struct stree *source)
{
	struct stree *ret = NULL;
	struct sm_state *tmp;

	FOR_EACH_SM(source, tmp) {
		if (tmp->owner == owner)
			avl_insert(&ret, tmp);
	} END_FOR_EACH_SM(tmp);

	return ret;
}

struct stree *get_all_states_stree(int owner)
{
	return get_all_states_from_stree(owner, cur_stree);
}

struct stree *__get_cur_stree(void)
{
	return cur_stree;
}

int is_reachable(void)
{
	if (cur_stree)
		return 1;
	return 0;
}

void set_true_false_states(int owner, const char *name, struct symbol *sym,
			   struct smatch_state *true_state,
			   struct smatch_state *false_state)
{
	if (read_only)
		sm_perror("cur_stree is read only.");

	if (option_debug || strcmp(check_name(owner), option_debug_check) == 0) {
		struct smatch_state *tmp;

		tmp = __get_state(owner, name, sym);
		sm_msg("%s [%s] '%s'.  Was %s.  Now T:%s F:%s", __func__,
		       check_name(owner),  name, show_state(tmp),
		       show_state(true_state), show_state(false_state));
	}

	if (unreachable())
		return;

	if (!cond_false_stack || !cond_true_stack) {
		sm_perror("missing true/false stacks");
		return;
	}

	if (true_state)
		set_state_stree_stack(&cond_true_stack, owner, name, sym, true_state);
	if (false_state)
		set_state_stree_stack(&cond_false_stack, owner, name, sym, false_state);
}

void set_true_false_states_expr(int owner, struct expression *expr,
			   struct smatch_state *true_state,
			   struct smatch_state *false_state)
{
	char *name;
	struct symbol *sym;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	set_true_false_states(owner, name, sym, true_state, false_state);
free:
	free_string(name);
}

void __set_true_false_sm(struct sm_state *true_sm, struct sm_state *false_sm)
{
	int owner;
	const char *name;
	struct symbol *sym;

	if (!true_sm && !false_sm)
		return;

	if (unreachable())
		return;

	owner = true_sm ? true_sm->owner : false_sm->owner;
	name = true_sm ? true_sm->name : false_sm->name;
	sym = true_sm ? true_sm->sym : false_sm->sym;
	if (option_debug || strcmp(check_name(owner), option_debug_check) == 0) {
		struct smatch_state *tmp;

		tmp = __get_state(owner, name, sym);
		sm_msg("%s [%s] '%s'.  Was %s.  Now T:%s F:%s", __func__,
		       check_name(owner),  name, show_state(tmp),
		       show_state(true_sm ? true_sm->state : NULL),
		       show_state(false_sm ? false_sm->state : NULL));
	}

	if (!cond_false_stack || !cond_true_stack) {
		sm_perror("missing true/false stacks");
		return;
	}

	if (true_sm)
		overwrite_sm_state_stree_stack(&cond_true_stack, true_sm);
	if (false_sm)
		overwrite_sm_state_stree_stack(&cond_false_stack, false_sm);
}

void nullify_path(void)
{
	if (fake_cur_stree_stack) {
		__free_fake_cur_stree();
		__push_fake_cur_stree();
	}
	free_stree(&cur_stree);
}

void __match_nullify_path_hook(const char *fn, struct expression *expr,
			       void *unused)
{
	nullify_path();
}

/*
 * At the start of every function we mark the path
 * as unnull.  That way there is always at least one state
 * in the cur_stree until nullify_path is called.  This
 * is used in merge_slist() for the first null check.
 */
void __unnullify_path(void)
{
	if (!cur_stree)
		set_state(-1, "unnull_path", NULL, &true_state);
}

int __path_is_null(void)
{
	if (cur_stree)
		return 0;
	return 1;
}

static void check_stree_stack_free(struct stree_stack **stack)
{
	if (*stack) {
		sm_perror("stack not empty");
		free_stack_and_strees(stack);
	}
}

void save_all_states(void)
{
	__add_ptr_list(&backup, cur_stree);
	cur_stree = NULL;

	__add_ptr_list(&backup, true_stack);
	true_stack = NULL;
	__add_ptr_list(&backup, false_stack);
	false_stack = NULL;
	__add_ptr_list(&backup, pre_cond_stack);
	pre_cond_stack = NULL;

	__add_ptr_list(&backup, cond_true_stack);
	cond_true_stack = NULL;
	__add_ptr_list(&backup, cond_false_stack);
	cond_false_stack = NULL;

	__add_ptr_list(&backup, fake_cur_stree_stack);
	fake_cur_stree_stack = NULL;

	__add_ptr_list(&backup, break_stack);
	break_stack = NULL;
	__add_ptr_list(&backup, fake_break_stack);
	fake_break_stack = NULL;

	__add_ptr_list(&backup, switch_stack);
	switch_stack = NULL;
	__add_ptr_list(&backup, remaining_cases);
	remaining_cases = NULL;
	__add_ptr_list(&backup, default_stack);
	default_stack = NULL;
	__add_ptr_list(&backup, continue_stack);
	continue_stack = NULL;

	__add_ptr_list(&backup, goto_stack);
	goto_stack = NULL;
}

static void *pop_backup(void)
{
	void *ret;

	ret = last_ptr_list(backup);
	delete_ptr_list_last(&backup);
	return ret;
}

void restore_all_states(void)
{
	goto_stack = pop_backup();

	continue_stack = pop_backup();
	default_stack = pop_backup();
	remaining_cases = pop_backup();
	switch_stack = pop_backup();
	fake_break_stack = pop_backup();
	break_stack = pop_backup();

	fake_cur_stree_stack = pop_backup();

	cond_false_stack = pop_backup();
	cond_true_stack = pop_backup();

	pre_cond_stack = pop_backup();
	false_stack = pop_backup();
	true_stack = pop_backup();

	cur_stree = pop_backup();
}

void free_goto_stack(void)
{
	struct named_stree *named_stree;

	FOR_EACH_PTR(goto_stack, named_stree) {
		free_stree(&named_stree->stree);
	} END_FOR_EACH_PTR(named_stree);
	__free_ptr_list((struct ptr_list **)&goto_stack);
}

void clear_all_states(void)
{
	nullify_path();
	check_stree_stack_free(&true_stack);
	check_stree_stack_free(&false_stack);
	check_stree_stack_free(&pre_cond_stack);
	check_stree_stack_free(&cond_true_stack);
	check_stree_stack_free(&cond_false_stack);
	check_stree_stack_free(&break_stack);
	check_stree_stack_free(&fake_break_stack);
	check_stree_stack_free(&switch_stack);
	check_stree_stack_free(&continue_stack);
	check_stree_stack_free(&fake_cur_stree_stack);

	free_goto_stack();

	free_every_single_sm_state();
	free_tmp_expressions();
}

void __push_cond_stacks(void)
{
	push_stree(&cond_true_stack, NULL);
	push_stree(&cond_false_stack, NULL);
	__push_fake_cur_stree();
}

void __fold_in_set_states(void)
{
	struct stree *new_states;
	struct sm_state *sm;

	new_states = __pop_fake_cur_stree();
	FOR_EACH_SM(new_states, sm) {
		__set_sm(sm);
		__set_true_false_sm(sm, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&new_states);
}

void __free_set_states(void)
{
	struct stree *new_states;

	new_states = __pop_fake_cur_stree();
	free_stree(&new_states);
}

struct stree *__copy_cond_true_states(void)
{
	struct stree *ret;

	ret = pop_stree(&cond_true_stack);
	push_stree(&cond_true_stack, clone_stree(ret));
	return ret;
}

struct stree *__copy_cond_false_states(void)
{
	struct stree *ret;

	ret = pop_stree(&cond_false_stack);
	push_stree(&cond_false_stack, clone_stree(ret));
	return ret;
}

struct stree *__pop_cond_true_stack(void)
{
	return pop_stree(&cond_true_stack);
}

struct stree *__pop_cond_false_stack(void)
{
	return pop_stree(&cond_false_stack);
}

/*
 * This combines the pre cond states with either the true or false states.
 * For example:
 * a = kmalloc() ; if (a !! foo(a)
 * In the pre state a is possibly null.  In the true state it is non null.
 * In the false state it is null.  Combine the pre and the false to get
 * that when we call 'foo', 'a' is null.
 */
static void __use_cond_stack(struct stree_stack **stack)
{
	struct stree *stree;

	free_stree(&cur_stree);

	cur_stree = pop_stree(&pre_cond_stack);
	push_stree(&pre_cond_stack, clone_stree(cur_stree));

	stree = pop_stree(stack);
	overwrite_stree(stree, &cur_stree);
	push_stree(stack, stree);
}

void __use_pre_cond_states(void)
{
	free_stree(&cur_stree);
	cur_stree = pop_stree(&pre_cond_stack);
}

void __use_cond_true_states(void)
{
	__use_cond_stack(&cond_true_stack);
}

void __use_cond_false_states(void)
{
	__use_cond_stack(&cond_false_stack);
}

void __negate_cond_stacks(void)
{
	struct stree *old_false, *old_true;

	old_false = pop_stree(&cond_false_stack);
	old_true = pop_stree(&cond_true_stack);
	push_stree(&cond_false_stack, old_true);
	push_stree(&cond_true_stack, old_false);
}

void __and_cond_states(void)
{
	and_stree_stack(&cond_true_stack);
	or_stree_stack(&pre_cond_stack, cur_stree, &cond_false_stack);
}

void __or_cond_states(void)
{
	or_stree_stack(&pre_cond_stack, cur_stree, &cond_true_stack);
	and_stree_stack(&cond_false_stack);
}

void __save_pre_cond_states(void)
{
	push_stree(&pre_cond_stack, clone_stree(cur_stree));
}

void __discard_pre_cond_states(void)
{
	struct stree *tmp;

	tmp = pop_stree(&pre_cond_stack);
	free_stree(&tmp);
}

struct stree *__get_true_states(void)
{
	return clone_stree(top_stree(cond_true_stack));
}

struct stree *__get_false_states(void)
{
	return clone_stree(top_stree(cond_false_stack));
}

void __use_cond_states(void)
{
	struct stree *pre, *pre_clone, *true_states, *false_states;

	pre = pop_stree(&pre_cond_stack);
	pre_clone = clone_stree(pre);

	true_states = pop_stree(&cond_true_stack);
	overwrite_stree(true_states, &pre);
	free_stree(&true_states);
	/* we use the true states right away */
	free_stree(&cur_stree);
	cur_stree = pre;

	false_states = pop_stree(&cond_false_stack);
	overwrite_stree(false_states, &pre_clone);
	free_stree(&false_states);
	push_stree(&false_stack, pre_clone);
}

void __push_true_states(void)
{
	push_stree(&true_stack, clone_stree(cur_stree));
}

void __use_false_states(void)
{
	free_stree(&cur_stree);
	cur_stree = pop_stree(&false_stack);
}

void __discard_false_states(void)
{
	struct stree *stree;

	stree = pop_stree(&false_stack);
	free_stree(&stree);
}

void __merge_false_states(void)
{
	struct stree *stree;

	stree = pop_stree(&false_stack);
	merge_stree(&cur_stree, stree);
	free_stree(&stree);
}

/*
 * This function probably seemed common sensical when I wrote it but, oh wow,
 * does it look subtle in retrospect.  Say we set a state on one side of the if
 * else path but not on the other, then what we should record in the fake stree
 * is the merged state.
 *
 * This function relies on the fact that the we always set the cur_stree as well
 * and we already have the infrastructure to merge things correctly into the
 * cur_stree.
 *
 * So instead of merging fake strees together which is probably a lot of work,
 * we just use it as a list of set states and look up the actual current values
 * in the cur_stree.
 *
 */
static void update_stree_with_merged(struct stree **stree)
{
	struct state_list *slist = NULL;
	struct sm_state *sm, *new;

	FOR_EACH_SM(*stree, sm) {
		new = get_sm_state(sm->owner, sm->name, sm->sym);
		if (!new)  /* This can happen if we go out of scope */
			continue;
		add_ptr_list(&slist, new);
	} END_FOR_EACH_SM(sm);

	FOR_EACH_PTR(slist, sm) {
		overwrite_sm_state_stree(stree, sm);
	} END_FOR_EACH_PTR(sm);

	free_slist(&slist);
}

static void update_fake_stree_with_merged(void)
{
	struct stree *stree;

	if (!fake_cur_stree_stack)
		return;
	stree = pop_stree(&fake_cur_stree_stack);
	update_stree_with_merged(&stree);
	push_stree(&fake_cur_stree_stack, stree);
}

void __merge_true_states(void)
{
	struct stree *stree;

	stree = pop_stree(&true_stack);
	merge_stree(&cur_stree, stree);
	update_fake_stree_with_merged();
	free_stree(&stree);
}

void __push_continues(void)
{
	push_stree(&continue_stack, NULL);
}

void __discard_continues(void)
{
	struct stree *stree;

	stree = pop_stree(&continue_stack);
	free_stree(&stree);
}

void __process_continues(void)
{
	struct stree *stree;

	stree = pop_stree(&continue_stack);
	if (!stree)
		stree = clone_stree(cur_stree);
	else
		merge_stree(&stree, cur_stree);

	push_stree(&continue_stack, stree);
}

void __merge_continues(void)
{
	struct stree *stree;

	stree = pop_stree(&continue_stack);
	merge_stree(&cur_stree, stree);
	free_stree(&stree);
}

void __push_breaks(void)
{
	push_stree(&break_stack, NULL);
	if (fake_cur_stree_stack)
		push_stree(&fake_break_stack, NULL);
}

void __process_breaks(void)
{
	struct stree *stree;

	stree = pop_stree(&break_stack);
	if (!stree)
		stree = clone_stree(cur_stree);
	else
		merge_stree(&stree, cur_stree);
	push_stree(&break_stack, stree);

	if (!fake_cur_stree_stack)
		return;

	stree = pop_stree(&fake_break_stack);
	if (!stree)
		stree = clone_stree(top_stree(fake_cur_stree_stack));
	else
		merge_stree(&stree, top_stree(fake_cur_stree_stack));
	push_stree(&fake_break_stack, stree);
}

int __has_breaks(void)
{
	struct stree *stree;
	int ret;

	stree = pop_stree(&break_stack);
	ret = !!stree;
	push_stree(&break_stack, stree);
	return ret;
}

void __merge_breaks(void)
{
	struct stree *stree;
	struct sm_state *sm;

	stree = pop_stree(&break_stack);
	merge_stree(&cur_stree, stree);
	free_stree(&stree);

	if (!fake_cur_stree_stack)
		return;

	stree = pop_stree(&fake_break_stack);
	update_stree_with_merged(&stree);
	FOR_EACH_SM(stree, sm) {
		overwrite_sm_state_stree_stack(&fake_cur_stree_stack, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);
}

void __use_breaks(void)
{
	struct stree *stree;
	struct sm_state *sm;

	free_stree(&cur_stree);
	cur_stree = pop_stree(&break_stack);

	if (!fake_cur_stree_stack)
		return;
	stree = pop_stree(&fake_break_stack);
	FOR_EACH_SM(stree, sm) {
		overwrite_sm_state_stree_stack(&fake_cur_stree_stack, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);


}

void __save_switch_states(struct expression *switch_expr)
{
	struct range_list *rl;

	get_absolute_rl(switch_expr, &rl);

	push_rl(&remaining_cases, rl);
	push_stree(&switch_stack, clone_stree(cur_stree));
}

int have_remaining_cases(void)
{
	return !!top_rl(remaining_cases);
}

void __merge_switches(struct expression *switch_expr, struct range_list *case_rl)
{
	struct stree *stree;
	struct stree *implied_stree;

	stree = pop_stree(&switch_stack);
	implied_stree = __implied_case_stree(switch_expr, case_rl, &remaining_cases, &stree);
	merge_stree(&cur_stree, implied_stree);
	free_stree(&implied_stree);
	push_stree(&switch_stack, stree);
}

void __discard_switches(void)
{
	struct stree *stree;

	pop_rl(&remaining_cases);
	stree = pop_stree(&switch_stack);
	free_stree(&stree);
}

void __push_default(void)
{
	push_stree(&default_stack, NULL);
}

void __set_default(void)
{
	set_state_stree_stack(&default_stack, 0, "has_default", NULL, &true_state);
}

int __pop_default(void)
{
	struct stree *stree;

	stree = pop_stree(&default_stack);
	if (stree) {
		free_stree(&stree);
		return 1;
	}
	return 0;
}

static struct named_stree *alloc_named_stree(const char *name, struct symbol *sym, struct stree *stree)
{
	struct named_stree *named_stree = __alloc_named_stree(0);

	named_stree->name = (char *)name;
	named_stree->stree = stree;
	named_stree->sym = sym;
	return named_stree;
}

void __save_gotos(const char *name, struct symbol *sym)
{
	struct stree **stree;
	struct stree *clone;

	stree = get_named_stree(goto_stack, name, sym);
	if (stree) {
		merge_stree(stree, cur_stree);
		return;
	} else {
		struct named_stree *named_stree;

		clone = clone_stree(cur_stree);
		named_stree = alloc_named_stree(name, sym, clone);
		add_ptr_list(&goto_stack, named_stree);
	}
}

void __merge_gotos(const char *name, struct symbol *sym)
{
	struct stree **stree;

	stree = get_named_stree(goto_stack, name, sym);
	if (stree)
		merge_stree(&cur_stree, *stree);
}

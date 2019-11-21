/*
 * Copyright (C) 2008,2009 Dan Carpenter.
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

#include <stdlib.h>
#include <stdio.h>
#include "smatch.h"
#include "smatch_slist.h"

#undef CHECKORDER

ALLOCATOR(smatch_state, "smatch state");
ALLOCATOR(sm_state, "sm state");
ALLOCATOR(named_stree, "named slist");
__DO_ALLOCATOR(char, 1, 4, "state names", sname);

int sm_state_counter;

static struct stree_stack *all_pools;

const char *show_sm(struct sm_state *sm)
{
	static char buf[256];
	struct sm_state *tmp;
	int pos;
	int i;

	if (!sm)
		return "<none>";

	pos = snprintf(buf, sizeof(buf), "[%s] %s = '%s'%s",
		       check_name(sm->owner), sm->name, show_state(sm->state),
		       sm->merged ? " [merged]" : "");
	if (pos > sizeof(buf))
		goto truncate;

	if (ptr_list_size((struct ptr_list *)sm->possible) == 1)
		return buf;

	pos += snprintf(buf + pos, sizeof(buf) - pos, " (");
	if (pos > sizeof(buf))
		goto truncate;
	i = 0;
	FOR_EACH_PTR(sm->possible, tmp) {
		if (i++)
			pos += snprintf(buf + pos, sizeof(buf) - pos, ", ");
		if (pos > sizeof(buf))
			goto truncate;
		pos += snprintf(buf + pos, sizeof(buf) - pos, "%s",
			       show_state(tmp->state));
		if (pos > sizeof(buf))
			goto truncate;
	} END_FOR_EACH_PTR(tmp);
	snprintf(buf + pos, sizeof(buf) - pos, ")");

	return buf;

truncate:
	for (i = 0; i < 3; i++)
		buf[sizeof(buf) - 2 - i] = '.';
	return buf;
}

void __print_stree(struct stree *stree)
{
	struct sm_state *sm;

	printf("dumping stree at %d [%ld states]\n", get_lineno(), stree_count(stree));
	FOR_EACH_SM(stree, sm) {
		printf("%s\n", show_sm(sm));
	} END_FOR_EACH_SM(sm);
	printf("---\n");
}

/* NULL states go at the end to simplify merge_slist */
int cmp_tracker(const struct sm_state *a, const struct sm_state *b)
{
	int ret;

	if (a == b)
		return 0;
	if (!b)
		return -1;
	if (!a)
		return 1;

	if (a->owner < b->owner)
		return -1;
	if (a->owner > b->owner)
		return 1;

	ret = strcmp(a->name, b->name);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	if (!b->sym && a->sym)
		return -1;
	if (!a->sym && b->sym)
		return 1;
	if (a->sym < b->sym)
		return -1;
	if (a->sym > b->sym)
		return 1;

	return 0;
}

int *dynamic_states;
void allocate_dynamic_states_array(int num_checks)
{
	dynamic_states = calloc(num_checks + 1, sizeof(int));
}

void set_dynamic_states(unsigned short owner)
{
	dynamic_states[owner] = true;
}

bool has_dynamic_states(unsigned short owner)
{
	if (owner >= num_checks)
		return false;
	return dynamic_states[owner];
}

static int cmp_possible_sm(const struct sm_state *a, const struct sm_state *b, int preserve)
{
	int ret;

	if (a == b)
		return 0;

	if (!has_dynamic_states(a->owner)) {
		if (a->state > b->state)
			return -1;
		if (a->state < b->state)
			return 1;
		return 0;
	}

	if (a->owner == SMATCH_EXTRA) {
		/*
		 * In Smatch extra you can have borrowed implications.
		 *
		 * FIXME: review how borrowed implications work and if they
		 * are the best way.  See also smatch_implied.c.
		 *
		 */
		ret = cmp_tracker(a, b);
		if (ret)
			return ret;

		/*
		 * We want to preserve leaf states.  They're use to split
		 * returns in smatch_db.c.
		 *
		 */
		if (preserve) {
			if (a->merged && !b->merged)
				return -1;
			if (!a->merged)
				return 1;
		}
	}
	if (!a->state->name || !b->state->name)
		return 0;

	return strcmp(a->state->name, b->state->name);
}

struct sm_state *alloc_sm_state(int owner, const char *name,
				struct symbol *sym, struct smatch_state *state)
{
	struct sm_state *sm_state = __alloc_sm_state(0);

	sm_state_counter++;

	sm_state->name = alloc_sname(name);
	sm_state->owner = owner;
	sm_state->sym = sym;
	sm_state->state = state;
	sm_state->line = get_lineno();
	sm_state->merged = 0;
	sm_state->pool = NULL;
	sm_state->left = NULL;
	sm_state->right = NULL;
	sm_state->possible = NULL;
	add_ptr_list(&sm_state->possible, sm_state);
	return sm_state;
}

static struct sm_state *alloc_state_no_name(int owner, const char *name,
				     struct symbol *sym,
				     struct smatch_state *state)
{
	struct sm_state *tmp;

	tmp = alloc_sm_state(owner, NULL, sym, state);
	tmp->name = name;
	return tmp;
}

int too_many_possible(struct sm_state *sm)
{
	if (ptr_list_size((struct ptr_list *)sm->possible) >= 100)
		return 1;
	return 0;
}

void add_possible_sm(struct sm_state *to, struct sm_state *new)
{
	struct sm_state *tmp;
	int preserve = 1;
	int cmp;

	if (too_many_possible(to))
		preserve = 0;

	FOR_EACH_PTR(to->possible, tmp) {
		cmp = cmp_possible_sm(tmp, new, preserve);
		if (cmp < 0)
			continue;
		else if (cmp == 0) {
			return;
		} else {
			INSERT_CURRENT(new, tmp);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
	add_ptr_list(&to->possible, new);
}

static void copy_possibles(struct sm_state *to, struct sm_state *one, struct sm_state *two)
{
	struct sm_state *large = one;
	struct sm_state *small = two;
	struct sm_state *tmp;

	/*
	 * We spend a lot of time copying the possible lists.  I've tried to
	 * optimize the process a bit.
	 *
	 */

	if (ptr_list_size((struct ptr_list *)two->possible) >
	    ptr_list_size((struct ptr_list *)one->possible)) {
		large = two;
		small = one;
	}

	to->possible = clone_slist(large->possible);
	add_possible_sm(to, to);
	FOR_EACH_PTR(small->possible, tmp) {
		add_possible_sm(to, tmp);
	} END_FOR_EACH_PTR(tmp);
}

char *alloc_sname(const char *str)
{
	char *tmp;

	if (!str)
		return NULL;
	tmp = __alloc_sname(strlen(str) + 1);
	strcpy(tmp, str);
	return tmp;
}

static struct symbol *oom_func;
static int oom_limit = 3000000;  /* Start with a 3GB limit */
int out_of_memory(void)
{
	if (oom_func)
		return 1;

	/*
	 * I decided to use 50M here based on trial and error.
	 * It works out OK for the kernel and so it should work
	 * for most other projects as well.
	 */
	if (sm_state_counter * sizeof(struct sm_state) >= 100000000)
		return 1;

	/*
	 * We're reading from statm to figure out how much memory we
	 * are using.  The problem is that at the end of the function
	 * we release the memory, so that it can be re-used but it
	 * stays in cache, it's not released to the OS.  So then if
	 * we allocate memory for different purposes we can easily
	 * hit the 3GB limit on the next function, so that's why I give
	 * the next function an extra 100MB to work with.
	 *
	 */
	if (get_mem_kb() > oom_limit) {
		oom_func = cur_func_sym;
		final_pass++;
		sm_perror("OOM: %luKb sm_state_count = %d", get_mem_kb(), sm_state_counter);
		final_pass--;
		return 1;
	}

	return 0;
}

int low_on_memory(void)
{
	if (sm_state_counter * sizeof(struct sm_state) >= 25000000)
		return 1;
	return 0;
}

static void free_sm_state(struct sm_state *sm)
{
	free_slist(&sm->possible);
	/*
	 * fixme.  Free the actual state.
	 * Right now we leave it until the end of the function
	 * because we don't want to double free it.
	 * Use the freelist to not double free things
	 */
}

static void free_all_sm_states(struct allocation_blob *blob)
{
	unsigned int size = sizeof(struct sm_state);
	unsigned int offset = 0;

	while (offset < blob->offset) {
		free_sm_state((struct sm_state *)(blob->data + offset));
		offset += size;
	}
}

/* At the end of every function we free all the sm_states */
void free_every_single_sm_state(void)
{
	struct allocator_struct *desc = &sm_state_allocator;
	struct allocation_blob *blob = desc->blobs;

	desc->blobs = NULL;
	desc->allocations = 0;
	desc->total_bytes = 0;
	desc->useful_bytes = 0;
	desc->freelist = NULL;
	while (blob) {
		struct allocation_blob *next = blob->next;
		free_all_sm_states(blob);
		blob_free(blob, desc->chunking);
		blob = next;
	}
	clear_sname_alloc();
	clear_smatch_state_alloc();

	free_stack_and_strees(&all_pools);
	sm_state_counter = 0;
	if (oom_func) {
		oom_limit += 100000;
		oom_func = NULL;
	}
}

unsigned long get_pool_count(void)
{
	return ptr_list_size((struct ptr_list *)all_pools);
}

struct sm_state *clone_sm(struct sm_state *s)
{
	struct sm_state *ret;

	ret = alloc_state_no_name(s->owner, s->name, s->sym, s->state);
	ret->merged = s->merged;
	ret->line = s->line;
	/* clone_sm() doesn't copy the pools.  Each state needs to have
	   only one pool. */
	ret->possible = clone_slist(s->possible);
	ret->left = s->left;
	ret->right = s->right;
	return ret;
}

int is_merged(struct sm_state *sm)
{
	return sm->merged;
}

int is_leaf(struct sm_state *sm)
{
	return !sm->merged;
}

int slist_has_state(struct state_list *slist, struct smatch_state *state)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(slist, tmp) {
		if (tmp->state == state)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

struct state_list *clone_slist(struct state_list *from_slist)
{
	struct sm_state *sm;
	struct state_list *to_slist = NULL;

	FOR_EACH_PTR(from_slist, sm) {
		add_ptr_list(&to_slist, sm);
	} END_FOR_EACH_PTR(sm);
	return to_slist;
}

static struct smatch_state *merge_states(int owner, const char *name,
					 struct symbol *sym,
					 struct smatch_state *state1,
					 struct smatch_state *state2)
{
	struct smatch_state *ret;

	if (state1 == state2)
		ret = state1;
	else if (__has_merge_function(owner))
		ret = __client_merge_function(owner, state1, state2);
	else if (state1 == &ghost)
		ret = state2;
	else if (state2 == &ghost)
		ret = state1;
	else if (!state1 || !state2)
		ret = &undefined;
	else
		ret = &merged;
	return ret;
}

struct sm_state *merge_sm_states(struct sm_state *one, struct sm_state *two)
{
	struct smatch_state *s;
	struct sm_state *result;
	static int warned;

	if (one == two)
		return one;
	if (out_of_memory()) {
		if (!warned)
			sm_warning("Function too hairy.  No more merges.");
		warned = 1;
		return one;
	}
	warned = 0;
	s = merge_states(one->owner, one->name, one->sym, one->state, two->state);
	result = alloc_state_no_name(one->owner, one->name, one->sym, s);
	result->merged = 1;
	result->left = one;
	result->right = two;

	copy_possibles(result, one, two);

	/*
	 * The ->line information is used by deref_check where we complain about
	 * checking pointers that have already been dereferenced.  Let's say we
	 * dereference a pointer on both the true and false paths and then merge
	 * the states here.  The result state is &derefed, but the ->line number
	 * is on the line where the pointer is merged not where it was
	 * dereferenced..
	 *
	 * So in that case, let's just pick one dereference and set the ->line
	 * to point at it.
	 *
	 */

	if (result->state == one->state)
		result->line = one->line;
	if (result->state == two->state)
		result->line = two->line;

	if (option_debug ||
	    strcmp(check_name(one->owner), option_debug_check) == 0) {
		struct sm_state *tmp;
		int i = 0;

		printf("%s:%d %s() merge [%s] '%s' %s(L %d) + %s(L %d) => %s (",
			get_filename(), get_lineno(), get_function(),
			check_name(one->owner), one->name,
			show_state(one->state), one->line,
			show_state(two->state), two->line,
			show_state(s));

		FOR_EACH_PTR(result->possible, tmp) {
			if (i++)
				printf(", ");
			printf("%s", show_state(tmp->state));
		} END_FOR_EACH_PTR(tmp);
		printf(")\n");
	}

	return result;
}

struct sm_state *get_sm_state_stree(struct stree *stree, int owner, const char *name,
				struct symbol *sym)
{
	struct tracker tracker = {
		.owner = owner,
		.name = (char *)name,
		.sym = sym,
	};

	if (!name)
		return NULL;


	return avl_lookup(stree, (struct sm_state *)&tracker);
}

struct smatch_state *get_state_stree(struct stree *stree,
				int owner, const char *name,
				struct symbol *sym)
{
	struct sm_state *sm;

	sm = get_sm_state_stree(stree, owner, name, sym);
	if (sm)
		return sm->state;
	return NULL;
}

/* FIXME: this is almost exactly the same as set_sm_state_slist() */
void overwrite_sm_state_stree(struct stree **stree, struct sm_state *new)
{
	avl_insert(stree, new);
}

void overwrite_sm_state_stree_stack(struct stree_stack **stack,
			struct sm_state *sm)
{
	struct stree *stree;

	stree = pop_stree(stack);
	overwrite_sm_state_stree(&stree, sm);
	push_stree(stack, stree);
}

struct sm_state *set_state_stree(struct stree **stree, int owner, const char *name,
		     struct symbol *sym, struct smatch_state *state)
{
	struct sm_state *new = alloc_sm_state(owner, name, sym, state);

	avl_insert(stree, new);
	return new;
}

void set_state_stree_perm(struct stree **stree, int owner, const char *name,
		     struct symbol *sym, struct smatch_state *state)
{
	struct sm_state *sm;

	sm = malloc(sizeof(*sm) + strlen(name) + 1);
	memset(sm, 0, sizeof(*sm));
	sm->owner = owner;
	sm->name = (char *)(sm + 1);
	strcpy((char *)sm->name, name);
	sm->sym = sym;
	sm->state = state;

	overwrite_sm_state_stree(stree, sm);
}

void delete_state_stree(struct stree **stree, int owner, const char *name,
			struct symbol *sym)
{
	struct tracker tracker = {
		.owner = owner,
		.name = (char *)name,
		.sym = sym,
	};

	avl_remove(stree, (struct sm_state *)&tracker);
}

void delete_state_stree_stack(struct stree_stack **stack, int owner, const char *name,
			struct symbol *sym)
{
	struct stree *stree;

	stree = pop_stree(stack);
	delete_state_stree(&stree, owner, name, sym);
	push_stree(stack, stree);
}

void push_stree(struct stree_stack **stack, struct stree *stree)
{
	add_ptr_list(stack, stree);
}

struct stree *pop_stree(struct stree_stack **stack)
{
	struct stree *stree;

	stree = last_ptr_list((struct ptr_list *)*stack);
	delete_ptr_list_last((struct ptr_list **)stack);
	return stree;
}

struct stree *top_stree(struct stree_stack *stack)
{
	return last_ptr_list((struct ptr_list *)stack);
}

void free_slist(struct state_list **slist)
{
	__free_ptr_list((struct ptr_list **)slist);
}

void free_stree_stack(struct stree_stack **stack)
{
	__free_ptr_list((struct ptr_list **)stack);
}

void free_stack_and_strees(struct stree_stack **stree_stack)
{
	struct stree *stree;

	FOR_EACH_PTR(*stree_stack, stree) {
		free_stree(&stree);
	} END_FOR_EACH_PTR(stree);
	free_stree_stack(stree_stack);
}

struct sm_state *set_state_stree_stack(struct stree_stack **stack, int owner, const char *name,
				struct symbol *sym, struct smatch_state *state)
{
	struct stree *stree;
	struct sm_state *sm;

	stree = pop_stree(stack);
	sm = set_state_stree(&stree, owner, name, sym, state);
	push_stree(stack, stree);

	return sm;
}

/*
 * get_sm_state_stack() gets the state for the top slist on the stack.
 */
struct sm_state *get_sm_state_stree_stack(struct stree_stack *stack,
				int owner, const char *name,
				struct symbol *sym)
{
	struct stree *stree;
	struct sm_state *ret;

	stree = pop_stree(&stack);
	ret = get_sm_state_stree(stree, owner, name, sym);
	push_stree(&stack, stree);
	return ret;
}

struct smatch_state *get_state_stree_stack(struct stree_stack *stack,
				int owner, const char *name,
				struct symbol *sym)
{
	struct sm_state *sm;

	sm = get_sm_state_stree_stack(stack, owner, name, sym);
	if (sm)
		return sm->state;
	return NULL;
}

static void match_states_stree(struct stree **one, struct stree **two)
{
	struct smatch_state *tmp_state;
	struct sm_state *sm;
	struct state_list *add_to_one = NULL;
	struct state_list *add_to_two = NULL;
	AvlIter one_iter;
	AvlIter two_iter;

	__set_cur_stree_readonly();

	avl_iter_begin(&one_iter, *one, FORWARD);
	avl_iter_begin(&two_iter, *two, FORWARD);

	for (;;) {
		if (!one_iter.sm && !two_iter.sm)
			break;
		if (cmp_tracker(one_iter.sm, two_iter.sm) < 0) {
			__set_fake_cur_stree_fast(*two);
			__in_unmatched_hook++;
			tmp_state = __client_unmatched_state_function(one_iter.sm);
			__in_unmatched_hook--;
			__pop_fake_cur_stree_fast();
			sm = alloc_state_no_name(one_iter.sm->owner, one_iter.sm->name,
						  one_iter.sm->sym, tmp_state);
			add_ptr_list(&add_to_two, sm);
			avl_iter_next(&one_iter);
		} else if (cmp_tracker(one_iter.sm, two_iter.sm) == 0) {
			avl_iter_next(&one_iter);
			avl_iter_next(&two_iter);
		} else {
			__set_fake_cur_stree_fast(*one);
			__in_unmatched_hook++;
			tmp_state = __client_unmatched_state_function(two_iter.sm);
			__in_unmatched_hook--;
			__pop_fake_cur_stree_fast();
			sm = alloc_state_no_name(two_iter.sm->owner, two_iter.sm->name,
						  two_iter.sm->sym, tmp_state);
			add_ptr_list(&add_to_one, sm);
			avl_iter_next(&two_iter);
		}
	}

	__set_cur_stree_writable();

	FOR_EACH_PTR(add_to_one, sm) {
		avl_insert(one, sm);
	} END_FOR_EACH_PTR(sm);

	FOR_EACH_PTR(add_to_two, sm) {
		avl_insert(two, sm);
	} END_FOR_EACH_PTR(sm);

	free_slist(&add_to_one);
	free_slist(&add_to_two);
}

static void call_pre_merge_hooks(struct stree **one, struct stree **two)
{
	struct sm_state *sm, *cur;
	struct stree *new;

	__in_unmatched_hook++;

	__set_fake_cur_stree_fast(*one);
	__push_fake_cur_stree();
	FOR_EACH_SM(*two, sm) {
		cur = get_sm_state(sm->owner, sm->name, sm->sym);
		if (cur == sm)
			continue;
		call_pre_merge_hook(cur, sm);
	} END_FOR_EACH_SM(sm);
	new = __pop_fake_cur_stree();
	overwrite_stree(new, one);
	free_stree(&new);
	__pop_fake_cur_stree_fast();

	__set_fake_cur_stree_fast(*two);
	__push_fake_cur_stree();
	FOR_EACH_SM(*one, sm) {
		cur = get_sm_state(sm->owner, sm->name, sm->sym);
		if (cur == sm)
			continue;
		call_pre_merge_hook(cur, sm);
	} END_FOR_EACH_SM(sm);
	new = __pop_fake_cur_stree();
	overwrite_stree(new, two);
	free_stree(&new);
	__pop_fake_cur_stree_fast();

	__in_unmatched_hook--;
}

static void clone_pool_havers_stree(struct stree **stree)
{
	struct sm_state *sm, *tmp;
	struct state_list *slist = NULL;

	FOR_EACH_SM(*stree, sm) {
		if (sm->pool) {
			tmp = clone_sm(sm);
			add_ptr_list(&slist, tmp);
		}
	} END_FOR_EACH_SM(sm);

	FOR_EACH_PTR(slist, sm) {
		avl_insert(stree, sm);
	} END_FOR_EACH_PTR(sm);

	free_slist(&slist);
}

int __stree_id;

/*
 * merge_slist() is called whenever paths merge, such as after
 * an if statement.  It takes the two slists and creates one.
 */
static void __merge_stree(struct stree **to, struct stree *stree, int add_pool)
{
	struct stree *results = NULL;
	struct stree *implied_one = NULL;
	struct stree *implied_two = NULL;
	AvlIter one_iter;
	AvlIter two_iter;
	struct sm_state *one, *two, *res;

	if (out_of_memory())
		return;

	/* merging a null and nonnull path gives you only the nonnull path */
	if (!stree)
		return;
	if (*to == stree)
		return;

	if (!*to) {
		*to = clone_stree(stree);
		return;
	}

	implied_one = clone_stree(*to);
	implied_two = clone_stree(stree);

	match_states_stree(&implied_one, &implied_two);
	call_pre_merge_hooks(&implied_one, &implied_two);

	if (add_pool) {
		clone_pool_havers_stree(&implied_one);
		clone_pool_havers_stree(&implied_two);

		set_stree_id(&implied_one, ++__stree_id);
		set_stree_id(&implied_two, ++__stree_id);
		if (implied_one->base_stree)
			set_stree_id(&implied_one->base_stree, ++__stree_id);
		if (implied_two->base_stree)
			set_stree_id(&implied_two->base_stree, ++__stree_id);
	}

	push_stree(&all_pools, implied_one);
	push_stree(&all_pools, implied_two);

	avl_iter_begin(&one_iter, implied_one, FORWARD);
	avl_iter_begin(&two_iter, implied_two, FORWARD);

	for (;;) {
		if (!one_iter.sm || !two_iter.sm)
			break;

		one = one_iter.sm;
		two = two_iter.sm;

		if (one == two) {
			avl_insert(&results, one);
			goto next;
		}

		if (add_pool) {
			one->pool = implied_one;
			if (implied_one->base_stree)
				one->pool = implied_one->base_stree;
			two->pool = implied_two;
			if (implied_two->base_stree)
				two->pool = implied_two->base_stree;
		}
		res = merge_sm_states(one, two);
		add_possible_sm(res, one);
		add_possible_sm(res, two);
		avl_insert(&results, res);
next:
		avl_iter_next(&one_iter);
		avl_iter_next(&two_iter);
	}

	free_stree(to);
	*to = results;
}

void merge_stree(struct stree **to, struct stree *stree)
{
	__merge_stree(to, stree, 1);
}

void merge_stree_no_pools(struct stree **to, struct stree *stree)
{
	__merge_stree(to, stree, 0);
}

/*
 * This is unfortunately a bit subtle...  The problem is that if a
 * state is set on one fake stree but not the other then we should
 * look up the the original state and use that as the unset state.
 * Fortunately, after you pop your fake stree then the cur_slist should
 * reflect the original state.
 */
void merge_fake_stree(struct stree **to, struct stree *stree)
{
	struct stree *one = *to;
	struct stree *two = stree;
	struct sm_state *sm;
	struct state_list *add_to_one = NULL;
	struct state_list *add_to_two = NULL;
	AvlIter one_iter;
	AvlIter two_iter;

	if (!stree)
		return;
	if (*to == stree)
		return;
	if (!*to) {
		*to = clone_stree(stree);
		return;
	}

	avl_iter_begin(&one_iter, one, FORWARD);
	avl_iter_begin(&two_iter, two, FORWARD);

	for (;;) {
		if (!one_iter.sm && !two_iter.sm)
			break;
		if (cmp_tracker(one_iter.sm, two_iter.sm) < 0) {
			sm = get_sm_state(one_iter.sm->owner, one_iter.sm->name,
					  one_iter.sm->sym);
			if (sm)
				add_ptr_list(&add_to_two, sm);
			avl_iter_next(&one_iter);
		} else if (cmp_tracker(one_iter.sm, two_iter.sm) == 0) {
			avl_iter_next(&one_iter);
			avl_iter_next(&two_iter);
		} else {
			sm = get_sm_state(two_iter.sm->owner, two_iter.sm->name,
					  two_iter.sm->sym);
			if (sm)
				add_ptr_list(&add_to_one, sm);
			avl_iter_next(&two_iter);
		}
	}

	FOR_EACH_PTR(add_to_one, sm) {
		avl_insert(&one, sm);
	} END_FOR_EACH_PTR(sm);

	FOR_EACH_PTR(add_to_two, sm) {
		avl_insert(&two, sm);
	} END_FOR_EACH_PTR(sm);

	one->base_stree = clone_stree(__get_cur_stree());
	FOR_EACH_SM(one, sm) {
		avl_insert(&one->base_stree, sm);
	} END_FOR_EACH_SM(sm);

	two->base_stree = clone_stree(__get_cur_stree());
	FOR_EACH_SM(two, sm) {
		avl_insert(&two->base_stree, sm);
	} END_FOR_EACH_SM(sm);

	free_slist(&add_to_one);
	free_slist(&add_to_two);

	__merge_stree(&one, two, 1);

	*to = one;
}

/*
 * filter_slist() removes any sm states "slist" holds in common with "filter"
 */
void filter_stree(struct stree **stree, struct stree *filter)
{
	struct stree *results = NULL;
	AvlIter one_iter;
	AvlIter two_iter;

	avl_iter_begin(&one_iter, *stree, FORWARD);
	avl_iter_begin(&two_iter, filter, FORWARD);

	/* FIXME: This should probably be re-written with trees in mind */

	for (;;) {
		if (!one_iter.sm && !two_iter.sm)
			break;
		if (cmp_tracker(one_iter.sm, two_iter.sm) < 0) {
			avl_insert(&results, one_iter.sm);
			avl_iter_next(&one_iter);
		} else if (cmp_tracker(one_iter.sm, two_iter.sm) == 0) {
			if (one_iter.sm != two_iter.sm)
				avl_insert(&results, one_iter.sm);
			avl_iter_next(&one_iter);
			avl_iter_next(&two_iter);
		} else {
			avl_iter_next(&two_iter);
		}
	}

	free_stree(stree);
	*stree = results;
}


/*
 * and_slist_stack() pops the top two slists, overwriting the one with
 * the other and pushing it back on the stack.
 */
void and_stree_stack(struct stree_stack **stack)
{
	struct sm_state *tmp;
	struct stree *right_stree = pop_stree(stack);

	FOR_EACH_SM(right_stree, tmp) {
		overwrite_sm_state_stree_stack(stack, tmp);
	} END_FOR_EACH_SM(tmp);
	free_stree(&right_stree);
}

/*
 * or_slist_stack() is for if we have:  if (foo || bar) { foo->baz;
 * It pops the two slists from the top of the stack and merges them
 * together in a way that preserves the things they have in common
 * but creates a merged state for most of the rest.
 * You could have code that had:  if (foo || foo) { foo->baz;
 * It's this function which ensures smatch does the right thing.
 */
void or_stree_stack(struct stree_stack **pre_conds,
		    struct stree *cur_stree,
		    struct stree_stack **stack)
{
	struct stree *new;
	struct stree *old;
	struct stree *pre_stree;
	struct stree *res;
	struct stree *tmp_stree;

	new = pop_stree(stack);
	old = pop_stree(stack);

	pre_stree = pop_stree(pre_conds);
	push_stree(pre_conds, clone_stree(pre_stree));

	res = clone_stree(pre_stree);
	overwrite_stree(old, &res);

	tmp_stree = clone_stree(cur_stree);
	overwrite_stree(new, &tmp_stree);

	merge_stree(&res, tmp_stree);
	filter_stree(&res, pre_stree);

	push_stree(stack, res);
	free_stree(&tmp_stree);
	free_stree(&pre_stree);
	free_stree(&new);
	free_stree(&old);
}

/*
 * get_named_stree() is only used for gotos.
 */
struct stree **get_named_stree(struct named_stree_stack *stack,
			       const char *name,
			       struct symbol *sym)
{
	struct named_stree *tmp;

	FOR_EACH_PTR(stack, tmp) {
		if (tmp->sym == sym &&
		    strcmp(tmp->name, name) == 0)
			return &tmp->stree;
	} END_FOR_EACH_PTR(tmp);
	return NULL;
}

/* FIXME:  These parameters are in a different order from expected */
void overwrite_stree(struct stree *from, struct stree **to)
{
	struct sm_state *tmp;

	FOR_EACH_SM(from, tmp) {
		overwrite_sm_state_stree(to, tmp);
	} END_FOR_EACH_SM(tmp);
}


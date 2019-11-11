/*
 * Copyright (C) 2008 Dan Carpenter.
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
 *
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Imagine we have this code:
 * foo = 1;
 * if (bar)
 *         foo = 99;
 * else
 *         frob();
 *                   //  <-- point #1
 * if (foo == 99)    //  <-- point #2
 *         bar->baz; //  <-- point #3
 *
 *
 * At point #3 bar is non null and can be dereferenced.
 *
 * It's smatch_implied.c which sets bar to non null at point #2.
 *
 * At point #1 merge_slist() stores the list of states from both
 * the true and false paths.  On the true path foo == 99 and on
 * the false path foo == 1.  merge_slist() sets their pool
 * list to show the other states which were there when foo == 99.
 *
 * When it comes to the if (foo == 99) the smatch implied hook
 * looks for all the pools where foo was not 99.  It makes a list
 * of those.
 *
 * Then for bar (and all the other states) it says, ok bar is a
 * merged state that came from these previous states.  We'll
 * chop out all the states where it came from a pool where
 * foo != 99 and merge it all back together.
 *
 * That is the implied state of bar.
 *
 * merge_slist() sets up ->pool.  An sm_state only has one ->pool and
 *    that is the pool where it was first set.  The my pool gets set when
 *    code paths merge.  States that have been set since the last merge do
 *    not have a ->pool.
 * merge_sm_state() sets ->left and ->right.  (These are the states which were
 *    merged to form the current state.)
 * a pool:  a pool is an slist that has been merged with another slist.
 */

#include <time.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

char *implied_debug_msg;

bool implications_off;

#define implied_debug 0
#define DIMPLIED(msg...) do { if (implied_debug) printf(msg); } while (0)

bool debug_implied(void)
{
	return implied_debug;
}

/*
 * tmp_range_list():
 * It messes things up to free range list allocations.  This helper fuction
 * lets us reuse memory instead of doing new allocations.
 */
static struct range_list *tmp_range_list(struct symbol *type, long long num)
{
	static struct range_list *my_list = NULL;
	static struct data_range *my_range;

	__free_ptr_list((struct ptr_list **)&my_list);
	my_range = alloc_range(ll_to_sval(num), ll_to_sval(num));
	add_ptr_list(&my_list, my_range);
	return my_list;
}

static void print_debug_tf(struct sm_state *sm, int istrue, int isfalse)
{
	if (!implied_debug && !option_debug)
		return;

	if (istrue && isfalse) {
		printf("%s: %d: does not exist.\n", show_sm(sm), sm->line);
	} else if (istrue) {
		printf("'%s = %s' from %d is true. %s[stree %d]\n", sm->name, show_state(sm->state),
			sm->line, sm->merged ? "[merged]" : "[leaf]",
			get_stree_id(sm->pool));
	} else if (isfalse) {
		printf("'%s = %s' from %d is false. %s[stree %d]\n", sm->name, show_state(sm->state),
			sm->line,
			sm->merged ? "[merged]" : "[leaf]",
			get_stree_id(sm->pool));
	} else {
		printf("'%s = %s' from %d could be true or false. %s[stree %d]\n", sm->name,
			show_state(sm->state), sm->line,
			sm->merged ? "[merged]" : "[leaf]",
			get_stree_id(sm->pool));
	}
}

static int create_fake_history(struct sm_state *sm, int comparison, struct range_list *rl)
{
	struct range_list *orig_rl;
	struct range_list *true_rl, *false_rl;
	struct stree *true_stree, *false_stree;
	struct sm_state *true_sm, *false_sm;
	sval_t sval;

	if (is_merged(sm) || sm->left || sm->right)
		return 0;
	if (!rl_to_sval(rl, &sval))
		return 0;
	if (!estate_rl(sm->state))
		return 0;

	orig_rl = cast_rl(rl_type(rl), estate_rl(sm->state));
	split_comparison_rl(orig_rl, comparison, rl, &true_rl, &false_rl, NULL, NULL);

	true_rl = rl_truncate_cast(estate_type(sm->state), true_rl);
	false_rl = rl_truncate_cast(estate_type(sm->state), false_rl);
	if (is_whole_rl(true_rl) || is_whole_rl(false_rl) ||
	    !true_rl || !false_rl ||
	    rl_equiv(orig_rl, true_rl) || rl_equiv(orig_rl, false_rl) ||
	    rl_equiv(estate_rl(sm->state), true_rl) || rl_equiv(estate_rl(sm->state), false_rl))
		return 0;

	if (rl_intersection(true_rl, false_rl)) {
		sm_perror("parsing (%s (%s) %s %s)",
			sm->name, sm->state->name, show_special(comparison), show_rl(rl));
		sm_msg("true_rl = %s false_rl = %s intersection = %s",
		       show_rl(true_rl), show_rl(false_rl), show_rl(rl_intersection(true_rl, false_rl)));
		return 0;
	}

	if (implied_debug)
		sm_msg("fake_history: %s vs %s.  %s %s %s. --> T: %s F: %s",
		       sm->name, show_rl(rl), sm->state->name, show_special(comparison), show_rl(rl),
		       show_rl(true_rl), show_rl(false_rl));

	true_sm = clone_sm(sm);
	false_sm = clone_sm(sm);

	true_sm->state = clone_partial_estate(sm->state, true_rl);
	free_slist(&true_sm->possible);
	add_possible_sm(true_sm, true_sm);
	false_sm->state = clone_partial_estate(sm->state, false_rl);
	free_slist(&false_sm->possible);
	add_possible_sm(false_sm, false_sm);

	true_stree = clone_stree(sm->pool);
	false_stree = clone_stree(sm->pool);

	overwrite_sm_state_stree(&true_stree, true_sm);
	overwrite_sm_state_stree(&false_stree, false_sm);

	true_sm->pool = true_stree;
	false_sm->pool = false_stree;

	sm->merged = 1;
	sm->left = true_sm;
	sm->right = false_sm;

	return 1;
}

/*
 * add_pool() adds a slist to *pools. If the slist has already been
 * added earlier then it doesn't get added a second time.
 */
void add_pool(struct state_list **pools, struct sm_state *new)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(*pools, tmp) {
		if (tmp->pool < new->pool)
			continue;
		else if (tmp->pool == new->pool) {
			return;
		} else {
			INSERT_CURRENT(new, tmp);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
	add_ptr_list(pools, new);
}

static int pool_in_pools(struct stree *pool,
			 const struct state_list *slist)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(slist, tmp) {
		if (!tmp->pool)
			continue;
		if (tmp->pool == pool)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int remove_pool(struct state_list **pools, struct stree *remove)
{
	struct sm_state *tmp;
	int ret = 0;

	FOR_EACH_PTR(*pools, tmp) {
		if (tmp->pool == remove) {
			DELETE_CURRENT_PTR(tmp);
			ret = 1;
		}
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

/*
 * If 'foo' == 99 add it that pool to the true pools.  If it's false, add it to
 * the false pools.  If we're not sure, then we don't add it to either.
 */
static void do_compare(struct sm_state *sm, int comparison, struct range_list *rl,
			struct state_list **true_stack,
			struct state_list **maybe_stack,
			struct state_list **false_stack,
			int *mixed, struct sm_state *gate_sm)
{
	int istrue;
	int isfalse;
	struct range_list *var_rl;

	if (!sm->pool)
		return;

	var_rl = cast_rl(rl_type(rl), estate_rl(sm->state));

	istrue = !possibly_false_rl(var_rl, comparison, rl);
	isfalse = !possibly_true_rl(var_rl, comparison, rl);

	print_debug_tf(sm, istrue, isfalse);

	/* give up if we have borrowed implications (smatch_equiv.c) */
	if (sm->sym != gate_sm->sym ||
	    strcmp(sm->name, gate_sm->name) != 0) {
		if (mixed)
			*mixed = 1;
	}

	if (mixed && !*mixed && !is_merged(sm) && !istrue && !isfalse) {
		if (!create_fake_history(sm, comparison, rl))
			*mixed = 1;
	}

	if (istrue)
		add_pool(true_stack, sm);
	else if (isfalse)
		add_pool(false_stack, sm);
	else
		add_pool(maybe_stack, sm);
}

static int is_checked(struct state_list *checked, struct sm_state *sm)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(checked, tmp) {
		if (tmp == sm)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

/*
 * separate_pools():
 * Example code:  if (foo == 99) {
 *
 * Say 'foo' is a merged state that has many possible values.  It is the combination
 * of merges.  separate_pools() iterates through the pools recursively and calls
 * do_compare() for each time 'foo' was set.
 */
static void __separate_pools(struct sm_state *sm, int comparison, struct range_list *rl,
			struct state_list **true_stack,
			struct state_list **maybe_stack,
			struct state_list **false_stack,
			struct state_list **checked, int *mixed, struct sm_state *gate_sm,
			struct timeval *start_time)
{
	int free_checked = 0;
	struct state_list *checked_states = NULL;
	struct timeval now, diff;

	if (!sm)
		return;

	gettimeofday(&now, NULL);
	timersub(&now, start_time, &diff);
	if (diff.tv_sec >= 1) {
		if (implied_debug) {
			sm_msg("debug: %s: implications taking too long.  (%s %s %s)",
			       __func__, sm->state->name, show_special(comparison), show_rl(rl));
		}
		if (mixed)
			*mixed = 1;
	}

	if (checked == NULL) {
		checked = &checked_states;
		free_checked = 1;
	}
	if (is_checked(*checked, sm))
		return;
	add_ptr_list(checked, sm);

	do_compare(sm, comparison, rl, true_stack, maybe_stack, false_stack, mixed, gate_sm);

	__separate_pools(sm->left, comparison, rl, true_stack, maybe_stack, false_stack, checked, mixed, gate_sm, start_time);
	__separate_pools(sm->right, comparison, rl, true_stack, maybe_stack, false_stack, checked, mixed, gate_sm, start_time);
	if (free_checked)
		free_slist(checked);
}

static void separate_pools(struct sm_state *sm, int comparison, struct range_list *rl,
			struct state_list **true_stack,
			struct state_list **false_stack,
			struct state_list **checked, int *mixed)
{
	struct state_list *maybe_stack = NULL;
	struct sm_state *tmp;
	struct timeval start_time;


	gettimeofday(&start_time, NULL);
	__separate_pools(sm, comparison, rl, true_stack, &maybe_stack, false_stack, checked, mixed, sm, &start_time);

	if (implied_debug) {
		struct sm_state *sm;

		FOR_EACH_PTR(*true_stack, sm) {
			sm_msg("TRUE %s [stree %d]", show_sm(sm), get_stree_id(sm->pool));
		} END_FOR_EACH_PTR(sm);

		FOR_EACH_PTR(maybe_stack, sm) {
			sm_msg("MAYBE %s %s[stree %d]",
			       show_sm(sm), sm->merged ? "(merged) ": "", get_stree_id(sm->pool));
		} END_FOR_EACH_PTR(sm);

		FOR_EACH_PTR(*false_stack, sm) {
			sm_msg("FALSE %s [stree %d]", show_sm(sm), get_stree_id(sm->pool));
		} END_FOR_EACH_PTR(sm);
	}
	/* if it's a maybe then remove it */
	FOR_EACH_PTR(maybe_stack, tmp) {
		remove_pool(false_stack, tmp->pool);
		remove_pool(true_stack, tmp->pool);
	} END_FOR_EACH_PTR(tmp);

	/* if it's both true and false remove it from both */
	FOR_EACH_PTR(*true_stack, tmp) {
		if (remove_pool(false_stack, tmp->pool))
			DELETE_CURRENT_PTR(tmp);
	} END_FOR_EACH_PTR(tmp);
}

static int sm_in_keep_leafs(struct sm_state *sm, const struct state_list *keep_gates)
{
	struct sm_state *tmp, *old;

	FOR_EACH_PTR(keep_gates, tmp) {
		if (is_merged(tmp))
			continue;
		old = get_sm_state_stree(tmp->pool, sm->owner, sm->name, sm->sym);
		if (!old)
			continue;
		if (old == sm)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int going_too_slow(void)
{
	static void *printed;

	if (out_of_memory()) {
		implications_off = true;
		return 1;
	}

	if (!option_timeout || time_parsing_function() < option_timeout) {
		implications_off = false;
		return 0;
	}

	if (!__inline_fn && printed != cur_func_sym) {
		if (!is_skipped_function())
			sm_perror("turning off implications after %d seconds", option_timeout);
		printed = cur_func_sym;
	}
	implications_off = true;
	return 1;
}

static char *sm_state_info(struct sm_state *sm)
{
	static char buf[512];
	int n = 0;

	n += snprintf(buf + n, sizeof(buf) - n, "[stree %d line %d] ",
		      get_stree_id(sm->pool),  sm->line);
	if (n >= sizeof(buf))
		return buf;
	n += snprintf(buf + n, sizeof(buf) - n, "%s ", show_sm(sm));
	if (n >= sizeof(buf))
		return buf;
	n += snprintf(buf + n, sizeof(buf) - n, "left = %s [stree %d] ",
		      sm->left ? sm->left->state->name : "<none>",
		      sm->left ? get_stree_id(sm->left->pool) : -1);
	if (n >= sizeof(buf))
		return buf;
	n += snprintf(buf + n, sizeof(buf) - n, "right = %s [stree %d]",
		      sm->right ? sm->right->state->name : "<none>",
		      sm->right ? get_stree_id(sm->right->pool) : -1);
	return buf;
}

/*
 * NOTE: If a state is in both the keep stack and the remove stack then that is
 * a bug.  Only add states which are definitely true or definitely false.  If
 * you have a leaf state that could be both true and false, then create a fake
 * split history where one side is true and one side is false.  Otherwise, if
 * you can't do that, then don't add it to either list.
 */
#define RECURSE_LIMIT 300
struct sm_state *filter_pools(struct sm_state *sm,
			      const struct state_list *remove_stack,
			      const struct state_list *keep_stack,
			      int *modified, int *recurse_cnt,
			      struct timeval *start, int *skip, int *bail)
{
	struct sm_state *ret = NULL;
	struct sm_state *left;
	struct sm_state *right;
	int removed = 0;
	struct timeval now, diff;

	if (!sm)
		return NULL;
	if (*bail)
		return NULL;
	gettimeofday(&now, NULL);
	timersub(&now, start, &diff);
	if (diff.tv_sec >= 3) {
		DIMPLIED("%s: implications taking too long: %s\n", __func__, sm_state_info(sm));
		*bail = 1;
		return NULL;
	}
	if ((*recurse_cnt)++ > RECURSE_LIMIT) {
		DIMPLIED("%s: recursed too far:  %s\n", __func__, sm_state_info(sm));
		*skip = 1;
		return NULL;
	}

	if (pool_in_pools(sm->pool, remove_stack)) {
		DIMPLIED("%s: remove: %s\n", __func__, sm_state_info(sm));
		*modified = 1;
		return NULL;
	}

	if (!is_merged(sm) || pool_in_pools(sm->pool, keep_stack) || sm_in_keep_leafs(sm, keep_stack)) {
		DIMPLIED("%s: keep %s (%s, %s, %s): %s\n", __func__, sm->state->name,
			is_merged(sm) ? "merged" : "not merged",
			pool_in_pools(sm->pool, keep_stack) ? "not in keep pools" : "in keep pools",
			sm_in_keep_leafs(sm, keep_stack) ? "reachable keep leaf" : "no keep leaf",
			sm_state_info(sm));
		return sm;
	}

	left = filter_pools(sm->left, remove_stack, keep_stack, &removed, recurse_cnt, start, skip, bail);
	right = filter_pools(sm->right, remove_stack, keep_stack, &removed, recurse_cnt, start, skip, bail);
	if (*bail || *skip)
		return NULL;
	if (!removed) {
		DIMPLIED("%s: kept all: %s\n", __func__, sm_state_info(sm));
		return sm;
	}
	*modified = 1;
	if (!left && !right) {
		DIMPLIED("%s: removed all: %s\n", __func__, sm_state_info(sm));
		return NULL;
	}

	if (!left) {
		ret = clone_sm(right);
		ret->merged = 1;
		ret->right = right;
		ret->left = NULL;
	} else if (!right) {
		ret = clone_sm(left);
		ret->merged = 1;
		ret->left = left;
		ret->right = NULL;
	} else {
		if (left->sym != sm->sym || strcmp(left->name, sm->name) != 0) {
			left = clone_sm(left);
			left->sym = sm->sym;
			left->name = sm->name;
		}
		if (right->sym != sm->sym || strcmp(right->name, sm->name) != 0) {
			right = clone_sm(right);
			right->sym = sm->sym;
			right->name = sm->name;
		}
		ret = merge_sm_states(left, right);
	}

	ret->pool = sm->pool;

	DIMPLIED("%s: partial: %s\n", __func__, sm_state_info(sm));
	return ret;
}

static struct stree *filter_stack(struct sm_state *gate_sm,
				       struct stree *pre_stree,
				       const struct state_list *remove_stack,
				       const struct state_list *keep_stack)
{
	struct stree *ret = NULL;
	struct sm_state *tmp;
	struct sm_state *filtered_sm;
	int modified;
	int recurse_cnt;
	struct timeval start;
	int skip;
	int bail = 0;

	if (!remove_stack)
		return NULL;

	gettimeofday(&start, NULL);
	FOR_EACH_SM(pre_stree, tmp) {
		if (!tmp->merged || sm_in_keep_leafs(tmp, keep_stack))
			continue;
		modified = 0;
		recurse_cnt = 0;
		skip = 0;
		filtered_sm = filter_pools(tmp, remove_stack, keep_stack, &modified, &recurse_cnt, &start, &skip, &bail);
		if (going_too_slow())
			return NULL;
		if (bail)
			return ret;  /* Return the implications we figured out before time ran out. */


		if (skip || !filtered_sm || !modified)
			continue;
		/* the assignments here are for borrowed implications */
		filtered_sm->name = tmp->name;
		filtered_sm->sym = tmp->sym;
		avl_insert(&ret, filtered_sm);
	} END_FOR_EACH_SM(tmp);
	return ret;
}

static void separate_and_filter(struct sm_state *sm, int comparison, struct range_list *rl,
		struct stree *pre_stree,
		struct stree **true_states,
		struct stree **false_states,
		int *mixed)
{
	struct state_list *true_stack = NULL;
	struct state_list *false_stack = NULL;
	struct timeval time_before;
	struct timeval time_after;
	int sec;

	gettimeofday(&time_before, NULL);

	DIMPLIED("checking implications: (%s (%s) %s %s)\n",
		 sm->name, sm->state->name, show_special(comparison), show_rl(rl));

	if (!is_merged(sm)) {
		DIMPLIED("%d '%s' from line %d is not merged.\n", get_lineno(), sm->name, sm->line);
		return;
	}

	separate_pools(sm, comparison, rl, &true_stack, &false_stack, NULL, mixed);

	DIMPLIED("filtering true stack.\n");
	*true_states = filter_stack(sm, pre_stree, false_stack, true_stack);
	DIMPLIED("filtering false stack.\n");
	*false_states = filter_stack(sm, pre_stree, true_stack, false_stack);
	free_slist(&true_stack);
	free_slist(&false_stack);

	gettimeofday(&time_after, NULL);
	sec = time_after.tv_sec - time_before.tv_sec;
	if (option_timeout && sec > option_timeout) {
		sm_perror("Function too hairy.  Ignoring implications after %d seconds.", sec);
	}
}

static struct expression *get_last_expr(struct statement *stmt)
{
	struct statement *last;

	last = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (last->type == STMT_EXPRESSION)
		return last->expression;

	if (last->type == STMT_LABEL) {
		if (last->label_statement &&
		    last->label_statement->type == STMT_EXPRESSION)
			return last->label_statement->expression;
	}

	return NULL;
}

static struct expression *get_left_most_expr(struct expression *expr)
{
	struct statement *compound;

	compound = get_expression_statement(expr);
	if (compound)
		return get_last_expr(compound);

	expr = strip_parens(expr);
	if (expr->type == EXPR_ASSIGNMENT)
		return get_left_most_expr(expr->left);
	return expr;
}

static int is_merged_expr(struct expression  *expr)
{
	struct sm_state *sm;
	sval_t dummy;

	if (get_value(expr, &dummy))
		return 0;
	sm = get_sm_state_expr(SMATCH_EXTRA, expr);
	if (!sm)
		return 0;
	if (is_merged(sm))
		return 1;
	return 0;
}

static void delete_gate_sm_equiv(struct stree **stree, const char *name, struct symbol *sym)
{
	struct smatch_state *state;
	struct relation *rel;

	state = get_state(SMATCH_EXTRA, name, sym);
	if (!state)
		return;
	FOR_EACH_PTR(estate_related(state), rel) {
		delete_state_stree(stree, SMATCH_EXTRA, rel->name, rel->sym);
	} END_FOR_EACH_PTR(rel);
}

static void delete_gate_sm(struct stree **stree, const char *name, struct symbol *sym)
{
	delete_state_stree(stree, SMATCH_EXTRA, name, sym);
}

static int handle_comparison(struct expression *expr,
			      struct stree **implied_true,
			      struct stree **implied_false)
{
	struct sm_state *sm = NULL;
	struct range_list *rl = NULL;
	struct expression *left;
	struct expression *right;
	struct symbol *type;
	int comparison = expr->op;
	int mixed = 0;

	left = get_left_most_expr(expr->left);
	right = get_left_most_expr(expr->right);

	if (is_merged_expr(left)) {
		sm = get_sm_state_expr(SMATCH_EXTRA, left);
		get_implied_rl(right, &rl);
	} else if (is_merged_expr(right)) {
		sm = get_sm_state_expr(SMATCH_EXTRA, right);
		get_implied_rl(left, &rl);
		comparison = flip_comparison(comparison);
	}

	if (!rl || !sm)
		return 0;

	type = get_type(expr);
	if (!type)
		return 0;
	if (type_positive_bits(rl_type(rl)) > type_positive_bits(type))
		type = rl_type(rl);
	if (type_positive_bits(type) < 31)
		type = &int_ctype;
	rl = cast_rl(type, rl);

	separate_and_filter(sm, comparison, rl, __get_cur_stree(), implied_true, implied_false, &mixed);

	delete_gate_sm_equiv(implied_true, sm->name, sm->sym);
	delete_gate_sm_equiv(implied_false, sm->name, sm->sym);
	if (mixed) {
		delete_gate_sm(implied_true, sm->name, sm->sym);
		delete_gate_sm(implied_false, sm->name, sm->sym);
	}

	return 1;
}

static int handle_zero_comparison(struct expression *expr,
				struct stree **implied_true,
				struct stree **implied_false)
{
	struct symbol *sym;
	char *name;
	struct sm_state *sm;
	int mixed = 0;
	int ret = 0;

	if (expr->type == EXPR_POSTOP)
		expr = strip_expr(expr->unop);

	if (expr->type == EXPR_ASSIGNMENT) {
		/* most of the time ->pools will be empty here because we
		   just set the state, but if have assigned a conditional
		   function there are implications. */
		expr = expr->left;
	}

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	sm = get_sm_state(SMATCH_EXTRA, name, sym);
	if (!sm)
		goto free;

	separate_and_filter(sm, SPECIAL_NOTEQUAL, tmp_range_list(estate_type(sm->state), 0), __get_cur_stree(), implied_true, implied_false, &mixed);
	delete_gate_sm_equiv(implied_true, sm->name, sm->sym);
	delete_gate_sm_equiv(implied_false, sm->name, sm->sym);
	if (mixed) {
		delete_gate_sm(implied_true, sm->name, sm->sym);
		delete_gate_sm(implied_false, sm->name, sm->sym);
	}

	ret = 1;
free:
	free_string(name);
	return ret;
}

static int handled_by_comparison_hook(struct expression *expr,
				   struct stree **implied_true,
				   struct stree **implied_false)
{
	struct state_list *true_stack = NULL;
	struct state_list *false_stack = NULL;
	struct stree *pre_stree;
	struct sm_state *sm;

	sm = comparison_implication_hook(expr, &true_stack, &false_stack);
	if (!sm)
		return 0;

	pre_stree = clone_stree(__get_cur_stree());

	*implied_true = filter_stack(sm, pre_stree, false_stack, true_stack);
	*implied_false = filter_stack(sm, pre_stree, true_stack, false_stack);

	free_stree(&pre_stree);
	free_slist(&true_stack);
	free_slist(&false_stack);

	return 1;
}

static int handled_by_extra_states(struct expression *expr,
				   struct stree **implied_true,
				   struct stree **implied_false)
{
	sval_t sval;

	/* If the expression is known then it has no implications.  */
	if (get_implied_value(expr, &sval))
		return true;

	if (expr->type == EXPR_COMPARE)
		return handle_comparison(expr, implied_true, implied_false);
	else
		return handle_zero_comparison(expr, implied_true, implied_false);
}

static int handled_by_stored_conditions(struct expression *expr,
					struct stree **implied_true,
					struct stree **implied_false)
{
	struct state_list *true_stack = NULL;
	struct state_list *false_stack = NULL;
	struct stree *pre_stree;
	struct sm_state *sm;

	sm = stored_condition_implication_hook(expr, &true_stack, &false_stack);
	if (!sm)
		return 0;

	pre_stree = clone_stree(__get_cur_stree());

	*implied_true = filter_stack(sm, pre_stree, false_stack, true_stack);
	*implied_false = filter_stack(sm, pre_stree, true_stack, false_stack);

	free_stree(&pre_stree);
	free_slist(&true_stack);
	free_slist(&false_stack);

	return 1;
}

static struct stree *saved_implied_true;
static struct stree *saved_implied_false;
static struct stree *extra_saved_implied_true;
static struct stree *extra_saved_implied_false;

static void separate_extra_states(struct stree **implied_true,
				  struct stree **implied_false)
{
	struct sm_state *sm;

	/* We process extra states later to preserve the implications. */
	FOR_EACH_SM(*implied_true, sm) {
		if (sm->owner == SMATCH_EXTRA)
			overwrite_sm_state_stree(&extra_saved_implied_true, sm);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(extra_saved_implied_true, sm) {
		delete_state_stree(implied_true, sm->owner, sm->name, sm->sym);
	} END_FOR_EACH_SM(sm);

	FOR_EACH_SM(*implied_false, sm) {
		if (sm->owner == SMATCH_EXTRA)
			overwrite_sm_state_stree(&extra_saved_implied_false, sm);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(extra_saved_implied_false, sm) {
		delete_state_stree(implied_false, sm->owner, sm->name, sm->sym);
	} END_FOR_EACH_SM(sm);
}

static void get_tf_states(struct expression *expr,
			  struct stree **implied_true,
			  struct stree **implied_false)
{
	if (handled_by_comparison_hook(expr, implied_true, implied_false))
		return;

	if (handled_by_extra_states(expr, implied_true, implied_false)) {
		separate_extra_states(implied_true, implied_false);
		return;
	}

	if (handled_by_stored_conditions(expr, implied_true, implied_false))
		return;
}

static void save_implications_hook(struct expression *expr)
{
	if (going_too_slow())
		return;
	get_tf_states(expr, &saved_implied_true, &saved_implied_false);
}

static void set_implied_states(struct expression *expr)
{
	struct sm_state *sm;

	if (implied_debug &&
	    (expr || saved_implied_true || saved_implied_false)) {
		char *name;

		name = expr_to_str(expr);
		printf("These are the implied states for the true path: (%s)\n", name);
		__print_stree(saved_implied_true);
		printf("These are the implied states for the false path: (%s)\n", name);
		__print_stree(saved_implied_false);
		free_string(name);
	}

	FOR_EACH_SM(saved_implied_true, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	free_stree(&saved_implied_true);

	FOR_EACH_SM(saved_implied_false, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&saved_implied_false);
}

static void set_extra_implied_states(struct expression *expr)
{
	saved_implied_true = extra_saved_implied_true;
	saved_implied_false = extra_saved_implied_false;
	extra_saved_implied_true = NULL;
	extra_saved_implied_false = NULL;
	set_implied_states(NULL);
}

void param_limit_implications(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	struct symbol *compare_type;
	char *name;
	struct symbol *sym;
	struct sm_state *sm;
	struct sm_state *tmp;
	struct stree *implied_true = NULL;
	struct stree *implied_false = NULL;
	struct range_list *orig, *limit;

	if (time_parsing_function() > 40)
		return;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	arg = strip_parens(arg);
	while (arg->type == EXPR_ASSIGNMENT && arg->op == '=')
		arg = strip_parens(arg->left);

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	sm = get_sm_state(SMATCH_EXTRA, name, sym);
	if (!sm || !sm->merged)
		goto free;

	if (strcmp(key, "$") == 0)
		compare_type = get_arg_type(expr->fn, param);
	else
		compare_type = get_member_type_from_key(arg, key);

	orig = estate_rl(sm->state);
	orig = cast_rl(compare_type, orig);

	call_results_to_rl(expr, compare_type, value, &limit);

	separate_and_filter(sm, SPECIAL_EQUAL, limit, __get_cur_stree(), &implied_true, &implied_false, NULL);

	FOR_EACH_SM(implied_true, tmp) {
		__set_sm_fake_stree(tmp);
	} END_FOR_EACH_SM(tmp);

	free_stree(&implied_true);
	free_stree(&implied_false);
free:
	free_string(name);
}

struct stree *__implied_case_stree(struct expression *switch_expr,
				   struct range_list *rl,
				   struct range_list_stack **remaining_cases,
				   struct stree **raw_stree)
{
	char *name;
	struct symbol *sym;
	struct var_sym_list *vsl;
	struct sm_state *sm;
	struct stree *true_states = NULL;
	struct stree *false_states = NULL;
	struct stree *extra_states;
	struct stree *ret = clone_stree(*raw_stree);

	name = expr_to_chunk_sym_vsl(switch_expr, &sym, &vsl);

	if (rl)
		filter_top_rl(remaining_cases, rl);
	else
		rl = clone_rl(top_rl(*remaining_cases));

	if (name) {
		sm = get_sm_state_stree(*raw_stree, SMATCH_EXTRA, name, sym);
		if (sm)
			separate_and_filter(sm, SPECIAL_EQUAL, rl, *raw_stree, &true_states, &false_states, NULL);
	}

	__push_fake_cur_stree();
	__unnullify_path();
	if (name)
		set_extra_nomod_vsl(name, sym, vsl, NULL, alloc_estate_rl(rl));
	__pass_case_to_client(switch_expr, rl);
	extra_states = __pop_fake_cur_stree();
	overwrite_stree(extra_states, &true_states);
	overwrite_stree(true_states, &ret);
	free_stree(&extra_states);
	free_stree(&true_states);
	free_stree(&false_states);

	free_string(name);
	return ret;
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	implied_debug_msg = NULL;
}

static void get_tf_stacks_from_pool(struct sm_state *gate_sm,
				    struct sm_state *pool_sm,
				    struct state_list **true_stack,
				    struct state_list **false_stack)
{
	struct sm_state *tmp;
	int possibly_true = 0;

	if (!gate_sm)
		return;

	if (strcmp(gate_sm->state->name, pool_sm->state->name) == 0) {
		add_ptr_list(true_stack, pool_sm);
		return;
	}

	FOR_EACH_PTR(gate_sm->possible, tmp) {
		if (strcmp(tmp->state->name, pool_sm->state->name) == 0) {
			possibly_true = 1;
			break;
		}
	} END_FOR_EACH_PTR(tmp);

	if (!possibly_true) {
		add_ptr_list(false_stack, gate_sm);
		return;
	}

	get_tf_stacks_from_pool(gate_sm->left, pool_sm, true_stack, false_stack);
	get_tf_stacks_from_pool(gate_sm->right, pool_sm, true_stack, false_stack);
}

/*
 * The situation is we have a SMATCH_EXTRA state and we want to break it into
 * each of the ->possible states and find the implications of each.  The caller
 * has to use __push_fake_cur_stree() to preserve the correct states so they
 * can be restored later.
 */
void overwrite_states_using_pool(struct sm_state *gate_sm, struct sm_state *pool_sm)
{
	struct state_list *true_stack = NULL;
	struct state_list *false_stack = NULL;
	struct stree *pre_stree;
	struct stree *implied_true;
	struct sm_state *tmp;

	if (!pool_sm->pool)
		return;

	get_tf_stacks_from_pool(gate_sm, pool_sm, &true_stack, &false_stack);

	pre_stree = clone_stree(__get_cur_stree());

	implied_true = filter_stack(gate_sm, pre_stree, false_stack, true_stack);

	free_stree(&pre_stree);
	free_slist(&true_stack);
	free_slist(&false_stack);

	FOR_EACH_SM(implied_true, tmp) {
		set_state(tmp->owner, tmp->name, tmp->sym, tmp->state);
	} END_FOR_EACH_SM(tmp);

	free_stree(&implied_true);
}

int assume(struct expression *expr)
{
	int orig_final_pass = final_pass;

	in_fake_env++;
	final_pass = 0;
	__push_fake_cur_stree();
	__split_whole_condition(expr);
	final_pass = orig_final_pass;
	in_fake_env--;

	return 1;
}

void end_assume(void)
{
	__discard_false_states();
	__free_fake_cur_stree();
}

int impossible_assumption(struct expression *left, int op, sval_t sval)
{
	struct expression *value;
	struct expression *comparison;
	int ret;

	value = value_expr(sval.value);
	comparison = compare_expression(left, op, value);

	if (!assume(comparison))
		return 0;
	ret = is_impossible_path();
	end_assume();

	return ret;
}

void __extra_match_condition(struct expression *expr);
void __comparison_match_condition(struct expression *expr);
void __stored_condition(struct expression *expr);
void register_implications(int id)
{
	add_hook(&save_implications_hook, CONDITION_HOOK);
	add_hook(&set_implied_states, CONDITION_HOOK);
	add_hook(&__extra_match_condition, CONDITION_HOOK);
	add_hook(&set_extra_implied_states, CONDITION_HOOK);
	add_hook(&__comparison_match_condition, CONDITION_HOOK);
	add_hook(&__stored_condition, CONDITION_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

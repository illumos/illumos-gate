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
 * smatch_equiv.c is for tracking how variables are the same
 *
 * if (a == b) {
 * Or
 * x = y;
 *
 * When a variable gets modified all the old relationships are
 * deleted.  remove_equiv(expr);
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

ALLOCATOR(relation, "related variables");

static struct relation *alloc_relation(const char *name, struct symbol *sym)
{
	struct relation *tmp;

	tmp = __alloc_relation(0);
	tmp->name = alloc_string(name);
	tmp->sym = sym;
	return tmp;
}

struct related_list *clone_related_list(struct related_list *related)
{
	struct relation *rel;
	struct related_list *to_list = NULL;

	FOR_EACH_PTR(related, rel) {
		add_ptr_list(&to_list, rel);
	} END_FOR_EACH_PTR(rel);

	return to_list;
}

static int cmp_relation(struct relation *a, struct relation *b)
{
	int ret;

	if (a == b)
		return 0;

	if (a->sym > b->sym)
		return -1;
	if (a->sym < b->sym)
		return 1;

	ret = strcmp(a->name, b->name);
	if (ret)
		return ret;

	return 0;
}

struct related_list *get_shared_relations(struct related_list *one,
					      struct related_list *two)
{
	struct related_list *ret = NULL;
	struct relation *one_rel;
	struct relation *two_rel;

	PREPARE_PTR_LIST(one, one_rel);
	PREPARE_PTR_LIST(two, two_rel);
	for (;;) {
		if (!one_rel || !two_rel)
			break;
		if (cmp_relation(one_rel, two_rel) < 0) {
			NEXT_PTR_LIST(one_rel);
		} else if (cmp_relation(one_rel, two_rel) == 0) {
			add_ptr_list(&ret, one_rel);
			NEXT_PTR_LIST(one_rel);
			NEXT_PTR_LIST(two_rel);
		} else {
			NEXT_PTR_LIST(two_rel);
		}
	}
	FINISH_PTR_LIST(two_rel);
	FINISH_PTR_LIST(one_rel);

	return ret;
}

static void add_related(struct related_list **rlist, const char *name, struct symbol *sym)
{
	struct relation *rel;
	struct relation *new;
	struct relation tmp = {
		.name = (char *)name,
		.sym = sym
	};

	FOR_EACH_PTR(*rlist, rel) {
		if (cmp_relation(rel, &tmp) < 0)
			continue;
		if (cmp_relation(rel, &tmp) == 0)
			return;
		new = alloc_relation(name, sym);
		INSERT_CURRENT(new, rel);
		return;
	} END_FOR_EACH_PTR(rel);
	new = alloc_relation(name, sym);
	add_ptr_list(rlist, new);
}

static struct related_list *del_related(struct smatch_state *state, const char *name, struct symbol *sym)
{
	struct relation *tmp;
	struct relation remove = {
		.name = (char *)name,
		.sym = sym,
	};
	struct related_list *ret = NULL;

	FOR_EACH_PTR(estate_related(state), tmp) {
		if (cmp_relation(tmp, &remove) != 0)
			add_ptr_list(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

void remove_from_equiv(const char *name, struct symbol *sym)
{
	struct sm_state *orig_sm;
	struct relation *rel;
	struct smatch_state *state;
	struct related_list *to_update;

	orig_sm = get_sm_state(SMATCH_EXTRA, name, sym);
	if (!orig_sm || !get_dinfo(orig_sm->state)->related)
		return;

	state = clone_estate(orig_sm->state);
	to_update = del_related(state, name, sym);

	FOR_EACH_PTR(to_update, rel) {
		struct sm_state *old_sm, *new_sm;

		old_sm = get_sm_state(SMATCH_EXTRA, rel->name, rel->sym);
		if (!old_sm)
			continue;

		new_sm = clone_sm(old_sm);
		get_dinfo(new_sm->state)->related = to_update;
		__set_sm(new_sm);
	} END_FOR_EACH_PTR(rel);
}

void remove_from_equiv_expr(struct expression *expr)
{
	char *name;
	struct symbol *sym;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	remove_from_equiv(name, sym);
free:
	free_string(name);
}

void set_related(struct smatch_state *estate, struct related_list *rlist)
{
	if (!estate_related(estate) && !rlist)
		return;
	get_dinfo(estate)->related = rlist;
}

/*
 * set_equiv() is only used for assignments where we set one variable
 * equal to the other.  a = b;.  It's not used for if conditions where
 * a == b.
 */
void set_equiv(struct expression *left, struct expression *right)
{
	struct sm_state *right_sm, *left_sm, *other_sm;
	struct relation *rel;
	char *left_name;
	struct symbol *left_sym;
	struct related_list *rlist;
	char *other_name;
	struct symbol *other_sym;

	left_name = expr_to_var_sym(left, &left_sym);
	if (!left_name || !left_sym)
		goto free;

	other_name = get_other_name_sym(left_name, left_sym, &other_sym);

	right_sm = get_sm_state_expr(SMATCH_EXTRA, right);
	if (!right_sm) {
		struct range_list *rl;

		if (!get_implied_rl(right, &rl))
			rl = alloc_whole_rl(get_type(right));
		right_sm = set_state_expr(SMATCH_EXTRA, right, alloc_estate_rl(rl));
	}
	if (!right_sm)
		goto free;

	/* This block is because we want to preserve the implications. */
	left_sm = clone_sm(right_sm);
	left_sm->name = alloc_string(left_name);
	left_sm->sym = left_sym;
	left_sm->state = clone_estate_cast(get_type(left), right_sm->state);
	/* FIXME: The expression we're passing is wrong */
	set_extra_mod_helper(left_name, left_sym, left, left_sm->state);
	__set_sm(left_sm);

	if (other_name && other_sym) {
		other_sm = clone_sm(right_sm);
		other_sm->name = alloc_string(other_name);
		other_sm->sym = other_sym;
		other_sm->state = clone_estate_cast(get_type(left), left_sm->state);
		set_extra_mod_helper(other_name, other_sym, NULL, other_sm->state);
		__set_sm(other_sm);
	}

	rlist = clone_related_list(estate_related(right_sm->state));
	add_related(&rlist, right_sm->name, right_sm->sym);
	add_related(&rlist, left_name, left_sym);
	if (other_name && other_sym)
		add_related(&rlist, other_name, other_sym);

	FOR_EACH_PTR(rlist, rel) {
		struct sm_state *old_sm, *new_sm;

		old_sm = get_sm_state(SMATCH_EXTRA, rel->name, rel->sym);
		if (!old_sm)  /* shouldn't happen */
			continue;
		new_sm = clone_sm(old_sm);
		new_sm->state = clone_estate(old_sm->state);
		get_dinfo(new_sm->state)->related = rlist;
		__set_sm(new_sm);
	} END_FOR_EACH_PTR(rel);
free:
	free_string(left_name);
}

void set_equiv_state_expr(int id, struct expression *expr, struct smatch_state *state)
{
	struct relation *rel;
	struct smatch_state *estate;

	estate = get_state_expr(SMATCH_EXTRA, expr);

	if (!estate)
		return;

	FOR_EACH_PTR(get_dinfo(estate)->related, rel) {
		set_state(id, rel->name, rel->sym, state);
	} END_FOR_EACH_PTR(rel);
}

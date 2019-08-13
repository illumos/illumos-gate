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
 */

/*
 * smatch_extra.c is supposed to track the value of every variable.
 *
 */

#define _GNU_SOURCE
#include <string.h>

#include <stdlib.h>
#include <errno.h>
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <limits.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static int link_id;
extern int check_assigned_expr_id;

static void match_link_modify(struct sm_state *sm, struct expression *mod_expr);

struct string_list *__ignored_macros = NULL;
int in_warn_on_macro(void)
{
	struct statement *stmt;
	char *tmp;
	char *macro;

	stmt = get_current_statement();
	if (!stmt)
		return 0;
	macro = get_macro_name(stmt->pos);
	if (!macro)
		return 0;

	FOR_EACH_PTR(__ignored_macros, tmp) {
		if (!strcmp(tmp, macro))
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

typedef void (mod_hook)(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state);
DECLARE_PTR_LIST(void_fn_list, mod_hook *);
static struct void_fn_list *extra_mod_hooks;
static struct void_fn_list *extra_nomod_hooks;

void add_extra_mod_hook(mod_hook *fn)
{
	mod_hook **p = malloc(sizeof(mod_hook *));
	*p = fn;
	add_ptr_list(&extra_mod_hooks, p);
}

void add_extra_nomod_hook(mod_hook *fn)
{
	mod_hook **p = malloc(sizeof(mod_hook *));
	*p = fn;
	add_ptr_list(&extra_nomod_hooks, p);
}

void call_extra_hooks(struct void_fn_list *hooks, const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	mod_hook **fn;

	FOR_EACH_PTR(hooks, fn) {
		(*fn)(name, sym, expr, state);
	} END_FOR_EACH_PTR(fn);
}

void call_extra_mod_hooks(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	call_extra_hooks(extra_mod_hooks, name, sym, expr, state);
}

void call_extra_nomod_hooks(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	call_extra_hooks(extra_nomod_hooks, name, sym, expr, state);
}

static bool in_param_set;
void set_extra_mod_helper(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	remove_from_equiv(name, sym);
	call_extra_mod_hooks(name, sym, expr, state);
	if ((__in_fake_assign || in_param_set) &&
	    estate_is_unknown(state) && !get_state(SMATCH_EXTRA, name, sym))
		return;
	set_state(SMATCH_EXTRA, name, sym, state);
}

static void set_extra_nomod_helper(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	call_extra_nomod_hooks(name, sym, expr, state);
	set_state(SMATCH_EXTRA, name, sym, state);
}

static char *get_pointed_at(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	struct expression *assigned;

	if (name[0] != '*')
		return NULL;
	if (strcmp(name + 1, sym->ident->name) != 0)
		return NULL;

	assigned = get_assigned_expr_name_sym(sym->ident->name, sym);
	if (!assigned)
		return NULL;
	assigned = strip_parens(assigned);
	if (assigned->type != EXPR_PREOP || assigned->op != '&')
		return NULL;

	return expr_to_var_sym(assigned->unop, new_sym);
}

char *get_other_name_sym_from_chunk(const char *name, const char *chunk, int len, struct symbol *sym, struct symbol **new_sym)
{
	struct expression *assigned;
	char *orig_name = NULL;
	char buf[256];
	char *ret;

	assigned = get_assigned_expr_name_sym(chunk, sym);
	if (!assigned)
		return NULL;
	if (assigned->type == EXPR_CALL)
		return map_call_to_other_name_sym(name, sym, new_sym);
	if (assigned->type == EXPR_PREOP && assigned->op == '&') {

		orig_name = expr_to_var_sym(assigned, new_sym);
		if (!orig_name || !*new_sym)
			goto free;

		snprintf(buf, sizeof(buf), "%s.%s", orig_name + 1, name + len);
		ret = alloc_string(buf);
		free_string(orig_name);
		return ret;
	}

	orig_name = expr_to_var_sym(assigned, new_sym);
	if (!orig_name || !*new_sym)
		goto free;

	snprintf(buf, sizeof(buf), "%s->%s", orig_name, name + len);
	ret = alloc_string(buf);
	free_string(orig_name);
	return ret;
free:
	free_string(orig_name);
	return NULL;
}

static char *get_long_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	struct expression *tmp;
	struct sm_state *sm;
	char buf[256];

	/*
	 * Just prepend the name with a different name/sym and return that.
	 * For example, if we set "foo->bar = bar;" then we clamp "bar->baz",
	 * that also clamps "foo->bar->baz".
	 *
	 */

	FOR_EACH_MY_SM(check_assigned_expr_id, __get_cur_stree(), sm) {
		tmp = sm->state->data;
		if (!tmp || tmp->type != EXPR_SYMBOL)
			continue;
		if (tmp->symbol == sym)
			goto found;
	} END_FOR_EACH_SM(sm);

	return NULL;

found:
	snprintf(buf, sizeof(buf), "%s%s", sm->name, name + tmp->symbol->ident->len);
	*new_sym = sm->sym;
	return alloc_string(buf);
}

char *get_other_name_sym_helper(const char *name, struct symbol *sym, struct symbol **new_sym, bool use_stack)
{
	char buf[256];
	char *ret;
	int len;

	*new_sym = NULL;

	if (!sym || !sym->ident)
		return NULL;

	ret = get_pointed_at(name, sym, new_sym);
	if (ret)
		return ret;

	ret = map_long_to_short_name_sym(name, sym, new_sym, use_stack);
	if (ret)
		return ret;

	len = snprintf(buf, sizeof(buf), "%s", name);
	if (len >= sizeof(buf) - 2)
		return NULL;

	while (len >= 1) {
		if (buf[len] == '>' && buf[len - 1] == '-') {
			len--;
			buf[len] = '\0';
			ret = get_other_name_sym_from_chunk(name, buf, len + 2, sym, new_sym);
			if (ret)
				return ret;
		}
		len--;
	}

	ret = get_long_name_sym(name, sym, new_sym);
	if (ret)
		return ret;

	return NULL;
}

char *get_other_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	return get_other_name_sym_helper(name, sym, new_sym, true);
}

char *get_other_name_sym_nostack(const char *name, struct symbol *sym, struct symbol **new_sym)
{
	return get_other_name_sym_helper(name, sym, new_sym, false);
}

void set_extra_mod(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	char *new_name;
	struct symbol *new_sym;

	set_extra_mod_helper(name, sym, expr, state);
	new_name = get_other_name_sym(name, sym, &new_sym);
	if (new_name && new_sym)
		set_extra_mod_helper(new_name, new_sym, expr, state);
	free_string(new_name);
}

static struct expression *chunk_get_array_base(struct expression *expr)
{
	/*
	 * The problem with is_array() is that it only returns true for things
	 * like foo[1] but not for foo[1].bar.
	 *
	 */
	expr = strip_expr(expr);
	while (expr && expr->type == EXPR_DEREF)
		expr = strip_expr(expr->deref);
	return get_array_base(expr);
}

static int chunk_has_array(struct expression *expr)
{
	return !!chunk_get_array_base(expr);
}

static void clear_array_states(struct expression *array)
{
	struct sm_state *sm;

	sm = get_sm_state_expr(link_id, array);
	if (sm)
		match_link_modify(sm, NULL);
}

static void set_extra_array_mod(struct expression *expr, struct smatch_state *state)
{
	struct expression *array;
	struct var_sym_list *vsl;
	struct var_sym *vs;
	char *name;
	struct symbol *sym;

	array = chunk_get_array_base(expr);

	name = expr_to_chunk_sym_vsl(expr, &sym, &vsl);
	if (!name || !vsl) {
		clear_array_states(array);
		goto free;
	}

	FOR_EACH_PTR(vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, sym);
	} END_FOR_EACH_PTR(vs);

	call_extra_mod_hooks(name, sym, expr, state);
	set_state(SMATCH_EXTRA, name, sym, state);
free:
	free_string(name);
}

void set_extra_expr_mod(struct expression *expr, struct smatch_state *state)
{
	struct symbol *sym;
	char *name;

	if (chunk_has_array(expr)) {
		set_extra_array_mod(expr, state);
		return;
	}

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	set_extra_mod(name, sym, expr, state);
free:
	free_string(name);
}

void set_extra_nomod(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	char *new_name;
	struct symbol *new_sym;
	struct relation *rel;
	struct smatch_state *orig_state;

	orig_state = get_state(SMATCH_EXTRA, name, sym);

	/* don't save unknown states if leaving it blank is the same */
	if (!orig_state && estate_is_unknown(state))
		return;

	new_name = get_other_name_sym(name, sym, &new_sym);
	if (new_name && new_sym)
		set_extra_nomod_helper(new_name, new_sym, expr, state);
	free_string(new_name);

	if (!estate_related(orig_state)) {
		set_extra_nomod_helper(name, sym, expr, state);
		return;
	}

	set_related(state, estate_related(orig_state));
	FOR_EACH_PTR(estate_related(orig_state), rel) {
		struct smatch_state *estate;

		estate = get_state(SMATCH_EXTRA, rel->name, rel->sym);
		if (!estate)
			continue;
		set_extra_nomod_helper(rel->name, rel->sym, expr, clone_estate_cast(estate_type(estate), state));
	} END_FOR_EACH_PTR(rel);
}

void set_extra_nomod_vsl(const char *name, struct symbol *sym, struct var_sym_list *vsl, struct expression *expr, struct smatch_state *state)
{
	struct var_sym *vs;

	FOR_EACH_PTR(vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, sym);
	} END_FOR_EACH_PTR(vs);

	set_extra_nomod(name, sym, expr, state);
}

/*
 * This is for return_implies_state() hooks which modify a SMATCH_EXTRA state
 */
void set_extra_expr_nomod(struct expression *expr, struct smatch_state *state)
{
	struct var_sym_list *vsl;
	struct var_sym *vs;
	char *name;
	struct symbol *sym;

	name = expr_to_chunk_sym_vsl(expr, &sym, &vsl);
	if (!name || !vsl)
		goto free;
	FOR_EACH_PTR(vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, sym);
	} END_FOR_EACH_PTR(vs);

	set_extra_nomod(name, sym, expr, state);
free:
	free_string(name);
}

static void set_extra_true_false(const char *name, struct symbol *sym,
			struct smatch_state *true_state,
			struct smatch_state *false_state)
{
	char *new_name;
	struct symbol *new_sym;
	struct relation *rel;
	struct smatch_state *orig_state;

	if (!true_state && !false_state)
		return;

	if (in_warn_on_macro())
		return;

	new_name = get_other_name_sym(name, sym, &new_sym);
	if (new_name && new_sym)
		set_true_false_states(SMATCH_EXTRA, new_name, new_sym, true_state, false_state);
	free_string(new_name);

	orig_state = get_state(SMATCH_EXTRA, name, sym);

	if (!estate_related(orig_state)) {
		set_true_false_states(SMATCH_EXTRA, name, sym, true_state, false_state);
		return;
	}

	if (true_state)
		set_related(true_state, estate_related(orig_state));
	if (false_state)
		set_related(false_state, estate_related(orig_state));

	FOR_EACH_PTR(estate_related(orig_state), rel) {
		set_true_false_states(SMATCH_EXTRA, rel->name, rel->sym,
				true_state, false_state);
	} END_FOR_EACH_PTR(rel);
}

static void set_extra_chunk_true_false(struct expression *expr,
				       struct smatch_state *true_state,
				       struct smatch_state *false_state)
{
	struct var_sym_list *vsl;
	struct var_sym *vs;
	struct symbol *type;
	char *name;
	struct symbol *sym;

	if (in_warn_on_macro())
		return;

	type = get_type(expr);
	if (!type)
		return;

	name = expr_to_chunk_sym_vsl(expr, &sym, &vsl);
	if (!name || !vsl)
		goto free;
	FOR_EACH_PTR(vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, sym);
	} END_FOR_EACH_PTR(vs);

	set_true_false_states(SMATCH_EXTRA, name, sym,
			      clone_estate(true_state),
			      clone_estate(false_state));
free:
	free_string(name);
}

static void set_extra_expr_true_false(struct expression *expr,
		struct smatch_state *true_state,
		struct smatch_state *false_state)
{
	char *name;
	struct symbol *sym;
	sval_t sval;

	if (!true_state && !false_state)
		return;

	if (get_value(expr, &sval))
		return;

	expr = strip_expr(expr);
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym) {
		free_string(name);
		set_extra_chunk_true_false(expr, true_state, false_state);
		return;
	}
	set_extra_true_false(name, sym, true_state, false_state);
	free_string(name);
}

static int get_countdown_info(struct expression *condition, struct expression **unop, int *op, sval_t *right)
{
	struct expression *unop_expr;
	int comparison;
	sval_t limit;

	right->type = &int_ctype;
	right->value = 0;

	condition = strip_expr(condition);

	if (condition->type == EXPR_COMPARE) {
		comparison = remove_unsigned_from_comparison(condition->op);

		if (comparison != SPECIAL_GTE && comparison != '>')
			return 0;
		if (!get_value(condition->right, &limit))
			return 0;

		unop_expr = condition->left;
		if (unop_expr->type != EXPR_PREOP && unop_expr->type != EXPR_POSTOP)
			return 0;
		if (unop_expr->op != SPECIAL_DECREMENT)
			return 0;

		*unop = unop_expr;
		*op = comparison;
		*right = limit;

		return 1;
	}

	if (condition->type != EXPR_PREOP && condition->type != EXPR_POSTOP)
		return 0;
	if (condition->op != SPECIAL_DECREMENT)
		return 0;

	*unop = condition;
	*op = '>';

	return 1;
}

static struct sm_state *handle_canonical_while_count_down(struct statement *loop)
{
	struct expression *iter_var;
	struct expression *condition, *unop;
	struct symbol *type;
	struct sm_state *sm;
	struct smatch_state *estate;
	int op;
	sval_t start, right;

	right.type = &int_ctype;
	right.value = 0;

	condition = strip_expr(loop->iterator_pre_condition);
	if (!condition)
		return NULL;

	if (!get_countdown_info(condition, &unop, &op, &right))
		return NULL;

	iter_var = unop->unop;

	sm = get_sm_state_expr(SMATCH_EXTRA, iter_var);
	if (!sm)
		return NULL;
	if (sval_cmp(estate_min(sm->state), right) < 0)
		return NULL;
	start = estate_max(sm->state);

	type = get_type(iter_var);
	right = sval_cast(type, right);
	start = sval_cast(type, start);

	if  (sval_cmp(start, right) <= 0)
		return NULL;
	if (!sval_is_max(start))
		start.value--;

	if (op == SPECIAL_GTE)
		right.value--;

	if (unop->type == EXPR_PREOP) {
		right.value++;
		estate = alloc_estate_range(right, start);
		if (estate_has_hard_max(sm->state))
			estate_set_hard_max(estate);
		estate_copy_fuzzy_max(estate, sm->state);
		set_extra_expr_mod(iter_var, estate);
	}
	if (unop->type == EXPR_POSTOP) {
		estate = alloc_estate_range(right, start);
		if (estate_has_hard_max(sm->state))
			estate_set_hard_max(estate);
		estate_copy_fuzzy_max(estate, sm->state);
		set_extra_expr_mod(iter_var, estate);
	}
	return get_sm_state_expr(SMATCH_EXTRA, iter_var);
}

static struct sm_state *handle_canonical_for_inc(struct expression *iter_expr,
						struct expression *condition)
{
	struct expression *iter_var;
	struct sm_state *sm;
	struct smatch_state *estate;
	sval_t start, end, max;
	struct symbol *type;

	iter_var = iter_expr->unop;
	sm = get_sm_state_expr(SMATCH_EXTRA, iter_var);
	if (!sm)
		return NULL;
	if (!estate_get_single_value(sm->state, &start))
		return NULL;
	if (!get_implied_value(condition->right, &end))
		return NULL;

	if (get_sm_state_expr(SMATCH_EXTRA, condition->left) != sm)
		return NULL;

	switch (condition->op) {
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_NOTEQUAL:
	case '<':
		if (!sval_is_min(end))
			end.value--;
		break;
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		break;
	default:
		return NULL;
	}
	if (sval_cmp(end, start) < 0)
		return NULL;
	type = get_type(iter_var);
	start = sval_cast(type, start);
	end = sval_cast(type, end);
	estate = alloc_estate_range(start, end);
	if (get_hard_max(condition->right, &max)) {
		if (!get_macro_name(condition->pos))
			estate_set_hard_max(estate);
		if (condition->op == '<' ||
		    condition->op == SPECIAL_UNSIGNED_LT ||
		    condition->op == SPECIAL_NOTEQUAL)
			max.value--;
		max = sval_cast(type, max);
		estate_set_fuzzy_max(estate, max);
	}
	set_extra_expr_mod(iter_var, estate);
	return get_sm_state_expr(SMATCH_EXTRA, iter_var);
}

static struct sm_state *handle_canonical_for_dec(struct expression *iter_expr,
						struct expression *condition)
{
	struct expression *iter_var;
	struct sm_state *sm;
	struct smatch_state *estate;
	sval_t start, end;

	iter_var = iter_expr->unop;
	sm = get_sm_state_expr(SMATCH_EXTRA, iter_var);
	if (!sm)
		return NULL;
	if (!estate_get_single_value(sm->state, &start))
		return NULL;
	if (!get_implied_min(condition->right, &end))
		end = sval_type_min(get_type(iter_var));
	end = sval_cast(estate_type(sm->state), end);
	if (get_sm_state_expr(SMATCH_EXTRA, condition->left) != sm)
		return NULL;

	switch (condition->op) {
	case SPECIAL_NOTEQUAL:
	case '>':
		if (!sval_is_max(end))
			end.value++;
		break;
	case SPECIAL_GTE:
		break;
	default:
		return NULL;
	}
	if (sval_cmp(end, start) > 0)
		return NULL;
	estate = alloc_estate_range(end, start);
	estate_set_hard_max(estate);
	estate_set_fuzzy_max(estate, estate_get_fuzzy_max(estate));
	set_extra_expr_mod(iter_var, estate);
	return get_sm_state_expr(SMATCH_EXTRA, iter_var);
}

static struct sm_state *handle_canonical_for_loops(struct statement *loop)
{
	struct expression *iter_expr;
	struct expression *condition;

	if (!loop->iterator_post_statement)
		return NULL;
	if (loop->iterator_post_statement->type != STMT_EXPRESSION)
		return NULL;
	iter_expr = loop->iterator_post_statement->expression;
	if (!loop->iterator_pre_condition)
		return NULL;
	if (loop->iterator_pre_condition->type != EXPR_COMPARE)
		return NULL;
	condition = loop->iterator_pre_condition;

	if (iter_expr->op == SPECIAL_INCREMENT)
		return handle_canonical_for_inc(iter_expr, condition);
	if (iter_expr->op == SPECIAL_DECREMENT)
		return handle_canonical_for_dec(iter_expr, condition);
	return NULL;
}

struct sm_state *__extra_handle_canonical_loops(struct statement *loop, struct stree **stree)
{
	struct sm_state *ret;

	/*
	 * Canonical loops are a hack.  The proper way to handle this is to
	 * use two passes, but unfortunately, doing two passes makes parsing
	 * code twice as slow.
	 *
	 * What we do is we set the inside state here, which overwrites whatever
	 * __extra_match_condition() does.  Then we set the outside state in
	 * __extra_pre_loop_hook_after().
	 *
	 */
	__push_fake_cur_stree();
	if (!loop->iterator_post_statement)
		ret = handle_canonical_while_count_down(loop);
	else
		ret = handle_canonical_for_loops(loop);
	*stree = __pop_fake_cur_stree();
	return ret;
}

int __iterator_unchanged(struct sm_state *sm)
{
	if (!sm)
		return 0;
	if (get_sm_state(my_id, sm->name, sm->sym) == sm)
		return 1;
	return 0;
}

static void while_count_down_after(struct sm_state *sm, struct expression *condition)
{
	struct expression *unop;
	int op;
	sval_t limit, after_value;

	if (!get_countdown_info(condition, &unop, &op, &limit))
		return;
	after_value = estate_min(sm->state);
	after_value.value--;
	set_extra_mod(sm->name, sm->sym, condition->unop, alloc_estate_sval(after_value));
}

void __extra_pre_loop_hook_after(struct sm_state *sm,
				struct statement *iterator,
				struct expression *condition)
{
	struct expression *iter_expr;
	sval_t limit;
	struct smatch_state *state;

	if (!iterator) {
		while_count_down_after(sm, condition);
		return;
	}

	iter_expr = iterator->expression;

	if (condition->type != EXPR_COMPARE)
		return;
	if (iter_expr->op == SPECIAL_INCREMENT) {
		limit = sval_binop(estate_max(sm->state), '+',
				   sval_type_val(estate_type(sm->state), 1));
	} else {
		limit = sval_binop(estate_min(sm->state), '-',
				   sval_type_val(estate_type(sm->state), 1));
	}
	limit = sval_cast(estate_type(sm->state), limit);
	if (!estate_has_hard_max(sm->state) && !__has_breaks()) {
		if (iter_expr->op == SPECIAL_INCREMENT)
			state = alloc_estate_range(estate_min(sm->state), limit);
		else
			state = alloc_estate_range(limit, estate_max(sm->state));
	} else {
		state = alloc_estate_sval(limit);
	}
	if (!estate_has_hard_max(sm->state)) {
		estate_clear_hard_max(state);
	}
	if (estate_has_fuzzy_max(sm->state)) {
		sval_t hmax = estate_get_fuzzy_max(sm->state);
		sval_t max = estate_max(sm->state);

		if (sval_cmp(hmax, max) != 0)
			estate_clear_fuzzy_max(state);
	} else if (!estate_has_fuzzy_max(sm->state)) {
		estate_clear_fuzzy_max(state);
	}

	set_extra_mod(sm->name, sm->sym, iter_expr, state);
}

static bool get_global_rl(const char *name, struct symbol *sym, struct range_list **rl)
{
	struct expression *expr;

	if (!sym || !(sym->ctype.modifiers & MOD_TOPLEVEL) || !sym->ident)
		return false;
	if (strcmp(sym->ident->name, name) != 0)
		return false;

	expr = symbol_expression(sym);
	return get_implied_rl(expr, rl);
}

static struct stree *unmatched_stree;
static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct smatch_state *state;
	struct range_list *rl;

	if (unmatched_stree) {
		state = get_state_stree(unmatched_stree, SMATCH_EXTRA, sm->name, sm->sym);
		if (state)
			return state;
	}
	if (parent_is_gone_var_sym(sm->name, sm->sym))
		return alloc_estate_empty();
	if (get_global_rl(sm->name, sm->sym, &rl))
		return alloc_estate_rl(rl);
	return alloc_estate_whole(estate_type(sm->state));
}

static void clear_the_pointed_at(struct expression *expr)
{
	struct stree *stree;
	char *name;
	struct symbol *sym;
	struct sm_state *tmp;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	stree = __get_cur_stree();
	FOR_EACH_MY_SM(SMATCH_EXTRA, stree, tmp) {
		if (tmp->name[0] != '*')
			continue;
		if (tmp->sym != sym)
			continue;
		if (strcmp(tmp->name + 1, name) != 0)
			continue;
		set_extra_mod(tmp->name, tmp->sym, expr, alloc_estate_whole(estate_type(tmp->state)));
	} END_FOR_EACH_SM(tmp);

free:
	free_string(name);
}

static int is_const_param(struct expression *expr, int param)
{
	struct symbol *type;

	type = get_arg_type(expr, param);
	if (!type)
		return 0;
	if (type->ctype.modifiers & MOD_CONST)
		return 1;
	return 0;
}

static void match_function_call(struct expression *expr)
{
	struct expression *arg;
	struct expression *tmp;
	int param = -1;

	/* if we have the db this is handled in smatch_function_hooks.c */
	if (!option_no_db)
		return;
	if (inlinable(expr->fn))
		return;

	FOR_EACH_PTR(expr->args, arg) {
		param++;
		if (is_const_param(expr->fn, param))
			continue;
		tmp = strip_expr(arg);
		if (tmp->type == EXPR_PREOP && tmp->op == '&')
			set_extra_expr_mod(tmp->unop, alloc_estate_whole(get_type(tmp->unop)));
		else
			clear_the_pointed_at(tmp);
	} END_FOR_EACH_PTR(arg);
}

int values_fit_type(struct expression *left, struct expression *right)
{
	struct range_list *rl;
	struct symbol *type;

	type = get_type(left);
	if (!type)
		return 0;
	get_absolute_rl(right, &rl);
	if (type == rl_type(rl))
		return 1;
	if (type_unsigned(type) && sval_is_negative(rl_min(rl)))
		return 0;
	if (sval_cmp(sval_type_min(type), rl_min(rl)) > 0)
		return 0;
	if (sval_cmp(sval_type_max(type), rl_max(rl)) < 0)
		return 0;
	return 1;
}

static void save_chunk_info(struct expression *left, struct expression *right)
{
	struct var_sym_list *vsl;
	struct var_sym *vs;
	struct expression *add_expr;
	struct symbol *type;
	sval_t sval;
	char *name;
	struct symbol *sym;

	if (right->type != EXPR_BINOP || right->op != '-')
		return;
	if (!get_value(right->left, &sval))
		return;
	if (!expr_to_sym(right->right))
		return;

	add_expr = binop_expression(left, '+', right->right);
	type = get_type(add_expr);
	if (!type)
		return;
	name = expr_to_chunk_sym_vsl(add_expr, &sym, &vsl);
	if (!name || !vsl)
		goto free;
	FOR_EACH_PTR(vsl, vs) {
		store_link(link_id, vs->var, vs->sym, name, sym);
	} END_FOR_EACH_PTR(vs);

	set_state(SMATCH_EXTRA, name, sym, alloc_estate_sval(sval_cast(type, sval)));
free:
	free_string(name);
}

static void do_array_assign(struct expression *left, int op, struct expression *right)
{
	struct range_list *rl;

	if (op == '=') {
		get_absolute_rl(right, &rl);
		rl = cast_rl(get_type(left), rl);
	} else {
		rl = alloc_whole_rl(get_type(left));
	}

	set_extra_array_mod(left, alloc_estate_rl(rl));
}

static void match_vanilla_assign(struct expression *left, struct expression *right)
{
	struct range_list *orig_rl = NULL;
	struct range_list *rl = NULL;
	struct symbol *right_sym;
	struct symbol *left_type;
	struct symbol *right_type;
	char *right_name = NULL;
	struct symbol *sym;
	char *name;
	sval_t sval, max;
	struct smatch_state *state;
	int comparison;

	if (is_struct(left))
		return;

	save_chunk_info(left, right);

	name = expr_to_var_sym(left, &sym);
	if (!name) {
		if (chunk_has_array(left))
			do_array_assign(left, '=', right);
		return;
	}

	left_type = get_type(left);
	right_type = get_type(right);

	right_name = expr_to_var_sym(right, &right_sym);

	if (!__in_fake_assign &&
	    !(right->type == EXPR_PREOP && right->op == '&') &&
	    right_name && right_sym &&
	    values_fit_type(left, strip_expr(right)) &&
	    !has_symbol(right, sym)) {
		set_equiv(left, right);
		goto free;
	}

	if (is_pointer(right) && get_address_rl(right, &rl)) {
		state = alloc_estate_rl(rl);
		goto done;
	}

	if (get_implied_value(right, &sval)) {
		state = alloc_estate_sval(sval_cast(left_type, sval));
		goto done;
	}

	if (__in_fake_assign) {
		struct smatch_state *right_state;
		sval_t sval;

		if (get_value(right, &sval)) {
			sval = sval_cast(left_type, sval);
			state = alloc_estate_sval(sval);
			goto done;
		}

		right_state = get_state(SMATCH_EXTRA, right_name, right_sym);
		if (right_state) {
			/* simple assignment */
			state = clone_estate(right_state);
			goto done;
		}

		state = alloc_estate_rl(alloc_whole_rl(left_type));
		goto done;
	}

	comparison = get_comparison_no_extra(left, right);
	if (comparison) {
		comparison = flip_comparison(comparison);
		get_implied_rl(left, &orig_rl);
	}

	if (get_implied_rl(right, &rl)) {
		rl = cast_rl(left_type, rl);
		if (orig_rl)
			filter_by_comparison(&rl, comparison, orig_rl);
		state = alloc_estate_rl(rl);
		if (get_hard_max(right, &max)) {
			estate_set_hard_max(state);
			estate_set_fuzzy_max(state, max);
		}
	} else {
		rl = alloc_whole_rl(right_type);
		rl = cast_rl(left_type, rl);
		if (orig_rl)
			filter_by_comparison(&rl, comparison, orig_rl);
		state = alloc_estate_rl(rl);
	}

done:
	set_extra_mod(name, sym, left, state);
free:
	free_string(right_name);
}

static void match_assign(struct expression *expr)
{
	struct range_list *rl = NULL;
	struct expression *left;
	struct expression *right;
	struct expression *binop_expr;
	struct symbol *left_type;
	struct symbol *sym;
	char *name;

	left = strip_expr(expr->left);

	right = strip_parens(expr->right);
	if (right->type == EXPR_CALL && sym_name_is("__builtin_expect", right->fn))
		right = get_argument_from_call_expr(right->args, 0);
	while (right->type == EXPR_ASSIGNMENT && right->op == '=')
		right = strip_parens(right->left);

	if (expr->op == '=' && is_condition(expr->right))
		return; /* handled in smatch_condition.c */
	if (expr->op == '=' && right->type == EXPR_CALL)
		return; /* handled in smatch_function_hooks.c */
	if (expr->op == '=') {
		match_vanilla_assign(left, right);
		return;
	}

	name = expr_to_var_sym(left, &sym);
	if (!name)
		return;

	left_type = get_type(left);

	switch (expr->op) {
	case SPECIAL_ADD_ASSIGN:
	case SPECIAL_SUB_ASSIGN:
	case SPECIAL_AND_ASSIGN:
	case SPECIAL_MOD_ASSIGN:
	case SPECIAL_SHL_ASSIGN:
	case SPECIAL_SHR_ASSIGN:
	case SPECIAL_OR_ASSIGN:
	case SPECIAL_XOR_ASSIGN:
	case SPECIAL_MUL_ASSIGN:
	case SPECIAL_DIV_ASSIGN:
		binop_expr = binop_expression(expr->left,
					      op_remove_assign(expr->op),
					      expr->right);
		get_absolute_rl(binop_expr, &rl);
		rl = cast_rl(left_type, rl);
		if (inside_loop()) {
			if (expr->op == SPECIAL_ADD_ASSIGN)
				add_range(&rl, rl_max(rl), sval_type_max(rl_type(rl)));

			if (expr->op == SPECIAL_SUB_ASSIGN &&
			    !sval_is_negative(rl_min(rl))) {
				sval_t zero = { .type = rl_type(rl) };

				add_range(&rl, rl_min(rl), zero);
			}
		}
		set_extra_mod(name, sym, left, alloc_estate_rl(rl));
		goto free;
	}
	set_extra_mod(name, sym, left, alloc_estate_whole(left_type));
free:
	free_string(name);
}

static struct smatch_state *increment_state(struct smatch_state *state)
{
	sval_t min = estate_min(state);
	sval_t max = estate_max(state);

	if (!estate_rl(state))
		return NULL;

	if (inside_loop())
		max = sval_type_max(max.type);

	if (!sval_is_min(min) && !sval_is_max(min))
		min.value++;
	if (!sval_is_min(max) && !sval_is_max(max))
		max.value++;
	return alloc_estate_range(min, max);
}

static struct smatch_state *decrement_state(struct smatch_state *state)
{
	sval_t min = estate_min(state);
	sval_t max = estate_max(state);

	if (!estate_rl(state))
		return NULL;

	if (inside_loop())
		min = sval_type_min(min.type);

	if (!sval_is_min(min) && !sval_is_max(min))
		min.value--;
	if (!sval_is_min(max) && !sval_is_max(max))
		max.value--;
	return alloc_estate_range(min, max);
}

static void clear_pointed_at_state(struct expression *expr)
{
	struct symbol *type;

	/*
         * ALERT: This is sort of a mess.  If it's is a struct assigment like
	 * "foo = bar;", then that's handled by smatch_struct_assignment.c.
	 * the same thing for p++ where "p" is a struct.  Most modifications
	 * are handled by the assignment hook or the db.  Smatch_extra.c doesn't
	 * use smatch_modification.c because we have to get the ordering right
	 * or something.  So if you have p++ where p is a pointer to a standard
	 * c type then we handle that here.  What a mess.
	 */
	expr = strip_expr(expr);
	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_BASETYPE)
		return;
	set_extra_expr_nomod(deref_expression(expr), alloc_estate_whole(type));
}

static void unop_expr(struct expression *expr)
{
	struct smatch_state *state;

	if (expr->smatch_flags & Handled)
		return;

	switch (expr->op) {
	case SPECIAL_INCREMENT:
		state = get_state_expr(SMATCH_EXTRA, expr->unop);
		state = increment_state(state);
		if (!state)
			state = alloc_estate_whole(get_type(expr));
		set_extra_expr_mod(expr->unop, state);
		clear_pointed_at_state(expr->unop);
		break;
	case SPECIAL_DECREMENT:
		state = get_state_expr(SMATCH_EXTRA, expr->unop);
		state = decrement_state(state);
		if (!state)
			state = alloc_estate_whole(get_type(expr));
		set_extra_expr_mod(expr->unop, state);
		clear_pointed_at_state(expr->unop);
		break;
	default:
		return;
	}
}

static void asm_expr(struct statement *stmt)
{

	struct expression *expr;
	struct symbol *type;
	int state = 0;

	FOR_EACH_PTR(stmt->asm_outputs, expr) {
		switch (state) {
		case 0: /* identifier */
		case 1: /* constraint */
			state++;
			continue;
		case 2: /* expression */
			state = 0;
			type = get_type(strip_expr(expr));
			set_extra_expr_mod(expr, alloc_estate_whole(type));
			continue;
		}
	} END_FOR_EACH_PTR(expr);
}

static void check_dereference(struct expression *expr)
{
	struct smatch_state *state;

	if (__in_fake_assign)
		return;
	if (outside_of_function())
		return;
	state = get_extra_state(expr);
	if (state) {
		struct range_list *rl;

		rl = rl_intersection(estate_rl(state), valid_ptr_rl);
		if (rl_equiv(rl, estate_rl(state)))
			return;
		set_extra_expr_nomod(expr, alloc_estate_rl(rl));
	} else {
		struct range_list *rl;

		if (get_mtag_rl(expr, &rl))
			rl = rl_intersection(rl, valid_ptr_rl);
		else
			rl = clone_rl(valid_ptr_rl);

		set_extra_expr_nomod(expr, alloc_estate_rl(rl));
	}
}

static void match_dereferences(struct expression *expr)
{
	if (expr->type != EXPR_PREOP)
		return;
	/* it's saying that foo[1] = bar dereferences foo[1] */
	if (is_array(expr))
		return;
	check_dereference(expr->unop);
}

static void match_pointer_as_array(struct expression *expr)
{
	if (!is_array(expr))
		return;
	check_dereference(get_array_base(expr));
}

static void find_dereferences(struct expression *expr)
{
	while (expr->type == EXPR_PREOP) {
		if (expr->op == '*')
			check_dereference(expr->unop);
		expr = strip_expr(expr->unop);
	}
}

static void set_param_dereferenced(struct expression *call, struct expression *arg, char *key, char *unused)
{
	struct symbol *sym;
	char *name;

	name = get_variable_from_key(arg, key, &sym);
	if (name && sym) {
		struct smatch_state *orig, *new;
		struct range_list *rl;

		orig = get_state(SMATCH_EXTRA, name, sym);
		if (orig) {
			rl = rl_intersection(estate_rl(orig),
					     alloc_rl(valid_ptr_min_sval,
						      valid_ptr_max_sval));
			new = alloc_estate_rl(rl);
		} else {
			new = alloc_estate_range(valid_ptr_min_sval, valid_ptr_max_sval);
		}

		set_extra_nomod(name, sym, NULL, new);
	}
	free_string(name);

	find_dereferences(arg);
}

static sval_t add_one(sval_t sval)
{
	sval.value++;
	return sval;
}

static int handle_postop_inc(struct expression *left, int op, struct expression *right)
{
	struct statement *stmt;
	struct expression *cond;
	struct smatch_state *true_state, *false_state;
	struct symbol *type;
	sval_t start;
	sval_t limit;

	/*
	 * If we're decrementing here then that's a canonical while count down
	 * so it's handled already.  We're only handling loops like:
	 * i = 0;
	 * do { ... } while (i++ < 3);
	 */

	if (left->type != EXPR_POSTOP || left->op != SPECIAL_INCREMENT)
		return 0;

	stmt = __cur_stmt->parent;
	if (!stmt)
		return 0;
	if (stmt->type == STMT_COMPOUND)
		stmt = stmt->parent;
	if (!stmt || stmt->type != STMT_ITERATOR || !stmt->iterator_post_condition)
		return 0;

	cond = strip_expr(stmt->iterator_post_condition);
	if (cond->type != EXPR_COMPARE || cond->op != op)
		return 0;
	if (left != strip_expr(cond->left) || right != strip_expr(cond->right))
		return 0;

	if (!get_implied_value(left->unop, &start))
		return 0;
	if (!get_implied_value(right, &limit))
		return 0;
	type = get_type(left->unop);
	limit = sval_cast(type, limit);
	if (sval_cmp(start, limit) > 0)
		return 0;

	switch (op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		break;
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		limit = add_one(limit);
	default:
		return 0;

	}

	true_state = alloc_estate_range(add_one(start), limit);
	false_state = alloc_estate_range(add_one(limit), add_one(limit));

	/* Currently we just discard the false state but when two passes is
	 * implimented correctly then it will use it.
	 */

	set_extra_expr_true_false(left->unop, true_state, false_state);

	return 1;
}

bool is_impossible_variable(struct expression *expr)
{
	struct smatch_state *state;

	state = get_extra_state(expr);
	if (state && !estate_rl(state))
		return true;
	return false;
}

static bool in_macro(struct expression *left, struct expression *right)
{
	if (!left || !right)
		return 0;
	if (left->pos.line != right->pos.line || left->pos.pos != right->pos.pos)
		return 0;
	if (get_macro_name(left->pos))
		return 1;
	return 0;
}

static void handle_comparison(struct symbol *type, struct expression *left, int op, struct expression *right)
{
	struct range_list *left_orig;
	struct range_list *left_true;
	struct range_list *left_false;
	struct range_list *right_orig;
	struct range_list *right_true;
	struct range_list *right_false;
	struct smatch_state *left_true_state;
	struct smatch_state *left_false_state;
	struct smatch_state *right_true_state;
	struct smatch_state *right_false_state;
	sval_t dummy, hard_max;
	int left_postop = 0;
	int right_postop = 0;

	if (left->op == SPECIAL_INCREMENT || left->op == SPECIAL_DECREMENT) {
		if (left->type == EXPR_POSTOP) {
			left->smatch_flags |= Handled;
			left_postop = left->op;
			if (handle_postop_inc(left, op, right))
				return;
		}
		left = strip_parens(left->unop);
	}
	while (left->type == EXPR_ASSIGNMENT)
		left = strip_parens(left->left);

	if (right->op == SPECIAL_INCREMENT || right->op == SPECIAL_DECREMENT) {
		if (right->type == EXPR_POSTOP) {
			right->smatch_flags |= Handled;
			right_postop = right->op;
		}
		right = strip_parens(right->unop);
	}

	if (is_impossible_variable(left) || is_impossible_variable(right))
		return;

	get_real_absolute_rl(left, &left_orig);
	left_orig = cast_rl(type, left_orig);

	get_real_absolute_rl(right, &right_orig);
	right_orig = cast_rl(type, right_orig);

	split_comparison_rl(left_orig, op, right_orig, &left_true, &left_false, &right_true, &right_false);

	left_true = rl_truncate_cast(get_type(strip_expr(left)), left_true);
	left_false = rl_truncate_cast(get_type(strip_expr(left)), left_false);
	right_true = rl_truncate_cast(get_type(strip_expr(right)), right_true);
	right_false = rl_truncate_cast(get_type(strip_expr(right)), right_false);

	if (!left_true || !left_false) {
		struct range_list *tmp_true, *tmp_false;

		split_comparison_rl(alloc_whole_rl(type), op, right_orig, &tmp_true, &tmp_false, NULL, NULL);
		tmp_true = rl_truncate_cast(get_type(strip_expr(left)), tmp_true);
		tmp_false = rl_truncate_cast(get_type(strip_expr(left)), tmp_false);
		if (tmp_true && tmp_false)
			__save_imaginary_state(left, tmp_true, tmp_false);
	}

	if (!right_true || !right_false) {
		struct range_list *tmp_true, *tmp_false;

		split_comparison_rl(alloc_whole_rl(type), op, right_orig, NULL, NULL, &tmp_true, &tmp_false);
		tmp_true = rl_truncate_cast(get_type(strip_expr(right)), tmp_true);
		tmp_false = rl_truncate_cast(get_type(strip_expr(right)), tmp_false);
		if (tmp_true && tmp_false)
			__save_imaginary_state(right, tmp_true, tmp_false);
	}

	left_true_state = alloc_estate_rl(left_true);
	left_false_state = alloc_estate_rl(left_false);
	right_true_state = alloc_estate_rl(right_true);
	right_false_state = alloc_estate_rl(right_false);

	switch (op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		if (get_implied_value(right, &dummy) && !in_macro(left, right))
			estate_set_hard_max(left_true_state);
		if (get_implied_value(left, &dummy) && !in_macro(left, right))
			estate_set_hard_max(right_false_state);
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_UNSIGNED_GTE:
	case SPECIAL_GTE:
		if (get_implied_value(left, &dummy) && !in_macro(left, right))
			estate_set_hard_max(right_true_state);
		if (get_implied_value(right, &dummy) && !in_macro(left, right))
			estate_set_hard_max(left_false_state);
		break;
	}

	switch (op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		if (get_hard_max(right, &hard_max)) {
			if (op == '<' || op == SPECIAL_UNSIGNED_LT)
				hard_max.value--;
			estate_set_fuzzy_max(left_true_state, hard_max);
		}
		if (get_implied_value(right, &hard_max)) {
			if (op == SPECIAL_UNSIGNED_LTE ||
			    op == SPECIAL_LTE)
				hard_max.value++;
			estate_set_fuzzy_max(left_false_state, hard_max);
		}
		if (get_hard_max(left, &hard_max)) {
			if (op == SPECIAL_UNSIGNED_LTE ||
			    op == SPECIAL_LTE)
				hard_max.value--;
			estate_set_fuzzy_max(right_false_state, hard_max);
		}
		if (get_implied_value(left, &hard_max)) {
			if (op == '<' || op == SPECIAL_UNSIGNED_LT)
				hard_max.value++;
			estate_set_fuzzy_max(right_true_state, hard_max);
		}
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_UNSIGNED_GTE:
	case SPECIAL_GTE:
		if (get_hard_max(left, &hard_max)) {
			if (op == '>' || op == SPECIAL_UNSIGNED_GT)
				hard_max.value--;
			estate_set_fuzzy_max(right_true_state, hard_max);
		}
		if (get_implied_value(left, &hard_max)) {
			if (op == SPECIAL_UNSIGNED_GTE ||
			    op == SPECIAL_GTE)
				hard_max.value++;
			estate_set_fuzzy_max(right_false_state, hard_max);
		}
		if (get_hard_max(right, &hard_max)) {
			if (op == SPECIAL_UNSIGNED_LTE ||
			    op == SPECIAL_LTE)
				hard_max.value--;
			estate_set_fuzzy_max(left_false_state, hard_max);
		}
		if (get_implied_value(right, &hard_max)) {
			if (op == '>' ||
			    op == SPECIAL_UNSIGNED_GT)
				hard_max.value++;
			estate_set_fuzzy_max(left_true_state, hard_max);
		}
		break;
	case SPECIAL_EQUAL:
		if (get_hard_max(left, &hard_max))
			estate_set_fuzzy_max(right_true_state, hard_max);
		if (get_hard_max(right, &hard_max))
			estate_set_fuzzy_max(left_true_state, hard_max);
		break;
	}

	if (get_hard_max(left, &hard_max)) {
		estate_set_hard_max(left_true_state);
		estate_set_hard_max(left_false_state);
	}
	if (get_hard_max(right, &hard_max)) {
		estate_set_hard_max(right_true_state);
		estate_set_hard_max(right_false_state);
	}

	if (left_postop == SPECIAL_INCREMENT) {
		left_true_state = increment_state(left_true_state);
		left_false_state = increment_state(left_false_state);
	}
	if (left_postop == SPECIAL_DECREMENT) {
		left_true_state = decrement_state(left_true_state);
		left_false_state = decrement_state(left_false_state);
	}
	if (right_postop == SPECIAL_INCREMENT) {
		right_true_state = increment_state(right_true_state);
		right_false_state = increment_state(right_false_state);
	}
	if (right_postop == SPECIAL_DECREMENT) {
		right_true_state = decrement_state(right_true_state);
		right_false_state = decrement_state(right_false_state);
	}

	if (estate_rl(left_true_state) && estates_equiv(left_true_state, left_false_state)) {
		left_true_state = NULL;
		left_false_state = NULL;
	}

	if (estate_rl(right_true_state) && estates_equiv(right_true_state, right_false_state)) {
		right_true_state = NULL;
		right_false_state = NULL;
	}

	/* Don't introduce new states for known true/false conditions */
	if (rl_equiv(left_orig, estate_rl(left_true_state)))
		left_true_state = NULL;
	if (rl_equiv(left_orig, estate_rl(left_false_state)))
		left_false_state = NULL;
	if (rl_equiv(right_orig, estate_rl(right_true_state)))
		right_true_state = NULL;
	if (rl_equiv(right_orig, estate_rl(right_false_state)))
		right_false_state = NULL;

	set_extra_expr_true_false(left, left_true_state, left_false_state);
	set_extra_expr_true_false(right, right_true_state, right_false_state);
}

static int is_simple_math(struct expression *expr)
{
	if (!expr)
		return 0;
	if (expr->type != EXPR_BINOP)
		return 0;
	switch (expr->op) {
	case '+':
	case '-':
	case '*':
		return 1;
	}
	return 0;
}

static int flip_op(int op)
{
	/* We only care about simple math */
	switch (op) {
	case '+':
		return '-';
	case '-':
		return '+';
	case '*':
		return '/';
	}
	return 0;
}

static void move_known_to_rl(struct expression **expr_p, struct range_list **rl_p)
{
	struct expression *expr = *expr_p;
	struct range_list *rl = *rl_p;
	sval_t sval;

	if (!is_simple_math(expr))
		return;

	if (get_implied_value(expr->right, &sval)) {
		*expr_p = expr->left;
		*rl_p = rl_binop(rl, flip_op(expr->op), alloc_rl(sval, sval));
		move_known_to_rl(expr_p, rl_p);
		return;
	}
	if (expr->op == '-')
		return;
	if (get_implied_value(expr->left, &sval)) {
		*expr_p = expr->right;
		*rl_p = rl_binop(rl, flip_op(expr->op), alloc_rl(sval, sval));
		move_known_to_rl(expr_p, rl_p);
		return;
	}
}

static void move_known_values(struct expression **left_p, struct expression **right_p)
{
	struct expression *left = *left_p;
	struct expression *right = *right_p;
	sval_t sval, dummy;

	if (get_implied_value(left, &sval)) {
		if (!is_simple_math(right))
			return;
		if (get_implied_value(right, &dummy))
			return;
		if (right->op == '*') {
			sval_t divisor;

			if (!get_value(right->right, &divisor))
				return;
			if (divisor.value == 0)
				return;
			*left_p = binop_expression(left, invert_op(right->op), right->right);
			*right_p = right->left;
			return;
		}
		if (right->op == '+' && get_value(right->left, &sval)) {
			*left_p = binop_expression(left, invert_op(right->op), right->left);
			*right_p = right->right;
			return;
		}
		if (get_value(right->right, &sval)) {
			*left_p = binop_expression(left, invert_op(right->op), right->right);
			*right_p = right->left;
			return;
		}
		return;
	}
	if (get_implied_value(right, &sval)) {
		if (!is_simple_math(left))
			return;
		if (get_implied_value(left, &dummy))
			return;
		if (left->op == '*') {
			sval_t divisor;

			if (!get_value(left->right, &divisor))
				return;
			if (divisor.value == 0)
				return;
			*right_p = binop_expression(right, invert_op(left->op), left->right);
			*left_p = left->left;
			return;
		}
		if (left->op == '+' && get_value(left->left, &sval)) {
			*right_p = binop_expression(right, invert_op(left->op), left->left);
			*left_p = left->right;
			return;
		}

		if (get_value(left->right, &sval)) {
			*right_p = binop_expression(right, invert_op(left->op), left->right);
			*left_p = left->left;
			return;
		}
		return;
	}
}

/*
 * The reason for do_simple_algebra() is to solve things like:
 * if (foo > 66 || foo + bar > 64) {
 * "foo" is not really a known variable so it won't be handled by
 * move_known_variables() but it's a super common idiom.
 *
 */
static int do_simple_algebra(struct expression **left_p, struct expression **right_p)
{
	struct expression *left = *left_p;
	struct expression *right = *right_p;
	struct range_list *rl;
	sval_t tmp;

	if (left->type != EXPR_BINOP || left->op != '+')
		return 0;
	if (can_integer_overflow(get_type(left), left))
		return 0;
	if (!get_implied_value(right, &tmp))
		return 0;

	if (!get_implied_value(left->left, &tmp) &&
	    get_implied_rl(left->left, &rl) &&
	    !is_whole_rl(rl)) {
		*right_p = binop_expression(right, '-', left->left);
		*left_p = left->right;
		return 1;
	}
	if (!get_implied_value(left->right, &tmp) &&
	    get_implied_rl(left->right, &rl) &&
	    !is_whole_rl(rl)) {
		*right_p = binop_expression(right, '-', left->right);
		*left_p = left->left;
		return 1;
	}

	return 0;
}

static int match_func_comparison(struct expression *expr)
{
	struct expression *left = strip_expr(expr->left);
	struct expression *right = strip_expr(expr->right);

	if (left->type == EXPR_CALL || right->type == EXPR_CALL) {
		function_comparison(left, expr->op, right);
		return 1;
	}

	return 0;
}

/* Handle conditions like "if (foo + bar < foo) {" */
static int handle_integer_overflow_test(struct expression *expr)
{
	struct expression *left, *right;
	struct symbol *type;
	sval_t left_min, right_min, min, max;

	if (expr->op != '<' && expr->op != SPECIAL_UNSIGNED_LT)
		return 0;

	left = strip_parens(expr->left);
	right = strip_parens(expr->right);

	if (left->op != '+')
		return 0;

	type = get_type(expr);
	if (!type)
		return 0;
	if (type_positive_bits(type) == 32) {
		max.type = &uint_ctype;
		max.uvalue = (unsigned int)-1;
	} else if (type_positive_bits(type) == 64) {
		max.type = &ulong_ctype;
		max.value = (unsigned long long)-1;
	} else {
		return 0;
	}

	if (!expr_equiv(left->left, right) && !expr_equiv(left->right, right))
		return 0;

	get_absolute_min(left->left, &left_min);
	get_absolute_min(left->right, &right_min);
	min = sval_binop(left_min, '+', right_min);

	type = get_type(left);
	min = sval_cast(type, min);
	max = sval_cast(type, max);

	set_extra_chunk_true_false(left, NULL, alloc_estate_range(min, max));
	return 1;
}

static void match_comparison(struct expression *expr)
{
	struct expression *left_orig = strip_parens(expr->left);
	struct expression *right_orig = strip_parens(expr->right);
	struct expression *left, *right, *tmp;
	struct expression *prev;
	struct symbol *type;
	int redo, count;

	if (match_func_comparison(expr))
		return;

	type = get_type(expr);
	if (!type)
		type = &llong_ctype;

	if (handle_integer_overflow_test(expr))
		return;

	left = left_orig;
	right = right_orig;
	move_known_values(&left, &right);
	handle_comparison(type, left, expr->op, right);

	left = left_orig;
	right = right_orig;
	if (do_simple_algebra(&left, &right))
		handle_comparison(type, left, expr->op, right);

	prev = get_assigned_expr(left_orig);
	if (is_simple_math(prev) && has_variable(prev, left_orig) == 0) {
		left = prev;
		right = right_orig;
		move_known_values(&left, &right);
		handle_comparison(type, left, expr->op, right);
	}

	prev = get_assigned_expr(right_orig);
	if (is_simple_math(prev) && has_variable(prev, right_orig) == 0) {
		left = left_orig;
		right = prev;
		move_known_values(&left, &right);
		handle_comparison(type, left, expr->op, right);
	}

	redo = 0;
	left = left_orig;
	right = right_orig;
	if (get_last_expr_from_expression_stmt(left_orig)) {
		left = get_last_expr_from_expression_stmt(left_orig);
		redo = 1;
	}
	if (get_last_expr_from_expression_stmt(right_orig)) {
		right = get_last_expr_from_expression_stmt(right_orig);
		redo = 1;
	}

	if (!redo)
		return;

	count = 0;
	while ((tmp = get_assigned_expr(left))) {
		if (count++ > 3)
			break;
		left = strip_expr(tmp);
	}
	count = 0;
	while ((tmp = get_assigned_expr(right))) {
		if (count++ > 3)
			break;
		right = strip_expr(tmp);
	}

	handle_comparison(type, left, expr->op, right);
}

static sval_t get_high_mask(sval_t known)
{
	sval_t ret;
	int i;

	ret = known;
	ret.value = 0;

	for (i = type_bits(known.type) - 1; i >= 0; i--) {
		if (known.uvalue & (1ULL << i))
			ret.uvalue |= (1ULL << i);
		else
			return ret;

	}
	return ret;
}

static bool handle_bit_test(struct expression *expr)
{
	struct range_list *orig_rl, *rl;
	struct expression *shift, *mask, *var;
	struct bit_info *bit_info;
	sval_t sval;
	sval_t high = { .type = &int_ctype };
	sval_t low = { .type = &int_ctype };

	shift = strip_expr(expr->right);
	mask = strip_expr(expr->left);
	if (shift->type != EXPR_BINOP || shift->op != SPECIAL_LEFTSHIFT) {
		shift = strip_expr(expr->left);
		mask = strip_expr(expr->right);
		if (shift->type != EXPR_BINOP || shift->op != SPECIAL_LEFTSHIFT)
			return false;
	}
	if (!get_implied_value(shift->left, &sval) || sval.value != 1)
		return false;
	var = strip_expr(shift->right);

	bit_info = get_bit_info(mask);
	if (!bit_info)
		return false;
	if (!bit_info->possible)
		return false;

	get_absolute_rl(var, &orig_rl);
	if (sval_is_negative(rl_min(orig_rl)) ||
	    rl_max(orig_rl).uvalue > type_bits(get_type(shift->left)))
		return false;

	low.value = ffsll(bit_info->possible);
	high.value = sm_fls64(bit_info->possible);
	rl = alloc_rl(low, high);
	rl = cast_rl(get_type(var), rl);
	rl = rl_intersection(orig_rl, rl);
	if (!rl)
		return false;

	set_extra_expr_true_false(shift->right, alloc_estate_rl(rl), NULL);

	return true;
}

static void handle_AND_op(struct expression *var, sval_t known)
{
	struct range_list *orig_rl;
	struct range_list *true_rl = NULL;
	struct range_list *false_rl = NULL;
	int bit;
	sval_t low_mask = known;
	sval_t high_mask;
	sval_t max;

	get_absolute_rl(var, &orig_rl);

	if (known.value > 0) {
		bit = ffsll(known.value) - 1;
		low_mask.uvalue = (1ULL << bit) - 1;
		true_rl = remove_range(orig_rl, sval_type_val(known.type, 0), low_mask);
	}
	high_mask = get_high_mask(known);
	if (high_mask.value) {
		bit = ffsll(high_mask.value) - 1;
		low_mask.uvalue = (1ULL << bit) - 1;

		false_rl = orig_rl;
		if (sval_is_negative(rl_min(orig_rl)))
			false_rl = remove_range(false_rl, sval_type_min(known.type), sval_type_val(known.type, -1));
		false_rl = remove_range(false_rl, low_mask, sval_type_max(known.type));
		if (type_signed(high_mask.type) && type_unsigned(rl_type(false_rl))) {
			false_rl = remove_range(false_rl,
						sval_type_val(rl_type(false_rl), sval_type_max(known.type).uvalue),
					sval_type_val(rl_type(false_rl), -1));
		}
	} else if (known.value == 1 &&
		   get_hard_max(var, &max) &&
		   sval_cmp(max, rl_max(orig_rl)) == 0 &&
		   max.value & 1) {
		false_rl = remove_range(orig_rl, max, max);
	}
	set_extra_expr_true_false(var,
				  true_rl ? alloc_estate_rl(true_rl) : NULL,
				  false_rl ? alloc_estate_rl(false_rl) : NULL);
}

static void handle_AND_condition(struct expression *expr)
{
	sval_t known;

	if (handle_bit_test(expr))
		return;

	if (get_implied_value(expr->left, &known))
		handle_AND_op(expr->right, known);
	else if (get_implied_value(expr->right, &known))
		handle_AND_op(expr->left, known);
}

static void handle_MOD_condition(struct expression *expr)
{
	struct range_list *orig_rl;
	struct range_list *true_rl;
	struct range_list *false_rl = NULL;
	sval_t right;
	sval_t zero = { 0, };

	if (!get_implied_value(expr->right, &right) || right.value == 0)
		return;
	get_absolute_rl(expr->left, &orig_rl);

	zero.value = 0;
	zero.type = rl_type(orig_rl);

	/* We're basically dorking around the min and max here */
	true_rl = remove_range(orig_rl, zero, zero);
	if (!sval_is_max(rl_max(true_rl)) &&
	    !(rl_max(true_rl).value % right.value))
		true_rl = remove_range(true_rl, rl_max(true_rl), rl_max(true_rl));

	if (rl_equiv(true_rl, orig_rl))
		true_rl = NULL;

	if (sval_is_positive(rl_min(orig_rl)) &&
	    (rl_max(orig_rl).value - rl_min(orig_rl).value) / right.value < 5) {
		sval_t add;
		int i;

		add = rl_min(orig_rl);
		add.value += right.value - (add.value % right.value);
		add.value -= right.value;

		for (i = 0; i < 5; i++) {
			add.value += right.value;
			if (add.value > rl_max(orig_rl).value)
				break;
			add_range(&false_rl, add, add);
		}
	} else {
		if (rl_min(orig_rl).uvalue != 0 &&
		    rl_min(orig_rl).uvalue < right.uvalue) {
			sval_t chop = right;
			chop.value--;
			false_rl = remove_range(orig_rl, zero, chop);
		}

		if (!sval_is_max(rl_max(orig_rl)) &&
		    (rl_max(orig_rl).value % right.value)) {
			sval_t chop = rl_max(orig_rl);
			chop.value -= chop.value % right.value;
			chop.value++;
			if (!false_rl)
				false_rl = clone_rl(orig_rl);
			false_rl = remove_range(false_rl, chop, rl_max(orig_rl));
		}
	}

	set_extra_expr_true_false(expr->left,
				  true_rl ? alloc_estate_rl(true_rl) : NULL,
				  false_rl ? alloc_estate_rl(false_rl) : NULL);
}

/* this is actually hooked from smatch_implied.c...  it's hacky, yes */
void __extra_match_condition(struct expression *expr)
{
	expr = strip_expr(expr);
	switch (expr->type) {
	case EXPR_CALL:
		function_comparison(expr, SPECIAL_NOTEQUAL, zero_expr());
		return;
	case EXPR_PREOP:
	case EXPR_SYMBOL:
	case EXPR_DEREF:
		handle_comparison(get_type(expr), expr, SPECIAL_NOTEQUAL, zero_expr());
		return;
	case EXPR_COMPARE:
		match_comparison(expr);
		return;
	case EXPR_ASSIGNMENT:
		__extra_match_condition(expr->left);
		return;
	case EXPR_BINOP:
		if (expr->op == '&')
			handle_AND_condition(expr);
		if (expr->op == '%')
			handle_MOD_condition(expr);
		return;
	}
}

static void assume_indexes_are_valid(struct expression *expr)
{
	struct expression *array_expr;
	int array_size;
	struct expression *offset;
	struct symbol *offset_type;
	struct range_list *rl_before;
	struct range_list *rl_after;
	struct range_list *filter = NULL;
	sval_t size;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	offset = get_array_offset(expr);
	offset_type = get_type(offset);
	if (offset_type && type_signed(offset_type)) {
		filter = alloc_rl(sval_type_min(offset_type),
				  sval_type_val(offset_type, -1));
	}

	array_expr = get_array_base(expr);
	array_size = get_real_array_size(array_expr);
	if (array_size > 1) {
		size = sval_type_val(offset_type, array_size);
		add_range(&filter, size, sval_type_max(offset_type));
	}

	if (!filter)
		return;
	get_absolute_rl(offset, &rl_before);
	rl_after = rl_filter(rl_before, filter);
	if (rl_equiv(rl_before, rl_after))
		return;
	set_extra_expr_nomod(offset, alloc_estate_rl(rl_after));
}

/* returns 1 if it is not possible for expr to be value, otherwise returns 0 */
int implied_not_equal(struct expression *expr, long long val)
{
	return !possibly_false(expr, SPECIAL_NOTEQUAL, value_expr(val));
}

int implied_not_equal_name_sym(char *name, struct symbol *sym, long long val)
{
	struct smatch_state *estate;

	estate = get_state(SMATCH_EXTRA, name, sym);
	if (!estate)
		return 0;
	if (!rl_has_sval(estate_rl(estate), sval_type_val(estate_type(estate), 0)))
		return 1;
	return 0;
}

int parent_is_null_var_sym(const char *name, struct symbol *sym)
{
	char buf[256];
	char *start;
	char *end;
	struct smatch_state *state;

	strncpy(buf, name, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	start = &buf[0];
	while (*start == '*') {
		start++;
		state = get_state(SMATCH_EXTRA, start, sym);
		if (!state)
			continue;
		if (!estate_rl(state))
			return 1;
		if (estate_min(state).value == 0 &&
		    estate_max(state).value == 0)
			return 1;
	}

	start = &buf[0];
	while (*start == '&')
		start++;

	while ((end = strrchr(start, '-'))) {
		*end = '\0';
		state = __get_state(SMATCH_EXTRA, start, sym);
		if (!state)
			continue;
		if (estate_min(state).value == 0 &&
		    estate_max(state).value == 0)
			return 1;
	}
	return 0;
}

int parent_is_null(struct expression *expr)
{
	struct symbol *sym;
	char *var;
	int ret = 0;

	expr = strip_expr(expr);
	var = expr_to_var_sym(expr, &sym);
	if (!var || !sym)
		goto free;
	ret = parent_is_null_var_sym(var, sym);
free:
	free_string(var);
	return ret;
}

static int param_used_callback(void *found, int argc, char **argv, char **azColName)
{
	*(int *)found = 1;
	return 0;
}

static int is_kzalloc_info(struct sm_state *sm)
{
	sval_t sval;

	/*
	 * kzalloc() information is treated as special because so there is just
	 * a lot of stuff initialized to zero and it makes building the database
	 * take hours and hours.
	 *
	 * In theory, we should just remove this line and not pass any unused
	 * information, but I'm not sure enough that this code works so I want
	 * to hold off on that for now.
	 */
	if (!estate_get_single_value(sm->state, &sval))
		return 0;
	if (sval.value != 0)
		return 0;
	return 1;
}

static int is_really_long(struct sm_state *sm)
{
	const char *p;
	int cnt = 0;

	p = sm->name;
	while ((p = strstr(p, "->"))) {
		p += 2;
		cnt++;
	}

	if (cnt < 3 ||
	    strlen(sm->name) < 40)
		return 0;
	return 1;
}

static int filter_unused_param_value_info(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	int found = 0;

	/* for function pointers assume everything is used */
	if (call->fn->type != EXPR_SYMBOL)
		return 0;

	/*
	 * This is to handle __builtin_mul_overflow().  In an ideal world we
	 * would only need this for invalid code.
	 *
	 */
	if (!call->fn->symbol)
		return 0;

	if (!is_kzalloc_info(sm) && !is_really_long(sm))
		return 0;

	run_sql(&param_used_callback, &found,
		"select * from return_implies where %s and type = %d and parameter = %d and key = '%s';",
		get_static_filter(call->fn->symbol), PARAM_USED, param, printed_name);
	if (found)
		return 0;

	/* If the database is not built yet, then assume everything is used */
	run_sql(&param_used_callback, &found,
		"select * from return_implies where %s and type = %d;",
		get_static_filter(call->fn->symbol), PARAM_USED);
	if (!found)
		return 0;

	return 1;
}

struct range_list *intersect_with_real_abs_var_sym(const char *name, struct symbol *sym, struct range_list *start)
{
	struct smatch_state *state;

	/*
	 * Here is the difference between implied value and real absolute, say
	 * you have:
	 *
	 *	int a = (u8)x;
	 *
	 * Then you know that a is 0-255.  That's real absolute.  But you don't
	 * know for sure that it actually goes up to 255.  So it's not implied.
	 * Implied indicates a degree of certainty.
	 *
	 * But then say you cap "a" at 8.  That means you know it goes up to
	 * 8.  So now the implied value is s32min-8.  But you can combine it
	 * with the real absolute to say that actually it's 0-8.
	 *
	 * We are combining it here.  But now that I think about it, this is
	 * probably not the ideal place to combine it because it should proably
	 * be done earlier.  Oh well, this is an improvement on what was there
	 * before so I'm going to commit this code.
	 *
	 */

	state = get_real_absolute_state_var_sym(name, sym);
	if (!state || !estate_rl(state))
		return start;

	return rl_intersection(estate_rl(state), start);
}

struct range_list *intersect_with_real_abs_expr(struct expression *expr, struct range_list *start)
{
	struct smatch_state *state;
	struct range_list *abs_rl;

	state = get_real_absolute_state(expr);
	if (!state || !estate_rl(state))
		return start;

	abs_rl = cast_rl(rl_type(start), estate_rl(state));
	return rl_intersection(abs_rl, start);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	struct range_list *rl;
	sval_t dummy;

	if (estate_is_whole(sm->state))
		return;
	if (filter_unused_param_value_info(call, param, printed_name, sm))
		return;
	rl = estate_rl(sm->state);
	rl = intersect_with_real_abs_var_sym(sm->name, sm->sym, rl);
	sql_insert_caller_info(call, PARAM_VALUE, param, printed_name, show_rl(rl));
	if (!estate_get_single_value(sm->state, &dummy)) {
		if (estate_has_hard_max(sm->state))
			sql_insert_caller_info(call, HARD_MAX, param, printed_name,
					       sval_to_str(estate_max(sm->state)));
		if (estate_has_fuzzy_max(sm->state))
			sql_insert_caller_info(call, FUZZY_MAX, param, printed_name,
					       sval_to_str(estate_get_fuzzy_max(sm->state)));
	}
}

static void returned_struct_members(int return_id, char *return_ranges, struct expression *expr)
{
	struct symbol *returned_sym;
	char *returned_name;
	struct sm_state *sm;
	char *compare_str;
	char name_buf[256];
	char val_buf[256];
	int len;

	// FIXME handle *$

	if (!is_pointer(expr))
		return;

	returned_name = expr_to_var_sym(expr, &returned_sym);
	if (!returned_name || !returned_sym)
		goto free;
	len = strlen(returned_name);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (!estate_rl(sm->state))
			continue;
		if (returned_sym != sm->sym)
			continue;
		if (strncmp(returned_name, sm->name, len) != 0)
			continue;
		if (sm->name[len] != '-')
			continue;

		snprintf(name_buf, sizeof(name_buf), "$%s", sm->name + len);

		compare_str = name_sym_to_param_comparison(sm->name, sm->sym);
		if (!compare_str && estate_is_whole(sm->state))
			continue;
		snprintf(val_buf, sizeof(val_buf), "%s%s", sm->state->name, compare_str ?: "");

		sql_insert_return_states(return_id, return_ranges, PARAM_VALUE,
					 -1, name_buf, val_buf);
	} END_FOR_EACH_SM(sm);

free:
	free_string(returned_name);
}

static void db_limited_before(void)
{
	unmatched_stree = clone_stree(__get_cur_stree());
}

static void db_limited_after(void)
{
	free_stree(&unmatched_stree);
}

static int basically_the_same(struct range_list *orig, struct range_list *new)
{
	if (rl_equiv(orig, new))
		return 1;

	/*
	 * The whole range is essentially the same as 0,4096-27777777777 so
	 * don't overwrite the implications just to store that.
	 *
	 */
	if (rl_type(orig)->type == SYM_PTR &&
	    is_whole_rl(orig) &&
	    rl_min(new).value == 0 &&
	    rl_max(new).value == valid_ptr_max)
		return 1;
	return 0;
}

static void db_param_limit_binops(struct expression *arg, char *key, struct range_list *rl)
{
	struct range_list *left_rl;
	sval_t zero = {	.type = rl_type(rl), };
	sval_t sval;

	if (arg->op != '*')
		return;
	if (!get_implied_value(arg->right, &sval))
		return;
	if (can_integer_overflow(get_type(arg), arg))
		return;

	left_rl = rl_binop(rl, '/', alloc_rl(sval, sval));
	if (!rl_has_sval(rl, zero))
		left_rl = remove_range(left_rl, zero, zero);

	set_extra_expr_nomod(arg->left, alloc_estate_rl(left_rl));
}

static void db_param_limit_filter(struct expression *expr, int param, char *key, char *value, enum info_type op)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;
	struct var_sym_list *vsl = NULL;
	struct sm_state *sm;
	struct symbol *compare_type, *var_type;
	struct range_list *rl;
	struct range_list *limit;
	struct range_list *new;
	char *other_name;
	struct symbol *other_sym;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	if (strcmp(key, "$") == 0)
		compare_type = get_arg_type(expr->fn, param);
	else
		compare_type = get_member_type_from_key(arg, key);

	call_results_to_rl(expr, compare_type, value, &limit);
	if (strcmp(key, "$") == 0)
		move_known_to_rl(&arg, &limit);
	name = get_chunk_from_key(arg, key, &sym, &vsl);
	if (!name)
		return;
	if (op != PARAM_LIMIT && !sym)
		goto free;

	sm = get_sm_state(SMATCH_EXTRA, name, sym);
	if (sm)
		rl = estate_rl(sm->state);
	else
		rl = alloc_whole_rl(compare_type);

	if (op == PARAM_LIMIT && !rl_fits_in_type(rl, compare_type))
		goto free;

	new = rl_intersection(rl, limit);

	var_type = get_member_type_from_key(arg, key);
	new = cast_rl(var_type, new);

	/* We want to preserve the implications here */
	if (sm && basically_the_same(rl, new))
		goto free;
	other_name = get_other_name_sym(name, sym, &other_sym);

	if (op == PARAM_LIMIT)
		set_extra_nomod_vsl(name, sym, vsl, NULL, alloc_estate_rl(new));
	else
		set_extra_mod(name, sym, NULL, alloc_estate_rl(new));

	if (other_name && other_sym) {
		if (op == PARAM_LIMIT)
			set_extra_nomod_vsl(other_name, other_sym, vsl, NULL, alloc_estate_rl(new));
		else
			set_extra_mod(other_name, other_sym, NULL, alloc_estate_rl(new));
	}

	if (op == PARAM_LIMIT && arg->type == EXPR_BINOP)
		db_param_limit_binops(arg, key, new);
free:
	free_string(name);
}

static void db_param_limit(struct expression *expr, int param, char *key, char *value)
{
	db_param_limit_filter(expr, param, key, value, PARAM_LIMIT);
}

static void db_param_filter(struct expression *expr, int param, char *key, char *value)
{
	db_param_limit_filter(expr, param, key, value, PARAM_FILTER);
}

static void db_param_add_set(struct expression *expr, int param, char *key, char *value, enum info_type op)
{
	struct expression *arg;
	char *name;
	char *other_name = NULL;
	struct symbol *sym, *other_sym;
	struct symbol *param_type, *arg_type;
	struct smatch_state *state;
	struct range_list *new = NULL;
	struct range_list *added = NULL;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;

	arg_type = get_arg_type_from_key(expr->fn, param, arg, key);
	param_type = get_member_type_from_key(arg, key);
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	state = get_state(SMATCH_EXTRA, name, sym);
	if (state)
		new = estate_rl(state);

	call_results_to_rl(expr, arg_type, value, &added);
	added = cast_rl(param_type, added);
	if (op == PARAM_SET)
		new = added;
	else
		new = rl_union(new, added);

	other_name = get_other_name_sym_nostack(name, sym, &other_sym);
	set_extra_mod(name, sym, NULL, alloc_estate_rl(new));
	if (other_name && other_sym)
		set_extra_mod(other_name, other_sym, NULL, alloc_estate_rl(new));
free:
	free_string(other_name);
	free_string(name);
}

static void db_param_add(struct expression *expr, int param, char *key, char *value)
{
	in_param_set = true;
	db_param_add_set(expr, param, key, value, PARAM_ADD);
	in_param_set = false;
}

static void db_param_set(struct expression *expr, int param, char *key, char *value)
{
	in_param_set = true;
	db_param_add_set(expr, param, key, value, PARAM_SET);
	in_param_set = false;
}

static void match_lost_param(struct expression *call, int param)
{
	struct expression *arg;

	if (is_const_param(call->fn, param))
		return;

	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;

	arg = strip_expr(arg);
	if (arg->type == EXPR_PREOP && arg->op == '&')
		set_extra_expr_mod(arg->unop, alloc_estate_whole(get_type(arg->unop)));
	else
		; /* if pointer then set struct members, maybe?*/
}

static void db_param_value(struct expression *expr, int param, char *key, char *value)
{
	struct expression *call;
	char *name;
	struct symbol *sym;
	struct symbol *type;
	struct range_list *rl = NULL;

	if (param != -1)
		return;

	call = expr;
	while (call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (call->type != EXPR_CALL)
		return;

	type = get_member_type_from_key(expr->left, key);
	name = get_variable_from_key(expr->left, key, &sym);
	if (!name || !sym)
		goto free;

	call_results_to_rl(call, type, value, &rl);

	set_extra_mod(name, sym, NULL, alloc_estate_rl(rl));
free:
	free_string(name);
}

static void match_call_info(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl = NULL;
	struct expression *arg;
	struct symbol *type;
	sval_t dummy;
	int i = 0;

	FOR_EACH_PTR(expr->args, arg) {
		type = get_arg_type(expr->fn, i);

		get_absolute_rl(arg, &rl);
		rl = cast_rl(type, rl);

		if (!is_whole_rl(rl)) {
			rl = intersect_with_real_abs_expr(arg, rl);
			sql_insert_caller_info(expr, PARAM_VALUE, i, "$", show_rl(rl));
		}
		state = get_state_expr(SMATCH_EXTRA, arg);
		if (!estate_get_single_value(state, &dummy) && estate_has_hard_max(state)) {
			sql_insert_caller_info(expr, HARD_MAX, i, "$",
					       sval_to_str(estate_max(state)));
		}
		if (estate_has_fuzzy_max(state)) {
			sql_insert_caller_info(expr, FUZZY_MAX, i, "$",
					       sval_to_str(estate_get_fuzzy_max(state)));
		}
		i++;
	} END_FOR_EACH_PTR(arg);
}

static void set_param_value(const char *name, struct symbol *sym, char *key, char *value)
{
	struct expression *expr;
	struct range_list *rl = NULL;
	struct smatch_state *state;
	struct symbol *type;
	char fullname[256];
	char *key_orig = key;
	bool add_star = false;
	sval_t dummy;

	if (key[0] == '*') {
		add_star = true;
		key++;
	}

	snprintf(fullname, 256, "%s%s%s", add_star ? "*" : "", name, key + 1);

	expr = symbol_expression(sym);
	type = get_member_type_from_key(expr, key_orig);
	str_to_rl(type, value, &rl);
	state = alloc_estate_rl(rl);
	if (estate_get_single_value(state, &dummy))
		estate_set_hard_max(state);
	set_state(SMATCH_EXTRA, fullname, sym, state);
}

static void set_param_fuzzy_max(const char *name, struct symbol *sym, char *key, char *value)
{
	struct range_list *rl = NULL;
	struct smatch_state *state;
	struct symbol *type;
	char fullname[256];
	sval_t max;

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	state = get_state(SMATCH_EXTRA, fullname, sym);
	if (!state)
		return;
	type = estate_type(state);
	str_to_rl(type, value, &rl);
	if (!rl_to_sval(rl, &max))
		return;
	estate_set_fuzzy_max(state, max);
}

static void set_param_hard_max(const char *name, struct symbol *sym, char *key, char *value)
{
	struct smatch_state *state;
	char fullname[256];

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	state = get_state(SMATCH_EXTRA, fullname, sym);
	if (!state)
		return;
	estate_set_hard_max(state);
}

struct sm_state *get_extra_sm_state(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct sm_state *ret = NULL;

	name = expr_to_known_chunk_sym(expr, &sym);
	if (!name)
		goto free;

	ret = get_sm_state(SMATCH_EXTRA, name, sym);
free:
	free_string(name);
	return ret;
}

struct smatch_state *get_extra_state(struct expression *expr)
{
	struct sm_state *sm;

	sm = get_extra_sm_state(expr);
	if (!sm)
		return NULL;
	return sm->state;
}

void register_smatch_extra(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_merge_hook(my_id, &merge_estates);
	add_unmatched_state_hook(my_id, &unmatched_state);
	select_caller_info_hook(set_param_value, PARAM_VALUE);
	select_caller_info_hook(set_param_fuzzy_max, FUZZY_MAX);
	select_caller_info_hook(set_param_hard_max, HARD_MAX);
	select_return_states_before(&db_limited_before);
	select_return_states_hook(PARAM_LIMIT, &db_param_limit);
	select_return_states_hook(PARAM_FILTER, &db_param_filter);
	select_return_states_hook(PARAM_ADD, &db_param_add);
	select_return_states_hook(PARAM_SET, &db_param_set);
	add_lost_param_hook(&match_lost_param);
	select_return_states_hook(PARAM_VALUE, &db_param_value);
	select_return_states_after(&db_limited_after);
}

static void match_link_modify(struct sm_state *sm, struct expression *mod_expr)
{
	struct var_sym_list *links;
	struct var_sym *tmp;
	struct smatch_state *state;

	links = sm->state->data;

	FOR_EACH_PTR(links, tmp) {
		if (sm->sym == tmp->sym &&
		    strcmp(sm->name, tmp->var) == 0)
			continue;
		state = get_state(SMATCH_EXTRA, tmp->var, tmp->sym);
		if (!state)
			continue;
		set_state(SMATCH_EXTRA, tmp->var, tmp->sym, alloc_estate_whole(estate_type(state)));
	} END_FOR_EACH_PTR(tmp);
	set_state(link_id, sm->name, sm->sym, &undefined);
}

void register_smatch_extra_links(int id)
{
	link_id = id;
	set_dynamic_states(link_id);
}

void register_smatch_extra_late(int id)
{
	add_merge_hook(link_id, &merge_link_states);
	add_modification_hook(link_id, &match_link_modify);
	add_hook(&match_dereferences, DEREF_HOOK);
	add_hook(&match_pointer_as_array, OP_HOOK);
	select_return_implies_hook(DEREFERENCE, &set_param_dereferenced);
	add_hook(&match_function_call, FUNCTION_CALL_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_assign, GLOBAL_ASSIGNMENT_HOOK);
	add_hook(&unop_expr, OP_HOOK);
	add_hook(&asm_expr, ASM_HOOK);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	add_split_return_callback(&returned_struct_members);

//	add_hook(&assume_indexes_are_valid, OP_HOOK);
}

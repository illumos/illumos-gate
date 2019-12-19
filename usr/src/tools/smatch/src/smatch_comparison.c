/*
 * Copyright (C) 2012 Oracle.
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
 * The point here is to store the relationships between two variables.
 * Ie:  y > x.
 * To do that we create a state with the two variables in alphabetical order:
 * ->name = "x vs y" and the state would be "<".  On the false path the state
 * would be ">=".
 *
 * Part of the trick of it is that if x or y is modified then we need to reset
 * the state.  We need to keep a list of all the states which depend on x and
 * all the states which depend on y.  The link_id code handles this.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

int comparison_id;
static int link_id;
static int inc_dec_id;
static int inc_dec_link_id;

static void add_comparison(struct expression *left, int comparison, struct expression *right);

/* for handling for loops */
STATE(start);
STATE(incremented);

ALLOCATOR(compare_data, "compare data");

static struct symbol *vsl_to_sym(struct var_sym_list *vsl)
{
	struct var_sym *vs;

	if (!vsl)
		return NULL;
	if (ptr_list_size((struct ptr_list *)vsl) != 1)
		return NULL;
	vs = first_ptr_list((struct ptr_list *)vsl);
	return vs->sym;
}

static const char *show_comparison(int comparison)
{
	if (comparison == IMPOSSIBLE_COMPARISON)
		return "impossible";
	if (comparison == UNKNOWN_COMPARISON)
		return "unknown";
	return show_special(comparison);
}

struct smatch_state *alloc_compare_state(
		struct expression *left,
		const char *left_var, struct var_sym_list *left_vsl,
		int comparison,
		struct expression *right,
		const char *right_var, struct var_sym_list *right_vsl)
{
	struct smatch_state *state;
	struct compare_data *data;

	state = __alloc_smatch_state(0);
	state->name = alloc_sname(show_comparison(comparison));
	data = __alloc_compare_data(0);
	data->left = left;
	data->left_var = alloc_sname(left_var);
	data->left_vsl = clone_var_sym_list(left_vsl);
	data->comparison = comparison;
	data->right = right;
	data->right_var = alloc_sname(right_var);
	data->right_vsl = clone_var_sym_list(right_vsl);
	state->data = data;
	return state;
}

int state_to_comparison(struct smatch_state *state)
{
	if (!state || !state->data)
		return UNKNOWN_COMPARISON;
	return ((struct compare_data *)state->data)->comparison;
}

/*
 * flip_comparison() reverses the op left and right.  So "x >= y" becomes "y <= x".
 */
int flip_comparison(int op)
{
	switch (op) {
	case UNKNOWN_COMPARISON:
		return UNKNOWN_COMPARISON;
	case '<':
		return '>';
	case SPECIAL_UNSIGNED_LT:
		return SPECIAL_UNSIGNED_GT;
	case SPECIAL_LTE:
		return SPECIAL_GTE;
	case SPECIAL_UNSIGNED_LTE:
		return SPECIAL_UNSIGNED_GTE;
	case SPECIAL_EQUAL:
		return SPECIAL_EQUAL;
	case SPECIAL_NOTEQUAL:
		return SPECIAL_NOTEQUAL;
	case SPECIAL_GTE:
		return SPECIAL_LTE;
	case SPECIAL_UNSIGNED_GTE:
		return SPECIAL_UNSIGNED_LTE;
	case '>':
		return '<';
	case SPECIAL_UNSIGNED_GT:
		return SPECIAL_UNSIGNED_LT;
	case IMPOSSIBLE_COMPARISON:
		return UNKNOWN_COMPARISON;
	default:
		sm_perror("unhandled comparison %d", op);
		return op;
	}
}

int negate_comparison(int op)
{
	switch (op) {
	case UNKNOWN_COMPARISON:
		return UNKNOWN_COMPARISON;
	case '<':
		return SPECIAL_GTE;
	case SPECIAL_UNSIGNED_LT:
		return SPECIAL_UNSIGNED_GTE;
	case SPECIAL_LTE:
		return '>';
	case SPECIAL_UNSIGNED_LTE:
		return SPECIAL_UNSIGNED_GT;
	case SPECIAL_EQUAL:
		return SPECIAL_NOTEQUAL;
	case SPECIAL_NOTEQUAL:
		return SPECIAL_EQUAL;
	case SPECIAL_GTE:
		return '<';
	case SPECIAL_UNSIGNED_GTE:
		return SPECIAL_UNSIGNED_LT;
	case '>':
		return SPECIAL_LTE;
	case SPECIAL_UNSIGNED_GT:
		return SPECIAL_UNSIGNED_LTE;
	case IMPOSSIBLE_COMPARISON:
		return UNKNOWN_COMPARISON;
	default:
		sm_perror("unhandled comparison %d", op);
		return op;
	}
}

static int rl_comparison(struct range_list *left_rl, struct range_list *right_rl)
{
	sval_t left_min, left_max, right_min, right_max;
	struct symbol *type = &int_ctype;

	if (!left_rl || !right_rl)
		return UNKNOWN_COMPARISON;

	if (type_positive_bits(rl_type(left_rl)) > type_positive_bits(type))
		type = rl_type(left_rl);
	if (type_positive_bits(rl_type(right_rl)) > type_positive_bits(type))
		type = rl_type(right_rl);

	left_rl = cast_rl(type, left_rl);
	right_rl = cast_rl(type, right_rl);

	left_min = rl_min(left_rl);
	left_max = rl_max(left_rl);
	right_min = rl_min(right_rl);
	right_max = rl_max(right_rl);

	if (left_min.value == left_max.value &&
	    right_min.value == right_max.value &&
	    left_min.value == right_min.value)
		return SPECIAL_EQUAL;

	if (sval_cmp(left_max, right_min) < 0)
		return '<';
	if (sval_cmp(left_max, right_min) == 0)
		return SPECIAL_LTE;
	if (sval_cmp(left_min, right_max) > 0)
		return '>';
	if (sval_cmp(left_min, right_max) == 0)
		return SPECIAL_GTE;

	return UNKNOWN_COMPARISON;
}

static int comparison_from_extra(struct expression *a, struct expression *b)
{
	struct range_list *left, *right;

	if (!get_implied_rl(a, &left))
		return UNKNOWN_COMPARISON;
	if (!get_implied_rl(b, &right))
		return UNKNOWN_COMPARISON;

	return rl_comparison(left, right);
}

static struct range_list *get_orig_rl(struct var_sym_list *vsl)
{
	struct symbol *sym;
	struct smatch_state *state;

	if (!vsl)
		return NULL;
	sym = vsl_to_sym(vsl);
	if (!sym || !sym->ident)
		return NULL;
	state = get_orig_estate(sym->ident->name, sym);
	return estate_rl(state);
}

static struct smatch_state *unmatched_comparison(struct sm_state *sm)
{
	struct compare_data *data = sm->state->data;
	struct range_list *left_rl, *right_rl;
	int op = UNKNOWN_COMPARISON;

	if (!data)
		return &undefined;

	if (is_impossible_path()) {
		op = IMPOSSIBLE_COMPARISON;
		goto alloc;
	}

	if (strstr(data->left_var, " orig"))
		left_rl = get_orig_rl(data->left_vsl);
	else if (!get_implied_rl_var_sym(data->left_var, vsl_to_sym(data->left_vsl), &left_rl))
		goto alloc;

	if (strstr(data->right_var, " orig"))
		right_rl = get_orig_rl(data->right_vsl);
	else if (!get_implied_rl_var_sym(data->right_var, vsl_to_sym(data->right_vsl), &right_rl))
		goto alloc;

	op = rl_comparison(left_rl, right_rl);

alloc:
	return alloc_compare_state(data->left, data->left_var, data->left_vsl,
				   op,
				   data->right, data->right_var, data->right_vsl);
}

/* remove_unsigned_from_comparison() is obviously a hack. */
int remove_unsigned_from_comparison(int op)
{
	switch (op) {
	case SPECIAL_UNSIGNED_LT:
		return '<';
	case SPECIAL_UNSIGNED_LTE:
		return SPECIAL_LTE;
	case SPECIAL_UNSIGNED_GTE:
		return SPECIAL_GTE;
	case SPECIAL_UNSIGNED_GT:
		return '>';
	default:
		return op;
	}
}

/*
 * This is for when you merge states "a < b" and "a == b", the result is that
 * we can say for sure, "a <= b" after the merge.
 */
int merge_comparisons(int one, int two)
{
	int LT, EQ, GT;

	if (one == UNKNOWN_COMPARISON || two == UNKNOWN_COMPARISON)
		return UNKNOWN_COMPARISON;

	if (one == IMPOSSIBLE_COMPARISON)
		return two;
	if (two == IMPOSSIBLE_COMPARISON)
		return one;

	one = remove_unsigned_from_comparison(one);
	two = remove_unsigned_from_comparison(two);

	if (one == two)
		return one;

	LT = EQ = GT = 0;

	switch (one) {
	case '<':
		LT = 1;
		break;
	case SPECIAL_LTE:
		LT = 1;
		EQ = 1;
		break;
	case SPECIAL_EQUAL:
		EQ = 1;
		break;
	case SPECIAL_GTE:
		GT = 1;
		EQ = 1;
		break;
	case '>':
		GT = 1;
	}

	switch (two) {
	case '<':
		LT = 1;
		break;
	case SPECIAL_LTE:
		LT = 1;
		EQ = 1;
		break;
	case SPECIAL_EQUAL:
		EQ = 1;
		break;
	case SPECIAL_GTE:
		GT = 1;
		EQ = 1;
		break;
	case '>':
		GT = 1;
	}

	if (LT && EQ && GT)
		return UNKNOWN_COMPARISON;
	if (LT && EQ)
		return SPECIAL_LTE;
	if (LT && GT)
		return SPECIAL_NOTEQUAL;
	if (LT)
		return '<';
	if (EQ && GT)
		return SPECIAL_GTE;
	if (GT)
		return '>';
	return UNKNOWN_COMPARISON;
}

/*
 * This is for if you have "a < b" and "b <= c" and you want to see how "a
 * compares to c".  You would call this like get_combined_comparison('<', '<=').
 * The return comparison would be '<'.
 */
int combine_comparisons(int left_compare, int right_compare)
{
	int LT, EQ, GT;

	left_compare = remove_unsigned_from_comparison(left_compare);
	right_compare = remove_unsigned_from_comparison(right_compare);

	LT = EQ = GT = 0;

	switch (left_compare) {
	case '<':
		LT++;
		break;
	case SPECIAL_LTE:
		LT++;
		EQ++;
		break;
	case SPECIAL_EQUAL:
		return right_compare;
	case SPECIAL_GTE:
		GT++;
		EQ++;
		break;
	case '>':
		GT++;
	}

	switch (right_compare) {
	case '<':
		LT++;
		break;
	case SPECIAL_LTE:
		LT++;
		EQ++;
		break;
	case SPECIAL_EQUAL:
		return left_compare;
	case SPECIAL_GTE:
		GT++;
		EQ++;
		break;
	case '>':
		GT++;
	}

	if (LT == 2) {
		if (EQ == 2)
			return SPECIAL_LTE;
		return '<';
	}

	if (GT == 2) {
		if (EQ == 2)
			return SPECIAL_GTE;
		return '>';
	}
	return UNKNOWN_COMPARISON;
}

/*
 * This is mostly used when you know from extra state that a <= b but you
 * know from comparisons that a != b so then if take the intersection then
 * we know that a < b.  The name is taken from the fact that the intersection
 * of < and <= is <.
 */
int comparison_intersection(int left_compare, int right_compare)
{
	int LT, GT, EQ, NE, total;

	if (left_compare == IMPOSSIBLE_COMPARISON ||
	    right_compare == IMPOSSIBLE_COMPARISON)
		return IMPOSSIBLE_COMPARISON;

	left_compare = remove_unsigned_from_comparison(left_compare);
	right_compare = remove_unsigned_from_comparison(right_compare);

	LT = GT = EQ = NE = total = 0;

	/* Only one side is known. */
	if (!left_compare)
		return right_compare;
	if (!right_compare)
		return left_compare;

	switch (left_compare) {
	case '<':
		LT++;
		total += 1;
		break;
	case SPECIAL_LTE:
		LT++;
		EQ++;
		total += 2;
		break;
	case SPECIAL_EQUAL:
		EQ++;
		total += 1;
		break;
	case SPECIAL_NOTEQUAL:
		NE++;
		total += 1;
		break;
	case SPECIAL_GTE:
		GT++;
		EQ++;
		total += 2;
		break;
	case '>':
		GT++;
		total += 1;
		break;
	default:
		return UNKNOWN_COMPARISON;
	}

	switch (right_compare) {
	case '<':
		LT++;
		total += 1;
		break;
	case SPECIAL_LTE:
		LT++;
		EQ++;
		total += 2;
		break;
	case SPECIAL_EQUAL:
		EQ++;
		total += 1;
		break;
	case SPECIAL_NOTEQUAL:
		NE++;
		total += 1;
		break;
	case SPECIAL_GTE:
		GT++;
		EQ++;
		total += 2;
		break;
	case '>':
		GT++;
		total += 1;
		break;
	default:
		return UNKNOWN_COMPARISON;
	}

	if (LT == 2) {
		if (EQ == 2)
			return SPECIAL_LTE;
		return '<';
	}

	if (GT == 2) {
		if (EQ == 2)
			return SPECIAL_GTE;
		return '>';
	}
	if (EQ == 2)
		return SPECIAL_EQUAL;
	if (total == 2 && EQ && NE)
		return IMPOSSIBLE_COMPARISON;
	if (GT && LT)
		return IMPOSSIBLE_COMPARISON;
	if (GT && NE)
		return '>';
	if (LT && NE)
		return '<';
	if (NE == 2)
		return SPECIAL_NOTEQUAL;
	if (total == 2 && (LT || GT) && EQ)
		return IMPOSSIBLE_COMPARISON;

	return UNKNOWN_COMPARISON;
}

static void pre_merge_hook(struct sm_state *cur, struct sm_state *other)
{
	struct compare_data *data = cur->state->data;
	int extra, new;
	static bool in_recurse;

	// FIXME.  No data is useless
	if (!data)
		return;

	if (in_recurse)
		return;
	in_recurse = true;
	extra = comparison_from_extra(data->left, data->right);
	in_recurse = false;
	if (!extra)
		return;
	new = comparison_intersection(extra, data->comparison);
	if (new == data->comparison)
		return;

	// FIXME: we should always preserve implications
	set_state(comparison_id, cur->name, NULL,
		  alloc_compare_state(data->left, data->left_var, data->left_vsl,
				      new,
				      data->right, data->right_var, data->right_vsl));
}

struct smatch_state *merge_compare_states(struct smatch_state *s1, struct smatch_state *s2)
{
	struct compare_data *data = s1->data;
	int op;

	if (!data)
		return &undefined;

	op = merge_comparisons(state_to_comparison(s1), state_to_comparison(s2));
	return alloc_compare_state(
			data->left, data->left_var, data->left_vsl,
			op,
			data->right, data->right_var, data->right_vsl);
}

static struct smatch_state *alloc_link_state(struct string_list *links)
{
	struct smatch_state *state;
	static char buf[256];
	char *tmp;
	int i;

	state = __alloc_smatch_state(0);

	i = 0;
	FOR_EACH_PTR(links, tmp) {
		if (!i++) {
			snprintf(buf, sizeof(buf), "%s", tmp);
		} else {
			append(buf, ", ", sizeof(buf));
			append(buf, tmp, sizeof(buf));
		}
	} END_FOR_EACH_PTR(tmp);

	state->name = alloc_sname(buf);
	state->data = links;
	return state;
}

static void save_start_states(struct statement *stmt)
{
	struct symbol *param;
	char orig[64];
	char state_name[128];
	struct smatch_state *state;
	struct string_list *links;
	char *link;

	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, param) {
		struct var_sym_list *left_vsl = NULL;
		struct var_sym_list *right_vsl = NULL;

		if (!param->ident)
			continue;
		snprintf(orig, sizeof(orig), "%s orig", param->ident->name);
		snprintf(state_name, sizeof(state_name), "%s vs %s", param->ident->name, orig);
		add_var_sym(&left_vsl, param->ident->name, param);
		add_var_sym(&right_vsl, orig, param);
		state = alloc_compare_state(
				NULL, param->ident->name, left_vsl,
				SPECIAL_EQUAL,
				NULL, alloc_sname(orig), right_vsl);
		set_state(comparison_id, state_name, NULL, state);

		link = alloc_sname(state_name);
		links = NULL;
		insert_string(&links, link);
		state = alloc_link_state(links);
		set_state(link_id, param->ident->name, param, state);
	} END_FOR_EACH_PTR(param);
}

static struct smatch_state *merge_links(struct smatch_state *s1, struct smatch_state *s2)
{
	struct smatch_state *ret;
	struct string_list *links;

	links = combine_string_lists(s1->data, s2->data);
	ret = alloc_link_state(links);
	return ret;
}

static void save_link_var_sym(const char *var, struct symbol *sym, const char *link)
{
	struct smatch_state *old_state, *new_state;
	struct string_list *links;
	char *new;

	old_state = get_state(link_id, var, sym);
	if (old_state)
		links = clone_str_list(old_state->data);
	else
		links = NULL;

	new = alloc_sname(link);
	insert_string(&links, new);

	new_state = alloc_link_state(links);
	set_state(link_id, var, sym, new_state);
}

static void match_inc(struct sm_state *sm, bool preserve)
{
	struct string_list *links;
	struct smatch_state *state, *new;
	struct compare_data *data;
	char *tmp;
	int flip;
	int op;

	links = sm->state->data;

	FOR_EACH_PTR(links, tmp) {
		state = get_state(comparison_id, tmp, NULL);
		if (!state)
			continue;
		data = state->data;
		if (!data)
			continue;

		flip = 0;
		if (strncmp(sm->name, tmp, strlen(sm->name)) != 0 ||
		    tmp[strlen(sm->name)] != ' ')
			flip = 1;

		op = state_to_comparison(state);

		switch (flip ? flip_comparison(op) : op) {
		case SPECIAL_EQUAL:
		case SPECIAL_GTE:
		case SPECIAL_UNSIGNED_GTE:
		case '>':
		case SPECIAL_UNSIGNED_GT:
			if (preserve)
				break;
			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					flip ? '<' : '>',
					data->right, data->right_var, data->right_vsl);
			set_state(comparison_id, tmp, NULL, new);
			break;
		case '<':
		case SPECIAL_UNSIGNED_LT:
			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					flip ? SPECIAL_GTE : SPECIAL_LTE,
					data->right, data->right_var, data->right_vsl);
			set_state(comparison_id, tmp, NULL, new);
			break;
		default:
			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					UNKNOWN_COMPARISON,
					data->right, data->right_var, data->right_vsl);
			set_state(comparison_id, tmp, NULL, new);
		}
	} END_FOR_EACH_PTR(tmp);
}

static void match_dec(struct sm_state *sm, bool preserve)
{
	struct string_list *links;
	struct smatch_state *state;
	char *tmp;

	links = sm->state->data;

	FOR_EACH_PTR(links, tmp) {
		struct compare_data *data;
		struct smatch_state *new;

		state = get_state(comparison_id, tmp, NULL);
		if (!state || !state->data)
			continue;

		data = state->data;

		switch (state_to_comparison(state)) {
		case SPECIAL_EQUAL:
		case SPECIAL_LTE:
		case SPECIAL_UNSIGNED_LTE:
		case '<':
		case SPECIAL_UNSIGNED_LT: {
			if (preserve)
				break;

			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					'<',
					data->right, data->right_var, data->right_vsl);
			set_state(comparison_id, tmp, NULL, new);
			break;
			}
		default:
			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					UNKNOWN_COMPARISON,
					data->right, data->right_var, data->right_vsl);
			set_state(comparison_id, tmp, NULL, new);
		}
	} END_FOR_EACH_PTR(tmp);
}

static void reset_sm(struct sm_state *sm)
{
	struct string_list *links;
	char *tmp;

	links = sm->state->data;

	FOR_EACH_PTR(links, tmp) {
		struct smatch_state *old, *new;

		old = get_state(comparison_id, tmp, NULL);
		if (!old || !old->data) {
			new = &undefined;
		} else {
			struct compare_data *data = old->data;

			new = alloc_compare_state(
					data->left, data->left_var, data->left_vsl,
					UNKNOWN_COMPARISON,
					data->right, data->right_var, data->right_vsl);
		}
		set_state(comparison_id, tmp, NULL, new);
	} END_FOR_EACH_PTR(tmp);
	set_state(link_id, sm->name, sm->sym, &undefined);
}

static bool match_add_sub_assign(struct sm_state *sm, struct expression *expr)
{
	struct range_list *rl;
	sval_t zero = { .type = &int_ctype };

	if (!expr || expr->type != EXPR_ASSIGNMENT)
		return false;
	if (expr->op != SPECIAL_ADD_ASSIGN && expr->op != SPECIAL_SUB_ASSIGN)
		return false;

	get_absolute_rl(expr->right, &rl);
	if (sval_is_negative(rl_min(rl))) {
		reset_sm(sm);
		return false;
	}

	if (expr->op == SPECIAL_ADD_ASSIGN)
		match_inc(sm, rl_has_sval(rl, zero));
	else
		match_dec(sm, rl_has_sval(rl, zero));
	return true;
}

static void match_inc_dec(struct sm_state *sm, struct expression *mod_expr)
{
	/*
	 * if (foo > bar) then ++foo is also > bar.
	 */
	if (!mod_expr)
		return;
	if (match_add_sub_assign(sm, mod_expr))
		return;
	if (mod_expr->type != EXPR_PREOP && mod_expr->type != EXPR_POSTOP)
		return;

	if (mod_expr->op == SPECIAL_INCREMENT)
		match_inc(sm, false);
	else if (mod_expr->op == SPECIAL_DECREMENT)
		match_dec(sm, false);
}

static int is_self_assign(struct expression *expr)
{
	if (!expr || expr->type != EXPR_ASSIGNMENT || expr->op != '=')
		return 0;
	return expr_equiv(expr->left, expr->right);
}

static void match_modify(struct sm_state *sm, struct expression *mod_expr)
{
	if (mod_expr && is_self_assign(mod_expr))
		return;

	/* handled by match_inc_dec() */
	if (mod_expr &&
	    ((mod_expr->type == EXPR_PREOP || mod_expr->type == EXPR_POSTOP) &&
	     (mod_expr->op == SPECIAL_INCREMENT || mod_expr->op == SPECIAL_DECREMENT)))
		return;
	if (mod_expr && mod_expr->type == EXPR_ASSIGNMENT &&
	    (mod_expr->op == SPECIAL_ADD_ASSIGN || mod_expr->op == SPECIAL_SUB_ASSIGN))
		return;

	reset_sm(sm);
}

static void match_preop(struct expression *expr)
{
	struct expression *parent;
	struct range_list *left, *right;
	int op;

	/*
	 * This is an important special case.  Say you have:
	 *
	 * 	if (++j == limit)
	 *
	 * Assume that we know the range of limit is higher than the start
	 * value for "j".  Then the first thing that we process is the ++j.  We
	 * have not comparison states set up so it doesn't get caught by the
	 * modification hook.  But it does get caught by smatch_extra which sets
	 * j to unknown then we parse the "j == limit" and sets false to != but
	 * really we want false to be <.
	 *
	 * So what we do is we set j < limit here, then the match_modify catches
	 * it and we do a match_inc_dec().
	 *
	 */

	if (expr->type != EXPR_PREOP ||
	    (expr->op != SPECIAL_INCREMENT && expr->op != SPECIAL_DECREMENT))
		return;

	parent = expr_get_parent_expr(expr);
	if (!parent)
		return;
	if (parent->type != EXPR_COMPARE || parent->op != SPECIAL_EQUAL)
		return;
	if (parent->left != expr)
		return;

	if (!get_implied_rl(expr->unop, &left) ||
	   !get_implied_rl(parent->right, &right))
		return;

	op = rl_comparison(left, right);
	if (op == UNKNOWN_COMPARISON)
		return;

	add_comparison(expr->unop, op, parent->right);
}

static char *chunk_to_var_sym(struct expression *expr, struct symbol **sym)
{
	expr = strip_expr(expr);
	if (!expr)
		return NULL;
	if (sym)
		*sym = NULL;

	if (expr->type == EXPR_PREOP &&
	    (expr->op == SPECIAL_INCREMENT ||
	     expr->op == SPECIAL_DECREMENT))
		expr = strip_expr(expr->unop);

	if (expr->type == EXPR_CALL) {
		char buf[64];

		snprintf(buf, sizeof(buf), "return %p", expr);
		return alloc_string(buf);
	}

	return expr_to_chunk_sym_vsl(expr, sym, NULL);
}

static char *chunk_to_var(struct expression *expr)
{
	return chunk_to_var_sym(expr, NULL);
}

static struct smatch_state *get_state_chunk(int owner, struct expression *expr)
{
	char *name;
	struct symbol *sym;
	struct smatch_state *ret;

	name = chunk_to_var_sym(expr, &sym);
	if (!name)
		return NULL;

	ret = get_state(owner, name, sym);
	free_string(name);
	return ret;
}

static void save_link(struct expression *expr, char *link)
{
	char *var;
	struct symbol *sym;

	expr = strip_expr(expr);
	if (expr->type == EXPR_BINOP) {
		char *chunk;

		chunk = chunk_to_var(expr);
		if (!chunk)
			return;

		save_link(expr->left, link);
		save_link(expr->right, link);
		save_link_var_sym(chunk, NULL, link);
		return;
	}

	var = chunk_to_var_sym(expr, &sym);
	if (!var)
		return;

	save_link_var_sym(var, sym, link);
	free_string(var);
}

static int get_orig_comparison(struct stree *pre_stree, const char *left, const char *right)
{
	struct smatch_state *state;
	struct compare_data *data;
	int flip = 0;
	char state_name[256];

	if (strcmp(left, right) > 0) {
		const char *tmp = right;

		flip = 1;
		right = left;
		left = tmp;
	}

	snprintf(state_name, sizeof(state_name), "%s vs %s", left, right);
	state = get_state_stree(pre_stree, comparison_id, state_name, NULL);
	if (!state || !state->data)
		return 0;
	data = state->data;
	if (flip)
		return flip_comparison(data->comparison);
	return data->comparison;

}

static int have_common_var_sym(struct var_sym_list *left_vsl, struct var_sym_list *right_vsl)
{
	struct var_sym *tmp;

	FOR_EACH_PTR(left_vsl, tmp) {
		if (in_var_sym_list(right_vsl, tmp->var, tmp->sym))
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

/*
 * The idea here is that we take a comparison "a < b" and then we look at all
 * the things which "b" is compared against "b < c" and we say that that implies
 * a relationship "a < c".
 *
 * The names here about because the comparisons are organized like this
 * "a < b < c".
 *
 */
static void update_tf_links(struct stree *pre_stree,
			    struct expression *left_expr,
			    const char *left_var, struct var_sym_list *left_vsl,
			    int left_comparison, int left_false_comparison,
			    const char *mid_var, struct var_sym_list *mid_vsl,
			    struct string_list *links)
{
	struct smatch_state *state;
	struct smatch_state *true_state, *false_state;
	struct compare_data *data;
	struct expression *right_expr;
	const char *right_var;
	struct var_sym_list *right_vsl;
	int orig_comparison;
	int right_comparison;
	int true_comparison;
	int false_comparison;
	char *tmp;
	char state_name[256];
	struct var_sym *vs;

	FOR_EACH_PTR(links, tmp) {
		state = get_state_stree(pre_stree, comparison_id, tmp, NULL);
		if (!state || !state->data)
			continue;
		data = state->data;
		right_comparison = data->comparison;
		right_expr = data->right;
		right_var = data->right_var;
		right_vsl = data->right_vsl;
		if (strcmp(mid_var, right_var) == 0) {
			right_expr = data->left;
			right_var = data->left_var;
			right_vsl = data->left_vsl;
			right_comparison = flip_comparison(right_comparison);
		}
		if (have_common_var_sym(left_vsl, right_vsl))
			continue;

		orig_comparison = get_orig_comparison(pre_stree, left_var, right_var);

		true_comparison = combine_comparisons(left_comparison, right_comparison);
		false_comparison = combine_comparisons(left_false_comparison, right_comparison);

		true_comparison = comparison_intersection(orig_comparison, true_comparison);
		false_comparison = comparison_intersection(orig_comparison, false_comparison);

		if (strcmp(left_var, right_var) > 0) {
		  	struct expression *tmp_expr = left_expr;
			const char *tmp_var = left_var;
			struct var_sym_list *tmp_vsl = left_vsl;

			left_expr = right_expr;
			left_var = right_var;
			left_vsl = right_vsl;
			right_expr = tmp_expr;
			right_var = tmp_var;
			right_vsl = tmp_vsl;
			true_comparison = flip_comparison(true_comparison);
			false_comparison = flip_comparison(false_comparison);
		}

		if (!true_comparison && !false_comparison)
			continue;

		if (true_comparison)
			true_state = alloc_compare_state(
					left_expr, left_var, left_vsl,
					true_comparison,
					right_expr, right_var, right_vsl);
		else
			true_state = NULL;
		if (false_comparison)
			false_state = alloc_compare_state(
					left_expr, left_var, left_vsl,
					false_comparison,
					right_expr, right_var, right_vsl);
		else
			false_state = NULL;

		snprintf(state_name, sizeof(state_name), "%s vs %s", left_var, right_var);
		set_true_false_states(comparison_id, state_name, NULL, true_state, false_state);
		FOR_EACH_PTR(left_vsl, vs) {
			save_link_var_sym(vs->var, vs->sym, state_name);
		} END_FOR_EACH_PTR(vs);
		FOR_EACH_PTR(right_vsl, vs) {
			save_link_var_sym(vs->var, vs->sym, state_name);
		} END_FOR_EACH_PTR(vs);
		if (!vsl_to_sym(left_vsl))
			save_link_var_sym(left_var, NULL, state_name);
		if (!vsl_to_sym(right_vsl))
			save_link_var_sym(right_var, NULL, state_name);
	} END_FOR_EACH_PTR(tmp);
}

static void update_tf_data(struct stree *pre_stree,
		struct expression *left_expr,
		const char *left_name, struct var_sym_list *left_vsl,
		struct expression *right_expr,
		const char *right_name, struct var_sym_list *right_vsl,
		int true_comparison, int false_comparison)
{
	struct smatch_state *state;

	state = get_state_stree(pre_stree, link_id, right_name, vsl_to_sym(right_vsl));
	if (state)
		update_tf_links(pre_stree, left_expr, left_name, left_vsl, true_comparison, false_comparison, right_name, right_vsl, state->data);

	state = get_state_stree(pre_stree, link_id, left_name, vsl_to_sym(left_vsl));
	if (state)
		update_tf_links(pre_stree, right_expr, right_name, right_vsl, flip_comparison(true_comparison), flip_comparison(false_comparison), left_name, left_vsl, state->data);
}

static void iter_modify(struct sm_state *sm, struct expression *mod_expr)
{
	if (sm->state != &start ||
	    !mod_expr ||
	    (mod_expr->type != EXPR_PREOP && mod_expr->type != EXPR_POSTOP) ||
	    mod_expr->op != SPECIAL_INCREMENT)
		set_state(inc_dec_id, sm->name, sm->sym, &undefined);
	else
		set_state(inc_dec_id, sm->name, sm->sym, &incremented);
}

static void handle_for_loops(struct expression *expr, char *state_name, struct smatch_state *false_state)
{
	sval_t sval;
	char *iter_name, *cap_name;
	struct symbol *iter_sym, *cap_sym;
	struct compare_data *data;

	if (expr->op != '<' && expr->op != SPECIAL_UNSIGNED_LT)
		return;

	if (!__cur_stmt || !__prev_stmt)
		return;
	if (__cur_stmt->type != STMT_ITERATOR)
		return;
	if (__cur_stmt->iterator_pre_condition != expr)
		return;

	/* literals are handled in smatch_extra.c */
	if (get_value(expr->right, &sval))
		return;

	/* First time checking the condition */
	if (__prev_stmt == __cur_stmt->iterator_pre_statement) {
		if (!get_implied_value(expr->left, &sval) ||
		    sval.value != 0)
			return;

		iter_name = expr_to_var_sym(expr->left, &iter_sym);
		cap_name = expr_to_var_sym(expr->right, &cap_sym);
		if (!iter_name || !cap_name || !iter_sym || !cap_sym) {
			free_string(iter_name);
			free_string(cap_name);
			return;
		}

		set_state(inc_dec_id, iter_name, iter_sym, &start);
		store_link(inc_dec_link_id, cap_name, cap_sym, iter_name, iter_sym);

		free_string(iter_name);
		free_string(cap_name);
		return;
	}

	/* Second time checking the condtion */
	if (__prev_stmt != __cur_stmt->iterator_post_statement)
		return;

	if (get_state_chunk(inc_dec_id, expr->left) != &incremented)
		return;

	data = false_state->data;
	false_state = alloc_compare_state(
			data->left, data->left_var, data->left_vsl,
			SPECIAL_EQUAL,
			data->right, data->right_var, data->right_vsl);

	// FIXME: This doesn't handle links correct so it doesn't set "param orig"
	set_true_false_states(comparison_id, state_name, NULL, NULL, false_state);
}

static int is_plus_one(struct expression *expr)
{
	sval_t sval;

	if (expr->type != EXPR_BINOP || expr->op != '+')
		return 0;
	if (!get_implied_value(expr->right, &sval) || sval.value != 1)
		return 0;
	return 1;
}

static int is_minus_one(struct expression *expr)
{
	sval_t sval;

	if (expr->type != EXPR_BINOP || expr->op != '-')
		return 0;
	if (!get_implied_value(expr->right, &sval) || sval.value != 1)
		return 0;
	return 1;
}

static void move_plus_to_minus_helper(struct expression **left_p, struct expression **right_p)
{
	struct expression *left = *left_p;
	struct expression *right = *right_p;

	/*
	 * These two are basically equivalent: "foo + 1 != bar" and
	 * "foo != bar - 1".  There are issues with signedness and integer
	 * overflows.  There are also issues with type as well.  But let's
	 * pretend we can ignore all that stuff for now.
	 *
	 */

	if (!is_plus_one(left))
		return;

	*left_p = left->left;
	*right_p = binop_expression(right, '-', left->right);
}

static void move_plus_to_minus(struct expression **left_p, struct expression **right_p)
{
	if (is_plus_one(*left_p) && is_plus_one(*right_p))
		return;

	move_plus_to_minus_helper(left_p, right_p);
	move_plus_to_minus_helper(right_p, left_p);
}

static void handle_comparison(struct expression *left_expr, int op, struct expression *right_expr, char **_state_name, struct smatch_state **_false_state)
{
	char *left = NULL;
	char *right = NULL;
	struct symbol *left_sym, *right_sym;
	struct var_sym_list *left_vsl = NULL;
	struct var_sym_list *right_vsl = NULL;
	int false_op;
	int orig_comparison;
	struct smatch_state *true_state, *false_state;
	static char state_name[256];
	struct stree *pre_stree;
	sval_t sval;

	if (!left_expr || !right_expr)
		return;

	left_expr = strip_parens(left_expr);
	right_expr = strip_parens(right_expr);

	while (left_expr->type == EXPR_ASSIGNMENT)
		left_expr = strip_parens(left_expr->left);
	while (right_expr->type == EXPR_ASSIGNMENT)
		right_expr = strip_parens(right_expr->left);

	false_op = negate_comparison(op);

	move_plus_to_minus(&left_expr, &right_expr);

	if (op == SPECIAL_UNSIGNED_LT &&
	    get_implied_value(left_expr, &sval) &&
	    sval.value == 0)
		false_op = SPECIAL_EQUAL;

	if (op == SPECIAL_UNSIGNED_GT &&
	    get_implied_value(right_expr, &sval) &&
	    sval.value == 0)
		false_op = SPECIAL_EQUAL;

	left = chunk_to_var_sym(left_expr, &left_sym);
	if (!left)
		goto free;
	if (left_sym)
		add_var_sym(&left_vsl, left, left_sym);
	else
		left_vsl = expr_to_vsl(left_expr);
	right = chunk_to_var_sym(right_expr, &right_sym);
	if (!right)
		goto free;
	if (right_sym)
		add_var_sym(&right_vsl, right, right_sym);
	else
		right_vsl = expr_to_vsl(right_expr);

	if (strcmp(left, right) > 0) {
		char *tmp_name = left;
		struct var_sym_list *tmp_vsl = left_vsl;
		struct expression *tmp_expr = left_expr;

		left = right;
		left_vsl = right_vsl;
		left_expr = right_expr;
		right = tmp_name;
		right_vsl = tmp_vsl;
		right_expr = tmp_expr;
		op = flip_comparison(op);
		false_op = flip_comparison(false_op);
	}

	orig_comparison = get_comparison(left_expr, right_expr);
	op = comparison_intersection(orig_comparison, op);
	false_op = comparison_intersection(orig_comparison, false_op);

	snprintf(state_name, sizeof(state_name), "%s vs %s", left, right);
	true_state = alloc_compare_state(
			left_expr, left, left_vsl,
			op,
			right_expr, right, right_vsl);
	false_state = alloc_compare_state(
			left_expr, left, left_vsl,
			false_op,
			right_expr, right, right_vsl);

	pre_stree = clone_stree(__get_cur_stree());
	update_tf_data(pre_stree, left_expr, left, left_vsl, right_expr, right, right_vsl, op, false_op);
	free_stree(&pre_stree);

	set_true_false_states(comparison_id, state_name, NULL, true_state, false_state);
	__compare_param_limit_hook(left_expr, right_expr, state_name, true_state, false_state);
	save_link(left_expr, state_name);
	save_link(right_expr, state_name);

	if (_false_state)
		*_false_state = false_state;
	if (_state_name)
		*_state_name = state_name;
free:
	free_string(left);
	free_string(right);
}

void __comparison_match_condition(struct expression *expr)
{
	struct expression *left, *right, *new_left, *new_right, *tmp;
	struct smatch_state *false_state = NULL;
	char *state_name = NULL;
	int redo, count;

	if (expr->type != EXPR_COMPARE)
		return;

	handle_comparison(expr->left, expr->op, expr->right, &state_name, &false_state);
	if (false_state && state_name)
		handle_for_loops(expr, state_name, false_state);

	left = strip_parens(expr->left);
	right = strip_parens(expr->right);

	if (left->type == EXPR_BINOP && left->op == '+') {
		new_left = left->left;
		new_right = binop_expression(right, '-', left->right);
		handle_comparison(new_left, expr->op, new_right, NULL, NULL);

		new_left = left->right;
		new_right = binop_expression(right, '-', left->left);
		handle_comparison(new_left, expr->op, new_right, NULL, NULL);
	}

	redo = 0;
	left = strip_parens(expr->left);
	right = strip_parens(expr->right);
	if (get_last_expr_from_expression_stmt(expr->left)) {
		left = get_last_expr_from_expression_stmt(expr->left);
		redo = 1;
	}
	if (get_last_expr_from_expression_stmt(expr->right)) {
		right = get_last_expr_from_expression_stmt(expr->right);
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

	handle_comparison(left, expr->op, right, NULL, NULL);
}

static void add_comparison_var_sym(
		struct expression *left_expr,
		const char *left_name, struct var_sym_list *left_vsl,
		int comparison,
		struct expression *right_expr,
		const char *right_name, struct var_sym_list *right_vsl)
{
	struct smatch_state *state;
	struct var_sym *vs;
	char state_name[256];

	if (strcmp(left_name, right_name) > 0) {
		struct expression *tmp_expr = left_expr;
		const char *tmp_name = left_name;
		struct var_sym_list *tmp_vsl = left_vsl;

		left_expr = right_expr;
		left_name = right_name;
		left_vsl = right_vsl;
		right_expr = tmp_expr;
		right_name = tmp_name;
		right_vsl = tmp_vsl;
		comparison = flip_comparison(comparison);
	}
	snprintf(state_name, sizeof(state_name), "%s vs %s", left_name, right_name);
	state = alloc_compare_state(
			left_expr, left_name, left_vsl,
			comparison,
			right_expr, right_name, right_vsl);

	set_state(comparison_id, state_name, NULL, state);

	FOR_EACH_PTR(left_vsl, vs) {
		save_link_var_sym(vs->var, vs->sym, state_name);
	} END_FOR_EACH_PTR(vs);
	FOR_EACH_PTR(right_vsl, vs) {
		save_link_var_sym(vs->var, vs->sym, state_name);
	} END_FOR_EACH_PTR(vs);
}

static void add_comparison(struct expression *left, int comparison, struct expression *right)
{
	char *left_name = NULL;
	char *right_name = NULL;
	struct symbol *left_sym, *right_sym;
	struct var_sym_list *left_vsl, *right_vsl;
	struct smatch_state *state;
	char state_name[256];

	left_name = chunk_to_var_sym(left, &left_sym);
	if (!left_name)
		goto free;
	left_vsl = expr_to_vsl(left);
	right_name = chunk_to_var_sym(right, &right_sym);
	if (!right_name)
		goto free;
	right_vsl = expr_to_vsl(right);

	if (strcmp(left_name, right_name) > 0) {
		struct expression *tmp_expr = left;
		struct symbol *tmp_sym = left_sym;
		char *tmp_name = left_name;
		struct var_sym_list *tmp_vsl = left_vsl;

		left = right;
		left_name = right_name;
		left_sym = right_sym;
		left_vsl = right_vsl;
		right = tmp_expr;
		right_name = tmp_name;
		right_sym = tmp_sym;
		right_vsl = tmp_vsl;
		comparison = flip_comparison(comparison);
	}
	snprintf(state_name, sizeof(state_name), "%s vs %s", left_name, right_name);
	state = alloc_compare_state(
			left, left_name, left_vsl,
			comparison,
			right, right_name, right_vsl);

	set_state(comparison_id, state_name, NULL, state);
	save_link(left, state_name);
	save_link(right, state_name);

free:
	free_string(left_name);
	free_string(right_name);
}

static void match_assign_add(struct expression *expr)
{
	struct expression *right;
	struct expression *r_left, *r_right;
	sval_t left_tmp, right_tmp;

	right = strip_expr(expr->right);
	r_left = strip_expr(right->left);
	r_right = strip_expr(right->right);

	get_absolute_min(r_left, &left_tmp);
	get_absolute_min(r_right, &right_tmp);

	if (left_tmp.value > 0)
		add_comparison(expr->left, '>', r_right);
	else if (left_tmp.value == 0)
		add_comparison(expr->left, SPECIAL_GTE, r_right);

	if (right_tmp.value > 0)
		add_comparison(expr->left, '>', r_left);
	else if (right_tmp.value == 0)
		add_comparison(expr->left, SPECIAL_GTE, r_left);
}

static void match_assign_sub(struct expression *expr)
{
	struct expression *right;
	struct expression *r_left, *r_right;
	int comparison;
	sval_t min;

	right = strip_expr(expr->right);
	r_left = strip_expr(right->left);
	r_right = strip_expr(right->right);

	if (get_absolute_min(r_right, &min) && sval_is_negative(min))
		return;

	comparison = get_comparison(r_left, r_right);

	switch (comparison) {
	case '>':
	case SPECIAL_GTE:
		if (implied_not_equal(r_right, 0))
			add_comparison(expr->left, '>', r_left);
		else
			add_comparison(expr->left, SPECIAL_GTE, r_left);
		return;
	}
}

static void match_assign_divide(struct expression *expr)
{
	struct expression *right;
	struct expression *r_left, *r_right;
	sval_t min;

	right = strip_expr(expr->right);
	r_left = strip_expr(right->left);
	r_right = strip_expr(right->right);
	if (!get_implied_min(r_right, &min) || min.value <= 1)
		return;

	add_comparison(expr->left, '<', r_left);
}

static void match_binop_assign(struct expression *expr)
{
	struct expression *right;

	right = strip_expr(expr->right);
	if (right->op == '+')
		match_assign_add(expr);
	if (right->op == '-')
		match_assign_sub(expr);
	if (right->op == '/')
		match_assign_divide(expr);
}

static void copy_comparisons(struct expression *left, struct expression *right)
{
	struct string_list *links;
	struct smatch_state *state;
	struct compare_data *data;
	struct symbol *left_sym, *right_sym;
	char *left_var = NULL;
	char *right_var = NULL;
	struct var_sym_list *left_vsl;
	struct expression *expr;
	const char *var;
	struct var_sym_list *vsl;
	int comparison;
	char *tmp;

	left_var = chunk_to_var_sym(left, &left_sym);
	if (!left_var)
		goto done;
	left_vsl = expr_to_vsl(left);
	right_var = chunk_to_var_sym(right, &right_sym);
	if (!right_var)
		goto done;

	state = get_state(link_id, right_var, right_sym);
	if (!state)
		return;
	links = state->data;

	FOR_EACH_PTR(links, tmp) {
		state = get_state(comparison_id, tmp, NULL);
		if (!state || !state->data)
			continue;
		data = state->data;
		comparison = data->comparison;
		expr = data->right;
		var = data->right_var;
		vsl = data->right_vsl;
		if (strcmp(var, right_var) == 0) {
			expr = data->left;
			var = data->left_var;
			vsl = data->left_vsl;
			comparison = flip_comparison(comparison);
		}
		/* n = copy_from_user(dest, src, n); leads to n <= n which is nonsense */
		if (strcmp(left_var, var) == 0)
			continue;
		add_comparison_var_sym(left, left_var, left_vsl, comparison, expr, var, vsl);
	} END_FOR_EACH_PTR(tmp);

done:
	free_string(right_var);
}

static void match_assign(struct expression *expr)
{
	struct expression *right;

	if (expr->op != '=')
		return;
	if (__in_fake_assign || outside_of_function())
		return;

	if (is_struct(expr->left))
		return;

	if (is_self_assign(expr))
		return;

	copy_comparisons(expr->left, expr->right);
	add_comparison(expr->left, SPECIAL_EQUAL, expr->right);

	right = strip_expr(expr->right);
	if (right->type == EXPR_BINOP)
		match_binop_assign(expr);
}

int get_comparison_strings(const char *one, const char *two)
{
	char buf[256];
	struct smatch_state *state;
	int invert = 0;
	int ret = 0;

	if (!one || !two)
		return UNKNOWN_COMPARISON;

	if (strcmp(one, two) == 0)
		return SPECIAL_EQUAL;

	if (strcmp(one, two) > 0) {
		const char *tmp = one;

		one = two;
		two = tmp;
		invert = 1;
	}

	snprintf(buf, sizeof(buf), "%s vs %s", one, two);
	state = get_state(comparison_id, buf, NULL);
	if (state)
		ret = state_to_comparison(state);

	if (invert)
		ret = flip_comparison(ret);

	return ret;
}

static int get_comparison_helper(struct expression *a, struct expression *b, bool use_extra)
{
	char *one = NULL;
	char *two = NULL;
	int ret = UNKNOWN_COMPARISON;
	int extra = UNKNOWN_COMPARISON;

	if (a == UNKNOWN_COMPARISON ||
	    b == UNKNOWN_COMPARISON)
		return UNKNOWN_COMPARISON;

	a = strip_parens(a);
	b = strip_parens(b);

	move_plus_to_minus(&a, &b);

	one = chunk_to_var(a);
	if (!one)
		goto free;
	two = chunk_to_var(b);
	if (!two)
		goto free;

	ret = get_comparison_strings(one, two);
	if (ret)
		goto free;

	if (is_plus_one(a) || is_minus_one(a)) {
		free_string(one);
		one = chunk_to_var(a->left);
		ret = get_comparison_strings(one, two);
	} else if (is_plus_one(b) || is_minus_one(b)) {
		free_string(two);
		two = chunk_to_var(b->left);
		ret = get_comparison_strings(one, two);
	}

	if (ret == UNKNOWN_COMPARISON)
		goto free;

	if ((is_plus_one(a) || is_minus_one(b)) && ret == '<')
		ret = SPECIAL_LTE;
	else if ((is_minus_one(a) || is_plus_one(b)) && ret == '>')
		ret = SPECIAL_GTE;
	else
		ret = UNKNOWN_COMPARISON;

free:
	free_string(one);
	free_string(two);

	extra = comparison_from_extra(a, b);
	return comparison_intersection(ret, extra);
}

int get_comparison(struct expression *a, struct expression *b)
{
	return get_comparison_helper(a, b, true);
}

int get_comparison_no_extra(struct expression *a, struct expression *b)
{
	return get_comparison_helper(a, b, false);
}

int possible_comparison(struct expression *a, int comparison, struct expression *b)
{
	char *one = NULL;
	char *two = NULL;
	int ret = 0;
	char buf[256];
	struct sm_state *sm;
	int saved;

	one = chunk_to_var(a);
	if (!one)
		goto free;
	two = chunk_to_var(b);
	if (!two)
		goto free;


	if (strcmp(one, two) == 0 && comparison == SPECIAL_EQUAL) {
		ret = 1;
		goto free;
	}

	if (strcmp(one, two) > 0) {
		char *tmp = one;

		one = two;
		two = tmp;
		comparison = flip_comparison(comparison);
	}

	snprintf(buf, sizeof(buf), "%s vs %s", one, two);
	sm = get_sm_state(comparison_id, buf, NULL);
	if (!sm)
		goto free;

	FOR_EACH_PTR(sm->possible, sm) {
		if (!sm->state->data)
			continue;
		saved = ((struct compare_data *)sm->state->data)->comparison;
		if (saved == comparison)
			ret = 1;
		if (comparison == SPECIAL_EQUAL &&
		    (saved == SPECIAL_LTE ||
		     saved == SPECIAL_GTE ||
		     saved == SPECIAL_UNSIGNED_LTE ||
		     saved == SPECIAL_UNSIGNED_GTE))
			ret = 1;
		if (ret == 1)
			goto free;
	} END_FOR_EACH_PTR(sm);

	return ret;
free:
	free_string(one);
	free_string(two);
	return ret;
}

struct state_list *get_all_comparisons(struct expression *expr)
{
	struct smatch_state *state;
	struct string_list *links;
	struct state_list *ret = NULL;
	struct sm_state *sm;
	char *tmp;

	state = get_state_chunk(link_id, expr);
	if (!state)
		return NULL;
	links = state->data;

	FOR_EACH_PTR(links, tmp) {
		sm = get_sm_state(comparison_id, tmp, NULL);
		if (!sm)
			continue;
		// FIXME have to compare name with vsl
		add_ptr_list(&ret, sm);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

struct state_list *get_all_possible_equal_comparisons(struct expression *expr)
{
	struct smatch_state *state;
	struct string_list *links;
	struct state_list *ret = NULL;
	struct sm_state *sm;
	char *tmp;

	state = get_state_chunk(link_id, expr);
	if (!state)
		return NULL;
	links = state->data;

	FOR_EACH_PTR(links, tmp) {
		sm = get_sm_state(comparison_id, tmp, NULL);
		if (!sm)
			continue;
		if (!strchr(sm->state->name, '='))
			continue;
		if (strcmp(sm->state->name, "!=") == 0)
			continue;
		add_ptr_list(&ret, sm);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

struct state_list *get_all_possible_not_equal_comparisons(struct expression *expr)
{
	struct smatch_state *state;
	struct string_list *links;
	struct state_list *ret = NULL;
	struct sm_state *sm;
	struct sm_state *possible;
	char *link;

	return NULL;

	state = get_state_chunk(link_id, expr);
	if (!state)
		return NULL;
	links = state->data;

	FOR_EACH_PTR(links, link) {
		sm = get_sm_state(comparison_id, link, NULL);
		if (!sm)
			continue;
		FOR_EACH_PTR(sm->possible, possible) {
			if (strcmp(possible->state->name, "!=") != 0)
				continue;
			add_ptr_list(&ret, sm);
			break;
		} END_FOR_EACH_PTR(link);
	} END_FOR_EACH_PTR(link);

	return ret;
}

static void update_links_from_call(struct expression *left,
				   int left_compare,
				   struct expression *right)
{
	struct string_list *links;
	struct smatch_state *state;
	struct compare_data *data;
	struct symbol *left_sym, *right_sym;
	char *left_var = NULL;
	char *right_var = NULL;
	struct var_sym_list *left_vsl;
	struct expression *expr;
	const char *var;
	struct var_sym_list *vsl;
	int comparison;
	char *tmp;

	left_var = chunk_to_var_sym(left, &left_sym);
	if (!left_var)
		goto done;
	left_vsl = expr_to_vsl(left);
	right_var = chunk_to_var_sym(right, &right_sym);
	if (!right_var)
		goto done;

	state = get_state(link_id, right_var, right_sym);
	if (!state)
		return;
	links = state->data;

	FOR_EACH_PTR(links, tmp) {
		state = get_state(comparison_id, tmp, NULL);
		if (!state || !state->data)
			continue;
		data = state->data;
		comparison = data->comparison;
		expr = data->right;
		var = data->right_var;
		vsl = data->right_vsl;
		if (strcmp(var, right_var) == 0) {
			expr = data->left;
			var = data->left_var;
			vsl = data->left_vsl;
			comparison = flip_comparison(comparison);
		}
		comparison = combine_comparisons(left_compare, comparison);
		if (!comparison)
			continue;
		add_comparison_var_sym(left, left_var, left_vsl, comparison, expr, var, vsl);
	} END_FOR_EACH_PTR(tmp);

done:
	free_string(right_var);
}

void __add_return_comparison(struct expression *call, const char *range)
{
	struct expression *arg;
	int comparison;
	char buf[16];

	if (!str_to_comparison_arg(range, call, &comparison, &arg))
		return;
	snprintf(buf, sizeof(buf), "%s", show_comparison(comparison));
	update_links_from_call(call, comparison, arg);
	add_comparison(call, comparison, arg);
}

void __add_comparison_info(struct expression *expr, struct expression *call, const char *range)
{
	copy_comparisons(expr, call);
}

static char *get_mask_comparison(struct expression *expr, int ignore)
{
	struct expression *tmp, *right;
	int count, param;
	char buf[256];

	/* The return value for "return foo & param;" is <= param */

	count = 0;
	while ((tmp = get_assigned_expr(expr))) {
		expr = strip_expr(tmp);
		if (count++ > 4)
			break;
	}

	if (expr->type != EXPR_BINOP || expr->op != '&')
		return NULL;

	right = strip_expr(expr->right);
	param = get_param_num(right);
	if (param < 0 || param == ignore)
		return NULL;

	snprintf(buf, sizeof(buf), "[<=$%d]", param);
	return alloc_sname(buf);
}

static char *range_comparison_to_param_helper(struct expression *expr, char starts_with, int ignore)
{
	struct symbol *param;
	char *var = NULL;
	char buf[256];
	char *ret_str = NULL;
	int compare;
	int i;

	if (!expr)
		return NULL;

	var = chunk_to_var(expr);
	if (!var)
		goto try_mask;

	i = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, param) {
		i++;
		if (i == ignore)
			continue;
		if (!param->ident)
			continue;
		snprintf(buf, sizeof(buf), "%s orig", param->ident->name);
		compare = get_comparison_strings(var, buf);
		if (compare == UNKNOWN_COMPARISON ||
		    compare == IMPOSSIBLE_COMPARISON)
			continue;
		if (show_comparison(compare)[0] != starts_with)
			continue;
		snprintf(buf, sizeof(buf), "[%s$%d]", show_comparison(compare), i);
		ret_str = alloc_sname(buf);
		break;
	} END_FOR_EACH_PTR(param);

	free_string(var);
	if (!ret_str)
		goto try_mask;

	return ret_str;

try_mask:
	if (starts_with == '<')
		ret_str = get_mask_comparison(expr, ignore);
	return ret_str;
}

char *name_sym_to_param_comparison(const char *name, struct symbol *sym)
{
	struct symbol *param;
	char buf[256];
	int compare;
	int i;

	i = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, param) {
		i++;
		if (!param->ident)
			continue;
		snprintf(buf, sizeof(buf), "%s orig", param->ident->name);
		compare = get_comparison_strings(name, buf);
		if (compare == UNKNOWN_COMPARISON ||
		    compare == IMPOSSIBLE_COMPARISON)
			continue;
		snprintf(buf, sizeof(buf), "[%s$%d]", show_comparison(compare), i);
		return alloc_sname(buf);
	} END_FOR_EACH_PTR(param);

	return NULL;
}

char *expr_equal_to_param(struct expression *expr, int ignore)
{
	return range_comparison_to_param_helper(expr, '=', ignore);
}

char *expr_lte_to_param(struct expression *expr, int ignore)
{
	return range_comparison_to_param_helper(expr, '<', ignore);
}

char *expr_param_comparison(struct expression *expr, int ignore)
{
	struct symbol *param;
	char *var = NULL;
	char buf[256];
	char *ret_str = NULL;
	int compare;
	int i;

	var = chunk_to_var(expr);
	if (!var)
		goto free;

	i = -1;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, param) {
		i++;
		if (i == ignore)
			continue;
		if (!param->ident)
			continue;
		snprintf(buf, sizeof(buf), "%s orig", param->ident->name);
		compare = get_comparison_strings(var, buf);
		if (!compare)
			continue;
		snprintf(buf, sizeof(buf), "[%s$%d]", show_comparison(compare), i);
		ret_str = alloc_sname(buf);
		break;
	} END_FOR_EACH_PTR(param);

free:
	free_string(var);
	return ret_str;
}

char *get_printed_param_name(struct expression *call, const char *param_name, struct symbol *param_sym)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;
	static char buf[256];
	int len;
	int i;

	i = -1;
	FOR_EACH_PTR(call->args, arg) {
		i++;

		name = expr_to_var_sym(arg, &sym);
		if (!name || !sym)
			continue;
		if (sym != param_sym)
			continue;

		len = strlen(name);
		if (strncmp(name, param_name, len) != 0)
			continue;
		if (param_name[len] == '\0') {
			snprintf(buf, sizeof(buf), "$%d", i);
			return buf;
		}
		if (param_name[len] != '-')
			continue;
		snprintf(buf, sizeof(buf), "$%d%s", i, param_name + len);
		return buf;
	} END_FOR_EACH_PTR(arg);

	return NULL;
}

static void match_call_info(struct expression *expr)
{
	struct expression *arg;
	struct smatch_state *state;
	struct sm_state *sm;
	struct compare_data *data;
	int comparison;
	struct string_list *links;
	char *arg_name;
	const char *right_name;
	char *link;
	char info_buf[256];
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;

		state = get_state_chunk(link_id, arg);
		if (!state)
			continue;

		links = state->data;
		FOR_EACH_PTR(links, link) {
			struct var_sym_list *right_vsl;
			struct var_sym *right_vs;


			if (strstr(link, " orig"))
				continue;
			sm = get_sm_state(comparison_id, link, NULL);
			if (!sm)
				continue;
			data = sm->state->data;
			if (!data ||
			    data->comparison == UNKNOWN_COMPARISON ||
			    data->comparison == IMPOSSIBLE_COMPARISON)
				continue;
			arg_name = expr_to_var(arg);
			if (!arg_name)
				continue;

			right_vsl = NULL;
			if (strcmp(data->left_var, arg_name) == 0) {
				comparison = data->comparison;
				right_name = data->right_var;
				right_vsl = data->right_vsl;
			} else if (strcmp(data->right_var, arg_name) == 0) {
				comparison = flip_comparison(data->comparison);
				right_name = data->left_var;
				right_vsl = data->left_vsl;
			}
			if (!right_vsl || ptr_list_size((struct ptr_list *)right_vsl) != 1)
				goto free;

			right_vs = first_ptr_list((struct ptr_list *)right_vsl);
			if (strcmp(right_vs->var, right_name) != 0)
				goto free;
			right_name = get_printed_param_name(expr, right_vs->var, right_vs->sym);
			if (!right_name)
				goto free;
			snprintf(info_buf, sizeof(info_buf), "%s %s", show_comparison(comparison), right_name);
			sql_insert_caller_info(expr, PARAM_COMPARE, i, "$", info_buf);

free:
			free_string(arg_name);
		} END_FOR_EACH_PTR(link);
	} END_FOR_EACH_PTR(arg);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *link_sm)
{
	struct sm_state *compare_sm;
	struct string_list *links;
	char *link;
	struct compare_data *data;
	struct var_sym *left, *right;
	static char info_buf[256];
	const char *right_name;

	if (strstr(printed_name, " orig"))
		return;

	links = link_sm->state->data;
	FOR_EACH_PTR(links, link) {
		compare_sm = get_sm_state(comparison_id, link, NULL);
		if (!compare_sm)
			continue;
		data = compare_sm->state->data;
		if (!data || !data->comparison)
			continue;

		if (ptr_list_size((struct ptr_list *)data->left_vsl) != 1 ||
		    ptr_list_size((struct ptr_list *)data->right_vsl) != 1)
			continue;
		left = first_ptr_list((struct ptr_list *)data->left_vsl);
		right = first_ptr_list((struct ptr_list *)data->right_vsl);
		if (left->sym == right->sym &&
		    strcmp(left->var, right->var) == 0)
			continue;
		/*
		 * Both parameters link to this comparison so only
		 * record the first one.
		 */
		if (left->sym != link_sm->sym ||
		    strcmp(left->var, link_sm->name) != 0)
			continue;

		right_name = get_printed_param_name(call, right->var, right->sym);
		if (!right_name)
			continue;
		snprintf(info_buf, sizeof(info_buf), "%s %s", show_comparison(data->comparison), right_name);
		sql_insert_caller_info(call, PARAM_COMPARE, param, printed_name, info_buf);
	} END_FOR_EACH_PTR(link);
}

static void print_return_value_comparison(int return_id, char *return_ranges, struct expression *expr)
{
	char *name;
	const char *tmp_name;
	struct symbol *sym;
	int param;
	char info_buf[256];

	/*
	 * TODO: This only prints == comparisons. That's probably the most
	 * useful comparison because == max has lots of implications.  But it
	 * would be good to capture the rest as well.
	 *
	 * This information is already in the DB but it's in the parameter math
	 * bits and it's awkward to use it.  This is is the simpler, possibly
	 * cleaner way, but not necessarily the best, I don't know.
	 */

	if (!expr)
		return;
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	param = get_param_num_from_sym(sym);
	if (param < 0)
		goto free;
	if (param_was_set_var_sym(name, sym))
		goto free;

	tmp_name = get_param_name_var_sym(name, sym);
	if (!tmp_name)
		goto free;

	snprintf(info_buf, sizeof(info_buf), "== $%d%s", param, tmp_name + 1);
	sql_insert_return_states(return_id, return_ranges,
				PARAM_COMPARE, -1, "$", info_buf);
free:
	free_string(name);
}

static void print_return_comparison(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *tmp;
	struct string_list *links;
	char *link;
	struct sm_state *sm;
	struct compare_data *data;
	struct var_sym *left, *right;
	int left_param, right_param;
	char left_buf[256];
	char right_buf[256];
	char info_buf[258];
	const char *tmp_name;

	print_return_value_comparison(return_id, return_ranges, expr);

	FOR_EACH_MY_SM(link_id, __get_cur_stree(), tmp) {
		if (get_param_num_from_sym(tmp->sym) < 0)
			continue;
		links = tmp->state->data;
		FOR_EACH_PTR(links, link) {
			sm = get_sm_state(comparison_id, link, NULL);
			if (!sm)
				continue;
			data = sm->state->data;
			if (!data ||
			    data->comparison == UNKNOWN_COMPARISON ||
			    data->comparison == IMPOSSIBLE_COMPARISON)
				continue;
			if (ptr_list_size((struct ptr_list *)data->left_vsl) != 1 ||
			    ptr_list_size((struct ptr_list *)data->right_vsl) != 1)
				continue;
			left = first_ptr_list((struct ptr_list *)data->left_vsl);
			right = first_ptr_list((struct ptr_list *)data->right_vsl);
			if (left->sym == right->sym &&
			    strcmp(left->var, right->var) == 0)
				continue;
			/*
			 * Both parameters link to this comparison so only
			 * record the first one.
			 */
			if (left->sym != tmp->sym ||
			    strcmp(left->var, tmp->name) != 0)
				continue;

			if (strstr(right->var, " orig"))
				continue;

			left_param = get_param_num_from_sym(left->sym);
			right_param = get_param_num_from_sym(right->sym);
			if (left_param < 0 || right_param < 0)
				continue;

			tmp_name = get_param_name_var_sym(left->var, left->sym);
			if (!tmp_name)
				continue;
			snprintf(left_buf, sizeof(left_buf), "%s", tmp_name);

			tmp_name = get_param_name_var_sym(right->var, right->sym);
			if (!tmp_name || tmp_name[0] != '$')
				continue;
			snprintf(right_buf, sizeof(right_buf), "$%d%s", right_param, tmp_name + 1);

			/*
			 * FIXME: this should reject $ type variables (as
			 * opposed to $->foo type).  Those should come from
			 * smatch_param_compare_limit.c.
			 */

			snprintf(info_buf, sizeof(info_buf), "%s %s", show_comparison(data->comparison), right_buf);
			sql_insert_return_states(return_id, return_ranges,
					PARAM_COMPARE, left_param, left_buf, info_buf);
		} END_FOR_EACH_PTR(link);

	} END_FOR_EACH_SM(tmp);
}

static int parse_comparison(char **value, int *op)
{

	*op = **value;

	switch (*op) {
	case '<':
		(*value)++;
		if (**value == '=') {
			(*value)++;
			*op = SPECIAL_LTE;
		}
		break;
	case '=':
		(*value)++;
		(*value)++;
		*op = SPECIAL_EQUAL;
		break;
	case '!':
		(*value)++;
		(*value)++;
		*op = SPECIAL_NOTEQUAL;
		break;
	case '>':
		(*value)++;
		if (**value == '=') {
			(*value)++;
			*op = SPECIAL_GTE;
		}
		break;
	default:
		return 0;
	}

	if (**value != ' ') {
		sm_perror("parsing comparison.  %s", *value);
		return 0;
	}

	(*value)++;
	return 1;
}

static int split_op_param_key(char *value, int *op, int *param, char **key)
{
	static char buf[256];
	char *p;

	if (!parse_comparison(&value, op))
		return 0;

	snprintf(buf, sizeof(buf), "%s", value);

	p = buf;
	if (*p++ != '$')
		return 0;

	*param = atoi(p);
	if (*param < 0 || *param > 99)
		return 0;
	p++;
	if (*param > 9)
		p++;
	p--;
	*p = '$';
	*key = p;

	return 1;
}

static void db_return_comparison(struct expression *expr, int left_param, char *key, char *value)
{
	struct expression *left_arg, *right_arg;
	char *left_name = NULL;
	struct symbol *left_sym;
	char *right_name = NULL;
	struct symbol *right_sym;
	int op;
	int right_param;
	char *right_key;
	struct var_sym_list *left_vsl = NULL, *right_vsl = NULL;

	if (left_param == -1) {
		if (expr->type != EXPR_ASSIGNMENT)
			return;
		left_arg = strip_expr(expr->left);

		while (expr->type == EXPR_ASSIGNMENT)
			expr = strip_expr(expr->right);
		if (expr->type != EXPR_CALL)
			return;
	} else {
		while (expr->type == EXPR_ASSIGNMENT)
			expr = strip_expr(expr->right);
		if (expr->type != EXPR_CALL)
			return;

		left_arg = get_argument_from_call_expr(expr->args, left_param);
		if (!left_arg)
			return;
	}

	if (!split_op_param_key(value, &op, &right_param, &right_key))
		return;

	right_arg = get_argument_from_call_expr(expr->args, right_param);
	if (!right_arg)
		return;

	left_name = get_variable_from_key(left_arg, key, &left_sym);
	if (!left_name || !left_sym)
		goto free;

	right_name = get_variable_from_key(right_arg, right_key, &right_sym);
	if (!right_name || !right_sym)
		goto free;

	add_var_sym(&left_vsl, left_name, left_sym);
	add_var_sym(&right_vsl, right_name, right_sym);

	add_comparison_var_sym(NULL, left_name, left_vsl, op, NULL, right_name, right_vsl);

free:
	free_string(left_name);
	free_string(right_name);
}

int param_compare_limit_is_impossible(struct expression *expr, int left_param, char *left_key, char *value)
{
	struct smatch_state *state;
	char *left_name = NULL;
	char *right_name = NULL;
	struct symbol *left_sym, *right_sym;
	struct expression *left_arg, *right_arg;
	int op, state_op;
	int right_param;
	char *right_key;
	int ret = 0;
	char buf[256];

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return 0;

	if (!split_op_param_key(value, &op, &right_param, &right_key))
		return 0;

	left_arg = get_argument_from_call_expr(expr->args, left_param);
	if (!left_arg)
		return 0;

	right_arg = get_argument_from_call_expr(expr->args, right_param);
	if (!right_arg)
		return 0;

	left_name = get_variable_from_key(left_arg, left_key, &left_sym);
	right_name = get_variable_from_key(right_arg, right_key, &right_sym);
	if (!left_name || !right_name)
		goto free;

	snprintf(buf, sizeof(buf), "%s vs %s", left_name, right_name);
	state = get_state(comparison_id, buf, NULL);
	if (!state)
		goto free;
	state_op = state_to_comparison(state);
	if (!state_op)
		goto free;

	if (!comparison_intersection(remove_unsigned_from_comparison(state_op), op))
		ret = 1;
free:
	free_string(left_name);
	free_string(right_name);
	return ret;
}

int impossibly_high_comparison(struct expression *expr)
{
	struct smatch_state *link_state;
	struct sm_state *sm;
	struct string_list *links;
	char *link;
	struct compare_data *data;

	link_state = get_state_expr(link_id, expr);
	if (!link_state) {
		if (expr->type == EXPR_BINOP &&
		    (impossibly_high_comparison(expr->left) ||
		     impossibly_high_comparison(expr->right)))
			return 1;
		return 0;
	}

	links = link_state->data;
	FOR_EACH_PTR(links, link) {
		sm = get_sm_state(comparison_id, link, NULL);
		if (!sm)
			continue;
		data = sm->state->data;
		if (!data)
			continue;
		if (!possibly_true(data->left, data->comparison, data->right))
			return 1;
	} END_FOR_EACH_PTR(link);

	return 0;
}

static void free_data(struct symbol *sym)
{
	if (__inline_fn)
		return;
	clear_compare_data_alloc();
}

void register_comparison(int id)
{
	comparison_id = id;
	set_dynamic_states(comparison_id);
	add_hook(&save_start_states, AFTER_DEF_HOOK);
	add_unmatched_state_hook(comparison_id, unmatched_comparison);
	add_pre_merge_hook(comparison_id, &pre_merge_hook);
	add_merge_hook(comparison_id, &merge_compare_states);
	add_hook(&free_data, AFTER_FUNC_HOOK);
	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_split_return_callback(&print_return_comparison);

	select_return_states_hook(PARAM_COMPARE, &db_return_comparison);
	add_hook(&match_preop, OP_HOOK);
}

void register_comparison_late(int id)
{
	add_hook(&match_assign, ASSIGNMENT_HOOK);
}

void register_comparison_links(int id)
{
	link_id = id;
	db_ignore_states(link_id);
	set_dynamic_states(link_id);
	add_merge_hook(link_id, &merge_links);
	add_modification_hook(link_id, &match_modify);
	add_modification_hook_late(link_id, match_inc_dec);

	add_member_info_callback(link_id, struct_member_callback);
}

void register_comparison_inc_dec(int id)
{
	inc_dec_id = id;
	add_modification_hook_late(inc_dec_id, &iter_modify);
}

void register_comparison_inc_dec_links(int id)
{
	inc_dec_link_id = id;
	set_dynamic_states(inc_dec_link_id);
	set_up_link_functions(inc_dec_id, inc_dec_link_id);
}

static struct sm_state *clone_partial_sm(struct sm_state *sm, int comparison)
{
	struct compare_data *data;
	struct sm_state *clone;
	struct stree *stree;

	data = sm->state->data;

	clone = clone_sm(sm);
	clone->state = alloc_compare_state(data->left, data->left_var, data->left_vsl,
					   comparison,
					   data->right, data->right_var, data->right_vsl);
	free_slist(&clone->possible);
	add_possible_sm(clone, clone);

	stree = clone_stree(sm->pool);
	overwrite_sm_state_stree(&stree, clone);
	clone->pool = stree;

	return clone;
}

static void create_fake_history(struct sm_state *sm, int op,
			       struct state_list **true_stack,
			       struct state_list **false_stack)
{
	struct sm_state *true_sm, *false_sm;
	struct compare_data *data;
	int true_comparison;
	int false_comparison;

	data = sm->state->data;

	if (is_merged(sm) || sm->left || sm->right)
		return;

	true_comparison = comparison_intersection(data->comparison, op);
	false_comparison = comparison_intersection(data->comparison, negate_comparison(op));

	true_sm = clone_partial_sm(sm, true_comparison);
	false_sm = clone_partial_sm(sm, false_comparison);

	sm->merged = 1;
	sm->left = true_sm;
	sm->right = false_sm;

	add_ptr_list(true_stack, true_sm);
	add_ptr_list(false_stack, false_sm);
}

static void filter_by_sm(struct sm_state *sm, int op,
		       struct state_list **true_stack,
		       struct state_list **false_stack,
		       bool *useful)
{
	struct compare_data *data;
	int is_true = 0;
	int is_false = 0;

	if (!sm)
		return;
	data = sm->state->data;
	if (!data)
		goto split;
	if (data->comparison == IMPOSSIBLE_COMPARISON)
		return;

	/*
	 * We want to check that "data->comparison" is totally inside "op".  So
	 * if data->comparison is < and op is <= then that's true.  Or if
	 * data->comparison is == and op is <= then that's true.  But if
	 * data->comparison is <= and op is < than that's neither true nor
	 * false.
	 */
	if (data->comparison == comparison_intersection(data->comparison, op))
		is_true = 1;
	if (data->comparison == comparison_intersection(data->comparison, negate_comparison(op)))
		is_false = 1;

	if (!is_true && !is_false && !is_merged(sm)) {
		create_fake_history(sm, op, true_stack, false_stack);
		return;
	}

	if (debug_implied()) {
		sm_msg("%s: %s: op = '%s' negated '%s'. true_intersect = '%s' false_insersect = '%s' sm = '%s'",
		       __func__,
		       sm->state->name,
		       alloc_sname(show_comparison(op)),
		       alloc_sname(show_comparison(negate_comparison(op))),
		       alloc_sname(show_comparison(comparison_intersection(data->comparison, op))),
		       alloc_sname(show_comparison(comparison_intersection(data->comparison, negate_comparison(op)))),
		       show_sm(sm));
	}

	*useful = true;
	if (is_true)
		add_ptr_list(true_stack, sm);
	if (is_false)
		add_ptr_list(false_stack, sm);
split:
	filter_by_sm(sm->left, op, true_stack, false_stack, useful);
	filter_by_sm(sm->right, op, true_stack, false_stack, useful);
}

struct sm_state *comparison_implication_hook(struct expression *expr,
				struct state_list **true_stack,
				struct state_list **false_stack)
{
	struct sm_state *sm;
	char *left, *right;
	int op;
	static char buf[256];
	bool useful = false;

	if (expr->type != EXPR_COMPARE)
		return NULL;

	op = expr->op;

	left = expr_to_var(expr->left);
	right = expr_to_var(expr->right);
	if (!left || !right) {
		free_string(left);
		free_string(right);
		return NULL;
	}

	if (strcmp(left, right) > 0) {
		char *tmp = left;

		left = right;
		right = tmp;
		op = flip_comparison(op);
	}

	snprintf(buf, sizeof(buf), "%s vs %s", left, right);
	sm = get_sm_state(comparison_id, buf, NULL);
	if (!sm)
		return NULL;
	if (!sm->merged)
		return NULL;

	filter_by_sm(sm, op, true_stack, false_stack, &useful);
	if (!useful)
		return NULL;

	if (debug_implied())
		sm_msg("implications from comparison: (%s)", show_sm(sm));

	return sm;
}

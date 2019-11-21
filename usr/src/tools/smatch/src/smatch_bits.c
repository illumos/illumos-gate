/*
 * Copyright (C) 2015 Oracle.
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
 * This is to track when variables are masked away.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

static const struct bit_info unknown_bit_info = {
	.possible = -1ULL,
};

ALLOCATOR(bit_info, "bit data");
static struct bit_info *alloc_bit_info(unsigned long long set, unsigned long long possible)
{
	struct bit_info *bit_info = __alloc_bit_info(0);

	bit_info->set = set;
	bit_info->possible = possible;

	return bit_info;
}

static struct smatch_state *alloc_bstate(unsigned long long set, unsigned long long possible)
{
	struct smatch_state *state;
	char buf[64];

	state = __alloc_smatch_state(0);
	snprintf(buf, sizeof(buf), "0x%llx + 0x%llx", set, possible);
	state->name = alloc_sname(buf);
	state->data = alloc_bit_info(set, possible);

	return state;
}

struct bit_info *rl_to_binfo(struct range_list *rl)
{
	struct bit_info *ret = __alloc_bit_info(0);
	sval_t sval;

	if (rl_to_sval(rl, &sval)) {
		ret->set = sval.uvalue;
		ret->possible = sval.uvalue;

		return ret;
	}

	ret->set = 0;
	ret->possible = sval_fls_mask(rl_max(rl));
	// FIXME: what about negatives?

	return ret;
}

static int is_unknown_binfo(struct symbol *type, struct bit_info *binfo)
{
	if (!type)
		type = &ullong_ctype;

	if (binfo->set != 0)
		return 0;
	if (binfo->possible < (-1ULL >> (64 - type_bits(type))))
		return 0;

	return 1;
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	struct smatch_state *estate;
	struct symbol *type;
	unsigned long long possible;
	struct bit_info *p;

	estate = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (estate_rl(estate)) {
		p = rl_to_binfo(estate_rl(estate));
		return alloc_bstate(p->set, p->possible);
	}

	type = estate_type(estate);
	if (!type)
		return alloc_bstate(0, -1ULL);

	if (type_bits(type) == 64)
		possible = -1ULL;
	else
		possible = (1ULL << type_bits(type)) - 1;

	return alloc_bstate(0, possible);
}

static void match_modify(struct sm_state *sm, struct expression *mod_expr)
{
	// FIXME: we really need to store the type

	set_state(my_id, sm->name, sm->sym, alloc_bstate(0, -1ULL));
}

static int binfo_equiv(struct bit_info *one, struct bit_info *two)
{
	if (one->set == two->set &&
	    one->possible == two->possible)
		return 1;
	return 0;
}

static struct smatch_state *merge_bstates(struct smatch_state *one_state, struct smatch_state *two_state)
{
	struct bit_info *one, *two;

	one = one_state->data;
	two = two_state->data;

	if (binfo_equiv(one, two))
		return one_state;

	return alloc_bstate(one->set & two->set, one->possible | two->possible);
}

/*
 * The combine_bit_info() takes two bit_infos and takes creates the most
 * accurate picture we can assuming both are true.  Or it returns unknown if
 * the information is logically impossible.
 *
 * Which means that it takes the | of the ->set bits and the & of the possibly
 * set bits, which is the opposite of what merge_bstates() does.
 *
 */
static struct bit_info *combine_bit_info(struct bit_info *one, struct bit_info *two)
{
	struct bit_info *ret = __alloc_bit_info(0);

	if ((one->set & two->possible) != one->set)
		return alloc_bit_info(0, -1ULL);
	if ((two->set & one->possible) != two->set)
		return alloc_bit_info(0, -1ULL);

	ret->set = one->set | two->set;
	ret->possible = one->possible & two->possible;

	return ret;
}

static struct bit_info *binfo_AND(struct bit_info *left, struct bit_info *right)
{
	unsigned long long set = 0;
	unsigned long long possible = -1ULL;

	if (!left && !right) {
		/* nothing */
	} else if (!left) {
		possible = right->possible;
	} else if (!right) {
		possible = left->possible;
	} else {
		set = left->set & right->set;
		possible = left->possible & right->possible;
	}

	return alloc_bit_info(set, possible);
}

static struct bit_info *binfo_OR(struct bit_info *left, struct bit_info *right)
{
	unsigned long long set = 0;
	unsigned long long possible = -1ULL;

	if (!left && !right) {
		/* nothing */
	} else if (!left) {
		set = right->set;
	} else if (!right) {
		set = left->set;
	} else {
		set = left->set | right->set;
		possible = left->possible | right->possible;
	}

	return alloc_bit_info(set, possible);
}

struct bit_info *get_bit_info(struct expression *expr)
{
	struct range_list *rl;
	struct smatch_state *bstate;
	struct bit_info tmp;
	struct bit_info *extra_info;
	struct bit_info *bit_info;
	sval_t known;

	expr = strip_parens(expr);

	if (get_implied_value(expr, &known))
		return alloc_bit_info(known.value, known.value);

	if (expr->type == EXPR_BINOP) {
		if (expr->op == '&')
			return binfo_AND(get_bit_info(expr->left),
					 get_bit_info(expr->right));
		if (expr->op == '|')
			return binfo_OR(get_bit_info(expr->left),
					get_bit_info(expr->right));
	}

	if (get_implied_rl(expr, &rl))
		extra_info = rl_to_binfo(rl);
	else {
		struct symbol *type;

		tmp = unknown_bit_info;
		extra_info = &tmp;

		type = get_type(expr);
		if (!type)
			type = &ullong_ctype;
		if (type_bits(type) == 64)
			extra_info->possible = -1ULL;
		else
			extra_info->possible = (1ULL << type_bits(type)) - 1;
	}

	bstate = get_state_expr(my_id, expr);
	if (bstate)
		bit_info = bstate->data;
	else
		bit_info = (struct bit_info *)&unknown_bit_info;

	return combine_bit_info(extra_info, bit_info);
}

static int is_single_bit(sval_t sval)
{
	int i;
	int count = 0;

	for (i = 0; i < 64; i++) {
		if (sval.uvalue & 1ULL << i &&
		    count++)
			return 0;
	}
	if (count == 1)
		return 1;
	return 0;
}

static void match_compare(struct expression *expr)
{
	sval_t val;

	if (expr->type != EXPR_COMPARE)
		return;
	if (expr->op != SPECIAL_EQUAL &&
	    expr->op != SPECIAL_NOTEQUAL)
		return;

	if (!get_implied_value(expr->right, &val))
		return;

	set_true_false_states_expr(my_id, expr->left,
			(expr->op == SPECIAL_EQUAL) ? alloc_bstate(val.uvalue, val.uvalue) : NULL,
			(expr->op == SPECIAL_EQUAL) ? NULL : alloc_bstate(val.uvalue, val.uvalue));
}

static bool is_loop_iterator(struct expression *expr)
{
	struct statement *pre_stmt, *loop_stmt;

	pre_stmt = expr_get_parent_stmt(expr);
	if (!pre_stmt || pre_stmt->type != STMT_EXPRESSION)
		return false;

	loop_stmt = stmt_get_parent_stmt(pre_stmt);
	if (!loop_stmt || loop_stmt->type != STMT_ITERATOR)
		return false;
	if (loop_stmt->iterator_pre_statement != pre_stmt)
		return false;

	return true;
}

static void match_assign(struct expression *expr)
{
	struct bit_info *binfo;

	if (expr->op != '=')
		return;
	if (__in_fake_assign)
		return;
	if (is_loop_iterator(expr))
		return;

	binfo = get_bit_info(expr->right);
	if (!binfo)
		return;
	if (is_unknown_binfo(get_type(expr->left), binfo))
		return;
	set_state_expr(my_id, expr->left, alloc_bstate(binfo->set, binfo->possible));
}

static void match_condition(struct expression *expr)
{
	struct bit_info *orig;
	struct bit_info true_info;
	struct bit_info false_info;
	sval_t right;

	if (expr->type != EXPR_BINOP ||
	    expr->op != '&')
		return;

	if (!get_value(expr->right, &right))
		return;

	orig = get_bit_info(expr->left);
	true_info = *orig;
	false_info = *orig;

	if (right.uvalue == 0 || is_single_bit(right))
		true_info.set &= right.uvalue;

	true_info.possible &= right.uvalue;
	false_info.possible &= ~right.uvalue;

	set_true_false_states_expr(my_id, expr->left,
				   alloc_bstate(true_info.set, true_info.possible),
				   alloc_bstate(false_info.set, false_info.possible));
}

static void match_call_info(struct expression *expr)
{
	struct bit_info *binfo, *rl_binfo;
	struct expression *arg;
	struct range_list *rl;
	char buf[64];
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		binfo = get_bit_info(arg);
		if (!binfo)
			continue;
		if (is_unknown_binfo(get_type(arg), binfo))
			continue;
		if (get_implied_rl(arg, &rl)) {
			rl_binfo = rl_to_binfo(rl);
			if (binfo_equiv(rl_binfo, binfo))
				continue;
		}
		// If is just non-negative continue
		// If ->set == ->possible continue
		snprintf(buf, sizeof(buf), "0x%llx,0x%llx", binfo->set, binfo->possible);
		sql_insert_caller_info(expr, BIT_INFO, i, "$", buf);
	} END_FOR_EACH_PTR(arg);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	struct bit_info *binfo = sm->state->data;
	struct smatch_state *estate;
	struct bit_info *implied_binfo;
	char buf[64];

	if (!binfo)
		return;

	/* This means it can only be one value, so it's handled by smatch_extra. */
	if (binfo->set == binfo->possible)
		return;

	estate = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (is_unknown_binfo(estate_type(estate), binfo))
		return;

	if (estate_rl(estate)) {
		sval_t sval;

		if (estate_get_single_value(estate, &sval))
			return;

		implied_binfo = rl_to_binfo(estate_rl(estate));
		if (binfo_equiv(implied_binfo, binfo))
			return;
	}

	snprintf(buf, sizeof(buf), "0x%llx,0x%llx", binfo->set, binfo->possible);
	sql_insert_caller_info(call, BIT_INFO, param, printed_name, buf);
}

static void set_param_bits(const char *name, struct symbol *sym, char *key, char *value)
{
	char fullname[256];
	unsigned long long set, possible;

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	set = strtoull(value, &value, 16);
	if (*value != ',')
		return;
	value++;
	possible = strtoull(value, &value, 16);

	set_state(my_id, fullname, sym, alloc_bstate(set, possible));
}

void register_bits(int id)
{
	my_id = id;

	set_dynamic_states(my_id);

	add_unmatched_state_hook(my_id, &unmatched_state);
	add_merge_hook(my_id, &merge_bstates);

	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_compare, CONDITION_HOOK);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_modification_hook(my_id, &match_modify);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	select_caller_info_hook(set_param_bits, BIT_INFO);
}

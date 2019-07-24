/*
 * Copyright (C) 2011 Dan Carpenter.
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
 * There are a couple checks that try to see if a variable
 * comes from the user.  It would be better to unify them
 * into one place.  Also it we should follow the data down
 * the call paths.  Hence this file.
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static int my_call_id;

STATE(called);
static bool func_gets_user_data;

static const char *kstr_funcs[] = {
	"kstrtoull", "kstrtoll", "kstrtoul", "kstrtol", "kstrtouint",
	"kstrtoint", "kstrtou64", "kstrtos64", "kstrtou32", "kstrtos32",
	"kstrtou16", "kstrtos16", "kstrtou8", "kstrtos8", "kstrtoull_from_user"
	"kstrtoll_from_user", "kstrtoul_from_user", "kstrtol_from_user",
	"kstrtouint_from_user", "kstrtoint_from_user", "kstrtou16_from_user",
	"kstrtos16_from_user", "kstrtou8_from_user", "kstrtos8_from_user",
	"kstrtou64_from_user", "kstrtos64_from_user", "kstrtou32_from_user",
	"kstrtos32_from_user",
};

static const char *returns_user_data[] = {
	"simple_strtol", "simple_strtoll", "simple_strtoul", "simple_strtoull",
	"kvm_register_read",
};

static const char *returns_pointer_to_user_data[] = {
	"nlmsg_data", "nla_data", "memdup_user", "kmap_atomic", "skb_network_header",
};

static void set_points_to_user_data(struct expression *expr);

static struct stree *start_states;
static struct stree_stack *saved_stack;
static void save_start_states(struct statement *stmt)
{
	start_states = clone_stree(__get_cur_stree());
}

static void free_start_states(void)
{
	free_stree(&start_states);
}

static void match_save_states(struct expression *expr)
{
	push_stree(&saved_stack, start_states);
	start_states = NULL;
}

static void match_restore_states(struct expression *expr)
{
	free_stree(&start_states);
	start_states = pop_stree(&saved_stack);
}

static struct smatch_state *empty_state(struct sm_state *sm)
{
	return alloc_estate_empty();
}

static void pre_merge_hook(struct sm_state *sm)
{
	struct smatch_state *user;
	struct smatch_state *extra;
	struct smatch_state *state;
	struct range_list *rl;
	sval_t dummy;
	sval_t sval_100;

	sval_100.value = 100;
	sval_100.type = &int_ctype;

	user = __get_state(my_id, sm->name, sm->sym);
	if (!user || !estate_rl(user))
		return;
	extra = __get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!extra)
		return;
	rl = rl_intersection(estate_rl(user), estate_rl(extra));
	if (rl_to_sval(rl, &dummy))
		rl = NULL;
	state = alloc_estate_rl(clone_rl(rl));
	if (estate_capped(user) || is_capped_var_sym(sm->name, sm->sym))
		estate_set_capped(state);
	set_state(my_id, sm->name, sm->sym, state);
}

static void extra_nomod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	struct smatch_state *user, *new;
	struct range_list *rl;

	user = __get_state(my_id, name, sym);
	if (!user)
		return;
	rl = rl_intersection(estate_rl(user), estate_rl(state));
	if (rl_equiv(rl, estate_rl(user)))
		return;
	new = alloc_estate_rl(rl);
	if (estate_capped(user))
		estate_set_capped(new);
	set_state(my_id, name, sym, new);
}

static bool binop_capped(struct expression *expr)
{
	struct range_list *left_rl;
	int comparison;

	if (expr->op == '-' && get_user_rl(expr->left, &left_rl)) {
		if (user_rl_capped(expr->left))
			return true;
		comparison = get_comparison(expr->left, expr->right);
		if (comparison && show_special(comparison)[0] == '>')
			return true;
		return false;
	}

	if (expr->op == '&' || expr->op == '%') {
		if (is_capped(expr->left) || is_capped(expr->right))
			return true;
		if (user_rl_capped(expr->left) || user_rl_capped(expr->right))
			return true;
		return false;
	}

	if (user_rl_capped(expr->left) &&
	    user_rl_capped(expr->right))
		return true;
	return false;
}

bool user_rl_capped(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;
	sval_t sval;

	expr = strip_expr(expr);
	if (!expr)
		return false;
	if (get_value(expr, &sval))
		return true;
	if (expr->type == EXPR_BINOP)
		return binop_capped(expr);
	if ((expr->type == EXPR_PREOP || expr->type == EXPR_POSTOP) &&
	    (expr->op == SPECIAL_INCREMENT || expr->op == SPECIAL_DECREMENT))
		return user_rl_capped(expr->unop);
	state = get_state_expr(my_id, expr);
	if (state)
		return estate_capped(state);

	if (get_user_rl(expr, &rl))
		return false;  /* uncapped user data */

	return true;  /* not actually user data */
}

static void tag_inner_struct_members(struct expression *expr, struct symbol *member)
{
	struct expression *edge_member;
	struct symbol *base = get_real_base_type(member);
	struct symbol *tmp;

	if (member->ident)
		expr = member_expression(expr, '.', member->ident);

	FOR_EACH_PTR(base->symbol_list, tmp) {
		struct symbol *type;

		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			tag_inner_struct_members(expr, tmp);
			continue;
		}

		if (!tmp->ident)
			continue;

		edge_member = member_expression(expr, '.', tmp->ident);
		set_state_expr(my_id, edge_member, alloc_estate_whole(type));
	} END_FOR_EACH_PTR(tmp);
}

static void tag_struct_members(struct symbol *type, struct expression *expr)
{
	struct symbol *tmp;
	struct expression *member;
	int op = '*';

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		op = '.';
	}

	FOR_EACH_PTR(type->symbol_list, tmp) {
		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			tag_inner_struct_members(expr, tmp);
			continue;
		}

		if (!tmp->ident)
			continue;

		member = member_expression(expr, op, tmp->ident);
		set_state_expr(my_id, member, alloc_estate_whole(get_type(member)));

		if (type->type == SYM_ARRAY)
			set_points_to_user_data(member);
	} END_FOR_EACH_PTR(tmp);
}

static void tag_base_type(struct expression *expr)
{
	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_expr(expr->unop);
	else
		expr = deref_expression(expr);
	set_state_expr(my_id, expr, alloc_estate_whole(get_type(expr)));
}

static void tag_as_user_data(struct expression *expr)
{
	struct symbol *type;

	expr = strip_expr(expr);

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type)
		return;
	if (type == &void_ctype) {
		set_state_expr(my_id, deref_expression(expr), alloc_estate_whole(&ulong_ctype));
		return;
	}
	if (type->type == SYM_BASETYPE)
		tag_base_type(expr);
	if (type->type == SYM_STRUCT || type->type == SYM_UNION) {
		if (expr->type != EXPR_PREOP || expr->op != '&')
			expr = deref_expression(expr);
		else
			set_state_expr(my_id, deref_expression(expr), alloc_estate_whole(&ulong_ctype));
		tag_struct_members(type, expr);
	}
}

static void match_user_copy(const char *fn, struct expression *expr, void *_param)
{
	int param = PTR_INT(_param);
	struct expression *dest;

	func_gets_user_data = true;

	dest = get_argument_from_call_expr(expr->args, param);
	dest = strip_expr(dest);
	if (!dest)
		return;
	tag_as_user_data(dest);
}

static int is_dev_attr_name(struct expression *expr)
{
	char *name;
	int ret = 0;

	name = expr_to_str(expr);
	if (!name)
		return 0;
	if (strstr(name, "->attr.name"))
		ret = 1;
	free_string(name);
	return ret;
}

static int ends_in_n(struct expression *expr)
{
	struct string *str;

	if (!expr)
		return 0;
	if (expr->type != EXPR_STRING || !expr->string)
		return 0;

	str = expr->string;
	if (str->length < 3)
		return 0;

	if (str->data[str->length - 3] == '%' &&
	    str->data[str->length - 2] == 'n')
		return 1;
	return 0;
}

static void match_sscanf(const char *fn, struct expression *expr, void *unused)
{
	struct expression *str, *format, *arg;
	int i, last;

	func_gets_user_data = true;

	str = get_argument_from_call_expr(expr->args, 0);
	if (is_dev_attr_name(str))
		return;

	format = get_argument_from_call_expr(expr->args, 1);
	if (is_dev_attr_name(format))
		return;

	last = ptr_list_size((struct ptr_list *)expr->args) - 1;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		if (i < 2)
			continue;
		if (i == last && ends_in_n(format))
			continue;
		tag_as_user_data(arg);
	} END_FOR_EACH_PTR(arg);
}

static int is_skb_data(struct expression *expr)
{
	struct symbol *sym;

	if (!expr)
		return 0;

	if (expr->type == EXPR_BINOP && expr->op == '+')
		return is_skb_data(expr->left);

	expr = strip_expr(expr);
	if (!expr)
		return 0;
	if (expr->type != EXPR_DEREF || expr->op != '.')
		return 0;

	if (!expr->member)
		return 0;
	if (strcmp(expr->member->name, "data") != 0)
		return 0;

	sym = expr_to_sym(expr->deref);
	if (!sym)
		return 0;
	sym = get_real_base_type(sym);
	if (!sym || sym->type != SYM_PTR)
		return 0;
	sym = get_real_base_type(sym);
	if (!sym || sym->type != SYM_STRUCT || !sym->ident)
		return 0;
	if (strcmp(sym->ident->name, "sk_buff") != 0)
		return 0;

	return 1;
}

static bool is_points_to_user_data_fn(struct expression *expr)
{
	int i;

	expr = strip_expr(expr);
	if (expr->type != EXPR_CALL || expr->fn->type != EXPR_SYMBOL ||
	    !expr->fn->symbol)
		return false;
	expr = expr->fn;
	for (i = 0; i < ARRAY_SIZE(returns_pointer_to_user_data); i++) {
		if (sym_name_is(returns_pointer_to_user_data[i], expr))
			return true;
	}
	return false;
}

static int get_rl_from_function(struct expression *expr, struct range_list **rl)
{
	int i;

	if (expr->type != EXPR_CALL || expr->fn->type != EXPR_SYMBOL ||
	    !expr->fn->symbol_name || !expr->fn->symbol_name->name)
		return 0;

	for (i = 0; i < ARRAY_SIZE(returns_user_data); i++) {
		if (strcmp(expr->fn->symbol_name->name, returns_user_data[i]) == 0) {
			*rl = alloc_whole_rl(get_type(expr));
			return 1;
		}
	}
	return 0;
}

int points_to_user_data(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;
	char buf[256];
	struct symbol *sym;
	char *name;
	int ret = 0;

	expr = strip_expr(expr);
	if (!expr)
		return 0;
	if (is_skb_data(expr))
		return 1;
	if (is_points_to_user_data_fn(expr))
		return 1;
	if (get_rl_from_function(expr, &rl))
		return 1;

	if (expr->type == EXPR_BINOP && expr->op == '+') {
		if (points_to_user_data(expr->left))
			return 1;
		if (points_to_user_data(expr->right))
			return 1;
		return 0;
	}

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	snprintf(buf, sizeof(buf), "*%s", name);
	state = __get_state(my_id, buf, sym);
	if (state && estate_rl(state))
		ret = 1;
free:
	free_string(name);
	return ret;
}

static void set_points_to_user_data(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	char buf[256];
	struct symbol *type;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	snprintf(buf, sizeof(buf), "*%s", name);
	type = get_type(expr);
	if (type && type->type == SYM_PTR)
		type = get_real_base_type(type);
	if (!type || type->type != SYM_BASETYPE)
		type = &llong_ctype;
	set_state(my_id, buf, sym, alloc_estate_whole(type));
free:
	free_string(name);
}

static int comes_from_skb_data(struct expression *expr)
{
	expr = strip_expr(expr);
	if (!expr || expr->type != EXPR_PREOP || expr->op != '*')
		return 0;

	expr = strip_expr(expr->unop);
	if (!expr)
		return 0;
	if (expr->type == EXPR_BINOP && expr->op == '+')
		expr = strip_expr(expr->left);

	return is_skb_data(expr);
}

static int handle_struct_assignment(struct expression *expr)
{
	struct expression *right;
	struct symbol *left_type, *right_type;

	left_type = get_type(expr->left);
	if (!left_type || left_type->type != SYM_PTR)
		return 0;
	left_type = get_real_base_type(left_type);
	if (!left_type)
		return 0;
	if (left_type->type != SYM_STRUCT &&
	    left_type->type != SYM_UNION)
		return 0;

	/*
	 * Ignore struct to struct assignments because for those we look at the
	 * individual members.
	 */
	right = strip_expr(expr->right);
	right_type = get_type(right);
	if (!right_type || right_type->type != SYM_PTR)
		return 0;

	/* If we are assigning struct members then normally that is handled
	 * by fake assignments, however if we cast one struct to a different
	 * of struct then we handle that here.
	 */
	right_type = get_real_base_type(right_type);
	if (right_type == left_type)
		return 0;

	if (!points_to_user_data(right))
		return 0;

	tag_as_user_data(expr->left);
	return 1;
}

static int handle_get_user(struct expression *expr)
{
	char *name;
	int ret = 0;

	name = get_macro_name(expr->pos);
	if (!name || strcmp(name, "get_user") != 0)
		return 0;

	name = expr_to_var(expr->right);
	if (!name || strcmp(name, "__val_gu") != 0)
		goto free;
	set_state_expr(my_id, expr->left, alloc_estate_whole(get_type(expr->left)));
	ret = 1;
free:
	free_string(name);
	return ret;
}

static bool handle_op_assign(struct expression *expr)
{
	struct expression *binop_expr;
	struct smatch_state *state;
	struct range_list *rl;

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
		if (!get_user_rl(binop_expr, &rl))
			return true;

		rl = cast_rl(get_type(expr->left), rl);
		state = alloc_estate_rl(rl);
		if (user_rl_capped(binop_expr))
			estate_set_capped(state);
		set_state_expr(my_id, expr->left, state);
		return true;
	}
	return false;
}

static void match_assign(struct expression *expr)
{
	struct range_list *rl;
	static struct expression *handled;
	struct smatch_state *state;
	struct expression *faked;

	faked = get_faked_expression();
	if (faked && faked == handled)
		return;
	if (is_fake_call(expr->right))
		goto clear_old_state;
	if (handle_get_user(expr))
		return;
	if (points_to_user_data(expr->right)) {
		handled = expr;
		set_points_to_user_data(expr->left);
	}
	if (handle_struct_assignment(expr))
		return;

	if (handle_op_assign(expr))
		return;
	if (expr->op != '=')
		goto clear_old_state;

	/* Handled by DB code */
	if (expr->right->type == EXPR_CALL || __in_fake_parameter_assign)
		return;

	if (!get_user_rl(expr->right, &rl))
		goto clear_old_state;

	rl = cast_rl(get_type(expr->left), rl);
	state = alloc_estate_rl(rl);
	if (user_rl_capped(expr->right))
		estate_set_capped(state);
	set_state_expr(my_id, expr->left, state);

	return;

clear_old_state:
	if (get_state_expr(my_id, expr->left))
		set_state_expr(my_id, expr->left, alloc_estate_empty());
}

static void handle_eq_noteq(struct expression *expr)
{
	struct smatch_state *left_orig, *right_orig;

	left_orig = get_state_expr(my_id, expr->left);
	right_orig = get_state_expr(my_id, expr->right);

	if (!left_orig && !right_orig)
		return;
	if (left_orig && right_orig)
		return;

	if (left_orig) {
		set_true_false_states_expr(my_id, expr->left,
				expr->op == SPECIAL_EQUAL ? alloc_estate_empty() : NULL,
				expr->op == SPECIAL_EQUAL ? NULL : alloc_estate_empty());
	} else {
		set_true_false_states_expr(my_id, expr->right,
				expr->op == SPECIAL_EQUAL ? alloc_estate_empty() : NULL,
				expr->op == SPECIAL_EQUAL ? NULL : alloc_estate_empty());
	}
}

static struct range_list *strip_negatives(struct range_list *rl)
{
	sval_t min = rl_min(rl);
	sval_t minus_one;
	sval_t over;
	sval_t max = sval_type_max(rl_type(rl));

	minus_one.type = rl_type(rl);
	minus_one.value = INT_MAX + 1ULL;
	over.type = rl_type(rl);
	over.value = -1;

	if (!rl)
		return NULL;

	if (type_unsigned(rl_type(rl)) && type_bits(rl_type(rl)) > 31)
		return remove_range(rl, over, max);

	return remove_range(rl, min, minus_one);
}

static void handle_compare(struct expression *expr)
{
	struct expression  *left, *right;
	struct range_list *left_rl = NULL;
	struct range_list *right_rl = NULL;
	struct range_list *user_rl;
	struct smatch_state *capped_state;
	struct smatch_state *left_true = NULL;
	struct smatch_state *left_false = NULL;
	struct smatch_state *right_true = NULL;
	struct smatch_state *right_false = NULL;
	struct symbol *type;
	sval_t sval;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	while (left->type == EXPR_ASSIGNMENT)
		left = strip_expr(left->left);

	/*
	 * Conditions are mostly handled by smatch_extra.c, but there are some
	 * times where the exact values are not known so we can't do that.
	 *
	 * Normally, we might consider using smatch_capped.c to supliment smatch
	 * extra but that doesn't work when we merge unknown uncapped kernel
	 * data with unknown capped user data.  The result is uncapped user
	 * data.  We need to keep it separate and say that the user data is
	 * capped.  In the past, I would have marked this as just regular
	 * kernel data (not user data) but we can't do that these days because
	 * we need to track user data for Spectre.
	 *
	 * The other situation which we have to handle is when we do have an
	 * int and we compare against an unknown unsigned kernel variable.  In
	 * that situation we assume that the kernel data is less than INT_MAX.
	 * Otherwise then we get all sorts of array underflow false positives.
	 *
	 */

	/* Handled in smatch_extra.c */
	if (get_implied_value(left, &sval) ||
	    get_implied_value(right, &sval))
		return;

	get_user_rl(left, &left_rl);
	get_user_rl(right, &right_rl);

	/* nothing to do */
	if (!left_rl && !right_rl)
		return;
	/* if both sides are user data that's not a good limit */
	if (left_rl && right_rl)
		return;

	if (left_rl)
		user_rl = left_rl;
	else
		user_rl = right_rl;

	type = get_type(expr);
	if (type_unsigned(type))
		user_rl = strip_negatives(user_rl);
	capped_state = alloc_estate_rl(user_rl);
	estate_set_capped(capped_state);

	switch (expr->op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		if (left_rl)
			left_true = capped_state;
		else
			right_false = capped_state;
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		if (left_rl)
			left_false = capped_state;
		else
			right_true = capped_state;
		break;
	}

	set_true_false_states_expr(my_id, left, left_true, left_false);
	set_true_false_states_expr(my_id, right, right_true, right_false);
}

static void match_condition(struct expression *expr)
{
	if (expr->type != EXPR_COMPARE)
		return;

	if (expr->op == SPECIAL_EQUAL ||
	    expr->op == SPECIAL_NOTEQUAL) {
		handle_eq_noteq(expr);
		return;
	}

	handle_compare(expr);
}

static void match_user_assign_function(const char *fn, struct expression *expr, void *unused)
{
	tag_as_user_data(expr->left);
	set_points_to_user_data(expr->left);
}

static void match_returns_user_rl(const char *fn, struct expression *expr, void *unused)
{
	func_gets_user_data = true;
}

static int get_user_macro_rl(struct expression *expr, struct range_list **rl)
{
	struct expression *parent;
	char *macro;

	if (!expr)
		return 0;

	macro = get_macro_name(expr->pos);
	if (!macro)
		return 0;

	/* handle ntohl(foo[i]) where "i" is trusted */
	parent = expr_get_parent_expr(expr);
	while (parent && parent->type != EXPR_BINOP)
		parent = expr_get_parent_expr(parent);
	if (parent && parent->type == EXPR_BINOP) {
		char *parent_macro = get_macro_name(parent->pos);

		if (parent_macro && strcmp(macro, parent_macro) == 0)
			return 0;
	}

	if (strcmp(macro, "ntohl") == 0) {
		*rl = alloc_whole_rl(&uint_ctype);
		return 1;
	}
	if (strcmp(macro, "ntohs") == 0) {
		*rl = alloc_whole_rl(&ushort_ctype);
		return 1;
	}
	return 0;
}

static int has_user_data(struct symbol *sym)
{
	struct sm_state *tmp;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), tmp) {
		if (tmp->sym == sym)
			return 1;
	} END_FOR_EACH_SM(tmp);
	return 0;
}

static int we_pass_user_data(struct expression *call)
{
	struct expression *arg;
	struct symbol *sym;

	FOR_EACH_PTR(call->args, arg) {
		sym = expr_to_sym(arg);
		if (!sym)
			continue;
		if (has_user_data(sym))
			return 1;
	} END_FOR_EACH_PTR(arg);

	return 0;
}

static int db_returned_user_rl(struct expression *call, struct range_list **rl)
{
	struct smatch_state *state;
	char buf[48];

	if (is_fake_call(call))
		return 0;
	snprintf(buf, sizeof(buf), "return %p", call);
	state = get_state(my_id, buf, NULL);
	if (!state || !estate_rl(state))
		return 0;
	*rl = estate_rl(state);
	return 1;
}

struct stree *get_user_stree(void)
{
	return get_all_states_stree(my_id);
}

static int user_data_flag;
static int no_user_data_flag;
struct range_list *var_user_rl(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;
	struct range_list *absolute_rl;

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		no_user_data_flag = 1;
		return NULL;
	}

	if (expr->type == EXPR_BINOP && expr->op == '%') {
		struct range_list *left, *right;

		if (!get_user_rl(expr->right, &right))
			return NULL;
		get_absolute_rl(expr->left, &left);
		rl = rl_binop(left, '%', right);
		goto found;
	}

	if (expr->type == EXPR_BINOP && expr->op == '/') {
		struct range_list *left = NULL;
		struct range_list *right = NULL;
		struct range_list *abs_right;

		/*
		 * The specific bug I'm dealing with is:
		 *
		 * foo = capped_user / unknown;
		 *
		 * Instead of just saying foo is now entirely user_rl we should
		 * probably say instead that it is not at all user data.
		 *
		 */

		get_user_rl(expr->left, &left);
		get_user_rl(expr->right, &right);
		get_absolute_rl(expr->right, &abs_right);

		if (left && !right) {
			rl = rl_binop(left, '/', abs_right);
			if (sval_cmp(rl_max(left), rl_max(rl)) < 0)
				no_user_data_flag = 1;
		}

		return NULL;
	}

	if (get_rl_from_function(expr, &rl))
		goto found;

	if (get_user_macro_rl(expr, &rl))
		goto found;

	if (comes_from_skb_data(expr)) {
		rl = alloc_whole_rl(get_type(expr));
		goto found;
	}

	state = get_state_expr(my_id, expr);
	if (state && estate_rl(state)) {
		rl = estate_rl(state);
		goto found;
	}

	if (expr->type == EXPR_CALL && db_returned_user_rl(expr, &rl))
		goto found;

	if (is_array(expr)) {
		struct expression *array = get_array_base(expr);

		if (!get_state_expr(my_id, array)) {
			no_user_data_flag = 1;
			return NULL;
		}
	}

	if (expr->type == EXPR_PREOP && expr->op == '*' &&
	    is_user_rl(expr->unop)) {
		rl = var_to_absolute_rl(expr);
		goto found;
	}

	return NULL;
found:
	user_data_flag = 1;
	absolute_rl = var_to_absolute_rl(expr);
	return clone_rl(rl_intersection(rl, absolute_rl));
}

static bool is_ptr_subtract(struct expression *expr)
{
	expr = strip_expr(expr);
	if (!expr)
		return false;
	if (expr->type == EXPR_BINOP && expr->op == '-' &&
	    type_is_ptr(get_type(expr->left))) {
		return true;
	}
	return false;
}

int get_user_rl(struct expression *expr, struct range_list **rl)
{
	if (is_ptr_subtract(expr))
		return 0;

	user_data_flag = 0;
	no_user_data_flag = 0;
	custom_get_absolute_rl(expr, &var_user_rl, rl);
	if (!user_data_flag || no_user_data_flag)
		*rl = NULL;

	return !!*rl;
}

int is_user_rl(struct expression *expr)
{
	struct range_list *tmp;

	return !!get_user_rl(expr, &tmp);
}

int get_user_rl_var_sym(const char *name, struct symbol *sym, struct range_list **rl)
{
	struct smatch_state *state;

	state = get_state(my_id, name, sym);
	if (state && estate_rl(state)) {
		*rl = estate_rl(state);
		return 1;
	}
	return 0;
}

static char *get_user_rl_str(struct expression *expr, struct symbol *type)
{
	struct range_list *rl;
	static char buf[64];

	if (!get_user_rl(expr, &rl))
		return NULL;
	rl = cast_rl(type, rl);
	snprintf(buf, sizeof(buf), "%s%s",
		 show_rl(rl), user_rl_capped(expr) ? "[c]" : "");
	return buf;
}

static void match_call_info(struct expression *expr)
{
	struct expression *arg;
	struct symbol *type;
	char *str;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		type = get_arg_type(expr->fn, i);
		str = get_user_rl_str(arg, type);
		if (!str)
			continue;

		sql_insert_caller_info(expr, USER_DATA, i, "$", str);
	} END_FOR_EACH_PTR(arg);
}

static int is_struct_ptr(struct symbol *sym)
{
	struct symbol *type;

	if (!sym)
		return 0;
	type = get_real_base_type(sym);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_STRUCT)
		return 0;
	return 1;
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	struct smatch_state *state;
	struct range_list *rl;
	struct symbol *type;
	char buf[64];

	/*
	 * Smatch uses a hack where if we get an unsigned long we say it's
	 * both user data and it points to user data.  But if we pass it to a
	 * function which takes an int, then it's just user data.  There's not
	 * enough bytes for it to be a pointer.
	 *
	 */
	type = get_arg_type(call->fn, param);
	if (type && type_bits(type) < type_bits(&ptr_ctype))
		return;

	if (strcmp(sm->state->name, "") == 0)
		return;

	if (strcmp(printed_name, "*$") == 0 &&
	    is_struct_ptr(sm->sym))
		return;

	state = __get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!state || !estate_rl(state))
		rl = estate_rl(sm->state);
	else
		rl = rl_intersection(estate_rl(sm->state), estate_rl(state));

	if (!rl)
		return;

	snprintf(buf, sizeof(buf), "%s%s", show_rl(rl),
		 estate_capped(sm->state) ? "[c]" : "");
	sql_insert_caller_info(call, USER_DATA, param, printed_name, buf);
}

static void db_param_set(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;
	struct smatch_state *state;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	state = get_state(my_id, name, sym);
	if (!state)
		goto free;

	set_state(my_id, name, sym, alloc_estate_empty());
free:
	free_string(name);
}

static bool param_data_capped(const char *value)
{
	if (strstr(value, ",c") || strstr(value, "[c"))
		return true;
	return false;
}

static void set_param_user_data(const char *name, struct symbol *sym, char *key, char *value)
{
	struct range_list *rl = NULL;
	struct smatch_state *state;
	struct expression *expr;
	struct symbol *type;
	char fullname[256];
	char *key_orig = key;
	bool add_star = false;

	if (strcmp(key, "**$") == 0) {
		snprintf(fullname, sizeof(fullname), "**%s", name);
	} else {
		if (key[0] == '*') {
			add_star = true;
			key++;
		}

		snprintf(fullname, 256, "%s%s%s", add_star ? "*" : "", name, key + 1);
	}

	expr = symbol_expression(sym);
	type = get_member_type_from_key(expr, key_orig);

	/*
	 * Say this function takes a struct ponter but the caller passes
	 * this_function(skb->data).  We have two options, we could pass *$
	 * as user data or we could pass foo->bar, foo->baz as user data.
	 * The second option is easier to implement so we do that.
	 *
	 */
	if (strcmp(key_orig, "*$") == 0) {
		struct symbol *tmp = type;

		while (tmp && tmp->type == SYM_PTR)
			tmp = get_real_base_type(tmp);

		if (tmp && (tmp->type == SYM_STRUCT || tmp->type == SYM_UNION)) {
			tag_as_user_data(symbol_expression(sym));
			return;
		}
	}

	str_to_rl(type, value, &rl);
	state = alloc_estate_rl(rl);
	if (param_data_capped(value) || is_capped(expr))
		estate_set_capped(state);
	set_state(my_id, fullname, sym, state);
}

static void set_called(const char *name, struct symbol *sym, char *key, char *value)
{
	set_state(my_call_id, "this_function", NULL, &called);
}

static void match_syscall_definition(struct symbol *sym)
{
	struct symbol *arg;
	char *macro;
	char *name;
	int is_syscall = 0;

	macro = get_macro_name(sym->pos);
	if (macro &&
	    (strncmp("SYSCALL_DEFINE", macro, strlen("SYSCALL_DEFINE")) == 0 ||
	     strncmp("COMPAT_SYSCALL_DEFINE", macro, strlen("COMPAT_SYSCALL_DEFINE")) == 0))
		is_syscall = 1;

	name = get_function();
	if (!option_no_db && get_state(my_call_id, "this_function", NULL) != &called) {
		if (name && strncmp(name, "sys_", 4) == 0)
			is_syscall = 1;
	}

	if (name && strncmp(name, "compat_sys_", 11) == 0)
		is_syscall = 1;

	if (!is_syscall)
		return;

	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		set_state(my_id, arg->ident->name, arg, alloc_estate_whole(get_real_base_type(arg)));
	} END_FOR_EACH_PTR(arg);
}

static void store_user_data_return(struct expression *expr, char *key, char *value)
{
	struct range_list *rl;
	struct symbol *type;
	char buf[48];

	if (strcmp(key, "$") != 0)
		return;

	type = get_type(expr);
	snprintf(buf, sizeof(buf), "return %p", expr);
	call_results_to_rl(expr, type, value, &rl);

	set_state(my_id, buf, NULL, alloc_estate_rl(rl));
}

static void set_to_user_data(struct expression *expr, char *key, char *value)
{
	struct smatch_state *state;
	char *name;
	struct symbol *sym;
	struct symbol *type;
	struct range_list *rl = NULL;

	type = get_member_type_from_key(expr, key);
	name = get_variable_from_key(expr, key, &sym);
	if (!name || !sym)
		goto free;

	call_results_to_rl(expr, type, value, &rl);

	state = alloc_estate_rl(rl);
	if (param_data_capped(value))
		estate_set_capped(state);
	set_state(my_id, name, sym, state);
free:
	free_string(name);
}

static void returns_param_user_data(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	struct expression *call;

	call = expr;
	while (call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (call->type != EXPR_CALL)
		return;

	if (!we_pass_user_data(call))
		return;

	if (param == -1) {
		if (expr->type != EXPR_ASSIGNMENT) {
			store_user_data_return(expr, key, value);
			return;
		}
		set_to_user_data(expr->left, key, value);
		return;
	}

	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;
	set_to_user_data(arg, key, value);
}

static void returns_param_user_data_set(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;

	func_gets_user_data = true;

	if (param == -1) {
		if (expr->type != EXPR_ASSIGNMENT) {
			store_user_data_return(expr, key, value);
			return;
		}
		if (strcmp(key, "*$") == 0) {
			set_points_to_user_data(expr->left);
			tag_as_user_data(expr->left);
		} else {
			set_to_user_data(expr->left, key, value);
		}
		return;
	}

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return;
	set_to_user_data(arg, key, value);
}

static void param_set_to_user_data(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	struct smatch_state *start_state;
	struct range_list *rl;
	int param;
	char *return_str;
	const char *param_name;
	struct symbol *ret_sym;
	bool return_found = false;
	bool pointed_at_found = false;
	char buf[64];

	expr = strip_expr(expr);
	return_str = expr_to_str(expr);
	ret_sym = expr_to_sym(expr);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;

		if (!param_was_set_var_sym(sm->name, sm->sym))
			continue;

		/* The logic here was that if we were passed in a user data then
		 * we don't record that.  It's like the difference between
		 * param_filter and param_set.  When I think about it, I'm not
		 * sure it actually works.  It's probably harmless because we
		 * checked earlier that we're not returning a parameter...
		 * Let's mark this as a TODO.
		 */
		start_state = get_state_stree(start_states, my_id, sm->name, sm->sym);
		if (start_state && rl_equiv(estate_rl(sm->state), estate_rl(start_state)))
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		if (strcmp(param_name, "$") == 0)  /* The -1 param is handled after the loop */
			continue;

		snprintf(buf, sizeof(buf), "%s%s",
			 show_rl(estate_rl(sm->state)),
			 estate_capped(sm->state) ? "[c]" : "");
		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA_SET : USER_DATA,
					 param, param_name, buf);
	} END_FOR_EACH_SM(sm);

	/* This if for "return foo;" where "foo->bar" is user data. */
	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (!ret_sym)
			break;
		if (ret_sym != sm->sym)
			continue;

		param_name = state_name_to_param_name(sm->name, return_str);
		if (!param_name)
			continue;
		if (strcmp(param_name, "$") == 0)
			return_found = true;
		if (strcmp(param_name, "*$") == 0)
			pointed_at_found = true;
		snprintf(buf, sizeof(buf), "%s%s",
			 show_rl(estate_rl(sm->state)),
			 estate_capped(sm->state) ? "[c]" : "");
		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA_SET : USER_DATA,
					 -1, param_name, buf);
	} END_FOR_EACH_SM(sm);

	/* This if for "return ntohl(foo);" */
	if (!return_found && get_user_rl(expr, &rl)) {
		snprintf(buf, sizeof(buf), "%s%s",
			 show_rl(rl), user_rl_capped(expr) ? "[c]" : "");
		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA_SET : USER_DATA,
					 -1, "$", buf);
	}

	/*
	 * This is to handle things like return skb->data where we don't set a
	 * state for that.
	 */
	if (!pointed_at_found && points_to_user_data(expr)) {
		sql_insert_return_states(return_id, return_ranges,
					 (is_skb_data(expr) || func_gets_user_data) ?
					 USER_DATA_SET : USER_DATA,
					 -1, "*$", "s64min-s64max");
	}

	free_string(return_str);
}

static void returns_param_capped(struct expression *expr, int param, char *key, char *value)
{
	struct smatch_state *state, *new;
	struct symbol *sym;
	char *name;

	name = return_state_to_var_sym(expr, param, key, &sym);
	if (!name || !sym)
		goto free;

	state = get_state(my_id, name, sym);
	if (!state || estate_capped(state))
		goto free;

	new = clone_estate(state);
	estate_set_capped(new);

	set_state(my_id, name, sym, new);
free:
	free_string(name);
}

static struct int_stack *gets_data_stack;
static void match_function_def(struct symbol *sym)
{
	func_gets_user_data = false;
}

static void match_inline_start(struct expression *expr)
{
	push_int(&gets_data_stack, func_gets_user_data);
}

static void match_inline_end(struct expression *expr)
{
	func_gets_user_data = pop_int(&gets_data_stack);
}

void register_kernel_user_data(int id)
{
	int i;

	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

	set_dynamic_states(my_id);

	add_hook(&match_function_def, FUNC_DEF_HOOK);
	add_hook(&match_inline_start, INLINE_FN_START);
	add_hook(&match_inline_end, INLINE_FN_END);

	add_hook(&save_start_states, AFTER_DEF_HOOK);
	add_hook(&free_start_states, AFTER_FUNC_HOOK);
	add_hook(&match_save_states, INLINE_FN_START);
	add_hook(&match_restore_states, INLINE_FN_END);

	add_unmatched_state_hook(my_id, &empty_state);
	add_extra_nomod_hook(&extra_nomod_hook);
	add_pre_merge_hook(my_id, &pre_merge_hook);
	add_merge_hook(my_id, &merge_estates);

	add_function_hook("copy_from_user", &match_user_copy, INT_PTR(0));
	add_function_hook("__copy_from_user", &match_user_copy, INT_PTR(0));
	add_function_hook("memcpy_fromiovec", &match_user_copy, INT_PTR(0));
	for (i = 0; i < ARRAY_SIZE(kstr_funcs); i++)
		add_function_hook(kstr_funcs[i], &match_user_copy, INT_PTR(2));
	add_function_hook("usb_control_msg", &match_user_copy, INT_PTR(6));

	for (i = 0; i < ARRAY_SIZE(returns_user_data); i++) {
		add_function_assign_hook(returns_user_data[i], &match_user_assign_function, NULL);
		add_function_hook(returns_user_data[i], &match_returns_user_rl, NULL);
	}

	add_function_hook("sscanf", &match_sscanf, NULL);

	add_hook(&match_syscall_definition, AFTER_DEF_HOOK);

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	select_return_states_hook(PARAM_SET, &db_param_set);
	add_hook(&match_condition, CONDITION_HOOK);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	select_caller_info_hook(set_param_user_data, USER_DATA);
	select_return_states_hook(USER_DATA, &returns_param_user_data);
	select_return_states_hook(USER_DATA_SET, &returns_param_user_data_set);
	select_return_states_hook(CAPPED_DATA, &returns_param_capped);
	add_split_return_callback(&param_set_to_user_data);
}

void register_kernel_user_data2(int id)
{
	my_call_id = id;

	if (option_project != PROJ_KERNEL)
		return;
	select_caller_info_hook(set_called, INTERNAL);
}

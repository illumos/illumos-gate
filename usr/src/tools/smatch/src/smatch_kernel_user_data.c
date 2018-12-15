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

static const char * kstr_funcs[] = {
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
	"kvm_register_read", "nlmsg_data", "nla_data", "memdup_user",
	"kmap_atomic", "skb_network_header",
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
	struct range_list *rl;
	sval_t dummy;
	sval_t sval_100;

	sval_100.value = 100;
	sval_100.type = &int_ctype;

	user = get_state(my_id, sm->name, sm->sym);
	if (!user)
		return;
	if (!__in_function_def && !estate_rl(sm->state)) {
		/*
		 * If the one side is capped and the other side is empty then
		 * let's just mark it as not-user data because the information
		 * isn't going to be useful.  How this looks is:
		 *
		 * if (user_var > trusted)
		 *	user_var = trusted;  <-- empty state
		 * else
		 *	<-- capped
		 *
		 * The problem is that sometimes things are capped to a literal
		 * and we'd like to keep the state in that case...  Ugh.  I've
		 * added a check which assumes that everything less than 100 is
		 * probably capped against a literal.
		 *
		 */
		if (is_capped_var_sym(sm->name, sm->sym) &&
		    sval_cmp(estate_max(user), sval_100) > 0)
			set_state(my_id, sm->name, sm->sym, alloc_estate_empty());
		return;
	}
	extra = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!extra || !estate_rl(extra))
		return;
	rl = rl_intersection(estate_rl(user), estate_rl(extra));
	if (rl_to_sval(rl, &dummy))
		rl = NULL;
	set_state(my_id, sm->name, sm->sym, alloc_estate_rl(clone_rl(rl)));
}

static void extra_nomod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	struct smatch_state *user;
	struct range_list *rl;

	user = get_state(my_id, name, sym);
	if (!user)
		return;
	rl = rl_intersection(estate_rl(user), estate_rl(state));
	if (rl_equiv(rl, estate_rl(user)))
		return;
	set_state(my_id, name, sym, alloc_estate_rl(rl));
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
	state = get_state(my_id, buf, sym);
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

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	snprintf(buf, sizeof(buf), "*%s", name);
	set_state(my_id, buf, sym, alloc_estate_whole(&llong_ctype));
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

static void match_assign(struct expression *expr)
{
	struct range_list *rl;

	if (is_fake_call(expr->right))
		goto clear_old_state;
	if (handle_get_user(expr))
		return;
	if (points_to_user_data(expr->right))
		set_points_to_user_data(expr->left);
	if (handle_struct_assignment(expr))
		return;

	if (!get_user_rl(expr->right, &rl))
		goto clear_old_state;

	rl = cast_rl(get_type(expr->left), rl);
	set_state_expr(my_id, expr->left, alloc_estate_rl(rl));

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

static void handle_unsigned_lt_gt(struct expression *expr)
{
	struct symbol *type;
	struct range_list *left;
	struct range_list *right;
	struct range_list *non_negative;
	sval_t min, minus_one;

	/*
	 * conditions are mostly handled by smatch_extra.c.  The special case
	 * here is that say you have if (user_int < unknown_u32) {
	 * In Smatch extra we say that, We have no idea what value
	 * unknown_u32 is so the only thin we can say for sure is that
	 * user_int is not -1 (UINT_MAX).  But in check_user_data2.c we should
	 * assume that unless unknown_u32 is user data, it's probably less than
	 * INT_MAX.
	 *
	 */

	type = get_type(expr);
	if (!type_unsigned(type))
		return;

	/*
	 * Assume if (user < trusted) { ... because I am lazy and because this
	 * is the correct way to write code.
	 */
	if (!get_user_rl(expr->left, &left))
		return;
	if (get_user_rl(expr->right, &right))
		return;

	if (!sval_is_negative(rl_min(left)))
		return;
	min = rl_min(left);
	minus_one.type = rl_type(left);
	minus_one.value = -1;
	non_negative = remove_range(left, min, minus_one);

	switch (expr->op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		set_true_false_states_expr(my_id, expr->left,
					   alloc_estate_rl(non_negative), NULL);
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		set_true_false_states_expr(my_id, expr->left,
					   NULL, alloc_estate_rl(non_negative));
		break;
	}
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

	handle_unsigned_lt_gt(expr);
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

struct db_info {
	struct range_list *rl;
	struct expression *call;
};
static int returned_rl_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_info *db_info = _info;
	struct range_list *rl;
	char *return_ranges = argv[0];
	char *user_ranges = argv[1];
	struct expression *arg;
	int comparison;

	if (argc != 2)
		return 0;

	call_results_to_rl(db_info->call, get_type(db_info->call), user_ranges, &rl);
	if (str_to_comparison_arg(return_ranges, db_info->call, &comparison, &arg) &&
	    comparison == SPECIAL_EQUAL) {
		struct range_list *orig_rl;

		if (!get_user_rl(arg, &orig_rl))
			return 0;
		rl = rl_intersection(rl, orig_rl);
		if (!rl)
			return 0;
	}
	db_info->rl = rl_union(db_info->rl, rl);

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
	struct db_info db_info = {};

	/* for function pointers assume everything is used */
	if (call->fn->type != EXPR_SYMBOL)
		return 0;
	if (is_fake_call(call))
		return 0;

	db_info.call = call;
	run_sql(&returned_rl_callback, &db_info,
		"select return, value from return_states where %s and type = %d and parameter = -1 and key = '$';",
		get_static_filter(call->fn->symbol), USER_DATA3_SET);
	if (db_info.rl) {
		func_gets_user_data = true;
		*rl = db_info.rl;
		return 1;
	}

	run_sql(&returned_rl_callback, &db_info,
		"select return, value from return_states where %s and type = %d and parameter = -1 and key = '$';",
		get_static_filter(call->fn->symbol), USER_DATA3);
	if (db_info.rl) {
		if (!we_pass_user_data(call))
			return 0;
		*rl = db_info.rl;
		return 1;
	}

	return 0;
}

struct stree *get_user_stree(void)
{
	return get_all_states_stree(my_id);
}

static int user_data_flag;
static int no_user_data_flag;
static struct range_list *var_user_rl(struct expression *expr)
{
	struct smatch_state *state;
	struct range_list *rl;
	struct range_list *absolute_rl;

	if (expr->type == EXPR_BINOP && expr->op == '%') {
		struct range_list *left, *right;

		if (!get_user_rl(expr->right, &right))
			return NULL;
		get_absolute_rl(expr->left, &left);
		rl = rl_binop(left, '%', right);
		goto found;
	}

	if (!option_spammy && expr->type == EXPR_BINOP && expr->op == '/') {
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

int get_user_rl(struct expression *expr, struct range_list **rl)
{
	user_data_flag = 0;
	no_user_data_flag = 0;
	custom_get_absolute_rl(expr, &var_user_rl, rl);
	if (!user_data_flag || no_user_data_flag)
		*rl = NULL;

	return !!*rl;
}

int get_user_rl_spammy(struct expression *expr, struct range_list **rl)
{
	int ret;

	option_spammy++;
	ret = get_user_rl(expr, rl);
	option_spammy--;

	return ret;
}

int is_user_rl(struct expression *expr)
{
	struct range_list *tmp;

	return get_user_rl_spammy(expr, &tmp);
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

static void match_call_info(struct expression *expr)
{
	struct range_list *rl;
	struct expression *arg;
	struct symbol *type;
	int i = 0;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		type = get_arg_type(expr->fn, i);

		if (!get_user_rl(arg, &rl))
			continue;

		rl = cast_rl(type, rl);
		sql_insert_caller_info(expr, USER_DATA3, i, "$", show_rl(rl));
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

	state = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!state || !estate_rl(state))
		rl = estate_rl(sm->state);
	else
		rl = rl_intersection(estate_rl(sm->state), estate_rl(state));

	sql_insert_caller_info(call, USER_DATA3, param, printed_name, show_rl(rl));
}

static void set_param_user_data(const char *name, struct symbol *sym, char *key, char *value)
{
	struct range_list *rl = NULL;
	struct smatch_state *state;
	struct symbol *type;
	char fullname[256];

	if (strcmp(key, "*$") == 0)
		snprintf(fullname, sizeof(fullname), "*%s", name);
	else if (strncmp(key, "$", 1) == 0)
		snprintf(fullname, 256, "%s%s", name, key + 1);
	else
		return;

	type = get_member_type_from_key(symbol_expression(sym), key);

	/* if the caller passes a void pointer with user data */
	if (strcmp(key, "*$") == 0 && type && type != &void_ctype) {
		struct expression *expr = symbol_expression(sym);

		tag_as_user_data(expr);
		set_points_to_user_data(expr);
		return;
	}
	str_to_rl(type, value, &rl);
	state = alloc_estate_rl(rl);
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

static void set_to_user_data(struct expression *expr, char *key, char *value)
{
	char *name;
	struct symbol *sym;
	struct symbol *type;
	struct range_list *rl = NULL;

	type = get_member_type_from_key(expr, key);
	name = get_variable_from_key(expr, key, &sym);
	if (!name || !sym)
		goto free;

	call_results_to_rl(expr, type, value, &rl);

	set_state(my_id, name, sym, alloc_estate_rl(rl));
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
		if (expr->type != EXPR_ASSIGNMENT)
			return;
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
		if (expr->type != EXPR_ASSIGNMENT)
			return;
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

static int has_empty_state(struct sm_state *sm)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!estate_rl(tmp->state))
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
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

	expr = strip_expr(expr);
	return_str = expr_to_str(expr);
	ret_sym = expr_to_sym(expr);

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (has_empty_state(sm))
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
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

		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA3_SET : USER_DATA3,
					 param, param_name, show_rl(estate_rl(sm->state)));
	} END_FOR_EACH_SM(sm);

	if (points_to_user_data(expr)) {
		sql_insert_return_states(return_id, return_ranges,
					 (is_skb_data(expr) || !func_gets_user_data) ?
					 USER_DATA3_SET : USER_DATA3,
					 -1, "*$", "");
		goto free_string;
	}


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
		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA3_SET : USER_DATA3,
					 -1, param_name, show_rl(estate_rl(sm->state)));
	} END_FOR_EACH_SM(sm);


	if (!return_found && get_user_rl(expr, &rl)) {
		sql_insert_return_states(return_id, return_ranges,
					 func_gets_user_data ? USER_DATA3_SET : USER_DATA3,
					 -1, "$", show_rl(rl));
		goto free_string;
	}

free_string:
	free_string(return_str);
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

void register_kernel_user_data2(int id)
{
	int i;

	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;

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
	add_hook(&match_condition, CONDITION_HOOK);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_id, struct_member_callback);
	select_caller_info_hook(set_param_user_data, USER_DATA3);
	select_return_states_hook(USER_DATA3, &returns_param_user_data);
	select_return_states_hook(USER_DATA3_SET, &returns_param_user_data_set);
	add_split_return_callback(&param_set_to_user_data);
}

void register_kernel_user_data3(int id)
{
	my_call_id = id;

	if (option_project != PROJ_KERNEL)
		return;
	select_caller_info_hook(set_called, INTERNAL);
}


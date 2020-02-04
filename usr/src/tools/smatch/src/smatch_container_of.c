/*
 * Copyright (C) 2017 Oracle.
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
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static int param_id;

int get_param_from_container_of(struct expression *expr)
{
	struct expression *param_expr;
	struct symbol *type;
	sval_t sval;
	int param;


	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return -1;

	expr = strip_expr(expr);
	if (expr->type != EXPR_BINOP || expr->op != '-')
		return -1;

	if (!get_value(expr->right, &sval))
		return -1;
	if (sval.value < 0 || sval.value > 4096)
		return -1;

	param_expr = get_assigned_expr(expr->left);
	if (!param_expr)
		return -1;
	param = get_param_num(param_expr);
	if (param < 0)
		return -1;

	return param;
}

int get_offset_from_container_of(struct expression *expr)
{
	struct expression *param_expr;
	struct symbol *type;
	sval_t sval;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return -1;

	expr = strip_expr(expr);
	if (expr->type != EXPR_BINOP || expr->op != '-')
		return -1;

	if (!get_value(expr->right, &sval))
		return -1;
	if (sval.value < 0 || sval.value > 4096)
		return -1;

	param_expr = get_assigned_expr(expr->left);
	if (!param_expr)
		return -1;

	return sval.value;
}

static void print_returns_container_of(int return_id, char *return_ranges, struct expression *expr)
{
	int offset;
	int param;
	char key[64];
	char value[64];

	param = get_param_from_container_of(expr);
	if (param < 0)
		return;
	offset = get_offset_from_container_of(expr);
	if (offset < 0)
		return;

	snprintf(key, sizeof(key), "%d", param);
	snprintf(value, sizeof(value), "-%d", offset);

	/* no need to add it to return_implies because it's not really param_used */
	sql_insert_return_states(return_id, return_ranges, CONTAINER, -1,
			key, value);
}

static int get_deref_count(struct expression *expr)
{
	int cnt = 0;

	while (expr && expr->type == EXPR_DEREF) {
		expr = expr->deref;
		if (expr->type == EXPR_PREOP && expr->op == '*')
			expr = expr->unop;
		cnt++;
		if (cnt > 100)
			return -1;
	}
	return cnt;
}

static struct expression *get_partial_deref(struct expression *expr, int cnt)
{
	while (--cnt >= 0) {
		if (!expr || expr->type != EXPR_DEREF)
			return expr;
		expr = expr->deref;
		if (expr->type == EXPR_PREOP && expr->op == '*')
			expr = expr->unop;
	}
	return expr;
}

static int partial_deref_to_offset_str(struct expression *expr, int cnt, char op, char *buf, int size)
{
	int n, offset;

	if (cnt == 0)
		return snprintf(buf, size, "%c0", op);

	n = 0;
	while (--cnt >= 0) {
		offset = get_member_offset_from_deref(expr);
		if (offset < 0)
			return -1;
		n += snprintf(buf + n, size - n, "%c%d", op, offset);
		if (expr->type != EXPR_DEREF)
			return -1;
		expr = expr->deref;
		if (expr->type == EXPR_PREOP && expr->op == '*')
			expr = expr->unop;
	}

	return n;
}

static char *get_shared_str(struct expression *expr, struct expression *container)
{
	struct expression *one, *two;
	int exp, cont, min, ret, n;
	static char buf[48];

	exp = get_deref_count(expr);
	cont = get_deref_count(container);
	if (exp < 0 || cont < 0)
		return NULL;

	min = (exp < cont) ? exp : cont;
	while (min >= 0) {
		one = get_partial_deref(expr, exp - min);
		two = get_partial_deref(container, cont - min);
		if (expr_equiv(one, two))
			goto found;
		min--;
	}

	return NULL;

found:
	ret = partial_deref_to_offset_str(expr, exp - min, '-', buf, sizeof(buf));
	if (ret < 0)
		return NULL;
	n = ret;
	ret = partial_deref_to_offset_str(container, cont - min, '+', buf + ret, sizeof(buf) - ret);
	if (ret < 0)
		return NULL;
	n += ret;
	if (n >= sizeof(buf))
		return NULL;

	return buf;
}

static char *get_stored_container_name(struct expression *container,
				       struct expression *expr)
{
	struct smatch_state *state;
	static char buf[64];
	char *p;
	int param;

	if (!container || container->type != EXPR_SYMBOL)
		return NULL;
	if (!expr || expr->type != EXPR_SYMBOL)
		return NULL;
	state = get_state_expr(param_id, expr);
	if (!state)
		return NULL;

	snprintf(buf, sizeof(buf), "%s", state->name);
	p = strchr(buf, '|');
	if (!p)
		return NULL;
	*p = '\0';
	param = atoi(p + 2);
	if (get_param_sym_from_num(param) == container->symbol)
		return buf;
	return NULL;
}

static char *get_container_name_helper(struct expression *container, struct expression *expr)
{
	struct symbol *container_sym, *sym;
	static char buf[64];
	char *ret, *shared;
	bool star;

	expr = strip_expr(expr);
	container = strip_expr(container);
	if (!expr || !container)
		return NULL;

	ret = get_stored_container_name(container, expr);
	if (ret)
		return ret;

	sym = expr_to_sym(expr);
	container_sym = expr_to_sym(container);
	if (!sym || !container_sym)
		return NULL;
	if (sym != container_sym)
		return NULL;

	if (container->type == EXPR_DEREF)
		star = true;
	else
		star = false;

	if (container->type == EXPR_PREOP && container->op == '&')
		container = strip_expr(container->unop);
	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_expr(expr->unop);

	shared = get_shared_str(expr, container);
	if (!shared)
		return NULL;
	if (star)
		snprintf(buf, sizeof(buf), "*(%s)", shared);
	else
		snprintf(buf, sizeof(buf), "%s", shared);

	return buf;
}

char *get_container_name(struct expression *container, struct expression *expr)
{
	char *ret;

	ret = get_container_name_helper(container, expr);
	if (ret)
		return ret;

	ret = get_container_name_helper(get_assigned_expr(container), expr);
	if (ret)
		return ret;

	ret = get_container_name_helper(container, get_assigned_expr(expr));
	if (ret)
		return ret;

	ret = get_container_name_helper(get_assigned_expr(container),
					get_assigned_expr(expr));
	if (ret)
		return ret;

	return NULL;
}

static bool is_fn_ptr(struct expression *expr)
{
	struct symbol *type;

	if (!expr)
		return false;
	if (expr->type != EXPR_SYMBOL && expr->type != EXPR_DEREF)
		return false;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return false;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_FN)
		return false;
	return true;
}

static void match_call(struct expression *call)
{
	struct expression *fn, *arg, *tmp;
	bool found = false;
	int fn_param, param;
	char buf[32];
	char *name;

	/*
	 * We're trying to link the function with the parameter.  There are a
	 * couple ways this can be passed:
	 * foo->func(foo, ...);
	 * foo->func(foo->x, ...);
	 * foo->bar.func(&foo->bar, ...);
	 * foo->bar->baz->func(foo, ...);
	 *
	 * So the method is basically to subtract the offsets until we get to
	 * the common bit, then add the member offsets to get the parameter.
	 *
	 * If we're taking an address then the offset math is not stared,
	 * otherwise it is.  Starred means dereferenced.
	 */
	fn = strip_expr(call->fn);

	param = -1;
	FOR_EACH_PTR(call->args, arg) {
		param++;

		name = get_container_name(arg, fn);
		if (!name)
			continue;

		found = true;
		sql_insert_caller_info(call, CONTAINER, param, name, "$(-1)");
	} END_FOR_EACH_PTR(arg);

	if (found)
		return;

	fn_param = -1;
	FOR_EACH_PTR(call->args, arg) {
		fn_param++;
		if (!is_fn_ptr(arg))
			continue;
		param = -1;
		FOR_EACH_PTR(call->args, tmp) {
			param++;

			/* the function isn't it's own container */
			if (arg == tmp)
				continue;

			name = get_container_name(tmp, arg);
			if (!name)
				continue;

			snprintf(buf, sizeof(buf), "$%d", param);
			sql_insert_caller_info(call, CONTAINER, fn_param, name, buf);
			return;
		} END_FOR_EACH_PTR(tmp);
	} END_FOR_EACH_PTR(arg);
}

static void db_passed_container(const char *name, struct symbol *sym, char *key, char *value)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%s|%s", key, value);
	set_state(param_id, name, sym, alloc_state_str(buf));
}

struct db_info {
	struct symbol *arg;
	int prev_offset;
	struct range_list *rl;
	int star;
	struct stree *stree;
};

static struct symbol *get_member_from_offset(struct symbol *sym, int offset)
{
	struct symbol *type, *tmp;
	int cur;

	type = get_real_base_type(sym);
	if (!type || type->type != SYM_PTR)
		return NULL;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_STRUCT)
		return NULL;

	cur = 0;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		cur = ALIGN(cur, tmp->ctype.alignment);
		if (offset == cur)
			return tmp;
		cur += type_bytes(tmp);
	} END_FOR_EACH_PTR(tmp);
	return NULL;
}

static struct symbol *get_member_type_from_offset(struct symbol *sym, int offset)
{
	struct symbol *base_type;
	struct symbol *member;

	base_type = get_real_base_type(sym);
	if (base_type && base_type->type == SYM_PTR)
		base_type = get_real_base_type(base_type);
	if (offset == 0 && base_type && base_type->type == SYM_BASETYPE)
		return base_type;

	member = get_member_from_offset(sym, offset);
	if (!member)
		return NULL;
	return get_real_base_type(member);
}

static const char *get_name_from_offset(struct symbol *arg, int offset)
{
	struct symbol *member, *type;
	const char *name;
	static char fullname[256];

	name = arg->ident->name;

	type = get_real_base_type(arg);
	if (!type || type->type != SYM_PTR)
		return name;

	type = get_real_base_type(type);
	if (!type)
		return NULL;
	if (type->type != SYM_STRUCT) {
		snprintf(fullname, sizeof(fullname), "*%s", name);
		return fullname;
	}

	member = get_member_from_offset(arg, offset);
	if (!member || !member->ident)
		return NULL;

	snprintf(fullname, sizeof(fullname), "%s->%s", name, member->ident->name);
	return fullname;
}

static void set_param_value(struct stree **stree, struct symbol *arg, int offset, struct range_list *rl)
{
	const char *name;

	name = get_name_from_offset(arg, offset);
	if (!name)
		return;
	set_state_stree(stree, SMATCH_EXTRA, name, arg, alloc_estate_rl(rl));
}

static int save_vals(void *_db_info, int argc, char **argv, char **azColName)
{
	struct db_info *db_info = _db_info;
	struct symbol *type;
	struct range_list *rl;
	int offset = 0;
	const char *value;

	if (argc == 2) {
		offset = atoi(argv[0]);
		value = argv[1];
	} else {
		value = argv[0];
	}

	if (db_info->prev_offset != -1 &&
	    db_info->prev_offset != offset) {
		set_param_value(&db_info->stree, db_info->arg, db_info->prev_offset, db_info->rl);
		db_info->rl = NULL;
	}

	db_info->prev_offset = offset;

	type = get_real_base_type(db_info->arg);
	if (db_info->star)
		goto found_type;
	if (type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (type->type == SYM_BASETYPE)
		goto found_type;
	type = get_member_type_from_offset(db_info->arg, offset);
found_type:
	str_to_rl(type, (char *)value, &rl);
	if (db_info->rl)
		db_info->rl = rl_union(db_info->rl, rl);
	else
		db_info->rl = rl;

	return 0;
}

static struct stree *load_tag_info_sym(mtag_t tag, struct symbol *arg, int arg_offset, int star)
{
	struct db_info db_info = {
		.arg = arg,
		.prev_offset = -1,
		.star = star,
	};
	struct symbol *type;

	if (!tag || !arg->ident)
		return NULL;

	type = get_real_base_type(arg);
	if (!type)
		return NULL;
	if (!star) {
		if (type->type != SYM_PTR)
			return NULL;
		type = get_real_base_type(type);
		if (!type)
			return NULL;
	}

	if (star || type->type == SYM_BASETYPE) {
		run_sql(save_vals, &db_info,
			"select value from mtag_data where tag = %lld and offset = %d and type = %d;",
			tag, arg_offset, DATA_VALUE);
	} else {  /* presumably the parameter is a struct pointer */
		run_sql(save_vals, &db_info,
			"select offset, value from mtag_data where tag = %lld and type = %d;",
			tag, DATA_VALUE);
	}

	if (db_info.prev_offset != -1)
		set_param_value(&db_info.stree, arg, db_info.prev_offset, db_info.rl);

	// FIXME: handle an offset correctly
	if (!star && !arg_offset) {
		sval_t sval;

		sval.type = get_real_base_type(arg);
		sval.uvalue = tag;
		set_state_stree(&db_info.stree, SMATCH_EXTRA, arg->ident->name, arg, alloc_estate_sval(sval));
	}
	return db_info.stree;
}

static void load_container_data(struct symbol *arg, const char *info)
{
	mtag_t cur_tag, container_tag, arg_tag;
	int container_offset, arg_offset;
	struct sm_state *sm;
	struct stree *stree;
	char *p, *cont;
	char copy[64];
	bool star = 0;

	snprintf(copy, sizeof(copy), "%s", info);
	p = strchr(copy, '|');
	if (!p)
		return;
	*p = '\0';
	cont = p + 1;
	p = copy;
	if (p[0] == '*') {
		star = 1;
		p += 2;
	}

	if (strcmp(cont, "$(-1)") != 0)
		return;

	if (!get_toplevel_mtag(cur_func_sym, &cur_tag))
		return;

	while (true) {
		container_offset = strtoul(p, &p, 0);
		if (local_debug)
			sm_msg("%s: cur_tag = %llu container_offset = %d",
			       __func__, cur_tag, container_offset);
		if (!mtag_map_select_container(cur_tag, container_offset, &container_tag))
			return;
		cur_tag = container_tag;
		if (local_debug)
			sm_msg("%s: container_tag = %llu p = '%s'",
			       __func__, container_tag, p);
		if (!p)
			return;
		if (p[0] != '-')
			break;
		p++;
	}

	if (p[0] != '+')
		return;

	p++;
	arg_offset = strtoul(p, &p, 0);
	if (p && *p && *p != ')')
		return;

	if (!arg_offset || star) {
		arg_tag = container_tag;
	} else {
		if (!mtag_map_select_tag(container_tag, -arg_offset, &arg_tag))
			return;
	}

	stree = load_tag_info_sym(arg_tag, arg, arg_offset, star);
	FOR_EACH_SM(stree, sm) {
		set_state(sm->owner, sm->name, sm->sym, sm->state);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);
}

static void handle_passed_container(struct symbol *sym)
{
	struct symbol *arg;
	struct smatch_state *state;

	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		state = get_state(param_id, arg->ident->name, arg);
		if (!state || state == &merged)
			continue;
		load_container_data(arg, state->name);
	} END_FOR_EACH_PTR(arg);
}

void register_container_of(int id)
{
	my_id = id;

	add_split_return_callback(&print_returns_container_of);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}

void register_container_of2(int id)
{
	param_id = id;

	set_dynamic_states(param_id);
	select_caller_info_hook(db_passed_container, CONTAINER);
	add_merge_hook(param_id, &merge_str_state);
	add_hook(&handle_passed_container, AFTER_DEF_HOOK);
}


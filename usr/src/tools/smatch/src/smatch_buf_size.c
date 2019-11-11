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

#include <stdlib.h>
#include <errno.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"
#include "smatch_function_hashtable.h"

#define UNKNOWN_SIZE -1

static int my_size_id;

static DEFINE_HASHTABLE_INSERT(insert_func, char, int);
static DEFINE_HASHTABLE_SEARCH(search_func, char, int);
static struct hashtable *allocation_funcs;

static char *get_fn_name(struct expression *expr)
{
	if (expr->type != EXPR_CALL)
		return NULL;
	if (expr->fn->type != EXPR_SYMBOL)
		return NULL;
	return expr_to_var(expr->fn);
}

static int is_allocation_function(struct expression *expr)
{
	char *func;
	int ret = 0;

	func = get_fn_name(expr);
	if (!func)
		return 0;
	if (search_func(allocation_funcs, func))
		ret = 1;
	free_string(func);
	return ret;
}

static void add_allocation_function(const char *func, void *call_back, int param)
{
	insert_func(allocation_funcs, (char *)func, (int *)1);
	add_function_assign_hook(func, call_back, INT_PTR(param));
}

static int estate_to_size(struct smatch_state *state)
{
	sval_t sval;

	if (!state || !estate_rl(state))
		return 0;
	sval = estate_max(state);
	return sval.value;
}

static struct smatch_state *size_to_estate(int size)
{
	sval_t sval;

	sval.type = &int_ctype;
	sval.value = size;

	return alloc_estate_sval(sval);
}

static struct range_list *size_to_rl(int size)
{
	sval_t sval;

	sval.type = &int_ctype;
	sval.value = size;

	return alloc_rl(sval, sval);
}

static struct smatch_state *unmatched_size_state(struct sm_state *sm)
{
	return size_to_estate(UNKNOWN_SIZE);
}

static void set_size_undefined(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(sm->owner, sm->name, sm->sym, size_to_estate(UNKNOWN_SIZE));
}

static struct smatch_state *merge_size_func(struct smatch_state *s1, struct smatch_state *s2)
{
	return merge_estates(s1, s2);
}

void set_param_buf_size(const char *name, struct symbol *sym, char *key, char *value)
{
	struct range_list *rl = NULL;
	struct smatch_state *state;
	char fullname[256];

	if (strncmp(key, "$", 1) != 0)
		return;

	snprintf(fullname, 256, "%s%s", name, key + 1);

	str_to_rl(&int_ctype, value, &rl);
	if (!rl || is_whole_rl(rl))
		return;
	state = alloc_estate_rl(rl);
	set_state(my_size_id, fullname, sym, state);
}

static int bytes_per_element(struct expression *expr)
{
	struct symbol *type;

	if (!expr)
		return 0;
	if (expr->type == EXPR_STRING)
		return 1;
	if (expr->type == EXPR_PREOP && expr->op == '&') {
		type = get_type(expr->unop);
		if (type && type->type == SYM_ARRAY)
			expr = expr->unop;
	}
	type = get_type(expr);
	if (!type)
		return 0;

	if (type->type != SYM_PTR && type->type != SYM_ARRAY)
		return 0;

	type = get_base_type(type);
	return type_bytes(type);
}

static int bytes_to_elements(struct expression *expr, int bytes)
{
	int bpe;

	bpe = bytes_per_element(expr);
	if (bpe == 0)
		return 0;
	return bytes / bpe;
}

static int elements_to_bytes(struct expression *expr, int elements)
{
	int bpe;

	bpe = bytes_per_element(expr);
	return elements * bpe;
}

static int get_initializer_size(struct expression *expr)
{
	switch (expr->type) {
	case EXPR_STRING:
		return expr->string->length;
	case EXPR_INITIALIZER: {
		struct expression *tmp;
		int i = 0;

		FOR_EACH_PTR(expr->expr_list, tmp) {
			if (tmp->type == EXPR_INDEX) {
				if (tmp->idx_to >= i)
					i = tmp->idx_to;
				else
					continue;
			}

			i++;
		} END_FOR_EACH_PTR(tmp);
		return i;
	}
	case EXPR_SYMBOL:
		return get_array_size(expr);
	}
	return 0;
}

static struct range_list *db_size_rl;
static int db_size_callback(void *unused, int argc, char **argv, char **azColName)
{
	struct range_list *tmp = NULL;

	if (!db_size_rl) {
		str_to_rl(&int_ctype, argv[0], &db_size_rl);
	} else {
		str_to_rl(&int_ctype, argv[0], &tmp);
		db_size_rl = rl_union(db_size_rl, tmp);
	}
	return 0;
}

static struct range_list *size_from_db_type(struct expression *expr)
{
	int this_file_only = 0;
	char *name;

	name = get_member_name(expr);
	if (!name && is_static(expr)) {
		name = expr_to_var(expr);
		this_file_only = 1;
	}
	if (!name)
		return NULL;

	if (this_file_only) {
		db_size_rl = NULL;
		run_sql(db_size_callback, NULL,
			"select size from function_type_size where type = '%s' and file = '%s';",
			name, get_filename());
		if (db_size_rl)
			return db_size_rl;
		return NULL;
	}

	db_size_rl = NULL;
	run_sql(db_size_callback, NULL,
		"select size from type_size where type = '%s';",
		name);
	return db_size_rl;
}

static struct range_list *size_from_db_symbol(struct expression *expr)
{
	struct symbol *sym;

	if (expr->type != EXPR_SYMBOL)
		return NULL;
	sym = expr->symbol;
	if (!sym || !sym->ident ||
	    !(sym->ctype.modifiers & MOD_TOPLEVEL) ||
	    sym->ctype.modifiers & MOD_STATIC)
		return NULL;

	db_size_rl = NULL;
	run_sql(db_size_callback, NULL,
		"select value from data_info where file = 'extern' and data = '%s' and type = %d;",
		sym->ident->name, BUF_SIZE);
	return db_size_rl;
}

static struct range_list *size_from_db(struct expression *expr)
{
	struct range_list *rl;

	rl = size_from_db_symbol(expr);
	if (rl)
		return rl;
	return size_from_db_type(expr);
}

static void db_returns_buf_size(struct expression *expr, int param, char *unused, char *math)
{
	struct expression *call;
	struct range_list *rl;

	if (expr->type != EXPR_ASSIGNMENT)
		return;
	call = strip_expr(expr->right);

	call_results_to_rl(call, &int_ctype, math, &rl);
	rl = cast_rl(&int_ctype, rl);
	set_state_expr(my_size_id, expr->left, alloc_estate_rl(rl));
}

static int get_real_array_size_from_type(struct symbol *type)
{
	sval_t sval;

	if (!type)
		return 0;
	if (!type || type->type != SYM_ARRAY)
		return 0;

	if (!get_implied_value(type->array_size, &sval))
		return 0;

	return sval.value;
}

int get_real_array_size(struct expression *expr)
{
	if (!expr)
		return 0;
	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = expr->unop;
	if (expr->type == EXPR_BINOP) /* array elements foo[5] */
		return 0;
	return get_real_array_size_from_type(get_type(expr));
}

static int get_size_from_initializer(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL || !expr->symbol || !expr->symbol->initializer)
		return 0;
	if (expr->symbol->initializer == expr) /* int a = a; */
		return 0;
	return get_initializer_size(expr->symbol->initializer);
}

static struct range_list *get_stored_size_bytes(struct expression *expr)
{
	struct smatch_state *state;

	state = get_state_expr(my_size_id, expr);
	if (!state)
		return NULL;
	return estate_rl(state);
}

static int get_bytes_from_address(struct expression *expr)
{
	struct symbol *type;
	int ret;

	if (expr->type != EXPR_PREOP || expr->op != '&')
		return 0;
	type = get_type(expr);
	if (!type)
		return 0;

	if (type->type == SYM_PTR)
		type = get_base_type(type);

	ret = type_bytes(type);
	if (ret == 1)
		return 0;  /* ignore char pointers */

	return ret;
}

static struct expression *remove_addr_fluff(struct expression *expr)
{
	struct expression *tmp;
	sval_t sval;

	expr = strip_expr(expr);

	/* remove '&' and '*' operations that cancel */
	while (expr && expr->type == EXPR_PREOP && expr->op == '&') {
		tmp = strip_expr(expr->unop);
		if (tmp->type != EXPR_PREOP)
			break;
		if (tmp->op != '*')
			break;
		expr = strip_expr(tmp->unop);
	}

	if (!expr)
		return NULL;

	/* "foo + 0" is just "foo" */
	if (expr->type == EXPR_BINOP && expr->op == '+' &&
	    get_value(expr->right, &sval) && sval.value == 0)
		return expr->left;

	return expr;
}

static int is_last_member_of_struct(struct symbol *sym, struct ident *member)
{
	struct symbol *tmp;
	int i;

	i = 0;
	FOR_EACH_PTR_REVERSE(sym->symbol_list, tmp) {
		if (i++ || !tmp->ident)
			return 0;
		if (tmp->ident == member)
			return 1;
		return 0;
	} END_FOR_EACH_PTR_REVERSE(tmp);

	return 0;
}

int last_member_is_resizable(struct symbol *sym)
{
	struct symbol *last_member;
	struct symbol *type;
	sval_t sval;

	if (!sym || sym->type != SYM_STRUCT)
		return 0;

	last_member = last_ptr_list((struct ptr_list *)sym->symbol_list);
	if (!last_member || !last_member->ident)
		return 0;

	type = get_real_base_type(last_member);
	if (type->type == SYM_STRUCT)
		return last_member_is_resizable(type);
	if (type->type != SYM_ARRAY)
		return 0;

	if (!get_implied_value(type->array_size, &sval))
		return 0;

	if (sval.value != 0 && sval.value != 1)
		return 0;

	return 1;
}

static int get_stored_size_end_struct_bytes(struct expression *expr)
{
	struct symbol *sym;
	struct symbol *base_sym;
	struct smatch_state *state;

	if (expr->type == EXPR_BINOP) /* array elements foo[5] */
		return 0;

	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_parens(expr->unop);

	sym = expr_to_sym(expr);
	if (!sym || !sym->ident)
		return 0;
	if (!type_bytes(sym))
		return 0;
	if (sym->type != SYM_NODE)
		return 0;

	base_sym = get_real_base_type(sym);
	if (!base_sym || base_sym->type != SYM_PTR)
		return 0;
	base_sym = get_real_base_type(base_sym);
	if (!base_sym || base_sym->type != SYM_STRUCT)
		return 0;

	if (!is_last_member_of_struct(base_sym, expr->member))
		return 0;
	if (!last_member_is_resizable(base_sym))
		return 0;

	state = get_state(my_size_id, sym->ident->name, sym);
	if (!estate_to_size(state))
		return 0;

	return estate_to_size(state) - type_bytes(base_sym) + type_bytes(get_type(expr));
}

static struct range_list *alloc_int_rl(int value)
{
	sval_t sval = {
		.type = &int_ctype,
		{.value = value},
	};

	return alloc_rl(sval, sval);
}

struct range_list *get_array_size_bytes_rl(struct expression *expr)
{
	struct range_list *ret = NULL;
	sval_t sval;
	int size;

	expr = remove_addr_fluff(expr);
	if (!expr)
		return NULL;

	/* "BAR" */
	if (expr->type == EXPR_STRING)
		return alloc_int_rl(expr->string->length);

	if (expr->type == EXPR_BINOP && expr->op == '+') {
		sval_t offset;
		struct symbol *type;
		int bytes;

		if (!get_implied_value(expr->right, &offset))
			return NULL;
		type = get_type(expr->left);
		if (!type)
			return NULL;
		if (type->type != SYM_ARRAY && type->type != SYM_PTR)
			return NULL;
		type = get_real_base_type(type);
		bytes = type_bytes(type);
		if (bytes == 0)
			return NULL;
		offset.value *= bytes;
		size = get_array_size_bytes(expr->left);
		if (size <= 0)
			return NULL;
		return alloc_int_rl(size - offset.value);
	}

	size = get_stored_size_end_struct_bytes(expr);
	if (size)
		return alloc_int_rl(size);

	/* buf[4] */
	size = get_real_array_size(expr);
	if (size)
		return alloc_int_rl(elements_to_bytes(expr, size));

	/* buf = malloc(1024); */
	ret = get_stored_size_bytes(expr);
	if (ret)
		return ret;

	/* char *foo = "BAR" */
	size = get_size_from_initializer(expr);
	if (size)
		return alloc_int_rl(elements_to_bytes(expr, size));

	size = get_bytes_from_address(expr);
	if (size)
		return alloc_int_rl(size);

	ret = size_from_db(expr);
	if (rl_to_sval(ret, &sval) && sval.value == -1)
		return NULL;
	if (ret)
		return ret;

	return NULL;
}

int get_array_size_bytes(struct expression *expr)
{
	struct range_list *rl;
	sval_t sval;

	rl = get_array_size_bytes_rl(expr);
	if (!rl_to_sval(rl, &sval))
		return 0;
	if (sval.uvalue >= INT_MAX)
		return 0;
	return sval.value;
}

int get_array_size_bytes_max(struct expression *expr)
{
	struct range_list *rl;
	sval_t bytes;

	rl = get_array_size_bytes_rl(expr);
	if (!rl)
		return 0;
	bytes = rl_min(rl);
	if (bytes.value < 0)
		return 0;
	bytes = rl_max(rl);
	if (bytes.uvalue >= INT_MAX)
		return 0;
	return bytes.value;
}

int get_array_size_bytes_min(struct expression *expr)
{
	struct range_list *rl;
	struct data_range *range;

	rl = get_array_size_bytes_rl(expr);
	if (!rl)
		return 0;

	FOR_EACH_PTR(rl, range) {
		if (range->min.value <= 0)
			return 0;
		if (range->max.value <= 0)
			return 0;
		if (range->min.uvalue >= INT_MAX)
			return 0;
		return range->min.value;
	} END_FOR_EACH_PTR(range);

	return 0;
}

int get_array_size(struct expression *expr)
{
	if (!expr)
		return 0;
	return bytes_to_elements(expr, get_array_size_bytes_max(expr));
}

static struct expression *strip_ampersands(struct expression *expr)
{
	struct symbol *type;

	if (expr->type != EXPR_PREOP)
		return expr;
	if (expr->op != '&')
		return expr;
	type = get_type(expr->unop);
	if (!type || type->type != SYM_ARRAY)
		return expr;
	return expr->unop;
}

static void info_record_alloction(struct expression *buffer, struct range_list *rl)
{
	char *name;

	if (!option_info)
		return;

	name = get_member_name(buffer);
	if (!name && is_static(buffer))
		name = expr_to_var(buffer);
	if (!name)
		return;
	if (rl && !is_whole_rl(rl))
		sql_insert_function_type_size(name, show_rl(rl));
	else
		sql_insert_function_type_size(name, "(-1)");

	free_string(name);
}

static void store_alloc(struct expression *expr, struct range_list *rl)
{
	struct symbol *type;

	rl = clone_rl(rl); // FIXME!!!
	if (!rl)
		rl = size_to_rl(UNKNOWN_SIZE);
	set_state_expr(my_size_id, expr, alloc_estate_rl(rl));

	type = get_type(expr);
	if (!type)
		return;
	if (type->type != SYM_PTR)
		return;
	type = get_real_base_type(type);
	if (!type)
		return;
	if (type == &void_ctype)
		return;
	if (type->type != SYM_BASETYPE && type->type != SYM_PTR)
		return;

	info_record_alloction(expr, rl);
}

static void match_array_assignment(struct expression *expr)
{
	struct expression *left;
	struct expression *right;
	char *left_member, *right_member;
	struct range_list *rl;
	sval_t sval;

	if (expr->op != '=')
		return;
	left = strip_expr(expr->left);
	right = strip_expr(expr->right);
	right = strip_ampersands(right);

	if (!is_pointer(left))
		return;
	if (is_allocation_function(right))
		return;

	left_member = get_member_name(left);
	right_member = get_member_name(right);
	if (left_member && right_member && strcmp(left_member, right_member) == 0) {
		free_string(left_member);
		free_string(right_member);
		return;
	}
	free_string(left_member);
	free_string(right_member);

	if (get_implied_value(right, &sval) && sval.value == 0) {
		rl = alloc_int_rl(0);
		goto store;
	}

	rl = get_array_size_bytes_rl(right);
	if (!rl && __in_fake_assign)
		return;

store:
	store_alloc(left, rl);
}

static void match_alloc(const char *fn, struct expression *expr, void *_size_arg)
{
	int size_arg = PTR_INT(_size_arg);
	struct expression *right;
	struct expression *arg;
	struct range_list *rl;

	right = strip_expr(expr->right);
	arg = get_argument_from_call_expr(right->args, size_arg);
	get_absolute_rl(arg, &rl);
	rl = cast_rl(&int_ctype, rl);
	store_alloc(expr->left, rl);
}

static void match_calloc(const char *fn, struct expression *expr, void *unused)
{
	struct expression *right;
	struct expression *size, *nr, *mult;
	struct range_list *rl;

	right = strip_expr(expr->right);
	nr = get_argument_from_call_expr(right->args, 0);
	size = get_argument_from_call_expr(right->args, 1);
	mult = binop_expression(nr, '*', size);
	if (get_implied_rl(mult, &rl))
		store_alloc(expr->left, rl);
	else
		store_alloc(expr->left, size_to_rl(UNKNOWN_SIZE));
}

static void match_page(const char *fn, struct expression *expr, void *_unused)
{
	sval_t page_size = {
		.type = &int_ctype,
		{.value = 4096},
	};

	store_alloc(expr->left, alloc_rl(page_size, page_size));
}

static void match_strndup(const char *fn, struct expression *expr, void *unused)
{
	struct expression *fn_expr;
	struct expression *size_expr;
	sval_t size;

	fn_expr = strip_expr(expr->right);
	size_expr = get_argument_from_call_expr(fn_expr->args, 1);
	if (get_implied_max(size_expr, &size)) {
		size.value++;
		store_alloc(expr->left, size_to_rl(size.value));
	} else {
		store_alloc(expr->left, size_to_rl(UNKNOWN_SIZE));
	}

}

static void match_alloc_pages(const char *fn, struct expression *expr, void *_order_arg)
{
	int order_arg = PTR_INT(_order_arg);
	struct expression *right;
	struct expression *arg;
	sval_t sval;

	right = strip_expr(expr->right);
	arg = get_argument_from_call_expr(right->args, order_arg);
	if (!get_implied_value(arg, &sval))
		return;
	if (sval.value < 0 || sval.value > 10)
		return;

	sval.type = &int_ctype;
	sval.value = 1 << sval.value;
	sval.value *= 4096;

	store_alloc(expr->left, alloc_rl(sval, sval));
}

static int is_type_bytes(struct range_list *rl, struct expression *arg)
{
	struct symbol *type;
	sval_t sval;

	if (!rl_to_sval(rl, &sval))
		return 0;

	type = get_type(arg);
	if (!type)
		return 0;
	if (type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (type->type != SYM_STRUCT &&
	    type->type != SYM_UNION)
		return 0;
	if (sval.value != type_bytes(type))
		return 0;
	return 1;
}

static void match_call(struct expression *expr)
{
	struct expression *arg;
	struct symbol *type;
	struct range_list *rl;
	int i;

	i = -1;
	FOR_EACH_PTR(expr->args, arg) {
		i++;
		type = get_type(arg);
		if (!type || (type->type != SYM_PTR && type->type != SYM_ARRAY))
			continue;
		rl = get_array_size_bytes_rl(arg);
		if (!rl)
			continue;
		if (is_whole_rl(rl))
			continue;
		if (is_type_bytes(rl, arg))
			continue;
		sql_insert_caller_info(expr, BUF_SIZE, i, "$", show_rl(rl));
	} END_FOR_EACH_PTR(arg);
}

static void struct_member_callback(struct expression *call, int param, char *printed_name, struct sm_state *sm)
{
	sval_t sval;

	if (!estate_rl(sm->state) ||
	    (estate_get_single_value(sm->state, &sval) &&
	     (sval.value == -1 || sval.value == 0)))
		return;

	sql_insert_caller_info(call, BUF_SIZE, param, printed_name, sm->state->name);
}

/*
 * This is slightly (very) weird because half of this stuff is handled in
 * smatch_parse_call_math.c which is poorly named.  But anyway, add some buf
 * sizes here.
 *
 */
static void print_returned_allocations(int return_id, char *return_ranges, struct expression *expr)
{
	const char *param_math;
	struct range_list *rl;
	char buf[64];
	sval_t sval;

	rl = get_array_size_bytes_rl(expr);
	param_math = get_allocation_math(expr);
	if (!rl && !param_math)
		return;

	if (!param_math &&
	    rl_to_sval(rl, &sval) &&
	    (sval.value == -1 || sval.value == 0))
		return;

	if (param_math)
		snprintf(buf, sizeof(buf), "%s[%s]", show_rl(rl), param_math);
	else
		snprintf(buf, sizeof(buf), "%s", show_rl(rl));

	// FIXME: don't store if you can guess the size from the type
	// FIXME: return if we allocate a parameter $0->bar
	sql_insert_return_states(return_id, return_ranges, BUF_SIZE, -1, "", buf);
}

static void record_global_size(struct symbol *sym)
{
	int bytes;
	char buf[16];

	if (!sym->ident)
		return;

	if (!(sym->ctype.modifiers & MOD_TOPLEVEL) ||
	    sym->ctype.modifiers & MOD_STATIC)
		return;

	bytes = get_array_size_bytes(symbol_expression(sym));
	if (bytes <= 1)
		return;

	snprintf(buf, sizeof(buf), "%d", bytes);
	sql_insert_data_info_var_sym(sym->ident->name, sym, BUF_SIZE, buf);
}

void register_buf_size(int id)
{
	my_size_id = id;

	set_dynamic_states(my_size_id);

	add_unmatched_state_hook(my_size_id, &unmatched_size_state);
	add_merge_hook(my_size_id, &merge_estates);

	select_caller_info_hook(set_param_buf_size, BUF_SIZE);
	select_return_states_hook(BUF_SIZE, &db_returns_buf_size);
	add_split_return_callback(print_returned_allocations);

	allocation_funcs = create_function_hashtable(100);
	add_allocation_function("malloc", &match_alloc, 0);
	add_allocation_function("calloc", &match_calloc, 0);
	add_allocation_function("memdup", &match_alloc, 1);
	add_allocation_function("realloc", &match_alloc, 1);
	if (option_project == PROJ_KERNEL) {
		add_allocation_function("kmalloc", &match_alloc, 0);
		add_allocation_function("kmalloc_node", &match_alloc, 0);
		add_allocation_function("kzalloc", &match_alloc, 0);
		add_allocation_function("kzalloc_node", &match_alloc, 0);
		add_allocation_function("vmalloc", &match_alloc, 0);
		add_allocation_function("__vmalloc", &match_alloc, 0);
		add_allocation_function("kcalloc", &match_calloc, 0);
		add_allocation_function("kmalloc_array", &match_calloc, 0);
		add_allocation_function("drm_malloc_ab", &match_calloc, 0);
		add_allocation_function("drm_calloc_large", &match_calloc, 0);
		add_allocation_function("sock_kmalloc", &match_alloc, 1);
		add_allocation_function("kmemdup", &match_alloc, 1);
		add_allocation_function("kmemdup_user", &match_alloc, 1);
		add_allocation_function("dma_alloc_attrs", &match_alloc, 1);
		add_allocation_function("pci_alloc_consistent", &match_alloc, 1);
		add_allocation_function("pci_alloc_coherent", &match_alloc, 1);
		add_allocation_function("devm_kmalloc", &match_alloc, 1);
		add_allocation_function("devm_kzalloc", &match_alloc, 1);
		add_allocation_function("krealloc", &match_alloc, 1);
		add_allocation_function("__alloc_bootmem", &match_alloc, 0);
		add_allocation_function("alloc_bootmem", &match_alloc, 0);
		add_allocation_function("kmap", &match_page, 0);
		add_allocation_function("kmap_atomic", &match_page, 0);
		add_allocation_function("get_zeroed_page", &match_page, 0);
		add_allocation_function("alloc_page", &match_page, 0);
		add_allocation_function("alloc_pages", &match_alloc_pages, 1);
		add_allocation_function("alloc_pages_current", &match_alloc_pages, 1);
		add_allocation_function("__get_free_pages", &match_alloc_pages, 1);
		add_allocation_function("dma_alloc_contiguous", &match_alloc, 1);
		add_allocation_function("dma_alloc_coherent", &match_alloc, 1);
	}

	add_allocation_function("strndup", match_strndup, 0);
	if (option_project == PROJ_KERNEL)
		add_allocation_function("kstrndup", match_strndup, 0);

	add_modification_hook(my_size_id, &set_size_undefined);

	add_merge_hook(my_size_id, &merge_size_func);

	if (option_info)
		add_hook(record_global_size, BASE_HOOK);
}

void register_buf_size_late(int id)
{
	/* has to happen after match_alloc() */
	add_hook(&match_array_assignment, ASSIGNMENT_HOOK);

	add_hook(&match_call, FUNCTION_CALL_HOOK);
	add_member_info_callback(my_size_id, struct_member_callback);
}

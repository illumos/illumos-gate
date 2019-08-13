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
 * The point here is to store that a buffer has x bytes even if we don't know
 * the value of x.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int size_id;
static int link_id;

/*
 * There is a bunch of code which does this:
 *
 *     if (size)
 *         foo = malloc(size);
 *
 * So if "size" is non-zero then the size of "foo" is size.  But really it's
 * also true if size is zero.  It's just better to assume to not trample over
 * the data that we have by merging &undefined states.
 *
 */
static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	return sm->state;
}

static struct smatch_state *merge_links(struct smatch_state *s1, struct smatch_state *s2)
{
	struct expression *expr1, *expr2;

	expr1 = s1->data;
	expr2 = s2->data;

	if (expr1 && expr2 && expr_equiv(expr1, expr2))
		return s1;
	return &merged;
}

static void match_link_modify(struct sm_state *sm, struct expression *mod_expr)
{
	struct expression *expr;
	struct sm_state *tmp;

	expr = sm->state->data;
	if (expr) {
		set_state_expr(size_id, expr, &undefined);
		set_state(link_id, sm->name, sm->sym, &undefined);
		return;
	}

	FOR_EACH_PTR(sm->possible, tmp) {
		expr = tmp->state->data;
		if (expr)
			set_state_expr(size_id, expr, &undefined);
	} END_FOR_EACH_PTR(tmp);
	set_state(link_id, sm->name, sm->sym, &undefined);
}

static const char *limit_map[] = {
	"byte_count",
	"elem_count",
	"elem_last",
	"used_count",
	"used_last",
};

int state_to_limit(struct smatch_state *state)
{
	int i;

	if (!state || !state->data)
		return -1;

	for (i = 0; i < ARRAY_SIZE(limit_map); i++) {
		if (strncmp(state->name, limit_map[i], strlen(limit_map[i])) == 0)
			return i + BYTE_COUNT;
	}

	return -1;
}

const char *limit_type_str(unsigned int limit_type)
{
	if (limit_type - BYTE_COUNT >= ARRAY_SIZE(limit_map)) {
		sm_msg("internal: wrong size type %u", limit_type);
		return "unknown";
	}

	return limit_map[limit_type - BYTE_COUNT];
}

static struct smatch_state *alloc_compare_size(int limit_type, struct expression *expr)
{
	struct smatch_state *state;
	char *name;
	char buf[256];

	state = __alloc_smatch_state(0);
	expr = strip_expr(expr);
	name = expr_to_str(expr);
	snprintf(buf, sizeof(buf), "%s %s", limit_type_str(limit_type), name);
	state->name = alloc_sname(buf);
	free_string(name);
	state->data = expr;
	return state;
}

static int bytes_per_element(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return 0;

	if (type->type != SYM_PTR && type->type != SYM_ARRAY)
		return 0;

	type = get_base_type(type);
	return type_bytes(type);
}

static void db_save_type_links(struct expression *array, int type_limit, struct expression *size)
{
	const char *array_name;

	array_name = get_data_info_name(array);
	if (!array_name)
		array_name = "";
	sql_insert_data_info(size, type_limit, array_name);
}

static void match_alloc_helper(struct expression *pointer, struct expression *size)
{
	struct expression *tmp;
	struct sm_state *sm;
	int limit_type = ELEM_COUNT;
	sval_t sval;
	int cnt = 0;

	pointer = strip_expr(pointer);
	size = strip_expr(size);
	if (!size || !pointer)
		return;

	while ((tmp = get_assigned_expr(size))) {
		size = strip_expr(tmp);
		if (cnt++ > 5)
			break;
	}

	if (size->type == EXPR_BINOP && size->op == '*') {
		struct expression *mult_left, *mult_right;

		mult_left = strip_expr(size->left);
		mult_right = strip_expr(size->right);

		if (get_implied_value(mult_left, &sval) &&
		    sval.value == bytes_per_element(pointer))
			size = mult_right;
		else if (get_implied_value(mult_right, &sval) &&
		    sval.value == bytes_per_element(pointer))
			size = mult_left;
		else
			return;
	}

	/* Only save links to variables, not fixed sizes */
	if (get_value(size, &sval))
		return;

	if (size->type == EXPR_BINOP && size->op == '+' &&
	    get_value(size->right, &sval) && sval.value == 1) {
		size = size->left;
		limit_type = ELEM_LAST;
	}

	db_save_type_links(pointer, limit_type, size);
	sm = set_state_expr(size_id, pointer, alloc_compare_size(limit_type, size));
	if (!sm)
		return;
	set_state_expr(link_id, size, alloc_state_expr(pointer));
}

static void match_alloc(const char *fn, struct expression *expr, void *_size_arg)
{
	int size_arg = PTR_INT(_size_arg);
	struct expression *pointer, *call, *arg;

	pointer = strip_expr(expr->left);
	call = strip_expr(expr->right);
	arg = get_argument_from_call_expr(call->args, size_arg);
	match_alloc_helper(pointer, arg);
}

static void match_calloc(const char *fn, struct expression *expr, void *_start_arg)
{
	int start_arg = PTR_INT(_start_arg);
	struct expression *pointer, *call, *arg;
	struct sm_state *tmp;
	int limit_type = ELEM_COUNT;
	sval_t sval;

	pointer = strip_expr(expr->left);
	call = strip_expr(expr->right);
	arg = get_argument_from_call_expr(call->args, start_arg);
	if (get_implied_value(arg, &sval) &&
	    sval.value == bytes_per_element(pointer))
		arg = get_argument_from_call_expr(call->args, start_arg + 1);

	if (arg->type == EXPR_BINOP && arg->op == '+' &&
	    get_value(arg->right, &sval) && sval.value == 1) {
		arg = arg->left;
		limit_type = ELEM_LAST;
	}

	db_save_type_links(pointer, limit_type, arg);
	tmp = set_state_expr(size_id, pointer, alloc_compare_size(limit_type, arg));
	if (!tmp)
		return;
	set_state_expr(link_id, arg, alloc_state_expr(pointer));
}

struct expression *get_size_variable(struct expression *buf, int *limit_type)
{
	struct smatch_state *state;

	state = get_state_expr(size_id, buf);
	if (!state)
		return NULL;
	*limit_type = state_to_limit(state);
	return state->data;
}

struct expression *get_array_variable(struct expression *size)
{
	struct smatch_state *state;

	state = get_state_expr(link_id, size);
	if (state)
		return state->data;
	return NULL;
}

static void array_check(struct expression *expr)
{
	struct expression *array;
	struct expression *size;
	struct expression *offset;
	char *array_str, *offset_str;
	int limit_type;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	array = get_array_base(expr);
	size = get_size_variable(array, &limit_type);
	if (!size)
		return;
	if (limit_type != ELEM_COUNT)
		return;
	offset = get_array_offset(expr);
	if (!possible_comparison(size, SPECIAL_EQUAL, offset))
		return;

	array_str = expr_to_str(array);
	offset_str = expr_to_str(offset);
	sm_warning("potentially one past the end of array '%s[%s]'", array_str, offset_str);
	free_string(array_str);
	free_string(offset_str);
}

struct db_info {
	char *name;
	int ret;
};

static int db_limitter_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_info *info = _info;

	/*
	 * If possible the limitters are tied to the struct they limit.  If we
	 * aren't sure which struct they limit then we use them as limitters for
	 * everything.
	 */
	if (!info->name || argv[0][0] == '\0' || strcmp(info->name, argv[0]) == 0)
		info->ret = 1;
	return 0;
}

static char *vsl_to_data_info_name(const char *name, struct var_sym_list *vsl)
{
	struct var_sym *vs;
	struct symbol *type;
	static char buf[80];
	const char *p;

	if (ptr_list_size((struct ptr_list *)vsl) != 1)
		return NULL;
	vs = first_ptr_list((struct ptr_list *)vsl);

	type = get_real_base_type(vs->sym);
	if (!type || type->type != SYM_PTR)
		goto top_level_name;
	type = get_real_base_type(type);
	if (!type || type->type != SYM_STRUCT)
		goto top_level_name;
	if (!type->ident)
		goto top_level_name;

	p = name;
	while ((name = strstr(p, "->")))
		p = name + 2;

	snprintf(buf, sizeof(buf),"(struct %s)->%s", type->ident->name, p);
	return alloc_sname(buf);

top_level_name:
	if (!(vs->sym->ctype.modifiers & MOD_TOPLEVEL))
		return NULL;
	if (vs->sym->ctype.modifiers & MOD_STATIC)
		snprintf(buf, sizeof(buf),"static %s", name);
	else
		snprintf(buf, sizeof(buf),"global %s", name);
	return alloc_sname(buf);
}

int db_var_is_array_limit(struct expression *array, const char *name, struct var_sym_list *vsl)
{
	char *size_name;
	char *array_name = get_data_info_name(array);
	struct db_info db_info = {.name = array_name,};

	size_name = vsl_to_data_info_name(name, vsl);
	if (!size_name)
		return 0;

	run_sql(db_limitter_callback, &db_info,
		"select value from data_info where type = %d and data = '%s';",
		ARRAY_LEN, size_name);

	return db_info.ret;
}

int buf_comparison_index_ok(struct expression *expr)
{
	struct expression *array;
	struct expression *size;
	struct expression *offset;
	int limit_type;
	int comparison;

	array = get_array_base(expr);
	size = get_size_variable(array, &limit_type);
	if (!size)
		return 0;
	offset = get_array_offset(expr);
	comparison = get_comparison(offset, size);
	if (!comparison)
		return 0;

	if ((limit_type == ELEM_COUNT || limit_type == ELEM_LAST) &&
	    (comparison == '<' || comparison == SPECIAL_UNSIGNED_LT))
		return 1;
	if (limit_type == ELEM_LAST &&
	    (comparison == SPECIAL_LTE ||
	     comparison == SPECIAL_UNSIGNED_LTE ||
	     comparison == SPECIAL_EQUAL))
		return 1;

	return 0;
}

static int known_access_ok_numbers(struct expression *expr)
{
	struct expression *array;
	struct expression *offset;
	sval_t max;
	int size;

	array = get_array_base(expr);
	offset = get_array_offset(expr);

	size = get_array_size(array);
	if (size <= 0)
		return 0;

	get_absolute_max(offset, &max);
	if (max.uvalue < size)
		return 1;
	return 0;
}

static void array_check_data_info(struct expression *expr)
{
	struct expression *array;
	struct expression *offset;
	struct state_list *slist;
	struct sm_state *sm;
	struct compare_data *comp;
	char *offset_name;
	const char *equal_name = NULL;

	expr = strip_expr(expr);
	if (!is_array(expr))
		return;

	if (known_access_ok_numbers(expr))
		return;
	if (buf_comparison_index_ok(expr))
		return;

	array = get_array_base(expr);
	offset = get_array_offset(expr);
	offset_name = expr_to_var(offset);
	if (!offset_name)
		return;
	slist = get_all_possible_equal_comparisons(offset);
	if (!slist)
		goto free;

	FOR_EACH_PTR(slist, sm) {
		comp = sm->state->data;
		if (strcmp(comp->left_var, offset_name) == 0) {
			if (db_var_is_array_limit(array, comp->right_var, comp->right_vsl)) {
				equal_name = comp->right_var;
				break;
			}
		} else if (strcmp(comp->right_var, offset_name) == 0) {
			if (db_var_is_array_limit(array, comp->left_var, comp->left_vsl)) {
				equal_name = comp->left_var;
				break;
			}
		}
	} END_FOR_EACH_PTR(sm);

	if (equal_name) {
		char *array_name = expr_to_str(array);

		sm_warning("potential off by one '%s[]' limit '%s'", array_name, equal_name);
		free_string(array_name);
	}

free:
	free_slist(&slist);
	free_string(offset_name);
}

static void add_allocation_function(const char *func, void *call_back, int param)
{
	add_function_assign_hook(func, call_back, INT_PTR(param));
}

static int is_sizeof(struct expression *expr)
{
	const char *name;

	if (expr->type == EXPR_SIZEOF)
		return 1;
	name = pos_ident(expr->pos);
	if (name && strcmp(name, "sizeof") == 0)
		return 1;
	return 0;
}

static int match_size_binop(struct expression *size, struct expression *expr, int *limit_type)
{
	int orig_type = *limit_type;
	struct expression *left;
	sval_t sval;

	left = expr->left;
	if (!expr_equiv(size, left))
		return 0;

	if (expr->op == '-' &&
	    get_value(expr->right, &sval) &&
	    sval.value == 1 &&
	    orig_type == ELEM_COUNT) {
		*limit_type = ELEM_LAST;
		return 1;
	}

	if (expr->op == '+' &&
	    get_value(expr->right, &sval) &&
	    sval.value == 1 &&
	    orig_type == ELEM_LAST) {
		*limit_type = ELEM_COUNT;
		return 1;
	}

	if (expr->op == '*' &&
	    is_sizeof(expr->right) &&
	    orig_type == ELEM_COUNT) {
		*limit_type = BYTE_COUNT;
		return 1;
	}

	if (expr->op == '/' &&
	    is_sizeof(expr->right) &&
	    orig_type == BYTE_COUNT) {
		*limit_type = ELEM_COUNT;
		return 1;
	}

	return 0;
}

static char *buf_size_param_comparison(struct expression *array, struct expression_list *args, int *limit_type)
{
	struct expression *tmp, *arg;
	struct expression *size;
	static char buf[32];
	int i;

	size = get_size_variable(array, limit_type);
	if (!size)
		return NULL;

	if (*limit_type == USED_LAST)
		*limit_type = ELEM_LAST;
	if (*limit_type == USED_COUNT)
		*limit_type = ELEM_COUNT;

	i = -1;
	FOR_EACH_PTR(args, tmp) {
		i++;
		arg = tmp;
		if (arg == array)
			continue;
		if (expr_equiv(arg, size) ||
		    (arg->type == EXPR_BINOP &&
		     match_size_binop(size, arg, limit_type))) {
			snprintf(buf, sizeof(buf), "==$%d", i);
			return buf;
		}
	} END_FOR_EACH_PTR(tmp);

	return NULL;
}

static void match_call(struct expression *call)
{
	struct expression *arg;
	char *compare;
	int param;
	char buf[5];
	int limit_type;

	param = -1;
	FOR_EACH_PTR(call->args, arg) {
		param++;
		if (!is_pointer(arg))
			continue;
		compare = buf_size_param_comparison(arg, call->args, &limit_type);
		if (!compare)
			continue;
		snprintf(buf, sizeof(buf), "%d", limit_type);
		sql_insert_caller_info(call, limit_type, param, compare, buf);
	} END_FOR_EACH_PTR(arg);
}

static int get_param(int param, char **name, struct symbol **sym)
{
	struct symbol *arg;
	int i;

	i = 0;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		/*
		 * this is a temporary hack to work around a bug (I think in sparse?)
		 * 2.6.37-rc1:fs/reiserfs/journal.o
		 * If there is a function definition without parameter name found
		 * after a function implementation then it causes a crash.
		 * int foo() {}
		 * int bar(char *);
		 */
		if (arg->ident->name < (char *)100)
			continue;
		if (i == param) {
			*name = arg->ident->name;
			*sym = arg;
			return TRUE;
		}
		i++;
	} END_FOR_EACH_PTR(arg);

	return FALSE;
}

static void set_param_compare(const char *array_name, struct symbol *array_sym, char *key, char *value)
{
	struct expression *array_expr;
	struct expression *size_expr;
	struct symbol *size_sym;
	char *size_name;
	long param;
	struct sm_state *tmp;
	int limit_type;

	if (strncmp(key, "==$", 3) != 0)
		return;
	param = strtol(key + 3, NULL, 10);
	if (!get_param(param, &size_name, &size_sym))
		return;
	array_expr = symbol_expression(array_sym);
	size_expr = symbol_expression(size_sym);
	limit_type = strtol(value, NULL, 10);

	tmp = set_state_expr(size_id, array_expr, alloc_compare_size(limit_type, size_expr));
	if (!tmp)
		return;
	set_state_expr(link_id, size_expr, alloc_state_expr(array_expr));
}

static void set_implied(struct expression *call, struct expression *array_expr, char *key, char *value)
{
	struct expression *size_expr;
	struct symbol *size_sym;
	char *size_name;
	long param;
	struct sm_state *tmp;
	int limit_type;

	if (strncmp(key, "==$", 3) != 0)
		return;
	param = strtol(key + 3, NULL, 10);
	if (!get_param(param, &size_name, &size_sym))
		return;
	size_expr = symbol_expression(size_sym);

	limit_type = strtol(value, NULL, 10);
	tmp = set_state_expr(size_id, array_expr, alloc_compare_size(limit_type, size_expr));
	if (!tmp)
		return;
	set_state_expr(link_id, size_expr, alloc_state_expr(array_expr));
}

static void munge_start_states(struct statement *stmt)
{
	struct state_list *slist = NULL;
	struct sm_state *sm;
	struct sm_state *poss;

	FOR_EACH_MY_SM(size_id, __get_cur_stree(), sm) {
		if (sm->state != &merged)
			continue;
		/*
		 * screw it.  let's just assume that if one caller passes the
		 * size then they all do.
		 */
		FOR_EACH_PTR(sm->possible, poss) {
			if (poss->state != &merged &&
			    poss->state != &undefined) {
				add_ptr_list(&slist, poss);
				break;
			}
		} END_FOR_EACH_PTR(poss);
	} END_FOR_EACH_SM(sm);

	FOR_EACH_PTR(slist, sm) {
		set_state(size_id, sm->name, sm->sym, sm->state);
	} END_FOR_EACH_PTR(sm);

	free_slist(&slist);
}

static void set_used(struct expression *expr)
{
	struct expression *parent;
	struct expression *array;
	struct expression *offset;
	struct sm_state *tmp;
	int limit_type;

	if (expr->op != SPECIAL_INCREMENT)
		return;

	limit_type = USED_LAST;
	if (expr->type == EXPR_POSTOP)
		limit_type = USED_COUNT;

	parent = expr_get_parent_expr(expr);
	if (!parent || parent->type != EXPR_BINOP)
		return;
	parent = expr_get_parent_expr(parent);
	if (!parent || !is_array(parent))
		return;

	array = get_array_base(parent);
	offset = get_array_offset(parent);
	if (offset != expr)
		return;

	tmp = set_state_expr(size_id, array, alloc_compare_size(limit_type, offset->unop));
	if (!tmp)
		return;
	set_state_expr(link_id, offset->unop, alloc_state_expr(array));
}

static int match_assign_array(struct expression *expr)
{
	// FIXME: implement
	return 0;
}

static int match_assign_size(struct expression *expr)
{
	struct expression *right, *size, *array;
	struct smatch_state *state;
	struct sm_state *tmp;
	int limit_type;

	right = expr->right;
	size = right;
	if (size->type == EXPR_BINOP)
		size = size->left;

	array = get_array_variable(size);
	if (!array)
		return 0;
	state = get_state_expr(size_id, array);
	if (!state || !state->data)
		return 0;

	limit_type = state_to_limit(state);
	if (limit_type < 0)
		return 0;

	if (right->type == EXPR_BINOP && !match_size_binop(size, right, &limit_type))
		return 0;

	tmp = set_state_expr(size_id, array, alloc_compare_size(limit_type, expr->left));
	if (!tmp)
		return 0;
	set_state_expr(link_id, expr->left, alloc_state_expr(array));
	return 1;
}

static void match_assign(struct expression *expr)
{
	if (expr->op != '=')
		return;

	if (match_assign_array(expr))
		return;
	match_assign_size(expr);
}

static void match_copy(const char *fn, struct expression *expr, void *unused)
{
	struct expression *src, *size;
	int src_param, size_param;

	src = get_argument_from_call_expr(expr->args, 1);
	size = get_argument_from_call_expr(expr->args, 2);
	src = strip_expr(src);
	size = strip_expr(size);
	if (!src || !size)
		return;
	if (src->type != EXPR_SYMBOL || size->type != EXPR_SYMBOL)
		return;

	src_param = get_param_num_from_sym(src->symbol);
	size_param = get_param_num_from_sym(size->symbol);
	if (src_param < 0 || size_param < 0)
		return;

	sql_insert_cache(call_implies, "'%s', '%s', 0, %d, %d, %d, '==$%d', '%d'",
			 get_base_file(), get_function(), fn_static(),
			 BYTE_COUNT, src_param, size_param, BYTE_COUNT);
}

void register_buf_comparison(int id)
{
	int i;

	size_id = id;

	set_dynamic_states(size_id);

	add_unmatched_state_hook(size_id, &unmatched_state);

	add_allocation_function("malloc", &match_alloc, 0);
	add_allocation_function("memdup", &match_alloc, 1);
	add_allocation_function("realloc", &match_alloc, 1);
	if (option_project == PROJ_KERNEL) {
		add_allocation_function("kmalloc", &match_alloc, 0);
		add_allocation_function("kzalloc", &match_alloc, 0);
		add_allocation_function("vmalloc", &match_alloc, 0);
		add_allocation_function("__vmalloc", &match_alloc, 0);
		add_allocation_function("sock_kmalloc", &match_alloc, 1);
		add_allocation_function("kmemdup", &match_alloc, 1);
		add_allocation_function("kmemdup_user", &match_alloc, 1);
		add_allocation_function("dma_alloc_attrs", &match_alloc, 1);
		add_allocation_function("pci_alloc_consistent", &match_alloc, 1);
		add_allocation_function("pci_alloc_coherent", &match_alloc, 1);
		add_allocation_function("devm_kmalloc", &match_alloc, 1);
		add_allocation_function("devm_kzalloc", &match_alloc, 1);
		add_allocation_function("kcalloc", &match_calloc, 0);
		add_allocation_function("devm_kcalloc", &match_calloc, 1);
		add_allocation_function("kmalloc_array", &match_calloc, 0);
		add_allocation_function("krealloc", &match_alloc, 1);

		add_function_hook("copy_from_user", &match_copy, NULL);
		add_function_hook("__copy_from_user", &match_copy, NULL);
	}

	add_hook(&array_check, OP_HOOK);
	add_hook(&array_check_data_info, OP_HOOK);
	add_hook(&set_used, OP_HOOK);

	add_hook(&match_call, FUNCTION_CALL_HOOK);
	add_hook(&munge_start_states, AFTER_DEF_HOOK);

	add_hook(&match_assign, ASSIGNMENT_HOOK);

	for (i = BYTE_COUNT; i <= USED_COUNT; i++) {
		select_call_implies_hook(i, &set_implied);
		select_caller_info_hook(set_param_compare, i);
		select_return_implies_hook(i, &set_implied);
	}
}

void register_buf_comparison_links(int id)
{
	link_id = id;
	set_dynamic_states(link_id);
	add_merge_hook(link_id, &merge_links);
	add_modification_hook(link_id, &match_link_modify);
}

/*
 * Copyright (C) 2018 Oracle.  All rights reserved.
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
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

struct db_info {
	int count;
	struct symbol *type;
	struct range_list *rl;
};

static int get_vals(void *_db_info, int argc, char **argv, char **azColName)
{
	struct db_info *db_info = _db_info;
	struct range_list *rl;

	str_to_rl(db_info->type, argv[0], &rl);
	db_info->rl = rl_union(db_info->rl, rl);

	return 0;
}

static int is_file_local(struct expression *array)
{
	struct symbol *sym = NULL;
	char *name;

	name = expr_to_str_sym(array, &sym);
	free_string(name);
	if (!sym)
		return 0;

	if ((sym->ctype.modifiers & MOD_TOPLEVEL) &&
	    (sym->ctype.modifiers & MOD_STATIC))
		return 1;
	return 0;
}

static char *get_toplevel_name(struct expression *array)
{
	char *name;
	char buf[128];

	if (is_array(array))
		array = get_array_base(array);

	if (!array || array->type != EXPR_SYMBOL)
		return NULL;
	if (!is_file_local(array))
		return NULL;

	name = expr_to_str(array);
	snprintf(buf, sizeof(buf), "%s[]", name);
	free_string(name);

	return alloc_sname(buf);
}

static char *get_member_array(struct expression *array)
{
	char *name;
	char buf[128];

	name = get_member_name(array);
	if (!name)
		return NULL;
	snprintf(buf, sizeof(buf), "%s[]", name);
	free_string(name);
	return alloc_sname(buf);
}

static char *get_array_name(struct expression *array)
{
	struct symbol *type;
	char *name;

	type = get_type(array);
	if (!type || type->type != SYM_ARRAY)
		return NULL;

	name = get_toplevel_name(array);
	if (name)
		return name;
	name = get_member_array(array);
	if (name)
		return name;

	return NULL;
}

int get_array_rl(struct expression *expr, struct range_list **rl)
{
	struct expression *array;
	struct symbol *type;
	struct db_info db_info = {};
	char *name;

	type = get_type(expr);
	if (!type || type->type != SYM_BASETYPE)
		return 0;
	db_info.type = type;

	array = get_array_base(expr);
	name = get_array_name(array);
	if (!name)
		return 0;

	if (is_file_local(array)) {
		run_sql(&get_vals, &db_info,
			"select value from sink_info where file = '%s' and static = 1 and sink_name = '%s' and type = %d;",
			get_filename(), name, DATA_VALUE);
	} else {
		run_sql(&get_vals, &db_info,
			"select value from sink_info where sink_name = '%s' and type = %d limit 10;",
			name, DATA_VALUE);
	}
	if (!db_info.rl || db_info.count >= 10)
		return 0;

	*rl = db_info.rl;
	return 1;
}

static struct range_list *get_saved_rl(struct symbol *type, char *name)
{
	struct db_info db_info = {.type = type};

	cache_sql(&get_vals, &db_info, "select value from sink_info where sink_name = '%s' and type = %d;",
		  name, DATA_VALUE);
	return db_info.rl;
}

static void update_cache(char *name, int is_static, struct range_list *rl)
{
	cache_sql(NULL, NULL, "delete from sink_info where sink_name = '%s' and type = %d;",
		  name, DATA_VALUE);
	cache_sql(NULL, NULL, "insert into sink_info values ('%s', %d, '%s', %d, '', '%s');",
		  get_filename(), is_static, name, DATA_VALUE, show_rl(rl));
}

static void match_assign(struct expression *expr)
{
	struct expression *left, *array;
	struct range_list *orig_rl, *rl;
	struct symbol *type;
	char *name;

	type = get_type(expr->left);
	if (!type || type->type != SYM_BASETYPE)
		return;

	left = strip_expr(expr->left);
	if (!is_array(left))
		return;
	array = get_array_base(left);
	name = get_array_name(array);
	if (!name)
		return;

	if (expr->op != '=') {
		rl = alloc_whole_rl(get_type(expr->right));
		rl = cast_rl(type, rl);
	} else {
		get_absolute_rl(expr->right, &rl);
		rl = cast_rl(type, rl);
		orig_rl = get_saved_rl(type, name);
		rl = rl_union(orig_rl, rl);
	}

	update_cache(name, is_file_local(array), rl);
}

static void mark_strings_unknown(const char *fn, struct expression *expr, void *_arg)
{
	struct expression *dest;
	struct symbol *type;
	int arg = PTR_INT(_arg);
	char *name;

	dest = get_argument_from_call_expr(expr->args, arg);
	if (!dest)
		return;
	name = get_array_name(dest);
	if (!name)
		return;
	type = get_type(dest);
	if (type_is_ptr(type))
		type = get_real_base_type(type);
	update_cache(name, is_file_local(dest), alloc_whole_rl(type));
}

void register_array_values(int id)
{
	my_id = id;

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_assign, GLOBAL_ASSIGNMENT_HOOK);

	add_function_hook("sprintf", &mark_strings_unknown, INT_PTR(0));
	add_function_hook("snprintf", &mark_strings_unknown, INT_PTR(0));

	add_function_hook("strcpy", &mark_strings_unknown, INT_PTR(0));
	add_function_hook("strncpy", &mark_strings_unknown, INT_PTR(0));
	add_function_hook("strlcpy", &mark_strings_unknown, INT_PTR(0));
	add_function_hook("strscpy", &mark_strings_unknown, INT_PTR(0));
}

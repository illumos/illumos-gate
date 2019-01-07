/*
 * Copyright (C) 2016 Oracle.
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
 * What we're doing here is saving all the possible values for static variables.
 * Later on we might do globals as well.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;
static struct stree *vals;

static int save_rl(void *_rl, int argc, char **argv, char **azColName)
{
	unsigned long *rl = _rl;

	*rl = strtoul(argv[0], NULL, 10);
	return 0;
}

static struct range_list *select_orig_rl(sval_t sval)
{
	struct range_list *rl = NULL;
	mtag_t tag = sval.uvalue & ~MTAG_OFFSET_MASK;
	int offset = sval.uvalue & MTAG_OFFSET_MASK;

	mem_sql(&save_rl, &rl, "select value from mtag_data where tag = %lld and offset = %d;",
		tag, offset);
	return rl;
}

static int is_kernel_param(const char *name)
{
	struct sm_state *tmp;
	char buf[256];

	/*
	 * I'm ignoring these because otherwise Smatch thinks that kernel
	 * parameters are always set to the default.
	 *
	 */

	if (option_project != PROJ_KERNEL)
		return 0;

	snprintf(buf, sizeof(buf), "__param_%s.arg", name);

	FOR_EACH_SM(vals, tmp) {
		if (strcmp(tmp->name, buf) == 0)
			return 1;
	} END_FOR_EACH_SM(tmp);

	return 0;
}

void insert_mtag_data(sval_t sval, struct range_list *rl)
{
	mtag_t tag = sval.uvalue & ~MTAG_OFFSET_MASK;
	int offset = sval.uvalue & MTAG_OFFSET_MASK;

	rl = clone_rl_permanent(rl);

	mem_sql(NULL, NULL, "delete from mtag_data where tag = %lld and offset = %d and type = %d",
		tag, offset, DATA_VALUE);
	mem_sql(NULL, NULL, "insert into mtag_data values (%lld, %d, %d, '%lu');",
		tag, offset, DATA_VALUE, (unsigned long)rl);
}

void update_mtag_data(struct expression *expr)
{
	struct range_list *orig, *new, *rl;
	char *name;
	sval_t sval;

	name = expr_to_var(expr);
	if (is_kernel_param(name)) {
		free_string(name);
		return;
	}
	free_string(name);

	if (!get_mtag_addr_sval(expr, &sval))
		return;

	get_absolute_rl(expr, &rl);

	orig = select_orig_rl(sval);
	new = rl_union(orig, rl);
	insert_mtag_data(sval, new);
}

static void match_global_assign(struct expression *expr)
{
	struct range_list *rl;
	sval_t sval;
	char *name;

	name = expr_to_var(expr->left);
	if (is_kernel_param(name)) {
		free_string(name);
		return;
	}
	free_string(name);

	if (!get_mtag_addr_sval(expr->left, &sval))
		return;

	get_absolute_rl(expr->right, &rl);
	insert_mtag_data(sval, rl);
}

static int save_mtag_data(void *_unused, int argc, char **argv, char **azColName)
{
	struct range_list *rl;

	if (argc != 4) {
		sm_msg("Error saving mtag data");
		return 0;
	}
	if (!option_info)
		return 0;

	rl = (struct range_list *)strtoul(argv[3], NULL, 10);
	sm_msg("SQL: insert into mtag_data values ('%s', '%s', '%s', '%s');",
	       argv[0], argv[1], argv[2], show_rl(rl));

	return 0;
}

static void match_end_file(struct symbol_list *sym_list)
{
	mem_sql(&save_mtag_data, NULL, "select * from mtag_data where type = %d;",
		DATA_VALUE);
}

struct db_info {
	struct symbol *type;
	struct range_list *rl;
};

static int get_vals(void *_db_info, int argc, char **argv, char **azColName)
{
	struct db_info *db_info = _db_info;
	struct range_list *tmp;

	str_to_rl(db_info->type, argv[0], &tmp);
	if (db_info->rl)
		db_info->rl = rl_union(db_info->rl, tmp);
	else
		db_info->rl = tmp;

	return 0;
}

struct db_cache_results {
	sval_t sval;
	struct range_list *rl;
};
static struct db_cache_results cached_results[8];

static int get_rl_from_mtag_sval(sval_t sval, struct symbol *type, struct range_list **rl)
{
	struct db_info db_info = {};
	mtag_t tag;
	int offset;
	static int idx;
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(cached_results); i++) {
		if (sval.uvalue == cached_results[i].sval.uvalue) {
			if (cached_results[i].rl) {
				*rl = cached_results[i].rl;
				return 1;
			}
			return 0;
		}
	}

	tag = sval.uvalue & ~MTAG_OFFSET_MASK;
	offset = sval.uvalue & MTAG_OFFSET_MASK;
	if (offset == MTAG_OFFSET_MASK) {
		ret = 0;
		goto update_cache;
	}
	db_info.type = type;

	run_sql(get_vals, &db_info,
		"select value from mtag_data where tag = %lld and offset = %d and type = %d;",
		tag, offset, DATA_VALUE);
	if (!db_info.rl || is_whole_rl(db_info.rl)) {
		db_info.rl = NULL;
		ret = 0;
		goto update_cache;
	}

	*rl = db_info.rl;
	ret = 1;

update_cache:
	cached_results[idx].sval = sval;
	cached_results[idx].rl = db_info.rl;
	idx = (idx + 1) % ARRAY_SIZE(cached_results);

	return ret;
}

static void clear_cache(struct symbol *sym)
{
	memset(cached_results, 0, sizeof(cached_results));
}

int get_mtag_rl(struct expression *expr, struct range_list **rl)
{
	struct symbol *type;
	sval_t sval;

	if (!get_mtag_addr_sval(expr, &sval))
		return 0;

	type = get_type(expr);
	if (!type)
		return 0;

	return get_rl_from_mtag_sval(sval, type, rl);
}

void register_mtag_data(int id)
{
	my_id = id;

	add_hook(&clear_cache, FUNC_DEF_HOOK);

//	if (!option_info)
//		return;
	add_hook(&match_global_assign, GLOBAL_ASSIGNMENT_HOOK);
	add_hook(&match_end_file, END_FILE_HOOK);
}


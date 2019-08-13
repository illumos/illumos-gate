/*
 * Copyright (C) 2013 Oracle.
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

#include "scope.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

/*
 * I'm going to store the states of local data at the end of each function.
 * Then at the end of the file, I'll combine the possible range lists for
 * each state and store the value in the on-disk database.
 *
 * One issue is that when I read the data back from the in-memory database at
 * the end of the file, then I don't have access to type information.  I'll just
 * cast everything to "long long" for now, I guess.  We'll see how that works.
 */

static char *db_vals;
static int get_vals(void *unused, int argc, char **argv, char **azColName)
{
	db_vals = alloc_string(argv[0]);
	return 0;
}

static int is_array_symbol(struct expression *expr)
{
	struct symbol *type;

	if (!expr || expr->type != EXPR_SYMBOL)
		return 0;
	type = get_type(expr);
	if (!type)
		return 0;
	if (type->type == SYM_ARRAY)
		return 1;
	return 0;
}

int get_local_rl(struct expression *expr, struct range_list **rl)
{
	char *name;
	struct range_list *tmp;

	if (!is_static(expr))
		return 0;
	if (is_array_symbol(expr))
		return 0;
	name = expr_to_var(expr);
	if (!name)
		return 0;

	db_vals = NULL;
	run_sql(get_vals, NULL,
		"select value from local_values where file = '%s' and variable = '%s';",
		get_filename(), name);
	free_string(name);
	if (!db_vals)
		return 0;
	str_to_rl(&llong_ctype, db_vals, &tmp);
	*rl = cast_rl(get_type(expr), tmp);
	free_string(db_vals);

	return 1;
}

int get_local_max_helper(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (!get_local_rl(expr, &rl))
		return 0;
	*sval = rl_max(rl);
	return 1;
}

int get_local_min_helper(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (!get_local_rl(expr, &rl))
		return 0;
	*sval = rl_min(rl);
	return 1;
}

static struct smatch_state *unmatched_state(struct sm_state *sm)
{
	return alloc_estate_empty();
}

static void extra_mod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	struct smatch_state *old;
	struct smatch_state *new;

	if (!sym || !(sym->ctype.modifiers & MOD_STATIC))
		return;
	old = get_state(my_id, name, sym);
	if (old)
		new = merge_estates(old, state);
	else
		new = state;
	set_state(my_id, name, sym, new);
}

static void process_states(void)
{
	struct sm_state *sm;
	struct smatch_state *extra;
	struct range_list *rl;

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (sm->owner != my_id)
			continue;
		extra = get_state(SMATCH_EXTRA, sm->name, sm->sym);
		if (extra && estate_rl(extra))
			rl = rl_intersection(estate_rl(sm->state), estate_rl(extra));
		else
			rl = estate_rl(sm->state);
		rl = cast_rl(&llong_ctype, rl);
		mem_sql(NULL, NULL,
			"insert into local_values values ('%s', '%s', '%s', %lu);",
			get_filename(), sm->name, show_rl(rl),
			(unsigned long)sm->sym);
	} END_FOR_EACH_SM(sm);
}

static int get_initial_value_sym(struct symbol *sym, char *name, sval_t *sval)
{
	struct expression *expr_symbol, *deref, *tmp;
	char *member_name;

	if (!sym)
		return 0;

	if (!sym->initializer) {
		*sval = sval_type_val(&llong_ctype, 0);
		return 1;
	}
	if (sym->initializer->type != EXPR_INITIALIZER)
		return get_value(sym->initializer, sval);

	expr_symbol = symbol_expression(sym);
	FOR_EACH_PTR(sym->initializer->expr_list, tmp) {
		if (tmp->type != EXPR_IDENTIFIER) /* how to handle arrays?? */
			continue;
		deref = member_expression(expr_symbol, '.', tmp->expr_ident);
		member_name = expr_to_var(deref);
		if (!member_name)
			continue;
		if (strcmp(name, member_name) == 0) {
			free_string(member_name);
			return get_value(tmp->ident_expression, sval);
		}
		free_string(member_name);
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static char *cur_name;
static struct symbol *cur_symbol;
static struct range_list *cur_rl;
static void add_current_local(void)
{
	sval_t initial;

	if (!get_initial_value_sym(cur_symbol, cur_name, &initial)) {
		free_string(cur_name);
		cur_name = NULL;
		cur_rl = NULL;
		return;
	}
	add_range(&cur_rl, initial, initial);
	if (!is_whole_rl(cur_rl))
		sql_insert_local_values(cur_name, show_rl(cur_rl));
	free_string(cur_name);
	cur_name = NULL;
	cur_rl = NULL;
}

static int save_final_values(void *unused, int argc, char **argv, char **azColName)
{
	char *name = argv[0];
	char *sym_str = argv[1];
	char *value = argv[2];
	struct range_list *rl;

	if (!cur_name) {
		cur_name = alloc_string(name);
		cur_symbol = (struct symbol *)strtoul(sym_str, NULL, 10);
	} else if (strcmp(cur_name, name) != 0) {
		add_current_local();
		cur_name = alloc_string(name);
		cur_symbol = (struct symbol *)strtoul(sym_str, NULL, 10);
		cur_rl = NULL;
	}

	str_to_rl(&llong_ctype, value, &rl);
	cur_rl = rl_union(cur_rl, rl);

	return 0;
}

static void match_end_file(struct symbol_list *sym_list)
{
	mem_sql(save_final_values, NULL,
		"select distinct variable, symbol, value from local_values order by variable;");
	if (cur_name)
		add_current_local();
}

void register_local_values(int id)
{
	my_id = id;

	if (!option_info)
		return;

	set_dynamic_states(my_id);
	add_extra_mod_hook(&extra_mod_hook);
	add_unmatched_state_hook(my_id, &unmatched_state);
	add_merge_hook(my_id, &merge_estates);
	all_return_states_hook(&process_states);
	add_hook(match_end_file, END_FILE_HOOK);
	mem_sql(NULL, NULL, "alter table local_values add column symbol integer;");
}

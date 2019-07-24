/*
 * Copyright (C) 2018 Oracle.
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

/* New chips will probably be able to speculate further ahead */
#define MAX_SPEC_STMT 200

static int my_id;

struct stree *first_halfs;

struct expression *recently_set;

void set_spectre_first_half(struct expression *expr)
{
	char buf[64];
	char *name;

	name = expr_to_str(expr);
	snprintf(buf, sizeof(buf), "%p %s", expr, name);
	free_string(name);

	set_state_stree(&first_halfs, my_id, buf, NULL, alloc_state_num(get_stmt_cnt()));
}

void clear_spectre_second_halfs(void)
{
	struct sm_state *sm;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		set_state(my_id, sm->name, sm->sym, alloc_state_num(-MAX_SPEC_STMT));
	} END_FOR_EACH_SM(sm);
}

static struct smatch_state *get_spectre_first_half(struct expression *expr)
{
	char buf[64];
	char *name;

	name = expr_to_str(expr);
	snprintf(buf, sizeof(buf), "%p %s", expr, name);
	free_string(name);

	return get_state_stree(first_halfs, my_id, buf, NULL);
}

static void match_assign(struct expression *expr)
{
	struct smatch_state *state;

	if (expr->op == SPECIAL_AND_ASSIGN)
		return;

	state = get_spectre_first_half(expr->right);
	if (state) {
		set_state_expr(my_id, expr->left, state);
		recently_set = expr->left;
		return;
	}
	state = get_state_expr(my_id, expr->right);
	if (!state)
		return;
	set_state_expr(my_id, expr->left, state);
	recently_set = expr->left;
}

static void match_done(struct expression *expr)
{
	struct smatch_state *state;
	char *name;

	if (expr == recently_set)
		return;

	state = get_state_expr(my_id, expr);
	if (!state)
		return;

	if (get_stmt_cnt() - (long)state->data > MAX_SPEC_STMT)
		return;

	name = expr_to_str(expr);
	sm_msg("warn: possible spectre second half.  '%s'", name);
	free_string(name);

	set_state_expr(my_id, expr, alloc_state_num(-MAX_SPEC_STMT));
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;
	free_stree(&first_halfs);
}

void check_spectre_second_half(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;
	set_dynamic_states(my_id);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_done, SYM_HOOK);
	add_hook(&match_done, DEREF_HOOK);

	add_hook(&match_end_func, END_FUNC_HOOK);
}

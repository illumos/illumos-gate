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

#include <stdlib.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static struct smatch_state *merge_states(struct smatch_state *s1, struct smatch_state *s2)
{
	int left, right, min;

	left = PTR_INT(s1->data);
	right = PTR_INT(s2->data);

	min = left;
	if (right < min)
		min = right;
	return alloc_state_num(min);
}

long get_stmt_cnt(void)
{
	struct smatch_state *state;

	state = get_state(my_id, "stmts", NULL);
	if (!state)
		return 0;
	return (long)state->data;
}

static void match_statement(struct statement *stmt)
{
	int cnt;

	cnt = get_stmt_cnt();
	cnt++;
	set_state(my_id, "stmts", NULL, alloc_state_num(cnt));
}

static void insert_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	char buf[32];
	int cnt;

	cnt = get_stmt_cnt();
	snprintf(buf, sizeof(buf), "%d", cnt);
	sql_insert_return_states(return_id, return_ranges, STMT_CNT, -1, "", buf);
}

static void select_return_info(struct expression *expr, int param, char *key, char *value)
{
	int cnt, add;

	cnt = get_stmt_cnt();
	add = atoi(value);

	set_state(my_id, "stmts", NULL, alloc_state_num(cnt + add));
}

void register_statement_count(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_hook(match_statement, STMT_HOOK);
	add_merge_hook(my_id, &merge_states);

	add_split_return_callback(&insert_return_info);
	select_return_states_hook(STMT_CNT, &select_return_info);
}


/*
 * Copyright (C) 2014 Oracle.
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

STATE(capable);

static int capable_id;
static int ns_capable_id;

static void match_capable(const char *fn, struct expression *expr, void *_param)
{
	struct expression *arg;
	sval_t sval;
	char buf[32];

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!get_implied_value(arg, &sval))
		return;
	snprintf(buf, sizeof(buf), "%s", sval_to_str(sval));
	set_state(capable_id, buf, NULL, &capable);
}

static void match_ns_capable(const char *fn, struct expression *expr, void *_param)
{
	struct expression *arg;
	sval_t sval;
	char buf[32];

	if (get_function() && strcmp(get_function(), "capable") == 0)
		return;

	arg = get_argument_from_call_expr(expr->args, 1);
	if (!get_implied_value(arg, &sval))
		return;
	snprintf(buf, sizeof(buf), "%s", sval_to_str(sval));
	set_state(ns_capable_id, buf, NULL, &capable);
}

static void save_call_info(struct expression *call)
{
	struct sm_state *sm;

	FOR_EACH_MY_SM(capable_id, __get_cur_stree(), sm) {
		if (sm->state == &capable)
			sql_insert_caller_info(call, CAPABLE, 0, sm->name, "");
	} END_FOR_EACH_SM(sm);

	FOR_EACH_MY_SM(ns_capable_id, __get_cur_stree(), sm) {
		if (sm->state == &capable)
			sql_insert_caller_info(call, NS_CAPABLE, 0, sm->name, "");
	} END_FOR_EACH_SM(sm);
}

static void save_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;

	FOR_EACH_MY_SM(capable_id, __get_cur_stree(), sm) {
		if (sm->state == &capable)
			sql_insert_return_states(return_id, return_ranges,
						 CAPABLE, 0, sm->name, "");
	} END_FOR_EACH_SM(sm);

	FOR_EACH_MY_SM(ns_capable_id, __get_cur_stree(), sm) {
		if (sm->state == &capable)
			sql_insert_return_states(return_id, return_ranges,
						 CAPABLE, 0, sm->name, "");
	} END_FOR_EACH_SM(sm);
}

static void set_db_capable(const char *name, struct symbol *sym, char *key, char *value)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%s", key);
	set_state(capable_id, buf, NULL, &capable);
}

static void set_db_ns_capable(const char *name, struct symbol *sym, char *key, char *value)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%s", key);
	set_state(ns_capable_id, buf, NULL, &capable);
}

void check_capable(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	capable_id = id;
	add_function_hook("capable", &match_capable, INT_PTR(0));

	add_hook(&save_call_info, FUNCTION_CALL_HOOK);
	add_split_return_callback(save_return_info);
	select_caller_info_hook(set_db_capable, CAPABLE);
}

void check_ns_capable(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	ns_capable_id = id;
	add_function_hook("ns_capable", &match_ns_capable, INT_PTR(0));
	select_caller_info_hook(set_db_ns_capable, NS_CAPABLE);
}

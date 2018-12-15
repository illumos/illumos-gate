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
 * This works together with smatch_clear_buffer.c.  This one is only for
 * tracking the information and smatch_clear_buffer.c changes SMATCH_EXTRA.
 *
 * This tracks functions like memset() which clear out a chunk of memory.
 * It fills in a gap that smatch_param_set.c can't handle.  It only handles
 * void pointers because smatch_param_set.c should handle the rest.  Oh.  And
 * also it handles arrays because Smatch sucks at handling arrays.
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(cleared);
STATE(zeroed);

static void db_param_cleared(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg;
	char *name;
	struct symbol *sym;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	arg = strip_expr(arg);
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	if (strcmp(value, "0") == 0)
		set_state(my_id, name, sym, &zeroed);
	else
		set_state(my_id, name, sym, &cleared);
free:
	free_string(name);
}

static void match_memset(const char *fn, struct expression *expr, void *arg)
{
	db_param_cleared(expr, PTR_INT(arg), (char *)"$", (char *)"0");
}

static void match_memcpy(const char *fn, struct expression *expr, void *arg)
{
	db_param_cleared(expr, PTR_INT(arg), (char *)"$", (char *)"");
}

static void print_return_value_param(int return_id, char *return_ranges, struct expression *expr)
{
	struct stree *stree;
	struct sm_state *sm;
	int param;
	const char *param_name;

	stree = __get_cur_stree();

	FOR_EACH_MY_SM(my_id, stree, sm) {
		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;

		param_name = get_param_name(sm);
		if (!param_name)
			continue;

		if (sm->state == &zeroed) {
			sql_insert_return_states(return_id, return_ranges,
						 PARAM_CLEARED, param, param_name, "0");
		}

		if (sm->state == &cleared) {
			sql_insert_return_states(return_id, return_ranges,
						 PARAM_CLEARED, param, param_name, "");
		}
	} END_FOR_EACH_SM(sm);
}

static void register_clears_param(void)
{
	struct token *token;
	char name[256];
	const char *function;
	int param;

	if (option_project == PROJ_NONE)
		return;

	snprintf(name, 256, "%s.clears_argument", option_project_str);

	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		function = show_ident(token->ident);
		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		param = atoi(token->number);
		add_function_hook(function, &match_memcpy, INT_PTR(param));
		token = token->next;
	}
	clear_token_alloc();
}

#define USB_DIR_IN 0x80
static void match_usb_control_msg(const char *fn, struct expression *expr, void *_size_arg)
{
	struct expression *inout;
	sval_t sval;

	inout = get_argument_from_call_expr(expr->args, 3);

	if (get_value(inout, &sval) && !(sval.uvalue & USB_DIR_IN))
		return;

	db_param_cleared(expr, 6, (char *)"$", (char *)"");
}

static void match_assign(struct expression *expr)
{
	struct symbol *type;

	/*
	 * If we have struct foo x, y; and we say that x = y; then it
	 * initializes the struct holes.  So we record that here.
	 */
	type = get_type(expr->left);
	if (!type || type->type != SYM_STRUCT)
		return;
	set_state_expr(my_id, expr->left, &cleared);
}

static void match_array_assign(struct expression *expr)
{
	struct expression *array_expr;

	if (!is_array(expr->left))
		return;

	array_expr = get_array_base(expr->left);
	set_state_expr(my_id, array_expr, &cleared);
}

void register_param_cleared(int id)
{
	my_id = id;

	add_function_hook("memset", &match_memset, INT_PTR(0));
	add_function_hook("memzero", &match_memset, INT_PTR(0));
	add_function_hook("__memset", &match_memset, INT_PTR(0));
	add_function_hook("__memzero", &match_memset, INT_PTR(0));

	add_function_hook("memcpy", &match_memcpy, INT_PTR(0));
	add_function_hook("memmove", &match_memcpy, INT_PTR(0));
	add_function_hook("__memcpy", &match_memcpy, INT_PTR(0));
	add_function_hook("__memmove", &match_memcpy, INT_PTR(0));
	add_function_hook("strcpy", &match_memcpy, INT_PTR(0));
	add_function_hook("strncpy", &match_memcpy, INT_PTR(0));
	add_function_hook("sprintf", &match_memcpy, INT_PTR(0));
	add_function_hook("snprintf", &match_memcpy, INT_PTR(0));

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_array_assign, ASSIGNMENT_HOOK);

	register_clears_param();

	select_return_states_hook(PARAM_CLEARED, &db_param_cleared);
	add_split_return_callback(&print_return_value_param);

	if (option_project == PROJ_KERNEL) {
		add_function_hook("usb_control_msg", &match_usb_control_msg, NULL);
	}

}


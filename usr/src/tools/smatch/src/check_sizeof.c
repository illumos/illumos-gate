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

#include "smatch.h"

static int my_id;

static void check_pointer(struct expression *expr, char *ptr_name)
{
	char *name;
	sval_t sval;

	if (!expr || expr->type != EXPR_SIZEOF)
		return;

	get_value(expr, &sval);

	expr = strip_expr(expr->cast_expression);
	name = expr_to_str(expr);
	if (!name)
		return;

	if (strcmp(ptr_name, name) == 0)
		sm_warning("was 'sizeof(*%s)' intended?", ptr_name);
	free_string(name);
}

static void match_call_assignment(struct expression *expr)
{
	struct expression *call = strip_expr(expr->right);
	struct expression *arg;
	char *ptr_name;

	if (!is_pointer(expr->left))
		return;

	ptr_name = expr_to_str(expr->left);
	if (!ptr_name)
		return;

	FOR_EACH_PTR(call->args, arg) {
		check_pointer(arg, ptr_name);
	} END_FOR_EACH_PTR(arg);

	free_string(ptr_name);
}

static void check_passes_pointer(char *name, struct expression *call)
{
	struct expression *arg;
	char *ptr_name;

	FOR_EACH_PTR(call->args, arg) {
		ptr_name = expr_to_var(arg);
		if (!ptr_name)
			continue;
		if (strcmp(name, ptr_name) == 0)
			sm_warning("was 'sizeof(*%s)' intended?", name);
		free_string(ptr_name);
	} END_FOR_EACH_PTR(arg);
}

static void match_check_params(struct expression *call)
{
	struct expression *arg;
	struct expression *obj;
	char *name;

	FOR_EACH_PTR(call->args, arg) {
		if (arg->type != EXPR_SIZEOF)
			continue;
		obj = strip_expr(arg->cast_expression);
		if (!is_pointer(obj))
			continue;
		name = expr_to_var(obj);
		if (!name)
			continue;
		check_passes_pointer(name, call);
		free_string(name);
	} END_FOR_EACH_PTR(arg);
}

static struct string_list *macro_takes_sizeof_argument;
static void check_sizeof_number(struct expression *expr)
{
	char *macro, *tmp;

	if (expr->type != EXPR_VALUE)
		return;
	macro = get_macro_name(expr->pos);
	FOR_EACH_PTR(macro_takes_sizeof_argument, tmp) {
		if (macro && strcmp(tmp, macro) == 0)
			return;
	} END_FOR_EACH_PTR(tmp);

	sm_warning("sizeof(NUMBER)?");
}

static void match_sizeof(struct expression *expr)
{
	check_sizeof_number(expr);
	if (expr->type == EXPR_PREOP && expr->op == '&')
		sm_warning("sizeof(&pointer)?");
	if (expr->type == EXPR_SIZEOF)
		sm_warning("sizeof(sizeof())?");
	/* the ilog2() macro is a valid place to check the size of a binop */
	if (expr->type == EXPR_BINOP && !get_macro_name(expr->pos))
		sm_warning("taking sizeof binop");
}

static void register_macro_takes_sizeof_argument(void)
{
	struct token *token;
	char *macro;
	char name[256];

	snprintf(name, 256, "%s.macro_takes_sizeof_argument", option_project_str);

	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		macro = alloc_string(show_ident(token->ident));
		add_ptr_list(&macro_takes_sizeof_argument, macro);
		token = token->next;
	}
	clear_token_alloc();
}

void check_sizeof(int id)
{
	my_id = id;

	register_macro_takes_sizeof_argument();
	add_hook(&match_call_assignment, CALL_ASSIGNMENT_HOOK);
	add_hook(&match_check_params, FUNCTION_CALL_HOOK);
	add_hook(&match_sizeof, SIZEOF_HOOK);
}

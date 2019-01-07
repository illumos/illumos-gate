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
 * This test is used to warn about mixups between bit shifters and bit flags.
 *
 */

#include "smatch.h"
#include "smatch_function_hashtable.h"

static int my_id;

static DEFINE_HASHTABLE_INSERT(insert_struct, char, int);
static DEFINE_HASHTABLE_SEARCH(search_struct, char, int);
static struct hashtable *shifters;

static const char *get_shifter(struct expression *expr)
{
	const char *name;
	sval_t expr_value;
	const int *shifter_value;

	expr = strip_expr(expr);
	if (expr->type != EXPR_VALUE)
		return NULL;
	if (!get_value(expr, &expr_value))
		return NULL;
	name = pos_ident(expr->pos);
	if (!name)
		return NULL;
	shifter_value = search_struct(shifters, (char *)name);
	if (!shifter_value)
		return NULL;
	if (sval_cmp_val(expr_value, *shifter_value) != 0)
		return NULL;
	return name;
}

static void match_assign(struct expression *expr)
{
	const char *name;

	if (expr->op != SPECIAL_OR_ASSIGN)
		return;
	if (positions_eq(expr->pos, expr->right->pos))
		return;
	name = get_shifter(expr->right);
	if (!name)
		return;

	sm_warning("'%s' is a shifter (not for '%s').",
			name, show_special(expr->op));
}

static void match_binop(struct expression *expr)
{
	const char *name;

	if (positions_eq(expr->pos, expr->right->pos))
		return;
	if (expr->op != '&')
		return;
	name = get_shifter(expr->right);
	if (!name)
		return;

	sm_warning("bit shifter '%s' used for logical '%s'",
			name, show_special(expr->op));
}

static void register_shifters(void)
{
	char filename[256];
	struct token *token;
	char *name;
	int *val;

	snprintf(filename, sizeof(filename), "%s.bit_shifters", option_project_str);
	token = get_tokens_file(filename);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		name = alloc_string(show_ident(token->ident));
		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		val = malloc(sizeof(int));
		*val = atoi(token->number);
		insert_struct(shifters, name, val);
		token = token->next;
	}
	clear_token_alloc();
}

static void match_binop_info(struct expression *expr)
{
	char *name;
	sval_t sval;

	if (positions_eq(expr->pos, expr->right->pos))
		return;
	if (expr->op != SPECIAL_LEFTSHIFT)
		return;
	if (expr->right->type != EXPR_VALUE)
		return;
	name = pos_ident(expr->right->pos);
	if (!name)
		return;
	if (!get_value(expr->right, &sval))
		return;
	sm_msg("info: bit shifter '%s' '%s'", name, sval_to_str(sval));
}

static void match_call(const char *fn, struct expression *expr, void *_arg_no)
{
	struct expression *arg_expr;
	int arg_no = PTR_INT(_arg_no);
	sval_t sval;
	char *name;

	arg_expr = get_argument_from_call_expr(expr->args, arg_no);
	if (positions_eq(expr->pos, arg_expr->pos))
		return;
	name = pos_ident(arg_expr->pos);
	if (!name)
		return;
	if (!get_value(arg_expr, &sval))
		return;
	sm_msg("info: bit shifter '%s' '%s'", name, sval_to_str(sval));
}

void check_bit_shift(int id)
{
	my_id = id;

	shifters = create_function_hashtable(5000);
	register_shifters();

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_binop, BINOP_HOOK);

	if (option_info) {
		add_hook(&match_binop_info, BINOP_HOOK);
		if (option_project == PROJ_KERNEL) {
			add_function_hook("set_bit", &match_call, INT_PTR(0));
			add_function_hook("test_bit", &match_call, INT_PTR(0));
		}
	}
}

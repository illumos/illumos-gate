/*
 * Copyright (C) 2010 Dan Carpenter.
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
 * According to an email on lkml you are not allowed to reuse the skb
 * passed to dev_queue_xmit()
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(do_not_use);

static void ok_to_use(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &undefined);
}

static int valid_use(void)
{
	struct expression *tmp;
	int i = 0;
	int dot_ops = 0;

	FOR_EACH_PTR_REVERSE(big_expression_stack, tmp) {
		if (!i++)
			continue;
		if (tmp->type == EXPR_PREOP && tmp->op == '(')
			continue;
		if (tmp->op == '.' && !dot_ops++)
			continue;
//		if (tmp->type == EXPR_POSTOP)
//			return 1;
		if (tmp->type == EXPR_CALL && sym_name_is("kfree_skb", tmp->fn))
			return 1;
		return 0;
	} END_FOR_EACH_PTR_REVERSE(tmp);
	return 0;
}

/* match symbol is expensive.  only turn it on after we match the xmit function */
static int match_symbol_active;
static void match_symbol(struct expression *expr)
{
	struct sm_state *sm;
	char *name;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm || !slist_has_state(sm->possible, &do_not_use))
		return;
	if (valid_use())
		return;
	name = expr_to_var(expr);
	sm_error("'%s' was already used up by dev_queue_xmit()", name);
	free_string(name);
}

static void match_kfree_skb(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, 0);
	if (!arg)
		return;
	set_state_expr(my_id, arg, &undefined);
}

static void match_xmit(const char *fn, struct expression *expr, void *param)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, PTR_INT(param));
	if (!arg)
		return;
	set_state_expr(my_id, arg, &do_not_use);
	if (!match_symbol_active++) {
		add_hook(&match_symbol, SYM_HOOK);
		add_function_hook("kfree_skb", &match_kfree_skb, NULL);
	}
}

static void register_funcs_from_file(void)
{
	struct token *token;
	const char *func;
	int arg;

	token = get_tokens_file("kernel.dev_queue_xmit");
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);
		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		arg = atoi(token->number);
		add_function_hook(func, &match_xmit, INT_PTR(arg));
		token = token->next;
	}
	clear_token_alloc();
}

void check_dev_queue_xmit(int id)
{
	if (option_project != PROJ_KERNEL)
		return;
	my_id = id;
	add_modification_hook(my_id, ok_to_use);
	register_funcs_from_file();
}

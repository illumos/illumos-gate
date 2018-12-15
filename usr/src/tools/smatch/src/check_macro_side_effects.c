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

#include "scope.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_expression_stacks.h"

static int my_id;

static struct string_list *ignored_macros;
static struct position old_pos;

static struct smatch_state *alloc_my_state(struct expression *expr)
{
	struct smatch_state *state;
	char *name;

	state = __alloc_smatch_state(0);
	expr = strip_expr(expr);
	name = expr_to_str(expr);
	state->name = alloc_sname(name);
	free_string(name);
	state->data = expr;
	return state;
}

static int defined_inside_macro(struct position macro_pos, struct expression *expr)
{
	char *name;
	struct symbol *sym;
	int ret = 0;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	if (!sym->scope || !sym->scope->token)
		goto free;
	if (positions_eq(macro_pos, sym->scope->token->pos))
		ret = 1;
free:
	free_string(name);
	return ret;
}

static int affected_inside_macro_before(struct expression *expr)
{
	struct sm_state *sm;
	struct sm_state *tmp;
	struct expression *old_mod;

	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return 0;

	FOR_EACH_PTR(sm->possible, tmp) {
		old_mod = tmp->state->data;
		if (!old_mod)
			continue;
		if (positions_eq(old_mod->pos, expr->pos))
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int is_ignored_macro(const char *macro)
{
	char *tmp;

	FOR_EACH_PTR(ignored_macros, tmp) {
		if (!strcmp(tmp, macro))
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static void match_unop(struct expression *raw_expr)
{
	struct expression *expr;
	char *macro, *name;

	if (raw_expr->op != SPECIAL_INCREMENT && raw_expr->op != SPECIAL_DECREMENT)
		return;

	macro = get_macro_name(raw_expr->pos);
	if (!macro)
		return;

	expr = strip_expr(raw_expr->unop);

	if (defined_inside_macro(expr->pos, expr))
		return;

	if (is_ignored_macro(macro))
		return;

	if (!affected_inside_macro_before(expr)) {
		set_state_expr(my_id, expr, alloc_my_state(expr));
		old_pos = expr->pos;
		return;
	}

	if (!positions_eq(old_pos, expr->pos))
		return;

	name = expr_to_str(raw_expr);
	sm_warning("side effect in macro '%s' doing '%s'",
		macro, name);
	free_string(name);
}

static void match_stmt(struct statement *stmt)
{
	if (!positions_eq(old_pos, stmt->pos))
		old_pos.line = 0;
}

static void register_ignored_macros(void)
{
	struct token *token;
	char *macro;
	char name[256];

	snprintf(name, 256, "%s.ignore_side_effects", option_project_str);

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
		add_ptr_list(&ignored_macros, macro);
		token = token->next;
	}
	clear_token_alloc();
}

void check_macro_side_effects(int id)
{
	my_id = id;

	if (!option_spammy)
		return;

	add_hook(&match_unop, OP_HOOK);
	add_hook(&match_stmt, STMT_HOOK);
	register_ignored_macros();
}

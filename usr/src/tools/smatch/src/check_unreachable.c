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

static int my_id;

static int print_unreached = 1;
static struct string_list *turn_off_names;
static struct string_list *ignore_names;

static int empty_statement(struct statement *stmt)
{
	if (!stmt)
		return 0;
	if (stmt->type == STMT_EXPRESSION && !stmt->expression)
		return 1;
	return 0;
}

static int is_last_stmt(struct statement *cur_stmt)
{
	struct symbol *fn = get_base_type(cur_func_sym);
	struct statement *stmt;

	if (!fn)
		return 0;
	stmt = fn->stmt;
	if (!stmt)
		stmt = fn->inline_stmt;
	if (!stmt || stmt->type != STMT_COMPOUND)
		return 0;
	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt == cur_stmt)
		return 1;
	return 0;
}

static void print_unreached_initializers(struct symbol_list *sym_list)
{
	struct symbol *sym;

	FOR_EACH_PTR(sym_list, sym) {
		if (sym->initializer && !(sym->ctype.modifiers & MOD_STATIC))
			sm_msg("info: '%s' is not actually initialized (unreached code).",
				(sym->ident ? sym->ident->name : "this variable"));
	} END_FOR_EACH_PTR(sym);
}

static int is_ignored_macro(struct statement *stmt)
{
	char *name;
	char *tmp;

	name = get_macro_name(stmt->pos);
	if (!name)
		return 0;

	FOR_EACH_PTR(ignore_names, tmp) {
		if (strcmp(tmp, name) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static int prev_line_was_endif(struct statement *stmt)
{
	struct token *token;
	struct position pos = stmt->pos;

	pos.line--;
	pos.pos = 2;

	token = pos_get_token(pos);
	if (token && token_type(token) == TOKEN_IDENT &&
	    strcmp(show_ident(token->ident), "endif") == 0)
		return 1;

	pos.line--;
	token = pos_get_token(pos);
	if (token && token_type(token) == TOKEN_IDENT &&
	    strcmp(show_ident(token->ident), "endif") == 0)
		return 1;

	return 0;
}

static int we_jumped_into_the_middle_of_a_loop(struct statement *stmt)
{
	struct statement *prev;

	/*
	 * Smatch doesn't handle loops correctly and this is a hack.  What we
	 * do is that if the first unreachable statement is a loop and the
	 * previous statement was a goto then it's probably code like this:
	 * 	goto first;
	 * 	for (;;) {
	 *		frob();
	 * first:
	 *		more_frob();
	 * 	}
	 * Every statement is reachable but only on the second iteration.
	 */

	if (stmt->type != STMT_ITERATOR)
		return 0;
	prev = get_prev_statement();
	if (prev && prev->type == STMT_GOTO)
		return 1;
	return 0;
}

static void unreachable_stmt(struct statement *stmt)
{

	if (__inline_fn)
		return;

	if (!__path_is_null()) {
		print_unreached = 1;
		return;
	}

	/* if we hit a label then assume there is a matching goto */
	if (stmt->type == STMT_LABEL)
		print_unreached = 0;
	if (prev_line_was_endif(stmt))
		print_unreached = 0;
	if (we_jumped_into_the_middle_of_a_loop(stmt))
		print_unreached = 0;

	if (!print_unreached)
		return;
	if (empty_statement(stmt))
		return;
	if (is_ignored_macro(stmt))
		return;

	switch (stmt->type) {
	case STMT_COMPOUND: /* after a switch before a case stmt */
	case STMT_RANGE:
	case STMT_CASE:
		return;
	case STMT_DECLARATION: /* switch (x) { int a; case foo: ... */
		print_unreached_initializers(stmt->declaration);
		return;
	case STMT_RETURN: /* gcc complains if you don't have a return statement */
		if (is_last_stmt(stmt))
			return;
		break;
	case STMT_GOTO:
		/* people put extra breaks inside switch statements */
		if (stmt->goto_label && stmt->goto_label->type == SYM_NODE &&
		    strcmp(stmt->goto_label->ident->name, "break") == 0)
			return;
		break;
	default:
		break;
	}
	sm_msg("info: ignoring unreachable code.");
	print_unreached = 0;
}

static int is_turn_off(char *name)
{
	char *tmp;

	if (!name)
		return 0;

	FOR_EACH_PTR(turn_off_names, tmp) {
		if (strcmp(tmp, name) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static char *get_function_name(struct statement *stmt)
{
	struct expression *expr;

	if (stmt->type != STMT_EXPRESSION)
		return NULL;
	expr = stmt->expression;
	if (!expr || expr->type != EXPR_CALL)
		return NULL;
	if (expr->fn->type != EXPR_SYMBOL || !expr->fn->symbol_name)
		return NULL;
	return expr->fn->symbol_name->name;
}

static void turn_off_unreachable(struct statement *stmt)
{
	char *name;

	name = get_macro_name(stmt->pos);
	if (is_turn_off(name)) {
		print_unreached = 0;
		return;
	}

	if (stmt->type == STMT_IF &&
	    known_condition_true(stmt->if_conditional) &&  __path_is_null()) {
		print_unreached = 0;
		return;
	}

	name = get_function_name(stmt);
	if (is_turn_off(name))
		print_unreached = 0;
}

static void register_turn_off_macros(void)
{
	struct token *token;
	char *macro;
	char name[256];

	if (option_project == PROJ_NONE)
		strcpy(name, "unreachable.turn_off");
	else
		snprintf(name, 256, "%s.unreachable.turn_off", option_project_str);

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
		add_ptr_list(&turn_off_names, macro);
		token = token->next;
	}
	clear_token_alloc();
}

static void register_ignored_macros(void)
{
	struct token *token;
	char *macro;
	char name[256];

	if (option_project == PROJ_NONE)
		strcpy(name, "unreachable.ignore");
	else
		snprintf(name, 256, "%s.unreachable.ignore", option_project_str);

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
		add_ptr_list(&ignore_names, macro);
		token = token->next;
	}
	clear_token_alloc();
}

void check_unreachable(int id)
{
	my_id = id;

	register_turn_off_macros();
	register_ignored_macros();
	add_hook(&unreachable_stmt, STMT_HOOK);
	add_hook(&turn_off_unreachable, STMT_HOOK_AFTER);
}

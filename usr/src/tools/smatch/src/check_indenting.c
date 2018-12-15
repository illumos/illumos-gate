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

static struct string_list *ignored_macros;

static int in_ignored_macro(struct statement *stmt)
{
	const char *macro;
	char *tmp;

	macro = get_macro_name(stmt->pos);
	if (!macro)
		return 0;

	FOR_EACH_PTR(ignored_macros, tmp) {
		if (!strcmp(tmp, macro))
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int missing_curly_braces(struct statement *stmt)
{
	int inside_pos;

	if (stmt->pos.pos == __prev_stmt->pos.pos)
		return 0;

	if (__prev_stmt->type == STMT_IF) {
		if (__prev_stmt->if_true->type == STMT_COMPOUND)
			return 0;
		inside_pos = __prev_stmt->if_true->pos.pos;
	} else if (__prev_stmt->type == STMT_ITERATOR) {
		if (!__prev_stmt->iterator_pre_condition)
			return 0;
		if (__prev_stmt->iterator_statement->type == STMT_COMPOUND)
			return 0;
		inside_pos = __prev_stmt->iterator_statement->pos.pos;
	} else {
		return 0;
	}

	if (stmt->pos.pos != inside_pos)
		return 0;

	sm_warning("curly braces intended?");
	return 1;
}

static int prev_lines_say_endif(struct statement *stmt)
{
	struct token *token;
	struct position pos = stmt->pos;
	int i;

	pos.pos = 2;

	for (i = 0; i < 4; i++) {
		pos.line--;
		token = pos_get_token(pos);
		if (token && token_type(token) == TOKEN_IDENT &&
		    strcmp(show_ident(token->ident), "endif") == 0)
			return 1;
	}

	return 0;
}

static int is_pre_or_post_statement(struct statement *stmt)
{
	if (!stmt->parent)
		return 0;
	if (stmt->parent->type != STMT_ITERATOR)
		return 0;
	if (stmt->parent->iterator_pre_statement == stmt ||
	    stmt->parent->iterator_post_statement == stmt)
		return 1;
	return 0;
}

/*
 * If we go out of position, then warn, but don't warn when we go back
 * into the correct position.
 */
static int orig_pos;

/*
 * If the code has two statements on the same line then don't complain
 * on the following line.  This is a bit of hack because it relies on the
 * quirk that we don't process nested inline functions.
 */
static struct position ignore_prev;
static struct position ignore_prev_inline;

static void match_stmt(struct statement *stmt)
{
	if (stmt != __cur_stmt)
		return;
	if (!__prev_stmt)
		return;

	if (prev_lines_say_endif(stmt))
		return;

	if (is_pre_or_post_statement(stmt))
		return;
	/* ignore empty statements if (foo) frob();; */
	if (stmt->type == STMT_EXPRESSION && !stmt->expression)
		return;
	if (__prev_stmt->type == STMT_EXPRESSION && !__prev_stmt->expression)
		return;

	if (__prev_stmt->type == STMT_LABEL || __prev_stmt->type == STMT_CASE)
		return;
	/*
	 * This is sort of ugly.  The first statement after a case/label is
	 * special.  Probably we should handle this in smatch_flow.c so that
	 * this is not a special case.  Anyway it's like this:
	 * "foo: one++; two++;"  The code is on the same line.
	 * Also there is still a false positive here, if the first case
	 * statement has two statements on the same line.  I'm not sure what the
	 * deal is with that.
	 */
	if (stmt->type == STMT_CASE) {
		if (__next_stmt &&
		    __next_stmt->pos.line == stmt->case_statement->pos.line)
			ignore_prev = __next_stmt->pos;
		return;
	}
	if (stmt->type == STMT_LABEL) {
		if (__next_stmt &&
		    __next_stmt->pos.line == stmt->label_statement->pos.line)
			ignore_prev = __next_stmt->pos;
		return;
	}

	if (missing_curly_braces(stmt))
		return;

	if (stmt->pos.line == __prev_stmt->pos.line) {
		if (__inline_fn)
			ignore_prev_inline = stmt->pos;
		else
			ignore_prev = stmt->pos;
		return;
	}
	if (stmt->pos.pos == __prev_stmt->pos.pos)
		return;

	/* some people like to line up their break and case statements. */
	if (stmt->type == STMT_GOTO && stmt->goto_label &&
	    stmt->goto_label->type == SYM_NODE &&
	    strcmp(stmt->goto_label->ident->name, "break") == 0) {
		if (__next_stmt && __next_stmt->type == STMT_CASE &&
		    (stmt->pos.line == __next_stmt->pos.line ||
		     stmt->pos.pos == __next_stmt->pos.pos))
			return;
		/*
		 * If we have a compound and the last statement is a break then
		 * it's probably intentional.  This is most likely inside a
		 * case statement.
		 */
		if (!__next_stmt)
			return;
	}

	if (cmp_pos(__prev_stmt->pos, ignore_prev) == 0 ||
	    cmp_pos(__prev_stmt->pos, ignore_prev_inline) == 0)
		return;

	if (in_ignored_macro(stmt))
		return;

	if (stmt->pos.pos == orig_pos) {
		orig_pos = 0;
		return;
	}
	sm_warning("inconsistent indenting");
	orig_pos = __prev_stmt->pos.pos;
}

static void match_end_func(void)
{
	if (__inline_fn)
		return;
	orig_pos = 0;
}

static void register_ignored_macros(void)
{
	struct token *token;
	char *macro;
	char name[256];

	snprintf(name, 256, "%s.ignore_macro_indenting", option_project_str);

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

void check_indenting(int id)
{
	my_id = id;
	add_hook(&match_stmt, STMT_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
	register_ignored_macros();
}

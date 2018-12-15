/*
 * sparse/token_store.c
 *
 * Copyright (C) 2012 Oracle.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "parse.h"
#include "allocate.h"

struct line {
	struct position pos;
	struct line *prev;
	struct token *token;
	struct line *next;
};

__ALLOCATOR(struct token, "token store", perm_token);
ALLOCATOR(line, "line of tokens");

static struct token *copy_token(struct token *token)
{
	struct token *new;

	new = __alloc_perm_token(0);
	memcpy(new, token, sizeof(*token));
	new->next = NULL;
	return new;
}

static struct line *cursor;

static void find_line(struct position pos)
{
	if (!cursor)
		return;
	if (pos.line == cursor->pos.line)
		return;
	if (pos.line < cursor->pos.line) {
		if (!cursor->prev)
			return;
		cursor = cursor->prev;
		find_line(pos);
		return;
	}
	if (!cursor->next)
		return;
	if (pos.line < cursor->next->pos.line)
		return;
	cursor = cursor->next;
	find_line(pos);
}

static void insert_into_line(struct token **current, struct token *new)
{
	if (!*current) {
		*current = new;
		return;
	}

	if (new->pos.pos < (*current)->pos.pos) {
		new->next = *current;
		*current = new;
		return;
	}

	if (new->pos.pos == (*current)->pos.pos)
		return;

	insert_into_line(&(*current)->next, new);
}

static void store_token(struct token *token)
{
	token = copy_token(token);

	find_line(token->pos);

	if (!cursor) {
		cursor = __alloc_line(0);
		cursor->pos = token->pos;
		cursor->token = token;
		return;
	}

	if (token->pos.line < cursor->pos.line) {
		cursor->prev = __alloc_line(0);
		cursor->prev->next = cursor;
		cursor = cursor->prev;
		cursor->pos = token->pos;
		cursor->token = token;
		return;
	}

	if (token->pos.line == cursor->pos.line) {
		insert_into_line(&cursor->token, token);
		return;
	}

	cursor->next = __alloc_line(0);
	cursor->next->prev = cursor;
	cursor = cursor->next;
	cursor->pos = token->pos;
	cursor->token = token;
}

void store_all_tokens(struct token *token)
{
	while (token_type(token) != TOKEN_STREAMEND) {
		store_token(token);
		token = token->next;
	}
}

struct token *first_token_from_line(struct position pos)
{
	find_line(pos);

	if (!cursor)
		return NULL;

	if (cursor->pos.stream != pos.stream)
		return NULL;
	if (cursor->pos.line != pos.line)
		return NULL;

	return cursor->token;
}

struct token *pos_get_token(struct position pos)
{
	struct token *token;

	token = first_token_from_line(pos);
	while (token) {
		if (pos.pos == token->pos.pos)
			return token;
		if (pos.pos < token->pos.pos)
			return NULL;
		token = token->next;
	}
	return NULL;
}

char *pos_ident(struct position pos)
{
	struct token *token;

	token = pos_get_token(pos);
	if (!token)
		return NULL;
	if (token_type(token) != TOKEN_IDENT)
		return NULL;
	return token->ident->name;
}


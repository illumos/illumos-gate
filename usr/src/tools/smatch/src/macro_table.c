/*
 * sparse/macro_table.c
 *
 * Copyright (C) 2010 Dan Carpenter.
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
#include "cwchash/hashtable.h"

static struct hashtable *macro_table;

static DEFINE_HASHTABLE_INSERT(do_insert_macro, struct position, char);
static DEFINE_HASHTABLE_SEARCH(do_search_macro, struct position, char);

static inline unsigned int position_hash(void *_pos)
{
	struct position *pos = _pos;

	return pos->line | (pos->pos << 22) | (pos->stream << 18); 
}

static inline int equalkeys(void *_pos1, void *_pos2)
{
	struct position *pos1 = _pos1;
	struct position *pos2 = _pos2;

	return pos1->line == pos2->line && pos1->pos == pos2->pos &&
		pos1->stream == pos2->stream;
}

void store_macro_pos(struct token *token)
{
	if (!macro_table)
		macro_table = create_hashtable(5000, position_hash, equalkeys);

	if (get_macro_name(token->pos))
		return;

	do_insert_macro(macro_table, &token->pos, token->ident->name);
}

char *get_macro_name(struct position pos)
{
	return do_search_macro(macro_table, &pos);
}

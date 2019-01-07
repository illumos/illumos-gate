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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "smatch.h"
#include "cwchash/hashtable.h"

static inline unsigned int djb2_hash(void *ky)
{
	char *str = (char *)ky;
	unsigned long hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return hash;
}

static inline int equalkeys(void *k1, void *k2)
{
	return !strcmp((char *)k1, (char *)k2);
}

#define DEFINE_FUNCTION_ADD_HOOK(_name, _item_type, _list_type) \
void add_##_name(struct hashtable *table, const char *look_for, _item_type *value) \
{                                                               \
	_list_type *list;                                       \
	char *key;                                              \
                                                                \
	key = alloc_string(look_for);                           \
	list = search_##_name(table, key);                      \
	if (!list) {                                            \
		add_ptr_list(&list, value);                     \
	} else {                                                \
		remove_##_name(table, key);                     \
		add_ptr_list(&list, value);                     \
	}                                                       \
	insert_##_name(table, key, list);                       \
}

static inline struct hashtable *create_function_hashtable(int size)
{
	return create_hashtable(size, djb2_hash, equalkeys);
}

static inline void destroy_function_hashtable(struct hashtable *table)
{
	hashtable_destroy(table, 0);
}

#define DEFINE_FUNCTION_HASHTABLE(_name, _item_type, _list_type)   \
	DEFINE_HASHTABLE_INSERT(insert_##_name, char, _list_type); \
	DEFINE_HASHTABLE_SEARCH(search_##_name, char, _list_type); \
	DEFINE_HASHTABLE_REMOVE(remove_##_name, char, _list_type); \
	DEFINE_FUNCTION_ADD_HOOK(_name, _item_type, _list_type);

#define DEFINE_FUNCTION_HASHTABLE_STATIC(_name, _item_type, _list_type)   \
	static DEFINE_HASHTABLE_INSERT(insert_##_name, char, _list_type); \
	static DEFINE_HASHTABLE_SEARCH(search_##_name, char, _list_type); \
	static DEFINE_HASHTABLE_REMOVE(remove_##_name, char, _list_type); \
	static DEFINE_FUNCTION_ADD_HOOK(_name, _item_type, _list_type);

#define DEFINE_STRING_HASHTABLE_STATIC(_name)   \
	static DEFINE_HASHTABLE_INSERT(insert_##_name, char, int); \
	static DEFINE_HASHTABLE_SEARCH(search_##_name, char, int); \
	static struct hashtable *_name

static inline void load_hashtable_helper(const char *file, int (*insert_func)(struct hashtable *, char *, int *), struct hashtable *table)
{
	char filename[256];
	struct token *token;
	char *name;

	snprintf(filename, sizeof(filename), "%s.%s", option_project_str, file);
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
		insert_func(table, name, (void *)1);
		token = token->next;
	}
	clear_token_alloc();
}

#define load_strings(file, _table) load_hashtable_helper(file, insert_##_table, _table)

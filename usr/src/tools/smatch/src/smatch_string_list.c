/*
 * Copyright (C) 2013 Oracle.
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

int list_has_string(struct string_list *str_list, const char *str)
{
	char *tmp;
	int cmp;

	if (!str)
		return 0;

	FOR_EACH_PTR(str_list, tmp) {
		cmp = strcmp(tmp, str);
		if (cmp < 0)
			continue;
		if (cmp == 0)
			return 1;
		return 0;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

int insert_string(struct string_list **str_list, const char *_new)
{
	char *new = (char *)_new;
	char *tmp;
	int cmp;

	FOR_EACH_PTR(*str_list, tmp) {
		cmp = strcmp(tmp, new);
		if (cmp < 0)
			continue;
		else if (cmp == 0) {
			return 0;
		} else {
			INSERT_CURRENT(alloc_string(new), tmp);
			return 1;
		}
	} END_FOR_EACH_PTR(tmp);
	new = alloc_string(new);
	add_ptr_list(str_list, new);
	return 1;
}

struct string_list *clone_str_list(struct string_list *orig)
{
	char *tmp;
	struct string_list *ret = NULL;

	FOR_EACH_PTR(orig, tmp) {
		add_ptr_list(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

struct string_list *combine_string_lists(struct string_list *one, struct string_list *two)
{
	struct string_list *ret;
	char *tmp;

	ret = clone_str_list(one);
	FOR_EACH_PTR(two, tmp) {
		insert_string(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}



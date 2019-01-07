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
 * The kernel has a small stack so putting huge structs and arrays on the
 * stack is a bug.
 *
 */

#include "smatch.h"

static int my_id;

static int total_size;
static int max_size;
static int max_lineno;
static int complained;

#define MAX_ALLOWED 1000

static void scope_end(void *_size)
{
	int size = PTR_INT(_size);
	total_size -= size;
}

static void match_declarations(struct symbol *sym)
{
	struct symbol *base;
	const char *name;

	base = get_base_type(sym);
	if (sym->ctype.modifiers & MOD_STATIC)
		return;
	name = sym->ident->name;
	total_size += type_bytes(base);
	if (total_size > max_size) {
		max_size = total_size;
		max_lineno = get_lineno();
	}
	if (type_bytes(base) >= MAX_ALLOWED) {
		complained = 1;
		sm_warning("'%s' puts %d bytes on stack", name, type_bytes(base));
	}
	add_scope_hook(&scope_end, INT_PTR(type_bytes(base))); 
}

static void match_end_func(struct symbol *sym)
{
	if (__inline_fn)
		return;

	if ((max_size >= MAX_ALLOWED) && !complained) {
		sm_printf("%s:%d %s() ", get_filename(), max_lineno, get_function());
		sm_printf("warn: function puts %d bytes on stack\n", max_size);
	}
	total_size = 0;
	complained = 0;
	max_size = 0;
	max_lineno = 0;
}

void check_stack(int id)
{
	if (option_project != PROJ_KERNEL || !option_spammy)
		return;

	my_id = id;
	add_hook(&match_declarations, DECLARATION_HOOK);
	add_hook(&match_end_func, END_FUNC_HOOK);
}

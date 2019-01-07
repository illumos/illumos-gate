/*
 * Symbol scoping.
 *
 * This is pretty trivial.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
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
#include <string.h>
#include <stdio.h>

#include "lib.h"
#include "allocate.h"
#include "symbol.h"
#include "scope.h"

static struct scope builtin_scope = { .next = &builtin_scope };

struct scope	*block_scope = &builtin_scope,		// regular automatic variables etc
		*function_scope = &builtin_scope,	// labels, arguments etc
		*file_scope = &builtin_scope,		// static
		*global_scope = &builtin_scope;		// externally visible

void bind_scope(struct symbol *sym, struct scope *scope)
{
	sym->scope = scope;
	add_symbol(&scope->symbols, sym);
}

void rebind_scope(struct symbol *sym, struct scope *new)
{
	struct scope *old = sym->scope;

	if (old == new)
		return;

	if (old)
		delete_ptr_list_entry((struct ptr_list**) &old->symbols, sym, 1);

	bind_scope(sym, new);
}

static void start_scope(struct scope **s, struct position pos)
{
	struct scope *scope = __alloc_scope(0);
	memset(scope, 0, sizeof(*scope));
	scope->token = __alloc_token(0);
	scope->token->pos = pos;
	scope->next = *s;
	*s = scope;
}

void start_file_scope(void)
{
	struct scope *scope = __alloc_scope(0);

	memset(scope, 0, sizeof(*scope));
	scope->next = &builtin_scope;
	file_scope = scope;

	/* top-level stuff defaults to file scope, "extern" etc will choose global scope */
	function_scope = scope;
	block_scope = scope;
}

void start_symbol_scope(struct position pos)
{
	start_scope(&block_scope, pos);
}

void start_function_scope(struct position pos)
{
	start_scope(&function_scope, pos);
	start_scope(&block_scope, pos);
}

static void remove_symbol_scope(struct symbol *sym)
{
	struct symbol **ptr = &sym->ident->symbols;

	while (*ptr != sym)
		ptr = &(*ptr)->next_id;
	*ptr = sym->next_id;
}

static void end_scope(struct scope **s)
{
	struct scope *scope = *s;
	struct symbol_list *symbols = scope->symbols;
	struct symbol *sym;

	*s = scope->next;
	scope->symbols = NULL;
	FOR_EACH_PTR(symbols, sym) {
		remove_symbol_scope(sym);
	} END_FOR_EACH_PTR(sym);
}

void end_file_scope(void)
{
	end_scope(&file_scope);
}

void new_file_scope(void)
{
	if (file_scope != &builtin_scope)
		end_file_scope();
	start_file_scope();
}

void end_symbol_scope(void)
{
	end_scope(&block_scope);
}

void end_function_scope(void)
{
	end_scope(&block_scope);
	end_scope(&function_scope);
}

int is_outer_scope(struct scope *scope)
{
	if (scope == block_scope)
		return 0;
	if (scope == &builtin_scope && block_scope->next == &builtin_scope)
		return 0;
	return 1;
}


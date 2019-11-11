/*
 * allocate.c - simple space-efficient blob allocator.
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
 *
 * Simple allocator for data that doesn't get partially free'd.
 * The tokenizer and parser allocate a _lot_ of small data structures
 * (often just two-three bytes for things like small integers),
 * and since they all depend on each other you can't free them
 * individually _anyway_. So do something that is very space-
 * efficient: allocate larger "blobs", and give out individual
 * small bits and pieces of it with no maintenance overhead.
 */
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>

#include "lib.h"
#include "allocate.h"
#include "compat.h"
#include "token.h"
#include "symbol.h"
#include "scope.h"
#include "expression.h"
#include "linearize.h"

void protect_allocations(struct allocator_struct *desc)
{
	desc->blobs = NULL;
}

void drop_all_allocations(struct allocator_struct *desc)
{
	struct allocation_blob *blob = desc->blobs;

	desc->blobs = NULL;
	desc->allocations = 0;
	desc->total_bytes = 0;
	desc->useful_bytes = 0;
	desc->freelist = NULL;
	while (blob) {
		struct allocation_blob *next = blob->next;
		blob_free(blob, desc->chunking);
		blob = next;
	}
}

void free_one_entry(struct allocator_struct *desc, void *entry)
{
	void **p = entry;
	*p = desc->freelist;
	desc->freelist = p;
}

void *allocate(struct allocator_struct *desc, unsigned int size)
{
	unsigned long alignment = desc->alignment;
	struct allocation_blob *blob = desc->blobs;
	void *retval;

	/*
	 * NOTE! The freelist only works with things that are
	 *  (a) sufficiently aligned
	 *  (b) use a constant size
	 * Don't try to free allocators that don't follow
	 * these rules.
	 */
	if (desc->freelist) {
		void **p = desc->freelist;
		retval = p;
		desc->freelist = *p;
		do {
			*p = NULL;
			p++;
		} while ((size -= sizeof(void *)) > 0);
		return retval;
	}

	desc->allocations++;
	desc->useful_bytes += size;
	size = (size + alignment - 1) & ~(alignment-1);
	if (!blob || blob->left < size) {
		unsigned int offset, chunking = desc->chunking;
		struct allocation_blob *newblob = blob_alloc(chunking);
		if (!newblob)
			die("out of memory");
		if (size > chunking)
			die("alloc too big");
		desc->total_bytes += chunking;
		newblob->next = blob;
		blob = newblob;
		desc->blobs = newblob;
		offset = offsetof(struct allocation_blob, data);
		offset = (offset + alignment - 1) & ~(alignment-1);
		blob->left = chunking - offset;
		blob->offset = offset - offsetof(struct allocation_blob, data);
	}
	retval = blob->data + blob->offset;
	blob->offset += size;
	blob->left -= size;
	return retval;
}

void show_allocations(struct allocator_struct *x)
{
	fprintf(stderr, "%s: %lu allocations, %lu bytes (%lu total bytes, "
			"%6.2f%% usage, %6.2f average size)\n",
		x->name, x->allocations, x->useful_bytes, x->total_bytes,
		100 * (double) x->useful_bytes / x->total_bytes,
		(double) x->useful_bytes / x->allocations);
}

void get_allocator_stats(struct allocator_struct *x, struct allocator_stats *s)
{
	s->name = x->name;
	s->allocations = x->allocations;
	s->useful_bytes = x->useful_bytes;
	s->total_bytes = x->total_bytes;
}

ALLOCATOR(ident, "identifiers");
ALLOCATOR(token, "tokens");
ALLOCATOR(context, "contexts");
ALLOCATOR(symbol, "symbols");
ALLOCATOR(expression, "expressions");
ALLOCATOR(statement, "statements");
ALLOCATOR(string, "strings");
ALLOCATOR(scope, "scopes");
__DO_ALLOCATOR(void, 0, 1, "bytes", bytes);
ALLOCATOR(basic_block, "basic_block");
ALLOCATOR(entrypoint, "entrypoint");
ALLOCATOR(instruction, "instruction");
ALLOCATOR(multijmp, "multijmp");
ALLOCATOR(pseudo, "pseudo");



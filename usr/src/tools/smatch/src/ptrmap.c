// SPDX-License-Identifier: MIT
/*
 * Stupid implementation of pointer -> pointer map.
 *
 * Copyright (c) 2017 Luc Van Oostenryck.
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

#include "ptrmap.h"
#include "allocate.h"
#include <stddef.h>

#define	MAP_NR	7

struct ptrpair {
	void *key;
	void *val;
};
struct ptrmap {
	struct ptrmap *next;
	int nr;
	struct ptrpair pairs[MAP_NR];
};

DECLARE_ALLOCATOR(ptrmap);
ALLOCATOR(ptrmap, "ptrmap");

void __ptrmap_add(struct ptrmap **mapp, void *key, void *val)
{
	struct ptrmap *head = *mapp;
	struct ptrmap *newmap;
	struct ptrmap *map;
	struct ptrpair *pair;
	int nr;

	if ((map = head)) {
		struct ptrmap *next = map->next;
		if (next)		// head is full
			map = next;
		if ((nr = map->nr) < MAP_NR)
			goto oldmap;
	}

	// need a new block
	newmap = __alloc_ptrmap(0);
	if (!head) {
		*mapp = newmap;
	} else {
		newmap->next = head->next;
		head->next = newmap;
	}
	map = newmap;
	nr = 0;

oldmap:
	pair = &map->pairs[nr];
	pair->key = key;
	pair->val = val;
	map->nr = ++nr;
}

void *__ptrmap_lookup(struct ptrmap *map, void *key)
{
	for (; map; map = map->next) {
		int i, n = map->nr;
		for (i = 0; i < n; i++) {
			struct ptrpair *pair = &map->pairs[i];
			if (pair->key == key)
				return pair->val;
		}
	}
	return NULL;
}

void __ptrmap_update(struct ptrmap **mapp, void *key, void *val)
{
	struct ptrmap *map = *mapp;

	for (; map; map = map->next) {
		int i, n = map->nr;
		for (i = 0; i < n; i++) {
			struct ptrpair *pair = &map->pairs[i];
			if (pair->key == key) {
				if (pair->val != val)
					pair->val = val;
				return;
			}
		}
	}

	__ptrmap_add(mapp, key, val);
}

// SPDX-License-Identifier: MIT

#ifndef SSET_H
#define SSET_H

/*
 * sset.h - an all O(1) implementation of sparse sets as presented in:
 *	"An Efficient Representation for Sparse Sets"
 *	by Preston Briggs and Linda Torczon
 *
 * Copyright (C) 2017 - Luc Van Oostenryck
 */

#include <stdbool.h>

struct sset {
	unsigned int nbr;
	unsigned int off;
	unsigned int size;
	unsigned int sets[0];
};

extern struct sset *sset_init(unsigned int size, unsigned int off);
extern void sset_free(struct sset *s);


static inline void sset_reset(struct sset *s)
{
	s->nbr = 0;
}

static inline void sset_add(struct sset *s, unsigned int idx)
{
	unsigned int __idx = idx - s->off;
	unsigned int n = s->nbr++;
	s->sets[__idx] = n;
	s->sets[s->size + n] = __idx;
}

static inline bool sset_test(struct sset *s, unsigned int idx)
{
	unsigned int __idx = idx - s->off;
	unsigned int n = s->sets[__idx];

	return (n < s->nbr) && (s->sets[s->size + n] == __idx);
}

static inline bool sset_testset(struct sset *s, unsigned int idx)
{
	if (sset_test(s, idx))
		return true;
	sset_add(s, idx);
	return false;
}

#endif

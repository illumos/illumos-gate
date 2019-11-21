// SPDX-License-Identifier: MIT
//
// sset.c - an all O(1) implementation of sparse sets as presented in:
//	"An Efficient Representation for Sparse Sets"
//	by Preston Briggs and Linda Torczon
//
// Copyright (C) 2017 - Luc Van Oostenryck

#include "sset.h"
#include "lib.h"
#include <stdlib.h>


struct sset *sset_init(unsigned int first, unsigned int last)
{
	unsigned int size = last - first + 1;
	struct sset *s = malloc(sizeof(*s) + size * 2 * sizeof(s->sets[0]));

	s->size = size;
	s->off = first;
	s->nbr = 0;
	return s;
}

void sset_free(struct sset *s)
{
	free(s);
}

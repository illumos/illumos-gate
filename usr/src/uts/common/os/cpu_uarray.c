/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/cpu_uarray.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/kmem.h>

static size_t
cpu_uarray_size(size_t nr_items)
{
	size_t size = P2ROUNDUP(nr_items * sizeof (uint64_t), CUA_ALIGN);
	size *= NCPU;
	return (sizeof (cpu_uarray_t) + size);
}

cpu_uarray_t *
cpu_uarray_zalloc(size_t nr_items, int kmflags)
{
	cpu_uarray_t *cua;

	cua = kmem_zalloc(cpu_uarray_size(nr_items), kmflags);

	if (cua != NULL) {
		VERIFY(IS_P2ALIGNED(cua->cu_vals, CUA_ALIGN));
		cua->cu_nr_items = nr_items;
	}

	return (cua);
}

void
cpu_uarray_free(cpu_uarray_t *cua)
{
	kmem_free(cua, cpu_uarray_size(cua->cu_nr_items));
}

uint64_t
cpu_uarray_sum(cpu_uarray_t *cua, size_t index)
{
	uint64_t sum = 0;

	VERIFY3U(index, <, cua->cu_nr_items);

	for (size_t c = 0; c < ncpus; c++) {
		uint64_t addend = CPU_UARRAY_VAL(cua, c, index);
		sum = UINT64_OVERFLOW_ADD(sum, addend);
	}

	return (sum);
}

uint64_t
cpu_uarray_sum_all(cpu_uarray_t *cua)
{
	uint64_t sum = 0;

	for (size_t c = 0; c < ncpus; c++) {
		for (size_t i = 0; i < cua->cu_nr_items; i++) {
			uint64_t addend = CPU_UARRAY_VAL(cua, c, i);
			sum = UINT64_OVERFLOW_ADD(sum, addend);
		}
	}

	return (sum);
}

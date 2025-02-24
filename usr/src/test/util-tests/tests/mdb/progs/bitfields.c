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
 * Copyright 2025 oxide Computer Company
 */

/*
 * Test various awkward bitfield cases. In particular, where we have things that
 * don't cross byte alignment.
 */

#include <stdint.h>

typedef struct broken {
	uint32_t	brk_a:3;
	uint32_t	brk_b:2;
	uint32_t	brk_c:1;
	uint32_t	brk_d:1;
	uint32_t	brk_e:1;
	uint32_t	brk_f:1;
	uint32_t	brk_g:3;
	uint32_t	brk_h:3;
	uint32_t	brk_i:5;
	uint32_t	brk_j:4;
	uint32_t	brk_k:6;
	uint32_t	brk_l:1;
	uint32_t	brk_m:1;
} broken_t;

broken_t first = {
	.brk_a = 3,
	.brk_b = 3,
	.brk_c = 0,
	.brk_d = 1,
	.brk_e = 1,
	.brk_f = 1,
	.brk_g = 3,
	.brk_h = 5,
	.brk_i = 3,
	.brk_j = 9,
	.brk_k = 19,
	.brk_l = 0,
	.brk_m = 1
};

typedef struct broken6461 {
	unsigned short a:1;
	unsigned short b:8;
	unsigned short c:3;
	unsigned short d:2;
	unsigned short e:1;
	unsigned short f:1;
} broken6461_t;

broken6461_t second = {
	.a = 1,
	.b = 2,
	.e = 1
};

int
main(void)
{
	return (0);
}

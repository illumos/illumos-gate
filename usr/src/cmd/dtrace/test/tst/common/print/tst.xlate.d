/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2024 Ryan Zezeski
 */

#pragma D option quiet

typedef struct pancakes {
	int i;
	string s;
	timespec_t t;
} pancakes_t;

translator pancakes_t < void *V > {
	i = 2 * 10;
	s = strjoin("I like ", "pancakes");
	t = *(timespec_t *)`dtrace_zero;
};

typedef struct stb {
	uint8_t v;
	uint8_t z;
} stb_t;

translator stb_t < void *V > {
	v = 0x8877665544332211;
};

typedef struct sth {
	uint16_t v;
	uint8_t z;
} sth_t;

translator sth_t < void *V > {
	v = 0x8877665544332211;
};

typedef struct stw {
	uint32_t v;
	uint8_t z;
} stw_t;

translator stw_t < void *V > {
	v = 0x8877665544332211;
};

typedef struct stx {
	uint64_t v;
	uint8_t z;
} stx_t;

translator stx_t < void *V > {
	v = 0x8877665544332211;
};

BEGIN
{
	print(*(xlate < pancakes_t * > ((void *)NULL)));
	printf("\n");
	print(*(xlate < stb_t * > ((void *)NULL)));
	printf("\n");
	print(*(xlate < sth_t * > ((void *)NULL)));
	printf("\n");
	print(*(xlate < stw_t * > ((void *)NULL)));
	printf("\n");
	print(*(xlate < stx_t * > ((void *)NULL)));
}

BEGIN
{
	exit(0);
}

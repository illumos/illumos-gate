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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This is designed to allow us to execute print() and various dereferencing
 * operations with bitfields. It reads the values from argc and passes them to
 * functions that we can then take apart. Crtitically this uses bitfields
 * constructed via CTF and not the D compiler.
 */

#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

typedef struct bit0 {
	uint32_t a:3;
	uint32_t b:2;
	uint32_t c:1;
	uint32_t d:1;
	uint32_t e:1;
	uint32_t f:1;
	uint32_t g:3;
	uint32_t h:3;
	uint32_t i:5;
	uint32_t j:4;
	uint32_t k:6;
	uint32_t l:1;
	uint32_t m:1;
} bit0_t;

typedef struct bit1 {
	uint16_t a:1;
	uint16_t b:8;
	uint16_t c:3;
	uint16_t d:2;
	uint16_t e:1;
	uint16_t f:1;
} bit1_t;

void
mumble(FILE *f, bit0_t *zero, bit1_t *one)
{
	(void) fprintf(f, "%u\n%u\n", zero->k, one->d);
}

int
main(int argc, char *argv[])
{
	unsigned long l;
	uint16_t u16;
	uint32_t u32;
	FILE *f;

	if (argc != 3) {
		errx(EXIT_FAILURE, "Need two ints");
	}

	f = fopen("/dev/null", "rw+");
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to open /dev/null");
	}

	errno = 0;
	l = strtoul(argv[1], NULL, 0);
	if (errno != 0 || l == 0 || l > UINT16_MAX) {
		errx(EXIT_FAILURE, "invalid u16 value: %s", argv[1]);
	}
	u16 = (uint16_t)l;

	l = strtoul(argv[2], NULL, 0);
	if (errno != 0 || l == 0 || l > UINT32_MAX) {
		errx(EXIT_FAILURE, "invalid u32 value: %s", argv[1]);
	}
	u32 = (uint32_t)l;
	mumble(f, (bit0_t *)&u32, (bit1_t *)&u16);

	return (0);
}

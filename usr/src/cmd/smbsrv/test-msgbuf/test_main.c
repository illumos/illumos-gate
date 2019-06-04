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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test & debug program for smb_msgbuf.c and smb_mbuf_marshaling.c
 */

#include <sys/types.h>
#include <sys/debug.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "test_defs.h"


int
main(int argc, char *argv[])
{

	test_conv();
	test_mbmarshal();
	test_msgbuf();

	return (0);
}

void
hexdump(const uchar_t *buf, int len)
{
	int idx;
	char ascii[24];
	char *pa = ascii;

	memset(ascii, '\0', sizeof (ascii));

	idx = 0;
	while (len--) {
		if ((idx & 15) == 0) {
			printf("%04X: ", idx);
			pa = ascii;
		}
		if (*buf > ' ' && *buf <= '~')
			*pa++ = *buf;
		else
			*pa++ = '.';
		printf("%02x ", *buf++);

		idx++;
		if ((idx & 3) == 0) {
			*pa++ = ' ';
			putchar(' ');
		}
		if ((idx & 15) == 0) {
			*pa = '\0';
			printf("%s\n", ascii);
		}
	}

	if ((idx & 15) != 0) {
		*pa = '\0';
		/* column align the last ascii row */
		while ((idx & 15) != 0) {
			if ((idx & 3) == 0)
				putchar(' ');
			printf("   ");
			idx++;
		}
		printf("%s\n", ascii);
	}
}

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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * memrchr(3C) implementation. Find the first occurence of 'c' as an unsigned
 * char in 's', by searching in reverse.
 */

#include <string.h>

void *
memrchr(const void *s, int c, size_t len)
{
	unsigned char val = (unsigned char)c;
	const unsigned char *data = s;

	for (; len > 0; len--) {
		size_t pos = len - 1;

		if (data[pos] == val) {
			return ((void *)&data[pos]);
		}
	}

	return (NULL);
}

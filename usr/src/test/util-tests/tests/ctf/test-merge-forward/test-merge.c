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
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <stdio.h>

struct foo;

typedef struct foo_list {
	int count;
	struct foo *head;
	struct foo *tail;
} foo_list_t;

foo_list_t list;

int
main(void)
{
	(void) printf("%p", &list);
}

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <libadm.h>

#define	ERR_MEMORY	"memory allocation failure, errno=%d"

/*
 * using factor of eight limits maximum
 * memory fragmentation to 12.5%
 */
#define	MEMSIZ	PATH_MAX*8

struct dup {
	char	mem[MEMSIZ];
	struct dup *next;
};

static struct dup *head, *tail, *new;

static int	size, initialized;
static void	pathinit();
static void	growstore();

/*
 * These functions allocate space for all the path names required
 * in the packaging code. They are all allocated here so as to reduce
 * memory fragmentation.
 */

/* Initialize storage area. */
static void
pathinit()
{
	if (head == NULL)
		size = (-1);
	else {
		/* free all memory used except initial structure */
		tail = head->next;
		while (tail) {
			new = tail->next;
			free(tail);
			tail = new;
		}
		tail = head;
		size = MEMSIZ;
	}

	initialized = 1;
}

/* Allocate additional space for storage area. */
static void
growstore()
{
	/* need more memory */
	new = calloc(1, sizeof (struct dup));
	if (new == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}
	if (head == NULL)
		head = new;
	else
		tail->next = new;
	tail = new;
	size = MEMSIZ;
}

/* Allocate and return a pointer. If n == 0, initialize. */
char *
pathalloc(int n)
{
	char	*pt;

	if (n <= 0) {
		pathinit();
		pt = NULL;
	} else {
		if (!initialized)
			pathinit();

		n++;	/* Account for terminating null. */

		if (size < n)
			growstore();

		pt = &tail->mem[MEMSIZ-size];
		size -= n;
	}

	return (pt);
}

/* Allocate and insert a pathname returning a pointer to the new string. */
char *
pathdup(char *s)
{
	char	*pt;
	int	n;

	if (s == NULL) {
		pathinit();
		pt = NULL;
	} else {
		if (!initialized)
			pathinit();

		n = strlen(s) + 1;	/* string + null terminator */

		if (size < n)
			growstore();

		pt = &tail->mem[MEMSIZ-size];
		size -= n;

		(void) strcpy(pt, s);
	}

	return (pt);
}

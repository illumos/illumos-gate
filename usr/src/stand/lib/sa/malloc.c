/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/salib.h>

/*
 * For documentation on these functions, see malloc(3C).
 */

void *
malloc(size_t size)
{
	size_t *iaddr;

	iaddr = (size_t *)bkmem_alloc(size + sizeof (size_t));
	if (iaddr == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	iaddr[0] = size;
	return (&iaddr[1]);
}

void *
calloc(size_t number, size_t size)
{
	void *addr;

	addr = malloc(number * size);
	if (addr == NULL)
		return (NULL);

	return (memset(addr, 0, number * size));
}

void *
realloc(void *oldaddr, size_t size)
{
	void *addr;
	size_t oldsize;

	addr = malloc(size);
	if (oldaddr != NULL) {
		oldsize = ((size_t *)oldaddr)[-1];
		if (addr != NULL) {
			bcopy(oldaddr, addr, (oldsize > size ? oldsize : size));
			free(oldaddr);
		}
	}

	return (addr);
}

void
free(void *addr)
{
	size_t *lenloc;

	if (addr == NULL)
		return;
	lenloc = (size_t *)addr - 1;
	bkmem_free((caddr_t)lenloc, *lenloc + sizeof (size_t));
}

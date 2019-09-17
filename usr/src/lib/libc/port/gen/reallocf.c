/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdlib.h>

void *
reallocf(void *ptr, size_t size)
{
	void *nptr = realloc(ptr, size);

	/* If size is zero, realloc will have already freed ptr. */
	if (nptr == NULL && size != 0)
		free(ptr);

	return (nptr);
}

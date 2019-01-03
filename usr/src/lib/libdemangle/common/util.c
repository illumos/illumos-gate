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
 * Copyright 2017 Jason King
 * Copyright 2019, Joyent, Inc.
 */

#include <sys/debug.h>
#include <stdlib.h>
#include <string.h>
#include "demangle-sys.h"
#include "demangle_int.h"

void *
zalloc(sysdem_ops_t *ops, size_t len)
{
	void *p = ops->alloc(len);

	if (p != NULL)
		(void) memset(p, 0, len);

#ifdef DEBUG
	/*
	 * In normal operation, we should never exhaust memory.  Either
	 * something's wrong, or the system is so hosed that aborting
	 * shouldn't hurt anything, and it gives us a more useful stack
	 * trace.
	 */
	if (p == NULL)
		abort();
#endif

	return (p);
}

void
xfree(sysdem_ops_t *ops, void *p, size_t len)
{
	if (p == NULL || len == 0)
		return;

	ops->free(p, len);
}

void *
xrealloc(sysdem_ops_t *ops, void *p, size_t oldsz, size_t newsz)
{
	if (newsz == oldsz)
		return (p);

	VERIFY3U(newsz, >, oldsz);

	void *temp = zalloc(ops, newsz);

	if (temp == NULL)
		return (NULL);

	if (oldsz > 0) {
		(void) memcpy(temp, p, oldsz);
		xfree(ops, p, oldsz);
	}

	return (temp);
}

char *
xstrdup(sysdem_ops_t *ops, const char *src)
{
	size_t len = strlen(src);
	char *str = zalloc(ops, len + 1);

	if (str == NULL)
		return (NULL);

	/* zalloc(len+1) guarantees this will be NUL-terminated */
	(void) memcpy(str, src, len);
	return (str);
}

/*ARGSUSED*/
static void
def_free(void *p, size_t len)
{
	free(p);
}

static sysdem_ops_t i_sysdem_ops_default = {
	.alloc = malloc,
	.free = def_free
};
sysdem_ops_t *sysdem_ops_default = &i_sysdem_ops_default;

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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <thread.h>
#include <pthread.h>
#include <ctype.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>
#include "smp_impl.h"

__thread smp_errno_t _smp_errno;
__thread char _smp_errmsg[LIBSMP_ERRMSGLEN];

int
smp_assert(const char *expr, const char *file, int line)
{
	char *msg;
	size_t len;

	len = snprintf(NULL, 0,
	    "ABORT: \"%s\", line %d: assertion failed: %s\n", file, line, expr);

	msg = alloca(len + 1);

	(void) snprintf(msg, len + 1,
	    "ABORT: \"%s\", line %d: assertion failed: %s\n", file, line, expr);

	(void) write(STDERR_FILENO, msg, strlen(msg));

	abort();
	/*NOTREACHED*/
}

int
smp_set_errno(smp_errno_t err)
{
	_smp_errno = err;
	_smp_errmsg[0] = '\0';

	return (-1);
}

/*
 * Internal routine for setting both _smp_errno and _smp_errmsg.  We save
 * and restore the UNIX errno across this routing so the caller can use either
 * smp_set_errno(), smp_error(), or smp_verror() without this value changing.
 */
int
smp_verror(smp_errno_t err, const char *fmt, va_list ap)
{
	size_t n;
	char *errmsg;

	/*
	 * To allow the existing error message to itself be used in an error
	 * message, we put the new error message into a buffer on the stack,
	 * and then copy it into lsh_errmsg.  We also need to set the errno,
	 * but because the call to smp_set_errno() is destructive to
	 * lsh_errmsg, we do this after we print into our temporary buffer
	 * (in case _smp_errmsg is part of the error message) and before we
	 * copy the temporary buffer on to _smp_errmsg (to prevent our new
	 * message from being nuked by the call to smp_set_errno()).
	 */
	errmsg = alloca(sizeof (_smp_errmsg));
	(void) vsnprintf(errmsg, sizeof (_smp_errmsg), fmt, ap);
	(void) smp_set_errno(err);

	n = strlen(errmsg);

	if (n != 0 && errmsg[n - 1] == '\n')
		errmsg[n - 1] = '\0';

	bcopy(errmsg, _smp_errmsg, n + 1);

	return (-1);
}

int
smp_error(smp_errno_t err, const char *fmt, ...)
{
	va_list ap;

	if (fmt == NULL)
		return (smp_set_errno(err));

	va_start(ap, fmt);
	err = smp_verror(err, fmt, ap);
	va_end(ap);

	return (err);
}

smp_errno_t
smp_errno(void)
{
	return (_smp_errno);
}

const char *
smp_errmsg(void)
{
	if (_smp_errmsg[0] == '\0')
		(void) strlcpy(_smp_errmsg, smp_strerror(_smp_errno),
		    sizeof (_smp_errmsg));

	return (_smp_errmsg);
}

/*ARGSUSED*/
void *
smp_alloc(size_t size)
{
	void *mem;

	if (size == 0) {
		(void) smp_set_errno(ESMP_ZERO_LENGTH);
		return (NULL);
	}

	if ((mem = malloc(size)) == NULL)
		(void) smp_set_errno(ESMP_NOMEM);

	return (mem);
}

void *
smp_zalloc(size_t size)
{
	void *mem;

	if ((mem = smp_alloc(size)) == NULL)
		return (NULL);

	bzero(mem, size);

	return (mem);
}

char *
smp_strdup(const char *str)
{
	size_t len = strlen(str);
	char *dup = smp_alloc(len + 1);

	if (dup == NULL)
		return (NULL);

	return (strcpy(dup, str));
}

void
smp_free(void *ptr)
{
	free(ptr);
}

/*
 * Trim any leading and/or trailing spaces from the fixed-length string
 * argument and return a newly-allocated copy of it.
 */
char *
smp_trim_strdup(const char *str, size_t len)
{
	const char *p;
	char *r;

	for (p = str; p - str < len && isspace(*p); p++)
		;

	len -= (p - str);

	if (len == 0)
		return (NULL);

	for (str = p + len - 1; str > p && isspace(*str); str--, len--)
		;

	if (len == 0)
		return (NULL);

	r = smp_alloc(len + 1);
	if (r == NULL)
		return (NULL);

	bcopy(p, r, len);
	r[len] = '\0';

	return (r);
}

int
smp_init(int version)
{
	if (version != LIBSMP_VERSION)
		return (smp_error(ESMP_VERSION,
		    "library version %d does not match requested version %d",
		    LIBSMP_VERSION, version));

	smp_engine_init();

	return (0);
}

void
smp_fini(void)
{
	smp_engine_fini();
}

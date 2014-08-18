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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <pthread.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zerror.h"

static const char *PREFIX = "%s ZDOOR:%s:T(%d): ";

static const char *DEBUG_ENV_VAR = "ZDOOR_TRACE";

static boolean_t
is_debug_enabled()
{
	boolean_t enabled = B_FALSE;
	const char *_envp = getenv(DEBUG_ENV_VAR);
	if (_envp != NULL && atoi(_envp) >= 2)
		enabled = B_TRUE;

	return (enabled);
}

static boolean_t
is_info_enabled()
{
	boolean_t enabled = B_FALSE;
	const char *_envp = getenv(DEBUG_ENV_VAR);
	if (_envp != NULL && atoi(_envp) >= 1)
		enabled = B_TRUE;

	return (enabled);
}

void
zdoor_debug(const char *fmt, ...)
{
	va_list alist;

	if (!is_debug_enabled())
		return;

	va_start(alist, fmt);

	(void) fprintf(stderr, PREFIX, __TIME__, "DEBUG", pthread_self());
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

void
zdoor_info(const char *fmt, ...)
{
	va_list alist;

	if (!is_info_enabled())
		return;

	va_start(alist, fmt);

	(void) fprintf(stderr, PREFIX, __TIME__, "INFO", pthread_self());
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

void
zdoor_warn(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);

	(void) fprintf(stderr, PREFIX, __TIME__, "WARN", pthread_self());
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

void
zdoor_error(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);

	(void) fprintf(stderr, PREFIX, __TIME__, "ERROR", pthread_self());
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

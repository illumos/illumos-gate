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
 *
 * Copyright 2018 Jason King.
 * Copyright 2018, Joyent, Inc.
 */

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <demangle-sys.h>

#include "dis_util.h"

int g_error;	/* global process exit status, set when warn() is called */

/*
 * Fatal error.  Print out the error with a leading "dis: ", and then exit the
 * program.
 */
void
die(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "dis: fatal: ");

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "\n");

	exit(1);
}

/*
 * Non-fatal error.  Print out the error with a leading "dis: ", set the global
 * error flag, and return.
 */
void
warn(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "dis: warning: ");

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "\n");

	g_error = 1;
}

/*
 * Convenience wrapper around malloc() to cleanly exit if any allocation fails.
 */
void *
safe_malloc(size_t size)
{
	void *ret;

	if ((ret = calloc(1, size)) == NULL)
		die("Out of memory");

	return (ret);
}


/*
 * Since the -C flag explicitly says C++, for now at least, force language to
 * C++
 */
const char *
dis_demangle(const char *name)
{
	static char *demangled_name = NULL;

	/*
	 * Since demangled_name is static, it may be preserved across
	 * invocations.  As such, make sure any memory that might be present
	 * from previous invocations is freed.
	 */
	free(demangled_name);
	demangled_name = sysdemangle(name, SYSDEM_LANG_AUTO, NULL);
	return ((demangled_name != NULL) ? demangled_name : name);
}

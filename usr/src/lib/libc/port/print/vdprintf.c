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
 * Copyright 2025 Hans Rosenfeld
 */

#include <stdarg.h>
#include <sys/types.h>
#include "print.h"

int
vdprintf(int fildes, const char *format, va_list ap)
{
	FILE *file;
	int count;
	int ret;

	file = fdopen(fildes, "w");
	if (file == NULL)
		return (EOF);

	/*
	 * Make the FILE unbuffered, avoiding all kinds of headaches associated
	 * with buffering and recovering from potential late failure of delayed
	 * writes.
	 */
	(void) setvbuf(file, NULL, _IONBF, 0);

	/*
	 * As this FILE is temporary and exists only for the runtime of this
	 * function, there should be no need for locking.
	 */
	SET_IONOLOCK(file);

	count = vfprintf(file, format, ap);

	(void) fdclose(file, NULL);

	return (count);
}

int
dprintf(int fildes, const char *format, ...)
{
	int count;
	va_list ap;

	va_start(ap, format);
	count = vdprintf(fildes, format, ap);
	va_end(ap);

	return (count);
}

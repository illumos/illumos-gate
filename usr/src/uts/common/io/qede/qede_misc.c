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
 * Copyright (c) 2017, Joyent, Inc. 
 */

/*
 * Misc. support routines
 */

#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * We need to emulate sprintf. Unfortunately illumos sprintf does not return the
 * number of bytes written, only a pointer to the string. Therefore we need this
 * wrapper.
 */
size_t
qede_sprintf(char *s, const char *fmt, ...)
{
	size_t r;
	va_list args;

	va_start(args, fmt);
	r = vsnprintf(s, SIZE_MAX, fmt, args);
	va_end(args);

	return (r);
}

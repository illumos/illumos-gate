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
 * Copyright 2015, Joyent, Inc.
 */

/*
 * No, 'tis not so deep as a well, nor so wide as a church door; but 'tis
 * enough, 'twill serve. Ask for me tomorrow, and you shall find me a grave man.
 *
 * This file maintains various routines for handling when we die.
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <thread.h>
#include <stdlib.h>

/*
 * Normally these would be static, but if they're static, that throws off lint
 * because it thinks we never use them, which is kind of the point, because we
 * only read them in the core...
 */
int varpd_panic_errno;
char varpd_panic_buf[1024];
thread_t varpd_panic_thread;

void
libvarpd_panic(const char *fmt, ...)
{
	va_list ap;

	/* Always save errno first! */
	varpd_panic_errno = errno;
	varpd_panic_thread = thr_self();

	if (fmt != NULL) {
		va_start(ap, fmt);
		(void) vsnprintf(varpd_panic_buf, sizeof (varpd_panic_buf), fmt,
		    ap);
	}
	abort();
}

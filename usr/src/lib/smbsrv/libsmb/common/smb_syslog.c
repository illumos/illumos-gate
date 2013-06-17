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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <smbsrv/libsmb.h>

/*
 * This is exported NODIRECT so that smbd can provide it's own.
 */
void
smb_vsyslog(int pri, const char *fmt, va_list ap)
{
	vsyslog(pri, fmt, ap);
}

/*
 * This is exported NODIRECT so that fksmbd can provide it's own.
 */
void
smb_syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	smb_vsyslog(pri, fmt, ap);
	va_end(ap);
}

/*
 * Helper for smb_vsyslog().  Does %m substitutions.
 */
char *
smb_syslog_fmt_m(char *buf, int buflen, const char *str, int err)
{
	char		*bp = buf;
	const char	*sp = str;
	const char	*endp = buf + buflen - 1;

	while ((*bp = *sp) != '\0' && bp != endp) {
		if ((*sp++ == '%') && (*sp == 'm')) {
			sp++;
			if (strerror_r(err, bp, endp - bp) == 0)
				bp += strlen(bp);
		} else {
			bp++;
		}
	}
	*bp = '\0';

	return (buf);
}

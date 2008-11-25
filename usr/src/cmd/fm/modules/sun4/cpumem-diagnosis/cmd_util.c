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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <cmd.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

int
cmd_set_errno(int err)
{
	errno = err;
	return (-1);
}

void *
cmd_buf_read(fmd_hdl_t *hdl, fmd_case_t *cp, const char *bufname, size_t bufsz)
{
	void *buf;
	size_t sz;

	if ((sz = fmd_buf_size(hdl, cp, bufname)) == 0) {
		(void) cmd_set_errno(ENOENT);
		return (NULL);
	} else if (sz != bufsz) {
		(void) cmd_set_errno(EINVAL);
		return (NULL);
	}

	buf = fmd_hdl_alloc(hdl, bufsz, FMD_SLEEP);
	fmd_buf_read(hdl, cp, bufname, buf, bufsz);

	return (buf);
}

void
cmd_vbufname(char *buf, size_t bufsz, const char *fmt, va_list ap)
{
	char *c;

	(void) vsnprintf(buf, bufsz, fmt, ap);

	for (c = buf; *c != '\0'; c++) {
		if (*c == ' ' || *c == '/' || *c == ':')
			*c = '_';
	}
}

void
cmd_bufname(char *buf, size_t bufsz, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cmd_vbufname(buf, bufsz, fmt, ap);
	va_end(ap);
}

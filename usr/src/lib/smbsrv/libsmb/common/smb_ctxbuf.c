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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Buffer manipulation routines. These routines can be used to format
 * data within a data buffer without worrying about overrunning the
 * buffer.
 *
 * A ctxbuf_t structure is used to track the current location within
 * the buffer. The ctxbuf_init() must be called first to initialize the
 * context structure. ctxbuf_printf() can then be called to fill the buffer.
 * ctxbuf_printf will discard any data that would overrun the buffer and
 * the buffer will always be null terminated.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <smbsrv/libsmb.h>

/*
 * smb_ctxbuf_init
 *
 * Initialize the buffer context structure.
 * This must be called before any of the other
 * buffer routines can be used.
 *
 * Returns -1 if invalid parameters, 0 otherwise
 */
int
smb_ctxbuf_init(smb_ctxbuf_t *ctx, unsigned char *buf, size_t buflen)
{
	if (ctx == 0 || buf == 0 || buflen == 0)
		return (-1);

	buf[0] = '\0';

	ctx->basep = buf;
	ctx->curp = buf;
	ctx->endp = &buf[buflen];

	return (0);
}

/*
 * smb_ctxbuf_len
 *
 * Return the amount of data stored in the buffer,
 * excluding the terminating null character. Similar
 * to strlen()
 *
 * Returns 0 if the ctx is invalid.
 */
int
smb_ctxbuf_len(smb_ctxbuf_t *ctx)
{
	if (ctx == 0 || ctx->basep == 0 ||
	    ctx->curp == 0 || ctx->endp == 0)
		return (0);
	else
		/*LINTED E_PTRDIFF_OVERFLOW*/
		return (ctx->curp - ctx->basep);
}

/*
 * smb_ctxbuf_printf
 *
 * Move formatted output (based on fmt string) to the buffer
 * identified in ctxbuf.  Any output characters beyond the buffer
 * are discarded and a null character is written at the end of the
 * characters actually written.
 *
 * Returns
 * Always return the number of bytes actually written (excluding the
 * terminating null).
 */
int
smb_ctxbuf_printf(smb_ctxbuf_t   *ctx, const char *fmt, ...)
{
	int n;
	va_list args;

	if (ctx == 0 || ctx->basep == 0 ||
	    ctx->curp == 0 || ctx->endp == 0)
		return (-1);

	va_start(args, fmt);
	/*LINTED E_PTRDIFF_OVERFLOW*/
	n = vsnprintf((char *)ctx->curp, ctx->endp-ctx->curp, fmt, args);
	ctx->curp += n;
	va_end(args);

	/*
	 * return the number of bytes moved into the buffer.
	 */
	return (n);
}

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>

#include "praudit.h"


/*
 * pr_adr_char - pull out characters
 */
int
pr_adr_char(pr_context_t *context, char *cp, int count)
{
	int	err;
	adr_t	*adr = context->audit_adr;
	adrf_t	*adrf = context->audit_adrf;

	if (context->data_mode == FILEMODE) {
		err = adrf_char(adrf, cp, count);
		if (err) {
			errno = EIO;
			return (-1);
		} else
			return (0);
	}

	/* adrm routines don't return error, so check before calling */
	if (!pr_input_remaining(context, (sizeof (char) * count))) {
		errno = EIO;
		return (-1);
	}

	adrm_char(adr, cp, count);
	return (0);
}

/*
 * pr_adr_short - pull out shorts
 */
int
pr_adr_short(pr_context_t *context, short *sp, int count)
{
	int	err;
	adr_t	*adr = context->audit_adr;
	adrf_t	*adrf = context->audit_adrf;

	if (context->data_mode == FILEMODE) {
		err = adrf_short(adrf, sp, count);
		if (err) {
			errno = EIO;
			return (-1);
		} else
			return (0);
	}

	/* adrm routines don't return error, so check before calling */
	if (!pr_input_remaining(context, (sizeof (short) * count))) {
		errno = EIO;
		return (-1);
	}

	adrm_short(adr, sp, count);
	return (0);
}

/*
 * pr_adr_int32 - pull out int32
 */
int
pr_adr_int32(pr_context_t *context, int32_t *lp, int count)
{
	int	err;
	adr_t	*adr = context->audit_adr;
	adrf_t	*adrf = context->audit_adrf;

	if (context->data_mode == FILEMODE) {
		err = adrf_int32(adrf, lp, count);
		if (err) {
			errno = EIO;
			return (-1);
		} else
			return (0);
	}

	/* adrm routines don't return error, so check before calling */
	if (!pr_input_remaining(context, (sizeof (int32_t) * count))) {
		errno = EIO;
		return (-1);
	}

	adrm_int32(adr, lp, count);
	return (0);
}

int
pr_adr_int64(pr_context_t *context, int64_t *lp, int count)
{
	int	err;
	adr_t	*adr = context->audit_adr;
	adrf_t	*adrf = context->audit_adrf;

	if (context->data_mode == FILEMODE) {
		err = adrf_int64(adrf, lp, count);
		if (err) {
			errno = EIO;
			return (-1);
		} else
			return (0);
	}

	/* adrm routines don't return error, so check before calling */
	if (!pr_input_remaining(context, (sizeof (int64_t) * count))) {
		errno = EIO;
		return (-1);
	}

	adrm_int64(adr, lp, count);
	return (0);
}

int
pr_adr_u_int32(pr_context_t *context, uint32_t *cp, int count)
{
	return (pr_adr_int32(context, (int32_t *)cp, count));
}

int
pr_adr_u_char(pr_context_t *context, uchar_t *cp, int count)
{
	return (pr_adr_char(context, (char *)cp, count));
}

int
pr_adr_u_int64(pr_context_t *context, uint64_t *lp, int count)
{
	return (pr_adr_int64(context, (int64_t *)lp, count));
}

int
pr_adr_u_short(pr_context_t *context, ushort_t *sp, int count)
{
	return (pr_adr_short(context, (short *)sp, count));
}

int
pr_putchar(pr_context_t *context, char c)
{
	if (context->data_mode == FILEMODE) {
		(void) putchar(c);
		return (0);
	}
	/* Buffer-based output processing otherwise... */

	/* Need at least room for char + null-byte */
	if (context->outbuf_remain_len < 2) {
		/* no space left */
		errno = ENOSPC;
		return (-1);
	}

	*(context->outbuf_p) = c;
	context->outbuf_p += 1;
	context->outbuf_remain_len -= 1;

	return (0);
}

int
pr_printf(pr_context_t *context, const char *fmt, ...)
{
	int addlen;
	va_list ap;

	va_start(ap, fmt);

	if (context->data_mode == FILEMODE) {
		(void) vprintf(fmt, ap);
		va_end(ap);
		return (0);
	}
	/* Buffer-based output processing otherwise... */

	if (context->outbuf_remain_len < 2) {
		/* no space at all left */
		va_end(ap);
		errno = ENOSPC;
		return (-1);
	}

	/* Attempt to tack on this string */
	addlen = vsnprintf(context->outbuf_p, context->outbuf_remain_len - 1,
	    fmt, ap);
	va_end(ap);
	if (addlen < 0) {
		/* output error */
		errno = EPERM;
		return (-1);
	}
	if (addlen >= context->outbuf_remain_len - 1) {
		/* not enough space; bail out */
		errno = ENOSPC;
		return (-1);
	}

	/*
	 * vsnprintf was successful; update pointers and counters
	 * as needed. If no bytes were written, treat it as a no-op
	 * and don't need to update anything.
	 */
	if (addlen >= 1) {
		context->outbuf_remain_len -= addlen;
		context->outbuf_p += addlen;
	}

	return (0);
}


/*
 * pr_input_remaining - Check whether size bytes (or more) are remaining in
 * the inbuf.
 * returns	1 - there are enough bytes remaining
 *		0 - not enough bytes left
 */
int
pr_input_remaining(pr_context_t *context, size_t size)
{
	adr_t	*adr = context->audit_adr;

	/* no-op if not doing buf mode */
	if (context->data_mode != BUFMODE)
		return (1);

	if ((adr_count(adr) + size) > context->inbuf_totalsize)
		return (0);
	else
		return (1);
}

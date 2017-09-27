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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/types.h>

/* ARGSUSED */
static bool_t
x_putint32_t(XDR *xdrs, int32_t *ip)
{
	xdrs->x_handy += BYTES_PER_XDR_UNIT;
	return (TRUE);
}

/* ARGSUSED */
static bool_t
x_putbytes(XDR *xdrs, char *bp, int len)
{
	xdrs->x_handy += len;
	return (TRUE);
}

static uint_t
x_getpostn(XDR *xdrs)
{
	return (xdrs->x_handy);
}

/* ARGSUSED */
static bool_t
x_setpostn(XDR *xdrs, uint_t pos)
{
	/* This is not allowed */
	return (FALSE);
}

static rpc_inline_t *
x_inline(XDR *xdrs, int len)
{
	if (len == 0) {
		return (NULL);
	}
	if (xdrs->x_op != XDR_ENCODE) {
		return (NULL);
	}
	if (len < (uintptr_t)xdrs->x_base) {
		/* x_private was already allocated */
		xdrs->x_handy += len;
		return ((rpc_inline_t *)xdrs->x_private);
	} else {
		/* Free the earlier space and allocate new area */
		if (xdrs->x_private)
			mem_free(xdrs->x_private, (uintptr_t)xdrs->x_base);
		if ((xdrs->x_private = (caddr_t)mem_alloc(len)) == NULL) {
			xdrs->x_base = 0;
			return (NULL);
		}
		xdrs->x_base = (caddr_t)(uintptr_t)len;
		xdrs->x_handy += len;
		return ((rpc_inline_t *)xdrs->x_private);
	}
}

static int
harmless()
{
	/* Always return FALSE/NULL, as the case may be */
	return (0);
}

static void
x_destroy(XDR *xdrs)
{
	xdrs->x_handy = 0;
	if (xdrs->x_private) {
		mem_free(xdrs->x_private, (uintptr_t)xdrs->x_base);
		xdrs->x_private = NULL;
	}
	xdrs->x_base = 0;
}

unsigned int
xdr_sizeof(xdrproc_t func, void *data)
{
	XDR x;
	struct xdr_ops ops;
	bool_t stat;
	/* to stop ANSI-C compiler from complaining */
	typedef  bool_t (* dummyfunc1)(XDR *, caddr_t, int);
	typedef	 bool_t (* dummyfunc2)(XDR *, int, void *);
#if defined(_LP64) || defined(_KERNEL)
	typedef  bool_t (* dummyfunc3)(XDR *, int32_t *);
#endif

	ops.x_putbytes = x_putbytes;
	ops.x_inline = x_inline;
	ops.x_getpostn = x_getpostn;
	ops.x_setpostn = x_setpostn;
	ops.x_destroy = x_destroy;

#if defined(_LP64) || defined(_KERNEL)
	ops.x_getint32 = (dummyfunc3)harmless;
	ops.x_putint32 = x_putint32_t;
#endif

	/* the other harmless ones */
	ops.x_getbytes = (dummyfunc1)harmless;
	ops.x_control = (dummyfunc2)harmless;

	x.x_op = XDR_ENCODE;
	x.x_ops = &ops;
	x.x_handy = 0;
	x.x_private = (caddr_t)NULL;
	x.x_base = NULL;

	stat = func(&x, data);
	if (x.x_private)
		mem_free(x.x_private, (uintptr_t)x.x_base);
	return (stat == TRUE ? (unsigned int)x.x_handy: 0);
}

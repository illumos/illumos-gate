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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/types.h>
#include <rpc/auth.h>
#include <rpc/rpc_rdma.h>

static struct xdr_ops *xdrrdma_xops(void);

struct private {
	int	min_chunk;
	uint_t	flags;			/* controls setting for rdma xdr */
	int	num_chunk;
	caddr_t	inline_buf;		/* temporary buffer for xdr inlining */
	int	inline_len;		/* inline buffer length */
};

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
	struct private *xdrp = (struct private *)xdrs->x_private;

	/*
	 * min_chunk = 0, means that the stream of bytes, to estimate size of,
	 * contains no chunks to seperate out. See xdrrdma_putbytes()
	 */
	if (len < xdrp->min_chunk || (xdrp->flags & RDMA_NOCHUNK)) {
		xdrs->x_handy += len;
		return (TRUE);
	}
	/*
	 * Chunk item. No impact on xdr size.
	 */
	xdrp->num_chunk++;
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

/* ARGSUSED */
static bool_t
x_control(XDR *xdrs, int request, void *info)
{
	int32_t *int32p;
	uint_t in_flags;
	struct private *xdrp = (struct private *)xdrs->x_private;

	switch (request) {
	case XDR_RDMASET:
		/*
		 * Set the flags provided in the *info in xp_flags for rdma xdr
		 * stream control.
		 */
		int32p = (int32_t *)info;
		in_flags = (uint_t)(*int32p);

		xdrp->flags = in_flags;
		return (TRUE);

	case XDR_RDMAGET:
		/*
		 * Get the flags provided in xp_flags return through *info
		 */
		int32p = (int32_t *)info;

		*int32p = (int32_t)xdrp->flags;
		return (TRUE);

	default:
		return (FALSE);
	}
}

/* ARGSUSED */
static rpc_inline_t *
x_inline(XDR *xdrs, int len)
{
	struct private *xdrp = (struct private *)xdrs->x_private;

	if (len == 0) {
		return (NULL);
	}
	if (xdrs->x_op != XDR_ENCODE) {
		return (NULL);
	}
	if (len >= xdrp->min_chunk) {
		return (NULL);
	}
	if (len <= xdrp->inline_len) {
		/* inline_buf was already allocated, just reuse it */
		xdrs->x_handy += len;
		return ((rpc_inline_t *)xdrp->inline_buf);
	} else {
		/* Free the earlier space and allocate new area */
		if (xdrp->inline_buf)
			mem_free(xdrp->inline_buf, xdrp->inline_len);
		if ((xdrp->inline_buf = (caddr_t)mem_alloc(len)) == NULL) {
			xdrp->inline_len = 0;
			return (NULL);
		}
		xdrp->inline_len = len;
		xdrs->x_handy += len;
		return ((rpc_inline_t *)xdrp->inline_buf);
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
	struct private *xdrp = (struct private *)xdrs->x_private;

	xdrs->x_handy = 0;
	if (xdrp) {
		if (xdrp->inline_buf)
			mem_free(xdrp->inline_buf, xdrp->inline_len);
		mem_free(xdrp, sizeof (struct private));
		xdrs->x_private = NULL;
	}
	xdrs->x_base = 0;
}

static bool_t
xdrrdma_common(XDR *xdrs, int min_chunk)
{
	struct private *xdrp;

	xdrs->x_ops = xdrrdma_xops();
	xdrs->x_op = XDR_ENCODE;
	xdrs->x_handy = 0;
	xdrs->x_base = NULL;
	xdrs->x_private = kmem_zalloc(sizeof (struct private), KM_SLEEP);
	xdrp = (struct private *)xdrs->x_private;
	xdrp->min_chunk = min_chunk;
	xdrp->flags = 0;
	if (xdrp->min_chunk == 0)
		xdrp->flags |= RDMA_NOCHUNK;

	return (TRUE);
}

unsigned int
xdrrdma_sizeof(xdrproc_t func, void *data, int min_chunk)
{
	XDR x;
	struct xdr_ops ops;
	bool_t stat;
	struct private *xdrp;

	x.x_ops = &ops;
	(void) xdrrdma_common(&x, min_chunk);

	stat = func(&x, data);
	xdrp = (struct private *)x.x_private;
	if (xdrp) {
		if (xdrp->inline_buf)
			mem_free(xdrp->inline_buf, xdrp->inline_len);
		mem_free(xdrp, sizeof (struct private));
	}
	return (stat == TRUE ? (unsigned int)x.x_handy: 0);
}

unsigned int
xdrrdma_authsize(AUTH *auth, struct cred *cred, int min_chunk)
{
	XDR x;
	struct xdr_ops ops;
	bool_t stat;
	struct private *xdrp;

	x.x_ops = &ops;
	(void) xdrrdma_common(&x, min_chunk);

	stat = AUTH_MARSHALL(auth, &x, cred);
	xdrp = (struct private *)x.x_private;
	if (xdrp) {
		if (xdrp->inline_buf)
			mem_free(xdrp->inline_buf, xdrp->inline_len);
		mem_free(xdrp, sizeof (struct private));
	}
	return (stat == TRUE ? (unsigned int)x.x_handy: 0);
}

static struct xdr_ops *
xdrrdma_xops(void)
{
	static struct xdr_ops ops;

	/* to stop ANSI-C compiler from complaining */
	typedef  bool_t (* dummyfunc1)(XDR *, long *);
	typedef  bool_t (* dummyfunc2)(XDR *, caddr_t, int);
	typedef  bool_t (* dummyfunc3)(XDR *, int32_t *);

	ops.x_putbytes = x_putbytes;
	ops.x_inline = x_inline;
	ops.x_getpostn = x_getpostn;
	ops.x_setpostn = x_setpostn;
	ops.x_destroy = x_destroy;
	ops.x_control = x_control;

#if defined(_LP64) || defined(_KERNEL)
	ops.x_getint32 = (dummyfunc3)harmless;
	ops.x_putint32 = x_putint32_t;
#endif

	/* the other harmless ones */
	ops.x_getbytes = (dummyfunc2)harmless;

	return (&ops);
}

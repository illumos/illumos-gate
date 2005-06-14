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
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xdr_mem.h, XDR implementation using memory buffers.
 *
 * If you have some data to be interpreted as external data representation
 * or to be converted to external data representation in a memory buffer,
 * then this is the package for you.
 *
 */

#ifdef KERNEL
#include <sys/param.h>
#endif

#include "mt.h"
#include "rpc_mt.h"
#include <sys/types.h>
#include <rpc/trace.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <memory.h>
#include <inttypes.h>

static struct xdr_ops *xdrmem_ops(void);

/*
 * Meaning of the private areas of the xdr struct for xdr_mem
 * 	x_base : Base from where the xdr stream starts
 * 	x_private : The current position of the stream.
 * 	x_handy : The size of the stream buffer.
 */

/*
 * The procedure xdrmem_create initializes a stream descriptor for a
 * memory buffer.
 */
void
xdrmem_create(XDR *xdrs, caddr_t addr, uint_t size, enum xdr_op op)
{
	caddr_t eaddr = addr;

	trace2(TR_xdrmem_create, 0, size);
	xdrs->x_op = op;
	xdrs->x_ops = xdrmem_ops();
	xdrs->x_private = xdrs->x_base = 0;
	/*
	 * We check here that the size is with in the range of the
	 * address space. If not we set x_handy to zero. This will cause
	 * all xdrmem entry points to fail.
	 */
	eaddr = addr + size;

	if (eaddr < addr)
		xdrs->x_handy = 0;
	else {
		xdrs->x_handy = size;
		xdrs->x_private = xdrs->x_base = addr;
	}
	trace2(TR_xdrmem_create, 1, size);
}

static void
xdrmem_destroy(XDR *xdrs)
{
	trace1(TR_xdrmem_destroy, 0);
	trace1(TR_xdrmem_destroy, 1);
}

static bool_t
xdrmem_getlong(XDR *xdrs, long *lp)
{
	trace1(TR_xdrmem_getlong, 0);
	if (sizeof (int32_t) > (uint32_t)xdrs->x_handy) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_getlong, 1);
		return (FALSE);
	}
	xdrs->x_handy -= sizeof (int32_t);
	*lp = (int32_t)ntohl((uint32_t)(*((int32_t *)(xdrs->x_private))));
	xdrs->x_private += sizeof (int32_t);
	trace1(TR_xdrmem_getlong, 1);
	return (TRUE);
}

static bool_t
xdrmem_putlong(XDR *xdrs, long *lp)
{
	trace1(TR_xdrmem_putlong, 0);
#if defined(_LP64)
	if ((*lp > INT32_MAX) || (*lp < INT32_MIN)) {
		return (FALSE);
	}
#endif

	if ((sizeof (int32_t) > (uint32_t)xdrs->x_handy)) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_putlong, 1);
		return (FALSE);
	}
	xdrs->x_handy -= sizeof (int32_t);
	*(int32_t *)xdrs->x_private = (int32_t)htonl((uint32_t)(*lp));
	xdrs->x_private += sizeof (int32_t);
	trace1(TR_xdrmem_putlong, 1);
	return (TRUE);
}

#if defined(_LP64)

static bool_t
xdrmem_getint32(XDR *xdrs, int32_t *ip)
{
	trace1(TR_xdrmem_getint32, 0);
	if (sizeof (int32_t) > (uint_t)xdrs->x_handy) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_putlong, 1);
		return (FALSE);
	}
	xdrs->x_handy -= sizeof (int32_t);
	*ip = (int32_t)ntohl((uint32_t)(*((int32_t *)(xdrs->x_private))));
	xdrs->x_private += sizeof (int32_t);
	trace1(TR_xdrmem_getint32, 1);
	return (TRUE);
}

static bool_t
xdrmem_putint32(XDR *xdrs, int32_t *ip)
{
	trace1(TR_xdrmem_putint32, 0);
	if (sizeof (int32_t) > (uint32_t)xdrs->x_handy) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_putlong, 1);
		return (FALSE);
	}
	xdrs->x_handy -= sizeof (int32_t);
	*(int32_t *)xdrs->x_private = (int32_t)htonl((uint32_t)(*ip));
	xdrs->x_private += sizeof (int32_t);
	trace1(TR_xdrmem_putint32, 1);
	return (TRUE);
}

#endif /* _LP64 */

static bool_t
xdrmem_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	trace2(TR_xdrmem_getbytes, 0, len);
	if ((uint32_t)len > (uint32_t)xdrs->x_handy) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_getbytes, 1);
		return (FALSE);
	}
	xdrs->x_handy -= len;
	(void) memcpy(addr, xdrs->x_private, (uint_t)len);
	xdrs->x_private += (uint_t)len;
	trace1(TR_xdrmem_getbytes, 1);
	return (TRUE);
}

static bool_t
xdrmem_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	trace2(TR_xdrmem_putbytes, 0, len);
	if ((uint32_t)len > (uint32_t)xdrs->x_handy) {
		xdrs->x_private += (uint_t)xdrs->x_handy;
		xdrs->x_handy = 0;
		trace1(TR_xdrmem_putbytes, 1);
		return (FALSE);
	}
	xdrs->x_handy -= len;
	(void) memcpy(xdrs->x_private, addr, (uint_t)len);
	xdrs->x_private += (uint_t)len;
	trace1(TR_xdrmem_putbytes, 1);
	return (TRUE);
}

static uint_t
xdrmem_getpos(xdrs)
	XDR *xdrs;
{
	trace1(TR_xdrmem_getpos, 0);
	trace1(TR_xdrmem_getpos, 1);
	return (uint_t)((uintptr_t)xdrs->x_private - (uintptr_t)xdrs->x_base);
}

static bool_t
xdrmem_setpos(xdrs, pos)
	XDR *xdrs;
	uint_t pos;
{
	caddr_t newaddr = xdrs->x_base + pos;
	caddr_t lastaddr = xdrs->x_private + (uint_t)xdrs->x_handy;

	trace2(TR_xdrmem_setpos, 0, pos);
	if ((long)newaddr > (long)lastaddr) {
		trace1(TR_xdrmem_setpos, 1);
		return (FALSE);
	}
	xdrs->x_private = newaddr;
	xdrs->x_handy = (int)((uintptr_t)lastaddr - (uintptr_t)newaddr);
	trace1(TR_xdrmem_setpos, 1);
	return (TRUE);
}

static rpc_inline_t *
xdrmem_inline(XDR *xdrs, int len)
{
	rpc_inline_t *buf = 0;

	trace2(TR_xdrmem_inline, 0, len);
	if ((uint32_t)xdrs->x_handy >= (uint32_t)len) {
		xdrs->x_handy -= len;
		buf = (rpc_inline_t *)xdrs->x_private;
		xdrs->x_private += (uint_t)len;
	}
	trace2(TR_xdrmem_inline, 1, len);
	return (buf);
}

static bool_t
xdrmem_control(XDR *xdrs, int request, void *info)
{
	xdr_bytesrec *xptr;

	switch (request) {

	case XDR_GET_BYTES_AVAIL:
		xptr = (xdr_bytesrec *) info;
		xptr->xc_is_last_record = TRUE;
		xptr->xc_num_avail = xdrs->x_handy;
		return (TRUE);
	default:
		return (FALSE);

	}

}

static struct xdr_ops *
xdrmem_ops()
{
	static struct xdr_ops ops;
	extern mutex_t	ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */


	trace1(TR_xdrmem_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.x_getlong == NULL) {
		ops.x_getlong = xdrmem_getlong;
		ops.x_putlong = xdrmem_putlong;
		ops.x_getbytes = xdrmem_getbytes;
		ops.x_putbytes = xdrmem_putbytes;
		ops.x_getpostn = xdrmem_getpos;
		ops.x_setpostn = xdrmem_setpos;
		ops.x_inline = xdrmem_inline;
		ops.x_destroy = xdrmem_destroy;
		ops.x_control = xdrmem_control;
#if defined(_LP64)
		ops.x_getint32 = xdrmem_getint32;
		ops.x_putint32 = xdrmem_putint32;
#endif
	}
	mutex_unlock(&ops_lock);
	trace1(TR_xdrmem_ops, 1);
	return (&ops);
}

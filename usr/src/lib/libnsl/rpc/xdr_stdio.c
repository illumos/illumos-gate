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
 * xdr_stdio.c, XDR implementation on standard i/o file.
 *
 * This set of routines implements a XDR on a stdio stream.
 * XDR_ENCODE serializes onto the stream, XDR_DECODE de-serializes
 * from the stream.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/types.h>
#include <stdio.h>
#include <rpc/xdr.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <inttypes.h>

static struct xdr_ops *xdrstdio_ops(void);

/*
 * Initialize a stdio xdr stream.
 * Sets the xdr stream handle xdrs for use on the stream file.
 * Operation flag is set to op.
 */
void
xdrstdio_create(XDR *xdrs, FILE *file, enum xdr_op op)
{
	trace1(TR_xdrstdio_create, 0);
	xdrs->x_op = op;
	xdrs->x_ops = xdrstdio_ops();
	xdrs->x_private = (caddr_t)file;
	xdrs->x_handy = 0;
	xdrs->x_base = 0;
	trace1(TR_xdrstdio_create, 1);
}

/*
 * Destroy a stdio xdr stream.
 * Cleans up the xdr stream handle xdrs previously set up by xdrstdio_create.
 */
static void
xdrstdio_destroy(XDR *xdrs)
{
	trace1(TR_xdrstdio_destroy, 0);
	(void) fflush((FILE *)xdrs->x_private);
	/* xx should we close the file ?? */
	trace1(TR_xdrstdio_destroy, 1);
}


static bool_t
xdrstdio_getint32(XDR *xdrs, int32_t *lp)
{
	trace1(TR_xdrstdio_getint32, 0);
	if (fread((caddr_t)lp, sizeof (int32_t), 1,
			(FILE *)xdrs->x_private) != 1) {
		trace1(TR_xdrstdio_getint32, 1);
		return (FALSE);
	}
	*lp = ntohl(*lp);
	trace1(TR_xdrstdio_getint32, 1);
	return (TRUE);
}

static bool_t
xdrstdio_putint32(XDR *xdrs, int32_t *lp)
{

	int32_t mycopy = htonl(*lp);
	lp = &mycopy;

	trace1(TR_xdrstdio_putint32, 0);
	if (fwrite((caddr_t)lp, sizeof (int32_t), 1,
			(FILE *)xdrs->x_private) != 1) {
		trace1(TR_xdrstdio_putint32, 1);
		return (FALSE);
	}
	trace1(TR_xdrstdio_putint32, 1);
	return (TRUE);
}

static bool_t
xdrstdio_getlong(xdrs, lp)
	XDR *xdrs;
	long *lp;
{
	int32_t i;

	if (!xdrstdio_getint32(xdrs, &i))
		return (FALSE);

	*lp = (long)i;

	return (TRUE);
}

static bool_t
xdrstdio_putlong(xdrs, lp)
	XDR *xdrs;
	long *lp;
{
	int32_t i;

#if defined(_LP64)
	if ((*lp > INT32_MAX) || (*lp < INT32_MIN)) {
		return (FALSE);
	}
#endif

	i = (int32_t)*lp;

	return (xdrstdio_putint32(xdrs, &i));
}

static bool_t
xdrstdio_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	trace2(TR_xdrstdio_getbytes, 0, len);
	if ((len != 0) &&
		(fread(addr, (int)len, 1, (FILE *)xdrs->x_private) != 1)) {
		trace1(TR_xdrstdio_getbytes, 1);
		return (FALSE);
	}
	trace1(TR_xdrstdio_getbytes, 1);
	return (TRUE);
}

static bool_t
xdrstdio_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	trace2(TR_xdrstdio_putbytes, 0, len);
	if ((len != 0) &&
		(fwrite(addr, (int)len, 1, (FILE *)xdrs->x_private) != 1)) {
		trace1(TR_xdrstdio_putbytes, 1);
		return (FALSE);
	}
	trace1(TR_xdrstdio_putbytes, 1);
	return (TRUE);
}

static uint_t
xdrstdio_getpos(XDR *xdrs)
{
	uint_t dummy1;

	trace1(TR_xdrstdio_getpos, 0);
	dummy1 = (uint_t)ftell((FILE *)xdrs->x_private);
	trace1(TR_xdrstdio_getpos, 1);
	return (dummy1);
}

static bool_t
xdrstdio_setpos(XDR *xdrs, uint_t pos)
{
	bool_t dummy2;

	trace2(TR_xdrstdio_setpos, 0, pos);
	dummy2 = (fseek((FILE *)xdrs->x_private,
			(int)pos, 0) < 0) ? FALSE : TRUE;
	trace1(TR_xdrstdio_setpos, 1);
	return (dummy2);
}

static rpc_inline_t *
xdrstdio_inline(XDR *xdrs, int len)
{

	/*
	 * Must do some work to implement this: must insure
	 * enough data in the underlying stdio buffer,
	 * that the buffer is aligned so that we can indirect through a
	 * long *, and stuff this pointer in xdrs->x_buf.  Doing
	 * a fread or fwrite to a scratch buffer would defeat
	 * most of the gains to be had here and require storage
	 * management on this buffer, so we don't do this.
	 */
	trace2(TR_xdrstdio_inline, 0, len);
	trace2(TR_xdrstdio_inline, 1, len);
	return (NULL);
}

static bool_t
xdrstdio_control(XDR *xdrs, int request, void *info)
{
	switch (request) {

	default:
		return (FALSE);
	}
}

static struct xdr_ops *
xdrstdio_ops()
{
	static struct xdr_ops ops;
	extern mutex_t	ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_xdrstdio_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.x_getlong == NULL) {
		ops.x_getlong = xdrstdio_getlong;
		ops.x_putlong = xdrstdio_putlong;
		ops.x_getbytes = xdrstdio_getbytes;
		ops.x_putbytes = xdrstdio_putbytes;
		ops.x_getpostn = xdrstdio_getpos;
		ops.x_setpostn = xdrstdio_setpos;
		ops.x_inline = xdrstdio_inline;
		ops.x_destroy = xdrstdio_destroy;
		ops.x_control = xdrstdio_control;
#if defined(_LP64)
		ops.x_getint32 = xdrstdio_getint32;
		ops.x_putint32 = xdrstdio_putint32;
#endif
	}
	mutex_unlock(&ops_lock);
	trace1(TR_xdrstdio_ops, 1);
	return (&ops);
}

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

/*
 * xdr_rdma.c, XDR implementation using RDMA to move large chunks
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kmem.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/cmn_err.h>
#include <rpc/rpc_sztypes.h>
#include <rpc/rpc_rdma.h>

static struct xdr_ops *xdrrdma_ops(void);

/*
 * A chunk list entry identifies a chunk
 * of opaque data to be moved separately
 * from the rest of the RPC message.
 * xp_min_chunk = 0, is a special case for ENCODING, which means
 * do not chunk the incoming stream of data.
 */

struct private {
	caddr_t		xp_offp;
	int		xp_min_chunk;
	uint_t		xp_flags;	/* Controls setting for rdma xdr */
	int		xp_buf_size;		/* size of xdr buffer */
	struct clist	*xp_cl;			/* head of chunk list */
	struct clist	**xp_cl_next;	/* location to place/find next chunk */
	CONN		*xp_conn;	/* connection for chunk data xfer */
};


/*
 * The procedure xdrrdma_create initializes a stream descriptor for a
 * memory buffer.
 */
void
xdrrdma_create(XDR *xdrs, caddr_t addr, uint_t size,
	int min_chunk, struct clist *cl, enum xdr_op op, CONN *conn)
{
	struct private *xdrp;
	struct clist *cle;

	xdrs->x_op = op;
	xdrs->x_ops = xdrrdma_ops();
	xdrs->x_base = addr;
	xdrs->x_handy = size;
	xdrs->x_public = NULL;

	xdrp = (struct private *)kmem_zalloc(sizeof (struct private), KM_SLEEP);
	xdrs->x_private = (caddr_t)xdrp;
	xdrp->xp_offp = addr;
	xdrp->xp_min_chunk = min_chunk;
	xdrp->xp_flags = 0;
	xdrp->xp_buf_size = size;
	xdrp->xp_cl = cl;
	if (op == XDR_ENCODE && cl != NULL) {
		/* Find last element in chunk list and set xp_cl_next */
		for (cle = cl; cle->c_next != NULL; cle = cle->c_next);
		xdrp->xp_cl_next = &(cle->c_next);
	} else
		xdrp->xp_cl_next = &(xdrp->xp_cl);
	xdrp->xp_conn = conn;
	if (xdrp->xp_min_chunk == 0)
		xdrp->xp_flags |= RDMA_NOCHUNK;
}

/* ARGSUSED */
void
xdrrdma_destroy(XDR *xdrs)
{
	(void) kmem_free(xdrs->x_private, sizeof (struct private));
}

struct clist *
xdrrdma_clist(XDR *xdrs) {
	return (((struct private *)(xdrs->x_private))->xp_cl);
}

static bool_t
xdrrdma_getint32(XDR *xdrs, int32_t *int32p)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);

	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);

	/* LINTED pointer alignment */
	*int32p = (int32_t)ntohl((uint32_t)(*((int32_t *)(xdrp->xp_offp))));
	xdrp->xp_offp += sizeof (int32_t);

	return (TRUE);
}

static bool_t
xdrrdma_putint32(XDR *xdrs, int32_t *int32p)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);

	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);

	/* LINTED pointer alignment */
	*(int32_t *)xdrp->xp_offp = (int32_t)htonl((uint32_t)(*int32p));
	xdrp->xp_offp += sizeof (int32_t);

	return (TRUE);
}

/*
 * DECODE some bytes from an XDR stream
 */
static bool_t
xdrrdma_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);
	struct clist *cle = *(xdrp->xp_cl_next);
	struct clist cl;
	bool_t  retval = TRUE;

	/*
	 * If there was a chunk at the current offset
	 * first record the destination address and length
	 * in the chunk list that came with the message, then
	 * RDMA READ the chunk data.
	 */
	if (cle != NULL &&
		cle->c_xdroff == (xdrp->xp_offp - xdrs->x_base)) {
		cle->c_daddr = (uint64)(uintptr_t)addr;
		cle->c_len  = len;
		xdrp->xp_cl_next = &cle->c_next;

		/*
		 * RDMA READ the chunk data from the remote end.
		 * First prep the destination buffer by registering
		 * it, then RDMA READ the chunk data. Since we are
		 * doing streaming memory, sync the destination buffer
		 * to CPU and deregister the buffer.
		 */
		if (xdrp->xp_conn == NULL) {
			return (FALSE);
		}

		cl = *cle;
		cl.c_next = NULL;
		if (clist_register(xdrp->xp_conn, &cl, 0) != RDMA_SUCCESS) {
			return (FALSE);
		}

		/*
		 * Now read the chunk in
		 */
		if (RDMA_READ(xdrp->xp_conn, &cl, WAIT) != RDMA_SUCCESS) {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"xdrrdma_getbytes: RDMA_READ failed\n");
#endif
			retval = FALSE;
			goto out;
		}
		/*
		 * sync the memory for cpu
		 */
		if (clist_syncmem(xdrp->xp_conn, &cl, 0) != RDMA_SUCCESS) {
			retval = FALSE;
			goto out;
		}

out:
		/*
		 * Deregister the chunks
		 */
		(void) clist_deregister(xdrp->xp_conn, &cl, 0);
		return (retval);
	}

	if ((xdrs->x_handy -= len) < 0)
		return (FALSE);

	bcopy(xdrp->xp_offp, addr, len);
	xdrp->xp_offp += len;

	return (TRUE);
}

/*
 * ENCODE some bytes into an XDR stream
 * xp_min_chunk = 0, means the stream of bytes contain no chunks
 * to seperate out, and if the bytes do not fit in the supplied
 * buffer, grow the buffer and free the old buffer.
 */
static bool_t
xdrrdma_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);
	struct clist *clzero = xdrp->xp_cl;

	/*
	 * If this chunk meets the minimum chunk size
	 * then don't encode it.  Just record its address
	 * and length in a chunk list entry so that it
	 * can be moved separately via RDMA.
	 */
	if (!(xdrp->xp_flags & RDMA_NOCHUNK) && xdrp->xp_min_chunk != 0 &&
	    len >= xdrp->xp_min_chunk) {
		struct clist *cle;
		int offset = xdrp->xp_offp - xdrs->x_base;

		cle = (struct clist *)kmem_zalloc(sizeof (struct clist),
				KM_SLEEP);
		cle->c_xdroff = offset;
		cle->c_len  = len;
		cle->c_saddr = (uint64)(uintptr_t)addr;
		cle->c_next = NULL;

		*(xdrp->xp_cl_next) = cle;
		xdrp->xp_cl_next = &(cle->c_next);

		return (TRUE);
	}

	if ((xdrs->x_handy -= len) < 0) {
		if (xdrp->xp_min_chunk == 0) {
			int  newbuflen, encodelen;
			caddr_t newbuf;

			xdrs->x_handy += len;
			encodelen = xdrp->xp_offp - xdrs->x_base;
			newbuflen = xdrp->xp_buf_size + len;
			newbuf = kmem_zalloc(newbuflen, KM_SLEEP);
			bcopy(xdrs->x_base, newbuf, encodelen);
			(void) kmem_free(xdrs->x_base, xdrp->xp_buf_size);
			xdrs->x_base = newbuf;
			xdrp->xp_offp = newbuf + encodelen;
			xdrp->xp_buf_size = newbuflen;
			if (xdrp->xp_min_chunk == 0 && clzero->c_xdroff == 0) {
				clzero->c_len = newbuflen;
				clzero->c_saddr = (uint64)(uintptr_t)newbuf;
			}
		} else
			return (FALSE);
	}

	bcopy(addr, xdrp->xp_offp, len);
	xdrp->xp_offp += len;

	return (TRUE);
}

uint_t
xdrrdma_getpos(XDR *xdrs)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);

	return ((uint_t)((uintptr_t)xdrp->xp_offp - (uintptr_t)xdrs->x_base));
}

bool_t
xdrrdma_setpos(XDR *xdrs, uint_t pos)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);

	caddr_t newaddr = xdrs->x_base + pos;
	caddr_t lastaddr = xdrp->xp_offp + xdrs->x_handy;
	ptrdiff_t diff;

	if (newaddr > lastaddr)
		return (FALSE);

	xdrp->xp_offp = newaddr;
	diff = lastaddr - newaddr;
	xdrs->x_handy = (int)diff;

	return (TRUE);
}

/* ARGSUSED */
static rpc_inline_t *
xdrrdma_inline(XDR *xdrs, int len)
{
	rpc_inline_t *buf = NULL;
	struct private *xdrp = (struct private *)(xdrs->x_private);
	struct clist *cle = *(xdrp->xp_cl_next);

	if (xdrs->x_op == XDR_DECODE) {
		/*
		 * Since chunks aren't in-line, check to see whether
		 * there is a chunk in the inline range.
		 */
		if (cle != NULL &&
			cle->c_xdroff <= (xdrp->xp_offp - xdrs->x_base + len))
		return (NULL);
	}

	if ((xdrs->x_handy < len) || (xdrp->xp_min_chunk != 0 &&
	    len >= xdrp->xp_min_chunk)) {
		return (NULL);
	} else {
		xdrs->x_handy -= len;
		/* LINTED pointer alignment */
		buf = (rpc_inline_t *)xdrp->xp_offp;
		xdrp->xp_offp += len;
		return (buf);
	}
}

static bool_t
xdrrdma_control(XDR *xdrs, int request, void *info)
{
	int32_t *int32p;
	int len;
	uint_t in_flags;
	struct private *xdrp = (struct private *)(xdrs->x_private);

	switch (request) {
	case XDR_PEEK:
		/*
		 * Return the next 4 byte unit in the XDR stream.
		 */
		if (xdrs->x_handy < sizeof (int32_t))
			return (FALSE);

		int32p = (int32_t *)info;
		*int32p = (int32_t)ntohl((uint32_t)
		    (*((int32_t *)(xdrp->xp_offp))));

		return (TRUE);

	case XDR_SKIPBYTES:
		/*
		 * Skip the next N bytes in the XDR stream.
		 */
		int32p = (int32_t *)info;
		len = RNDUP((int)(*int32p));
		if ((xdrs->x_handy -= len) < 0)
			return (FALSE);
		xdrp->xp_offp += len;

		return (TRUE);

	case XDR_RDMASET:
		/*
		 * Set the flags provided in the *info in xp_flags for rdma xdr
		 * stream control.
		 */
		int32p = (int32_t *)info;
		in_flags = (uint_t)(*int32p);

		xdrp->xp_flags |= in_flags;
		return (TRUE);

	case XDR_RDMAGET:
		/*
		 * Get the flags provided in xp_flags return through *info
		 */
		int32p = (int32_t *)info;

		*int32p = (int32_t)xdrp->xp_flags;
		return (TRUE);

	default:
		return (FALSE);
	}
}

static struct xdr_ops *
xdrrdma_ops(void)
{
	static struct xdr_ops ops;

	if (ops.x_getint32 == NULL) {
		ops.x_getbytes = xdrrdma_getbytes;
		ops.x_putbytes = xdrrdma_putbytes;
		ops.x_getpostn = xdrrdma_getpos;
		ops.x_setpostn = xdrrdma_setpos;
		ops.x_inline = xdrrdma_inline;
		ops.x_destroy = xdrrdma_destroy;
		ops.x_control = xdrrdma_control;
		ops.x_getint32 = xdrrdma_getint32;
		ops.x_putint32 = xdrrdma_putint32;
	}
	return (&ops);
}

/*
 * Not all fields in struct clist are interesting to the
 * RPC over RDMA protocol. Only XDR the interesting fields.
 */
bool_t
xdr_clist(XDR *xdrs, clist *objp)
{

	if (!xdr_uint32(xdrs, &objp->c_xdroff))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->c_len))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->c_smemhandle.mrc_rmr))
		return (FALSE);
	if (!xdr_uint64(xdrs, &objp->c_saddr))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->c_next, sizeof (clist),
		(xdrproc_t)xdr_clist))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_do_clist(XDR *xdrs, clist **clp)
{
	return (xdr_pointer(xdrs, (char **)clp,
		sizeof (clist), (xdrproc_t)xdr_clist));
}

uint_t
xdr_getbufsize(XDR *xdrs)
{
	struct private *xdrp = (struct private *)(xdrs->x_private);

	return ((uint_t)xdrp->xp_buf_size);
}

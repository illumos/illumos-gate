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

/*
 * Copyright (c) 2007, The Ohio State University. All rights reserved.
 *
 * Portions of this source code is developed by the team members of
 * The Ohio State University's Network-Based Computing Laboratory (NBCL),
 * headed by Professor Dhabaleswar K. (DK) Panda.
 *
 * Acknowledgements to contributions from developors:
 *   Ranjit Noronha: noronha@cse.ohio-state.edu
 *   Lei Chai      : chail@cse.ohio-state.edu
 *   Weikuan Yu    : yuw@cse.ohio-state.edu
 *
 */

/*
 * xdr_rdma.c, XDR implementation using RDMA to move large chunks
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/debug.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/cmn_err.h>
#include <rpc/rpc_sztypes.h>
#include <rpc/rpc_rdma.h>
#include <sys/sysmacros.h>

static bool_t   xdrrdma_getint32(XDR *, int32_t *);
static bool_t   xdrrdma_putint32(XDR *, int32_t *);
static bool_t   xdrrdma_getbytes(XDR *, caddr_t, int);
static bool_t   xdrrdma_putbytes(XDR *, caddr_t, int);
uint_t		xdrrdma_getpos(XDR *);
bool_t		xdrrdma_setpos(XDR *, uint_t);
static rpc_inline_t *xdrrdma_inline(XDR *, int);
void		xdrrdma_destroy(XDR *);
static bool_t   xdrrdma_control(XDR *, int, void *);

struct xdr_ops  xdrrdmablk_ops = {
	xdrrdma_getbytes,
	xdrrdma_putbytes,
	xdrrdma_getpos,
	xdrrdma_setpos,
	xdrrdma_inline,
	xdrrdma_destroy,
	xdrrdma_control,
	xdrrdma_getint32,
	xdrrdma_putint32
};

struct xdr_ops  xdrrdma_ops = {
	xdrrdma_getbytes,
	xdrrdma_putbytes,
	xdrrdma_getpos,
	xdrrdma_setpos,
	xdrrdma_inline,
	xdrrdma_destroy,
	xdrrdma_control,
	xdrrdma_getint32,
	xdrrdma_putint32
};

/*
 * A chunk list entry identifies a chunk of opaque data to be moved
 * separately from the rest of the RPC message. xp_min_chunk = 0, is a
 * special case for ENCODING, which means do not chunk the incoming stream of
 * data.
 */

typedef struct {
	caddr_t		xp_offp;
	int		xp_min_chunk;
	uint_t		xp_flags;	/* Controls setting for rdma xdr */
	int		xp_buf_size;	/* size of xdr buffer */
	struct clist	*xp_rcl;		/* head of chunk list */
	struct clist	**xp_rcl_next;	/* location to place/find next chunk */
	struct clist	*xp_wcl;	/* head of write chunk list */
	CONN		*xp_conn;	/* connection for chunk data xfer */
	uint_t		xp_reply_chunk_len;
	/* used to track length for security modes: integrity/privacy */
	uint_t		xp_reply_chunk_len_alt;
} xrdma_private_t;

extern kmem_cache_t *clist_cache;

bool_t
xdrrdma_getrdmablk(XDR *xdrs, struct clist **rlist, uint_t *sizep,
    CONN **conn, const uint_t maxsize)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	struct clist	*cle = *(xdrp->xp_rcl_next);
	struct clist	*cls = *(xdrp->xp_rcl_next);
	struct clist	*rdclist = NULL, *prev = NULL;
	bool_t		retval = TRUE;
	uint32_t	cur_offset = 0;
	uint32_t	total_segments = 0;
	uint32_t	actual_segments = 0;
	uint32_t	alen;
	uint_t		total_len;

	ASSERT(xdrs->x_op != XDR_FREE);

	/*
	 * first deal with the length since xdr bytes are counted
	 */
	if (!xdr_u_int(xdrs, sizep)) {
		DTRACE_PROBE(xdr__e__getrdmablk_sizep_fail);
		return (FALSE);
	}
	total_len = *sizep;
	if (total_len > maxsize) {
		DTRACE_PROBE2(xdr__e__getrdmablk_bad_size,
		    int, total_len, int, maxsize);
		return (FALSE);
	}
	(*conn) = xdrp->xp_conn;

	/*
	 * if no data we are done
	 */
	if (total_len == 0)
		return (TRUE);

	while (cle) {
		total_segments++;
		cle = cle->c_next;
	}

	cle = *(xdrp->xp_rcl_next);

	/*
	 * If there was a chunk at the current offset, then setup a read
	 * chunk list which records the destination address and length
	 * and will RDMA READ the data in later.
	 */
	if (cle == NULL)
		return (FALSE);

	if (cle->c_xdroff != (xdrp->xp_offp - xdrs->x_base))
		return (FALSE);

	/*
	 * Setup the chunk list with appropriate
	 * address (offset) and length
	 */
	for (actual_segments = 0;
	    actual_segments < total_segments; actual_segments++) {
		if (total_len <= 0)
			break;
		cle->u.c_daddr = (uint64) cur_offset;
		alen = 0;
		if (cle->c_len > total_len) {
			alen = cle->c_len;
			cle->c_len = total_len;
		}
		if (!alen)
			xdrp->xp_rcl_next = &cle->c_next;

		cur_offset += cle->c_len;
		total_len -= cle->c_len;

		if ((total_segments - actual_segments - 1) == 0 &&
		    total_len > 0) {
			DTRACE_PROBE(krpc__e__xdrrdma_getblk_chunktooshort);
			retval = FALSE;
		}

		if ((total_segments - actual_segments - 1) > 0 &&
		    total_len == 0) {
			DTRACE_PROBE2(krpc__e__xdrrdma_getblk_toobig,
			    int, total_segments, int, actual_segments);
		}

		rdclist = clist_alloc();
		(*rdclist) = (*cle);
		if ((*rlist) == NULL)
			(*rlist) = rdclist;
		if (prev == NULL)
			prev = rdclist;
		else {
			prev->c_next = rdclist;
			prev = rdclist;
		}

		cle = cle->c_next;
	}

out:
	if (prev != NULL)
		prev->c_next = NULL;

	cle = cls;
	if (alen) {
		cle->w.c_saddr =
		    (uint64)(uintptr_t)cle->w.c_saddr + cle->c_len;
		cle->c_len = alen - cle->c_len;
	}

	return (retval);
}

/*
 * The procedure xdrrdma_create initializes a stream descriptor for a memory
 * buffer.
 */
void
xdrrdma_create(XDR *xdrs, caddr_t addr, uint_t size,
    int min_chunk, struct clist *cl, enum xdr_op op, CONN *conn)
{
	xrdma_private_t *xdrp;
	struct clist   *cle;

	xdrs->x_op = op;
	xdrs->x_ops = &xdrrdma_ops;
	xdrs->x_base = addr;
	xdrs->x_handy = size;
	xdrs->x_public = NULL;

	xdrp = (xrdma_private_t *)kmem_zalloc(sizeof (xrdma_private_t),
	    KM_SLEEP);
	xdrs->x_private = (caddr_t)xdrp;
	xdrp->xp_offp = addr;
	xdrp->xp_min_chunk = min_chunk;
	xdrp->xp_flags = 0;
	xdrp->xp_buf_size = size;
	xdrp->xp_rcl = cl;
	xdrp->xp_reply_chunk_len = 0;
	xdrp->xp_reply_chunk_len_alt = 0;

	if (op == XDR_ENCODE && cl != NULL) {
		/* Find last element in chunk list and set xp_rcl_next */
		for (cle = cl; cle->c_next != NULL; cle = cle->c_next)
			continue;

		xdrp->xp_rcl_next = &(cle->c_next);
	} else {
		xdrp->xp_rcl_next = &(xdrp->xp_rcl);
	}

	xdrp->xp_wcl = NULL;

	xdrp->xp_conn = conn;
	if (xdrp->xp_min_chunk != 0)
		xdrp->xp_flags |= XDR_RDMA_CHUNK;
}

/* ARGSUSED */
void
xdrrdma_destroy(XDR * xdrs)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);

	if (xdrp == NULL)
		return;

	if (xdrp->xp_wcl) {
		if (xdrp->xp_flags & XDR_RDMA_WLIST_REG) {
			(void) clist_deregister(xdrp->xp_conn,
			    xdrp->xp_wcl, CLIST_REG_DST);
			rdma_buf_free(xdrp->xp_conn,
			    &xdrp->xp_wcl->rb_longbuf);
		}
		clist_free(xdrp->xp_wcl);
	}

	if (xdrp->xp_rcl) {
		if (xdrp->xp_flags & XDR_RDMA_RLIST_REG) {
			(void) clist_deregister(xdrp->xp_conn,
			    xdrp->xp_rcl, CLIST_REG_SOURCE);
			rdma_buf_free(xdrp->xp_conn,
			    &xdrp->xp_rcl->rb_longbuf);
		}
		clist_free(xdrp->xp_rcl);
	}

	(void) kmem_free(xdrs->x_private, sizeof (xrdma_private_t));
	xdrs->x_private = NULL;
}

static	bool_t
xdrrdma_getint32(XDR *xdrs, int32_t *int32p)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);

	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);

	/* LINTED pointer alignment */
	*int32p = (int32_t)ntohl((uint32_t)(*((int32_t *)(xdrp->xp_offp))));
	xdrp->xp_offp += sizeof (int32_t);

	return (TRUE);
}

static	bool_t
xdrrdma_putint32(XDR *xdrs, int32_t *int32p)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);

	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0)
		return (FALSE);

	/* LINTED pointer alignment */
	*(int32_t *)xdrp->xp_offp = (int32_t)htonl((uint32_t)(*int32p));
	xdrp->xp_offp += sizeof (int32_t);

	return (TRUE);
}

/*
 * DECODE bytes from XDR stream for rdma.
 * If the XDR stream contains a read chunk list,
 * it will go through xdrrdma_getrdmablk instead.
 */
static	bool_t
xdrrdma_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	struct clist	*cle = *(xdrp->xp_rcl_next);
	struct clist	*cls = *(xdrp->xp_rcl_next);
	struct clist	cl;
	bool_t		retval = TRUE;
	uint32_t	total_len = len;
	uint32_t	cur_offset = 0;
	uint32_t	total_segments = 0;
	uint32_t	actual_segments = 0;
	uint32_t	status;
	uint32_t	alen;

	while (cle) {
		total_segments++;
		cle = cle->c_next;
	}

	cle = *(xdrp->xp_rcl_next);
	/*
	 * If there was a chunk at the current offset, then setup a read
	 * chunk list which records the destination address and length
	 * and will RDMA READ the data in later.
	 */

	if (cle != NULL &&
	    cle->c_xdroff == (xdrp->xp_offp - xdrs->x_base)) {
		for (actual_segments = 0;
		    actual_segments < total_segments; actual_segments++) {
			if (total_len <= 0)
				break;
			cle->u.c_daddr = (uint64)(uintptr_t)addr + cur_offset;
			alen = 0;
			if (cle->c_len > total_len) {
				alen = cle->c_len;
				cle->c_len = total_len;
			}
			if (!alen)
				xdrp->xp_rcl_next = &cle->c_next;

			cur_offset += cle->c_len;
			total_len -= cle->c_len;

			if ((total_segments - actual_segments - 1) == 0 &&
			    total_len > 0) {
				DTRACE_PROBE(
				    krpc__e__xdrrdma_getbytes_chunktooshort);
				retval = FALSE;
			}

			if ((total_segments - actual_segments - 1) > 0 &&
			    total_len == 0) {
				DTRACE_PROBE2(krpc__e__xdrrdma_getbytes_toobig,
				    int, total_segments, int, actual_segments);
			}

			/*
			 * RDMA READ the chunk data from the remote end.
			 * First prep the destination buffer by registering
			 * it, then RDMA READ the chunk data. Since we are
			 * doing streaming memory, sync the destination
			 * buffer to CPU and deregister the buffer.
			 */
			if (xdrp->xp_conn == NULL) {
				return (FALSE);
			}
			cl = *cle;
			cl.c_next = NULL;
			if (clist_register(xdrp->xp_conn, &cl, CLIST_REG_DST)
			    != RDMA_SUCCESS) {
				return (FALSE);
			}
			cle->c_dmemhandle = cl.c_dmemhandle;
			cle->c_dsynchandle = cl.c_dsynchandle;

			/*
			 * Now read the chunk in
			 */
			if ((total_segments - actual_segments - 1) == 0 ||
			    total_len == 0) {
				status = RDMA_READ(xdrp->xp_conn, &cl, WAIT);
			} else {
				status = RDMA_READ(xdrp->xp_conn, &cl, NOWAIT);
			}
			if (status != RDMA_SUCCESS) {
				DTRACE_PROBE1(
				    krpc__i__xdrrdma_getblk_readfailed,
				    int, status);
				retval = FALSE;
				goto out;
			}
			cle = cle->c_next;
		}

		/*
		 * sync the memory for cpu
		 */
		cl = *cls;
		cl.c_next = NULL;
		cl.c_len = cur_offset;
		if (clist_syncmem(xdrp->xp_conn, &cl, 0) != RDMA_SUCCESS) {
			retval = FALSE;
		}
out:
		/*
		 * Deregister the chunks
		 */
		cle = cls;
		cl = *cle;
		cl.c_next = NULL;
		cl.c_len = cur_offset;
		(void) clist_deregister(xdrp->xp_conn, &cl, CLIST_REG_DST);
		if (alen) {
			cle->w.c_saddr =
			    (uint64)(uintptr_t)cle->w.c_saddr + cle->c_len;
			cle->c_len = alen - cle->c_len;
		}
		return (retval);
	}
	if ((xdrs->x_handy -= len) < 0)
		return (FALSE);

	bcopy(xdrp->xp_offp, addr, len);
	xdrp->xp_offp += len;

	return (TRUE);
}

/*
 * ENCODE some bytes into an XDR stream xp_min_chunk = 0, means the stream of
 * bytes contain no chunks to seperate out, and if the bytes do not fit in
 * the supplied buffer, grow the buffer and free the old buffer.
 */
static	bool_t
xdrrdma_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	/*
	 * Is this stream accepting chunks?
	 * If so, does the either of the two following conditions exist?
	 * - length of bytes to encode is greater than the min chunk size?
	 * - remaining space in this stream is shorter than length of
	 *   bytes to encode?
	 *
	 * If the above exists, then create a chunk for this encoding
	 * and save the addresses, etc.
	 */
	if (xdrp->xp_flags & XDR_RDMA_CHUNK &&
	    ((xdrp->xp_min_chunk != 0 &&
	    len >= xdrp->xp_min_chunk) ||
	    (xdrs->x_handy - len  < 0))) {
		struct clist	*cle;
		int		offset = xdrp->xp_offp - xdrs->x_base;

		cle = clist_alloc();
		cle->c_xdroff = offset;
		cle->c_len = len;
		cle->w.c_saddr = (uint64)(uintptr_t)addr;
		cle->c_next = NULL;

		*(xdrp->xp_rcl_next) = cle;
		xdrp->xp_rcl_next = &(cle->c_next);

		return (TRUE);
	}
	/* Is there enough space to encode what is left? */
	if ((xdrs->x_handy -= len) < 0) {
		return (FALSE);
	}
	bcopy(addr, xdrp->xp_offp, len);
	xdrp->xp_offp += len;

	return (TRUE);
}

uint_t
xdrrdma_getpos(XDR *xdrs)
{
	xrdma_private_t *xdrp = (xrdma_private_t *)(xdrs->x_private);

	return ((uint_t)((uintptr_t)xdrp->xp_offp - (uintptr_t)xdrs->x_base));
}

bool_t
xdrrdma_setpos(XDR *xdrs, uint_t pos)
{
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);

	caddr_t		newaddr = xdrs->x_base + pos;
	caddr_t		lastaddr = xdrp->xp_offp + xdrs->x_handy;
	ptrdiff_t	diff;

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
	rpc_inline_t	*buf = NULL;
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	struct clist	*cle = *(xdrp->xp_rcl_next);

	if (xdrs->x_op == XDR_DECODE) {
		/*
		 * Since chunks aren't in-line, check to see whether there is
		 * a chunk in the inline range.
		 */
		if (cle != NULL &&
		    cle->c_xdroff <= (xdrp->xp_offp - xdrs->x_base + len))
			return (NULL);
	}

	/* LINTED pointer alignment */
	buf = (rpc_inline_t *)xdrp->xp_offp;
	if (!IS_P2ALIGNED(buf, sizeof (int32_t)))
		return (NULL);

	if ((xdrs->x_handy < len) || (xdrp->xp_min_chunk != 0 &&
	    len >= xdrp->xp_min_chunk)) {
		return (NULL);
	} else {
		xdrs->x_handy -= len;
		xdrp->xp_offp += len;
		return (buf);
	}
}

static	bool_t
xdrrdma_control(XDR *xdrs, int request, void *info)
{
	int32_t		*int32p;
	int		len, i;
	uint_t		in_flags;
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	rdma_chunkinfo_t *rcip = NULL;
	rdma_wlist_conn_info_t *rwcip = NULL;
	rdma_chunkinfo_lengths_t *rcilp = NULL;
	struct uio *uiop;
	struct clist	*rwl = NULL;
	struct clist	*prev = NULL;

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

	case XDR_RDMA_SET_FLAGS:
		/*
		 * Set the flags provided in the *info in xp_flags for rdma
		 * xdr stream control.
		 */
		int32p = (int32_t *)info;
		in_flags = (uint_t)(*int32p);

		xdrp->xp_flags |= in_flags;
		return (TRUE);

	case XDR_RDMA_GET_FLAGS:
		/*
		 * Get the flags provided in xp_flags return through *info
		 */
		int32p = (int32_t *)info;

		*int32p = (int32_t)xdrp->xp_flags;
		return (TRUE);

	case XDR_RDMA_GET_CHUNK_LEN:
		rcilp = (rdma_chunkinfo_lengths_t *)info;
		rcilp->rcil_len = xdrp->xp_reply_chunk_len;
		rcilp->rcil_len_alt = xdrp->xp_reply_chunk_len_alt;

		return (TRUE);

	case XDR_RDMA_ADD_CHUNK:
		/*
		 * Store wlist information
		 */

		rcip = (rdma_chunkinfo_t *)info;

		switch (rcip->rci_type) {
		case RCI_WRITE_UIO_CHUNK:
			xdrp->xp_reply_chunk_len_alt += rcip->rci_len;

			if (rcip->rci_len < xdrp->xp_min_chunk) {
				xdrp->xp_wcl = NULL;
				*(rcip->rci_clpp) = NULL;
				return (TRUE);
			}
			uiop = rcip->rci_a.rci_uiop;

			for (i = 0; i < uiop->uio_iovcnt; i++) {
				rwl = clist_alloc();
				rwl->c_len = uiop->uio_iov[i].iov_len;
				rwl->u.c_daddr =
				    (uint64)(uintptr_t)
				    (uiop->uio_iov[i].iov_base);
				/*
				 * if userspace address, put adspace ptr in
				 * clist. If not, then do nothing since it's
				 * already set to NULL (from kmem_zalloc)
				 */
				if (uiop->uio_segflg == UIO_USERSPACE) {
					rwl->c_adspc = ttoproc(curthread)->p_as;
				}

				if (prev == NULL)
					prev = rwl;
				else {
					prev->c_next = rwl;
					prev = rwl;
				}
			}

			rwl->c_next = NULL;
			xdrp->xp_wcl = rwl;
			*(rcip->rci_clpp) = rwl;

			break;

		case RCI_WRITE_ADDR_CHUNK:
			rwl = clist_alloc();

			rwl->c_len = rcip->rci_len;
			rwl->u.c_daddr3 = rcip->rci_a.rci_addr;
			rwl->c_next = NULL;
			xdrp->xp_reply_chunk_len_alt += rcip->rci_len;

			xdrp->xp_wcl = rwl;
			*(rcip->rci_clpp) = rwl;

			break;

		case RCI_REPLY_CHUNK:
			xdrp->xp_reply_chunk_len += rcip->rci_len;
			break;
		}
		return (TRUE);

	case XDR_RDMA_GET_WLIST:
		*((struct clist **)info) = xdrp->xp_wcl;
		return (TRUE);

	case XDR_RDMA_SET_WLIST:
		xdrp->xp_wcl = (struct clist *)info;
		return (TRUE);

	case XDR_RDMA_GET_RLIST:
		*((struct clist **)info) = xdrp->xp_rcl;
		return (TRUE);

	case XDR_RDMA_GET_WCINFO:
		rwcip = (rdma_wlist_conn_info_t *)info;

		rwcip->rwci_wlist = xdrp->xp_wcl;
		rwcip->rwci_conn = xdrp->xp_conn;

		return (TRUE);

	default:
		return (FALSE);
	}
}

bool_t xdr_do_clist(XDR *, clist **);

/*
 * Not all fields in struct clist are interesting to the RPC over RDMA
 * protocol. Only XDR the interesting fields.
 */
bool_t
xdr_clist(XDR *xdrs, clist *objp)
{
	if (!xdr_uint32(xdrs, &objp->c_xdroff))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->c_smemhandle.mrc_rmr))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->c_len))
		return (FALSE);
	if (!xdr_uint64(xdrs, &objp->w.c_saddr))
		return (FALSE);
	if (!xdr_do_clist(xdrs, &objp->c_next))
		return (FALSE);
	return (TRUE);
}

/*
 * The following two functions are forms of xdr_pointer()
 * and xdr_reference(). Since the generic versions just
 * kmem_alloc() a new clist, we actually want to use the
 * rdma_clist kmem_cache.
 */

/*
 * Generate or free a clist structure from the
 * kmem_cache "rdma_clist"
 */
bool_t
xdr_ref_clist(XDR *xdrs, caddr_t *pp)
{
	caddr_t loc = *pp;
	bool_t stat;

	if (loc == NULL) {
		switch (xdrs->x_op) {
		case XDR_FREE:
			return (TRUE);

		case XDR_DECODE:
			*pp = loc = (caddr_t)clist_alloc();
			break;

		case XDR_ENCODE:
			ASSERT(loc);
			break;
		}
	}

	stat = xdr_clist(xdrs, (struct clist *)loc);

	if (xdrs->x_op == XDR_FREE) {
		kmem_cache_free(clist_cache, loc);
		*pp = NULL;
	}
	return (stat);
}

/*
 * XDR a pointer to a possibly recursive clist. This differs
 * with xdr_reference in that it can serialize/deserialiaze
 * trees correctly.
 *
 *  What is sent is actually a union:
 *
 *  union object_pointer switch (boolean b) {
 *  case TRUE: object_data data;
 *  case FALSE: void nothing;
 *  }
 *
 * > objpp: Pointer to the pointer to the object.
 *
 */

bool_t
xdr_do_clist(XDR *xdrs, clist **objpp)
{
	bool_t more_data;

	more_data = (*objpp != NULL);
	if (!xdr_bool(xdrs, &more_data))
		return (FALSE);
	if (!more_data) {
		*objpp = NULL;
		return (TRUE);
	}
	return (xdr_ref_clist(xdrs, (caddr_t *)objpp));
}

uint_t
xdr_getbufsize(XDR *xdrs)
{
	xrdma_private_t *xdrp = (xrdma_private_t *)(xdrs->x_private);

	return ((uint_t)xdrp->xp_buf_size);
}

/* ARGSUSED */
bool_t
xdr_encode_rlist_svc(XDR *xdrs, clist *rlist)
{
	bool_t	vfalse = FALSE;

	ASSERT(rlist == NULL);
	return (xdr_bool(xdrs, &vfalse));
}

bool_t
xdr_encode_wlist(XDR *xdrs, clist *w)
{
	bool_t		vfalse = FALSE, vtrue = TRUE;
	int		i;
	uint_t		num_segment = 0;
	struct clist	*cl;

	/* does a wlist exist? */
	if (w == NULL) {
		return (xdr_bool(xdrs, &vfalse));
	}
	/* Encode N consecutive segments, 1, N, HLOO, ..., HLOO, 0 */
	if (!xdr_bool(xdrs, &vtrue))
		return (FALSE);

	for (cl = w; cl != NULL; cl = cl->c_next) {
		num_segment++;
	}

	if (!xdr_uint32(xdrs, &num_segment))
		return (FALSE);
	for (i = 0; i < num_segment; i++) {
		if (!xdr_uint32(xdrs, &w->c_dmemhandle.mrc_rmr))
			return (FALSE);

		if (!xdr_uint32(xdrs, &w->c_len))
			return (FALSE);

		if (!xdr_uint64(xdrs, &w->u.c_daddr))
			return (FALSE);

		w = w->c_next;
	}

	if (!xdr_bool(xdrs, &vfalse))
		return (FALSE);

	return (TRUE);
}


/*
 * Conditionally decode a RDMA WRITE chunk list from XDR stream.
 *
 * If the next boolean in the XDR stream is false there is no
 * RDMA WRITE chunk list present. Otherwise iterate over the
 * array and for each entry: allocate a struct clist and decode.
 * Pass back an indication via wlist_exists if we have seen a
 * RDMA WRITE chunk list.
 */
bool_t
xdr_decode_wlist(XDR *xdrs, struct clist **w, bool_t *wlist_exists)
{
	struct clist	*tmp;
	bool_t		more = FALSE;
	uint32_t	seg_array_len;
	uint32_t	i;

	if (!xdr_bool(xdrs, &more))
		return (FALSE);

	/* is there a wlist? */
	if (more == FALSE) {
		*wlist_exists = FALSE;
		return (TRUE);
	}
	*wlist_exists = TRUE;

	if (!xdr_uint32(xdrs, &seg_array_len))
		return (FALSE);

	tmp = *w = clist_alloc();
	for (i = 0; i < seg_array_len; i++) {
		if (!xdr_uint32(xdrs, &tmp->c_dmemhandle.mrc_rmr))
			return (FALSE);
		if (!xdr_uint32(xdrs, &tmp->c_len))
			return (FALSE);
		if (!xdr_uint64(xdrs, &tmp->u.c_daddr))
			return (FALSE);
		if (i < seg_array_len - 1) {
			tmp->c_next = clist_alloc();
			tmp = tmp->c_next;
		} else {
			tmp->c_next = NULL;
		}
	}

	more = FALSE;
	if (!xdr_bool(xdrs, &more))
		return (FALSE);

	return (TRUE);
}

/*
 * Server side RDMA WRITE list decode.
 * XDR context is memory ops
 */
bool_t
xdr_decode_wlist_svc(XDR *xdrs, struct clist **wclp, bool_t *wwl,
    uint32_t *total_length, CONN *conn)
{
	struct clist	*first, *ncl;
	char		*memp;
	uint32_t	num_wclist;
	uint32_t	wcl_length = 0;
	uint32_t	i;
	bool_t		more = FALSE;

	*wclp = NULL;
	*wwl = FALSE;
	*total_length = 0;

	if (!xdr_bool(xdrs, &more)) {
		return (FALSE);
	}

	if (more == FALSE) {
		return (TRUE);
	}

	*wwl = TRUE;

	if (!xdr_uint32(xdrs, &num_wclist)) {
		DTRACE_PROBE(krpc__e__xdrrdma__wlistsvc__listlength);
		return (FALSE);
	}

	first = ncl = clist_alloc();

	for (i = 0; i < num_wclist; i++) {
		if (!xdr_uint32(xdrs, &ncl->c_dmemhandle.mrc_rmr))
			goto err_out;
		if (!xdr_uint32(xdrs, &ncl->c_len))
			goto err_out;
		if (!xdr_uint64(xdrs, &ncl->u.c_daddr))
			goto err_out;

		if (ncl->c_len > MAX_SVC_XFER_SIZE) {
			DTRACE_PROBE(
			    krpc__e__xdrrdma__wlistsvc__chunklist_toobig);
			ncl->c_len = MAX_SVC_XFER_SIZE;
		}

		wcl_length += ncl->c_len;

		if (i < num_wclist - 1) {
			ncl->c_next = clist_alloc();
			ncl = ncl->c_next;
		}
	}

	if (!xdr_bool(xdrs, &more))
		goto err_out;

	first->rb_longbuf.type = RDMA_LONG_BUFFER;
	first->rb_longbuf.len =
	    wcl_length > WCL_BUF_LEN ? wcl_length : WCL_BUF_LEN;

	if (rdma_buf_alloc(conn, &first->rb_longbuf)) {
		clist_free(first);
		return (FALSE);
	}

	memp = first->rb_longbuf.addr;

	ncl = first;
	for (i = 0; i < num_wclist; i++) {
		ncl->w.c_saddr3 = (caddr_t)memp;
		memp += ncl->c_len;
		ncl = ncl->c_next;
	}

	*wclp = first;
	*total_length = wcl_length;
	return (TRUE);

err_out:
	clist_free(first);
	return (FALSE);
}

/*
 * XDR decode the long reply write chunk.
 */
bool_t
xdr_decode_reply_wchunk(XDR *xdrs, struct clist **clist)
{
	bool_t		have_rchunk = FALSE;
	struct clist	*first = NULL, *ncl = NULL;
	uint32_t	num_wclist;
	uint32_t	i;

	if (!xdr_bool(xdrs, &have_rchunk))
		return (FALSE);

	if (have_rchunk == FALSE)
		return (TRUE);

	if (!xdr_uint32(xdrs, &num_wclist)) {
		DTRACE_PROBE(krpc__e__xdrrdma__replywchunk__listlength);
		return (FALSE);
	}

	if (num_wclist == 0) {
		return (FALSE);
	}

	first = ncl = clist_alloc();

	for (i = 0; i < num_wclist; i++) {
		if (!xdr_uint32(xdrs, &ncl->c_dmemhandle.mrc_rmr))
			goto err_out;
		if (!xdr_uint32(xdrs, &ncl->c_len))
			goto err_out;
		if (!xdr_uint64(xdrs, &ncl->u.c_daddr))
			goto err_out;

		if (ncl->c_len > MAX_SVC_XFER_SIZE) {
			DTRACE_PROBE(
			    krpc__e__xdrrdma__replywchunk__chunklist_toobig);
			ncl->c_len = MAX_SVC_XFER_SIZE;
		}
		if (!(ncl->c_dmemhandle.mrc_rmr &&
		    (ncl->c_len > 0) && ncl->u.c_daddr))
			DTRACE_PROBE(
			    krpc__e__xdrrdma__replywchunk__invalid_segaddr);

		if (i > 0) {
			ncl->c_next = clist_alloc();
			ncl = ncl->c_next;
		}
	}
	*clist = first;
	return (TRUE);

err_out:
	clist_free(first);
	return (FALSE);
}


bool_t
xdr_encode_reply_wchunk(XDR *xdrs,
    struct clist *cl_longreply, uint32_t seg_array_len)
{
	int		i;
	bool_t		long_reply_exists = TRUE;
	uint32_t	length;
	uint64		offset;

	if (seg_array_len > 0) {
		if (!xdr_bool(xdrs, &long_reply_exists))
			return (FALSE);
		if (!xdr_uint32(xdrs, &seg_array_len))
			return (FALSE);

		for (i = 0; i < seg_array_len; i++) {
			if (!cl_longreply)
				return (FALSE);
			length = cl_longreply->c_len;
			offset = (uint64) cl_longreply->u.c_daddr;

			if (!xdr_uint32(xdrs,
			    &cl_longreply->c_dmemhandle.mrc_rmr))
				return (FALSE);
			if (!xdr_uint32(xdrs, &length))
				return (FALSE);
			if (!xdr_uint64(xdrs, &offset))
				return (FALSE);
			cl_longreply = cl_longreply->c_next;
		}
	} else {
		long_reply_exists = FALSE;
		if (!xdr_bool(xdrs, &long_reply_exists))
			return (FALSE);
	}
	return (TRUE);
}
bool_t
xdrrdma_read_from_client(struct clist **rlist, CONN **conn, uint_t count)
{
	struct clist	*rdclist;
	struct clist	cl;
	uint_t		total_len = 0;
	uint32_t	status;
	bool_t		retval = TRUE;

	(*rlist)->rb_longbuf.type = RDMA_LONG_BUFFER;
	(*rlist)->rb_longbuf.len =
	    count > RCL_BUF_LEN ? count : RCL_BUF_LEN;

	if (rdma_buf_alloc(*conn, &(*rlist)->rb_longbuf)) {
		return (FALSE);
	}

	for (rdclist = *rlist;
	    rdclist != NULL; rdclist = rdclist->c_next) {
		total_len += rdclist->c_len;
#if (defined(OBJ32)||defined(DEBUG32))
		rdclist->u.c_daddr3 =
		    (caddr_t)((char *)(*rlist)->rb_longbuf.addr +
		    (uint32) rdclist->u.c_daddr3);
#else
		rdclist->u.c_daddr3 =
		    (caddr_t)((char *)(*rlist)->rb_longbuf.addr +
		    (uint64) rdclist->u.c_daddr);

#endif
		cl = (*rdclist);
		cl.c_next = NULL;

		if (clist_register(*conn, &cl, CLIST_REG_DST) != RDMA_SUCCESS) {
			rdma_buf_free(*conn, &(*rlist)->rb_longbuf);
			DTRACE_PROBE(
			    krpc__e__xdrrdma__readfromclient__clist__reg);
			return (FALSE);
		}

		DTRACE_PROBE1(krpc__i__xdrrdma__readfromclient__buflen,
		    int, rdclist->c_len);

		/*
		 * Now read the chunk in
		 */
		if (rdclist->c_next == NULL) {
			status = RDMA_READ(*conn, &cl, WAIT);
		} else {
			status = RDMA_READ(*conn, &cl, NOWAIT);
		}
		if (status != RDMA_SUCCESS) {
			DTRACE_PROBE(
			    krpc__e__xdrrdma__readfromclient__readfailed);
			rdma_buf_free(*conn, &(*rlist)->rb_longbuf);
			return (FALSE);
		}
	}

	cl = (*(*rlist));
	cl.c_next = NULL;
	cl.c_len = total_len;
	if (clist_syncmem(*conn, &cl, 0) != RDMA_SUCCESS) {
		retval = FALSE;
	}
	return (retval);
}

bool_t
xdrrdma_free_clist(CONN *conn, struct clist *clp)
{
	rdma_buf_free(conn, &clp->rb_longbuf);
	clist_free(clp);
	return (TRUE);
}

bool_t
xdrrdma_send_read_data(XDR *xdrs, struct clist *wcl)
{
	int status;
	xrdma_private_t	*xdrp = (xrdma_private_t *)(xdrs->x_private);
	struct xdr_ops *xops = xdrrdma_xops();

	/* caller is doing a sizeof */
	if (xdrs->x_ops != &xdrrdma_ops || xdrs->x_ops == xops)
		return (TRUE);

	status = clist_register(xdrp->xp_conn, wcl, CLIST_REG_SOURCE);
	if (status != RDMA_SUCCESS) {
		return (FALSE);
	}

	status = clist_syncmem(xdrp->xp_conn, wcl, CLIST_REG_SOURCE);
	if (status != RDMA_SUCCESS) {
		return (FALSE);
	}

	status = RDMA_WRITE(xdrp->xp_conn, wcl, WAIT);
	if (status != RDMA_SUCCESS) {
		return (FALSE);
	}

	return (TRUE);
}

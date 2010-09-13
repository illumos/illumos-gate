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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xdr_rec.c, Implements TCP/IP based XDR streams with a "record marking"
 * layer above tcp (for rpc's use).
 *
 * These routines interface XDRSTREAMS to a tcp/ip connection.
 * There is a record marking layer between the xdr stream
 * and the tcp transport level.  A record is composed on one or more
 * record fragments.  A record fragment is a thirty-two bit header followed
 * by n bytes of data, where n is contained in the header.  The header
 * is represented as a htonl(u_long).  The high order bit encodes
 * whether or not the fragment is the last fragment of the record
 * (1 => fragment is last, 0 => more fragments to follow.
 * The other 31 bits encode the byte length of the fragment.
 */

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <netinet/in.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/bootdebug.h>

#define	dprintf if (boothowto & RB_DEBUG) printf

extern long	lseek();

static bool_t	xdrrec_getint32();
static bool_t	xdrrec_putint32();
static bool_t	xdrrec_getbytes();
static bool_t	xdrrec_putbytes();
static uint_t	xdrrec_getpos();
static bool_t	xdrrec_setpos();
static int32_t *xdrrec_inline();
static void	xdrrec_destroy();

static struct xdr_ops *xdrrec_ops();
static bool_t flush_out();
static bool_t fill_input_buf();
static bool_t get_input_bytes();
static bool_t set_input_fragment();
static bool_t skip_input_bytes();
static uint_t fix_buf_size();

/*
 * A record is composed of one or more record fragments.
 * A record fragment is a four-byte header followed by zero to
 * 2**32-1 bytes.  The header is treated as a long unsigned and is
 * encode/decoded to the network via htonl/ntohl.  The low order 31 bits
 * are a byte count of the fragment.  The highest order bit is a boolean:
 * 1 => this fragment is the last fragment of the record,
 * 0 => this fragment is followed by more fragment(s).
 *
 * The fragment/record machinery is not general;  it is constructed to
 * meet the needs of xdr and rpc based on tcp.
 */
#define	LAST_FRAG 0x80000000

typedef struct rec_strm {
	caddr_t tcp_handle;
	caddr_t the_buffer;
	/*
	 * out-goung bits
	 */
	int (*writeit)();
	caddr_t out_base;	/* output buffer (points to frag header) */
	caddr_t out_finger;	/* next output position */
	caddr_t out_boundry;	/* data cannot up to this address */
	uint32_t *frag_header;	/* beginning of current fragment */
	bool_t frag_sent;	/* true if buffer sent in middle of record */
	/*
	 * in-coming bits
	 */
	int (*readit)();
	uint32_t in_size;	/* fixed size of the input buffer */
	caddr_t in_base;
	caddr_t in_finger;	/* location of next byte to be had */
	caddr_t in_boundry;	/* can read up to this location */
	int fbtbc;		/* fragment bytes to be consumed */
	bool_t last_frag;
	uint_t sendsize;
	uint_t recvsize;
} RECSTREAM;


/*
 * Create an xdr handle for xdrrec
 * xdrrec_create fills in xdrs.  Sendsize and recvsize are
 * send and recv buffer sizes (0 => use default).
 * tcp_handle is an opaque handle that is passed as the first parameter to
 * the procedures readit and writeit.  Readit and writeit are read and
 * write respectively.   They are like the system
 * calls expect that they take an opaque handle rather than an fd.
 */
void
xdrrec_create(XDR *xdrs, uint_t sendsize, uint_t recvsize, caddr_t tcp_handle,
		int (*readit)(), int (*writeit)())
{
	RECSTREAM *rstrm = (RECSTREAM *)mem_alloc(sizeof (RECSTREAM));
	if (rstrm == NULL) {
		dprintf("xdrrec_create: out of memory\n");
		/*
		 *  This is bad.  Should rework xdrrec_create to
		 *  return a handle, and in this case return NULL
		 */
		return;
	}
	/*
	 * adjust sizes and allocate buffer quad byte aligned
	 */
	rstrm->sendsize = sendsize = fix_buf_size(sendsize);
	rstrm->recvsize = recvsize = fix_buf_size(recvsize);
	rstrm->the_buffer = mem_alloc(sendsize + recvsize + BYTES_PER_XDR_UNIT);
	if (rstrm->the_buffer == NULL) {
		dprintf("xdrrec_create: out of memory\n");
		return;
	}
	for (rstrm->out_base = rstrm->the_buffer;
		(uintptr_t)rstrm->out_base % BYTES_PER_XDR_UNIT != 0;
		rstrm->out_base++);
	rstrm->in_base = rstrm->out_base + sendsize;
	/*
	 * now the rest ...
	 */
	xdrs->x_ops = xdrrec_ops();
	xdrs->x_private = (caddr_t)rstrm;
	rstrm->tcp_handle = tcp_handle;
	rstrm->readit = readit;
	rstrm->writeit = writeit;
	rstrm->out_finger = rstrm->out_boundry = rstrm->out_base;
	rstrm->frag_header = (uint32_t *)rstrm->out_base;
	rstrm->out_finger += sizeof (uint_t);
	rstrm->out_boundry += sendsize;
	rstrm->frag_sent = FALSE;
	rstrm->in_size = recvsize;
	rstrm->in_boundry = rstrm->in_base;
	rstrm->in_finger = (rstrm->in_boundry += recvsize);
	rstrm->fbtbc = 0;
	rstrm->last_frag = TRUE;

}


/*
 * The routines defined below are the xdr ops which will go into the
 * xdr handle filled in by xdrrec_create.
 */

static bool_t
xdrrec_getint32(XDR *xdrs, int32_t *ip)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int32_t *bufip = (int32_t *)(rstrm->in_finger);
	int32_t myint;

	/* first try the inline, fast case */
	if ((rstrm->fbtbc >= sizeof (int32_t)) &&
		(((ptrdiff_t)rstrm->in_boundry
		    - (ptrdiff_t)bufip) >= sizeof (int32_t))) {
		*ip = (int32_t)ntohl((uint32_t)(*bufip));
		rstrm->fbtbc -= sizeof (int32_t);
		rstrm->in_finger += sizeof (int32_t);
	} else {
		if (!xdrrec_getbytes(xdrs, (caddr_t)&myint, sizeof (int32_t)))
			return (FALSE);
		*ip = (int32_t)ntohl((uint32_t)myint);
	}
	return (TRUE);
}

static bool_t
xdrrec_putint32(XDR *xdrs, int32_t *ip)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int32_t *dest_ip = ((int32_t *)(rstrm->out_finger));

	if ((rstrm->out_finger += sizeof (int32_t)) > rstrm->out_boundry) {
		/*
		 * this case should almost never happen so the code is
		 * inefficient
		 */
		rstrm->out_finger -= sizeof (int32_t);
		rstrm->frag_sent = TRUE;
		if (! flush_out(rstrm, FALSE))
			return (FALSE);
		dest_ip = ((int32_t *)(rstrm->out_finger));
		rstrm->out_finger += sizeof (int32_t);
	}
	*dest_ip = (int32_t)htonl((uint32_t)(*ip));
	return (TRUE);
}

/*
 * We need to be a little smarter here because we don't want to induce any
 * pathological behavior in inetboot's networking stack.  The algorithm we
 * pursue is to try to consume the entire fragment exactly instead of
 * blindly requesting the max to fill the input buffer.
 */
static bool_t  /* must manage buffers, fragments, and records */
xdrrec_getbytes(XDR *xdrs, caddr_t addr, int32_t len)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int current;
	int frag_len;

	while (len > 0) {
		current =  frag_len = rstrm->fbtbc;
		if (current == 0) {
			if (rstrm->last_frag)
				return (FALSE);
			if (!set_input_fragment(rstrm))
				return (FALSE);
			continue;
		}

		current = (len < current) ? len : current;
		if (!get_input_bytes(rstrm, addr, frag_len, current))
			return (FALSE);
		addr += current;
		rstrm->fbtbc -= current;
		len -= current;
	}
	return (TRUE);
}

static bool_t
xdrrec_putbytes(XDR *xdrs, caddr_t addr, int32_t len)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	ptrdiff_t current;

	while (len > 0) {
		current = rstrm->out_boundry - rstrm->out_finger;
		current = (len < current) ? len : current;
		bcopy(addr, rstrm->out_finger, current);
		rstrm->out_finger += current;
		addr += current;
		len -= current;
		if (rstrm->out_finger == rstrm->out_boundry) {
			rstrm->frag_sent = TRUE;
			if (! flush_out(rstrm, FALSE))
				return (FALSE);
		}
	}
	return (TRUE);
}

static uint_t
xdrrec_getpos(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	int32_t pos;

	pos = lseek((int)(intptr_t)rstrm->tcp_handle, 0, 1);
	if (pos != -1)
		switch (xdrs->x_op) {

		case XDR_ENCODE:
			pos += rstrm->out_finger - rstrm->out_base;
			break;

		case XDR_DECODE:
			pos -= rstrm->in_boundry - rstrm->in_finger;
			break;

		default:
			pos = (uint_t)-1;
			break;
		}
	return ((uint_t)pos);
}

static bool_t
xdrrec_setpos(XDR *xdrs, uint_t pos)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	uint_t currpos = xdrrec_getpos(xdrs);
	int delta = currpos - pos;
	caddr_t newpos;

	if ((int)currpos != -1)
		switch (xdrs->x_op) {

		case XDR_ENCODE:
			newpos = rstrm->out_finger - delta;
			if ((newpos > (caddr_t)(rstrm->frag_header)) &&
				(newpos < rstrm->out_boundry)) {
				rstrm->out_finger = newpos;
				return (TRUE);
			}
			break;

		case XDR_DECODE:
			newpos = rstrm->in_finger - delta;
			if ((delta < (int)(rstrm->fbtbc)) &&
				(newpos <= rstrm->in_boundry) &&
				(newpos >= rstrm->in_base)) {
				rstrm->in_finger = newpos;
				rstrm->fbtbc -= delta;
				return (TRUE);
			}
			break;
		}
	return (FALSE);
}

static int32_t *
xdrrec_inline(XDR *xdrs, int len)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	int32_t *buf = NULL;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		if ((rstrm->out_finger + len) <= rstrm->out_boundry) {
			buf = (int32_t *)rstrm->out_finger;
			rstrm->out_finger += len;
		}
		break;

	case XDR_DECODE:
		if ((len <= rstrm->fbtbc) &&
			((rstrm->in_finger + len) <= rstrm->in_boundry)) {
			buf = (int32_t *)rstrm->in_finger;
			rstrm->fbtbc -= len;
			rstrm->in_finger += len;
		}
		break;
	}
	return (buf);
}

static void
xdrrec_destroy(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;

	mem_free(rstrm->the_buffer,
		rstrm->sendsize + rstrm->recvsize + BYTES_PER_XDR_UNIT);
	mem_free((caddr_t)rstrm, sizeof (RECSTREAM));
}


/*
 * Exported routines to manage xdr records
 */

/*
 * Before reading (deserializing from the stream, one should always call
 * this procedure to guarantee proper record alignment.
 */
bool_t
xdrrec_skiprecord(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		if (! skip_input_bytes(rstrm, rstrm->fbtbc))
			return (FALSE);
		rstrm->fbtbc = 0;
		if ((! rstrm->last_frag) && (! set_input_fragment(rstrm)))
			return (FALSE);
	}
	rstrm->last_frag = FALSE;
	return (TRUE);
}

#ifdef notneeded
/*
 * Look ahead fuction.
 * Returns TRUE iff there is no more input in the buffer
 * after consuming the rest of the current record.
 */
bool_t
xdrrec_eof(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		if (! skip_input_bytes(rstrm, rstrm->fbtbc))
			return (TRUE);
		rstrm->fbtbc = 0;
		if ((! rstrm->last_frag) && (! set_input_fragment(rstrm)))
			return (TRUE);
	}
	if (rstrm->in_finger == rstrm->in_boundry)
		return (TRUE);
	return (FALSE);
}
#endif /* notneeded */

/*
 * The client must tell the package when an end-of-record has occurred.
 * The second paraemters tells whether the record should be flushed to the
 * (output) tcp stream.  (This let's the package support batched or
 * pipelined procedure calls.)  TRUE => immmediate flush to tcp connection.
 */
bool_t
xdrrec_endofrecord(XDR *xdrs, bool_t sendnow)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	ptrdiff_t len;  /* fragment length */

	if (sendnow || rstrm->frag_sent ||
		((ptrdiff_t)rstrm->out_finger + sizeof (uint32_t)
		    >= (ptrdiff_t)rstrm->out_boundry)) {
		rstrm->frag_sent = FALSE;
		return (flush_out(rstrm, TRUE));
	}
	len = (ptrdiff_t)rstrm->out_finger - (ptrdiff_t)rstrm->frag_header;
	len -= sizeof (uint32_t);
	*(rstrm->frag_header) = htonl((uint32_t)len | LAST_FRAG);
	rstrm->frag_header = (uint32_t *)rstrm->out_finger;
	rstrm->out_finger += sizeof (uint32_t);
	return (TRUE);
}


/*
 * Internal useful routines
 */
static bool_t
flush_out(RECSTREAM *rstrm, bool_t eor)
{
	uint32_t eormask = (eor == TRUE) ? LAST_FRAG : 0;
	ptrdiff_t len;

	len = (ptrdiff_t)rstrm->out_finger - (ptrdiff_t)rstrm->frag_header;
	len -= sizeof (uint32_t);

	*(rstrm->frag_header) = htonl(len | eormask);
	len = rstrm->out_finger - rstrm->out_base;
	if ((*(rstrm->writeit))(rstrm->tcp_handle, rstrm->out_base, (int)len)
	    != (int)len)
		return (FALSE);

	rstrm->frag_header = (uint32_t *)rstrm->out_base;
	rstrm->out_finger = (caddr_t)rstrm->out_base + sizeof (uint32_t);
	return (TRUE);
}

static bool_t  /* knows nothing about records!  Only about input buffers */
fill_input_buf(RECSTREAM *rstrm, int frag_len)
{
	caddr_t where;
	uintptr_t i;
	int len;

	where = rstrm->in_base;
	i = (uintptr_t)rstrm->in_boundry % BYTES_PER_XDR_UNIT;
	where += i;
	len = (frag_len < (rstrm->in_size - i)) ? frag_len :
		rstrm->in_size - i;
#ifdef DEBUG
	printf("fill_input_buf: len = %d\n", len);
#endif
	if ((len = (*(rstrm->readit))(rstrm->tcp_handle, where, len)) == -1)
		return (FALSE);
	rstrm->in_finger = where;
	where += len;
	rstrm->in_boundry = where;
	return (TRUE);
}

static bool_t
get_input_bytes(RECSTREAM *rstrm, caddr_t addr, int frag_len, int len)
{
	ptrdiff_t current;

	while (len > 0) {
		current = rstrm->in_boundry - rstrm->in_finger;
#ifdef DEBUG
	printf("get_input_bytes: len = %d, frag_len = %d, current %d\n",
		len, frag_len, current);
#endif
		/*
		 * set_input_bytes doesn't know how large the fragment is, we
		 * need to get the header so just grab a header's size worth
		 */
		if (frag_len == 0)
			frag_len = len;

		if (current == 0) {
			if (! fill_input_buf(rstrm, frag_len))
				return (FALSE);
			continue;
		}

		current = (len < current) ? len : current;
		bcopy(rstrm->in_finger, addr, current);
		rstrm->in_finger += current;
		addr += current;
		len -= current;
	}
	return (TRUE);
}

static bool_t  /* next four bytes of the input stream are treated as a header */
set_input_fragment(RECSTREAM *rstrm)
{
	uint32_t header;

	if (! get_input_bytes(rstrm, (caddr_t)&header, 0, sizeof (header)))
		return (FALSE);
	header = (uint32_t)ntohl(header);
	rstrm->last_frag = ((header & LAST_FRAG) == 0) ? FALSE : TRUE;
	rstrm->fbtbc = header & (~LAST_FRAG);
#ifdef DEBUG
	printf("set_input_fragment: frag_len = %d, last frag = %s\n",
		rstrm->fbtbc, rstrm->last_frag ? "TRUE" : "FALSE");
#endif
	return (TRUE);
}

static bool_t  /* consumes input bytes; knows nothing about records! */
skip_input_bytes(RECSTREAM *rstrm, int32_t cnt)
{
	ptrdiff_t current;
#ifdef DEBUG
	printf("skip_input_fragment: cnt = %d\n", cnt);
#endif
	while (cnt > 0) {
		current = rstrm->in_boundry - rstrm->in_finger;
		if (current == 0) {
			if (! fill_input_buf(rstrm, cnt))
				return (FALSE);
			continue;
		}
		current = (cnt < current) ? cnt : current;
		rstrm->in_finger += current;
		cnt -= current;
	}
	return (TRUE);
}

static uint_t
fix_buf_size(uint_t s)
{

	if (s < 100)
		s = 4000;
	return (RNDUP(s));
}

static struct xdr_ops *
xdrrec_ops()
{
	static struct xdr_ops ops;

	if (ops.x_getint32 == NULL) {
		ops.x_getint32 = xdrrec_getint32;
		ops.x_putint32 = xdrrec_putint32;
		ops.x_getbytes = xdrrec_getbytes;
		ops.x_putbytes = xdrrec_putbytes;
		ops.x_getpostn = xdrrec_getpos;
		ops.x_setpostn = xdrrec_setpos;
		ops.x_inline = xdrrec_inline;
		ops.x_destroy = xdrrec_destroy;
	}

	return (&ops);
}

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
 * xdr_rec.c, Implements (TCP/IP based) XDR streams with a "record marking"
 * layer above connection oriented transport layer (e.g. tcp) (for rpc's use).
 *
 *
 * These routines interface XDRSTREAMS to a (tcp/ip) connection transport.
 * There is a record marking layer between the xdr stream
 * and the (tcp) cv transport level.  A record is composed on one or more
 * record fragments.  A record fragment is a thirty-two bit header followed
 * by n bytes of data, where n is contained in the header.  The header
 * is represented as a htonl(ulong_t).  The order bit encodes
 * whether or not the fragment is the last fragment of the record
 * (1 => fragment is last, 0 => more fragments to follow.
 * The other 31 bits encode the byte length of the fragment.
 */

#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <syslog.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "rac_private.h"

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

#define	LAST_FRAG (((uint32_t)1 << 31))

typedef struct rec_strm {
	caddr_t tcp_handle;
	caddr_t the_buffer;
	/*
	 * out-going bits
	 */
	int (*writeit)(void *, caddr_t, int);
	caddr_t out_base;	/* output buffer (points to frag header) */
	caddr_t out_finger;	/* next output position */
	caddr_t out_boundry;	/* data cannot up to this address */
	uint32_t *frag_header;	/* beginning of current fragment */
	bool_t frag_sent;	/* true if buffer sent in middle of record */
	/*
	 * in-coming bits
	 */
	int (*readit)(void *, caddr_t, int);
	uint_t in_size;		/* fixed size of the input buffer */
	caddr_t in_base;
	caddr_t in_finger;	/* location of next byte to be had */
	caddr_t in_boundry;	/* can read up to this location */
	int fbtbc;		/* fragment bytes to be consumed */
	bool_t last_frag;
	uint_t sendsize;
	uint_t recvsize;
} RECSTREAM;

static uint_t	fix_buf_size(uint_t);
static struct	xdr_ops *xdrrec_ops(void);
static bool_t	xdrrec_getbytes(XDR *, caddr_t, int);
static bool_t	flush_out(RECSTREAM *, bool_t);
static bool_t	get_input_bytes(RECSTREAM *, caddr_t, int);
static bool_t	set_input_fragment(RECSTREAM *);
static bool_t	skip_input_bytes(RECSTREAM *, int);


/*
 * Create an xdr handle for xdrrec
 * xdrrec_create fills in xdrs.  Sendsize and recvsize are
 * send and recv buffer sizes (0 => use default).
 * vc_handle is an opaque handle that is passed as the first parameter to
 * the procedures readit and writeit.  Readit and writeit are read and
 * write respectively. They are like the system calls expect that they
 * take an opaque handle rather than an fd.
 */

static const char mem_err_msg_rec[] = "xdrrec_create: out of memory";

void
xdrrec_create(XDR *xdrs, const uint_t sendsize, const uint_t recvsize,
    const caddr_t tcp_handle,
    int (*readit)(void *, caddr_t, int), int (*writeit)(void *, caddr_t, int))
{
	uint_t ssize, rsize;
	register RECSTREAM *rstrm =
		(RECSTREAM *)malloc(sizeof (RECSTREAM));

	trace3(TR_xdrrec_create, 0, sendsize, recvsize);
	if (rstrm == NULL) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		/*
		 *  XXX: This is bad.  Should rework xdrrec_create to
		 *  return a handle, and in this case return NULL
		 */
		trace1(TR_xdrrec_create, 1);
		return;
	}
	/*
	 * adjust sizes and allocate buffer quad byte aligned
	 */
	rstrm->sendsize = ssize = fix_buf_size(sendsize);
	rstrm->recvsize = rsize = fix_buf_size(recvsize);
	rstrm->the_buffer = (caddr_t)malloc(ssize + rsize + BYTES_PER_XDR_UNIT);
	if (rstrm->the_buffer == NULL) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		(void) free((char *)rstrm);
		trace1(TR_xdrrec_create, 1);
		return;
	}
	for (rstrm->out_base = rstrm->the_buffer;
		(uintptr_t)rstrm->out_base % BYTES_PER_XDR_UNIT != 0;
		rstrm->out_base++);
	rstrm->in_base = rstrm->out_base + ssize;
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
	rstrm->out_boundry += ssize;
	rstrm->frag_sent = FALSE;
	rstrm->in_size = rsize;
	rstrm->in_boundry = rstrm->in_base;
	rstrm->in_finger = (rstrm->in_boundry += rsize);
	rstrm->fbtbc = 0;
	rstrm->last_frag = TRUE;

	trace1(TR_xdrrec_create, 1);
}

/*
 * The routines defined below are the xdr ops which will go into the
 * xdr handle filled in by xdrrec_create.
 */
static bool_t
xdrrec_getint32(XDR *xdrs, int32_t *ip)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register int32_t *buflp = (int32_t *)(rstrm->in_finger);
	int32_t mylong;

	trace1(TR_xdrrec_getint32, 0);
	/* first try the inline, fast case */
	if ((rstrm->fbtbc >= sizeof (int32_t)) &&
	    (((intptr_t)rstrm->in_boundry - (intptr_t)buflp) >=
	    sizeof (int32_t))) {
		*ip = (int32_t)ntohl((uint32_t)(*buflp));
		rstrm->fbtbc -= (int)sizeof (int32_t);
		rstrm->in_finger += sizeof (int32_t);
	} else {
		if (! xdrrec_getbytes(xdrs, (caddr_t)&mylong,
			sizeof (int32_t))) {
			trace1(TR_xdrrec_getint32_t, 1);
			return (FALSE);
		}
		*ip = (int32_t)ntohl((uint32_t)mylong);
	}
	trace1(TR_xdrrec_getint32, 1);
	return (TRUE);
}

static bool_t
xdrrec_putint32(XDR *xdrs, int32_t *ip)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register int32_t *dest_lp = ((int32_t *)(rstrm->out_finger));

	trace1(TR_xdrrec_putint32, 0);
	if ((rstrm->out_finger += sizeof (int32_t)) > rstrm->out_boundry) {
		/*
		 * this case should almost never happen so the code is
		 * inefficient
		 */
		rstrm->out_finger -= sizeof (int32_t);
		rstrm->frag_sent = TRUE;
		if (! flush_out(rstrm, FALSE)) {
			trace1(TR_xdrrec_putint32, 1);
			return (FALSE);
		}
		dest_lp = ((int32_t *)(rstrm->out_finger));
		rstrm->out_finger += sizeof (int32_t);
	}
	*dest_lp = (int32_t)htonl((uint32_t)(*ip));
	trace1(TR_xdrrec_putint32, 1);
	return (TRUE);
}

static bool_t
xdrrec_getlong(XDR *xdrs, long *lp)
{
	int32_t i;
	bool_t ret;

	ret = xdrrec_getint32(xdrs, &i);

	*lp = (long)i;

	return (ret);
}

static bool_t
xdrrec_putlong(XDR *xdrs, long *lp)
{
	int32_t i;

#if defined(_LP64)
	if ((*lp > INT32_MAX) || (*lp < INT32_MIN)) {
		return (FALSE);
	}
#endif

	i = (int32_t)*lp;

	return (xdrrec_putint32(xdrs, &i));
}

static bool_t	/* must manage buffers, fragments, and records */
xdrrec_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register int current;

	trace2(TR_xdrrec_getbytes, 0, len);
	while (len > 0) {
		current = rstrm->fbtbc;
		if (current == 0) {
			if (rstrm->last_frag) {
				trace1(TR_xdrrec_getbytes, 1);
				return (FALSE);
			}
			if (! set_input_fragment(rstrm)) {
				trace1(TR_xdrrec_getbytes, 1);
				return (FALSE);
			}
			continue;
		}
		current = (len < current) ? len : current;
		if (! get_input_bytes(rstrm, addr, current)) {
			trace1(TR_xdrrec_getbytes, 1);
			return (FALSE);
		}
		addr += current;
		rstrm->fbtbc -= current;
		len -= current;
	}
	trace1(TR_xdrrec_getbytes, 1);
	return (TRUE);
}

static bool_t
xdrrec_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register int current;

	trace2(TR_xdrrec_putbytes, 0, len);
	while (len > 0) {

		current = (uintptr_t)rstrm->out_boundry -
						(uintptr_t)rstrm->out_finger;
		current = (len < current) ? len : current;
		(void) memcpy(rstrm->out_finger, addr, current);
		rstrm->out_finger += current;
		addr += current;
		len -= current;
		if (rstrm->out_finger == rstrm->out_boundry) {
			rstrm->frag_sent = TRUE;
			if (! flush_out(rstrm, FALSE)) {
				trace1(TR_xdrrec_putbytes, 1);
				return (FALSE);
			}
		}
	}
	trace1(TR_xdrrec_putbytes, 1);
	return (TRUE);
}
/*
 * This is just like the ops vector x_getbytes(), except that
 * instead of returning success or failure on getting a certain number
 * of bytes, it behaves much more like the read() system call against a
 * pipe -- it returns up to the number of bytes requested and a return of
 * zero indicates end-of-record.  A -1 means something very bad happened.
 */
uint_t /* must manage buffers, fragments, and records */
xdrrec_readbytes(XDR *xdrs, caddr_t addr, uint_t l)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register int current, len;

	len = l;
	while (len > 0) {
		current = rstrm->fbtbc;
		if (current == 0) {
			if (rstrm->last_frag)
				return (l - len);
			if (! set_input_fragment(rstrm))
				return ((uint_t)-1);
			continue;
		}
		current = (len < current) ? len : current;
		if (! get_input_bytes(rstrm, addr, current))
			return ((uint_t)-1);
		addr += current;
		rstrm->fbtbc -= current;
		len -= current;
	}
	return (l - len);
}

static uint_t
xdrrec_getpos(XDR *xdrs)
{
	register RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	register int pos;

	trace1(TR_xdrrec_getpos, 0);
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
	trace1(TR_xdrrec_getpos, 1);
	return ((uint_t)pos);
}

static bool_t
xdrrec_setpos(XDR *xdrs, uint_t pos)
{
	register RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	uint_t currpos = xdrrec_getpos(xdrs);
	int delta = currpos - pos;
	caddr_t newpos;

	trace2(TR_xdrrec_setpos, 0, pos);
	if ((int)currpos != -1)
		switch (xdrs->x_op) {

		case XDR_ENCODE:
			newpos = rstrm->out_finger - delta;
			if ((newpos > (caddr_t)(rstrm->frag_header)) &&
				(newpos < rstrm->out_boundry)) {
				rstrm->out_finger = newpos;
				trace1(TR_xdrrec_setpos, 1);
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
				trace1(TR_xdrrec_setpos, 1);
				return (TRUE);
			}
			break;
		}
	trace1(TR_xdrrec_setpos, 1);
	return (FALSE);
}

static rpc_inline_t *
xdrrec_inline(XDR *xdrs, int len)
{
	register RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	rpc_inline_t *buf = NULL;

	trace2(TR_xdrrec_inline, 0, len);
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		if ((rstrm->out_finger + len) <= rstrm->out_boundry) {
			buf = (rpc_inline_t *)rstrm->out_finger;
			rstrm->out_finger += len;
		}
		break;

	case XDR_DECODE:
		if ((len <= rstrm->fbtbc) &&
			((rstrm->in_finger + len) <= rstrm->in_boundry)) {
			buf = (rpc_inline_t *)rstrm->in_finger;
			rstrm->fbtbc -= len;
			rstrm->in_finger += len;
		}
		break;
	}
	trace1(TR_xdrrec_inline, 1);
	return (buf);
}

static void
xdrrec_destroy(XDR *xdrs)
{
	register RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;

	trace1(TR_xdrrec_destroy, 0);
	free(rstrm->the_buffer);
	free((caddr_t)rstrm);
	trace1(TR_xdrrec_destroy, 1);
}


/*
 * Exported routines to manage xdr records
 */

/*
 * Before reading (deserializing) from the stream, one should always call
 * this procedure to guarantee proper record alignment.
 */
bool_t
xdrrec_skiprecord(XDR *xdrs)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	trace1(TR_xdrrec_skiprecord, 0);
	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		if (! skip_input_bytes(rstrm, rstrm->fbtbc)) {
			trace1(TR_xdrrec_skiprecord, 1);
			return (FALSE);
		}
		rstrm->fbtbc = 0;
		if ((! rstrm->last_frag) && (! set_input_fragment(rstrm))) {
			trace1(TR_xdrrec_skiprecord, 1);
			return (FALSE);
		}
	}
	rstrm->last_frag = FALSE;
	trace1(TR_xdrrec_skiprecord, 1);
	return (TRUE);
}

/*
 * Look ahead fuction.
 * Returns TRUE iff there is no more input in the buffer
 * after consuming the rest of the current record.
 */
bool_t
xdrrec_eof(XDR *xdrs)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	trace1(TR_xdrrec_eof, 0);
	while (rstrm->fbtbc > 0 || (! rstrm->last_frag)) {
		if (! skip_input_bytes(rstrm, rstrm->fbtbc)) {
			trace1(TR_xdrrec_eof, 1);
			return (TRUE);
		}
		rstrm->fbtbc = 0;
		if ((! rstrm->last_frag) && (! set_input_fragment(rstrm))) {
			trace1(TR_xdrrec_eof, 1);
			return (TRUE);
		}
	}
	if (rstrm->in_finger == rstrm->in_boundry) {
		trace1(TR_xdrrec_eof, 1);
		return (TRUE);
	}
	trace1(TR_xdrrec_eof, 1);
	return (FALSE);
}

/*
 * The client must tell the package when an end-of-record has occurred.
 * The second parameters tells whether the record should be flushed to the
 * (output) tcp stream.  (This let's the package support batched or
 * pipelined procedure calls.)  TRUE => immmediate flush to tcp connection.
 */
bool_t
xdrrec_endofrecord(XDR *xdrs, bool_t sendnow)
{
	register RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	register uint32_t len;	/* fragment length */
	bool_t dummy;

	trace1(TR_xdrrec_endofrecord, 0);
	if (sendnow || rstrm->frag_sent ||
		((uintptr_t)rstrm->out_finger + sizeof (uint_t) >=
		(uintptr_t)rstrm->out_boundry)) {
		rstrm->frag_sent = FALSE;
		dummy = flush_out(rstrm, TRUE);
		trace1(TR_xdrrec_endofrecord, 1);
		return (dummy);
	}
	len = (uintptr_t)(rstrm->out_finger) - (uintptr_t)(rstrm->frag_header) -
		sizeof (uint_t);
	*(rstrm->frag_header) = htonl((uint32_t)len | LAST_FRAG);
	rstrm->frag_header = (uint32_t *)rstrm->out_finger;
	rstrm->out_finger += sizeof (uint_t);
	trace1(TR_xdrrec_endofrecord, 1);
	return (TRUE);
}

void
xdrrec_resetinput(XDR *xdrs)
{
	RECSTREAM	*rstrm = (RECSTREAM *)(xdrs->x_private);

	rstrm->last_frag = TRUE;
}

/*
 * Internal useful routines
 */
static bool_t
flush_out(RECSTREAM *rstrm, bool_t eor)
{
	register uint32_t eormask = (eor == TRUE) ? LAST_FRAG : 0;
	register uint_t len = (uintptr_t)(rstrm->out_finger) -
		(uintptr_t)(rstrm->frag_header) - sizeof (uint_t);

	trace1(TR_flush_out, 0);
	*(rstrm->frag_header) = htonl(len | eormask);


	len = (uintptr_t)(rstrm->out_finger) - (uintptr_t)(rstrm->out_base);

	if ((*(rstrm->writeit))(rstrm->tcp_handle, rstrm->out_base, (int)len)
		!= (int)len) {
		trace1(TR_flush_out, 1);
		return (FALSE);
	}
	rstrm->frag_header = (uint32_t *)rstrm->out_base;
	rstrm->out_finger = (caddr_t)rstrm->out_base + sizeof (uint_t);
	trace1(TR_flush_out, 1);
	return (TRUE);
}

/* knows nothing about records!  Only about input buffers */
static bool_t
fill_input_buf(RECSTREAM *rstrm)
{
	register caddr_t where;
	uint_t i;
	register int len;

	trace1(TR_fill_input_buf, 0);
	where = rstrm->in_base;
	i = (uintptr_t)rstrm->in_boundry % BYTES_PER_XDR_UNIT;
	where += i;
	len = rstrm->in_size - i;
	if ((len = (*(rstrm->readit))(rstrm->tcp_handle, where, len)) == -1) {
		trace1(TR_fill_input_buf, 1);
		return (FALSE);
	}
	rstrm->in_finger = where;
	where += len;
	rstrm->in_boundry = where;
	trace1(TR_fill_input_buf, 1);
	return (TRUE);
}

/* knows nothing about records!  Only about input buffers */
static bool_t
get_input_bytes(RECSTREAM *rstrm, caddr_t addr, int len)
{
	register int current;

	trace2(TR_get_input_bytes, 0, len);
	while (len > 0) {
		current = (intptr_t)rstrm->in_boundry -
			(intptr_t)rstrm->in_finger;
		if (current == 0) {
			if (! fill_input_buf(rstrm)) {
				trace1(TR_get_input_bytes, 1);
				return (FALSE);
			}
			continue;
		}
		current = (len < current) ? len : current;
		(void) memcpy(addr, rstrm->in_finger, current);
		rstrm->in_finger += current;
		addr += current;
		len -= current;
	}
	trace1(TR_get_input_bytes, 1);
	return (TRUE);
}

/* next two bytes of the input stream are treated as a header */
static bool_t
set_input_fragment(RECSTREAM *rstrm)
{
	uint_t header;

	trace1(TR_set_input_fragment, 0);
	if (! get_input_bytes(rstrm, (caddr_t)&header, (int)sizeof (header))) {
		trace1(TR_set_input_fragment, 1);
		return (FALSE);
	}
	rstrm->last_frag = ((header & LAST_FRAG) == 0) ? FALSE : TRUE;
	rstrm->fbtbc = header & (~LAST_FRAG);
	trace1(TR_set_input_fragment, 1);
	return (TRUE);
}

/* consumes input bytes; knows nothing about records! */
static bool_t
skip_input_bytes(RECSTREAM *rstrm, int cnt)
{
	register int current;

	trace2(TR_skip_input_bytes, 0, cnt);
	while (cnt > 0) {
		current = (intptr_t)rstrm->in_boundry -
			(intptr_t)rstrm->in_finger;
		if (current == 0) {
			if (! fill_input_buf(rstrm)) {
				trace1(TR_skip_input_bytes, 1);
				return (FALSE);
			}
			continue;
		}
		current = (cnt < current) ? cnt : current;
		rstrm->in_finger += current;
		cnt -= current;
	}
	trace1(TR_skip_input_bytes, 1);
	return (TRUE);
}

static uint_t
fix_buf_size(uint_t s)
{
	static uint_t dummy1;

	trace2(TR_fix_buf_size, 0, s);
	if (s < 100)
		s = 4000;
	dummy1 = RNDUP(s);
	trace1(TR_fix_buf_size, 1);
	return (dummy1);
}

static struct xdr_ops *
xdrrec_ops()
{
	static struct xdr_ops ops;

	trace1(TR_xdrrec_ops, 0);
	if (ops.x_getlong == NULL) {
		ops.x_getlong = xdrrec_getlong;
		ops.x_putlong = xdrrec_putlong;
		ops.x_getbytes = xdrrec_getbytes;
		ops.x_putbytes = xdrrec_putbytes;
		ops.x_getpostn = xdrrec_getpos;
		ops.x_setpostn = xdrrec_setpos;
		ops.x_inline = xdrrec_inline;
		ops.x_destroy = xdrrec_destroy;
#if defined(_LP64)
		ops.x_getint32 = xdrrec_getint32;
		ops.x_putint32 = xdrrec_putint32;
#endif
	}
	trace1(TR_xdrrec_ops, 1);
	return (&ops);
}

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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
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

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <syslog.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

static uint_t	fix_buf_size();
static struct	xdr_ops *xdrrec_ops();
static bool_t	xdrrec_getbytes();
static bool_t	flush_out();
static bool_t	get_input_bytes();
static bool_t	set_input_fragment();
static bool_t	skip_input_bytes();

bool_t		__xdrrec_getbytes_nonblock();

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

/*
 * Minimum fragment size is size of rpc callmsg over TCP:
 * xid direction vers prog vers proc
 *   cred flavor, cred length, cred
 *   verf flavor, verf length, verf
 *   (with no cred or verf allocated)
 */
#define	MIN_FRAG	(10 * BYTES_PER_XDR_UNIT)

typedef struct rec_strm {
	caddr_t tcp_handle;
	/*
	 * out-going bits
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
	caddr_t in_base;	/* input buffer */
	caddr_t in_finger;	/* location of next byte to be had */
	caddr_t in_boundry;	/* can read up to this location */
	int fbtbc;		/* fragment bytes to be consumed */
	bool_t last_frag;
	uint_t sendsize;
	uint_t recvsize;
	/*
	 * Is this the first time that the
	 * getbytes routine has been called ?
	 */
	uint_t firsttime;
	/*
	 * Is this non-blocked?
	 */
	uint_t in_nonblock;	/* non-blocked input */
	uint_t in_needpoll;	/* need to poll to get more data ? */
	uint32_t in_maxrecsz;	/* maximum record size */
	caddr_t in_nextrec;	/* start of next record */
	uint32_t in_nextrecsz;	/* part of next record in buffer */
} RECSTREAM;

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
xdrrec_create(XDR *xdrs, uint_t sendsize, uint_t recvsize, caddr_t tcp_handle,
    int (*readit)(), int (*writeit)())
{
	RECSTREAM *rstrm =
		(RECSTREAM *)mem_alloc(sizeof (RECSTREAM));

	/*
	 * XXX: Should still rework xdrrec_create to return a handle,
	 * and in any malloc-failure case return NULL.
	 */
	trace3(TR_xdrrec_create, 0, sendsize, recvsize);
	if (rstrm == NULL) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		trace1(TR_xdrrec_create, 1);
		return;
	}
	/*
	 * Adjust sizes and allocate buffers; malloc(3C), for which mem_alloc
	 * is a wrapper, provides a buffer suitably aligned for any use, so
	 * there's no need for us to mess around with alignment.
	 *
	 * Since non-blocking connections may need to reallocate the input
	 * buffer, we use separate mem_alloc()s for input and output.
	 */
	rstrm->sendsize = sendsize = fix_buf_size(sendsize);
	rstrm->recvsize = recvsize = fix_buf_size(recvsize);
	rstrm->out_base = (caddr_t)mem_alloc(rstrm->sendsize);
	if (rstrm->out_base == NULL) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		(void) mem_free((char *)rstrm, sizeof (RECSTREAM));
		trace1(TR_xdrrec_create, 1);
		return;
	}
	rstrm->in_base = (caddr_t)mem_alloc(rstrm->recvsize);
	if (rstrm->in_base == NULL) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		(void) mem_free(rstrm->out_base, rstrm->sendsize);
		(void) mem_free(rstrm, sizeof (RECSTREAM));
		trace1(TR_xdrrec_create, 1);
		return;
	}

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
	rstrm->in_boundry = rstrm->in_base;
	rstrm->in_finger = (rstrm->in_boundry += recvsize);
	rstrm->fbtbc = 0;
	rstrm->last_frag = TRUE;
	rstrm->firsttime = 0;
	rstrm->in_nonblock = 0;
	rstrm->in_needpoll = 1;
	rstrm->in_maxrecsz = 0;
	rstrm->in_nextrec = rstrm->in_base;
	rstrm->in_nextrecsz = 0;

	trace1(TR_xdrrec_create, 1);
}

/*
 * Align input stream.  If all applications behaved correctly, this
 * defensive procedure will not be necessary, since received data will be
 * aligned correctly.
 */
static void
align_instream(RECSTREAM *rstrm)
{
	int current = rstrm->in_boundry - rstrm->in_finger;

	(void) memcpy(rstrm->in_base, rstrm->in_finger, current);
	rstrm->in_finger = rstrm->in_base;
	rstrm->in_boundry = rstrm->in_finger + current;
}

/*
 * The routines defined below are the xdr ops which will go into the
 * xdr handle filled in by xdrrec_create.
 */
static bool_t
xdrrec_getint32(XDR *xdrs, int32_t *ip)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int32_t *buflp = (int32_t *)(rstrm->in_finger);
	int32_t mylong;

	trace1(TR_xdrrec_getint32, 0);
	/* first try the inline, fast case */
	if ((rstrm->fbtbc >= (int)sizeof (int32_t)) &&
		((uint_t)(rstrm->in_boundry - (caddr_t)buflp) >=
					(uint_t)sizeof (int32_t))) {
		/*
		 * Check if buflp is longword aligned.  If not, align it.
		 */
		if (((uintptr_t)buflp) & ((int)sizeof (int32_t) - 1)) {
			align_instream(rstrm);
			buflp = (int32_t *)(rstrm->in_finger);
		}
		*ip = (int32_t)ntohl((uint32_t)(*buflp));
		rstrm->fbtbc -= (int)sizeof (int32_t);
		rstrm->in_finger += sizeof (int32_t);
	} else {
		if (!xdrrec_getbytes(xdrs, &mylong, sizeof (int32_t))) {
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int32_t *dest_lp = ((int32_t *)(rstrm->out_finger));

	trace1(TR_xdrrec_putint32, 0);
	if ((rstrm->out_finger += sizeof (int32_t)) > rstrm->out_boundry) {
		/*
		 * this case should almost never happen so the code is
		 * inefficient
		 */
		rstrm->out_finger -= sizeof (int32_t);
		rstrm->frag_sent = TRUE;
		if (! flush_out(rstrm, FALSE)) {
			trace1(TR_xdrrec_putint32_t, 1);
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

	if (!xdrrec_getint32(xdrs, &i))
		return (FALSE);

	*lp = (long)i;

	return (TRUE);
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int current;

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
		if (! get_input_bytes(rstrm, addr, current, FALSE)) {
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int current;

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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	int current, len;

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
		if (! get_input_bytes(rstrm, addr, current, FALSE))
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
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
	int32_t pos;

	trace1(TR_xdrrec_getpos, 0);
	pos = lseek((intptr_t)rstrm->tcp_handle, 0, 1);
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
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
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
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;
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
			/*
			 * Check if rstrm->in_finger is longword aligned;
			 * if not, align it.
			 */
			if (((intptr_t)rstrm->in_finger) &
			    (sizeof (int32_t) - 1))
				align_instream(rstrm);
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
	RECSTREAM *rstrm = (RECSTREAM *)xdrs->x_private;

	trace1(TR_xdrrec_destroy, 0);
	mem_free(rstrm->out_base, rstrm->sendsize);
	mem_free(rstrm->in_base,  rstrm->recvsize);
	mem_free((caddr_t)rstrm, sizeof (RECSTREAM));
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	trace1(TR_xdrrec_skiprecord, 0);
	if (rstrm->in_nonblock) {
		enum xprt_stat pstat;
		/*
		 * Read and discard a record from the non-blocking
		 * buffer. Return succes only if a complete record can
		 * be retrieved without blocking, or if the buffer was
		 * empty and there was no data to fetch.
		 */
		if (__xdrrec_getbytes_nonblock(xdrs, &pstat) ||
			(pstat == XPRT_MOREREQS &&
				rstrm->in_finger == rstrm->in_boundry)) {
			rstrm->fbtbc = 0;
			trace1(TR_xdrrec_skiprecord, 1);
			return (TRUE);
		} else {
			trace1(TR_xdrrec_skiprecord, 1);
			return (FALSE);
		}
	}
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	trace1(TR_xdrrec_eof, 0);
	if (rstrm->in_nonblock) {
		/*
		 * If in_needpoll is true, the non-blocking XDR stream
		 * does not have a complete record.
		 */
		return (rstrm->in_needpoll);
	}
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
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	uint32_t len;	/* fragment length */
	bool_t dummy;

	trace1(TR_xdrrec_endofrecord, 0);
	if (sendnow || rstrm->frag_sent ||
		((uintptr_t)rstrm->out_finger + sizeof (uint32_t) >=
		(uintptr_t)rstrm->out_boundry)) {
		rstrm->frag_sent = FALSE;
		dummy = flush_out(rstrm, TRUE);
		trace1(TR_xdrrec_endofrecord, 1);
		return (dummy);
	}
	len = (uintptr_t)(rstrm->out_finger) - (uintptr_t)(rstrm->frag_header) -
		sizeof (uint32_t);
	*(rstrm->frag_header) = htonl((uint32_t)len | LAST_FRAG);
	rstrm->frag_header = (uint32_t *)rstrm->out_finger;
	rstrm->out_finger += sizeof (uint32_t);
	trace1(TR_xdrrec_endofrecord, 1);
	return (TRUE);
}


/*
 * Internal useful routines
 */
static bool_t
flush_out(RECSTREAM *rstrm, bool_t eor)
{
	uint32_t eormask = (eor == TRUE) ? LAST_FRAG : 0;
	uint32_t len = (uintptr_t)(rstrm->out_finger) -
		(uintptr_t)(rstrm->frag_header) - sizeof (uint32_t);
	int written;

	trace1(TR_flush_out, 0);
	*(rstrm->frag_header) = htonl(len | eormask);
	len = (uintptr_t)(rstrm->out_finger) - (uintptr_t)(rstrm->out_base);

	written = (*(rstrm->writeit))
	    (rstrm->tcp_handle, rstrm->out_base, (int)len);
	/*
	 * Handle the specific 'CANT_STORE' error. In this case, the
	 * fragment must be cleared.
	 */
	if ((written != (int)len) && (written != -2)) {
		trace1(TR_flush_out, 1);
		return (FALSE);
	}
	rstrm->frag_header = (uint32_t *)rstrm->out_base;
	rstrm->out_finger = (caddr_t)rstrm->out_base + sizeof (uint32_t);

	trace1(TR_flush_out, 1);
	return (TRUE);
}

/* knows nothing about records!  Only about input buffers */
static bool_t
fill_input_buf(RECSTREAM *rstrm, bool_t do_align)
{
	caddr_t where;
	int len;

	trace1(TR_fill_input_buf, 0);
	if (rstrm->in_nonblock) {
		/* Should never get here in the non-blocking case */
		trace1(TR_fill_input_buf, 1);
		return (FALSE);
	}
	where = rstrm->in_base;
	if (do_align) {
		len = rstrm->recvsize;
	} else {
		uint_t i = (uintptr_t)rstrm->in_boundry % BYTES_PER_XDR_UNIT;

		where += i;
		len = rstrm->recvsize - i;
	}
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
get_input_bytes(RECSTREAM *rstrm, caddr_t addr,
		int len, bool_t do_align)
{
	int current;

	trace2(TR_get_input_bytes, 0, len);

	if (rstrm->in_nonblock) {
		/*
		 * Data should already be in the rstrm buffer, so we just
		 * need to copy it to 'addr'.
		 */
		current = (int)(rstrm->in_boundry - rstrm->in_finger);
		if (len > current) {
			trace1(TR_get_input_bytes, 1);
			return (FALSE);
		}
		(void) memcpy(addr, rstrm->in_finger, len);
		rstrm->in_finger += len;
		addr += len;
		trace1(TR_get_input_bytes, 1);
		return (TRUE);
	}

	while (len > 0) {
		current = (intptr_t)rstrm->in_boundry -
			(intptr_t)rstrm->in_finger;
		if (current == 0) {
			if (! fill_input_buf(rstrm, do_align)) {
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
		do_align = FALSE;
	}
	trace1(TR_get_input_bytes, 1);
	return (TRUE);
}

/* next four bytes of the input stream are treated as a header */
static bool_t
set_input_fragment(RECSTREAM *rstrm)
{
	uint32_t header;

	trace1(TR_set_input_fragment, 0);
	if (rstrm->in_nonblock) {
		/*
		 * In the non-blocking case, the fragment headers should
		 * already have been consumed, so we should never get
		 * here. Might as well return failure right away.
		 */
		trace1(TR_set_input_fragment, 1);
		return (FALSE);
	}
	if (! get_input_bytes(rstrm, (caddr_t)&header, (int)sizeof (header),
							rstrm->last_frag)) {
		trace1(TR_set_input_fragment, 1);
		return (FALSE);
	}
	header = (uint32_t)ntohl(header);
	rstrm->last_frag = ((header & LAST_FRAG) == 0) ? FALSE : TRUE;
	rstrm->fbtbc = header & (~LAST_FRAG);
	trace1(TR_set_input_fragment, 1);
	return (TRUE);
}

/* consumes input bytes; knows nothing about records! */
static bool_t
skip_input_bytes(RECSTREAM *rstrm, int32_t cnt)
{
	int current;

	trace2(TR_skip_input_bytes, 0, cnt);
	while (cnt > 0) {
		current = (intptr_t)rstrm->in_boundry -
			(intptr_t)rstrm->in_finger;
		if (current == 0) {
			if (! fill_input_buf(rstrm, FALSE)) {
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


static bool_t
__xdrrec_nonblock_realloc(RECSTREAM *rstrm, uint32_t newsize)
{
	caddr_t newbuf = rstrm->in_base;
	ptrdiff_t offset;
	bool_t ret = TRUE;

	if (newsize > rstrm->recvsize) {
		newbuf = (caddr_t)realloc(newbuf, newsize);
		if (newbuf == 0) {
			ret = FALSE;
		} else {
			/* Make pointers valid for the new buffer */
			offset = newbuf - rstrm->in_base;
			rstrm->in_finger += offset;
			rstrm->in_boundry += offset;
			rstrm->in_nextrec += offset;
			rstrm->in_base = newbuf;
			rstrm->recvsize = newsize;
		}
	}

	return (ret);
}

/*
 * adjust sizes and allocate buffer quad byte aligned
 */
bool_t
__xdrrec_set_conn_nonblock(XDR *xdrs, uint32_t tcp_maxrecsz)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	caddr_t realloc_buffer;
	size_t newsize;

	rstrm->in_nonblock = TRUE;
	if (tcp_maxrecsz == 0) {
		/*
		 * If maxrecsz has not been set, use the default
		 * that was set from xdrrec_create() and
		 * fix_buf_size()
		 */
		rstrm->in_maxrecsz = rstrm->recvsize;
		return (TRUE);
	}
	rstrm->in_maxrecsz = tcp_maxrecsz;
	if (tcp_maxrecsz <= rstrm->recvsize)
		return (TRUE);

	/*
	 * For nonblocked connection, the entire record is read into the
	 * buffer before any xdr processing. This implies that the record
	 * size must allow for the maximum expected message size of the
	 * service. However, it's inconvenient to allocate very large
	 * buffers up front, so we limit ourselves to a reasonable
	 * default size here, and reallocate (up to the maximum record
	 * size allowed for the connection) as necessary.
	 */
	if ((newsize = tcp_maxrecsz) > RPC_MAXDATASIZE) {
		newsize = RPC_MAXDATASIZE;
	}
	if (! __xdrrec_nonblock_realloc(rstrm, newsize)) {
		(void) syslog(LOG_ERR, mem_err_msg_rec);
		(void) mem_free(rstrm->out_base, rstrm->sendsize);
		(void) mem_free(rstrm->in_base,  rstrm->recvsize);
		(void) mem_free((char *)rstrm, sizeof (RECSTREAM));
		trace1(TR_xdrrec_create, 1);
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Retrieve input data from the non-blocking connection, increase
 * the size of the read buffer if necessary, and check that the
 * record size stays below the allowed maximum for the connection.
 */
bool_t
__xdrrec_getbytes_nonblock(XDR *xdrs, enum xprt_stat *pstat)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	uint32_t prevbytes_thisrec, minreqrecsize;
	uint32_t *header;
	uint32_t len_received = 0, unprocessed = 0;

	trace2(TR__xdrrec_getbytes_nonblock, 0, len);

	/*
	 * For connection oriented protocols, there's no guarantee that
	 * we will receive the data nicely chopped into records, no
	 * matter how it was sent. We use the in_nextrec pointer to
	 * indicate where in the buffer the next record starts. If
	 * in_nextrec != in_base, there's data in the buffer from
	 * previous reads, and if in_nextrecsz > 0, we need to copy
	 * the portion of the next record already read to the start of
	 * the input buffer
	 */
	if (rstrm->in_nextrecsz > 0) {
		/* Starting on new record with data already in the buffer */
		(void) memmove(rstrm->in_base, rstrm->in_nextrec,
			rstrm->in_nextrecsz);
		rstrm->in_nextrec = rstrm->in_finger = rstrm->in_base;
		rstrm->in_boundry = rstrm->in_nextrec + rstrm->in_nextrecsz;
		unprocessed = rstrm->in_nextrecsz;
		rstrm->in_nextrecsz = 0;
	} else if (rstrm->in_nextrec == rstrm->in_base) {
		/* Starting on new record with empty buffer */
		rstrm->in_boundry = rstrm->in_finger = rstrm->in_base;
		rstrm->last_frag = FALSE;
		rstrm->in_needpoll = TRUE;
	}

	prevbytes_thisrec = (uint32_t)(rstrm->in_boundry - rstrm->in_base);

	/* Do we need to retrieve data ? */
	if (rstrm->in_needpoll) {
		int len_requested, len_total_received;

		rstrm->in_needpoll = FALSE;
		len_total_received =
			(int)(rstrm->in_boundry - rstrm->in_base);
		len_requested = rstrm->recvsize - len_total_received;
		/*
		 * if len_requested is 0, this means that the input
		 * buffer is full and need to be increased.
		 * The minimum record size we will need is whatever's
		 * already in the buffer, plus what's yet to be
		 * consumed in the current fragment, plus space for at
		 * least one more fragment header, if this is not the
		 * last fragment. We use the RNDUP() macro to
		 * account for possible realignment of the next
		 * fragment header.
		 */
		if (len_requested == 0) {
			minreqrecsize = rstrm->recvsize +
			    rstrm->fbtbc +
			    (rstrm->last_frag ? 0 : sizeof (*header));
			minreqrecsize = RNDUP(minreqrecsize);
			if (minreqrecsize == rstrm->recvsize) {
				/*
				 * no more bytes to be consumed and
				 * last fragment. We should never end up
				 * here. Might as well return failure
				 * right away.
				 */
				*pstat = XPRT_DIED;
				trace1(TR__xdrrec_getbytes_nonblock, 1);
				return (FALSE);
			} else if (minreqrecsize > rstrm->in_maxrecsz) {
				goto recsz_invalid;
			} else {
				goto needpoll;
			}
		}
		if ((len_received = (*(rstrm->readit))(rstrm->tcp_handle,
				rstrm->in_boundry, len_requested)) == -1) {
			*pstat = XPRT_DIED;
			trace1(TR__xdrrec_getbytes_nonblock, 1);
			return (FALSE);
		}
		rstrm->in_boundry += len_received;
		rstrm->in_nextrec = rstrm->in_boundry;
	}

	/* Account for any left over data from previous processing */
	len_received += unprocessed;

	/* Set a lower limit on the buffer space we'll need */
	minreqrecsize = prevbytes_thisrec + rstrm->fbtbc;

	/*
	 * Consume bytes for this record until it's either complete,
	 * rejected, or we need to poll for more bytes.
	 *
	 * If fbtbc == 0, in_finger points to the start of the fragment
	 * header. Otherwise, it points to the start of the fragment data.
	 */
	while (len_received > 0) {
		if (rstrm->fbtbc == 0) {
			uint32_t hdrlen, minfraglen = 0;
			uint32_t len_recvd_thisfrag;
			bool_t last_frag;

			len_recvd_thisfrag = (uint32_t)(rstrm->in_boundry -
						rstrm->in_finger);
			header = (uint32_t *)rstrm->in_finger;
			hdrlen = (len_recvd_thisfrag < sizeof (*header)) ?
				len_recvd_thisfrag : sizeof (*header);
			memcpy(&minfraglen, header, hdrlen);
			last_frag = (ntohl(minfraglen) & LAST_FRAG) != 0;
			minfraglen = ntohl(minfraglen) & (~LAST_FRAG);
			/*
			 * The minimum record size we will need is whatever's
			 * already in the buffer, plus the size of this
			 * fragment, plus (if this isn't the last fragment)
			 * space for at least one more fragment header. We
			 * use the RNDUP() macro to account for possible
			 * realignment of the next fragment header.
			 */
			minreqrecsize += minfraglen +
					(last_frag?0:sizeof (*header));
			minreqrecsize = RNDUP(minreqrecsize);

			if (hdrlen < sizeof (*header)) {
				/*
				 * We only have a partial fragment header,
				 * but we can still put a lower limit on the
				 * final fragment size, and check against the
				 * maximum allowed.
				 */
				if (len_recvd_thisfrag > 0 &&
					(minreqrecsize > rstrm->in_maxrecsz)) {
					goto recsz_invalid;
				}
				/* Need more bytes to obtain fbtbc value */
				goto needpoll;
			}
			/*
			 * We've got a complete fragment header, so
			 * 'minfraglen' is the actual fragment length, and
			 * 'minreqrecsize' the requested record size.
			 */
			rstrm->last_frag = last_frag;
			rstrm->fbtbc = minfraglen;
			/*
			 * Check that the sum of the total number of bytes read
			 * so far (for the record) and the size of the incoming
			 * fragment is less than the maximum allowed.
			 *
			 * If this is the last fragment, also check that the
			 * record (message) meets the minimum length
			 * requirement.
			 *
			 * If this isn't the last fragment, check for a zero
			 * fragment length. Accepting such fragments would
			 * leave us open to an attack where the sender keeps
			 * the connection open indefinitely, without any
			 * progress, by occasionally sending a zero length
			 * fragment.
			 */
			if ((minreqrecsize > rstrm->in_maxrecsz) ||
			(rstrm->last_frag && minreqrecsize < MIN_FRAG) ||
			(!rstrm->last_frag && minfraglen == 0)) {
recsz_invalid:
				rstrm->fbtbc = 0;
				rstrm->last_frag = 1;
				*pstat = XPRT_DIED;
				trace1(TR__xdrrec_getbytes_nonblock, 1);
				return (FALSE);
			}
			/*
			 * Make this fragment abut the previous one. If it's
			 * the first fragment, just advance in_finger past
			 * the header. This avoids buffer copying for the
			 * usual case where there's one fragment per record.
			 */
			if (rstrm->in_finger == rstrm->in_base) {
				rstrm->in_finger += sizeof (*header);
			} else {
				rstrm->in_boundry -= sizeof (*header);
				(void) memmove(rstrm->in_finger,
					rstrm->in_finger + sizeof (*header),
					rstrm->in_boundry - rstrm->in_finger);
			}
			/* Consume the fragment header */
			if (len_received > sizeof (*header)) {
				len_received -= sizeof (*header);
			} else {
				len_received = 0;
			}
		}
		/*
		 * Consume whatever fragment bytes we have.
		 * If we've received all bytes for this fragment, advance
		 * in_finger to point to the start of the next fragment
		 * header. Otherwise, make fbtbc tell how much is left in
		 * in this fragment and advance finger to point to end of
		 * fragment data.
		 */
		if (len_received >= rstrm->fbtbc) {
			len_received -= rstrm->fbtbc;
			rstrm->in_finger += rstrm->fbtbc;
			rstrm->fbtbc = 0;
		} else {
			rstrm->fbtbc -= len_received;
			rstrm->in_finger += len_received;
			len_received = 0;
		}
		/*
		 * If there's more data in the buffer, there are two
		 * possibilities:
		 *
		 * (1)	This is the last fragment, so the extra data
		 *	presumably belongs to the next record.
		 *
		 * (2)	Not the last fragment, so we'll start over
		 *	from the top of the loop.
		 */
		if (len_received > 0 && rstrm->last_frag) {
			rstrm->in_nextrec = rstrm->in_finger;
			rstrm->in_nextrecsz = (uint32_t)(rstrm->in_boundry -
							rstrm->in_nextrec);
			len_received = 0;
		}
	}

	/* Was this the last fragment, and have we read the entire record ? */
	if (rstrm->last_frag && rstrm->fbtbc == 0) {
		*pstat = XPRT_MOREREQS;
		/*
		 * We've been using both in_finger and fbtbc for our own
		 * purposes. Now's the time to update them to be what
		 * xdrrec_inline() expects. Set in_finger to point to the
		 * start of data for this record, and fbtbc to the number
		 * of bytes in the record.
		 */
		rstrm->fbtbc = (int)(rstrm->in_finger -
				rstrm->in_base - sizeof (*header));
		rstrm->in_finger = rstrm->in_base + sizeof (*header);
		if (rstrm->in_nextrecsz == 0)
			rstrm->in_nextrec = rstrm->in_base;
		trace1(TR__xdrrec_getbytes_nonblock, 1);
		return (TRUE);
	}
needpoll:
	/*
	 * Need more bytes, so we set the needpoll flag, and go back to
	 * the main RPC request loop. However, first we reallocate the
	 * input buffer, if necessary.
	 */
	if (minreqrecsize > rstrm->recvsize) {
		if (! __xdrrec_nonblock_realloc(rstrm, minreqrecsize)) {
			rstrm->fbtbc = 0;
			rstrm->last_frag = 1;
			*pstat = XPRT_DIED;
			trace1(TR__xdrrec_getbytes_nonblock, 1);
			return (FALSE);
		}
	}

	rstrm->in_needpoll = TRUE;
	*pstat = XPRT_MOREREQS;
	trace1(TR__xdrrec_getbytes_nonblock, 1);
	return (FALSE);
}

int
__is_xdrrec_first(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	return ((rstrm->firsttime == TRUE)? 1 : 0);
}

int
__xdrrec_setfirst(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	/*
	 * Set rstrm->firsttime only if the input buffer is empty.
	 * Otherwise, the first read from the network could skip
	 * a poll.
	 */
	if (rstrm->in_finger == rstrm->in_boundry)
		rstrm->firsttime = TRUE;
	else
		rstrm->firsttime = FALSE;
	return (1);
}

int
__xdrrec_resetfirst(XDR *xdrs)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);

	rstrm->firsttime = FALSE;
	return (1);
}


static uint_t
fix_buf_size(uint_t s)
{
	uint_t dummy1;

	trace2(TR_fix_buf_size, 0, s);
	if (s < 100)
		s = 4000;
	dummy1 = RNDUP(s);
	trace1(TR_fix_buf_size, 1);
	return (dummy1);
}



static bool_t
xdrrec_control(XDR *xdrs, int request, void *info)
{
	RECSTREAM *rstrm = (RECSTREAM *)(xdrs->x_private);
	xdr_bytesrec *xptr;

	switch (request) {

	case XDR_GET_BYTES_AVAIL:
		/* Check if at end of fragment and not last fragment */
		if ((rstrm->fbtbc == 0)	&& (!rstrm->last_frag))
			if (!set_input_fragment(rstrm)) {
				return (FALSE);
			};

		xptr = (xdr_bytesrec *)info;
		xptr->xc_is_last_record = rstrm->last_frag;
		xptr->xc_num_avail = rstrm->fbtbc;

		return (TRUE);
	default:
		return (FALSE);

	}

}

static struct xdr_ops *
xdrrec_ops()
{
	static struct xdr_ops ops;
	extern mutex_t	ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_xdrrec_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.x_getlong == NULL) {
		ops.x_getlong = xdrrec_getlong;
		ops.x_putlong = xdrrec_putlong;
		ops.x_getbytes = xdrrec_getbytes;
		ops.x_putbytes = xdrrec_putbytes;
		ops.x_getpostn = xdrrec_getpos;
		ops.x_setpostn = xdrrec_setpos;
		ops.x_inline = xdrrec_inline;
		ops.x_destroy = xdrrec_destroy;
		ops.x_control = xdrrec_control;
#if defined(_LP64)
		ops.x_getint32 = xdrrec_getint32;
		ops.x_putint32 = xdrrec_putint32;
#endif
	}
	mutex_unlock(&ops_lock);
	trace1(TR_xdrrec_ops, 1);
	return (&ops);
}

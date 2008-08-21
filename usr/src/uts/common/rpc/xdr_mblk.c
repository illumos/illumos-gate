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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * xdr_mblk.c, XDR implementation on kernel streams mblks.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

static bool_t	xdrmblk_getint32(XDR *, int32_t *);
static bool_t	xdrmblk_putint32(XDR *, int32_t *);
static bool_t	xdrmblk_getbytes(XDR *, caddr_t, int);
static bool_t	xdrmblk_putbytes(XDR *, caddr_t, int);
static uint_t	xdrmblk_getpos(XDR *);
static bool_t	xdrmblk_setpos(XDR *, uint_t);
static rpc_inline_t *xdrmblk_inline(XDR *, int);
static void	xdrmblk_destroy(XDR *);
static bool_t	xdrmblk_control(XDR *, int, void *);

static mblk_t *xdrmblk_alloc(int);

/*
 * Xdr on mblks operations vector.
 */
struct	xdr_ops xdrmblk_ops = {
	xdrmblk_getbytes,
	xdrmblk_putbytes,
	xdrmblk_getpos,
	xdrmblk_setpos,
	xdrmblk_inline,
	xdrmblk_destroy,
	xdrmblk_control,
	xdrmblk_getint32,
	xdrmblk_putint32
};

/*
 * Initialize xdr stream.
 */
void
xdrmblk_init(XDR *xdrs, mblk_t *m, enum xdr_op op, int sz)
{
	xdrs->x_op = op;
	xdrs->x_ops = &xdrmblk_ops;
	xdrs->x_base = (caddr_t)m;
	xdrs->x_public = NULL;
	xdrs->x_private = (caddr_t)(uintptr_t)sz;

	if (op == XDR_DECODE)
		xdrs->x_handy = (int)(m->b_wptr - m->b_rptr);
	else
		xdrs->x_handy = (int)(m->b_datap->db_lim - m->b_datap->db_base);
}

/* ARGSUSED */
static void
xdrmblk_destroy(XDR *xdrs)
{
}

static bool_t
xdrmblk_getint32(XDR *xdrs, int32_t *int32p)
{
	mblk_t *m;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);
	/*
	 * If the pointer is not aligned or there is not
	 * enough bytes, pullupmsg to get enough bytes and
	 * align the mblk.
	 */
	if (!IS_P2ALIGNED(m->b_rptr, sizeof (int32_t)) ||
	    xdrs->x_handy < sizeof (int32_t)) {
		while (!pullupmsg(m, sizeof (int32_t))) {
			/*
			 * Could have failed due to not
			 * enough data or an allocb failure.
			 */
			if (xmsgsize(m) < sizeof (int32_t))
				return (FALSE);
			delay(hz);
		}
		xdrs->x_handy = (int)(m->b_wptr - m->b_rptr);
	}

	/* LINTED pointer alignment */
	*int32p = ntohl(*((int32_t *)(m->b_rptr)));
	m->b_rptr += sizeof (int32_t);

	/*
	 * Instead of leaving handy as 0 causing more pullupmsg's
	 * simply move to the next mblk.
	 */
	if ((xdrs->x_handy -= sizeof (int32_t)) == 0) {
		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		if (m != NULL)
			xdrs->x_handy = (int)(m->b_wptr - m->b_rptr);
	}
	return (TRUE);
}

static bool_t
xdrmblk_putint32(XDR *xdrs, int32_t *int32p)
{
	mblk_t *m;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);
	if ((xdrs->x_handy -= (int)sizeof (int32_t)) < 0) {
		if (m->b_cont == NULL) {
			m->b_cont = xdrmblk_alloc((int)(uintptr_t)
			    xdrs->x_private);
		}
		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)(m->b_datap->db_lim - m->b_rptr -
		    sizeof (int32_t));
		ASSERT(m->b_rptr == m->b_wptr);
		ASSERT(m->b_rptr >= m->b_datap->db_base);
		ASSERT(m->b_rptr < m->b_datap->db_lim);
	}
	/* LINTED pointer alignment */
	*(int32_t *)m->b_wptr = htonl(*int32p);
	m->b_wptr += sizeof (int32_t);
	ASSERT(m->b_wptr <= m->b_datap->db_lim);
	return (TRUE);
}

/*
 * We pick 16 as a compromise threshold for most architectures.
 */
#define	XDRMBLK_BCOPY_LIMIT	16

static bool_t
xdrmblk_getbytes(XDR *xdrs, caddr_t addr, int len)
{
	mblk_t *m;
	int i;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);
	/*
	 * Performance tweak: converted explicit bcopy()
	 * call to simple in-line. This function is called
	 * to process things like readdir reply filenames
	 * which are small strings--typically 12 bytes or less.
	 * Overhead of calling bcopy() is obnoxious for such
	 * small copies.
	 */
	while ((xdrs->x_handy -= len) < 0) {
		if ((xdrs->x_handy += len) > 0) {
			if (len < XDRMBLK_BCOPY_LIMIT) {
				for (i = 0; i < xdrs->x_handy; i++)
					*addr++ = *m->b_rptr++;
			} else {
				bcopy(m->b_rptr, addr, xdrs->x_handy);
				m->b_rptr += xdrs->x_handy;
				addr += xdrs->x_handy;
			}
			len -= xdrs->x_handy;
		}
		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)(m->b_wptr - m->b_rptr);
	}
	if (len < XDRMBLK_BCOPY_LIMIT) {
		for (i = 0; i < len; i++)
			*addr++ = *m->b_rptr++;
	} else {
		bcopy(m->b_rptr, addr, len);
		m->b_rptr += len;
	}
	return (TRUE);
}

/*
 * Sort of like getbytes except that instead of getting bytes we return the
 * mblk chain which contains the data.  If the data ends in the middle of
 * an mblk, the mblk is dup'd and split, so that the data will end on an
 * mblk.  Note that it is up to the caller to keep track of the data length
 * and not walk too far down the mblk chain.
 */

bool_t
xdrmblk_getmblk(XDR *xdrs, mblk_t **mm, uint_t *lenp)
{
	mblk_t *m, *nextm;
	int len;
	int32_t llen;

	if (!xdrmblk_getint32(xdrs, &llen))
		return (FALSE);

	*lenp = llen;
	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	*mm = m;

	/*
	 * Walk the mblk chain until we get to the end or we've gathered
	 * enough data.
	 */
	len = 0;
	llen = roundup(llen, BYTES_PER_XDR_UNIT);
	while (m != NULL && len + (int)MBLKL(m) <= llen) {
		len += (int)MBLKL(m);
		m = m->b_cont;
	}
	if (len < llen) {
		if (m == NULL) {
			return (FALSE);
		} else {
			int tail_bytes = llen - len;

			/*
			 * Split the mblk with the last chunk of data and
			 * insert it into the chain.  The new mblk goes
			 * after the existing one so that it will get freed
			 * properly.
			 */
			nextm = dupb(m);
			if (nextm == NULL)
				return (FALSE);
			nextm->b_cont = m->b_cont;
			m->b_cont = nextm;
			m->b_wptr = m->b_rptr + tail_bytes;
			nextm->b_rptr += tail_bytes;
			ASSERT(nextm->b_rptr != nextm->b_wptr);

			m = nextm;	/* for x_base */
		}
	}
	xdrs->x_base = (caddr_t)m;
	xdrs->x_handy = m != NULL ? MBLKL(m) : 0;
	return (TRUE);
}

static bool_t
xdrmblk_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	mblk_t *m;
	uint_t i;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);
	/*
	 * Performance tweak: converted explicit bcopy()
	 * call to simple in-line. This function is called
	 * to process things like readdir reply filenames
	 * which are small strings--typically 12 bytes or less.
	 * Overhead of calling bcopy() is obnoxious for such
	 * small copies.
	 */
	while ((xdrs->x_handy -= len) < 0) {
		if ((xdrs->x_handy += len) > 0) {
			if (xdrs->x_handy < XDRMBLK_BCOPY_LIMIT) {
				for (i = 0; i < (uint_t)xdrs->x_handy; i++)
					*m->b_wptr++ = *addr++;
			} else {
				bcopy(addr, m->b_wptr, xdrs->x_handy);
				m->b_wptr += xdrs->x_handy;
				addr += xdrs->x_handy;
			}
			len -= xdrs->x_handy;
		}

		/*
		 * We don't have enough space, so allocate the
		 * amount we need, or x_private, whichever is larger.
		 * It is better to let the underlying transport divide
		 * large chunks than to try and guess what is best.
		 */
		if (m->b_cont == NULL)
			m->b_cont = xdrmblk_alloc(MAX(len,
			    (int)(uintptr_t)xdrs->x_private));

		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)(m->b_datap->db_lim - m->b_rptr);
		ASSERT(m->b_rptr == m->b_wptr);
		ASSERT(m->b_rptr >= m->b_datap->db_base);
		ASSERT(m->b_rptr < m->b_datap->db_lim);
	}
	if (len < XDRMBLK_BCOPY_LIMIT) {
		for (i = 0; i < len; i++)
			*m->b_wptr++ = *addr++;
	} else {
		bcopy(addr, m->b_wptr, len);
		m->b_wptr += len;
	}
	ASSERT(m->b_wptr <= m->b_datap->db_lim);
	return (TRUE);
}

/*
 * We avoid a copy by merely adding this mblk to the list.  The caller is
 * responsible for allocating and filling in the mblk. If len is
 * not a multiple of BYTES_PER_XDR_UNIT, the caller has the option
 * of making the data a BYTES_PER_XDR_UNIT multiple (b_wptr - b_rptr is
 * a BYTES_PER_XDR_UNIT multiple), but in this case the caller has to ensure
 * that the filler bytes are initialized to zero. Note: Doesn't to work for
 * chained mblks.
 */
bool_t
xdrmblk_putmblk(XDR *xdrs, mblk_t *m, uint_t len)
{
	int32_t llen = (int32_t)len;

	if (((m->b_wptr - m->b_rptr) % BYTES_PER_XDR_UNIT) != 0)
		return (FALSE);
	if (!xdrmblk_putint32(xdrs, &llen))
		return (FALSE);
	/* LINTED pointer alignment */
	((mblk_t *)xdrs->x_base)->b_cont = m;
	xdrs->x_base = (caddr_t)m;
	xdrs->x_handy = 0;
	return (TRUE);
}

static uint_t
xdrmblk_getpos(XDR *xdrs)
{
	uint_t tmp;
	mblk_t *m;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;

	if (xdrs->x_op == XDR_DECODE)
		tmp = (uint_t)(m->b_rptr - m->b_datap->db_base);
	else
		tmp = (uint_t)(m->b_wptr - m->b_datap->db_base);
	return (tmp);

}

static bool_t
xdrmblk_setpos(XDR *xdrs, uint_t pos)
{
	mblk_t *m;
	unsigned char *newaddr;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);

	/* calculate the new address from the base */
	newaddr = m->b_datap->db_base + pos;

	if (xdrs->x_op == XDR_DECODE) {
		if (newaddr > m->b_wptr)
			return (FALSE);
		m->b_rptr = newaddr;
		xdrs->x_handy = (int)(m->b_wptr - newaddr);
	} else {
		if (newaddr > m->b_datap->db_lim)
			return (FALSE);
		m->b_wptr = newaddr;
		xdrs->x_handy = (int)(m->b_datap->db_lim - newaddr);
	}

	return (TRUE);
}

#ifdef DEBUG
static int xdrmblk_inline_hits = 0;
static int xdrmblk_inline_misses = 0;
static int do_xdrmblk_inline = 1;
#endif

static rpc_inline_t *
xdrmblk_inline(XDR *xdrs, int len)
{
	rpc_inline_t *buf;
	mblk_t *m;

	/*
	 * Can't inline XDR_FREE calls, doesn't make sense.
	 */
	if (xdrs->x_op == XDR_FREE)
		return (NULL);

	/*
	 * Can't inline if there isn't enough room, don't have an
	 * mblk pointer, its not 4 byte aligned, or if there is more than
	 * one reference to the data block associated with this mblk.  This last
	 * check is used because the caller may want to modified
	 * the data in the inlined portion and someone else is
	 * holding a reference to the data who may not want it
	 * to be modified.
	 */
	if (xdrs->x_handy < len ||
	    /* LINTED pointer alignment */
	    (m = (mblk_t *)xdrs->x_base) == NULL ||
	    !IS_P2ALIGNED(m->b_rptr, sizeof (int32_t)) ||
	    m->b_datap->db_ref != 1) {
#ifdef DEBUG
		xdrmblk_inline_misses++;
#endif
		return (NULL);
	}

#ifdef DEBUG
	if (!do_xdrmblk_inline) {
		xdrmblk_inline_misses++;
		return (NULL);
	}
#endif

	xdrs->x_handy -= len;
	if (xdrs->x_op == XDR_DECODE) {
		/* LINTED pointer alignment */
		buf = (rpc_inline_t *)m->b_rptr;
		m->b_rptr += len;
	} else {
		/* LINTED pointer alignment */
		buf = (rpc_inline_t *)m->b_wptr;
		m->b_wptr += len;
	}
#ifdef DEBUG
	xdrmblk_inline_hits++;
#endif
	return (buf);
}

static bool_t
xdrmblk_control(XDR *xdrs, int request, void *info)
{
	mblk_t *m;
	int32_t *int32p;
	int len;

	switch (request) {
	case XDR_PEEK:
		/*
		 * Return the next 4 byte unit in the XDR stream.
		 */
		if (xdrs->x_handy < sizeof (int32_t))
			return (FALSE);

		/* LINTED pointer alignment */
		m = (mblk_t *)xdrs->x_base;
		if (m == NULL)
			return (FALSE);

		/*
		 * If the pointer is not aligned, fail the peek
		 */
		if (!IS_P2ALIGNED(m->b_rptr, sizeof (int32_t)))
			return (FALSE);

		int32p = (int32_t *)info;
		/* LINTED pointer alignment */
		*int32p = ntohl(*((int32_t *)(m->b_rptr)));
		return (TRUE);

	case XDR_SKIPBYTES:
		/* LINTED pointer alignment */
		m = (mblk_t *)xdrs->x_base;
		if (m == NULL)
			return (FALSE);
		int32p = (int32_t *)info;
		len = RNDUP((int)(*int32p));
		if (len < 0)
			return (FALSE);
		while ((xdrs->x_handy -= len) < 0) {
			if ((xdrs->x_handy += len) > 0) {
				m->b_rptr += xdrs->x_handy;
				len -= xdrs->x_handy;
			}
			m = m->b_cont;
			xdrs->x_base = (caddr_t)m;
			if (m == NULL) {
				xdrs->x_handy = 0;
				return (FALSE);
			}
			xdrs->x_handy = (int)(m->b_wptr - m->b_rptr);
		}
		m->b_rptr += len;
		return (TRUE);

	default:
		return (FALSE);
	}
}

#define	HDR_SPACE	128

static mblk_t *
xdrmblk_alloc(int sz)
{
	mblk_t *mp;

	if (sz == 0)
		return (NULL);

	/*
	 * Pad the front of the message to allow the lower networking
	 * layers space to add headers as needed.
	 */
	sz += HDR_SPACE;

	while ((mp = allocb(sz, BPRI_LO)) == NULL) {
		if (strwaitbuf(sz, BPRI_LO))
			return (NULL);
	}

	mp->b_wptr += HDR_SPACE;
	mp->b_rptr = mp->b_wptr;

	return (mp);
}

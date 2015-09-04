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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
static void xdrmblk_skip_fully_read_mblks(XDR *);

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
 * The xdrmblk_params structure holds the internal data for the XDR stream.
 * The x_private member of the XDR points to this structure.  The
 * xdrmblk_params structure is dynamically allocated in xdrmblk_init() and
 * freed in xdrmblk_destroy().
 *
 * The apos and rpos members of the xdrmblk_params structure are used to
 * implement xdrmblk_getpos() and xdrmblk_setpos().
 *
 * In addition to the xdrmblk_params structure we store some additional
 * internal data directly in the XDR stream structure:
 *
 * x_base	A pointer to the current mblk (that one we are currently
 * 		working with).
 * x_handy	The number of available bytes (either for read or for write) in
 * 		the current mblk.
 */
struct xdrmblk_params {
	int sz;
	uint_t apos;	/* Absolute position of the current mblk */
	uint_t rpos;	/* Relative position in the current mblk */
};

/*
 * Initialize xdr stream.
 */
void
xdrmblk_init(XDR *xdrs, mblk_t *m, enum xdr_op op, int sz)
{
	struct xdrmblk_params *p;

	xdrs->x_op = op;
	xdrs->x_ops = &xdrmblk_ops;
	xdrs->x_base = (caddr_t)m;
	xdrs->x_public = NULL;
	p = kmem_alloc(sizeof (struct xdrmblk_params), KM_SLEEP);
	xdrs->x_private = (caddr_t)p;

	p->sz = sz;
	p->apos = 0;
	p->rpos = 0;

	if (op == XDR_DECODE) {
		xdrs->x_handy = (int)MBLKL(m);
	} else {
		xdrs->x_handy = (int)MBLKTAIL(m);
		if (p->sz < sizeof (int32_t))
			p->sz = sizeof (int32_t);
	}
}

static void
xdrmblk_destroy(XDR *xdrs)
{
	kmem_free(xdrs->x_private, sizeof (struct xdrmblk_params));
}

static bool_t
xdrmblk_getint32(XDR *xdrs, int32_t *int32p)
{
	mblk_t *m;
	struct xdrmblk_params *p;

	xdrmblk_skip_fully_read_mblks(xdrs);

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);

	p = (struct xdrmblk_params *)xdrs->x_private;

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
		p->apos += p->rpos;
		p->rpos = 0;
		xdrs->x_handy = (int)MBLKL(m);
	}

	/* LINTED pointer alignment */
	*int32p = ntohl(*((int32_t *)(m->b_rptr)));
	m->b_rptr += sizeof (int32_t);
	xdrs->x_handy -= sizeof (int32_t);
	p->rpos += sizeof (int32_t);

	return (TRUE);
}

static bool_t
xdrmblk_putint32(XDR *xdrs, int32_t *int32p)
{
	mblk_t *m;
	struct xdrmblk_params *p;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);

	p = (struct xdrmblk_params *)xdrs->x_private;

	while (!IS_P2ALIGNED(m->b_wptr, sizeof (int32_t)) ||
	    xdrs->x_handy < sizeof (int32_t)) {
		if (m->b_cont == NULL) {
			ASSERT(p->sz >= sizeof (int32_t));
			m->b_cont = xdrmblk_alloc(p->sz);
		}
		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		p->apos += p->rpos;
		p->rpos = 0;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)MBLKTAIL(m);
		ASSERT(m->b_rptr == m->b_wptr);
		ASSERT(m->b_rptr >= m->b_datap->db_base);
		ASSERT(m->b_rptr < m->b_datap->db_lim);
	}
	/* LINTED pointer alignment */
	*(int32_t *)m->b_wptr = htonl(*int32p);
	m->b_wptr += sizeof (int32_t);
	xdrs->x_handy -= sizeof (int32_t);
	p->rpos += sizeof (int32_t);
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
	struct xdrmblk_params *p;
	int i;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);

	p = (struct xdrmblk_params *)xdrs->x_private;

	/*
	 * Performance tweak: converted explicit bcopy()
	 * call to simple in-line. This function is called
	 * to process things like readdir reply filenames
	 * which are small strings--typically 12 bytes or less.
	 * Overhead of calling bcopy() is obnoxious for such
	 * small copies.
	 */
	while (xdrs->x_handy < len) {
		if (xdrs->x_handy > 0) {
			if (xdrs->x_handy < XDRMBLK_BCOPY_LIMIT) {
				for (i = 0; i < xdrs->x_handy; i++)
					*addr++ = *m->b_rptr++;
			} else {
				bcopy(m->b_rptr, addr, xdrs->x_handy);
				m->b_rptr += xdrs->x_handy;
				addr += xdrs->x_handy;
			}
			len -= xdrs->x_handy;
			p->rpos += xdrs->x_handy;
		}
		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		p->apos += p->rpos;
		p->rpos = 0;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)MBLKL(m);
	}

	xdrs->x_handy -= len;
	p->rpos += len;

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
	struct xdrmblk_params *p;
	int len;
	uint32_t llen;

	if (!xdrmblk_getint32(xdrs, (int32_t *)&llen))
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

	p = (struct xdrmblk_params *)xdrs->x_private;
	p->apos += p->rpos + llen;
	p->rpos = 0;

	return (TRUE);
}

static bool_t
xdrmblk_putbytes(XDR *xdrs, caddr_t addr, int len)
{
	mblk_t *m;
	struct xdrmblk_params *p;
	int i;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return (FALSE);

	p = (struct xdrmblk_params *)xdrs->x_private;

	/*
	 * Performance tweak: converted explicit bcopy()
	 * call to simple in-line. This function is called
	 * to process things like readdir reply filenames
	 * which are small strings--typically 12 bytes or less.
	 * Overhead of calling bcopy() is obnoxious for such
	 * small copies.
	 */
	while (xdrs->x_handy < len) {
		if (xdrs->x_handy > 0) {
			if (xdrs->x_handy < XDRMBLK_BCOPY_LIMIT) {
				for (i = 0; i < xdrs->x_handy; i++)
					*m->b_wptr++ = *addr++;
			} else {
				bcopy(addr, m->b_wptr, xdrs->x_handy);
				m->b_wptr += xdrs->x_handy;
				addr += xdrs->x_handy;
			}
			len -= xdrs->x_handy;
			p->rpos += xdrs->x_handy;
		}

		/*
		 * We don't have enough space, so allocate the
		 * amount we need, or sz, whichever is larger.
		 * It is better to let the underlying transport divide
		 * large chunks than to try and guess what is best.
		 */
		if (m->b_cont == NULL)
			m->b_cont = xdrmblk_alloc(MAX(len, p->sz));

		m = m->b_cont;
		xdrs->x_base = (caddr_t)m;
		p->apos += p->rpos;
		p->rpos = 0;
		if (m == NULL) {
			xdrs->x_handy = 0;
			return (FALSE);
		}
		xdrs->x_handy = (int)MBLKTAIL(m);
		ASSERT(m->b_rptr == m->b_wptr);
		ASSERT(m->b_rptr >= m->b_datap->db_base);
		ASSERT(m->b_rptr < m->b_datap->db_lim);
	}

	xdrs->x_handy -= len;
	p->rpos += len;

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
 * that the filler bytes are initialized to zero.
 */
bool_t
xdrmblk_putmblk(XDR *xdrs, mblk_t *m, uint_t len)
{
	struct xdrmblk_params *p;
	int32_t llen = (int32_t)len;

	if ((DLEN(m) % BYTES_PER_XDR_UNIT) != 0)
		return (FALSE);
	if (!xdrmblk_putint32(xdrs, &llen))
		return (FALSE);

	p = (struct xdrmblk_params *)xdrs->x_private;

	/* LINTED pointer alignment */
	((mblk_t *)xdrs->x_base)->b_cont = m;
	p->apos += p->rpos;

	/* base points to the last mblk */
	while (m->b_cont) {
		p->apos += MBLKL(m);
		m = m->b_cont;
	}
	xdrs->x_base = (caddr_t)m;
	xdrs->x_handy = 0;
	p->rpos = MBLKL(m);
	return (TRUE);
}

static uint_t
xdrmblk_getpos(XDR *xdrs)
{
	struct xdrmblk_params *p = (struct xdrmblk_params *)xdrs->x_private;

	return (p->apos + p->rpos);
}

static bool_t
xdrmblk_setpos(XDR *xdrs, uint_t pos)
{
	mblk_t *m;
	struct xdrmblk_params *p;

	p = (struct xdrmblk_params *)xdrs->x_private;

	if (pos < p->apos)
		return (FALSE);

	if (pos > p->apos + p->rpos + xdrs->x_handy)
		return (FALSE);

	if (pos == p->apos + p->rpos)
		return (TRUE);

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	ASSERT(m != NULL);

	if (xdrs->x_op == XDR_DECODE)
		m->b_rptr = m->b_rptr - p->rpos + (pos - p->apos);
	else
		m->b_wptr = m->b_wptr - p->rpos + (pos - p->apos);

	xdrs->x_handy = p->rpos + xdrs->x_handy - (pos - p->apos);
	p->rpos = pos - p->apos;

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
	unsigned char **mptr;
	struct xdrmblk_params *p;

	/*
	 * Can't inline XDR_FREE calls, doesn't make sense.
	 */
	if (xdrs->x_op == XDR_FREE)
		return (NULL);

#ifdef DEBUG
	if (!do_xdrmblk_inline) {
		xdrmblk_inline_misses++;
		return (NULL);
	}
#endif

	if (xdrs->x_op == XDR_DECODE)
		xdrmblk_skip_fully_read_mblks(xdrs);

	/*
	 * Can't inline if there isn't enough room.
	 */
	if (len <= 0 || xdrs->x_handy < len) {
#ifdef DEBUG
		xdrmblk_inline_misses++;
#endif
		return (NULL);
	}

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	ASSERT(m != NULL);

	if (xdrs->x_op == XDR_DECODE) {
		/* LINTED pointer alignment */
		mptr = &m->b_rptr;
	} else {
		/* LINTED pointer alignment */
		mptr = &m->b_wptr;
	}

	/*
	 * Can't inline if the buffer is not 4 byte aligned, or if there is
	 * more than one reference to the data block associated with this mblk.
	 * This last check is used because the caller may want to modify the
	 * data in the inlined portion and someone else is holding a reference
	 * to the data who may not want it to be modified.
	 */
	if (!IS_P2ALIGNED(*mptr, sizeof (int32_t)) ||
	    m->b_datap->db_ref != 1) {
#ifdef DEBUG
		xdrmblk_inline_misses++;
#endif
		return (NULL);
	}

	buf = (rpc_inline_t *)*mptr;

	p = (struct xdrmblk_params *)xdrs->x_private;

	*mptr += len;
	xdrs->x_handy -= len;
	p->rpos += len;

#ifdef DEBUG
	xdrmblk_inline_hits++;
#endif

	return (buf);
}

static bool_t
xdrmblk_control(XDR *xdrs, int request, void *info)
{
	mblk_t *m;
	struct xdrmblk_params *p;
	int32_t *int32p;
	int len;

	switch (request) {
	case XDR_PEEK:
		xdrmblk_skip_fully_read_mblks(xdrs);

		/*
		 * Return the next 4 byte unit in the XDR stream.
		 */
		if (xdrs->x_handy < sizeof (int32_t))
			return (FALSE);

		/* LINTED pointer alignment */
		m = (mblk_t *)xdrs->x_base;
		ASSERT(m != NULL);

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
		int32p = (int32_t *)info;
		len = RNDUP((int)(*int32p));
		if (len < 0)
			return (FALSE);
		if (len == 0)
			return (TRUE);

		/* LINTED pointer alignment */
		m = (mblk_t *)xdrs->x_base;
		if (m == NULL)
			return (FALSE);

		p = (struct xdrmblk_params *)xdrs->x_private;

		while (xdrs->x_handy < len) {
			if (xdrs->x_handy > 0) {
				m->b_rptr += xdrs->x_handy;
				len -= xdrs->x_handy;
				p->rpos += xdrs->x_handy;
			}
			m = m->b_cont;
			xdrs->x_base = (caddr_t)m;
			p->apos += p->rpos;
			p->rpos = 0;
			if (m == NULL) {
				xdrs->x_handy = 0;
				return (FALSE);
			}
			xdrs->x_handy = (int)MBLKL(m);
		}

		xdrs->x_handy -= len;
		p->rpos += len;
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

/*
 * Skip fully read or empty mblks
 */
static void
xdrmblk_skip_fully_read_mblks(XDR *xdrs)
{
	mblk_t *m;
	struct xdrmblk_params *p;

	if (xdrs->x_handy != 0)
		return;

	/* LINTED pointer alignment */
	m = (mblk_t *)xdrs->x_base;
	if (m == NULL)
		return;

	p = (struct xdrmblk_params *)xdrs->x_private;
	p->apos += p->rpos;
	p->rpos = 0;

	do {
		m = m->b_cont;
		if (m == NULL)
			break;

		xdrs->x_handy = (int)MBLKL(m);
	} while (xdrs->x_handy == 0);

	xdrs->x_base = (caddr_t)m;
}

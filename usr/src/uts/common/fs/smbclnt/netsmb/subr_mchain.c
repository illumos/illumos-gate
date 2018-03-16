/*
 * Copyright (c) 2000, 2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/kern/subr_mchain.c,v 1.1 2001/02/24 15:44:29 bp Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/mchain.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

/* BEGIN CSTYLED */
/*
 * BSD-style mbufs, vs SysV-style mblks:
 * One big difference: the mbuf payload is:
 *   m_data ... (m_data + m_len)
 * In Unix STREAMS, the mblk payload is:
 *   b_rptr ... b_wptr
 *
 * Here are some handy conversion notes:
 *
 * struct mbuf                     struct mblk
 *   m->m_next                       m->b_cont
 *   m->m_nextpkt                    m->b_next
 *   m->m_data                       m->b_rptr
 *   m->m_len                        MBLKL(m)
 *   m->m_dat[]                      m->b_datap->db_base
 *   &m->m_dat[MLEN]                 m->b_datap->db_lim
 *   M_TRAILINGSPACE(m)              MBLKTAIL(m)
 *   m_freem(m)                      freemsg(m)
 *
 * Note that mbufs chains also have a special "packet" header,
 * which has the length of the whole message.  In STREAMS one
 * typically just calls msgdsize(m) to get that.
 */
/* END CSTYLED */


/*
 *
 * MODULE_VERSION(libmchain, 1);
 */

#ifdef __GNUC__
#define	MBERROR(format, args...) printf("%s(%d): "format, \
				    __FUNCTION__, __LINE__, ## args)
#define	MBPANIC(format, args...) printf("%s(%d): "format, \
				    __FUNCTION__, __LINE__, ## args)
#else
#define	MBERROR(...) \
	smb_errmsg(CE_NOTE, __func__, __VA_ARGS__)
#define	MBPANIC(...) \
	smb_errmsg(CE_PANIC, __func__, __VA_ARGS__)
#endif

/*
 * MLEN: The smallest mblk we'll allocate.
 *
 * There's more to MLEN than you might think.
 * Some ethernet drivers may send each mblk as a
 * separate frame, so we want MLEN at least 1K.
 * We could have used 1K here, but that might
 * hurt transports that support larger frames.
 * 4K fits nicely in 3 Ethernet frames (3 * 1500)
 * leaving about 500 bytes for protocol headers.
 */
#define	MLEN	4096

#if (MLEN < SMB2_HDRLEN)
#error "MLEN can't fit a contiguous SMB2 header"
#endif

/*
 * Some UIO routines.
 * Taken from Darwin Sourcecs.
 */

/*
 * uio_isuserspace - non zero value if the address space
 * flag is for a user address space (could be 32 or 64 bit).
 */
#define	uio_isuserspace(uio) (uio->uio_segflg == UIO_USERSPACE)

/*
 * uio_curriovbase - return the base address of the current iovec associated
 *      with the given uio_t.  May return 0.
 */
caddr_t
uio_curriovbase(uio_t *a_uio)
{
	if (a_uio->uio_iovcnt < 1) {
		return (0);
	}
	return ((caddr_t)((uintptr_t)a_uio->uio_iov->iov_base));
}

/*
 * uio_curriovlen - return the length value of the current iovec associated
 *      with the given uio_t.
 */
size_t
uio_curriovlen(uio_t *a_uio)
{
	if (a_uio->uio_iovcnt < 1) {
		return (0);
	}
	return ((size_t)a_uio->uio_iov->iov_len);
}


/*
 * uio_update - update the given uio_t for a_count of completed IO.
 *      This call decrements the current iovec length and residual IO value
 *      and increments the current iovec base address and offset value.
 *      If the current iovec length is 0 then advance to the next
 *      iovec (if any).
 *      If the a_count passed in is 0, than only do the advancement
 *      over any 0 length iovec's.
 */
void
uio_update(uio_t *a_uio, size_t a_count)
{
	if (a_uio->uio_iovcnt < 1) {
		return;
	}

	/*
	 * if a_count == 0, then we are asking to skip over
	 * any empty iovs
	 */
	if (a_count) {
		if (a_count > a_uio->uio_iov->iov_len) {
			a_uio->uio_iov->iov_base += a_uio->uio_iov->iov_len;
			a_uio->uio_iov->iov_len = 0;
		} else {
			a_uio->uio_iov->iov_base += a_count;
			a_uio->uio_iov->iov_len -= a_count;
		}
		if (a_uio->uio_resid < 0) {
			a_uio->uio_resid = 0;
		}
		if (a_count > (size_t)a_uio->uio_resid) {
			a_uio->uio_loffset += a_uio->uio_resid;
			a_uio->uio_resid = 0;
		} else {
			a_uio->uio_loffset += a_count;
			a_uio->uio_resid -= a_count;
		}
	}
	/*
	 * advance to next iovec if current one is totally consumed
	 */
	while (a_uio->uio_iovcnt > 0 && a_uio->uio_iov->iov_len == 0) {
		a_uio->uio_iovcnt--;
		if (a_uio->uio_iovcnt > 0) {
			a_uio->uio_iov++;
		}
	}
}

/*
 * This is now used only to extend an existing mblk chain,
 * so don't need to use allocb_cred_wait here.
 */
/*ARGSUSED*/
mblk_t *
m_getblk(int size, int type)
{
	mblk_t *mblk;
	int error;

	/* Make size at least MLEN. */
	if (size < MLEN)
		size = MLEN;
	mblk = allocb_wait(size, BPRI_LO, STR_NOSIG, &error);
	ASSERT(mblk);
	return (mblk);
}

void
mb_done(struct mbchain *mbp)
{
	if (mbp->mb_top) {
		freemsg(mbp->mb_top);
		mbp->mb_top = NULL;
	}
	/* Avoid dangling references */
	mbp->mb_cur = NULL;
}

unsigned int
m_length(mblk_t *mblk)
{
	uint64_t diff;

	diff = (uintptr_t)mblk->b_datap->db_lim -
	    (uintptr_t)mblk->b_datap->db_base;
	ASSERT(diff == (uint64_t)((unsigned int)diff));
	return ((unsigned int)diff);
}

void
mb_initm(struct mbchain *mbp, mblk_t *m)
{
	bzero(mbp, sizeof (*mbp));
	mbp->mb_top = mbp->mb_cur = m;
}


int
mb_init(struct mbchain *mbp)
{
	cred_t *cr;
	mblk_t *mblk;
	int error;

	/*
	 * This message will be the head of a new mblk chain,
	 * so we'd like its db_credp set.  If we extend this
	 * chain later, we'll just use allocb_wait()
	 */
	cr = ddi_get_cred();
	mblk = allocb_cred_wait(MLEN, STR_NOSIG, &error, cr, NOPID);

	/*
	 * Leave room in this first mblk so we can
	 * prepend a 4-byte NetBIOS header.
	 * See smb_nbst_send()
	 */
	mblk->b_wptr += 4;
	mblk->b_rptr = mblk->b_wptr;

	mb_initm(mbp, mblk);
	return (0);
}


/*
 * mb_detach() function returns the value of mbp->mb_top field
 * and sets its * value to NULL.
 */

mblk_t *
mb_detach(struct mbchain *mbp)
{
	mblk_t *m;

	m = mbp->mb_top;
	mbp->mb_top = mbp->mb_cur = NULL;
	return (m);
}

/*
 * Returns the length of the mblk_t data.
 * Should be m_totlen() perhaps?
 */
int
m_fixhdr(mblk_t *m0)
{
	size_t dsz;

	dsz = msgdsize(m0);
	return ((int)dsz);
}

/*
 * BSD code set the message header length here, and
 * returned the length.  We don't have that field, so
 * just return the message length.
 */
int
mb_fixhdr(struct mbchain *mbp)
{
	return (m_fixhdr(mbp->mb_top));
}


/*
 * Check if object of size 'size' fit to the current position and
 * allocate new mbuf if not. Advance pointers and increase len. of mbuf(s).
 * Return pointer to the object placeholder or NULL if any error occured.
 * Note: size should be <= MLEN
 */
void *
mb_reserve(struct mbchain *mbp, int size)
{
	mblk_t *m, *mn;
	void *bpos;

	m = mbp->mb_cur;
	/*
	 * If the requested size is more than the space left.
	 * Allocate and appenad a new mblk.
	 */
	if (MBLKTAIL(m) < size) {
		mn = m_getblk(size, 1);
		if (mn == NULL)
			return (NULL);
		mbp->mb_cur = m->b_cont = mn;
		m = mn;
	}
	/*
	 * If 'size' bytes fits into the buffer, then
	 * 1. increment the write pointer to the size.
	 * 2. return the position from where the memory is reserved.
	 */
	bpos = m->b_wptr;
	m->b_wptr += size;
	mbp->mb_count += size;
	return (bpos);
}

/*
 * All mb_put_*() functions perform an actual copy of the data into mbuf
 * chain. Functions which have le or be suffixes will perform conversion to
 * the little- or big-endian data formats.
 *
 * Inline version of mb_put_mem().  Handles the easy case in-line,
 * and calls mb_put_mem() if crossing mblk boundaries, etc.
 *
 * We build with -xspace, which causes these inline functions
 * to not be inlined.  Using macros instead for now.
 */
#ifdef	INLINE_WORKS

static inline int
mb_put_inline(struct mbchain *mbp, void *src, int size)
{
	mblk_t *m = mbp->mb_cur;

	if (m != NULL && size <= MBLKTAIL(m)) {
		uchar_t *p = src;
		int n = size;
		while (n--)
			*(m->b_wptr)++ = *p++;
		mbp->mb_count += size;
		return (0);
	}
	return (mb_put_mem(mbp, src, size, MB_MINLINE));
}
#define	MB_PUT_INLINE(MBP, SRC, SZ) \
	return (mb_put_inline(MBP, SRC, SZ))

#else /* INLINE_WORKS */

#define	MB_PUT_INLINE(MBP, SRC, SZ) \
	mblk_t *m = MBP->mb_cur; \
	if (m != NULL && SZ <= MBLKTAIL(m)) { \
		uchar_t *p = (void *) SRC; \
		int n = SZ; \
		while (n--) \
			*(m->b_wptr)++ = *p++; \
		MBP->mb_count += SZ; \
		return (0); \
	} \
	return (mb_put_mem(MBP, SRC, SZ, MB_MINLINE))

#endif /* INLINE_WORKS */

/*
 * Assumes total data length in previous mblks is EVEN.
 * Might need to compute the offset from mb_top instead.
 */
int
mb_put_padbyte(struct mbchain *mbp)
{
	uintptr_t dst;
	char v = 0;

	dst = (uintptr_t)mbp->mb_cur->b_wptr;
	/* only add padding if address is odd */
	if (dst & 1) {
		MB_PUT_INLINE(mbp, &v, sizeof (v));
	}

	return (0);
}

/*
 * Adds padding to 8 byte boundary
 */
int
mb_put_align8(struct mbchain *mbp)
{
	static const char zeros[8] = { 0 };
	int pad_len = 0;

	if ((mbp->mb_count % 8) != 0) {
		pad_len = 8 - (mbp->mb_count % 8);
		MB_PUT_INLINE(mbp, zeros, pad_len);
	}
	return (0);
}

int
mb_put_uint8(struct mbchain *mbp, u_int8_t x)
{
	u_int8_t v = x;
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint16be(struct mbchain *mbp, u_int16_t x)
{
	u_int16_t v = htobes(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint16le(struct mbchain *mbp, u_int16_t x)
{
	u_int16_t v = htoles(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint32be(struct mbchain *mbp, u_int32_t x)
{
	u_int32_t v = htobel(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint32le(struct mbchain *mbp, u_int32_t x)
{
	u_int32_t v = htolel(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint64be(struct mbchain *mbp, u_int64_t x)
{
	u_int64_t v = htobeq(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

int
mb_put_uint64le(struct mbchain *mbp, u_int64_t x)
{
	u_int64_t v = htoleq(x);
	MB_PUT_INLINE(mbp, &v, sizeof (v));
}

/*
 * mb_put_mem() function copies size bytes of data specified by the source
 * argument to an mbuf chain.  The type argument specifies the method used
 * to perform a copy
 */
int
mb_put_mem(struct mbchain *mbp, const void *vsrc, int size, int type)
{
	mblk_t *n, *m = mbp->mb_cur;
	c_caddr_t source = vsrc;
	c_caddr_t src;
	caddr_t dst;
	uint64_t diff;
	int cplen, mleft, count;

	diff = MBLKTAIL(m);
	ASSERT(diff == (uint64_t)((int)diff));
	mleft = (int)diff;

	while (size > 0) {
		if (mleft == 0) {
			if (m->b_cont == NULL) {
				/*
				 * Changed m_getm() to m_getblk()
				 * with the requested size, so we
				 * don't need m_getm() anymore.
				 */
				n = m_getblk(size, 1);
				if (n == NULL)
					return (ENOBUFS);
				m->b_cont = n;
			}
			m = m->b_cont;
			diff = MBLKTAIL(m);
			ASSERT(diff == (uint64_t)((int)diff));
			mleft = (int)diff;
			continue;
		}
		cplen = mleft > size ? size : mleft;
		dst = (caddr_t)m->b_wptr;
		switch (type) {
		case MB_MINLINE:
			for (src = source, count = cplen; count; count--)
				*dst++ = *src++;
			break;
		case MB_MSYSTEM:
			bcopy(source, dst, cplen);
			break;
		case MB_MUSER:
			if (copyin((void *)source, dst, cplen))
				return (EFAULT);
			break;
		case MB_MZERO:
			bzero(dst, cplen);
			break;
		}
		size -= cplen;
		source += cplen;
		mleft -= cplen;
		m->b_wptr += cplen;
		mbp->mb_count += cplen;
	}
	mbp->mb_cur = m;
	return (0);
}

/*
 * Append an mblk to the chain.
 * Note: The mblk_t *m is consumed.
 */
int
mb_put_mbuf(struct mbchain *mbp, mblk_t *m)
{
	mblk_t *nm, *tail_mb;
	size_t size;

	/* See: linkb(9f) */
	tail_mb = mbp->mb_cur;
	while (tail_mb->b_cont != NULL)
		tail_mb = tail_mb->b_cont;

	/*
	 * Avoid small frags:  Only link if the size of the
	 * new mbuf is larger than the space left in the last
	 * mblk of the chain (tail), otherwise just copy.
	 */
	while (m != NULL) {
		size = MBLKL(m);
		if (size > MBLKTAIL(tail_mb)) {
			/* Link */
			tail_mb->b_cont = m;
			mbp->mb_cur = m;
			mbp->mb_count += msgdsize(m);
			return (0);
		}
		/* Copy */
		bcopy(m->b_rptr, tail_mb->b_wptr, size);
		tail_mb->b_wptr += size;
		mbp->mb_count += size;
		nm = unlinkb(m);
		freeb(m);
		m = nm;
	}

	return (0);
}

/*
 * Put an mbchain into another mbchain
 * Leave sub_mbp untouched.
 */
int
mb_put_mbchain(struct mbchain *mbp, struct mbchain *sub_mbp)
{
	mblk_t *m;

	if (sub_mbp == NULL)
		return (0);

	m = sub_mbp->mb_top;
	if (m == NULL)
		return (0);

	m = dupmsg(m);
	if (m == NULL)
		return (ENOSR);

	return (mb_put_mbuf(mbp, m));
}

/*
 * copies a uio scatter/gather list to an mbuf chain.
 */
int
mb_put_uio(struct mbchain *mbp, uio_t *uiop, size_t size)
{
	size_t left;
	int mtype, error;

	mtype = (uio_isuserspace(uiop) ? MB_MUSER : MB_MSYSTEM);
	while (size > 0 && uiop->uio_resid) {
		if (uiop->uio_iovcnt <= 0 ||
		    uio_curriovbase(uiop) == USER_ADDR_NULL)
			return (EFBIG);
		left = uio_curriovlen(uiop);
		if (left > size)
			left = size;
		error = mb_put_mem(mbp, CAST_DOWN(caddr_t,
		    uio_curriovbase(uiop)), left, mtype);
		if (error)
			return (error);
		uio_update(uiop, left);
		size -= left;
	}
	return (0);
}

/*
 * Routines for fetching data from an mbuf chain
 */

void
md_initm(struct mdchain *mdp, mblk_t *m)
{
	bzero(mdp, sizeof (*mdp));
	mdp->md_top = mdp->md_cur = m;
	mdp->md_pos = m->b_rptr;
}

void
md_done(struct mdchain *mdp)
{
	mblk_t *m;

	/*
	 * Deal with the fact that we can error out of
	 * smb_t2_reply or smb_nt_reply without using up
	 * all the "records" added by md_append_record().
	 */
	while ((m = mdp->md_top) != NULL) {
		mdp->md_top = m->b_next;
		m->b_next = NULL;
		freemsg(m);
	}
	/* Avoid dangling references */
	mdp->md_cur = NULL;
	mdp->md_pos = NULL;
}

/*
 * Append a new message (separate mbuf chain).
 * It is caller responsibility to prevent
 * multiple calls to fetch/record routines.
 * Note unusual use of mblk->b_next here.
 */
void
md_append_record(struct mdchain *mdp, mblk_t *top)
{
	mblk_t *m;

	top->b_next = NULL;
	if (mdp->md_top == NULL) {
		md_initm(mdp, top);
		return;
	}
	m = mdp->md_top;
	/* Get to last message (not b_cont chain) */
	while (m->b_next)
		m = m->b_next;
	m->b_next = top;
}

/*
 * Advance mdp->md_top to the next message.
 * Note unusual use of mblk->b_next here.
 */
void
md_next_record(struct mdchain *mdp)
{
	mblk_t *m, *top;

	if ((top = mdp->md_top) == NULL)
		return;

	/*
	 * Get the next message, if any,
	 * stored by md_append_record.
	 * Note: NOT b_cont chain
	 */
	m = top->b_next;
	top->b_next = NULL;

	/* Done with old "top". */
	md_done(mdp);
	if (m == NULL)
		return;

	/* Setup new "top". */
	md_initm(mdp, m);
}

/*
 * Inline version of md_get_mem().  Handles the easy case in-line,
 * and calls md_get_mem() if crossing mblk boundaries, etc.
 */
#ifdef	INLINE_WORKS	/* see above */

static inline int
md_get_inline(struct mdchain *mdp, void *dst, int size)
{
	mblk_t *m = mdp->md_cur;

	if (m != NULL && mdp->md_pos + size <= m->b_wptr) {
		uchar_t *p = dst;
		int n = size;
		while (n--)
			*p++ = *(mdp->md_pos)++;
		/* no md_count += size */
		return (0);
	}
	return (md_get_mem(mdp, dst, size, MB_MINLINE));
}
#define	MD_GET_INLINE(MDP, DST, SZ) \
	error = md_get_inline(MDP, DST, SZ)

#else /* INLINE_WORKS */

/* Note, sets variable: error */
#define	MD_GET_INLINE(MDP, DST, SZ) \
	mblk_t *m = MDP->md_cur; \
	if (m != NULL && MDP->md_pos + SZ <= m->b_wptr) { \
		uchar_t *p = (void *) DST; \
		int n = SZ; \
		while (n--) \
			*p++ = *(mdp->md_pos)++; \
		/* no md_count += SZ */ \
		error = 0; \
	} else \
		error = md_get_mem(MDP, DST, SZ, MB_MINLINE)

#endif /* INLINE_WORKS */


int
md_get_uint8(struct mdchain *mdp, u_int8_t *x)
{
	uint8_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = v;
	return (error);
}

int
md_get_uint16be(struct mdchain *mdp, u_int16_t *x) {
	u_int16_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = betohs(v);
	return (error);
}

int
md_get_uint16le(struct mdchain *mdp, u_int16_t *x)
{
	u_int16_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = letohs(v);
	return (error);
}

int
md_get_uint32be(struct mdchain *mdp, u_int32_t *x)
{
	u_int32_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = betohl(v);
	return (error);
}

int
md_get_uint32le(struct mdchain *mdp, u_int32_t *x)
{
	u_int32_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = letohl(v);
	return (error);
}

int
md_get_uint64be(struct mdchain *mdp, u_int64_t *x)
{
	u_int64_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = betohq(v);
	return (error);
}

int
md_get_uint64le(struct mdchain *mdp, u_int64_t *x)
{
	u_int64_t v;
	int error;

	MD_GET_INLINE(mdp, &v, sizeof (v));
	if (x)
		*x = letohq(v);
	return (error);
}

int
md_get_mem(struct mdchain *mdp, void *vdst, int size, int type)
{
	mblk_t *m = mdp->md_cur;
	caddr_t target = vdst;
	unsigned char *s;
	uint64_t diff;
	int count;

	while (size > 0) {
		if (m == NULL) {
			SMBSDEBUG("incomplete copy\n");
			return (EBADRPC);
		}

		/*
		 * Offset in the current MBUF.
		 */
		s = mdp->md_pos;
		ASSERT((m->b_rptr <= s) && (s <= m->b_wptr));

		/* Data remaining. */
		diff = (uintptr_t)m->b_wptr - (uintptr_t)s;
		ASSERT(diff == (uint64_t)((int)diff));
		count = (int)diff;

		/*
		 * Check if the no. of bytes remaining is less than
		 * the bytes requested.
		 */
		if (count == 0) {
			m = m->b_cont;
			if (m) {
				mdp->md_cur = m;
				mdp->md_pos = s = m->b_rptr;
			}
			continue;
		}
		if (count > size)
			count = size;
		size -= count;
		mdp->md_pos += count;
		if (target == NULL)
			continue;
		switch (type) {
		case MB_MUSER:
			if (copyout(s, target, count))
				return (EFAULT);
			break;
		case MB_MSYSTEM:
			bcopy(s, target, count);
			break;
		case MB_MINLINE:
			while (count--)
				*target++ = *s++;
			continue;
		}
		target += count;
	}
	return (0);
}

/*
 * Get the next SIZE bytes as a separate mblk.
 * Advances position in mdp by SIZE.
 */
int
md_get_mbuf(struct mdchain *mdp, int size, mblk_t **ret)
{
	mblk_t *m, *rm;

	unsigned char *s;
	uint64_t diff;
	int off;

	/*
	 * Offset in the current MBUF.
	 */
	m = mdp->md_cur;
	s = mdp->md_pos;
	ASSERT((m->b_rptr <= s) && (s <= m->b_wptr));
	diff = (uintptr_t)s - (uintptr_t)m->b_rptr;
	ASSERT(diff == (uint64_t)((int)diff));
	off = (int)diff;

	rm = m_copym(m, off, size, M_WAITOK);
	if (rm == NULL)
		return (EBADRPC);
	(void) md_get_mem(mdp, NULL, size, MB_MSYSTEM);

	*ret = rm;
	return (0);
}

int
md_get_uio(struct mdchain *mdp, uio_t *uiop, size_t size)
{
	size_t left;
	int mtype, error;

	mtype = (uio_isuserspace(uiop) ? MB_MUSER : MB_MSYSTEM);
	while (size > 0 && uiop->uio_resid) {
		if (uiop->uio_iovcnt <= 0 ||
		    uio_curriovbase(uiop) == USER_ADDR_NULL)
			return (EFBIG);
		left = uio_curriovlen(uiop);
		if (left > size)
			left = size;
		error = md_get_mem(mdp, CAST_DOWN(caddr_t,
		    uio_curriovbase(uiop)), left, mtype);
		if (error)
			return (error);
		uio_update(uiop, left);
		size -= left;
	}
	return (0);
}

/*
 * Additions for Solaris
 */

/*
 * concatenate mblk chain n to m.
 * go till end of data in m.
 * then add the link of b_cont to n.
 * See: linkb(9f)
 */

void m_cat(
	mblk_t *m,
	mblk_t *n)
{
	if (!n)
		return;
	while (m->b_cont) {
		m = m->b_cont;
	}
	m->b_cont = n;
}

/*ARGSUSED*/
mblk_t *
m_copym(mblk_t *m, int off, int len, int wait)
{
	mblk_t *n;
	size_t dsz;
	ssize_t adj;

	dsz = msgdsize(m);
	if (len == M_COPYALL) {
		if (off > dsz)
			return (0);
	} else {
		if ((off + len) > dsz)
			return (0);
	}

	if ((n = dupmsg(m)) == NULL)
		return (0);

	/* trim from head */
	adj = off;
	if (!adjmsg(n, adj)) {
		freemsg(n);
		return (0);
	}

	/* trim from tail */
	if (len != M_COPYALL) {
		dsz = msgdsize(n);
		ASSERT(len <= dsz);
		if (len < dsz) {
			adj = (ssize_t)len - (ssize_t)dsz;
			ASSERT(adj < 0);
			(void) adjmsg(n, adj);
		}
	}

	return (n);
}

/*
 * Get "rqlen" contiguous bytes into the first mblk of a chain.
 */
mblk_t *
m_pullup(
	mblk_t *m,
	int rqlen)
{
	ptrdiff_t diff;

	diff = MBLKL(m);
	ASSERT(diff == (ptrdiff_t)((int)diff));
	if ((int)diff < rqlen) {
		/* This should be rare. */
		if (!pullupmsg(m, rqlen)) {
			SMBSDEBUG("pullupmsg failed!\n");
			freemsg(m);
			return (NULL);
		}
	}
	return (m);
}


/*
 * m_split : split the mblk from the offset(len0) to the end.
 * Partition an mbuf chain in two pieces, returning the tail --
 * all but the first len0 bytes.  In case of failure, it returns NULL and
 * attempts to restore the chain to its original state.
 * Similar to dupmsg() + adjmsg() on Solaris.
 */
/*ARGSUSED*/
mblk_t *
m_split(
	mblk_t *m0,
	int len0,
	int wait)
{
	mblk_t *m, *n;
	int mbl, len = len0;
	ptrdiff_t	diff;

#if 0 /* If life were simple, this would be: */
	for (m = m0; m && len > MBLKL(m); m = m->b_cont)
		len -= MBLKL(m);
#else /* but with LP64 and picky lint we have: */
	for (m = m0; m; m = m->b_cont) {
		diff = MBLKL(m);
		ASSERT(diff == (ptrdiff_t)((int)diff));
		mbl = (int)diff;
		if (len <= mbl)
			break;
		len -= mbl;
	}
#endif

	if (m == 0)
		return (0);

	/* This is the one to split (dupb, adjust) */
	if ((n = dupb(m)) == 0)
		return (0);

	ASSERT(len <= MBLKL(m));

	m->b_wptr = m->b_rptr + len;
	n->b_rptr += len;

	/* Move any b_cont (tail) to the new head. */
	n->b_cont = m->b_cont;
	m->b_cont = NULL;

	return (n);
}

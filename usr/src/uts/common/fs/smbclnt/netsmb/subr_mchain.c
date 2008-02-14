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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

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
 *
 * XXX: Would Ethernet drivers be happier
 * (more efficient) if we used 1K here?
 */
#define	MLEN	4096


/*
 * Some UIO routines.
 * Taken from Darwin Sourcecs.
 */

/*
 * uio_isuserspace - return non zero value if the address space
 * flag is for a user address space (could be 32 or 64 bit).
 */
int
uio_isuserspace(uio_t *a_uio)
{
	if (a_uio->uio_segflg == UIO_USERSPACE) {
		return (1);
	}
	return (0);
}

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
			a_uio->uio_offset += a_uio->uio_resid;
			a_uio->uio_resid = 0;
		} else {
			a_uio->uio_offset += a_count;
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
	mblk_t *mblk;

	mblk = m_getblk(MLEN, 1);
	if (mblk == NULL) {
		return (ENOSR);
	}

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
 *
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
	/*LINTED*/
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
 * XXX: Assumes total data length in previous mblks is EVEN.
 * XXX: Might need to compute the offset from mb_top instead.
 */
int
mb_put_padbyte(struct mbchain *mbp)
{
	caddr_t dst;
	char x = 0;

	dst = (caddr_t)mbp->mb_cur->b_wptr;

	/* only add padding if address is odd */
	if ((long)dst & 1)
		return (mb_put_mem(mbp, (caddr_t)&x, 1, MB_MSYSTEM));
	else
		return (0);
}

int
mb_put_uint8(struct mbchain *mbp, u_int8_t x)
{
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint16be(struct mbchain *mbp, u_int16_t x)
{
	x = htobes(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint16le(struct mbchain *mbp, u_int16_t x)
{
	x = htoles(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint32be(struct mbchain *mbp, u_int32_t x)
{
	x = htobel(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint32le(struct mbchain *mbp, u_int32_t x)
{
	x = htolel(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint64be(struct mbchain *mbp, u_int64_t x)
{
	x = htobeq(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

int
mb_put_uint64le(struct mbchain *mbp, u_int64_t x)
{
	x = htoleq(x);
	return (mb_put_mem(mbp, (caddr_t)&x, sizeof (x), MB_MSYSTEM));
}

/*
 * mb_put_mem() function copies size bytes of data specified by the source
 * argument to an mbuf chain.  The type argument specifies the method used
 * to perform a copy
 */
int
mb_put_mem(struct mbchain *mbp, c_caddr_t source, int size, int type)
{
	mblk_t *m, *n;
	caddr_t dst;
	c_caddr_t src;
	int cplen, error, mleft, count;
	uint64_t diff;

	m = mbp->mb_cur;

	/*LINTED*/
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
			/*LINTED*/
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
			/*
			 * Try copying the raw bytes instead of using bcopy()
			 */
			bcopy(source, dst, cplen);
			break;
		case MB_MUSER:
			error = copyin((void *)source, dst, cplen);
			if (error)
				return (error);
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
 */
int
mb_put_mbuf(struct mbchain *mbp, mblk_t *m)
{
	mblk_t *mb;

	/* See: linkb(9f) */
	for (mb = mbp->mb_cur; mb->b_cont; mb = mb->b_cont)
		;
	mb->b_cont = m;
	mbp->mb_cur = m;
	mbp->mb_count += msgdsize(m);

	return (0);
}

/*
 * copies a uio scatter/gather list to an mbuf chain.
 */
int
mb_put_uio(struct mbchain *mbp, uio_t *uiop, int size)
{
	int left;
	int mtype, error;

	mtype = (uio_isuserspace(uiop) ? MB_MUSER : MB_MSYSTEM);

	while (size > 0 && uiop->uio_resid) {
		if (uiop->uio_iovcnt <= 0 || uio_curriovbase(uiop) ==
		    USER_ADDR_NULL)
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
int
md_init(struct mdchain *mdp)
{
	mblk_t *m;

	m = m_getblk(MLEN, 1);
	if (m == NULL)
		return (ENOBUFS);
	md_initm(mdp, m);
	return (0);
}

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
 * XXX: Note (mis)use of mblk->b_next here.
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
 * XXX: Note (mis)use of mblk->b_next here.
 */
int
md_next_record(struct mdchain *mdp)
{
	mblk_t *m;

	if (mdp->md_top == NULL)
		return (ENOENT);
	/* Get to next message (not b_cont chain) */
	m = mdp->md_top->b_next;
	mdp->md_top->b_next = NULL;
	md_done(mdp);
	if (m == NULL)
		return (ENOENT);
	md_initm(mdp, m);
	return (0);
}

int
md_get_uint8(struct mdchain *mdp, u_int8_t *x)
{
	return (md_get_mem(mdp, (char *)x, 1, MB_MINLINE));
}

int
md_get_uint16(struct mdchain *mdp, u_int16_t *x)
{
	return (md_get_mem(mdp, (char *)x, 2, MB_MINLINE));
}

int
md_get_uint16le(struct mdchain *mdp, u_int16_t *x)
{
	u_int16_t v;
	int error = md_get_uint16(mdp, &v);

	if (x)
		*x = letohs(v);
	return (error);
}

int
md_get_uint16be(struct mdchain *mdp, u_int16_t *x) {
	u_int16_t v;
	int error = md_get_uint16(mdp, &v);

	if (x)
		*x = betohs(v);
	return (error);
}

int
md_get_uint32(struct mdchain *mdp, u_int32_t *x)
{
	return (md_get_mem(mdp, (caddr_t)x, 4, MB_MINLINE));
}

int
md_get_uint32be(struct mdchain *mdp, u_int32_t *x)
{
	u_int32_t v;
	int error;

	error = md_get_uint32(mdp, &v);
	if (x)
		*x = betohl(v);
	return (error);
}

int
md_get_uint32le(struct mdchain *mdp, u_int32_t *x)
{
	u_int32_t v;
	int error;

	error = md_get_uint32(mdp, &v);
	if (x)
		*x = letohl(v);
	return (error);
}

int
md_get_uint64(struct mdchain *mdp, u_int64_t *x)
{
	return (md_get_mem(mdp, (caddr_t)x, 8, MB_MINLINE));
}

int
md_get_uint64be(struct mdchain *mdp, u_int64_t *x)
{
	u_int64_t v;
	int error;

	error = md_get_uint64(mdp, &v);
	if (x)
		*x = betohq(v);
	return (error);
}

int
md_get_uint64le(struct mdchain *mdp, u_int64_t *x)
{
	u_int64_t v;
	int error;

	error = md_get_uint64(mdp, &v);
	if (x)
		*x = letohq(v);
	return (error);
}

int
md_get_mem(struct mdchain *mdp, caddr_t target, int size, int type)
{
	mblk_t *m = mdp->md_cur;
	int error;
	int count;
	unsigned char *s;
	uint64_t diff;

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
			error = copyout(s, (void *)target, count);
			if (error)
				return (error);
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

	*ret = rm;
	return (0);
}

int
md_get_uio(struct mdchain *mdp, uio_t *uiop, int size)
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
			adjmsg(n, adj);
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

	/*LINTED*/
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
		/*LINTED*/
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

	/*LINTED*/
	ASSERT(len <= MBLKL(m));

	m->b_wptr = m->b_rptr + len;
	n->b_rptr += len;

	/* Move any b_cont (tail) to the new head. */
	n->b_cont = m->b_cont;
	m->b_cont = NULL;

	return (n);
}

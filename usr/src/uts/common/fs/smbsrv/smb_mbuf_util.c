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
 * Copyright 2011-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2023 RackTop Systems, Inc.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>

static kmem_cache_t	*smb_mbc_cache = NULL;
static kmem_cache_t	*smb_mbuf_cache = NULL;
static kmem_cache_t	*smb_mbufcl_cache = NULL;

/* Perhaps move this to libfakekernel? */
#ifdef	_FAKE_KERNEL
size_t kmem_max_cached = 0x20000;	// UMEM_MAXBUF
#endif

void
smb_mbc_init(void)
{
	if (smb_mbc_cache != NULL)
		return;
	smb_mbc_cache = kmem_cache_create(SMBSRV_KSTAT_MBC_CACHE,
	    sizeof (mbuf_chain_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_mbuf_cache = kmem_cache_create("smb_mbuf_cache",
	    sizeof (mbuf_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_mbufcl_cache = kmem_cache_create("smb_mbufcl_cache",
	    MCLBYTES, 8, NULL, NULL, NULL, NULL, NULL, 0);
}

void
smb_mbc_fini(void)
{
	if (smb_mbc_cache != NULL) {
		kmem_cache_destroy(smb_mbc_cache);
		smb_mbc_cache = NULL;
	}
	if (smb_mbuf_cache != NULL) {
		kmem_cache_destroy(smb_mbuf_cache);
		smb_mbuf_cache = NULL;
	}
	if (smb_mbufcl_cache != NULL) {
		kmem_cache_destroy(smb_mbufcl_cache);
		smb_mbufcl_cache = NULL;
	}
}

mbuf_chain_t *
smb_mbc_alloc(uint32_t max_bytes)
{
	mbuf_chain_t	*mbc;
	mbuf_t		*m;

	mbc = kmem_cache_alloc(smb_mbc_cache, KM_SLEEP);
	bzero(mbc, sizeof (*mbc));
	mbc->mbc_magic = SMB_MBC_MAGIC;

	if (max_bytes != 0) {
		MGET(m, M_WAIT, MT_DATA);
		m->m_len = 0;
		mbc->chain = m;
		if (max_bytes > MINCLSIZE)
			MCLGET(m, M_WAIT);
	}
	mbc->max_bytes = max_bytes;
	return (mbc);
}

void
smb_mbc_free(mbuf_chain_t *mbc)
{
	SMB_MBC_VALID(mbc);

	m_freem(mbc->chain);
	mbc->chain = NULL;
	mbc->mbc_magic = 0;
	kmem_cache_free(smb_mbc_cache, mbc);
}

/*
 * smb_mbuf_get
 *
 * Allocate mbufs to hold the amount of data specified.
 * A pointer to the head of the mbuf list is returned.
 */
struct mbuf *
smb_mbuf_get(uchar_t *buf, int nbytes)
{
	struct mbuf *mhead = 0;
	struct mbuf *m = 0;
	int count;
	int offset = 0;

	while (nbytes) {
		count = (nbytes > MCLBYTES) ? MCLBYTES : nbytes;
		nbytes -= count;

		if (mhead == 0) {
			MGET(mhead, M_WAIT, MT_DATA);
			m = mhead;
		} else {
			MGET(m->m_next, M_WAIT, MT_DATA);
			m = m->m_next;
		}

		if (count > MLEN) {
			MCLGET(m, M_WAIT);
		}

		m->m_len = count;
		bcopy(buf + offset, m->m_data, count);
		offset += count;
	}
	return (mhead);
}

/*
 * Build an mbuf with external storage
 * Like esballoca()
 */
mbuf_t *
smb_mbuf_alloc_ext(caddr_t buf, int len, m_ext_free_t ff, void *arg)
{
	mbuf_t	*m = 0;

	MGET(m, M_WAIT, MT_DATA);

	/* Like MCLGET(), but external buf. */
	m->m_ext.ext_buf = buf;
	m->m_data = m->m_ext.ext_buf;
	m->m_flags |= M_EXT;
	m->m_ext.ext_size = len;
	m->m_ext.ext_free = ff;
	m->m_ext.ext_arg1 = arg;

	m->m_len = len;

	return (m);
}

static void
smb_mbuf_kmem_free(mbuf_t *m)
{
	ASSERT((m->m_flags & M_EXT) != 0);

	kmem_free(m->m_ext.ext_buf, m->m_ext.ext_size);
	/* Caller sets m->m_ext.ext_buf = NULL */
}

/*
 * Allocate one mbuf with contiguous (external) storage
 * obtained via kmem_alloc.  Most places should be using
 * smb_mbuf_alloc_chain below.
 */
mbuf_t *
smb_mbuf_alloc_kmem(int len)
{
	mbuf_t *m;
	caddr_t buf;

	VERIFY(len > 0);
#ifdef	DEBUG
	if (len > kmem_max_cached) {
		debug_enter("fix caller");
	}
#endif

	buf = kmem_alloc(len, KM_SLEEP);
	m = smb_mbuf_alloc_ext(buf, len, smb_mbuf_kmem_free, NULL);

	return (m);
}

/*
 * smb_mbuf_alloc_chain
 *
 * Allocate mbufs to hold the amount of data specified.
 * A pointer to the head of the mbuf chain is returned.
 *
 * For large messages, put the large mbufs at the tail, starting with
 * kmem_max_cached messages (128K) and then a shorter (eg MCLBYTES)
 * message at the front where we're more likely to need to copy.
 *
 * Must limit this to kmem_max_cached, to avoid contention with
 * allocating from kmem_oversize_arena.
 */
struct mbuf *
smb_mbuf_alloc_chain(int nbytes)
{
	struct mbuf *mhead = NULL;
	struct mbuf *m;
	int len;	/* m_len for current mbuf */

	ASSERT(nbytes > 0);

	while (nbytes >= kmem_max_cached) {
		len = kmem_max_cached;
		m = smb_mbuf_alloc_kmem(len);

		/* prepend to chain at mhead */
		m->m_next = mhead;
		mhead = m;

		nbytes -= len;
	}

	if (nbytes > MCLBYTES) {
		len = nbytes;
		m = smb_mbuf_alloc_kmem(len);

		/* prepend to chain at mhead */
		m->m_next = mhead;
		mhead = m;

		nbytes -= len;
	} else if (nbytes > 0) {
		ASSERT(nbytes <= MCLBYTES);
		len = nbytes;
		MGET(m, M_WAIT, MT_DATA);
		if (len > MLEN) {
			MCLGET(m, M_WAIT);
		}
		m->m_len = len;

		/* prepend to chain at mhead */
		m->m_next = mhead;
		mhead = m;

		nbytes -= len;
	}

	return (mhead);
}

/*
 * Get an smb_vdb_t and initialize it.
 * Free'd via smb_request_free
 */
smb_vdb_t *
smb_get_vdb(smb_request_t *sr)
{
	smb_vdb_t *vdb;

	vdb = smb_srm_zalloc(sr, sizeof (*vdb));
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	return (vdb);
}

/*
 * Allocate enough mbufs to accommodate the residual count in uio,
 * and setup the uio_iov to point to them.  Note that uio->uio_iov
 * is allocated by the call and has MAX_IOVEC elements.  Currently
 * the uio passed is always part of an smb_vdb_t and starts with
 * uio->uio_iovcnt = MAX_IOVEC;
 *
 * This is used by the various SMB read code paths.  That code is
 * going to do a disk read into this buffer, so we'd like the
 * segments to be large.  See smb_mbuf_alloc_chain().
 */
struct mbuf *
smb_mbuf_allocate(struct uio *uio)
{
	mbuf_t	*mhead;
	int	rc;

	ASSERT(uio->uio_resid > 0);
	ASSERT(uio->uio_iovcnt == MAX_IOVEC);

	mhead = smb_mbuf_alloc_chain(uio->uio_resid);

	rc = smb_mbuf_mkuio(mhead, uio);
	VERIFY(rc == 0);

	return (mhead);
}

/*
 * Build an iovec for an mbuf chain. with some portion of the iovec
 * already filled in. This may only ever be called once per uio_t.
 *
 * smb2_sign_calc uses this to build a UIO where the first segment
 * is a copy of the SMB header (with the signature zero'ed out)
 * and the rest if the remainder of the message (in mbufs).
 *
 * The resulting iovec covers uio_resid length in the chain,
 * which could be shorter than the mbuf chain total length.
 *
 * uio->uio_iovcnt is allocated size on entry, used size on return.
 * Errors if iovec too small or mbuf chain too short.
 */
int
smb_mbuf_mkuio_cont(mbuf_t *m, uio_t *uio, int iov_off)
{
	iovec_t	*iov;
	ssize_t off = 0;
	int iovcnt = 0;
	int tlen;

	iov = uio->uio_iov;

	while (iov_off > iovcnt) {
		if (iovcnt >= uio->uio_iovcnt)
			return (E2BIG);
		iovcnt++;
		off += iov->iov_len;
		iov++;
	}
	while (off < uio->uio_resid) {
		if (m == NULL)
			return (EFAULT);
		if (iovcnt >= uio->uio_iovcnt)
			return (E2BIG);
		tlen = m->m_len;
		if ((off + tlen) > uio->uio_resid)
			tlen = (int)(uio->uio_resid - off);
		iov->iov_base = m->m_data;
		iov->iov_len = tlen;
		off += tlen;
		m = m->m_next;
		iovcnt++;
		iov++;
	}
	uio->uio_iovcnt = iovcnt;

	return (0);
}

int
smb_mbuf_mkuio(mbuf_t *m, uio_t *uio)
{
	return (smb_mbuf_mkuio_cont(m, uio, 0));
}

/*
 * Trim an mbuf chain to nbytes.
 */
void
smb_mbuf_trim(struct mbuf *mhead, int nbytes)
{
	struct mbuf	*m = mhead;

	while (m != 0) {
		if (nbytes <= m->m_len) {
			m->m_len = nbytes;
			if (m->m_next != 0) {
				m_freem(m->m_next);
				m->m_next = 0;
			}
			break;
		}
		nbytes -= m->m_len;
		m = m->m_next;
	}
}

int
MBC_LENGTH(struct mbuf_chain *MBC)
{
	struct mbuf	*m = (MBC)->chain;
	int		used = 0;

	while (m != 0) {
		used += m->m_len;
		m = m->m_next;
	}
	return (used);
}

int
MBC_MAXBYTES(struct mbuf_chain *MBC)
{
	return (MBC->max_bytes);
}

void
MBC_SETUP(struct mbuf_chain *MBC, uint32_t max_bytes)
{
	bzero((MBC), sizeof (struct mbuf_chain));
	(MBC)->max_bytes = max_bytes;
}

/*
 * Initialize an mbuf chain and allocate the first message (if max_bytes
 * is specified).  Leave some prepend space at the head.
 */
void
MBC_INIT(struct mbuf_chain *MBC, uint32_t max_bytes)
{
	struct mbuf *m;

	bzero((MBC), sizeof (struct mbuf_chain));

	if (max_bytes != 0) {
		MGET(m, M_WAIT, MT_DATA);
		m->m_len = 0;
		(MBC)->chain = m;
		if (max_bytes > MINCLSIZE)
			MCLGET(m, M_WAIT);
		m->m_data += MH_PREPEND_SPACE;
	}
	(MBC)->max_bytes = max_bytes;
}

void
MBC_FLUSH(struct mbuf_chain *MBC)
{
	extern void	m_freem(struct mbuf *);
	struct mbuf	*m;

	while ((m = (MBC)->chain) != 0) {
		(MBC)->chain = m->m_nextpkt;
		m->m_nextpkt = 0;
		m_freem(m);
	}
	MBC_SETUP(MBC, (MBC)->max_bytes);
}

void
MBC_ATTACH_MBUF(struct mbuf_chain *MBC, struct mbuf *MBUF)
{
	if (MBC->chain != 0)
		MBC_FLUSH(MBC);

	(MBC)->chain_offset = 0;
	(MBC)->chain = (MBUF);
}

void
MBC_APPEND_MBUF(struct mbuf_chain *MBC, struct mbuf *MBUF)
{
	struct mbuf	*m;

	if ((MBC)->chain == 0) {
		(MBC)->chain = (MBUF);
	} else {
		m = (MBC)->chain;
		while (m->m_next != 0)
			m = m->m_next;
		m->m_next = (MBUF);
	}
}

static void /*ARGSUSED*/
mclrefnoop(mbuf_t *m)
{
}

void
MBC_ATTACH_BUF(struct mbuf_chain *MBC, unsigned char *BUF, int LEN)
{
	MGET((MBC)->chain, M_WAIT, MT_DATA);
	(MBC)->chain_offset = 0;
	(MBC)->chain->m_flags |= M_EXT;
	(MBC)->chain->m_data = (caddr_t)(BUF);
	(MBC)->chain->m_ext.ext_buf = (caddr_t)(BUF);
	(MBC)->chain->m_len = (LEN);
	(MBC)->chain->m_ext.ext_size = (LEN);
	(MBC)->chain->m_ext.ext_free = mclrefnoop;
	(MBC)->max_bytes = (LEN);
}


int
MBC_SHADOW_CHAIN(struct mbuf_chain *submbc, struct mbuf_chain *mbc,
    int off, int len)
{
	int x = off + len;

	if (off < 0 || len < 0 || x < 0 ||
	    off > mbc->max_bytes || x > mbc->max_bytes)
		return (EMSGSIZE);

	*submbc = *mbc;
	submbc->chain_offset = off;
	submbc->max_bytes = x;
	submbc->shadow_of = mbc;
	return (0);
}

/*
 * Trim req_len bytes from the message,
 * from head if > 0, else from tail.
 */
void
m_adjust(struct mbuf *mp, int req_len)
{
	int len = req_len;
	struct mbuf *m;

	if ((m = mp) == NULL)
		return;

	/*
	 * We don't use the trim-from-tail case.
	 * Using smb_mbuf_trim() for that.
	 */
	VERIFY(len >= 0);

	/*
	 * Trim from head.
	 */
	while (m != NULL && len > 0) {
		if (m->m_len <= len) {
			len -= m->m_len;
			m->m_len = 0;
			m = m->m_next;
		} else {
			m->m_len -= len;
			m->m_data += len;
			len = 0;
		}
	}
}

/*
 * Arrange to prepend space of size plen to mbuf m.  If a new mbuf must be
 * allocated, how specifies whether to wait.  If the allocation fails, the
 * original mbuf chain is freed and m is set to NULL.
 * BSD had a macro: M_PREPEND(m, plen, how)
 */

struct mbuf *
m_prepend(struct mbuf *m, int plen, int how)
{
	struct mbuf *mn;

	if (M_LEADINGSPACE(m) >= plen) {
		m->m_data -= plen;
		m->m_len += plen;
		return (m);
	}
	if (m->m_flags & M_PKTHDR) {
		MGETHDR(mn, how, m->m_type);
	} else {
		MGET(mn, how, m->m_type);
	}
	VERIFY(mn != NULL);
	if (m->m_flags & M_PKTHDR) {
		// BSD: m_move_pkthdr(mn, m);
		// We don't use any pkthdr stuff.
		mn->m_pkthdr.len += plen;
	}
	mn->m_next = m;
	m = mn;
	if (plen < M_SIZE(m))
		M_ALIGN(m, plen);
	m->m_len = plen;
	DTRACE_PROBE1(prepend_allocated, struct mbuf *, m);
	return (m);
}

/*
 * Free a single mbuf structure.  Calls m->m_ext.ext_ref() to free any
 * associated external buffers if present (indicated by m->m_flags & M_EXT)
 */
struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n;

	MFREE(m, n);
	return (n);
}

/*
 * Free a list of mbufs.  Each mbuf in the list is freed similarly to m_free.
 */
void
m_freem(struct mbuf *m)
{
	struct mbuf *n;

	if (m == NULL)
		return;
	/*
	 * Lint doesn't like the m = n assignment at the close of the loop
	 * but it is correct.  MFREE assigns n = (m)->m_next so the loop
	 * is effectively assigning m = (m)->m_next then exiting when
	 * m == NULL
	 */
	do {
		MFREE(m, n);
	} while ((m = n) != 0);
}

/*
 * Mbuffer utility routines.
 */

mbuf_t *
smb_mbuf_alloc(void)
{
	mbuf_t *m;

	m = kmem_cache_alloc(smb_mbuf_cache, KM_SLEEP);
	bzero(m, sizeof (*m));
	return (m);
}

void
smb_mbuf_free(mbuf_t *m)
{
	kmem_cache_free(smb_mbuf_cache, m);
}

void *
smb_mbufcl_alloc(void)
{
	void *p;

	p = kmem_cache_alloc(smb_mbufcl_cache, KM_SLEEP);
	bzero(p, MCLBYTES);
	return (p);
}

void
smb_mbufcl_free(mbuf_t *m)
{
	ASSERT((m->m_flags & M_EXT) != 0);
	ASSERT(m->m_ext.ext_size == MCLBYTES);

	kmem_cache_free(smb_mbufcl_cache, m->m_ext.ext_buf);
	/* Caller sets m->m_ext.ext_buf = NULL */
}

int
smb_mbufcl_ref(void *p, uint_t sz, int incr)
{
	ASSERT3S(sz, ==, MCLBYTES);
	if (incr < 0)
		kmem_cache_free(smb_mbufcl_cache, p);
	return (0);
}

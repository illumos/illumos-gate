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
 * $FreeBSD: src/sys/sys/mchain.h,v 1.1 2001/02/24 15:44:30 bp Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _MCHAIN_H_
#define	_MCHAIN_H_

#include <sys/types.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>

#ifdef _LITTLE_ENDIAN

/* little-endian values on little-endian */
#define	htoles(x)	((uint16_t)(x))
#define	letohs(x)	((uint16_t)(x))
#define	htolel(x)	((uint32_t)(x))
#define	letohl(x)	((uint32_t)(x))
#define	htoleq(x)	((uint64_t)(x))
#define	letohq(x)	((uint64_t)(x))

/*
 * big-endian values on little-endian (swap)
 *
 * Use the BSWAP macros because they're fastest, and they're
 * available in all environments where we use this header.
 */
#define	htobes(x)	BSWAP_16(x)
#define	betohs(x)	BSWAP_16(x)
#define	htobel(x)	BSWAP_32(x)
#define	betohl(x)	BSWAP_32(x)
#define	htobeq(x)	BSWAP_64(x)
#define	betohq(x)	BSWAP_64(x)

#else	/* (BYTE_ORDER == LITTLE_ENDIAN) */

/* little-endian values on big-endian (swap) */
#define	letohs(x)	BSWAP_16(x)
#define	htoles(x)	BSWAP_16(x)
#define	letohl(x)	BSWAP_32(x)
#define	htolel(x)	BSWAP_32(x)
#define	letohq(x)	BSWAP_64(x)
#define	htoleq(x)	BSWAP_64(x)

/* big-endian values on big-endian */
#define	htobes(x)	((uint16_t)(x))
#define	betohs(x)	((uint16_t)(x))
#define	htobel(x)	((uint32_t)(x))
#define	betohl(x)	((uint32_t)(x))
#define	htobeq(x)	((uint64_t)(x))
#define	betohq(x)	((uint64_t)(x))
#endif	/* (BYTE_ORDER == LITTLE_ENDIAN) */


/*
 * Additions for Solaris to replace things that came from
 * <sys/mbuf.h> in the Darwin code.  These are mostly just
 * wrappers for streams functions.  See: subr_mchain.c
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

/*
 * BSD-style mbuf "shim" for kernel code.  Note, this
 * does NOT implement BSD mbufs in the kernel.  Rather,
 * macros and wrapper functions are used so that code
 * fomerly using mbuf_t now use STREAMS mblk_t instead.
 */

#include <sys/stream.h> /* mblk_t */
#include <sys/strsun.h> /* MBLKL */
typedef mblk_t mbuf_t;

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

#define	mtod(m, t) ((t)((m)->b_rptr))

/* length arg for m_copym to "copy all" */
#define	M_COPYALL		-1

mblk_t *m_copym(mblk_t *, int, int, int);
mblk_t *m_pullup(mblk_t *, int);
mblk_t *m_split(mblk_t *, int, int);
void m_cat(mblk_t *, mblk_t *);
#define	m_freem(x)	freemsg(x)
mblk_t *m_getblk(int, int);
int  m_fixhdr(mblk_t *m);

#else	/* _KERNEL */

/*
 * BSD-style mbuf work-alike, for user-level.
 * See libsmbfs mbuf.c
 */
typedef struct mbuf {
	int		m_len;
	int		m_maxlen;
	char		*m_data;
	struct mbuf	*m_next;
} mbuf_t;

#define	mtod(m, t)	((t)(m)->m_data)

int m_get(int, mbuf_t **);
void m_freem(mbuf_t *);

#endif	/* _KERNEL */

/*
 * BSD-style mbchain/mdchain work-alike
 */

/*
 * Type of copy for mb_{put|get}_mem()
 */
#define	MB_MSYSTEM	0		/* use bcopy() */
#define	MB_MUSER	1		/* use copyin()/copyout() */
#define	MB_MINLINE	2		/* use an inline copy loop */
#define	MB_MZERO	3		/* bzero(), mb_put_mem only */
#define	MB_MCUSTOM	4		/* use an user defined function */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

struct mbchain {
	mblk_t *mb_top;
	mblk_t *mb_cur;
	uint_t mb_count;
};
typedef struct mbchain mbchain_t;

struct mdchain {
	mblk_t *md_top;		/* head of mblk chain */
	mblk_t *md_cur;		/* current mblk */
	uchar_t *md_pos;	/* position in md_cur */
	/* NB: md_pos is same type as mblk_t b_rptr, b_wptr members. */
};
typedef struct mdchain mdchain_t;

mblk_t *mb_detach(mbchain_t *mbp);
int  mb_fixhdr(mbchain_t *mbp);
int  mb_put_uio(mbchain_t *mbp, uio_t *uiop, size_t size);

void md_append_record(mdchain_t *mdp, mblk_t *top);
void md_next_record(mdchain_t *mdp);
int  md_get_uio(mdchain_t *mdp, uio_t *uiop, size_t size);

#else	/* _KERNEL */

/*
 * user-level code uses the same struct for both (MB, MD)
 */
typedef struct mbdata {
	mbuf_t	*mb_top;	/* head of mbuf chain */
	mbuf_t	*mb_cur;	/* current mbuf */
	char	*mb_pos;	/* position in mb_cur (get) */
	/* NB: mb_pos is same type as mbuf_t m_data member. */
	int	mb_count;	/* bytes marshalled (put) */
} mbdata_t;
typedef struct mbdata mbchain_t;
typedef struct mbdata mdchain_t;

#endif	/* _KERNEL */

int  mb_init(mbchain_t *);
void mb_initm(mbchain_t *, mbuf_t *);
void mb_done(mbchain_t *);
void *mb_reserve(mbchain_t *, int size);

int  mb_put_align8(mbchain_t *mbp);
int  mb_put_padbyte(mbchain_t *mbp);
int  mb_put_uint8(mbchain_t *, uint8_t);
int  mb_put_uint16be(mbchain_t *, uint16_t);
int  mb_put_uint16le(mbchain_t *, uint16_t);
int  mb_put_uint32be(mbchain_t *, uint32_t);
int  mb_put_uint32le(mbchain_t *, uint32_t);
int  mb_put_uint64be(mbchain_t *, uint64_t);
int  mb_put_uint64le(mbchain_t *, uint64_t);
int  mb_put_mem(mbchain_t *, const void *, int, int);
int  mb_put_mbuf(mbchain_t *, mbuf_t *);
int  mb_put_mbchain(mbchain_t *, mbchain_t *);

int  md_init(mdchain_t *mdp);
void md_initm(mdchain_t *mbp, mbuf_t *m);
void md_done(mdchain_t *mdp);

int  md_get_uint8(mdchain_t *, uint8_t *);
int  md_get_uint16be(mdchain_t *, uint16_t *);
int  md_get_uint16le(mdchain_t *, uint16_t *);
int  md_get_uint32be(mdchain_t *, uint32_t *);
int  md_get_uint32le(mdchain_t *, uint32_t *);
int  md_get_uint64be(mdchain_t *, uint64_t *);
int  md_get_uint64le(mdchain_t *, uint64_t *);
int  md_get_mem(mdchain_t *, void *, int, int);
int  md_get_mbuf(mdchain_t *, int, mbuf_t **);
int  md_seek(mdchain_t *, uint32_t);
uint32_t md_tell(mdchain_t *);

#endif	/* !_MCHAIN_H_ */

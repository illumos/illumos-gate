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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MCHAIN_H_
#define	_MCHAIN_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#define	letohs(x) 	BSWAP_16(x)
#define	htoles(x) 	BSWAP_16(x)
#define	letohl(x) 	BSWAP_32(x)
#define	htolel(x) 	BSWAP_32(x)
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


#ifdef _KERNEL

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

#include <sys/stream.h> /* mblk_t */

/*
 * Type of copy for mb_{put|get}_mem()
 */
#define	MB_MSYSTEM	0		/* use bcopy() */
#define	MB_MUSER	1		/* use copyin()/copyout() */
#define	MB_MINLINE	2		/* use an inline copy loop */
#define	MB_MZERO	3		/* bzero(), mb_put_mem only */
#define	MB_MCUSTOM	4		/* use an user defined function */

struct mbchain {
	mblk_t *mb_top;
	mblk_t *mb_cur;
	uint_t mb_count;
};
typedef struct mbchain mbchain_t;

struct mdchain {
	mblk_t *md_top;		/* head of mblk chain */
	mblk_t *md_cur;		/* current mblk */
	uchar_t *md_pos;		/* offset in the current mblk */
};
typedef struct mdchain mdchain_t;

int  m_fixhdr(mblk_t *m);

int  mb_init(struct mbchain *mbp);
void mb_initm(struct mbchain *mbp, mblk_t *m);
void mb_done(struct mbchain *mbp);
mblk_t *mb_detach(struct mbchain *mbp);
int  mb_fixhdr(struct mbchain *mbp);
void *mb_reserve(struct mbchain *mbp, int size);

int  mb_put_padbyte(struct mbchain *mbp);
int  mb_put_uint8(struct mbchain *mbp, uint8_t x);
int  mb_put_uint16be(struct mbchain *mbp, uint16_t x);
int  mb_put_uint16le(struct mbchain *mbp, uint16_t x);
int  mb_put_uint32be(struct mbchain *mbp, uint32_t x);
int  mb_put_uint32le(struct mbchain *mbp, uint32_t x);
int  mb_put_uint64be(struct mbchain *mbp, uint64_t x);
int  mb_put_uint64le(struct mbchain *mbp, uint64_t x);
int  mb_put_mem(struct mbchain *mbp, const char *src, int size, int type);

int  mb_put_mblk(struct mbchain *mbp, mblk_t *m);
int  mb_put_uio(struct mbchain *mbp, uio_t *uiop, int size);

int  md_init(struct mdchain *mdp);
void md_initm(struct mdchain *mbp, mblk_t *m);
void md_done(struct mdchain *mdp);
void md_append_record(struct mdchain *mdp, mblk_t *top);
int  md_next_record(struct mdchain *mdp);
int  md_get_uint8(struct mdchain *mdp, uint8_t *x);
int  md_get_uint16(struct mdchain *mdp, uint16_t *x);
int  md_get_uint16le(struct mdchain *mdp, uint16_t *x);
int  md_get_uint16be(struct mdchain *mdp, uint16_t *x);
int  md_get_uint32(struct mdchain *mdp, uint32_t *x);
int  md_get_uint32be(struct mdchain *mdp, uint32_t *x);
int  md_get_uint32le(struct mdchain *mdp, uint32_t *x);
int  md_get_uint64(struct mdchain *mdp, uint64_t *x);
int  md_get_uint64be(struct mdchain *mdp, uint64_t *x);
int  md_get_uint64le(struct mdchain *mdp, uint64_t *x);
int  md_get_mem(struct mdchain *mdp, caddr_t target, int size, int type);
int  md_get_mblk(struct mdchain *mdp, int size, mblk_t **m);
int  md_get_uio(struct mdchain *mdp, uio_t *uiop, int size);

/*
 * Additions for Solaris to replace things that came from
 * <sys/mbuf.h> in the Darwin code.  These are mostly just
 * wrappers for streams functions.  See: subr_mchain.c
 */

#define	mtod(m, t) ((t)((m)->b_rptr))

/* length to m_copym to copy all */
#define	M_COPYALL		-1

mblk_t *m_copym(mblk_t *, int, int, int);
mblk_t *m_pullup(mblk_t *, int);
mblk_t *m_split(mblk_t *, int, int);
void m_cat(mblk_t *, mblk_t *);
#define	m_freem(x)	freemsg(x)
mblk_t *m_getblk(int, int);

#endif	/* ifdef _KERNEL */
#endif	/* !_MCHAIN_H_ */

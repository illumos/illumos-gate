/*
 * Copyright (c) 2000-2001 Boris Popov
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
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PRIVATE_H
#define	_PRIVATE_H

/*
 * Private declarations for this library.
 * Moved from smb_lib.h
 */

#include <inttypes.h>

/*
 * BSD-style mbuf simulation
 */
struct mbuf {
	int		m_len;
	int		m_maxlen;
	char		*m_data;
	struct mbuf	*m_next;
};
typedef struct mbuf mbuf_t;

#if 0 /* in smb_lib.h */
struct mbdata {
	struct mbuf	*mb_top;
	struct mbuf	*mb_cur;
	char		*mb_pos;
	int		mb_count;
};
typedef struct mbdata mbdata_t;
#endif

#define	M_ALIGNFACTOR	(sizeof (long))
#define	M_ALIGN(len)	(((len) + M_ALIGNFACTOR - 1) & ~(M_ALIGNFACTOR - 1))
#define	M_BASESIZE	(sizeof (struct mbuf))
#define	M_MINSIZE	(256 - M_BASESIZE)
#define	M_TOP(m)	((char *)(m) + M_BASESIZE)
#define	M_TRAILINGSPACE(m) ((m)->m_maxlen - (m)->m_len)
#define	mtod(m, t)	((t)(m)->m_data)

/*
 * request handling structures
 */
struct smb_rq {
	uchar_t		rq_cmd;
	struct mbdata	rq_rq;
	struct mbdata	rq_rp;
	struct smb_ctx *rq_ctx;
	int		rq_wcount;
	int		rq_bcount;
};
typedef struct smb_rq smb_rq_t;

#define	smb_rq_getrequest(rqp)	(&(rqp)->rq_rq)
#define	smb_rq_getreply(rqp)	(&(rqp)->rq_rp)

int  smb_rq_init(struct smb_ctx *, uchar_t, size_t, struct smb_rq **);
void smb_rq_done(struct smb_rq *);
void smb_rq_wend(struct smb_rq *);
int  smb_rq_simple(struct smb_rq *);
int  smb_rq_dmem(struct mbdata *, const char *, size_t);
int  smb_rq_dstring(struct mbdata *, const char *);


/*
 * Message compose/parse
 */

int  m_getm(struct mbuf *, size_t, struct mbuf **);
int  m_lineup(struct mbuf *, struct mbuf **);
int  mb_init(struct mbdata *, size_t);
int  mb_initm(struct mbdata *, struct mbuf *);
int  mb_done(struct mbdata *);
int  mb_fit(struct mbdata *mbp, size_t size, char **pp);
int  mb_put_uint8(struct mbdata *, uint8_t);
int  mb_put_uint16be(struct mbdata *, uint16_t);
int  mb_put_uint16le(struct mbdata *, uint16_t);
int  mb_put_uint32be(struct mbdata *, uint32_t);
int  mb_put_uint32le(struct mbdata *, uint32_t);
int  mb_put_uint64be(struct mbdata *, uint64_t);
int  mb_put_uint64le(struct mbdata *, uint64_t);
int  mb_put_mem(struct mbdata *, const char *, size_t);
int  mb_put_pstring(struct mbdata *mbp, const char *s);
int  mb_put_mbuf(struct mbdata *, struct mbuf *);

int  mb_get_uint8(struct mbdata *, uint8_t *);
int  mb_get_uint16(struct mbdata *, uint16_t *);
int  mb_get_uint16le(struct mbdata *, uint16_t *);
int  mb_get_uint16be(struct mbdata *, uint16_t *);
int  mb_get_uint32(struct mbdata *, uint32_t *);
int  mb_get_uint32be(struct mbdata *, uint32_t *);
int  mb_get_uint32le(struct mbdata *, uint32_t *);
int  mb_get_uint64(struct mbdata *, uint64_t *);
int  mb_get_uint64be(struct mbdata *, uint64_t *);
int  mb_get_uint64le(struct mbdata *, uint64_t *);
int  mb_get_mem(struct mbdata *, char *, size_t);

/*
 * Network stuff (NetBIOS and otherwise)
 */

int nb_name_len(struct nb_name *);
/* new flag UCflag. 1=uppercase,0=don't */
int nb_name_encode(struct nb_name *, uchar_t *);
int nb_encname_len(const uchar_t *);

int  nb_snballoc(int namelen, struct sockaddr_nb **);
void nb_snbfree(struct sockaddr *);
int  nb_sockaddr(struct sockaddr *, struct nb_name *, struct sockaddr_nb **);

int  nbns_resolvename(const char *, struct nb_ctx *, struct sockaddr **);
int  nbns_getnodestatus(struct sockaddr *targethost,
    struct nb_ctx *ctx, char *system, char *workgroup);
int  nb_getlocalname(char *name, size_t maxlen);

extern uchar_t nls_lower[256], nls_upper[256];

#endif /* _PRIVATE_H */

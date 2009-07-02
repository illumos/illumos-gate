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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PRIVATE_H
#define	_PRIVATE_H

/*
 * Private declarations for this library.
 * Moved from smb_lib.h
 */

#include <inttypes.h>
#include <sys/byteorder.h>
#include <sys/ccompile.h>

#include <netsmb/netbios.h>

extern void dprint(const char *, const char *, ...)
	__PRINTFLIKE(2);

#if defined(DEBUG) || defined(__lint)
#define	DPRINT(...) dprint(__func__, __VA_ARGS__)
#else
#define	DPRINT(...) ((void)0)
#endif

/*
 * Flags bits in ct_vcflags (copied from smb_conn.h)
 * Pass these to the driver?
 */
#define	SMBV_RECONNECTING	0x0002	/* conn in process of reconnection */
#define	SMBV_LONGNAMES		0x0004	/* conn configured to use long names */
#define	SMBV_ENCRYPT		0x0008	/* server demands encrypted password */
#define	SMBV_WIN95		0x0010	/* used to apply bugfixes for this OS */
#define	SMBV_NT4		0x0020	/* used when NT4 issues invalid resp */
#define	SMBV_UNICODE		0x0040	/* conn configured to use Unicode */
#define	SMBV_EXT_SEC		0x0080	/* conn to use extended security */
#define	SMBV_WILL_SIGN		0x0100	/* negotiated signing */


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

struct mbdata {
	struct mbuf	*mb_top;
	struct mbuf	*mb_cur;
	char		*mb_pos;
	int		mb_count;
};
typedef struct mbdata mbdata_t;

/*
 * Note: Leaving a little space (8 bytes) between the
 * mbuf header and the start of the data so we can
 * prepend a NetBIOS header in that space.
 */
#define	M_ALIGNFACTOR	(sizeof (long))
#define	M_ALIGN(len)	(((len) + M_ALIGNFACTOR - 1) & ~(M_ALIGNFACTOR - 1))
#define	M_BASESIZE	(sizeof (struct mbuf) + 8)
#define	M_MINSIZE	(1024 - M_BASESIZE)
#define	M_TOP(m)	((char *)(m) + M_BASESIZE)
#define	M_TRAILINGSPACE(m) ((m)->m_maxlen - (m)->m_len)
#define	mtod(m, t)	((t)(m)->m_data)

/*
 * request handling structures
 */
struct smb_rq {
	struct smb_ctx *rq_ctx;
	struct mbdata	rq_rq;
	struct mbdata	rq_rp;
	int		rq_rpbufsz;
	uint8_t		rq_cmd;
	uint8_t		rq_hflags;
	uint16_t	rq_hflags2;
	uint32_t	rq_status;
	uint16_t	rq_uid;
	uint16_t	rq_tid;
	uint16_t	rq_mid;
	uint32_t	rq_seqno;
	/* See rq_[bw]{start,end} functions */
	char		*rq_wcntp;
	int		rq_wcbase;
	char		*rq_bcntp;
	int		rq_bcbase;
};
typedef struct smb_rq smb_rq_t;

#define	smb_rq_getrequest(rqp)	(&(rqp)->rq_rq)
#define	smb_rq_getreply(rqp)	(&(rqp)->rq_rp)

int  smb_rq_init(struct smb_ctx *, uchar_t, struct smb_rq **);
void smb_rq_done(struct smb_rq *);
void smb_rq_bstart(struct smb_rq *);
void smb_rq_bend(struct smb_rq *);
void smb_rq_wstart(struct smb_rq *);
void smb_rq_wend(struct smb_rq *);
int  smb_rq_simple(struct smb_rq *);
int  smb_rq_dmem(struct mbdata *, const char *, size_t);
int  smb_rq_internal(struct smb_ctx *, struct smb_rq *);
int  smb_rq_sign(struct smb_rq *);
int  smb_rq_verify(struct smb_rq *);


/*
 * Message compose/parse
 */

void m_freem(struct mbuf *);
int  m_getm(struct mbuf *, size_t, struct mbuf **);
int  m_lineup(struct mbuf *, struct mbuf **);
size_t m_totlen(struct mbuf *);

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
int  mb_put_mem(struct mbdata *, const void *, size_t);
int  mb_put_mbuf(struct mbdata *, struct mbuf *);
int  mb_put_astring(struct mbdata *mbp, const char *s);
int  mb_put_dstring(struct mbdata *mbp, const char *s, int);
int  mb_put_ustring(struct mbdata *mbp, const char *s);

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
int  mb_get_mem(struct mbdata *, void *, size_t);
int  mb_get_mbuf(struct mbdata *, int, struct mbuf **);
int  mb_get_string(struct mbdata *, char **, int);
int  mb_get_astring(struct mbdata *, char **);
int  mb_get_ustring(struct mbdata *, char **);


/*
 * Network stuff (NetBIOS and otherwise)
 */
struct nb_name;
struct sockaddr_nb;

extern int smb_recv_timeout; /* seconds */

void dump_ctx(char *, struct smb_ctx *);
void dump_addrinfo(struct addrinfo *);
void dump_sockaddr(struct sockaddr *);
int nb_ssn_request(struct smb_ctx *, char *);

int nb_name_len(struct nb_name *);
int nb_name_encode(struct mbdata *, struct nb_name *);
int nb_encname_len(const uchar_t *);

int  nb_snballoc(struct sockaddr_nb **);
void nb_snbfree(struct sockaddr *);
int  nb_sockaddr(struct sockaddr *, struct nb_name *, struct sockaddr_nb **);

int nbns_getaddrinfo(const char *name, struct nb_ctx *nbc,
	struct addrinfo **res);
int  nbns_resolvename(const char *, struct nb_ctx *, struct sockaddr **);
int  get_xti_err(int);


/*
 * Private SMB stuff
 */

struct smb_bitname {
	uint_t	bn_bit;
	char	*bn_name;
};
typedef struct smb_bitname smb_bitname_t;
char *smb_printb(char *, int, const struct smb_bitname *);

int smb_ctx_getaddr(struct smb_ctx *ctx);
int smb_ctx_gethandle(struct smb_ctx *ctx);

int smb_ssn_send(struct smb_ctx *, struct mbdata *);
int smb_ssn_recv(struct smb_ctx *, struct mbdata *);

int smb_negprot(struct smb_ctx *, struct mbdata *);

int smb_ssnsetup_null(struct smb_ctx *);
int smb_ssnsetup_ntlm1(struct smb_ctx *);
int smb_ssnsetup_ntlm2(struct smb_ctx *);
int smb_ssnsetup_spnego(struct smb_ctx *, struct mbdata *);

void smb_time_local2server(struct timeval *, int, long *);
void smb_time_server2local(ulong_t, int, struct timeval *);
void smb_time_NT2local(uint64_t, int, struct timeval *);
void smb_time_local2NT(struct timeval *, int, uint64_t *);

int smb_getlocalname(char **);
int smb_get_authentication(struct smb_ctx *);
int smb_get_keychain(struct smb_ctx *ctx);
void smb_hexdump(const void *buf, int len);

/* See ssp.c */
int ssp_ctx_create_client(struct smb_ctx *, struct mbdata *);
int ssp_ctx_next_token(struct smb_ctx *, struct mbdata *, struct mbdata *);
void ssp_ctx_destroy(struct smb_ctx *);

#ifdef KICONV_SUPPORT
/* See nls.c (get rid of this?) */
extern uchar_t nls_lower[256], nls_upper[256];
#endif	/* KICONV_SUPPORT */

#endif /* _PRIVATE_H */

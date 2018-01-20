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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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

#include <netsmb/mchain.h>
#include <netsmb/netbios.h>

extern void dprint(const char *, const char *, ...)
	__PRINTFLIKE(2);

#if defined(DEBUG) || defined(__lint)
#define	DPRINT(...) dprint(__func__, __VA_ARGS__)
#else
#define	DPRINT(...) ((void)0)
#endif

/*
 * This library extends the mchain.h function set a little.
 */
int  m_getm(struct mbuf *, int, struct mbuf **);
int  m_lineup(struct mbuf *, struct mbuf **);
size_t m_totlen(struct mbuf *);

int  mb_init_sz(struct mbdata *, int);
int  mb_fit(struct mbdata *mbp, int size, char **pp);

int  mb_put_string(struct mbdata *mbp, const char *s, int);
int  mb_put_astring(struct mbdata *mbp, const char *s);
int  mb_put_ustring(struct mbdata *mbp, const char *s);

int  md_get_string(struct mbdata *, char **, int);
int  md_get_astring(struct mbdata *, char **);
int  md_get_ustring(struct mbdata *, char **);

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

int  smb_iod_start(struct smb_ctx *);
const char *smb_iod_state_name(enum smbiod_state st);

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

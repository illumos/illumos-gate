/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	$OpenBSD: kex.h,v 1.32 2002/09/09 14:54:14 markus Exp $	*/

#ifndef	_KEX_H
#define	_KEX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>
#include "buffer.h"
#include "cipher.h"
#include "key.h"

#ifdef GSSAPI
#ifdef SUNW_GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#else
#ifdef GSS_KRB5
#ifdef HEIMDAL
#include <gssapi.h>
#else
#include <gssapi_generic.h>
#endif /* HEIMDAL */
#endif /* GSS_KRB5 */
#endif /* SUNW_GSSAPI */
#endif /* GSSAPI */

#define	KEX_DH1		"diffie-hellman-group1-sha1"
#define	KEX_DHGEX	"diffie-hellman-group-exchange-sha1"

enum kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

enum kex_exchange {
	KEX_DH_GRP1_SHA1,
	KEX_DH_GEX_SHA1,
#ifdef GSSAPI
	KEX_GSS_GRP1_SHA1,
#endif /* GSSAPI */
	KEX_MAX
};


#define KEX_INIT_SENT	0x0001

typedef struct Kex Kex;
typedef struct Mac Mac;
typedef struct Comp Comp;
typedef struct Enc Enc;
typedef struct Newkeys Newkeys;

struct Enc {
	char	*name;
	Cipher	*cipher;
	int	enabled;
	u_int	key_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
struct Mac {
	char	*name;
	int	enabled;
	const EVP_MD	*md;
	int	mac_len;
	u_char	*key;
	int	key_len;
};
struct Comp {
	int	type;
	int	enabled;
	char	*name;
};
struct Newkeys {
	Enc	enc;
	Mac	mac;
	Comp	comp;
};

struct KexOptions {
	int	gss_deleg_creds;
};

struct Kex {
	u_char	*session_id;
	u_int	session_id_len;
	Newkeys	*newkeys[MODE_MAX];
	int	we_need;
	int	server;
	char	*serverhost;
	char	*name;
	int	hostkey_type;
	int	kex_type;
	Buffer	my;
	Buffer	peer;
	int	initial_kex_done;
	int	done;
	int	flags;
	char	*client_version_string;
	char	*server_version_string;
	struct  KexOptions options;
	int	(*verify_host_key)(Key *);
	int	(*accept_host_key)(Key *); /* for GSS keyex */
	Key	*(*load_host_key)(int);
	int	(*host_key_index)(Key *);
	void    (*kex[KEX_MAX])(Kex *);
	void	(*kex_hook)(Kex *, char **); /* for GSS keyex rekeying */
#ifdef GSSAPI
	gss_OID_set mechs; /* mechs in my proposal */
#endif /* GSSAPI */
};

typedef void (*Kex_hook_func)(Kex *, char **); /* for GSS-API rekeying */

Kex	 *kex_setup(const char *host,
		    char *proposal[PROPOSAL_MAX],
		    Kex_hook_func hook);
void	  kex_start(Kex *);
void	  kex_finish(Kex *);

void	  kex_send_kexinit(Kex *);
void	  kex_input_kexinit(int, u_int32_t, void *);
void	  kex_derive_keys(Kex *, u_char *, BIGNUM *);

/* XXX Remove after merge of 3.6/7 code is completed */
#if 0
void	 kexdh(Kex *);
void	 kexgex(Kex *);
#endif

Newkeys *kex_get_newkeys(int);

void    kexdh_client(Kex *);
void    kexdh_server(Kex *);
void    kexgex_client(Kex *);
void    kexgex_server(Kex *);

u_char *
kex_dh_hash(char *, char *, char *, int, char *, int, u_char *, int,
	    BIGNUM *, BIGNUM *, BIGNUM *);
u_char *
kexgex_hash(char *, char *, char *, int, char *, int, u_char *, int,
	    int, int, int, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *);

#ifdef GSSAPI
void     kexgss_client(Kex *);
void     kexgss_server(Kex *);
#endif

#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH)
void	dump_digest(char *, u_char *, int);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _KEX_H */

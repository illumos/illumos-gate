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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_INET_KSSL_KSSLIMPL_H
#define	_INET_KSSL_KSSLIMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/atomic.h>
#include <sys/mutex.h>
#include <sys/crypto/common.h>
#include <sys/kstat.h>
#include <sys/sdt.h>
#include <inet/kssl/ksslapi.h>
#include <inet/kssl/ksslproto.h>

/*
 * Certificate structure. The msg field is the BER data of the
 * certificate.
 */
typedef struct Certificate {
    uchar_t *msg;
    int len;
} Certificate_t;

/* Generic linked chain type */
typedef struct kssl_chain_s {
	struct kssl_chain_s	*next;
	void			*item;
} kssl_chain_t;

/* Proxies chain. follows the generic kssl_chain_t layout */
typedef struct kssl_proxy_s {
	struct kssl_proxy_s	*next;
	void			*proxy_bound;
} kssl_proxy_t;

/* Fallback endpoints chain. Ditto. */
typedef struct kssl_fallback_s {
	struct kssl_fallback_s	*next;
	void			*fallback_bound;
} kssl_fallback_t;

/*
 * Structure to support using a non-extractable key in
 * a crypto provider. We keep the token label and pin so
 * that we can reauthenticate when needed.
 */
typedef struct kssl_session_info_s {
	boolean_t		is_valid_handle;
	boolean_t		do_reauth;
	crypto_provider_t	prov;
	crypto_session_id_t	sid;
	crypto_key_t		key;
	crypto_notify_handle_t	evnt_handle;
	char			toklabel[CRYPTO_EXT_SIZE_LABEL];
	int			pinlen;
	char			tokpin[1];
} kssl_session_info_t;

/* kssl_entry_t structure. */

typedef struct kssl_entry_s {
	uint_t			ke_refcnt;	/* for hold/release */
	boolean_t		ke_no_freeall;
	kmutex_t		ke_mutex;

	in6_addr_t		ke_laddr;
	in_port_t		ke_ssl_port;	/* SSL port */
	in_port_t		ke_proxy_port;	/* SSL proxy port */

	uint32_t		sid_cache_timeout; /* In seconds */
	uint32_t		sid_cache_nentries;
	kssl_sid_ent_t		*sid_cache;

	uint16_t		kssl_cipherSuites[CIPHER_SUITE_COUNT];
	int			kssl_cipherSuites_nentries;
	uint16_t		kssl_saved_Suites[CIPHER_SUITE_COUNT];

	boolean_t		ke_is_nxkey;
	kssl_session_info_t	*ke_sessinfo;

	crypto_key_t		*ke_private_key; /* instance's private key */
	Certificate_t		*ke_server_certificate;

	Certificate_t		**ke_cacert_chain;

	kssl_proxy_t	*ke_proxy_head;		/* Proxies chain */
	kssl_fallback_t	*ke_fallback_head;	/* Fall-back endpoints chain */

} kssl_entry_t;

typedef struct mech_to_cipher_s {
	crypto_mech_type_t mech;
	char *name;
	uint16_t kssl_suites[CIPHER_SUITE_COUNT];
} mech_to_cipher_t;

#define	KSSL_ENTRY_REFHOLD(kssl_entry) {				\
	atomic_inc_32(&(kssl_entry)->ke_refcnt);			\
	ASSERT((kssl_entry)->ke_refcnt != 0);				\
}

#define	KSSL_ENTRY_REFRELE(kssl_entry) {				\
	ASSERT((kssl_entry)->ke_refcnt != 0);				\
	membar_exit();							\
	if (atomic_dec_32_nv(&(kssl_entry)->ke_refcnt) == 0) {	\
		kssl_free_entry((kssl_entry));				\
	}								\
}

#define	CRYPTO_ERR(r) ((r) != CRYPTO_SUCCESS && (r) != CRYPTO_QUEUED)

/*
 * Enqueue mblk into KSSL input queue. Watch for mblk b_cont chains
 * returned by tcp_reass() and enqueue them properly. Caller should
 * be aware that mp is modified by this macro.
 */
#define	KSSL_ENQUEUE_MP(ssl, mp) {					\
	DTRACE_PROBE1(kssl_mblk__enqueue_mp, mblk_t *, mp);		\
	if ((ssl)->rec_ass_tail == NULL) {				\
		(ssl)->rec_ass_head = (mp);				\
		while (mp->b_cont)					\
			mp = mp->b_cont;				\
		(ssl)->rec_ass_tail = (mp);				\
	} else {							\
		(ssl)->rec_ass_tail->b_cont = (mp);			\
		while (mp->b_cont)					\
			mp = mp->b_cont;				\
		(ssl)->rec_ass_tail = (mp);				\
	}								\
}

#define	SSL_MISS	123	/* Internal SSL error */

extern crypto_mechanism_t rsa_x509_mech;
extern crypto_mechanism_t hmac_md5_mech;
extern crypto_mechanism_t hmac_sha1_mech;
extern crypto_call_flag_t kssl_call_flag;
extern KSSLCipherDef cipher_defs[];

extern struct kmem_cache *kssl_cache;

#define	KSSL_TAB_INITSIZE	4
extern kssl_entry_t **kssl_entry_tab;
extern int kssl_entry_tab_size;
extern int kssl_entry_tab_nentries;
extern kmutex_t kssl_tab_mutex;

typedef struct kssl_stats {
	kstat_named_t sid_cache_lookups;
	kstat_named_t sid_cache_hits;
	kstat_named_t sid_cached;
	kstat_named_t sid_uncached;
	kstat_named_t full_handshakes;
	kstat_named_t resumed_sessions;
	kstat_named_t fallback_connections;
	kstat_named_t proxy_fallback_failed;
	kstat_named_t appdata_record_ins;
	kstat_named_t appdata_record_outs;
	kstat_named_t alloc_fails;
	kstat_named_t fatal_alerts;
	kstat_named_t warning_alerts;
	kstat_named_t no_suite_found;
	kstat_named_t compute_mac_failure;
	kstat_named_t verify_mac_failure;
	kstat_named_t record_decrypt_failure;
	kstat_named_t bad_pre_master_secret;
	kstat_named_t internal_errors;
} kssl_stats_t;

extern kssl_stats_t *kssl_statp;

#define	KSSL_COUNTER(p, v)	 atomic_add_64(&kssl_statp->p.value.ui64, v)

#define	IS_SSL_PORT	1
#define	IS_PROXY_PORT	2

extern void kssl_free_entry(kssl_entry_t *);
extern void kssl_free_context(ssl_t *);
extern int kssl_compute_record_mac(ssl_t *, int, uint64_t, SSL3ContentType,
    uchar_t *, uchar_t *, int, uchar_t *);
extern int kssl_handle_handshake_message(ssl_t *, mblk_t *, int *,
    kssl_callback_t, void *);
extern int kssl_handle_v2client_hello(ssl_t *, mblk_t *, int);
extern void kssl_uncache_sid(sslSessionID *, kssl_entry_t *);
extern int kssl_mac_encrypt_record(ssl_t *, SSL3ContentType, uchar_t *,
    uchar_t *, mblk_t *);
extern mblk_t *kssl_get_next_record(ssl_t *);
extern int kssl_get_obj_handle(kssl_entry_t *);
extern void kssl_prov_evnt(uint32_t, void *);

#ifdef	__cplusplus
}
#endif

#endif /* _INET_KSSL_KSSLIMPL_H */

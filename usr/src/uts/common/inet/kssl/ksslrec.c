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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>

#include <sys/errno.h>
#include <sys/isa_defs.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/random.h>
#include <inet/common.h>
#include <netinet/in.h>

#include <sys/systm.h>
#include <sys/param.h>

#include "ksslimpl.h"
#include "ksslapi.h"
#include "ksslproto.h"

static ssl3CipherSuiteDef cipher_suite_defs[] = {
	/* 2 X 16 byte keys +  2 x 20 byte MAC secrets, no IVs */
	{SSL_RSA_WITH_RC4_128_SHA,	cipher_rc4,	mac_sha,	72},

	/* 2 X 16 byte keys +  2 x 16 byte MAC secrets, no IVs */
	{SSL_RSA_WITH_RC4_128_MD5,	cipher_rc4,	mac_md5,	64},

	/* 2 X 8 byte keys +  2 x 20 byte MAC secrets, 2 x 8 byte IVs */
	{SSL_RSA_WITH_DES_CBC_SHA,	cipher_des,	mac_sha,	72},

	/* 2 X 24 byte keys +  2 x 20 byte MAC secrets, 2 x 8 byte IVs */
	{SSL_RSA_WITH_3DES_EDE_CBC_SHA,	cipher_3des,	mac_sha,	104},

	/* 2 X 16 byte keys +  2 x 20 byte MAC secrets, 2 x 16 byte IVs */
	{TLS_RSA_WITH_AES_128_CBC_SHA,	cipher_aes128,	mac_sha,	104},

	/* 2 X 32 byte keys +  2 x 20 byte MAC secrets, 2 x 16 byte IVs */
	{TLS_RSA_WITH_AES_256_CBC_SHA,	cipher_aes256,	mac_sha,	136},

	{SSL_RSA_WITH_NULL_SHA,		cipher_null,	mac_sha,	40}
};

static int cipher_suite_defs_nentries =
    sizeof (cipher_suite_defs) / sizeof (cipher_suite_defs[0]);

static KSSLMACDef mac_defs[] = { /* indexed by SSL3MACAlgorithm */
	/* macsz padsz HashInit HashUpdate HashFinal */

	{MD5_HASH_LEN, SSL3_MD5_PAD_LEN,
	    (hashinit_func_t)MD5Init, (hashupdate_func_t)MD5Update,
	    (hashfinal_func_t)MD5Final},

	{SHA1_HASH_LEN, SSL3_SHA1_PAD_LEN,
	    (hashinit_func_t)SHA1Init, (hashupdate_func_t)SHA1Update,
	    (hashfinal_func_t)SHA1Final},
};

static uchar_t kssl_pad_1[60] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36
};
static uchar_t kssl_pad_2[60] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c
};

static boolean_t kssl_synchronous = B_FALSE;

static void kssl_update_handshake_hashes(ssl_t *, uchar_t *, uint_t);
static int kssl_compute_handshake_hashes(ssl_t *, SSL3Hashes *, uint32_t);
static int kssl_handle_client_hello(ssl_t *, mblk_t *, int);
static int kssl_handle_client_key_exchange(ssl_t *, mblk_t *, int,
    kssl_callback_t, void *);
static int kssl_send_server_hello(ssl_t *);
static int kssl_send_certificate_and_server_hello_done(ssl_t *);
static int kssl_send_change_cipher_specs(ssl_t *);
static int kssl_send_finished(ssl_t *, int);
static int kssl_handle_finished(ssl_t *, mblk_t *, int);
static void kssl_get_hello_random(uchar_t *);
static uchar_t *kssl_rsa_unwrap(uchar_t *, size_t *);
static void kssl_cache_sid(sslSessionID *, kssl_entry_t *);
static void kssl_lookup_sid(sslSessionID *, uchar_t *, in6_addr_t *,
    kssl_entry_t *);
static int kssl_generate_tls_ms(ssl_t *, uchar_t *, size_t);
static void kssl_generate_ssl_ms(ssl_t *, uchar_t *, size_t);
static int kssl_generate_tls_keyblock(ssl_t *);
static void kssl_generate_keyblock(ssl_t *);
static void kssl_ssl3_key_material_derive_step(ssl_t *, uchar_t *, size_t,
    int, uchar_t *, int);
static int kssl_tls_PRF(ssl_t *, uchar_t *, size_t,
    uchar_t *, size_t, uchar_t *, size_t, uchar_t *, size_t);
static int kssl_tls_P_hash(crypto_mechanism_t *, crypto_key_t *,
    size_t, uchar_t *, size_t, uchar_t *, size_t, uchar_t *, size_t);
static void kssl_cke_done(void *, int);

#define	HMAC_INIT(m, k, c) \
	rv = crypto_mac_init(m, k, NULL, c, NULL); if (CRYPTO_ERR(rv)) goto end;

#define	HMAC_UPDATE(c, d, l) \
	dd.cd_raw.iov_base = (char *)d; \
	dd.cd_length = dd.cd_raw.iov_len = l; \
	rv = crypto_mac_update(c, &dd, NULL); if (CRYPTO_ERR(rv)) goto end;

#define	HMAC_FINAL(c, d, l) \
	mac.cd_raw.iov_base = (char *)d; \
	mac.cd_length = mac.cd_raw.iov_len = l; \
	rv = crypto_mac_final(c, &mac, NULL); if (CRYPTO_ERR(rv)) goto end;

/*
 * This hack can go away once we have SSL3 MAC support by KCF
 * software providers (See 4873559).
 */
extern int kcf_md5_threshold;

int
kssl_compute_record_mac(
	ssl_t *ssl,
	int direction,
	uint64_t seq_num,
	SSL3ContentType ct,
	uchar_t *versionp,
	uchar_t *buf,
	int len,
	uchar_t *digest)
{
	KSSL_HASHCTX mac_ctx;
	KSSL_HASHCTX *ctx = &mac_ctx;
	uchar_t temp[16], *p;
	KSSLCipherSpec *spec;
	boolean_t hash_use_ok = B_FALSE;
	int rv = 0;

	spec = &ssl->spec[direction];

	if (spec->mac_hashsz == 0) {
		return (1);
	}

	p = temp;

	*p++ = (seq_num >> 56) & 0xff;
	*p++ = (seq_num >> 48) & 0xff;
	*p++ = (seq_num >> 40) & 0xff;
	*p++ = (seq_num >> 32) & 0xff;
	*p++ = (seq_num >> 24) & 0xff;
	*p++ = (seq_num >> 16) & 0xff;
	*p++ = (seq_num >> 8) & 0xff;
	*p++ = (seq_num) & 0xff;
	*p++ = (uchar_t)ct;
	if (IS_TLS(ssl)) {
		*p++ = versionp[0];
		*p++ = versionp[1];
	}
	*p++ = (len >> 8) & 0xff;
	*p++ = (len) & 0xff;

	if (IS_TLS(ssl) || (spec->hmac_mech.cm_type != CRYPTO_MECH_INVALID &&
	    len >= kcf_md5_threshold)) {
		crypto_data_t dd, mac;
		struct uio uio_pt;
		struct iovec iovarray_pt[2];

		/* init the array of iovecs for use in the uio struct */
		iovarray_pt[0].iov_base = (char *)temp;
		iovarray_pt[0].iov_len = (p - temp);
		iovarray_pt[1].iov_base = (char *)buf;
		iovarray_pt[1].iov_len = len;

		/* init the uio struct for use in the crypto_data_t struct */
		bzero(&uio_pt, sizeof (uio_pt));
		uio_pt.uio_iov = iovarray_pt;
		uio_pt.uio_iovcnt = 2;
		uio_pt.uio_segflg = UIO_SYSSPACE;

		dd.cd_format = CRYPTO_DATA_UIO;
		dd.cd_offset = 0;
		dd.cd_length =  (p - temp) + len;
		dd.cd_miscdata = NULL;
		dd.cd_uio = &uio_pt;

		mac.cd_format = CRYPTO_DATA_RAW;
		mac.cd_offset = 0;
		mac.cd_raw.iov_base = (char *)digest;
		mac.cd_length = mac.cd_raw.iov_len = spec->mac_hashsz;

		/*
		 * The calling context can tolerate a blocking call here.
		 * For outgoing traffic, we are in user context when called
		 * from kssl_data_out_cb(). For incoming traffic past the
		 * SSL handshake, we are in user context when called from
		 * kssl_data_in_proc_cb(). During the SSL handshake, we are
		 * called for client_finished message handling from a taskq
		 * thread.
		 */
		rv = crypto_mac(&spec->hmac_mech, &dd, &spec->hmac_key,
		    NULL, &mac, NULL);

		if (CRYPTO_ERR(rv)) {
			hash_use_ok = (rv == CRYPTO_MECH_NOT_SUPPORTED &&
			    !IS_TLS(ssl));
			if (!hash_use_ok) {
				DTRACE_PROBE1(kssl_err__crypto_mac_error,
				    int, rv);
				KSSL_COUNTER(compute_mac_failure, 1);
			}
		}
	} else
		hash_use_ok = B_TRUE;

	if (hash_use_ok) {
		bcopy(&(ssl->mac_ctx[direction][0]), ctx,
		    sizeof (KSSL_HASHCTX));
		spec->MAC_HashUpdate((void *)ctx, temp, p - temp);
		spec->MAC_HashUpdate((void *)ctx, buf, len);
		spec->MAC_HashFinal(digest, (void *)ctx);

		bcopy(&(ssl->mac_ctx[direction][1]), ctx,
		    sizeof (KSSL_HASHCTX));
		spec->MAC_HashUpdate((void *)ctx, digest, spec->mac_hashsz);
		spec->MAC_HashFinal(digest, (void *)ctx);
	}

	return (rv);
}

/*
 * Handles handshake messages.
 * Messages to be replied are returned in handshake_sendbuf.
 */
int
kssl_handle_handshake_message(ssl_t *ssl, mblk_t *mp, int *err,
    kssl_callback_t cbfn, void *arg)
{
	uint32_t msglen;
	uchar_t msghdr[4];

	ASSERT(ssl->msg.state == MSG_BODY);
	ASSERT(ssl->msg.msglen_bytes == 3);
	ASSERT(mp->b_wptr >= mp->b_rptr + ssl->msg.msglen);

	ssl->sslcnt++;
	msglen = ssl->msg.msglen;

	if (ssl->msg.type == client_hello) {
		MD5Init(&ssl->hs_md5);
		SHA1Init(&ssl->hs_sha1);
	}

	if (ssl->msg.type == finished && ssl->resumed == B_FALSE) {
		if (kssl_compute_handshake_hashes(ssl, &ssl->hs_hashes,
		    sender_client) != 0) {
			*err = SSL_MISS;
			return (0);
		}
	}

	if (ssl->msg.type != finished || ssl->resumed == B_FALSE) {
		msghdr[0] = (uchar_t)ssl->msg.type;

		msghdr[1] = (uchar_t)(msglen >> 16);
		msghdr[2] = (uchar_t)(msglen >> 8);
		msghdr[3] = (uchar_t)(msglen);
		kssl_update_handshake_hashes(ssl, msghdr, 4);
		kssl_update_handshake_hashes(ssl, mp->b_rptr, msglen);
	}

	ssl->msg.state = MSG_INIT;
	ssl->msg.msglen = 0;
	ssl->msg.msglen_bytes = 0;

	switch (ssl->msg.type) {
	case client_hello:
		if (ssl->hs_waitstate != wait_client_hello) {
			kssl_send_alert(ssl, alert_fatal,
			    unexpected_message);
			*err = EBADMSG;
			ssl->activeinput = B_FALSE;
			return (1);
		}
		*err = kssl_handle_client_hello(ssl, mp, msglen);
		if (*err == SSL_MISS) {
			ssl->activeinput = B_FALSE;
			return (0);
		}
		return (1);
	case client_key_exchange:
		if (ssl->hs_waitstate != wait_client_key) {
			kssl_send_alert(ssl, alert_fatal,
			    unexpected_message);
			*err = EBADMSG;
			ssl->activeinput = B_FALSE;
			return (1);
		}
		*err = kssl_handle_client_key_exchange(ssl, mp,
		    msglen, cbfn, arg);
		return (1);
	case finished:
		if (ssl->hs_waitstate != wait_finished) {
			kssl_send_alert(ssl, alert_fatal,
			    unexpected_message);
			*err = EBADMSG;
			ssl->activeinput = B_FALSE;
			return (1);
		}
		*err = kssl_handle_finished(ssl, mp, msglen);
		return (1);
	default:
		kssl_send_alert(ssl, alert_fatal, unexpected_message);
		ssl->activeinput = B_FALSE;
		*err = EBADMSG;
		return (1);
	}
}

static void
kssl_update_handshake_hashes(ssl_t *ssl, uchar_t *buf, uint_t len)
{
	MD5Update(&ssl->hs_md5, buf, len);
	SHA1Update(&ssl->hs_sha1, buf, len);
}

static int
kssl_compute_handshake_hashes(
	ssl_t *ssl,
	SSL3Hashes *hashes,
	uint32_t sender)
{
	MD5_CTX md5 = ssl->hs_md5;	/* clone md5 context */
	SHA1_CTX sha1 = ssl->hs_sha1;	/* clone sha1 context */
	MD5_CTX *md5ctx = &md5;
	SHA1_CTX *sha1ctx = &sha1;

	if (IS_TLS(ssl)) {
		uchar_t seed[MD5_HASH_LEN + SHA1_HASH_LEN];
		char *label;

		/*
		 * Do not take another hash step here.
		 * Just complete the operation.
		 */
		MD5Final(hashes->md5, md5ctx);
		SHA1Final(hashes->sha1, sha1ctx);

		bcopy(hashes->md5, seed, MD5_HASH_LEN);
		bcopy(hashes->sha1, seed + MD5_HASH_LEN, SHA1_HASH_LEN);

		if (sender == sender_client)
			label = TLS_CLIENT_FINISHED_LABEL;
		else
			label = TLS_SERVER_FINISHED_LABEL;

		return (kssl_tls_PRF(ssl,
		    ssl->sid.master_secret,
		    (size_t)SSL3_MASTER_SECRET_LEN,
		    (uchar_t *)label, strlen(label),
		    seed, (size_t)(MD5_HASH_LEN + SHA1_HASH_LEN),
		    hashes->tlshash, (size_t)TLS_FINISHED_SIZE));
	} else {
		uchar_t s[4];
		s[0] = (sender >> 24) & 0xff;
		s[1] = (sender >> 16) & 0xff;
		s[2] = (sender >> 8) & 0xff;
		s[3] = (sender) & 0xff;

		MD5Update(md5ctx, s, 4);
		MD5Update(md5ctx, ssl->sid.master_secret,
		    SSL3_MASTER_SECRET_LEN);
		MD5Update(md5ctx, kssl_pad_1, SSL3_MD5_PAD_LEN);
		MD5Final(hashes->md5, md5ctx);

		MD5Init(md5ctx);
		MD5Update(md5ctx, ssl->sid.master_secret,
		    SSL3_MASTER_SECRET_LEN);
		MD5Update(md5ctx, kssl_pad_2, SSL3_MD5_PAD_LEN);
		MD5Update(md5ctx, hashes->md5, MD5_HASH_LEN);
		MD5Final(hashes->md5, md5ctx);

		SHA1Update(sha1ctx, s, 4);
		SHA1Update(sha1ctx, ssl->sid.master_secret,
		    SSL3_MASTER_SECRET_LEN);
		SHA1Update(sha1ctx, kssl_pad_1, SSL3_SHA1_PAD_LEN);
		SHA1Final(hashes->sha1, sha1ctx);

		SHA1Init(sha1ctx);
		SHA1Update(sha1ctx, ssl->sid.master_secret,
		    SSL3_MASTER_SECRET_LEN);
		SHA1Update(sha1ctx, kssl_pad_2, SSL3_SHA1_PAD_LEN);
		SHA1Update(sha1ctx, hashes->sha1, SHA1_HASH_LEN);
		SHA1Final(hashes->sha1, sha1ctx);
		return (0);
	}
}


/*
 * Minimum message length for a client hello =
 * 2-byte client_version +
 * 32-byte random +
 * 1-byte session_id length +
 * 2-byte cipher_suites length +
 * 1-byte compression_methods length +
 * 1-byte CompressionMethod.null
 */
#define	KSSL_SSL3_CH_MIN_MSGLEN	(39)

/*
 * Process SSL/TLS Client Hello message. Return 0 on success, errno value
 * or SSL_MISS if no cipher suite of the server matches the list received
 * in the message.
 */
static int
kssl_handle_client_hello(ssl_t *ssl, mblk_t *mp, int msglen)
{
	uchar_t *msgend;
	int err;
	SSL3AlertDescription desc = illegal_parameter;
	uint_t sidlen, cslen, cmlen;
	uchar_t *suitesp;
	uint_t i, j;
	uint16_t suite, selected_suite;
	int ch_msglen = KSSL_SSL3_CH_MIN_MSGLEN;
	boolean_t suite_found = B_FALSE;

	ASSERT(mp->b_wptr >= mp->b_rptr + msglen);
	ASSERT(ssl->msg.type == client_hello);
	ASSERT(ssl->hs_waitstate == wait_client_hello);
	ASSERT(ssl->resumed == B_FALSE);

	if (msglen < ch_msglen) {
		DTRACE_PROBE2(kssl_err__msglen_less_than_minimum,
		    int, msglen, int, ch_msglen);
		goto falert;
	}

	msgend = mp->b_rptr + msglen;

	/* Support SSLv3 (version == 3.0) or TLS (version == 3.1) */
	if (ssl->major_version != 3 || (ssl->major_version == 3 &&
	    ssl->minor_version != 0 && ssl->minor_version != 1)) {
		DTRACE_PROBE2(kssl_err__SSL_version_not_supported,
		    uchar_t, ssl->major_version,
		    uchar_t, ssl->minor_version);
		desc = handshake_failure;
		goto falert;
	}
	mp->b_rptr += 2; /* skip the version bytes */

	/* read client random field */
	bcopy(mp->b_rptr, ssl->client_random, SSL3_RANDOM_LENGTH);
	mp->b_rptr += SSL3_RANDOM_LENGTH;

	/* read session ID length */
	ASSERT(ssl->sid.cached == B_FALSE);
	sidlen = *mp->b_rptr++;
	ch_msglen += sidlen;
	if (msglen < ch_msglen) {
		DTRACE_PROBE2(kssl_err__invalid_message_length_after_ver,
		    int, msglen, int, ch_msglen);
		goto falert;
	}
	if (sidlen != SSL3_SESSIONID_BYTES) {
		mp->b_rptr += sidlen;
	} else {
		kssl_lookup_sid(&ssl->sid, mp->b_rptr, &ssl->faddr,
		    ssl->kssl_entry);
		mp->b_rptr += SSL3_SESSIONID_BYTES;
	}

	/* read cipher suite length */
	cslen = ((uint_t)mp->b_rptr[0] << 8) + (uint_t)mp->b_rptr[1];
	mp->b_rptr += 2;
	ch_msglen += cslen;

	/*
	 * This check can't be a "!=" since there can be
	 * compression methods other than CompressionMethod.null.
	 * Also, there can be extra data (TLS extensions) after the
	 * compression methods field.
	 */
	if (msglen < ch_msglen) {
		DTRACE_PROBE2(kssl_err__invalid_message_length_after_cslen,
		    int, msglen, int, ch_msglen);
		goto falert;
	}

	/* The length has to be even since a cipher suite is 2-byte long. */
	if (cslen & 0x1) {
		DTRACE_PROBE1(kssl_err__uneven_cipher_suite_length,
		    uint_t, cslen);
		goto falert;
	}
	suitesp = mp->b_rptr;

	/* session resumption checks */
	if (ssl->sid.cached == B_TRUE) {
		suite = ssl->sid.cipher_suite;
		for (j = 0; j < cslen; j += 2) {
			DTRACE_PROBE2(kssl_cipher_suite_check_resumpt,
			    uint16_t, suite,
			    uint16_t,
			    (uint16_t)((suitesp[j] << 8) + suitesp[j+1]));
			/* Check for regular (true) cipher suite. */
			if (suitesp[j] == ((suite >> 8) & 0xff) &&
			    suitesp[j + 1] == (suite & 0xff)) {
				DTRACE_PROBE1(kssl_cipher_suite_found_resumpt,
				    uint16_t, suite);
				suite_found = B_TRUE;
				selected_suite = suite;
			}

			/* Check for SCSV. */
			if (suitesp[j] ==  ((SSL_SCSV >> 8) & 0xff) &&
			    suitesp[j + 1] == (SSL_SCSV & 0xff)) {
				DTRACE_PROBE(kssl_scsv_found_resumpt);
				ssl->secure_renegotiation = B_TRUE;
			}

			/*
			 * If we got cipher suite match and SCSV we can
			 * terminate the cycle now.
			 */
			if (suite_found && ssl->secure_renegotiation)
				break;
		}
		if (suite_found)
			goto suite_found;
		kssl_uncache_sid(&ssl->sid, ssl->kssl_entry);
	}

	/* Check if this server is capable of the cipher suite. */
	for (i = 0; i < ssl->kssl_entry->kssl_cipherSuites_nentries; i++) {
		suite = ssl->kssl_entry->kssl_cipherSuites[i];
		for (j = 0; j < cslen; j += 2) {
			DTRACE_PROBE2(kssl_cipher_suite_check, uint16_t, suite,
			    uint16_t,
			    (uint16_t)((suitesp[j] << 8) + suitesp[j+1]));
			/* Check for regular (true) cipher suite. */
			if (suitesp[j] == ((suite >> 8) & 0xff) &&
			    suitesp[j + 1] == (suite & 0xff)) {
				DTRACE_PROBE1(kssl_cipher_suite_found,
				    uint16_t, suite);
				suite_found = B_TRUE;
				selected_suite = suite;
			}

			/* Check for SCSV. */
			if (suitesp[j] ==  ((SSL_SCSV >> 8) & 0xff) &&
			    suitesp[j + 1] == (SSL_SCSV & 0xff)) {
				DTRACE_PROBE(kssl_scsv_found);
				ssl->secure_renegotiation = B_TRUE;
			}

			/*
			 * If we got cipher suite match and SCSV or went
			 * through the whole list of client cipher suites
			 * (hence we know if SCSV was present or not) we
			 * can terminate the cycle now.
			 */
			if (suite_found &&
			    (ssl->secure_renegotiation || (i > 0)))
				break;
		}
		if (suite_found)
			break;
	}
	if (!suite_found) {
		if (ssl->sslcnt == 1) {
			DTRACE_PROBE(kssl_no_cipher_suite_found);
			KSSL_COUNTER(no_suite_found, 1);
			/*
			 * If there is no fallback point terminate the
			 * handshake with SSL alert otherwise return with
			 * SSL_MISS.
			 */
			if (ssl->kssl_entry->ke_fallback_head == NULL) {
				DTRACE_PROBE(kssl_no_fallback);
				desc = handshake_failure;
				goto falert;
			} else {
				return (SSL_MISS);
			}
		}
		desc = handshake_failure;
		DTRACE_PROBE(kssl_err__no_cipher_suites_found);
		goto falert;
	}

suite_found:
	mp->b_rptr += cslen;

	/*
	 * Check for the mandatory CompressionMethod.null. We do not
	 * support any other compression methods.
	 */
	cmlen = *mp->b_rptr++;
	ch_msglen += cmlen - 1;	/* -1 accounts for the null method */
	if (msglen < ch_msglen) {
		DTRACE_PROBE2(kssl_err__invalid_message_length_after_complen,
		    int, msglen, int, ch_msglen);
		goto falert;
	}

	/*
	 * Search for null compression method (encoded as 0 byte) in the
	 * compression methods field.
	 */
	while (cmlen >= 1) {
		if (*mp->b_rptr++ == 0)
			break;
		cmlen--;
	}

	if (cmlen == 0) {
		desc = handshake_failure;
		DTRACE_PROBE(kssl_err__no_null_compression_method);
		goto falert;
	}

	/* Find the suite in the internal cipher suite table. */
	for (i = 0; i < cipher_suite_defs_nentries; i++) {
		if (selected_suite == cipher_suite_defs[i].suite) {
			break;
		}
	}

	/* Get past the remaining compression methods (minus null method). */
	mp->b_rptr += cmlen - 1;

	ASSERT(i < cipher_suite_defs_nentries);

	ssl->pending_cipher_suite = selected_suite;
	ssl->pending_malg = cipher_suite_defs[i].malg;
	ssl->pending_calg = cipher_suite_defs[i].calg;
	ssl->pending_keyblksz = cipher_suite_defs[i].keyblksz;

	/* Parse TLS extensions (if any). */
	if (ch_msglen + 2 < msglen) {
		/* Get the length of the extensions. */
		uint16_t ext_total_len = ((uint_t)mp->b_rptr[0] << 8) +
		    (uint_t)mp->b_rptr[1];
		DTRACE_PROBE1(kssl_total_length_extensions, uint16_t,
		    ext_total_len);
		/*
		 * Consider zero extensions length as invalid extension
		 * encoding.
		 */
		if (ext_total_len == 0) {
			DTRACE_PROBE1(kssl_err__zero_extensions_length,
			    mblk_t *, mp);
			goto falert;
		}
		ch_msglen += 2;
		if (ch_msglen + ext_total_len > msglen) {
			DTRACE_PROBE2(kssl_err__invalid_extensions_length,
			    int, msglen, int, ch_msglen);
			goto falert;
		}
		mp->b_rptr += 2;

		/*
		 * Go through the TLS extensions. This is only done to check
		 * for the presence of renegotiation_info extension. We do not
		 * support any other TLS extensions and hence ignore them.
		 */
		while (mp->b_rptr < msgend) {
			uint16_t ext_len, ext_type;

			/*
			 * Check that the extension has at least type and
			 * length (2 + 2 bytes).
			 */
			if (ch_msglen + 4 > msglen) {
				DTRACE_PROBE(kssl_err__invalid_ext_format);
				goto falert;
			}

			/* Get extension type and length */
			ext_type = ((uint_t)mp->b_rptr[0] << 8) +
			    (uint_t)mp->b_rptr[1];
			mp->b_rptr += 2;
			ext_len = ((uint_t)mp->b_rptr[0] << 8) +
			    (uint_t)mp->b_rptr[1];
			mp->b_rptr += 2;
			ch_msglen += 4;
			DTRACE_PROBE3(kssl_ext_detected, uint16_t, ext_type,
			    uint16_t, ext_len, mblk_t *, mp);

			/*
			 * Make sure the contents of the extension are
			 * accessible.
			 */
			if (ch_msglen + ext_len > msglen) {
				DTRACE_PROBE1(
				    kssl_err__invalid_ext_len,
				    uint16_t, ext_len);
				goto falert;
			}

			switch (ext_type) {
			case TLSEXT_RENEGOTIATION_INFO:
				/*
				 * Search for empty "renegotiation_info"
				 * extension (encoded as ff 01 00 01 00).
				 */
				DTRACE_PROBE(kssl_reneg_info_found);
				if ((ext_len != 1) ||
				    (*mp->b_rptr != 0)) {
					DTRACE_PROBE2(
					    kssl_err__non_empty_reneg_info,
					    uint16_t, ext_len,
					    mblk_t *, mp);
					goto falert;
				}
				ssl->secure_renegotiation = B_TRUE;
				break;
			default:
				/* FALLTHRU */
				break;
			}

			/* jump to the next extension */
			ch_msglen += ext_len;
			mp->b_rptr += ext_len;
		}
	}

	mp->b_rptr = msgend;

	if (ssl->sid.cached == B_TRUE) {
		err = kssl_send_server_hello(ssl);
		if (err != 0) {
			return (err);
		}
		if (IS_TLS(ssl))
			err = kssl_generate_tls_keyblock(ssl);
		else
			kssl_generate_keyblock(ssl);

		err = kssl_send_change_cipher_specs(ssl);
		if (err != 0) {
			return (err);
		}

		err = kssl_send_finished(ssl, 1);
		if (err != 0)
			return (err);

		err = kssl_compute_handshake_hashes(ssl, &ssl->hs_hashes,
		    sender_client);
		if (err != 0)
			return (err);

		ssl->hs_waitstate = wait_change_cipher;
		ssl->resumed = B_TRUE;
		ssl->activeinput = B_FALSE;
		KSSL_COUNTER(resumed_sessions, 1);
		return (0);
	}

	(void) random_get_pseudo_bytes(ssl->sid.session_id,
	    SSL3_SESSIONID_BYTES);
	ssl->sid.client_addr = ssl->faddr;
	ssl->sid.cipher_suite = selected_suite;

	err = kssl_send_server_hello(ssl);
	if (err != 0) {
		return (err);
	}
	err = kssl_send_certificate_and_server_hello_done(ssl);
	if (err != 0) {
		return (err);
	}
	KSSL_COUNTER(full_handshakes, 1);
	ssl->hs_waitstate = wait_client_key;
	ssl->activeinput = B_FALSE;
	return (0);

falert:
	kssl_send_alert(ssl, alert_fatal, desc);
	return (EBADMSG);
}

#define	SET_HASH_INDEX(index, s, clnt_addr) {				\
	int addr;							\
									\
	IN6_V4MAPPED_TO_IPADDR(clnt_addr, addr);			\
	index = addr ^ (((int)(s)[0] << 24) | ((int)(s)[1] << 16) |	\
	    ((int)(s)[2] << 8) | (int)(s)[SSL3_SESSIONID_BYTES - 1]);	\
}

/*
 * Creates a cache entry. Sets the sid->cached flag
 * and sid->time fields. So, the caller should not set them.
 */
static void
kssl_cache_sid(sslSessionID *sid, kssl_entry_t *kssl_entry)
{
	uint_t index;
	uchar_t *s = sid->session_id;
	kmutex_t *lock;

	ASSERT(sid->cached == B_FALSE);

	/* set the values before creating the cache entry */
	sid->cached = B_TRUE;
	sid->time = ddi_get_lbolt();

	SET_HASH_INDEX(index, s, &sid->client_addr);
	index %= kssl_entry->sid_cache_nentries;

	lock = &(kssl_entry->sid_cache[index].se_lock);
	mutex_enter(lock);
	kssl_entry->sid_cache[index].se_used++;
	bcopy(sid, &(kssl_entry->sid_cache[index].se_sid), sizeof (*sid));
	mutex_exit(lock);

	KSSL_COUNTER(sid_cached, 1);
}

/*
 * Invalidates the cache entry, if any. Clears the sid->cached flag
 * as a side effect.
 */
void
kssl_uncache_sid(sslSessionID *sid, kssl_entry_t *kssl_entry)
{
	uint_t index;
	uchar_t *s = sid->session_id;
	sslSessionID *csid;
	kmutex_t *lock;

	ASSERT(sid->cached == B_TRUE);
	sid->cached = B_FALSE;

	SET_HASH_INDEX(index, s, &sid->client_addr);
	index %= kssl_entry->sid_cache_nentries;

	lock = &(kssl_entry->sid_cache[index].se_lock);
	mutex_enter(lock);
	csid = &(kssl_entry->sid_cache[index].se_sid);
	if (!(IN6_ARE_ADDR_EQUAL(&csid->client_addr, &sid->client_addr)) ||
	    bcmp(csid->session_id, s, SSL3_SESSIONID_BYTES)) {
		mutex_exit(lock);
		return;
	}
	csid->cached = B_FALSE;
	mutex_exit(lock);

	KSSL_COUNTER(sid_uncached, 1);
}

static void
kssl_lookup_sid(sslSessionID *sid, uchar_t *s, in6_addr_t *faddr,
    kssl_entry_t *kssl_entry)
{
	uint_t index;
	kmutex_t *lock;
	sslSessionID *csid;

	KSSL_COUNTER(sid_cache_lookups, 1);

	SET_HASH_INDEX(index, s, faddr);
	index %= kssl_entry->sid_cache_nentries;

	lock = &(kssl_entry->sid_cache[index].se_lock);
	mutex_enter(lock);
	csid = &(kssl_entry->sid_cache[index].se_sid);
	if (csid->cached == B_FALSE ||
	    !IN6_ARE_ADDR_EQUAL(&csid->client_addr, faddr) ||
	    bcmp(csid->session_id, s, SSL3_SESSIONID_BYTES)) {
		mutex_exit(lock);
		return;
	}

	if (TICK_TO_SEC(ddi_get_lbolt() - csid->time) >
	    kssl_entry->sid_cache_timeout) {
		csid->cached = B_FALSE;
		mutex_exit(lock);
		return;
	}

	bcopy(csid, sid, sizeof (*sid));
	mutex_exit(lock);
	ASSERT(sid->cached == B_TRUE);

	KSSL_COUNTER(sid_cache_hits, 1);
}

static uchar_t *
kssl_rsa_unwrap(uchar_t *buf, size_t *lenp)
{
	size_t len = *lenp;
	int i = 2;

	if (buf[0] != 0 || buf[1] != 2) {
		return (NULL);
	}

	while (i < len) {
		if (buf[i++] == 0) {
			*lenp = len - i;
			break;
		}
	}

	if (i == len) {
		return (NULL);
	}

	return (buf + i);
}


#define	KSSL_SSL3_SH_RECLEN	(74)
#define	KSSL_SSL3_FIN_MSGLEN	(36)
#define	KSSL_EMPTY_RENEG_INFO_LEN	(7)

#define	KSSL_SSL3_MAX_CCP_FIN_MSGLEN	(128)	/* comfortable upper bound */

/*
 * Send ServerHello record to the client.
 */
static int
kssl_send_server_hello(ssl_t *ssl)
{
	mblk_t *mp;
	uchar_t *buf;
	uchar_t *msgstart;
	uint16_t reclen = KSSL_SSL3_SH_RECLEN;

	mp = allocb(ssl->tcp_mss, BPRI_HI);
	if (mp == NULL) {
		KSSL_COUNTER(alloc_fails, 1);
		return (ENOMEM);
	}
	ssl->handshake_sendbuf = mp;
	buf = mp->b_wptr;

	if (ssl->secure_renegotiation)
		reclen += KSSL_EMPTY_RENEG_INFO_LEN;

	/* 5 byte record header */
	buf[0] = content_handshake;
	buf[1] = ssl->major_version;
	buf[2] = ssl->minor_version;
	buf[3] = reclen >> 8;
	buf[4] = reclen & 0xff;
	buf += SSL3_HDR_LEN;

	msgstart = buf;

	/* 6 byte message header */
	buf[0] = (uchar_t)server_hello;			/* message type */
	buf[1] = 0;					/* message len byte 0 */
	buf[2] = ((reclen - 4) >> 8) &
	    0xff;					/* message len byte 1 */
	buf[3] = (reclen - 4) & 0xff;	/* message len byte 2 */

	buf[4] = ssl->major_version;	/* version byte 0 */
	buf[5] = ssl->minor_version;	/* version byte 1 */

	buf += 6;

	kssl_get_hello_random(ssl->server_random);
	bcopy(ssl->server_random, buf, SSL3_RANDOM_LENGTH);
	buf += SSL3_RANDOM_LENGTH;

	buf[0] = SSL3_SESSIONID_BYTES;
	bcopy(ssl->sid.session_id, buf + 1, SSL3_SESSIONID_BYTES);
	buf += SSL3_SESSIONID_BYTES + 1;

	buf[0] = (ssl->pending_cipher_suite >> 8) & 0xff;
	buf[1] = ssl->pending_cipher_suite & 0xff;

	buf[2] = 0;	/* No compression */
	buf += 3;

	/*
	 * Add "renegotiation_info" extension if the ClientHello message
	 * contained either SCSV value in cipher suite list or
	 * "renegotiation_info" extension. This is per RFC 5746, section 3.6.
	 */
	if (ssl->secure_renegotiation) {
		/* Extensions length */
		buf[0] = 0x00;
		buf[1] = 0x05;
		/* empty renegotiation_info extension encoding (section 3.2) */
		buf[2] = 0xff;
		buf[3] = 0x01;
		buf[4] = 0x00;
		buf[5] = 0x01;
		buf[6] = 0x00;
		buf += KSSL_EMPTY_RENEG_INFO_LEN;
	}

	mp->b_wptr = buf;
	ASSERT(mp->b_wptr < mp->b_datap->db_lim);

	kssl_update_handshake_hashes(ssl, msgstart, reclen);
	return (0);
}

static void
kssl_get_hello_random(uchar_t *buf)
{
	timestruc_t ts;
	time_t sec;

	gethrestime(&ts);
	sec = ts.tv_sec;

	buf[0] = (sec >> 24) & 0xff;
	buf[1] = (sec >> 16) & 0xff;
	buf[2] = (sec >> 8) & 0xff;
	buf[3] = (sec) & 0xff;

	(void) random_get_pseudo_bytes(&buf[4], SSL3_RANDOM_LENGTH - 4);

	/* Should this be caching? */
}

static int
kssl_tls_P_hash(crypto_mechanism_t *mech, crypto_key_t *key, size_t hashlen,
    uchar_t *label, size_t label_len, uchar_t *seed, size_t seedlen,
    uchar_t *data, size_t datalen)
{
	int rv = 0;
	uchar_t A1[MAX_HASH_LEN], result[MAX_HASH_LEN];
	int bytes_left = (int)datalen;
	crypto_data_t dd, mac;
	crypto_context_t ctx;

	dd.cd_format = CRYPTO_DATA_RAW;
	dd.cd_offset = 0;
	mac.cd_format = CRYPTO_DATA_RAW;
	mac.cd_offset = 0;

	/*
	 * A(i) = HMAC_hash(secret, seed + A(i-1));
	 * A(0) = seed;
	 *
	 * Compute A(1):
	 * A(1) = HMAC_hash(secret, label + seed)
	 *
	 */
	HMAC_INIT(mech, key, &ctx);
	HMAC_UPDATE(ctx, label, label_len);
	HMAC_UPDATE(ctx, seed, seedlen);
	HMAC_FINAL(ctx, A1, hashlen);

	/* Compute A(2) ... A(n) */
	while (bytes_left > 0) {
		HMAC_INIT(mech, key, &ctx);
		HMAC_UPDATE(ctx, A1, hashlen);
		HMAC_UPDATE(ctx, label, label_len);
		HMAC_UPDATE(ctx, seed, seedlen);
		HMAC_FINAL(ctx, result, hashlen);

		/*
		 * The A(i) value is stored in "result".
		 * Save the results of the MAC so it can be input to next
		 * iteration.
		 */
		if (bytes_left > hashlen) {
			/* Store the chunk result */
			bcopy(result, data, hashlen);
			data += hashlen;

			bytes_left -= hashlen;

			/* Update A1 for next iteration */
			HMAC_INIT(mech, key, &ctx);
			HMAC_UPDATE(ctx, A1, hashlen);
			HMAC_FINAL(ctx, A1, hashlen);

		} else {
			bcopy(result, data, bytes_left);
			data += bytes_left;
			bytes_left = 0;
		}
	}
end:
	if (CRYPTO_ERR(rv)) {
		DTRACE_PROBE1(kssl_err__crypto_mac_error, int, rv);
		KSSL_COUNTER(compute_mac_failure, 1);
	}
	return (rv);
}

/* ARGSUSED */
static int
kssl_tls_PRF(ssl_t *ssl, uchar_t *secret, size_t secret_len, uchar_t *label,
    size_t label_len, uchar_t *seed, size_t seed_len, uchar_t *prfresult,
    size_t prfresult_len)
{
	/*
	 * RFC 2246:
	 *  PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
	 *				P_SHA1(S2, label + seed);
	 * S1 = 1st half of secret.
	 * S1 = 2nd half of secret.
	 *
	 */

	int rv, i;
	uchar_t psha1[MAX_KEYBLOCK_LENGTH];
	crypto_key_t S1, S2;

	/* length of secret keys is ceil(length/2) */
	size_t slen = roundup(secret_len, 2) / 2;

	if (prfresult_len >  MAX_KEYBLOCK_LENGTH) {
		DTRACE_PROBE1(kssl_err__unexpected_keyblock_size,
		    size_t, prfresult_len);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	ASSERT(prfresult != NULL);
	ASSERT(label != NULL);
	ASSERT(seed != NULL);

	S1.ck_data   = secret;
	S1.ck_length = slen * 8; /* bits */
	S1.ck_format = CRYPTO_KEY_RAW;

	S2.ck_data   = secret + slen;
	S2.ck_length = slen * 8; /* bits */
	S2.ck_format = CRYPTO_KEY_RAW;

	rv = kssl_tls_P_hash(&hmac_md5_mech, &S1, MD5_HASH_LEN,
	    label, label_len,
	    seed, seed_len,
	    prfresult, prfresult_len);
	if (CRYPTO_ERR(rv))
		goto end;

	rv = kssl_tls_P_hash(&hmac_sha1_mech, &S2, SHA1_HASH_LEN,
	    label, label_len,
	    seed, seed_len,
	    psha1, prfresult_len);
	if (CRYPTO_ERR(rv))
		goto end;

	for (i = 0; i < prfresult_len; i++)
		prfresult[i] ^= psha1[i];

end:
	if (CRYPTO_ERR(rv))
		bzero(prfresult, prfresult_len);

	return (rv);
}

#define	IS_BAD_PRE_MASTER_SECRET(pms, pmslen, ssl)			\
	(pms == NULL || pmslen != SSL3_PRE_MASTER_SECRET_LEN ||		\
	pms[0] != ssl->major_version || pms[1] != ssl->minor_version)

#define	FAKE_PRE_MASTER_SECRET(pms, pmslen, ssl, buf) {			\
		KSSL_COUNTER(bad_pre_master_secret, 1);			\
		pms = buf;						\
		pmslen = SSL3_PRE_MASTER_SECRET_LEN;			\
		pms[0] = ssl->major_version;				\
		pms[1] = ssl->minor_version;				\
		(void) random_get_pseudo_bytes(&buf[2], pmslen - 2);	\
}

static int
kssl_generate_tls_ms(ssl_t *ssl, uchar_t *pms, size_t pmslen)
{
	uchar_t buf[SSL3_PRE_MASTER_SECRET_LEN];
	uchar_t seed[SSL3_RANDOM_LENGTH * 2];

	/*
	 * Computing the master secret:
	 * ----------------------------
	 * master_secret = PRF (pms, "master secret",
	 *		ClientHello.random + ServerHello.random);
	 */
	bcopy(ssl->client_random, seed, SSL3_RANDOM_LENGTH);
	bcopy(ssl->server_random, seed + SSL3_RANDOM_LENGTH,
	    SSL3_RANDOM_LENGTH);

	/* if pms is bad fake it to thwart Bleichenbacher attack */
	if (IS_BAD_PRE_MASTER_SECRET(pms, pmslen, ssl)) {
		DTRACE_PROBE(kssl_err__under_Bleichenbacher_attack);
		FAKE_PRE_MASTER_SECRET(pms, pmslen, ssl, buf);
	}

	return (kssl_tls_PRF(ssl,
	    pms, pmslen,
	    (uchar_t *)TLS_MASTER_SECRET_LABEL,
	    (size_t)strlen(TLS_MASTER_SECRET_LABEL),
	    seed, sizeof (seed),
	    ssl->sid.master_secret,
	    (size_t)sizeof (ssl->sid.master_secret)));
}


static void
kssl_generate_ssl_ms(ssl_t *ssl, uchar_t *pms, size_t pmslen)
{
	uchar_t buf[SSL3_PRE_MASTER_SECRET_LEN];
	uchar_t *ms;
	int hlen = MD5_HASH_LEN;

	ms = ssl->sid.master_secret;

	/* if pms is bad fake it to thwart Bleichenbacher attack */
	if (IS_BAD_PRE_MASTER_SECRET(pms, pmslen, ssl)) {
		DTRACE_PROBE(kssl_err__under_Bleichenbacher_attack);
		FAKE_PRE_MASTER_SECRET(pms, pmslen, ssl, buf);
	}

	kssl_ssl3_key_material_derive_step(ssl, pms, pmslen, 1, ms, 0);
	kssl_ssl3_key_material_derive_step(ssl, pms, pmslen, 2, ms + hlen, 0);
	kssl_ssl3_key_material_derive_step(ssl, pms, pmslen, 3, ms + 2 * hlen,
	    0);
}

static int
kssl_generate_tls_keyblock(ssl_t *ssl)
{
	uchar_t seed[2 * SSL3_RANDOM_LENGTH];

	bcopy(ssl->server_random, seed, SSL3_RANDOM_LENGTH);
	bcopy(ssl->client_random, seed + SSL3_RANDOM_LENGTH,
	    SSL3_RANDOM_LENGTH);

	return (kssl_tls_PRF(ssl, ssl->sid.master_secret,
	    (size_t)SSL3_MASTER_SECRET_LEN,
	    (uchar_t *)TLS_KEY_EXPANSION_LABEL,
	    (size_t)strlen(TLS_KEY_EXPANSION_LABEL),
	    seed, (size_t)sizeof (seed),
	    ssl->pending_keyblock,
	    (size_t)ssl->pending_keyblksz));

}

static void
kssl_generate_keyblock(ssl_t *ssl)
{
	uchar_t *ms;
	size_t mslen = SSL3_MASTER_SECRET_LEN;
	int hlen = MD5_HASH_LEN;
	uchar_t *keys = ssl->pending_keyblock;
	int steps = howmany(ssl->pending_keyblksz, hlen);
	int i;

	ms = ssl->sid.master_secret;

	ASSERT(hlen * steps <= MAX_KEYBLOCK_LENGTH);

	for (i = 1; i <= steps; i++) {
		kssl_ssl3_key_material_derive_step(ssl, ms, mslen, i, keys, 1);
		keys += hlen;
	}
}

static char *ssl3_key_derive_seeds[9] = {"A", "BB", "CCC", "DDDD", "EEEEE",
	"FFFFFF", "GGGGGGG", "HHHHHHHH", "IIIIIIIII"};

static void
kssl_ssl3_key_material_derive_step(ssl_t *ssl, uchar_t *secret,
    size_t secretlen, int step, uchar_t *dst, int sr_first)
{
	SHA1_CTX sha1, *sha1ctx;
	MD5_CTX md5, *md5ctx;
	uchar_t sha1_hash[SHA1_HASH_LEN];

	sha1ctx = &sha1;
	md5ctx = &md5;

	ASSERT(step <=
	    sizeof (ssl3_key_derive_seeds) /
	    sizeof (ssl3_key_derive_seeds[0]));
	step--;

	SHA1Init(sha1ctx);
	SHA1Update(sha1ctx, (uchar_t *)ssl3_key_derive_seeds[step],
	    step + 1);
	SHA1Update(sha1ctx, secret, secretlen);
	if (sr_first) {
		SHA1Update(sha1ctx, ssl->server_random, SSL3_RANDOM_LENGTH);
		SHA1Update(sha1ctx, ssl->client_random, SSL3_RANDOM_LENGTH);
	} else {
		SHA1Update(sha1ctx, ssl->client_random, SSL3_RANDOM_LENGTH);
		SHA1Update(sha1ctx, ssl->server_random, SSL3_RANDOM_LENGTH);
	}
	SHA1Final(sha1_hash, sha1ctx);

	MD5Init(md5ctx);
	MD5Update(md5ctx, secret, secretlen);
	MD5Update(md5ctx, sha1_hash, SHA1_HASH_LEN);
	MD5Final(dst, md5ctx);
}

static int
kssl_send_certificate_and_server_hello_done(ssl_t *ssl)
{
	int cur_reclen;
	int mss;
	int len, copylen;
	mblk_t *mp;
	uchar_t *cert_buf;
	int cert_len;
	uchar_t *msgbuf;
	Certificate_t *cert;
	uint16_t reclen = KSSL_SSL3_SH_RECLEN;

	cert = ssl->kssl_entry->ke_server_certificate;
	if (cert == NULL) {
		return (ENOENT);
	}
	cert_buf = cert->msg;
	cert_len = cert->len;

	if (ssl->secure_renegotiation)
		reclen += KSSL_EMPTY_RENEG_INFO_LEN;

	mp = ssl->handshake_sendbuf;
	mss = ssl->tcp_mss;
	ASSERT(mp != NULL);
	cur_reclen = mp->b_wptr - mp->b_rptr - SSL3_HDR_LEN;
	ASSERT(cur_reclen == reclen);
	/* Assume MSS is at least 80 bytes */
	ASSERT(mss > cur_reclen + SSL3_HDR_LEN);
	ASSERT(cur_reclen < SSL3_MAX_RECORD_LENGTH); /* XXX */

	copylen = mss - (cur_reclen + SSL3_HDR_LEN);
	len = cert_len;
	copylen = MIN(copylen, len);
	copylen = MIN(copylen, SSL3_MAX_RECORD_LENGTH - cur_reclen);

	/* new record always starts in a new mblk for simplicity */
	msgbuf = cert_buf;
	for (;;) {
		ASSERT(mp->b_wptr + copylen <= mp->b_datap->db_lim);
		bcopy(msgbuf, mp->b_wptr, copylen);
		msgbuf += copylen;
		mp->b_wptr += copylen;
		cur_reclen += copylen;
		len -= copylen;
		if (len == 0) {
			break;
		}
		if (cur_reclen == SSL3_MAX_RECORD_LENGTH) {
			cur_reclen = 0;
		}
		copylen = MIN(len, mss);
		copylen = MIN(copylen, SSL3_MAX_RECORD_LENGTH - cur_reclen);
		mp->b_cont = allocb(copylen, BPRI_HI);
		if (mp->b_cont == NULL) {
			KSSL_COUNTER(alloc_fails, 1);
			freemsg(ssl->handshake_sendbuf);
			ssl->handshake_sendbuf = NULL;
			return (ENOMEM);
		}
		mp = mp->b_cont;
		if (cur_reclen == 0) {
			mp->b_wptr[0] = content_handshake;
			mp->b_wptr[1] = ssl->major_version;
			mp->b_wptr[2] = ssl->minor_version;
			cur_reclen = MIN(len, reclen);
			mp->b_wptr[3] = (cur_reclen >> 8) & 0xff;
			mp->b_wptr[4] = (cur_reclen) & 0xff;
			mp->b_wptr += SSL3_HDR_LEN;
			cur_reclen = 0;
			copylen = MIN(copylen, mss - SSL3_HDR_LEN);
		}
	}

	/* adjust the record length field for the first record */
	mp = ssl->handshake_sendbuf;
	cur_reclen = MIN(reclen + cert_len, SSL3_MAX_RECORD_LENGTH);
	mp->b_rptr[3] = (cur_reclen >> 8) & 0xff;
	mp->b_rptr[4] = (cur_reclen) & 0xff;

	kssl_update_handshake_hashes(ssl, cert_buf, cert_len);

	return (0);
}

static int
kssl_send_change_cipher_specs(ssl_t *ssl)
{
	mblk_t *mp, *newmp;
	uchar_t *buf;

	mp = ssl->handshake_sendbuf;

	/* We're most likely to hit the fast path for resumed sessions */
	if ((mp != NULL) &&
	    (mp->b_datap->db_lim - mp->b_wptr > KSSL_SSL3_MAX_CCP_FIN_MSGLEN)) {
		buf = mp->b_wptr;
	} else {
		newmp = allocb(KSSL_SSL3_MAX_CCP_FIN_MSGLEN, BPRI_HI);

		if (newmp == NULL)
			return (ENOMEM);	/* need to do better job! */

		if (mp == NULL) {
			ssl->handshake_sendbuf = newmp;
		} else {
			linkb(ssl->handshake_sendbuf, newmp);
		}
		mp = newmp;
		buf = mp->b_rptr;
	}

	/* 5 byte record header */
	buf[0] = content_change_cipher_spec;
	buf[1] = ssl->major_version;
	buf[2] = ssl->minor_version;
	buf[3] = 0;
	buf[4] = 1;
	buf += SSL3_HDR_LEN;

	buf[0] = 1;

	mp->b_wptr = buf + 1;
	ASSERT(mp->b_wptr < mp->b_datap->db_lim);

	ssl->seq_num[KSSL_WRITE] = 0;
	return (kssl_spec_init(ssl, KSSL_WRITE));
}

int
kssl_spec_init(ssl_t *ssl, int dir)
{
	KSSL_HASHCTX *ctx;
	KSSLCipherSpec *spec = &ssl->spec[dir];
	int ret = 0;

	spec->mac_hashsz = mac_defs[ssl->pending_malg].hashsz;
	spec->mac_padsz = mac_defs[ssl->pending_malg].padsz;

	spec->MAC_HashInit = mac_defs[ssl->pending_malg].HashInit;
	spec->MAC_HashUpdate = mac_defs[ssl->pending_malg].HashUpdate;
	spec->MAC_HashFinal = mac_defs[ssl->pending_malg].HashFinal;

	if (dir == KSSL_READ) {
		bcopy(ssl->pending_keyblock, ssl->mac_secret[dir],
		    spec->mac_hashsz);
	} else {
		bcopy(&(ssl->pending_keyblock[spec->mac_hashsz]),
		    ssl->mac_secret[dir], spec->mac_hashsz);
	}

	/* Pre-compute these here. will save cycles on each record later */
	if (!IS_TLS(ssl)) {
		ctx = &ssl->mac_ctx[dir][0];
		spec->MAC_HashInit((void *)ctx);
		spec->MAC_HashUpdate((void *)ctx, ssl->mac_secret[dir],
		    spec->mac_hashsz);
		spec->MAC_HashUpdate((void *)ctx, kssl_pad_1,
		    spec->mac_padsz);

		ctx = &ssl->mac_ctx[dir][1];
		spec->MAC_HashInit((void *)ctx);
		spec->MAC_HashUpdate((void *)ctx, ssl->mac_secret[dir],
		    spec->mac_hashsz);
		spec->MAC_HashUpdate((void *)ctx, kssl_pad_2,
		    spec->mac_padsz);
	}

	spec->cipher_type = cipher_defs[ssl->pending_calg].type;
	spec->cipher_mech.cm_type = cipher_defs[ssl->pending_calg].mech_type;
	spec->cipher_bsize = cipher_defs[ssl->pending_calg].bsize;
	spec->cipher_keysz = cipher_defs[ssl->pending_calg].keysz;

	if (spec->cipher_ctx != NULL) {
		crypto_cancel_ctx(spec->cipher_ctx);
		spec->cipher_ctx = 0;
	}

	/*
	 * Initialize HMAC keys for TLS and SSL3 HMAC keys
	 * for SSL 3.0.
	 */
	if (IS_TLS(ssl)) {
		if (ssl->pending_malg == mac_md5) {
			spec->hmac_mech = hmac_md5_mech;
		} else if (ssl->pending_malg == mac_sha) {
			spec->hmac_mech = hmac_sha1_mech;
		}

		spec->hmac_key.ck_format = CRYPTO_KEY_RAW;
		spec->hmac_key.ck_data = ssl->mac_secret[dir];
		spec->hmac_key.ck_length = spec->mac_hashsz * 8;
	} else {
		static uint32_t param;

		spec->hmac_mech.cm_type = CRYPTO_MECH_INVALID;
		spec->hmac_mech.cm_param = (caddr_t)&param;
		spec->hmac_mech.cm_param_len = sizeof (param);
		if (ssl->pending_malg == mac_md5) {
			spec->hmac_mech.cm_type =
			    crypto_mech2id("CKM_SSL3_MD5_MAC");
			param = MD5_HASH_LEN;
		} else if (ssl->pending_malg == mac_sha) {
			spec->hmac_mech.cm_type =
			    crypto_mech2id("CKM_SSL3_SHA1_MAC");
			param = SHA1_HASH_LEN;
		}

		spec->hmac_key.ck_format = CRYPTO_KEY_RAW;
		spec->hmac_key.ck_data = ssl->mac_secret[dir];
		spec->hmac_key.ck_length = spec->mac_hashsz * 8;
	}

	/* We're done if this is the nil cipher */
	if (spec->cipher_keysz == 0) {
		return (0);
	}

	/* Initialize the key and the active context */
	spec->cipher_key.ck_format = CRYPTO_KEY_RAW;
	spec->cipher_key.ck_length = 8 * spec->cipher_keysz; /* in bits */

	if (cipher_defs[ssl->pending_calg].bsize > 0) {
		/* client_write_IV */
		spec->cipher_mech.cm_param =
		    (caddr_t)&(ssl->pending_keyblock[2 * spec->mac_hashsz +
		    2 * spec->cipher_keysz]);
		spec->cipher_mech.cm_param_len = spec->cipher_bsize;
	}
	spec->cipher_data.cd_format = CRYPTO_DATA_RAW;
	if (dir == KSSL_READ) {
		spec->cipher_mech.cm_param_len =
		    cipher_defs[ssl->pending_calg].bsize;

		/* client_write_key */
		spec->cipher_key.ck_data =
		    &(ssl->pending_keyblock[2 * spec->mac_hashsz]);

		ret = crypto_decrypt_init(&(spec->cipher_mech),
		    &(spec->cipher_key), NULL, &spec->cipher_ctx, NULL);
		if (CRYPTO_ERR(ret)) {
			DTRACE_PROBE1(kssl_err__crypto_decrypt_init_read,
			    int, ret);
		}
	} else {
		if (cipher_defs[ssl->pending_calg].bsize > 0) {
			/* server_write_IV */
			spec->cipher_mech.cm_param += spec->cipher_bsize;
		}

		/* server_write_key */
		spec->cipher_key.ck_data =
		    &(ssl->pending_keyblock[2 * spec->mac_hashsz +
		    spec->cipher_keysz]);

		ret = crypto_encrypt_init(&(spec->cipher_mech),
		    &(spec->cipher_key), NULL, &spec->cipher_ctx, NULL);
		if (CRYPTO_ERR(ret))
			DTRACE_PROBE1(kssl_err__crypto_encrypt_init_non_read,
			    int, ret);
	}
	return (ret);
}

static int
kssl_send_finished(ssl_t *ssl, int update_hsh)
{
	mblk_t *mp;
	uchar_t *buf;
	uchar_t *rstart;
	uchar_t *versionp;
	SSL3Hashes ssl3hashes;
	uchar_t finish_len;
	int ret;
	uint16_t adj_len = 0;

	mp = ssl->handshake_sendbuf;
	ASSERT(mp != NULL);
	buf = mp->b_wptr;
	if (ssl->secure_renegotiation)
		adj_len = KSSL_EMPTY_RENEG_INFO_LEN;
	/*
	 * It should be either a message with Server Hello record or just plain
	 * SSL header (data packet).
	 */
	ASSERT(buf - mp->b_rptr ==
	    SSL3_HDR_LEN + KSSL_SSL3_SH_RECLEN + SSL3_HDR_LEN + 1 + adj_len ||
	    buf - mp->b_rptr == SSL3_HDR_LEN + 1);

	rstart = buf;

	if (IS_TLS(ssl))
		finish_len = TLS_FINISHED_SIZE;
	else
		finish_len = KSSL_SSL3_FIN_MSGLEN;

	/* 5 byte record header */
	buf[0] = content_handshake;
	buf[1] = ssl->major_version;
	buf[2] = ssl->minor_version;
	buf[3] = 0;
	buf[4] = 4 + finish_len;

	versionp = &buf[1];

	buf += SSL3_HDR_LEN;

	/* 4 byte message header */
	buf[0] = (uchar_t)finished;	/* message type */
	buf[1] = 0;			/* message len byte 0 */
	buf[2] = 0;			/* message len byte 1 */
	buf[3] = finish_len;	/* message len byte 2 */
	buf += 4;

	if (IS_TLS(ssl)) {
		bcopy(ssl->hs_hashes.md5, ssl3hashes.md5,
		    sizeof (ssl3hashes.md5));
		bcopy(ssl->hs_hashes.sha1, ssl3hashes.sha1,
		    sizeof (ssl3hashes.sha1));
	}

	/* Compute hashes for the SENDER side */
	ret = kssl_compute_handshake_hashes(ssl, &ssl3hashes, sender_server);
	if (ret != 0)
		return (ret);

	if (IS_TLS(ssl)) {
		bcopy(ssl3hashes.tlshash, buf, sizeof (ssl3hashes.tlshash));
	} else {
		bcopy(ssl3hashes.md5, buf, MD5_HASH_LEN);
		bcopy(ssl3hashes.sha1, buf + MD5_HASH_LEN, SHA1_HASH_LEN);
	}

	if (update_hsh) {
		kssl_update_handshake_hashes(ssl, buf - 4, finish_len + 4);
	}

	mp->b_wptr = buf + finish_len;

	ret = kssl_mac_encrypt_record(ssl, content_handshake, versionp,
	    rstart, mp);
	ASSERT(mp->b_wptr <= mp->b_datap->db_lim);

	return (ret);
}

int
kssl_mac_encrypt_record(ssl_t *ssl, SSL3ContentType ct, uchar_t *versionp,
    uchar_t *rstart, mblk_t *mp)
{
	KSSLCipherSpec *spec;
	int mac_sz;
	int ret = 0;
	uint16_t rec_sz;
	int pad_sz;
	int i;

	ASSERT(ssl != NULL);
	ASSERT(rstart >= mp->b_rptr);
	ASSERT(rstart < mp->b_wptr);

	spec = &ssl->spec[KSSL_WRITE];
	mac_sz = spec->mac_hashsz;

	rec_sz = (mp->b_wptr - rstart) - SSL3_HDR_LEN;
	ASSERT(rec_sz > 0);

	if (mac_sz != 0) {
		ASSERT(mp->b_wptr + mac_sz <= mp->b_datap->db_lim);
		ret = kssl_compute_record_mac(ssl, KSSL_WRITE,
		    ssl->seq_num[KSSL_WRITE], ct, versionp,
		    rstart + SSL3_HDR_LEN, rec_sz, mp->b_wptr);
		if (ret == CRYPTO_SUCCESS) {
			ssl->seq_num[KSSL_WRITE]++;
			mp->b_wptr += mac_sz;
			rec_sz += mac_sz;
		} else {
			return (ret);
		}
	}

	if (spec->cipher_type == type_block) {
		pad_sz = spec->cipher_bsize -
		    (rec_sz & (spec->cipher_bsize - 1));
		ASSERT(mp->b_wptr + pad_sz <= mp->b_datap->db_lim);
		for (i = 0; i < pad_sz; i++) {
			mp->b_wptr[i] = pad_sz - 1;
		}
		mp->b_wptr += pad_sz;
		rec_sz += pad_sz;
	}

	ASSERT(rec_sz <= SSL3_MAX_RECORD_LENGTH);

	U16_TO_BE16(rec_sz, rstart + 3);

	if (spec->cipher_ctx == 0)
		return (ret);

	spec->cipher_data.cd_length = rec_sz;
	spec->cipher_data.cd_raw.iov_base = (char *)(rstart + SSL3_HDR_LEN);
	spec->cipher_data.cd_raw.iov_len = rec_sz;
	/* One record at a time. Otherwise, gotta allocate the crypt_data_t */
	ret = crypto_encrypt_update(spec->cipher_ctx, &spec->cipher_data,
	    NULL, NULL);
	if (CRYPTO_ERR(ret)) {
		DTRACE_PROBE1(kssl_err__crypto_encrypt_update,
		    int, ret);
	}
	return (ret);
}

/*
 * Produce SSL alert message (SSLv3/TLS) or error message (SSLv2). For SSLv2
 * it is only done to tear down the SSL connection so it has fixed encoding.
 */
void
kssl_send_alert(ssl_t *ssl, SSL3AlertLevel level, SSL3AlertDescription desc)
{
	mblk_t *mp;
	uchar_t *buf;
	KSSLCipherSpec *spec;
	size_t len;

	ASSERT(ssl != NULL);

	ssl->sendalert_level = level;
	ssl->sendalert_desc = desc;

	if (level == alert_fatal) {
		DTRACE_PROBE2(kssl_sending_alert,
		    SSL3AlertLevel, level, SSL3AlertDescription, desc);
		if (ssl->sid.cached == B_TRUE) {
			kssl_uncache_sid(&ssl->sid, ssl->kssl_entry);
		}
		ssl->fatal_alert = B_TRUE;
		KSSL_COUNTER(fatal_alerts, 1);
	} else
		KSSL_COUNTER(warning_alerts, 1);

	spec = &ssl->spec[KSSL_WRITE];

	ASSERT(ssl->alert_sendbuf == NULL);
	if (ssl->major_version == 0x03) {
		len = SSL3_HDR_LEN + SSL3_ALERT_LEN;
	} else {
		/* KSSL generates 5 byte SSLv2 alert messages only. */
		len = 5;
	}
	ssl->alert_sendbuf = mp = allocb(len + spec->mac_hashsz +
	    spec->cipher_bsize, BPRI_HI);
	if (mp == NULL) {
		KSSL_COUNTER(alloc_fails, 1);
		return;
	}
	buf = mp->b_wptr;

	/* SSLv3/TLS */
	if (ssl->major_version == 0x03) {
		/* 5 byte record header */
		buf[0] = content_alert;
		buf[1] = ssl->major_version;
		buf[2] = ssl->minor_version;
		buf[3] = 0;
		buf[4] = 2;
		buf += SSL3_HDR_LEN;

		/* alert contents */
		buf[0] = (uchar_t)level;
		buf[1] = (uchar_t)desc;
		buf += SSL3_ALERT_LEN;
	} else {
	/* SSLv2 has different encoding. */
		/* 2-byte encoding of the length */
		buf[0] = 0x80;
		buf[1] = 0x03;
		buf += 2;

		/* Protocol Message Code = Error */
		buf[0] = 0;
		/* Error Message Code = Undefined Error */
		buf[1] = 0;
		buf[2] = 0;
		buf += 3;
	}

	mp->b_wptr = buf;
}

/* Assumes RSA encryption */
static int
kssl_handle_client_key_exchange(ssl_t *ssl, mblk_t *mp, int msglen,
    kssl_callback_t cbfn, void *arg)
{
	char *buf;
	uchar_t *pms;
	size_t pmslen;
	int allocated;
	int err, rverr = ENOMEM;
	kssl_entry_t *ep;
	crypto_key_t *privkey;
	crypto_data_t *wrapped_pms_data, *pms_data;
	crypto_call_req_t creq, *creqp;

	ep = ssl->kssl_entry;
	privkey = ep->ke_private_key;
	if (privkey == NULL) {
		return (ENOENT);
	}

	ASSERT(ssl->msg.type == client_key_exchange);
	ASSERT(ssl->hs_waitstate == wait_client_key);

	/*
	 * TLS adds an extra 2 byte length field before the data.
	 */
	if (IS_TLS(ssl)) {
		msglen = (mp->b_rptr[0] << 8) | mp->b_rptr[1];
		mp->b_rptr += 2;
	}

	/*
	 * Allocate all we need in one shot. about 300 bytes total, for
	 * 1024 bit RSA modulus.
	 * The buffer layout will be: pms_data, wrapped_pms_data, the
	 * value of the wrapped pms from the client, then room for the
	 * resulting decrypted premaster secret.
	 */
	allocated = 2 * (sizeof (crypto_data_t) + msglen);
	buf = kmem_alloc(allocated, KM_NOSLEEP);
	if (buf == NULL) {
		return (ENOMEM);
	}

	pms_data = (crypto_data_t *)buf;
	wrapped_pms_data = &(((crypto_data_t *)buf)[1]);

	wrapped_pms_data->cd_format = pms_data->cd_format = CRYPTO_DATA_RAW;
	wrapped_pms_data->cd_offset = pms_data->cd_offset = 0;
	wrapped_pms_data->cd_length = pms_data->cd_length = msglen;
	wrapped_pms_data->cd_miscdata = pms_data->cd_miscdata = NULL;
	wrapped_pms_data->cd_raw.iov_len = pms_data->cd_raw.iov_len = msglen;
	wrapped_pms_data->cd_raw.iov_base = buf + 2 * sizeof (crypto_data_t);
	pms_data->cd_raw.iov_base = wrapped_pms_data->cd_raw.iov_base + msglen;

	bcopy(mp->b_rptr, wrapped_pms_data->cd_raw.iov_base, msglen);
	mp->b_rptr += msglen;

	/* Proceed synchronously if out of interrupt and configured to do so */
	if ((kssl_synchronous) && (!servicing_interrupt())) {
		creqp = NULL;
	} else {
		ssl->cke_callback_func = cbfn;
		ssl->cke_callback_arg = arg;
		creq.cr_flag = kssl_call_flag;
		creq.cr_callback_func = kssl_cke_done;
		creq.cr_callback_arg = ssl;

		creqp = &creq;
	}

	if (ep->ke_is_nxkey) {
		kssl_session_info_t *s;

		s = ep->ke_sessinfo;
		err = CRYPTO_SUCCESS;
		if (!s->is_valid_handle) {
			/* Reauthenticate to the provider */
			if (s->do_reauth) {
				err = kssl_get_obj_handle(ep);
				if (err == CRYPTO_SUCCESS) {
					s->is_valid_handle = B_TRUE;
					s->do_reauth = B_FALSE;
				}
			} else
				err = CRYPTO_FAILED;
		}

		if (err == CRYPTO_SUCCESS) {
			ASSERT(s->is_valid_handle);
			err = crypto_decrypt_prov(s->prov, s->sid,
			    &rsa_x509_mech, wrapped_pms_data, &s->key,
			    NULL, pms_data, creqp);
		}

		/*
		 * Deal with session specific errors. We translate to
		 * the closest errno.
		 */
		switch (err) {
		case CRYPTO_KEY_HANDLE_INVALID:
		case CRYPTO_SESSION_HANDLE_INVALID:
			s->is_valid_handle = B_FALSE;
			s->do_reauth = B_TRUE;
			rverr = EINVAL;
			break;
		case CRYPTO_PIN_EXPIRED:
		case CRYPTO_PIN_LOCKED:
			rverr = EACCES;
			break;
		case CRYPTO_UNKNOWN_PROVIDER:
			rverr = ENXIO;
			break;
		}
	} else {
		err = crypto_decrypt(&rsa_x509_mech, wrapped_pms_data,
		    privkey, NULL, pms_data, creqp);
	}

	switch (err) {
	case CRYPTO_SUCCESS:
		break;

	case CRYPTO_QUEUED:
		/*
		 * Finish the master secret then the rest of key material
		 * derivation later.
		 */
		ssl->job.kjob = creq.cr_reqid;
		ssl->job.buf = buf;
		ssl->job.buflen = allocated;
		ssl->hs_waitstate = wait_client_key_done;
		return (0);
	default:
		DTRACE_PROBE1(kssl_err__crypto_decrypt, int, err);
		kmem_free(buf, allocated);
		return (rverr);
	}

	pmslen = pms_data->cd_length;
	pms = kssl_rsa_unwrap((uchar_t *)pms_data->cd_raw.iov_base, &pmslen);

	/* generate master key and save it in the ssl sid structure */
	if (IS_TLS(ssl)) {
		err = kssl_generate_tls_ms(ssl, pms, pmslen);
		if (!CRYPTO_ERR(err))
			err = kssl_generate_tls_keyblock(ssl);
	} else {
		kssl_generate_ssl_ms(ssl, pms, pmslen);
		kssl_generate_keyblock(ssl);
	}

	if (err == CRYPTO_SUCCESS)
		ssl->hs_waitstate = wait_change_cipher;

	ssl->activeinput = B_FALSE;

	kmem_free(buf, allocated);

	return (0);
}

static int
kssl_handle_finished(ssl_t *ssl, mblk_t *mp, int msglen)
{
	int err;
	size_t finish_len;
	int hashcompare;

	ASSERT(ssl->msg.type == finished);
	ASSERT(ssl->hs_waitstate == wait_finished);

	if (IS_TLS(ssl))
		finish_len = TLS_FINISHED_SIZE;
	else
		finish_len = KSSL_SSL3_FIN_MSGLEN;

	if (msglen != finish_len) {
		kssl_send_alert(ssl, alert_fatal, illegal_parameter);
		return (EBADMSG);
	}

	if (IS_TLS(ssl)) {
		hashcompare = bcmp(mp->b_rptr, ssl->hs_hashes.tlshash,
		    finish_len);
	} else {
		hashcompare = bcmp(mp->b_rptr, &ssl->hs_hashes, finish_len);
	}

	/* The handshake hashes should be computed by now */
	if (hashcompare != 0) {
		kssl_send_alert(ssl, alert_fatal, handshake_failure);
		return (EBADMSG);
	}

	mp->b_rptr += msglen;

	ssl->hs_waitstate = idle_handshake;

	if (ssl->resumed == B_TRUE) {
		ssl->activeinput = B_FALSE;
		return (0);
	}

	err = kssl_send_change_cipher_specs(ssl);
	if (err != 0) {
		return (err);
	}
	err = kssl_send_finished(ssl, 0);
	if (err != 0) {
		return (err);
	}

	kssl_cache_sid(&ssl->sid, ssl->kssl_entry);
	ssl->activeinput = B_FALSE;

	return (0);
}

#define	KSSL2_CH_MIN_RECSZ	(9)

/*
 * This method is needed to handle clients which send the
 * SSLv2/SSLv3 handshake for backwards compat with SSLv2 servers.
 * We are not really doing SSLv2 here, just handling the header
 * and then switching to SSLv3.
 */
int
kssl_handle_v2client_hello(ssl_t *ssl, mblk_t *mp, int recsz)
{
	uchar_t *recend;
	int err;
	SSL3AlertDescription desc = illegal_parameter;
	uint_t randlen;
	uint_t sidlen;
	uint_t cslen;
	uchar_t *suitesp;
	uchar_t *rand;
	uint_t i, j;
	uint16_t suite, selected_suite;
	int ch_recsz = KSSL2_CH_MIN_RECSZ;
	boolean_t suite_found = B_FALSE;

	ASSERT(mp->b_wptr >= mp->b_rptr + recsz);
	ASSERT(ssl->hs_waitstate == wait_client_hello);
	ASSERT(ssl->resumed == B_FALSE);

	if (recsz < ch_recsz) {
		DTRACE_PROBE2(kssl_err__reclen_less_than_minimum,
		    int, recsz, int, ch_recsz);
		goto falert;
	}

	MD5Init(&ssl->hs_md5);
	SHA1Init(&ssl->hs_sha1);

	kssl_update_handshake_hashes(ssl, mp->b_rptr, recsz);

	recend = mp->b_rptr + recsz;

	if (*mp->b_rptr != 1) {
		DTRACE_PROBE1(kssl_err__invalid_version, uint_t, *mp->b_rptr);
		goto falert;
	}
	mp->b_rptr += 3;

	cslen = ((uint_t)mp->b_rptr[0] << 8) + (uint_t)mp->b_rptr[1];
	sidlen = ((uint_t)mp->b_rptr[2] << 8) + (uint_t)mp->b_rptr[3];
	randlen = ((uint_t)mp->b_rptr[4] << 8) + (uint_t)mp->b_rptr[5];
	if (cslen % 3 != 0) {
		DTRACE_PROBE1(kssl_err__cipher_suites_len_error, uint_t, cslen);
		goto falert;
	}
	if (randlen < SSL_MIN_CHALLENGE_BYTES ||
	    randlen > SSL_MAX_CHALLENGE_BYTES) {
		DTRACE_PROBE1(kssl_err__randlen_out_of_range,
		    uint_t, randlen);
		goto falert;
	}
	mp->b_rptr += 6;
	ch_recsz += cslen + sidlen + randlen;
	if (recsz != ch_recsz) {
		DTRACE_PROBE2(kssl_err__invalid_message_len_sum,
		    int, recsz, int, ch_recsz);
		goto falert;
	}
	suitesp = mp->b_rptr;
	rand = suitesp + cslen + sidlen;
	if (randlen < SSL3_RANDOM_LENGTH) {
		bzero(ssl->client_random, SSL3_RANDOM_LENGTH);
	}
	bcopy(rand, &ssl->client_random[SSL3_RANDOM_LENGTH - randlen],
	    randlen);

	for (i = 0; i < ssl->kssl_entry->kssl_cipherSuites_nentries; i++) {
		suite = ssl->kssl_entry->kssl_cipherSuites[i];
		for (j = 0; j < cslen; j += 3) {
			DTRACE_PROBE2(kssl_cipher_suite_check_v2,
			    uint16_t, suite,
			    uint16_t,
			    (uint16_t)((suitesp[j+1] << 8) + suitesp[j+2]));
			if (suitesp[j] != 0) {
				continue;
			}

			/* Check for regular (true) cipher suite. */
			if (suitesp[j + 1] == ((suite >> 8) & 0xff) &&
			    suitesp[j + 2] == (suite & 0xff)) {
				DTRACE_PROBE1(kssl_cipher_suite_found,
				    uint16_t, suite);
				suite_found = B_TRUE;
				selected_suite = suite;
			}

			/* Check for SCSV. */
			if (suitesp[j + 1] ==  ((SSL_SCSV >> 8) & 0xff) &&
			    suitesp[j + 2] == (SSL_SCSV & 0xff)) {
				DTRACE_PROBE(kssl_scsv_found);
				ssl->secure_renegotiation = B_TRUE;
			}
			/*
			 * If we got cipher suite match and SCSV or went
			 * through the whole list of client cipher suites
			 * (hence we know if SCSV was present or not) we
			 * can terminate the cycle now.
			 */
			if (suite_found &&
			    (ssl->secure_renegotiation || (i > 0)))
				break;
		}
		if (suite_found)
			break;
	}
	if (!suite_found) {
		DTRACE_PROBE(kssl_err__no_SSLv2_cipher_suite);
		ssl->activeinput = B_FALSE;
		/*
		 * If there is no fallback point terminate the handshake with
		 * SSL alert otherwise return with SSL_MISS.
		 */
		if (ssl->kssl_entry->ke_fallback_head == NULL) {
			DTRACE_PROBE(kssl_no_fallback);
			desc = handshake_failure;
			goto falert;
		} else {
			return (SSL_MISS);
		}
	}

	mp->b_rptr = recend;

	for (i = 0; i < cipher_suite_defs_nentries; i++) {
		if (selected_suite == cipher_suite_defs[i].suite) {
			break;
		}
	}

	ASSERT(i < cipher_suite_defs_nentries);

	ssl->pending_cipher_suite = selected_suite;
	ssl->pending_malg = cipher_suite_defs[i].malg;
	ssl->pending_calg = cipher_suite_defs[i].calg;
	ssl->pending_keyblksz = cipher_suite_defs[i].keyblksz;

	ASSERT(ssl->sid.cached == B_FALSE);

	(void) random_get_pseudo_bytes(ssl->sid.session_id,
	    SSL3_SESSIONID_BYTES);
	ssl->sid.client_addr = ssl->faddr;
	ssl->sid.cipher_suite = selected_suite;

	err = kssl_send_server_hello(ssl);
	if (err != 0) {
		return (err);
	}
	err = kssl_send_certificate_and_server_hello_done(ssl);
	if (err != 0) {
		return (err);
	}
	KSSL_COUNTER(full_handshakes, 1);
	ssl->hs_waitstate = wait_client_key;
	ssl->activeinput = B_FALSE;
	return (0);

falert:
	kssl_send_alert(ssl, alert_fatal, desc);
	ssl->activeinput = B_FALSE;
	return (EBADMSG);
}

/*
 * Call back routine for asynchronously submitted RSA decryption jobs.
 * This routine retrieves the pre-master secret, and proceeds to generate
 * the remaining key materials.
 */
static void
kssl_cke_done(void *arg, int status)
{
	int ret = 0;
	uchar_t *pms;
	size_t pmslen;
	crypto_data_t *pms_data;
	kssl_cmd_t kssl_cmd = KSSL_CMD_NONE;
	ssl_t *ssl = (ssl_t *)arg;
	mblk_t *alertmp;
	kssl_callback_t cbfn;
	void *cbarg;

	mutex_enter(&ssl->kssl_lock);

	ASSERT(ssl->msg.type == client_key_exchange);
	ASSERT(ssl->hs_waitstate == wait_client_key_done);

	if (status != CRYPTO_SUCCESS) {
		kssl_send_alert(ssl, alert_fatal, decrypt_error);
		kssl_cmd = KSSL_CMD_SEND;
		goto out;
	}

	pms_data = (crypto_data_t *)(ssl->job.buf);

	ASSERT(pms_data != NULL);

	pmslen = pms_data->cd_length;
	pms = kssl_rsa_unwrap((uchar_t *)pms_data->cd_raw.iov_base, &pmslen);

	/* generate master key and save it in the ssl sid structure */
	if (IS_TLS(ssl)) {
		ret = kssl_generate_tls_ms(ssl, pms, pmslen);
		if (!CRYPTO_ERR(ret))
			ret = kssl_generate_tls_keyblock(ssl);
	} else {
		kssl_generate_ssl_ms(ssl, pms, pmslen);
		kssl_generate_keyblock(ssl);
	}

	if (ret == CRYPTO_SUCCESS)
		ssl->hs_waitstate = wait_change_cipher;

out:
	kmem_free(ssl->job.buf, ssl->job.buflen);

	ssl->job.kjob = 0;
	ssl->job.buf = NULL;
	ssl->job.buflen = 0;

	ssl->activeinput = B_FALSE;

	cbfn = ssl->cke_callback_func;
	cbarg = ssl->cke_callback_arg;
	alertmp = ssl->alert_sendbuf;
	ssl->alert_sendbuf = NULL;

	/* dropped by callback when it has completed */
	ssl->async_ops_pending++;
	mutex_exit(&ssl->kssl_lock);

	/* Now call the callback routine */
	(*(cbfn))(cbarg, alertmp, kssl_cmd);
}

/*
 * Returns the first complete contiguous record out of rec_ass_head
 * The record is returned in a separate contiguous mblk, rec_ass_head is
 * left pointing to the next record in the queue.
 *
 * The output looks as follows:
 *
 * |--------|---------- .... -----|<---------->|<----------->|--- ... ---|
 * ^        ^                     ^  mac_size     pad_size               ^
 * |        |___ b_rptr  b_wptr __|                                      |
 * |                                                                     |
 * |___ db_base                                                db_lim ___|
 */
mblk_t *
kssl_get_next_record(ssl_t *ssl)
{
	mblk_t *mp, *retmp;
	int rhsz = SSL3_HDR_LEN;
	uint16_t rec_sz;
	int mpsz, total_size;
	SSL3ContentType content_type;

	ASSERT(MUTEX_HELD(&ssl->kssl_lock));

	mp = ssl->rec_ass_head;
	if (mp == NULL)
		return (NULL);

	/* Fast path: when mp has at least a complete record */
	if (MBLKL(mp) < rhsz) {
		DTRACE_PROBE1(kssl_mblk__incomplete_header,
		    mblk_t *, mp);
		/* Not even a complete header in there yet */
		if (msgdsize(mp) < rhsz) {
			return (NULL);
		}

		if (!pullupmsg(mp, rhsz)) {
			kssl_send_alert(ssl, alert_fatal, internal_error);
			freemsg(mp);
			ssl->rec_ass_head = ssl->rec_ass_tail = NULL;
			return (NULL);
		}
	}
	content_type = (SSL3ContentType)mp->b_rptr[0];
	if (content_type == content_handshake_v2) {
		DTRACE_PROBE1(kssl_mblk__ssl_v2, mblk_t *, mp);
		rec_sz = (uint16_t)mp->b_rptr[1];
		rhsz = 2;
	} else {
		DTRACE_PROBE1(kssl_mblk__ssl_v3, mblk_t *, mp);
		uint8_t *rec_sz_p = (uint8_t *)mp->b_rptr + 3;
		rec_sz = BE16_TO_U16(rec_sz_p);
	}

	/*
	 * same tests as above. Only rare very fragmented cases will
	 * incur the cost of msgdsize() and msgpullup(). Well formed
	 * packets will fall in the most frequent fast path.
	 */
	total_size = rhsz + rec_sz;

	/*
	 * Missing: defensive against record fabricated with longer than
	 * MAX record length.
	 */
	if (MBLKL(mp) < total_size) {
		DTRACE_PROBE2(kssl_mblk__smaller_than_total_size,
		    mblk_t *, mp, int, total_size);
		/* Not a complete record yet. Keep accumulating */
		if (msgdsize(mp) < total_size) {
			return (NULL);
		}

		if (!pullupmsg(mp, total_size)) {
			kssl_send_alert(ssl, alert_fatal, internal_error);
			freemsg(mp);
			ssl->rec_ass_head = ssl->rec_ass_tail = NULL;
			return (NULL);
		}
	}
	mpsz = MBLKL(mp);	/* could've changed after the pullup */

	if (mpsz > total_size) {
		DTRACE_PROBE2(kssl_mblk__bigger_than_total_size,
		    mblk_t *, mp, int, total_size);
		/* gotta allocate a new block */
		if ((retmp = dupb(mp)) == NULL) {
			kssl_send_alert(ssl, alert_fatal, internal_error);
			freemsg(mp);
			ssl->rec_ass_head = ssl->rec_ass_tail = NULL;
			return (NULL);
		}

		retmp->b_wptr = retmp->b_rptr + total_size;
		mp->b_rptr += total_size;
		ssl->rec_ass_head = mp;
	} else {
		DTRACE_PROBE2(kssl_mblk__equal_to_total_size,
		    mblk_t *, mp, int, total_size);
		ASSERT(mpsz == total_size);
		ssl->rec_ass_head = mp->b_cont;
		mp->b_cont = NULL;
		retmp = mp;
	}
	/* Adjust the tail */
	if ((mp = ssl->rec_ass_tail = ssl->rec_ass_head) != NULL) {
		for (; mp->b_cont != NULL; mp = mp->b_cont) {
			ssl->rec_ass_tail = mp->b_cont;
		}
	}

	return (retmp);
}


static void
kssl_mblksfree(ssl_t *ssl)
{

	ASSERT(ssl != NULL);

	if (ssl->rec_ass_head != NULL) {
		freemsg(ssl->rec_ass_head);
	}
	ssl->rec_ass_head = NULL;
	ssl->rec_ass_tail = NULL;

	if (ssl->msg.head != NULL) {
		freemsg(ssl->msg.head);
	}
	ssl->msg.head = NULL;
	ssl->msg.tail = NULL;

	if (ssl->handshake_sendbuf != NULL) {
		freemsg(ssl->handshake_sendbuf);
		ssl->handshake_sendbuf = NULL;
	}
	if (ssl->alert_sendbuf != NULL) {
		freemsg(ssl->alert_sendbuf);
		ssl->alert_sendbuf = NULL;
	}
}

static void
kssl_specsfree(ssl_t *ssl)
{
	KSSLCipherSpec *spec = &ssl->spec[KSSL_READ];

	if (spec->cipher_ctx != NULL) {
		crypto_cancel_ctx(spec->cipher_ctx);
		spec->cipher_ctx = 0;
	}

	spec = &ssl->spec[KSSL_WRITE];

	if (spec->cipher_ctx != NULL) {
		crypto_cancel_ctx(spec->cipher_ctx);
		spec->cipher_ctx = 0;
	}
}

/*
 * Frees the ssl structure (aka the context of an SSL session).
 * Any pending crypto jobs are cancelled.
 * Any initiated crypto contexts are freed as well.
 */
void
kssl_free_context(ssl_t *ssl)
{
	crypto_req_id_t reqid;

	ASSERT(ssl != NULL);
	if (!(MUTEX_HELD(&ssl->kssl_lock))) {
		/* we're coming from an external API entry point */
		mutex_enter(&ssl->kssl_lock);
	}

	/*
	 * Cancel any active crypto request and wait for pending async
	 * operations to complete. We loop here because the async thread
	 * might submit a new cryto request.
	 */
	do {
		if (ssl->job.kjob != 0) {
			/*
			 * Drop the lock before canceling the request;
			 * otherwise we might deadlock if the completion
			 * callback is running.
			 */
			reqid = ssl->job.kjob;
			mutex_exit(&ssl->kssl_lock);
			crypto_cancel_req(reqid);
			mutex_enter(&ssl->kssl_lock);

			/* completion callback might have done the cleanup */
			if (ssl->job.kjob != 0) {
				kmem_free(ssl->job.buf, ssl->job.buflen);
				ssl->job.kjob = 0;
				ssl->job.buf = NULL;
				ssl->job.buflen = 0;
			}
		}
		while (ssl->async_ops_pending > 0)
			cv_wait(&ssl->async_cv, &ssl->kssl_lock);
	} while (ssl->job.kjob != 0);

	kssl_mblksfree(ssl);
	kssl_specsfree(ssl);

	KSSL_ENTRY_REFRELE(ssl->kssl_entry);
	ssl->kssl_entry = NULL;

	mutex_exit(&ssl->kssl_lock);

	kmem_cache_free(kssl_cache, ssl);
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_KSSL_KSSLPROTO_H
#define	_INET_KSSL_KSSLPROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <inet/kssl/kssl.h>	/* Cipher suite definitions */
#include <inet/kssl/ksslapi.h>
#include <inet/kssl/ksslimpl.h>

#define	SSL3_RANDOM_LENGTH		32
#define	SSL3_SESSIONID_BYTES		32
#define	SSL3_HDR_LEN			5
#define	SSL3_MAX_RECORD_LENGTH		16384
#define	SSL3_PRE_MASTER_SECRET_LEN	48
#define	SSL3_MASTER_SECRET_LEN		48
#define	SSL3_MD5_PAD_LEN		48
#define	SSL3_SHA1_PAD_LEN		40

#define	SSL_MIN_CHALLENGE_BYTES		16
#define	SSL_MAX_CHALLENGE_BYTES		32

#define	SHA1_HASH_LEN			20
#define	MD5_HASH_LEN			16
#define	MAX_HASH_LEN			SHA1_HASH_LEN

#define	KSSL_READ			0
#define	KSSL_WRITE			1

#define	KSSL_ENCRYPT			0
#define	KSSL_DECRYPT			1

#define	MSG_INIT			0
#define	MSG_INIT_LEN			1
#define	MSG_BODY			2

/*
 * More than enough for the cipher suite that needs the
 * largest key material (AES_256_CBC_SHA needs 136 bytes).
 */
#define	MAX_KEYBLOCK_LENGTH		160

#define	TLS_MASTER_SECRET_LABEL		"master secret"
#define	TLS_CLIENT_WRITE_KEY_LABEL	"client write key"
#define	TLS_SERVER_WRITE_KEY_LABEL	"server write key"
#define	TLS_CLIENT_FINISHED_LABEL	"client finished"
#define	TLS_SERVER_FINISHED_LABEL	"server finished"
#define	TLS_KEY_EXPANSION_LABEL		"key expansion"
#define	TLS_IV_BLOCK_LABEL		"IV block"
#define	TLS_MAX_LABEL_SIZE		24

#define	TLS_FINISHED_SIZE		12

/*
 * The following constants try to insure an input buffer is optimally aligned
 * for MAC hash computation.  SHA1/MD5 code prefers 4 byte alignment of each
 * 64byte input block to avoid a copy. Our goal is to reach 4 byte alignment
 * starting form the 3rd MAC block (input buffer starts in the 3rd block). The
 * 3rd block includes the first 53 (MD5 SSL3 MAC) or 57 (SHA1 SSL3 MAC) bytes
 * of the input buffer. This means input buffer should start at offset 3
 * within a 4 byte word so that its next block is 4 byte aligned. Since the
 * SSL3 record header is 5 bytes long it should start at at offset 2 within a
 * 4 byte word. To insure the next record (for buffers that don't fit into 1
 * SSL3 record) also starts at offset 2 within a 4 byte word the previous
 * record length should be 3 mod 8 since 5 + 3 mod 8 is 0 i.e. the next record
 * starts at the same offset within a 4 byte word as the the previous record.
 */
#define	SSL3_MAX_OPTIMAL_RECORD_LENGTH	(SSL3_MAX_RECORD_LENGTH - 1)
#define	SSL3_OPTIMAL_RECORD_ALIGNMENT	2

/* session state */
typedef struct sslSessionIDStr {
	uchar_t	session_id[SSL3_SESSIONID_BYTES];
	uchar_t master_secret[SSL3_MASTER_SECRET_LEN];
	clock_t time;
	ipaddr_t client_addr;
	boolean_t cached;
	uint16_t cipher_suite;
} sslSessionID;

/* An element of the session cache */
typedef struct kssl_sid_ent {
	kmutex_t se_lock;
	uint64_t se_used;	/* Counter to check hash distribution */
	sslSessionID se_sid;
	uchar_t  pad[2 * 64 - sizeof (kmutex_t) - sizeof (uint64_t) \
	    - sizeof (sslSessionID)];
} kssl_sid_ent_t;

typedef struct RC4ContextStr {
	uchar_t i;
	uchar_t j;
	uchar_t S[256];
} RC4Context;

typedef enum {
    content_change_cipher_spec	= 20,
    content_alert		= 21,
    content_handshake		= 22,
    content_application_data	= 23,
    content_handshake_v2	= 128
} SSL3ContentType;

typedef enum {
    hello_request	= 0,
    client_hello	= 1,
    server_hello	= 2,
    certificate		= 11,
    server_key_exchange	= 12,
    certificate_request	= 13,
    server_hello_done	= 14,
    certificate_verify	= 15,
    client_key_exchange	= 16,
    finished		= 20
} SSL3HandshakeType;

typedef struct SSL3HandshakeMsgStr {
	int state;
	SSL3HandshakeType type;
	int msglen;
	int msglen_bytes;
	mblk_t *head;
	mblk_t *tail;
} SSL3HandshakeMsg;

typedef struct KSSLJOBStr {
	struct ssl_s	*ssl;
	crypto_req_id_t	kjob;
	char		*buf;
	size_t		buflen;
	int		status;
} KSSLJOB;

typedef struct KSSLMACJOBStr {
	struct ssl_s *ssl;
	buf_t *in;
	buf_t *out;
	uchar_t *rstart;
	int rlen;
	uint64_t seq;
	SSL3ContentType ct;
	uchar_t *digest;
	int dir;
} KSSLMACJOB;


typedef struct {
	uchar_t md5[MD5_HASH_LEN];
	uchar_t sha1[SHA1_HASH_LEN];
	uchar_t tlshash[TLS_FINISHED_SIZE];
} SSL3Hashes;

typedef enum {
	close_notify		= 0,
	unexpected_message	= 10,
	bad_record_mac		= 20,
	decompression_failure	= 30,
	handshake_failure	= 40,
	no_certificate		= 41,
	bad_certificate		= 42,
	unsupported_certificate	= 43,
	certificate_revoked	= 44,
	certificate_expired	= 45,
	certificate_unknown	= 46,
	illegal_parameter	= 47,
	unknown_ca		= 48,
	access_denied		= 49,
	decode_error		= 50,
	decrypt_error		= 51,
	export_restriction	= 60,
	protocol_version	= 70,
	insufficient_security	= 71,
	internal_error		= 80,
	user_canceled		= 90,
	no_renegotiation	= 100
} SSL3AlertDescription;

typedef enum {
	alert_warning = 1,
	alert_fatal = 2
} SSL3AlertLevel;

typedef enum {
	wait_client_hello = 0,
	wait_client_key = 1,
	wait_client_key_done = 2,
	wait_change_cipher = 3,
	wait_finished = 4,
	idle_handshake = 5
} SSL3WaitState;

typedef enum {
    sender_client = 0x434c4e54,
    sender_server = 0x53525652
} SSL3Sender;

typedef enum {
    mac_md5	= 0,
    mac_sha	= 1
} SSL3MACAlgorithm;

/* The SSL bulk cipher definition */
typedef enum {
    cipher_null = 0,
    cipher_rc4 = 1,
    cipher_des = 2,
    cipher_3des = 3,
    cipher_aes128 = 4,
    cipher_aes256 = 5,
} SSL3BulkCipher;

typedef enum { type_stream = 0, type_block = 1 } CipherType;

typedef struct ssl3CipherSuiteDefStr {
	uint16_t		suite;
	SSL3BulkCipher		calg;
	SSL3MACAlgorithm	malg;
	int			keyblksz;
} ssl3CipherSuiteDef;

typedef void (*hashinit_func_t)(void *);
typedef void (*hashupdate_func_t)(void *, uchar_t *, uint32_t);
typedef void (*hashfinal_func_t)(uchar_t *, void *);

typedef struct KSSLMACDefStr {
	int			hashsz;
	int			padsz;
	hashinit_func_t		HashInit;
	hashupdate_func_t	HashUpdate;
	hashfinal_func_t	HashFinal;
} KSSLMACDef;

typedef struct KSSLCipherDefStr {
	CipherType		type;
	int			bsize;
	int			keysz;
	crypto_mech_type_t	mech_type;
} KSSLCipherDef;

typedef union KSSL_HASHCTXUnion {
	SHA1_CTX	sha;
	MD5_CTX		md5;
} KSSL_HASHCTX;

typedef struct KSSLCipherSpecStr {
	int		mac_hashsz;
	int		mac_padsz;
	void		(*MAC_HashInit)(void *);
	void		(*MAC_HashUpdate)(void *, uchar_t *, uint32_t);
	void		(*MAC_HashFinal)(uchar_t *, void *);

	CipherType	cipher_type;
	int		cipher_bsize;
	int		cipher_keysz;

	crypto_mechanism_t	cipher_mech;
	crypto_mechanism_t	hmac_mech;	/* for TLS */
	crypto_key_t		cipher_key;
	crypto_key_t		hmac_key;	/* for TLS */

	crypto_context_t	cipher_ctx;
	crypto_data_t		cipher_data;

} KSSLCipherSpec;

/*
 * SSL connection state. This one hangs off of a tcp_t structure.
 */
typedef struct ssl_s {
	kmutex_t		kssl_lock;
	struct kssl_entry_s	*kssl_entry;
	mblk_t			*rec_ass_head;
	mblk_t			*rec_ass_tail;
	uint_t			kssl_refcnt;
	ipaddr_t		faddr;
	uint32_t		tcp_mss;
	SSL3WaitState		hs_waitstate;
	boolean_t		resumed;
	boolean_t		close_notify;
	boolean_t		fatal_alert;
	boolean_t		fatal_error;
	boolean_t		alert_sent;
	boolean_t		appdata_sent;
	boolean_t		activeinput;
	SSL3AlertLevel		sendalert_level;
	SSL3AlertDescription	sendalert_desc;
	mblk_t			*handshake_sendbuf;
	mblk_t			*alert_sendbuf;
	kssl_callback_t		cke_callback_func;
	void			*cke_callback_arg;
	uint32_t		macjobs_todo;
	uint32_t		macjobs_done;
	uint16_t		pending_cipher_suite;
	SSL3MACAlgorithm	pending_malg;
	SSL3BulkCipher		pending_calg;
	int			pending_keyblksz;
	uint64_t		seq_num[2];
	SSL3HandshakeMsg	msg;
	KSSLJOB			job;
	KSSLCipherSpec		spec[2];
	uchar_t			pending_keyblock[MAX_KEYBLOCK_LENGTH];
	uchar_t			mac_secret[2][MAX_HASH_LEN];
	KSSL_HASHCTX		mac_ctx[2][2];	/* inner 'n outer per dir */
	sslSessionID		sid;
	SHA1_CTX		hs_sha1;
	MD5_CTX			hs_md5;
	SSL3Hashes		hs_hashes;
	uchar_t			client_random[SSL3_RANDOM_LENGTH];
	uchar_t			server_random[SSL3_RANDOM_LENGTH];
	int			sslcnt;
	uchar_t			major_version;
	uchar_t			minor_version;
} ssl_t;

#define	IS_TLS(s) (s->major_version == 3 && s->minor_version == 1)

#define	SSL3_REC_SIZE(mp)	(uint8_t *)(mp)->b_rptr + 3

extern int kssl_spec_init(ssl_t *, int);
extern void kssl_send_alert(ssl_t *, SSL3AlertLevel, SSL3AlertDescription);

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_KSSL_KSSLPROTO_H */

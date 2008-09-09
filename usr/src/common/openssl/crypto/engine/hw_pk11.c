/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* crypto/engine/hw_pk11.c */
/* This product includes software developed by the OpenSSL Project for 
 * use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 * This project also referenced hw_pkcs11-0.9.7b.patch written by 
 * Afchine Madjlessi.
 */
/* ====================================================================
 * Copyright (c) 2000-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/dso.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <cryptlib.h>
#include <dlfcn.h>
#include <pthread.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_PK11

/* label for debug messages printed on stderr */
#define	PK11_DBG	"PKCS#11 ENGINE DEBUG"
/* prints a lot of debug messages on stderr about slot selection process */
#undef	DEBUG_SLOT_SELECTION
/*
 * Solaris specific code. See comment at check_hw_mechanisms() for more
 * information.
 */
#define	SOLARIS_HW_SLOT_SELECTION

/*
 * AES counter mode is not supported in the OpenSSL EVP API yet and neither
 * there are official OIDs for mechanisms based on this mode. With our changes,
 * an application can define its own EVP calls for AES counter mode and then
 * it can make use of hardware acceleration through this engine. However, it's
 * better if we keep AES CTR support code under ifdef's.
 */
#define	SOLARIS_AES_CTR

#include "security/cryptoki.h"
#include "security/pkcs11.h"
#include "hw_pk11_err.c"

#ifdef	SOLARIS_AES_CTR
/*
 * NIDs for AES counter mode that will be defined during the engine
 * initialization.
 */
int NID_aes_128_ctr = NID_undef;
int NID_aes_192_ctr = NID_undef;
int NID_aes_256_ctr = NID_undef;
#endif	/* SOLARIS_AES_CTR */

#ifdef	SOLARIS_HW_SLOT_SELECTION
/*
 * Tables for symmetric ciphers and digest mechs found in the pkcs11_kernel
 * library. See comment at check_hw_mechanisms() for more information.
 */
int *hw_cnids;
int *hw_dnids;
#endif	/* SOLARIS_HW_SLOT_SELECTION */

/* PKCS#11 session caches and their locks for all operation types */
static PK11_CACHE session_cache[OP_MAX];

/*
 * As stated in v2.20, 11.7 Object Management Function, in section for
 * C_FindObjectsInit(), at most one search operation may be active at a given
 * time in a given session. Therefore, C_Find{,Init,Final}Objects() should be
 * grouped together to form one atomic search operation. This is already
 * ensured by the property of unique PKCS#11 session handle used for each
 * PK11_SESSION object.
 *
 * This is however not the biggest concern - maintaining consistency of the
 * underlying object store is more important. The same section of the spec also
 * says that one thread can be in the middle of a search operation while another
 * thread destroys the object matching the search template which would result in
 * invalid handle returned from the search operation.
 *
 * Hence, the following locks are used for both protection of the object stores.
 * They are also used for active list protection.
 */
pthread_mutex_t *find_lock[OP_MAX] = { NULL };

/*
 * lists of asymmetric key handles which are active (referenced by at least one
 * PK11_SESSION structure, either held by a thread or present in free_session
 * list) for given algorithm type
 */
PK11_active *active_list[OP_MAX] = { NULL };

/*
 * Create all secret key objects in a global session so that they are available
 * to use for other sessions. These other sessions may be opened or closed
 * without losing the secret key objects.
 */
static CK_SESSION_HANDLE	global_session = CK_INVALID_HANDLE;

/* ENGINE level stuff */
static int pk11_init(ENGINE *e);
static int pk11_library_init(ENGINE *e);
static int pk11_finish(ENGINE *e);
static int pk11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());
static int pk11_destroy(ENGINE *e);

/* RAND stuff */
static void pk11_rand_seed(const void *buf, int num);
static void pk11_rand_add(const void *buf, int num, double add_entropy);
static void pk11_rand_cleanup(void);
static int pk11_rand_bytes(unsigned char *buf, int num);
static int pk11_rand_status(void);

/* These functions are also used in other files */
PK11_SESSION *pk11_get_session(PK11_OPTYPE optype);
void pk11_return_session(PK11_SESSION *sp, PK11_OPTYPE optype);

/* active list manipulation functions used in this file */
extern int pk11_active_delete(CK_OBJECT_HANDLE h, PK11_OPTYPE type);
extern void pk11_free_active_list(PK11_OPTYPE type);

#ifndef OPENSSL_NO_RSA
int pk11_destroy_rsa_key_objects(PK11_SESSION *session);
int pk11_destroy_rsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock);
int pk11_destroy_rsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock);
#endif
#ifndef OPENSSL_NO_DSA
int pk11_destroy_dsa_key_objects(PK11_SESSION *session);
int pk11_destroy_dsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock);
int pk11_destroy_dsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock);
#endif
#ifndef OPENSSL_NO_DH
int pk11_destroy_dh_key_objects(PK11_SESSION *session);
int pk11_destroy_dh_object(PK11_SESSION *session, CK_BBOOL uselock);
#endif

/* Local helper functions */
static int pk11_free_all_sessions(void);
static int pk11_free_session_list(PK11_OPTYPE optype);
static int pk11_setup_session(PK11_SESSION *sp, PK11_OPTYPE optype);
static int pk11_destroy_cipher_key_objects(PK11_SESSION *session);
static int pk11_destroy_object(CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE oh);
static const char *get_PK11_LIBNAME(void);
static void free_PK11_LIBNAME(void);
static long set_PK11_LIBNAME(const char *name);

/* Symmetric cipher and digest support functions */
static int cipher_nid_to_pk11(int nid);
#ifdef	SOLARIS_AES_CTR
static int pk11_add_NID(char *sn, char *ln);
static int pk11_add_aes_ctr_NIDs(void);
#endif	/* SOLARIS_AES_CTR */
static int pk11_usable_ciphers(const int **nids);
static int pk11_usable_digests(const int **nids);
static int pk11_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc);
static int pk11_cipher_final(PK11_SESSION *sp);
static int pk11_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, unsigned int inl);
static int pk11_cipher_cleanup(EVP_CIPHER_CTX *ctx);
static int pk11_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid);
static int pk11_engine_digests(ENGINE *e, const EVP_MD **digest,
	const int **nids, int nid);
static CK_OBJECT_HANDLE pk11_get_cipher_key(EVP_CIPHER_CTX *ctx, 
	const unsigned char *key, CK_KEY_TYPE key_type, PK11_SESSION *sp);
static int check_new_cipher_key(PK11_SESSION *sp, const unsigned char *key,
	int key_len);
static int md_nid_to_pk11(int nid);
static int pk11_digest_init(EVP_MD_CTX *ctx);
static int pk11_digest_update(EVP_MD_CTX *ctx,const void *data,
	size_t count);
static int pk11_digest_final(EVP_MD_CTX *ctx,unsigned char *md);
static int pk11_digest_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from);
static int pk11_digest_cleanup(EVP_MD_CTX *ctx);

static int pk11_choose_slots(int *any_slot_found);
static void pk11_find_symmetric_ciphers(CK_FUNCTION_LIST_PTR pflist,
    CK_SLOT_ID current_slot, int *current_slot_n_cipher,
    int *local_cipher_nids);
static void pk11_find_digests(CK_FUNCTION_LIST_PTR pflist,
    CK_SLOT_ID current_slot, int *current_slot_n_digest,
    int *local_digest_nids);
static void pk11_get_symmetric_cipher(CK_FUNCTION_LIST_PTR, int slot_id,
    CK_MECHANISM_TYPE mech, int *current_slot_n_cipher, int *local_cipher_nids,
    int id);
static void pk11_get_digest(CK_FUNCTION_LIST_PTR pflist, int slot_id,
    CK_MECHANISM_TYPE mech, int *current_slot_n_digest, int *local_digest_nids,
    int id);

static int pk11_init_all_locks(void);
static void pk11_free_all_locks(void);

#ifdef	SOLARIS_HW_SLOT_SELECTION
static int check_hw_mechanisms(void);
static int nid_in_table(int nid, int *nid_table);
#endif	/* SOLARIS_HW_SLOT_SELECTION */

/* Index for the supported ciphers */
enum pk11_cipher_id {
	PK11_DES_CBC,
	PK11_DES3_CBC,
	PK11_DES_ECB,
	PK11_DES3_ECB,
	PK11_RC4,
	PK11_AES_128_CBC,
	PK11_AES_192_CBC,
	PK11_AES_256_CBC,
	PK11_AES_128_ECB,
	PK11_AES_192_ECB,
	PK11_AES_256_ECB,
	PK11_BLOWFISH_CBC,
#ifdef	SOLARIS_AES_CTR
	PK11_AES_128_CTR,
	PK11_AES_192_CTR,
	PK11_AES_256_CTR,
#endif	/* SOLARIS_AES_CTR */
	PK11_CIPHER_MAX
};

/* Index for the supported digests */
enum pk11_digest_id {
	PK11_MD5,
	PK11_SHA1,
	PK11_SHA224,
	PK11_SHA256,
	PK11_SHA384,
	PK11_SHA512,
	PK11_DIGEST_MAX
};

#define	TRY_OBJ_DESTROY(sess_hdl, obj_hdl, retval, uselock, alg_type)	\
	{								\
	if (uselock)							\
		LOCK_OBJSTORE(alg_type);				\
	if (pk11_active_delete(obj_hdl, alg_type) == 1)			\
		{							\
		retval = pk11_destroy_object(sess_hdl, obj_hdl);	\
		}							\
	if (uselock)							\
		UNLOCK_OBJSTORE(alg_type);				\
	}

static int cipher_nids[PK11_CIPHER_MAX];
static int digest_nids[PK11_DIGEST_MAX];
static int cipher_count		= 0;
static int digest_count		= 0;
static CK_BBOOL pk11_have_rsa	= CK_FALSE;
static CK_BBOOL pk11_have_dsa	= CK_FALSE;
static CK_BBOOL pk11_have_dh	= CK_FALSE;
static CK_BBOOL pk11_have_random = CK_FALSE;

typedef struct PK11_CIPHER_st 
	{
	enum pk11_cipher_id	id;
	int			nid;
	int			iv_len;
	int			key_len;
	CK_KEY_TYPE		key_type;
	CK_MECHANISM_TYPE	mech_type;
	} PK11_CIPHER;

static PK11_CIPHER ciphers[] = 
	{
	{PK11_DES_CBC,	   NID_des_cbc,      8,  8, CKK_DES,      CKM_DES_CBC, },
	{PK11_DES3_CBC,	   NID_des_ede3_cbc, 8, 24, CKK_DES3,     CKM_DES3_CBC, },
	{PK11_DES_ECB,	   NID_des_ecb,      0,  8, CKK_DES,      CKM_DES_ECB, },
	{PK11_DES3_ECB,	   NID_des_ede3_ecb, 0, 24, CKK_DES3,     CKM_DES3_ECB, },
	{PK11_RC4,	   NID_rc4,          0, 16, CKK_RC4,      CKM_RC4, },
	{PK11_AES_128_CBC, NID_aes_128_cbc, 16, 16, CKK_AES,      CKM_AES_CBC, },
	{PK11_AES_192_CBC, NID_aes_192_cbc, 16, 24, CKK_AES,      CKM_AES_CBC, },
	{PK11_AES_256_CBC, NID_aes_256_cbc, 16, 32, CKK_AES,      CKM_AES_CBC, },
	{PK11_AES_128_ECB, NID_aes_128_ecb,  0, 16, CKK_AES,      CKM_AES_ECB, },
	{PK11_AES_192_ECB, NID_aes_192_ecb,  0, 24, CKK_AES,      CKM_AES_ECB, },
	{PK11_AES_256_ECB, NID_aes_256_ecb,  0, 32, CKK_AES,      CKM_AES_ECB, },
	{PK11_BLOWFISH_CBC,NID_bf_cbc,       8, 16, CKK_BLOWFISH, CKM_BLOWFISH_CBC,},
#ifdef	SOLARIS_AES_CTR
	/* we don't know the correct NIDs until the engine is initialized */
	{PK11_AES_128_CTR, NID_undef,	    16, 16, CKK_AES,      CKM_AES_CTR, },
	{PK11_AES_192_CTR, NID_undef,	    16, 24, CKK_AES,      CKM_AES_CTR, },
	{PK11_AES_256_CTR, NID_undef,	    16, 32, CKK_AES,      CKM_AES_CTR, },
#endif	/* SOLARIS_AES_CTR */
	};

typedef struct PK11_DIGEST_st
	{
	enum pk11_digest_id	id;
	int			nid;
	CK_MECHANISM_TYPE	mech_type;
	} PK11_DIGEST;

static PK11_DIGEST digests[] = 
	{
	{PK11_MD5,	NID_md5,	CKM_MD5, },
	{PK11_SHA1,	NID_sha1,	CKM_SHA_1, },
	{PK11_SHA224,	NID_sha224,	CKM_SHA224, },
	{PK11_SHA256,	NID_sha256,	CKM_SHA256, },
	{PK11_SHA384,	NID_sha384,	CKM_SHA384, },
	{PK11_SHA512,	NID_sha512,	CKM_SHA512, },
	{0,		NID_undef,	0xFFFF, },
	};

/* Structure to be used for the cipher_data/md_data in 
 * EVP_CIPHER_CTX/EVP_MD_CTX structures in order to use the same 
 * pk11 session in multiple cipher_update calls
 */
typedef struct PK11_CIPHER_STATE_st
	{
	PK11_SESSION	*sp;
	} PK11_CIPHER_STATE;


/*
 * libcrypto EVP stuff - this is how we get wired to EVP so the engine gets
 * called when libcrypto requests a cipher NID.
 *
 * Note how the PK11_CIPHER_STATE is used here.
 */

/* DES CBC EVP */
static const EVP_CIPHER pk11_des_cbc = 
	{
	NID_des_cbc,
	8, 8, 8,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

/* 3DES CBC EVP */
static const EVP_CIPHER pk11_3des_cbc = 
	{
	NID_des_ede3_cbc,
	8, 24, 8,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

/*
 * ECB modes don't use an Initial Vector so that's why set_asn1_parameters and
 * get_asn1_parameters fields are set to NULL.
 */
static const EVP_CIPHER pk11_des_ecb = 
	{
	NID_des_ecb,
	8, 8, 8,
	EVP_CIPH_ECB_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};

static const EVP_CIPHER pk11_3des_ecb = 
	{
	NID_des_ede3_ecb,
	8, 24, 8,
	EVP_CIPH_ECB_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};


static const EVP_CIPHER pk11_aes_128_cbc = 
	{
	NID_aes_128_cbc,
	16, 16, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

static const EVP_CIPHER pk11_aes_192_cbc = 
	{
	NID_aes_192_cbc,
	16, 24, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

static const EVP_CIPHER pk11_aes_256_cbc = 
	{
	NID_aes_256_cbc,
	16, 32, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

/*
 * ECB modes don't use IV so that's why set_asn1_parameters and
 * get_asn1_parameters are set to NULL.
 */
static const EVP_CIPHER pk11_aes_128_ecb = 
	{
	NID_aes_128_ecb,
	16, 16, 0,
	EVP_CIPH_ECB_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};

static const EVP_CIPHER pk11_aes_192_ecb = 
	{
	NID_aes_192_ecb,
	16, 24, 0,
	EVP_CIPH_ECB_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};

static const EVP_CIPHER pk11_aes_256_ecb = 
	{
	NID_aes_256_ecb,
	16, 32, 0,
	EVP_CIPH_ECB_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};

#ifdef	SOLARIS_AES_CTR
/*
 * NID_undef's will be changed to the AES counter mode NIDs as soon they are
 * created in pk11_library_init(). Note that the need to change these structures
 * is the reason why we don't define them with the const keyword.
 */
static EVP_CIPHER pk11_aes_128_ctr = 
	{
	NID_undef,
	16, 16, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

static EVP_CIPHER pk11_aes_192_ctr = 
	{
	NID_undef,
	16, 24, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

static EVP_CIPHER pk11_aes_256_ctr = 
	{
	NID_undef,
	16, 32, 16,
	EVP_CIPH_CBC_MODE,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};
#endif	/* SOLARIS_AES_CTR */

static const EVP_CIPHER pk11_bf_cbc = 
	{
	NID_bf_cbc,
	8, 16, 8,
	EVP_CIPH_VARIABLE_LENGTH,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL
	};

static const EVP_CIPHER pk11_rc4 =
	{
	NID_rc4,
	1, 16, 0,
	EVP_CIPH_VARIABLE_LENGTH,
	pk11_cipher_init,
	pk11_cipher_do_cipher,
	pk11_cipher_cleanup,
	sizeof(PK11_CIPHER_STATE),
	NULL,
	NULL,
	NULL
	};

static const EVP_MD pk11_md5 =
	{
	NID_md5,
	NID_md5WithRSAEncryption,
	MD5_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	MD5_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

static const EVP_MD pk11_sha1 =
	{
	NID_sha1,
	NID_sha1WithRSAEncryption,
	SHA_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	SHA_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

static const EVP_MD pk11_sha224 =
	{
	NID_sha224,
	NID_sha224WithRSAEncryption,
	SHA224_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	/* SHA-224 uses the same cblock size as SHA-256 */
	SHA256_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

static const EVP_MD pk11_sha256 =
	{
	NID_sha256,
	NID_sha256WithRSAEncryption,
	SHA256_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	SHA256_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

static const EVP_MD pk11_sha384 =
	{
	NID_sha384,
	NID_sha384WithRSAEncryption,
	SHA384_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	/* SHA-384 uses the same cblock size as SHA-512 */
	SHA512_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

static const EVP_MD pk11_sha512 =
	{
	NID_sha512,
	NID_sha512WithRSAEncryption,
	SHA512_DIGEST_LENGTH,
	0,
	pk11_digest_init,
	pk11_digest_update,
	pk11_digest_final,
	pk11_digest_copy,
	pk11_digest_cleanup,
	EVP_PKEY_RSA_method,
	SHA512_CBLOCK,
	sizeof(PK11_CIPHER_STATE),
	};

/* Initialization function. Sets up various pk11 library components.
 */
/* The definitions for control commands specific to this engine
 */
#define PK11_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN pk11_cmd_defns[] =
	{
		{
		PK11_CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs#11' shared library",
		ENGINE_CMD_FLAG_STRING
		},
		{0, NULL, NULL, 0}
	};


static RAND_METHOD pk11_random =
	{
	pk11_rand_seed,
	pk11_rand_bytes,
	pk11_rand_cleanup,
	pk11_rand_add,
	pk11_rand_bytes,
	pk11_rand_status
	};


/* Constants used when creating the ENGINE
 */
static const char *engine_pk11_id = "pkcs11";
static const char *engine_pk11_name = "PKCS #11 engine support";

CK_FUNCTION_LIST_PTR pFuncList = NULL;
static const char PK11_GET_FUNCTION_LIST[] = "C_GetFunctionList";

/* These are the static string constants for the DSO file name and the function
 * symbol names to bind to.
 */
#if defined(__sparcv9) || defined(__x86_64) || defined(__amd64)
static const char def_PK11_LIBNAME[] = "/usr/lib/64/libpkcs11.so.1";
#else
static const char def_PK11_LIBNAME[] = "/usr/lib/libpkcs11.so.1";
#endif

static CK_BBOOL true = TRUE;
static CK_BBOOL false = FALSE;
static CK_SLOT_ID pubkey_SLOTID = 0;
static CK_SLOT_ID rand_SLOTID = 0;
static CK_SLOT_ID SLOTID = 0;
static CK_BBOOL pk11_library_initialized = FALSE;
static CK_BBOOL pk11_atfork_initialized = FALSE;
static int pk11_pid = 0;

static DSO *pk11_dso = NULL;

/* allocate and initialize all locks used by the engine itself */
static int pk11_init_all_locks(void)
	{
	int type;

#ifndef OPENSSL_NO_RSA
	find_lock[OP_RSA] = OPENSSL_malloc(sizeof (pthread_mutex_t));
	if (find_lock[OP_RSA] == NULL)
		goto malloc_err;
	(void) pthread_mutex_init(find_lock[OP_RSA], NULL);
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
	find_lock[OP_DSA] = OPENSSL_malloc(sizeof (pthread_mutex_t));
	if (find_lock[OP_DSA] == NULL)
		goto malloc_err;
	(void) pthread_mutex_init(find_lock[OP_DSA], NULL);
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
	find_lock[OP_DH] = OPENSSL_malloc(sizeof (pthread_mutex_t));
	if (find_lock[OP_DH] == NULL)
		goto malloc_err;
	(void) pthread_mutex_init(find_lock[OP_DH], NULL);
#endif /* OPENSSL_NO_DH */

	for (type = 0; type < OP_MAX; type++)
		{
		session_cache[type].lock =
		    OPENSSL_malloc(sizeof (pthread_mutex_t));
		if (session_cache[type].lock == NULL)
			goto malloc_err;
		(void) pthread_mutex_init(session_cache[type].lock, NULL);
		}

	return (1);

malloc_err:
	pk11_free_all_locks();
	PK11err(PK11_F_INIT_ALL_LOCKS, PK11_R_MALLOC_FAILURE);
	return (0);
	}

static void pk11_free_all_locks(void)
	{
	int type;

#ifndef OPENSSL_NO_RSA
	if (find_lock[OP_RSA] != NULL)
		{
		(void) pthread_mutex_destroy(find_lock[OP_RSA]);
		OPENSSL_free(find_lock[OP_RSA]);
		find_lock[OP_RSA] = NULL;
		}
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	if (find_lock[OP_DSA] != NULL)
		{
		(void) pthread_mutex_destroy(find_lock[OP_DSA]);
		OPENSSL_free(find_lock[OP_DSA]);
		find_lock[OP_DSA] = NULL;
		}
#endif /* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
	if (find_lock[OP_DH] != NULL)
		{
		(void) pthread_mutex_destroy(find_lock[OP_DH]);
		OPENSSL_free(find_lock[OP_DH]);
		find_lock[OP_DH] = NULL;
		}
#endif /* OPENSSL_NO_DH */

	for (type = 0; type < OP_MAX; type++)
		{
		if (session_cache[type].lock != NULL)
			{
			(void) pthread_mutex_destroy(session_cache[type].lock);
			OPENSSL_free(session_cache[type].lock);
			session_cache[type].lock = NULL;
			}
		}
	}

/*
 * This internal function is used by ENGINE_pk11() and "dynamic" ENGINE support.
 */
static int bind_pk11(ENGINE *e)
	{
#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *rsa = NULL;
	RSA_METHOD *pk11_rsa = PK11_RSA();
#endif	/* OPENSSL_NO_RSA */
	if (!pk11_library_initialized)
		(void) pk11_library_init(e);

	if(!ENGINE_set_id(e, engine_pk11_id) ||
	   !ENGINE_set_name(e, engine_pk11_name) ||
	   !ENGINE_set_ciphers(e, pk11_engine_ciphers) ||
	   !ENGINE_set_digests(e, pk11_engine_digests))
	   	return 0;
#ifndef OPENSSL_NO_RSA
	if(pk11_have_rsa == CK_TRUE)
		{
		if(!ENGINE_set_RSA(e, PK11_RSA()) ||
	           !ENGINE_set_load_privkey_function(e, pk11_load_privkey) ||
	           !ENGINE_set_load_pubkey_function(e, pk11_load_pubkey))
			return 0;
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: registered RSA\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
		}
#endif	/* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	if(pk11_have_dsa == CK_TRUE)
		{	
	  	if (!ENGINE_set_DSA(e, PK11_DSA()))
			return 0;
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: registered DSA\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	    	}
#endif	/* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
	if(pk11_have_dh == CK_TRUE)
		{
	  	if (!ENGINE_set_DH(e, PK11_DH()))
			return 0;
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: registered DH\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	    	}
#endif	/* OPENSSL_NO_DH */
	if(pk11_have_random)
		{
		if(!ENGINE_set_RAND(e, &pk11_random))
			return 0;
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: registered random\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
		}
	if(!ENGINE_set_init_function(e, pk11_init) ||
	   !ENGINE_set_destroy_function(e, pk11_destroy) ||
	   !ENGINE_set_finish_function(e, pk11_finish) ||
	   !ENGINE_set_ctrl_function(e, pk11_ctrl) ||
	   !ENGINE_set_cmd_defns(e, pk11_cmd_defns))
		return 0;

/* Apache calls OpenSSL function RSA_blinding_on() once during startup
 * which in turn calls bn_mod_exp. Since we do not implement bn_mod_exp
 * here, we wire it back to the OpenSSL software implementation. 
 * Since it is used only once, performance is not a concern. */
#ifndef OPENSSL_NO_RSA
        rsa = RSA_PKCS1_SSLeay();
        pk11_rsa->rsa_mod_exp = rsa->rsa_mod_exp;
        pk11_rsa->bn_mod_exp = rsa->bn_mod_exp;
#endif	/* OPENSSL_NO_RSA */

	/* Ensure the pk11 error handling is set up */
	ERR_load_pk11_strings();
	
	return 1;
	}

/* Dynamic engine support is disabled at a higher level for Solaris
 */
#ifdef	ENGINE_DYNAMIC_SUPPORT
static int bind_helper(ENGINE *e, const char *id)
	{
	if (id && (strcmp(id, engine_pk11_id) != 0))
		return 0;

	if (!bind_pk11(e))
		return 0;

	return 1;
	}	   

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#else
static ENGINE *engine_pk11(void)
	{
	ENGINE *ret = ENGINE_new();

	if (!ret)
		return NULL;

	if (!bind_pk11(ret))
		{
		ENGINE_free(ret);
		return NULL;
		}

	return ret;
	}

void ENGINE_load_pk11(void)
	{
	ENGINE *e_pk11 = NULL;

	/* Do not use dynamic PKCS#11 library on Solaris due to 
	 * security reasons. We will link it in statically
	 */
	/* Attempt to load PKCS#11 library 
	 */
	if (!pk11_dso)
		pk11_dso = DSO_load(NULL, get_PK11_LIBNAME(), NULL, 0);

	if (pk11_dso == NULL)
		{
		PK11err(PK11_F_LOAD, PK11_R_DSO_FAILURE);
		return;
		}

	e_pk11 = engine_pk11();
	if (!e_pk11) 
		{
		DSO_free(pk11_dso);
		pk11_dso = NULL;
		return;
		}

	/* At this point, the pk11 shared library is either dynamically
	 * loaded or statically linked in. So, initialize the pk11 
	 * library before calling ENGINE_set_default since the latter 
	 * needs cipher and digest algorithm information
	 */
	if (!pk11_library_init(e_pk11))
		{
		DSO_free(pk11_dso);
		pk11_dso = NULL;
		ENGINE_free(e_pk11);
		return;
		}

	ENGINE_add(e_pk11);

	ENGINE_free(e_pk11);
	ERR_clear_error();
	}
#endif	/* ENGINE_DYNAMIC_SUPPORT */

/* These are the static string constants for the DSO file name and 
 * the function symbol names to bind to. 
 */
static const char *PK11_LIBNAME = NULL;

static const char *get_PK11_LIBNAME(void)
	{
	if (PK11_LIBNAME)
		return PK11_LIBNAME;

	return def_PK11_LIBNAME;
	}

static void free_PK11_LIBNAME(void)
	{
	if (PK11_LIBNAME)
		OPENSSL_free((void*)PK11_LIBNAME);

	PK11_LIBNAME = NULL;
	}

static long set_PK11_LIBNAME(const char *name)
	{
	free_PK11_LIBNAME();

	return ((PK11_LIBNAME = BUF_strdup(name)) != NULL ? 1 : 0);
	}

/* acquire all engine specific mutexes before fork */
static void pk11_fork_prepare(void)
	{
	int i;

	LOCK_OBJSTORE(OP_RSA);
	LOCK_OBJSTORE(OP_DSA);
	LOCK_OBJSTORE(OP_DH);
	for (i = 0; i < OP_MAX; i++)
		{
		(void) pthread_mutex_lock(session_cache[i].lock);
		}
	}

/* release all engine specific mutexes */
static void pk11_fork_parent(void)
	{
	int i;

	for (i = OP_MAX - 1; i >= 0; i--)
		{
		(void) pthread_mutex_unlock(session_cache[i].lock);
		}
	UNLOCK_OBJSTORE(OP_DH);
	UNLOCK_OBJSTORE(OP_DSA);
	UNLOCK_OBJSTORE(OP_RSA);
	}

/*
 * same situation as in parent - we need to unlock all locks to make them
 * accessible to all threads.
 */
static void pk11_fork_child(void)
	{
	int i;

	for (i = OP_MAX - 1; i >= 0; i--)
		{
		(void) pthread_mutex_unlock(session_cache[i].lock);
		}
	UNLOCK_OBJSTORE(OP_DH);
	UNLOCK_OBJSTORE(OP_DSA);
	UNLOCK_OBJSTORE(OP_RSA);
	}

/* Initialization function for the pk11 engine */
static int pk11_init(ENGINE *e)
{
	return pk11_library_init(e);
}

/* Initialization function. Sets up various pk11 library components.
 * It selects a slot based on predefined critiera. In the process, it also
 * count how many ciphers and digests to support. Since the cipher and
 * digest information is needed when setting default engine, this function
 * needs to be called before calling ENGINE_set_default.
 */
static int pk11_library_init(ENGINE *e)
	{
	CK_C_GetFunctionList p;
	CK_RV rv = CKR_OK;
	CK_INFO info;
	CK_ULONG ul_state_len;
	int any_slot_found;
	int i;

	/*
	 * pk11_library_initialized is set to 0 in pk11_finish() which is called
	 * from ENGINE_finish(). However, if there is still at least one
	 * existing functional reference to the engine (see engine(3) for more
	 * information), pk11_finish() is skipped. For example, this can happen
	 * if an application forgets to clear one cipher context. In case of a
	 * fork() when the application is finishing the engine so that it can be
	 * reinitialized in the child, forgotten functional reference causes
	 * pk11_library_initialized to stay 1. In that case we need the PID
	 * check so that we properly initialize the engine again.
	 */
	if (pk11_library_initialized)
		{
		if (pk11_pid == getpid())
			{
			return 1;
			}
		else
			{
			global_session = CK_INVALID_HANDLE;
			/*
			 * free the locks first to prevent memory leak in case
			 * the application calls fork() without finishing the
			 * engine first.
			 */
			pk11_free_all_locks();
			}
		}
	
	if (pk11_dso == NULL)
		{
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_DSO_FAILURE);
		goto err;
		}

#ifdef	SOLARIS_AES_CTR
	/*
	 * We must do this before we start working with slots since we need all
	 * NIDs there.
	 */
	if (pk11_add_aes_ctr_NIDs() == 0)
		goto err;
#endif	/* SOLARIS_AES_CTR */

#ifdef	SOLARIS_HW_SLOT_SELECTION
	if (check_hw_mechanisms() == 0)
		goto err;
#endif	/* SOLARIS_HW_SLOT_SELECTION */

	/* get the C_GetFunctionList function from the loaded library
	 */
	p = (CK_C_GetFunctionList)DSO_bind_func(pk11_dso, 
		PK11_GET_FUNCTION_LIST);
	if ( !p )
		{
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_DSO_FAILURE);
		goto err;
		}
 
	/* get the full function list from the loaded library 
	 */
	rv = p(&pFuncList);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_LIBRARY_INIT, PK11_R_DSO_FAILURE, rv);
		goto err;
		}
 
	rv = pFuncList->C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
		{
		PK11err_add_data(PK11_F_LIBRARY_INIT, PK11_R_INITIALIZE, rv);
		goto err;
		}

	rv = pFuncList->C_GetInfo(&info);
	if (rv != CKR_OK) 
		{
		PK11err_add_data(PK11_F_LIBRARY_INIT, PK11_R_GETINFO, rv);
		goto err;
		}

	if (pk11_choose_slots(&any_slot_found) == 0)
		goto err;

	/*
	 * The library we use, set in def_PK11_LIBNAME, may not offer any
	 * slot(s). In that case, we must not proceed but we must not return an
	 * error. The reason is that applications that try to set up the PKCS#11
	 * engine don't exit on error during the engine initialization just
	 * because no slot was present.
	 */
	if (any_slot_found == 0)
		return 1;

	if (global_session == CK_INVALID_HANDLE)
		{
		/* Open the global_session for the new process */
		rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &global_session);
		if (rv != CKR_OK)
			{
			PK11err_add_data(PK11_F_LIBRARY_INIT,
			    PK11_R_OPENSESSION, rv);
			goto err;
			}
		}

	/* Disable digest if C_GetOperationState is not supported since
	 * this function is required by OpenSSL digest copy function */
	if (pFuncList->C_GetOperationState(global_session, NULL, &ul_state_len)
			== CKR_FUNCTION_NOT_SUPPORTED) {
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: C_GetOperationState() not supported, "
		    "setting digest_count to 0\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
		digest_count = 0;
	}

	pk11_library_initialized = TRUE;
	pk11_pid = getpid();
	/*
	 * if initialization of the locks fails pk11_init_all_locks()
	 * will do the cleanup.
	 */
	if (!pk11_init_all_locks())
		goto err;
	for (i = 0; i < OP_MAX; i++)
		session_cache[i].head = NULL;
	/*
	 * initialize active lists. We only use active lists
	 * for asymmetric ciphers.
	 */
	for (i = 0; i < OP_MAX; i++)
		active_list[i] = NULL;

	if (!pk11_atfork_initialized)
		{
		if (pthread_atfork(pk11_fork_prepare, pk11_fork_parent,
		    pk11_fork_child) != 0)
			{
			PK11err(PK11_F_LIBRARY_INIT, PK11_R_ATFORK_FAILED);
			goto err;
			}
		pk11_atfork_initialized = TRUE;
		}

	return 1;

err:
	return 0;
	}

/* Destructor (complements the "ENGINE_pk11()" constructor)
 */
static int pk11_destroy(ENGINE *e)
	{
	free_PK11_LIBNAME();
	ERR_unload_pk11_strings();
	return 1;
	}

/* Termination function to clean up the session, the token, and 
 * the pk11 library.
 */
static int pk11_finish(ENGINE *e)
	{
	int i;

	if (pk11_dso == NULL)
		{
		PK11err(PK11_F_FINISH, PK11_R_NOT_LOADED);
		goto err;
		}

	OPENSSL_assert(pFuncList != NULL);

	if (pk11_free_all_sessions() == 0)
		goto err;

	/* free all active lists */
	for (i = 0; i < OP_MAX; i++)
		pk11_free_active_list(i);

	pFuncList->C_CloseSession(global_session);
	global_session = CK_INVALID_HANDLE;

	/*
	 * Since we are part of a library (libcrypto.so), calling this function
	 * may have side-effects.
	 */
#if 0
	pFuncList->C_Finalize(NULL);
#endif

	if (!DSO_free(pk11_dso))
		{
		PK11err(PK11_F_FINISH, PK11_R_DSO_FAILURE);
		goto err;
		}
	pk11_dso = NULL;
	pFuncList = NULL;
	pk11_library_initialized = FALSE;
	pk11_pid = 0;
	pk11_free_all_locks();

	return 1;

err:
	return 0;
	}

/* Standard engine interface function to set the dynamic library path */
static int pk11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	int initialized = ((pk11_dso == NULL) ? 0 : 1);

	switch(cmd)
		{
	case PK11_CMD_SO_PATH:
		if (p == NULL)
			{
			PK11err(PK11_F_CTRL, ERR_R_PASSED_NULL_PARAMETER);
			return 0;
			}

		if (initialized)
			{
			PK11err(PK11_F_CTRL, PK11_R_ALREADY_LOADED);
			return 0;
			}

		return set_PK11_LIBNAME((const char*)p);
	default:
		break;
		}

	PK11err(PK11_F_CTRL,PK11_R_CTRL_COMMAND_NOT_IMPLEMENTED);

	return 0;
	}


/* Required function by the engine random interface. It does nothing here
 */
static void pk11_rand_cleanup(void)
	{
	return;
	}

static void pk11_rand_add(const void *buf, int num, double add)
	{
	PK11_SESSION *sp;

	if ((sp = pk11_get_session(OP_RAND)) == NULL)
		return;

	/* Ignore any errors (e.g. CKR_RANDOM_SEED_NOT_SUPPORTED) since 
	 * the calling functions do not care anyway
	 */
	pFuncList->C_SeedRandom(sp->session, (unsigned char *) buf, num);
	pk11_return_session(sp, OP_RAND);

	return;
	}

static void pk11_rand_seed(const void *buf, int num)
	{
	pk11_rand_add(buf, num, 0);
	}

static int pk11_rand_bytes(unsigned char *buf, int num)
	{
	CK_RV rv;
	PK11_SESSION *sp;
	
	if ((sp = pk11_get_session(OP_RAND)) == NULL)
		return 0;
	
	rv = pFuncList->C_GenerateRandom(sp->session, buf, num);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_RAND_BYTES, PK11_R_GENERATERANDOM, rv);
		pk11_return_session(sp, OP_RAND);
		return 0;
		}

	pk11_return_session(sp, OP_RAND);
	return 1;
	}

/* Required function by the engine random interface. It does nothing here
 */
static int pk11_rand_status(void)
	{
	return 1;
	}

/*
 * Free all BIGNUM structures from PK11_SESSION.
 */
static void pk11_free_nums(PK11_SESSION *sp, PK11_OPTYPE optype)
	{
	switch (optype)
		{
#ifndef	OPENSSL_NO_RSA
		case OP_RSA:
			if (sp->opdata_rsa_n_num != NULL)
				{
				BN_free(sp->opdata_rsa_n_num);
				sp->opdata_rsa_n_num = NULL;
				}
			if (sp->opdata_rsa_e_num != NULL)
				{
				BN_free(sp->opdata_rsa_e_num);
				sp->opdata_rsa_e_num = NULL;
				}
			if (sp->opdata_rsa_d_num != NULL)
				{
				BN_free(sp->opdata_rsa_d_num);
				sp->opdata_rsa_d_num = NULL;
				}
			break;
#endif
#ifndef	OPENSSL_NO_DSA
		case OP_DSA:
			if (sp->opdata_dsa_pub_num != NULL)
				{
				BN_free(sp->opdata_dsa_pub_num);
				sp->opdata_dsa_pub_num = NULL;
				}
			if (sp->opdata_dsa_priv_num != NULL)
				{
				BN_free(sp->opdata_dsa_priv_num);
				sp->opdata_dsa_priv_num = NULL;
				}
			break;
#endif
#ifndef	OPENSSL_NO_DH
		case OP_DH:
			if (sp->opdata_dh_priv_num != NULL)
				{
				BN_free(sp->opdata_dh_priv_num);
				sp->opdata_dh_priv_num = NULL;
				}
			break;
#endif
		default:
			break;
		}
	}

/*
 * Get new PK11_SESSION structure ready for use. Every process must have
 * its own freelist of PK11_SESSION structures so handle fork() here
 * by destroying the old and creating new freelist.
 * The returned PK11_SESSION structure is disconnected from the freelist.
 */
PK11_SESSION *pk11_get_session(PK11_OPTYPE optype)
	{
	PK11_SESSION *sp = NULL, *sp1, *freelist;
	pthread_mutex_t *freelist_lock;
	CK_RV rv;

	switch (optype)
		{
		case OP_RSA:
		case OP_DSA:
		case OP_DH:
		case OP_RAND:
		case OP_DIGEST:
		case OP_CIPHER:
			freelist_lock = session_cache[optype].lock;
			break;
		default:
			PK11err(PK11_F_GET_SESSION, 
				PK11_R_INVALID_OPERATION_TYPE);
			return (NULL);
		}
	(void) pthread_mutex_lock(freelist_lock);
	freelist = session_cache[optype].head;
	sp = freelist;

	/*
	 * If the free list is empty, allocate new unitialized (filled
	 * with zeroes) PK11_SESSION structure otherwise return first
	 * structure from the freelist.
	 */
	if (sp == NULL)
		{
		if ((sp = OPENSSL_malloc(sizeof(PK11_SESSION))) == NULL)
			{
			PK11err(PK11_F_GET_SESSION, 
				PK11_R_MALLOC_FAILURE);
			goto err;
			}
		memset(sp, 0, sizeof(PK11_SESSION));
		}
	else
		{
		freelist = sp->next;
		}

	if (sp->pid != 0 && sp->pid != getpid())
		{
		/*
		 * We are a new process and thus need to free any inherited
		 * PK11_SESSION objects.
		 */
		while ((sp1 = freelist) != NULL)
			{
			freelist = sp1->next;
			/*
			 * NOTE: we do not want to call pk11_free_all_sessions()
			 * here because it would close underlying PKCS#11
			 * sessions and destroy all objects.
			 */
			pk11_free_nums(sp1, optype);
			OPENSSL_free(sp1);
			}

		/* we have to free the active list as well. */
		pk11_free_active_list(optype);

		/* Initialize the process */
		rv = pFuncList->C_Initialize(NULL_PTR);
		if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
			{
			PK11err_add_data(PK11_F_GET_SESSION, PK11_R_INITIALIZE,
			    rv);
			OPENSSL_free(sp);
			sp = NULL;
			goto err;
			}

		/*
		 * Choose slot here since the slot table is different on this
		 * process. If we are here then we must have found at least one
		 * usable slot before so we don't need to check any_slot_found.
		 * See pk11_library_init()'s usage of this function for more
		 * information.
		 */
#ifdef	SOLARIS_HW_SLOT_SELECTION
		if (check_hw_mechanisms() == 0)
			goto err;
#endif	/* SOLARIS_HW_SLOT_SELECTION */
		if (pk11_choose_slots(NULL) == 0)
			goto err;

		/* Open the global_session for the new process */
		rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &global_session);
		if (rv != CKR_OK)
			{
			PK11err_add_data(PK11_F_GET_SESSION, PK11_R_OPENSESSION,
			    rv);
			OPENSSL_free(sp);
			sp = NULL;
			goto err;
			}

		/* It is an inherited session and needs re-initialization.
		 */
		if (pk11_setup_session(sp, optype) == 0)
			{
			OPENSSL_free(sp);
			sp = NULL;
			}
		}
	else if (sp->pid == 0)
		{
		/* It is a new session and needs initialization. */
		if (pk11_setup_session(sp, optype) == 0)
			{
			OPENSSL_free(sp);
			sp = NULL;
			}
		}

	/* set new head for the list of PK11_SESSION objects */
	session_cache[optype].head = freelist;

err:
	if (sp != NULL)
		sp->next = NULL;

	(void) pthread_mutex_unlock(freelist_lock);

	return sp;
	}


void pk11_return_session(PK11_SESSION *sp, PK11_OPTYPE optype)
	{
	pthread_mutex_t *freelist_lock;
	PK11_SESSION *freelist;

	if (sp == NULL || sp->pid != getpid())
		return;
	
	switch (optype)
		{
		case OP_RSA:
		case OP_DSA:
		case OP_DH:
		case OP_RAND:
		case OP_DIGEST:
		case OP_CIPHER:
			freelist_lock = session_cache[optype].lock;
			break;
		default:
			PK11err(PK11_F_RETURN_SESSION,
				PK11_R_INVALID_OPERATION_TYPE);
			return;
		}

	(void) pthread_mutex_lock(freelist_lock);
	freelist = session_cache[optype].head;
	sp->next = freelist;
	session_cache[optype].head = sp;
	(void) pthread_mutex_unlock(freelist_lock);
	}


/* Destroy all objects. This function is called when the engine is finished
 */
static int pk11_free_all_sessions()
	{
	int ret = 1;
	int type;

#ifndef OPENSSL_NO_RSA
	(void) pk11_destroy_rsa_key_objects(NULL);
#endif	/* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	(void) pk11_destroy_dsa_key_objects(NULL);
#endif	/* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
	(void) pk11_destroy_dh_key_objects(NULL);
#endif	/* OPENSSL_NO_DH */
	(void) pk11_destroy_cipher_key_objects(NULL);

	/*
	 * We try to release as much as we can but any error means that we will
	 * return 0 on exit.
	 */
	for (type = 0; type < OP_MAX; type++)
		{
		if (pk11_free_session_list(type) == 0)
			ret = 0;
		}

	return ret;
	}
	
/*
 * Destroy session structures from the linked list specified. Free as many
 * sessions as possible but any failure in C_CloseSession() means that we
 * return an error on return.
 */
static int pk11_free_session_list(PK11_OPTYPE optype)
	{
	CK_RV rv;
	PK11_SESSION *sp = NULL;
	PK11_SESSION *freelist = NULL;
	pid_t mypid = getpid();
	pthread_mutex_t *freelist_lock;
	int ret = 1;

	switch (optype)
		{
		case OP_RSA:
		case OP_DSA:
		case OP_DH:
		case OP_RAND:
		case OP_DIGEST:
		case OP_CIPHER:
			freelist_lock = session_cache[optype].lock;
			break;
		default:
			PK11err(PK11_F_FREE_ALL_SESSIONS,
				PK11_R_INVALID_OPERATION_TYPE);
			return (0);
		}

	(void) pthread_mutex_lock(freelist_lock);
	freelist = session_cache[optype].head;
	while ((sp = freelist) != NULL)
		{
		if (sp->session != CK_INVALID_HANDLE && sp->pid == mypid)
			{
			rv = pFuncList->C_CloseSession(sp->session);
			if (rv != CKR_OK)
				{
				PK11err_add_data(PK11_F_FREE_ALL_SESSIONS, 
					PK11_R_CLOSESESSION, rv);
				ret = 0;
				}
			}
		freelist = sp->next;
		pk11_free_nums(sp, optype);
		OPENSSL_free(sp);
		}

	(void) pthread_mutex_unlock(freelist_lock);
	return ret;
	}


static int pk11_setup_session(PK11_SESSION *sp, PK11_OPTYPE optype)
	{
	CK_RV rv;
	CK_SLOT_ID myslot;

	switch (optype)
		{
		case OP_RSA:
		case OP_DSA:
		case OP_DH:
			myslot = pubkey_SLOTID;
			break;
		case OP_RAND:
			myslot = rand_SLOTID;
			break;
		case OP_DIGEST:
		case OP_CIPHER:
			myslot = SLOTID;
			break;
		default:
			PK11err(PK11_F_SETUP_SESSION,
			    PK11_R_INVALID_OPERATION_TYPE);
			return 0;
		}

	sp->session = CK_INVALID_HANDLE;
#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: myslot=%d optype=%d\n", PK11_DBG, myslot, optype);
#endif	/* DEBUG_SLOT_SELECTION */
	rv = pFuncList->C_OpenSession(myslot, CKF_SERIAL_SESSION,
		NULL_PTR, NULL_PTR, &sp->session);
	if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
		/*
		 * We are probably a child process so force the
		 * reinitialize of the session
		 */
		pk11_library_initialized = FALSE;
		(void) pk11_library_init(NULL);
		rv = pFuncList->C_OpenSession(myslot, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &sp->session);
		}
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_SETUP_SESSION, PK11_R_OPENSESSION, rv);
		return 0;
		}

	sp->pid = getpid();

	switch (optype)
		{
#ifndef OPENSSL_NO_RSA
		case OP_RSA:
			sp->opdata_rsa_pub_key = CK_INVALID_HANDLE;
			sp->opdata_rsa_priv_key = CK_INVALID_HANDLE;
			sp->opdata_rsa_pub = NULL;
			sp->opdata_rsa_n_num = NULL;
			sp->opdata_rsa_e_num = NULL;
			sp->opdata_rsa_priv = NULL;
			sp->opdata_rsa_d_num = NULL;
			break;
#endif	/* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
		case OP_DSA:
			sp->opdata_dsa_pub_key = CK_INVALID_HANDLE;
			sp->opdata_dsa_priv_key = CK_INVALID_HANDLE;
			sp->opdata_dsa_pub = NULL;
			sp->opdata_dsa_pub_num = NULL;
			sp->opdata_dsa_priv = NULL;
			sp->opdata_dsa_priv_num = NULL;
			break;
#endif	/* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
		case OP_DH:
			sp->opdata_dh_key = CK_INVALID_HANDLE;
			sp->opdata_dh = NULL;
			sp->opdata_dh_priv_num = NULL;
			break;
#endif	/* OPENSSL_NO_DH */
		case OP_CIPHER:
			sp->opdata_cipher_key = CK_INVALID_HANDLE;
			sp->opdata_encrypt = -1;
			break;
		}

	return 1;
	}

#ifndef OPENSSL_NO_RSA
/* Destroy RSA public key from single session. */
int pk11_destroy_rsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->opdata_rsa_pub_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->opdata_rsa_pub_key,
		    ret, uselock, OP_RSA);
		sp->opdata_rsa_pub_key = CK_INVALID_HANDLE;
		sp->opdata_rsa_pub = NULL;
		if (sp->opdata_rsa_n_num != NULL)
			{
			BN_free(sp->opdata_rsa_n_num);
			sp->opdata_rsa_n_num = NULL;
			}
		if (sp->opdata_rsa_e_num != NULL)
			{
			BN_free(sp->opdata_rsa_e_num);
			sp->opdata_rsa_e_num = NULL;
			}
		}

	return (ret);
	}

/* Destroy RSA private key from single session. */
int pk11_destroy_rsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->opdata_rsa_priv_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->opdata_rsa_priv_key,
		    ret, uselock, OP_RSA);
		sp->opdata_rsa_priv_key = CK_INVALID_HANDLE;
		sp->opdata_rsa_priv = NULL;
		if (sp->opdata_rsa_d_num != NULL)
			{
			BN_free(sp->opdata_rsa_d_num);
			sp->opdata_rsa_d_num = NULL;
			}
		}

	return (ret);
	}

/*
 * Destroy RSA key object wrapper. If session is NULL, try to destroy all
 * objects in the free list.
 */
int pk11_destroy_rsa_key_objects(PK11_SESSION *session)
	{
	int ret = 1;
	PK11_SESSION *sp = NULL;
	PK11_SESSION *local_free_session;
	CK_BBOOL uselock = TRUE;

	if (session != NULL)
		local_free_session = session;
	else
		{
		(void) pthread_mutex_lock(session_cache[OP_RSA].lock);
		local_free_session = session_cache[OP_RSA].head;
		uselock = FALSE;
		}

	/*
	 * go through the list of sessions and delete key objects
	 */
	while ((sp = local_free_session) != NULL)
		{
		local_free_session = sp->next;

		/*
		 * Do not terminate list traversal if one of the
		 * destroy operations fails.
		 */
		if (pk11_destroy_rsa_object_pub(sp, uselock) == 0)
			{
			ret = 0;
			continue;
			}
		if (pk11_destroy_rsa_object_priv(sp, uselock) == 0)
			{
			ret = 0;
			continue;
			}
		}

	if (session == NULL)
		(void) pthread_mutex_unlock(session_cache[OP_RSA].lock);

	return ret;
	}
#endif	/* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
/* Destroy DSA public key from single session. */
int pk11_destroy_dsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->opdata_dsa_pub_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->opdata_dsa_pub_key,
		    ret, uselock, OP_DSA);
		sp->opdata_dsa_pub_key = CK_INVALID_HANDLE;
		sp->opdata_dsa_pub = NULL;
		if (sp->opdata_dsa_pub_num != NULL)
			{
			BN_free(sp->opdata_dsa_pub_num);
			sp->opdata_dsa_pub_num = NULL;
			}
		}

	return (ret);
	}

/* Destroy DSA private key from single session. */
int pk11_destroy_dsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->opdata_dsa_priv_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->opdata_dsa_priv_key,
		    ret, uselock, OP_DSA);
		sp->opdata_dsa_priv_key = CK_INVALID_HANDLE;
		sp->opdata_dsa_priv = NULL;
		if (sp->opdata_dsa_priv_num != NULL)
			{
			BN_free(sp->opdata_dsa_priv_num);
			sp->opdata_dsa_priv_num = NULL;
			}
		}

	return (ret);
	}

/*
 * Destroy DSA key object wrapper. If session is NULL, try to destroy all
 * objects in the free list.
 */
int pk11_destroy_dsa_key_objects(PK11_SESSION *session)
	{
	int ret = 1;
	PK11_SESSION *sp = NULL;
	PK11_SESSION *local_free_session;
	CK_BBOOL uselock = TRUE;

	if (session != NULL)
		local_free_session = session;
	else
		{
		(void) pthread_mutex_lock(session_cache[OP_DSA].lock);
		local_free_session = session_cache[OP_DSA].head;
		uselock = FALSE;
		}

	/*
	 * go through the list of sessions and delete key objects
	 */
	while ((sp = local_free_session) != NULL)
		{
		local_free_session = sp->next;

		/*
		 * Do not terminate list traversal if one of the
		 * destroy operations fails.
		 */
		if (pk11_destroy_dsa_object_pub(sp, uselock) == 0)
			{
			ret = 0;
			continue;
			}
		if (pk11_destroy_dsa_object_priv(sp, uselock) == 0)
			{
			ret = 0;
			continue;
			}
		}

	if (session == NULL)
		(void) pthread_mutex_unlock(session_cache[OP_DSA].lock);

	return ret;
	}
#endif	/* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
/* Destroy DH key from single session. */
int pk11_destroy_dh_object(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->opdata_dh_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->opdata_dh_key,
		    ret, uselock, OP_DH);
		sp->opdata_dh_key = CK_INVALID_HANDLE;
		sp->opdata_dh = NULL;
		if (sp->opdata_dh_priv_num != NULL)
			{
			BN_free(sp->opdata_dh_priv_num);
			sp->opdata_dh_priv_num = NULL;
			}
		}

	return (ret);
	}

/*
 * Destroy DH key object wrapper.
 *
 * arg0: pointer to PKCS#11 engine session structure
 *       if session is NULL, try to destroy all objects in the free list
 */
int pk11_destroy_dh_key_objects(PK11_SESSION *session)
	{
	int ret = 1;
	PK11_SESSION *sp = NULL;
	PK11_SESSION *local_free_session;
	CK_BBOOL uselock = TRUE;

	if (session != NULL)
		local_free_session = session;
	else
		{
		(void) pthread_mutex_lock(session_cache[OP_DH].lock);
		local_free_session = session_cache[OP_DH].head;
		uselock = FALSE;
		}

	while ((sp = local_free_session) != NULL)
		{
		local_free_session = sp->next;

		/*
		 * Do not terminate list traversal if one of the
		 * destroy operations fails.
		 */
		if (pk11_destroy_dh_object(sp, uselock) == 0)
			{
			ret = 0;
			continue;
			}
		}
err:
	if (session == NULL)
		(void) pthread_mutex_unlock(session_cache[OP_DH].lock);

	return ret;
	}
#endif	/* OPENSSL_NO_DH */

static int pk11_destroy_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE oh)
	{
	CK_RV rv;
	rv = pFuncList->C_DestroyObject(session, oh);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DESTROY_OBJECT, PK11_R_DESTROYOBJECT,
		    rv);
		return 0;
		}

	return 1;
	}


/* Symmetric ciphers and digests support functions
 */

static int
cipher_nid_to_pk11(int nid)
	{
	int i;

	for (i = 0; i < PK11_CIPHER_MAX; i++)
		if (ciphers[i].nid == nid)
			return (ciphers[i].id);
	return (-1);
	}

static int
pk11_usable_ciphers(const int **nids)
	{
	if (cipher_count > 0)
		*nids = cipher_nids;
	else
		*nids = NULL;
	return (cipher_count);
	}

static int
pk11_usable_digests(const int **nids)
	{
	if (digest_count > 0)
		*nids = digest_nids;
	else
		*nids = NULL;
	return (digest_count);
	}

/*
 * Init context for encryption or decryption using a symmetric key.
 */
static int pk11_init_symmetric(EVP_CIPHER_CTX *ctx, PK11_CIPHER *pcipher,
	PK11_SESSION *sp, CK_MECHANISM_PTR pmech)
	{
	CK_RV rv;
#ifdef	SOLARIS_AES_CTR
	CK_AES_CTR_PARAMS ctr_params;
#endif	/* SOLARIS_AES_CTR */
	
	/*
	 * We expect pmech->mechanism to be already set and
	 * pParameter/ulParameterLen initialized to NULL/0 before
	 * pk11_init_symetric() is called.
	 */
	OPENSSL_assert(pmech->mechanism != NULL);
	OPENSSL_assert(pmech->pParameter == NULL);
	OPENSSL_assert(pmech->ulParameterLen == 0);

#ifdef	SOLARIS_AES_CTR
	if (ctx->cipher->nid == NID_aes_128_ctr ||
	    ctx->cipher->nid == NID_aes_192_ctr ||
	    ctx->cipher->nid == NID_aes_256_ctr)
		{
		pmech->pParameter = (void *)(&ctr_params);
		pmech->ulParameterLen = sizeof(ctr_params);
		/*
		 * For now, we are limited to the fixed length of the counter,
		 * it covers the whole counter block. That's what RFC 4344
		 * needs. For more information on internal structure of the
		 * counter block, see RFC 3686. If needed in the future, we can
		 * add code so that the counter length can be set via
		 * ENGINE_ctrl() function.
		 */
		ctr_params.ulCounterBits = AES_BLOCK_SIZE * 8;
		OPENSSL_assert(pcipher->iv_len == AES_BLOCK_SIZE);
		memcpy(ctr_params.cb, ctx->iv, AES_BLOCK_SIZE);
		}
	else
#endif	/* SOLARIS_AES_CTR */
		{
		if (pcipher->iv_len > 0)
			{
			pmech->pParameter = (void *)ctx->iv;
			pmech->ulParameterLen = pcipher->iv_len;
			}
		}

	/* if we get here, the encryption needs to be reinitialized */
	if (ctx->encrypt)
		rv = pFuncList->C_EncryptInit(sp->session, pmech,
			sp->opdata_cipher_key);
	else
		rv = pFuncList->C_DecryptInit(sp->session, pmech,
			sp->opdata_cipher_key);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_CIPHER_INIT, ctx->encrypt ?
		    PK11_R_ENCRYPTINIT : PK11_R_DECRYPTINIT, rv);
		pk11_return_session(sp, OP_CIPHER);
		return (0);
		}

	return (1);
	}

static int
pk11_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
	{
	CK_MECHANISM mech;
	int index;
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->cipher_data;
	PK11_SESSION *sp;
	PK11_CIPHER *p_ciph_table_row;
	
	state->sp = NULL;

	index = cipher_nid_to_pk11(ctx->cipher->nid);
	if (index < 0 || index >= PK11_CIPHER_MAX)
		return 0;

	p_ciph_table_row = &ciphers[index];
	/*
	 * iv_len in the ctx->cipher structure is the maximum IV length for the
	 * current cipher and it must be less or equal to the IV length in our
	 * ciphers table. The key length must match precisely. Every application
	 * can define its own EVP functions so this code serves as a sanity
	 * check.
	 *
	 * Note that the reason why the IV length in ctx->cipher might be
	 * greater than the actual length is that OpenSSL uses BLOCK_CIPHER_defs
	 * macro to define functions that return EVP structures for all DES
	 * modes. So, even ECB modes get 8 byte IV.
	 */
	if (ctx->cipher->iv_len < p_ciph_table_row->iv_len ||
	    ctx->key_len != p_ciph_table_row->key_len)
		{
		PK11err(PK11_F_CIPHER_INIT, PK11_R_KEY_OR_IV_LEN_PROBLEM);
		return 0;
		}

	if ((sp = pk11_get_session(OP_CIPHER)) == NULL)
		return 0;

	/* if applicable, the mechanism parameter is used for IV */
	mech.mechanism = p_ciph_table_row->mech_type;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	/* The key object is destroyed here if it is not the current key
	 */
	(void) check_new_cipher_key(sp, key, p_ciph_table_row->key_len);
	
	/* If the key is the same and the encryption is also the same,
	 * then just reuse it. However, we must not forget to reinitialize the
	 * context that was finalized in pk11_cipher_cleanup().
	 */
	if (sp->opdata_cipher_key != CK_INVALID_HANDLE &&
	    sp->opdata_encrypt == ctx->encrypt)
		{
		state->sp = sp;
		if (pk11_init_symmetric(ctx, p_ciph_table_row, sp, &mech) == 0)
			return (0);

		return (1);
		}

	/* Check if the key has been invalidated. If so, a new key object
	 * needs to be created.
	 */
	if (sp->opdata_cipher_key == CK_INVALID_HANDLE)
		{
		sp->opdata_cipher_key = pk11_get_cipher_key(
			ctx, key, p_ciph_table_row->key_type, sp);
		}

	if (sp->opdata_encrypt != ctx->encrypt && sp->opdata_encrypt != -1)
		{
		/* The previous encryption/decryption
		 * is different. Need to terminate the previous
		 * active encryption/decryption here
		 */
		if (!pk11_cipher_final(sp))
			{
			pk11_return_session(sp, OP_CIPHER);
			return 0;
			}
		}

	if (sp->opdata_cipher_key == CK_INVALID_HANDLE)
		{
		pk11_return_session(sp, OP_CIPHER);
		return 0;
		}

	/* now initialize the context with a new key */
	if (pk11_init_symmetric(ctx, p_ciph_table_row, sp, &mech) == 0)
		return (0);

	sp->opdata_encrypt = ctx->encrypt;
	state->sp = sp;

	return 1;
	}

/* When reusing the same key in an encryption/decryption session for a 
 * decryption/encryption session, we need to close the active session
 * and recreate a new one. Note that the key is in the global session so
 * that it needs not be recreated.
 *
 * It is more appropriate to use C_En/DecryptFinish here. At the time of this
 * development, these two functions in the PKCS#11 libraries used return
 * unexpected errors when passing in 0 length output. It may be a good
 * idea to try them again if performance is a problem here and fix
 * C_En/DecryptFinial if there are bugs there causing the problem.
 */
static int
pk11_cipher_final(PK11_SESSION *sp)
	{
	CK_RV rv;

	rv = pFuncList->C_CloseSession(sp->session);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_CIPHER_FINAL, PK11_R_CLOSESESSION, rv);
		return 0;
		}

	rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
		NULL_PTR, NULL_PTR, &sp->session);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_CIPHER_FINAL, PK11_R_OPENSESSION, rv);
		return 0;
		}

	return 1;
	}

/* An engine interface function. The calling function allocates sufficient
 * memory for the output buffer "out" to hold the results */
static int
pk11_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, unsigned int inl)
	{
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->cipher_data;
	PK11_SESSION *sp;
	CK_RV rv;
	unsigned long outl = inl;

	if (state == NULL || state->sp == NULL)
		return 0;

	sp = (PK11_SESSION *) state->sp;

	if (!inl)
		return 1;

	/* RC4 is the only stream cipher we support */
	if (ctx->cipher->nid != NID_rc4 && (inl % ctx->cipher->block_size) != 0)
		return 0;

	if (ctx->encrypt)
		{
		rv = pFuncList->C_EncryptUpdate(sp->session,
			(unsigned char *)in, inl, out, &outl);

		if (rv != CKR_OK)
			{
			PK11err_add_data(PK11_F_CIPHER_DO_CIPHER, 
			    PK11_R_ENCRYPTUPDATE, rv);
			return 0;
			}
		}
	else
		{
		rv = pFuncList->C_DecryptUpdate(sp->session,
			(unsigned char *)in, inl, out, &outl);

		if (rv != CKR_OK)
			{
			PK11err_add_data(PK11_F_CIPHER_DO_CIPHER,
			    PK11_R_DECRYPTUPDATE, rv);
			return 0;
			}
		}

	/* for DES_CBC, DES3_CBC, AES_CBC, and RC4, the output size is always
	 * the same size of input
	 * The application has guaranteed to call the block ciphers with 
	 * correctly aligned buffers.
	 */
	if (inl != outl)
		return 0;

	return 1;
	}

/*
 * Return the session to the pool. Calling C_EncryptFinal() and C_DecryptFinal()
 * here is the right thing because in EVP_DecryptFinal_ex(), engine's
 * do_cipher() is not even called, and in EVP_EncryptFinal_ex() it is called but
 * the engine can't find out that it's the finalizing call. We wouldn't
 * necessarily have to finalize the context here since reinitializing it with
 * C_(Encrypt|Decrypt)Init() should be fine but for the sake of correctness,
 * let's do it. Some implementations might leak memory if the previously used
 * context is initialized without finalizing it first.
 */
static int
pk11_cipher_cleanup(EVP_CIPHER_CTX *ctx)
	{
	CK_RV rv;
	CK_ULONG len = EVP_MAX_BLOCK_LENGTH;
	CK_BYTE buf[EVP_MAX_BLOCK_LENGTH];
	PK11_CIPHER_STATE *state = ctx->cipher_data;

	if (state != NULL && state->sp != NULL)
		{
		/*
		 * We are not interested in the data here, we just need to get
		 * rid of the context.
		 */
		if (ctx->encrypt)
			rv = pFuncList->C_EncryptFinal(
			    state->sp->session, buf, &len);
		else
			rv = pFuncList->C_DecryptFinal(
			    state->sp->session, buf, &len);

		if (rv != CKR_OK)
			{
			PK11err_add_data(PK11_F_CIPHER_CLEANUP, ctx->encrypt ?
			    PK11_R_ENCRYPTFINAL : PK11_R_DECRYPTFINAL, rv);
			pk11_return_session(state->sp, OP_CIPHER);
			return (0);
			}

		pk11_return_session(state->sp, OP_CIPHER);
		state->sp = NULL;
		}

	return (1);
	}

/* Registered by the ENGINE when used to find out how to deal with
 * a particular NID in the ENGINE. This says what we'll do at the
 * top level - note, that list is restricted by what we answer with
 */
static int
pk11_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid)
	{
	if (!cipher)
		return (pk11_usable_ciphers(nids));

	switch (nid)
		{
		case NID_des_ede3_cbc:
			*cipher = &pk11_3des_cbc;
			break;
		case NID_des_cbc:
			*cipher = &pk11_des_cbc;
			break;
		case NID_des_ede3_ecb:
			*cipher = &pk11_3des_ecb;
			break;
		case NID_des_ecb:
			*cipher = &pk11_des_ecb;
			break;
		case NID_aes_128_cbc:
			*cipher = &pk11_aes_128_cbc;
			break;
		case NID_aes_192_cbc:
			*cipher = &pk11_aes_192_cbc;
			break;
		case NID_aes_256_cbc:
			*cipher = &pk11_aes_256_cbc;
			break;
		case NID_aes_128_ecb:
			*cipher = &pk11_aes_128_ecb;
			break;
		case NID_aes_192_ecb:
			*cipher = &pk11_aes_192_ecb;
			break;
		case NID_aes_256_ecb:
			*cipher = &pk11_aes_256_ecb;
			break;
		case NID_bf_cbc:
			*cipher = &pk11_bf_cbc;
			break;
		case NID_rc4:
			*cipher = &pk11_rc4;
			break;
		default:
#ifdef	SOLARIS_AES_CTR
			/*
			 * These can't be in separated cases because the NIDs
			 * here are not constants.
			 */
			if (nid == NID_aes_128_ctr)
				*cipher = &pk11_aes_128_ctr;
			else if (nid == NID_aes_192_ctr)
				*cipher = &pk11_aes_192_ctr;
			else if (nid == NID_aes_256_ctr)
				*cipher = &pk11_aes_256_ctr;
			else
#endif	/* SOLARIS_AES_CTR */
			*cipher = NULL;
			break;
		}
	return (*cipher != NULL);
	}

static int
pk11_engine_digests(ENGINE *e, const EVP_MD **digest,
	const int **nids, int nid)
	{
	if (!digest)
		return (pk11_usable_digests(nids));

	switch (nid)
		{
		case NID_md5:
			*digest = &pk11_md5; 
			break;
		case NID_sha1:
			*digest = &pk11_sha1; 
			break;
		case NID_sha224:
			*digest = &pk11_sha224; 
			break;
		case NID_sha256:
			*digest = &pk11_sha256; 
			break;
		case NID_sha384:
			*digest = &pk11_sha384; 
			break;
		case NID_sha512:
			*digest = &pk11_sha512; 
			break;
		default:
			*digest = NULL;
			break;
		}
	return (*digest != NULL);
	}


/* Create a secret key object in a PKCS#11 session
 */
static CK_OBJECT_HANDLE pk11_get_cipher_key(EVP_CIPHER_CTX *ctx, 
	const unsigned char *key, CK_KEY_TYPE key_type, PK11_SESSION *sp)
	{
	CK_RV rv;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_key = CKO_SECRET_KEY;
	CK_ULONG ul_key_attr_count = 6;

	CK_ATTRIBUTE  a_key_template[] =
		{
		{CKA_CLASS, (void*) NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, (void*) NULL, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &false, sizeof(false)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)},
		{CKA_VALUE, (void*) NULL, 0},
		};

	/* Create secret key object in global_session. All other sessions
	 * can use the key handles. Here is why:
	 * OpenSSL will call EncryptInit and EncryptUpdate using a secret key.
	 * It may then call DecryptInit and DecryptUpdate using the same key.
	 * To use the same key object, we need to call EncryptFinal with
	 * a 0 length message. Currently, this does not work for 3DES 
	 * mechanism. To get around this problem, we close the session and
	 * then create a new session to use the same key object. When a session
	 * is closed, all the object handles will be invalid. Thus, create key 
	 * objects in a global session, an individual session may be closed to
	 * terminate the active operation.
	 */
	CK_SESSION_HANDLE session = global_session;
	a_key_template[0].pValue = &obj_key;
	a_key_template[1].pValue = &key_type;
	a_key_template[5].pValue = (void *) key;
	a_key_template[5].ulValueLen = (unsigned long) ctx->key_len;

	rv = pFuncList->C_CreateObject(session, 
		a_key_template, ul_key_attr_count, &h_key);
	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_GET_CIPHER_KEY, PK11_R_CREATEOBJECT,
		    rv);
		goto err;
		}

	/* Save the key information used in this session.
	 * The max can be saved is PK11_KEY_LEN_MAX.
	 */
	sp->opdata_key_len = ctx->key_len > PK11_KEY_LEN_MAX ?
		PK11_KEY_LEN_MAX : ctx->key_len;
	memcpy(sp->opdata_key, key, sp->opdata_key_len);
err:

	return h_key;
	}

static int
md_nid_to_pk11(int nid)
	{
	int i;

	for (i = 0; i < PK11_DIGEST_MAX; i++)
		if (digests[i].nid == nid)
			return (digests[i].id);
	return (-1);
	}

static int 
pk11_digest_init(EVP_MD_CTX *ctx)
        { 
	CK_RV rv;
	CK_MECHANISM mech;
	int index;
	PK11_SESSION *sp;
	PK11_DIGEST *pdp;
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->md_data;
	
	state->sp = NULL;

	index = md_nid_to_pk11(ctx->digest->type);
	if (index < 0 || index >= PK11_DIGEST_MAX)
		return 0;

	pdp = &digests[index];
	if ((sp = pk11_get_session(OP_DIGEST)) == NULL)
		return 0;

	/* at present, no parameter is needed for supported digests */
	mech.mechanism = pdp->mech_type;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	rv = pFuncList->C_DigestInit(sp->session, &mech);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_INIT, PK11_R_DIGESTINIT, rv);
		pk11_return_session(sp, OP_DIGEST);
		return 0;
		}

	state->sp = sp;

	return 1;
	}

static int 
pk11_digest_update(EVP_MD_CTX *ctx,const void *data,size_t count)
        { 
	CK_RV rv;
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->md_data;
	
	/* 0 length message will cause a failure in C_DigestFinal */
	if (count == 0)
		return 1;

	if (state == NULL || state->sp == NULL)
		return 0;

	rv = pFuncList->C_DigestUpdate(state->sp->session, (CK_BYTE *) data,
		count);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_UPDATE, PK11_R_DIGESTUPDATE, rv);
		pk11_return_session(state->sp, OP_DIGEST);
		state->sp = NULL;
		return 0;
		}

	return 1;
	}

static int 
pk11_digest_final(EVP_MD_CTX *ctx,unsigned char *md)
        { 
	CK_RV rv;
	unsigned long len;
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->md_data;
	len = ctx->digest->md_size;
	
	if (state == NULL || state->sp == NULL)
		return 0;

	rv = pFuncList->C_DigestFinal(state->sp->session, md, &len);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_FINAL, PK11_R_DIGESTFINAL, rv);
		pk11_return_session(state->sp, OP_DIGEST);
		state->sp = NULL;
		return 0;
		}

	if (ctx->digest->md_size != len)
		return 0;

	/* Final is called and digest is returned, so return the session
	 * to the pool
	 */
	pk11_return_session(state->sp, OP_DIGEST);
	state->sp = NULL;

	return 1;
	}

static int 
pk11_digest_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from)
        { 
	CK_RV rv;
	int ret = 0;
	PK11_CIPHER_STATE *state, *state_to;
	CK_BYTE_PTR pstate = NULL;
	CK_ULONG ul_state_len;
	
	/* The copy-from state */
	state = (PK11_CIPHER_STATE *) from->md_data;
	if (state == NULL || state->sp == NULL)
		goto err;

	/* Initialize the copy-to state */
	if (!pk11_digest_init(to))
		goto err;
	state_to = (PK11_CIPHER_STATE *) to->md_data;

	/* Get the size of the operation state of the copy-from session */
	rv = pFuncList->C_GetOperationState(state->sp->session, NULL, 
		&ul_state_len);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_COPY, PK11_R_GET_OPERATION_STATE,
		    rv);
		goto err;
		}
	if (ul_state_len == 0)
		{
		goto err;
		}

	pstate = OPENSSL_malloc(ul_state_len);
	if (pstate == NULL)
		{
		PK11err(PK11_F_DIGEST_COPY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/* Get the operation state of the copy-from session */
	rv = pFuncList->C_GetOperationState(state->sp->session, pstate, 
		&ul_state_len);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_COPY, PK11_R_GET_OPERATION_STATE,
		    rv);
		goto err;
		}

	/* Set the operation state of the copy-to session */
	rv = pFuncList->C_SetOperationState(state_to->sp->session, pstate, 
		ul_state_len, 0, 0);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_DIGEST_COPY, PK11_R_SET_OPERATION_STATE, rv);
		goto err;
		}

	ret = 1;
err:
	if (pstate != NULL)
		OPENSSL_free(pstate);

	return ret;
	}

/* Return any pending session state to the pool */
static int
pk11_digest_cleanup(EVP_MD_CTX *ctx)
	{
	PK11_CIPHER_STATE *state = ctx->md_data;
	unsigned char buf[EVP_MAX_MD_SIZE];

	if (state != NULL && state->sp != NULL)
		{
		/*
		 * If state->sp is not NULL then pk11_digest_final() has not
		 * been called yet. We must call it now to free any memory
		 * that might have been allocated in the token when
		 * pk11_digest_init() was called.
		 */
		(void) pk11_digest_final(ctx, buf);
		pk11_return_session(state->sp, OP_DIGEST);
		state->sp = NULL;
		}

	return 1;
	}

/*
 * Check if the new key is the same as the key object in the session. If the key
 * is the same, no need to create a new key object. Otherwise, the old key
 * object needs to be destroyed and a new one will be created. Return 1 for
 * cache hit, 0 for cache miss. Note that we must check the key length first
 * otherwise we could end up reusing a different, longer key with the same
 * prefix.
 */
static int check_new_cipher_key(PK11_SESSION *sp, const unsigned char *key,
	int key_len)
	{
	if (sp->opdata_key_len != key_len ||
	    memcmp(sp->opdata_key, key, key_len) != 0)
		{
		(void) pk11_destroy_cipher_key_objects(sp);
		return (0);
		}
	return (1);
	}

/* Destroy one or more secret key objects. 
 */
static int pk11_destroy_cipher_key_objects(PK11_SESSION *session)
	{
	int ret = 0;
	PK11_SESSION *sp = NULL;
	PK11_SESSION *local_free_session;

	if (session != NULL)
		local_free_session = session;
	else
		{
		(void) pthread_mutex_lock(session_cache[OP_CIPHER].lock);
		local_free_session = session_cache[OP_CIPHER].head;
		}

	while ((sp = local_free_session) != NULL)
		{
		local_free_session = sp->next;

		if (sp->opdata_cipher_key != CK_INVALID_HANDLE)
			{
			/* The secret key object is created in the 
			 * global_session. See pk11_get_cipher_key
			 */
			if (pk11_destroy_object(global_session, 
				sp->opdata_cipher_key) == 0)
				goto err;
			sp->opdata_cipher_key = CK_INVALID_HANDLE;
			}
		}
	ret = 1;
err:

	if (session == NULL)
		(void) pthread_mutex_unlock(session_cache[OP_CIPHER].lock);

	return ret;
	}


/*
 * Public key mechanisms optionally supported
 *
 * CKM_RSA_X_509
 * CKM_RSA_PKCS
 * CKM_DSA
 *
 * The first slot that supports at least one of those mechanisms is chosen as a
 * public key slot.
 *
 * Symmetric ciphers optionally supported
 *
 * CKM_DES3_CBC
 * CKM_DES_CBC
 * CKM_AES_CBC
 * CKM_DES3_ECB
 * CKM_DES_ECB
 * CKM_AES_ECB
 * CKM_AES_CTR
 * CKM_RC4
 * CKM_BLOWFISH_CBC
 *
 * Digests optionally supported
 *
 * CKM_MD5
 * CKM_SHA_1
 * CKM_SHA224
 * CKM_SHA256
 * CKM_SHA384
 * CKM_SHA512
 *
 * The output of this function is a set of global variables indicating which
 * mechanisms from RSA, DSA, DH and RAND are present, and also two arrays of
 * mechanisms, one for symmetric ciphers and one for digests. Also, 3 global
 * variables carry information about which slot was chosen for (a) public key
 * mechanisms, (b) random operations, and (c) symmetric ciphers and digests.
 */
static int 
pk11_choose_slots(int *any_slot_found)
	{
	CK_SLOT_ID_PTR pSlotList = NULL_PTR;
	CK_ULONG ulSlotCount = 0;
	CK_MECHANISM_INFO mech_info;
	CK_TOKEN_INFO token_info;
	int i;
	CK_RV rv;
	CK_SLOT_ID best_slot_sofar;
	CK_BBOOL found_candidate_slot = CK_FALSE;
	int slot_n_cipher = 0;
	int slot_n_digest = 0;
	CK_SLOT_ID current_slot = 0;
	int current_slot_n_cipher = 0;
	int current_slot_n_digest = 0;

	int local_cipher_nids[PK11_CIPHER_MAX];
	int local_digest_nids[PK11_DIGEST_MAX];

	/* let's initialize the output parameter */
	if (any_slot_found != NULL)
		*any_slot_found = 0;

	/* Get slot list for memory allocation */
	rv = pFuncList->C_GetSlotList(0, NULL_PTR, &ulSlotCount);

	if (rv != CKR_OK)
		{
		PK11err_add_data(PK11_F_CHOOSE_SLOT, PK11_R_GETSLOTLIST, rv);
		return 0;
		}

	/* it's not an error if we didn't find any providers */
	if (ulSlotCount == 0) 
		{
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: no crypto providers found\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
		return 1;
		}

	pSlotList = OPENSSL_malloc(ulSlotCount * sizeof (CK_SLOT_ID));

	if (pSlotList == NULL) 
		{
		PK11err(PK11_F_CHOOSE_SLOT, PK11_R_MALLOC_FAILURE);
		return 0;
		}

	/* Get the slot list for processing */
	rv = pFuncList->C_GetSlotList(0, pSlotList, &ulSlotCount);
	if (rv != CKR_OK) 
		{
		PK11err_add_data(PK11_F_CHOOSE_SLOT, PK11_R_GETSLOTLIST, rv);
		OPENSSL_free(pSlotList);
		return 0;
		}

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: provider: %s\n", PK11_DBG, def_PK11_LIBNAME);
	fprintf(stderr, "%s: number of slots: %d\n", PK11_DBG, ulSlotCount);

	fprintf(stderr, "%s: == checking rand slots ==\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	for (i = 0; i < ulSlotCount; i++) 
		{
		current_slot = pSlotList[i];

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: checking slot: %d\n", PK11_DBG, i);
#endif	/* DEBUG_SLOT_SELECTION */
		/* Check if slot has random support. */
		rv = pFuncList->C_GetTokenInfo(current_slot, &token_info);
		if (rv != CKR_OK)
			continue;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: token label: %.32s\n", PK11_DBG, token_info.label);
#endif	/* DEBUG_SLOT_SELECTION */

		if (token_info.flags & CKF_RNG)
			{
#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: this token has CKF_RNG flag\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
			pk11_have_random = CK_TRUE;
			break;
			}
		}

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: == checking pubkey slots ==\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	for (i = 0; i < ulSlotCount; i++) 
		{
		CK_BBOOL slot_has_rsa = CK_FALSE;
		CK_BBOOL slot_has_dsa = CK_FALSE;
		CK_BBOOL slot_has_dh = CK_FALSE;
		current_slot = pSlotList[i];

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: checking slot: %d\n", PK11_DBG, i);
#endif	/* DEBUG_SLOT_SELECTION */
		rv = pFuncList->C_GetTokenInfo(current_slot, &token_info);
		if (rv != CKR_OK)
			continue;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: token label: %.32s\n", PK11_DBG, token_info.label);
#endif	/* DEBUG_SLOT_SELECTION */

#ifndef OPENSSL_NO_RSA
		/*
		 * Check if this slot is capable of signing and
		 * verifying with CKM_RSA_PKCS.
		 */
		rv = pFuncList->C_GetMechanismInfo(current_slot, CKM_RSA_PKCS, 
			&mech_info);

		if (rv == CKR_OK && ((mech_info.flags & CKF_SIGN) &&
				(mech_info.flags & CKF_VERIFY)))
			{
			/*
			 * Check if this slot is capable of encryption,
			 * decryption, sign, and verify with CKM_RSA_X_509.
			 */
			rv = pFuncList->C_GetMechanismInfo(current_slot,
			  CKM_RSA_X_509, &mech_info);

			if (rv == CKR_OK && ((mech_info.flags & CKF_SIGN) &&
			    (mech_info.flags & CKF_VERIFY) &&
			    (mech_info.flags & CKF_ENCRYPT) &&
			    (mech_info.flags & CKF_VERIFY_RECOVER) &&
			    (mech_info.flags & CKF_DECRYPT)))
				{
				slot_has_rsa = CK_TRUE;
				}
			}
#endif	/* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
		/*
		 * Check if this slot is capable of signing and
		 * verifying with CKM_DSA.
		 */
		rv = pFuncList->C_GetMechanismInfo(current_slot, CKM_DSA, 
			&mech_info);
		if (rv == CKR_OK && ((mech_info.flags & CKF_SIGN) &&
		    (mech_info.flags & CKF_VERIFY)))
			{
			slot_has_dsa = CK_TRUE;
			}

#endif	/* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
		/*
		 * Check if this slot is capable of DH key generataion and
		 * derivation.
		 */
		rv = pFuncList->C_GetMechanismInfo(current_slot,
		  CKM_DH_PKCS_KEY_PAIR_GEN, &mech_info);

		if (rv == CKR_OK && (mech_info.flags & CKF_GENERATE_KEY_PAIR))
			{    
			rv = pFuncList->C_GetMechanismInfo(current_slot,
				CKM_DH_PKCS_DERIVE, &mech_info);
			if (rv == CKR_OK && (mech_info.flags & CKF_DERIVE))
				{
				slot_has_dh = CK_TRUE;
				}
			}
#endif	/* OPENSSL_NO_DH */

		if (!found_candidate_slot &&
		    (slot_has_rsa || slot_has_dsa || slot_has_dh))
			{
#ifdef	DEBUG_SLOT_SELECTION
			fprintf(stderr,
			  "%s: potential slot: %d\n", PK11_DBG, current_slot);
#endif	/* DEBUG_SLOT_SELECTION */
			best_slot_sofar = current_slot;
			pk11_have_rsa = slot_has_rsa;
			pk11_have_dsa = slot_has_dsa;
			pk11_have_dh = slot_has_dh;
			found_candidate_slot = CK_TRUE;
#ifdef	DEBUG_SLOT_SELECTION
			fprintf(stderr,
		            "%s: setting found_candidate_slot to CK_TRUE\n",
			    PK11_DBG);
			fprintf(stderr,
		            "%s: best so far slot: %d\n", PK11_DBG,
		    	    best_slot_sofar);
			}
		else
			{
			fprintf(stderr,
			  "%s: no rsa/dsa/dh\n", PK11_DBG);
			}
#else
			} /* if */
#endif	/* DEBUG_SLOT_SELECTION */
		} /* for */

	if (found_candidate_slot)
		{
		pubkey_SLOTID = best_slot_sofar;
		}

	found_candidate_slot = CK_FALSE;
	best_slot_sofar = 0;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: == checking cipher/digest ==\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	for (i = 0; i < ulSlotCount; i++) 
		{
#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: checking slot: %d\n", PK11_DBG, i);
#endif	/* DEBUG_SLOT_SELECTION */

		current_slot = pSlotList[i];
		current_slot_n_cipher = 0;
		current_slot_n_digest = 0;
		memset(local_cipher_nids, 0, sizeof(local_cipher_nids));
		memset(local_digest_nids, 0, sizeof(local_digest_nids));

		pk11_find_symmetric_ciphers(pFuncList, current_slot,
		    &current_slot_n_cipher, local_cipher_nids);

		pk11_find_digests(pFuncList, current_slot,
		    &current_slot_n_digest, local_digest_nids);

#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, "%s: current_slot_n_cipher %d\n", PK11_DBG,
			current_slot_n_cipher);
		fprintf(stderr, "%s: current_slot_n_digest %d\n", PK11_DBG,
			current_slot_n_digest);
		fprintf(stderr, "%s: best so far cipher/digest slot: %d\n",
			PK11_DBG, best_slot_sofar);
#endif	/* DEBUG_SLOT_SELECTION */

		/*
		 * If the current slot supports more ciphers/digests than 
		 * the previous best one we change the current best to this one,
		 * otherwise leave it where it is.
		 */
		if ((current_slot_n_cipher + current_slot_n_digest) >
		    (slot_n_cipher + slot_n_digest))
			{
#ifdef	DEBUG_SLOT_SELECTION
			fprintf(stderr,
				"%s: changing best so far slot to %d\n",
				PK11_DBG, current_slot);
#endif	/* DEBUG_SLOT_SELECTION */
			best_slot_sofar = SLOTID = current_slot;
			cipher_count = slot_n_cipher = current_slot_n_cipher;
			digest_count = slot_n_digest = current_slot_n_digest;
			memcpy(cipher_nids, local_cipher_nids,
			    sizeof (local_cipher_nids));
			memcpy(digest_nids, local_digest_nids,
			    sizeof (local_digest_nids));
			}
		}

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr,
	    "%s: chosen pubkey slot: %d\n", PK11_DBG, pubkey_SLOTID);
	fprintf(stderr,
	    "%s: chosen rand slot: %d\n", PK11_DBG, rand_SLOTID);
	fprintf(stderr,
	    "%s: chosen cipher/digest slot: %d\n", PK11_DBG, SLOTID);
	fprintf(stderr,
	    "%s: pk11_have_rsa %d\n", PK11_DBG, pk11_have_rsa);
	fprintf(stderr,
	    "%s: pk11_have_dsa %d\n", PK11_DBG, pk11_have_dsa);
	fprintf(stderr,
	    "%s: pk11_have_dh %d\n", PK11_DBG, pk11_have_dh);
	fprintf(stderr,
	    "%s: pk11_have_random %d\n", PK11_DBG, pk11_have_random);
	fprintf(stderr,
	    "%s: cipher_count %d\n", PK11_DBG, cipher_count);
	fprintf(stderr,
	    "%s: digest_count %d\n", PK11_DBG, digest_count);
#endif	/* DEBUG_SLOT_SELECTION */
		
	if (pSlotList != NULL)
		OPENSSL_free(pSlotList);

#ifdef	SOLARIS_HW_SLOT_SELECTION
	OPENSSL_free(hw_cnids);
	OPENSSL_free(hw_dnids);
#endif	/* SOLARIS_HW_SLOT_SELECTION */

	if (any_slot_found != NULL)
		*any_slot_found = 1;
	return 1;
	}

static void pk11_get_symmetric_cipher(CK_FUNCTION_LIST_PTR pflist,
    int slot_id, CK_MECHANISM_TYPE mech, int *current_slot_n_cipher,
    int *local_cipher_nids, int id)
	{
	CK_MECHANISM_INFO mech_info;
	CK_RV rv;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: checking mech: %x", PK11_DBG, mech);
#endif	/* DEBUG_SLOT_SELECTION */
	rv = pflist->C_GetMechanismInfo(slot_id, mech, &mech_info);

	if (rv != CKR_OK) 
		{
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, " not found\n");
#endif	/* DEBUG_SLOT_SELECTION */
		return;
		}

	if ((mech_info.flags & CKF_ENCRYPT) &&
	    (mech_info.flags & CKF_DECRYPT))
		{
#ifdef	SOLARIS_HW_SLOT_SELECTION
		if (nid_in_table(ciphers[id].nid, hw_cnids))
#endif	/* SOLARIS_HW_SLOT_SELECTION */
			{
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, " usable\n");
#endif	/* DEBUG_SLOT_SELECTION */
			local_cipher_nids[(*current_slot_n_cipher)++] =
			    ciphers[id].nid;
			}
#ifdef	SOLARIS_HW_SLOT_SELECTION
#ifdef	DEBUG_SLOT_SELECTION
		else
			{
		fprintf(stderr, " rejected, software implementation only\n");
			}
#endif	/* DEBUG_SLOT_SELECTION */
#endif	/* SOLARIS_HW_SLOT_SELECTION */
		}
#ifdef	DEBUG_SLOT_SELECTION
	else
		{
		fprintf(stderr, " unusable\n");
		}
#endif	/* DEBUG_SLOT_SELECTION */

	return;
	}

static void pk11_get_digest(CK_FUNCTION_LIST_PTR pflist, int slot_id,
    CK_MECHANISM_TYPE mech, int *current_slot_n_digest, int *local_digest_nids,
    int id)
	{
	CK_MECHANISM_INFO mech_info;
	CK_RV rv;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: checking mech: %x", PK11_DBG, mech);
#endif	/* DEBUG_SLOT_SELECTION */
	rv = pflist->C_GetMechanismInfo(slot_id, mech, &mech_info);

	if (rv != CKR_OK) 
		{
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, " not found\n");
#endif	/* DEBUG_SLOT_SELECTION */
		return;
		}

	if (mech_info.flags & CKF_DIGEST)
		{
#ifdef	SOLARIS_HW_SLOT_SELECTION
	    	if (nid_in_table(digests[id].nid, hw_dnids))
#endif	/* SOLARIS_HW_SLOT_SELECTION */
			{
#ifdef	DEBUG_SLOT_SELECTION
		fprintf(stderr, " usable\n");
#endif	/* DEBUG_SLOT_SELECTION */
			local_digest_nids[(*current_slot_n_digest)++] =
			    digests[id].nid;
			}
#ifdef	SOLARIS_HW_SLOT_SELECTION
#ifdef	DEBUG_SLOT_SELECTION
		else
			{
		fprintf(stderr, " rejected, software implementation only\n");
			}
#endif	/* DEBUG_SLOT_SELECTION */
#endif	/* SOLARIS_HW_SLOT_SELECTION */
		}
#ifdef	DEBUG_SLOT_SELECTION
	else
		{
		fprintf(stderr, " unusable\n");
		}
#endif	/* DEBUG_SLOT_SELECTION */

	return;
	}

#ifdef	SOLARIS_AES_CTR
/* create a new NID when we have no OID for that mechanism */
static int pk11_add_NID(char *sn, char *ln)
	{
	ASN1_OBJECT *o;
	int nid;

	if ((o = ASN1_OBJECT_create(OBJ_new_nid(1), (unsigned char *)"",
	    1, sn, ln)) == NULL)
		{
		return 0;
		}

	/* will return NID_undef on error */
	nid = OBJ_add_object(o);
	ASN1_OBJECT_free(o);

	return (nid);
	}

/*
 * Create new NIDs for AES counter mode. OpenSSL doesn't support them now so we
 * have to help ourselves here.
 */
static int pk11_add_aes_ctr_NIDs(void)
	{
	/* are we already set? */
	if (NID_aes_256_ctr != NID_undef)
		return 1;

	/*
	 * There are no official names for AES counter modes yet so we just
	 * follow the format of those that exist.
	 */
	if ((NID_aes_128_ctr = pk11_add_NID("AES-128-CTR", "aes-128-ctr")) ==
	    NID_undef)
		goto err;
	ciphers[PK11_AES_128_CTR].nid = pk11_aes_128_ctr.nid = NID_aes_128_ctr;
	if ((NID_aes_192_ctr = pk11_add_NID("AES-192-CTR", "aes-192-ctr")) ==
	    NID_undef)
		goto err;
	ciphers[PK11_AES_192_CTR].nid = pk11_aes_192_ctr.nid = NID_aes_192_ctr;
	if ((NID_aes_256_ctr = pk11_add_NID("AES-256-CTR", "aes-256-ctr")) ==
	    NID_undef)
		goto err;
	ciphers[PK11_AES_256_CTR].nid = pk11_aes_256_ctr.nid = NID_aes_256_ctr;
	return 1;

err:
	PK11err(PK11_F_ADD_AES_CTR_NIDS, PK11_R_ADD_NID_FAILED);
	return 0;
	}
#endif	/* SOLARIS_AES_CTR */

/* Find what symmetric ciphers this slot supports. */
static void pk11_find_symmetric_ciphers(CK_FUNCTION_LIST_PTR pflist,
    CK_SLOT_ID current_slot, int *current_slot_n_cipher, int *local_cipher_nids)
	{
	int i;

	for (i = 0; i < PK11_CIPHER_MAX; ++i)
		{
		pk11_get_symmetric_cipher(pflist, current_slot,
		    ciphers[i].mech_type, current_slot_n_cipher,
		    local_cipher_nids, ciphers[i].id);
		}
	}

/* Find what digest algorithms this slot supports. */
static void pk11_find_digests(CK_FUNCTION_LIST_PTR pflist,
    CK_SLOT_ID current_slot, int *current_slot_n_digest, int *local_digest_nids)
	{
	int i;

	for (i = 0; i < PK11_DIGEST_MAX; ++i)
		{
		pk11_get_digest(pflist, current_slot, digests[i].mech_type,
		    current_slot_n_digest, local_digest_nids, digests[i].id);
		}
	}

#ifdef	SOLARIS_HW_SLOT_SELECTION
/*
 * It would be great if we could use pkcs11_kernel directly since this library
 * offers hardware slots only. That's the easiest way to achieve the situation
 * where we use the hardware accelerators when present and OpenSSL native code
 * otherwise. That presumes the fact that OpenSSL native code is faster than the
 * code in the soft token. It's a logical assumption - Crypto Framework has some
 * inherent overhead so going there for the software implementation of a
 * mechanism should be logically slower in contrast to the OpenSSL native code,
 * presuming that both implementations are of similar speed. For example, the
 * soft token for AES is roughly three times slower than OpenSSL for 64 byte
 * blocks and still 20% slower for 8KB blocks. So, if we want to ship products
 * that use the PKCS#11 engine by default, we must somehow avoid that regression
 * on machines without hardware acceleration. That's why switching to the
 * pkcs11_kernel library seems like a very good idea.
 *
 * The problem is that OpenSSL built with SunStudio is roughly 2x slower for
 * asymmetric operations (RSA/DSA/DH) than the soft token built with the same
 * compiler. That means that if we switched to pkcs11_kernel from the libpkcs11
 * library, we would have had a performance regression on machines without
 * hardware acceleration for asymmetric operations for all applications that use
 * the PKCS#11 engine. There is one such application - Apache web server since
 * it's shipped configured to use the PKCS#11 engine by default. Having said
 * that, we can't switch to the pkcs11_kernel library now and have to come with
 * a solution that, on non-accelerated machines, uses the OpenSSL native code
 * for all symmetric ciphers and digests while it uses the soft token for
 * asymmetric operations.
 *
 * This is the idea: dlopen() pkcs11_kernel directly and find out what
 * mechanisms are there. We don't care about duplications (more slots can
 * support the same mechanism), we just want to know what mechanisms can be
 * possibly supported in hardware on that particular machine. As said before,
 * pkcs11_kernel will show you hardware providers only.
 *
 * Then, we rely on the fact that since we use libpkcs11 library we will find
 * the metaslot. When we go through the metaslot's mechanisms for symmetric
 * ciphers and digests, we check that any found mechanism is in the table
 * created using the pkcs11_kernel library. So, as a result we have two arrays
 * of mechanisms that were advertised as supported in hardware which was the
 * goal of that whole excercise. Thus, we can use libpkcs11 but avoid soft token
 * code for symmetric ciphers and digests. See pk11_choose_slots() for more
 * information.
 *
 * This is Solaris specific code, if SOLARIS_HW_SLOT_SELECTION is not defined
 * the code won't be used.
 */
#if defined(__sparcv9) || defined(__x86_64) || defined(__amd64)
static const char pkcs11_kernel[] = "/usr/lib/security/64/pkcs11_kernel.so.1";
#else
static const char pkcs11_kernel[] = "/usr/lib/security/pkcs11_kernel.so.1";
#endif

/*
 * Check hardware capabilities of the machines. The output are two lists,
 * hw_cnids and hw_dnids, that contain hardware mechanisms found in all hardware
 * providers together. They are not sorted and may contain duplicate mechanisms.
 */
static int check_hw_mechanisms(void)
	{
	int i;
	CK_RV rv;
	void *handle;
	CK_C_GetFunctionList p;
	CK_TOKEN_INFO token_info;
	CK_ULONG ulSlotCount = 0;
	int n_cipher = 0, n_digest = 0;
	CK_FUNCTION_LIST_PTR pflist = NULL;
	CK_SLOT_ID_PTR pSlotList = NULL_PTR;
	int *tmp_hw_cnids, *tmp_hw_dnids;
	int hw_ctable_size, hw_dtable_size;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: SOLARIS_HW_SLOT_SELECTION code running\n",
	    PK11_DBG);
#endif
	if ((handle = dlopen(pkcs11_kernel, RTLD_LAZY)) == NULL)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_DSO_FAILURE);
		goto err;
		}

	if ((p = (CK_C_GetFunctionList)dlsym(handle, 
	    PK11_GET_FUNCTION_LIST)) == NULL)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_DSO_FAILURE);
		goto err;
		}
 
	/* get the full function list from the loaded library 
	 */
	if (p(&pflist) != CKR_OK)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_DSO_FAILURE);
		goto err;
		}
 
	rv = pflist->C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
		{
		PK11err_add_data(PK11_F_CHECK_HW_MECHANISMS,
		    PK11_R_INITIALIZE, rv);
		goto err;
		}

	if (pflist->C_GetSlotList(0, NULL_PTR, &ulSlotCount) != CKR_OK)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_GETSLOTLIST);
		goto err;
		}

	/* no slots, set the hw mechanism tables as empty */
	if (ulSlotCount == 0)
		{
#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: no hardware mechanisms found\n", PK11_DBG);
#endif
		hw_cnids = OPENSSL_malloc(sizeof (int));
		hw_dnids = OPENSSL_malloc(sizeof (int));
		if (hw_cnids == NULL || hw_dnids == NULL)
			{
			PK11err(PK11_F_CHECK_HW_MECHANISMS,
			    PK11_R_MALLOC_FAILURE);
			return (0);
			}
		/* this means empty tables */
		hw_cnids[0] = NID_undef;
		hw_dnids[0] = NID_undef;
		return (1);
		}

	pSlotList = OPENSSL_malloc(ulSlotCount * sizeof (CK_SLOT_ID));
	if (pSlotList == NULL) 
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/* Get the slot list for processing */
	if (pflist->C_GetSlotList(0, pSlotList, &ulSlotCount) != CKR_OK)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_GETSLOTLIST);
		goto err;
		}

	/*
	 * We don't care about duplicit mechanisms in multiple slots and also
	 * reserve one slot for the terminal NID_undef which we use to stop the
	 * search.
	 */
	hw_ctable_size = ulSlotCount * PK11_CIPHER_MAX + 1;
	hw_dtable_size = ulSlotCount * PK11_DIGEST_MAX + 1;
	tmp_hw_cnids = OPENSSL_malloc(hw_ctable_size * sizeof (int));
	tmp_hw_dnids = OPENSSL_malloc(hw_dtable_size * sizeof (int));
	if (tmp_hw_cnids == NULL || tmp_hw_dnids == NULL)
		{
		PK11err(PK11_F_CHECK_HW_MECHANISMS, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/*
	 * Do not use memset since we should not rely on the fact that NID_undef
	 * is zero now.
	 */
	for (i = 0; i < hw_ctable_size; ++i)
		tmp_hw_cnids[i] = NID_undef;
	for (i = 0; i < hw_dtable_size; ++i)
		tmp_hw_dnids[i] = NID_undef;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: provider: %s\n", PK11_DBG, pkcs11_kernel);
	fprintf(stderr, "%s: found %d hardware slots\n", PK11_DBG, ulSlotCount);
	fprintf(stderr, "%s: now looking for mechs supported in hw\n",
	    PK11_DBG); 
#endif	/* DEBUG_SLOT_SELECTION */

	for (i = 0; i < ulSlotCount; i++) 
		{
		if (pflist->C_GetTokenInfo(pSlotList[i], &token_info) != CKR_OK)
			continue;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: token label: %.32s\n", PK11_DBG, token_info.label);
#endif	/* DEBUG_SLOT_SELECTION */

		/*
		 * We are filling the hw mech tables here. Global tables are
		 * still NULL so all mechanisms are put into tmp tables.
		 */
		pk11_find_symmetric_ciphers(pflist, pSlotList[i],
		    &n_cipher, tmp_hw_cnids);
		pk11_find_digests(pflist, pSlotList[i],
		    &n_digest, tmp_hw_dnids);
		}

	/*
	 * Since we are part of a library (libcrypto.so), calling this function
	 * may have side-effects. Also, C_Finalize() is triggered by
	 * dlclose(3C).
	 */
#if 0
	pflist->C_Finalize(NULL);
#endif
	OPENSSL_free(pSlotList);
	dlclose(handle);
	hw_cnids = tmp_hw_cnids;
	hw_dnids = tmp_hw_dnids;

#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, "%s: hw mechs check complete\n", PK11_DBG);
#endif	/* DEBUG_SLOT_SELECTION */
	return (1);

err:
	if (pSlotList != NULL)
		OPENSSL_free(pSlotList);
	if (tmp_hw_cnids != NULL)
		OPENSSL_free(tmp_hw_cnids);
	if (tmp_hw_dnids != NULL)
		OPENSSL_free(tmp_hw_dnids);

	return (0);
	}

/*
 * Check presence of a NID in the table of NIDs. The table may be NULL (i.e.,
 * non-existent).
 */
static int nid_in_table(int nid, int *nid_table)
	{
	int i = 0;

	/*
	 * a special case. NULL means that we are initializing a new
	 * table.
	 */
	if (nid_table == NULL)
		return (1);

	/*
	 * the table is never full, there is always at least one
	 * NID_undef.
	 */
	while (nid_table[i] != NID_undef)
		{
		if (nid_table[i++] == nid)
			{
#ifdef	DEBUG_SLOT_SELECTION
	fprintf(stderr, " (NID %d in hw table, idx %d)", nid, i);
#endif	/* DEBUG_SLOT_SELECTION */
			return (1);
			}
		}

	return (0);
	}
#endif	/* SOLARIS_HW_SLOT_SELECTION */

#endif	/* OPENSSL_NO_HW_PK11 */
#endif	/* OPENSSL_NO_HW */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <cryptlib.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_PK11

#undef DEBUG_SLOT_SELECTION

#include "security/cryptoki.h"
#include "security/pkcs11.h"
#include "hw_pk11_err.c"


/* The head of the free PK11 session list */
static struct PK11_SESSION_st *free_session = NULL;

/* Create all secret key objects in a global session so that they are available
 * to use for other sessions. These other sessions may be opened or closed
 * without losing the secret key objects */
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
PK11_SESSION *pk11_get_session();
void pk11_return_session(PK11_SESSION *sp);

/* active list manipulation functions used here */
int pk11_active_delete(CK_OBJECT_HANDLE h);

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
static int pk11_free_all_sessions();
static int pk11_setup_session(PK11_SESSION *sp);
static int pk11_destroy_cipher_key_objects(PK11_SESSION *session);
static int pk11_destroy_object(CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE oh);
static const char *get_PK11_LIBNAME(void);
static void free_PK11_LIBNAME(void);
static long set_PK11_LIBNAME(const char *name);

/* Symmetric cipher and digest support functions */
static int cipher_nid_to_pk11(int nid);
static int pk11_usable_ciphers(const int **nids);
static int pk11_usable_digests(const int **nids);
static int pk11_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc);
static int pk11_init_symmetric(EVP_CIPHER_CTX *ctx, PK11_SESSION *sp,
	CK_MECHANISM_PTR pmech);
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
static int check_new_cipher_key(PK11_SESSION *sp, const unsigned char *key);
static int md_nid_to_pk11(int nid);
static int pk11_digest_init(EVP_MD_CTX *ctx);
static int pk11_digest_update(EVP_MD_CTX *ctx,const void *data,
	size_t count);
static int pk11_digest_final(EVP_MD_CTX *ctx,unsigned char *md);
static int pk11_digest_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from);
static int pk11_digest_cleanup(EVP_MD_CTX *ctx);

static int pk11_choose_slot();
static int pk11_count_symmetric_cipher(int slot_id, CK_MECHANISM_TYPE mech,
    int *current_slot_n_cipher, int *local_cipher_nids, int id);
static int pk11_count_digest(int slot_id, CK_MECHANISM_TYPE mech,
    int *current_slot_n_digest, int *local_digest_nids, int id);

/* Index for the supported ciphers */
#define PK11_DES_CBC		0
#define PK11_DES3_CBC		1
#define PK11_AES_CBC		2
#define PK11_RC4		3

/* Index for the supported digests */
#define PK11_MD5		0
#define PK11_SHA1		1

#define PK11_CIPHER_MAX		4	/* Max num of ciphers supported */
#define PK11_DIGEST_MAX		2	/* Max num of digests supported */

#define PK11_KEY_LEN_MAX	24

#define	TRY_OBJ_DESTROY(sess_hdl, obj_hdl, retval, uselock)		\
	{								\
	if (uselock)							\
		CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);			\
	if (pk11_active_delete(obj_hdl) == 1)				\
		{							\
		retval = pk11_destroy_object(sess_hdl, obj_hdl);	\
		}							\
	if (uselock)							\
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);		\
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
	int			id;
	int			nid;
	int			ivmax;
	int			key_len;
	CK_KEY_TYPE		key_type;
	CK_MECHANISM_TYPE	mech_type;
	} PK11_CIPHER;

static PK11_CIPHER ciphers[] = 
	{
	{PK11_DES_CBC,  NID_des_cbc,      8,  8,   CKK_DES,  CKM_DES_CBC, },
	{PK11_DES3_CBC, NID_des_ede3_cbc, 8,  24,  CKK_DES3, CKM_DES3_CBC, },
	{PK11_AES_CBC,  NID_aes_128_cbc,  16, 16,  CKK_AES,  CKM_AES_CBC, },
	{PK11_RC4,      NID_rc4,          0,  16,  CKK_RC4,  CKM_RC4, },
	};

typedef struct PK11_DIGEST_st
	{
	int			id;
	int			nid;
	CK_MECHANISM_TYPE	mech_type;
	} PK11_DIGEST;

static PK11_DIGEST digests[] = 
	{
	{PK11_MD5,	NID_md5,	CKM_MD5, },
	{PK11_SHA1,	NID_sha1,	CKM_SHA_1, },
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


/* libcrypto EVP stuff - this is how we get wired to EVP so the engine
 * gets called when libcrypto requests a cipher NID.
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

static const EVP_CIPHER pk11_aes_cbc = 
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

static const EVP_CIPHER pk11_rc4 =
	{
	NID_rc4,
	1,16,0,
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
static CK_SLOT_ID SLOTID = 0;
static int pk11_library_initialized = 0;

static DSO *pk11_dso = NULL;

/*
 * This internal function is used by ENGINE_pk11() and "dynamic" ENGINE support.
 */
static int bind_pk11(ENGINE *e)
	{
#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *rsa = NULL;
	RSA_METHOD *pk11_rsa = PK11_RSA();
#endif
	if (!pk11_library_initialized)
		pk11_library_init(e);

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
#ifdef DEBUG_SLOT_SELECTION
		fprintf(stderr, "OPENSSL_PKCS#11_ENGINE: registered RSA\n");
#endif /* DEBUG_SLOT_SELECTION */
		}
#endif
#ifndef OPENSSL_NO_DSA
	if(pk11_have_dsa == CK_TRUE)
		{	
	  	if (!ENGINE_set_DSA(e, PK11_DSA()))
			return 0;
#ifdef DEBUG_SLOT_SELECTION
		fprintf(stderr, "OPENSSL_PKCS#11_ENGINE: registered DSA\n");
#endif /* DEBUG_SLOT_SELECTION */
	    	}
#endif
#ifndef OPENSSL_NO_DH
	if(pk11_have_dh == CK_TRUE)
		{
	  	if (!ENGINE_set_DH(e, PK11_DH()))
			return 0;
#ifdef DEBUG_SLOT_SELECTION
		fprintf(stderr, "OPENSSL_PKCS#11_ENGINE: registered DH\n");
#endif /* DEBUG_SLOT_SELECTION */
	    	}
#endif
	if(pk11_have_random)
		{
		if(!ENGINE_set_RAND(e, &pk11_random))
			return 0;
#ifdef DEBUG_SLOT_SELECTION
		fprintf(stderr, "OPENSSL_PKCS#11_ENGINE: registered random\n");
#endif /* DEBUG_SLOT_SELECTION */
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
#endif

	/* Ensure the pk11 error handling is set up */
	ERR_load_pk11_strings();
	
	return 1;
	}

/* Dynamic engine support is disabled at a higher level for Solaris
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
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
#endif

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
	char tmp_buf[20];

	if (pk11_library_initialized)
		return 1;
	
	if (pk11_dso == NULL)
		{
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_DSO_FAILURE);
		goto err;
		}

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
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_DSO_FAILURE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}
 
	rv = pFuncList->C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
		{
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_INITIALIZE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	rv = pFuncList->C_GetInfo(&info);
	if (rv != CKR_OK) 
		{
		PK11err(PK11_F_LIBRARY_INIT, PK11_R_GETINFO);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	if (pk11_choose_slot() == 0)
		goto err;

	if (global_session == CK_INVALID_HANDLE)
		{
		/* Open the global_session for the new process */
		rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &global_session);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_LIBRARY_INIT, PK11_R_OPENSESSION);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto err;
			}
		}

	/* Disable digest if C_GetOperationState is not supported since
	 * this function is required by OpenSSL digest copy function */
	if (pFuncList->C_GetOperationState(global_session, NULL, &ul_state_len)
			== CKR_FUNCTION_NOT_SUPPORTED)
		digest_count = 0;

	pk11_library_initialized = 1;
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

	if (pk11_dso == NULL)
		{
		PK11err(PK11_F_FINISH, PK11_R_NOT_LOADED);
		goto err;
		}

	OPENSSL_assert(pFuncList != NULL);

	if (pk11_free_all_sessions() == 0)
		goto err;

	pFuncList->C_CloseSession(global_session);
	
	/* Since we are part of a library (libcrypto.so), calling this
	 * function may have side-effects.
	pFuncList->C_Finalize(NULL);
	 */

	if (!DSO_free(pk11_dso))
		{
		PK11err(PK11_F_FINISH, PK11_R_DSO_FAILURE);
		goto err;
		}
	pk11_dso = NULL;
	pFuncList = NULL;
	pk11_library_initialized = 0;

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

	if ((sp = pk11_get_session()) == NULL)
		return;

	/* Ignore any errors (e.g. CKR_RANDOM_SEED_NOT_SUPPORTED) since 
	 * the calling functions do not care anyway
	 */
	pFuncList->C_SeedRandom(sp->session, (unsigned char *) buf, num);
	pk11_return_session(sp);

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
	
	if ((sp = pk11_get_session()) == NULL)
		return 0;
	
	rv = pFuncList->C_GenerateRandom(sp->session, buf, num);
	if (rv != CKR_OK)
		{
		char tmp_buf[20];
		PK11err(PK11_F_RAND_BYTES, PK11_R_GENERATERANDOM);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		pk11_return_session(sp);
		return 0;
		}

	pk11_return_session(sp);
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
static void pk11_free_nums(PK11_SESSION *sp)
	{
#ifndef	OPENSSL_NO_RSA
		if (sp->rsa_n_num != NULL)
			BN_free(sp->rsa_n_num);
		if (sp->rsa_e_num != NULL)
			BN_free(sp->rsa_e_num);
		if (sp->rsa_d_num != NULL)
			BN_free(sp->rsa_d_num);
#endif
#ifndef	OPENSSL_NO_DSA
		if (sp->dsa_pub_num != NULL)
			BN_free(sp->dsa_pub_num);
		if (sp->dsa_priv_num != NULL)
			BN_free(sp->dsa_priv_num);
#endif
#ifndef	OPENSSL_NO_DH
		if (sp->dh_priv_num != NULL)
			BN_free(sp->dh_priv_num);
#endif
	}

/*
 * Get new PK11_SESSION structure ready for use. Every process must have
 * its own freelist of PK11_SESSION structures so handle fork() here
 * by destroying the old and creating new freelist.
 * The returned PK11_SESSION structure is disconnected from the freelist.
 */
PK11_SESSION *pk11_get_session()
	{
	PK11_SESSION *sp, *sp1;
	CK_RV rv;
	char tmp_buf[20];

	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	/*
	 * If the free list is empty, allocate new unitialized (filled
	 * with zeroes) PK11_SESSION structure otherwise return first
	 * structure from the freelist.
	 */
	if ((sp = free_session) == NULL)
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
		free_session = sp->next;
		}

	if (sp->pid != 0 && sp->pid != getpid())
		{
		/*
		 * We are a new process and thus need to free any inherited
		 * PK11_SESSION objects.
		 */
		while ((sp1 = free_session) != NULL)
			{
			free_session = sp1->next;
			/*
			 * NOTE:
			 *   we do not want to call pk11_free_all_sessions()
			 *   here because it would close underlying PKCS11
			 *   sessions and destroy objects.
			 */
			pk11_free_nums(sp1);
			OPENSSL_free(sp1);
			}

		/* Initialize the process */
		rv = pFuncList->C_Initialize(NULL_PTR);
		if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
			{
			PK11err(PK11_F_GET_SESSION, PK11_R_INITIALIZE);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			OPENSSL_free(sp);
			sp = NULL;
			goto err;
			}

		/*
		 * Choose slot here since the slot table is different on
		 * this process.
		 */
		if (pk11_choose_slot() == 0)
			goto err;

		/* Open the global_session for the new process */
		rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &global_session);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_SESSION, PK11_R_OPENSESSION);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			OPENSSL_free(sp);
			sp = NULL;
			goto err;
			}

		/* It is an inherited session and needs re-initialization.
		 */
		if (pk11_setup_session(sp) == 0)
			{
			OPENSSL_free(sp);
			sp = NULL;
			}
		}
	else if (sp->pid == 0)
		{
		/* It is a new session and needs initialization.
		 */
		if (pk11_setup_session(sp) == 0)
			{
			OPENSSL_free(sp);
			sp = NULL;
			}
		}

err:
	if (sp != NULL)
		sp->next = NULL;

	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return sp;
	}


void pk11_return_session(PK11_SESSION *sp)
	{
	if (sp == NULL || sp->pid != getpid())
		return;

	
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);

	sp->next = free_session;
	free_session = sp;

	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
	}


/* Destroy all objects. This function is called when the engine is finished
 */
static int pk11_free_all_sessions()
	{
	CK_RV rv;
	PK11_SESSION *sp = NULL;
	pid_t mypid = getpid();
	int ret = 0;

#ifndef OPENSSL_NO_RSA
	(void) pk11_destroy_rsa_key_objects(NULL);
#endif
#ifndef OPENSSL_NO_DSA
	(void) pk11_destroy_dsa_key_objects(NULL);
#endif
#ifndef OPENSSL_NO_DH
	(void) pk11_destroy_dh_key_objects(NULL);
#endif
	(void) pk11_destroy_cipher_key_objects(NULL);
	
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	while ((sp = free_session) != NULL)
		{
		if (sp->session != CK_INVALID_HANDLE && sp->pid == mypid)
			{
			rv = pFuncList->C_CloseSession(sp->session);
			if (rv != CKR_OK)
				{
				char tmp_buf[20];
				PK11err(PK11_F_FREE_ALL_SESSIONS, 
					PK11_R_CLOSESESSION);
				snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
				ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
				}
			}
		if (sp->session_cipher != CK_INVALID_HANDLE && sp->pid == mypid)
			{
			rv = pFuncList->C_CloseSession(sp->session_cipher);
			if (rv != CKR_OK)
				{
				char tmp_buf[20];
				PK11err(PK11_F_FREE_ALL_SESSIONS, 
					PK11_R_CLOSESESSION);
				snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
				ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
				}
			}
		free_session = sp->next;
		pk11_free_nums(sp);
		OPENSSL_free(sp);
		}
	ret = 1;
err:
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return ret;
	}


static int pk11_setup_session(PK11_SESSION *sp)
	{
	CK_RV rv;
	sp->session = CK_INVALID_HANDLE;
	rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
		NULL_PTR, NULL_PTR, &sp->session);
	if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
		/*
		 * We are probably a child process so force the
		 * reinitialize of the session
		 */
		pk11_library_initialized = 0;
		(void) pk11_library_init(NULL);
		rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
			NULL_PTR, NULL_PTR, &sp->session);
		}
	if (rv != CKR_OK)
		{
		char tmp_buf[20];
		PK11err(PK11_F_SETUP_SESSION, PK11_R_OPENSESSION);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		return 0;
		}

	sp->session_cipher = CK_INVALID_HANDLE;
	rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
		NULL_PTR, NULL_PTR, &sp->session_cipher);
	if (rv != CKR_OK)
		{
		char tmp_buf[20];

		(void) pFuncList->C_CloseSession(sp->session);
		sp->session = CK_INVALID_HANDLE;

		PK11err(PK11_F_SETUP_SESSION, PK11_R_OPENSESSION);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		return 0;
		}

	sp->pid = getpid();
	sp->rsa_pub_key = CK_INVALID_HANDLE;
	sp->rsa_priv_key = CK_INVALID_HANDLE;
	sp->dsa_pub_key = CK_INVALID_HANDLE;
	sp->dsa_priv_key = CK_INVALID_HANDLE;
	sp->dh_key = CK_INVALID_HANDLE;
	sp->cipher_key = CK_INVALID_HANDLE;
#ifndef OPENSSL_NO_RSA
	sp->rsa_pub = NULL;
	sp->rsa_n_num = NULL;
	sp->rsa_e_num = NULL;
	sp->rsa_priv = NULL;
	sp->rsa_d_num = NULL;
#endif
#ifndef OPENSSL_NO_DSA
	sp->dsa_pub = NULL;
	sp->dsa_pub_num = NULL;
	sp->dsa_priv = NULL;
	sp->dsa_priv_num = NULL;
#endif
#ifndef OPENSSL_NO_DH
	sp->dh = NULL;
	sp->dh_priv_num = NULL;
#endif
	sp->encrypt = -1;

	return 1;
	}

#ifndef OPENSSL_NO_RSA
/* Destroy RSA public key from single session. */
int pk11_destroy_rsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->rsa_pub_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->rsa_pub_key, ret, uselock);
		sp->rsa_pub_key = CK_INVALID_HANDLE;
		sp->rsa_pub = NULL;
		if (sp->rsa_n_num != NULL)
			BN_free(sp->rsa_n_num);
		sp->rsa_n_num = NULL;
		if (sp->rsa_e_num != NULL)
			BN_free(sp->rsa_e_num);
		sp->rsa_e_num = NULL;
		}

	return (ret);
	}

/* Destroy RSA private key from single session. */
int pk11_destroy_rsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->rsa_priv_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->rsa_priv_key, ret, uselock);
		sp->rsa_priv_key = CK_INVALID_HANDLE;
		sp->rsa_priv = NULL;
		if (sp->rsa_d_num != NULL)
			BN_free(sp->rsa_d_num);
		sp->rsa_d_num = NULL;
		}

	return (ret);
	}


/*
 * Destroy RSA key object wrapper.
 *
 * arg0: pointer to PKCS#11 engine session structure
 *       if session is NULL, try to destroy all objects in the free list
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
		CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
		local_free_session = free_session;
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
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return ret;
	}
#endif

#ifndef OPENSSL_NO_DSA
/* Destroy DSA public key from single session. */
int pk11_destroy_dsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->dsa_pub_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->dsa_pub_key, ret, uselock);
		sp->dsa_pub_key = CK_INVALID_HANDLE;
		sp->dsa_pub = NULL;
		if (sp->dsa_pub_num != NULL)
			BN_free(sp->dsa_pub_num);
		sp->dsa_pub_num = NULL;
		}

	return (ret);
	}

/* Destroy DSA private key from single session. */
int pk11_destroy_dsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->dsa_priv_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->dsa_priv_key, ret, uselock);
		sp->dsa_priv_key = CK_INVALID_HANDLE;
		sp->dsa_priv = NULL;
		if (sp->dsa_priv_num != NULL)
			BN_free(sp->dsa_priv_num);
		sp->dsa_priv_num = NULL;
		}

	return (ret);
	}

/*
 * Destroy DSA key object wrapper.
 *
 * arg0: pointer to PKCS#11 engine session structure
 *       if session is NULL, try to destroy all objects in the free list
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
		CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
		local_free_session = free_session;
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
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return ret;
	}
#endif

#ifndef OPENSSL_NO_DH
/* Destroy DH key from single session. */
int pk11_destroy_dh_object(PK11_SESSION *sp, CK_BBOOL uselock)
	{
	int ret = 0;

	if (sp->dh_key != CK_INVALID_HANDLE)
		{
		TRY_OBJ_DESTROY(sp->session, sp->dh_key, ret, uselock);
		sp->dh_key = CK_INVALID_HANDLE;
		sp->dh = NULL;
		if (sp->dh_priv_num != NULL)
			BN_free(sp->dh_priv_num);
		sp->dh_priv_num = NULL;
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
		CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
		local_free_session = free_session;
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
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return ret;
	}
#endif


static int pk11_destroy_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE oh)
	{
	CK_RV rv;
	rv = pFuncList->C_DestroyObject(session, oh);
	if (rv != CKR_OK)
		{
		char tmp_buf[20];
		PK11err(PK11_F_DESTROY_OBJECT, PK11_R_DESTROYOBJECT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", 
			tmp_buf);
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

static int
pk11_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
	{
	CK_RV rv;
	CK_MECHANISM mech;
	int index;
	PK11_CIPHER_STATE *state = (PK11_CIPHER_STATE *) ctx->cipher_data;
	PK11_SESSION *sp;
	PK11_CIPHER *pcp;
	char tmp_buf[20];
	
	state->sp = NULL;

	index = cipher_nid_to_pk11(ctx->cipher->nid);
	if (index < 0 || index >= PK11_CIPHER_MAX)
		return 0;

	pcp = &ciphers[index];
	if (ctx->cipher->iv_len > pcp->ivmax || ctx->key_len != pcp->key_len)
		return 0;

	if ((sp = pk11_get_session()) == NULL)
		return 0;

	/* if applicable, the mechanism parameter is used for IV */
	mech.mechanism = pcp->mech_type;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	/* The key object is destroyed here if it is not the current key
	 */
	(void) check_new_cipher_key(sp, key);
	
	/* If the key is the same and the encryption is also the same,
	 * then just reuse it. However, we must not forget to reinitialize the
	 * context that was finalized in pk11_cipher_cleanup().
	 */
	if (sp->cipher_key != CK_INVALID_HANDLE && sp->encrypt == ctx->encrypt)
		{
		state->sp = sp;
		if (pk11_init_symmetric(ctx, sp, &mech) == 0)
			return (0);

		return (1);
		}

	/* Check if the key has been invalidated. If so, a new key object
	 * needs to be created.
	 */
	if (sp->cipher_key == CK_INVALID_HANDLE)
		{
		sp->cipher_key = pk11_get_cipher_key(
			ctx, key, pcp->key_type, sp);
		}

	if (sp->encrypt != ctx->encrypt && sp->encrypt != -1)
		{
		/* The previous encryption/decryption
		 * is different. Need to terminate the previous
		 * active encryption/decryption here
		 */
		if (!pk11_cipher_final(sp))
			{
			pk11_return_session(sp);
			return 0;
			}
		}

	if (sp->cipher_key == CK_INVALID_HANDLE)
		{
		pk11_return_session(sp);
		return 0;
		}

	/* now initialize the context with a new key */
	if (pk11_init_symmetric(ctx, sp, &mech) == 0)
		return (0);

	sp->encrypt = ctx->encrypt;
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
	char tmp_buf[20];

	rv = pFuncList->C_CloseSession(sp->session_cipher);
	if (rv != CKR_OK)
		{
		PK11err(PK11_F_CIPHER_FINAL, PK11_R_CLOSESESSION);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		return 0;
		}

	rv = pFuncList->C_OpenSession(SLOTID, CKF_SERIAL_SESSION,
		NULL_PTR, NULL_PTR, &sp->session_cipher);
	if (rv != CKR_OK)
		{
		PK11err(PK11_F_CIPHER_FINAL, PK11_R_OPENSESSION);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
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
	char tmp_buf[20];

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
		rv = pFuncList->C_EncryptUpdate(sp->session_cipher, 
			(unsigned char *)in, inl, out, &outl);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_CIPHER_DO_CIPHER, 
				PK11_R_ENCRYPTUPDATE);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			return 0;
			}
		}
	else
		{
		rv = pFuncList->C_DecryptUpdate(sp->session_cipher, 
			(unsigned char *)in, inl, out, &outl);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_CIPHER_DO_CIPHER, 
				PK11_R_DECRYPTUPDATE);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
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
 * Return the session to the pool. Calling C_EncryptFinal() and
 * C_DecryptFinal() here is the right thing because in
 * EVP_DecryptFinal_ex(), engine's do_cipher() is not even called, and in
 * EVP_EncryptFinal_ex() it is called but the engine can't find out that
 * it's the finalizing call. We wouldn't necessarily have to finalize the
 * context here since reinitializing it with C_(Encrypt|Decrypt)Init()
 * should be fine but for the sake of correctness, let's do it. Some
 * implementations might leak memory if the previously used context is
 * initialized without finalizing it first.
 */
static int
pk11_cipher_cleanup(EVP_CIPHER_CTX *ctx)
	{
	CK_RV rv;
	CK_ULONG len;
	char tmp_buf[20];
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
			    state->sp->session_cipher, buf, &len);
		else
			rv = pFuncList->C_DecryptFinal(
			    state->sp->session_cipher, buf, &len);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_CIPHER_CLEANUP, ctx->encrypt ?
			    PK11_R_ENCRYPTFINAL : PK11_R_DECRYPTFINAL);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(state->sp);
			return (0);
			}

		pk11_return_session(state->sp);
		state->sp = NULL;
		}

	return (1);
	}

/*
 * Init context for encryption or decryption using a symmetric key.
 */
static int pk11_init_symmetric(EVP_CIPHER_CTX *ctx, PK11_SESSION *sp,
    CK_MECHANISM_PTR pmech)
	{
	CK_RV rv;
	char tmp_buf[20];

	if (ctx->cipher->iv_len > 0)
		{
		/*
		 * We expect pmech->mechanism to be already set and
		 * pParameter/ulParameterLen initialized to NULL/0 before
		 * pk11_init_symetric() is called.
		 */
		OPENSSL_assert(pmech->mechanism != NULL);
		OPENSSL_assert(pmech->pParameter == NULL);
		OPENSSL_assert(pmech->ulParameterLen == 0);
		pmech->pParameter = (void *) ctx->iv;
		pmech->ulParameterLen = ctx->cipher->iv_len;
		}

	/* If we get here, the encryption needs to be reinitialized */
	if (ctx->encrypt)
		rv = pFuncList->C_EncryptInit(sp->session_cipher, pmech,
			sp->cipher_key);
	else
		rv = pFuncList->C_DecryptInit(sp->session_cipher, pmech,
			sp->cipher_key);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_CIPHER_INIT, ctx->encrypt ?
		    PK11_R_ENCRYPTINIT : PK11_R_DECRYPTINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		pk11_return_session(sp);
		return (0);
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
		case NID_aes_128_cbc:
			*cipher = &pk11_aes_cbc;
			break;
		case NID_rc4:
			*cipher = &pk11_rc4;
			break;
		default:
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
	char tmp_buf[20];

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
		PK11err(PK11_F_GET_CIPHER_KEY, PK11_R_CREATEOBJECT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	/* Save the key information used in this session.
	 * The max can be saved is PK11_KEY_LEN_MAX.
	 */
	sp->key_len = ctx->key_len > PK11_KEY_LEN_MAX ? 
		PK11_KEY_LEN_MAX : ctx->key_len;
	memcpy(sp->key, key, sp->key_len);
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
	if ((sp = pk11_get_session()) == NULL)
		return 0;

	/* at present, no parameter is needed for supported digests */
	mech.mechanism = pdp->mech_type;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	rv = pFuncList->C_DigestInit(sp->session, &mech);

	if (rv != CKR_OK)
		{
		char tmp_buf[20];
		PK11err(PK11_F_DIGEST_INIT, PK11_R_DIGESTINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		pk11_return_session(sp);
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
		char tmp_buf[20];
		PK11err(PK11_F_DIGEST_UPDATE, PK11_R_DIGESTUPDATE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		pk11_return_session(state->sp);
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
		char tmp_buf[20];
		PK11err(PK11_F_DIGEST_FINAL, PK11_R_DIGESTFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		pk11_return_session(state->sp);
		state->sp = NULL;
		return 0;
		}

	if (ctx->digest->md_size != len)
		return 0;

	/* Final is called and digest is returned, so return the session
	 * to the pool
	 */
	pk11_return_session(state->sp);
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
	char tmp_buf[20];
	
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
		PK11err(PK11_F_DIGEST_COPY, PK11_R_GET_OPERATION_STATE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
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
		PK11err(PK11_F_DIGEST_COPY, PK11_R_GET_OPERATION_STATE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	/* Set the operation state of the copy-to session */
	rv = pFuncList->C_SetOperationState(state_to->sp->session, pstate, 
		ul_state_len, 0, 0);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DIGEST_COPY, PK11_R_SET_OPERATION_STATE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
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
		pk11_digest_final(ctx,buf);
		pk11_return_session(state->sp);
		state->sp = NULL;
		}

	return 1;
	}

/*
 * Check if the new key is the same as the key object in the session.
 * If the key is the same, no need to create a new key object. Otherwise,
 * the old key object needs to be destroyed and a new one will be created.
 * Return 1 for cache hit, 0 for cache miss.
 */
static int check_new_cipher_key(PK11_SESSION *sp, const unsigned char *key)
	{
	if (memcmp(sp->key, key, sp->key_len) != 0)
		{
		pk11_destroy_cipher_key_objects(sp);
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

	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	if (session)
		local_free_session = session;
	else
		local_free_session = free_session;
	while ((sp = local_free_session) != NULL)
		{
		local_free_session = sp->next;

		if (sp->cipher_key != CK_INVALID_HANDLE)
			{
			/* The secret key object is created in the 
			 * global_session. See pk11_get_cipher_key
			 */
			if (pk11_destroy_object(global_session, 
				sp->cipher_key) == 0)
				goto err;
			sp->cipher_key = CK_INVALID_HANDLE;
			}
		}
	ret = 1;
err:
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

	return ret;
	}


/*
 * Required mechanisms
 *
 * CKM_RSA_X_509
 * CKM_RSA_PKCS
 * CKM_DSA
 *
 * As long as these required mechanisms are met, it will return success. 
 * Otherwise, it will return failure and the engine initialization will fail. 
 * The application will then decide whether to use another engine or 
 * no engine.
 *
 * Symmetric ciphers optionally supported
 *
 * CKM_DES3_CBC
 * CKM_DES_CBC
 * CKM_AES_CBC
 * CKM_RC4
 *
 * Digests optionally supported
 *
 * CKM_MD5
 * CKM_SHA_1
 */

static int 
pk11_choose_slot()
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
	char tmp_buf[20];
	int retval = 0;

	/* Get slot list for memory alloction */
	rv = pFuncList->C_GetSlotList(0, NULL_PTR, &ulSlotCount);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_CHOOSE_SLOT, PK11_R_GETSLOTLIST);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		return retval;
		}

	if (ulSlotCount == 0) 
		{
		PK11err(PK11_F_CHOOSE_SLOT, PK11_R_GETSLOTLIST);
		return retval;
		}

	pSlotList = OPENSSL_malloc(ulSlotCount * sizeof (CK_SLOT_ID));

	if (pSlotList == NULL) 
		{
		PK11err(PK11_F_CHOOSE_SLOT, PK11_R_MALLOC_FAILURE);
		return retval;
		}

	/* Get the slot list for processing */
	rv = pFuncList->C_GetSlotList(0, pSlotList, &ulSlotCount);
	if (rv != CKR_OK) 
		{
		PK11err(PK11_F_CHOOSE_SLOT, PK11_R_GETSLOTLIST);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		OPENSSL_free(pSlotList);
		return retval;
		}

	for (i = 0; i < ulSlotCount; i++) 
		{
		CK_BBOOL slot_has_rsa = CK_FALSE;
		CK_BBOOL slot_has_dsa = CK_FALSE;
		CK_BBOOL slot_has_dh = CK_FALSE;
		current_slot = pSlotList[i];
		current_slot_n_cipher = 0;
		current_slot_n_digest = 0;
		memset(local_cipher_nids, 0, sizeof(local_cipher_nids));
		memset(local_digest_nids, 0, sizeof(local_digest_nids));

#ifdef DEBUG_SLOT_SELECTION
		fprintf(stderr, "OPENSSL_PKCS#11_ENGINE: checking slot: %d\n",
		    current_slot);
#endif
		/* Check if slot has random support. */
		rv = pFuncList->C_GetTokenInfo(current_slot, &token_info);
		if (rv != CKR_OK)
			continue;

		if (token_info.flags & CKF_RNG)
			pk11_have_random = CK_TRUE;
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
				slot_has_rsa = CK_TRUE;
			}
#endif
#ifndef OPENSSL_NO_DSA
		/*
		 * Check if this slot is capable of signing and
		 * verifying with CKM_DSA.
		 */
		rv = pFuncList->C_GetMechanismInfo(current_slot, CKM_DSA, 
			&mech_info);
		if (rv == CKR_OK && ((mech_info.flags & CKF_SIGN) &&
		    (mech_info.flags & CKF_VERIFY)))
			slot_has_dsa = CK_TRUE;
#endif
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
				slot_has_dh = CK_TRUE;
			}
#endif
		if (!found_candidate_slot &&
		    (slot_has_rsa || slot_has_dsa || slot_has_dh))
			{
#ifdef DEBUG_SLOT_SELECTION
			fprintf(stderr,
			    "OPENSSL_PKCS#11_ENGINE: potential slot: %d\n",
			    current_slot);
#endif
			best_slot_sofar = current_slot;
			pk11_have_rsa = slot_has_rsa;
			pk11_have_dsa = slot_has_dsa;
			pk11_have_dh = slot_has_dh;
			found_candidate_slot = CK_TRUE;
#ifdef DEBUG_SLOT_SELECTION
			fprintf(stderr,
		    	    "OPENSSL_PKCS#11_ENGINE: best so far slot: %d\n",
		    	    best_slot_sofar);
#endif
			}

		/* Count symmetric cipher support. */
		if (!pk11_count_symmetric_cipher(current_slot, CKM_DES_CBC,
				&current_slot_n_cipher, local_cipher_nids,
				PK11_DES_CBC))
			continue;
		if (!pk11_count_symmetric_cipher(current_slot, CKM_DES3_CBC,
				&current_slot_n_cipher, local_cipher_nids,
				PK11_DES3_CBC))
			continue;
		if (!pk11_count_symmetric_cipher(current_slot, CKM_AES_CBC,
				&current_slot_n_cipher, local_cipher_nids,
				PK11_AES_CBC))
			continue;
		if (!pk11_count_symmetric_cipher(current_slot, CKM_RC4,
				&current_slot_n_cipher, local_cipher_nids,
				PK11_RC4))
			continue;

		/* Count digest support */
		if (!pk11_count_digest(current_slot, CKM_MD5,
				&current_slot_n_digest, local_digest_nids,
				PK11_MD5))
			continue;
		if (!pk11_count_digest(current_slot, CKM_SHA_1,
				&current_slot_n_digest, local_digest_nids,
				PK11_SHA1))
			continue;

		/*
		 * If the current slot supports more ciphers/digests than 
		 * the previous best one we change the current best to this one.
		 * otherwise leave it where it is.
		 */
		if (((current_slot_n_cipher > slot_n_cipher) &&
		    (current_slot_n_digest > slot_n_digest)) &&
		    ((slot_has_rsa == pk11_have_rsa) &&
		     (slot_has_dsa == pk11_have_dsa) &&
		     (slot_has_dh == pk11_have_dh)))
			{
			best_slot_sofar = current_slot;
			slot_n_cipher = current_slot_n_cipher;
			slot_n_digest = current_slot_n_digest;

			memcpy(cipher_nids, local_cipher_nids, 
				sizeof(local_cipher_nids));
			memcpy(digest_nids, local_digest_nids, 
				sizeof(local_digest_nids));
			}

		}

	if (found_candidate_slot)
		{
		cipher_count = slot_n_cipher;
		digest_count = slot_n_digest;
		SLOTID = best_slot_sofar;
		retval = 1;
		}
	else
		{
		cipher_count = 0;
		digest_count = 0;
		}

#ifdef DEBUG_SLOT_SELECTION
	fprintf(stderr,
	  "OPENSSL_PKCS#11_ENGINE: choose slot: %d\n", SLOTID);
	fprintf(stderr,
	  "OPENSSL_PKCS#11_ENGINE: pk11_have_rsa %d\n", pk11_have_rsa);
	fprintf(stderr,
	  "OPENSSL_PKCS#11_ENGINE: pk11_have_dsa %d\n", pk11_have_dsa);
	fprintf(stderr,
	  "OPENSSL_PKCS#11_ENGINE: pk11_have_dh %d\n", pk11_have_dh);
	fprintf(stderr,
	  "OPENSSL_PKCS#11_ENGINE: pk11_have_random %d\n", pk11_have_random);
#endif /* DEBUG_SLOT_SELECTION */
		
	if (pSlotList != NULL)
		OPENSSL_free(pSlotList);

	return retval;
	}

static int pk11_count_symmetric_cipher(int slot_id, CK_MECHANISM_TYPE mech,
    int *current_slot_n_cipher, int *local_cipher_nids, int id)
	{
	CK_MECHANISM_INFO mech_info;
	CK_RV rv;

	rv = pFuncList->C_GetMechanismInfo(slot_id, mech, &mech_info);

	if (rv != CKR_OK) 
		return 0;

	if ((mech_info.flags & CKF_ENCRYPT) &&
			(mech_info.flags & CKF_DECRYPT))
		{
		local_cipher_nids[(*current_slot_n_cipher)++] = ciphers[id].nid;
		}

	return 1;
	}


static int pk11_count_digest(int slot_id, CK_MECHANISM_TYPE mech,
    int *current_slot_n_digest, int *local_digest_nids, int id)
	{
	CK_MECHANISM_INFO mech_info;
	CK_RV rv;

	rv = pFuncList->C_GetMechanismInfo(slot_id, mech, &mech_info);

	if (rv != CKR_OK) 
		return 0;

	if (mech_info.flags & CKF_DIGEST)
		{
		local_digest_nids[(*current_slot_n_digest)++] = digests[id].nid;
		}

	return 1;
	}
#endif
#endif

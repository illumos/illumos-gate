/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* crypto/engine/hw_pk11_err.h */
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

#ifndef HW_PK11_ERR_H
#define HW_PK11_ERR_H

void ERR_pk11_error(int function, int reason, char *file, int line);
void PK11err_add_data(int function, int reason, CK_RV rv);
#define	PK11err(f, r)	ERR_pk11_error((f), (r), __FILE__, __LINE__)

/* Error codes for the PK11 functions. */

/* Function codes. */

#define	PK11_F_INIT 				100
#define	PK11_F_FINISH				101
#define	PK11_F_DESTROY 				102
#define	PK11_F_CTRL 				103
#define	PK11_F_RSA_INIT 			104
#define	PK11_F_RSA_FINISH 			105
#define	PK11_F_GET_PUB_RSA_KEY 			106
#define	PK11_F_GET_PRIV_RSA_KEY 		107
#define	PK11_F_RSA_GEN_KEY 			108
#define	PK11_F_RSA_PUB_ENC 			109
#define	PK11_F_RSA_PRIV_ENC 			110
#define	PK11_F_RSA_PUB_DEC 			111
#define	PK11_F_RSA_PRIV_DEC 			112
#define	PK11_F_RSA_SIGN 			113
#define	PK11_F_RSA_VERIFY 			114
#define	PK11_F_RAND_ADD 			115
#define	PK11_F_RAND_BYTES 			116
#define	PK11_F_GET_SESSION 			117
#define	PK11_F_FREE_SESSION 			118
#define	PK11_F_LOAD_PUBKEY 			119
#define	PK11_F_LOAD_PRIVKEY 			120
#define	PK11_F_RSA_PUB_ENC_LOW 			121
#define	PK11_F_RSA_PRIV_ENC_LOW 		122
#define	PK11_F_RSA_PUB_DEC_LOW 			123
#define	PK11_F_RSA_PRIV_DEC_LOW 		124
#define	PK11_F_DSA_SIGN				125
#define	PK11_F_DSA_VERIFY			126
#define	PK11_F_DSA_INIT				127
#define	PK11_F_DSA_FINISH			128
#define	PK11_F_GET_PUB_DSA_KEY 			129
#define	PK11_F_GET_PRIV_DSA_KEY 		130
#define	PK11_F_DH_INIT 				131
#define	PK11_F_DH_FINISH 			132
#define	PK11_F_MOD_EXP_DH 			133
#define	PK11_F_GET_DH_KEY 			134
#define	PK11_F_FREE_ALL_SESSIONS		135
#define	PK11_F_SETUP_SESSION			136
#define	PK11_F_DESTROY_OBJECT			137
#define	PK11_F_CIPHER_INIT			138
#define	PK11_F_CIPHER_DO_CIPHER			139
#define	PK11_F_GET_CIPHER_KEY			140
#define	PK11_F_DIGEST_INIT			141
#define	PK11_F_DIGEST_UPDATE			142
#define	PK11_F_DIGEST_FINAL			143
#define	PK11_F_CHOOSE_SLOT			144
#define	PK11_F_CIPHER_FINAL			145
#define	PK11_F_LIBRARY_INIT 			146
#define	PK11_F_LOAD 				147
#define	PK11_F_DH_GEN_KEY			148
#define	PK11_F_DH_COMP_KEY 			149
#define	PK11_F_DIGEST_COPY 			150
#define	PK11_F_CIPHER_CLEANUP			151
#define	PK11_F_ACTIVE_ADD			152
#define	PK11_F_ACTIVE_DELETE			153
#define	PK11_F_CHECK_HW_MECHANISMS		154
#define	PK11_F_INIT_SYMMETRIC			155
#define	PK11_F_ADD_AES_CTR_NIDS			156
#define	PK11_F_INIT_ALL_LOCKS			157
#define	PK11_F_RETURN_SESSION			158

/* Reason codes. */
#define	PK11_R_ALREADY_LOADED 			100
#define	PK11_R_DSO_FAILURE 			101
#define	PK11_R_NOT_LOADED 			102
#define	PK11_R_PASSED_NULL_PARAMETER 		103
#define	PK11_R_COMMAND_NOT_IMPLEMENTED 		104
#define	PK11_R_INITIALIZE 			105
#define	PK11_R_FINALIZE 			106
#define	PK11_R_GETINFO 				107
#define	PK11_R_GETSLOTLIST 			108
#define	PK11_R_NO_MODULUS_OR_NO_EXPONENT 	109
#define	PK11_R_ATTRIBUT_SENSITIVE_OR_INVALID 	110
#define	PK11_R_GETATTRIBUTVALUE 		111
#define	PK11_R_NO_MODULUS 			112
#define	PK11_R_NO_EXPONENT 			113
#define	PK11_R_FINDOBJECTSINIT 			114
#define	PK11_R_FINDOBJECTS 			115
#define	PK11_R_FINDOBJECTSFINAL 		116
#define	PK11_R_CREATEOBJECT 			118
#define	PK11_R_DESTROYOBJECT 			119
#define	PK11_R_OPENSESSION 			120
#define	PK11_R_CLOSESESSION 			121
#define	PK11_R_ENCRYPTINIT 			122
#define	PK11_R_ENCRYPT 				123
#define	PK11_R_SIGNINIT 			124
#define	PK11_R_SIGN 				125
#define	PK11_R_DECRYPTINIT 			126
#define	PK11_R_DECRYPT 				127
#define	PK11_R_VERIFYINIT 			128
#define	PK11_R_VERIFY 				129
#define	PK11_R_VERIFYRECOVERINIT 		130
#define	PK11_R_VERIFYRECOVER 			131
#define	PK11_R_GEN_KEY 				132
#define	PK11_R_SEEDRANDOM 			133
#define	PK11_R_GENERATERANDOM 			134
#define	PK11_R_INVALID_MESSAGE_LENGTH 		135
#define	PK11_R_UNKNOWN_ALGORITHM_TYPE 		136
#define	PK11_R_UNKNOWN_ASN1_OBJECT_ID 		137
#define	PK11_R_UNKNOWN_PADDING_TYPE 		138
#define	PK11_R_PADDING_CHECK_FAILED 		139
#define	PK11_R_DIGEST_TOO_BIG 			140
#define	PK11_R_MALLOC_FAILURE 			141
#define	PK11_R_CTRL_COMMAND_NOT_IMPLEMENTED 	142
#define	PK11_R_DATA_GREATER_THAN_MOD_LEN 	143
#define	PK11_R_DATA_TOO_LARGE_FOR_MODULUS 	144
#define	PK11_R_MISSING_KEY_COMPONENT		145
#define	PK11_R_INVALID_SIGNATURE_LENGTH		146
#define	PK11_R_INVALID_DSA_SIGNATURE_R		147
#define	PK11_R_INVALID_DSA_SIGNATURE_S		148
#define	PK11_R_INCONSISTENT_KEY			149
#define	PK11_R_ENCRYPTUPDATE			150
#define	PK11_R_DECRYPTUPDATE			151
#define	PK11_R_DIGESTINIT			152
#define	PK11_R_DIGESTUPDATE			153
#define	PK11_R_DIGESTFINAL			154
#define	PK11_R_ENCRYPTFINAL			155
#define	PK11_R_DECRYPTFINAL			156
#define	PK11_R_NO_PRNG_SUPPORT			157
#define	PK11_R_GETTOKENINFO			158
#define	PK11_R_DERIVEKEY			159
#define	PK11_R_GET_OPERATION_STATE		160
#define	PK11_R_SET_OPERATION_STATE		161
#define	PK11_R_INVALID_HANDLE			162
#define	PK11_R_KEY_OR_IV_LEN_PROBLEM		163
#define	PK11_R_INVALID_OPERATION_TYPE		164
#define	PK11_R_ADD_NID_FAILED			165
#define	PK11_R_ATFORK_FAILED			166

/* max byte length of a symetric key we support */
#define	PK11_KEY_LEN_MAX			32

/*
 * This structure encapsulates all reusable information for a PKCS#11
 * session. A list of these objects is created on behalf of the
 * calling application using an on-demand method. Each operation
 * type (see PK11_OPTYPE below) has its own per-process list.
 * Each of the lists is basically a cache for faster PKCS#11 object
 * access to avoid expensive C_Find{,Init,Final}Object() calls.
 *
 * When a new request comes in, an object will be taken from the list
 * (if there is one) or a new one is created to handle the request
 * (if the list is empty). See pk11_get_session() on how it is done.
 */
typedef struct PK11_st_SESSION
	{
	struct PK11_st_SESSION	*next;
	CK_SESSION_HANDLE	session;	/* PK11 session handle */
	pid_t			pid;		/* Current process ID */
	union
		{
#ifndef OPENSSL_NO_RSA
		struct
			{
			CK_OBJECT_HANDLE	rsa_pub_key; /* pub handle */
			CK_OBJECT_HANDLE	rsa_priv_key; /* priv handle */
			RSA			*rsa_pub; /* pub key addr */
			BIGNUM			*rsa_n_num; /* pub modulus */
			BIGNUM			*rsa_e_num; /* pub exponent */
			RSA			*rsa_priv; /* priv key addr */
			BIGNUM			*rsa_d_num; /* priv exponent */
			} u_RSA;
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
		struct
			{
			CK_OBJECT_HANDLE	dsa_pub_key; /* pub handle */
			CK_OBJECT_HANDLE	dsa_priv_key; /* priv handle */
			DSA			*dsa_pub; /* pub key addr */
			BIGNUM			*dsa_pub_num; /* pub key */
			DSA			*dsa_priv; /* priv key addr */
			BIGNUM			*dsa_priv_num; /* priv key */
			} u_DSA;
#endif /* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
		struct
			{
			CK_OBJECT_HANDLE	dh_key; /* key handle */
			DH			*dh; /* dh key addr */
			BIGNUM			*dh_priv_num; /* priv dh key */
			} u_DH;
#endif /* OPENSSL_NO_DH */
		struct
			{
			CK_OBJECT_HANDLE	cipher_key; /* key handle */
			unsigned char		key[PK11_KEY_LEN_MAX];
			int			key_len; /* priv key len */
			int			encrypt; /* 1/0 enc/decr */
			} u_cipher;
		} opdata_u;
	} PK11_SESSION;

#define	opdata_rsa_pub_key	opdata_u.u_RSA.rsa_pub_key
#define	opdata_rsa_priv_key	opdata_u.u_RSA.rsa_priv_key
#define	opdata_rsa_pub		opdata_u.u_RSA.rsa_pub
#define	opdata_rsa_priv		opdata_u.u_RSA.rsa_priv
#define	opdata_rsa_n_num	opdata_u.u_RSA.rsa_n_num
#define	opdata_rsa_e_num	opdata_u.u_RSA.rsa_e_num
#define	opdata_rsa_d_num	opdata_u.u_RSA.rsa_d_num
#define	opdata_dsa_pub_key	opdata_u.u_DSA.dsa_pub_key
#define	opdata_dsa_priv_key	opdata_u.u_DSA.dsa_priv_key
#define	opdata_dsa_pub		opdata_u.u_DSA.dsa_pub
#define	opdata_dsa_pub_num	opdata_u.u_DSA.dsa_pub_num
#define	opdata_dsa_priv		opdata_u.u_DSA.dsa_priv
#define	opdata_dsa_priv_num	opdata_u.u_DSA.dsa_priv_num
#define	opdata_dh_key		opdata_u.u_DH.dh_key
#define	opdata_dh		opdata_u.u_DH.dh
#define	opdata_dh_priv_num	opdata_u.u_DH.dh_priv_num
#define	opdata_cipher_key	opdata_u.u_cipher.cipher_key
#define	opdata_key		opdata_u.u_cipher.key
#define	opdata_key_len		opdata_u.u_cipher.key_len
#define	opdata_encrypt		opdata_u.u_cipher.encrypt

/*
 * We have 3 different groups of operation types:
 *   1) asymmetric operations
 *   2) random operations
 *   3) symmetric and digest operations
 *
 * This division into groups stems from the fact that it's common that hardware
 * providers may support operations from one group only. For example, hardware
 * providers on UltraSPARC T2, n2rng(7d), ncp(7d), and n2cp(7d), each support
 * only a single group of operations.
 *
 * For every group a different slot can be chosen. That means that we must have
 * at least 3 different lists of cached PKCS#11 sessions since sessions from
 * different groups may be initialized in different slots.
 *
 * To provide locking granularity in multithreaded environment, the groups are
 * further splitted into types with each type having a separate session cache.
 */
typedef enum PK11_OPTYPE_ENUM
	{
	OP_RAND,
	OP_RSA,
	OP_DSA,
	OP_DH,
	OP_CIPHER,
	OP_DIGEST,
	OP_MAX
	} PK11_OPTYPE;

/*
 * This structure contains the heads of the lists forming the object caches
 * and locks associated with the lists.
 */
typedef struct PK11_st_CACHE
	{
	PK11_SESSION *head;
	pthread_mutex_t *lock;
	} PK11_CACHE;

/* structure for tracking handles of asymmetric key objects */
typedef struct PK11_active_st
	{
	CK_OBJECT_HANDLE h;
	unsigned int refcnt;
	struct PK11_active_st *prev;
	struct PK11_active_st *next;
	} PK11_active;

extern pthread_mutex_t *find_lock[];
extern PK11_active *active_list[];

#define	LOCK_OBJSTORE(alg_type)	\
	(void) pthread_mutex_lock(find_lock[alg_type])
#define	UNLOCK_OBJSTORE(alg_type)	\
	(void) pthread_mutex_unlock(find_lock[alg_type])

extern PK11_SESSION *pk11_get_session(PK11_OPTYPE optype);
extern void pk11_return_session(PK11_SESSION *sp, PK11_OPTYPE optype);

#ifndef OPENSSL_NO_RSA
extern int pk11_destroy_rsa_key_objects(PK11_SESSION *session);
extern int pk11_destroy_rsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock);
extern int pk11_destroy_rsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock);
extern EVP_PKEY *pk11_load_privkey(ENGINE *e, const char *pubkey_file,
	UI_METHOD *ui_method, void *callback_data);
extern EVP_PKEY *pk11_load_pubkey(ENGINE *e, const char *pubkey_file,
	UI_METHOD *ui_method, void *callback_data);
extern RSA_METHOD *PK11_RSA(void);
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
extern int pk11_destroy_dsa_key_objects(PK11_SESSION *session);
extern int pk11_destroy_dsa_object_pub(PK11_SESSION *sp, CK_BBOOL uselock);
extern int pk11_destroy_dsa_object_priv(PK11_SESSION *sp, CK_BBOOL uselock);
extern DSA_METHOD *PK11_DSA(void);
#endif /* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
extern int pk11_destroy_dh_key_objects(PK11_SESSION *session);
extern int pk11_destroy_dh_object(PK11_SESSION *sp, CK_BBOOL uselock);
extern DH_METHOD *PK11_DH(void);
#endif /* OPENSSL_NO_DH */

extern CK_FUNCTION_LIST_PTR pFuncList;

#endif /* HW_PK11_ERR_H */

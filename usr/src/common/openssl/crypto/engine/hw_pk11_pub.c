/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* crypto/engine/hw_pk11_pub.c */
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

#include "security/cryptoki.h"
#include "security/pkcs11.h"
#include "hw_pk11_err.c"

/*
 * structure for tracking handles of asymmetric key objects
 *
 * Note: can be split into multiple active lists per
 *       assym cipher (RSA, DSA, DH)
 */
typedef struct PK11_active_st
	{
	CK_OBJECT_HANDLE h;
	unsigned int refcnt;
	struct PK11_active_st *prev;
	struct PK11_active_st *next;
	} PK11_active;

/*
 * list of asymmetric key handles which are active (referenced by at least
 * one PK11_SESSION structure, either held by a thread or present
 * in free_session list)
 */
static PK11_active *active_list = NULL;

#ifndef OPENSSL_NO_RSA
/* RSA stuff */
static int pk11_RSA_public_encrypt(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa, int padding);
static int pk11_RSA_private_encrypt(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa, int padding);
static int pk11_RSA_public_decrypt(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa, int padding);
static int pk11_RSA_private_decrypt(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa, int padding);
static int pk11_RSA_init(RSA *rsa);
static int pk11_RSA_finish(RSA *rsa);
static int pk11_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
static int pk11_RSA_verify(int dtype, const unsigned char *m, 
	unsigned int m_len, unsigned char *sigbuf, unsigned int siglen, 
	const RSA *rsa);
EVP_PKEY *pk11_load_privkey(ENGINE*, const char* pubkey_file,
	UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *pk11_load_pubkey(ENGINE*, const char* pubkey_file,
	UI_METHOD *ui_method, void *callback_data);

static int pk11_RSA_public_encrypt_low(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa);
static int pk11_RSA_private_encrypt_low(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa);
static int pk11_RSA_public_decrypt_low(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa);
static int pk11_RSA_private_decrypt_low(int flen, const unsigned char *from, 
	unsigned char *to, RSA *rsa);

static CK_OBJECT_HANDLE pk11_get_public_rsa_key(RSA* rsa, RSA** key_ptr,
	BIGNUM **rsa_n_num, BIGNUM **rsa_e_num, CK_SESSION_HANDLE session);
static CK_OBJECT_HANDLE pk11_get_private_rsa_key(RSA* rsa, RSA** key_ptr,
	BIGNUM **rsa_d_num, CK_SESSION_HANDLE session);

static int check_new_rsa_key_pub(PK11_SESSION *sp, const RSA *rsa);
static int check_new_rsa_key_priv(PK11_SESSION *sp, const RSA *rsa);
#endif

/* DSA stuff */
#ifndef OPENSSL_NO_DSA
static int pk11_DSA_init(DSA *dsa);
static int pk11_DSA_finish(DSA *dsa);
static DSA_SIG *pk11_dsa_do_sign(const unsigned char *dgst, int dlen, 
	DSA *dsa);
static int pk11_dsa_do_verify(const unsigned char *dgst, int dgst_len,
	DSA_SIG *sig, DSA *dsa);

static CK_OBJECT_HANDLE pk11_get_public_dsa_key(DSA* dsa, DSA **key_ptr,
	BIGNUM **dsa_pub_num, CK_SESSION_HANDLE session);
static CK_OBJECT_HANDLE pk11_get_private_dsa_key(DSA* dsa, DSA **key_ptr,
	BIGNUM **dsa_priv_num, CK_SESSION_HANDLE session);

static int check_new_dsa_key_pub(PK11_SESSION *sp, DSA *dsa);
static int check_new_dsa_key_priv(PK11_SESSION *sp, DSA *dsa);
#endif

/* DH stuff */
#ifndef OPENSSL_NO_DH
static int pk11_DH_init(DH *dh);
static int pk11_DH_finish(DH *dh);
static int pk11_DH_generate_key(DH *dh);
static int pk11_DH_compute_key(unsigned char *key,
	const BIGNUM *pub_key,DH *dh);

static CK_OBJECT_HANDLE pk11_get_dh_key(DH* dh, DH **key_ptr,
	BIGNUM **priv_key, CK_SESSION_HANDLE session);

static int check_new_dh_key(PK11_SESSION *sp, DH *dh);
#endif

static int init_template_value(BIGNUM *bn, CK_VOID_PTR *pValue,
        CK_ULONG *ulValueLen);

/*
 * Find active list entry according to object handle and return pointer
 * to the entry otherwise return NULL.
 */
static PK11_active *pk11_active_find(CK_OBJECT_HANDLE h)
	{
	PK11_active *entry;

	for (entry = active_list; entry != NULL; entry = entry->next)
		if (entry->h == h)
			return (entry);

	return (NULL);
	}

/*
 * Search for an entry in the active list using PKCS#11 object handle as a
 * search key and return refcnt of the found/created entry or -1 in case
 * of failure.
 *
 * This function presumes we are called with lock protecting the active
 * list held.
 */
int pk11_active_add(CK_OBJECT_HANDLE h)
	{
	int found = 0;
	PK11_active *entry = NULL;

	if (h == CK_INVALID_HANDLE)
		{
		PK11err(PK11_F_ACTIVE_ADD, PK11_R_INVALID_HANDLE);
		return (-1);
		}

	/* search for entry in the active list */
	if ((entry = pk11_active_find(h)) != NULL)
		entry->refcnt++;
	else
		{
		/* not found, create new entry and add it to the list */
		entry = OPENSSL_malloc(sizeof (PK11_active));
		if (entry == NULL)
			{
			PK11err(PK11_F_ACTIVE_ADD, PK11_R_MALLOC_FAILURE);
			return (-1);
			}
		entry->h = h;
		entry->refcnt = 1;
		entry->prev = NULL;
		entry->next = NULL;
		/* connect the newly created entry to the list */
		if (active_list == NULL)
			active_list = entry;
		else /* make the entry first in the list */
			{
			entry->next = active_list;
			active_list->prev = entry;
			active_list = entry;
			}
		}

	return (entry->refcnt);
	}

/*
 * Search for active list entry associated with given PKCS#11 object handle,
 * decrement its refcnt and if it drops to 0, disconnect the entry and free it.
 *
 * Return 1 if the PKCS#11 object associated with the entry has no references,
 * return 0 if there is at least one reference, -1 on error.
 *
 * This function presumes it is called with lock protecting the active
 * list held.
 */
int pk11_active_delete(CK_OBJECT_HANDLE h)
	{
	PK11_active *prev_entry = NULL;
	PK11_active *entry = NULL;

	if ((entry = pk11_active_find(h)) == NULL)
		{
		PK11err(PK11_F_ACTIVE_DELETE, PK11_R_INVALID_HANDLE);
		return (-1);
		}

	OPENSSL_assert(entry->refcnt > 0);
	entry->refcnt--;
	if (entry->refcnt == 0)
		{
		/* remove the entry from the list and free it */
		if ((prev_entry = entry->prev) != NULL)
			{
			prev_entry->next = entry->next;
			entry->next->prev = prev_entry;
			}
		else
			{
			active_list = entry->next;
			/* we are the first but not the only one */
			if (entry->next != NULL)
				entry->next->prev = NULL;
			}

		/* sanitization */
		entry->h = CK_INVALID_HANDLE;
		entry->prev = NULL;
		entry->next = NULL;
		OPENSSL_free(entry);
		return (1);
		}

	return (0);
	}

#ifndef OPENSSL_NO_RSA
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD pk11_rsa =
	{
	"PKCS#11 RSA method",
	pk11_RSA_public_encrypt,		/* rsa_pub_encrypt */
	pk11_RSA_public_decrypt,		/* rsa_pub_decrypt */
	pk11_RSA_private_encrypt,		/* rsa_priv_encrypt */
	pk11_RSA_private_decrypt,		/* rsa_priv_decrypt */
	NULL,					/* rsa_mod_exp */
	NULL,					/* bn_mod_exp */
	pk11_RSA_init,				/* init */
	pk11_RSA_finish,			/* finish */
	RSA_FLAG_SIGN_VER,			/* flags */
	NULL,					/* app_data */
	pk11_RSA_sign,				/* rsa_sign */
	pk11_RSA_verify/*,*/			/* rsa_verify */
	};

RSA_METHOD *PK11_RSA(void)
	{
	return(&pk11_rsa);
	}
#endif

#ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD pk11_dsa =
	{
	"PKCS#11 DSA method",
	pk11_dsa_do_sign, 	/* dsa_do_sign */
	NULL, 			/* dsa_sign_setup */
	pk11_dsa_do_verify, 	/* dsa_do_verify */
	NULL,			/* dsa_mod_exp */
	NULL, 			/* bn_mod_exp */
	pk11_DSA_init, 		/* init */
	pk11_DSA_finish, 	/* finish */
	0, 			/* flags */
	NULL 			/* app_data */
	};

DSA_METHOD *PK11_DSA(void)
	{
	return(&pk11_dsa);
	}
#endif

#ifndef OPENSSL_NO_DH
/*
 * PKCS #11 V2.20, section 11.2 specifies that the number of bytes needed for
 * output buffer may somewhat exceed the precise number of bytes needed, but
 * should not exceed it by a large amount. That may be caused, for example, by
 * rounding it up to multiple of X in the underlying bignum library. 8 should be
 * enough.
 */
#define	DH_BUF_RESERVE	8

/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD pk11_dh =
	{
	"PKCS#11 DH method",
	pk11_DH_generate_key,	/* generate_key */
	pk11_DH_compute_key,	/* compute_key */
	NULL,			/* bn_mod_exp */
	pk11_DH_init,		/* init */
	pk11_DH_finish,		/* finish */
	0,			/* flags */
	NULL			/* app_data */
	};

DH_METHOD *PK11_DH(void)
	{
	return(&pk11_dh);
	}
#endif

/* Size of an SSL signature: MD5+SHA1
 */
#define SSL_SIG_LENGTH          36

/* Lengths of DSA data and signature
 */
#define DSA_DATA_LEN            20
#define DSA_SIGNATURE_LEN       40

static CK_BBOOL true = TRUE;
static CK_BBOOL false = FALSE;

#ifndef OPENSSL_NO_RSA
/* Similiar to Openssl to take advantage of the paddings. The goal is to
 * support all paddings in this engine although PK11 library does not 
 * support all the paddings used in OpenSSL. 
 * The input errors should have been checked in the padding functions
 */
static int pk11_RSA_public_encrypt(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
	{
	int i,num=0,r= -1;
	unsigned char *buf=NULL;

	num=BN_num_bytes(rsa->n);
	if ((buf=(unsigned char *)OPENSSL_malloc(num)) == NULL)
		{
		RSAerr(PK11_F_RSA_PUB_ENC,PK11_R_MALLOC_FAILURE);
		goto err;
		}

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		i=RSA_padding_add_PKCS1_type_2(buf,num,from,flen);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		i=RSA_padding_add_PKCS1_OAEP(buf,num,from,flen,NULL,0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		i=RSA_padding_add_SSLv23(buf,num,from,flen);
		break;
	case RSA_NO_PADDING:
		i=RSA_padding_add_none(buf,num,from,flen);
		break;
	default:
		RSAerr(PK11_F_RSA_PUB_ENC,PK11_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (i <= 0) goto err;

	/* PK11 functions are called here */
	r = pk11_RSA_public_encrypt_low(num, buf, to, rsa);
err:
	if (buf != NULL) 
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}


/* Similar to Openssl to take advantage of the paddings. The input errors
 * should be catched in the padding functions
 */
static int pk11_RSA_private_encrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	int i,num=0,r= -1;
	unsigned char *buf=NULL;

	num=BN_num_bytes(rsa->n);
	if ((buf=(unsigned char *)OPENSSL_malloc(num)) == NULL)
		{
		RSAerr(PK11_F_RSA_PRIV_ENC,PK11_R_MALLOC_FAILURE);
		goto err;
		}

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		i=RSA_padding_add_PKCS1_type_1(buf,num,from,flen);
		break;
	case RSA_NO_PADDING:
		i=RSA_padding_add_none(buf,num,from,flen);
		break;
	case RSA_SSLV23_PADDING:
	default:
		RSAerr(PK11_F_RSA_PRIV_ENC,PK11_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (i <= 0) goto err;

	/* PK11 functions are called here */
	r=pk11_RSA_private_encrypt_low(num, buf, to, rsa);
err:
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

/* Similar to Openssl. Input errors are also checked here
 */
static int pk11_RSA_private_decrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM f;
	int j,num=0,r= -1;
	unsigned char *p;
	unsigned char *buf=NULL;

	BN_init(&f);

	num=BN_num_bytes(rsa->n);

	if ((buf=(unsigned char *)OPENSSL_malloc(num)) == NULL)
		{
		RSAerr(PK11_F_RSA_PRIV_DEC,PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
		{
		RSAerr(PK11_F_RSA_PRIV_DEC,
			PK11_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
		}

	/* make data into a big number */
	if (BN_bin2bn(from,(int)flen,&f) == NULL) goto err;

	if (BN_ucmp(&f, rsa->n) >= 0)
		{
		RSAerr(PK11_F_RSA_PRIV_DEC,
			PK11_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	/* PK11 functions are called here */
	r = pk11_RSA_private_decrypt_low(flen, from, buf, rsa);

	/* PK11 CKM_RSA_X_509 mechanism pads 0's at the beginning.
	 * Needs to skip these 0's paddings here */
	for (j = 0; j < r; j++)
		if (buf[j] != 0)
			break;

	p = buf + j;
	j = r - j;  /* j is only used with no-padding mode */

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		r=RSA_padding_check_PKCS1_type_2(to,num,p,j,num);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		r=RSA_padding_check_PKCS1_OAEP(to,num,p,j,num,NULL,0);
		break;
#endif
 	case RSA_SSLV23_PADDING:
		r=RSA_padding_check_SSLv23(to,num,p,j,num);
		break;
	case RSA_NO_PADDING:
		r=RSA_padding_check_none(to,num,p,j,num);
		break;
	default:
		RSAerr(PK11_F_RSA_PRIV_DEC,PK11_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (r < 0)
		RSAerr(PK11_F_RSA_PRIV_DEC,PK11_R_PADDING_CHECK_FAILED);

err:
	BN_clear_free(&f);
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

/* Similar to Openssl. Input errors are also checked here
 */
static int pk11_RSA_public_decrypt(int flen, const unsigned char *from,
	     unsigned char *to, RSA *rsa, int padding)
	{
	BIGNUM f;
	int i,num=0,r= -1;
	unsigned char *p;
	unsigned char *buf=NULL;

	BN_init(&f);
	num=BN_num_bytes(rsa->n);
	buf=(unsigned char *)OPENSSL_malloc(num);
	if (buf == NULL)
		{
		RSAerr(PK11_F_RSA_PUB_DEC,PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
		{
		RSAerr(PK11_F_RSA_PUB_DEC,PK11_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
		}

	if (BN_bin2bn(from,flen,&f) == NULL) goto err;

	if (BN_ucmp(&f, rsa->n) >= 0)
		{
		RSAerr(PK11_F_RSA_PUB_DEC,
			PK11_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
		}

	/* PK11 functions are called here */
	r = pk11_RSA_public_decrypt_low(flen, from, buf, rsa);

	/* PK11 CKM_RSA_X_509 mechanism pads 0's at the beginning.
	 * Needs to skip these 0's here */
	for (i = 0; i < r; i++)
		if (buf[i] != 0)
			break;

	p = buf + i;
	i = r - i;  /* i is only used with no-padding mode */

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		r=RSA_padding_check_PKCS1_type_1(to,num,p,i,num);
		break;
	case RSA_NO_PADDING:
		r=RSA_padding_check_none(to,num,p,i,num);
		break;
	default:
		RSAerr(PK11_F_RSA_PUB_DEC,PK11_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	if (r < 0)
		RSAerr(PK11_F_RSA_PUB_DEC,PK11_R_PADDING_CHECK_FAILED);

err:
	BN_clear_free(&f);
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,num);
		OPENSSL_free(buf);
		}
	return(r);
	}

/* This function implements RSA public encryption using C_EncryptInit and
 * C_Encrypt pk11 interfaces. Note that the CKM_RSA_X_509 is used here.
 * The calling function allocated sufficient memory in "to" to store results.
 */
static int pk11_RSA_public_encrypt_low(int flen,
	const unsigned char *from, unsigned char *to, RSA *rsa)
	{
	CK_ULONG bytes_encrypted=flen;
	int retval = -1;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_X_509, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_pub_key = CK_INVALID_HANDLE;
	PK11_SESSION *sp;
	char tmp_buf[20];
	
	if ((sp = pk11_get_session()) == NULL)
		return -1;

	(void) check_new_rsa_key_pub(sp, rsa);
	
	h_pub_key = sp->rsa_pub_key;
	if (h_pub_key == CK_INVALID_HANDLE)
		h_pub_key = sp->rsa_pub_key =
			pk11_get_public_rsa_key(rsa, &sp->rsa_pub,
			    &sp->rsa_n_num, &sp->rsa_e_num, sp->session);

	if (h_pub_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_EncryptInit(sp->session, p_mech, 
			h_pub_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PUB_ENC_LOW, 
				PK11_R_ENCRYPTINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
	
		rv = pFuncList->C_Encrypt(sp->session, 
			(unsigned char *)from, flen, to, &bytes_encrypted);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PUB_ENC_LOW, PK11_R_ENCRYPT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
		retval = bytes_encrypted;
		}
	
	pk11_return_session(sp);
	return retval;
	}


/* This function implements RSA private encryption using C_SignInit and 
 * C_Sign pk11 APIs. Note that CKM_RSA_X_509 is used here.
 * The calling function allocated sufficient memory in "to" to store results.
 */
static int pk11_RSA_private_encrypt_low(int flen,
	const unsigned char *from, unsigned char *to, RSA *rsa)
	{
	CK_ULONG ul_sig_len=flen;
	int retval = -1;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_X_509, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_priv_key= CK_INVALID_HANDLE;
	PK11_SESSION *sp;
	char tmp_buf[20];
	
	if ((sp = pk11_get_session()) == NULL)
		return -1;
	
	(void) check_new_rsa_key_priv(sp, rsa);
	
	h_priv_key = sp->rsa_priv_key;
	if (h_priv_key == CK_INVALID_HANDLE)
		h_priv_key = sp->rsa_priv_key =
			pk11_get_private_rsa_key(rsa, &sp->rsa_priv,
			    &sp->rsa_d_num, sp->session);
	
	if (h_priv_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_SignInit(sp->session, p_mech, 
			h_priv_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PRIV_ENC_LOW, PK11_R_SIGNINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
	
		rv = pFuncList->C_Sign(sp->session, 
			(unsigned char *)from, flen, to, &ul_sig_len);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PRIV_ENC_LOW, PK11_R_SIGN);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}

		retval = ul_sig_len;
		}
	
	pk11_return_session(sp);
	return retval;
	}


/* This function implements RSA private decryption using C_DecryptInit and
 * C_Decrypt pk11 APIs. Note that CKM_RSA_X_509 mechanism is used here.
 * The calling function allocated sufficient memory in "to" to store results.
 */
static int pk11_RSA_private_decrypt_low(int flen,
	const unsigned char *from, unsigned char *to, RSA *rsa)
	{
	CK_ULONG bytes_decrypted = flen;
	int retval = -1;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_X_509, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_priv_key;
	PK11_SESSION *sp;
	char tmp_buf[20];
	
	if ((sp = pk11_get_session()) == NULL)
		return -1;
	
	(void) check_new_rsa_key_priv(sp, rsa);
	
	h_priv_key = sp->rsa_priv_key;
	if (h_priv_key == CK_INVALID_HANDLE)
		h_priv_key = sp->rsa_priv_key =
			pk11_get_private_rsa_key(rsa, &sp->rsa_priv,
			    &sp->rsa_d_num, sp->session);

	if (h_priv_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_DecryptInit(sp->session, p_mech, 
			h_priv_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PRIV_DEC_LOW, 
				PK11_R_DECRYPTINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
	
		rv = pFuncList->C_Decrypt(sp->session, 
			(unsigned char *)from, flen, to, &bytes_decrypted);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PRIV_DEC_LOW, PK11_R_DECRYPT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
		retval = bytes_decrypted;
		}

	pk11_return_session(sp);
	return retval;
	}


/* This function implements RSA public decryption using C_VerifyRecoverInit 
 * and C_VerifyRecover pk11 APIs. Note that CKM_RSA_X_509 is used here.
 * The calling function allocated sufficient memory in "to" to store results.
 */
static int pk11_RSA_public_decrypt_low(int flen,
	const unsigned char *from, unsigned char *to, RSA *rsa)
	{
	CK_ULONG bytes_decrypted = flen;
	int retval = -1;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_X_509, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_pub_key = CK_INVALID_HANDLE;
	PK11_SESSION *sp;
	char tmp_buf[20];
	
	if ((sp = pk11_get_session()) == NULL)
		return -1;
	
	(void) check_new_rsa_key_pub(sp, rsa);
	
	h_pub_key = sp->rsa_pub_key;
	if (h_pub_key == CK_INVALID_HANDLE)
		h_pub_key = sp->rsa_pub_key =
			pk11_get_public_rsa_key(rsa, &sp->rsa_pub,
			    &sp->rsa_n_num, &sp->rsa_e_num, sp->session);

	if (h_pub_key != CK_INVALID_HANDLE)
		{	
		rv = pFuncList->C_VerifyRecoverInit(sp->session, 
			p_mech, h_pub_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PUB_DEC_LOW, 
				PK11_R_VERIFYRECOVERINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
	
		rv = pFuncList->C_VerifyRecover(sp->session, 
			(unsigned char *)from, flen, to, &bytes_decrypted);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_PUB_DEC_LOW, 
				PK11_R_VERIFYRECOVER);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			pk11_return_session(sp);
			return -1;
			}
		retval = bytes_decrypted;
		}

	pk11_return_session(sp);
	return retval;
	}

static int pk11_RSA_init(RSA *rsa)
	{
	/* This flag in the RSA_METHOD enables the new rsa_sign, 
	 * rsa_verify functions. See rsa.h for details. */
	rsa->flags |= RSA_FLAG_SIGN_VER;

	return 1;
	}

static int pk11_RSA_finish(RSA *rsa)
	{
	/*
	 * Since we are overloading OpenSSL's native RSA_eay_finish() we need
	 * to do the same as in the original function, i.e. to free bignum
	 * structures.
	 */
	if (rsa->_method_mod_n != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_n);
	if (rsa->_method_mod_p != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_p);
	if (rsa->_method_mod_q != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_q);

	return (1);
	}

/* Standard engine interface function. Majority codes here are from 
 * rsa/rsa_sign.c. We replaced the decrypt function call by C_Sign of PKCS#11.
 * See more details in rsa/rsa_sign.c */
static int pk11_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
	{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j;
	unsigned char *p,*s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_priv_key;
	PK11_SESSION *sp = NULL;
	int ret = 0;
	char tmp_buf[20];
	unsigned long ulsiglen;

	/* Encode the digest */
	/* Special case: SSL signature, just check the length */
	if (type == NID_md5_sha1)
		{
		if (m_len != SSL_SIG_LENGTH)
			{
			PK11err(PK11_F_RSA_SIGN, 
				PK11_R_INVALID_MESSAGE_LENGTH);
			goto err;
			}
		i = SSL_SIG_LENGTH;
		s = (unsigned char *)m;
		}
	else
		{
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
			{
			PK11err(PK11_F_RSA_SIGN, 
				PK11_R_UNKNOWN_ALGORITHM_TYPE);
			goto err;
			}
		if (sig.algor->algorithm->length == 0)
			{
			PK11err(PK11_F_RSA_SIGN, 
				PK11_R_UNKNOWN_ASN1_OBJECT_ID);
			goto err;
			}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;
	
		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m;
		sig.digest->length=m_len;
	
		i=i2d_X509_SIG(&sig,NULL);
		}
	
	j=RSA_size(rsa);
	if ((i-RSA_PKCS1_PADDING) > j)
		{
		PK11err(PK11_F_RSA_SIGN, PK11_R_DIGEST_TOO_BIG);
		goto err;
		}
	
	if (type != NID_md5_sha1)
		{
		s=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (s == NULL)
			{
			PK11err(PK11_F_RSA_SIGN, PK11_R_MALLOC_FAILURE);
			goto err;
			}
		p=s;
		i2d_X509_SIG(&sig,&p);
		}
	
	if ((sp = pk11_get_session()) == NULL)
		goto err;

	(void) check_new_rsa_key_priv(sp, rsa);
	
	h_priv_key = sp->rsa_priv_key;
	if (h_priv_key == CK_INVALID_HANDLE)
		h_priv_key = sp->rsa_priv_key =
			pk11_get_private_rsa_key((RSA *)rsa, &sp->rsa_priv,
			    &sp->rsa_d_num, sp->session);

	if (h_priv_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_SignInit(sp->session, p_mech, h_priv_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_SIGN, PK11_R_SIGNINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto err;
			}

		ulsiglen = j;
		rv = pFuncList->C_Sign(sp->session, s, i, sigret, 
			(CK_ULONG_PTR) &ulsiglen);
		*siglen = ulsiglen;

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_SIGN, PK11_R_SIGN);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto err;
			}
		ret = 1;
		}

err:
	if (type != NID_md5_sha1)
		{
		memset(s,0,(unsigned int)j+1);
		OPENSSL_free(s);
		}
	
	pk11_return_session(sp);
	return ret;
	}

static int pk11_RSA_verify(int type, const unsigned char *m,
	unsigned int m_len, unsigned char *sigbuf, unsigned int siglen,
	const RSA *rsa)
	{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j;
	unsigned char *p,*s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	CK_RV rv;
	CK_MECHANISM mech_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *p_mech = &mech_rsa;
	CK_OBJECT_HANDLE h_pub_key;
	PK11_SESSION *sp = NULL;
	int ret = 0;
	char tmp_buf[20];

	/* Encode the digest	*/
	/* Special case: SSL signature, just check the length */
	if (type == NID_md5_sha1)
		{
		if (m_len != SSL_SIG_LENGTH)
			{
			PK11err(PK11_F_RSA_VERIFY, 
				PK11_R_INVALID_MESSAGE_LENGTH);
			goto err;
			}
		i = SSL_SIG_LENGTH;
		s = (unsigned char *)m;
		}
	else
		{
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
			{
			PK11err(PK11_F_RSA_VERIFY, 
				PK11_R_UNKNOWN_ALGORITHM_TYPE);
			goto err;
			}
		if (sig.algor->algorithm->length == 0)
			{
			PK11err(PK11_F_RSA_VERIFY, 
				PK11_R_UNKNOWN_ASN1_OBJECT_ID);
			goto err;
			}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;
		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m;
		sig.digest->length=m_len;
		i=i2d_X509_SIG(&sig,NULL);
		}
	
	j=RSA_size(rsa);
	if ((i-RSA_PKCS1_PADDING) > j)
		{
		PK11err(PK11_F_RSA_VERIFY, PK11_R_DIGEST_TOO_BIG);
		goto err;
		}
	
	if (type != NID_md5_sha1)
		{
		s=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (s == NULL)
			{
			PK11err(PK11_F_RSA_VERIFY, PK11_R_MALLOC_FAILURE);
			goto err;
			}
		p=s;
		i2d_X509_SIG(&sig,&p);
		}
	
	if ((sp = pk11_get_session()) == NULL)
		goto err;
	
	(void) check_new_rsa_key_pub(sp, rsa);
	
	h_pub_key = sp->rsa_pub_key;
	if (h_pub_key == CK_INVALID_HANDLE)
		h_pub_key = sp->rsa_pub_key =
			pk11_get_public_rsa_key((RSA *)rsa, &sp->rsa_pub,
			    &sp->rsa_n_num, &sp->rsa_e_num, sp->session);

	if (h_pub_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_VerifyInit(sp->session, p_mech, 
			h_pub_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_VERIFY, PK11_R_VERIFYINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto err;
			}
		rv = pFuncList->C_Verify(sp->session, s, i, sigbuf, 
			(CK_ULONG)siglen);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_RSA_VERIFY, PK11_R_VERIFY);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto err;
			}
		ret = 1;
		}

err:
	if (type != NID_md5_sha1)
		{
		memset(s,0,(unsigned int)siglen);
		OPENSSL_free(s);
		}

	pk11_return_session(sp);
	return ret;
	}

/* load RSA private key from a file */
EVP_PKEY *pk11_load_privkey(ENGINE* e, const char* privkey_file,
	UI_METHOD *ui_method, void *callback_data)
	{
	EVP_PKEY *pkey=NULL;
	FILE *pubkey;
	CK_OBJECT_HANDLE  h_priv_key = CK_INVALID_HANDLE;
	RSA *rsa;
	PK11_SESSION *sp;

	if ((sp = pk11_get_session()) == NULL)
		return NULL;

	if ((pubkey=fopen(privkey_file,"r")) != NULL)
		{
		pkey = PEM_read_PrivateKey(pubkey, NULL, NULL, NULL);
		fclose(pubkey);
		if (pkey != NULL)
			{
			rsa = EVP_PKEY_get1_RSA(pkey);
			if (rsa != NULL)
				{
				(void) check_new_rsa_key_priv(sp, rsa);
	
				h_priv_key = sp->rsa_priv_key =
				    pk11_get_private_rsa_key(rsa,
				    &sp->rsa_priv, &sp->rsa_d_num, sp->session);
				if (h_priv_key == CK_INVALID_HANDLE)
					{
					EVP_PKEY_free(pkey);
					pkey = NULL;
					}
				}
			else
				{
				EVP_PKEY_free(pkey);
				pkey = NULL;
				}
			}
		}

	pk11_return_session(sp);
	return(pkey);
	}

/* load RSA public key from a file */
EVP_PKEY *pk11_load_pubkey(ENGINE* e, const char* pubkey_file,
	UI_METHOD *ui_method, void *callback_data)
	{
	EVP_PKEY *pkey=NULL;
	FILE *pubkey;
	CK_OBJECT_HANDLE  h_pub_key = CK_INVALID_HANDLE;
	RSA *rsa;
	PK11_SESSION *sp;

	if ((sp = pk11_get_session()) == NULL)
		return NULL;

	if ((pubkey=fopen(pubkey_file,"r")) != NULL)
		{
		pkey = PEM_read_PUBKEY(pubkey, NULL, NULL, NULL);
		fclose(pubkey);
		if (pkey != NULL)
			{
			rsa = EVP_PKEY_get1_RSA(pkey);
			if (rsa != NULL)
				{
				(void) check_new_rsa_key_pub(sp, rsa);
	
				h_pub_key = sp->rsa_pub_key =
				    pk11_get_public_rsa_key(rsa,
				    &sp->rsa_pub, &sp->rsa_n_num,
				    &sp->rsa_e_num, sp->session);
				if (h_pub_key == CK_INVALID_HANDLE)
					{
					EVP_PKEY_free(pkey);
					pkey = NULL;
					}
				}
			else
				{
				EVP_PKEY_free(pkey);
				pkey = NULL;
				}
			}
		}

	pk11_return_session(sp);
	return(pkey);
	}

/* Create a public key object in a session from a given rsa structure.
 */
static CK_OBJECT_HANDLE pk11_get_public_rsa_key(RSA* rsa,
    RSA** key_ptr, BIGNUM **rsa_n_num, BIGNUM **rsa_e_num,
    CK_SESSION_HANDLE session)
	{
	CK_RV rv;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	CK_ULONG found;
	CK_OBJECT_CLASS o_key = CKO_PUBLIC_KEY;
	CK_KEY_TYPE k_type = CKK_RSA;
	CK_ULONG ul_key_attr_count = 7;
	char tmp_buf[20];

	CK_ATTRIBUTE  a_key_template[] =
		{
		{CKA_CLASS, (void *) NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, (void *) NULL, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &false, sizeof(true)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_VERIFY_RECOVER, &true, sizeof(true)},
		{CKA_MODULUS, (void *)NULL, 0},
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0}
		};

	int i;

	a_key_template[0].pValue = &o_key;
	a_key_template[1].pValue = &k_type;

	a_key_template[5].ulValueLen = BN_num_bytes(rsa->n);
	a_key_template[5].pValue = (CK_VOID_PTR)OPENSSL_malloc(
		(size_t)a_key_template[5].ulValueLen);
	if (a_key_template[5].pValue == NULL)
		{
		PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	BN_bn2bin(rsa->n, a_key_template[5].pValue);

	a_key_template[6].ulValueLen = BN_num_bytes(rsa->e);
	a_key_template[6].pValue = (CK_VOID_PTR)OPENSSL_malloc(
		(size_t)a_key_template[6].ulValueLen);
	if (a_key_template[6].pValue == NULL)
		{
		PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	BN_bn2bin(rsa->e, a_key_template[6].pValue);

	/*
	 * As stated in v2.20, 11.7 Object Management Function, in section for
	 * C_FindObjectsInit(), at most one search operation may be active at
	 * a given time in a given session. Therefore, we must group these
	 * three calls in one atomic operation.
	 */
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	rv = pFuncList->C_FindObjectsInit(session, a_key_template, 
		ul_key_attr_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_FINDOBJECTSINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjects(session, &h_key, 1, &found);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_FINDOBJECTS);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjectsFinal(session);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_FINDOBJECTSFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	if (found == 0)
		{
		rv = pFuncList->C_CreateObject(session, 
			a_key_template, ul_key_attr_count, &h_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_PUB_RSA_KEY, 
				PK11_R_CREATEOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
		}

	(void) pk11_active_add(h_key);
	if (key_ptr != NULL)
		*key_ptr = rsa;
	if (rsa_n_num != NULL)
		if ((*rsa_n_num = BN_dup(rsa->n)) == NULL)
			{
			PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	if (rsa_e_num != NULL)
		if ((*rsa_e_num = BN_dup(rsa->e)) == NULL)
			{
			PK11err(PK11_F_GET_PUB_RSA_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

err:
	for (i = 5; i <= 6; i++)
		{
		if (a_key_template[i].pValue != NULL)
			{
			OPENSSL_free(a_key_template[i].pValue);
			a_key_template[i].pValue = NULL;
			}
		}

	return h_key;
	}

/* Create a private key object in the session from a given rsa structure
 */
static CK_OBJECT_HANDLE pk11_get_private_rsa_key(RSA* rsa,
    RSA** key_ptr, BIGNUM **rsa_d_num, CK_SESSION_HANDLE session)
	{
	CK_RV rv;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	int i;
	CK_ULONG found;
	CK_OBJECT_CLASS o_key = CKO_PRIVATE_KEY;
	CK_KEY_TYPE k_type = CKK_RSA;
	CK_ULONG ul_key_attr_count = 14;
	char tmp_buf[20];

	/* Both CKA_TOKEN and CKA_SENSITIVE have to be FALSE for session keys
	 */
	CK_ATTRIBUTE  a_key_template[] =
		{
		{CKA_CLASS, (void *) NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, (void *) NULL, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &false, sizeof(true)},
		{CKA_SENSITIVE, &false, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)},
		{CKA_SIGN, &true, sizeof(true)},
		{CKA_MODULUS, (void *)NULL, 0},
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0},
		{CKA_PRIVATE_EXPONENT, (void *)NULL, 0},
		{CKA_PRIME_1, (void *)NULL, 0},
		{CKA_PRIME_2, (void *)NULL, 0},
		{CKA_EXPONENT_1, (void *)NULL, 0},
		{CKA_EXPONENT_2, (void *)NULL, 0},
		{CKA_COEFFICIENT, (void *)NULL, 0}
		};

	a_key_template[0].pValue = &o_key;
	a_key_template[1].pValue = &k_type;

	/* Put the private key components into the template */
	if (init_template_value(rsa->n, &a_key_template[6].pValue,
		&a_key_template[6].ulValueLen) == 0 ||
	    init_template_value(rsa->e, &a_key_template[7].pValue,
		&a_key_template[7].ulValueLen) == 0 ||
	    init_template_value(rsa->d, &a_key_template[8].pValue,
		&a_key_template[8].ulValueLen) == 0 ||
	    init_template_value(rsa->p, &a_key_template[9].pValue,
		&a_key_template[9].ulValueLen) == 0 ||
	    init_template_value(rsa->q, &a_key_template[10].pValue,
		&a_key_template[10].ulValueLen) == 0 ||
	    init_template_value(rsa->dmp1, &a_key_template[11].pValue,
		&a_key_template[11].ulValueLen) == 0 ||
	    init_template_value(rsa->dmq1, &a_key_template[12].pValue,
		&a_key_template[12].ulValueLen) == 0 ||
	    init_template_value(rsa->iqmp, &a_key_template[13].pValue,
		&a_key_template[13].ulValueLen) == 0)
		{
		PK11err(PK11_F_GET_PRIV_RSA_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/*
	 * As stated in v2.20, 11.7 Object Management Function, in section for
	 * C_FindObjectsInit(), at most one search operation may be active at
	 * a given time in a given session. Therefore, we must group these
	 * three calls in one atomic operation.
	 */
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	rv = pFuncList->C_FindObjectsInit(session, a_key_template, 
		ul_key_attr_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_RSA_KEY, PK11_R_FINDOBJECTSINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjects(session, &h_key, 1, &found);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_RSA_KEY, PK11_R_FINDOBJECTS);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjectsFinal(session);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_RSA_KEY, PK11_R_FINDOBJECTSFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	if (found == 0)
		{
		rv = pFuncList->C_CreateObject(session, 
			a_key_template, ul_key_attr_count, &h_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_PRIV_RSA_KEY, 
				PK11_R_CREATEOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
		}

	(void) pk11_active_add(h_key);
	if (key_ptr != NULL)
		*key_ptr = rsa;
	if (rsa_d_num != NULL)
		if ((*rsa_d_num = BN_dup(rsa->d)) == NULL)
			{
			PK11err(PK11_F_GET_PRIV_RSA_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

err:
	/* 6 to 13 entries in the key template are key components
	 * They need to be freed apon exit or error.
	 */
	for (i = 6; i <= 13; i++)
		{
		if (a_key_template[i].pValue != NULL)
			{
			memset(a_key_template[i].pValue, 0, 
				a_key_template[i].ulValueLen);
			OPENSSL_free(a_key_template[i].pValue);
			a_key_template[i].pValue = NULL;
			}
		}

	return h_key;
	}

/*
 * Check for cache miss and clean the object pointer and handle
 * in such case. Return 1 for cache hit, 0 for cache miss.
 */
static int check_new_rsa_key_pub(PK11_SESSION *sp, const RSA *rsa)
	{
	/*
	 * Provide protection against RSA structure reuse by making the
	 * check for cache hit stronger. Only public components of RSA
	 * key matter here so it is sufficient to compare them with values
	 * cached in PK11_SESSION structure.
	 */
	if ((sp->rsa_pub != rsa) ||
	    (BN_cmp(sp->rsa_n_num, rsa->n) != 0) ||
	    (BN_cmp(sp->rsa_e_num, rsa->e) != 0))
		{
		/*
		 * We do not check the return value because even in case of
		 * failure the sp structure will have both key pointer
		 * and object handle cleaned and pk11_destroy_object()
		 * reports the failure to the OpenSSL error message buffer.
		 */
		(void) pk11_destroy_rsa_object_pub(sp, TRUE);
		return (0);
		}
	return (1);
	}

/*
 * Check for cache miss and clean the object pointer and handle
 * in such case. Return 1 for cache hit, 0 for cache miss.
 */
static int check_new_rsa_key_priv(PK11_SESSION *sp, const RSA *rsa)
	{
	/*
	 * Provide protection against RSA structure reuse by making the
	 * check for cache hit stronger. Comparing private exponent of RSA
	 * key with value cached in PK11_SESSION structure should
	 * be sufficient.
	 */
	if ((sp->rsa_priv != rsa) ||
	    (BN_cmp(sp->rsa_d_num, rsa->d) != 0))
		{
		/*
		 * We do not check the return value because even in case of
		 * failure the sp structure will have both key pointer
		 * and object handle cleaned and pk11_destroy_object()
		 * reports the failure to the OpenSSL error message buffer.
		 */
		(void) pk11_destroy_rsa_object_priv(sp, TRUE);
		return (0);
		}
	return (1);
	}
#endif

#ifndef OPENSSL_NO_DSA
/* The DSA function implementation
 */
static int pk11_DSA_init(DSA *dsa)
	{
	return 1;
	}


static int pk11_DSA_finish(DSA *dsa)
	{
	return (1);
	}


static DSA_SIG *
pk11_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
	{
	BIGNUM *r = NULL, *s = NULL;
	int i;
	DSA_SIG *dsa_sig = NULL;

	CK_RV rv;
	CK_MECHANISM Mechanism_dsa = {CKM_DSA, NULL, 0};
	CK_MECHANISM *p_mech = &Mechanism_dsa;
	CK_OBJECT_HANDLE h_priv_key;

	/* The signature is the concatenation of r and s, 
	 * each is 20 bytes long
	 */
	unsigned char sigret[DSA_SIGNATURE_LEN];
	unsigned long siglen = DSA_SIGNATURE_LEN;
	unsigned int siglen2 = DSA_SIGNATURE_LEN / 2;

	PK11_SESSION *sp = NULL;
	char tmp_buf[20];

	if ((dsa->p == NULL) || (dsa->q == NULL) || (dsa->g == NULL)) 
		{
		PK11err(PK11_F_DSA_SIGN, PK11_R_MISSING_KEY_COMPONENT);
		goto ret;
		}

	i=BN_num_bytes(dsa->q); /* should be 20 */
	if (dlen > i)
		{
		PK11err(PK11_F_DSA_SIGN, PK11_R_INVALID_SIGNATURE_LENGTH);
		goto ret;
		}

	if ((sp = pk11_get_session()) == NULL)
		goto ret;

	(void) check_new_dsa_key_priv(sp, dsa);

	h_priv_key = sp->dsa_priv_key;
	if (h_priv_key == CK_INVALID_HANDLE)
		h_priv_key = sp->dsa_priv_key =
			pk11_get_private_dsa_key((DSA *)dsa, &sp->dsa_priv,
			    &sp->dsa_priv_num, sp->session);

	if (h_priv_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_SignInit(sp->session, p_mech, h_priv_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DSA_SIGN, PK11_R_SIGNINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto ret;
			}

		memset(sigret, 0, siglen);
		rv = pFuncList->C_Sign(sp->session, 
			(unsigned char*) dgst, dlen, sigret, 
			(CK_ULONG_PTR) &siglen);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DSA_SIGN, PK11_R_SIGN);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto ret;
			}
		}


	if ((s = BN_new()) == NULL)
		{
		PK11err(PK11_F_DSA_SIGN, PK11_R_MALLOC_FAILURE);
		goto ret;
		}

	if ((r = BN_new()) == NULL)
		{
		PK11err(PK11_F_DSA_SIGN, PK11_R_MALLOC_FAILURE);
		goto ret;
		}

	if ((dsa_sig = DSA_SIG_new()) == NULL)
		{
		PK11err(PK11_F_DSA_SIGN, PK11_R_MALLOC_FAILURE);
		goto ret;
		}

	BN_bin2bn(sigret, siglen2, r);
	BN_bin2bn(&sigret[siglen2], siglen2, s);

	dsa_sig->r = r;
	dsa_sig->s = s;

ret:
	if (dsa_sig == NULL) 
		{
		if (r != NULL)
			BN_free(r);
		if (s != NULL)
			BN_free(s);
		}

	pk11_return_session(sp);
	return (dsa_sig);
	}

static int
pk11_dsa_do_verify(const unsigned char *dgst, int dlen, DSA_SIG *sig,
	DSA *dsa)
	{
	int i;
	CK_RV rv;
	int retval = 0;
	CK_MECHANISM Mechanism_dsa = {CKM_DSA, NULL, 0};
	CK_MECHANISM *p_mech = &Mechanism_dsa;
	CK_OBJECT_HANDLE h_pub_key;

	unsigned char sigbuf[DSA_SIGNATURE_LEN];
	unsigned long siglen = DSA_SIGNATURE_LEN;
	unsigned long siglen2 = DSA_SIGNATURE_LEN/2;

	PK11_SESSION *sp = NULL;
	char tmp_buf[20];

	if (BN_is_zero(sig->r) || sig->r->neg || BN_ucmp(sig->r, dsa->q) >= 0)
		{
		PK11err(PK11_F_DSA_VERIFY, 
			PK11_R_INVALID_DSA_SIGNATURE_R);
		goto ret;
		}

	if (BN_is_zero(sig->s) || sig->s->neg || BN_ucmp(sig->s, dsa->q) >= 0) 
		{
		PK11err(PK11_F_DSA_VERIFY, 
			PK11_R_INVALID_DSA_SIGNATURE_S);
		goto ret;
		}

	i = BN_num_bytes(dsa->q); /* should be 20 */

	if (dlen > i)
		{
		PK11err(PK11_F_DSA_VERIFY, 
			PK11_R_INVALID_SIGNATURE_LENGTH);
		goto ret;
		}

	if ((sp = pk11_get_session()) == NULL)
		goto ret;
	
	(void) check_new_dsa_key_pub(sp, dsa);

	h_pub_key = sp->dsa_pub_key;
	if (h_pub_key == CK_INVALID_HANDLE)
		h_pub_key = sp->dsa_pub_key =
			pk11_get_public_dsa_key((DSA *)dsa, &sp->dsa_pub,
			    &sp->dsa_pub_num, sp->session);

	if (h_pub_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_VerifyInit(sp->session, p_mech, 
			h_pub_key);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DSA_VERIFY, PK11_R_VERIFYINIT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto ret;
			}

		/*
		 * The representation of each of the two big numbers could
		 * be shorter than DSA_SIGNATURE_LEN/2 bytes so we need
		 * to act accordingly and shift if necessary.
		 */
		memset(sigbuf, 0, siglen);
		BN_bn2bin(sig->r, sigbuf +
		    siglen2 - BN_num_bytes(sig->r));
		BN_bn2bin(sig->s, &sigbuf[siglen2] +
		    siglen2 - BN_num_bytes(sig->s));
		
		rv = pFuncList->C_Verify(sp->session, 
			(unsigned char *) dgst, dlen, sigbuf, (CK_ULONG)siglen);

		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DSA_VERIFY, PK11_R_VERIFY);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			goto ret;
			}
		}

	retval = 1;
ret:

	pk11_return_session(sp);
	return retval;
	}


/* Create a public key object in a session from a given dsa structure.
 */
static CK_OBJECT_HANDLE pk11_get_public_dsa_key(DSA* dsa,
    DSA **key_ptr, BIGNUM **dsa_pub_num, CK_SESSION_HANDLE session)
	{
	CK_RV rv;
	CK_OBJECT_CLASS o_key = CKO_PUBLIC_KEY;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	CK_ULONG found;
	CK_KEY_TYPE k_type = CKK_DSA;
	CK_ULONG ul_key_attr_count = 8;
	int i;
	char tmp_buf[20];

	CK_ATTRIBUTE  a_key_template[] =
		{
		{CKA_CLASS, (void *) NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, (void *) NULL, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &false, sizeof(true)},
		{CKA_VERIFY, &true, sizeof(true)},
		{CKA_PRIME, (void *)NULL, 0},		/* p */
		{CKA_SUBPRIME, (void *)NULL, 0},	/* q */
		{CKA_BASE, (void *)NULL, 0},		/* g */
		{CKA_VALUE, (void *)NULL, 0}		/* pub_key - y */
		};

	a_key_template[0].pValue = &o_key;
	a_key_template[1].pValue = &k_type;

	if (init_template_value(dsa->p, &a_key_template[4].pValue,
		&a_key_template[4].ulValueLen) == 0 ||
	    init_template_value(dsa->q, &a_key_template[5].pValue,
		&a_key_template[5].ulValueLen) == 0 ||
	    init_template_value(dsa->g, &a_key_template[6].pValue,
		&a_key_template[6].ulValueLen) == 0 ||
	    init_template_value(dsa->pub_key, &a_key_template[7].pValue,
		&a_key_template[7].ulValueLen) == 0)
		{
		PK11err(PK11_F_GET_PUB_DSA_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}


	/*
	 * As stated in v2.20, 11.7 Object Management Function, in section for
	 * C_FindObjectsInit(), at most one search operation may be active at
	 * a given time in a given session. Therefore, we must group these
	 * three calls in one atomic operation.
	 */
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	rv = pFuncList->C_FindObjectsInit(session, a_key_template, 
		ul_key_attr_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_DSA_KEY, PK11_R_FINDOBJECTSINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjects(session, &h_key, 1, &found);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_DSA_KEY, PK11_R_FINDOBJECTS);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjectsFinal(session);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PUB_DSA_KEY, PK11_R_FINDOBJECTSFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	if (found == 0)
		{
		rv = pFuncList->C_CreateObject(session, 
			a_key_template, ul_key_attr_count, &h_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_PUB_DSA_KEY, 
				PK11_R_CREATEOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
		}

	(void) pk11_active_add(h_key);
	if (key_ptr != NULL)
		*key_ptr = dsa;
	if (dsa_pub_num != NULL)
		if ((*dsa_pub_num = BN_dup(dsa->pub_key)) == NULL)
			{
			PK11err(PK11_F_GET_PUB_DSA_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

err:
	for (i = 4; i <= 7; i++)
		{
		if (a_key_template[i].pValue != NULL)
			{
			OPENSSL_free(a_key_template[i].pValue);
			a_key_template[i].pValue = NULL;
			}
		}

	return h_key;

	}

/* Create a private key object in the session from a given dsa structure
 */
static CK_OBJECT_HANDLE pk11_get_private_dsa_key(DSA* dsa,
    DSA **key_ptr, BIGNUM **dsa_priv_num, CK_SESSION_HANDLE session)
	{
	CK_RV rv;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS o_key = CKO_PRIVATE_KEY;
	int i;
	char tmp_buf[20];
	CK_ULONG found;
	CK_KEY_TYPE k_type = CKK_DSA;
	CK_ULONG ul_key_attr_count = 9;

	/* Both CKA_TOKEN and CKA_SENSITIVE have to be FALSE for session keys
	 */
	CK_ATTRIBUTE  a_key_template[] =
		{
		{CKA_CLASS, (void *) NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, (void *) NULL, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &false, sizeof(true)},
		{CKA_SENSITIVE, &false, sizeof(true)},
		{CKA_SIGN, &true, sizeof(true)},
		{CKA_PRIME, (void *)NULL, 0},		/* p */
		{CKA_SUBPRIME, (void *)NULL, 0},	/* q */
		{CKA_BASE, (void *)NULL, 0},		/* g */
		{CKA_VALUE, (void *)NULL, 0}		/* priv_key - x */
		};

	a_key_template[0].pValue = &o_key;
	a_key_template[1].pValue = &k_type;

	/* Put the private key components into the template
	 */
	if (init_template_value(dsa->p, &a_key_template[5].pValue,
		&a_key_template[5].ulValueLen) == 0 ||
	    init_template_value(dsa->q, &a_key_template[6].pValue,
		&a_key_template[6].ulValueLen) == 0 ||
	    init_template_value(dsa->g, &a_key_template[7].pValue,
		&a_key_template[7].ulValueLen) == 0 ||
	    init_template_value(dsa->priv_key, &a_key_template[8].pValue,
		&a_key_template[8].ulValueLen) == 0)
		{
		PK11err(PK11_F_GET_PRIV_DSA_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	/*
	 * As stated in v2.20, 11.7 Object Management Function, in section for
	 * C_FindObjectsInit(), at most one search operation may be active at
	 * a given time in a given session. Therefore, we must group these
	 * three calls in one atomic operation.
	 */
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	rv = pFuncList->C_FindObjectsInit(session, a_key_template, 
		ul_key_attr_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_DSA_KEY, PK11_R_FINDOBJECTSINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjects(session, &h_key, 1, &found);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_DSA_KEY, PK11_R_FINDOBJECTS);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjectsFinal(session);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_PRIV_DSA_KEY, PK11_R_FINDOBJECTSFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	if (found == 0)
		{
		rv = pFuncList->C_CreateObject(session, 
			a_key_template, ul_key_attr_count, &h_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_PRIV_DSA_KEY, 
				PK11_R_CREATEOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
		}

	(void) pk11_active_add(h_key);
	if (key_ptr != NULL)
		*key_ptr = dsa;
	if (dsa_priv_num != NULL)
		if ((*dsa_priv_num = BN_dup(dsa->priv_key)) == NULL)
			{
			PK11err(PK11_F_GET_PRIV_DSA_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

err:
	/* 5 to 8 entries in the key template are key components
	 * They need to be freed apon exit or error.
	 */
	for (i = 5; i <= 8; i++)
		{
		if (a_key_template[i].pValue != NULL)
			{
			memset(a_key_template[i].pValue, 0,
				a_key_template[i].ulValueLen);
			OPENSSL_free(a_key_template[i].pValue);
			a_key_template[i].pValue = NULL;
			}
		}

	return h_key;

	}

/*
 * Check for cache miss and clean the object pointer and handle
 * in such case. Return 1 for cache hit, 0 for cache miss.
 */
static int check_new_dsa_key_pub(PK11_SESSION *sp, DSA *dsa)
	{
	/*
	 * Provide protection against DSA structure reuse by making the
	 * check for cache hit stronger. Only public key component of DSA
	 * key matters here so it is sufficient to compare it with value
	 * cached in PK11_SESSION structure.
	 */
	if ((sp->dsa_pub != dsa) ||
	    (BN_cmp(sp->dsa_pub_num, dsa->pub_key) != 0))
		{
		/*
		 * We do not check the return value because even in case of
		 * failure the sp structure will have both key pointer
		 * and object handle cleaned and pk11_destroy_object()
		 * reports the failure to the OpenSSL error message buffer.
		 */
		(void) pk11_destroy_dsa_object_pub(sp, TRUE);
		return (0);
		}
	return (1);
	}

/*
 * Check for cache miss and clean the object pointer and handle
 * in such case. Return 1 for cache hit, 0 for cache miss.
 */
static int check_new_dsa_key_priv(PK11_SESSION *sp, DSA *dsa)
	{
	/*
	 * Provide protection against DSA structure reuse by making the
	 * check for cache hit stronger. Only private key component of DSA
	 * key matters here so it is sufficient to compare it with value
	 * cached in PK11_SESSION structure.
	 */
	if ((sp->dsa_priv != dsa) ||
	    (BN_cmp(sp->dsa_priv_num, dsa->priv_key) != 0))
		{
		/*
		 * We do not check the return value because even in case of
		 * failure the sp structure will have both key pointer
		 * and object handle cleaned and pk11_destroy_object()
		 * reports the failure to the OpenSSL error message buffer.
		 */
		(void) pk11_destroy_dsa_object_priv(sp, TRUE);
		return (0);
		}
	return (1);
	}
#endif


#ifndef OPENSSL_NO_DH
/* The DH function implementation
 */
static int pk11_DH_init(DH *dh)
	{
	return 1;
	}

static int pk11_DH_finish(DH *dh)
	{
	return (1);
	}

/*
 * Generate DH key-pair.
 *
 * Warning: Unlike OpenSSL's DH_generate_key(3) we ignore dh->priv_key
 * and override it even if it is set. OpenSSL does not touch dh->priv_key
 * if set and just computes dh->pub_key. It looks like PKCS#11 standard
 * is not capable of providing this functionality. This could be a problem
 * for applications relying on OpenSSL's semantics.
 */
static int pk11_DH_generate_key(DH *dh)
	{
	CK_ULONG i;
	CK_RV rv, rv1;
	int reuse_mem_len = 0, ret = 0;
	PK11_SESSION *sp = NULL;
	char tmp_buf[20];
	CK_BYTE_PTR reuse_mem;

	CK_MECHANISM mechanism = {CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_OBJECT_HANDLE h_pub_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE h_priv_key = CK_INVALID_HANDLE;

	CK_ULONG ul_pub_key_attr_count = 3; 
	CK_ATTRIBUTE pub_key_template[] =
		{
		{CKA_PRIVATE, &false, sizeof(false)},
		{CKA_PRIME, (void *)NULL, 0},
		{CKA_BASE, (void *)NULL, 0}
		};

	CK_ULONG ul_priv_key_attr_count = 3; 
	CK_ATTRIBUTE priv_key_template[] =
		{
		{CKA_PRIVATE, &false, sizeof(false)},
		{CKA_SENSITIVE, &false, sizeof(false)},
		{CKA_DERIVE, &true, sizeof(true)}
		};

	CK_ULONG pub_key_attr_result_count = 1;
	CK_ATTRIBUTE pub_key_result[] =
		{
		{CKA_VALUE, (void *)NULL, 0}
		};

	CK_ULONG priv_key_attr_result_count = 1;
	CK_ATTRIBUTE priv_key_result[] =
		{
		{CKA_VALUE, (void *)NULL, 0}
		};

	pub_key_template[1].ulValueLen = BN_num_bytes(dh->p);
	if (pub_key_template[1].ulValueLen > 0)
		{
		/*
		 * We must not increase ulValueLen by DH_BUF_RESERVE since that
		 * could cause the same rounding problem. See definition of
		 * DH_BUF_RESERVE above.
		 */
		pub_key_template[1].pValue = 
			OPENSSL_malloc(pub_key_template[1].ulValueLen +
			DH_BUF_RESERVE);
		if (pub_key_template[1].pValue == NULL)
			{
			PK11err(PK11_F_DH_GEN_KEY, PK11_R_MALLOC_FAILURE);
			goto err;
			}

		i = BN_bn2bin(dh->p, pub_key_template[1].pValue);
		}
	else
		goto err;

	pub_key_template[2].ulValueLen = BN_num_bytes(dh->g);
	if (pub_key_template[2].ulValueLen > 0)
		{
		pub_key_template[2].pValue = 
			OPENSSL_malloc(pub_key_template[2].ulValueLen +
			DH_BUF_RESERVE);
		if (pub_key_template[2].pValue == NULL)
			{
			PK11err(PK11_F_DH_GEN_KEY, PK11_R_MALLOC_FAILURE);
			goto err;
			}

		i = BN_bn2bin(dh->g, pub_key_template[2].pValue);
		}
	else
		goto err;

	/*
	 * Note: we are only using PK11_SESSION structure for getting
	 *	 a session handle. The objects created in this function are
	 *	 destroyed before return and thus not cached.
	 */
	if ((sp = pk11_get_session()) == NULL)
		goto err;
	
	rv = pFuncList->C_GenerateKeyPair(sp->session,
			   &mechanism,
			   pub_key_template,
			   ul_pub_key_attr_count,
			   priv_key_template,
			   ul_priv_key_attr_count,
			   &h_pub_key,
			   &h_priv_key);
	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_GEN_KEY, PK11_R_GEN_KEY);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	/* Reuse the larger memory allocated. We know the larger memory
	 * should be sufficient for reuse */
	if (pub_key_template[1].ulValueLen > pub_key_template[2].ulValueLen)
		{
		reuse_mem = pub_key_template[1].pValue;
		reuse_mem_len = pub_key_template[1].ulValueLen + DH_BUF_RESERVE;
		}
	else
		{
		reuse_mem = pub_key_template[2].pValue;
		reuse_mem_len = pub_key_template[2].ulValueLen + DH_BUF_RESERVE;
		}

	rv = pFuncList->C_GetAttributeValue(sp->session, h_pub_key, 
		pub_key_result, pub_key_attr_result_count);
	rv1 = pFuncList->C_GetAttributeValue(sp->session, h_priv_key, 
		priv_key_result, priv_key_attr_result_count);

	if (rv != CKR_OK || rv1 != CKR_OK)
		{
		rv = (rv != CKR_OK) ? rv : rv1;
		PK11err(PK11_F_DH_GEN_KEY, PK11_R_GETATTRIBUTVALUE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	if (((CK_LONG) pub_key_result[0].ulValueLen) <= 0 ||
		((CK_LONG) priv_key_result[0].ulValueLen) <= 0)
		{
		PK11err(PK11_F_DH_GEN_KEY, PK11_R_GETATTRIBUTVALUE);
		goto err;
		}
	
	/* Reuse the memory allocated */
	pub_key_result[0].pValue = reuse_mem;
	pub_key_result[0].ulValueLen = reuse_mem_len;

	rv = pFuncList->C_GetAttributeValue(sp->session, h_pub_key, 
		pub_key_result, pub_key_attr_result_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_GEN_KEY, PK11_R_GETATTRIBUTVALUE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	if (pub_key_result[0].type == CKA_VALUE)
		{
		if (dh->pub_key == NULL)
			if ((dh->pub_key = BN_new()) == NULL)
				{
				PK11err(PK11_F_DH_GEN_KEY,
					PK11_R_MALLOC_FAILURE);
				goto err;
				}
		dh->pub_key = BN_bin2bn(pub_key_result[0].pValue, 
			pub_key_result[0].ulValueLen, dh->pub_key);
		}

	/* Reuse the memory allocated */
	priv_key_result[0].pValue = reuse_mem;
	priv_key_result[0].ulValueLen = reuse_mem_len;

	rv = pFuncList->C_GetAttributeValue(sp->session, h_priv_key, 
		priv_key_result, priv_key_attr_result_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_GEN_KEY, PK11_R_GETATTRIBUTVALUE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	if (priv_key_result[0].type == CKA_VALUE)
		{
		if (dh->priv_key == NULL)
			if ((dh->priv_key = BN_new()) == NULL)
				{
				PK11err(PK11_F_DH_GEN_KEY,
					PK11_R_MALLOC_FAILURE);
				goto err;
				}
		dh->priv_key = BN_bin2bn(priv_key_result[0].pValue, 
			priv_key_result[0].ulValueLen, dh->priv_key);
		}

	ret = 1;

err:
	 
	if (h_pub_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_DestroyObject(sp->session, h_pub_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DH_GEN_KEY, PK11_R_DESTROYOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			}
		}

	if (h_priv_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_DestroyObject(sp->session, h_priv_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DH_GEN_KEY, PK11_R_DESTROYOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			}
		}

	for (i = 1; i <= 2; i++)
		{
		if (pub_key_template[i].pValue != NULL)
			{
			OPENSSL_free(pub_key_template[i].pValue);
			pub_key_template[i].pValue = NULL;
			}
		}

	pk11_return_session(sp);
	return ret;
	}

static int pk11_DH_compute_key(unsigned char *key,const BIGNUM *pub_key,DH *dh)
	{
	int i;
	CK_MECHANISM mechanism = {CKM_DH_PKCS_DERIVE, NULL_PTR, 0};
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE h_derived_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;

	CK_ULONG ul_priv_key_attr_count = 2;
	CK_ATTRIBUTE priv_key_template[] =
		{
		{CKA_CLASS, (void*) NULL, sizeof(key_class)},
		{CKA_KEY_TYPE, (void*) NULL,  sizeof(key_type)},
		};

	CK_ULONG priv_key_attr_result_count = 1;
	CK_ATTRIBUTE priv_key_result[] =
		{
		{CKA_VALUE, (void *)NULL, 0}
		};

	CK_RV rv;
	int ret = -1;
	PK11_SESSION *sp = NULL;
	char tmp_buf[20];

	if (dh->priv_key == NULL)
		goto err;

	priv_key_template[0].pValue = &key_class;
	priv_key_template[1].pValue = &key_type;

	if ((sp = pk11_get_session()) == NULL)
		goto err;

	mechanism.ulParameterLen = BN_num_bytes(pub_key);
	mechanism.pParameter = OPENSSL_malloc(mechanism.ulParameterLen);
	if (mechanism.pParameter == NULL)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}
	BN_bn2bin(pub_key, mechanism.pParameter);

	(void) check_new_dh_key(sp, dh);

	h_key = sp->dh_key;
	if (h_key == CK_INVALID_HANDLE)
		h_key = sp->dh_key =
			pk11_get_dh_key((DH*) dh, &sp->dh,
			    &sp->dh_priv_num, sp->session);

	if (h_key == CK_INVALID_HANDLE)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_CREATEOBJECT);
		goto err;
		}

	rv = pFuncList->C_DeriveKey(sp->session,
			   &mechanism,
			   h_key,
			   priv_key_template,
			   ul_priv_key_attr_count,
			   &h_derived_key);
	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_DERIVEKEY);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	rv = pFuncList->C_GetAttributeValue(sp->session, h_derived_key, 
		priv_key_result, priv_key_attr_result_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_GETATTRIBUTVALUE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	if (((CK_LONG) priv_key_result[0].ulValueLen) <= 0)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_GETATTRIBUTVALUE);
		goto err;
		}
	priv_key_result[0].pValue = 
		OPENSSL_malloc(priv_key_result[0].ulValueLen);
	if (!priv_key_result[0].pValue)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	rv = pFuncList->C_GetAttributeValue(sp->session, h_derived_key, 
		priv_key_result, priv_key_attr_result_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_DH_COMP_KEY, PK11_R_GETATTRIBUTVALUE);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		goto err;
		}

	/* OpenSSL allocates the output buffer 'key' which is the same
	 * length of the public key. It is long enough for the derived key */
	if (priv_key_result[0].type == CKA_VALUE)
		{
		/* CKM_DH_PKCS_DERIVE mechanism is not supposed to strip
		 * leading zeros from a computed shared secret. However,
		 * OpenSSL always did it so we must do the same here. The
		 * vagueness of the spec regarding leading zero bytes was
		 * finally cleared with TLS 1.1 (RFC 4346) saying that leading
		 * zeros are stripped before the computed data is used as the
		 * pre-master secret.
		 */
		for (i = 0; i < priv_key_result[0].ulValueLen; ++i)
			{
			if (((char *) priv_key_result[0].pValue)[i] != 0)
				break;
			}

		memcpy(key, ((char *) priv_key_result[0].pValue) + i, 
			priv_key_result[0].ulValueLen - i);
		ret = priv_key_result[0].ulValueLen - i;
		}

err:

	if (h_derived_key != CK_INVALID_HANDLE)
		{
		rv = pFuncList->C_DestroyObject(sp->session, h_derived_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_DH_COMP_KEY, PK11_R_DESTROYOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			}
		}
	if (priv_key_result[0].pValue)
		{ 
		OPENSSL_free(priv_key_result[0].pValue);
		priv_key_result[0].pValue = NULL;
		}

	if (mechanism.pParameter)
		{
		OPENSSL_free(mechanism.pParameter);
		mechanism.pParameter = NULL;
		}

	pk11_return_session(sp);
	return ret;
	}


static CK_OBJECT_HANDLE pk11_get_dh_key(DH* dh,
	DH **key_ptr, BIGNUM **dh_priv_num, CK_SESSION_HANDLE session)
	{
	CK_RV rv;
	CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_DH;
	CK_ULONG found;
	int i;
	char tmp_buf[20];

	CK_ULONG ul_key_attr_count = 7;
	CK_ATTRIBUTE key_template[] =
		{
		{CKA_CLASS, (void*) NULL, sizeof(class)},
		{CKA_KEY_TYPE, (void*) NULL, sizeof(key_type)},
		{CKA_DERIVE, &true, sizeof(true)},
		{CKA_PRIVATE, &false, sizeof(false)},
		{CKA_PRIME, (void *) NULL, 0},
		{CKA_BASE, (void *) NULL, 0},
		{CKA_VALUE, (void *) NULL, 0},
		};

	key_template[0].pValue = &class;
	key_template[1].pValue = &key_type;

	key_template[4].ulValueLen = BN_num_bytes(dh->p);
	key_template[4].pValue = (CK_VOID_PTR)OPENSSL_malloc(
		(size_t)key_template[4].ulValueLen);
	if (key_template[4].pValue == NULL)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	BN_bn2bin(dh->p, key_template[4].pValue);

	key_template[5].ulValueLen = BN_num_bytes(dh->g);
	key_template[5].pValue = (CK_VOID_PTR)OPENSSL_malloc(
		(size_t)key_template[5].ulValueLen);
	if (key_template[5].pValue == NULL)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	BN_bn2bin(dh->g, key_template[5].pValue);

	key_template[6].ulValueLen = BN_num_bytes(dh->priv_key);
	key_template[6].pValue = (CK_VOID_PTR)OPENSSL_malloc(
		(size_t)key_template[6].ulValueLen);
	if (key_template[6].pValue == NULL)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_MALLOC_FAILURE);
		goto err;
		}

	BN_bn2bin(dh->priv_key, key_template[6].pValue);

	/*
	 * As stated in v2.20, 11.7 Object Management Function, in section for
	 * C_FindObjectsInit(), at most one search operation may be active at
	 * a given time in a given session. Therefore, we must group these
	 * three calls in one atomic operation.
	 */
	CRYPTO_w_lock(CRYPTO_LOCK_PK11_ENGINE);
	rv = pFuncList->C_FindObjectsInit(session, key_template, 
		ul_key_attr_count);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_FINDOBJECTSINIT);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjects(session, &h_key, 1, &found);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_FINDOBJECTS);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	rv = pFuncList->C_FindObjectsFinal(session);

	if (rv != CKR_OK)
		{
		PK11err(PK11_F_GET_DH_KEY, PK11_R_FINDOBJECTSFINAL);
		snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
		ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
		CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
		goto err;
		}

	if (found == 0)
		{
		rv = pFuncList->C_CreateObject(session, 
			key_template, ul_key_attr_count, &h_key);
		if (rv != CKR_OK)
			{
			PK11err(PK11_F_GET_DH_KEY, PK11_R_CREATEOBJECT);
			snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
			ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
		}

	(void) pk11_active_add(h_key);
	if (key_ptr != NULL)
		*key_ptr = dh;
	if (dh_priv_num != NULL)
		if ((*dh_priv_num = BN_dup(dh->priv_key)) == NULL)
			{
			PK11err(PK11_F_GET_DH_KEY, PK11_R_MALLOC_FAILURE);
			CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);
			goto err;
			}
	CRYPTO_w_unlock(CRYPTO_LOCK_PK11_ENGINE);

err:
	for (i = 4; i <= 6; i++)
		{
		if (key_template[i].pValue != NULL)
			{
			OPENSSL_free(key_template[i].pValue);
			key_template[i].pValue = NULL;
			}
		}

	return h_key;
	}

/*
 * Check for cache miss and clean the object pointer and handle
 * in such case. Return 1 for cache hit, 0 for cache miss.
 *
 * Note: we rely on pk11_destroy_dh_key_objects() to set sp->dh
 *       to CK_INVALID_HANDLE even when it fails to destroy the object.
 */
static int check_new_dh_key(PK11_SESSION *sp, DH *dh)
	{
	/*
	 * Provide protection against DH structure reuse by making the
	 * check for cache hit stronger. Private key component of DH key
	 * is unique so it is sufficient to compare it with value cached
	 * in PK11_SESSION structure.
	 */
	if ((sp->dh != dh) ||
	    (BN_cmp(sp->dh_priv_num, dh->priv_key) != 0))
		{
		/*
		 * We do not check the return value because even in case of
		 * failure the sp structure will have both key pointer
		 * and object handle cleaned and pk11_destroy_object()
		 * reports the failure to the OpenSSL error message buffer.
		 */
		(void) pk11_destroy_dh_object(sp, TRUE);
		return (0);
		}
	return (1);
	}
#endif

/* Local function to simplify key template population
 * Return 0 -- error, 1 -- no error
 */
static int init_template_value(BIGNUM *bn, CK_VOID_PTR *p_value, 
	CK_ULONG *ul_value_len)
	{
	CK_ULONG len = BN_num_bytes(bn);
	if (len == 0)
		return 1;

	*ul_value_len = len;
	*p_value = (CK_VOID_PTR)OPENSSL_malloc((size_t) *ul_value_len);
	if (*p_value == NULL)
		return 0;

	BN_bn2bin(bn, *p_value);

	return 1;
	}
#endif
#endif

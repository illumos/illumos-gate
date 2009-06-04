/*
 * ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _P12LIB_H
#define	_P12LIB_H


#include <openssl/pkcs12.h>
#include <openssl/pem.h>

/*
 * PKCS12 file routines borrowed from SNT's libwanboot.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* These declarations allow us to make stacks of EVP_PKEY objects */
DECLARE_STACK_OF(EVP_PKEY)
#define	sk_EVP_PKEY_new_null() SKM_sk_new_null(EVP_PKEY)
#define	sk_EVP_PKEY_free(st) SKM_sk_free(EVP_PKEY, (st))
#define	sk_EVP_PKEY_num(st) SKM_sk_num(EVP_PKEY, (st))
#define	sk_EVP_PKEY_value(st, i) SKM_sk_value(EVP_PKEY, (st), (i))
#define	sk_EVP_PKEY_push(st, val) SKM_sk_push(EVP_PKEY, (st), (val))
#define	sk_EVP_PKEY_find(st, val) SKM_sk_find(EVP_PKEY, (st), (val))
#define	sk_EVP_PKEY_delete(st, i) SKM_sk_delete(EVP_PKEY, (st), (i))
#define	sk_EVP_PKEY_delete_ptr(st, ptr) SKM_sk_delete_ptr(EVP_PKEY, (st), (ptr))
#define	sk_EVP_PKEY_insert(st, val, i) SKM_sk_insert(EVP_PKEY, (st), (val), (i))
#define	sk_EVP_PKEY_pop_free(st, free_func) SKM_sk_pop_free(EVP_PKEY, (st), \
	    (free_func))
#define	sk_EVP_PKEY_pop(st) SKM_sk_pop(EVP_PKEY, (st))

/* Error reporting routines required by OpenSSL */
#define	SUNW_LIB_NAME	"SUNW_PKCS12"
#define	SUNWerr(f, r)	ERR_SUNW_error((f), (r), __FILE__, __LINE__)

/* Error codes for the SUNW functions. */
/* OpenSSL prefers codes to start at 100 */

/* Function codes. */
typedef enum {
	SUNW_F_USE_X509CERT = 100,
	SUNW_F_USE_PKEY,
	SUNW_F_USE_TASTORE,
	SUNW_F_USE_CERTFILE,
	SUNW_F_USE_KEYFILE,
	SUNW_F_USE_TRUSTFILE,
	SUNW_F_READ_FILE,
	SUNW_F_DOPARSE,
	SUNW_F_PKCS12_PARSE,
	SUNW_F_PKCS12_CONTENTS,
	SUNW_F_PARSE_ONE_BAG,
	SUNW_F_PKCS12_CREATE,
	SUNW_F_SPLIT_CERTS,
	SUNW_F_FIND_LOCALKEYID,
	SUNW_F_SET_LOCALKEYID,
	SUNW_F_SET_FNAME,
	SUNW_F_GET_LOCALKEYID,
	SUNW_F_GET_PKEY_FNAME,
	SUNW_F_APPEND_KEYS,
	SUNW_F_PEM_CONTENTS,
	SUNW_F_PEM_INFO,
	SUNW_F_ASC2BMPSTRING,
	SUNW_F_UTF82ASCSTR,
	SUNW_F_FINDATTR,
	SUNW_F_TYPE2ATTRIB,
	SUNW_F_MOVE_CERTS,
	SUNW_F_FIND_FNAME,
	SUNW_F_PARSE_OUTER,
	SUNW_F_CHECKFILE
} sunw_err_func_t;

/* Reason codes. */
typedef enum {
	SUNW_R_INVALID_ARG = 100,
	SUNW_R_MEMORY_FAILURE,
	SUNW_R_MAC_VERIFY_FAILURE,
	SUNW_R_MAC_CREATE_FAILURE,
	SUNW_R_BAD_FILETYPE,
	SUNW_R_BAD_PKEY,
	SUNW_R_BAD_PKEYTYPE,
	SUNW_R_PKEY_READ_ERR,
	SUNW_R_NO_TRUST_ANCHOR,
	SUNW_R_READ_TRUST_ERR,
	SUNW_R_ADD_TRUST_ERR,
	SUNW_R_PKCS12_PARSE_ERR,
	SUNW_R_PKCS12_CREATE_ERR,
	SUNW_R_PARSE_BAG_ERR,
	SUNW_R_MAKE_BAG_ERR,
	SUNW_R_BAD_CERTTYPE,
	SUNW_R_PARSE_CERT_ERR,
	SUNW_R_BAD_LKID,
	SUNW_R_SET_LKID_ERR,
	SUNW_R_BAD_FNAME,
	SUNW_R_SET_FNAME_ERR,
	SUNW_R_BAD_TRUST,
	SUNW_R_BAD_BAGTYPE,
	SUNW_R_CERT_ERR,
	SUNW_R_PKEY_ERR,
	SUNW_R_READ_ERR,
	SUNW_R_ADD_ATTR_ERR,
	SUNW_R_STR_CONVERT_ERR,
	SUNW_R_PKCS12_EMPTY_ERR,
	SUNW_R_PASSWORD_ERR
} sunw_err_reason_t;

/*
 * Type of checking to perform when calling sunw_check_cert_times
 */
typedef enum {
	CHK_NOT_BEFORE = 1,	/* Check 'not before' date */
	CHK_NOT_AFTER,		/* Check 'not after' date */
	CHK_BOTH		/* Check both dates */
} chk_actions_t;

/*
 * Return type for sunw_check_cert_times
 */
typedef enum {
	CHKERR_TIME_OK = 0,	/* Current time meets requested checks */
	CHKERR_TIME_BEFORE_BAD,	/* 'not before' field is invalid */
	CHKERR_TIME_AFTER_BAD,	/* 'not after' field is invalid */
	CHKERR_TIME_IS_BEFORE,	/* Current time is before 'not before' */
	CHKERR_TIME_HAS_EXPIRED	/* Current time is after 'not after' */
} chk_errs_t;

/*
 * This type indicates what to do with an attribute being returned.
 */
typedef enum {
	GETDO_COPY = 1,		/* Simply return the value of the attribute */
	GETDO_DEL		/* Delete the attribute at the same time. */
} getdo_actions_t;

/*
 * For sunw_pkcs12_parse, the following are values for bits that indicate
 * various types of searches/matching to do. Any of these values can be
 * OR'd together. However, the order in which an attempt will be made
 * to satisfy them is the order in which they are listed below. The
 * exception is DO_NONE. It should not be OR'd with any other value.
 */
#define	DO_NONE		0x00	/* Don't even try to match */
#define	DO_FIND_KEYID	0x01	/* 1st cert, key with matching localkeyid */
#define	DO_FIND_FN	0x02	/* 1st cert, key with matching friendlyname */
#define	DO_FIRST_PAIR	0x04	/* Return first matching cert/key pair found */
#define	DO_LAST_PAIR	0x08	/* Return last matching cert/key pair found */
#define	DO_UNMATCHING	0x10	/* Return first cert and/or key */

/* Bits returned, which indicate what values were found. */
#define	FOUND_PKEY	0x01	/* Found one or more private key */
#define	FOUND_CERT	0x02	/* Found one or more client certificate */
#define	FOUND_CA_CERTS	0x04	/* Added at least one cert to the CA list */
#define	FOUND_XPKEY	0x08	/* Found at least one private key which does */
				/* not match a certificate in the certs list */

/* p12lib.c */
PKCS12	*sunw_PKCS12_create(const char *, STACK_OF(EVP_PKEY) *,
    STACK_OF(X509) *, STACK_OF(X509) *);

int	sunw_split_certs(STACK_OF(EVP_PKEY) *, STACK_OF(X509) *,
    STACK_OF(X509) **, STACK_OF(EVP_PKEY) **);

void	sunw_evp_pkey_free(EVP_PKEY *);
int	sunw_set_localkeyid(const char *, int, EVP_PKEY *, X509 *);
int	sunw_get_pkey_localkeyid(getdo_actions_t, EVP_PKEY *, char **, int *);
int	sunw_get_pkey_fname(getdo_actions_t, EVP_PKEY *, char **);
int	sunw_find_localkeyid(char *, int, STACK_OF(EVP_PKEY) *,
    STACK_OF(X509) *, EVP_PKEY **, X509 **);
int	sunw_find_fname(char *, STACK_OF(EVP_PKEY) *, STACK_OF(X509) *,
    EVP_PKEY **, X509 **);
int	sunw_set_fname(const char *, EVP_PKEY *, X509 *);
int	sunw_check_keys(X509 *, EVP_PKEY *);

chk_errs_t	sunw_check_cert_times(chk_actions_t, X509 *);
extern void	ERR_SUNW_error(int function, int reason, char *file, int line);
extern void	ERR_load_SUNW_strings(void);
int		sunw_PKCS12_contents(PKCS12 *, const char *,
    STACK_OF(EVP_PKEY) **, STACK_OF(X509) **);
int		sunw_get_cert_fname(getdo_actions_t, X509 *, char **);
int		sunw_PEM_contents(FILE *, pem_password_cb, void *,
    STACK_OF(EVP_PKEY) **, STACK_OF(X509) **);

#ifdef __cplusplus
}
#endif

#endif /* _P12LIB_H */

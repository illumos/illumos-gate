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
 * Copyright 2008 Sun Microsystems, Inc.   All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CRYPTOKI_H
#define	_CRYPTOKI_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	CK_PTR
#define	CK_PTR *
#endif

#ifndef CK_DEFINE_FUNCTION
#define	CK_DEFINE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION
#define	CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
#define	CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#endif

#ifndef CK_CALLBACK_FUNCTION
#define	CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif

#ifndef NULL_PTR
#include <unistd.h>	/* For NULL */
#define	NULL_PTR NULL
#endif

/*
 * pkcs11t.h defines TRUE and FALSE in a way that upsets lint
 */
#ifndef	CK_DISABLE_TRUE_FALSE
#define	CK_DISABLE_TRUE_FALSE
#ifndef	TRUE
#define	TRUE	1
#endif /* TRUE */
#ifndef	FALSE
#define	FALSE	0
#endif /* FALSE */
#endif /* CK_DISABLE_TRUE_FALSE */

#undef CK_PKCS11_FUNCTION_INFO

#include <security/pkcs11.h>

/* Default salt len to generate PKCS#5 key */
#define	CK_PKCS5_PBKD2_SALT_SIZE	(16UL)

/* Default number of iterations to generate PKCS#5 key */
#define	CK_PKCS5_PBKD2_ITERATIONS	(1000UL)

/* Solaris specific functions */

#include <stdlib.h>

/*
 * pkcs11_GetCriteriaSession will initialize the framework and do all
 * the necessary work of calling C_GetSlotList(), C_GetMechanismInfo()
 * C_OpenSession() to create a session that meets all the criteria in
 * the given function pointer.
 */
CK_RV pkcs11_GetCriteriaSession(
    boolean_t (*criteria)(CK_SLOT_ID slot_id, void *args, CK_RV *rv),
    void *args, CK_SESSION_HANDLE_PTR hSession);

/*
 * SUNW_C_GetMechSession will initialize the framework and do all
 * the necessary PKCS#11 calls to create a session capable of
 * providing operations on the requested mechanism
 */
CK_RV SUNW_C_GetMechSession(CK_MECHANISM_TYPE mech,
    CK_SESSION_HANDLE_PTR hSession);

/*
 * SUNW_C_KeyToObject will create a secret key object for the given
 * mechanism from the rawkey data.
 */
CK_RV SUNW_C_KeyToObject(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_TYPE mech, const void *rawkey, size_t rawkey_len,
    CK_OBJECT_HANDLE_PTR obj);

/*
 * pkcs11_PasswdToPBKD2Object will create a secret key from the given string
 * (e.g. passphrase) using PKCS#5 Password-Based Key Derivation Function 2
 * (PBKD2).
 */
CK_RV
pkcs11_PasswdToPBKD2Object(CK_SESSION_HANDLE hSession, char *passphrase,
    size_t passphrase_len, void *salt, size_t salt_len, CK_ULONG iterations,
    CK_KEY_TYPE key_type, CK_ULONG key_len, CK_FLAGS key_flags,
    CK_OBJECT_HANDLE_PTR obj);

/*
 * pkcs11_ObjectToKey gets the rawkey data from a secret key object.
 * The caller is responsible to free the allocated rawkey data.
 */
CK_RV
pkcs11_ObjectToKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE obj,
    void **rawkey, size_t *rawkey_len, boolean_t destroy_obj);

/*
 * pkcs11_PasswdToKey will create PKCS#5 PBKD2 rawkey data from the
 * given passphrase.  The caller is responsible to free the allocated
 * rawkey data.
 */
CK_RV
pkcs11_PasswdToKey(CK_SESSION_HANDLE hSession, char *passphrase,
    size_t passphrase_len, void *salt, size_t salt_len, CK_KEY_TYPE key_type,
    CK_ULONG key_len, void **rawkey, size_t *rawkey_len);

#ifdef	__cplusplus
}
#endif

#endif	/* _CRYPTOKI_H */

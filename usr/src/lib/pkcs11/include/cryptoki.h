/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.   All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CRYPTOKI_H
#define	_CRYPTOKI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/* Solaris specific functions */

#include <stdlib.h>

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


#ifdef	__cplusplus
}
#endif

#endif	/* _CRYPTOKI_H */

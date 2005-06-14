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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTKEYS_H
#define	_SOFTKEYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>
#include "softObject.h"
#include "softSession.h"

#define	KEYGEN_RETRY	3

/*
 * Function Prototypes.
 */
CK_RV soft_genkey(soft_session_t *, CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

CK_RV soft_genkey_pair(soft_session_t *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
	CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR,
	CK_OBJECT_HANDLE_PTR);

CK_RV soft_derivekey(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *,
	CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

void soft_derive_enforce_flags(soft_object_t *, soft_object_t *);

CK_RV soft_gen_keyobject(CK_ATTRIBUTE_PTR,  CK_ULONG,
	CK_ULONG *, soft_session_t *, CK_OBJECT_CLASS, CK_KEY_TYPE,
	CK_ULONG, CK_ULONG, boolean_t);

CK_RV soft_generate_pkcs5_pbkdf2_key(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *);

CK_RV soft_wrapkey(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *,
	soft_object_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_unwrapkey(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *,
	CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
	CK_OBJECT_HANDLE_PTR);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTKEYS_H */

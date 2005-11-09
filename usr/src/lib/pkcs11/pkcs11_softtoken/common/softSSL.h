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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTSSL_H
#define	_SOFTSSL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <bignum.h>
#include "softObject.h"
#include "softSession.h"

CK_RV soft_ssl_master_key_derive(soft_session_t *, CK_MECHANISM_PTR,
    soft_object_t *, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV soft_ssl_key_and_mac_derive(soft_session_t *, CK_MECHANISM_PTR,
    soft_object_t *, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV derive_tls_prf(CK_TLS_PRF_PARAMS_PTR, soft_object_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTSSL_H */

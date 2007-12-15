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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTEC_H
#define	_SOFTEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <ecc_impl.h>
#include "softObject.h"
#include "softSession.h"

typedef struct soft_ecc_ctx {
	soft_object_t *key;
	ECParams ecparams;
} soft_ecc_ctx_t;

extern CK_RV soft_get_public_key_attribute(soft_object_t *, CK_ATTRIBUTE_PTR);
extern CK_RV soft_get_private_key_attribute(soft_object_t *, CK_ATTRIBUTE_PTR);
extern CK_RV set_extra_attr_to_object(soft_object_t *, CK_ATTRIBUTE_TYPE,
    CK_ATTRIBUTE_PTR);
extern CK_RV soft_ec_genkey_pair(soft_object_t *, soft_object_t *);
extern CK_RV soft_ec_key_derive(soft_object_t *, soft_object_t *, void *,
    size_t);
extern CK_RV soft_ecc_sign_verify_init_common(soft_session_t *,
    CK_MECHANISM_PTR, soft_object_t *, boolean_t);
extern CK_RV soft_ecc_sign(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG_PTR);
extern CK_RV soft_ecc_verify(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG);
extern CK_RV soft_ecc_digest_sign_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);
extern CK_RV soft_ecc_digest_verify_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTEC_H */

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

#ifndef	_KERNEL_SOFT_COMMON_H
#define	_KERNEL_SOFT_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>

#define	OP_INIT		0x01
#define	OP_UPDATE	0x02
#define	OP_FINAL 	0x04
#define	OP_SINGLE 	0x08
#define	OP_DIGEST	0x10
#define	OP_SIGN		0x20
#define	OP_VERIFY	0x40

void free_soft_ctx(void *s, int opflag);
CK_RV do_soft_digest(void **s, CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pBuf,
    CK_ULONG ulBufLen, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen, int opflag);

CK_RV do_soft_hmac_init(void **s, CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR kval,
    CK_ULONG klen, int opflag);
CK_RV do_soft_hmac_update(void **s, CK_BYTE_PTR pBuf,
    CK_ULONG ulBufLen, int opflag);
CK_RV do_soft_hmac_sign(void **s, CK_BYTE_PTR pBuf, CK_ULONG ulBufLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen, int opflag);
CK_RV do_soft_hmac_verify(void **s, CK_BYTE_PTR pBuf, CK_ULONG ulBufLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, int opflag);

#ifdef __cplusplus
}
#endif

#endif /* _KERNEL_SOFT_COMMON_H */

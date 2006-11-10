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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * File: ALGORITHM.H
 *
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */

#ifndef _ALGORITHM_H
#define	_ALGORITHM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmftypes.h>
#include <security/cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pkcs_algorithm_map
{
	CK_MECHANISM_TYPE	pkcs_mechanism;
	uint32_t		algorithm;
	uint32_t		context_type;
	uint32_t		enc_mode;
	CK_BBOOL		bMultiPart;
	CK_BBOOL		fix_keylength;
	uint32_t		keylength;
	CK_BBOOL		fix_blocksize;
	uint32_t		block_size;
	CK_BBOOL		requires_iv;
	uint32_t		iv_length;
	CK_FLAGS		required_flags;
	CK_KEY_TYPE		key_type;
	char			*szDescription;
} PKCS_ALGORITHM_MAP;

extern KMF_SIGNATURE_MODE PKCS_GetDefaultSignatureMode(KMF_ALGORITHM_INDEX);
extern PKCS_ALGORITHM_MAP* PKCS_GetAlgorithmMap(KMF_ALGCLASS, uint32_t,
	uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _ALGORITHM_H */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
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
extern PKCS_ALGORITHM_MAP* pkcs_get_alg_map(KMF_ALGCLASS, uint32_t,
	uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _ALGORITHM_H */

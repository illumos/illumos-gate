/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 *
 */

#ifndef _OIDSALG_H
#define	_OIDSALG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmftypes.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t
	OID_OIW_SHA1[] = { OID_OIW_ALGORITHM, 26},
	OID_OIW_DSA[] = { OID_OIW_ALGORITHM, 12  },
	OID_OIW_DSAWithSHA1[] = { OID_OIW_ALGORITHM, 27  },
	OID_RSAEncryption[] = { OID_PKCS_1, 1 },
	OID_MD2WithRSA[]   = { OID_PKCS_1, 2 },
	OID_MD5WithRSA[]   = { OID_PKCS_1, 4 },
	OID_SHA1WithRSA[]  = { OID_PKCS_1, 5 },
	OID_X9CM_DSA[] = { OID_X9CM_X9ALGORITHM, 1 },
	OID_X9CM_DSAWithSHA1[] = { OID_X9CM_X9ALGORITHM, 3}
;

KMF_OID
	KMFOID_SHA1 = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_SHA1},
	KMFOID_RSA = {OID_PKCS_1_LENGTH+1, OID_RSAEncryption},
	KMFOID_DSA = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_DSA},
	KMFOID_MD5WithRSA = {OID_PKCS_1_LENGTH+1, OID_MD5WithRSA},
	KMFOID_MD2WithRSA = {OID_PKCS_1_LENGTH+1, OID_MD2WithRSA},
	KMFOID_SHA1WithRSA = {OID_PKCS_1_LENGTH+1, OID_SHA1WithRSA},
	KMFOID_SHA1WithDSA = {OID_OIW_ALGORITHM_LENGTH+1, OID_OIW_DSAWithSHA1},
	KMFOID_OIW_DSAWithSHA1  = {OID_OIW_ALGORITHM_LENGTH+1,
		OID_OIW_DSAWithSHA1},
	KMFOID_X9CM_DSA = {OID_X9CM_X9ALGORITHM_LENGTH+1, OID_X9CM_DSA},
	KMFOID_X9CM_DSAWithSHA1 = {OID_X9CM_X9ALGORITHM_LENGTH+1,
		OID_X9CM_DSAWithSHA1}

;

#ifdef __cplusplus
}
#endif
#endif /* _OIDSALG_H */

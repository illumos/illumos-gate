/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>

#include <kmfapiP.h>

typedef struct {
	KMF_OID * AlgOID;
	KMF_ALGORITHM_INDEX AlgID;
} KMF_OID_ID;

/*
 * The following table defines the mapping of AlgOID's to AlgID's.
 */
static KMF_OID_ID ALGOID_ID_Table[] = {
	{(KMF_OID *)&KMFOID_X9CM_DSA, KMF_ALGID_DSA},
	{(KMF_OID *)&KMFOID_X9CM_DSAWithSHA1, KMF_ALGID_SHA1WithDSA},
	{(KMF_OID *)&KMFOID_SHA1, KMF_ALGID_SHA1},
	{(KMF_OID *)&KMFOID_RSA, KMF_ALGID_RSA},
	{(KMF_OID *)&KMFOID_DSA, KMF_ALGID_DSA},
	{(KMF_OID *)&KMFOID_MD5WithRSA, KMF_ALGID_MD5WithRSA},
	{(KMF_OID *)&KMFOID_MD2WithRSA, KMF_ALGID_MD2WithRSA},
	{(KMF_OID *)&KMFOID_SHA1WithRSA, KMF_ALGID_SHA1WithRSA},
	{(KMF_OID *)&KMFOID_SHA1WithDSA, KMF_ALGID_SHA1WithDSA}
};

#define	NUM_ALGOIDS ((sizeof (ALGOID_ID_Table))/(sizeof (ALGOID_ID_Table[0])))

/*
 * Name: x509_algid_to_algoid
 *
 * Description:
 * This function maps the specified AlgID to the corresponding
 * Algorithm OID.
 *
 * Parameters:
 * alg_int - AlgID to be mapped.
 *
 * Return value:
 * Pointer to OID structure and NULL in case of failure.
 *
 */
KMF_OID *
x509_algid_to_algoid(KMF_ALGORITHM_INDEX alg_int)
{
	int i;

	switch (alg_int) {
		case KMF_ALGID_NONE:
			return (NULL);

		default:
			for (i = 0; i < NUM_ALGOIDS; i++) {
				if (ALGOID_ID_Table[i].AlgID == alg_int)
					return (ALGOID_ID_Table[i].AlgOID);
			}
			break;
	}

	return (NULL);
}

/*
 * Name: x509_algoid_to_algid
 *
 * Description:
 * This function maps the specified Algorithm OID to the corresponding
 * AlgID.
 *
 * Parameters:
 * Oid - OID to be mapped.
 *
 * Return value:
 * Algorithm ID and KMF_ALGID_NONE in case of failures.
 */
KMF_ALGORITHM_INDEX
x509_algoid_to_algid(KMF_OID * Oid)
{
	int i;

	if ((Oid == NULL) || (Oid->Data == NULL) || (Oid->Length == 0)) {
		return (KMF_ALGID_NONE);
	}

	for (i = 0; i < NUM_ALGOIDS; i++) {
		if (IsEqualOid(ALGOID_ID_Table[i].AlgOID, Oid))
			return (ALGOID_ID_Table[i].AlgID);
	}

	return (KMF_ALGID_NONE);
}

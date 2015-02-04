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
 *
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <link.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ber_der.h>
#include <kmfapiP.h>
#include <libgen.h>
#include <cryptoutil.h>

KMF_RETURN
copy_data(KMF_DATA *dst, KMF_DATA *src)
{
	KMF_RETURN ret = KMF_OK;

	if (dst == NULL || src == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (src->Length == 0) {
		dst->Length = 0;
		dst->Data = NULL;
		src->Data = NULL;
		return (ret);
	}

	dst->Data = malloc(src->Length);
	if (dst->Data == NULL)
		return (KMF_ERR_MEMORY);

	dst->Length = src->Length;
	(void) memcpy(dst->Data, src->Data, src->Length);

	return (ret);
}

KMF_RETURN
copy_extension_data(KMF_X509_EXTENSION *dstext,
	KMF_X509_EXTENSION *srcext)
{
	KMF_RETURN ret = KMF_OK;

	if (dstext == NULL || srcext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(dstext, 0, sizeof (KMF_X509_EXTENSION));

	ret = copy_data(&dstext->extnId, &srcext->extnId);
	if (ret != KMF_OK)
		goto cleanup;

	dstext->extnId.Length = srcext->extnId.Length;
	dstext->critical = srcext->critical;
	dstext->format = srcext->format;

	ret = copy_data(&dstext->BERvalue, &srcext->BERvalue);
	if (ret != KMF_OK)
		goto cleanup;

	dstext->value.tagAndValue = malloc(sizeof (KMF_X509EXT_TAGandVALUE));
	if (dstext->value.tagAndValue == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	(void) memset(dstext->value.tagAndValue, 0,
	    sizeof (KMF_X509EXT_TAGandVALUE));

	ret = copy_data(&dstext->value.tagAndValue->value,
	    &srcext->value.tagAndValue->value);
	if (ret != KMF_OK)
		goto cleanup;

	dstext->value.tagAndValue->type = srcext->value.tagAndValue->type;

cleanup:
	if (ret != KMF_OK) {
		if (dstext->extnId.Data != NULL)
			kmf_free_data(&dstext->extnId);

		if (dstext->BERvalue.Data != NULL)
			kmf_free_data(&dstext->BERvalue);

		if (dstext->value.tagAndValue->value.Data == NULL)
			kmf_free_data(&dstext->value.tagAndValue->value);
	}

	return (ret);
}

/*
 * Given a block of DER encoded X.509 certificate data and
 * an OID for the desired extension, this routine will
 * parse the cert data and return the data associated with
 * the extension if it is found.
 *
 * RETURNS:
 *   KMF_OK - if extension found and copied OK.
 *   KMF_ERR_EXTENSION_NOT_FOUND - extension not found.
 *   parsing and memory allocation errors are also possible.
 */
KMF_RETURN
kmf_get_cert_extn(const KMF_DATA *certdata,
	KMF_OID *extoid, KMF_X509_EXTENSION *extdata)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *cert = NULL;
	KMF_X509_EXTENSION *eptr = NULL;
	int i, found = 0;

	if (certdata == NULL || extoid == NULL || extdata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = DerDecodeSignedCertificate(certdata, &cert);
	if (ret != KMF_OK)
		return (ret);

	if (cert->certificate.extensions.numberOfExtensions == 0) {
		goto end;
	}

	(void) memset((void *)extdata, 0, sizeof (KMF_X509_EXTENSION));
	for (i = 0; !found &&
	    i < cert->certificate.extensions.numberOfExtensions;
	    i++) {
		eptr = &cert->certificate.extensions.extensions[i];
		if (IsEqualOid(extoid, &eptr->extnId)) {
			ret = copy_extension_data(extdata, eptr);
			found++;
		}
	}
end:
	if (!found)
		ret = KMF_ERR_EXTENSION_NOT_FOUND;

	if (cert != NULL) {
		kmf_free_signed_cert(cert);
		free(cert);
	}

	return (ret);
}

/*
 * Given a block of DER encoded X.509 certificate data and
 * a "crit/non-crit/all" flag, search the extensions and
 * return the OIDs for critical, non-critical or all extensions.
 *
 * RETURNS:
 *   KMF_OK - if extension found and copied OK.
 *   parsing and memory allocation errors are also possible.
 *
 *   OIDlist - array of KMF_OID records, allocated
 *             by this function.
 *   NumOIDs - number of critical extensions found.
 */
KMF_RETURN
kmf_get_cert_extns(const KMF_DATA *certdata, KMF_FLAG_CERT_EXTN flag,
	KMF_X509_EXTENSION **extlist, int *nextns)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *cert;
	KMF_X509_EXTENSION *eptr, *elist;
	int i;

	if (certdata == NULL || extlist == NULL || nextns == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (flag < KMF_ALL_EXTNS || flag > KMF_NONCRITICAL_EXTNS)
		return (KMF_ERR_BAD_PARAMETER);

	*nextns = 0;
	*extlist = elist = NULL;
	ret = DerDecodeSignedCertificate(certdata, &cert);
	if (ret != KMF_OK)
		return (ret);

	if (cert->certificate.extensions.numberOfExtensions == 0)
		return (KMF_ERR_EXTENSION_NOT_FOUND);

	for (i = 0; i < cert->certificate.extensions.numberOfExtensions;
	    i++) {
		eptr = &cert->certificate.extensions.extensions[i];

		if (flag == KMF_CRITICAL_EXTNS && eptr->critical == 0)
			continue;
		else if (flag == KMF_NONCRITICAL_EXTNS && eptr->critical != 0)
			continue;

		(*nextns)++;
		elist = realloc(elist, sizeof (KMF_X509_EXTENSION) *
		    (*nextns));
		if (elist == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}

		ret = copy_extension_data(&elist[(*nextns) - 1], eptr);
		if (ret != KMF_OK)
			goto end;
	}

end:
	kmf_free_signed_cert(cert);
	free(cert);
	if (ret != KMF_OK) {
		if (elist != NULL) {
			free(elist);
			elist = NULL;
		}
		*nextns = 0;
	}

	/*
	 * If the flag is not all, then it is possible that we did not find
	 * any critical or non_critical extensions.  When that happened,
	 * return KMF_ERR_EXTENSION_NOT_FOUND.
	 */
	if (flag != KMF_ALL_EXTNS && ret == KMF_OK && *nextns == 0)
		ret = KMF_ERR_EXTENSION_NOT_FOUND;

	*extlist = elist;
	return (ret);
}

/*
 * If the given certificate data (X.509 DER encoded data)
 * contains the Key Usage extension, parse that
 * data and return it in the KMF_X509EXT_BASICCONSTRAINTS
 * record.
 *
 * RETURNS:
 *  KMF_OK - success
 *  KMF_ERR_BAD_PARAMETER - input data was bad.
 *  KMF_ERR_EXTENSION_NOT_FOUND - extension not found.
 */
KMF_RETURN
kmf_get_cert_ku(const KMF_DATA *certdata,
	KMF_X509EXT_KEY_USAGE *keyusage)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;

	if (certdata == NULL || keyusage == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (extn));
	/*
	 * Check standard KeyUsage bits
	 */
	ret = kmf_get_cert_extn(certdata, (KMF_OID *)&KMFOID_KeyUsage, &extn);

	if (ret != KMF_OK) {
		goto end;
	}
	keyusage->critical = (extn.critical != 0);
	if (extn.value.tagAndValue->value.Length > 1) {
		keyusage->KeyUsageBits =
		    extn.value.tagAndValue->value.Data[1] << 8;
	} else  {
		keyusage->KeyUsageBits = extn.value.tagAndValue->value.Data[0];
	}
end:
	kmf_free_extn(&extn);
	return (ret);
}

KMF_BOOL
is_eku_present(KMF_X509EXT_EKU *ekuptr, KMF_OID *ekuoid)
{
	int i;

	if (ekuptr == NULL || ekuoid == NULL)
		return (0);

	for (i = 0; i < ekuptr->nEKUs; i++)
		if (IsEqualOid(&ekuptr->keyPurposeIdList[i], ekuoid))
			return (1);

	return (0);
}

KMF_RETURN
parse_eku_data(const KMF_DATA *asn1data, KMF_X509EXT_EKU *ekuptr)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue exdata;
	KMF_OID oid;
	char *end = NULL;
	ber_len_t size;

	/*
	 * Decode the ASN.1 data for the extension.
	 */
	exdata.bv_val = (char *)asn1data->Data;
	exdata.bv_len = asn1data->Length;

	if ((asn1 = kmfder_init(&exdata)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	/*
	 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
	 */
	if (kmfber_first_element(asn1, &size, &end) != BER_OBJECT_IDENTIFIER) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}

	/*
	 * Count the number of EKU OIDs and store in
	 * the array.
	 */
	while (kmfber_next_element(asn1, &size, end) ==
	    BER_OBJECT_IDENTIFIER) {

		/* Skip over the CONSTRUCTED SET tag */
		if (kmfber_scanf(asn1, "D", &oid) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
		ekuptr->nEKUs++;
		ekuptr->keyPurposeIdList = realloc(ekuptr->keyPurposeIdList,
		    ekuptr->nEKUs * sizeof (KMF_OID));
		if (ekuptr->keyPurposeIdList == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}
		ekuptr->keyPurposeIdList[ekuptr->nEKUs - 1] = oid;
	}

end:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK) {
		if (ekuptr->keyPurposeIdList != NULL) {
			free_keyidlist(ekuptr->keyPurposeIdList, ekuptr->nEKUs);
			ekuptr->keyPurposeIdList = NULL;
			ekuptr->critical = 0;
		}
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_eku(const KMF_DATA *certdata,
	KMF_X509EXT_EKU *ekuptr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;

	if (certdata == NULL || ekuptr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (KMF_X509_EXTENSION));

	ekuptr->nEKUs = 0;
	ekuptr->keyPurposeIdList = NULL;
	ekuptr->critical = 0;

	ret = kmf_get_cert_extn(certdata,
	    (KMF_OID *)&KMFOID_ExtendedKeyUsage, &extn);

	if (ret != KMF_OK) {
		goto end;
	}

	ret = parse_eku_data(&extn.BERvalue, ekuptr);

end:
	kmf_free_extn(&extn);

	return (ret);
}

/*
 * If the given certificate data (X.509 DER encoded data)
 * contains the Basic Constraints extension, parse that
 * data and return it in the KMF_X509EXT_BASICCONSTRAINTS
 * record.
 *
 * RETURNS:
 *  KMF_OK - success
 *  KMF_ERR_BAD_PARAMETER - input data was bad.
 *  KMF_ERR_EXTENSION_NOT_FOUND - extension not found.
 */
KMF_RETURN
kmf_get_cert_basic_constraint(const KMF_DATA *certdata,
	KMF_BOOL *critical, KMF_X509EXT_BASICCONSTRAINTS *constraint)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	BerElement *asn1 = NULL;
	BerValue exdata;
	ber_len_t size;
	char *end = NULL;
	int tag;

	if (certdata == NULL || constraint == NULL || critical == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (KMF_X509_EXTENSION));
	ret = kmf_get_cert_extn(certdata,
	    (KMF_OID *)&KMFOID_BasicConstraints, &extn);

	if (ret != KMF_OK) {
		goto end;
	}

	*critical = (extn.critical != 0);

	exdata.bv_val = (char *)extn.value.tagAndValue->value.Data;
	exdata.bv_len = extn.value.tagAndValue->value.Length;

	if ((asn1 = kmfder_init(&exdata)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	if (kmfber_scanf(asn1, "b", &constraint->cA) == KMFBER_DEFAULT) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}
	constraint->pathLenConstraintPresent = KMF_FALSE;

	tag = kmfber_next_element(asn1, &size, end);
	if (tag == BER_INTEGER) {
		if (kmfber_scanf(asn1, "i",
		    &constraint->pathLenConstraint) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
		constraint->pathLenConstraintPresent = KMF_TRUE;
	}
end:
	kmf_free_extn(&extn);
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	return (ret);
}

static KMF_X509EXT_POLICYQUALIFIERINFO *
get_pqinfo(BerElement *asn1)
{
	KMF_X509EXT_POLICYQUALIFIERINFO *pqinfo = NULL;
	KMF_RETURN ret = KMF_OK;
	int tag;
	ber_len_t size;
	char *end = NULL;

	/*
	 * Policy Qualifiers may be a list of sequences.
	 *
	 * PolicyInformation ::= SEQUENCE {
	 * 	policyIdentifier   CertPolicyId,
	 * 	policyQualifiers   SEQUENCE SIZE (1..MAX) OF
	 *			PolicyQualifierInfo OPTIONAL
	 * }
	 *
	 * PolicyQualifierInfo ::= SEQUENCE {
	 *	policyQualifierId  PolicyQualifierId,
	 *	qualifier	  ANY DEFINED BY policyQualifierId
	 * }
	 */


	/*
	 * We already got the CertPolicyId, we just need to
	 * find all of the policyQualifiers in the set.
	 *
	 * Mark the first element of the SEQUENCE and reset the end ptr
	 * so the ber/der code knows when to stop looking.
	 */
	if ((tag = kmfber_first_element(asn1, &size, &end)) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}
	/* We found a sequence, loop until done */
	while ((tag = kmfber_next_element(asn1, &size, end)) ==
	    BER_CONSTRUCTED_SEQUENCE) {

		/* Skip over the CONSTRUCTED SET tag */
		if (kmfber_scanf(asn1, "T", &tag) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
		/*
		 * Allocate memory for the Policy Qualifier Info
		 */
		pqinfo = malloc(sizeof (KMF_X509EXT_POLICYQUALIFIERINFO));
		if (pqinfo == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}
		(void) memset((void *)pqinfo, 0,
		    sizeof (KMF_X509EXT_POLICYQUALIFIERINFO));
		/*
		 * Read the PolicyQualifier OID
		 */
		if (kmfber_scanf(asn1, "D",
		    &pqinfo->policyQualifierId) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
		/*
		 * The OID of the policyQualifierId determines what
		 * sort of data comes next.
		 */
		if (IsEqualOid(&pqinfo->policyQualifierId,
		    (KMF_OID *)&KMFOID_PKIX_PQ_CPSuri)) {
			/*
			 * CPS uri must be an IA5STRING
			 */
			if (kmfber_scanf(asn1, "tl", &tag, &size) ==
			    KMFBER_DEFAULT || tag != BER_IA5STRING ||
			    size == 0) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}
			if ((pqinfo->value.Data = malloc(size)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto end;
			}
			if (kmfber_scanf(asn1, "s", pqinfo->value.Data,
			    &pqinfo->value.Length) == KMFBER_DEFAULT) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}
		} else if (IsEqualOid(&pqinfo->policyQualifierId,
		    (KMF_OID *)&KMFOID_PKIX_PQ_Unotice)) {
			if (kmfber_scanf(asn1, "tl", &tag, &size) ==
			    KMFBER_DEFAULT ||
			    tag != BER_CONSTRUCTED_SEQUENCE) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}
			/*
			 * For now, just copy the while UserNotice ASN.1
			 * blob into the pqinfo data record.
			 * TBD - parse it into individual fields.
			 */
			if ((pqinfo->value.Data = malloc(size)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto end;
			}
			if (kmfber_scanf(asn1, "s", pqinfo->value.Data,
			    &pqinfo->value.Length) == KMFBER_DEFAULT) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}
		} else {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
	}
end:
	if (ret != KMF_OK) {
		if (pqinfo != NULL) {
			kmf_free_data(&pqinfo->value);
			kmf_free_data(&pqinfo->policyQualifierId);
			free(pqinfo);
			pqinfo = NULL;
		}
	}
	return (pqinfo);
}

/*
 * If the given certificate data (X.509 DER encoded data)
 * contains the Certificate Policies extension, parse that
 * data and return it in the KMF_X509EXT_CERT_POLICIES
 * record.
 *
 * RETURNS:
 *  KMF_OK - success
 *  KMF_ERR_BAD_PARAMETER - input data was bad.
 *  KMF_ERR_EXTENSION_NOT_FOUND - extension not found.
 *  parsing and memory allocation errors are also possible.
 */
KMF_RETURN
kmf_get_cert_policies(const KMF_DATA *certdata,
	KMF_BOOL *critical, KMF_X509EXT_CERT_POLICIES *extptr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	KMF_X509EXT_POLICYINFO	*pinfo;
	KMF_X509EXT_POLICYQUALIFIERINFO *pqinfo;
	BerElement *asn1 = NULL;
	BerValue exdata;
	ber_len_t size;
	char *end = NULL;
	int tag;

	if (certdata == NULL || critical == NULL || extptr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (extn));
	ret = kmf_get_cert_extn(certdata,
	    (KMF_OID *)&KMFOID_CertificatePolicies, &extn);

	if (ret != KMF_OK) {
		goto end;
	}

	*critical = (extn.critical != 0);

	/*
	 * Decode the ASN.1 data for the extension.
	 */
	exdata.bv_val = (char *)extn.BERvalue.Data;
	exdata.bv_len = extn.BERvalue.Length;

	(void) memset((void *)extptr, 0, sizeof (KMF_X509EXT_CERT_POLICIES));

	if ((asn1 = kmfder_init(&exdata)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	/*
	 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
	 */
	if ((tag = kmfber_first_element(asn1, &size, &end)) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}

	/*
	 * Collect all of the PolicyInformation SEQUENCES
	 *
	 * PolicyInformation ::= SEQUENCE {
	 * 	policyIdentifier   CertPolicyId,
	 * 	policyQualifiers   SEQUENCE SIZE (1..MAX) OF
	 *			PolicyQualifierInfo OPTIONAL
	 * }
	 *
	 * Loop over the SEQUENCES of PolicyInfo
	 */
	while ((tag = kmfber_next_element(asn1, &size, end)) ==
	    BER_CONSTRUCTED_SEQUENCE) {

		/* Skip over the CONSTRUCTED SET tag */
		if (kmfber_scanf(asn1, "T", &tag) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}

		pinfo = malloc(sizeof (KMF_X509EXT_POLICYINFO));
		if (pinfo == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}
		(void) memset((void *)pinfo, 0,
		    sizeof (KMF_X509EXT_POLICYINFO));
		/*
		 * Decode the PolicyInformation SEQUENCE
		 */
		if ((tag = kmfber_scanf(asn1, "D",
		    &pinfo->policyIdentifier)) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}
		/*
		 * Gather all of the associated PolicyQualifierInfo recs
		 */
		pqinfo = get_pqinfo(asn1);
		if (pqinfo != NULL) {
			int cnt =
			    pinfo->policyQualifiers.numberOfPolicyQualifiers;
			cnt++;
			pinfo->policyQualifiers.policyQualifier = realloc(
			    pinfo->policyQualifiers.policyQualifier,
			    cnt * sizeof (KMF_X509EXT_POLICYQUALIFIERINFO));
			if (pinfo->policyQualifiers.policyQualifier == NULL) {
				ret = KMF_ERR_MEMORY;
				goto end;
			}
			pinfo->policyQualifiers.numberOfPolicyQualifiers = cnt;
			pinfo->policyQualifiers.policyQualifier[cnt-1] =
			    *pqinfo;

			free(pqinfo);
		}
		extptr->numberOfPolicyInfo++;
		extptr->policyInfo = realloc(extptr->policyInfo,
		    extptr->numberOfPolicyInfo *
		    sizeof (KMF_X509EXT_POLICYINFO));
		if (extptr->policyInfo == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}
		extptr->policyInfo[extptr->numberOfPolicyInfo-1] = *pinfo;
		free(pinfo);
	}


end:
	kmf_free_extn(&extn);
	if (asn1 != NULL)
		kmfber_free(asn1, 1);
	return (ret);
}

/*
 * If the given certificate data (X.509 DER encoded data)
 * contains the Authority Information Access extension, parse that
 * data and return it in the KMF_X509EXT_AUTHINFOACCESS
 * record.
 *
 * RETURNS:
 *  KMF_OK - success
 *  KMF_ERR_BAD_PARAMETER - input data was bad.
 *  KMF_ERR_EXTENSION_NOT_FOUND - extension not found.
 */
KMF_RETURN
kmf_get_cert_auth_info_access(const KMF_DATA *certdata,
	KMF_X509EXT_AUTHINFOACCESS *aia)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	BerElement *asn1 = NULL;
	BerValue exdata;
	ber_len_t size;
	char *end = NULL;
	int tag;
	KMF_X509EXT_ACCESSDESC *access_info = NULL;

	if (certdata == NULL || aia == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	(void) memset(&extn, 0, sizeof (KMF_X509_EXTENSION));
	ret = kmf_get_cert_extn(certdata,
	    (KMF_OID *)&KMFOID_AuthorityInfoAccess, &extn);

	if (ret != KMF_OK) {
		goto end;
	}

	/*
	 * Decode the ASN.1 data for the extension.
	 */
	exdata.bv_val = (char *)extn.BERvalue.Data;
	exdata.bv_len = extn.BERvalue.Length;

	(void) memset((void *)aia, 0, sizeof (KMF_X509EXT_AUTHINFOACCESS));

	if ((asn1 = kmfder_init(&exdata)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	/*
	 * AuthorityInfoAccessSyntax  ::=
	 *	SEQUENCE SIZE (1..MAX) OF AccessDescription
	 */
	if ((tag = kmfber_first_element(asn1, &size, &end)) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}

	/*
	 * AccessDescription  ::=  SEQUENCE {
	 *	accessMethod	OBJECT IDENTIFIER,
	 *	accessLocation	GeneralName  }
	 */
	while ((tag = kmfber_next_element(asn1, &size, end)) ==
	    BER_CONSTRUCTED_SEQUENCE) {

		/* Skip over the CONSTRUCTED SET tag */
		if (kmfber_scanf(asn1, "T", &tag) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}

		access_info = malloc(sizeof (KMF_X509EXT_ACCESSDESC));
		if (access_info == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}

		(void) memset((void *)access_info, 0,
		    sizeof (KMF_X509EXT_ACCESSDESC));

		/*
		 * Read the AccessMethod OID
		 */
		if (kmfber_scanf(asn1, "D",
		    &access_info->AccessMethod) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}

		/*
		 * The OID of the AccessMethod determines what
		 * sort of data comes next.
		 */
		if (IsEqualOid(&access_info->AccessMethod,
		    (KMF_OID *)&KMFOID_PkixAdOcsp)) {
			if (kmfber_scanf(asn1, "tl", &tag, &size) ==
			    KMFBER_DEFAULT || size == 0) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}

			/*
			 * OCSP uri must be an IA5STRING or a GENNAME_URI
			 * with an implicit tag.
			 */
			if (tag != BER_IA5STRING &&
			    tag != (0x80 | GENNAME_URI)) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}

			if ((access_info->AccessLocation.Data =
			    malloc(size)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto end;
			}

			if (kmfber_scanf(asn1, "s",
			    access_info->AccessLocation.Data,
			    &access_info->AccessLocation.Length) ==
			    KMFBER_DEFAULT) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto end;
			}
		} else if (IsEqualOid(&access_info->AccessMethod,
		    (KMF_OID *)&KMFOID_PkixAdCaIssuers)) {
			/* will be supported later with PKIX */
			free(access_info);
			access_info = NULL;
			continue;
		} else {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto end;
		}

		aia->numberOfAccessDescription++;
		aia->AccessDesc = realloc(aia->AccessDesc,
		    aia->numberOfAccessDescription *
		    sizeof (KMF_X509EXT_ACCESSDESC));

		if (aia->AccessDesc == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}

		aia->AccessDesc[aia->numberOfAccessDescription-1] =
		    *access_info;
		free(access_info);
		access_info = NULL;
	}

end:
	kmf_free_extn(&extn);
	if (access_info != NULL)
		free(access_info);
	if (asn1 != NULL)
		kmfber_free(asn1, 1);
	return (ret);

}

/*
 * This function parses the name portion of a der-encoded distribution point
 * returns it in the KMF_CRL_DIST_POINT record.
 *
 * The "DistributionPointName" syntax is
 *
 *   DistributionPointName ::= CHOICE {
 *	fullName                [0]     GeneralNames,
 *	nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 *
 *   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GerneralName
 *
 * Note: for phase 1, we support fullName only.
 */
static KMF_RETURN
parse_dp_name(char *dp_der_code, int dp_der_size, KMF_CRL_DIST_POINT *dp)
{
	KMF_RETURN ret = KMF_OK;
	char *url = NULL;
	BerElement *asn1 = NULL;
	BerValue ber_data;
	ber_len_t size;
	char *end = NULL;
	int tag;
	KMF_GENERALNAMES *fullname;

	if (dp_der_code == NULL || dp_der_size == 0 || dp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ber_data.bv_val = dp_der_code;
	ber_data.bv_len = dp_der_size;
	if ((asn1 = kmfder_init(&ber_data)) == NULL)
		return (KMF_ERR_BAD_CERT_FORMAT);

	tag = kmfber_first_element(asn1, &size, &end);
	if (tag != 0xA0 && tag != 0xA1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

	if (tag == 0xA0) { /* fullName */
		dp->type = DP_GENERAL_NAME;

		fullname = &(dp->name.full_name);
		fullname->number = 0;

		/* Skip over the explicit tag and size */
		(void) kmfber_scanf(asn1, "T", &tag);

		tag = kmfber_next_element(asn1, &size, end);
		while (tag != KMFBER_DEFAULT &&
		    tag != KMFBER_END_OF_SEQORSET) {

			if (kmfber_scanf(asn1, "tl", &tag, &size) ==
			    KMFBER_DEFAULT || size == 0) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto out;
			}

			/* For phase 1, we are interested in a URI name only */
			if (tag != (0x80 | GENNAME_URI)) {
				tag = kmfber_next_element(asn1, &size, end);
				continue;
			}

			if ((url = malloc(size)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto out;
			}

			/* Skip type and len, then read url and save it. */
			if (kmfber_read(asn1, url, 2) != 2) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto out;
			}

			if (kmfber_read(asn1, url, size) !=
			    (ber_slen_t)size) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto out;
			}

			fullname->number++;
			fullname->namelist = realloc(fullname->namelist,
			    fullname->number * sizeof (KMF_GENERALNAME));
			if (fullname->namelist == NULL) {
				ret = KMF_ERR_MEMORY;
				goto out;
			}

			fullname->namelist[fullname->number - 1].choice =
			    GENNAME_URI;
			fullname->namelist[fullname->number - 1].name.Length =
			    size;
			fullname->namelist[fullname->number - 1].name.Data =
			    (unsigned char *)url;

			/* next */
			tag = kmfber_next_element(asn1, &size, end);
		}

	} else if (tag == 0xA1) {
		/* "nameRelativeToCRLIssuer" is not supported at phase 1. */
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

out:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK) {
		free_dp_name(dp);
	}

	if (ret == KMF_OK && fullname->number == 0) {
		ret = KMF_ERR_EXTENSION_NOT_FOUND;
		if (url != NULL)
			free(url);
	}

	return (ret);
}

/*
 * This function retrieves the CRL Distribution Points extension data from
 * a DER encoded certificate if it contains this extension, parses the
 * extension data, and returns it in the KMF_X509EXT_CRLDISTPOINTS record.
 */
KMF_RETURN
kmf_get_cert_crl_dist_pts(const KMF_DATA *certdata,
	KMF_X509EXT_CRLDISTPOINTS *crl_dps)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	BerElement *asn1 = NULL;
	BerValue exdata;
	ber_len_t size;
	char *end = NULL;
	int tag;
	KMF_CRL_DIST_POINT *dp = NULL;
	int i;

	if (certdata == NULL || crl_dps == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* Get the ASN.1 data for this extension. */
	(void) memset(&extn, 0, sizeof (KMF_X509_EXTENSION));
	ret = kmf_get_cert_extn(certdata,
	    (KMF_OID *)&KMFOID_CrlDistributionPoints, &extn);
	if (ret != KMF_OK) {
		return (ret);
	}

	/*
	 * Decode the CRLDistributionPoints ASN.1 data. The Syntax for
	 * CRLDistributionPoints is
	 *
	 * CRLDistributionPoints ::=
	 *	SEQUENCE SIZE (1..MAX) OF DistributionPoint
	 *
	 * DistributionPoint ::= SEQUENCE {
	 *	distributionPoint	[0]	DistributionPointName OPTIONAL,
	 *	reasons			[1]	ReasonFlags OPTIONAL,
	 *	cRLIssuer		[2]	GeneralNames OPTIONAL }
	 */

	exdata.bv_val = (char *)extn.BERvalue.Data;
	exdata.bv_len = extn.BERvalue.Length;
	if ((asn1 = kmfder_init(&exdata)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	if ((tag = kmfber_first_element(asn1, &size, &end)) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

	(void) memset((void *)crl_dps, 0, sizeof (KMF_X509EXT_CRLDISTPOINTS));

	while ((tag = kmfber_next_element(asn1, &size, end)) ==
	    BER_CONSTRUCTED_SEQUENCE) {
		boolean_t has_name = B_FALSE;
		boolean_t has_issuer = B_FALSE;

		/* Skip over the CONSTRUCTED SET tag */
		if (kmfber_scanf(asn1, "T", &tag) == KMFBER_DEFAULT) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto out;
		}

		tag = kmfber_next_element(asn1, &size, end);
		if (tag != 0xA0 && tag != 0xA1 && tag != 0xA2)
			goto out;

		if ((dp = malloc(sizeof (KMF_CRL_DIST_POINT))) == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}
		(void) memset((void *)dp, 0, sizeof (KMF_CRL_DIST_POINT));

		if (tag == 0xA0) { /* distributionPoint Name */
			char *name_der;
			int name_size = size + 2;

			if ((name_der = malloc(name_size)) == NULL) {
				ret = KMF_ERR_MEMORY;
				free(dp);
				dp = NULL;
				goto out;
			}

			if (kmfber_read(asn1, name_der, name_size) !=
			    (ber_slen_t)(name_size)) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				free(name_der);
				free(dp);
				dp = NULL;
				goto out;
			}
			has_name = B_TRUE;

			ret = parse_dp_name(name_der, name_size, dp);
			free(name_der);
			if (ret != KMF_OK) {
				free(dp);
				dp = NULL;
				goto out;
			}

			/* next field */
			tag = kmfber_next_element(asn1, &size, end);
		}

		if (tag == 0XA1) { /* reasons */
			char *bit_string;
			int len;

			if (kmfber_scanf(asn1, "B", &bit_string, &len) !=
			    BER_BIT_STRING) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				free(dp);
				dp = NULL;
				goto out;
			}

			dp->reasons.Length = len / 8;
			if ((dp->reasons.Data = malloc(dp->reasons.Length)) ==
			    NULL) {
				ret = KMF_ERR_MEMORY;
				free(dp);
				dp = NULL;
				goto out;
			}
			(void) memcpy(dp->reasons.Data, (uchar_t *)bit_string,
			    dp->reasons.Length);

			/* next field */
			tag = kmfber_next_element(asn1, &size, end);
		}

		if (tag == 0XA2) { /* cRLIssuer */
			char *issuer_der = NULL;
			int issuer_size;

			/* For cRLIssuer, read the data only at phase 1 */
			issuer_size = size + 2;
			issuer_der = malloc(issuer_size);
			if (issuer_der == NULL) {
				ret = KMF_ERR_MEMORY;
				free(dp);
				dp = NULL;
				goto out;
			}

			if (kmfber_read(asn1, issuer_der, issuer_size) !=
			    (ber_slen_t)(issuer_size)) {
				free(issuer_der);
				ret = KMF_ERR_BAD_CERT_FORMAT;
				free(dp);
				dp = NULL;
				goto out;
			}

			has_issuer = B_TRUE;
			free(issuer_der);
		}

		/* A distribution point cannot have a "reasons" field only. */
		if (has_name == B_FALSE && has_issuer == B_FALSE) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			free_dp(dp);
			free(dp);
			dp = NULL;
			goto out;
		}

		/*
		 * Although it is legal that a distributioon point contains
		 * a cRLIssuer field only, with or without "reasons", we will
		 * skip it if the name field is not presented for phase 1.
		 */
		if (has_name == B_FALSE) {
			free_dp(dp);
		} else {
			crl_dps->number++;
			crl_dps->dplist = realloc(crl_dps->dplist,
			    crl_dps->number * sizeof (KMF_CRL_DIST_POINT));
			if (crl_dps->dplist == NULL) {
				ret = KMF_ERR_MEMORY;
				free_dp(dp);
				free(dp);
				dp = NULL;
				goto out;
			}
			crl_dps->dplist[crl_dps->number - 1] = *dp;
			/* free the dp itself since we just used its contents */
		}
		if (dp != NULL) {
			free(dp);
			dp = NULL;
		}
	}

out:
	kmf_free_extn(&extn);

	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK) {
		for (i = 0; i < crl_dps->number; i++)
			free_dp(&(crl_dps->dplist[i]));
		free(crl_dps->dplist);
	}

	if (ret == KMF_OK && crl_dps->number == 0) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
	}

	return (ret);
}

static KMF_RETURN
KMF_CertGetPrintable(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
	KMF_PRINTABLE_ITEM flag, char *resultStr)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN (*getPrintableFn)(void *, const KMF_DATA *,
	    KMF_PRINTABLE_ITEM, char *);
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || resultStr == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/*
	 * This framework function is actually implemented in the openssl
	 * plugin library, so we find the function address and call it.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	getPrintableFn = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "OpenSSL_CertGetPrintable");
	if (getPrintableFn == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	return (getPrintableFn(handle, SignedCert, flag, resultStr));
}

KMF_RETURN
kmf_get_cert_version_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_VERSION,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}


KMF_RETURN
kmf_get_cert_subject_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_SUBJECT,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);

}

KMF_RETURN
kmf_get_cert_issuer_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_ISSUER,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_serial_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_SERIALNUM,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_start_date_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_NOTBEFORE,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_end_date_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
	char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_NOTAFTER,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_pubkey_alg_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_PUBKEY_ALG,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_sig_alg_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_SIGNATURE_ALG,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_pubkey_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_PUBKEY_DATA,
	    tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_email_str(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
	char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignedCert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, SignedCert, KMF_CERT_EMAIL, tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

/*
 * Given a certificate (DER Encoded data) and a KMF
 * extension identifier constant (e.g. KMF_X509_EXT_*),
 * return a human readable interpretation of the
 * extension data.
 *
 * The string will be a maximum of KMF_CERT_PRINTABLE_LEN
 * bytes long.  The string is allocated locally and
 * must be freed by the caller.
 */
KMF_RETURN
kmf_get_cert_extn_str(KMF_HANDLE_T handle, const KMF_DATA *cert,
	KMF_PRINTABLE_ITEM extension, char **result)
{
	KMF_RETURN ret;
	char *tmpstr;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (cert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	tmpstr = malloc(KMF_CERT_PRINTABLE_LEN);
	if (tmpstr == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(tmpstr, 0, KMF_CERT_PRINTABLE_LEN);

	ret = KMF_CertGetPrintable(handle, cert, extension, tmpstr);

	if (ret == KMF_OK) {
		*result = tmpstr;
	} else {
		free(tmpstr);
		*result = NULL;
	}

	return (ret);
}

KMF_RETURN
kmf_get_cert_id_data(const KMF_DATA *SignedCert, KMF_DATA *ID)
{
	KMF_RETURN ret;
	KMF_X509_CERTIFICATE *cert = NULL;

	if (SignedCert == NULL || ID == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = DerDecodeSignedCertificate(SignedCert, &cert);
	if (ret != KMF_OK)
		return (ret);

	ret = GetIDFromSPKI(&cert->certificate.subjectPublicKeyInfo, ID);

	kmf_free_signed_cert(cert);
	free(cert);
	return (ret);
}

KMF_RETURN
kmf_get_cert_id_str(const KMF_DATA *SignedCert,	char **idstr)
{
	KMF_RETURN ret;
	KMF_DATA ID = { 0, NULL };
	char tmpstr[256];
	int i;

	if (SignedCert == NULL || idstr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = kmf_get_cert_id_data(SignedCert, &ID);
	if (ret != KMF_OK) {
		kmf_free_data(&ID);
		return (ret);
	}

	(void) memset(tmpstr, 0, sizeof (tmpstr));
	for (i = 0; i < ID.Length; i++) {
		int len = strlen(tmpstr);
		(void) snprintf(&tmpstr[len], sizeof (tmpstr) -  len,
		    "%02x", (uchar_t)ID.Data[i]);
		if ((i+1) < ID.Length)
			(void) strcat(tmpstr, ":");
	}
	*idstr = strdup(tmpstr);
	if ((*idstr) == NULL)
		ret = KMF_ERR_MEMORY;

	kmf_free_data(&ID);

	return (ret);
}


/*
 * This function gets the time_t values of the notbefore and notafter dates
 * from a der-encoded certificate.
 */
KMF_RETURN
kmf_get_cert_validity(const KMF_DATA *cert, time_t *not_before,
    time_t *not_after)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_CERTIFICATE *certData = NULL;
	struct tm tm_tmp;
	time_t t_notbefore;
	time_t t_notafter;
	unsigned char *not_before_str;
	unsigned char *not_after_str;

	if (cert == NULL || not_before == NULL || not_after == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = DerDecodeSignedCertificate(cert, &certData);
	if (rv != KMF_OK)
		return (rv);

	/* Get notBefore */
	not_before_str = certData->certificate.validity.notBefore.time.Data;
	if (strptime((const char *)not_before_str, "%y %m %d %H %M %S",
	    &tm_tmp) == NULL) {
		rv = KMF_ERR_VALIDITY_PERIOD;
		goto out;
	}

	errno = 0;
	if (((t_notbefore = mktime(&tm_tmp)) == (time_t)(-1)) &&
	    errno == EOVERFLOW) {
		rv = KMF_ERR_VALIDITY_PERIOD;
		goto out;
	}
	*not_before = t_notbefore;

	/* Get notAfter */
	not_after_str = certData->certificate.validity.notAfter.time.Data;
	if (strptime((const char *)not_after_str, "%y %m %d %H %M %S",
	    &tm_tmp) == NULL) {
		rv = KMF_ERR_VALIDITY_PERIOD;
		goto out;
	}

	errno = 0;
	if (((t_notafter = mktime(&tm_tmp)) == (time_t)(-1)) &&
	    errno == EOVERFLOW) {
		rv = KMF_ERR_VALIDITY_PERIOD;
		goto out;
	}
	*not_after = t_notafter;

out:
	if (certData != NULL) {
		kmf_free_signed_cert(certData);
		free(certData);
	}

	return (rv);
}

KMF_RETURN
kmf_set_cert_pubkey(KMF_HANDLE_T handle,
	KMF_KEY_HANDLE *KMFKey,
	KMF_X509_CERTIFICATE *Cert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_SPKI *spki_ptr;
	KMF_PLUGIN *plugin;
	KMF_DATA KeyData = { 0, NULL };

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (KMFKey == NULL || Cert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* The keystore must extract the pubkey data */
	plugin = FindPlugin(handle, KMFKey->kstype);
	if (plugin != NULL && plugin->funclist->EncodePubkeyData != NULL) {
		ret = plugin->funclist->EncodePubkeyData(handle,
		    KMFKey, &KeyData);
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	spki_ptr = &Cert->certificate.subjectPublicKeyInfo;

	if (KeyData.Data != NULL) {
		ret = DerDecodeSPKI(&KeyData, spki_ptr);
		free(KeyData.Data);
	}

	return (ret);
}

KMF_RETURN
kmf_set_cert_subject(KMF_X509_CERTIFICATE *CertData,
	KMF_X509_NAME *subject_name_ptr)
{

	KMF_RETURN rv = KMF_OK;
	KMF_X509_NAME *temp_name_ptr = NULL;

	if (CertData != NULL && subject_name_ptr != NULL) {
		rv = CopyRDN(subject_name_ptr, &temp_name_ptr);
		if (rv == KMF_OK) {
			CertData->certificate.subject = *temp_name_ptr;
		}
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}
	return (rv);
}

KMF_RETURN
set_key_usage_extension(KMF_X509_EXTENSIONS *extns,
	int critical, uint32_t bits)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	BerElement *asn1 = NULL;
	BerValue *extdata;
	int bitlen, i;
	uint16_t kubits = (uint16_t)(bits & 0x0000ffff);

	if (extns == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (extn));
	ret = copy_data(&extn.extnId, (KMF_OID *)&KMFOID_KeyUsage);
	if (ret != KMF_OK)
		return (ret);
	extn.critical = critical;
	extn.format = KMF_X509_DATAFORMAT_ENCODED;

	for (i = 7; i <= 15 && !(kubits & (1 << i)); i++)
		/* empty body */
		;

	bitlen = 16 - i;

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	kubits = htons(kubits);
	if (kmfber_printf(asn1, "B", (char *)&kubits, bitlen) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}
	if (kmfber_flatten(asn1, &extdata) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	extn.BERvalue.Data = (uchar_t *)extdata->bv_val;
	extn.BERvalue.Length = extdata->bv_len;

	free(extdata);

	ret = add_an_extension(extns, &extn);
	if (ret != KMF_OK) {
		free(extn.BERvalue.Data);
	}
out:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	return (ret);
}

KMF_RETURN
kmf_set_cert_ku(KMF_X509_CERTIFICATE *CertData,
	int critical, uint16_t kubits)
{
	KMF_RETURN ret = KMF_OK;

	if (CertData == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = set_key_usage_extension(&CertData->certificate.extensions,
	    critical, kubits);

	return (ret);
}

KMF_RETURN
kmf_set_cert_issuer(KMF_X509_CERTIFICATE *CertData,
	KMF_X509_NAME *issuer_name_ptr)
{

	KMF_RETURN rv = KMF_OK;
	KMF_X509_NAME *temp_name_ptr = NULL;

	if (CertData != NULL && issuer_name_ptr != NULL) {
		rv = CopyRDN(issuer_name_ptr, &temp_name_ptr);
		if (rv == KMF_OK) {
			CertData->certificate.issuer = *temp_name_ptr;
		}
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}

	return (rv);
}

KMF_RETURN
kmf_set_cert_sig_alg(KMF_X509_CERTIFICATE *CertData,
	KMF_ALGORITHM_INDEX sigAlg)
{
	KMF_OID	*alg;

	if (CertData == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	alg = x509_algid_to_algoid(sigAlg);

	if (alg != NULL) {
		(void) copy_data((KMF_DATA *)
		    &CertData->certificate.signature.algorithm,
		    (KMF_DATA *)alg);
		(void) copy_data(&CertData->certificate.signature.parameters,
		    &CertData->certificate.subjectPublicKeyInfo.algorithm.
		    parameters);

		(void) copy_data(
		    &CertData->signature.algorithmIdentifier.algorithm,
		    &CertData->certificate.signature.algorithm);
		(void) copy_data(
		    &CertData->signature.algorithmIdentifier.parameters,
		    &CertData->certificate.signature.parameters);
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}

	return (KMF_OK);
}

KMF_RETURN
kmf_set_cert_validity(KMF_X509_CERTIFICATE *CertData,
	time_t notBefore, uint32_t delta)
{
	time_t		clock;
	struct tm	*gmt;
	char 		szNotBefore[256];
	char		szNotAfter[256];

	if (CertData == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Set up validity fields */
	if (notBefore == NULL)
		clock = time(NULL);
	else
		clock = notBefore;

	gmt = gmtime(&clock);  /* valid starting today */

	/* Build the format in 2 parts so SCCS doesn't get confused */
	(void) strftime(szNotBefore, sizeof (szNotBefore),
	    "%y%m%d%H" "%M00Z", gmt);

	CertData->certificate.validity.notBefore.timeType = BER_UTCTIME;
	CertData->certificate.validity.notBefore.time.Length =
	    strlen((char *)szNotBefore);
	CertData->certificate.validity.notBefore.time.Data =
	    (uchar_t *)strdup(szNotBefore);

	clock += delta;
	gmt = gmtime(&clock);

	/* Build the format in 2 parts so SCCS doesn't get confused */
	(void) strftime(szNotAfter, sizeof (szNotAfter),
	    "%y%m%d%H" "%M00Z", gmt);

	CertData->certificate.validity.notAfter.timeType = BER_UTCTIME;
	CertData->certificate.validity.notAfter.time.Length =
	    strlen((char *)szNotAfter);
	CertData->certificate.validity.notAfter.time.Data =
	    (uchar_t *)strdup(szNotAfter);

	return (KMF_OK);
}

/*
 * Utility routine to set Integer values in the Certificate template
 * for things like serialNumber and Version. The data structure
 * expects pointers, not literal values, so we must allocate
 * and copy here.  Don't use memory from the stack since this data
 * is freed later and that would be bad.
 */
KMF_RETURN
set_integer(KMF_DATA *data, void *value, int length)
{
	if (data == NULL || value == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	data->Data = malloc(length);
	if (data->Data == NULL)
		return (KMF_ERR_MEMORY);

	data->Length = length;
	(void) memcpy((void *)data->Data, (const void *)value, length);

	return (KMF_OK);
}

static KMF_RETURN
set_bigint(KMF_BIGINT *data, KMF_BIGINT *bigint)
{
	if (data == NULL || bigint == NULL || bigint->len == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	data->val = malloc(bigint->len);
	if (data->val == NULL)
		return (KMF_ERR_MEMORY);

	data->len = bigint->len;

	(void) memcpy((void *)data->val, bigint->val, bigint->len);

	return (KMF_OK);

}

KMF_RETURN
kmf_set_cert_serial(KMF_X509_CERTIFICATE *CertData,
	KMF_BIGINT *serno)
{
	if (CertData == NULL || serno == NULL || serno->len == 0)
		return (KMF_ERR_BAD_PARAMETER);
	return (set_bigint(&CertData->certificate.serialNumber, serno));
}

KMF_RETURN
kmf_set_cert_version(KMF_X509_CERTIFICATE *CertData,
	uint32_t version)
{
	if (CertData == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	/*
	 * From RFC 3280:
	 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */
	if (version != 0 && version != 1 && version != 2)
		return (KMF_ERR_BAD_PARAMETER);
	return (set_integer(&CertData->certificate.version, (void *)&version,
	    sizeof (uint32_t)));
}

KMF_RETURN
kmf_set_cert_issuer_altname(KMF_X509_CERTIFICATE *CertData,
	int critical,
	KMF_GENERALNAMECHOICES nametype,
	char *namedata)
{
	if (CertData == NULL || namedata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	return (kmf_set_altname(&CertData->certificate.extensions,
	    (KMF_OID *)&KMFOID_IssuerAltName, critical, nametype, namedata));
}

KMF_RETURN
kmf_set_cert_subject_altname(KMF_X509_CERTIFICATE *CertData,
	int critical,
	KMF_GENERALNAMECHOICES nametype,
	char *namedata)
{
	if (CertData == NULL || namedata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	return (kmf_set_altname(&CertData->certificate.extensions,
	    (KMF_OID *)&KMFOID_SubjectAltName, critical, nametype, namedata));
}

KMF_RETURN
kmf_add_cert_eku(KMF_X509_CERTIFICATE *CertData, KMF_OID *ekuOID,
	int critical)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION *foundextn;
	KMF_X509_EXTENSION newextn;
	BerElement *asn1 = NULL;
	BerValue *extdata = NULL;
	char *olddata = NULL;
	size_t oldsize = 0;
	KMF_X509EXT_EKU ekudata;

	if (CertData == NULL || ekuOID == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&ekudata, 0, sizeof (KMF_X509EXT_EKU));
	(void) memset(&newextn, 0, sizeof (newextn));

	foundextn = FindExtn(&CertData->certificate.extensions,
	    (KMF_OID *)&KMFOID_ExtendedKeyUsage);
	if (foundextn != NULL) {
		ret = GetSequenceContents((char *)foundextn->BERvalue.Data,
		    foundextn->BERvalue.Length,	&olddata, &oldsize);
		if (ret != KMF_OK)
			goto out;

		/*
		 * If the EKU is already in the cert, then just return OK.
		 */
		ret = parse_eku_data(&foundextn->BERvalue, &ekudata);
		if (ret == KMF_OK) {
			if (is_eku_present(&ekudata, ekuOID)) {
				goto out;
			}
		}
	}
	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/* Write the old extension data first */
	if (olddata != NULL && oldsize > 0) {
		if (kmfber_write(asn1, olddata, oldsize, 0) == -1) {
			ret = KMF_ERR_ENCODING;
			goto out;
		}
	}

	/* Append this EKU OID and close the sequence */
	if (kmfber_printf(asn1, "D}", ekuOID) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	if (kmfber_flatten(asn1, &extdata) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/*
	 * If we are just adding to an existing list of EKU OIDs,
	 * just replace the BER data associated with the found extension.
	 */
	if (foundextn != NULL) {
		free(foundextn->BERvalue.Data);
		foundextn->critical = critical;
		foundextn->BERvalue.Data = (uchar_t *)extdata->bv_val;
		foundextn->BERvalue.Length = extdata->bv_len;
	} else {
		ret = copy_data(&newextn.extnId,
		    (KMF_DATA *)&KMFOID_ExtendedKeyUsage);
		if (ret != KMF_OK)
			goto out;
		newextn.critical = critical;
		newextn.format = KMF_X509_DATAFORMAT_ENCODED;
		newextn.BERvalue.Data = (uchar_t *)extdata->bv_val;
		newextn.BERvalue.Length = extdata->bv_len;
		ret = kmf_set_cert_extn(CertData, &newextn);
		if (ret != KMF_OK)
			free(newextn.BERvalue.Data);
	}

out:
	kmf_free_eku(&ekudata);
	if (extdata != NULL)
		free(extdata);

	if (olddata != NULL)
		free(olddata);

	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK)
		kmf_free_data(&newextn.extnId);

	return (ret);
}

KMF_RETURN
kmf_set_cert_extn(KMF_X509_CERTIFICATE *CertData,
	KMF_X509_EXTENSION *extn)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSIONS *exts;

	if (CertData == NULL || extn == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	exts = &CertData->certificate.extensions;

	ret = add_an_extension(exts, extn);

	return (ret);
}

KMF_RETURN
kmf_set_cert_basic_constraint(KMF_X509_CERTIFICATE *CertData,
	KMF_BOOL critical, KMF_X509EXT_BASICCONSTRAINTS *constraint)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION extn;
	BerElement *asn1 = NULL;
	BerValue *extdata;

	if ((CertData == NULL) || (constraint == NULL))
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&extn, 0, sizeof (extn));
	ret = copy_data(&extn.extnId, (KMF_OID *)&KMFOID_BasicConstraints);
	if (ret != KMF_OK)
		return (ret);
	extn.critical = critical;
	extn.format = KMF_X509_DATAFORMAT_ENCODED;

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	if (kmfber_printf(asn1, "b", constraint->cA) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	if (constraint->pathLenConstraintPresent) {
		/* Write the pathLenConstraint value */
		if (kmfber_printf(asn1, "i",
		    constraint->pathLenConstraint) == -1) {
			ret = KMF_ERR_ENCODING;
			goto out;
		}
	}

	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	if (kmfber_flatten(asn1, &extdata) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	extn.BERvalue.Data = (uchar_t *)extdata->bv_val;
	extn.BERvalue.Length = extdata->bv_len;

	free(extdata);
	ret = kmf_set_cert_extn(CertData, &extn);
	if (ret != KMF_OK) {
		free(extn.BERvalue.Data);
	}

out:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	return (ret);
}


/*
 * Phase 1 APIs still needed to maintain compat with elfsign.
 */
KMF_RETURN
KMF_GetCertSubjectNameString(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	return (kmf_get_cert_subject_str(handle, SignedCert, result));
}

KMF_RETURN
KMF_GetCertIssuerNameString(KMF_HANDLE_T handle, const KMF_DATA *SignedCert,
    char **result)
{
	return (kmf_get_cert_issuer_str(handle, SignedCert, result));
}

KMF_RETURN
KMF_GetCertIDString(const KMF_DATA *SignedCert,	char **idstr)
{
	return (kmf_get_cert_id_str(SignedCert, idstr));
}

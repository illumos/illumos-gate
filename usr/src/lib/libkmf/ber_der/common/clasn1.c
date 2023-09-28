/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1995-1999 Intel Corporation. All rights reserved.
 */

#include <strings.h>
#include <kmftypes.h>
#include <ber_der.h>
#include <kmfber_int.h>
#include <kmfapi.h>
#include <kmfapiP.h>

#include <stdio.h>

#define	DSA_RAW_SIG_LEN	40

static uint8_t OID_ExtensionRequest[] = { OID_PKCS_9, 14 };
const KMF_OID extension_request_oid = {OID_PKCS_9_LENGTH + 1,
	OID_ExtensionRequest};

static KMF_RETURN
encode_algoid(BerElement *asn1, KMF_X509_ALGORITHM_IDENTIFIER *algoid,
    boolean_t encode_params)
{
	KMF_RETURN ret = KMF_OK;

	if (kmfber_printf(asn1, "{D", &algoid->algorithm) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
	}
	if (!encode_params) {
		if (kmfber_printf(asn1, "}") == -1)
			return (KMF_ERR_BAD_CERT_FORMAT);
	} else if (algoid->parameters.Data == NULL ||
	    algoid->parameters.Length == 0) {
		if (kmfber_printf(asn1, "n}") == -1)
			return (KMF_ERR_BAD_CERT_FORMAT);
	} else {
		/*
		 * The algorithm data can be anything, so we just write it
		 * straight into the buffer.  It is already DER encoded.
		 */
		(void) kmfber_write(asn1, (char *)algoid->parameters.Data,
		    algoid->parameters.Length, 0);
		if (kmfber_printf(asn1, "}") == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
		}
	}

	return (ret);
}

static void
free_data(KMF_DATA *data)
{
	if (data == NULL || data->Data == NULL)
		return;

	free(data->Data);
	data->Data = NULL;
	data->Length = 0;
}

static void
free_algoid(KMF_X509_ALGORITHM_IDENTIFIER *algoid)
{
	free_data(&algoid->algorithm);
	free_data(&algoid->parameters);
}

static void
free_decoded_spki(KMF_X509_SPKI *spki)
{
	if (spki != NULL) {
		free_algoid(&spki->algorithm);
		free_data(&spki->subjectPublicKey);
	}
}

static void
free_rdn_data(KMF_X509_NAME *name)
{
	KMF_X509_RDN 		*newrdn = NULL;
	KMF_X509_TYPE_VALUE_PAIR *av = NULL;
	int i, j;

	if (name && name->numberOfRDNs) {
		for (i = 0; i < name->numberOfRDNs; i++) {
			newrdn = &name->RelativeDistinguishedName[i];
			for (j = 0; j < newrdn->numberOfPairs; j++) {
				av = &newrdn->AttributeTypeAndValue[j];
				free_data(&av->type);
				free_data(&av->value);
			}
			free(newrdn->AttributeTypeAndValue);
		}
		free(name->RelativeDistinguishedName);
		name->numberOfRDNs = 0;
		name->RelativeDistinguishedName = NULL;
	}
}

static void
free_validity(KMF_X509_VALIDITY *validity)
{
	free_data(&validity->notBefore.time);
	free_data(&validity->notAfter.time);
}

static void
free_one_extension(KMF_X509_EXTENSION *exptr)
{
	free_data(&exptr->extnId);
	free_data(&exptr->BERvalue);

	if (exptr->value.tagAndValue) {
		free_data(&exptr->value.tagAndValue->value);
		free(exptr->value.tagAndValue);
	}
}

static void
free_extensions(KMF_X509_EXTENSIONS *extns)
{
	int i;
	KMF_X509_EXTENSION *exptr;

	if (extns && extns->numberOfExtensions > 0) {
		for (i = 0; i < extns->numberOfExtensions; i++) {
			exptr = &extns->extensions[i];
			free_one_extension(exptr);
		}
		free(extns->extensions);
		extns->numberOfExtensions = 0;
		extns->extensions = NULL;
	}
}

static void
free_tbscsr(KMF_TBS_CSR *tbscsr)
{
	if (tbscsr) {
		free_data(&tbscsr->version);

		free_rdn_data(&tbscsr->subject);

		free_decoded_spki(&tbscsr->subjectPublicKeyInfo);

		free_extensions(&tbscsr->extensions);
	}
}


static void
free_bigint(KMF_BIGINT *bn)
{
	if (bn != NULL && bn->val != NULL) {
		free(bn->val);
		bn->val = NULL;
		bn->len = 0;
	}
}

static void
free_tbscert(KMF_X509_TBS_CERT *tbscert)
{
	if (tbscert) {
		free_data(&tbscert->version);
		free_bigint(&tbscert->serialNumber);
		free_algoid(&tbscert->signature);

		free_rdn_data(&tbscert->issuer);
		free_rdn_data(&tbscert->subject);

		free_validity(&tbscert->validity);

		free_data(&tbscert->issuerUniqueIdentifier);
		free_data(&tbscert->subjectUniqueIdentifier);
		free_decoded_spki(&tbscert->subjectPublicKeyInfo);
		free_extensions(&tbscert->extensions);

		free_data(&tbscert->issuerUniqueIdentifier);
		free_data(&tbscert->subjectUniqueIdentifier);
	}
}

static void
free_decoded_cert(KMF_X509_CERTIFICATE *certptr)
{
	if (!certptr)
		return;

	free_tbscert(&certptr->certificate);

	free_algoid(&certptr->signature.algorithmIdentifier);
	free_data(&certptr->signature.encrypted);
}

static KMF_RETURN
get_sequence_data(BerElement *asn1, BerValue *seqdata)
{
	ber_tag_t tag;
	ber_len_t size;

	tag = kmfber_next_element(asn1, &size, NULL);
	if (tag == BER_OBJECT_IDENTIFIER) {
		/* The whole block is the OID. */
		size += kmfber_calc_taglen(tag) + kmfber_calc_lenlen(size);
		seqdata->bv_val = malloc(size);
		if (seqdata->bv_val == NULL) {
			return (KMF_ERR_MEMORY);
		}
		/* read the raw data into the Algoritm params area. */
		if (kmfber_read(asn1, seqdata->bv_val, size) ==
		    -1) {
			return (KMF_ERR_BAD_CERT_FORMAT);
		}
		seqdata->bv_len = size;
		return (KMF_OK);
	} else if (tag != BER_CONSTRUCTED_SEQUENCE)
		return (KMF_ERR_BAD_CERT_FORMAT);

	if ((kmfber_scanf(asn1, "tl", &tag, &size)) == -1) {
		return (KMF_ERR_BAD_CERT_FORMAT);
	}
	/*
	 * We need to read the tag and the length bytes too,
	 * so adjust the size.
	 */
	size += kmfber_calc_taglen(tag) + kmfber_calc_lenlen(size);
	seqdata->bv_val = malloc(size);
	if (seqdata->bv_val == NULL) {
		return (KMF_ERR_MEMORY);
	}
	/* read the raw data into the Algoritm params area. */
	if (kmfber_read(asn1, seqdata->bv_val, size) ==
	    -1) {
		return (KMF_ERR_BAD_CERT_FORMAT);
	}
	seqdata->bv_len = size;
	return (KMF_OK);
}

static KMF_RETURN
get_algoid(BerElement *asn1, KMF_X509_ALGORITHM_IDENTIFIER *algoid)
{
	KMF_RETURN rv = KMF_OK;
	ber_tag_t tag;
	ber_len_t size;
	BerValue algoid_data;
	BerValue AlgOID;
	BerElement *oidasn1 = NULL;

	/* Read the entire OID seq into it's own data block */
	rv = get_sequence_data(asn1, &algoid_data);
	if (rv != KMF_OK)
		return (rv);

	/* Now parse just this block so we don't overrun */
	if ((oidasn1 = kmfder_init(&algoid_data)) == NULL)
		return (KMF_ERR_MEMORY);
	tag = kmfber_next_element(oidasn1, &size, NULL);
	if (tag == BER_OBJECT_IDENTIFIER) {
		algoid->algorithm.Data = (uchar_t *)algoid_data.bv_val;
		algoid->algorithm.Length = algoid_data.bv_len;
		algoid->parameters.Data = NULL;
		algoid->parameters.Length = 0;
		kmfber_free(oidasn1, 1);
		return (KMF_OK);
	}

	if ((tag = kmfber_scanf(oidasn1, "{D", &AlgOID)) == -1) {
		kmfber_free(oidasn1, 1);
		return (KMF_ERR_BAD_CERT_FORMAT);
	}
	algoid->algorithm.Data = (uchar_t *)AlgOID.bv_val;
	algoid->algorithm.Length = AlgOID.bv_len;

	tag = kmfber_next_element(oidasn1, &size, NULL);
	if (tag == BER_NULL) {
		(void) kmfber_scanf(oidasn1, "n}");
		algoid->parameters.Data = NULL;
		algoid->parameters.Length = 0;
	} else if (tag == KMFBER_END_OF_SEQORSET || tag == KMFBER_DEFAULT) {
		/* close sequence, we are done with Algoid */
		algoid->parameters.Data = NULL;
		algoid->parameters.Length = 0;
	} else {
		/* The rest of the data is the algorithm parameters */
		if ((kmfber_scanf(oidasn1, "tl", &tag, &size)) == -1) {
			rv = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}

		/*
		 * We need to read the tag and the length bytes too,
		 * so adjust the size.
		 */
		size += kmfber_calc_taglen(tag) + kmfber_calc_lenlen(size);
		algoid->parameters.Data = malloc(size);
		if (algoid->parameters.Data == NULL) {
			rv = KMF_ERR_MEMORY;
			goto cleanup;
		}
		/* read the raw data into the Algoritm params area. */
		if (kmfber_read(oidasn1, (char *)algoid->parameters.Data,
		    size) == -1) {
			rv = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		algoid->parameters.Length = size;
	}
cleanup:
	if (rv != KMF_OK) {
		free_algoid(algoid);
	}
	kmfber_free(oidasn1, 1);

	return (rv);
}

static KMF_RETURN
CopyData(KMF_DATA *src, KMF_DATA *dst)
{
	if (src && dst && src->Data != NULL && src->Length > 0) {
		dst->Length = src->Length;
		dst->Data = malloc(dst->Length);
		if (dst->Data == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(dst->Data, src->Data, src->Length);
	}
	return (KMF_OK);
}

static KMF_RETURN
encode_spki(BerElement *asn1, KMF_X509_SPKI *spki)
{
	KMF_RETURN ret = KMF_OK;

	if (kmfber_printf(asn1, "{") == -1)
		return (KMF_ERR_BAD_CERT_FORMAT);

	/*
	 * The SPKI is the only place where algorithm parameters
	 * should be encoded.
	 */
	if ((ret = encode_algoid(asn1, &spki->algorithm, TRUE)) != KMF_OK)
		return (ret);

	if (kmfber_printf(asn1, "B}", spki->subjectPublicKey.Data,
	    spki->subjectPublicKey.Length * 8) == -1)
		return (KMF_ERR_BAD_CERT_FORMAT);

	return (ret);
}

KMF_RETURN
DerEncodeSPKI(KMF_X509_SPKI *spki, KMF_DATA *EncodedSPKI)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1;
	BerValue *result;

	if (spki == NULL || EncodedSPKI == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if ((ret = encode_spki(asn1, spki)) != KMF_OK) {
		return (ret);
	}

	if (kmfber_flatten(asn1, &result) == -1) {
		kmfber_free(asn1, 1);
		return (KMF_ERR_ENCODING);
	}

	EncodedSPKI->Data = (uchar_t *)result->bv_val;
	EncodedSPKI->Length = result->bv_len;

	free(result);
	kmfber_free(asn1, 1);
	return (KMF_OK);
}

static KMF_RETURN
get_spki(BerElement *asn1, KMF_X509_SPKI *spki)
{
	KMF_RETURN ret = KMF_OK;
	char *bitstr = NULL;
	ber_len_t size;

	if (kmfber_scanf(asn1, "{") == -1)
		return (KMF_ERR_BAD_CERT_FORMAT);

	if ((ret = get_algoid(asn1, &spki->algorithm)) != KMF_OK)
		return (ret);

	if (kmfber_scanf(asn1, "B}", &bitstr, &size) == BER_BIT_STRING) {
		spki->subjectPublicKey.Data = (uchar_t *)bitstr;
		spki->subjectPublicKey.Length = size / 8;
	} else {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
cleanup:
	if (ret != KMF_OK) {
		if (bitstr != NULL)
			free(bitstr);
		spki->subjectPublicKey.Data = NULL;
		spki->subjectPublicKey.Length = 0;

		free_algoid(&spki->algorithm);
	}
	return (ret);
}


KMF_RETURN
DerEncodeDSASignature(KMF_DATA *rawdata, KMF_DATA *signature)
{
	BerElement *asn1;
	BerValue *buf;
	int n;

	if (rawdata == NULL || signature == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (rawdata->Data == NULL || rawdata->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	/*
	 * The [EC]DSA signature is the concatenation of 2
	 * bignum values.
	 */
	n = rawdata->Length/2;
	if (kmfber_printf(asn1, "{II}",
	    rawdata->Data, n, &rawdata->Data[n], n) == -1) {
		kmfber_free(asn1, 1);
		return (KMF_ERR_MEMORY);
	}

	if (kmfber_flatten(asn1, &buf) == -1) {
		kmfber_free(asn1, 1);
		return (KMF_ERR_ENCODING);
	}

	signature->Data = (uchar_t *)buf->bv_val;
	signature->Length = buf->bv_len;

	kmfber_free(asn1, 1);
	free(buf);

	return (KMF_OK);
}

/*
 * ECDSA and DSA encode signatures the same way.
 */
KMF_RETURN
DerEncodeECDSASignature(KMF_DATA *rawdata, KMF_DATA *signature)
{
	return (DerEncodeDSASignature(rawdata, signature));
}

/*
 * Convert a signed DSA sig to a fixed-length unsigned one.
 * This is necessary because DER encoding seeks to use the
 * minimal amount of bytes but we need a full 20 byte DSA
 * value with leading 0x00 bytes.
 */
static KMF_RETURN
convert_signed_to_fixed(BerValue *src, BerValue *dst)
{
	int cnt;
	char *p;
	if (dst->bv_len > src->bv_len) {
		cnt = dst->bv_len - src->bv_len;
		/* prepend with leading 0s */
		(void) memset(dst->bv_val, 0x00, cnt);
		(void) memcpy(dst->bv_val + cnt, src->bv_val,
		    src->bv_len);
		return (KMF_OK);
	}
	if (dst->bv_len == src->bv_len) {
		(void) memcpy(dst->bv_val, src->bv_val,
		    dst->bv_len);
		return (KMF_OK);
	}
	/*
	 * src is larger than dest, strip leading 0s.
	 * This should not be necessary, but do it just in case.
	 */
	cnt = src->bv_len - dst->bv_len;
	p = src->bv_val;
	while (cnt-- > 0) {
		if (*p++ != 0x00)
			return (KMF_ERR_ENCODING);
	}
	(void) memcpy(dst->bv_val, p, dst->bv_len);
	return (KMF_OK);
}

KMF_RETURN
DerDecodeDSASignature(KMF_DATA *encoded, KMF_DATA *signature)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue buf, *R = NULL, *S = NULL;
	BerValue fixedR, fixedS;

	buf.bv_val = (char *)encoded->Data;
	buf.bv_len = encoded->Length;

	if (encoded == NULL || encoded->Data == NULL ||
	    signature == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	signature->Data = NULL;
	signature->Length = 0;

	if ((asn1 = kmfder_init(&buf)) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_scanf(asn1, "{II}", &R, &S) == -1) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}
	signature->Length = R->bv_len + S->bv_len;
	/*
	 * If either of the values had a leading 0 lopped off
	 * they will be 1 byte short and need to be adjusted below.
	 * The stripping is correct as per ASN.1 rules.
	 *
	 * We don't know the exact length that the R and S values
	 * must be, it depends on the signature algorithm and,
	 * in the case of EC, the curve used. So instead of
	 * checking for a specific length, we just check to see
	 * if the value came out to be an odd number.  If so,
	 * then we know it needs a leading 0x00 byte which
	 * will be added below when we convert it to a fixed
	 * length.
	 */
	if ((R->bv_len % 2) != 0)
		signature->Length++;
	if ((S->bv_len % 2) != 0)
		signature->Length++;

	signature->Data = malloc(signature->Length);
	if (signature->Data == NULL)  {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	fixedR.bv_val = (char *)signature->Data;
	/* adjust length if it needs a leading 0x00 byte */
	fixedR.bv_len = R->bv_len + (R->bv_len % 2);

	fixedS.bv_val = (char *)(signature->Data + fixedR.bv_len);
	/* adjust length if it needs a leading 0x00 byte */
	fixedS.bv_len = S->bv_len + (S->bv_len % 2);

	/*
	 * This will add back any missing leading 0's
	 * that were stripped off earlier when the signature
	 * was parsed.  This ensures that the 2 parts of the
	 * signature are the right length and have the proper
	 * leading 0's prepended.
	 */
	ret = convert_signed_to_fixed(R, &fixedR);
	if (ret)
		goto cleanup;

	ret = convert_signed_to_fixed(S, &fixedS);
cleanup:
	if (R && R->bv_val)
		free(R->bv_val);
	if (S && S->bv_val)
		free(S->bv_val);

	if (S) free(S);
	if (R) free(R);

	if (asn1) kmfber_free(asn1, 1);

	return (ret);
}

KMF_RETURN
DerDecodeECDSASignature(KMF_DATA *encoded, KMF_DATA *signature)
{
	/* ECDSA can be decoded using same code as standard DSA */
	return (DerDecodeDSASignature(encoded, signature));
}

KMF_RETURN
DerDecodeSPKI(KMF_DATA *EncodedSPKI, KMF_X509_SPKI *spki)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1;
	BerValue bv;

	if (EncodedSPKI == NULL || EncodedSPKI->Data == NULL ||
	    spki == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(spki, 0, sizeof (KMF_X509_SPKI));

	bv.bv_val = (char *)EncodedSPKI->Data;
	bv.bv_len = EncodedSPKI->Length;

	if ((asn1 = kmfder_init(&bv)) == NULL)
		return (KMF_ERR_MEMORY);

	ret = get_spki(asn1, spki);

	if (ret != KMF_OK) {
		free_decoded_spki(spki);
	}
	kmfber_free(asn1, 1);

	return (ret);
}

KMF_RETURN
CopySPKI(KMF_X509_SPKI *src,
		KMF_X509_SPKI **dest)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_SPKI *newspki;

	*dest = NULL;

	newspki = malloc(sizeof (KMF_X509_SPKI));
	if (newspki == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(newspki, 0, sizeof (KMF_X509_SPKI));

	ret = CopyData(&src->algorithm.algorithm,
	    &newspki->algorithm.algorithm);
	if (ret != KMF_OK)
		goto cleanup;

	ret = CopyData(&src->algorithm.parameters,
	    &newspki->algorithm.parameters);
	if (ret != KMF_OK)
		goto cleanup;

	ret = CopyData(&src->subjectPublicKey,
	    &newspki->subjectPublicKey);
	if (ret != KMF_OK)
		goto cleanup;

	*dest = newspki;
cleanup:
	if (ret != KMF_OK) {
		if (newspki)
			free_decoded_spki(newspki);
	}
	return (ret);
}

static KMF_RETURN
encode_validity(BerElement *asn1, KMF_X509_VALIDITY *validity)
{
	int ret;

	ret = kmfber_printf(asn1, "{tsts}",
	    validity->notBefore.timeType,
	    validity->notBefore.time.Data,
	    validity->notAfter.timeType,
	    validity->notAfter.time.Data);

	if (ret == -1)
		return (KMF_ERR_BAD_CERT_FORMAT);

	return (KMF_OK);
}

static KMF_RETURN
get_validity(BerElement *asn1, KMF_X509_VALIDITY *validity)
{
	KMF_RETURN ret = KMF_OK;
	int tag;
	int t1, t2;
	ber_len_t size;
	char *t1str, *t2str;

	(void) memset(validity, 0, sizeof (KMF_X509_VALIDITY));

	tag = kmfber_next_element(asn1, &size, NULL);
	if (tag != BER_CONSTRUCTED_SEQUENCE) {
		return (KMF_ERR_BAD_CERT_FORMAT);
	}

	if (kmfber_scanf(asn1, "{tata}", &t1, &t1str, &t2, &t2str) == -1) {
		return (KMF_ERR_BAD_CERT_FORMAT);
	}

	validity->notBefore.timeType = t1;
	validity->notBefore.time.Data = (uchar_t *)t1str;
	validity->notBefore.time.Length = strlen(t1str);

	validity->notAfter.timeType = t2;
	validity->notAfter.time.Data = (uchar_t *)t2str;
	validity->notAfter.time.Length = strlen(t2str);

	return (ret);
}

KMF_RETURN
AddRDN(KMF_X509_NAME *name, KMF_X509_RDN *newrdn)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_RDN *rdnslot = NULL;

	/* Add new RDN record to existing list */
	name->numberOfRDNs++;
	name->RelativeDistinguishedName =
	    realloc(name->RelativeDistinguishedName,
	    name->numberOfRDNs * sizeof (KMF_X509_RDN));

	if (name->RelativeDistinguishedName == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	rdnslot = &name->RelativeDistinguishedName[name->numberOfRDNs-1];

	if (newrdn) {
		(void) memcpy(rdnslot, newrdn, sizeof (KMF_X509_RDN));
	} else {
		rdnslot->numberOfPairs = 0;
		rdnslot->AttributeTypeAndValue = NULL;
	}

cleanup:
	/* No cleanup needed here */
	return (ret);
}

static KMF_RETURN
encode_rdn(BerElement *asn1, KMF_X509_NAME *name)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_TYPE_VALUE_PAIR *attrtvpair = NULL;
	int i;
	KMF_X509_RDN *rdn;

	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < name->numberOfRDNs; i++) {
		if (kmfber_printf(asn1, "[") == -1) {
			ret = KMF_ERR_MEMORY;
			goto cleanup;
		}
		rdn = &name->RelativeDistinguishedName[i];
		attrtvpair = rdn->AttributeTypeAndValue;

		if (rdn->numberOfPairs > 0) {
			if (kmfber_printf(asn1, "{Dto}",
			    &attrtvpair->type,
			    attrtvpair->valueType,
			    attrtvpair->value.Data,
			    attrtvpair->value.Length) == -1) {
				ret = KMF_ERR_MEMORY;
				goto cleanup;
			}
		}
		if (kmfber_printf(asn1, "]") == -1) {
			ret = KMF_ERR_MEMORY;
			goto cleanup;
		}
	}

	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

cleanup:
	/* No cleanup needed here */

	return (ret);
}


KMF_RETURN
CopyRDN(KMF_X509_NAME *srcname, KMF_X509_NAME **destname)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_NAME 		*newname = NULL;
	KMF_X509_RDN 		*rdn, *dstrdn;
	KMF_X509_TYPE_VALUE_PAIR *av = NULL;
	KMF_X509_TYPE_VALUE_PAIR *srcav = NULL;
	KMF_X509_TYPE_VALUE_PAIR *dstav = NULL;
	int i, j;

	newname = malloc(sizeof (KMF_X509_NAME));
	if (newname == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(newname, 0, sizeof (KMF_X509_NAME));

	newname->numberOfRDNs = srcname->numberOfRDNs;
	newname->RelativeDistinguishedName = malloc(newname->numberOfRDNs *
	    sizeof (KMF_X509_RDN));
	if (newname->RelativeDistinguishedName == NULL) {
		free(newname);
		return (KMF_ERR_MEMORY);
	}
	/* Copy each RDN in the list */
	for (i = 0; i < newname->numberOfRDNs; i++) {
		rdn = &srcname->RelativeDistinguishedName[i];

		dstrdn = &newname->RelativeDistinguishedName[i];
		(void) memset(dstrdn, 0, sizeof (KMF_X509_RDN));

		dstrdn->numberOfPairs = rdn->numberOfPairs;
		if (dstrdn->numberOfPairs > 0) {
			av = malloc(dstrdn->numberOfPairs *
			    sizeof (KMF_X509_TYPE_VALUE_PAIR));
			if (av == NULL) {
				ret = KMF_ERR_MEMORY;
				goto cleanup;
			}
			(void) memset(av, 0, dstrdn->numberOfPairs *
			    sizeof (KMF_X509_TYPE_VALUE_PAIR));

			dstrdn->AttributeTypeAndValue = av;
			if (av == NULL) {
				ret = KMF_ERR_MEMORY;
				goto cleanup;
			}
			/* Copy each A/V pair in the list */
			for (j = 0; j < dstrdn->numberOfPairs; j++) {
				srcav = &rdn->AttributeTypeAndValue[j];
				dstav = &dstrdn->AttributeTypeAndValue[j];
				if ((ret = CopyData(&srcav->type,
				    &dstav->type)) != KMF_OK)
					goto cleanup;
				dstav->valueType = srcav->valueType;
				if ((ret = CopyData(&srcav->value,
				    &dstav->value)) != KMF_OK)
					goto cleanup;
			}
		} else {
			dstrdn->AttributeTypeAndValue = NULL;
		}
	}
	*destname = newname;

cleanup:
	if (ret != KMF_OK) {
		if (newname)
			free_rdn_data(newname);

		free(newname);
		*destname = NULL;
	}
	return (ret);
}

#define	VALID_DIRECTORYSTRING_TAG(t) ( \
	(t == BER_UTF8_STRING) || \
	(t == BER_PRINTABLE_STRING) || \
	(t == BER_IA5STRING) || \
	(t == BER_T61STRING) || \
	(t == BER_BMP_STRING) || \
	(t == BER_UNIVERSAL_STRING))

static KMF_RETURN
get_rdn(BerElement *asn1, KMF_X509_NAME *name)
{
	KMF_RETURN ret = KMF_OK;
	ber_len_t size;
	char *end;
	int tag;
	BerValue AttrOID;
	char *AttrValue = NULL;
	KMF_X509_TYPE_VALUE_PAIR *newpair = NULL;
	KMF_X509_RDN 		newrdn;

	/*
	 * AttributeType	::=  OBJECT IDENTIFIER
	 * AttributeValue	::=  ANY
	 *
	 * AttributeTypeAndValue	::=  SEQUENCE {
	 *	type    AttributeType,
	 *	value   AttributeValue }
	 *
	 * Name ::= CHOICE { -- only one possibility for now --
	 * 		rdnSequence  RDNSequence }
	 *
	 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	 *
	 * DistinguishedName ::=   RDNSequence
	 *
	 * RelativeDistinguishedName  ::=
	 *		 SET SIZE (1 .. MAX) OF AttributeTypeAndValue
	 *
	 */

	name->numberOfRDNs = 0;
	name->RelativeDistinguishedName = NULL;

	/* Get the beginning of the RDN Set and a ptr to the end */
	tag = kmfber_first_element(asn1, &size, &end);
	if (tag != BER_CONSTRUCTED_SET) {
		goto cleanup;
	}

	/* Walk through the individual SET items until the "end" is reached */
	while ((tag = kmfber_next_element(asn1, &size, end)) ==
	    BER_CONSTRUCTED_SET) {
		/* Skip over the SET tag */
		if (kmfber_scanf(asn1, "T", &tag) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			break;
		}

		/* An "empty" set member means we tack on an empty node */
		if (size == 0) {
			if ((ret = AddRDN(name, NULL)) != KMF_OK)
				goto cleanup;
			continue;
		}

		/* Attr OID and peek at the next tag and field length */
		if (kmfber_scanf(asn1, "{Dtl", &AttrOID, &tag, &size) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			break;
		}

		if (!(VALID_DIRECTORYSTRING_TAG(tag))) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			break;
		}

		if (kmfber_scanf(asn1, "a}]", &AttrValue) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			break;
		}

		/* Allocate a new name/value pair record */
		newpair = malloc(sizeof (KMF_X509_TYPE_VALUE_PAIR));
		if (newpair == NULL) {
			ret = KMF_ERR_MEMORY;
			break;
		}
		(void) memset(newpair, 0, sizeof (KMF_X509_TYPE_VALUE_PAIR));
		newpair->type.Data = (uchar_t *)AttrOID.bv_val;
		newpair->type.Length = AttrOID.bv_len;
		newpair->valueType = tag; /* what kind of string is it? */
		newpair->value.Data = (uchar_t *)AttrValue;
		newpair->value.Length = strlen(AttrValue);

		(void) memset(&newrdn, 0, sizeof (KMF_X509_RDN));
		newrdn.numberOfPairs = 1;
		newrdn.AttributeTypeAndValue = newpair;

		if ((ret = AddRDN(name, &newrdn)) != KMF_OK)
			break;
	}

cleanup:
	if (ret != KMF_OK) {
		free_rdn_data(name);
	}
	return (ret);
}

static KMF_RETURN
set_der_integer(KMF_DATA *data, int value)
{
	if (data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	data->Data = malloc(sizeof (int));
	if (data->Data == NULL)
		return (KMF_ERR_MEMORY);

	data->Length = sizeof (int);
	(void) memcpy((void *)data->Data, (const void *)&value, sizeof (int));

	return (KMF_OK);
}

static KMF_RETURN
set_bigint(KMF_BIGINT *data, KMF_BIGINT *bigint)
{
	if (data == NULL || bigint == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	data->val = malloc(bigint->len);
	if (data->val == NULL)
		return (KMF_ERR_MEMORY);

	data->len = bigint->len;
	(void) memcpy((void *)data->val, (const void *)bigint->val,
	    bigint->len);

	return (KMF_OK);
}

static KMF_RETURN
encode_uniqueid(BerElement *asn1, int tag, KMF_DATA *id)
{
	KMF_RETURN ret = KMF_OK;
	uint32_t len;

	len = kmfber_calc_taglen(BER_BIT_STRING) +
	    kmfber_calc_lenlen(id->Length * 8) + id->Length;
	if (kmfber_printf(asn1, "TlB", tag, len,
	    id->Data, id->Length * 8) == -1)
		return (KMF_ERR_BAD_CERT_FORMAT);

	return (ret);
}

static KMF_RETURN
encode_extension_list(BerElement *asn1, KMF_X509_EXTENSIONS *extns)
{
	KMF_RETURN ret = KMF_OK;
	int i;

	for (i = 0; i < extns->numberOfExtensions; i++) {
		BerValue v;
		v.bv_val = (char *)extns->extensions[i].extnId.Data;
		v.bv_len = extns->extensions[i].extnId.Length;

		if (kmfber_printf(asn1, "{D", &v) == -1)  {
			ret = KMF_ERR_ENCODING;
			goto cleanup;
		}

		if (extns->extensions[i].critical) {
			if (kmfber_printf(asn1, "b",
			    extns->extensions[i].critical) == -1) {
				ret = KMF_ERR_ENCODING;
				goto cleanup;
			}
		}

		if (kmfber_printf(asn1, "o}",
		    extns->extensions[i].BERvalue.Data,
		    extns->extensions[i].BERvalue.Length) == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup;
		}
	}
cleanup:
	return (ret);
}

static KMF_RETURN
encode_extensions(BerElement *asn1, KMF_X509_EXTENSIONS *extns)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *extn = NULL;
	BerValue *extnvalue = NULL;

	extn = kmfder_alloc();
	if (extn == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(extn, "{") == -1) {
		ret = KMF_ERR_ENCODING;
		goto cleanup;
	}

	ret = encode_extension_list(extn, extns);

	if (kmfber_printf(extn, "}") == -1) {
		ret = KMF_ERR_ENCODING;
		goto cleanup;
	}

	if (kmfber_flatten(extn, &extnvalue) == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	if (kmfber_printf(asn1, "Tl", 0xA3, extnvalue->bv_len) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (kmfber_write(asn1, extnvalue->bv_val, extnvalue->bv_len, 0) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

cleanup:
	kmfber_free(extn, 1);
	if (extnvalue != NULL)
		kmfber_bvfree(extnvalue);

	return (ret);
}

static KMF_RETURN
get_one_extension(BerElement *asn1, KMF_X509_EXTENSION **retex, char *end)
{
	KMF_RETURN ret = KMF_OK;
	ber_len_t size;
	int  critical, tag;
	KMF_X509_EXTENSION *ex = NULL;
	BerValue extOID;
	BerValue extValue;
	BerElement *extnber = NULL;

	if (kmfber_scanf(asn1, "T", &tag) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	tag = kmfber_next_element(asn1, &size, end);
	if (tag != BER_OBJECT_IDENTIFIER) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	if (kmfber_scanf(asn1, "D", &extOID) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	tag = kmfber_next_element(asn1, &size, end);
	if (tag != BER_BOOLEAN) {
		critical = 0;
		if (tag != BER_OCTET_STRING)
			goto cleanup;
	} else {
		if (kmfber_scanf(asn1, "b", &critical) == -1)
			goto cleanup;
	}

	tag = kmfber_next_element(asn1, &size, end);
	if (tag != BER_OCTET_STRING)  {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	if (kmfber_scanf(asn1, "o", &extValue) == -1)  {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* allocate a new Extension record */
	ex = malloc(sizeof (KMF_X509_EXTENSION));
	if (ex == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	(void) memset(ex, 0, sizeof (ex));

	ex->extnId.Data = (uchar_t *)extOID.bv_val;
	ex->extnId.Length = extOID.bv_len;
	ex->critical = critical;
	ex->format = KMF_X509_DATAFORMAT_ENCODED;
	ex->BERvalue.Data = (uchar_t *)extValue.bv_val;
	ex->BERvalue.Length = extValue.bv_len;

	/* Tag and value is a little tricky */
	ex->value.tagAndValue = malloc(sizeof (KMF_X509EXT_TAGandVALUE));
	if (ex->value.tagAndValue == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	(void) memset(ex->value.tagAndValue, 0,
	    sizeof (KMF_X509EXT_TAGandVALUE));

	/* Parse the Extension value field */
	extnber = kmfder_init(&extValue);
	if (extnber == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	/* Get the tag and length of the extension field */
	if (kmfber_scanf(extnber, "tl", &tag, &size) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (kmfber_scanf(extnber, "T", &tag) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	ex->value.tagAndValue->value.Data = malloc(size);
	ex->value.tagAndValue->value.Length = size;
	size = kmfber_read(extnber,
	    (char *)ex->value.tagAndValue->value.Data, size);
	if (size != ex->value.tagAndValue->value.Length) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	kmfber_free(extnber, 1);
	ex->value.tagAndValue->type = tag;

	*retex = ex;
cleanup:
	if (ret != KMF_OK) {
		if (ex != NULL)
			free_one_extension(ex);
	}

	return (ret);
}

static KMF_RETURN
get_extensions(BerElement *asn1, KMF_X509_EXTENSIONS *extns)
{
	KMF_RETURN ret = KMF_OK;
	ber_len_t size;
	char *end = NULL;
	KMF_X509_EXTENSION *ex = NULL;

	/*
	 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 *
	 * Extension  ::=  SEQUENCE  {
	 *	extnID		OBJECT IDENTIFIER,
	 *	critical	BOOLEAN DEFAULT FALSE,
	 *	extnValue	OCTET STRING  }
	 *
	 * { {{D}Bo}, ... }
	 */
	if (kmfber_first_element(asn1, &size, &end) !=
	    BER_CONSTRUCTED_SEQUENCE)
		return (KMF_ERR_BAD_CERT_FORMAT);

	while (kmfber_next_element(asn1, &size, end) ==
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = get_one_extension(asn1, &ex, end);
		if (ret != KMF_OK)
			goto cleanup;

		extns->numberOfExtensions++;
		extns->extensions = realloc(extns->extensions,
		    extns->numberOfExtensions *
		    sizeof (KMF_X509_EXTENSION));
		if (extns->extensions == NULL) {
			ret = KMF_ERR_MEMORY;
			break;
		}

		extns->extensions[extns->numberOfExtensions-1] = *ex;
		free(ex);
	}

cleanup:
	if (ret != KMF_OK)
		free_extensions(extns);

	return (ret);
}

KMF_RETURN
decode_tbscert_data(BerElement *asn1,
	KMF_X509_TBS_CERT **signed_cert_ptr_ptr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_TBS_CERT	*tbscert = NULL;
	int tag, version;
	struct berval *bvserno = NULL;
	KMF_BIGINT serno;

	if (kmfber_scanf(asn1, "{t", &tag) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* Version number is optional */
	if (tag == 0xA0) {
		if (kmfber_scanf(asn1, "Ti", &tag, &version) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
	} else {
		version = 0; /* DEFAULT v1 (0) */
	}

	/* Now get the serial number, it is not optional */
	if (kmfber_scanf(asn1, "I", &bvserno) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	} else {
		serno.val = (uchar_t *)bvserno->bv_val;
		serno.len = bvserno->bv_len;
	}

	tbscert = malloc(sizeof (KMF_X509_TBS_CERT));
	if (!tbscert) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	(void) memset(tbscert, 0, sizeof (KMF_X509_TBS_CERT));

	if ((ret = set_der_integer(&tbscert->version, version)) != KMF_OK)
		goto cleanup;

	if ((ret = set_bigint(&tbscert->serialNumber, &serno)) != KMF_OK)
		goto cleanup;

	if ((ret = get_algoid(asn1, &tbscert->signature)) != KMF_OK)
		goto cleanup;

	if ((ret = get_rdn(asn1, &tbscert->issuer)) != KMF_OK)
		goto cleanup;

	if ((ret = get_validity(asn1, &tbscert->validity)) != KMF_OK)
		goto cleanup;

	if ((ret = get_rdn(asn1, &tbscert->subject)) != KMF_OK)
		goto cleanup;

	if ((ret = get_spki(asn1, &tbscert->subjectPublicKeyInfo)) != KMF_OK)
		goto cleanup;

	/* Check for the optional fields */
	tbscert->extensions.numberOfExtensions = 0;
	tbscert->extensions.extensions = NULL;

	while ((kmfber_scanf(asn1, "t", &tag)) != -1 &&
	    (tag == 0xA1 || tag == 0xA2 || tag == 0xA3)) {
		char *optfield;
		ber_len_t len;

		/* consume the tag and length */
		(void) kmfber_scanf(asn1, "T", &tag);
		switch (tag) {
			case 0xA1:
				if (kmfber_scanf(asn1, "B", &optfield, &len) !=
				    BER_BIT_STRING) {
					ret = KMF_ERR_BAD_CERT_FORMAT;
					goto cleanup;
				}
				tbscert->issuerUniqueIdentifier.Data =
				    (uchar_t *)optfield;
				tbscert->issuerUniqueIdentifier.Length =
				    len / 8;
				break;
			case 0xA2:
				if (kmfber_scanf(asn1, "B", &optfield, &len) !=
				    BER_BIT_STRING) {
					ret = KMF_ERR_BAD_CERT_FORMAT;
					goto cleanup;
				}
				tbscert->subjectUniqueIdentifier.Data =
				    (uchar_t *)optfield;
				tbscert->subjectUniqueIdentifier.Length =
				    len / 8;
				break;
			case 0xA3:
			ret = get_extensions(asn1, &tbscert->extensions);
			break;
		}
	}

	*signed_cert_ptr_ptr = tbscert;

cleanup:
	if (bvserno != NULL) {
		free(bvserno->bv_val);
		free(bvserno);
	}
	if (ret != KMF_OK) {
		if (tbscert) {
			free_tbscert(tbscert);
			free(tbscert);
		}
		*signed_cert_ptr_ptr = NULL;
	}
	return (ret);
}

KMF_RETURN
DerDecodeTbsCertificate(const KMF_DATA *Value,
	KMF_X509_TBS_CERT **tbscert)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue 	rawcert;
	KMF_X509_TBS_CERT *newcert = NULL;

	if (!tbscert || !Value || !Value->Data || !Value->Length)
		return (KMF_ERR_BAD_PARAMETER);

	rawcert.bv_val = (char *)Value->Data;
	rawcert.bv_len = Value->Length;

	if ((asn1 = kmfder_init(&rawcert)) == NULL)
		return (KMF_ERR_MEMORY);

	ret = decode_tbscert_data(asn1, &newcert);
	if (ret != KMF_OK)
		goto cleanup;

	*tbscert = newcert;

cleanup:
	if (ret != KMF_OK) {
		if (newcert)
			free_tbscert(newcert);
		*tbscert = NULL;
	}
	kmfber_free(asn1, 1);

	return (ret);
}

/*
 * Name: DerDecodeSignedCertificate
 *
 * Description:
 * DER decodes the encoded X509 certificate
 *
 * Parameters:
 * Value (input): DER encoded object that shd be decoded
 *
 * signed_cert_ptr_ptr (output) : Decoded KMF_X509_CERTIFICATE object
 */
KMF_RETURN
DerDecodeSignedCertificate(const KMF_DATA *Value,
	KMF_X509_CERTIFICATE **signed_cert_ptr_ptr)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue 	rawcert;
	ber_tag_t	tag;
	ber_len_t	size;
	char		*end = NULL;
	char		*signature;
	KMF_X509_TBS_CERT	*tbscert = NULL;
	KMF_X509_CERTIFICATE *certptr = NULL;

	if (!signed_cert_ptr_ptr || !Value || !Value->Data || !Value->Length)
		return (KMF_ERR_BAD_PARAMETER);

	rawcert.bv_val = (char *)Value->Data;
	rawcert.bv_len = Value->Length;

	if ((asn1 = kmfder_init(&rawcert)) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_first_element(asn1, &size, &end) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	certptr = malloc(sizeof (KMF_X509_CERTIFICATE));
	if (certptr == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	(void) memset(certptr, 0, sizeof (KMF_X509_CERTIFICATE));

	ret = decode_tbscert_data(asn1, &tbscert);
	if (ret != KMF_OK)
		goto cleanup;

	certptr->certificate = *tbscert;
	free(tbscert);
	tbscert = NULL;

	/*
	 * The signature data my not be present yet.
	 */
	if ((ret = get_algoid(asn1,
	    &certptr->signature.algorithmIdentifier)) == KMF_OK) {

		/* Check to see if the cert has a signature yet */
		if (kmfber_next_element(asn1, &size, end) == BER_BIT_STRING) {
			/* Finally, get the encrypted signature BITSTRING */
			if (kmfber_scanf(asn1, "tl", &tag, &size) == -1) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto cleanup;
			}
			if (tag != BER_BIT_STRING) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto cleanup;
			}
			if (kmfber_scanf(asn1, "B}", &signature, &size) == -1) {
				ret = KMF_ERR_BAD_CERT_FORMAT;
				goto cleanup;
			}
			certptr->signature.encrypted.Data =
			    (uchar_t *)signature;
			certptr->signature.encrypted.Length = size / 8;
		} else {
			certptr->signature.encrypted.Data = NULL;
			certptr->signature.encrypted.Length = 0;
		}
	} else {
		(void) memset(&certptr->signature, 0,
		    sizeof (certptr->signature));
		ret = KMF_OK;
	}

	*signed_cert_ptr_ptr = certptr;
cleanup:
	if (ret != KMF_OK) {
		if (certptr) {
			free_decoded_cert(certptr);
			free(certptr);
		}

		*signed_cert_ptr_ptr = NULL;
	}
	if (asn1)
		kmfber_free(asn1, 1);

	return (ret);

}

KMF_RETURN
DerDecodeExtension(KMF_DATA *Data, KMF_X509_EXTENSION **extn)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue bv;

	bv.bv_val = (char *)Data->Data;
	bv.bv_len = Data->Length;

	asn1 = kmfder_init(&bv);
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	ret = get_one_extension(asn1, extn, NULL);

	if (ret != KMF_OK) {
		if (*extn != NULL) {
			free(*extn);
		}
		*extn = NULL;
	}

	kmfber_free(asn1, 1);
	return (ret);
}

KMF_RETURN
DerDecodeName(KMF_DATA *encodedname, KMF_X509_NAME *name)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue  bv;

	bv.bv_val = (char *)encodedname->Data;
	bv.bv_len = encodedname->Length;

	asn1 = kmfder_init(&bv);
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset((void *)name, 0, sizeof (KMF_X509_NAME));

	if ((ret = get_rdn(asn1, name)) != KMF_OK)
		goto cleanup;

cleanup:
	if (asn1)
		kmfber_free(asn1, 1);
	return (ret);
}

KMF_RETURN
DerEncodeName(KMF_X509_NAME *name, KMF_DATA *encodedname)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue  *bv = NULL;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	if ((ret = encode_rdn(asn1, name)) != KMF_OK)
		goto cleanup;

	if (kmfber_flatten(asn1, &bv) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	encodedname->Data = (uchar_t *)bv->bv_val;
	encodedname->Length = bv->bv_len;

cleanup:
	if (bv)
		free(bv);

	if (asn1)
		kmfber_free(asn1, 1);

	return (ret);
}

static KMF_RETURN
encode_tbs_cert(BerElement *asn1, KMF_X509_TBS_CERT *tbscert)
{
	KMF_RETURN ret = KMF_OK;
	uint32_t version;

	/* version should be 4 bytes or less */
	if (tbscert->version.Length > sizeof (int))
		return (KMF_ERR_BAD_CERT_FORMAT);

	(void) memcpy(&version, tbscert->version.Data,
	    tbscert->version.Length);

	/* Start the sequence and add the version */
	if (kmfber_printf(asn1, "{Tli", 0xA0, 3, version) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	/* Write the serial number */
	if (kmfber_printf(asn1, "I",
	    (char *)tbscert->serialNumber.val,
	    (size_t)tbscert->serialNumber.len) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* Don't encode alg parameters in signature algid area */
	if ((ret = encode_algoid(asn1, &tbscert->signature, FALSE)) != KMF_OK)
		goto cleanup;

	/* Encode the Issuer RDN */
	if ((ret = encode_rdn(asn1, &tbscert->issuer)) != KMF_OK)
		goto cleanup;

	/* Encode the Validity fields */
	if ((ret = encode_validity(asn1, &tbscert->validity)) != KMF_OK)
		goto cleanup;

	/* Encode the Subject RDN */
	if ((ret = encode_rdn(asn1, &tbscert->subject)) != KMF_OK)
		goto cleanup;

	/* Encode the Subject Public Key Info */
	if ((ret = encode_spki(asn1, &tbscert->subjectPublicKeyInfo)) != KMF_OK)
		goto cleanup;

	/* Optional field:  issuer Unique ID */
	if (tbscert->issuerUniqueIdentifier.Length > 0) {
		if ((ret = encode_uniqueid(asn1, 0xA1,
		    &tbscert->issuerUniqueIdentifier)) != KMF_OK)
			goto cleanup;
	}

	/* Optional field:  Subject Unique ID */
	if (tbscert->subjectUniqueIdentifier.Length > 0) {
		if ((ret = encode_uniqueid(asn1, 0xA2,
		    &tbscert->subjectUniqueIdentifier)) != KMF_OK)
			goto cleanup;
	}

	/* Optional field: Certificate Extensions */
	if (tbscert->extensions.numberOfExtensions > 0) {
		if ((ret = encode_extensions(asn1,
		    &tbscert->extensions)) != KMF_OK)
			goto cleanup;
	}

	/* Close out the TBSCert sequence */
	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

cleanup:
	/*
	 * Memory cleanup is done in the caller or in the individual
	 * encoding routines.
	 */

	return (ret);
}

KMF_RETURN
DerEncodeTbsCertificate(KMF_X509_TBS_CERT *tbs_cert_ptr,
	KMF_DATA *enc_tbs_cert_ptr)
{
	KMF_RETURN ret;
	BerElement *asn1 = NULL;
	BerValue  *tbsdata = NULL;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	enc_tbs_cert_ptr->Data = NULL;
	enc_tbs_cert_ptr->Length = 0;

	ret = encode_tbs_cert(asn1, tbs_cert_ptr);
	if (ret != KMF_OK)
		goto cleanup;

	if (kmfber_flatten(asn1, &tbsdata) == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	enc_tbs_cert_ptr->Data = (uchar_t *)tbsdata->bv_val;
	enc_tbs_cert_ptr->Length = tbsdata->bv_len;

cleanup:
	if (ret != KMF_OK)
		free_data(enc_tbs_cert_ptr);

	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (tbsdata)
		free(tbsdata);

	return (ret);
}

KMF_RETURN
DerEncodeSignedCertificate(KMF_X509_CERTIFICATE *signed_cert_ptr,
	KMF_DATA *encodedcert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_TBS_CERT *tbscert = NULL;
	KMF_X509_SIGNATURE		*signature = NULL;
	BerElement	*asn1 = NULL;
	BerValue 	*tbsdata = NULL;

	if (signed_cert_ptr == NULL || encodedcert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	encodedcert->Data = NULL;
	encodedcert->Length = 0;

	tbscert = &signed_cert_ptr->certificate;
	signature = &signed_cert_ptr->signature;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	/* Start outer X509 Certificate SEQUENCE */
	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if ((ret = encode_tbs_cert(asn1, tbscert)) != KMF_OK) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* Add the Algorithm & Signature Sequence (no parameters) */
	if ((ret = encode_algoid(asn1,
	    &signature->algorithmIdentifier, FALSE)) != KMF_OK)
		goto cleanup;

	if (signature->encrypted.Length > 0) {
		if (kmfber_printf(asn1, "B", signature->encrypted.Data,
		    signature->encrypted.Length * 8) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
	}

	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (kmfber_flatten(asn1, &tbsdata) == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	encodedcert->Data = (uchar_t *)tbsdata->bv_val;
	encodedcert->Length = tbsdata->bv_len;

cleanup:
	if (ret != KMF_OK)
		free_data(encodedcert);

	if (tbsdata)
		free(tbsdata);

	if (asn1)
		kmfber_free(asn1, 1);

	return (ret);
}

KMF_RETURN
ExtractX509CertParts(KMF_DATA *x509cert, KMF_DATA *tbscert,
		KMF_DATA *signature)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *der = NULL;
	BerValue x509;
	ber_tag_t tag;
	ber_len_t size;

	if (tbscert == NULL || x509cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	x509.bv_val = (char *)x509cert->Data;
	x509.bv_len = x509cert->Length;

	der = kmfder_init(&x509);
	if (der == NULL)
		return (KMF_ERR_MEMORY);

	/* Skip over the overall Sequence tag to get at the TBS Cert data */
	if (kmfber_scanf(der, "Tl", &tag, &size) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	if (tag != BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/*
	 * Since we are extracting a copy of the ENCODED bytes, we
	 * must make sure to also include the bytes for the tag and
	 * the length fields for the CONSTRUCTED SEQUENCE (TBSCert).
	 */
	size += kmfber_calc_taglen(tag) + kmfber_calc_lenlen(size);

	tbscert->Data = malloc(size);
	if (tbscert->Data == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	tbscert->Length = size;

	/* The der data ptr is now set to the start of the TBS cert sequence */
	size = kmfber_read(der, (char *)tbscert->Data, tbscert->Length);
	if (size != tbscert->Length) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (signature != NULL) {
		KMF_X509_ALGORITHM_IDENTIFIER algoid;
		if ((ret = get_algoid(der, &algoid)) != KMF_OK)
			goto cleanup;
		free_algoid(&algoid);

		if (kmfber_scanf(der, "tl", &tag, &size) != BER_BIT_STRING) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		/* Now get the signature data */
		if (kmfber_scanf(der, "B", (char **)&signature->Data,
		    (ber_len_t *)&signature->Length) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		/* convert bitstring length to bytes */
		signature->Length = signature->Length / 8;
	}

cleanup:
	if (der)
		kmfber_free(der, 1);

	if (ret != KMF_OK)
		free_data(tbscert);

	return (ret);
}

static KMF_RETURN
decode_csr_extensions(BerElement *asn1, KMF_X509_EXTENSIONS *extns)
{
	KMF_RETURN ret = KMF_OK;
	BerValue oid;

	if (kmfber_scanf(asn1, "{D", &oid) == -1) {
		return (KMF_ERR_UNKNOWN_CSR_ATTRIBUTE);
	}

	/* We only understand extension requests in a CSR */
	if (memcmp(oid.bv_val, extension_request_oid.Data,
	    oid.bv_len) != 0) {
		return (KMF_ERR_UNKNOWN_CSR_ATTRIBUTE);
	}

	if (kmfber_scanf(asn1, "[") == -1) {
		return (KMF_ERR_ENCODING);
	}
	ret = get_extensions(asn1, extns);


	return (ret);
}

static KMF_RETURN
decode_tbscsr_data(BerElement *asn1,
	KMF_TBS_CSR **signed_csr_ptr_ptr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_TBS_CSR	*tbscsr = NULL;
	char *end = NULL;
	uint32_t version;
	ber_tag_t tag;
	ber_len_t size;

	/* Now get the version number, it is not optional */
	if (kmfber_scanf(asn1, "{i", &version) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	tbscsr = malloc(sizeof (KMF_TBS_CSR));
	if (!tbscsr) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	(void) memset(tbscsr, 0, sizeof (KMF_TBS_CSR));

	if ((ret = set_der_integer(&tbscsr->version, version)) != KMF_OK)
		goto cleanup;

	if ((ret = get_rdn(asn1, &tbscsr->subject)) != KMF_OK)
		goto cleanup;

	if ((ret = get_spki(asn1, &tbscsr->subjectPublicKeyInfo)) != KMF_OK)
		goto cleanup;

	/* Check for the optional fields (attributes) */
	if (kmfber_next_element(asn1, &size, end) == 0xA0) {
		if (kmfber_scanf(asn1, "Tl", &tag, &size) == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup;
		}

		ret = decode_csr_extensions(asn1, &tbscsr->extensions);
	}
	if (ret == KMF_OK)
		*signed_csr_ptr_ptr = tbscsr;

cleanup:
	if (ret != KMF_OK) {
		if (tbscsr) {
			free_tbscsr(tbscsr);
			free(tbscsr);
		}
		*signed_csr_ptr_ptr = NULL;
	}
	return (ret);
}

KMF_RETURN
DerDecodeTbsCsr(const KMF_DATA *Value,
	KMF_TBS_CSR **tbscsr)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue 	rawcsr;
	KMF_TBS_CSR *newcsr = NULL;

	if (!tbscsr || !Value || !Value->Data || !Value->Length)
		return (KMF_ERR_BAD_PARAMETER);

	rawcsr.bv_val = (char *)Value->Data;
	rawcsr.bv_len = Value->Length;

	if ((asn1 = kmfder_init(&rawcsr)) == NULL)
		return (KMF_ERR_MEMORY);

	ret = decode_tbscsr_data(asn1, &newcsr);
	if (ret != KMF_OK)
		goto cleanup;

	*tbscsr = newcsr;

cleanup:
	if (ret != KMF_OK) {
		if (newcsr)
			free_tbscsr(newcsr);
		*tbscsr = NULL;
	}
	kmfber_free(asn1, 1);

	return (ret);
}

KMF_RETURN
DerDecodeSignedCsr(const KMF_DATA *Value,
	KMF_CSR_DATA **signed_csr_ptr_ptr)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue 	rawcsr;
	int			tag;
	ber_len_t	size;
	char		*end = NULL;
	char		*signature;
	KMF_TBS_CSR	*tbscsr = NULL;
	KMF_CSR_DATA *csrptr = NULL;

	if (!signed_csr_ptr_ptr || !Value || !Value->Data || !Value->Length)
		return (KMF_ERR_BAD_PARAMETER);

	rawcsr.bv_val = (char *)Value->Data;
	rawcsr.bv_len = Value->Length;

	if ((asn1 = kmfder_init(&rawcsr)) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_first_element(asn1, &size, &end) !=
	    BER_CONSTRUCTED_SEQUENCE) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	csrptr = malloc(sizeof (KMF_CSR_DATA));
	if (csrptr == NULL) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}
	(void) memset(csrptr, 0, sizeof (KMF_CSR_DATA));

	ret = decode_tbscsr_data(asn1, &tbscsr);
	if (ret != KMF_OK)
		goto cleanup;

	csrptr->csr = *tbscsr;
	free(tbscsr);
	tbscsr = NULL;

	if ((ret = get_algoid(asn1,
	    &csrptr->signature.algorithmIdentifier)) != KMF_OK)
		goto cleanup;

	/* Check to see if the cert has a signature yet */
	if (kmfber_next_element(asn1, &size, end) == BER_BIT_STRING) {
		/* Finally, get the encrypted signature BITSTRING */
		if (kmfber_scanf(asn1, "tl", &tag, &size) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		if (tag != BER_BIT_STRING) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		if (kmfber_scanf(asn1, "B}", &signature, &size) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
		csrptr->signature.encrypted.Data = (uchar_t *)signature;
		csrptr->signature.encrypted.Length = size / 8;
	} else {
		csrptr->signature.encrypted.Data = NULL;
		csrptr->signature.encrypted.Length = 0;
	}

	*signed_csr_ptr_ptr = csrptr;
cleanup:
	if (ret != KMF_OK) {
		free_tbscsr(&csrptr->csr);
		free_algoid(&csrptr->signature.algorithmIdentifier);
		if (csrptr->signature.encrypted.Data)
			free(csrptr->signature.encrypted.Data);

		if (csrptr)
			free(csrptr);

		*signed_csr_ptr_ptr = NULL;
	}
	if (asn1)
		kmfber_free(asn1, 1);

	return (ret);

}

static KMF_RETURN
encode_csr_extensions(BerElement *asn1, KMF_TBS_CSR *tbscsr)
{
	KMF_RETURN ret = KMF_OK;
	int attlen = 0;
	BerElement *extnasn1 = NULL;
	BerValue *extnvalue = NULL;

	/* Optional field: CSR attributes and extensions */
	if (tbscsr->extensions.numberOfExtensions > 0) {
		if (kmfber_printf(asn1, "T", 0xA0) == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup;
		}
	} else {
		/* No extensions or attributes to encode */
		return (KMF_OK);
	}

	/*
	 * attributes [0] Attributes
	 * Attributes := SET OF Attribute
	 * Attribute  := SEQUENCE {
	 *   { ATTRIBUTE ID
	 *	values SET SIZE(1..MAX) of ATTRIBUTE
	 *   }
	 *
	 * Ex: { ExtensionRequest OID [ { {extn1 } , {extn2 } } ] }
	 */

	/*
	 * Encode any extensions and add to the attributes section.
	 */
	if (tbscsr->extensions.numberOfExtensions > 0) {
		extnasn1 = kmfder_alloc();
		if (extnasn1 == NULL) {
			ret = KMF_ERR_MEMORY;
			goto cleanup;
		}

		if (kmfber_printf(extnasn1, "{D[{",
		    &extension_request_oid) == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup_1;
		}

		if ((ret = encode_extension_list(extnasn1,
		    &tbscsr->extensions)) != KMF_OK) {
			goto cleanup_1;
		}

		if (kmfber_printf(extnasn1, "}]}") == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup_1;
		}

		if (kmfber_flatten(extnasn1, &extnvalue) == -1) {
			ret = KMF_ERR_MEMORY;
			goto cleanup_1;
		}
cleanup_1:
		kmfber_free(extnasn1, 1);

		if (ret == KMF_OK)
			/* Add 2 bytes to cover the tag and the length */
			attlen = extnvalue->bv_len;
	}
	if (ret != KMF_OK)
		goto cleanup;

	if (kmfber_printf(asn1, "l", attlen) == -1) {
		ret = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Write the actual encoded extensions */
	if (extnvalue != NULL && extnvalue->bv_val != NULL) {
		if (kmfber_write(asn1, extnvalue->bv_val,
		    extnvalue->bv_len, 0) == -1) {
			ret = KMF_ERR_ENCODING;
			goto cleanup;
		}
	}

cleanup:
	/*
	 * Memory cleanup is done in the caller or in the individual
	 * encoding routines.
	 */
	if (extnvalue) {
		if (extnvalue->bv_val)
			free(extnvalue->bv_val);
		free(extnvalue);
	}

	return (ret);
}

static KMF_RETURN
encode_tbs_csr(BerElement *asn1, KMF_TBS_CSR *tbscsr)
{
	KMF_RETURN ret = KMF_OK;
	uint32_t version;

	/* Start the version */
	(void) memcpy(&version, tbscsr->version.Data,
	    tbscsr->version.Length);

	if (kmfber_printf(asn1, "{i", version) == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* Encode the Subject RDN */
	if ((ret = encode_rdn(asn1, &tbscsr->subject)) != KMF_OK)
		goto cleanup;

	/* Encode the Subject Public Key Info */
	if ((ret = encode_spki(asn1, &tbscsr->subjectPublicKeyInfo)) != KMF_OK)
		goto cleanup;

	if ((ret = encode_csr_extensions(asn1, tbscsr)) != KMF_OK)
		goto cleanup;

	/* Close out the TBSCert sequence */
	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

cleanup:
	return (ret);
}

KMF_RETURN
DerEncodeDSAPrivateKey(KMF_DATA *encodedkey, KMF_RAW_DSA_KEY *dsa)
{
	KMF_RETURN rv = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue  *dsadata = NULL;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "I",
	    dsa->value.val, dsa->value.len) == -1) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}

	if (kmfber_flatten(asn1, &dsadata) == -1) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}

	encodedkey->Data = (uchar_t *)dsadata->bv_val;
	encodedkey->Length = dsadata->bv_len;

	free(dsadata);
cleanup:
	kmfber_free(asn1, 1);
	return (rv);
}

KMF_RETURN
DerEncodeRSAPrivateKey(KMF_DATA *encodedkey, KMF_RAW_RSA_KEY *rsa)
{
	KMF_RETURN rv = KMF_OK;
	BerElement *asn1 = NULL;
	uchar_t ver = 0;
	BerValue  *rsadata = NULL;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "{IIIIIIIII}",
	    &ver, 1,
	    rsa->mod.val, rsa->mod.len,
	    rsa->pubexp.val, rsa->pubexp.len,
	    rsa->priexp.val, rsa->priexp.len,
	    rsa->prime1.val, rsa->prime1.len,
	    rsa->prime2.val, rsa->prime2.len,
	    rsa->exp1.val, rsa->exp1.len,
	    rsa->exp2.val, rsa->exp2.len,
	    rsa->coef.val, rsa->coef.len) == -1)
		goto cleanup;

	if (kmfber_flatten(asn1, &rsadata) == -1) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}

	encodedkey->Data = (uchar_t *)rsadata->bv_val;
	encodedkey->Length = rsadata->bv_len;

	free(rsadata);
cleanup:
	kmfber_free(asn1, 1);
	return (rv);
}

KMF_RETURN
DerEncodeECPrivateKey(KMF_DATA *encodedkey, KMF_RAW_EC_KEY *eckey)
{
	KMF_RETURN rv = KMF_OK;
	BerElement *asn1 = NULL;
	uchar_t ver = 1;
	BerValue  *data = NULL;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "{io",
	    ver, eckey->value.val, eckey->value.len) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	/*
	 * Indicate that we are using the named curve option
	 * for the parameters.
	 */
	if (kmfber_printf(asn1, "T", 0xA0) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	if (kmfber_printf(asn1, "l", eckey->params.Length) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	if (kmfber_write(asn1, (char *)eckey->params.Data,
	    eckey->params.Length, 0) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	if (kmfber_printf(asn1, "}") == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	if (kmfber_flatten(asn1, &data) == -1) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}
	encodedkey->Data = (uchar_t *)data->bv_val;
	encodedkey->Length = data->bv_len;

cleanup:
	kmfber_free(asn1, 1);
	return (rv);
}


KMF_RETURN
DerEncodeTbsCsr(KMF_TBS_CSR *tbs_csr_ptr,
	KMF_DATA *enc_tbs_csr_ptr)
{
	KMF_RETURN ret;
	BerValue  *tbsdata = NULL;
	BerElement *asn1 = NULL;

	asn1 = kmfder_alloc();

	enc_tbs_csr_ptr->Data = NULL;
	enc_tbs_csr_ptr->Length = 0;

	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	ret = encode_tbs_csr(asn1, tbs_csr_ptr);
	if (ret != KMF_OK)
		goto cleanup;

	if (kmfber_flatten(asn1, &tbsdata) == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	enc_tbs_csr_ptr->Data = (uchar_t *)tbsdata->bv_val;
	enc_tbs_csr_ptr->Length = tbsdata->bv_len;

cleanup:
	if (ret != KMF_OK)
		free_data(enc_tbs_csr_ptr);

	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (tbsdata)
		free(tbsdata);

	return (ret);
}

KMF_RETURN
DerEncodeSignedCsr(KMF_CSR_DATA *signed_csr_ptr,
	KMF_DATA *encodedcsr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_TBS_CSR *tbscsr = NULL;
	KMF_X509_SIGNATURE		*signature = NULL;
	BerElement	*asn1 = NULL;
	BerValue 	*tbsdata = NULL;

	if (signed_csr_ptr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	tbscsr = &signed_csr_ptr->csr;
	signature = &signed_csr_ptr->signature;

	asn1 = kmfder_alloc();
	if (asn1 == NULL)
		return (KMF_ERR_MEMORY);

	/* Start outer CSR SEQUENCE */
	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	ret = encode_tbs_csr(asn1, tbscsr);

	/* Add the Algorithm & Signature Sequence */
	if ((ret = encode_algoid(asn1,
	    &signature->algorithmIdentifier, FALSE)) != KMF_OK)
		goto cleanup;

	if (signature->encrypted.Length > 0) {
		if (kmfber_printf(asn1, "B", signature->encrypted.Data,
		    signature->encrypted.Length * 8) == -1) {
			ret = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}
	}

	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (kmfber_flatten(asn1, &tbsdata) == -1) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	encodedcsr->Data = (uchar_t *)tbsdata->bv_val;
	encodedcsr->Length = tbsdata->bv_len;

cleanup:
	if (ret != KMF_OK) {
		free_data(encodedcsr);
	}

	if (tbsdata)
		free(tbsdata);

	if (asn1)
		kmfber_free(asn1, 1);
	return (ret);
}

static KMF_RETURN
ber_copy_data(KMF_DATA *dst, KMF_DATA *src)
{
	KMF_RETURN ret = KMF_OK;

	if (dst == NULL || src == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dst->Data = malloc(src->Length);
	if (dst->Data == NULL)
		return (KMF_ERR_MEMORY);

	dst->Length = src->Length;
	(void) memcpy(dst->Data, src->Data, src->Length);

	return (ret);
}

KMF_RETURN
ExtractSPKIData(
	const KMF_X509_SPKI *pKey,
	KMF_ALGORITHM_INDEX AlgorithmId,
	KMF_DATA *pKeyParts,
	uint32_t *uNumKeyParts)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue 	*P, *Q, *G, *Mod, *Exp, *PubKey;
	BerValue	PubKeyParams, PubKeyData;

	if (pKeyParts == NULL || uNumKeyParts == NULL || pKey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	switch (AlgorithmId) {
		case KMF_ALGID_DSA:
		case KMF_ALGID_SHA1WithDSA:
			*uNumKeyParts = 0;
			/* Get the parameters from the algorithm definition */
			PubKeyParams.bv_val =
			    (char *)pKey->algorithm.parameters.Data;
			PubKeyParams.bv_len = pKey->algorithm.parameters.Length;
			if ((asn1 = kmfder_init(&PubKeyParams)) == NULL)
				return (KMF_ERR_MEMORY);

			if (kmfber_scanf(asn1, "{III}", &P, &Q, &G) == -1) {
				kmfber_free(asn1, 1);
				return (KMF_ERR_BAD_KEY_FORMAT);
			}
			pKeyParts[KMF_DSA_PRIME].Data = (uchar_t *)P->bv_val;
			pKeyParts[KMF_DSA_PRIME].Length = P->bv_len;
			pKeyParts[KMF_DSA_SUB_PRIME].Data =
			    (uchar_t *)Q->bv_val;
			pKeyParts[KMF_DSA_SUB_PRIME].Length = Q->bv_len;
			pKeyParts[KMF_DSA_BASE].Data = (uchar_t *)G->bv_val;
			pKeyParts[KMF_DSA_BASE].Length = G->bv_len;

			free(P);
			free(Q);
			free(G);
			kmfber_free(asn1, 1);

			/* Get the PubKey data */
			PubKeyData.bv_val = (char *)pKey->subjectPublicKey.Data;
			PubKeyData.bv_len = pKey->subjectPublicKey.Length;
			if ((asn1 = kmfder_init(&PubKeyData)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto cleanup;
			}
			PubKey = NULL;
			if (kmfber_scanf(asn1, "I", &PubKey) == -1) {
				ret = KMF_ERR_BAD_KEY_FORMAT;
				goto cleanup;
			}
			pKeyParts[KMF_DSA_PUBLIC_VALUE].Data =
			    (uchar_t *)PubKey->bv_val;
			pKeyParts[KMF_DSA_PUBLIC_VALUE].Length = PubKey->bv_len;

			free(PubKey);

			*uNumKeyParts = KMF_NUMBER_DSA_PUBLIC_KEY_PARTS;
			break;
		case KMF_ALGID_SHA1WithECDSA:
		case KMF_ALGID_ECDSA:
			(void) ber_copy_data(&pKeyParts[KMF_ECDSA_PARAMS],
			    (KMF_DATA *)&pKey->algorithm.parameters);

			(void) ber_copy_data(&pKeyParts[KMF_ECDSA_POINT],
			    (KMF_DATA *)&pKey->subjectPublicKey);

			*uNumKeyParts = 2;
			break;

		case KMF_ALGID_RSA:
		case KMF_ALGID_MD2WithRSA:
		case KMF_ALGID_MD5WithRSA:
		case KMF_ALGID_SHA1WithRSA:
			*uNumKeyParts = 0;
			PubKeyData.bv_val = (char *)pKey->subjectPublicKey.Data;
			PubKeyData.bv_len = pKey->subjectPublicKey.Length;
			if ((asn1 = kmfder_init(&PubKeyData)) == NULL) {
				ret = KMF_ERR_MEMORY;
				goto cleanup;
			}
			if (kmfber_scanf(asn1, "{II}", &Mod, &Exp) == -1) {
				ret = KMF_ERR_BAD_KEY_FORMAT;
				goto cleanup;
			}
			pKeyParts[KMF_RSA_MODULUS].Data =
			    (uchar_t *)Mod->bv_val;
			pKeyParts[KMF_RSA_MODULUS].Length = Mod->bv_len;
			pKeyParts[KMF_RSA_PUBLIC_EXPONENT].Data =
			    (uchar_t *)Exp->bv_val;
			pKeyParts[KMF_RSA_PUBLIC_EXPONENT].Length = Exp->bv_len;
			*uNumKeyParts = KMF_NUMBER_RSA_PUBLIC_KEY_PARTS;

			free(Mod);
			free(Exp);
			break;
		default:
			return (KMF_ERR_BAD_PARAMETER);
	}
cleanup:
	if (ret != KMF_OK) {
		int i;
		for (i = 0; i < *uNumKeyParts; i++)
			free_data(&pKeyParts[i]);
	}
	if (asn1 != NULL) {
		kmfber_free(asn1, 1);
	}

	return (ret);
}

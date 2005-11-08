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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the import operation for this tool.
 * The basic flow of the process is to decrypt the PKCS#12
 * input file if it has a password, parse the elements in
 * the file, find the soft token, log into it, import the
 * PKCS#11 objects into the soft token, and log out.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"
#include "biginteger.h"
#include "osslcommon.h"
#include "p12common.h"
#include <openssl/pkcs12.h>
#include <openssl/err.h>

/*
 * Helper function decrypt and parse PKCS#12 import file.
 */
static CK_RV
extract_pkcs12(BIO *fbio, CK_UTF8CHAR *pin, CK_ULONG pinlen,
	EVP_PKEY **priv_key, X509 **cert, STACK_OF(X509) **ca)
/* ARGSUSED */
{
	PKCS12		*pk12, *pk12_tmp;
	EVP_PKEY	*temp_pkey = NULL;
	X509		*temp_cert = NULL;
	STACK_OF(X509)	*temp_ca = NULL;

	cryptodebug("inside extract_pkcs12");

	cryptodebug("calling PKCS12_new");
	if ((pk12 = PKCS12_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create PKCS#12 context."));
		return (CKR_GENERAL_ERROR);
	}

	cryptodebug("calling d2i_PKCS12_bio");
	if ((pk12_tmp = d2i_PKCS12_bio(fbio, &pk12)) == NULL) {
		/* This is ok; it seems to mean there is no more to read. */
		if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_ASN1 &&
		    ERR_GET_REASON(ERR_peek_error()) == ASN1_R_HEADER_TOO_LONG)
			goto end_extract_pkcs12;

		cryptoerror(LOG_STDERR, gettext(
		    "Unable to populate PKCS#12 context."));
		PKCS12_free(pk12);
		return (CKR_GENERAL_ERROR);
	}
	pk12 = pk12_tmp;

	cryptodebug("calling PKCS12_parse");
	if (PKCS12_parse(pk12, (char *)pin, &temp_pkey, &temp_cert,
	    &temp_ca) <= 0) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to parse import file."));
		PKCS12_free(pk12);
		return (CKR_GENERAL_ERROR);
	}

end_extract_pkcs12:

	*priv_key = temp_pkey;
	*cert = temp_cert;
	*ca = temp_ca;

	PKCS12_free(pk12);
	return (CKR_OK);
}

/*
 * Converts OpenSSL BIGNUM into PKCS#11 biginteger_t format.
 */
static CK_RV
cvt_bn2bigint(BIGNUM *from, biginteger_t *to)
{
	CK_BYTE		*temp;
	CK_ULONG	temp_alloc_sz, temp_cvt_sz;

	cryptodebug("inside cvt_bn2bigint");

	if (from == NULL || to == NULL)
		return (CKR_ARGUMENTS_BAD);

	cryptodebug("calling BN_num_bytes");
	temp_alloc_sz = BN_num_bytes(from);
	if ((temp = malloc(temp_alloc_sz)) == NULL)
		return (CKR_HOST_MEMORY);

	cryptodebug("calling BN_bn2bin");
	temp_cvt_sz = BN_bn2bin(from, (unsigned char *)temp);
	if (temp_cvt_sz != temp_alloc_sz)
		return (CKR_GENERAL_ERROR);

	to->big_value = temp;
	to->big_value_len = temp_cvt_sz;
	return (CKR_OK);
}

/*
 * Write RSA private key to token.
 */
static CK_RV
write_rsa_private(CK_SESSION_HANDLE sess, RSA *rsa, X509 *cert)
{
	CK_RV		rv = CKR_OK;
	int		i = 0;
	static CK_OBJECT_CLASS	objclass = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE	keytype = CKK_RSA;
	CK_BYTE		*label = NULL;
	CK_ULONG	label_len = 0;
	CK_BYTE		*id = NULL;
	CK_ULONG	id_len = 0;
	CK_DATE		startdate = { "", "", "" };
	CK_DATE		enddate = { "", "", "" };
	char		tmpdate[8];
	biginteger_t	mod = { NULL, 0 };	/* required */
	biginteger_t	pubexp = { NULL, 0 };	/* required */
	biginteger_t	priexp = { NULL, 0 };	/* optional */
	biginteger_t	prime1 = { NULL, 0 };	/* optional */
	biginteger_t	prime2 = { NULL, 0 };	/* optional */
	biginteger_t	exp1 = { NULL, 0 };	/* optional */
	biginteger_t	exp2 = { NULL, 0 };	/* optional */
	biginteger_t	coef = { NULL, 0 };	/* optional */
	CK_ATTRIBUTE	rsa_pri_attrs[16] = {
		{ CKA_CLASS, &objclass, sizeof (objclass) },
		{ CKA_KEY_TYPE, &keytype, sizeof (keytype) },
		{ CKA_PRIVATE, &pk_true, sizeof (pk_true) },
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_ID, NULL, 0 },
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		{ 0 /* CKA_PRIVATE_EXPONENT */, NULL, 0 },	/* optional */
		{ 0 /* CKA_PRIME_1 */, NULL, 0 },		/*  |  */
		{ 0 /* CKA_PRIME_2 */, NULL, 0 },		/*  |  */
		{ 0 /* CKA_EXPONENT_1 */, NULL, 0 },		/*  |  */
		{ 0 /* CKA_EXPONENT_2 */, NULL, 0 },		/*  |  */
		{ 0 /* CKA_COEFFICIENT */, NULL, 0 }		/*  V  */
	    };
	CK_ULONG	count = sizeof (rsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	CK_OBJECT_HANDLE	obj;

	cryptodebug("inside write_rsa_private");

	/* Attributes start at array index 4. */
	i = 4;

	/* Recycle the certificate label for the private key label. */
	cryptodebug("calling X509_alias_get0");
	if ((label = X509_alias_get0(cert, (int *)&label_len)) == NULL) {
		label = (CK_BYTE *)gettext("no label");
		label_len = strlen((char *)label);
	}
	copy_string_to_attr(label, label_len, &(rsa_pri_attrs[i++]));

	/* Recycle the certificate id for the private key id. */
	cryptodebug("calling PKTOOL_X509_keyid_get0");
	if ((id = PKTOOL_X509_keyid_get0(cert, (int *)&id_len)) == NULL) {
		id = (CK_BYTE *)gettext("no id");
		id_len = strlen((char *)id);
	}
	copy_string_to_attr(id, id_len, &(rsa_pri_attrs[i++]));

	/* Recycle the certificate start and end dates for private key.  */
	cryptodebug("calling X509_get_notBefore");
	if (PKTOOL_cvt_ossltime(X509_get_notBefore(cert), tmpdate)) {
		(void) memcpy(&startdate, tmpdate, sizeof (startdate));
		copy_string_to_attr((CK_BYTE *)&startdate, sizeof (startdate),
		    &(rsa_pri_attrs[i++]));
	}

	cryptodebug("calling X509_get_notAfter");
	if (PKTOOL_cvt_ossltime(X509_get_notAfter(cert), tmpdate)) {
		(void) memcpy(&enddate, tmpdate, sizeof (enddate));
		copy_string_to_attr((CK_BYTE *)&enddate, sizeof (enddate),
		    &(rsa_pri_attrs[i++]));
	}

	/* Modulus n */
	cryptodebug("converting RSA private key modulus");
	if ((rv = cvt_bn2bigint(rsa->n, &mod)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert RSA private key modulus."));
		return (rv);
	}
	copy_bigint_to_attr(mod, &(rsa_pri_attrs[i++]));

	/* Public exponent e */
	cryptodebug("converting RSA private key public exponent");
	if ((rv = cvt_bn2bigint(rsa->e, &pubexp)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert RSA private key public exponent."));
		return (rv);
	}
	copy_bigint_to_attr(pubexp, &(rsa_pri_attrs[i++]));

	/* Private exponent d */
	if (rsa->d != NULL) {
		cryptodebug("converting RSA private key private exponent");
		if ((rv = cvt_bn2bigint(rsa->d, &priexp)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext("Unable to convert "
			    "RSA private key private exponent."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_PRIVATE_EXPONENT;
		copy_bigint_to_attr(priexp, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key private exponent");

	/* Prime p */
	if (rsa->p != NULL) {
		cryptodebug("converting RSA private key prime 1");
		if ((rv = cvt_bn2bigint(rsa->p, &prime1)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key prime 1."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_PRIME_1;
		copy_bigint_to_attr(prime1, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key prime 1");

	/* Prime q */
	if (rsa->q != NULL) {
		cryptodebug("converting RSA private key prime 2");
		if ((rv = cvt_bn2bigint(rsa->q, &prime2)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key prime 2."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_PRIME_2;
		copy_bigint_to_attr(prime2, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key prime 2");

	/* Private exponent d modulo p-1 */
	if (rsa->dmp1 != NULL) {
		cryptodebug("converting RSA private key exponent 1");
		if ((rv = cvt_bn2bigint(rsa->dmp1, &exp1)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key exponent 1."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_EXPONENT_1;
		copy_bigint_to_attr(exp1, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key exponent 1");

	/* Private exponent d modulo q-1 */
	if (rsa->dmq1 != NULL) {
		cryptodebug("converting RSA private key exponent 2");
		if ((rv = cvt_bn2bigint(rsa->dmq1, &exp2)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key exponent 2."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_EXPONENT_2;
		copy_bigint_to_attr(exp2, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key exponent 2");

	/* CRT coefficient q-inverse mod p */
	if (rsa->iqmp != NULL) {
		cryptodebug("converting RSA private key coefficient");
		if ((rv = cvt_bn2bigint(rsa->iqmp, &coef)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key coefficient."));
			return (rv);
		}
		rsa_pri_attrs[i].type = CKA_COEFFICIENT;
		copy_bigint_to_attr(coef, &(rsa_pri_attrs[i++]));
	} else
		cryptodebug("no RSA private key coefficient");

	/* Indicates programming error:  attributes overran the template */
	if (i > count) {
		cryptodebug("error: more attributes found than accounted for");
		i = count;
	}

	cryptodebug("calling C_CreateObject");
	if ((rv = C_CreateObject(sess, rsa_pri_attrs, i, &obj)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create RSA private key object."));
		return (rv);
	}

	return (CKR_OK);
}

/*
 * Write DSA private key to token.
 */
static CK_RV
write_dsa_private(CK_SESSION_HANDLE sess, DSA *dsa, X509 *cert)
{
	CK_RV		rv = CKR_OK;
	int		i = 0;
	static CK_OBJECT_CLASS	objclass = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE	keytype = CKK_DSA;
	CK_BYTE		*label = NULL;
	CK_ULONG	label_len = 0;
	CK_BYTE		*id = NULL;
	CK_ULONG	id_len = 0;
	CK_DATE		startdate = { "", "", "" };
	CK_DATE		enddate = { "", "", "" };
	char		tmpdate[8];
	biginteger_t	prime = { NULL, 0 };	/* required */
	biginteger_t	subprime = { NULL, 0 };	/* required */
	biginteger_t	base = { NULL, 0 };	/* required */
	biginteger_t	value = { NULL, 0 };	/* required */
	CK_ATTRIBUTE	dsa_pri_attrs[12] = {
		{ CKA_CLASS, &objclass, sizeof (objclass) },
		{ CKA_KEY_TYPE, &keytype, sizeof (keytype) },
		{ CKA_PRIVATE, &pk_true, sizeof (pk_true) },
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_ID, NULL, 0 },
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	    };
	CK_ULONG	count = sizeof (dsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	CK_OBJECT_HANDLE	obj;

	cryptodebug("inside write_dsa_private");

	/* Attributes start at array index 4. */
	i = 4;

	/* Recycle the certificate label for the private key label. */
	cryptodebug("calling X509_alias_get0");
	if ((label = X509_alias_get0(cert, (int *)&label_len)) == NULL) {
		label = (CK_BYTE *)gettext("no label");
		label_len = strlen((char *)label);
	}
	copy_string_to_attr(label, label_len, &(dsa_pri_attrs[i++]));

	/* Recycle the certificate id for the private key id. */
	cryptodebug("calling PKTOOL_X509_keyid_get0");
	if ((id = PKTOOL_X509_keyid_get0(cert, (int *)&id_len)) == NULL) {
		id = (CK_BYTE *)gettext("no id");
		id_len = strlen((char *)id);
	}
	copy_string_to_attr(id, id_len, &(dsa_pri_attrs[i++]));

	/* Recycle the certificate start and end dates for private key.  */
	cryptodebug("calling X509_get_notBefore");
	if (PKTOOL_cvt_ossltime(X509_get_notBefore(cert), tmpdate)) {
		(void) memcpy(&startdate, tmpdate, sizeof (startdate));
		copy_string_to_attr((CK_BYTE *)&startdate, sizeof (startdate),
		    &(dsa_pri_attrs[i++]));
	}

	cryptodebug("calling X509_get_notAfter");
	if (PKTOOL_cvt_ossltime(X509_get_notAfter(cert), tmpdate)) {
		(void) memcpy(&enddate, tmpdate, sizeof (enddate));
		copy_string_to_attr((CK_BYTE *)&enddate, sizeof (enddate),
		    &(dsa_pri_attrs[i++]));
	}

	/* Prime p */
	cryptodebug("converting DSA private key prime");
	if ((rv = cvt_bn2bigint(dsa->p, &prime)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key prime."));
		return (rv);
	}
	copy_bigint_to_attr(prime, &(dsa_pri_attrs[i++]));

	/* Subprime q */
	cryptodebug("converting DSA private key subprime");
	if ((rv = cvt_bn2bigint(dsa->q, &subprime)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key subprime."));
		return (rv);
	}
	copy_bigint_to_attr(subprime, &(dsa_pri_attrs[i++]));

	/* Base g */
	cryptodebug("converting DSA private key base");
	if ((rv = cvt_bn2bigint(dsa->g, &base)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key base."));
		return (rv);
	}
	copy_bigint_to_attr(base, &(dsa_pri_attrs[i++]));

	/* Private key x */
	cryptodebug("converting DSA private key value");
	if ((rv = cvt_bn2bigint(dsa->priv_key, &value)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key value."));
		return (rv);
	}
	copy_bigint_to_attr(value, &(dsa_pri_attrs[i++]));

	/* Indicates programming error:  attributes overran the template */
	if (i > count) {
		cryptodebug("error: more attributes found than accounted for");
		i = count;
	}

	cryptodebug("calling C_CreateObject");
	if ((rv = C_CreateObject(sess, dsa_pri_attrs, i, &obj)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create DSA private key object."));
		return (rv);
	}

	return (CKR_OK);
}

/*
 * Write DH private key to token.
 */
static CK_RV
write_dh_private(CK_SESSION_HANDLE sess, DH *dh, X509 *cert)
{
	CK_RV		rv = CKR_OK;
	int		i = 0;
	static CK_OBJECT_CLASS	objclass = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE	keytype = CKK_DH;
	CK_BYTE		*label = NULL;
	CK_ULONG	label_len = 0;
	CK_BYTE		*id = NULL;
	CK_ULONG	id_len = 0;
	CK_DATE		startdate = { "", "", "" };
	CK_DATE		enddate = { "", "", "" };
	char		tmpdate[8];
	biginteger_t	prime = { NULL, 0 };	/* required */
	biginteger_t	base = { NULL, 0 };	/* required */
	biginteger_t	value = { NULL, 0 };	/* required */
	CK_ATTRIBUTE	dh_pri_attrs[11] = {
		{ CKA_CLASS, &objclass, sizeof (objclass) },
		{ CKA_KEY_TYPE, &keytype, sizeof (keytype) },
		{ CKA_PRIVATE, &pk_true, sizeof (pk_true) },
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_ID, NULL, 0 },
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	    };
	CK_ULONG	count = sizeof (dh_pri_attrs) / sizeof (CK_ATTRIBUTE);
	CK_OBJECT_HANDLE	obj;

	cryptodebug("inside write_dh_private");

	/* Attributes start at array index 4. */
	i = 4;

	/* Recycle the certificate label for the private key label. */
	cryptodebug("calling X509_alias_get0");
	if ((label = X509_alias_get0(cert, (int *)&label_len)) == NULL) {
		label = (CK_BYTE *)gettext("no label");
		label_len = strlen((char *)label);
	}
	copy_string_to_attr(label, label_len, &(dh_pri_attrs[i++]));

	/* Recycle the certificate id for the private key id. */
	cryptodebug("PKTOOL_X509_keyid_get0");
	if ((id = PKTOOL_X509_keyid_get0(cert, (int *)&id_len)) == NULL) {
		id = (CK_BYTE *)gettext("no id");
		id_len = strlen((char *)id);
	}
	copy_string_to_attr(id, id_len, &(dh_pri_attrs[i++]));

	/* Recycle the certificate start and end dates for private key.  */
	cryptodebug("calling X509_get_notBefore");
	if (PKTOOL_cvt_ossltime(X509_get_notBefore(cert), tmpdate)) {
		(void) memcpy(&startdate, tmpdate, sizeof (startdate));
		copy_string_to_attr((CK_BYTE *)&startdate, sizeof (startdate),
		    &(dh_pri_attrs[i++]));
	}

	cryptodebug("calling X509_get_notAfter");
	if (PKTOOL_cvt_ossltime(X509_get_notAfter(cert), tmpdate)) {
		(void) memcpy(&enddate, tmpdate, sizeof (enddate));
		copy_string_to_attr((CK_BYTE *)&enddate, sizeof (enddate),
		    &(dh_pri_attrs[i++]));
	}

	/* Prime p */
	cryptodebug("converting DH private key prime");
	if ((rv = cvt_bn2bigint(dh->p, &prime)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key prime."));
		return (rv);
	}
	copy_bigint_to_attr(prime, &(dh_pri_attrs[i++]));

	/* Base g */
	cryptodebug("converting DH private key base");
	if ((rv = cvt_bn2bigint(dh->g, &base)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key base."));
		return (rv);
	}
	copy_bigint_to_attr(base, &(dh_pri_attrs[i++]));

	/* Private value x */
	cryptodebug("converting DH private key value");
	if ((rv = cvt_bn2bigint(dh->priv_key, &value)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key value."));
		return (rv);
	}
	copy_bigint_to_attr(value, &(dh_pri_attrs[i++]));

	/* Indicates programming error:  attributes overran the template */
	if (i > count) {
		cryptodebug("error: more attributes found than accounted for");
		i = count;
	}

	cryptodebug("calling C_CreateObject");
	if ((rv = C_CreateObject(sess, dh_pri_attrs, i, &obj)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create DH private key object."));
		return (rv);
	}

	return (CKR_OK);
}

/*
 * Write certificate to token.
 */
static CK_RV
write_cert(CK_SESSION_HANDLE sess, X509 *cert)
{
	CK_RV		rv = CKR_OK;
	int		i = 0;
	static CK_OBJECT_CLASS	objclass = CKO_CERTIFICATE;
	static CK_CERTIFICATE_TYPE	certtype = CKC_X_509;
	CK_BYTE		*subject = NULL;
	CK_ULONG	subject_len = 0;
	CK_BYTE		*value = NULL;
	CK_ULONG	value_len = 0;
	CK_BYTE		*label = NULL;
	CK_ULONG	label_len = 0;
	CK_BYTE		*id = NULL;
	CK_ULONG	id_len = 0;
	CK_BYTE		*issuer = NULL;
	CK_ULONG	issuer_len = 0;
	CK_BYTE		*serial = NULL;
	CK_ULONG	serial_len = 0;
	CK_ATTRIBUTE	cert_attrs[9] = {
		{ CKA_CLASS, &objclass, sizeof (objclass) },
		{ CKA_CERTIFICATE_TYPE, &certtype, sizeof (certtype) },
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ CKA_SUBJECT, NULL, 0 },		/* required */
		{ CKA_VALUE, NULL, 0 },			/* required */
		{ 0 /* CKA_LABEL */, NULL, 0 },		/* optional */
		{ 0 /* CKA_ID */, NULL, 0 },		/* optional */
		{ 0 /* CKA_ISSUER */, NULL, 0 },	/* optional */
		{ 0 /* CKA_SERIAL_NUMBER */, NULL, 0 }	/* optional */
	    };
	CK_ULONG	count = sizeof (cert_attrs) / sizeof (CK_ATTRIBUTE);
	CK_OBJECT_HANDLE	obj;

	cryptodebug("inside write_cert");

	/* Attributes start at array index 3. */
	i = 3;

	/*
	 * OpenSSL subject name and issuer (a little further below) are
	 * actually stack structures that contain individual ASN.1
	 * components.  This stack of entries is packed into one DER string.
	 */
	cryptodebug("calling PKTOOL_X509_subject_name");
	if ((subject = PKTOOL_X509_subject_name(cert, (int *)&subject_len)) ==
	    NULL) {
		subject = (CK_BYTE *)gettext("no subject name");
		subject_len = strlen((char *)subject);
	}
	copy_string_to_attr(subject, subject_len, &(cert_attrs[i++]));

	/* Get cert value, but it has to be reconstructed from cert.  */
	cryptodebug("calling PKTOOL_X509_cert_value");
	if ((value = PKTOOL_X509_cert_value(cert, (int *)&value_len)) == NULL) {
		value = (CK_BYTE *)gettext("no value");
		value_len = strlen((char *)value);
	}
	copy_string_to_attr(value, value_len, &(cert_attrs[i++]));

	/*
	 * Get certificate label which is "friendlyName" Netscape,
	 * "alias" in OpenSSL.
	 */
	if ((label = X509_alias_get0(cert, (int *)&label_len)) == NULL) {
		cryptodebug("no certificate label");
	} else {
		cert_attrs[i].type = CKA_LABEL;
		copy_string_to_attr(label, label_len, &(cert_attrs[i++]));
	}

	/* Get the keyid for the cert. */
	if ((id = PKTOOL_X509_keyid_get0(cert, (int *)&id_len)) == NULL) {
		cryptodebug("no certificate id");
	} else {
		cert_attrs[i].type = CKA_ID;
		copy_string_to_attr(id, id_len, &(cert_attrs[i++]));
	}

	/* Get the issuer name for the cert. */
	if ((issuer = PKTOOL_X509_issuer_name(cert, (int *)&issuer_len)) ==
	    NULL) {
		cryptodebug("no certificate issuer name");
	} else {
		cert_attrs[i].type = CKA_ISSUER;
		copy_string_to_attr(issuer, issuer_len, &(cert_attrs[i++]));
	}

	/* Get the cert serial number. */
	if ((serial  = PKTOOL_X509_serial_number(cert, (int *)&serial_len)) ==
	    NULL) {
		cryptodebug("no certificate serial number");
	} else {
		cert_attrs[i].type = CKA_SERIAL_NUMBER;
		copy_string_to_attr(serial, serial_len, &(cert_attrs[i++]));
	}

	/* Indicates programming error:  attributes overran the template */
	if (i > count) {
		cryptodebug("error: more attributes found than accounted for");
		i = count;
	}

	cryptodebug("calling C_CreateObject");
	if ((rv = C_CreateObject(sess, cert_attrs, i, &obj)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create X.509 certificate object."));
		return (rv);
	}

	return (CKR_OK);
}

/*
 * Helper function to write PKCS#12 items to token.  Returns CKR_OK
 * or CKR_GENERAL_ERROR
 */
static CK_RV
write_token_objs(CK_SESSION_HANDLE sess, EVP_PKEY *priv_key, X509 *cert,
	    STACK_OF(X509) *ca, int *successes, int *failures)
{
	int		i;
	X509		*c;
	CK_RV		rv = CKR_OK;

	cryptodebug("inside write_token_objs");

	/* Do not reset *successes or *failures -- keep running totals. */

	/* Import user key. */
	switch (priv_key->type) {
	case EVP_PKEY_RSA:
		(void) fprintf(stdout, gettext("Writing RSA private key...\n"));
		if ((rv = write_rsa_private(sess,
		    EVP_PKEY_get1_RSA(priv_key), cert)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write RSA private key (%s)."),
			    pkcs11_strerror(rv));
			(*failures)++;
		} else
			(*successes)++;
		break;
	case EVP_PKEY_DSA:
		(void) fprintf(stdout, gettext("Writing DSA private key...\n"));
		if ((rv = write_dsa_private(sess,
		    EVP_PKEY_get1_DSA(priv_key), cert)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write DSA private key (%s)."),
			    pkcs11_strerror(rv));
			(*failures)++;
		} else
			(*successes)++;
		break;
	case EVP_PKEY_DH:
		(void) fprintf(stdout, gettext("Writing DH private key...\n"));
		if ((rv = write_dh_private(sess,
		    EVP_PKEY_get1_DH(priv_key), cert)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write DH private key (%s)."),
			    pkcs11_strerror(rv));
			(*failures)++;
		} else
			(*successes)++;
		break;

	default:
		/*
		 * Note that EVP_PKEY_DH for X9.42 is not implemented
		 * in the OpenSSL library.
		 */
		cryptoerror(LOG_STDERR, gettext(
		    "Private key type 0x%02x import not supported."),
		    priv_key->type);
		(*failures)++;
		break;
	}

	/* Import user certificate. */
	(void) fprintf(stdout, gettext("Writing user certificate...\n"));
	if ((rv = write_cert(sess, cert)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to write user certificate (%s)."),
		    pkcs11_strerror(rv));
		(*failures)++;
	} else
		(*successes)++;

	/* Import as many stacks of authority certificates as possible. */
	for (i = 0; i != sk_X509_num(ca); i++) {
		/*
		 * sk_X509_value() is macro that embeds a cast to (X509 *).
		 * Here it translates into ((X509 *)sk_value((ca), (i))).
		 * Lint is complaining about the embedded casting, and
		 * to fix it, you need to fix openssl header files.
		 */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		c = sk_X509_value(ca, i);
		(void) fprintf(stdout, gettext(
		    "Writing authority certificate...\n"));
		if ((rv = write_cert(sess, c)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write authority certificate (%s)."),
			    pkcs11_strerror(rv));
			(*failures)++;
		} else
			(*successes)++;
	}

	(void) fprintf(stdout, gettext("PKCS#12 element scan completed.\n"));
	return (*failures != 0 ? CKR_GENERAL_ERROR : CKR_OK);
}

/*
 * Import objects from PKCS#12 file into token.
 */
int
pk_import(int argc, char *argv[])
{
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*token_name = NULL;
	char		*manuf_id = NULL;
	char		*serial_no = NULL;
	char		full_name[FULL_NAME_LEN];
	char		*filename = NULL;
	struct stat	statbuf;
	CK_SLOT_ID	slot_id;
	CK_FLAGS	pin_state;
	CK_UTF8CHAR_PTR	pin = NULL;
	CK_ULONG	pinlen = 0;
	CK_UTF8CHAR_PTR	pk12pin = NULL;
	CK_ULONG	pk12pinlen = 0;
	CK_SESSION_HANDLE	sess;
	BIO		*fbio = NULL;
	EVP_PKEY	*priv_key = NULL;
	X509		*cert = NULL;
	STACK_OF(X509)	*ca = NULL;
	CK_RV		rv = CKR_OK;
	int		i;
	int		good_count = 0, bad_count = 0;	/* running totals */

	cryptodebug("inside pk_import");

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv, "T:(token)i:(infile)")) != EOF) {
		switch (opt) {
		case 'T':	/* token specifier */
			if (token_spec)
				return (PK_ERR_USAGE);
			token_spec = optarg_av;
			break;
		case 'i':	/* input file name */
			if (filename)
				return (PK_ERR_USAGE);
			filename = optarg_av;
			break;
		default:
			return (PK_ERR_USAGE);
			break;
		}
	}

	/* If nothing is specified, default is to use softtoken. */
	if (token_spec == NULL) {
		token_name = SOFT_TOKEN_LABEL;
		manuf_id = SOFT_MANUFACTURER_ID;
		serial_no = SOFT_TOKEN_SERIAL;
	} else {
		/*
		 * Parse token specifier into token_name, manuf_id, serial_no.
		 * Token_name is required; manuf_id and serial_no are optional.
		 */
		if (parse_token_spec(token_spec, &token_name, &manuf_id,
		    &serial_no) < 0)
			return (PK_ERR_USAGE);
	}

	/* Filename arg is required. */
	if (filename == NULL)
		return (PK_ERR_USAGE);

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* Check that the file exists and is non-empty. */
	if (access(filename, R_OK) < 0) {
		cryptoerror(LOG_STDERR, gettext("File \"%s\" is unreadable "
		    "(%s)."), filename, strerror(errno));
		return (CKR_OK);
	}
	if (stat(filename, &statbuf) < 0) {
		cryptoerror(LOG_STDERR, gettext("Unable to get size of "
		    "file \"%s\" (%s)."), filename, strerror(errno));
		return (CKR_OK);
	}
	if (statbuf.st_size == 0) {
		cryptoerror(LOG_STDERR, gettext("File \"%s\" is empty."),
		    filename);
		return (CKR_OK);
	}

	full_token_name(token_name, manuf_id, serial_no, full_name);

	/* Find the slot with token. */
	if ((rv = find_token_slot(token_name, manuf_id, serial_no, &slot_id,
	    &pin_state)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to find token %s (%s)."), full_name,
		    pkcs11_strerror(rv));
		return (PK_ERR_PK11);
	}

	/* Get the user's PIN. */
	if ((rv = get_pin(gettext("Enter token passphrase:"), NULL, &pin,
	    &pinlen)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get token passphrase (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(NULL);
		return (PK_ERR_PK11);
	}

	/* Assume user must be logged in R/W to import objects into token. */
	if ((rv = quick_start(slot_id, CKF_RW_SESSION, pin, pinlen, &sess)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to log into token (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	/* Setup OpenSSL context. */
	PKTOOL_setup_openssl();

	/* Open PKCS#12 file. */
	if ((open_pkcs12(filename, &fbio)) < 0) {
		cryptoerror(LOG_STDERR, gettext("Unable to open import file."));
		quick_finish(sess);
		return (PK_ERR_SYSTEM);
	}

	/* Get the PIN for the PKCS#12 import file. */
	if ((rv = get_pin(gettext("Enter import file passphrase:"), NULL,
	    &pk12pin, &pk12pinlen)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get import file passphrase (%s)."),
		    pkcs11_strerror(rv));
		close_pkcs12(fbio);
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	/* PKCS#12 import file may have multiple elements, loop until done. */
	for (i = 0; /* */; i++) {
		/* Extract the contents of the PKCS#12 import file. */
		if ((rv = extract_pkcs12(fbio, pk12pin, pk12pinlen, &priv_key,
		    &cert, &ca)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to parse PKCS#12 element #%d "
			    "in import file (%s)."), i+1, pkcs11_strerror(rv));
			close_pkcs12(fbio);
			quick_finish(sess);
			return (PK_ERR_OPENSSL);
		}

		/* Reached end of import file? */
		if (rv == CKR_OK && priv_key == NULL && cert == NULL &&
		    ca == NULL)
			break;

		(void) fprintf(stdout, gettext(
		    "Scanning PKCS#12 element #%d for objects...\n"), i+1);

		/* Write the objects to the token. */
		if ((rv = write_token_objs(sess, priv_key, cert, ca,
		    &good_count, &bad_count)) != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write PKCS#12 element #%d to token %s."),
			    i+1, full_name);
			close_pkcs12(fbio);
			quick_finish(sess);
			return (PK_ERR_PK11);
		}
	}

	(void) fprintf(stdout, gettext("%d PKCS#12 elements scanned: "
		"%d objects imported, %d errors occurred.\n"), i,
		good_count, bad_count);

	/* Close PKCS#12 file. */
	close_pkcs12(fbio);

	/* Clean up. */
	quick_finish(sess);
	return (0);
}

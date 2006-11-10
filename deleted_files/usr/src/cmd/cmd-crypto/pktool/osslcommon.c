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
 * This file implements some "missing" routines that should
 * be part of the OpenSSL library but are not there yet.
 */

#include <cryptoutil.h>
#include "osslcommon.h"
#include <openssl/pkcs12.h>
#include <openssl/engine.h>

/*
 * OpenSSL usage needs algorithms (ciphers and digests), strings,
 * and engines loaded first to be useful.
 */
void
PKTOOL_setup_openssl(void)
{
	cryptodebug("inside PKTOOL_setup_openssl");

	/* Add all ciphers and digests. */
	OpenSSL_add_all_algorithms();

	/* Load up error message strings. */
	ERR_load_crypto_strings();

	/* Load up PKCS#11 engine. */
	/* ENGINE_load_pk11(); */

	/* Load up builtin crypto engines. */
	/*
	 * This function is actually defined in OpenSSL libcrypto
	 * library.  However it doesn't make its lint library correctly
	 * which is why this lint error occurs.  OpenSSL needs fixing.
	 * Do not put a LINTED comment here because lint will complain
	 * that the directive is ununsed.
	 */
	ENGINE_load_builtin_engines();

	/* U/I methods are not necessary here. */
	/* setup_ui_method(); */
}

/*
 * This should be an OpenSSL function, but they haven't added it yet.
 * See <openssl>/crypto/asn1/x_x509a.c:X509_alias_get0() for the model.
 */
unsigned char	*
PKTOOL_X509_keyid_get0(X509 *x, int *len)
{
	cryptodebug("inside PKTOOL_setup_openssl");

	if (x->aux == NULL || x->aux->keyid == NULL) {
		cryptodebug("certificate aux or aux->keyid is null");
		return (NULL);
	}
	if (len)
		*len = x->aux->keyid->length;
	return (x->aux->keyid->data);
}

/*
 * This should be an OpenSSL function, but couldn't find it yet.
 * It gets the subject name safely without dereferencing null pointers.
 * If it is ever found in OpenSSL, this should be removed and all
 * calls to it need to be replaced with right OpenSSL function.
 */
unsigned char	*
PKTOOL_X509_subject_name(X509 *x, int *len)
{
	X509_NAME	*temp;

	cryptodebug("inside PKTOOL_X509_subject_name");

	if ((temp = X509_get_subject_name(x)) == NULL) {
		cryptodebug("certificate subject name stack is null");
		return (NULL);
	}
	if (temp->bytes == NULL) {
		cryptodebug("certificate subject name stack bytes is null");
		return (NULL);
	}
	if (len)
		*len = temp->bytes->length;
	return ((unsigned char *)temp->bytes->data);
}

/*
 * This should be an OpenSSL function, but couldn't find it yet.
 * It gets the issuer name safely without dereferencing null pointers.
 * If it is ever found in OpenSSL, this should be removed and all
 * calls to it need to be replaced with right OpenSSL function.
 */
unsigned char	*
PKTOOL_X509_issuer_name(X509 *x, int *len)
{
	X509_NAME	*temp;

	cryptodebug("inside PKTOOL_X509_issuer_name");

	if ((temp = X509_get_issuer_name(x)) == NULL) {
		cryptodebug("certificate issuer name stack is null");
		return (NULL);
	}
	if (temp->bytes == NULL) {
		cryptodebug("certificate issuer name stack bytes is null");
		return (NULL);
	}
	if (len)
		*len = temp->bytes->length;
	return ((unsigned char *)temp->bytes->data);
}

/*
 * This should be an OpenSSL function, but couldn't find it yet.
 * It gets the serial number safely without dereferencing null pointers.
 * If it is ever found in OpenSSL, this should be removed and all
 * calls to it need to be replaced with right OpenSSL function.
 */
unsigned char	*
PKTOOL_X509_serial_number(X509 *x, int *len)
{
	ASN1_INTEGER	*temp;

	cryptodebug("inside PKTOOL_X509_serial_number");

	if ((temp = X509_get_serialNumber(x)) == NULL) {
		cryptodebug("certificate serial number is null");
		return (NULL);
	}
	if (len)
		*len = temp->length;
	return (temp->data);
}

/*
 * This should be an OpenSSL function, but couldn't find it yet.
 * It gets the cert value safely without dereferencing null pointers.
 * If it is ever found in OpenSSL, this should be removed and all
 * calls to it need to be replaced with right OpenSSL function.
 */
unsigned char	*
PKTOOL_X509_cert_value(X509 *x, int *len)
{
	PKCS12_SAFEBAG	*bag;

	cryptodebug("inside PKTOOL_X509_cert_value");

	if ((bag = PKCS12_x5092certbag(x)) == NULL) {
		cryptodebug("unable to convert cert to PKCS#12 bag");
		return (NULL);
	}
	if (bag->value.bag == NULL || bag->value.bag->value.x509cert == NULL) {
		cryptodebug("PKCS#12 bag value or cert inside it is null");
		return (NULL);
	}
	if (len)
		*len = bag->value.bag->value.x509cert->length;
	return (bag->value.bag->value.x509cert->data);
}

/*
 * Convert OpenSSL's ASN1_TIME format into a character buffer that
 * can then be converted into PKCS#11 format.  The buffer must be
 * at least 8 bytes long.  The length of the result will be 8 bytes.
 * Return value of 0 indicates failure, 1 indicates success.
 */
int
PKTOOL_cvt_ossltime(ASN1_TIME *t, char *buf)
{
	cryptodebug("inside PKTOOL_cvt_ossltime");

	if (t == NULL) {
		cryptodebug("time string is empty");
		buf[0] = '\0';
		return (0);
	}

	if (t->length == 15) {	/* generalized time: YYYYMMDDmmhhssZ */
		cryptodebug("time string is in generalized format");
		(void) snprintf(buf, 8, "%08.8s", t->data);
		return (1);
	}

	if (t->length == 13) {		/* UTC time: YYMMDDmmhhssZ */
		cryptodebug("time string is in UTC format");
		/* Guess whether its a 197x to 199x date, or a 20xx date. */
		(void) snprintf(buf, 8, "%s%06.6s",
		    ('7' <= t->data[0] && t->data[0] <= '9') ? "19" : "20",
		    t->data);
		return (1);
	}

	cryptodebug("time string is in unknown format");
	buf[0] = '\0';
	return (0);
}

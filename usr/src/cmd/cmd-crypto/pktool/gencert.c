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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <libgen.h>
#include <errno.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

#include <kmfapi.h>

#define	SET_VALUE(f, s) \
	kmfrv = f; \
	if (kmfrv != KMF_OK) { \
		cryptoerror(LOG_STDERR, \
			gettext("Failed to set %s: 0x%02x\n"), \
			s, kmfrv); \
		goto cleanup; \
	}

static int
gencert_pkcs11(KMF_HANDLE_T kmfhandle,
	char *token, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	char *certlabel, KMF_KEY_ALG keyAlg,
	KMF_ALGORITHM_INDEX sigAlg,
	int keylen, uint32_t ltime, KMF_BIGINT *serial,
	uint16_t kubits, int kucrit, KMF_CREDENTIAL *tokencred,
	EKU_LIST *ekulist, KMF_OID *curveoid)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;
	KMF_KEY_ALG keytype;
	uint32_t keylength;

	(void) memset(&signedCert, 0, sizeof (signedCert));
	(void) memset(&certSubject, 0, sizeof (certSubject));
	(void) memset(&certIssuer, 0, sizeof (certIssuer));
	(void) memset(&x509DER, 0, sizeof (x509DER));

	/* If the subject name cannot be parsed, flag it now and exit */
	if (kmf_dn_parser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (kmf_dn_parser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	keylength = keylen; /* bits */
	keytype = keyAlg;

	/* Select a PKCS11 token */
	kmfrv = select_token(kmfhandle, token, FALSE);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	/*
	 * Share the "genkeypair" routine for creating the keypair.
	 */
	kmfrv = genkeypair_pkcs11(kmfhandle, token, certlabel,
	    keytype, keylength, tokencred, curveoid, &prik, &pubk);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	SET_VALUE(kmf_set_cert_pubkey(kmfhandle, &pubk, &signedCert),
	    "keypair");

	SET_VALUE(kmf_set_cert_version(&signedCert, 2), "version number");

	SET_VALUE(kmf_set_cert_serial(&signedCert, serial),
	    "serial number");

	SET_VALUE(kmf_set_cert_validity(&signedCert, NULL, ltime),
	    "validity time");

	SET_VALUE(kmf_set_cert_sig_alg(&signedCert, sigAlg),
	    "signature algorithm");

	SET_VALUE(kmf_set_cert_subject(&signedCert, &certSubject),
	    "subject name");

	SET_VALUE(kmf_set_cert_issuer(&signedCert, &certIssuer),
	    "issuer name");

	if (altname != NULL)
		SET_VALUE(kmf_set_cert_subject_altname(&signedCert, altcrit,
		    alttype, altname), "subjectAltName");

	if (kubits != 0)
		SET_VALUE(kmf_set_cert_ku(&signedCert, kucrit, kubits),
		    "KeyUsage");

	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_cert_eku(&signedCert,
			    &ekulist->ekulist[i], ekulist->critlist[i]),
			    "Extended Key Usage");
		}
	}

	/*
	 * Construct attributes for the kmf_sign_cert operation.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE_ATTR));
	numattr++;

	/* cert data that is to be signed */
	kmf_set_attr_at_index(attrlist, numattr, KMF_X509_CERTIFICATE_ATTR,
	    &signedCert, sizeof (KMF_X509_CERTIFICATE));
	numattr++;

	/* output buffer for the signed cert */
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_ALGORITHM_INDEX_ATTR,
	    &sigAlg, sizeof (sigAlg));
	numattr++;

	if ((kmfrv = kmf_sign_cert(kmfhandle, numattr, attrlist)) !=
	    KMF_OK) {
		goto cleanup;
	}

	/*
	 * Store the cert in the DB.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;

	if (certlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_LABEL_ATTR,
		    certlabel, strlen(certlabel));
		numattr++;
	}

	kmfrv = kmf_store_cert(kmfhandle, numattr, attrlist);

cleanup:
	kmf_free_data(&x509DER);
	kmf_free_dn(&certSubject);
	kmf_free_dn(&certIssuer);

	/*
	 * If kmf_sign_cert or kmf_store_cert failed, then we need to clean up
	 * the key pair from the token.
	 */
	if (kmfrv != KMF_OK) {
		/* delete the public key */
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEY_HANDLE_ATTR, &pubk, sizeof (KMF_KEY_HANDLE));
		numattr++;

		if (tokencred != NULL && tokencred->cred != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, tokencred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		(void) kmf_delete_key_from_keystore(kmfhandle, numattr,
		    attrlist);

		/* delete the private key */
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEY_HANDLE_ATTR, &prik, sizeof (KMF_KEY_HANDLE));
		numattr++;

		if (tokencred != NULL && tokencred->cred != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, tokencred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		(void) kmf_delete_key_from_keystore(kmfhandle, numattr,
		    attrlist);
	}

	return (kmfrv);
}

static int
gencert_file(KMF_HANDLE_T kmfhandle,
	KMF_KEY_ALG keyAlg, KMF_ALGORITHM_INDEX sigAlg,
	int keylen, KMF_ENCODE_FORMAT fmt,
	uint32_t ltime, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	KMF_BIGINT *serial, uint16_t kubits, int kucrit,
	char *outcert, char *outkey,
	EKU_LIST *ekulist)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;
	char *fullcertpath = NULL;
	char *fullkeypath = NULL;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_ATTRIBUTE attrlist[10];
	int numattr = 0;

	(void) memset(&signedCert, 0, sizeof (signedCert));
	(void) memset(&certSubject, 0, sizeof (certSubject));
	(void) memset(&certIssuer, 0, sizeof (certIssuer));
	(void) memset(&x509DER, 0, sizeof (x509DER));

	if (EMPTYSTRING(outcert) || EMPTYSTRING(outkey)) {
		cryptoerror(LOG_STDERR,
		    gettext("No output file was specified for "
		    "the cert or key\n"));
		return (PK_ERR_USAGE);
	}
	fullcertpath = strdup(outcert);
	if (verify_file(fullcertpath)) {
		cryptoerror(LOG_STDERR,
		    gettext("Cannot write the indicated output "
		    "certificate file (%s).\n"), fullcertpath);
		free(fullcertpath);
		return (PK_ERR_USAGE);
	}

	/* If the subject name cannot be parsed, flag it now and exit */
	if (kmf_dn_parser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed (%s)\n"), subject);
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (kmf_dn_parser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed (%s)\n"), subject);
		kmf_free_dn(&certSubject);
		return (PK_ERR_USAGE);
	}

	/*
	 * Share the "genkeypair" routine for creating the keypair.
	 */
	kmfrv = genkeypair_file(kmfhandle, keyAlg, keylen,
	    fmt, outkey, &prik, &pubk);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	SET_VALUE(kmf_set_cert_pubkey(kmfhandle, &pubk, &signedCert),
	    "keypair");

	SET_VALUE(kmf_set_cert_version(&signedCert, 2), "version number");

	SET_VALUE(kmf_set_cert_serial(&signedCert, serial),
	    "serial number");

	SET_VALUE(kmf_set_cert_validity(&signedCert, NULL, ltime),
	    "validity time");

	SET_VALUE(kmf_set_cert_sig_alg(&signedCert, sigAlg),
	    "signature algorithm");

	SET_VALUE(kmf_set_cert_subject(&signedCert, &certSubject),
	    "subject name");

	SET_VALUE(kmf_set_cert_issuer(&signedCert, &certIssuer),
	    "issuer name");

	if (altname != NULL)
		SET_VALUE(kmf_set_cert_subject_altname(&signedCert, altcrit,
		    alttype, altname), "subjectAltName");

	if (kubits != 0)
		SET_VALUE(kmf_set_cert_ku(&signedCert, kucrit, kubits),
		    "KeyUsage");

	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_cert_eku(&signedCert,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]), "Extended Key Usage");
		}
	}
	/*
	 * Construct attributes for the kmf_sign_cert operation.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE_ATTR));
	numattr++;

	/* cert data that is to be signed */
	kmf_set_attr_at_index(attrlist, numattr, KMF_X509_CERTIFICATE_ATTR,
	    &signedCert, sizeof (KMF_X509_CERTIFICATE));
	numattr++;

	/* output buffer for the signed cert */
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_ALGORITHM_INDEX_ATTR,
	    &sigAlg, sizeof (sigAlg));
	numattr++;

	if ((kmfrv = kmf_sign_cert(kmfhandle, numattr, attrlist)) !=
	    KMF_OK) {
		goto cleanup;
	}

	/*
	 * Store the cert in the DB.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_FILENAME_ATTR,
	    fullcertpath, strlen(fullcertpath));
	numattr++;
	kmf_set_attr_at_index(attrlist, numattr, KMF_ENCODE_FORMAT_ATTR,
	    &fmt, sizeof (fmt));
	numattr++;

	kmfrv = kmf_store_cert(kmfhandle, numattr, attrlist);

cleanup:
	if (fullkeypath != NULL)
		free(fullkeypath);
	if (fullcertpath != NULL)
		free(fullcertpath);

	kmf_free_data(&x509DER);
	kmf_free_dn(&certSubject);
	kmf_free_dn(&certIssuer);
	return (kmfrv);
}

static KMF_RETURN
gencert_nss(KMF_HANDLE_T kmfhandle,
	char *token, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	char *nickname, char *dir, char *prefix,
	KMF_KEY_ALG keyAlg,
	KMF_ALGORITHM_INDEX sigAlg,
	int keylen, char *trust,
	uint32_t ltime, KMF_BIGINT *serial, uint16_t kubits,
	int kucrit, KMF_CREDENTIAL *tokencred,
	EKU_LIST *ekulist, KMF_OID *curveoid)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;

	if (token == NULL)
		token = DEFAULT_NSS_TOKEN;

	kmfrv = configure_nss(kmfhandle, dir, prefix);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	(void) memset(&signedCert, 0, sizeof (signedCert));
	(void) memset(&certSubject, 0, sizeof (certSubject));
	(void) memset(&certIssuer, 0, sizeof (certIssuer));
	(void) memset(&x509DER, 0, sizeof (x509DER));

	/* If the subject name cannot be parsed, flag it now and exit */
	if (kmf_dn_parser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (kmf_dn_parser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	kmfrv = genkeypair_nss(kmfhandle, token, nickname, dir,
	    prefix, keyAlg, keylen, tokencred, curveoid,
	    &prik, &pubk);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	SET_VALUE(kmf_set_cert_pubkey(kmfhandle, &pubk, &signedCert),
	    "keypair");

	SET_VALUE(kmf_set_cert_version(&signedCert, 2), "version number");

	SET_VALUE(kmf_set_cert_serial(&signedCert, serial),
	    "serial number");

	SET_VALUE(kmf_set_cert_validity(&signedCert, NULL, ltime),
	    "validity time");

	SET_VALUE(kmf_set_cert_sig_alg(&signedCert, sigAlg),
	    "signature algorithm");

	SET_VALUE(kmf_set_cert_subject(&signedCert, &certSubject),
	    "subject name");

	SET_VALUE(kmf_set_cert_issuer(&signedCert, &certIssuer),
	    "issuer name");

	if (altname != NULL)
		SET_VALUE(kmf_set_cert_subject_altname(&signedCert, altcrit,
		    alttype, altname), "subjectAltName");

	if (kubits)
		SET_VALUE(kmf_set_cert_ku(&signedCert, kucrit, kubits),
		    "subjectAltName");

	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_cert_eku(&signedCert,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]), "Extended Key Usage");
		}
	}
	/*
	 * Construct attributes for the kmf_sign_cert operation.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE_ATTR));
	numattr++;

	/* cert data that is to be signed */
	kmf_set_attr_at_index(attrlist, numattr, KMF_X509_CERTIFICATE_ATTR,
	    &signedCert, sizeof (KMF_X509_CERTIFICATE));
	numattr++;

	/* output buffer for the signed cert */
	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_ALGORITHM_INDEX_ATTR,
	    &sigAlg, sizeof (sigAlg));
	numattr++;

	if ((kmfrv = kmf_sign_cert(kmfhandle, numattr, attrlist)) !=
	    KMF_OK) {
		goto cleanup;
	}

	/*
	 * Store the cert in the DB.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
	    &x509DER, sizeof (KMF_DATA));
	numattr++;

	if (nickname != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_LABEL_ATTR,
		    nickname, strlen(nickname));
		numattr++;
	}

	if (trust != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TRUSTFLAG_ATTR,
		    trust, strlen(trust));
		numattr++;
	}

	if (token != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}

	kmfrv = kmf_store_cert(kmfhandle, numattr, attrlist);

cleanup:
	kmf_free_data(&x509DER);
	kmf_free_dn(&certSubject);
	kmf_free_dn(&certIssuer);
	return (kmfrv);
}

int
pk_gencert(int argc, char *argv[])
{
	int rv;
	int opt;
	extern int	optind_av;
	extern char	*optarg_av;
	KMF_KEYSTORE_TYPE kstype = 0;
	char *subject = NULL;
	char *tokenname = NULL;
	char *dir = NULL;
	char *prefix = NULL;
	char *keytype = PK_DEFAULT_KEYTYPE;
	int keylen = PK_DEFAULT_KEYLENGTH;
	char *trust = NULL;
	char *lifetime = NULL;
	char *certlabel = NULL;
	char *outcert = NULL;
	char *outkey = NULL;
	char *format = NULL;
	char *serstr = NULL;
	char *altname = NULL;
	char *keyusagestr = NULL;
	char *ekustr = NULL;
	char *hashname = NULL;
	KMF_GENERALNAMECHOICES alttype = 0;
	KMF_BIGINT serial = { NULL, 0 };
	uint32_t ltime;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_ENCODE_FORMAT fmt = KMF_FORMAT_ASN1;
	KMF_KEY_ALG keyAlg = KMF_RSA;
	KMF_ALGORITHM_INDEX sigAlg = KMF_ALGID_SHA1WithRSA;
	boolean_t interactive = B_FALSE;
	char *subname = NULL;
	KMF_CREDENTIAL tokencred = { NULL, 0 };
	uint16_t kubits = 0;
	int altcrit = 0, kucrit = 0;
	EKU_LIST *ekulist = NULL;
	KMF_OID *curveoid = NULL; /* ECC */
	KMF_OID *hashoid = NULL;
	int y_flag = 0;

	while ((opt = getopt_av(argc, argv,
	    "ik:(keystore)s:(subject)n:(nickname)A:(altname)"
	    "T:(token)d:(dir)p:(prefix)t:(keytype)y:(keylen)"
	    "r:(trust)L:(lifetime)l:(label)c:(outcert)e:(eku)"
	    "K:(outkey)S:(serial)F:(format)u:(keyusage)C:(curve)"
	    "E(listcurves)h:(hash)")) != EOF) {

		if (opt != 'i' && opt != 'E' && EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);

		switch (opt) {
			case 'A':
				altname = optarg_av;
				break;
			case 'i':
				if (interactive || subject)
					return (PK_ERR_USAGE);
				else
					interactive = B_TRUE;
				break;
			case 'k':
				kstype = KS2Int(optarg_av);
				if (kstype == 0)
					return (PK_ERR_USAGE);
				break;
			case 's':
				if (interactive || subject)
					return (PK_ERR_USAGE);
				else
					subject = optarg_av;
				break;
			case 'l':
			case 'n':
				if (certlabel)
					return (PK_ERR_USAGE);
				certlabel = optarg_av;
				break;
			case 'T':
				if (tokenname)
					return (PK_ERR_USAGE);
				tokenname = optarg_av;
				break;
			case 'd':
				if (dir)
					return (PK_ERR_USAGE);
				dir = optarg_av;
				break;
			case 'p':
				if (prefix)
					return (PK_ERR_USAGE);
				prefix = optarg_av;
				break;
			case 't':
				keytype = optarg_av;
				break;
			case 'u':
				keyusagestr = optarg_av;
				break;
			case 'y':
				if (sscanf(optarg_av, "%d",
				    &keylen) != 1) {
					cryptoerror(LOG_STDERR,
					    gettext("key length must be"
					    "a numeric value (%s)\n"),
					    optarg_av);
					return (PK_ERR_USAGE);
				}
				y_flag++;
				break;
			case 'r':
				if (trust)
					return (PK_ERR_USAGE);
				trust = optarg_av;
				break;
			case 'L':
				if (lifetime)
					return (PK_ERR_USAGE);
				lifetime = optarg_av;
				break;
			case 'c':
				if (outcert)
					return (PK_ERR_USAGE);
				outcert = optarg_av;
				break;
			case 'K':
				if (outkey)
					return (PK_ERR_USAGE);
				outkey = optarg_av;
				break;
			case 'S':
				serstr = optarg_av;
				break;
			case 'F':
				if (format)
					return (PK_ERR_USAGE);
				format = optarg_av;
				break;
			case 'e':
				ekustr = optarg_av;
				break;
			case 'C':
				curveoid = ecc_name_to_oid(optarg_av);
				if (curveoid == NULL) {
					cryptoerror(LOG_STDERR,
					    gettext("Unrecognized ECC "
					    "curve.\n"));
					return (PK_ERR_USAGE);
				}
				break;
			case 'E':
				/*
				 * This argument is only to be used
				 * by itself, no other options should
				 * be present.
				 */
				if (argc != 2) {
					cryptoerror(LOG_STDERR,
					    gettext("listcurves has no other "
					    "options.\n"));
					return (PK_ERR_USAGE);
				}
				show_ecc_curves();
				return (0);
			case 'h':
				hashname = optarg_av;
				hashoid = ecc_name_to_oid(optarg_av);
				if (hashoid == NULL) {
					cryptoerror(LOG_STDERR,
					    gettext("Unrecognized hash.\n"));
					return (PK_ERR_USAGE);
				}
				break;
			default:
				return (PK_ERR_USAGE);
		}
	}

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc) {
		return (PK_ERR_USAGE);
	}

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing KMF\n"));
		return (PK_ERR_USAGE);
	}

	/* Assume keystore = PKCS#11 if not specified. */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	if ((kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_PK11TOKEN)) {
		if (interactive && EMPTYSTRING(certlabel)) {
			(void) get_certlabel(&certlabel);
		}
		/* It better not be empty now */
		if (EMPTYSTRING(certlabel)) {
			cryptoerror(LOG_STDERR, gettext("A label must be "
			    "specified to create a self-signed certificate."
			    "\n"));
			return (PK_ERR_USAGE);
		}
	} else if (kstype == KMF_KEYSTORE_OPENSSL && EMPTYSTRING(outcert)) {
		cryptoerror(LOG_STDERR, gettext("A certificate filename must "
		    "be specified to create a self-signed certificate.\n"));
		return (PK_ERR_USAGE);
	}

	DIR_OPTION_CHECK(kstype, dir);

	if (format && (fmt = Str2Format(format)) == KMF_FORMAT_UNDEF) {
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing format string (%s).\n"),
		    format);
		return (PK_ERR_USAGE);
	}

	if (Str2Lifetime(lifetime, &ltime) != 0) {
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing lifetime string\n"));
		return (PK_ERR_USAGE);
	}

	if (Str2KeyType(keytype, hashoid, &keyAlg, &sigAlg) != 0) {
		cryptoerror(LOG_STDERR,
		    gettext("Unsupported key/hash combination (%s/%s).\n"),
		    keytype, (hashname ? hashname : "none"));
		return (PK_ERR_USAGE);
	}
	if (curveoid != NULL && keyAlg != KMF_ECDSA) {
		cryptoerror(LOG_STDERR, gettext("EC curves are only "
		    "valid for EC keytypes.\n"));
		return (PK_ERR_USAGE);
	}
	if (keyAlg == KMF_ECDSA && curveoid == NULL) {
		cryptoerror(LOG_STDERR, gettext("A curve must be "
		    "specifed when using EC keys.\n"));
		return (PK_ERR_USAGE);
	}
	/* Adjust default keylength for NSS and DSA */
	if (keyAlg == KMF_DSA && !y_flag && kstype == KMF_KEYSTORE_NSS)
		keylen = 1024;

	/*
	 * Check the subject name.
	 * If interactive is true, get it now interactively.
	 */
	if (interactive) {
		subname = NULL;
		if (get_subname(&subname) != KMF_OK || subname == NULL) {
			cryptoerror(LOG_STDERR, gettext("Failed to get the "
			    "subject name interactively.\n"));
			return (PK_ERR_USAGE);
		}
		if (serstr == NULL) {
			(void) get_serial(&serstr);
		}
	} else {
		if (EMPTYSTRING(subject)) {
			cryptoerror(LOG_STDERR, gettext("A subject name or "
			    "-i must be specified to create a self-signed "
			    "certificate.\n"));
			return (PK_ERR_USAGE);
		} else {
			subname = strdup(subject);
			if (subname == NULL) {
				cryptoerror(LOG_STDERR,
				    gettext("Out of memory.\n"));
				return (PK_ERR_SYSTEM);
			}
		}
	}

	if (serstr == NULL) {
		(void) fprintf(stderr, gettext("A serial number "
		    "must be specified as a hex number when creating"
		    " a self-signed certificate "
		    "(ex: serial=0x0102030405feedface)\n"));
		rv = PK_ERR_USAGE;
		goto end;
	} else {
		uchar_t *bytes = NULL;
		size_t bytelen;

		rv = kmf_hexstr_to_bytes((uchar_t *)serstr, &bytes, &bytelen);
		if (rv != KMF_OK || bytes == NULL) {
			(void) fprintf(stderr, gettext("serial number "
			    "must be specified as a hex number "
			    "(ex: 0x0102030405ffeeddee)\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
		serial.val = bytes;
		serial.len = bytelen;
	}

	if (altname != NULL) {
		rv = verify_altname(altname, &alttype, &altcrit);
		if (rv != KMF_OK) {
			(void) fprintf(stderr, gettext("Subject AltName "
			    "must be specified as a name=value pair. "
			    "See the man page for details.\n"));
			rv = PK_ERR_USAGE;
			goto end;
		} else {
			/* advance the altname past the '=' sign */
			char *p = strchr(altname, '=');
			if (p != NULL)
				altname = p + 1;
		}
	}

	if (keyusagestr != NULL) {
		rv = verify_keyusage(keyusagestr, &kubits, &kucrit);
		if (rv != KMF_OK) {
			(void) fprintf(stderr, gettext("KeyUsage "
			    "must be specified as a comma-separated list. "
			    "See the man page for details.\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
	}
	if (ekustr != NULL) {
		rv = verify_ekunames(ekustr, &ekulist);
		if (rv != KMF_OK) {
			(void) fprintf(stderr, gettext("EKUs must "
			    "be specified as a comma-separated list. "
			    "See the man page for details.\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
	}
	if (keyAlg == KMF_ECDSA && kstype == KMF_KEYSTORE_OPENSSL) {
		(void) fprintf(stderr, gettext("ECC certificates are"
		    "only supported with the pkcs11 and nss keystores\n"));
		rv = PK_ERR_USAGE;
		goto end;
	}

	if (kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_PK11TOKEN) {
		if (tokenname == NULL || !strlen(tokenname)) {
			if (kstype == KMF_KEYSTORE_NSS) {
				tokenname = "internal";
			} else  {
				tokenname = PK_DEFAULT_PK11TOKEN;
			}
		}

		(void) get_token_password(kstype, tokenname, &tokencred);
	}

	if (kstype == KMF_KEYSTORE_NSS) {
		if (dir == NULL)
			dir = PK_DEFAULT_DIRECTORY;

		rv = gencert_nss(kmfhandle,
		    tokenname, subname, altname, alttype, altcrit,
		    certlabel, dir, prefix, keyAlg, sigAlg, keylen,
		    trust, ltime, &serial, kubits, kucrit, &tokencred,
		    ekulist, curveoid);

	} else if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = gencert_pkcs11(kmfhandle,
		    tokenname, subname, altname, alttype, altcrit,
		    certlabel, keyAlg, sigAlg, keylen, ltime,
		    &serial, kubits, kucrit, &tokencred, ekulist,
		    curveoid);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = gencert_file(kmfhandle,
		    keyAlg, sigAlg, keylen, fmt,
		    ltime, subname, altname, alttype, altcrit,
		    &serial, kubits, kucrit, outcert, outkey,
		    ekulist);
	}

	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
		    gettext("Error creating certificate and keypair"));
end:
	if (ekulist != NULL)
		free_eku_list(ekulist);
	if (subname)
		free(subname);
	if (tokencred.cred != NULL)
		free(tokencred.cred);

	if (serial.val != NULL)
		free(serial.val);

	(void) kmf_finalize(kmfhandle);
	return (rv);
}

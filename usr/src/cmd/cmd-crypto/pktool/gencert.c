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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	uint16_t kubits, int kucrit, KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_CREATEKEYPAIR_PARAMS kp_params;
	KMF_STORECERT_PARAMS sc_params;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;

	(void) memset(&signedCert, 0, sizeof (signedCert));
	(void) memset(&certSubject, 0, sizeof (certSubject));
	(void) memset(&certIssuer, 0, sizeof (certIssuer));
	(void) memset(&x509DER, 0, sizeof (x509DER));
	(void) memset(&kp_params, 0, sizeof (kp_params));

	/* If the subject name cannot be parsed, flag it now and exit */
	if (KMF_DNParser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (KMF_DNParser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	kp_params.kstype = KMF_KEYSTORE_PK11TOKEN;
	kp_params.keylabel = certlabel;
	kp_params.keylength = keylen; /* bits */
	kp_params.keytype = keyAlg;
	kp_params.cred.cred = tokencred->cred;
	kp_params.cred.credlen = tokencred->credlen;

	/* Select a PKCS11 token */
	kmfrv = select_token(kmfhandle, token, FALSE);

	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	kmfrv = KMF_CreateKeypair(kmfhandle, &kp_params, &prik, &pubk);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	SET_VALUE(KMF_SetCertPubKey(kmfhandle, &pubk, &signedCert),
			"keypair");

	SET_VALUE(KMF_SetCertVersion(&signedCert, 2), "version number");

	SET_VALUE(KMF_SetCertSerialNumber(&signedCert, serial),
			"serial number");

	SET_VALUE(KMF_SetCertValidityTimes(&signedCert, NULL, ltime),
		"validity time");

	SET_VALUE(KMF_SetCertSignatureAlgorithm(&signedCert, sigAlg),
		"signature algorithm");

	SET_VALUE(KMF_SetCertSubjectName(&signedCert, &certSubject),
		"subject name");

	SET_VALUE(KMF_SetCertIssuerName(&signedCert, &certIssuer),
		"issuer name");

	if (altname != NULL)
		SET_VALUE(KMF_SetCertSubjectAltName(&signedCert, altcrit,
			alttype, altname), "subjectAltName");

	if (kubits != 0)
		SET_VALUE(KMF_SetCertKeyUsage(&signedCert, kucrit, kubits),
			"KeyUsage");

	if ((kmfrv = KMF_SignCertRecord(kmfhandle, &prik,
		&signedCert, &x509DER)) != KMF_OK) {
		goto cleanup;
	}

	(void) memset(&sc_params, 0, sizeof (sc_params));
	sc_params.kstype = KMF_KEYSTORE_PK11TOKEN;
	sc_params.certLabel = certlabel;

	/*
	 * Store the cert in the DB.
	 */
	kmfrv = KMF_StoreCert(kmfhandle, &sc_params, &x509DER);

cleanup:
	KMF_FreeData(&x509DER);
	KMF_FreeDN(&certSubject);
	KMF_FreeDN(&certIssuer);
	return (kmfrv);
}

static int
gencert_file(KMF_HANDLE_T kmfhandle,
	KMF_KEY_ALG keyAlg, KMF_ALGORITHM_INDEX sigAlg,
	int keylen, KMF_ENCODE_FORMAT fmt,
	uint32_t ltime, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	KMF_BIGINT *serial, uint16_t kubits, int kucrit,
	char *dir, char *outcert, char *outkey)
{
	KMF_RETURN kmfrv;
	KMF_CREATEKEYPAIR_PARAMS kp_params;
	KMF_STORECERT_PARAMS sc_params;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;
	char *fullcertpath = NULL;
	char *fullkeypath = NULL;

	(void) memset(&signedCert, 0, sizeof (signedCert));
	(void) memset(&certSubject, 0, sizeof (certSubject));
	(void) memset(&certIssuer, 0, sizeof (certIssuer));
	(void) memset(&x509DER, 0, sizeof (x509DER));
	(void) memset(&kp_params, 0, sizeof (kp_params));
	(void) memset(&sc_params, 0, sizeof (sc_params));

	if (EMPTYSTRING(outcert) || EMPTYSTRING(outkey)) {
		cryptoerror(LOG_STDERR,
			gettext("No output file was specified for "
				"the cert or key\n"));
		return (PK_ERR_USAGE);
	}
	if (dir != NULL) {
		fullcertpath = get_fullpath(dir, outcert);
		if (fullcertpath == NULL) {
			cryptoerror(LOG_STDERR,
				gettext("Cannot create file %s in "
					"directory %s\n"), dir, outcert);
			return (PK_ERR_USAGE);
		}
	} else {
		fullcertpath = strdup(outcert);
	}
	if (verify_file(fullcertpath)) {
		cryptoerror(LOG_STDERR,
			gettext("Cannot write the indicated output "
				"certificate file (%s).\n"),
				fullcertpath);
		free(fullcertpath);
		return (PK_ERR_USAGE);
	}
	if (dir != NULL) {
		fullkeypath = get_fullpath(dir, outkey);
		if (fullkeypath == NULL) {
			cryptoerror(LOG_STDERR,
				gettext("Cannot create file %s in "
					"directory %s\n"), dir, outkey);
			free(fullcertpath);
			return (PK_ERR_USAGE);
		}
	} else {
		fullkeypath = strdup(outkey);
	}
	if (verify_file(fullkeypath)) {
		cryptoerror(LOG_STDERR,
			gettext("Cannot write the indicated output "
				"key file (%s).\n"),
				fullkeypath);
		free(fullkeypath);
		free(fullcertpath);
		return (PK_ERR_USAGE);
	}

	/* If the subject name cannot be parsed, flag it now and exit */
	if (KMF_DNParser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed (%s)\n"),
			subject);
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (KMF_DNParser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed (%s)\n"),
			subject);
		KMF_FreeDN(&certSubject);
		return (PK_ERR_USAGE);
	}

	kp_params.kstype = KMF_KEYSTORE_OPENSSL;
	kp_params.keylength = keylen; /* bits */
	kp_params.keytype = keyAlg;

	kp_params.sslparms.keyfile = fullkeypath;
	kp_params.sslparms.format = fmt;

	kmfrv = KMF_CreateKeypair(kmfhandle, &kp_params, &prik, &pubk);
	if (kmfrv != KMF_OK) {
		goto cleanup;
	}
	SET_VALUE(KMF_SetCertPubKey(kmfhandle, &pubk, &signedCert),
		"keypair");

	SET_VALUE(KMF_SetCertVersion(&signedCert, 2), "version number");

	SET_VALUE(KMF_SetCertSerialNumber(&signedCert, serial),
		"serial number");

	SET_VALUE(KMF_SetCertValidityTimes(&signedCert, NULL, ltime),
		"validity time");

	SET_VALUE(KMF_SetCertSignatureAlgorithm(&signedCert, sigAlg),
		"signature algorithm");

	SET_VALUE(KMF_SetCertSubjectName(&signedCert, &certSubject),
		"subject name");

	SET_VALUE(KMF_SetCertIssuerName(&signedCert, &certIssuer),
		"issuer name");

	if (altname != NULL)
		SET_VALUE(KMF_SetCertSubjectAltName(&signedCert, altcrit,
			alttype, altname), "subjectAltName");

	if (kubits != 0)
		SET_VALUE(KMF_SetCertKeyUsage(&signedCert, kucrit, kubits),
			"KeyUsage");

	if ((kmfrv = KMF_SignCertRecord(kmfhandle, &prik,
		&signedCert, &x509DER)) != KMF_OK) {
		goto cleanup;
	}

	sc_params.kstype = KMF_KEYSTORE_OPENSSL;
	sc_params.sslparms.certfile = fullcertpath;
	sc_params.sslparms.keyfile = fullkeypath;
	sc_params.sslparms.format = fmt;
	/*
	 * Store the cert in the DB.
	 */
	kmfrv = KMF_StoreCert(kmfhandle, &sc_params, &x509DER);

cleanup:
	if (fullkeypath != NULL)
		free(fullkeypath);
	if (fullcertpath != NULL)
		free(fullcertpath);

	KMF_FreeData(&x509DER);
	KMF_FreeDN(&certSubject);
	KMF_FreeDN(&certIssuer);
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
	int kucrit, KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN kmfrv;
	KMF_CREATEKEYPAIR_PARAMS kp_params;
	KMF_STORECERT_PARAMS sc_params;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_CERTIFICATE signedCert;
	KMF_X509_NAME	certSubject;
	KMF_X509_NAME	certIssuer;
	KMF_DATA x509DER;

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
	if (KMF_DNParser(subject, &certSubject) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	/* For a self-signed cert, the issuser and subject are the same */
	if (KMF_DNParser(subject, &certIssuer) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("Subject name cannot be parsed.\n"));
		return (PK_ERR_USAGE);
	}

	(void) memset(&kp_params, 0, sizeof (kp_params));

	kp_params.kstype = KMF_KEYSTORE_NSS;
	kp_params.keylabel = nickname;
	kp_params.keylength = keylen; /* bits */
	kp_params.keytype = keyAlg;
	kp_params.cred.cred = tokencred->cred;
	kp_params.cred.credlen = tokencred->credlen;
	kp_params.nssparms.slotlabel = token;

	kmfrv = KMF_CreateKeypair(kmfhandle, &kp_params, &prik, &pubk);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	SET_VALUE(KMF_SetCertPubKey(kmfhandle, &pubk, &signedCert),
			"keypair");

	SET_VALUE(KMF_SetCertVersion(&signedCert, 2), "version number");

	SET_VALUE(KMF_SetCertSerialNumber(&signedCert, serial),
			"serial number");

	SET_VALUE(KMF_SetCertValidityTimes(&signedCert, NULL, ltime),
		"validity time");

	SET_VALUE(KMF_SetCertSignatureAlgorithm(&signedCert, sigAlg),
		"signature algorithm");

	SET_VALUE(KMF_SetCertSubjectName(&signedCert, &certSubject),
		"subject name");

	SET_VALUE(KMF_SetCertIssuerName(&signedCert, &certIssuer),
		"issuer name");

	if (altname != NULL)
		SET_VALUE(KMF_SetCertSubjectAltName(&signedCert, altcrit,
			alttype, altname), "subjectAltName");

	if (kubits)
		SET_VALUE(KMF_SetCertKeyUsage(&signedCert, kucrit, kubits),
			"subjectAltName");

	if ((kmfrv = KMF_SignCertRecord(kmfhandle, &prik,
		&signedCert, &x509DER)) != KMF_OK) {
		goto cleanup;
	}

	sc_params.kstype = KMF_KEYSTORE_NSS;
	sc_params.certLabel = nickname;
	sc_params.nssparms.trustflag = trust;
	sc_params.nssparms.slotlabel = token;

	/*
	 * Store the cert in the DB.
	 */
	kmfrv = KMF_StoreCert(kmfhandle, &sc_params, &x509DER);

cleanup:
	KMF_FreeData(&x509DER);
	KMF_FreeDN(&certSubject);
	KMF_FreeDN(&certIssuer);
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
	KMF_GENERALNAMECHOICES alttype = 0;
	KMF_BIGINT serial = { NULL, 0 };
	uint32_t ltime;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_ENCODE_FORMAT fmt = KMF_FORMAT_ASN1;
	KMF_KEY_ALG keyAlg = KMF_RSA;
	KMF_ALGORITHM_INDEX sigAlg = KMF_ALGID_MD5WithRSA;
	boolean_t interactive = B_FALSE;
	char *subname = NULL;
	KMF_CREDENTIAL tokencred = {NULL, 0};
	uint16_t kubits = 0;
	int altcrit = 0, kucrit = 0;

	while ((opt = getopt_av(argc, argv,
		"ik:(keystore)s:(subject)n:(nickname)A:(altname)"
		"T:(token)d:(dir)p:(prefix)t:(keytype)y:(keylen)"
		"r:(trust)L:(lifetime)l:(label)c:(outcert)"
		"K:(outkey)S:(serial)F:(format)u:(keyusage)")) != EOF) {

		if (opt != 'i' && EMPTYSTRING(optarg_av))
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

	if ((rv = KMF_Initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing KMF\n"));
		return (PK_ERR_USAGE);
	}

	/* Assume keystore = PKCS#11 if not specified. */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	if ((kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_PK11TOKEN) &&
	    EMPTYSTRING(certlabel)) {
		cryptoerror(LOG_STDERR, gettext("A label must be specified "
		    "to create a self-signed certificate.\n"));
		return (PK_ERR_USAGE);
	} else if (kstype == KMF_KEYSTORE_OPENSSL && EMPTYSTRING(outcert)) {
		cryptoerror(LOG_STDERR, gettext("A certificate filename must "
		    "be specified to create a self-signed certificate.\n"));
		return (PK_ERR_USAGE);
	}

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

	if (Str2KeyType(keytype, &keyAlg, &sigAlg) != 0) {
		cryptoerror(LOG_STDERR, gettext("Unrecognized keytype (%s).\n"),
			keytype);
		return (PK_ERR_USAGE);
	}


	/*
	 * Check the subject name.
	 * If interactive is true, get it now interactively.
	 */
	if (interactive) {
		if (get_subname(&subname) != KMF_OK) {
			cryptoerror(LOG_STDERR, gettext("Failed to get the "
			    "subject name interactively.\n"));
			return (PK_ERR_USAGE);
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

		rv = KMF_HexString2Bytes((uchar_t *)serstr, &bytes, &bytelen);
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
			trust, ltime, &serial, kubits, kucrit, &tokencred);

	} else if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = gencert_pkcs11(kmfhandle,
			tokenname, subname, altname, alttype, altcrit,
			certlabel, keyAlg, sigAlg, keylen, ltime,
			&serial, kubits, kucrit, &tokencred);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = gencert_file(kmfhandle,
			keyAlg, sigAlg, keylen, fmt,
			ltime, subname, altname, alttype, altcrit,
			&serial, kubits, kucrit, dir, outcert, outkey);
	}

	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
			gettext("Error creating certificate and keypair"));
end:
	if (subname)
		free(subname);
	if (tokencred.cred != NULL)
		free(tokencred.cred);

	if (serial.val != NULL)
		free(serial.val);

	(void) KMF_Finalize(kmfhandle);
	return (rv);
}

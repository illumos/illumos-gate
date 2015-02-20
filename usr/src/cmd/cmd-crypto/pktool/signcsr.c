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

/*
 * This file implements the sign CSR operation for this tool.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

#include <kmfapi.h>
#include <kmfapiP.h>

#define	SET_VALUE(f, s) \
	rv = f; \
	if (rv != KMF_OK) { \
		cryptoerror(LOG_STDERR, \
		    gettext("Failed to set %s: 0x%02x\n"), s, rv); \
		goto cleanup; \
	}


static int
read_csrdata(KMF_HANDLE_T handle, char *csrfile, KMF_CSR_DATA *csrdata)
{
	KMF_RETURN rv = KMF_OK;
	KMF_ENCODE_FORMAT csrfmt;
	KMF_DATA csrfiledata = { 0, NULL };
	KMF_DATA rawcsr = { 0, NULL };

	rv = kmf_get_file_format(csrfile, &csrfmt);
	if (rv != KMF_OK)
		return (rv);

	rv = kmf_read_input_file(handle, csrfile, &csrfiledata);
	if (rv != KMF_OK)
		return (rv);

	if (csrfmt == KMF_FORMAT_PEM) {
		rv = kmf_pem_to_der(csrfiledata.Data, csrfiledata.Length,
		    &rawcsr.Data, (int *)&rawcsr.Length);
		if (rv != KMF_OK)
			return (rv);

		kmf_free_data(&csrfiledata);
	} else {
		rawcsr.Data = csrfiledata.Data;
		rawcsr.Length = csrfiledata.Length;
	}

	rv = kmf_decode_csr(handle, &rawcsr, csrdata);
	kmf_free_data(&rawcsr);

	return (rv);
}

static KMF_RETURN
find_csr_extn(KMF_X509_EXTENSIONS *extnlist, KMF_OID *extoid,
	KMF_X509_EXTENSION *outextn)
{
	int i, found = 0;
	KMF_X509_EXTENSION *eptr;
	KMF_RETURN rv = KMF_OK;

	(void) memset(outextn, 0, sizeof (KMF_X509_EXTENSION));
	for (i = 0; !found && i < extnlist->numberOfExtensions; i++) {
		eptr = &extnlist->extensions[i];
		if (IsEqualOid(extoid, &eptr->extnId)) {
			rv = copy_extension_data(outextn, eptr);
			found++;
		}
	}
	if (found == 0 || rv != KMF_OK)
		return (1);
	else
		return (rv);
}

static int
build_cert_from_csr(KMF_CSR_DATA *csrdata,
	KMF_X509_CERTIFICATE *signedCert,
	KMF_BIGINT *serial,
	uint32_t ltime,
	char *issuer, char *subject,
	char *altname,
	KMF_GENERALNAMECHOICES alttype,
	int altcrit,
	uint16_t kubits,
	int kucrit,
	EKU_LIST *ekulist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_NAME issuerDN, subjectDN;

	/*
	 * If the CSR is ok, now we can generate the final certificate.
	 */
	(void) memset(signedCert, 0, sizeof (KMF_X509_CERTIFICATE));
	(void) memset(&issuerDN, 0, sizeof (issuerDN));
	(void) memset(&subjectDN, 0, sizeof (subjectDN));

	SET_VALUE(kmf_set_cert_version(signedCert, 2), "version number");

	SET_VALUE(kmf_set_cert_serial(signedCert, serial), "serial number");

	SET_VALUE(kmf_set_cert_validity(signedCert, NULL, ltime),
	    "validity time");

	if (issuer) {
		if (kmf_dn_parser(issuer, &issuerDN) != KMF_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Issuer name cannot be parsed\n"));
			return (PK_ERR_USAGE);
		}
		SET_VALUE(kmf_set_cert_issuer(signedCert, &issuerDN),
		    "Issuer Name");
	}
	if (subject) {
		if (kmf_dn_parser(subject, &subjectDN) != KMF_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Subject name cannot be parsed\n"));
			return (PK_ERR_USAGE);
		}
		SET_VALUE(kmf_set_cert_subject(signedCert, &subjectDN),
		    "Subject Name");
	} else {
		signedCert->certificate.subject = csrdata->csr.subject;
	}

	signedCert->certificate.subjectPublicKeyInfo =
	    csrdata->csr.subjectPublicKeyInfo;

	signedCert->certificate.extensions = csrdata->csr.extensions;

	signedCert->certificate.signature =
	    csrdata->signature.algorithmIdentifier;

	if (kubits != 0) {
		KMF_X509_EXTENSION extn;
		uint16_t oldbits;
		/*
		 * If the CSR already has KU, merge them.
		 */
		rv = find_csr_extn(&csrdata->csr.extensions,
		    (KMF_OID *)&KMFOID_KeyUsage, &extn);
		if (rv == KMF_OK) {
			extn.critical |= kucrit;
			if (extn.value.tagAndValue->value.Length > 1) {
				oldbits =
				    extn.value.tagAndValue->value.Data[1] << 8;
			} else {
				oldbits =
				    extn.value.tagAndValue->value.Data[0];
			}
			oldbits |= kubits;
		} else {
			SET_VALUE(kmf_set_cert_ku(signedCert, kucrit, kubits),
			    "KeyUsage");
		}
	}
	if (altname != NULL) {
		SET_VALUE(kmf_set_cert_subject_altname(signedCert,
		    altcrit, alttype, altname), "subjectAltName");
	}
	if (ekulist != NULL) {
		int i;
		for (i = 0; rv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_cert_eku(signedCert,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]), "Extended Key Usage");
		}
	}
cleanup:
	if (issuer != NULL)
		kmf_free_dn(&issuerDN);
	if (subject != NULL)
		kmf_free_dn(&subjectDN);

	return (rv);
}

static int
pk_sign_cert(KMF_HANDLE_T handle, KMF_X509_CERTIFICATE *cert,
	KMF_KEY_HANDLE *key, KMF_OID *sigoid, KMF_DATA *outdata)
{
	KMF_RETURN rv;
	int numattr;
	KMF_ATTRIBUTE attrlist[4];

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYSTORE_TYPE_ATTR,
	    &key->kstype, sizeof (KMF_KEYSTORE_TYPE));

	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEY_HANDLE_ATTR,
	    key, sizeof (KMF_KEY_HANDLE_ATTR));

	/* cert data that is to be signed */
	kmf_set_attr_at_index(attrlist, numattr++, KMF_X509_CERTIFICATE_ATTR,
	    cert, sizeof (KMF_X509_CERTIFICATE));

	/* output buffer for the signed cert */
	kmf_set_attr_at_index(attrlist, numattr++, KMF_CERT_DATA_ATTR,
	    outdata, sizeof (KMF_DATA));

	/* Set the signature OID value so KMF knows how to generate the sig */
	if (sigoid) {
		kmf_set_attr_at_index(attrlist, numattr++, KMF_OID_ATTR,
		    sigoid, sizeof (KMF_OID));
	}

	if ((rv = kmf_sign_cert(handle, numattr, attrlist)) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Failed to sign certificate.\n"));
		return (rv);
	}

	return (rv);
}

static int
pk_signcsr_files(KMF_HANDLE_T handle,
	char *signkey,
	char *csrfile,
	KMF_BIGINT *serial,
	char *certfile,
	char *issuer,
	char *subject,
	char *altname,
	KMF_GENERALNAMECHOICES alttype,
	int altcrit,
	uint16_t kubits,
	int kucrit,
	EKU_LIST *ekulist,
	uint32_t ltime,
	KMF_ENCODE_FORMAT fmt)
{
	KMF_RETURN rv = KMF_OK;
	KMF_CSR_DATA csrdata;
	KMF_ATTRIBUTE attrlist[16];
	KMF_X509_CERTIFICATE signedCert;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_KEY_CLASS keyclass = KMF_ASYM_PRI;
	KMF_KEY_HANDLE cakey;
	KMF_DATA certdata = { 0, NULL };
	int numattr, count;

	(void) memset(&cakey, 0, sizeof (cakey));
	(void) memset(&signedCert, 0, sizeof (signedCert));

	rv = read_csrdata(handle, csrfile, &csrdata);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Error reading CSR data\n"));
		return (rv);
	}

	/* verify the signature first */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_CSR_DATA_ATTR,
	    &csrdata, sizeof (csrdata));
	numattr++;

	rv = kmf_verify_csr(handle, numattr, attrlist);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("CSR signature "
		    "verification failed.\n"));
		goto cleanup;
	}

	rv = build_cert_from_csr(&csrdata, &signedCert, serial, ltime,
	    issuer, subject, altname, alttype, altcrit, kubits,
	    kucrit, ekulist);

	if (rv != KMF_OK)
		goto cleanup;

	/*
	 * Find the signing key.
	 */
	(void) memset(&cakey, 0, sizeof (cakey));

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_FILENAME_ATTR,
	    signkey, strlen(signkey));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYCLASS_ATTR,
	    &keyclass, sizeof (keyclass));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &cakey, sizeof (cakey));
	numattr++;

	count = 1;
	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &count, sizeof (count));
	numattr++;

	rv = kmf_find_key(handle, numattr, attrlist);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Error finding CA signing key\n"));
		goto cleanup;
	}

	rv = pk_sign_cert(handle, &signedCert, &cakey, NULL, &certdata);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Error signing certificate.\n"));
		goto cleanup;
	}

	rv = kmf_create_cert_file(&certdata, fmt, certfile);

cleanup:
	kmf_free_signed_csr(&csrdata);
	kmf_free_data(&certdata);
	kmf_free_kmf_key(handle, &cakey);
	return (rv);
}

static int
pk_signcsr_pk11_nss(KMF_HANDLE_T handle,
	KMF_KEYSTORE_TYPE kstype,
	char *dir, char *prefix,
	char *token, KMF_CREDENTIAL *cred,
	char *signkey, char *csrfile,
	KMF_BIGINT *serial, char *certfile, char *issuer, char *subject,
	char *altname, KMF_GENERALNAMECHOICES alttype, int altcrit,
	uint16_t kubits, int kucrit,
	EKU_LIST *ekulist, uint32_t ltime,
	KMF_ENCODE_FORMAT fmt, int store, char *outlabel)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA outcert = { 0, NULL };
	KMF_CSR_DATA csrdata = { 0, NULL };
	KMF_KEY_HANDLE casignkey;
	KMF_KEY_CLASS keyclass = KMF_ASYM_PRI;
	KMF_ATTRIBUTE attrlist[16];
	KMF_X509_CERTIFICATE signedCert;
	boolean_t token_bool = B_TRUE;
	boolean_t private_bool = B_TRUE;
	int numattr = 0;
	int keys = 1;

	(void) memset(&casignkey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(&signedCert, 0, sizeof (signedCert));

	rv = read_csrdata(handle, csrfile, &csrdata);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Error reading CSR data\n"));
		return (rv);
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = select_token(handle, token, FALSE);
	} else if (kstype == KMF_KEYSTORE_NSS) {
		rv = configure_nss(handle, dir, prefix);
	}

	/* verify the signature first */
	kmf_set_attr_at_index(attrlist, numattr, KMF_CSR_DATA_ATTR,
	    &csrdata, sizeof (csrdata));
	numattr++;

	rv = kmf_verify_csr(handle, numattr, attrlist);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("CSR signature "
		    "verification failed.\n"));
		goto cleanup;
	}

	rv = build_cert_from_csr(&csrdata,
	    &signedCert, serial, ltime,
	    issuer, subject, altname,
	    alttype, altcrit, kubits,
	    kucrit, ekulist);

	if (rv != KMF_OK)
		goto cleanup;

	/*
	 * Find the signing key.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	if (kstype == KMF_KEYSTORE_NSS) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR, signkey,
	    strlen(signkey));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_PRIVATE_BOOL_ATTR,
	    &private_bool, sizeof (private_bool));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_BOOL_ATTR,
	    &token_bool, sizeof (token_bool));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYCLASS_ATTR,
	    &keyclass, sizeof (keyclass));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
	    cred, sizeof (KMF_CREDENTIAL_ATTR));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &keys, sizeof (keys));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &casignkey, sizeof (casignkey));
	numattr++;

	rv = kmf_find_key(handle, numattr, attrlist);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Failed to find signing key\n"));
		goto cleanup;
	}
	/*
	 * If we found the key, now we can sign the cert.
	 */
	rv = pk_sign_cert(handle, &signedCert, &casignkey, NULL,
	    &outcert);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Error signing certificate.\n"));
		goto cleanup;
	}

	/*
	 * Store it on the token if the user asked for it.
	 */
	if (store) {
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_DATA_ATTR,
		    &outcert, sizeof (KMF_DATA));
		numattr++;

		if (outlabel != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_LABEL_ATTR,
			    outlabel, strlen(outlabel));
			numattr++;
		}

		if (kstype == KMF_KEYSTORE_NSS) {
			if (token != NULL)
				kmf_set_attr_at_index(attrlist, numattr,
				    KMF_TOKEN_LABEL_ATTR,
				    token, strlen(token));
			numattr++;
		}

		rv = kmf_store_cert(handle, numattr, attrlist);
		if (rv != KMF_OK) {
			display_error(handle, rv,
			    gettext("Failed to store cert "
			    "on PKCS#11 token.\n"));
			rv = KMF_OK;
			/* Not fatal, we can still write it to a file. */
		}
	}
	rv = kmf_create_cert_file(&outcert, fmt, certfile);

cleanup:
	kmf_free_signed_csr(&csrdata);
	kmf_free_data(&outcert);
	kmf_free_kmf_key(handle, &casignkey);

	return (rv);
}

/*
 * sign a CSR and generate an x509v3 certificate file.
 */
int
pk_signcsr(int argc, char *argv[])
{
	int			opt;
	extern int		optind_av;
	extern char		*optarg_av;
	char			*token_spec = NULL;
	char			*subject = NULL;
	char			*issuer = NULL;
	char			*dir = NULL;
	char			*prefix = NULL;
	char			*csrfile = NULL;
	char			*serstr = NULL;
	char			*ekustr = NULL;
	char			*kustr = NULL;
	char			*format = NULL;
	char			*storestr = NULL;
	char			*altname = NULL;
	char			*certfile = NULL;
	char			*lifetime = NULL;
	char			*signkey = NULL;
	char			*outlabel = NULL;
	uint32_t		ltime = 365 * 24 * 60 * 60; /* 1 Year */
	int			store = 0;
	uint16_t		kubits = 0;
	int			altcrit = 0, kucrit = 0;
	KMF_BIGINT		serial = { NULL, 0 };
	EKU_LIST		*ekulist = NULL;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE_T		kmfhandle = NULL;
	KMF_CREDENTIAL		tokencred = { NULL, 0 };
	KMF_GENERALNAMECHOICES	alttype = 0;
	KMF_ENCODE_FORMAT	fmt = KMF_FORMAT_PEM;

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
	    "k:(keystore)c:(csr)T:(token)d:(dir)"
	    "p:(prefix)S:(serial)s:(subject)a:(altname)"
	    "t:(store)F:(format)K:(keyusage)l:(signkey)"
	    "L:(lifetime)e:(eku)i:(issuer)"
	    "n:(outlabel)o:(outcert)")) != EOF) {
		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
			case 'k':
				if (kstype != 0)
					return (PK_ERR_USAGE);
				kstype = KS2Int(optarg_av);
				if (kstype == 0)
					return (PK_ERR_USAGE);
				break;
			case 't':
				if (storestr != NULL)
					return (PK_ERR_USAGE);
				storestr = optarg_av;
				store = yn_to_int(optarg_av);
				if (store == -1)
					return (PK_ERR_USAGE);
				break;
			case 'a':
				if (altname)
					return (PK_ERR_USAGE);
				altname = optarg_av;
				break;
			case 's':
				if (subject)
					return (PK_ERR_USAGE);
				subject = optarg_av;
				break;
			case 'i':
				if (issuer)
					return (PK_ERR_USAGE);
				issuer = optarg_av;
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
			case 'S':
				if (serstr != NULL)
					return (PK_ERR_USAGE);
				serstr = optarg_av;
				break;
			case 'c':
				if (csrfile)
					return (PK_ERR_USAGE);
				csrfile = optarg_av;
				break;
			case 'T':	/* token specifier */
				if (token_spec)
					return (PK_ERR_USAGE);
				token_spec = optarg_av;
				break;
			case 'l':	/* object with specific label */
				if (signkey)
					return (PK_ERR_USAGE);
				signkey = optarg_av;
				break;
			case 'e':
				if (ekustr != NULL)
					return (PK_ERR_USAGE);
				ekustr = optarg_av;
				break;
			case 'K':
				if (kustr != NULL)
					return (PK_ERR_USAGE);
				kustr = optarg_av;
				break;
			case 'F':
				if (format != NULL)
					return (PK_ERR_USAGE);
				format = optarg_av;
				break;
			case 'o':
				if (certfile != NULL)
					return (PK_ERR_USAGE);
				certfile = optarg_av;
				break;
			case 'L':
				if (lifetime != NULL)
					return (PK_ERR_USAGE);
				lifetime = optarg_av;
				break;
			case 'n':
				if (outlabel != NULL)
					return (PK_ERR_USAGE);
				outlabel = optarg_av;
				break;
			default:
				return (PK_ERR_USAGE);
		}
	}
	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);


	/* Assume keystore = PKCS#11 if not specified. */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	DIR_OPTION_CHECK(kstype, dir);

	if (signkey == NULL) {
		(void) fprintf(stderr, gettext("The signing key label "
		    "or filename was not specified\n"));
		return (PK_ERR_USAGE);
	}
	if (csrfile == NULL) {
		(void) fprintf(stderr, gettext("The CSR filename was not"
		    " specified\n"));
		return (PK_ERR_USAGE);
	}
	if (certfile == NULL) {
		(void) fprintf(stderr, gettext("The output certificate file "
		    "was not specified\n"));
		return (PK_ERR_USAGE);
	}
	if (issuer == NULL) {
		(void) fprintf(stderr, gettext("The issuer DN "
		    "was not specified\n"));
		return (PK_ERR_USAGE);
	}
	if (lifetime != NULL) {
		if (Str2Lifetime(lifetime, &ltime) != 0) {
			cryptoerror(LOG_STDERR,
			    gettext("Error parsing lifetime string\n"));
			return (PK_ERR_USAGE);
		}
	}
	if (kstype == KMF_KEYSTORE_PK11TOKEN && EMPTYSTRING(token_spec)) {
		token_spec = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && EMPTYSTRING(token_spec)) {
		token_spec = DEFAULT_NSS_TOKEN;
	}

	if (serstr != NULL) {
		uchar_t *bytes = NULL;
		size_t bytelen;

		rv = kmf_hexstr_to_bytes((uchar_t *)serstr, &bytes, &bytelen);
		if (rv != KMF_OK || bytes == NULL) {
			(void) fprintf(stderr, gettext("Serial number "
			    "must be specified as a hex number "
			    "(ex: 0x0102030405ffeeddee)\n"));
			return (PK_ERR_USAGE);
		}
		serial.val = bytes;
		serial.len = bytelen;
	} else {
		(void) fprintf(stderr, gettext("The serial number was not"
		    " specified\n"));
		return (PK_ERR_USAGE);
	}

	if ((kstype == KMF_KEYSTORE_PK11TOKEN ||
	    kstype == KMF_KEYSTORE_NSS)) {
		/* Need to get password for private key access */
		(void) get_token_password(kstype, token_spec,
		    &tokencred);
	}
	if (kustr != NULL) {
		rv = verify_keyusage(kustr, &kubits, &kucrit);
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
	if (altname != NULL) {
		char *p;
		rv = verify_altname(altname, &alttype, &altcrit);
		if (rv != KMF_OK) {
			(void) fprintf(stderr, gettext("Subject AltName "
			    "must be specified as a name=value pair. "
			    "See the man page for details.\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
		/* advance the altname past the '=' sign */
		p = strchr(altname, '=');
		if (p != NULL)
			altname = p + 1;
	}
	if (format && (fmt = Str2Format(format)) == KMF_FORMAT_UNDEF) {
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing format string (%s).\n"),
		    format);
		return (PK_ERR_USAGE);
	}

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		return (rv);
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = pk_signcsr_pk11_nss(kmfhandle,
		    kstype, dir, prefix, token_spec, &tokencred,
		    signkey, csrfile, &serial, certfile, issuer, subject,
		    altname, alttype, altcrit, kubits, kucrit,
		    ekulist, ltime, fmt, store, outlabel);

	} else if (kstype == KMF_KEYSTORE_NSS) {
		if (dir == NULL)
			dir = PK_DEFAULT_DIRECTORY;

		rv = pk_signcsr_pk11_nss(kmfhandle,
		    kstype, dir, prefix, token_spec, &tokencred,
		    signkey, csrfile, &serial, certfile, issuer, subject,
		    altname, alttype, altcrit, kubits, kucrit,
		    ekulist, ltime, fmt, store, outlabel);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = pk_signcsr_files(kmfhandle,
		    signkey, csrfile, &serial, certfile, issuer, subject,
		    altname, alttype, altcrit, kubits, kucrit,
		    ekulist, ltime, fmt);
	}

end:
	if (rv != KMF_OK) {
		display_error(kmfhandle, rv,
		    gettext("Error listing objects"));
	}

	if (serial.val != NULL)
		free(serial.val);

	if (tokencred.cred != NULL)
		free(tokencred.cred);

	free_eku_list(ekulist);

	(void) kmf_finalize(kmfhandle);
	return (rv);
}

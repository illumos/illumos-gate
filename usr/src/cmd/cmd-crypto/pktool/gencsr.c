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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
			gettext("Failed to %s: 0x%02\n"), \
			s, kmfrv); \
		goto cleanup; \
	}

static KMF_RETURN
gencsr_pkcs11(KMF_HANDLE_T kmfhandle,
	char *token, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	char *certlabel, KMF_KEY_ALG keyAlg,
	int keylen, uint16_t kubits, int kucrit,
	KMF_ENCODE_FORMAT fmt, char *csrfile,
	KMF_CREDENTIAL *tokencred, EKU_LIST *ekulist)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_NAME	csrSubject;
	KMF_CSR_DATA	csr;
	KMF_ALGORITHM_INDEX sigAlg;
	KMF_DATA signedCsr = {NULL, 0};

	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	boolean_t storekey = TRUE;

	(void) memset(&csr, 0, sizeof (csr));
	(void) memset(&csrSubject, 0, sizeof (csrSubject));

	if (keyAlg == KMF_DSA)
		sigAlg = KMF_ALGID_SHA1WithDSA;
	else
		sigAlg = KMF_ALGID_MD5WithRSA;


	/* If the subject name cannot be parsed, flag it now and exit */
	if ((kmfrv = kmf_dn_parser(subject, &csrSubject)) != KMF_OK) {
		return (kmfrv);
	}

	/* Select a PKCS11 token */
	kmfrv = select_token(kmfhandle, token, FALSE);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (certlabel != NULL && strlen(certlabel)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR,
		    certlabel, strlen(certlabel));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLENGTH_ATTR,
	    &keylen, sizeof (keylen));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYALG_ATTR,
	    &keyAlg, sizeof (keyAlg));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
	    tokencred, sizeof (KMF_CREDENTIAL));
	numattr++;

	if (token && strlen(token)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr, KMF_PUBKEY_HANDLE_ATTR,
	    &pubk, sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_PRIVKEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_STOREKEY_BOOL_ATTR,
	    &storekey, sizeof (storekey));
	numattr++;

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	SET_VALUE(kmf_set_csr_pubkey(kmfhandle, &pubk, &csr), "keypair");

	SET_VALUE(kmf_set_csr_version(&csr, 2), "version number");

	SET_VALUE(kmf_set_csr_subject(&csr, &csrSubject), "subject name");

	SET_VALUE(kmf_set_csr_sig_alg(&csr, sigAlg),
	    "SignatureAlgorithm");

	if (altname != NULL) {
		SET_VALUE(kmf_set_csr_subject_altname(&csr, altname, altcrit,
		    alttype), "SetCSRSubjectAltName");
	}

	if (kubits != 0) {
		SET_VALUE(kmf_set_csr_ku(&csr, kucrit, kubits),
		    "SetCSRKeyUsage");
	}
	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_csr_eku(&csr,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]),
			    "Extended Key Usage");
		}
	}
	if ((kmfrv = kmf_sign_csr(kmfhandle, &csr, &prik, &signedCsr)) ==
	    KMF_OK) {
		kmfrv = kmf_create_csr_file(&signedCsr, fmt, csrfile);
	}

cleanup:
	(void) kmf_free_data(&signedCsr);
	(void) kmf_free_kmf_key(kmfhandle, &prik);
	/* delete the key */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_PUBKEY_HANDLE_ATTR,
	    &pubk, sizeof (KMF_KEY_HANDLE));
	numattr++;

	(void) kmf_delete_key_from_keystore(kmfhandle, numattr, attrlist);

	(void) kmf_free_signed_csr(&csr);

	return (kmfrv);
}

static KMF_RETURN
gencsr_file(KMF_HANDLE_T kmfhandle,
	KMF_KEY_ALG keyAlg,
	int keylen, KMF_ENCODE_FORMAT fmt,
	char *subject, char *altname, KMF_GENERALNAMECHOICES alttype,
	int altcrit, uint16_t kubits, int kucrit,
	char *outcsr, char *outkey, EKU_LIST *ekulist)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_NAME	csrSubject;
	KMF_CSR_DATA	csr;
	KMF_ALGORITHM_INDEX sigAlg;
	KMF_DATA signedCsr = {NULL, 0};
	char *fullcsrpath = NULL;
	char *fullkeypath = NULL;

	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	boolean_t	storekey = TRUE;

	(void) memset(&csr, 0, sizeof (csr));
	(void) memset(&csrSubject, 0, sizeof (csrSubject));

	if (EMPTYSTRING(outcsr) || EMPTYSTRING(outkey)) {
		cryptoerror(LOG_STDERR,
		    gettext("No output file was specified for "
		    "the csr or key\n"));
		return (KMF_ERR_BAD_PARAMETER);
	}
	fullcsrpath = strdup(outcsr);
	if (verify_file(fullcsrpath)) {
		cryptoerror(LOG_STDERR,
		    gettext("Cannot write the indicated output "
		    "certificate file (%s).\n"), fullcsrpath);
		free(fullcsrpath);
		return (PK_ERR_USAGE);
	}

	fullkeypath = strdup(outkey);
	if (verify_file(fullcsrpath)) {
		cryptoerror(LOG_STDERR,
		    gettext("Cannot write the indicated output "
		    "key file (%s).\n"), fullkeypath);
		free(fullcsrpath);
		return (PK_ERR_USAGE);
	}

	if (keyAlg == KMF_DSA)
		sigAlg = KMF_ALGID_SHA1WithDSA;
	else
		sigAlg = KMF_ALGID_MD5WithRSA;

	/* If the subject name cannot be parsed, flag it now and exit */
	if ((kmfrv = kmf_dn_parser(subject, &csrSubject)) != KMF_OK) {
		return (kmfrv);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_FILENAME_ATTR,
	    fullkeypath, strlen(fullkeypath));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLENGTH_ATTR,
	    &keylen, sizeof (keylen));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYALG_ATTR,
	    &keyAlg, sizeof (keyAlg));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_ENCODE_FORMAT_ATTR,
	    &fmt, sizeof (fmt));
	numattr++;

	(void) memset(&prik, 0, sizeof (prik));
	kmf_set_attr_at_index(attrlist, numattr, KMF_PRIVKEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE));
	numattr++;

	(void) memset(&pubk, 0, sizeof (pubk));
	kmf_set_attr_at_index(attrlist, numattr, KMF_PUBKEY_HANDLE_ATTR,
	    &pubk, sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_STOREKEY_BOOL_ATTR,
	    &storekey, sizeof (storekey));
	numattr++;

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		goto cleanup;
	}
	SET_VALUE(kmf_set_csr_pubkey(kmfhandle, &pubk, &csr),
	    "SetCSRPubKey");

	SET_VALUE(kmf_set_csr_version(&csr, 2), "SetCSRVersion");

	SET_VALUE(kmf_set_csr_subject(&csr, &csrSubject),
	    "kmf_set_csr_subject");

	SET_VALUE(kmf_set_csr_sig_alg(&csr, sigAlg), "kmf_set_csr_sig_alg");

	if (altname != NULL) {
		SET_VALUE(kmf_set_csr_subject_altname(&csr, altname, altcrit,
		    alttype), "kmf_set_csr_subject_altname");
	}
	if (kubits != NULL) {
		SET_VALUE(kmf_set_csr_ku(&csr, kucrit, kubits),
		    "kmf_set_csr_ku");
	}
	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_csr_eku(&csr,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]),
			    "Extended Key Usage");
		}
	}
	if ((kmfrv = kmf_sign_csr(kmfhandle, &csr, &prik, &signedCsr)) ==
	    KMF_OK) {
		kmfrv = kmf_create_csr_file(&signedCsr, fmt, fullcsrpath);
	}

cleanup:
	if (fullkeypath)
		free(fullkeypath);
	if (fullcsrpath)
		free(fullcsrpath);

	kmf_free_data(&signedCsr);
	kmf_free_kmf_key(kmfhandle, &prik);
	kmf_free_signed_csr(&csr);

	return (kmfrv);
}

static KMF_RETURN
gencsr_nss(KMF_HANDLE_T kmfhandle,
	char *token, char *subject, char *altname,
	KMF_GENERALNAMECHOICES alttype, int altcrit,
	char *nickname, char *dir, char *prefix,
	KMF_KEY_ALG keyAlg, int keylen,
	uint16_t kubits, int kucrit,
	KMF_ENCODE_FORMAT fmt, char *csrfile,
	KMF_CREDENTIAL *tokencred, EKU_LIST *ekulist)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_NAME	csrSubject;
	KMF_CSR_DATA	csr;
	KMF_ALGORITHM_INDEX sigAlg;
	KMF_DATA signedCsr = {NULL, 0};

	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	boolean_t storekey = TRUE;

	if (token == NULL)
		token = DEFAULT_NSS_TOKEN;

	if (keyAlg == KMF_DSA)
		sigAlg = KMF_ALGID_SHA1WithDSA;
	else
		sigAlg = KMF_ALGID_MD5WithRSA;

	kmfrv = configure_nss(kmfhandle, dir, prefix);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	(void) memset(&csr, 0, sizeof (csr));
	(void) memset(&csrSubject, 0, sizeof (csrSubject));
	(void) memset(&pubk, 0, sizeof (pubk));
	(void) memset(&prik, 0, sizeof (prik));

	/* If the subject name cannot be parsed, flag it now and exit */
	if ((kmfrv = kmf_dn_parser(subject, &csrSubject)) != KMF_OK) {
		return (kmfrv);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (nickname != NULL && strlen(nickname)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR,
		    nickname, strlen(nickname));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLENGTH_ATTR,
	    &keylen, sizeof (keylen));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYALG_ATTR,
	    &keyAlg, sizeof (keyAlg));
	numattr++;

	if (tokencred != NULL && tokencred->credlen > 0) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	if (token && strlen(token)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr, KMF_PUBKEY_HANDLE_ATTR,
	    &pubk, sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_PRIVKEY_HANDLE_ATTR,
	    &prik, sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_STOREKEY_BOOL_ATTR,
	    &storekey, sizeof (storekey));
	numattr++;

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		goto cleanup;
	}

	SET_VALUE(kmf_set_csr_pubkey(kmfhandle, &pubk, &csr),
	    "kmf_set_csr_pubkey");
	SET_VALUE(kmf_set_csr_version(&csr, 2), "kmf_set_csr_version");
	SET_VALUE(kmf_set_csr_subject(&csr, &csrSubject),
	    "kmf_set_csr_subject");
	SET_VALUE(kmf_set_csr_sig_alg(&csr, sigAlg), "kmf_set_csr_sig_alg");

	if (altname != NULL) {
		SET_VALUE(kmf_set_csr_subject_altname(&csr, altname, altcrit,
		    alttype), "kmf_set_csr_subject_altname");
	}
	if (kubits != NULL) {
		SET_VALUE(kmf_set_csr_ku(&csr, kucrit, kubits),
		    "kmf_set_csr_ku");
	}
	if (ekulist != NULL) {
		int i;
		for (i = 0; kmfrv == KMF_OK && i < ekulist->eku_count; i++) {
			SET_VALUE(kmf_add_csr_eku(&csr,
			    &ekulist->ekulist[i],
			    ekulist->critlist[i]),
			    "Extended Key Usage");
		}
	}
	if ((kmfrv = kmf_sign_csr(kmfhandle, &csr, &prik, &signedCsr)) ==
	    KMF_OK) {
		kmfrv = kmf_create_csr_file(&signedCsr, fmt, csrfile);
	}

cleanup:
	(void) kmf_free_data(&signedCsr);
	(void) kmf_free_kmf_key(kmfhandle, &prik);

	/* delete the key */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_PUBKEY_HANDLE_ATTR,
	    &pubk, sizeof (KMF_KEY_HANDLE));
	numattr++;

	if (tokencred != NULL && tokencred->credlen > 0) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	if (token && strlen(token)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}

	(void) kmf_delete_key_from_keystore(kmfhandle, numattr, attrlist);

	(void) kmf_free_signed_csr(&csr);

	return (kmfrv);
}

int
pk_gencsr(int argc, char *argv[])
{
	KMF_RETURN rv;
	int opt;
	extern int	optind_av;
	extern char	*optarg_av;
	KMF_KEYSTORE_TYPE kstype = 0;
	char *subject = NULL;
	char *tokenname = NULL;
	char *dir = NULL;
	char *prefix = NULL;
	int keylen = PK_DEFAULT_KEYLENGTH;
	char *certlabel = NULL;
	char *outcsr = NULL;
	char *outkey = NULL;
	char *format = NULL;
	char *altname = NULL;
	char *kustr = NULL;
	char *ekustr = NULL;
	uint16_t kubits = 0;
	char *keytype = PK_DEFAULT_KEYTYPE;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_ENCODE_FORMAT fmt = KMF_FORMAT_ASN1;
	KMF_KEY_ALG keyAlg = KMF_RSA;
	KMF_ALGORITHM_INDEX sigAlg = KMF_ALGID_MD5WithRSA;
	boolean_t interactive = B_FALSE;
	char *subname = NULL;
	KMF_CREDENTIAL tokencred = {NULL, 0};
	KMF_GENERALNAMECHOICES alttype = 0;
	int altcrit = 0, kucrit = 0;
	EKU_LIST *ekulist = NULL;

	while ((opt = getopt_av(argc, argv,
	    "ik:(keystore)s:(subject)n:(nickname)A:(altname)"
	    "u:(keyusage)T:(token)d:(dir)p:(prefix)t:(keytype)"
	    "y:(keylen)l:(label)c:(outcsr)e:(eku)"
	    "K:(outkey)F:(format)")) != EOF) {

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
				kustr = optarg_av;
				break;
			case 'y':
				if (sscanf(optarg_av, "%d",
				    &keylen) != 1) {
					cryptoerror(LOG_STDERR,
					    gettext("Unrecognized "
					    "key length (%s)\n"), optarg_av);
					return (PK_ERR_USAGE);
				}
				break;
			case 'c':
				if (outcsr)
					return (PK_ERR_USAGE);
				outcsr = optarg_av;
				break;
			case 'K':
				if (outkey)
					return (PK_ERR_USAGE);
				outkey = optarg_av;
				break;
			case 'F':
				if (format)
					return (PK_ERR_USAGE);
				format = optarg_av;
				break;
			case 'e':
				ekustr = optarg_av;
				break;
			default:
				cryptoerror(LOG_STDERR, gettext(
				    "unrecognized gencsr option '%s'\n"),
				    argv[optind_av]);
				return (PK_ERR_USAGE);
		}
	}
	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc) {
		return (PK_ERR_USAGE);
	}

	/* Assume keystore = PKCS#11 if not specified. */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	DIR_OPTION_CHECK(kstype, dir);

	if (EMPTYSTRING(outcsr) && interactive) {
		(void) get_filename("CSR", &outcsr);
	}
	if (EMPTYSTRING(outcsr)) {
		(void) printf(gettext("A filename must be specified to hold"
		    "the final certificate request data.\n"));
		return (PK_ERR_USAGE);
	}
	/*
	 * verify that the outcsr file does not already exist
	 * and that it can be created.
	 */
	rv = verify_file(outcsr);
	if (rv != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("output file (%s) "
		    "cannot be created.\n"), outcsr);
		return (PK_ERR_USAGE);
	}

	if ((kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_PK11TOKEN)) {
		if (EMPTYSTRING(certlabel) && interactive)
			(void) get_certlabel(&certlabel);

		if (EMPTYSTRING(certlabel)) {
			cryptoerror(LOG_STDERR, gettext("A label must be "
			    "specified to create a certificate request.\n"));
			return (PK_ERR_USAGE);
		}
	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		if (EMPTYSTRING(outkey) && interactive)
			(void) get_filename("private key", &outkey);

		if (EMPTYSTRING(outkey)) {
			cryptoerror(LOG_STDERR, gettext("A key filename "
			    "must be specified to create a certificate "
			    "request.\n"));
			return (PK_ERR_USAGE);
		}
	}

	if (format && (fmt = Str2Format(format)) == KMF_FORMAT_UNDEF) {
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing format string (%s).\n"), format);
		return (PK_ERR_USAGE);
	}
	if (format && fmt != KMF_FORMAT_ASN1 && fmt != KMF_FORMAT_PEM) {
		cryptoerror(LOG_STDERR,
		    gettext("CSR must be DER or PEM format.\n"));
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
			    "-i must be specified to create a certificate "
			    "request.\n"));
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
	if (altname != NULL) {
		rv = verify_altname(altname, &alttype, &altcrit);
		if (rv != KMF_OK) {
			cryptoerror(LOG_STDERR, gettext("Subject AltName "
			    "must be specified as a name=value pair. "
			    "See the man page for details."));
			goto end;
		} else {
			/* advance the altname past the '=' sign */
			char *p = strchr(altname, '=');
			if (p != NULL)
				altname = p + 1;
		}
	}

	if (kustr != NULL) {
		rv = verify_keyusage(kustr, &kubits, &kucrit);
		if (rv != KMF_OK) {
			cryptoerror(LOG_STDERR, gettext("KeyUsage "
			    "must be specified as a comma-separated list. "
			    "See the man page for details."));
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

	if ((rv = Str2KeyType(keytype, &keyAlg, &sigAlg)) != 0) {
		cryptoerror(LOG_STDERR, gettext("Unrecognized keytype (%s).\n"),
		    keytype);
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

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing KMF\n"));
		return (PK_ERR_USAGE);
	}


	if (kstype == KMF_KEYSTORE_NSS) {
		if (dir == NULL)
			dir = PK_DEFAULT_DIRECTORY;

		rv = gencsr_nss(kmfhandle,
		    tokenname, subname, altname, alttype, altcrit,
		    certlabel, dir, prefix,
		    keyAlg, keylen, kubits, kucrit,
		    fmt, outcsr, &tokencred, ekulist);

	} else if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = gencsr_pkcs11(kmfhandle,
		    tokenname, subname, altname, alttype, altcrit,
		    certlabel, keyAlg, keylen,
		    kubits, kucrit, fmt, outcsr, &tokencred, ekulist);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = gencsr_file(kmfhandle,
		    keyAlg, keylen, fmt, subname, altname,
		    alttype, altcrit, kubits, kucrit,
		    outcsr, outkey, ekulist);
	}

end:
	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
		    gettext("Error creating CSR or keypair"));

	if (ekulist != NULL)
		free_eku_list(ekulist);

	if (subname)
		free(subname);

	if (tokencred.cred != NULL)
		free(tokencred.cred);

	(void) kmf_finalize(kmfhandle);
	if (rv != KMF_OK)
		return (PK_ERR_USAGE);

	return (0);
}

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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This file implements the export operation for this tool.
 * The basic flow of the process is to find the soft token,
 * log into it, find the PKCS#11 objects in the soft token
 * to be exported matching keys with their certificates, export
 * them to the PKCS#12 file encrypting them with a file password
 * if desired, and log out.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "common.h"

#include <kmfapi.h>

static KMF_RETURN
pk_find_export_cert(KMF_HANDLE_T kmfhandle, KMF_ATTRIBUTE *attrlist,
	int numattr, KMF_X509_DER_CERT *cert)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numcerts = 0;

	numcerts = 0;
	(void) memset(cert, 0, sizeof (KMF_X509_DER_CERT));

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &numcerts, sizeof (uint32_t));
	numattr++;

	rv = kmf_find_cert(kmfhandle, numattr, attrlist);
	if (rv != KMF_OK) {
		return (rv);
	}
	if (numcerts == 0) {
		cryptoerror(LOG_STDERR,
		    gettext("No matching certificates found."));
		return (KMF_ERR_CERT_NOT_FOUND);

	} else if (numcerts == 1) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_X509_DER_CERT_ATTR, cert,
		    sizeof (KMF_X509_DER_CERT));
		numattr++;
		rv = kmf_find_cert(kmfhandle, numattr, attrlist);

	} else if (numcerts > 1) {
		cryptoerror(LOG_STDERR,
		    gettext("%d certificates found, refine the "
		    "search parameters to eliminate ambiguity\n"),
		    numcerts);
		return (KMF_ERR_BAD_PARAMETER);
	}
	return (rv);
}

static KMF_RETURN
pk_export_file_objects(KMF_HANDLE_T kmfhandle, int oclass,
	char *issuer, char *subject, KMF_BIGINT *serial,
	char *infile, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT kmfcert;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];

	/* If searching for public objects or certificates, find certs now */
	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		if (issuer != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_ISSUER_NAME_ATTR, issuer,
			    strlen(issuer));
			numattr++;
		}

		if (subject != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_SUBJECT_NAME_ATTR, subject,
			    strlen(subject));
			numattr++;
		}

		if (serial != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_BIGINT_ATTR, serial,
			    sizeof (KMF_BIGINT));
			numattr++;
		}

		if (infile != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_FILENAME_ATTR, infile,
			    strlen(infile));
			numattr++;
		}

		rv = pk_find_export_cert(kmfhandle, attrlist, numattr,
		    &kmfcert);
		if (rv == KMF_OK) {
			kstype = KMF_KEYSTORE_OPENSSL;
			numattr = 0;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_DATA_ATTR, &kmfcert.certificate,
			    sizeof (KMF_DATA));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_FILENAME_ATTR, filename,
			    strlen(filename));
			numattr++;

			rv = kmf_store_cert(kmfhandle, numattr,
			    attrlist);

			kmf_free_kmf_cert(kmfhandle, &kmfcert);
		}
	}
	return (rv);
}

static KMF_RETURN
pk_export_pk12_nss(KMF_HANDLE_T kmfhandle,
	char *token_spec, char *dir, char *prefix,
	char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_CREDENTIAL *tokencred,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;
	KMF_CREDENTIAL p12cred = { NULL, 0 };
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	if (token_spec == NULL)
		token_spec = DEFAULT_NSS_TOKEN;

	kstype = KMF_KEYSTORE_NSS;
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	numattr++;

	if (certlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_LABEL_ATTR, certlabel, strlen(certlabel));
		numattr++;
	}

	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ISSUER_NAME_ATTR, issuer, strlen(issuer));
		numattr++;
	}

	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_SUBJECT_NAME_ATTR, subject, strlen(subject));
		numattr++;
	}

	if (serial != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_BIGINT_ATTR, serial, sizeof (KMF_BIGINT));
		numattr++;
	}

	if (tokencred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CREDENTIAL_ATTR, tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
	    token_spec, strlen(token_spec));
	numattr++;

	(void) get_pk12_password(&p12cred);
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PK12CRED_ATTR, &p12cred, sizeof (KMF_CREDENTIAL));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OUTPUT_FILENAME_ATTR, filename, strlen(filename));
	numattr++;

	rv = kmf_export_pk12(kmfhandle, numattr, attrlist);

	if (p12cred.cred)
		free(p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_pk12_files(KMF_HANDLE_T kmfhandle,
	char *certfile, char *keyfile,
	char *outfile)
{
	KMF_RETURN rv;
	KMF_KEYSTORE_TYPE kstype;
	KMF_CREDENTIAL p12cred = { NULL, 0 };
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;

	kstype = KMF_KEYSTORE_OPENSSL;
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	numattr++;

	if (certfile != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_FILENAME_ATTR, certfile, strlen(certfile));
		numattr++;
	}

	if (keyfile != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEY_FILENAME_ATTR, keyfile, strlen(keyfile));
		numattr++;
	}

	(void) get_pk12_password(&p12cred);
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PK12CRED_ATTR, &p12cred, sizeof (KMF_CREDENTIAL));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OUTPUT_FILENAME_ATTR, outfile, strlen(outfile));
	numattr++;

	rv = kmf_export_pk12(kmfhandle, numattr, attrlist);

	if (p12cred.cred)
		free(p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_nss_objects(KMF_HANDLE_T kmfhandle, char *token_spec,
	int oclass, char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_ENCODE_FORMAT kfmt, char *dir,
	char *prefix, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT kmfcert;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	/* If searching for public objects or certificates, find certs now */
	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		if (certlabel != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_LABEL_ATTR, certlabel,
			    strlen(certlabel));
			numattr++;
		}

		if (issuer != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_ISSUER_NAME_ATTR, issuer,
			    strlen(issuer));
			numattr++;
		}

		if (subject != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_SUBJECT_NAME_ATTR, subject,
			    strlen(subject));
			numattr++;
		}

		if (serial != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_BIGINT_ATTR, serial,
			    sizeof (KMF_BIGINT));
			numattr++;
		}

		if (token_spec != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_TOKEN_LABEL_ATTR, token_spec,
			    strlen(token_spec));
			numattr++;
		}

		rv = pk_find_export_cert(kmfhandle, attrlist, numattr,
		    &kmfcert);
		if (rv == KMF_OK) {
			kstype = KMF_KEYSTORE_OPENSSL;
			numattr = 0;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_DATA_ATTR, &kmfcert.certificate,
			    sizeof (KMF_DATA));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_FILENAME_ATTR, filename,
			    strlen(filename));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_ENCODE_FORMAT_ATTR, &kfmt, sizeof (kfmt));
			numattr++;

			rv = kmf_store_cert(kmfhandle, numattr, attrlist);

			kmf_free_kmf_cert(kmfhandle, &kmfcert);
		}
	}
	return (rv);
}

static KMF_RETURN
pk_export_pk12_pk11(KMF_HANDLE_T kmfhandle, char *token_spec,
	char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_CREDENTIAL *tokencred, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;
	KMF_CREDENTIAL p12cred = { NULL, 0 };
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;

	rv = select_token(kmfhandle, token_spec, TRUE);
	if (rv != KMF_OK) {
		return (rv);
	}

	kstype = KMF_KEYSTORE_PK11TOKEN;
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	numattr++;

	if (certlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_LABEL_ATTR, certlabel, strlen(certlabel));
		numattr++;
	}

	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ISSUER_NAME_ATTR, issuer, strlen(issuer));
		numattr++;
	}

	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_SUBJECT_NAME_ATTR, subject, strlen(subject));
		numattr++;
	}

	if (serial != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_BIGINT_ATTR, serial, sizeof (KMF_BIGINT));
		numattr++;
	}

	if (tokencred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CREDENTIAL_ATTR, tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	(void) get_pk12_password(&p12cred);
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PK12CRED_ATTR, &p12cred, sizeof (KMF_CREDENTIAL));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OUTPUT_FILENAME_ATTR, filename, strlen(filename));
	numattr++;

	rv = kmf_export_pk12(kmfhandle, numattr, attrlist);

	if (p12cred.cred)
		free(p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_pk11_keys(KMF_HANDLE_T kmfhandle, char *token,
	KMF_CREDENTIAL *cred, KMF_ENCODE_FORMAT format,
	char *label, char *filename, int oclass)
{
	KMF_RETURN rv = KMF_OK;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_KEY_CLASS kclass = KMF_KEYCLASS_NONE;
	int numattr = 0;
	uint32_t numkeys = 1;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_HANDLE key;
	boolean_t is_token = B_TRUE;

	if (EMPTYSTRING(label)) {
		cryptoerror(LOG_STDERR, gettext("A label "
		    "must be specified to export a key."));
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = select_token(kmfhandle, token, TRUE);
	if (rv != KMF_OK) {
		return (rv);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (cred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    cred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR,
	    label, strlen(label));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &numkeys, sizeof (numkeys));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &key, sizeof (key));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_BOOL_ATTR,
	    &is_token, sizeof (is_token));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_ENCODE_FORMAT_ATTR,
	    &format, sizeof (format));
	numattr++;

	/* Check to see if we are exporting private or public only */
	if ((oclass & PK_KEY_OBJ) == PK_PRIKEY_OBJ)
		kclass = KMF_ASYM_PRI;
	else if ((oclass & PK_KEY_OBJ) == PK_PUBKEY_OBJ)
		kclass = KMF_ASYM_PUB;
	else if ((oclass & PK_KEY_OBJ) == PK_SYMKEY_OBJ)
		kclass = KMF_SYMMETRIC;
	else /* only 1 key at a time can be exported here, so default to pri */
		kclass = KMF_ASYM_PRI;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYCLASS_ATTR,
	    &kclass, sizeof (kclass));
	numattr++;

	rv = kmf_find_key(kmfhandle, numattr, attrlist);
	/*
	 * If nothing found but caller wanted ALL keys, try symmetric
	 * this time.
	 */
	if (rv == KMF_ERR_KEY_NOT_FOUND && (oclass == PK_KEY_OBJ)) {
		kclass = KMF_SYMMETRIC;
		rv = kmf_find_key(kmfhandle, numattr, attrlist);
	}
	/*
	 * If nothing found but caller wanted ALL keys, try asymmetric
	 * public this time.
	 */
	if (rv == KMF_ERR_KEY_NOT_FOUND && (oclass == PK_KEY_OBJ)) {
		kclass = KMF_ASYM_PUB;
		rv = kmf_find_key(kmfhandle, numattr, attrlist);
	}
	if (rv == KMF_OK && key.keyclass == KMF_SYMMETRIC) {
		KMF_RAW_SYM_KEY rkey;

		(void) memset(&rkey, 0, sizeof (KMF_RAW_SYM_KEY));
		rv = kmf_get_sym_key_value(kmfhandle, &key, &rkey);
		if (rv == KMF_OK) {
			int fd, n, total = 0;

			fd = open(filename, O_CREAT | O_RDWR |O_TRUNC, 0600);
			if (fd == -1) {
				rv = KMF_ERR_OPEN_FILE;
				goto done;
			}
			do {
				n = write(fd, rkey.keydata.val + total,
				    rkey.keydata.len - total);
				if (n < 0) {
					if (errno == EINTR)
						continue;
					(void) close(fd);
					rv = KMF_ERR_WRITE_FILE;
					goto done;
				}
				total += n;

			} while (total < rkey.keydata.len);
			(void) close(fd);
		}
done:
		kmf_free_bigint(&rkey.keydata);
		kmf_free_kmf_key(kmfhandle, &key);
	} else if (rv == KMF_OK) {
		KMF_KEYSTORE_TYPE sslks = KMF_KEYSTORE_OPENSSL;
		(void) printf(gettext("Found %d asymmetric keys\n"), numkeys);

		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &sslks, sizeof (sslks));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr, KMF_RAW_KEY_ATTR,
		    key.keyp, sizeof (KMF_RAW_KEY_DATA));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr, KMF_ENCODE_FORMAT_ATTR,
		    &format, sizeof (format));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_FILENAME_ATTR,
		    filename, strlen(filename));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYCLASS_ATTR,
		    &key.keyclass, sizeof (KMF_KEY_CLASS));
		numattr++;

		rv = kmf_store_key(kmfhandle, numattr, attrlist);
		kmf_free_kmf_key(kmfhandle, &key);
	}

	return (rv);
}

static KMF_RETURN
pk_export_pk11_objects(KMF_HANDLE_T kmfhandle, char *token_spec,
	KMF_CREDENTIAL *cred, char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_ENCODE_FORMAT kfmt,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT kmfcert;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];

	rv = select_token(kmfhandle, token_spec, TRUE);

	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (cred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    cred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}
	if (certlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_LABEL_ATTR, certlabel,
		    strlen(certlabel));
		numattr++;
	}

	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ISSUER_NAME_ATTR, issuer,
		    strlen(issuer));
		numattr++;
	}

	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_SUBJECT_NAME_ATTR, subject,
		    strlen(subject));
		numattr++;
	}

	if (serial != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_BIGINT_ATTR, serial,
		    sizeof (KMF_BIGINT));
		numattr++;
	}

	rv = pk_find_export_cert(kmfhandle, attrlist, numattr, &kmfcert);

	if (rv == KMF_OK) {
		kstype = KMF_KEYSTORE_OPENSSL;
		numattr = 0;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_DATA_ATTR, &kmfcert.certificate,
		    sizeof (KMF_DATA));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_FILENAME_ATTR, filename, strlen(filename));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ENCODE_FORMAT_ATTR, &kfmt, sizeof (kfmt));
		numattr++;

		rv = kmf_store_cert(kmfhandle, numattr, attrlist);

		kmf_free_kmf_cert(kmfhandle, &kmfcert);
	}
	return (rv);
}

/*
 * Export objects from one keystore to a file.
 */
int
pk_export(int argc, char *argv[])
{
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*filename = NULL;
	char		*dir = NULL;
	char		*prefix = NULL;
	char		*certlabel = NULL;
	char		*subject = NULL;
	char		*issuer = NULL;
	char		*infile = NULL;
	char		*keyfile = NULL;
	char		*certfile = NULL;
	char		*serstr = NULL;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_ENCODE_FORMAT	kfmt = KMF_FORMAT_PKCS12;
	KMF_RETURN		rv = KMF_OK;
	int		oclass = PK_CERT_OBJ;
	KMF_BIGINT	serial = { NULL, 0 };
	KMF_HANDLE_T	kmfhandle = NULL;
	KMF_CREDENTIAL	tokencred = { NULL, 0 };

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
	    "k:(keystore)y:(objtype)T:(token)"
	    "d:(dir)p:(prefix)"
	    "l:(label)n:(nickname)s:(subject)"
	    "i:(issuer)S:(serial)"
	    "K:(keyfile)c:(certfile)"
	    "F:(outformat)"
	    "I:(infile)o:(outfile)")) != EOF) {
		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
		case 'k':
			kstype = KS2Int(optarg_av);
			if (kstype == 0)
				return (PK_ERR_USAGE);
			break;
		case 'y':
			oclass = OT2Int(optarg_av);
			if (oclass == -1)
				return (PK_ERR_USAGE);
			break;
		case 'T':	/* token specifier */
			if (token_spec)
				return (PK_ERR_USAGE);
			token_spec = optarg_av;
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
		case 'n':
		case 'l':
			if (certlabel)
				return (PK_ERR_USAGE);
			certlabel = optarg_av;
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
		case 'S':
			serstr = optarg_av;
			break;
		case 'F':
			kfmt = Str2Format(optarg_av);
			if (kfmt == KMF_FORMAT_UNDEF)
				return (PK_ERR_USAGE);
			break;
		case 'I':	/* output file name */
			if (infile)
				return (PK_ERR_USAGE);
			infile = optarg_av;
			break;
		case 'o':	/* output file name */
			if (filename)
				return (PK_ERR_USAGE);
			filename = optarg_av;
			break;
		case 'c':	/* input cert file name */
			if (certfile)
				return (PK_ERR_USAGE);
			certfile = optarg_av;
			break;
		case 'K':	/* input key file name */
			if (keyfile)
				return (PK_ERR_USAGE);
			keyfile = optarg_av;
			break;
		default:
			return (PK_ERR_USAGE);
		}
	}

	/* Assume keystore = PKCS#11 if not specified */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	/* Filename arg is required. */
	if (EMPTYSTRING(filename)) {
		cryptoerror(LOG_STDERR, gettext("You must specify "
		    "an 'outfile' parameter when exporting.\n"));
		return (PK_ERR_USAGE);
	}

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);

	DIR_OPTION_CHECK(kstype, dir);

	/* if PUBLIC or PRIVATE obj was given, the old syntax was used. */
	if ((oclass & (PK_PUBLIC_OBJ | PK_PRIVATE_OBJ)) &&
	    kstype != KMF_KEYSTORE_PK11TOKEN) {

		(void) fprintf(stderr, gettext("The objtype parameter "
		    "is only relevant if keystore=pkcs11\n"));
		return (PK_ERR_USAGE);
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN && EMPTYSTRING(token_spec))
		token_spec = PK_DEFAULT_PK11TOKEN;
	else if (kstype == KMF_KEYSTORE_NSS && EMPTYSTRING(token_spec))
		token_spec = DEFAULT_NSS_TOKEN;

	if (kstype == KMF_KEYSTORE_OPENSSL) {
		if (kfmt != KMF_FORMAT_PKCS12) {
			cryptoerror(LOG_STDERR, gettext("PKCS12 "
			    "is the only export format "
			    "supported for the 'file' "
			    "keystore.\n"));
			return (PK_ERR_USAGE);
		}
		if (EMPTYSTRING(keyfile) || EMPTYSTRING(certfile)) {
			cryptoerror(LOG_STDERR, gettext("A cert file"
			    "and a key file must be specified "
			    "when exporting to PKCS12 from the "
			    "'file' keystore.\n"));
			return (PK_ERR_USAGE);
		}
	}

	/* Check if the file exists */
	if (verify_file(filename) != KMF_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Warning: file \"%s\" exists, "
		    "will be overwritten."), filename);
		if (yesno(gettext("Continue with export? "),
		    gettext("Respond with yes or no.\n"), B_FALSE) == B_FALSE) {
			return (0);
		} else {
			/* remove the file */
			(void) unlink(filename);
		}
	}

	if (serstr != NULL) {
		uchar_t *bytes = NULL;
		size_t bytelen;

		rv = kmf_hexstr_to_bytes((uchar_t *)serstr, &bytes, &bytelen);
		if (rv != KMF_OK || bytes == NULL) {
			(void) fprintf(stderr, gettext("serial number "
			    "must be specified as a hex number "
			    "(ex: 0x0102030405ffeeddee)\n"));
			return (PK_ERR_USAGE);
		}
		serial.val = bytes;
		serial.len = bytelen;
	}

	/*
	 * We need a password in the following situations:
	 * 1.  When accessing PKCS11 token
	 * 2.  If NSS keystore, when making a PKCS12 file or when
	 * accessing any private object or key.
	 */
	if (kstype == KMF_KEYSTORE_PK11TOKEN ||
	    ((kstype == KMF_KEYSTORE_NSS) &&
	    ((oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ)) ||
	    (kfmt == KMF_FORMAT_PKCS12)))) {
			(void) get_token_password(kstype, token_spec,
			    &tokencred);
	}

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing "
		    "KMF: 0x%02x\n"), rv);
		return (rv);
	}

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_export_pk12_pk11(kmfhandle,
				    token_spec, certlabel,
				    issuer, subject,
				    &serial, &tokencred,
				    filename);
			else if ((oclass & PK_KEY_OBJ) ||
			    kfmt == KMF_FORMAT_RAWKEY)
				rv = pk_export_pk11_keys(kmfhandle,
				    token_spec, &tokencred, kfmt,
				    certlabel, filename, oclass);
			else
				rv = pk_export_pk11_objects(kmfhandle,
				    token_spec, &tokencred, certlabel,
				    issuer, subject, &serial, kfmt,
				    filename);
			break;
		case KMF_KEYSTORE_NSS:
			if (dir == NULL)
				dir = PK_DEFAULT_DIRECTORY;
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_export_pk12_nss(kmfhandle,
				    token_spec, dir, prefix,
				    certlabel, issuer,
				    subject, &serial,
				    &tokencred, filename);
			else
				rv = pk_export_nss_objects(kmfhandle,
				    token_spec,
				    oclass, certlabel, issuer, subject,
				    &serial, kfmt, dir, prefix, filename);
			break;
		case KMF_KEYSTORE_OPENSSL:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_export_pk12_files(kmfhandle,
				    certfile, keyfile, filename);
			else
				rv = pk_export_file_objects(kmfhandle, oclass,
				    issuer, subject, &serial,
				    infile, filename);
			break;
		default:
			rv = PK_ERR_USAGE;
			break;
	}

	if (rv != KMF_OK) {
		display_error(kmfhandle, rv,
		    gettext("Error exporting objects"));
	}

	if (serial.val != NULL)
		free(serial.val);

	(void) kmf_finalize(kmfhandle);

	return (rv);
}

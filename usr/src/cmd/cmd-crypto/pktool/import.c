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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"

#include <kmfapi.h>

static KMF_RETURN
pk_import_pk12_files(KMF_HANDLE_T kmfhandle, KMF_CREDENTIAL *cred,
	char *outfile, char *certfile, char *keyfile,
	char *dir, char *keydir, KMF_ENCODE_FORMAT outformat)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;

	rv = KMF_ImportPK12(kmfhandle, outfile, cred,
		&certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK) {
		(void) printf(gettext("Found %d certificate(s) and %d "
			"key(s) in %s\n"), ncerts, nkeys, outfile);
	}

	if (rv == KMF_OK && ncerts > 0) {
		KMF_STORECERT_PARAMS params;
		char newcertfile[MAXPATHLEN];

		(void) memset(&params, 0, sizeof (KMF_STORECERT_PARAMS));
		params.kstype = KMF_KEYSTORE_OPENSSL;
		params.sslparms.dirpath = dir;
		params.sslparms.format = outformat;

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			/*
			 * If storing more than 1 cert, gotta change
			 * the name so we don't overwrite the previous one.
			 * Just append a _# to the name.
			 */
			if (i > 0) {
				(void) snprintf(newcertfile,
					sizeof (newcertfile),
					"%s_%d", certfile, i);
				params.sslparms.certfile = newcertfile;
			} else {
				params.sslparms.certfile = certfile;
			}
			rv = KMF_StoreCert(kmfhandle, &params, &certs[i]);
		}
	}
	if (rv == KMF_OK && nkeys > 0) {
		KMF_STOREKEY_PARAMS skparms;
		char newkeyfile[MAXPATHLEN];

		(void) memset(&skparms, 0, sizeof (skparms));

		/* The order of certificates and keys should match */
		for (i = 0; rv == KMF_OK && i < nkeys; i++) {
			skparms.kstype = KMF_KEYSTORE_OPENSSL;
			skparms.sslparms.dirpath = keydir;
			skparms.sslparms.format = outformat;
			skparms.cred = *cred;
			skparms.certificate = &certs[i];

			if (i > 0) {
				(void) snprintf(newkeyfile,
					sizeof (newkeyfile),
					"%s_%d", keyfile, i);
				skparms.sslparms.keyfile = newkeyfile;
			} else {
				skparms.sslparms.keyfile = keyfile;
			}

			rv = KMF_StorePrivateKey(kmfhandle, &skparms,
				&keys[i]);
		}
	}
	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			KMF_FreeData(&certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			KMF_FreeRawKey(&keys[i]);
		free(keys);
	}


	return (rv);
}


static KMF_RETURN
pk_import_pk12_nss(
	KMF_HANDLE_T kmfhandle, KMF_CREDENTIAL *kmfcred,
	KMF_CREDENTIAL *tokencred,
	char *token_spec, char *dir, char *prefix,
	char *nickname, char *trustflags, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	rv = KMF_ImportPK12(kmfhandle, filename, kmfcred,
		&certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK)
		(void) printf(gettext("Found %d certificate(s) and %d "
			"key(s) in %s\n"), ncerts, nkeys, filename);

	if (rv == KMF_OK) {
		KMF_STORECERT_PARAMS params;

		(void) memset(&params, 0, sizeof (KMF_STORECERT_PARAMS));
		params.kstype = KMF_KEYSTORE_NSS;
		params.nssparms.slotlabel = token_spec;
		params.nssparms.trustflag = trustflags;

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			if (i == 0)
				params.certLabel = nickname;
			else
				params.certLabel = NULL;

			rv = KMF_StoreCert(kmfhandle, &params, &certs[i]);
		}
		if (rv != KMF_OK) {
			display_error(kmfhandle, rv,
				gettext("Error storing certificate "
					"in PKCS11 token"));
		}
	}

	if (rv == KMF_OK) {
		KMF_STOREKEY_PARAMS skparms;

		/* The order of certificates and keys should match */
		for (i = 0; i < nkeys; i++) {
			(void) memset(&skparms, 0,
				sizeof (KMF_STOREKEY_PARAMS));
			skparms.kstype = KMF_KEYSTORE_NSS;
			skparms.cred = *tokencred;
			skparms.label = nickname;
			skparms.certificate = &certs[i];
			skparms.nssparms.slotlabel = token_spec;

			rv = KMF_StorePrivateKey(kmfhandle, &skparms, &keys[i]);
		}
	}

	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			KMF_FreeData(&certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			KMF_FreeRawKey(&keys[i]);
		free(keys);
	}

	return (rv);
}

static KMF_RETURN
pk_import_cert(
	KMF_HANDLE_T kmfhandle,
	KMF_KEYSTORE_TYPE kstype,
	char *label, char *token_spec, char *filename,
	char *dir, char *prefix, char *trustflags)
{
	KMF_RETURN rv = KMF_OK;
	KMF_IMPORTCERT_PARAMS params;

	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = select_token(kmfhandle, token_spec, FALSE);

		if (rv != KMF_OK) {
			return (rv);
		}
	}

	(void) memset(&params, 0, sizeof (params));
	params.kstype = kstype;
	params.certfile = filename;
	params.certLabel = label;

	if (kstype == KMF_KEYSTORE_NSS) {
		rv = configure_nss(kmfhandle, dir, prefix);
		if (rv != KMF_OK)
			return (rv);
		params.nssparms.trustflag = trustflags;
		params.nssparms.slotlabel = token_spec;
	}

	rv = KMF_ImportCert(kmfhandle, &params);

	return (rv);
}

static KMF_RETURN
pk_import_file_crl(void *kmfhandle,
	char *infile,
	char *outfile,
	char *outdir,
	KMF_ENCODE_FORMAT outfmt)
{
	KMF_IMPORTCRL_PARAMS 	icrl_params;
	KMF_OPENSSL_PARAMS sslparams;

	sslparams.crlfile = infile;
	sslparams.dirpath = outdir;
	sslparams.outcrlfile = outfile;
	sslparams.format = outfmt;
	sslparams.crl_check = B_FALSE;

	icrl_params.kstype = KMF_KEYSTORE_OPENSSL;
	icrl_params.sslparms = sslparams;

	return (KMF_ImportCRL(kmfhandle, &icrl_params));

}

static KMF_RETURN
pk_import_nss_crl(void *kmfhandle,
	boolean_t verify_crl_flag,
	char *infile,
	char *outdir,
	char *prefix)
{
	KMF_IMPORTCRL_PARAMS 	icrl_params;
	KMF_RETURN rv;

	rv = configure_nss(kmfhandle, outdir, prefix);
	if (rv != KMF_OK)
		return (rv);

	icrl_params.kstype = KMF_KEYSTORE_NSS;
	icrl_params.nssparms.slotlabel = NULL;
	icrl_params.nssparms.crlfile = infile;
	icrl_params.nssparms.crl_check = verify_crl_flag;

	return (KMF_ImportCRL(kmfhandle, &icrl_params));

}

static KMF_RETURN
pk_import_pk12_pk11(
	KMF_HANDLE_T kmfhandle,
	KMF_CREDENTIAL *p12cred,
	KMF_CREDENTIAL *tokencred,
	char *label, char *token_spec,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;

	rv = select_token(kmfhandle, token_spec, FALSE);

	if (rv != KMF_OK) {
		return (rv);
	}

	rv = KMF_ImportPK12(kmfhandle, filename, p12cred,
		&certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK) {
		KMF_STOREKEY_PARAMS skparms;

		/* The order of certificates and keys should match */
		for (i = 0; i < nkeys; i++) {
			(void) memset(&skparms, 0,
				sizeof (KMF_STOREKEY_PARAMS));
			skparms.kstype = KMF_KEYSTORE_PK11TOKEN;
			skparms.certificate = &certs[i];
			if (tokencred != NULL)
				skparms.cred = *tokencred;
			if (i == 0)
				skparms.label = label;
			else
				skparms.label = NULL;

			rv = KMF_StorePrivateKey(kmfhandle, &skparms,
				&keys[i]);
		}
	}

	if (rv == KMF_OK) {
		KMF_STORECERT_PARAMS params;

		(void) printf(gettext("Found %d certificate(s) and %d "
			"key(s) in %s\n"), ncerts, nkeys, filename);
		(void) memset(&params, 0, sizeof (KMF_STORECERT_PARAMS));

		params.kstype = KMF_KEYSTORE_PK11TOKEN;

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			if (i == 0)
				params.certLabel = label;
			else
				params.certLabel = NULL;

			rv = KMF_StoreCert(kmfhandle, &params, &certs[i]);
		}
	}

	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			KMF_FreeData(&certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			KMF_FreeRawKey(&keys[i]);
		free(keys);
	}

	return (rv);
}

/*
 * Import objects from into KMF repositories.
 */
int
pk_import(int argc, char *argv[])
{
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*filename = NULL;
	char		*keyfile = NULL;
	char		*certfile = NULL;
	char		*crlfile = NULL;
	char		*certlabel = NULL;
	char		*dir = NULL;
	char		*keydir = NULL;
	char		*prefix = NULL;
	char		*trustflags = NULL;
	char		*verify_crl = NULL;
	boolean_t	verify_crl_flag = B_FALSE;
	int		oclass = 0;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_ENCODE_FORMAT	kfmt = 0;
	KMF_ENCODE_FORMAT	okfmt = KMF_FORMAT_ASN1;
	KMF_RETURN		rv = KMF_OK;
	KMF_CREDENTIAL	pk12cred = { NULL, 0 };
	KMF_CREDENTIAL	tokencred = { NULL, 0 };
	KMF_HANDLE_T	kmfhandle = NULL;

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
		"T:(token)i:(infile)"
		"k:(keystore)y:(objtype)"
		"d:(dir)p:(prefix)"
		"n:(certlabel)N:(label)"
		"K:(outkey)c:(outcert)"
		"v:(verifycrl)l:(outcrl)"
		"t:(trust)D:(keydir)F:(outformat)")) != EOF) {
		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
		case 'T':	/* token specifier */
			if (token_spec)
				return (PK_ERR_USAGE);
			token_spec = optarg_av;
			break;
		case 'c':	/* output cert file name */
			if (certfile)
				return (PK_ERR_USAGE);
			certfile = optarg_av;
			break;
		case 'l':	/* output CRL file name */
			if (crlfile)
				return (PK_ERR_USAGE);
			crlfile = optarg_av;
			break;
		case 'K':	/* output key file name */
			if (keyfile)
				return (PK_ERR_USAGE);
			keyfile = optarg_av;
			break;
		case 'i':	/* input file name */
			if (filename)
				return (PK_ERR_USAGE);
			filename = optarg_av;
			break;
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
		case 'd':
			dir = optarg_av;
			break;
		case 'D':
			keydir = optarg_av;
			break;
		case 'p':
			if (prefix)
				return (PK_ERR_USAGE);
			prefix = optarg_av;
			break;
		case 'n':
		case 'N':
			if (certlabel)
				return (PK_ERR_USAGE);
			certlabel = optarg_av;
			break;
		case 'F':
			okfmt = Str2Format(optarg_av);
			if (okfmt == KMF_FORMAT_UNDEF)
				return (PK_ERR_USAGE);
			break;
		case 't':
			if (trustflags)
				return (PK_ERR_USAGE);
			trustflags = optarg_av;
			break;
		case 'v':
			verify_crl = optarg_av;
			if (tolower(verify_crl[0]) == 'y')
				verify_crl_flag = B_TRUE;
			else if (tolower(verify_crl[0]) == 'n')
				verify_crl_flag = B_FALSE;
			else
				return (PK_ERR_USAGE);
			break;
		default:
			return (PK_ERR_USAGE);
			break;
		}
	}

	/* Assume keystore = PKCS#11 if not specified */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	/* Filename arg is required. */
	if (EMPTYSTRING(filename)) {
		cryptoerror(LOG_STDERR, gettext("The 'infile' parameter"
			"is required for the import operation.\n"));
		return (PK_ERR_USAGE);
	}

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);

	/* if PUBLIC or PRIVATE obj was given, the old syntax was used. */
	if ((oclass & (PK_PUBLIC_OBJ | PK_PRIVATE_OBJ)) &&
		kstype != KMF_KEYSTORE_PK11TOKEN) {

		(void) fprintf(stderr, gettext("The objtype parameter "
			"is only relevant if keystore=pkcs11\n"));
		return (PK_ERR_USAGE);
	}

	/*
	 * You must specify a certlabel (cert label) when importing
	 * into NSS or PKCS#11.
	 */
	if (kstype == KMF_KEYSTORE_NSS &&
		(oclass != PK_CRL_OBJ) && EMPTYSTRING(certlabel)) {
		cryptoerror(LOG_STDERR, gettext("The 'label' argument "
			"is required for this operation\n"));
		return (PK_ERR_USAGE);
	}

	/*
	 * PKCS11 only imports PKCS#12 files or PEM/DER Cert files.
	 */
	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		/* we do not import private keys except in PKCS12 bundles */
		if (oclass & (PK_PRIVATE_OBJ | PK_PRIKEY_OBJ)) {
			cryptoerror(LOG_STDERR, gettext(
				"The PKCS11 keystore only imports PKCS12 "
				"files or raw certificate data files "
				" or CRL file.\n"));
			return (PK_ERR_USAGE);
		}
	}

	if ((rv = KMF_GetFileFormat(filename, &kfmt)) != KMF_OK) {
		cryptoerror(LOG_STDERR,
			gettext("File format not recognized."));
		return (rv);
	}
	if (oclass == 0 && (kfmt == KMF_FORMAT_ASN1 ||
		kfmt == KMF_FORMAT_PEM))
		oclass = PK_CERT_OBJ;

	if (kstype == KMF_KEYSTORE_NSS) {
		if (oclass == PK_CRL_OBJ &&
			(kfmt != KMF_FORMAT_ASN1 && kfmt != KMF_FORMAT_PEM)) {
			cryptoerror(LOG_STDERR, gettext(
				"CRL data can only be imported as DER or "
				"PEM format"));
			return (PK_ERR_USAGE);
		}

		if (oclass == PK_CERT_OBJ &&
			(kfmt != KMF_FORMAT_ASN1 && kfmt != KMF_FORMAT_PEM)) {
			cryptoerror(LOG_STDERR, gettext(
				"Certificates can only be imported as DER or "
				"PEM format"));
			return (PK_ERR_USAGE);
		}

		/* we do not import private keys except in PKCS12 bundles */
		if (oclass & (PK_PRIVATE_OBJ | PK_PRIKEY_OBJ)) {
			cryptoerror(LOG_STDERR, gettext(
				"Private key data can only be imported as part "
				"of a PKCS12 file.\n"));
			return (PK_ERR_USAGE);
		}
	}

	if (kstype == KMF_KEYSTORE_OPENSSL && oclass != PK_CRL_OBJ) {
		if (EMPTYSTRING(keyfile) || EMPTYSTRING(certfile)) {
			cryptoerror(LOG_STDERR, gettext(
				"The 'outkey' and 'outcert' parameters "
				"are required for the import operation "
				"when the 'file' keystore is used.\n"));
			return (PK_ERR_USAGE);
		}
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN && EMPTYSTRING(token_spec))
		token_spec = PK_DEFAULT_PK11TOKEN;
	else if (kstype == KMF_KEYSTORE_NSS && EMPTYSTRING(token_spec))
		token_spec = DEFAULT_NSS_TOKEN;

	if (kfmt == KMF_FORMAT_PKCS12) {
		(void) get_pk12_password(&pk12cred);

		if (kstype == KMF_KEYSTORE_PK11TOKEN ||
			kstype == KMF_KEYSTORE_NSS)
			(void) get_token_password(kstype, token_spec,
				&tokencred);
	}

	if ((rv = KMF_Initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing "
				"KMF: 0x%02x\n"), rv);
		goto end;
	}

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_pk11(
					kmfhandle,
					&pk12cred,
					&tokencred,
					certlabel,
					token_spec,
					filename);
			else if (oclass == PK_CERT_OBJ)
				rv = pk_import_cert(
					kmfhandle,
					kstype,
					certlabel,
					token_spec,
					filename,
					NULL, NULL, NULL);
			else if (oclass == PK_CRL_OBJ)
				rv = pk_import_file_crl(
					kmfhandle,
					filename,
					crlfile,
					dir,
					okfmt);
			break;
		case KMF_KEYSTORE_NSS:
			if (dir == NULL)
				dir = PK_DEFAULT_DIRECTORY;
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_nss(
					kmfhandle, &pk12cred,
					&tokencred,
					token_spec, dir, prefix,
					certlabel, trustflags, filename);
			else if (oclass == PK_CERT_OBJ) {
				rv = pk_import_cert(
					kmfhandle, kstype,
					certlabel, token_spec,
					filename, dir, prefix, trustflags);
			} else if (oclass == PK_CRL_OBJ) {
				rv = pk_import_nss_crl(
					kmfhandle,
					verify_crl_flag,
					filename,
					dir,
					prefix);
			}
			break;
		case KMF_KEYSTORE_OPENSSL:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_files(
					kmfhandle, &pk12cred,
					filename, certfile, keyfile,
					dir, keydir, okfmt);
			else if (oclass == PK_CRL_OBJ) {
				rv = pk_import_file_crl(
					kmfhandle,
					filename,
					crlfile,
					dir,
					okfmt);
			} else
				/*
				 * It doesn't make sense to import anything
				 * else for the files plugin.
				 */
				return (PK_ERR_USAGE);
			break;
		default:
			rv = PK_ERR_USAGE;
			break;
	}

end:
	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
			gettext("Error importing objects"));

	if (tokencred.cred != NULL)
		free(tokencred.cred);

	if (pk12cred.cred != NULL)
		free(pk12cred.cred);

	(void) KMF_Finalize(kmfhandle);

	if (rv != KMF_OK)
		return (PK_ERR_USAGE);

	return (0);
}

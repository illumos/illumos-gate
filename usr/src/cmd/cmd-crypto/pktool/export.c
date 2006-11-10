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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
pk_find_export_cert(KMF_HANDLE_T kmfhandle, KMF_FINDCERT_PARAMS *parms,
	KMF_X509_DER_CERT *cert)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numcerts = 0;

	numcerts = 0;
	(void) memset(cert, 0, sizeof (KMF_X509_DER_CERT));
	rv = KMF_FindCert(kmfhandle, parms, NULL, &numcerts);
	if (rv != KMF_OK) {
		return (rv);
	}
	if (numcerts == 0) {
		cryptoerror(LOG_STDERR,
			gettext("No matching certificates found."));
		return (KMF_ERR_CERT_NOT_FOUND);

	} else if (numcerts == 1) {
		rv = KMF_FindCert(kmfhandle, parms, cert, &numcerts);

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
	KMF_ENCODE_FORMAT ofmt,
	char *dir, char *infile, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_STORECERT_PARAMS scparms;
	KMF_X509_DER_CERT kmfcert;

	/* If searching for public objects or certificates, find certs now */
	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		KMF_FINDCERT_PARAMS fcargs;

		(void) memset(&fcargs, 0, sizeof (fcargs));
		fcargs.kstype = KMF_KEYSTORE_OPENSSL;
		fcargs.certLabel = NULL;
		fcargs.issuer = issuer;
		fcargs.subject = subject;
		fcargs.serial = serial;
		fcargs.sslparms.dirpath = dir;
		fcargs.sslparms.certfile = infile;
		fcargs.sslparms.format = ofmt;

		rv = pk_find_export_cert(kmfhandle, &fcargs, &kmfcert);
		if (rv == KMF_OK) {
			(void) memset(&scparms, 0, sizeof (scparms));
			scparms.kstype = KMF_KEYSTORE_OPENSSL;
			scparms.sslparms.certfile = filename;
			rv = KMF_StoreCert(kmfhandle, &scparms,
				&kmfcert.certificate);

			KMF_FreeKMFCert(kmfhandle, &kmfcert);
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
	KMF_EXPORTP12_PARAMS p12parms;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	(void) memset(&p12parms, 0, sizeof (p12parms));
	if (token_spec == NULL)
		token_spec = DEFAULT_NSS_TOKEN;

	p12parms.kstype = KMF_KEYSTORE_NSS;
	p12parms.certLabel = certlabel;
	p12parms.issuer = issuer;
	p12parms.subject = subject;
	p12parms.serial = serial;
	p12parms.idstr = NULL;
	if (tokencred != NULL)
		p12parms.cred = *tokencred;
	p12parms.nssparms.slotlabel = token_spec;

	(void) get_pk12_password(&p12parms.p12cred);

	rv = KMF_ExportPK12(kmfhandle, &p12parms, filename);
	if (p12parms.p12cred.cred)
		free(p12parms.p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_pk12_files(KMF_HANDLE_T kmfhandle,
	char *certfile, char *keyfile, char *dir,
	char *outfile)
{
	KMF_RETURN rv;
	KMF_EXPORTP12_PARAMS p12parms;

	(void) memset(&p12parms, 0, sizeof (p12parms));

	p12parms.kstype = KMF_KEYSTORE_OPENSSL;
	p12parms.certLabel = NULL;
	p12parms.issuer = NULL;
	p12parms.subject = NULL;
	p12parms.serial = 0;
	p12parms.idstr = NULL;
	p12parms.sslparms.dirpath = dir;
	p12parms.sslparms.certfile = certfile;
	p12parms.sslparms.keyfile = keyfile;

	(void) get_pk12_password(&p12parms.p12cred);

	rv = KMF_ExportPK12(kmfhandle, &p12parms, outfile);

	if (p12parms.p12cred.cred)
		free(p12parms.p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_nss_objects(KMF_HANDLE_T kmfhandle, char *token_spec,
	int oclass, char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_ENCODE_FORMAT kfmt, char *dir,
	char *prefix, char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_STORECERT_PARAMS scparms;
	KMF_X509_DER_CERT kmfcert;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	/* If searching for public objects or certificates, find certs now */
	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		KMF_FINDCERT_PARAMS fcargs;

		(void) memset(&fcargs, 0, sizeof (fcargs));
		fcargs.kstype = KMF_KEYSTORE_NSS;
		fcargs.certLabel = certlabel;
		fcargs.issuer = issuer;
		fcargs.subject = subject;
		fcargs.serial = serial;
		fcargs.nssparms.slotlabel = token_spec;

		rv = pk_find_export_cert(kmfhandle, &fcargs, &kmfcert);
		if (rv == KMF_OK) {
			(void) memset(&scparms, 0, sizeof (scparms));
			scparms.kstype = KMF_KEYSTORE_OPENSSL;
			scparms.sslparms.certfile = filename;
			scparms.sslparms.format = kfmt;

			rv = KMF_StoreCert(kmfhandle, &scparms,
				&kmfcert.certificate);

			KMF_FreeKMFCert(kmfhandle, &kmfcert);
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
	KMF_EXPORTP12_PARAMS p12parms;

	rv = select_token(kmfhandle, token_spec, TRUE);
	if (rv != KMF_OK) {
		return (rv);
	}

	(void) memset(&p12parms, 0, sizeof (p12parms));

	p12parms.kstype = KMF_KEYSTORE_PK11TOKEN;
	p12parms.certLabel = certlabel;
	p12parms.issuer = issuer;
	p12parms.subject = subject;
	p12parms.serial = serial;
	p12parms.idstr = NULL;
	if (tokencred != NULL)
		p12parms.cred = *tokencred;
	(void) get_pk12_password(&p12parms.p12cred);

	rv = KMF_ExportPK12(kmfhandle, &p12parms, filename);

	if (p12parms.p12cred.cred)
		free(p12parms.p12cred.cred);

	return (rv);
}

static KMF_RETURN
pk_export_pk11_objects(KMF_HANDLE_T kmfhandle, char *token_spec,
	char *certlabel, char *issuer, char *subject,
	KMF_BIGINT *serial, KMF_ENCODE_FORMAT kfmt,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDCERT_PARAMS fcparms;
	KMF_STORECERT_PARAMS scparms;
	KMF_X509_DER_CERT kmfcert;

	rv = select_token(kmfhandle, token_spec, TRUE);

	if (rv != KMF_OK) {
		return (rv);
	}

	(void) memset(&fcparms, 0, sizeof (fcparms));
	fcparms.kstype = KMF_KEYSTORE_PK11TOKEN;
	fcparms.certLabel = certlabel;
	fcparms.issuer = issuer;
	fcparms.subject = subject;
	fcparms.serial = serial;

	rv = pk_find_export_cert(kmfhandle, &fcparms, &kmfcert);

	if (rv == KMF_OK) {
		(void) memset(&scparms, 0, sizeof (scparms));
		scparms.kstype = KMF_KEYSTORE_OPENSSL;
		scparms.sslparms.certfile = filename;
		scparms.sslparms.format = kfmt;

		rv = KMF_StoreCert(kmfhandle, &scparms,
			&kmfcert.certificate);

		KMF_FreeKMFCert(kmfhandle, &kmfcert);
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
	KMF_CREDENTIAL	tokencred = {NULL, 0};

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
			break;
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

	/* Check if the file exists and might be overwritten. */
	if (access(filename, F_OK) == 0) {
		cryptoerror(LOG_STDERR,
			gettext("Warning: file \"%s\" exists, "
				"will be overwritten."), filename);
		if (yesno(gettext("Continue with export? "),
		    gettext("Respond with yes or no.\n"), B_FALSE) == B_FALSE) {
			return (0);
		}
	} else {
		rv = verify_file(filename);
		if (rv != KMF_OK) {
			cryptoerror(LOG_STDERR, gettext("The file (%s) "
				"cannot be created.\n"), filename);
			return (PK_ERR_USAGE);
		}
	}

	if (serstr != NULL) {
		uchar_t *bytes = NULL;
		size_t bytelen;

		rv = KMF_HexString2Bytes((uchar_t *)serstr, &bytes, &bytelen);
		if (rv != KMF_OK || bytes == NULL) {
			(void) fprintf(stderr, gettext("serial number "
				"must be specified as a hex number "
				"(ex: 0x0102030405ffeeddee)\n"));
			return (PK_ERR_USAGE);
		}
		serial.val = bytes;
		serial.len = bytelen;
	}

	if ((kstype == KMF_KEYSTORE_PK11TOKEN ||
		kstype == KMF_KEYSTORE_NSS) &&
		(oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ) ||
		kfmt == KMF_FORMAT_PKCS12)) {
			(void) get_token_password(kstype, token_spec,
				&tokencred);
	}

	if ((rv = KMF_Initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing "
				"KMF: 0x%02x\n"), rv);
		return (rv);
	}

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_export_pk12_pk11(
					kmfhandle,
					token_spec,
					certlabel,
					issuer, subject,
					&serial, &tokencred,
					filename);
			else
				rv = pk_export_pk11_objects(kmfhandle,
					token_spec,
					certlabel,
					issuer, subject,
					&serial, kfmt,
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
					certfile, keyfile, dir,
					filename);
			else
				rv = pk_export_file_objects(kmfhandle, oclass,
					issuer, subject, &serial, kfmt,
					dir, infile, filename);
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

	(void) KMF_Finalize(kmfhandle);

	return (rv);
}

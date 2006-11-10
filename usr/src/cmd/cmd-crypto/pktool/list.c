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
 * This file implements the token object list operation for this tool.
 * It loads the PKCS#11 modules, finds the object to list, lists it,
 * and cleans up.  User must be logged into the token to list private
 * objects.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

#include <kmfapi.h>

static void
pk_show_certs(KMF_HANDLE_T kmfhandle, KMF_X509_DER_CERT *certs, int num_certs)
{
	int i;
	char *subject, *issuer, *serial, *id, *altname;

	for (i = 0; i < num_certs; i++) {
		subject = NULL;
		issuer = NULL;
		serial = NULL;
		id = NULL;
		altname = NULL;

		(void) fprintf(stdout,
			gettext("%d. (X.509 certificate)\n"), i + 1);
		if (certs[i].kmf_private.label != NULL)
			(void) fprintf(stdout, gettext("\t%s: %s\n"),
				(certs[i].kmf_private.keystore_type ==
				KMF_KEYSTORE_OPENSSL ?  "Filename" : "Label"),
				certs[i].kmf_private.label);
		if (KMF_GetCertIDString(&certs[i].certificate,
				&id) == KMF_OK)
			(void) fprintf(stdout, gettext("\tID: %s\n"), id);
		if (KMF_GetCertSubjectNameString(kmfhandle,
			&certs[i].certificate, &subject) == KMF_OK)
			(void) fprintf(stdout, gettext("\tSubject: %s\n"),
				subject);
		if (KMF_GetCertIssuerNameString(kmfhandle,
			&certs[i].certificate, &issuer) == KMF_OK)
			(void) fprintf(stdout, gettext("\tIssuer: %s\n"),
				issuer);
		if (KMF_GetCertSerialNumberString(kmfhandle,
			&certs[i].certificate, &serial) == KMF_OK)
			(void) fprintf(stdout, gettext("\tSerial: %s\n"),
				serial);

		if (KMF_GetCertExtensionString(kmfhandle,
			&certs[i].certificate, KMF_X509_EXT_SUBJ_ALTNAME,
			&altname) == KMF_OK)  {
			(void) fprintf(stdout, gettext("\t%s\n"),
				altname);
		}

		KMF_FreeString(subject);
		KMF_FreeString(issuer);
		KMF_FreeString(serial);
		KMF_FreeString(id);
		KMF_FreeString(altname);
		(void) fprintf(stdout, "\n");
	}
}

static char *
describeKey(KMF_KEY_HANDLE *key)
{
	if (key->keyclass == KMF_ASYM_PUB) {
		if (key->keyalg == KMF_RSA)
			return (gettext("RSA public key"));
		if (key->keyalg == KMF_DSA)
			return (gettext("DSA public key"));
	}
	if (key->keyclass == KMF_ASYM_PRI) {
		if (key->keyalg == KMF_RSA)
			return ("RSA private key");
		if (key->keyalg == KMF_DSA)
			return ("DSA private key");
	}
	if (key->keyclass == KMF_SYMMETRIC) {
		switch (key->keyalg) {
			case KMF_AES:
				return (gettext("AES"));
				break;
			case KMF_RC4:
				return (gettext("ARCFOUR"));
				break;
			case KMF_DES:
				return (gettext("DES"));
				break;
			case KMF_DES3:
				return (gettext("Triple-DES"));
				break;
			default:
				return (gettext("symmetric"));
				break;
		}
	}

	return (gettext("unrecognized key object"));

}

static char *
keybitstr(KMF_KEY_HANDLE *key)
{
	KMF_RAW_SYM_KEY *rkey;
	char keystr[256];
	char *p;

	if (key == NULL || (key->keyclass != KMF_SYMMETRIC))
		return ("");

	rkey = (KMF_RAW_SYM_KEY *)key->keyp;
	(void) memset(keystr, 0, sizeof (keystr));
	if (rkey != NULL) {
		(void) snprintf(keystr, sizeof (keystr),
			" (%d bits)", rkey->keydata.len * 8);
		p = keystr;
	} else {
		return ("");
	}

	return (p);
}

static void
pk_show_keys(void *handle, KMF_KEY_HANDLE *keys, int numkeys)
{
	int i;

	for (i = 0; i < numkeys; i++) {
		(void) fprintf(stdout, gettext("Key #%d - %s:  %s%s"),
			i+1, describeKey(&keys[i]),
			keys[i].keylabel ? keys[i].keylabel :
			gettext("No label"),
			(keys[i].keyclass == KMF_SYMMETRIC ?
			keybitstr(&keys[i]) : ""));

		if (keys[i].keyclass == KMF_SYMMETRIC) {
			KMF_RETURN rv;
			KMF_RAW_SYM_KEY rkey;
			rv = KMF_GetSymKeyValue(handle, &keys[i],
				&rkey);
			if (rv == KMF_OK) {
				(void) fprintf(stdout, "\t %d bits",
					rkey.keydata.len * 8);
				KMF_FreeRawSymKey(&rkey);
			}
		}
		(void) fprintf(stdout, "\n");
	}
}

/*
 * Generic routine used by all "list cert" operations to find
 * all matching certificates.
 */
static KMF_RETURN
pk_find_certs(KMF_HANDLE_T kmfhandle, KMF_FINDCERT_PARAMS *params)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT *certlist = NULL;
	uint32_t numcerts = 0;

	numcerts = 0;
	rv = KMF_FindCert(kmfhandle, params, NULL, &numcerts);
	if (rv == KMF_OK && numcerts > 0) {
		(void) printf(gettext("Found %d certificates.\n"),
			numcerts);
		certlist = (KMF_X509_DER_CERT *)malloc(numcerts *
				sizeof (KMF_X509_DER_CERT));
		if (certlist == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(certlist, 0, numcerts *
			sizeof (KMF_X509_DER_CERT));

		rv = KMF_FindCert(kmfhandle, params, certlist, &numcerts);
		if (rv == KMF_OK) {
			int i;
			(void) pk_show_certs(kmfhandle, certlist,
				numcerts);
			for (i = 0; i < numcerts; i++)
				KMF_FreeKMFCert(kmfhandle, &certlist[i]);
		}
		free(certlist);
	}
	if (rv == KMF_ERR_CERT_NOT_FOUND &&
		params->kstype != KMF_KEYSTORE_OPENSSL)
		rv = KMF_OK;

	return (rv);
}

static KMF_RETURN
pk_list_keys(void *handle, KMF_FINDKEY_PARAMS *parms)
{
	KMF_RETURN rv;
	KMF_KEY_HANDLE *keys;
	uint32_t numkeys = 0;

	numkeys = 0;
	rv = KMF_FindKey(handle, parms, NULL, &numkeys);
	if (rv == KMF_OK && numkeys > 0) {
		int i;
		(void) printf(gettext("Found %d keys.\n"), numkeys);
		keys = (KMF_KEY_HANDLE *)malloc(numkeys *
				sizeof (KMF_KEY_HANDLE));
		if (keys == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(keys, 0, numkeys *
			sizeof (KMF_KEY_HANDLE));

		rv = KMF_FindKey(handle, parms, keys, &numkeys);
		if (rv == KMF_OK)
			pk_show_keys(handle, keys, numkeys);
		for (i = 0; i < numkeys; i++)
			KMF_FreeKMFKey(handle, &keys[i]);
		free(keys);
	}
	if (rv == KMF_ERR_KEY_NOT_FOUND &&
		parms->kstype != KMF_KEYSTORE_OPENSSL)
		rv = KMF_OK;
	return (rv);
}

static KMF_RETURN
list_pk11_objects(KMF_HANDLE_T kmfhandle, char *token, int oclass,
	char *objlabel, KMF_BIGINT *serial, char *issuer, char *subject,
	char *dir, char *filename, KMF_CREDENTIAL *tokencred,
	KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN rv;
	KMF_LISTCRL_PARAMS lcrlargs;

	/*
	 * Symmetric keys and RSA/DSA private keys are always
	 * created with the "CKA_PRIVATE" field == TRUE, so
	 * make sure we search for them with it also set.
	 */
	if (oclass & (PK_SYMKEY_OBJ | PK_PRIKEY_OBJ))
		oclass |= PK_PRIVATE_OBJ;

	rv = select_token(kmfhandle, token,
		!(oclass & (PK_PRIVATE_OBJ | PK_PRIKEY_OBJ)));

	if (rv != KMF_OK) {
		return (rv);
	}

	if (oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ)) {
		KMF_FINDKEY_PARAMS parms;

		(void) memset(&parms, 0, sizeof (parms));
		parms.kstype = KMF_KEYSTORE_PK11TOKEN;

		if (oclass & PK_PRIKEY_OBJ) {
			parms.keyclass = KMF_ASYM_PRI;
			parms.findLabel = objlabel;
			parms.cred = *tokencred;
			parms.pkcs11parms.private =
				((oclass & PK_PRIVATE_OBJ) > 0);

			/* list asymmetric private keys */
			rv = pk_list_keys(kmfhandle, &parms);
		}

		if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
			parms.keyclass = KMF_SYMMETRIC;
			parms.findLabel = objlabel;
			parms.cred = *tokencred;
			parms.format = KMF_FORMAT_RAWKEY;
			parms.pkcs11parms.private =
				((oclass & PK_PRIVATE_OBJ) > 0);

			/* list symmetric keys */
			rv = pk_list_keys(kmfhandle, &parms);
		}

		if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
			parms.keyclass = KMF_ASYM_PUB;
			parms.findLabel = objlabel;
			parms.pkcs11parms.private =
				((oclass & PK_PRIVATE_OBJ) > 0);

			/* list asymmetric public keys (if any) */
			rv = pk_list_keys(kmfhandle, &parms);
		}

		if (rv != KMF_OK)
			return (rv);
	}

	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		KMF_FINDCERT_PARAMS parms;

		(void) memset(&parms, 0, sizeof (parms));
		parms.kstype = KMF_KEYSTORE_PK11TOKEN;
		parms.certLabel = objlabel;
		parms.issuer = issuer;
		parms.subject = subject;
		parms.serial = serial;
		parms.pkcs11parms.private = FALSE;
		parms.find_cert_validity = find_criteria_flag;

		rv = pk_find_certs(kmfhandle, &parms);
		if (rv != KMF_OK)
			return (rv);
	}

	if (oclass & PK_CRL_OBJ) {
		char *crldata;

		(void) memset(&lcrlargs, 0, sizeof (lcrlargs));
		lcrlargs.kstype = KMF_KEYSTORE_OPENSSL;
		lcrlargs.sslparms.dirpath = dir;
		lcrlargs.sslparms.crlfile = filename;

		rv = KMF_ListCRL(kmfhandle, &lcrlargs, &crldata);
		if (rv == KMF_OK) {
			(void) printf("%s\n", crldata);
			free(crldata);
		}
	}

	return (rv);
}

static int
list_file_objects(KMF_HANDLE_T kmfhandle, int oclass,
	char *dir, char *filename, KMF_BIGINT *serial,
	char *issuer, char *subject,
	KMF_CERT_VALIDITY find_criteria_flag)
{
	int rv;
	KMF_FINDCERT_PARAMS fcargs;
	KMF_FINDKEY_PARAMS fkargs;
	KMF_LISTCRL_PARAMS lcrlargs;

	if (oclass & PK_KEY_OBJ) {
		(void) memset(&fkargs, 0, sizeof (fkargs));
		fkargs.kstype = KMF_KEYSTORE_OPENSSL;
		fkargs.sslparms.dirpath = dir;
		fkargs.sslparms.keyfile = filename;
		if (oclass & PK_PRIKEY_OBJ) {
			fkargs.keyclass = KMF_ASYM_PRI;

			rv = pk_list_keys(kmfhandle, &fkargs);
		}
		if (rv == KMF_ERR_KEY_NOT_FOUND)
			rv = KMF_OK;

		if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
			fkargs.keyclass = KMF_SYMMETRIC;
			fkargs.format = KMF_FORMAT_RAWKEY;

			rv = pk_list_keys(kmfhandle, &fkargs);
		}
		if (rv == KMF_ERR_KEY_NOT_FOUND)
			rv = KMF_OK;
		if (rv != KMF_OK)
			return (rv);
	}

	if (oclass & PK_CERT_OBJ) {
		(void) memset(&fcargs, 0, sizeof (fcargs));
		fcargs.kstype = KMF_KEYSTORE_OPENSSL;
		fcargs.certLabel = NULL;
		fcargs.issuer = issuer;
		fcargs.subject = subject;
		fcargs.serial = serial;
		fcargs.sslparms.dirpath = dir;
		fcargs.sslparms.certfile = filename;
		fcargs.find_cert_validity = find_criteria_flag;

		rv = pk_find_certs(kmfhandle, &fcargs);
		if (rv != KMF_OK)
			return (rv);
	}

	if (oclass & PK_CRL_OBJ) {
		char *crldata;

		(void) memset(&lcrlargs, 0, sizeof (lcrlargs));
		lcrlargs.kstype = KMF_KEYSTORE_OPENSSL;
		lcrlargs.sslparms.dirpath = dir;
		lcrlargs.sslparms.crlfile = filename;

		rv = KMF_ListCRL(kmfhandle, &lcrlargs, &crldata);
		if (rv == KMF_OK) {
			(void) printf("%s\n", crldata);
			free(crldata);
		}
	}

	return (rv);
}

static int
list_nss_objects(KMF_HANDLE_T kmfhandle,
	int oclass, char *token_spec, char *dir, char *prefix,
	char *nickname, KMF_BIGINT *serial, char *issuer, char *subject,
	KMF_CREDENTIAL *tokencred,
	KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS fkargs;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	if (oclass & PK_KEY_OBJ) {
		(void) memset(&fkargs, 0, sizeof (fkargs));
		fkargs.kstype = KMF_KEYSTORE_NSS;
		fkargs.findLabel = nickname;
		fkargs.cred = *tokencred;
		fkargs.nssparms.slotlabel = token_spec;
	}

	if (oclass & PK_PRIKEY_OBJ) {
		fkargs.keyclass = KMF_ASYM_PRI;
		rv = pk_list_keys(kmfhandle, &fkargs);
	}
	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		fkargs.keyclass = KMF_SYMMETRIC;
		fkargs.format = KMF_FORMAT_RAWKEY;
		rv = pk_list_keys(kmfhandle, &fkargs);
	}
	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		fkargs.keyclass = KMF_ASYM_PUB;
		rv = pk_list_keys(kmfhandle, &fkargs);
	}

	/* If searching for public objects or certificates, find certs now */
	if (rv == KMF_OK && (oclass & PK_CERT_OBJ)) {
		KMF_FINDCERT_PARAMS fcargs;

		(void) memset(&fcargs, 0, sizeof (fcargs));
		fcargs.kstype = KMF_KEYSTORE_NSS;
		fcargs.certLabel = nickname;
		fcargs.issuer = issuer;
		fcargs.subject = subject;
		fcargs.serial = serial;
		fcargs.nssparms.slotlabel = token_spec;
		fcargs.find_cert_validity = find_criteria_flag;

		rv = pk_find_certs(kmfhandle, &fcargs);
	}

	if (rv == KMF_OK && (oclass & PK_CRL_OBJ)) {
		int numcrls;
		KMF_FINDCRL_PARAMS fcrlargs;

		(void) memset(&fcrlargs, 0, sizeof (fcrlargs));
		fcrlargs.kstype = KMF_KEYSTORE_NSS;
		fcrlargs.nssparms.slotlabel = token_spec;

		rv = KMF_FindCRL(kmfhandle, &fcrlargs, NULL, &numcrls);
		if (rv == KMF_OK) {
			char **p;
			if (numcrls == 0) {
				(void) printf(gettext("No CRLs found in "
					"NSS keystore.\n"));

				return (KMF_OK);
			}
			p = malloc(numcrls * sizeof (char *));
			if (p == NULL) {
				return (KMF_ERR_MEMORY);
			}
			(void) memset(p, 0, numcrls * sizeof (char *));
			rv = KMF_FindCRL(kmfhandle, &fcrlargs,
				p, &numcrls);
			if (rv == KMF_OK) {
				int i;
				for (i = 0; i < numcrls; i++) {
					(void) printf("%d. Name = %s\n",
						i + 1, p[i]);
					free(p[i]);
				}
			}
			free(p);
		}
	}
	return (rv);
}

/*
 * List token object.
 */
int
pk_list(int argc, char *argv[])
{
	int			opt;
	extern int		optind_av;
	extern char		*optarg_av;
	char			*token_spec = NULL;
	char			*subject = NULL;
	char			*issuer = NULL;
	char			*dir = NULL;
	char			*prefix = NULL;
	char			*filename = NULL;
	char			*serstr = NULL;
	KMF_BIGINT		serial = { NULL, 0 };

	char			*list_label = NULL;
	int			oclass = 0;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE_T		kmfhandle = NULL;
	char			*find_criteria = NULL;
	KMF_CERT_VALIDITY	find_criteria_flag = KMF_ALL_CERTS;
	KMF_CREDENTIAL		tokencred = {NULL, 0};

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
		"k:(keystore)t:(objtype)T:(token)d:(dir)"
		"p:(prefix)n:(nickname)S:(serial)s:(subject)"
		"c:(criteria)"
		"i:(issuer)l:(label)f:(infile)")) != EOF) {
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
				if (oclass != 0)
					return (PK_ERR_USAGE);
				oclass = OT2Int(optarg_av);
				if (oclass == -1)
					return (PK_ERR_USAGE);
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
				serstr = optarg_av;
				break;
			case 'f':
				if (filename)
					return (PK_ERR_USAGE);
				filename = optarg_av;
				break;
			case 'T':	/* token specifier */
				if (token_spec)
					return (PK_ERR_USAGE);
				token_spec = optarg_av;
				break;
			case 'n':
			case 'l':	/* object with specific label */
				if (list_label)
					return (PK_ERR_USAGE);
				list_label = optarg_av;
				break;
			case 'c':
				find_criteria = optarg_av;
				if (!strcasecmp(find_criteria, "valid"))
					find_criteria_flag =
					    KMF_NONEXPIRED_CERTS;
				else if (!strcasecmp(find_criteria, "expired"))
					find_criteria_flag = KMF_EXPIRED_CERTS;
				else if (!strcasecmp(find_criteria, "both"))
					find_criteria_flag = KMF_ALL_CERTS;
				else
					return (PK_ERR_USAGE);
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

	if ((rv = KMF_Initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		/* Error message ? */
		return (rv);
	}

	/* Assume keystore = PKCS#11 if not specified. */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	/* if PUBLIC or PRIVATE obj was given, the old syntax was used. */
	if ((oclass & (PK_PUBLIC_OBJ | PK_PRIVATE_OBJ)) &&
		kstype != KMF_KEYSTORE_PK11TOKEN) {

		(void) fprintf(stderr, gettext("The objtype parameter "
			"is only relevant if keystore=pkcs11\n"));
		return (PK_ERR_USAGE);
	}

	/* If no object class specified, list certificate objects. */
	if (oclass == 0)
		oclass = PK_CERT_OBJ;

	if (kstype == KMF_KEYSTORE_PK11TOKEN && EMPTYSTRING(token_spec)) {
		token_spec = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && EMPTYSTRING(token_spec)) {
		token_spec = DEFAULT_NSS_TOKEN;
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
		(oclass & (PK_PRIKEY_OBJ | PK_PRIVATE_OBJ))) {

		(void) get_token_password(kstype, token_spec,
			&tokencred);
	}
	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = list_pk11_objects(kmfhandle, token_spec,
			oclass, list_label, &serial,
			issuer, subject, dir, filename,
			&tokencred, find_criteria_flag);

	} else if (kstype == KMF_KEYSTORE_NSS) {
		if (dir == NULL)
			dir = PK_DEFAULT_DIRECTORY;
		rv = list_nss_objects(kmfhandle,
			oclass, token_spec, dir, prefix,
			list_label, &serial, issuer, subject,
			&tokencred, find_criteria_flag);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {

		rv = list_file_objects(kmfhandle,
			oclass, dir, filename,
			&serial, issuer, subject, find_criteria_flag);
	}

	if (rv != KMF_OK) {
		display_error(kmfhandle, rv,
			gettext("Error listing objects"));
	}

	if (serial.val != NULL)
		free(serial.val);

	if (tokencred.cred != NULL)
		free(tokencred.cred);

	(void) KMF_Finalize(kmfhandle);
	return (rv);
}

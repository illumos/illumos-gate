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
 * This file implements the token object delete operation for this tool.
 * It loads the PKCS#11 modules, finds the object to delete, deletes it,
 * and cleans up.  User must be R/W logged into the token.
 */

#include <stdio.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"
#include <kmfapi.h>

static KMF_RETURN
pk_destroy_keys(void *handle, KMF_KEY_HANDLE *keys,
	KMF_FINDKEY_PARAMS *fkparams, uint32_t numkeys)
{
	int i;
	KMF_RETURN rv = KMF_OK;
	KMF_DELETEKEY_PARAMS dkparams;

	(void) memset(&dkparams, 0, sizeof (dkparams));
	dkparams.kstype = fkparams->kstype;

	switch (fkparams->kstype) {
	case KMF_KEYSTORE_NSS:
		dkparams.nssparms = fkparams->nssparms;
		dkparams.cred = fkparams->cred;
		break;
	case KMF_KEYSTORE_OPENSSL:
		break;
	case KMF_KEYSTORE_PK11TOKEN:
		dkparams.cred = fkparams->cred;
		break;
	default:
		return (PK_ERR_USAGE);
	}

	for (i = 0; rv == KMF_OK && i < numkeys; i++) {
		rv = KMF_DeleteKeyFromKeystore(handle, &dkparams, &keys[i]);
	}
	return (rv);
}

static KMF_RETURN
pk_delete_keys(KMF_HANDLE_T kmfhandle, KMF_FINDKEY_PARAMS *parms, char *desc,
	int *keysdeleted)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numkeys = 0;

	*keysdeleted = 0;
	numkeys = 0;
	rv = KMF_FindKey(kmfhandle, parms, NULL, &numkeys);
	if (rv == KMF_OK && numkeys > 0) {
		KMF_KEY_HANDLE *keys = NULL;
		char prompt[1024];

		(void) snprintf(prompt, sizeof (prompt),
			gettext("%d %s key(s) found, do you want "
			"to delete them (y/N) ?"), numkeys,
			(desc != NULL ? desc : ""));

		if (!yesno(prompt,
			gettext("Respond with yes or no.\n"),
			B_FALSE)) {
			return (KMF_OK);
		}
		keys = (KMF_KEY_HANDLE *)malloc(numkeys *
				sizeof (KMF_KEY_HANDLE));
		if (keys == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(keys, 0, numkeys *
			sizeof (KMF_KEY_HANDLE));

		rv = KMF_FindKey(kmfhandle, parms, keys, &numkeys);
		if (rv == KMF_OK) {
			rv = pk_destroy_keys(kmfhandle, keys,
				parms, numkeys);
		}

		free(keys);
	}

	if (rv == KMF_ERR_KEY_NOT_FOUND) {
		rv = KMF_OK;
	}

	*keysdeleted = numkeys;
	return (rv);
}

static KMF_RETURN
pk_delete_certs(KMF_HANDLE_T kmfhandle, KMF_FINDCERT_PARAMS *fcparms,
	KMF_DELETECERT_PARAMS *dcparms)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numcerts = 0;

	rv = KMF_FindCert(kmfhandle, fcparms, NULL, &numcerts);
	if (rv == KMF_OK && numcerts > 0) {
		char prompt[1024];
		(void) snprintf(prompt, sizeof (prompt),
			gettext("%d certificate(s) found, do you want "
			"to delete them (y/N) ?"), numcerts);

		if (!yesno(prompt,
			gettext("Respond with yes or no.\n"),
			B_FALSE)) {
			return (KMF_OK);
		}

		rv = KMF_DeleteCertFromKeystore(kmfhandle, dcparms);

	} else if (rv == KMF_ERR_CERT_NOT_FOUND) {
		rv = KMF_OK;
	}

	return (rv);
}

static KMF_RETURN
delete_nss_keys(KMF_HANDLE_T kmfhandle, char *dir, char *prefix,
	char *token, int oclass, char *objlabel,
	KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS parms;
	char *keytype = NULL;
	int nk, numkeys = 0;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	(void) memset(&parms, 0, sizeof (parms));
	parms.kstype = KMF_KEYSTORE_NSS;
	parms.findLabel = objlabel;
	parms.cred = *tokencred;
	parms.nssparms.slotlabel = token;

	if (oclass & PK_PRIKEY_OBJ) {
		parms.keyclass = KMF_ASYM_PRI;
		keytype = "private";
		rv = pk_delete_keys(kmfhandle, &parms, keytype, &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		parms.keyclass = KMF_SYMMETRIC;
		keytype = "symmetric";
		rv = pk_delete_keys(kmfhandle, &parms, keytype, &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		parms.keyclass = KMF_ASYM_PUB;
		keytype = "public";
		rv = pk_delete_keys(kmfhandle, &parms, keytype, &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && numkeys == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;

	return (rv);
}


static KMF_RETURN
delete_nss_certs(KMF_HANDLE_T kmfhandle,
	char *dir, char *prefix,
	char *token, char *objlabel,
	KMF_BIGINT *serno, char *issuer, char *subject,
	KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DELETECERT_PARAMS dcparms;
	KMF_FINDCERT_PARAMS fcargs;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	(void) memset(&dcparms, 0, sizeof (dcparms));
	dcparms.kstype = KMF_KEYSTORE_NSS;
	dcparms.certLabel = objlabel;
	dcparms.issuer = issuer;
	dcparms.subject = subject;
	dcparms.serial = serno;
	dcparms.find_cert_validity = find_criteria_flag;
	dcparms.nssparms.slotlabel = token;

	(void) memset(&fcargs, 0, sizeof (fcargs));
	fcargs.kstype = KMF_KEYSTORE_NSS;
	fcargs.certLabel = objlabel;
	fcargs.issuer = issuer;
	fcargs.subject = subject;
	fcargs.serial = serno;
	fcargs.find_cert_validity = find_criteria_flag;
	fcargs.nssparms.slotlabel = token;

	rv = pk_delete_certs(kmfhandle, &fcargs, &dcparms);

	return (rv);
}

static KMF_RETURN
delete_nss_crl(void *kmfhandle,
	char *dir, char *prefix, char *token,
	char *issuernickname, char *subject)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DELETECRL_PARAMS dcrlparms;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	(void) memset(&dcrlparms, 0, sizeof (dcrlparms));

	dcrlparms.kstype = KMF_KEYSTORE_NSS;
	dcrlparms.nssparms.slotlabel = token;
	dcrlparms.nssparms.crl_issuerName = issuernickname;
	dcrlparms.nssparms.crl_subjName = subject;

	rv = KMF_DeleteCRL(kmfhandle, &dcrlparms);

	return (rv);
}

static KMF_RETURN
delete_pk11_keys(KMF_HANDLE_T kmfhandle,
	char *token, int oclass, char *objlabel,
	KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS parms;
	int nk, numkeys = 0;

	/*
	 * Symmetric keys and RSA/DSA private keys are always
	 * created with the "CKA_PRIVATE" field == TRUE, so
	 * make sure we search for them with it also set.
	 */
	if (oclass & (PK_SYMKEY_OBJ | PK_PRIKEY_OBJ))
		oclass |= PK_PRIVATE_OBJ;

	rv = select_token(kmfhandle, token, FALSE);
	if (rv != KMF_OK) {
		return (rv);
	}

	(void) memset(&parms, 0, sizeof (parms));
	parms.kstype = KMF_KEYSTORE_PK11TOKEN;
	parms.findLabel = (char *)objlabel;
	parms.keytype = 0;
	parms.pkcs11parms.private = ((oclass & PK_PRIVATE_OBJ) > 0);
	parms.cred.cred = tokencred->cred;
	parms.cred.credlen = tokencred->credlen;

	if (oclass & PK_PRIKEY_OBJ) {
		parms.keyclass = KMF_ASYM_PRI;
		rv = pk_delete_keys(kmfhandle, &parms, "private", &nk);
		numkeys += nk;
	}

	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		parms.keyclass = KMF_SYMMETRIC;
		rv = pk_delete_keys(kmfhandle, &parms, "symmetric", &nk);
		numkeys += nk;
	}

	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		parms.keyclass = KMF_ASYM_PUB;
		rv = pk_delete_keys(kmfhandle, &parms, "public", &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && numkeys == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;

	return (rv);
}

static KMF_RETURN
delete_pk11_certs(KMF_HANDLE_T kmfhandle,
	char *token, char *objlabel,
	KMF_BIGINT *serno, char *issuer, char *subject,
	KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN kmfrv;
	KMF_DELETECERT_PARAMS dparms;
	KMF_FINDCERT_PARAMS fcargs;

	kmfrv = select_token(kmfhandle, token, FALSE);

	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	(void) memset(&dparms, 0, sizeof (dparms));
	dparms.kstype = KMF_KEYSTORE_PK11TOKEN;
	dparms.certLabel = objlabel;
	dparms.issuer = issuer;
	dparms.subject = subject;
	dparms.serial = serno;
	dparms.find_cert_validity = find_criteria_flag;

	fcargs = dparms;
	kmfrv = pk_delete_certs(kmfhandle, &fcargs, &dparms);

	return (kmfrv);
}

static KMF_RETURN
delete_file_certs(KMF_HANDLE_T kmfhandle,
	char *dir, char *filename, KMF_BIGINT *serial, char *issuer,
	char *subject, KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN rv;
	KMF_DELETECERT_PARAMS dparms;
	KMF_FINDCERT_PARAMS fcargs;

	(void *)memset(&dparms, 0, sizeof (dparms));
	(void *)memset(&fcargs, 0, sizeof (fcargs));
	fcargs.kstype = KMF_KEYSTORE_OPENSSL;
	fcargs.certLabel = NULL;
	fcargs.issuer = issuer;
	fcargs.subject = subject;
	fcargs.serial = serial;
	fcargs.sslparms.dirpath = dir;
	fcargs.sslparms.certfile = filename;
	fcargs.find_cert_validity = find_criteria_flag;

	/* For now, delete parameters and find parameters are the same */
	dparms = fcargs;

	rv = pk_delete_certs(kmfhandle, &fcargs, &dparms);

	return (rv);
}

static KMF_RETURN
delete_file_keys(KMF_HANDLE_T kmfhandle, int oclass,
	char *dir, char *infile)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS parms;
	char *keytype = "";
	int nk, numkeys = 0;

	(void) memset(&parms, 0, sizeof (parms));
	parms.kstype = KMF_KEYSTORE_OPENSSL;
	parms.sslparms.dirpath = dir;
	parms.sslparms.keyfile = infile;

	if (oclass & (PK_PUBKEY_OBJ | PK_PRIKEY_OBJ)) {
		parms.keyclass = KMF_ASYM_PRI;
		keytype = "Asymmetric";
		rv = pk_delete_keys(kmfhandle, &parms, keytype, &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		parms.keyclass = KMF_SYMMETRIC;
		keytype = "symmetric";
		rv = pk_delete_keys(kmfhandle, &parms, keytype, &nk);
		numkeys += nk;
	}
	if (rv == KMF_OK && numkeys == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;

	return (rv);
}

static KMF_RETURN
delete_file_crl(void *kmfhandle, char *dir, char *filename)
{
	KMF_RETURN rv;
	KMF_DELETECRL_PARAMS dcrlparms;

	(void) memset(&dcrlparms, 0, sizeof (dcrlparms));

	dcrlparms.kstype = KMF_KEYSTORE_OPENSSL;
	dcrlparms.sslparms.dirpath = dir;
	dcrlparms.sslparms.crlfile = filename;

	rv = KMF_DeleteCRL(kmfhandle, &dcrlparms);

	return (rv);
}

/*
 * Delete token objects.
 */
int
pk_delete(int argc, char *argv[])
{
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*subject = NULL;
	char		*issuer = NULL;
	char		*dir = NULL;
	char		*prefix = NULL;
	char		*infile = NULL;
	char		*object_label = NULL;
	char		*serstr = NULL;

	int		oclass = 0;
	KMF_BIGINT	serial = { NULL, 0 };
	KMF_HANDLE_T	kmfhandle = NULL;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_RETURN	kmfrv;
	int		rv = 0;
	char			*find_criteria = NULL;
	KMF_CERT_VALIDITY	find_criteria_flag = KMF_ALL_CERTS;
	KMF_CREDENTIAL	tokencred = {NULL, 0};

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
		"T:(token)y:(objtype)l:(label)"
		"k:(keystore)s:(subject)n:(nickname)"
		"d:(dir)p:(prefix)S:(serial)i:(issuer)"
		"c:(criteria)"
		"f:(infile)")) != EOF) {

		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
		case 'T':	/* token specifier */
			if (token_spec)
				return (PK_ERR_USAGE);
			token_spec = optarg_av;
			break;
		case 'y':	/* object type:  public, private, both */
			if (oclass)
				return (PK_ERR_USAGE);
			oclass = OT2Int(optarg_av);
			if (oclass == -1)
				return (PK_ERR_USAGE);
			break;
		case 'l':	/* objects with specific label */
		case 'n':
			if (object_label)
				return (PK_ERR_USAGE);
			object_label = (char *)optarg_av;
			break;
		case 'k':
			kstype = KS2Int(optarg_av);
			if (kstype == 0)
				return (PK_ERR_USAGE);
			break;
		case 's':
			subject = optarg_av;
			break;
		case 'i':
			issuer = optarg_av;
			break;
		case 'd':
			dir = optarg_av;
			break;
		case 'p':
			prefix = optarg_av;
			break;
		case 'S':
			serstr = optarg_av;
			break;
		case 'f':
			infile = optarg_av;
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
			break;
		}
	}

	/* Assume keystore = PKCS#11 if not specified */
	if (kstype == 0)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	/* if PUBLIC or PRIVATE obj was given, the old syntax was used. */
	if ((oclass & (PK_PUBLIC_OBJ | PK_PRIVATE_OBJ)) &&
		kstype != KMF_KEYSTORE_PK11TOKEN) {

		(void) fprintf(stderr, gettext("The objtype parameter "
			"is only relevant if keystore=pkcs11\n"));
		return (PK_ERR_USAGE);
	}

	/* If no object class specified, delete everything but CRLs */
	if (oclass == 0)
		oclass = PK_CERT_OBJ | PK_PUBKEY_OBJ | PK_PRIKEY_OBJ |
			PK_SYMKEY_OBJ;

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	if (kstype == KMF_KEYSTORE_PK11TOKEN && token_spec == NULL) {
		token_spec = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && token_spec == NULL) {
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
		(oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ))) {

		(void) get_token_password(kstype, token_spec,
			&tokencred);
	}

	if ((kmfrv = KMF_Initialize(&kmfhandle, NULL, NULL)) != KMF_OK)
		return (kmfrv);

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (oclass & PK_KEY_OBJ) {
				kmfrv = delete_pk11_keys(kmfhandle,
						token_spec, oclass,
						object_label,
						&tokencred);
				/*
				 * If deleting groups of objects, it is OK
				 * to ignore the "key not found" case so that
				 * we can continue to find other objects.
				 */
				if (kmfrv == KMF_ERR_KEY_NOT_FOUND &&
					(oclass != PK_KEY_OBJ))
					kmfrv = KMF_OK;
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
				kmfrv = delete_pk11_certs(kmfhandle,
						token_spec,
						object_label,
						&serial, issuer,
						subject, find_criteria_flag);
				/*
				 * If cert delete failed, but we are looking at
				 * other objects, then it is OK.
				 */
				if (kmfrv == KMF_ERR_CERT_NOT_FOUND &&
					(oclass & (PK_CRL_OBJ | PK_KEY_OBJ)))
					kmfrv = KMF_OK;
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				kmfrv = delete_file_crl(kmfhandle,
						dir, infile);
			break;
		case KMF_KEYSTORE_NSS:
			if (oclass & PK_KEY_OBJ) {
				kmfrv = delete_nss_keys(kmfhandle,
					dir, prefix, token_spec,
					oclass, (char  *)object_label,
					&tokencred);
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & PK_CERT_OBJ) {
				kmfrv = delete_nss_certs(kmfhandle,
					dir, prefix, token_spec,
					(char  *)object_label,
					&serial, issuer, subject,
					find_criteria_flag);
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				kmfrv = delete_nss_crl(kmfhandle,
					dir, prefix, token_spec,
					(char  *)object_label, subject);
			break;
		case KMF_KEYSTORE_OPENSSL:
			if (oclass & PK_KEY_OBJ) {
				kmfrv = delete_file_keys(kmfhandle, oclass,
					dir, infile);
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & (PK_CERT_OBJ)) {
				kmfrv = delete_file_certs(kmfhandle,
					dir, infile, &serial, issuer,
					subject, find_criteria_flag);
				if (kmfrv != KMF_OK)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				kmfrv = delete_file_crl(kmfhandle,
					dir, infile);
			break;
		default:
			rv = PK_ERR_USAGE;
			break;
	}

	if (kmfrv != KMF_OK) {
		display_error(kmfhandle, kmfrv,
			gettext("Error deleting objects"));
	}

	if (serial.val != NULL)
		free(serial.val);
	(void) KMF_Finalize(kmfhandle);
	return (kmfrv);
}

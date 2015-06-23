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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

KMF_RETURN
genkeypair_pkcs11(KMF_HANDLE_T kmfhandle,
	char *token, char *keylabel, KMF_KEY_ALG keyAlg,
	int keylen, KMF_CREDENTIAL *tokencred, KMF_OID *curveoid,
	KMF_KEY_HANDLE *outPriKey, KMF_KEY_HANDLE *outPubKey)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE pubk, prik;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;
	KMF_KEY_ALG keytype;
	uint32_t keylength;

	keylength = keylen; /* bits */
	keytype = keyAlg;

	/* Select a PKCS11 token */
	kmfrv = select_token(kmfhandle, token, FALSE);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYALG_ATTR, &keytype,
	    sizeof (keytype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYLENGTH_ATTR, &keylength,
	    sizeof (keylength));
	numattr++;

	if (keylabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYLABEL_ATTR, keylabel,
		    strlen(keylabel));
		numattr++;
	}

	if (tokencred != NULL && tokencred->cred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CREDENTIAL_ATTR, tokencred,
		    sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PRIVKEY_HANDLE_ATTR, &prik,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PUBKEY_HANDLE_ATTR, &pubk,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	if (keytype == KMF_ECDSA && curveoid != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ECC_CURVE_OID_ATTR, curveoid,
		    sizeof (KMF_OID));
		numattr++;
	}

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

cleanup:
	if (kmfrv == KMF_OK) {
		if (outPriKey != NULL)
			*outPriKey = prik;
		if (outPubKey != NULL)
			*outPubKey = pubk;
	}

	return (kmfrv);
}

KMF_RETURN
genkeypair_file(KMF_HANDLE_T kmfhandle,
	KMF_KEY_ALG keyAlg, int keylen, KMF_ENCODE_FORMAT fmt,
	char *outkey,
	KMF_KEY_HANDLE *outPriKey, KMF_KEY_HANDLE *outPubKey)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	char *fullkeypath = NULL;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_ATTRIBUTE attrlist[10];
	int numattr = 0;
	KMF_KEY_ALG keytype;
	uint32_t keylength;
	KMF_ENCODE_FORMAT format;

	if (EMPTYSTRING(outkey)) {
		cryptoerror(LOG_STDERR,
		    gettext("No output file was specified for "
		    "the key\n"));
		return (PK_ERR_USAGE);
	}

	fullkeypath = strdup(outkey);
	if (verify_file(fullkeypath)) {
		cryptoerror(LOG_STDERR,
		    gettext("Cannot write the indicated output "
		    "key file (%s).\n"), fullkeypath);
		free(fullkeypath);
		return (PK_ERR_USAGE);
	}

	keylength = keylen; /* bits */
	keytype = keyAlg;
	format = fmt;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYALG_ATTR, &keytype,
	    sizeof (keytype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYLENGTH_ATTR, &keylength,
	    sizeof (keylength));
	numattr++;

	if (fullkeypath != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEY_FILENAME_ATTR, fullkeypath,
		    strlen(fullkeypath));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_ENCODE_FORMAT_ATTR, &format,
	    sizeof (format));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PRIVKEY_HANDLE_ATTR, &prik,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PUBKEY_HANDLE_ATTR, &pubk,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		goto cleanup;
	}

cleanup:
	if (fullkeypath != NULL)
		free(fullkeypath);

	if (kmfrv == KMF_OK) {
		if (outPriKey != NULL)
			*outPriKey = prik;
		if (outPubKey != NULL)
			*outPubKey = pubk;
	}

	return (kmfrv);
}

KMF_RETURN
genkeypair_nss(KMF_HANDLE_T kmfhandle,
	char *token,
	char *nickname, char *dir, char *prefix,
	KMF_KEY_ALG keyAlg,
	int keylen, KMF_CREDENTIAL *tokencred,
	KMF_OID *curveoid,
	KMF_KEY_HANDLE *outPriKey, KMF_KEY_HANDLE *outPubKey)
{
	KMF_RETURN kmfrv;
	KMF_KEY_HANDLE pubk, prik;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;
	KMF_KEY_ALG keytype;
	uint32_t keylength;

	if (token == NULL)
		token = DEFAULT_NSS_TOKEN;

	kmfrv = configure_nss(kmfhandle, dir, prefix);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	keylength = keylen; /* bits */
	keytype = keyAlg;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYALG_ATTR, &keytype,
	    sizeof (keytype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYLENGTH_ATTR, &keylength,
	    sizeof (keylength));
	numattr++;

	if (nickname != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYLABEL_ATTR, nickname,
		    strlen(nickname));
		numattr++;
	}

	if (tokencred != NULL && tokencred->cred != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CREDENTIAL_ATTR, tokencred,
		    sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	if (token != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_TOKEN_LABEL_ATTR, token,
		    strlen(token));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PRIVKEY_HANDLE_ATTR, &prik,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_PUBKEY_HANDLE_ATTR, &pubk,
	    sizeof (KMF_KEY_HANDLE));
	numattr++;

	if (keytype == KMF_ECDSA && curveoid != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ECC_CURVE_OID_ATTR, curveoid,
		    sizeof (KMF_OID));
		numattr++;
	}

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}
cleanup:
	if (kmfrv == KMF_OK) {
		if (outPriKey != NULL)
			*outPriKey = prik;
		if (outPubKey != NULL)
			*outPubKey = pubk;
	}
	return (kmfrv);
}

int
pk_genkeypair(int argc, char *argv[])
{
	int rv;
	int opt;
	extern int	optind_av;
	extern char	*optarg_av;
	KMF_KEYSTORE_TYPE kstype = 0;
	char *tokenname = NULL;
	char *dir = NULL;
	char *prefix = NULL;
	char *keytype = PK_DEFAULT_KEYTYPE;
	int keylen = PK_DEFAULT_KEYLENGTH;
	char *label = NULL;
	char *outkey = NULL;
	char *format = NULL;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_ENCODE_FORMAT fmt = KMF_FORMAT_ASN1;
	KMF_KEY_ALG keyAlg = KMF_RSA;
	KMF_ALGORITHM_INDEX sigAlg;
	KMF_CREDENTIAL tokencred = { NULL, 0 };
	KMF_OID *curveoid = NULL; /* ECC */
	int y_flag = 0;

	while ((opt = getopt_av(argc, argv,
	    "k:(keystore)s:(subject)n:(nickname)"
	    "T:(token)d:(dir)p:(prefix)t:(keytype)y:(keylen)"
	    "l:(label)K:(outkey)F:(format)C:(curve)"
	    "E(listcurves)")) != EOF) {

		if (opt != 'i' && opt != 'E' && EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);

		switch (opt) {
			case 'k':
				kstype = KS2Int(optarg_av);
				if (kstype == 0)
					return (PK_ERR_USAGE);
				break;
			case 'l':
			case 'n':
				if (label)
					return (PK_ERR_USAGE);
				label = optarg_av;
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
			case 'C':
				curveoid = ecc_name_to_oid(optarg_av);
				if (curveoid == NULL) {
					cryptoerror(LOG_STDERR,
					    gettext(
					    "Unrecognized ECC curve.\n"));
					return (PK_ERR_USAGE);
				}
				break;
			case 'E':
				show_ecc_curves();
				return (0);
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

	DIR_OPTION_CHECK(kstype, dir);

	if (format && (fmt = Str2Format(format)) == KMF_FORMAT_UNDEF) {
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing format string (%s).\n"),
		    format);
		return (PK_ERR_USAGE);
	}

	if (Str2KeyType(keytype, NULL, &keyAlg, &sigAlg) != 0) {
		cryptoerror(LOG_STDERR, gettext("Unrecognized keytype (%s).\n"),
		    keytype);
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
	if (keyAlg == KMF_ECDSA && kstype == KMF_KEYSTORE_OPENSSL) {
		(void) fprintf(stderr, gettext("ECC certificates are"
		    "only supported with the pkcs11 and nss keystores\n"));
		rv = PK_ERR_USAGE;
		goto end;
	}
	/* Adjust default keylength for NSS and DSA */
	if (keyAlg == KMF_DSA && kstype == KMF_KEYSTORE_NSS) {
		/* NSS only allows for 512-1024 bit DSA keys */
		if (!y_flag)
			/* If nothing was given, default to 1024 */
			keylen = 1024;
		else if (keylen > 1024 || keylen < 512) {
			(void) fprintf(stderr, gettext("NSS keystore only "
			    "supports DSA keylengths of 512 - 1024 bits\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
	}

	if (kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_PK11TOKEN) {
		if (label == NULL) {
			(void) fprintf(stderr,
			    gettext("No key label specified\n"));
			rv = PK_ERR_USAGE;
			goto end;
		}
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

		rv = genkeypair_nss(kmfhandle,
		    tokenname, label, dir, prefix, keyAlg, keylen,
		    &tokencred, curveoid, NULL, NULL);

	} else if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = genkeypair_pkcs11(kmfhandle,
		    tokenname, label, keyAlg, keylen,
		    &tokencred, curveoid, NULL, NULL);

	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = genkeypair_file(kmfhandle, keyAlg, keylen,
		    fmt, outkey, NULL, NULL);
	}

	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
		    gettext("Error creating and keypair"));
end:
	if (tokencred.cred != NULL)
		free(tokencred.cred);

	(void) kmf_finalize(kmfhandle);
	return (rv);
}

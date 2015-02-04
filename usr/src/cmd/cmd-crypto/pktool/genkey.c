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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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


static KMF_RETURN
genkey_nss(KMF_HANDLE_T kmfhandle, char *token, char *dir, char *prefix,
    char *keylabel, KMF_KEY_ALG keyAlg, int keylen, KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE key;
	KMF_ATTRIBUTE attlist[20];
	int i = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_KEY_ALG keytype;
	uint32_t keylength;

	if (keylabel == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("A key label must be specified \n"));
		return (KMF_ERR_BAD_PARAMETER);
	}

	kmfrv = configure_nss(kmfhandle, dir, prefix);
	if (kmfrv != KMF_OK)
		return (kmfrv);

	(void) memset(&key, 0, sizeof (KMF_KEY_HANDLE));

	keytype = keyAlg;
	keylength = keylen;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEY_HANDLE_ATTR, &key, sizeof (KMF_KEY_HANDLE));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYALG_ATTR, &keytype, sizeof (keytype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYLENGTH_ATTR, &keylength, sizeof (keylength));
	i++;

	if (keylabel != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEYLABEL_ATTR, keylabel,
		    strlen(keylabel));
		i++;
	}

	if (tokencred != NULL && tokencred->cred != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_CREDENTIAL_ATTR, tokencred,
		    sizeof (KMF_CREDENTIAL));
		i++;
	}

	if (token != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_TOKEN_LABEL_ATTR, token,
		    strlen(token));
		i++;
	}

	kmfrv = kmf_create_sym_key(kmfhandle, i, attlist);

	return (kmfrv);
}

static KMF_RETURN
genkey_pkcs11(KMF_HANDLE_T kmfhandle, char *token,
	char *keylabel, KMF_KEY_ALG keyAlg, int keylen,
	char *senstr, char *extstr, boolean_t print_hex,
	KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE key;
	KMF_RAW_SYM_KEY  *rkey = NULL;
	boolean_t 	sensitive = B_FALSE;
	boolean_t	not_extractable = B_FALSE;
	char *hexstr = NULL;
	int  hexstrlen;
	KMF_ATTRIBUTE attlist[20];
	int i = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_KEY_ALG keytype;
	uint32_t keylength;

	if (keylabel == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("A key label must be specified \n"));
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* Check the sensitive option value if specified. */
	if (senstr != NULL) {
		if (tolower(senstr[0]) == 'y')
			sensitive = B_TRUE;
		else if (tolower(senstr[0]) == 'n')
			sensitive = B_FALSE;
		else {
			cryptoerror(LOG_STDERR,
			    gettext("Incorrect sensitive option value.\n"));
			return (KMF_ERR_BAD_PARAMETER);
		}
	}

	/* Check the extractable option value if specified. */
	if (extstr != NULL) {
		if (tolower(extstr[0]) == 'y')
			not_extractable = B_FALSE;
		else if (tolower(extstr[0]) == 'n')
			not_extractable = B_TRUE;
		else {
			cryptoerror(LOG_STDERR,
			    gettext("Incorrect extractable option value.\n"));
			return (KMF_ERR_BAD_PARAMETER);
		}
	}

	/* Select a PKCS11 token first */
	kmfrv = select_token(kmfhandle, token, FALSE);
	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	(void) memset(&key, 0, sizeof (KMF_KEY_HANDLE));

	keytype = keyAlg;
	keylength = keylen; /* bits */

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEY_HANDLE_ATTR, &key, sizeof (KMF_KEY_HANDLE));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYALG_ATTR, &keytype, sizeof (keytype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYLENGTH_ATTR, &keylength, sizeof (keylength));
	i++;

	if (keylabel != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEYLABEL_ATTR, keylabel,
		    strlen(keylabel));
		i++;
	}

	if (tokencred != NULL && tokencred->cred != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_CREDENTIAL_ATTR, tokencred,
		    sizeof (KMF_CREDENTIAL));
		i++;
	}

	kmf_set_attr_at_index(attlist, i,
	    KMF_SENSITIVE_BOOL_ATTR, &sensitive,
	    sizeof (sensitive));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_NON_EXTRACTABLE_BOOL_ATTR, &not_extractable,
	    sizeof (not_extractable));
	i++;

	kmfrv = kmf_create_sym_key(kmfhandle, i, attlist);
	if (kmfrv != KMF_OK) {
		goto out;
	}

	if (print_hex) {
		if (sensitive == B_TRUE || not_extractable == B_TRUE) {
			cryptoerror(LOG_STDERR,
			    gettext("Warning: can not reveal the key value "
			    "for a sensitive or non-extractable key.\n"));
			goto out;
		} else {
			rkey = malloc(sizeof (KMF_RAW_SYM_KEY));
			if (rkey == NULL) {
				kmfrv = KMF_ERR_MEMORY;
				goto out;
			}
			(void) memset(rkey, 0, sizeof (KMF_RAW_SYM_KEY));
			kmfrv = kmf_get_sym_key_value(kmfhandle, &key, rkey);
			if (kmfrv != KMF_OK) {
				goto out;
			}
			hexstrlen = 2 * rkey->keydata.len + 1;
			hexstr = malloc(hexstrlen);
			if (hexstr == NULL) {
				kmfrv = KMF_ERR_MEMORY;
				goto out;
			}

			tohexstr(rkey->keydata.val, rkey->keydata.len, hexstr,
			    hexstrlen);
			(void) printf(gettext("\tKey Value =\"%s\"\n"), hexstr);
		}
	}

out:
	kmf_free_raw_sym_key(rkey);

	if (hexstr != NULL)
		free(hexstr);

	return (kmfrv);
}


static KMF_RETURN
genkey_file(KMF_HANDLE_T kmfhandle, KMF_KEY_ALG keyAlg, int keylen, char *dir,
    char *outkey, boolean_t print_hex)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_KEY_HANDLE key;
	KMF_RAW_SYM_KEY *rkey = NULL;
	char *hexstr = NULL;
	int hexstrlen;
	KMF_ATTRIBUTE attlist[20];
	int i = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_KEY_ALG keytype;
	uint32_t keylength;
	char *dirpath;

	if (EMPTYSTRING(outkey)) {
		cryptoerror(LOG_STDERR,
		    gettext("No output key file was specified for the key\n"));
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (verify_file(outkey)) {
		cryptoerror(LOG_STDERR,
		    gettext("Cannot write the indicated output "
		    "key file (%s).\n"), outkey);
		return (KMF_ERR_BAD_PARAMETER);
	}

	(void) memset(&key, 0, sizeof (KMF_KEY_HANDLE));

	keytype = keyAlg;
	keylength = keylen;

	dirpath = dir;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEY_HANDLE_ATTR, &key, sizeof (KMF_KEY_HANDLE));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYALG_ATTR, &keytype, sizeof (keytype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYLENGTH_ATTR, &keylength, sizeof (keylength));
	i++;

	if (dirpath != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_DIRPATH_ATTR, dirpath,
		    strlen(dirpath));
		i++;
	}

	if (outkey != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEY_FILENAME_ATTR, outkey,
		    strlen(outkey));
		i++;
	}

	kmfrv = kmf_create_sym_key(kmfhandle, i, attlist);
	if (kmfrv != KMF_OK) {
		goto out;
	}

	if (print_hex) {
		rkey = malloc(sizeof (KMF_RAW_SYM_KEY));
		if (rkey == NULL) {
			kmfrv = KMF_ERR_MEMORY;
			goto out;
		}
		(void) memset(rkey, 0, sizeof (KMF_RAW_SYM_KEY));
		kmfrv = kmf_get_sym_key_value(kmfhandle, &key, rkey);
		if (kmfrv != KMF_OK) {
			goto out;
		}

		hexstrlen = 2 * rkey->keydata.len + 1;
		hexstr = malloc(hexstrlen);
		if (hexstr == NULL) {
			kmfrv = KMF_ERR_MEMORY;
			goto out;
		}
		tohexstr(rkey->keydata.val, rkey->keydata.len, hexstr,
		    hexstrlen);
		(void) printf(gettext("\tKey Value =\"%s\"\n"), hexstr);
	}

out:
	kmf_free_raw_sym_key(rkey);

	if (hexstr != NULL)
		free(hexstr);

	return (kmfrv);
}

int
pk_genkey(int argc, char *argv[])
{
	int rv;
	int opt;
	extern int	optind_av;
	extern char	*optarg_av;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	char *tokenname = NULL;
	char *dir = NULL;
	char *prefix = NULL;
	char *keytype = "generic";
	char *keylenstr = NULL;
	int keylen = 0;
	char *keylabel = NULL;
	char *outkey = NULL;
	char *senstr = NULL;
	char *extstr = NULL;
	char *printstr = NULL;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_KEY_ALG keyAlg = KMF_GENERIC_SECRET;
	boolean_t print_hex = B_FALSE;
	KMF_CREDENTIAL tokencred = { NULL, 0 };

	while ((opt = getopt_av(argc, argv,
	    "k:(keystore)l:(label)T:(token)d:(dir)p:(prefix)"
	    "t:(keytype)y:(keylen)K:(outkey)P:(print)"
	    "s:(sensitive)e:(extractable)")) != EOF) {
		if (EMPTYSTRING(optarg_av))
			return (PK_ERR_USAGE);
		switch (opt) {
			case 'k':
				kstype = KS2Int(optarg_av);
				if (kstype == 0)
					return (PK_ERR_USAGE);
				break;
			case 'l':
				if (keylabel)
					return (PK_ERR_USAGE);
				keylabel = optarg_av;
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
				if (keylenstr)
					return (PK_ERR_USAGE);
				keylenstr = optarg_av;
				break;
			case 'K':
				if (outkey)
					return (PK_ERR_USAGE);
				outkey = optarg_av;
				break;
			case 'P':
				if (printstr)
					return (PK_ERR_USAGE);
				printstr = optarg_av;
				break;
			case 's':
				if (senstr)
					return (PK_ERR_USAGE);
				senstr = optarg_av;
				break;
			case 'e':
				if (extstr)
					return (PK_ERR_USAGE);
				extstr = optarg_av;
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

	/* Check keytype. If not specified, default to AES */
	if (keytype != NULL && Str2SymKeyType(keytype, &keyAlg) != 0) {
		cryptoerror(LOG_STDERR, gettext("Unrecognized keytype(%s).\n"),
		    keytype);
		return (PK_ERR_USAGE);
	}

	/*
	 * Check and set the key length.
	 * - For DES and 3DES, the key size are fixed. Ingore the keylen
	 *   option, even if it is specified.
	 * - For AES and ARCFOUR, if keylen is not specified, default to
	 *   128 bits.
	 */
	if (keyAlg == KMF_DES)
		keylen = 64;  /* fixed size; ignore input */
	else if (keyAlg == KMF_DES3)
		keylen = 192; /* fixed size; ignore input */
	else /* AES, ARCFOUR, or GENERIC SECRET */ {
		if (keylenstr == NULL) {
			cryptoerror(LOG_STDERR,
			    gettext("Key length must be specified for "
			    "AES, ARCFOUR or GENERIC symmetric keys.\n"));
			return (PK_ERR_USAGE);
		}
		if (sscanf(keylenstr, "%d", &keylen) != 1) {
			cryptoerror(LOG_STDERR,
			    gettext("Unrecognized key length (%s).\n"),
			    keytype);
			return (PK_ERR_USAGE);
		}
		if (keylen == 0 || (keylen % 8) != 0) {
			cryptoerror(LOG_STDERR,
			    gettext("Key length bitlength must be a "
			    "multiple of 8.\n"));
			return (PK_ERR_USAGE);
		}
	}

	/* check the print option */
	if (printstr != NULL) {
		if (kstype == KMF_KEYSTORE_NSS) {
			cryptoerror(LOG_STDERR,
			    gettext("The print option does not apply "
			    "to the NSS keystore.\n"));
			return (PK_ERR_USAGE);
		}

		if (tolower(printstr[0]) == 'y')
			print_hex = B_TRUE;
		else if (tolower(printstr[0]) == 'n')
			print_hex = B_FALSE;
		else {
			cryptoerror(LOG_STDERR,
			    gettext("Incorrect print option value.\n"));
			return (PK_ERR_USAGE);
		}
	}

	/* check the sensitive and extractable options */
	if ((senstr != NULL || extstr != NULL) &&
	    (kstype == KMF_KEYSTORE_NSS || kstype == KMF_KEYSTORE_OPENSSL)) {
		cryptoerror(LOG_STDERR,
		    gettext("The sensitive or extractable option applies "
		    "to the PKCS11 keystore only.\n"));
		return (PK_ERR_USAGE);
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN && tokenname == NULL) {
		tokenname = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && tokenname == NULL) {
		tokenname = DEFAULT_NSS_TOKEN;
	}
	DIR_OPTION_CHECK(kstype, dir);

	if (kstype == KMF_KEYSTORE_PK11TOKEN || kstype == KMF_KEYSTORE_NSS)
		(void) get_token_password(kstype, tokenname, &tokencred);

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing KMF\n"));
		goto end;
	}

	if (kstype == KMF_KEYSTORE_NSS) {
		rv = genkey_nss(kmfhandle, tokenname, dir, prefix,
		    keylabel, keyAlg, keylen, &tokencred);
	} else if (kstype == KMF_KEYSTORE_OPENSSL) {
		rv = genkey_file(kmfhandle, keyAlg, keylen, dir, outkey,
		    print_hex);
	} else {
		rv = genkey_pkcs11(kmfhandle, tokenname, keylabel, keyAlg,
		    keylen, senstr, extstr, print_hex, &tokencred);
	}

end:
	if (rv != KMF_OK)
		display_error(kmfhandle, rv,
		    gettext("Error generating key"));

	if (tokencred.cred != NULL)
		free(tokencred.cred);

	(void) kmf_finalize(kmfhandle);
	if (rv != KMF_OK)
		return (PK_ERR_USAGE);

	return (0);
}

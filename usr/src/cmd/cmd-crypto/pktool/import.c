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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

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

#define	NEW_ATTRLIST(a, n) \
{ \
	a = (KMF_ATTRIBUTE *)malloc(n * sizeof (KMF_ATTRIBUTE)); \
	if (a == NULL) { \
		rv = KMF_ERR_MEMORY; \
		goto end; \
	} \
	(void) memset(a, 0, n * sizeof (KMF_ATTRIBUTE));  \
}

static KMF_RETURN
pk_import_pk12_files(KMF_HANDLE_T kmfhandle, KMF_CREDENTIAL *cred,
	char *outfile, char *certfile, char *keyfile,
	KMF_ENCODE_FORMAT outformat)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_ATTRIBUTE *attrlist = NULL;
	int numattr = 0;

	rv = kmf_import_objects(kmfhandle, outfile, cred,
	    &certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK) {
		(void) printf(gettext("Found %d certificate(s) and %d "
		    "key(s) in %s\n"), ncerts, nkeys, outfile);
	}

	if (rv == KMF_OK && ncerts > 0) {
		char newcertfile[MAXPATHLEN];

		NEW_ATTRLIST(attrlist,  (3 + (3 * ncerts)));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ENCODE_FORMAT_ATTR, &outformat, sizeof (outformat));
		numattr++;

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			int num = numattr;

			/*
			 * If storing more than 1 cert, gotta change
			 * the name so we don't overwrite the previous one.
			 * Just append a _# to the name.
			 */
			if (i > 0) {
				(void) snprintf(newcertfile,
				    sizeof (newcertfile), "%s_%d", certfile, i);

				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_FILENAME_ATTR, newcertfile,
				    strlen(newcertfile));
				num++;
			} else {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_FILENAME_ATTR, certfile,
				    strlen(certfile));
				num++;
			}

			if (certs[i].kmf_private.label != NULL) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_LABEL_ATTR,
				    certs[i].kmf_private.label,
				    strlen(certs[i].kmf_private.label));
				num++;
			}
			kmf_set_attr_at_index(attrlist, num,
			    KMF_CERT_DATA_ATTR, &certs[i].certificate,
			    sizeof (KMF_DATA));
			num++;
			rv = kmf_store_cert(kmfhandle, num, attrlist);
		}
		free(attrlist);
	}
	if (rv == KMF_OK && nkeys > 0) {
		char newkeyfile[MAXPATHLEN];
		numattr = 0;
		NEW_ATTRLIST(attrlist, (4 + (4 * nkeys)));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_ENCODE_FORMAT_ATTR, &outformat,
		    sizeof (outformat));
		numattr++;

		if (cred != NULL && cred->credlen > 0) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, cred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		/* The order of certificates and keys should match */
		for (i = 0; rv == KMF_OK && i < nkeys; i++) {
			int num = numattr;

			if (i > 0) {
				(void) snprintf(newkeyfile,
				    sizeof (newkeyfile), "%s_%d", keyfile, i);

				kmf_set_attr_at_index(attrlist, num,
				    KMF_KEY_FILENAME_ATTR, newkeyfile,
				    strlen(newkeyfile));
				num++;
			} else {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_KEY_FILENAME_ATTR, keyfile,
				    strlen(keyfile));
				num++;
			}

			if (i < ncerts) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_DATA_ATTR, &certs[i],
				    sizeof (KMF_CERT_DATA_ATTR));
				num++;
			}

			kmf_set_attr_at_index(attrlist, num,
			    KMF_RAW_KEY_ATTR, &keys[i],
			    sizeof (KMF_RAW_KEY_DATA));
			num++;

			rv = kmf_store_key(kmfhandle, num, attrlist);
		}
		free(attrlist);
	}
end:
	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			kmf_free_kmf_cert(kmfhandle, &certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			kmf_free_raw_key(&keys[i]);
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
	KMF_X509_DER_CERT *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_ATTRIBUTE *attrlist = NULL;
	int numattr = 0;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	rv = kmf_import_objects(kmfhandle, filename, kmfcred,
	    &certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK)
		(void) printf(gettext("Found %d certificate(s) and %d "
		    "key(s) in %s\n"), ncerts, nkeys, filename);

	if (rv == KMF_OK) {
		numattr = 0;
		NEW_ATTRLIST(attrlist, (4 + (2 * nkeys)));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		if (token_spec != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_TOKEN_LABEL_ATTR, token_spec,
			    strlen(token_spec));
			numattr++;
		}

		if (nickname != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYLABEL_ATTR, nickname,
			    strlen(nickname));
			numattr++;
		}

		if (tokencred->credlen > 0) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, tokencred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		/* The order of certificates and keys should match */
		for (i = 0; i < nkeys; i++) {
			int num = numattr;

			if (i < ncerts) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_DATA_ATTR, &certs[i],
				    sizeof (KMF_DATA));
				num++;
			}

			kmf_set_attr_at_index(attrlist, num,
			    KMF_RAW_KEY_ATTR, &keys[i],
			    sizeof (KMF_RAW_KEY_DATA));
			num++;

			rv = kmf_store_key(kmfhandle, num, attrlist);
		}
		free(attrlist);
		attrlist = NULL;
	}

	if (rv == KMF_OK) {
		numattr = 0;
		NEW_ATTRLIST(attrlist, (3 + (2 * ncerts)));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		if (token_spec != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_TOKEN_LABEL_ATTR, token_spec,
			    strlen(token_spec));
			numattr++;
		}

		if (trustflags != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_TRUSTFLAG_ATTR, trustflags,
			    strlen(trustflags));
			numattr++;
		}

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			int num = numattr;

			if (certs[i].kmf_private.label != NULL) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_LABEL_ATTR,
				    certs[i].kmf_private.label,
				    strlen(certs[i].kmf_private.label));
				num++;
			} else if (i == 0 && nickname != NULL) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_LABEL_ATTR, nickname,
				    strlen(nickname));
				num++;
			}

			kmf_set_attr_at_index(attrlist, num,
			    KMF_CERT_DATA_ATTR,
			    &certs[i].certificate, sizeof (KMF_DATA));
			num++;
			rv = kmf_store_cert(kmfhandle, num, attrlist);
		}
		free(attrlist);
		attrlist = NULL;
		if (rv != KMF_OK) {
			display_error(kmfhandle, rv,
			    gettext("Error storing certificate in NSS token"));
		}
	}

end:
	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			kmf_free_kmf_cert(kmfhandle, &certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			kmf_free_raw_key(&keys[i]);
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
	KMF_ATTRIBUTE attrlist[32];
	KMF_CREDENTIAL tokencred;
	int i = 0;

	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = select_token(kmfhandle, token_spec, FALSE);
	} else if (kstype == KMF_KEYSTORE_NSS) {
		rv = configure_nss(kmfhandle, dir, prefix);
	}
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (KMF_KEYSTORE_TYPE));
	i++;

	kmf_set_attr_at_index(attrlist, i, KMF_CERT_FILENAME_ATTR,
	    filename, strlen(filename));
	i++;

	if (label != NULL) {
		kmf_set_attr_at_index(attrlist, i, KMF_CERT_LABEL_ATTR,
		    label, strlen(label));
		i++;
	}

	if (kstype == KMF_KEYSTORE_NSS) {
		if (trustflags != NULL) {
			kmf_set_attr_at_index(attrlist, i, KMF_TRUSTFLAG_ATTR,
			    trustflags, strlen(trustflags));
			i++;
		}

		if (token_spec != NULL) {
			kmf_set_attr_at_index(attrlist, i,
			    KMF_TOKEN_LABEL_ATTR,
			    token_spec, strlen(token_spec));
			i++;
		}
	}

	rv = kmf_import_cert(kmfhandle, i, attrlist);
	if (rv == KMF_ERR_AUTH_FAILED) {
		/*
		 * The token requires a credential, prompt and try again.
		 */
		(void) get_token_password(kstype, token_spec, &tokencred);
		kmf_set_attr_at_index(attrlist, i, KMF_CREDENTIAL_ATTR,
		    &tokencred, sizeof (KMF_CREDENTIAL));
		i++;

		rv = kmf_import_cert(kmfhandle, i, attrlist);

	}
	return (rv);
}

static KMF_RETURN
pk_import_file_crl(void *kmfhandle,
	char *infile,
	char *outfile,
	KMF_ENCODE_FORMAT outfmt)
{
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[8];
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	if (infile) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CRL_FILENAME_ATTR, infile, strlen(infile));
		numattr++;
	}
	if (outfile) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CRL_OUTFILE_ATTR, outfile, strlen(outfile));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_ENCODE_FORMAT_ATTR, &outfmt, sizeof (outfmt));
	numattr++;

	return (kmf_import_crl(kmfhandle, numattr, attrlist));
}

static KMF_RETURN
pk_import_nss_crl(void *kmfhandle,
	boolean_t verify_crl_flag,
	char *infile,
	char *outdir,
	char *prefix)
{
	KMF_RETURN rv;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[4];
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;

	rv = configure_nss(kmfhandle, outdir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	if (infile) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_FILENAME_ATTR,
		    infile, strlen(infile));
		numattr++;
	}
	kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_CHECK_ATTR,
	    &verify_crl_flag, sizeof (verify_crl_flag));
	numattr++;

	return (kmf_import_crl(kmfhandle, numattr, attrlist));

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
	KMF_X509_DER_CERT *certs = NULL;
	KMF_RAW_KEY_DATA *keys = NULL;
	int ncerts = 0;
	int nkeys = 0;
	int i;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_ATTRIBUTE *attrlist = NULL;
	int numattr = 0;

	rv = select_token(kmfhandle, token_spec, FALSE);

	if (rv != KMF_OK) {
		return (rv);
	}

	rv = kmf_import_objects(kmfhandle, filename, p12cred,
	    &certs, &ncerts, &keys, &nkeys);

	if (rv == KMF_OK) {
		NEW_ATTRLIST(attrlist, (3 + (2 * nkeys)));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		if (label != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYLABEL_ATTR, label,
			    strlen(label));
			numattr++;
		}

		if (tokencred != NULL && tokencred->credlen > 0) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, tokencred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		/* The order of certificates and keys should match */
		for (i = 0; i < nkeys; i++) {
			int num = numattr;

			if (i < ncerts) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_DATA_ATTR, &certs[i].certificate,
				    sizeof (KMF_DATA));
				num++;
			}

			kmf_set_attr_at_index(attrlist, num,
			    KMF_RAW_KEY_ATTR, &keys[i],
			    sizeof (KMF_RAW_KEY_DATA));
			num++;

			rv = kmf_store_key(kmfhandle, num, attrlist);

		}
		free(attrlist);
	}

	if (rv == KMF_OK) {
		numattr = 0;
		NEW_ATTRLIST(attrlist, (1 + (2 * ncerts)));

		(void) printf(gettext("Found %d certificate(s) and %d "
		    "key(s) in %s\n"), ncerts, nkeys, filename);

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		numattr++;

		for (i = 0; rv == KMF_OK && i < ncerts; i++) {
			int num = numattr;
			if (certs[i].kmf_private.label != NULL) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_LABEL_ATTR,
				    certs[i].kmf_private.label,
				    strlen(certs[i].kmf_private.label));
				num++;
			} else if (i == 0 && label != NULL) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CERT_LABEL_ATTR, label, strlen(label));
				num++;
			}

			kmf_set_attr_at_index(attrlist, num,
			    KMF_CERT_DATA_ATTR, &certs[i].certificate,
			    sizeof (KMF_DATA));
			num++;

			rv = kmf_store_cert(kmfhandle, num, attrlist);
		}
		free(attrlist);
	}

end:
	/*
	 * Cleanup memory.
	 */
	if (certs) {
		for (i = 0; i < ncerts; i++)
			kmf_free_kmf_cert(kmfhandle, &certs[i]);
		free(certs);
	}
	if (keys) {
		for (i = 0; i < nkeys; i++)
			kmf_free_raw_key(&keys[i]);
		free(keys);
	}

	return (rv);
}

/*ARGSUSED*/
static KMF_RETURN
pk_import_keys(KMF_HANDLE_T kmfhandle,
	KMF_KEYSTORE_TYPE kstype, char *token_spec,
	KMF_CREDENTIAL *cred, char *filename,
	char *label, char *senstr, char *extstr)
{
	KMF_RETURN rv = KMF_OK;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEYSTORE_TYPE fileks = KMF_KEYSTORE_OPENSSL;
	int numattr = 0;
	KMF_KEY_HANDLE key;
	KMF_RAW_KEY_DATA rawkey;
	KMF_KEY_CLASS class = KMF_ASYM_PRI;
	int numkeys = 1;

	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		rv = select_token(kmfhandle, token_spec, FALSE);
	}
	if (rv != KMF_OK)
		return (rv);
	/*
	 * First, set up to read the keyfile using the FILE plugin
	 * mechanisms.
	 */
	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &fileks, sizeof (fileks));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &numkeys, sizeof (numkeys));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_HANDLE_ATTR,
	    &key, sizeof (key));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_RAW_KEY_ATTR,
	    &rawkey, sizeof (rawkey));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYCLASS_ATTR,
	    &class, sizeof (class));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_FILENAME_ATTR,
	    filename, strlen(filename));
	numattr++;

	rv = kmf_find_key(kmfhandle, numattr, attrlist);
	if (rv == KMF_OK) {
		numattr = 0;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (cred != NULL && cred->credlen > 0) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, cred, sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		if (label != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYLABEL_ATTR, label, strlen(label));
			numattr++;
		}

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_RAW_KEY_ATTR, &rawkey, sizeof (rawkey));
		numattr++;

		rv = kmf_store_key(kmfhandle, numattr, attrlist);
		if (rv == KMF_OK) {
			(void) printf(gettext("Importing %d keys\n"), numkeys);
		}

		kmf_free_kmf_key(kmfhandle, &key);
		kmf_free_raw_key(&rawkey);
	} else {
		cryptoerror(LOG_STDERR,
		    gettext("Failed to load key from file (%s)\n"),
		    filename);
	}
	return (rv);
}

static KMF_RETURN
pk_import_rawkey(KMF_HANDLE_T kmfhandle,
	KMF_KEYSTORE_TYPE kstype, char *token,
	KMF_CREDENTIAL *cred,
	char *filename, char *label, KMF_KEY_ALG keyAlg,
	char *senstr, char *extstr)
{
	KMF_RETURN rv = KMF_OK;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;
	uint32_t keylen;
	boolean_t sensitive = B_FALSE;
	boolean_t not_extractable = B_FALSE;
	KMF_DATA keydata = { 0, NULL };
	KMF_KEY_HANDLE rawkey;

	rv = kmf_read_input_file(kmfhandle, filename, &keydata);
	if (rv != KMF_OK)
		return (rv);

	rv = select_token(kmfhandle, token, FALSE);

	if (rv != KMF_OK) {
		return (rv);
	}
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
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEY_HANDLE_ATTR, &rawkey, sizeof (rawkey));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYALG_ATTR, &keyAlg, sizeof (KMF_KEY_ALG));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEY_DATA_ATTR, keydata.Data, keydata.Length);
	numattr++;

	/* Key length is given in bits not bytes */
	keylen = keydata.Length * 8;
	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_KEYLENGTH_ATTR, &keylen, sizeof (keydata.Length));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_SENSITIVE_BOOL_ATTR, &sensitive, sizeof (sensitive));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_NON_EXTRACTABLE_BOOL_ATTR, &not_extractable,
	    sizeof (not_extractable));
	numattr++;

	if (label != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYLABEL_ATTR, label, strlen(label));
		numattr++;
	}
	if (cred != NULL && cred->credlen > 0) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CREDENTIAL_ATTR, cred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}
	rv = kmf_create_sym_key(kmfhandle, numattr, attrlist);

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
	char		*label = NULL;
	char		*dir = NULL;
	char		*prefix = NULL;
	char		*trustflags = NULL;
	char		*verify_crl = NULL;
	char		*keytype = "generic";
	char		*senstr = NULL;
	char		*extstr = NULL;
	boolean_t	verify_crl_flag = B_FALSE;
	int		oclass = 0;
	KMF_KEYSTORE_TYPE	kstype = 0;
	KMF_ENCODE_FORMAT	kfmt = 0;
	KMF_ENCODE_FORMAT	okfmt = KMF_FORMAT_ASN1;
	KMF_RETURN		rv = KMF_OK;
	KMF_CREDENTIAL	pk12cred = { NULL, 0 };
	KMF_CREDENTIAL	tokencred = { NULL, 0 };
	KMF_HANDLE_T	kmfhandle = NULL;
	KMF_KEY_ALG	keyAlg = KMF_GENERIC_SECRET;

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
	    "T:(token)i:(infile)"
	    "k:(keystore)y:(objtype)"
	    "d:(dir)p:(prefix)"
	    "n:(certlabel)N:(label)"
	    "K:(outkey)c:(outcert)"
	    "v:(verifycrl)l:(outcrl)"
	    "E:(keytype)s:(sensitive)x:(extractable)"
	    "t:(trust)F:(outformat)")) != EOF) {
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
		case 'p':
			if (prefix)
				return (PK_ERR_USAGE);
			prefix = optarg_av;
			break;
		case 'n':
		case 'N':
			if (label)
				return (PK_ERR_USAGE);
			label = optarg_av;
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
		case 'E':
			keytype = optarg_av;
			break;
		case 's':
			if (senstr)
				return (PK_ERR_USAGE);
			senstr = optarg_av;
			break;
		case 'x':
			if (extstr)
				return (PK_ERR_USAGE);
			extstr = optarg_av;
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
		cryptoerror(LOG_STDERR, gettext("The 'infile' parameter"
		    "is required for the import operation.\n"));
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

	/*
	 * You must specify a certlabel (cert label) when importing
	 * into NSS or PKCS#11.
	 */
	if (kstype == KMF_KEYSTORE_NSS &&
	    (oclass != PK_CRL_OBJ) && EMPTYSTRING(label)) {
		cryptoerror(LOG_STDERR, gettext("The 'label' argument "
		    "is required for this operation\n"));
		return (PK_ERR_USAGE);
	}

	if ((rv = kmf_get_file_format(filename, &kfmt)) != KMF_OK) {
		char *kmferrstr = NULL;
		KMF_RETURN rv2;
		/*
		 * Allow for raw key data to be imported.
		 */
		if (rv == KMF_ERR_ENCODING) {
			rv = KMF_OK;
			kfmt = KMF_FORMAT_RAWKEY;
			/*
			 * Set the object class only if it was not
			 * given on the command line or if it was
			 * specified as a symmetric key object.
			 */
			if (oclass == 0 || (oclass & PK_SYMKEY_OBJ)) {
				oclass = PK_SYMKEY_OBJ;
			} else {
				cryptoerror(LOG_STDERR, gettext(
				    "The input file does not contain the "
				    "object type indicated on command "
				    "line."));
				return (KMF_ERR_BAD_PARAMETER);
			}
		} else {
			if (rv == KMF_ERR_OPEN_FILE) {
				cryptoerror(LOG_STDERR,
				    gettext("Cannot open file (%s)\n."),
				    filename);
			} else {
				rv2 = kmf_get_kmf_error_str(rv, &kmferrstr);
				if (rv2 == KMF_OK && kmferrstr) {
					cryptoerror(LOG_STDERR,
					    gettext("libkmf error: %s"),
					    kmferrstr);
					kmf_free_str(kmferrstr);
				}
			}
			return (rv);
		}
	}

	/* Check parameters for raw key import operation */
	if (kfmt == KMF_FORMAT_RAWKEY) {
		if (keytype != NULL &&
		    Str2SymKeyType(keytype, &keyAlg) != 0) {
			cryptoerror(LOG_STDERR,
			    gettext("Unrecognized keytype(%s).\n"), keytype);
			return (PK_ERR_USAGE);
		}
		if (senstr != NULL && extstr != NULL &&
		    kstype != KMF_KEYSTORE_PK11TOKEN) {
			cryptoerror(LOG_STDERR,
			    gettext("The sensitive or extractable option "
			    "applies only when importing a key from a file "
			    "into a PKCS#11 keystore.\n"));
			return (PK_ERR_USAGE);
		}
	}

	/* If no objtype was given, treat it as a certificate */
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
	}

	if ((kfmt == KMF_FORMAT_PKCS12 || kfmt == KMF_FORMAT_RAWKEY ||
	    (kfmt == KMF_FORMAT_PEM && (oclass & PK_KEY_OBJ))) &&
	    (kstype == KMF_KEYSTORE_PK11TOKEN || kstype == KMF_KEYSTORE_NSS)) {
		(void) get_token_password(kstype, token_spec, &tokencred);
	}

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		cryptoerror(LOG_STDERR, gettext("Error initializing "
		    "KMF: 0x%02x\n"), rv);
		goto end;
	}

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_pk11(
				    kmfhandle, &pk12cred,
				    &tokencred, label,
				    token_spec, filename);
			else if (oclass == PK_CERT_OBJ)
				rv = pk_import_cert(
				    kmfhandle, kstype,
				    label, token_spec,
				    filename,
				    NULL, NULL, NULL);
			else if (oclass == PK_CRL_OBJ)
				rv = pk_import_file_crl(
				    kmfhandle, filename,
				    crlfile, okfmt);
			else if (kfmt == KMF_FORMAT_RAWKEY &&
			    oclass == PK_SYMKEY_OBJ) {
				rv = pk_import_rawkey(kmfhandle,
				    kstype, token_spec, &tokencred,
				    filename, label,
				    keyAlg, senstr, extstr);
			} else if (kfmt == KMF_FORMAT_PEM ||
			    kfmt == KMF_FORMAT_PEM_KEYPAIR) {
				rv = pk_import_keys(kmfhandle,
				    kstype, token_spec, &tokencred,
				    filename, label, senstr, extstr);
			} else {
				rv = PK_ERR_USAGE;
			}
			break;
		case KMF_KEYSTORE_NSS:
			if (dir == NULL)
				dir = PK_DEFAULT_DIRECTORY;
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_nss(
				    kmfhandle, &pk12cred,
				    &tokencred,
				    token_spec, dir, prefix,
				    label, trustflags, filename);
			else if (oclass == PK_CERT_OBJ) {
				rv = pk_import_cert(
				    kmfhandle, kstype,
				    label, token_spec,
				    filename, dir, prefix, trustflags);
			} else if (oclass == PK_CRL_OBJ) {
				rv = pk_import_nss_crl(
				    kmfhandle, verify_crl_flag,
				    filename, dir, prefix);
			}
			break;
		case KMF_KEYSTORE_OPENSSL:
			if (kfmt == KMF_FORMAT_PKCS12)
				rv = pk_import_pk12_files(
				    kmfhandle, &pk12cred,
				    filename, certfile, keyfile,
				    okfmt);
			else if (oclass == PK_CRL_OBJ) {
				rv = pk_import_file_crl(
				    kmfhandle, filename,
				    crlfile, okfmt);
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

	(void) kmf_finalize(kmfhandle);

	if (rv != KMF_OK)
		return (PK_ERR_USAGE);

	return (0);
}

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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

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
	char *start, *end, *keyusage, *extkeyusage;

	for (i = 0; i < num_certs; i++) {
		subject = NULL;
		issuer = NULL;
		serial = NULL;
		id = NULL;
		altname = NULL;
		start = end = NULL;
		keyusage = extkeyusage = NULL;

		(void) fprintf(stdout,
		    gettext("%d. (X.509 certificate)\n"), i + 1);
		if (certs[i].kmf_private.label != NULL)
			(void) fprintf(stdout, gettext("\t%s: %s\n"),
			    (certs[i].kmf_private.keystore_type ==
			    KMF_KEYSTORE_OPENSSL ?  "Filename" : "Label"),
			    certs[i].kmf_private.label);
		if (kmf_get_cert_id_str(&certs[i].certificate,
		    &id) == KMF_OK)
			(void) fprintf(stdout, gettext("\tID: %s\n"), id);
		if (kmf_get_cert_subject_str(kmfhandle,
		    &certs[i].certificate, &subject) == KMF_OK)
			(void) fprintf(stdout, gettext("\tSubject: %s\n"),
			    subject);
		if (kmf_get_cert_issuer_str(kmfhandle,
		    &certs[i].certificate, &issuer) == KMF_OK)
			(void) fprintf(stdout, gettext("\tIssuer: %s\n"),
			    issuer);
		if (kmf_get_cert_start_date_str(kmfhandle,
		    &certs[i].certificate, &start) == KMF_OK)
			(void) fprintf(stdout, gettext("\tNot Before: %s\n"),
			    start);
		if (kmf_get_cert_end_date_str(kmfhandle,
		    &certs[i].certificate, &end) == KMF_OK)
			(void) fprintf(stdout, gettext("\tNot After: %s\n"),
			    end);
		if (kmf_get_cert_serial_str(kmfhandle,
		    &certs[i].certificate, &serial) == KMF_OK)
			(void) fprintf(stdout, gettext("\tSerial: %s\n"),
			    serial);
		if (kmf_get_cert_extn_str(kmfhandle,
		    &certs[i].certificate, KMF_X509_EXT_SUBJ_ALTNAME,
		    &altname) == KMF_OK)  {
			(void) fprintf(stdout, gettext("\t%s\n"),
			    altname);
		}
		if (kmf_get_cert_extn_str(kmfhandle,
		    &certs[i].certificate, KMF_X509_EXT_KEY_USAGE,
		    &keyusage) == KMF_OK)  {
			(void) fprintf(stdout, gettext("\t%s\n"),
			    keyusage);
		}
		if (kmf_get_cert_extn_str(kmfhandle,
		    &certs[i].certificate, KMF_X509_EXT_EXT_KEY_USAGE,
		    &extkeyusage) == KMF_OK)  {
			(void) fprintf(stdout, gettext("\t%s\n"),
			    extkeyusage);
		}
		kmf_free_str(subject);
		kmf_free_str(issuer);
		kmf_free_str(serial);
		kmf_free_str(id);
		kmf_free_str(altname);
		kmf_free_str(keyusage);
		kmf_free_str(extkeyusage);
		kmf_free_str(start);
		kmf_free_str(end);
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
		if (key->keyalg == KMF_ECDSA)
			return (gettext("ECDSA public key"));
	}
	if (key->keyclass == KMF_ASYM_PRI) {
		if (key->keyalg == KMF_RSA)
			return (gettext("RSA private key"));
		if (key->keyalg == KMF_DSA)
			return (gettext("DSA private key"));
		if (key->keyalg == KMF_ECDSA)
			return (gettext("ECDSA private key"));
	}
	if (key->keyclass == KMF_SYMMETRIC) {
		switch (key->keyalg) {
			case KMF_AES:
				return (gettext("AES"));
			case KMF_RC4:
				return (gettext("ARCFOUR"));
			case KMF_DES:
				return (gettext("DES"));
			case KMF_DES3:
				return (gettext("Triple-DES"));
			default:
				return (gettext("symmetric"));
		}
	}

	return (gettext("unrecognized key object"));

}


static void
pk_show_keys(void *handle, KMF_KEY_HANDLE *keys, int numkeys)
{
	int i;

	for (i = 0; i < numkeys; i++) {
		(void) fprintf(stdout, gettext("Key #%d - %s:  %s"),
		    i+1, describeKey(&keys[i]),
		    keys[i].keylabel ? keys[i].keylabel :
		    gettext("No label"));

		if (keys[i].keyclass == KMF_SYMMETRIC) {
			KMF_RETURN rv;
			KMF_RAW_SYM_KEY rkey;

			(void) memset(&rkey, 0, sizeof (rkey));
			rv = kmf_get_sym_key_value(handle, &keys[i],
			    &rkey);
			if (rv == KMF_OK) {
				(void) fprintf(stdout, " (%d bits)",
				    rkey.keydata.len * 8);
				kmf_free_bigint(&rkey.keydata);
			} else if (keys[i].kstype == KMF_KEYSTORE_PK11TOKEN) {
				if (rv == KMF_ERR_SENSITIVE_KEY) {
					(void) fprintf(stdout, " (sensitive)");
				} else if (rv == KMF_ERR_UNEXTRACTABLE_KEY) {
					(void) fprintf(stdout,
					    " (non-extractable)");
				} else {
					char *err = NULL;
					if (kmf_get_kmf_error_str(rv, &err) ==
					    KMF_OK)
						(void) fprintf(stdout,
						    " (error: %s)", err);
					if (err != NULL)
						free(err);
				}
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
pk_find_certs(KMF_HANDLE_T kmfhandle, KMF_ATTRIBUTE *attrlist, int numattr)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT *certlist = NULL;
	uint32_t numcerts = 0;
	KMF_KEYSTORE_TYPE kstype;

	rv = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &numcerts, sizeof (uint32_t));
	numattr++;

	rv = kmf_find_cert(kmfhandle, numattr, attrlist);
	if (rv == KMF_OK && numcerts > 0) {
		(void) printf(gettext("Found %d certificates.\n"),
		    numcerts);
		certlist = (KMF_X509_DER_CERT *)malloc(numcerts *
		    sizeof (KMF_X509_DER_CERT));
		if (certlist == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(certlist, 0, numcerts *
		    sizeof (KMF_X509_DER_CERT));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_X509_DER_CERT_ATTR, certlist,
		    sizeof (KMF_X509_DER_CERT));
		numattr++;

		rv = kmf_find_cert(kmfhandle, numattr, attrlist);
		if (rv == KMF_OK) {
			int i;
			(void) pk_show_certs(kmfhandle, certlist,
			    numcerts);
			for (i = 0; i < numcerts; i++)
				kmf_free_kmf_cert(kmfhandle, &certlist[i]);
		}
		free(certlist);
	}
	if (rv == KMF_ERR_CERT_NOT_FOUND &&
	    kstype != KMF_KEYSTORE_OPENSSL)
		rv = KMF_OK;

	return (rv);
}

static KMF_RETURN
pk_list_keys(void *handle, KMF_ATTRIBUTE *attrlist, int numattr, char *label)
{
	KMF_RETURN rv;
	KMF_KEY_HANDLE *keys;
	uint32_t numkeys = 0;
	KMF_KEYSTORE_TYPE kstype;

	rv = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_COUNT_ATTR,
	    &numkeys, sizeof (uint32_t));
	numattr++;

	rv = kmf_find_key(handle, numattr, attrlist);
	if (rv == KMF_OK && numkeys > 0) {
		int i;
		(void) printf(gettext("Found %d %s keys.\n"),
		    numkeys, label);
		keys = (KMF_KEY_HANDLE *)malloc(numkeys *
		    sizeof (KMF_KEY_HANDLE));
		if (keys == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(keys, 0, numkeys *
		    sizeof (KMF_KEY_HANDLE));

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEY_HANDLE_ATTR,
		    keys, sizeof (KMF_KEY_HANDLE));
		numattr++;

		rv = kmf_find_key(handle, numattr, attrlist);
		if (rv == KMF_OK)
			pk_show_keys(handle, keys, numkeys);
		for (i = 0; i < numkeys; i++)
			kmf_free_kmf_key(handle, &keys[i]);
		free(keys);
	}
	if (rv == KMF_ERR_KEY_NOT_FOUND &&
	    kstype != KMF_KEYSTORE_OPENSSL)
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
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[18];
	boolean_t token_bool = B_TRUE;
	boolean_t private = B_FALSE;
	KMF_KEY_CLASS keyclass;
	KMF_ENCODE_FORMAT format;
	int auth = 0;
	KMF_CREDENTIAL cred = { NULL, 0 };

	/*
	 * Symmetric keys and RSA/DSA/ECDSA private keys are always
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

	rv = token_auth_needed(kmfhandle, token, &auth);
	if (rv != KMF_OK)
		return (rv);

	if (tokencred != NULL)
		cred = *tokencred;

	if (oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (objlabel != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYLABEL_ATTR, objlabel,
			    strlen(objlabel));
			numattr++;
		}

		private = ((oclass & PK_PRIVATE_OBJ) > 0);

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_PRIVATE_BOOL_ATTR, &private,
		    sizeof (private));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_TOKEN_BOOL_ATTR, &token_bool,
		    sizeof (token_bool));
		numattr++;

		if (oclass & PK_PRIKEY_OBJ) {
			int num = numattr;

			keyclass = KMF_ASYM_PRI;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_KEYCLASS_ATTR, &keyclass,
			    sizeof (keyclass));
			num++;

			if (tokencred != NULL &&
			    tokencred->credlen > 0) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CREDENTIAL_ATTR, tokencred,
				    sizeof (KMF_CREDENTIAL));
				num++;
			}

			/* list asymmetric private keys */
			rv = pk_list_keys(kmfhandle, attrlist, num,
			    "asymmetric private");
		}

		if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
			int num = numattr;

			keyclass = KMF_SYMMETRIC;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_KEYCLASS_ATTR, &keyclass,
			    sizeof (keyclass));
			num++;

			if (tokencred != NULL &&
			    tokencred->credlen > 0) {
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CREDENTIAL_ATTR, tokencred,
				    sizeof (KMF_CREDENTIAL));
				num++;
			}

			format = KMF_FORMAT_RAWKEY;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_ENCODE_FORMAT_ATTR, &format,
			    sizeof (format));
			num++;

			/* list symmetric keys */
			rv = pk_list_keys(kmfhandle, attrlist, num,
			    "symmetric");
		}

		if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
			int num = numattr;

			if (auth > 0 && (tokencred == NULL ||
			    tokencred->cred == NULL) &&
			    (cred.cred == NULL)) {
				(void) get_token_password(kstype, token, &cred);
				kmf_set_attr_at_index(attrlist, num,
				    KMF_CREDENTIAL_ATTR,
				    &cred, sizeof (KMF_CREDENTIAL));
				num++;
			}

			private = B_FALSE;
			keyclass = KMF_ASYM_PUB;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_KEYCLASS_ATTR, &keyclass,
			    sizeof (keyclass));
			num++;

			/* list asymmetric public keys (if any) */
			rv = pk_list_keys(kmfhandle, attrlist, num,
			    "asymmetric public");
		}

		if (rv != KMF_OK)
			return (rv);
	}

	numattr = 0;
	if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));

		numattr++;
		if (auth > 0 && (cred.cred == NULL)) {
			(void) get_token_password(kstype, token, &cred);
		}

		if (cred.cred != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR,
			    &cred, sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		if (objlabel != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_LABEL_ATTR, objlabel,
			    strlen(objlabel));
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

		if (serial != NULL && serial->val != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_BIGINT_ATTR, serial,
			    sizeof (KMF_BIGINT));
			numattr++;
		}

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_PRIVATE_BOOL_ATTR, &private,
		    sizeof (private));
		numattr++;

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_VALIDITY_ATTR, &find_criteria_flag,
		    sizeof (KMF_CERT_VALIDITY));
		numattr++;

		rv = pk_find_certs(kmfhandle, attrlist, numattr);
		if (rv != KMF_OK)
			return (rv);
	}

	numattr = 0;
	kstype = KMF_KEYSTORE_OPENSSL; /* CRL is file-based */
	if (oclass & PK_CRL_OBJ) {
		char *crldata = NULL;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (dir != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_DIRPATH_ATTR, dir, strlen(dir));
			numattr++;
		}
		if (filename != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CRL_FILENAME_ATTR,
			    filename, strlen(filename));
			numattr++;
		}
		kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_DATA_ATTR,
		    &crldata, sizeof (char *));
		numattr++;

		rv = kmf_list_crl(kmfhandle, numattr, attrlist);
		if (rv == KMF_OK && crldata != NULL) {
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
	KMF_RETURN rv = KMF_OK;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_CLASS keyclass;
	KMF_ENCODE_FORMAT format;
	char *defaultdir = ".";

	if (oclass & PK_KEY_OBJ) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (dir == NULL && filename == NULL)
			dir = defaultdir;

		if (dir != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_DIRPATH_ATTR, dir,
			    strlen(dir));
			numattr++;
		}

		if (filename != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEY_FILENAME_ATTR, filename,
			    strlen(filename));
			numattr++;
		}

		if (oclass & PK_PRIKEY_OBJ) {
			int num = numattr;

			keyclass = KMF_ASYM_PRI;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_KEYCLASS_ATTR, &keyclass,
			    sizeof (keyclass));
			num++;

			/* list asymmetric private keys */
			rv = pk_list_keys(kmfhandle, attrlist, num,
			    "asymmetric private");
		}
		if (rv == KMF_ERR_KEY_NOT_FOUND)
			rv = KMF_OK;

		if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
			int num = numattr;

			keyclass = KMF_SYMMETRIC;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_KEYCLASS_ATTR, &keyclass,
			    sizeof (keyclass));
			num++;

			format = KMF_FORMAT_RAWKEY;
			kmf_set_attr_at_index(attrlist, num,
			    KMF_ENCODE_FORMAT_ATTR, &format,
			    sizeof (format));
			num++;

			/* list symmetric keys */
			rv = pk_list_keys(kmfhandle, attrlist, num,
			    "symmetric");
		}
		if (rv == KMF_ERR_KEY_NOT_FOUND)
			rv = KMF_OK;
		if (rv != KMF_OK)
			return (rv);
	}

	numattr = 0;
	if (oclass & PK_CERT_OBJ) {
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

		if (serial != NULL && serial->val != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_BIGINT_ATTR, serial,
			    sizeof (KMF_BIGINT));
			numattr++;
		}

		if (filename != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_FILENAME_ATTR, filename,
			    strlen(filename));
			numattr++;
		}

		if (dir != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_DIRPATH_ATTR, dir,
			    strlen(dir));
			numattr++;
		}

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_VALIDITY_ATTR, &find_criteria_flag,
		    sizeof (KMF_CERT_VALIDITY));
		numattr++;

		rv = pk_find_certs(kmfhandle, attrlist, numattr);
		if (rv != KMF_OK)
			return (rv);
	}

	numattr = 0;
	if (oclass & PK_CRL_OBJ) {
		char *crldata = NULL;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (dir != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_DIRPATH_ATTR, dir, strlen(dir));
			numattr++;
		}
		if (filename != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CRL_FILENAME_ATTR,
			    filename, strlen(filename));
			numattr++;
		}
		kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_DATA_ATTR,
		    &crldata, sizeof (char *));
		numattr++;

		rv = kmf_list_crl(kmfhandle, numattr, attrlist);
		if (rv == KMF_OK && crldata != NULL) {
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
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_CLASS keyclass;
	KMF_ENCODE_FORMAT format;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (oclass & PK_KEY_OBJ) {
		if (tokencred != NULL && tokencred->credlen > 0) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CREDENTIAL_ATTR, tokencred,
			    sizeof (KMF_CREDENTIAL));
			numattr++;
		}

		if (token_spec && strlen(token_spec)) {
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
	}

	if (oclass & PK_PRIKEY_OBJ) {
		int num = numattr;

		keyclass = KMF_ASYM_PRI;
		kmf_set_attr_at_index(attrlist, num,
		    KMF_KEYCLASS_ATTR, &keyclass,
		    sizeof (keyclass));
		num++;

		/* list asymmetric private keys */
		rv = pk_list_keys(kmfhandle, attrlist, num,
		    "asymmetric private");
	}

	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_SYMMETRIC;
		kmf_set_attr_at_index(attrlist, num,
		    KMF_KEYCLASS_ATTR, &keyclass,
		    sizeof (keyclass));
		num++;

		format = KMF_FORMAT_RAWKEY;
		kmf_set_attr_at_index(attrlist, num,
		    KMF_ENCODE_FORMAT_ATTR, &format,
		    sizeof (format));
		num++;

		/* list symmetric keys */
		rv = pk_list_keys(kmfhandle, attrlist, num, "symmetric");
	}

	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_ASYM_PUB;
		kmf_set_attr_at_index(attrlist, num,
		    KMF_KEYCLASS_ATTR, &keyclass,
		    sizeof (keyclass));
		num++;

		/* list asymmetric public keys */
		rv = pk_list_keys(kmfhandle, attrlist, num,
		    "asymmetric public");
	}

	/* If searching for public objects or certificates, find certs now */
	numattr = 0;
	if (rv == KMF_OK && (oclass & PK_CERT_OBJ)) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype,
		    sizeof (kstype));
		numattr++;

		if (nickname != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CERT_LABEL_ATTR, nickname,
			    strlen(nickname));
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

		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_VALIDITY_ATTR, &find_criteria_flag,
		    sizeof (KMF_CERT_VALIDITY));
		numattr++;

		rv = pk_find_certs(kmfhandle, attrlist, numattr);
	}

	numattr = 0;
	if (rv == KMF_OK && (oclass & PK_CRL_OBJ)) {
		int numcrls;

		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
		    &kstype, sizeof (kstype));
		numattr++;

		if (token_spec != NULL) {
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_TOKEN_LABEL_ATTR,
			    token_spec, strlen(token_spec));
			numattr++;
		}
		kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_COUNT_ATTR,
		    &numcrls, sizeof (int));
		numattr++;

		rv = kmf_find_crl(kmfhandle, numattr, attrlist);
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

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CRL_NAMELIST_ATTR, p, sizeof (char *));
			numattr++;
			rv = kmf_find_crl(kmfhandle, numattr, attrlist);
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
	KMF_CREDENTIAL		tokencred = { NULL, 0 };

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

	if ((rv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
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
			(void) fprintf(stderr, gettext("serial number "
			    "must be specified as a hex number "
			    "(ex: 0x0102030405ffeeddee)\n"));
			return (PK_ERR_USAGE);
		}
		serial.val = bytes;
		serial.len = bytelen;
		/* if objtype was not given, it must be for certs */
		if (oclass == 0)
			oclass = PK_CERT_OBJ;
	}
	if (oclass == 0 && (issuer != NULL || subject != NULL))
		oclass = PK_CERT_OBJ;

	/* If no object class specified, list public objects. */
	if (oclass == 0)
		oclass = PK_CERT_OBJ | PK_PUBKEY_OBJ;

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

	(void) kmf_finalize(kmfhandle);
	return (rv);
}

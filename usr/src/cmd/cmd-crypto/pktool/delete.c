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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 */

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
pk_destroy_keys(void *handle, KMF_ATTRIBUTE *attrlist, int numattr)
{
	int i;
	KMF_RETURN rv = KMF_OK;
	uint32_t *numkeys;
	KMF_KEY_HANDLE *keys = NULL;
	int del_num = 0;
	KMF_ATTRIBUTE delete_attlist[16];
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;
	boolean_t destroy = B_TRUE;
	KMF_CREDENTIAL cred;
	char *slotlabel = NULL;

	len = sizeof (kstype);
	rv = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, &len);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(delete_attlist, del_num,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	del_num++;

	/* "destroy" is optional. Default is TRUE */
	(void) kmf_get_attr(KMF_DESTROY_BOOL_ATTR, attrlist, numattr,
	    (void *)&destroy, NULL);

	kmf_set_attr_at_index(delete_attlist, del_num,
	    KMF_DESTROY_BOOL_ATTR, &destroy, sizeof (boolean_t));
	del_num++;

	switch (kstype) {
	case KMF_KEYSTORE_NSS:
		rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
		    (void *)&cred, NULL);
		if (rv == KMF_OK) {
			if (cred.credlen > 0) {
				kmf_set_attr_at_index(delete_attlist, del_num,
				    KMF_CREDENTIAL_ATTR, &cred,
				    sizeof (KMF_CREDENTIAL));
				del_num++;
			}
		}

		slotlabel = kmf_get_attr_ptr(KMF_TOKEN_LABEL_ATTR, attrlist,
		    numattr);
		if (slotlabel != NULL) {
			kmf_set_attr_at_index(delete_attlist, del_num,
			    KMF_TOKEN_LABEL_ATTR, slotlabel,
			    strlen(slotlabel));
			del_num++;
		}
		break;
	case KMF_KEYSTORE_OPENSSL:
		break;
	case KMF_KEYSTORE_PK11TOKEN:
		rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
		    (void *)&cred, NULL);
		if (rv == KMF_OK) {
			if (cred.credlen > 0) {
				kmf_set_attr_at_index(delete_attlist, del_num,
				    KMF_CREDENTIAL_ATTR, &cred,
				    sizeof (KMF_CREDENTIAL));
				del_num++;
			}
		}
		break;
	default:
		return (PK_ERR_USAGE);
	}

	numkeys = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (numkeys == NULL)
		return (PK_ERR_USAGE);

	keys = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (keys == NULL)
		return (PK_ERR_USAGE);

	for (i = 0; rv == KMF_OK && i < *numkeys; i++) {
		int num = del_num;

		kmf_set_attr_at_index(delete_attlist, num,
		    KMF_KEY_HANDLE_ATTR, &keys[i], sizeof (KMF_KEY_HANDLE));
		num++;

		rv = kmf_delete_key_from_keystore(handle, num, delete_attlist);
	}
	return (rv);
}

static KMF_RETURN
pk_delete_keys(KMF_HANDLE_T kmfhandle, KMF_ATTRIBUTE *attlist, int numattr,
    char *desc, int *keysdeleted)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numkeys = 0;
	int num = numattr;

	*keysdeleted = 0;
	numkeys = 0;

	kmf_set_attr_at_index(attlist, num,
	    KMF_COUNT_ATTR, &numkeys, sizeof (uint32_t));
	num++;

	rv = kmf_find_key(kmfhandle, num, attlist);

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
			*keysdeleted = numkeys;
			return (KMF_OK);
		}
		keys = (KMF_KEY_HANDLE *)malloc(numkeys *
		    sizeof (KMF_KEY_HANDLE));
		if (keys == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset(keys, 0, numkeys *
		    sizeof (KMF_KEY_HANDLE));

		kmf_set_attr_at_index(attlist, num,
		    KMF_KEY_HANDLE_ATTR, keys, sizeof (KMF_KEY_HANDLE));
		num++;

		rv = kmf_find_key(kmfhandle, num, attlist);
		if (rv == KMF_OK) {
			rv = pk_destroy_keys(kmfhandle, attlist, num);
		}

		free(keys);
	}

	*keysdeleted = numkeys;
	return (rv);
}

static KMF_RETURN
pk_delete_certs(KMF_HANDLE_T kmfhandle, KMF_ATTRIBUTE *attlist, int numattr)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t numcerts = 0;
	int num = numattr;

	kmf_set_attr_at_index(attlist, num,
	    KMF_COUNT_ATTR, &numcerts, sizeof (uint32_t));
	num++;

	rv = kmf_find_cert(kmfhandle, num, attlist);
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

		/*
		 * Use numattr because delete cert does not require
		 * KMF_COUNT_ATTR attribute.
		 */
		rv = kmf_delete_cert_from_keystore(kmfhandle, numattr, attlist);

	}

	return (rv);
}

static KMF_RETURN
delete_nss_keys(KMF_HANDLE_T kmfhandle, char *dir, char *prefix,
    char *token, int oclass, char *objlabel,
    KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN rv = KMF_OK;
	char *keytype = NULL;
	int nk, numkeys = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_CLASS keyclass;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (objlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR,
		    objlabel, strlen(objlabel));
		numattr++;
	}

	if (tokencred->credlen > 0) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	if (token && strlen(token)) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}

	if (oclass & PK_PRIKEY_OBJ) {
		int num = numattr;

		keyclass = KMF_ASYM_PRI;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		keytype = "private";
		rv = pk_delete_keys(kmfhandle, attrlist, num, keytype, &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_PRIKEY_OBJ)
			rv = KMF_OK;
	}
	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_SYMMETRIC;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		keytype = "symmetric";
		rv = pk_delete_keys(kmfhandle, attrlist, num, keytype, &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_SYMKEY_OBJ)
			rv = KMF_OK;
	}
	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_ASYM_PUB;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		keytype = "public";
		rv = pk_delete_keys(kmfhandle, attrlist, num, keytype, &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_PUBKEY_OBJ)
			rv = KMF_OK;
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
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

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

	if (serno != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_BIGINT_ATTR, serno,
		    sizeof (KMF_BIGINT));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_CERT_VALIDITY_ATTR, &find_criteria_flag,
	    sizeof (KMF_CERT_VALIDITY));
	numattr++;

	if (token != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_TOKEN_LABEL_ATTR, token,
		    strlen(token));
		numattr++;
	}

	rv = pk_delete_certs(kmfhandle, attrlist, numattr);

	return (rv);
}

static KMF_RETURN
delete_nss_crl(void *kmfhandle,
    char *dir, char *prefix, char *token,
    char *issuer, char *subject)
{
	KMF_RETURN rv = KMF_OK;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[8];
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;

	rv = configure_nss(kmfhandle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (token != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token, strlen(token));
		numattr++;
	}
	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_ISSUER_NAME_ATTR,
		    issuer, strlen(issuer));
		numattr++;
	}
	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_SUBJECT_NAME_ATTR,
		    subject, strlen(subject));
		numattr++;
	}

	rv = kmf_delete_crl(kmfhandle, numattr, attrlist);

	return (rv);
}

static KMF_RETURN
delete_pk11_keys(KMF_HANDLE_T kmfhandle,
    char *token, int oclass, char *objlabel,
    KMF_CREDENTIAL *tokencred)
{
	KMF_RETURN rv = KMF_OK;
	int nk, numkeys = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_CLASS keyclass;
	boolean_t token_bool = B_TRUE;
	boolean_t private;
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

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (objlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEYLABEL_ATTR,
		    objlabel, strlen(objlabel));
		numattr++;
	}

	if (tokencred != NULL && tokencred->credlen > 0) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
		    tokencred, sizeof (KMF_CREDENTIAL));
		numattr++;
	}

	private = ((oclass & PK_PRIVATE_OBJ) > 0);

	kmf_set_attr_at_index(attrlist, numattr, KMF_PRIVATE_BOOL_ATTR,
	    &private, sizeof (private));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_BOOL_ATTR,
	    &token_bool, sizeof (token_bool));
	numattr++;

	if (oclass & PK_PRIKEY_OBJ) {
		int num = numattr;

		keyclass = KMF_ASYM_PRI;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		rv = pk_delete_keys(kmfhandle, attrlist, num, "private", &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_PRIKEY_OBJ)
			rv = KMF_OK;
	}

	if (rv == KMF_OK && (oclass & PK_SYMKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_SYMMETRIC;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		rv = pk_delete_keys(kmfhandle, attrlist, num, "symmetric", &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_SYMKEY_OBJ)
			rv = KMF_OK;
	}

	if (rv == KMF_OK && (oclass & PK_PUBKEY_OBJ)) {
		int num = numattr;

		private = B_FALSE;
		keyclass = KMF_ASYM_PUB;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		rv = pk_delete_keys(kmfhandle, attrlist, num, "public", &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND &&
		    oclass != PK_PUBKEY_OBJ)
			rv = KMF_OK;
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
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];

	kmfrv = select_token(kmfhandle, token, FALSE);

	if (kmfrv != KMF_OK) {
		return (kmfrv);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (objlabel != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_LABEL_ATTR,
		    objlabel, strlen(objlabel));
		numattr++;
	}

	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_ISSUER_NAME_ATTR,
		    issuer, strlen(issuer));
		numattr++;
	}

	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_SUBJECT_NAME_ATTR,
		    subject, strlen(subject));
		numattr++;
	}

	if (serno != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_BIGINT_ATTR,
		    serno, sizeof (KMF_BIGINT));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_VALIDITY_ATTR,
	    &find_criteria_flag, sizeof (KMF_CERT_VALIDITY));
	numattr++;

	kmfrv = pk_delete_certs(kmfhandle, attrlist, numattr);

	return (kmfrv);
}

static KMF_RETURN
delete_file_certs(KMF_HANDLE_T kmfhandle,
    char *dir, char *filename, KMF_BIGINT *serial, char *issuer,
    char *subject, KMF_CERT_VALIDITY find_criteria_flag)
{
	KMF_RETURN rv;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (issuer != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_ISSUER_NAME_ATTR,
		    issuer, strlen(issuer));
		numattr++;
	}

	if (subject != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_SUBJECT_NAME_ATTR,
		    subject, strlen(subject));
		numattr++;
	}

	if (serial != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_BIGINT_ATTR,
		    serial, sizeof (KMF_BIGINT));
		numattr++;
	}

	if (dir != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_DIRPATH_ATTR,
		    dir, strlen(dir));
		numattr++;
	}

	if (filename != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_FILENAME_ATTR,
		    filename, strlen(filename));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_CERT_VALIDITY_ATTR,
	    &find_criteria_flag, sizeof (KMF_CERT_VALIDITY));
	numattr++;

	rv = pk_delete_certs(kmfhandle, attrlist, numattr);

	return (rv);
}

static KMF_RETURN
delete_file_keys(KMF_HANDLE_T kmfhandle, int oclass, char *dir, char *infile)
{
	KMF_RETURN rv = KMF_OK;
	char *keytype = "";
	int nk, numkeys = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[16];
	KMF_KEY_CLASS keyclass;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (dir != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_DIRPATH_ATTR,
		    dir, strlen(dir));
		numattr++;
	}

	if (infile != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_KEY_FILENAME_ATTR,
		    infile, strlen(infile));
		numattr++;
	}

	if (oclass & (PK_PUBKEY_OBJ | PK_PRIKEY_OBJ)) {
		int num = numattr;

		keyclass = KMF_ASYM_PRI;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		keytype = "Asymmetric";
		rv = pk_delete_keys(kmfhandle, attrlist, num, keytype, &nk);
		numkeys += nk;
	}
	if (oclass & PK_SYMKEY_OBJ) {
		int num = numattr;

		keyclass = KMF_SYMMETRIC;
		kmf_set_attr_at_index(attrlist, num, KMF_KEYCLASS_ATTR,
		    &keyclass, sizeof (keyclass));
		num++;

		keytype = "symmetric";
		rv = pk_delete_keys(kmfhandle, attrlist, num, keytype, &nk);
		numkeys += nk;
		if (rv == KMF_ERR_KEY_NOT_FOUND && numkeys > 0)
			rv = KMF_OK;
	}
	if (rv == KMF_OK && numkeys == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;

	return (rv);
}

static KMF_RETURN
delete_file_crl(void *kmfhandle, char *filename)
{
	KMF_RETURN rv;
	int numattr = 0;
	KMF_ATTRIBUTE attrlist[4];
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;

	if (filename == NULL || strlen(filename) == 0)
		return (KMF_ERR_BAD_PARAMETER);

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;

	if (filename) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_CRL_FILENAME_ATTR,
		    filename, strlen(filename));
		numattr++;
	}

	rv = kmf_delete_crl(kmfhandle, numattr, attrlist);

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
	KMF_RETURN	kmfrv, keyrv, certrv, crlrv;
	int		rv = 0;
	char			*find_criteria = NULL;
	KMF_CERT_VALIDITY	find_criteria_flag = KMF_ALL_CERTS;
	KMF_CREDENTIAL	tokencred = { NULL, 0 };

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


	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	DIR_OPTION_CHECK(kstype, dir);

	if (kstype == KMF_KEYSTORE_PK11TOKEN && token_spec == NULL) {
		token_spec = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && token_spec == NULL) {
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
		/* If serial number was given, it must be a cert search */
		if (oclass == 0)
			oclass = PK_CERT_OBJ;
	}
	/*
	 * If no object type was given but subject or issuer was,
	 * it must be a certificate we are looking to delete.
	 */
	if ((issuer != NULL || subject != NULL) && oclass == 0)
		oclass = PK_CERT_OBJ;
	/* If no object class specified, delete everything but CRLs */
	if (oclass == 0)
		oclass = PK_CERT_OBJ | PK_KEY_OBJ;

	if ((kstype == KMF_KEYSTORE_PK11TOKEN ||
	    kstype == KMF_KEYSTORE_NSS) &&
	    (oclass & (PK_KEY_OBJ | PK_PRIVATE_OBJ))) {

		(void) get_token_password(kstype, token_spec,
		    &tokencred);
	}

	if ((kmfrv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK)
		return (kmfrv);

	keyrv = certrv = crlrv = KMF_OK;
	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			if (oclass & PK_KEY_OBJ) {
				keyrv = delete_pk11_keys(kmfhandle,
				    token_spec, oclass,
				    object_label, &tokencred);
				/*
				 * If deleting groups of objects, it is OK
				 * to ignore the "key not found" case so that
				 * we can continue to find other objects.
				 */
				if (keyrv != KMF_OK &&
				    keyrv != KMF_ERR_KEY_NOT_FOUND)
					break;
			}
			if (oclass & (PK_CERT_OBJ | PK_PUBLIC_OBJ)) {
				certrv = delete_pk11_certs(kmfhandle,
				    token_spec, object_label,
				    &serial, issuer,
				    subject, find_criteria_flag);
				/*
				 * If cert delete failed, but we are looking at
				 * other objects, then it is OK.
				 */
				if (certrv != KMF_OK &&
				    certrv != KMF_ERR_CERT_NOT_FOUND)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				crlrv = delete_file_crl(kmfhandle,
				    infile);
			break;
		case KMF_KEYSTORE_NSS:
			keyrv = certrv = crlrv = KMF_OK;
			if (oclass & PK_KEY_OBJ) {
				keyrv = delete_nss_keys(kmfhandle,
				    dir, prefix, token_spec,
				    oclass, (char  *)object_label,
				    &tokencred);
				if (keyrv != KMF_OK &&
				    keyrv != KMF_ERR_KEY_NOT_FOUND)
					break;
			}
			if (oclass & PK_CERT_OBJ) {
				certrv = delete_nss_certs(kmfhandle,
				    dir, prefix, token_spec,
				    (char  *)object_label,
				    &serial, issuer, subject,
				    find_criteria_flag);
				if (certrv != KMF_OK &&
				    certrv != KMF_ERR_CERT_NOT_FOUND)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				crlrv = delete_nss_crl(kmfhandle,
				    dir, prefix, token_spec,
				    (char  *)object_label, subject);
			break;
		case KMF_KEYSTORE_OPENSSL:
			if (oclass & PK_KEY_OBJ) {
				keyrv = delete_file_keys(kmfhandle, oclass,
				    dir, infile);
				if (keyrv != KMF_OK)
					break;
			}
			if (oclass & (PK_CERT_OBJ)) {
				certrv = delete_file_certs(kmfhandle,
				    dir, infile, &serial, issuer,
				    subject, find_criteria_flag);
				if (certrv != KMF_OK)
					break;
			}
			if (oclass & PK_CRL_OBJ)
				crlrv = delete_file_crl(kmfhandle,
				    infile);
			break;
		default:
			rv = PK_ERR_USAGE;
			break;
	}

	/*
	 * Logic here:
	 *    If searching for more than just one class of object (key or cert)
	 *    and only 1 of the classes was not found, it is not an error.
	 *    If searching for just one class of object, that failure should
	 *    be reported.
	 *
	 *    Any error other than "KMF_ERR_[key/cert]_NOT_FOUND" should
	 *    be reported either way.
	 */
	if (keyrv != KMF_ERR_KEY_NOT_FOUND && keyrv != KMF_OK)
		kmfrv = keyrv;
	else if (certrv != KMF_OK && certrv != KMF_ERR_CERT_NOT_FOUND)
		kmfrv = certrv;
	else if (crlrv != KMF_OK && crlrv != KMF_ERR_CRL_NOT_FOUND)
		kmfrv = crlrv;

	/*
	 * If nothing was found, return error.
	 */
	if ((keyrv == KMF_ERR_KEY_NOT_FOUND && (oclass & PK_KEY_OBJ)) &&
	    (certrv == KMF_ERR_CERT_NOT_FOUND && (oclass & PK_CERT_OBJ)))
		kmfrv = KMF_ERR_KEY_NOT_FOUND;

	if (kmfrv != KMF_OK)
		goto out;

	if (keyrv != KMF_OK && (oclass == PK_KEY_OBJ))
		kmfrv = keyrv;
	else if (certrv != KMF_OK && (oclass == PK_CERT_OBJ))
		kmfrv = certrv;
	else if (crlrv != KMF_OK && (oclass == PK_CRL_OBJ))
		kmfrv = crlrv;

out:
	if (kmfrv != KMF_OK) {
		display_error(kmfhandle, kmfrv,
		    gettext("Error deleting objects"));
	}

	if (serial.val != NULL)
		free(serial.val);
	(void) kmf_finalize(kmfhandle);
	return (kmfrv);
}

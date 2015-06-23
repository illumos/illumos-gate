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
 * PKCS11 token KMF Plugin
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h> /* debugging only */
#include <errno.h>
#include <values.h>

#include <kmfapiP.h>
#include <ber_der.h>
#include <fcntl.h>
#include <sha1.h>
#include <bignum.h>

#include <cryptoutil.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

#define	DEV_RANDOM	"/dev/random"

#define	SETATTR(t, n, atype, value, size) \
	t[n].type = atype; \
	t[n].pValue = (CK_BYTE *)value; \
	t[n].ulValueLen = (CK_ULONG)size;

#define	SET_ERROR(h, c) h->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN; \
	h->lasterr.errcode = c;

typedef struct _objlist {
	CK_OBJECT_HANDLE handle;
	struct _objlist *next;
} OBJLIST;

static KMF_RETURN
search_certs(KMF_HANDLE_T, char *, char *, char *, KMF_BIGINT *,
	boolean_t, KMF_CERT_VALIDITY, OBJLIST **, uint32_t *);

static CK_RV
getObjectLabel(KMF_HANDLE_T, CK_OBJECT_HANDLE, char **);

static KMF_RETURN
keyObj2RawKey(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_KEY_DATA **);

static KMF_RETURN
create_generic_secret_key(KMF_HANDLE_T,
	int, KMF_ATTRIBUTE *, CK_OBJECT_HANDLE *);

KMF_RETURN
KMFPK11_ConfigureKeystore(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_FindCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

void
KMFPK11_FreeKMFCert(KMF_HANDLE_T,
	KMF_X509_DER_CERT *kmf_cert);

KMF_RETURN
KMFPK11_StoreCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_ImportCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_DeleteCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_CreateKeypair(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_StoreKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_DeleteKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_EncodePubKeyData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
KMFPK11_SignData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
KMFPK11_GetErrorString(KMF_HANDLE_T, char **);

KMF_RETURN
KMFPK11_FindPrikeyByCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_DecryptData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
KMFPK11_FindKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_CreateSymKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_SYM_KEY *);

KMF_RETURN
KMFPK11_SetTokenPin(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
KMFPK11_ExportPK12(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);


static
KMF_PLUGIN_FUNCLIST pk11token_plugin_table =
{
	1,			/* Version */
	KMFPK11_ConfigureKeystore,
	KMFPK11_FindCert,
	KMFPK11_FreeKMFCert,
	KMFPK11_StoreCert,
	KMFPK11_ImportCert,
	NULL,			/* ImportCRL */
	KMFPK11_DeleteCert,
	NULL,			/* DeleteCRL */
	KMFPK11_CreateKeypair,
	KMFPK11_FindKey,
	KMFPK11_EncodePubKeyData,
	KMFPK11_SignData,
	KMFPK11_DeleteKey,
	NULL,			/* ListCRL */
	NULL,			/* FindCRL */
	NULL,			/* FindCertInCRL */
	KMFPK11_GetErrorString,
	KMFPK11_FindPrikeyByCert,
	KMFPK11_DecryptData,
	KMFPK11_ExportPK12,
	KMFPK11_CreateSymKey,
	KMFPK11_GetSymKeyValue,
	KMFPK11_SetTokenPin,
	KMFPK11_StoreKey,
	NULL			/* Finalize */
};

KMF_PLUGIN_FUNCLIST *
KMF_Plugin_Initialize()
{
	return (&pk11token_plugin_table);
}

KMF_RETURN
KMFPK11_ConfigureKeystore(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	char *label;
	boolean_t readonly = B_TRUE;

	label = kmf_get_attr_ptr(KMF_TOKEN_LABEL_ATTR, attrlist, numattr);
	if (label == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* "readonly" is optional. Default is TRUE */
	(void) kmf_get_attr(KMF_READONLY_ATTR, attrlist, numattr,
	    (void *)&readonly, NULL);

	rv = kmf_select_token(handle, label, readonly);

	return (rv);
}

static KMF_RETURN
pk11_authenticate(KMF_HANDLE_T handle,
	KMF_CREDENTIAL *cred)
{

	CK_RV ck_rv = CKR_OK;
	CK_SESSION_HANDLE hSession = (CK_SESSION_HANDLE)handle->pk11handle;

	if (hSession == NULL)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (cred == NULL || cred->cred == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if ((ck_rv = C_Login(hSession, CKU_USER, (uchar_t *)cred->cred,
	    cred->credlen)) != CKR_OK) {
		if (ck_rv != CKR_USER_ALREADY_LOGGED_IN) {
			handle->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			handle->lasterr.errcode = ck_rv;
			return (KMF_ERR_AUTH_FAILED);
		}
	}

	return (KMF_OK);
}

static KMF_RETURN
PK11Cert2KMFCert(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE hObj,
		KMF_X509_DER_CERT *kmfcert)
{
	KMF_RETURN rv = 0;
	CK_RV ckrv = CKR_OK;

	CK_CERTIFICATE_TYPE cktype;
	CK_OBJECT_CLASS	class;
	CK_ULONG subject_len, value_len, issuer_len, serno_len, id_len;
	CK_BYTE *subject = NULL, *value = NULL;
	char *label = NULL;
	CK_ATTRIBUTE templ[10];

	(void) memset(templ, 0, 10 * sizeof (CK_ATTRIBUTE));
	SETATTR(templ, 0, CKA_CLASS, &class, sizeof (class));

	/*  Is this a certificate object ? */
	ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, 1);
	if (ckrv != CKR_OK || class != CKO_CERTIFICATE)  {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	SETATTR(templ, 0, CKA_CERTIFICATE_TYPE, &cktype, sizeof (cktype));
	ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, 1);

	if (ckrv != CKR_OK || cktype != CKC_X_509)  {
		SET_ERROR(kmfh, ckrv);
		return (ckrv);
	} else {
		int i = 0;
		/* What attributes are available and how big are they? */
		subject_len = issuer_len = serno_len = id_len = value_len = 0;

		SETATTR(templ, i, CKA_SUBJECT,	NULL, subject_len);
		i++;
		SETATTR(templ, i, CKA_ISSUER,	NULL, issuer_len);
		i++;
		SETATTR(templ, i, CKA_SERIAL_NUMBER, NULL, serno_len);
		i++;
		SETATTR(templ, i, CKA_ID, NULL, id_len);
		i++;
		SETATTR(templ, i, CKA_VALUE, NULL, value_len);
		i++;

		/*
		 * Query the object with NULL values in the pValue spot
		 * so we know how much space to allocate for each field.
		 */
		ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, i);
		if (ckrv != CKR_OK)  {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL); /* TODO - Error messages ? */
		}

		subject_len	= templ[0].ulValueLen;
		issuer_len	= templ[1].ulValueLen;
		serno_len	= templ[2].ulValueLen;
		id_len		= templ[3].ulValueLen;
		value_len	= templ[4].ulValueLen;

		/*
		 * For PKCS#11 CKC_X_509 certificate objects,
		 * the following attributes must be defined.
		 * CKA_SUBJECT, CKA_ID, CKA_ISSUER, CKA_SERIAL_NUMBER,
		 * CKA_VALUE.
		 */
		if (subject_len == 0 || issuer_len == 0 ||
		    serno_len == 0 || value_len == 0) {
			return (KMF_ERR_INTERNAL);
		}

		/* Only fetch the value field if we are saving the data */
		if (kmfcert != NULL) {
			int i = 0;
			value = malloc(value_len);
			if (value == NULL) {
				rv = KMF_ERR_MEMORY;
				goto errout;
			}

			SETATTR(templ, i, CKA_VALUE, value, value_len);
			i++;

			/* re-query the object with room for the value attr */
			ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj,
			    templ, i);

			if (ckrv != CKR_OK)  {
				SET_ERROR(kmfh, ckrv);
				rv = KMF_ERR_INTERNAL;
				goto errout;
			}

			kmfcert->certificate.Data = value;
			kmfcert->certificate.Length = value_len;
			kmfcert->kmf_private.flags |= KMF_FLAG_CERT_SIGNED;
			kmfcert->kmf_private.keystore_type =
			    KMF_KEYSTORE_PK11TOKEN;

			ckrv = getObjectLabel(kmfh, hObj, &label);
			if (ckrv == CKR_OK && label != NULL) {
				kmfcert->kmf_private.label = (char *)label;
			}

			rv = KMF_OK;
		}
	}

errout:
	if (rv != KMF_OK) {
		if (subject)
			free(subject);
		if (value)
			free(value);

		if (kmfcert) {
			kmfcert->certificate.Data = NULL;
			kmfcert->certificate.Length = 0;
		}
	}
	return (rv);
}

static void
free_objlist(OBJLIST *head)
{
	OBJLIST *temp = head;

	while (temp != NULL) {
		head = head->next;
		free(temp);
		temp = head;
	}
}

/*
 * The caller should make sure that the templ->pValue is NULL since
 * it will be overwritten below.
 */
static KMF_RETURN
get_attr(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj,
	CK_ATTRIBUTE *templ)
{
	CK_RV rv;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, templ, 1);
	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		return (KMF_ERR_INTERNAL);
	}

	if (templ->ulValueLen > 0) {
		templ->pValue = malloc(templ->ulValueLen);
		if (templ->pValue == NULL)
			return (KMF_ERR_MEMORY);

		rv = C_GetAttributeValue(kmfh->pk11handle, obj, templ, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, rv);
			return (KMF_ERR_INTERNAL);
		}
	}

	return (KMF_OK);
}

/*
 * Match a certificate with an issuer and/or subject name.
 * This is tricky because we cannot reliably compare DER encodings
 * because RDNs may have their AV-pairs in different orders even
 * if the values are the same.  You must compare individual
 * AV pairs for the RDNs.
 *
 * RETURN: 0 for a match, non-zero for a non-match.
 */
static KMF_RETURN
matchcert(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj,
	KMF_X509_NAME *issuer, KMF_X509_NAME *subject)
{
	KMF_RETURN rv = KMF_OK;
	CK_ATTRIBUTE certattr;
	KMF_DATA name;
	KMF_X509_NAME dn;

	if (issuer->numberOfRDNs > 0) {
		certattr.type = CKA_ISSUER;
		certattr.pValue = NULL;
		certattr.ulValueLen = 0;

		rv = get_attr(kmfh, obj, &certattr);

		if (rv == KMF_OK) {
			name.Data = certattr.pValue;
			name.Length = certattr.ulValueLen;
			rv = DerDecodeName(&name, &dn);
			if (rv == KMF_OK) {
				rv = kmf_compare_rdns(issuer, &dn);
				kmf_free_dn(&dn);
			}
			free(certattr.pValue);
		}

		if (rv != KMF_OK)
			return (rv);
	}
	if (subject->numberOfRDNs > 0) {
		certattr.type = CKA_SUBJECT;
		certattr.pValue = NULL;
		certattr.ulValueLen = 0;

		rv = get_attr(kmfh, obj, &certattr);

		if (rv == KMF_OK) {
			name.Data = certattr.pValue;
			name.Length = certattr.ulValueLen;
			rv = DerDecodeName(&name, &dn);
			if (rv == KMF_OK) {
				rv = kmf_compare_rdns(subject, &dn);
				kmf_free_dn(&dn);
			}
			free(certattr.pValue);
		}
	}

	return (rv);
}

/*
 * delete "curr" node from the "newlist".
 */
static void
pk11_delete_obj_from_list(OBJLIST **newlist,
	OBJLIST **prev, OBJLIST **curr)
{

	if (*curr == *newlist) {
		/* first node in the list */
		*newlist = (*curr)->next;
		*prev = (*curr)->next;
		free(*curr);
		*curr = *newlist;
	} else {
		(*prev)->next = (*curr)->next;
		free(*curr);
		*curr = (*prev)->next;
	}
}

/*
 * search_certs
 *
 * Because this code is shared by the FindCert and
 * DeleteCert functions, put it in a separate routine
 * to save some work and make code easier to debug and
 * read.
 */
static KMF_RETURN
search_certs(KMF_HANDLE_T handle,
	char *label, char *issuer, char *subject, KMF_BIGINT *serial,
	boolean_t private, KMF_CERT_VALIDITY validity,
	OBJLIST **objlist, uint32_t *numobj)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv = CKR_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_ATTRIBUTE templ[10];
	CK_BBOOL true = TRUE;
	CK_OBJECT_CLASS	oclass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE ctype = CKC_X_509;
	KMF_X509_NAME subjectDN, issuerDN;
	int i;
	OBJLIST *newlist, *tail;
	CK_ULONG num = 0;
	uint32_t num_ok_certs = 0; /* number of non-expired or expired certs */

	(void) memset(&templ, 0, 10 * sizeof (CK_ATTRIBUTE));
	(void) memset(&issuerDN, 0, sizeof (KMF_X509_NAME));
	(void) memset(&subjectDN, 0, sizeof (KMF_X509_NAME));
	i = 0;
	SETATTR(templ, i, CKA_TOKEN, &true, sizeof (true)); i++;
	SETATTR(templ, i, CKA_CLASS, &oclass, sizeof (oclass)); i++;
	SETATTR(templ, i, CKA_CERTIFICATE_TYPE, &ctype,	sizeof (ctype)); i++;

	if (label != NULL && strlen(label)) {
		SETATTR(templ, i, CKA_LABEL, label, strlen(label));
		i++;
	}
	if (private) {
		SETATTR(templ, i, CKA_PRIVATE, &true, sizeof (true)); i++;
	}

	if (issuer != NULL && strlen(issuer)) {
		if ((rv = kmf_dn_parser(issuer, &issuerDN)) != KMF_OK)
			return (rv);
	}
	if (subject != NULL && strlen(subject)) {
		if ((rv = kmf_dn_parser(subject, &subjectDN)) != KMF_OK)
			return (rv);
	}

	if (serial != NULL && serial->val != NULL && serial->len > 0) {
		SETATTR(templ, i, CKA_SERIAL_NUMBER, serial->val, serial->len);
		i++;
	}

	(*numobj) = 0;
	*objlist = NULL;
	newlist = NULL;

	ckrv = C_FindObjectsInit(kmfh->pk11handle, templ, i);
	if (ckrv != CKR_OK)
		goto cleanup;

	tail = newlist = NULL;
	while (ckrv == CKR_OK) {
		CK_OBJECT_HANDLE tObj;
		ckrv = C_FindObjects(kmfh->pk11handle, &tObj, 1, &num);
		if (ckrv != CKR_OK || num == 0)
			break;

		/*
		 * 'matchcert' returns 0 if subject/issuer match
		 *
		 * If no match, move on to the next one
		 */
		if (matchcert(kmfh, tObj, &issuerDN, &subjectDN))
			continue;

		if (newlist == NULL) {
			newlist = malloc(sizeof (OBJLIST));
			if (newlist == NULL) {
				rv = KMF_ERR_MEMORY;
				break;
			}
			newlist->handle = tObj;
			newlist->next = NULL;
			tail = newlist;
		} else {
			tail->next = malloc(sizeof (OBJLIST));
			if (tail->next != NULL) {
				tail = tail->next;
			} else {
				rv = KMF_ERR_MEMORY;
				break;
			}
			tail->handle = tObj;
			tail->next = NULL;
		}
		(*numobj)++;
	}
	ckrv = C_FindObjectsFinal(kmfh->pk11handle);

cleanup:
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		if (newlist != NULL) {
			free_objlist(newlist);
			*numobj = 0;
			newlist = NULL;
		}
	} else {
		if (validity == KMF_ALL_CERTS) {
			*objlist = newlist;
		} else {
			OBJLIST *node, *prev;
			KMF_X509_DER_CERT  tmp_kmf_cert;
			uint32_t i = 0;

			node = prev = newlist;
			/*
			 * Now check to see if any found certificate is expired
			 * or valid.
			 */
			while (node != NULL && i < (*numobj)) {
				(void) memset(&tmp_kmf_cert, 0,
				    sizeof (KMF_X509_DER_CERT));
				rv = PK11Cert2KMFCert(kmfh, node->handle,
				    &tmp_kmf_cert);
				if (rv != KMF_OK) {
					goto cleanup1;
				}

				rv = kmf_check_cert_date(handle,
				    &tmp_kmf_cert.certificate);

				if (validity == KMF_NONEXPIRED_CERTS) {
					if (rv == KMF_OK)  {
						num_ok_certs++;
						prev = node;
						node = node->next;
					} else if (rv ==
					    KMF_ERR_VALIDITY_PERIOD) {
						/*
						 * expired - remove it from list
						 */
						pk11_delete_obj_from_list(
						    &newlist, &prev, &node);
					} else {
						goto cleanup1;
					}
				}

				if (validity == KMF_EXPIRED_CERTS) {
					if (rv == KMF_ERR_VALIDITY_PERIOD)  {
						num_ok_certs++;
						prev = node;
						node = node->next;
						rv = KMF_OK;
					} else if (rv == KMF_OK) {
						/*
						 * valid - remove it from list
						 */
						pk11_delete_obj_from_list(
						    &newlist, &prev, &node);
					} else {
						goto cleanup1;
					}
				}
				i++;
				kmf_free_kmf_cert(handle, &tmp_kmf_cert);
			}
			*numobj = num_ok_certs;
			*objlist = newlist;
		}
	}

cleanup1:
	if (rv != KMF_OK && newlist != NULL) {
		free_objlist(newlist);
		*numobj = 0;
		*objlist = NULL;
	}

	if (issuer != NULL)
		kmf_free_dn(&issuerDN);

	if (subject != NULL)
		kmf_free_dn(&subjectDN);

	return (rv);
}

/*
 * The caller may pass a NULL value for kmf_cert below and the function will
 * just return the number of certs found (in num_certs).
 */
KMF_RETURN
KMFPK11_FindCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = 0;
	uint32_t want_certs;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OBJLIST *objlist = NULL;
	uint32_t *num_certs;
	KMF_X509_DER_CERT *kmf_cert = NULL;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY validity;
	KMF_CREDENTIAL *cred = NULL;
	boolean_t private;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	num_certs = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (num_certs == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (*num_certs > 0)
		want_certs = *num_certs;
	else
		want_certs = MAXINT; /* count them all */

	*num_certs = 0;

	/* Get the optional returned certificate list */
	kmf_cert = kmf_get_attr_ptr(KMF_X509_DER_CERT_ATTR, attrlist,
	    numattr);

	/* Get optional search criteria attributes */
	certlabel = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);
	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);

	rv = kmf_get_attr(KMF_CERT_VALIDITY_ATTR, attrlist, numattr,
	    &validity, NULL);
	if (rv != KMF_OK) {
		validity = KMF_ALL_CERTS;
		rv = KMF_OK;
	}

	rv = kmf_get_attr(KMF_PRIVATE_BOOL_ATTR, attrlist, numattr,
	    (void *)&private, NULL);
	if (rv != KMF_OK) {
		private = B_FALSE;
		rv = KMF_OK;
	}

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred != NULL) {
		rv = pk11_authenticate(handle, cred);
		if (rv != KMF_OK)
			return (rv);
	}

	/* Start searching */
	rv = search_certs(handle, certlabel, issuer, subject, serial, private,
	    validity, &objlist, num_certs);

	if (rv == KMF_OK && objlist != NULL && kmf_cert != NULL) {
		OBJLIST *node = objlist;
		int i = 0;
		while (node != NULL && i < want_certs) {
			rv = PK11Cert2KMFCert(kmfh, node->handle,
			    &kmf_cert[i]);
			i++;
			node = node->next;
		}
	}

	if (objlist != NULL)
		free_objlist(objlist);

	if (*num_certs == 0)
		rv = KMF_ERR_CERT_NOT_FOUND;

	return (rv);
}

/*ARGSUSED*/
void
KMFPK11_FreeKMFCert(KMF_HANDLE_T handle, KMF_X509_DER_CERT *kmf_cert)
{
	if (kmf_cert != NULL && kmf_cert->certificate.Data != NULL) {
		free(kmf_cert->certificate.Data);
		kmf_cert->certificate.Data = NULL;
		kmf_cert->certificate.Length = 0;

		if (kmf_cert->kmf_private.label != NULL) {
			free(kmf_cert->kmf_private.label);
			kmf_cert->kmf_private.label = NULL;
		}
	}
}

KMF_RETURN
KMFPK11_EncodePubKeyData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *pKey,
	KMF_DATA *eData)
{
	KMF_RETURN ret = KMF_OK;
	CK_RV rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_OBJECT_CLASS ckObjClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE ckKeyType;
	KMF_DATA Modulus, Exponent, Prime, Subprime, Base, Value;
	KMF_OID *Algorithm;
	BerElement *asn1 = NULL;
	BerValue *PubKeyParams = NULL, *EncodedKey = NULL;
	KMF_X509_SPKI spki;
	CK_BYTE ec_params[256], ec_point[256];

	CK_ATTRIBUTE rsaTemplate[4];
	CK_ATTRIBUTE dsaTemplate[6];
	CK_ATTRIBUTE ecdsaTemplate[6];

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (pKey == NULL || pKey->keyp == CK_INVALID_HANDLE)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&Modulus, 0, sizeof (Modulus));
	(void) memset(&Exponent, 0, sizeof (Exponent));
	(void) memset(&Prime, 0, sizeof (Prime));
	(void) memset(&Subprime, 0, sizeof (Subprime));
	(void) memset(&Base, 0, sizeof (Base));
	(void) memset(&Value, 0, sizeof (Value));

	switch (pKey->keyalg) {
		case KMF_RSA:
			SETATTR(rsaTemplate, 0, CKA_CLASS, &ckObjClass,
			    sizeof (ckObjClass));
			SETATTR(rsaTemplate, 1, CKA_KEY_TYPE, &ckKeyType,
			    sizeof (ckKeyType));
			SETATTR(rsaTemplate, 2, CKA_MODULUS, Modulus.Data,
			    Modulus.Length);
			SETATTR(rsaTemplate, 3, CKA_PUBLIC_EXPONENT,
			    Exponent.Data, Exponent.Length);
			/* Get the length of the fields */
			rv = C_GetAttributeValue(kmfh->pk11handle,
			    (CK_OBJECT_HANDLE)pKey->keyp, rsaTemplate, 4);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}

			Modulus.Length = rsaTemplate[2].ulValueLen;
			Modulus.Data = malloc(Modulus.Length);
			if (Modulus.Data == NULL)
				return (KMF_ERR_MEMORY);

			Exponent.Length = rsaTemplate[3].ulValueLen;
			Exponent.Data = malloc(Exponent.Length);
			if (Exponent.Data == NULL) {
				free(Modulus.Data);
				return (KMF_ERR_MEMORY);
			}

			SETATTR(rsaTemplate, 2, CKA_MODULUS, Modulus.Data,
			    Modulus.Length);
			SETATTR(rsaTemplate, 3, CKA_PUBLIC_EXPONENT,
			    Exponent.Data, Exponent.Length);
			/* Now get the values */
			rv = C_GetAttributeValue(kmfh->pk11handle,
			    (CK_OBJECT_HANDLE)pKey->keyp, rsaTemplate, 4);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				free(Modulus.Data);
				free(Exponent.Data);
				return (KMF_ERR_BAD_PARAMETER);
			}

			/*
			 * This is the KEY algorithm, not the
			 * signature algorithm.
			 */
			Algorithm = x509_algid_to_algoid(KMF_ALGID_RSA);
			if (Algorithm != NULL) {

				/* Encode the RSA Key Data */
				if ((asn1 = kmfder_alloc()) == NULL) {
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_MEMORY);
				}
				if (kmfber_printf(asn1, "{II}",	Modulus.Data,
				    Modulus.Length, Exponent.Data,
				    Exponent.Length) == -1) {
					kmfber_free(asn1, 1);
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_ENCODING);
				}
				if (kmfber_flatten(asn1, &EncodedKey) == -1) {
					kmfber_free(asn1, 1);
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_ENCODING);
				}
				kmfber_free(asn1, 1);
			}

			free(Exponent.Data);
			free(Modulus.Data);

			break;
		case KMF_DSA:
			SETATTR(dsaTemplate, 0, CKA_CLASS, &ckObjClass,
			    sizeof (ckObjClass));
			SETATTR(dsaTemplate, 1, CKA_KEY_TYPE, &ckKeyType,
			    sizeof (ckKeyType));
			SETATTR(dsaTemplate, 2, CKA_PRIME, Prime.Data,
			    Prime.Length);
			SETATTR(dsaTemplate, 3, CKA_SUBPRIME, Subprime.Data,
			    Subprime.Length);
			SETATTR(dsaTemplate, 4, CKA_BASE, Base.Data,
			    Base.Length);
			SETATTR(dsaTemplate, 5, CKA_VALUE, Value.Data,
			    Value.Length);

			/* Get the length of the fields */
			rv = C_GetAttributeValue(kmfh->pk11handle,
			    (CK_OBJECT_HANDLE)pKey->keyp, dsaTemplate, 6);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}
			Prime.Length = dsaTemplate[2].ulValueLen;
			Prime.Data = malloc(Prime.Length);
			if (Prime.Data == NULL) {
				return (KMF_ERR_MEMORY);
			}

			Subprime.Length = dsaTemplate[3].ulValueLen;
			Subprime.Data = malloc(Subprime.Length);
			if (Subprime.Data == NULL) {
				free(Prime.Data);
				return (KMF_ERR_MEMORY);
			}

			Base.Length = dsaTemplate[4].ulValueLen;
			Base.Data = malloc(Base.Length);
			if (Base.Data == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				return (KMF_ERR_MEMORY);
			}

			Value.Length = dsaTemplate[5].ulValueLen;
			Value.Data = malloc(Value.Length);
			if (Value.Data == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				return (KMF_ERR_MEMORY);
			}
			SETATTR(dsaTemplate, 2, CKA_PRIME, Prime.Data,
			    Prime.Length);
			SETATTR(dsaTemplate, 3, CKA_SUBPRIME, Subprime.Data,
			    Subprime.Length);
			SETATTR(dsaTemplate, 4, CKA_BASE, Base.Data,
			    Base.Length);
			SETATTR(dsaTemplate, 5, CKA_VALUE, Value.Data,
			    Value.Length);

			/* Now get the values */
			rv = C_GetAttributeValue(kmfh->pk11handle,
			    (CK_OBJECT_HANDLE)pKey->keyp, dsaTemplate, 6);
			if (rv != CKR_OK) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}
			/*
			 * This is the KEY algorithm, not the
			 * signature algorithm.
			 */
			Algorithm = x509_algid_to_algoid(KMF_ALGID_DSA);

			/* Encode the DSA Algorithm Parameters */
			if ((asn1 = kmfder_alloc()) == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_MEMORY);
			}

			if (kmfber_printf(asn1, "{III}", Prime.Data,
			    Prime.Length, Subprime.Data, Subprime.Length,
			    Base.Data, Base.Length) == -1) {

				kmfber_free(asn1, 1);
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			if (kmfber_flatten(asn1, &PubKeyParams) == -1) {
				kmfber_free(asn1, 1);
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			kmfber_free(asn1, 1);
			free(Prime.Data);
			free(Subprime.Data);
			free(Base.Data);

			/* Encode the DSA Key Value */
			if ((asn1 = kmfder_alloc()) == NULL) {
				free(Value.Data);
				return (KMF_ERR_MEMORY);
			}

			if (kmfber_printf(asn1, "I",
			    Value.Data, Value.Length) == -1) {
				kmfber_free(asn1, 1);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			if (kmfber_flatten(asn1, &EncodedKey) == -1) {
				kmfber_free(asn1, 1);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			kmfber_free(asn1, 1);
			free(Value.Data);
			break;
		case KMF_ECDSA:
			/* The EC_PARAMS are the PubKey algorithm parameters */
			PubKeyParams = calloc(1, sizeof (BerValue));
			if (PubKeyParams == NULL)
				return (KMF_ERR_MEMORY);
			EncodedKey = calloc(1, sizeof (BerValue));
			if (EncodedKey == NULL) {
				free(PubKeyParams);
				return (KMF_ERR_MEMORY);
			}
			SETATTR(ecdsaTemplate, 0, CKA_EC_PARAMS,
			    &ec_params, sizeof (ec_params));
			SETATTR(ecdsaTemplate, 1, CKA_EC_POINT,
			    &ec_point, sizeof (ec_point));

			/* Get the length of the fields */
			rv = C_GetAttributeValue(kmfh->pk11handle,
			    (CK_OBJECT_HANDLE)pKey->keyp,
			    ecdsaTemplate, 2);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}
			/* The params are to be used as algorithm parameters */
			PubKeyParams->bv_val = (char *)ec_params;
			PubKeyParams->bv_len = ecdsaTemplate[0].ulValueLen;
			/*
			 * The EC_POINT is to be used as the subject pub key.
			 */
			EncodedKey->bv_val = (char *)ec_point;
			EncodedKey->bv_len = ecdsaTemplate[1].ulValueLen;

			/* Use the EC_PUBLIC_KEY OID */
			Algorithm = (KMF_OID *)&KMFOID_EC_PUBLIC_KEY;
			break;
		default:
			return (KMF_ERR_BAD_PARAMETER);
	}

	/* Now, build an SPKI structure for the final encoding step */
	spki.algorithm.algorithm = *Algorithm;
	if (PubKeyParams != NULL) {
		spki.algorithm.parameters.Data =
		    (uchar_t *)PubKeyParams->bv_val;
		spki.algorithm.parameters.Length = PubKeyParams->bv_len;
	} else {
		spki.algorithm.parameters.Data = NULL;
		spki.algorithm.parameters.Length = 0;
	}

	if (EncodedKey != NULL) {
		spki.subjectPublicKey.Data = (uchar_t *)EncodedKey->bv_val;
		spki.subjectPublicKey.Length = EncodedKey->bv_len;
	} else {
		spki.subjectPublicKey.Data = NULL;
		spki.subjectPublicKey.Length = 0;
	}

	/* Finally, encode the entire SPKI record */
	ret = DerEncodeSPKI(&spki, eData);

cleanup:
	if (EncodedKey) {
		if (pKey->keyalg != KMF_ECDSA)
			free(EncodedKey->bv_val);
		free(EncodedKey);
	}

	if (PubKeyParams) {
		if (pKey->keyalg != KMF_ECDSA)
			free(PubKeyParams->bv_val);
		free(PubKeyParams);
	}

	return (ret);
}

static KMF_RETURN
CreateCertObject(KMF_HANDLE_T handle, char *label, KMF_DATA *pcert)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	KMF_X509_CERTIFICATE *signed_cert_ptr = NULL;
	KMF_DATA data;
	KMF_DATA Id;

	CK_RV ckrv;
	CK_ULONG subject_len, issuer_len, serno_len;
	CK_BYTE *subject, *issuer, *serial, nullserno;
	CK_BBOOL true = TRUE;
	CK_CERTIFICATE_TYPE certtype = CKC_X_509;
	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE x509templ[11];
	CK_OBJECT_HANDLE hCert = NULL;
	int i;

	if (kmfh == NULL)
		return (KMF_ERR_INTERNAL); /* should not happen */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_INTERNAL); /* should not happen */

	if (pcert == NULL || pcert->Data == NULL || pcert->Length == 0)
		return (KMF_ERR_INTERNAL);  /* should not happen */

	/*
	 * The data *must* be a DER encoded X.509 certificate.
	 * Convert it to a CSSM cert and then parse the fields so
	 * the PKCS#11 attributes can be filled in correctly.
	 */
	rv = DerDecodeSignedCertificate((const KMF_DATA *)pcert,
	    &signed_cert_ptr);
	if (rv != KMF_OK) {
		return (KMF_ERR_ENCODING);
	}

	/*
	 * Encode fields into PKCS#11 attributes.
	 */

	/* Get the subject name */
	rv = DerEncodeName(&signed_cert_ptr->certificate.subject, &data);
	if (rv == KMF_OK) {
		subject = data.Data;
		subject_len = data.Length;
	} else {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Encode the issuer */
	rv = DerEncodeName(&signed_cert_ptr->certificate.issuer, &data);
	if (rv == KMF_OK) {
		issuer = data.Data;
		issuer_len = data.Length;
	} else {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Encode serial number */
	if (signed_cert_ptr->certificate.serialNumber.len > 0 &&
	    signed_cert_ptr->certificate.serialNumber.val != NULL) {
		serial = signed_cert_ptr->certificate.serialNumber.val;
		serno_len = signed_cert_ptr->certificate.serialNumber.len;
	} else {
		/*
		 * RFC3280 says to gracefully handle certs with serial numbers
		 * of 0.
		 */
		nullserno = '\0';
		serial  = &nullserno;
		serno_len = 1;
	}

	/* Generate an ID from the SPKI data */
	rv = GetIDFromSPKI(&signed_cert_ptr->certificate.subjectPublicKeyInfo,
	    &Id);

	if (rv != KMF_OK) {
		goto cleanup;
	}

	i = 0;
	SETATTR(x509templ, i, CKA_CLASS, &certClass, sizeof (certClass)); i++;
	SETATTR(x509templ, i, CKA_CERTIFICATE_TYPE, &certtype,
	    sizeof (certtype));
	i++;
	SETATTR(x509templ, i, CKA_TOKEN, &true, sizeof (true)); i++;
	SETATTR(x509templ, i, CKA_SUBJECT, subject, subject_len); i++;
	SETATTR(x509templ, i, CKA_ISSUER, issuer, issuer_len); i++;
	SETATTR(x509templ, i, CKA_SERIAL_NUMBER, serial, serno_len); i++;
	SETATTR(x509templ, i, CKA_VALUE, pcert->Data, pcert->Length); i++;
	SETATTR(x509templ, i, CKA_ID, Id.Data, Id.Length); i++;
	if (label != NULL && strlen(label)) {
		SETATTR(x509templ, i, CKA_LABEL, label, strlen(label));	i++;
	}
	/*
	 * The cert object handle is actually "leaked" here.  If the app
	 * really wants to clean up the data space, it will have to call
	 * KMF_DeleteCert and specify the softtoken keystore.
	 */
	ckrv = C_CreateObject(kmfh->pk11handle, x509templ, i, &hCert);
	if (ckrv != CKR_OK) {
		/* Report authentication failures to the caller */
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
		SET_ERROR(kmfh, ckrv);
	}
	free(subject);
	free(issuer);

cleanup:
	if (Id.Data != NULL)
		free(Id.Data);

	if (signed_cert_ptr) {
		kmf_free_signed_cert(signed_cert_ptr);
		free(signed_cert_ptr);
	}
	return (rv);
}


KMF_RETURN
KMFPK11_StoreCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_DATA *cert = NULL;
	KMF_CREDENTIAL *cred = NULL;
	char *label = NULL;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL || cert->Data == NULL || cert->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	/* label attribute is optional */
	label = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred != NULL) {
		rv = pk11_authenticate(handle, cred);
		if (rv != KMF_OK)
			return (rv);
	}

	rv = CreateCertObject(handle, label, cert);
	return (rv);
}

KMF_RETURN
KMFPK11_ImportCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *certfile = NULL;
	char *label = NULL;
	KMF_ENCODE_FORMAT format;
	KMF_CREDENTIAL *cred = NULL;
	KMF_DATA  cert1 = { 0, NULL };
	KMF_DATA  cert2 = { 0, NULL };

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	/*
	 * Get the input cert filename attribute, check if it is a valid
	 * certificate and auto-detect the file format of it.
	 */
	certfile = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist, numattr);
	if (certfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_is_cert_file(handle, certfile, &format);
	if (rv != KMF_OK)
		return (rv);

	/* Read in the CERT file */
	rv = kmf_read_input_file(handle, certfile, &cert1);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* The label attribute is optional */
	label = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);

	/*
	 * If the input certificate is in PEM format, we need to convert
	 * it to DER first.
	 */
	if (format == KMF_FORMAT_PEM) {
		int derlen;
		rv = kmf_pem_to_der(cert1.Data, cert1.Length,
		    &cert2.Data, &derlen);
		if (rv != KMF_OK) {
			goto out;
		}
		cert2.Length = (size_t)derlen;
	}

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred != NULL) {
		rv = pk11_authenticate(handle, cred);
		if (rv != KMF_OK)
			return (rv);
	}

	rv = CreateCertObject(handle, label,
	    format == KMF_FORMAT_ASN1 ? &cert1 : &cert2);

out:
	if (cert1.Data != NULL) {
		free(cert1.Data);
	}

	if (cert2.Data != NULL) {
		free(cert2.Data);
	}

	return (rv);
}

KMF_RETURN
KMFPK11_DeleteCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OBJLIST *objlist;
	uint32_t numObjects = 0;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY validity;
	boolean_t private;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);


	/* Get the search criteria attributes. They are all optional. */
	certlabel = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);
	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);

	rv = kmf_get_attr(KMF_CERT_VALIDITY_ATTR, attrlist, numattr,
	    &validity, NULL);
	if (rv != KMF_OK) {
		validity = KMF_ALL_CERTS;
		rv = KMF_OK;
	}

	rv = kmf_get_attr(KMF_PRIVATE_BOOL_ATTR, attrlist, numattr,
	    (void *)&private, NULL);
	if (rv != KMF_OK) {
		private = B_FALSE;
		rv = KMF_OK;
	}

	/*
	 * Start searching for certificates that match the criteria and
	 * delete them.
	 */
	objlist = NULL;
	rv = search_certs(handle, certlabel, issuer, subject, serial,
	    private, validity, &objlist, &numObjects);

	if (rv == KMF_OK && objlist != NULL) {
		OBJLIST *node = objlist;

		while (node != NULL) {
			CK_RV ckrv;
			ckrv = C_DestroyObject(kmfh->pk11handle, node->handle);
			if (ckrv != CKR_OK) {
				SET_ERROR(kmfh, ckrv);
				rv = KMF_ERR_INTERNAL;
				break;
			}
			node = node->next;
		}
		free_objlist(objlist);
	}

	if (rv == KMF_OK && numObjects == 0)
		rv = KMF_ERR_CERT_NOT_FOUND;

out:
	return (rv);
}

static CK_RV
gendsa_keypair(KMF_HANDLE *kmfh, boolean_t storekey,
	CK_OBJECT_HANDLE *pubKey,
	CK_OBJECT_HANDLE *priKey)
{
	CK_RV ckrv = CKR_OK;
	CK_SESSION_HANDLE hSession = kmfh->pk11handle;
	static CK_ULONG	dsaKeyType = CKK_DSA;
	static CK_BBOOL	true = TRUE;
	static CK_BBOOL	false = FALSE;
	static CK_OBJECT_CLASS	priClass = CKO_PRIVATE_KEY;
	static CK_OBJECT_CLASS	pubClass = CKO_PUBLIC_KEY;

	static CK_BYTE ckDsaPrime[128] = {
	0xb2, 0x6b, 0xc3, 0xfb, 0xe3, 0x26, 0xf4, 0xc2,
	0xcf, 0xdd, 0xf9, 0xae, 0x3e, 0x39, 0x7f, 0x9c,
	0xa7, 0x73, 0xc3, 0x00, 0xa3, 0x50, 0x67, 0xc3,
	0xab, 0x49, 0x2c, 0xea, 0x59, 0x10, 0xa4, 0xbc,
	0x09, 0x94, 0xa9, 0x05, 0x3b, 0x0d, 0x35, 0x3c,
	0x55, 0x52, 0x47, 0xf0, 0xe3, 0x72, 0x5b, 0xe8,
	0x72, 0xa0, 0x71, 0x1c, 0x23, 0x4f, 0x6d, 0xe8,
	0xac, 0xe5, 0x21, 0x1b, 0xc0, 0xd8, 0x42, 0xd3,
	0x87, 0xae, 0x83, 0x5e, 0x52, 0x7e, 0x46, 0x09,
	0xb5, 0xc7, 0x3d, 0xd6, 0x00, 0xf5, 0xf2, 0x9c,
	0x84, 0x30, 0x81, 0x7e, 0x7b, 0x30, 0x5b, 0xd5,
	0xab, 0xd0, 0x2f, 0x21, 0xb3, 0xd8, 0xed, 0xdb,
	0x97, 0x77, 0xe4, 0x7e, 0x6c, 0xcc, 0xb9, 0x6b,
	0xdd, 0xaa, 0x96, 0x04, 0xe7, 0xd4, 0x55, 0x11,
	0x53, 0xab, 0xba, 0x95, 0x9a, 0xa2, 0x8c, 0x27,
	0xd9, 0xcf, 0xad, 0xf3, 0xcf, 0x3a, 0x0c, 0x4b};

	static CK_BYTE ckDsaSubPrime[20] = {
	0xa4, 0x5f, 0x2a, 0x27, 0x09, 0x49, 0xb6, 0xfe,
	0x73, 0xeb, 0x95, 0x7d, 0x00, 0xf3, 0x42, 0xfc,
	0x78, 0x47, 0xb0, 0xd5};

	static CK_BYTE ckDsaBase[128] = {
	0x5c, 0x57, 0x16, 0x49, 0xef, 0xc8, 0xfb, 0x4b,
	0xee, 0x07, 0x45, 0x3b, 0x6a, 0x1d, 0xf3, 0xe5,
	0xeb, 0xee, 0xad, 0x11, 0x13, 0xe3, 0x52, 0xe3,
	0x0d, 0xc0, 0x21, 0x25, 0xfa, 0xf0, 0x93, 0x1c,
	0x53, 0x4d, 0xdc, 0x0d, 0x76, 0xd2, 0xfe, 0xc2,
	0xd7, 0x72, 0x64, 0x69, 0x53, 0x3d, 0x33, 0xbd,
	0xe1, 0x34, 0xf2, 0x5a, 0x67, 0x83, 0xe0, 0xd3,
	0x1c, 0xd6, 0x41, 0x4d, 0x16, 0xe8, 0x6c, 0x5a,
	0x07, 0x95, 0x21, 0x9a, 0xa3, 0xc4, 0xb9, 0x05,
	0x9d, 0x11, 0xcb, 0xc8, 0xc4, 0x9d, 0x00, 0x1a,
	0xf4, 0x85, 0x2a, 0xa9, 0x20, 0x3c, 0xba, 0x67,
	0xe5, 0xed, 0x31, 0xb2, 0x11, 0xfb, 0x1f, 0x73,
	0xec, 0x61, 0x29, 0xad, 0xc7, 0x68, 0xb2, 0x3f,
	0x38, 0xea, 0xd9, 0x87, 0x83, 0x9e, 0x7e, 0x19,
	0x18, 0xdd, 0xc2, 0xc3, 0x5b, 0x16, 0x6d, 0xce,
	0xcf, 0x88, 0x91, 0x07, 0xe0, 0x2b, 0xa8, 0x54 };

	static CK_ATTRIBUTE ckDsaPubKeyTemplate[] = {
	{ CKA_CLASS, &pubClass, sizeof (pubClass) },
	{ CKA_KEY_TYPE, &dsaKeyType, sizeof (dsaKeyType) },
	{ CKA_TOKEN, &true, sizeof (true)},
	{ CKA_PRIVATE, &false, sizeof (false)},
	{ CKA_PRIME, &ckDsaPrime, sizeof (ckDsaPrime) },
	{ CKA_SUBPRIME, &ckDsaSubPrime, sizeof (ckDsaSubPrime)},
	{ CKA_BASE, &ckDsaBase, sizeof (ckDsaBase) },
	{ CKA_VERIFY, &true, sizeof (true) },
};

#define	NUMBER_DSA_PUB_TEMPLATES (sizeof (ckDsaPubKeyTemplate) / \
					sizeof (CK_ATTRIBUTE))
#define	MAX_DSA_PUB_TEMPLATES (sizeof (ckDsaPubKeyTemplate) / \
				    sizeof (CK_ATTRIBUTE))

	static CK_ATTRIBUTE ckDsaPriKeyTemplate[] = {
	{CKA_CLASS, &priClass, sizeof (priClass)},
	{CKA_KEY_TYPE, &dsaKeyType, sizeof (dsaKeyType)},
	{CKA_TOKEN, &true, sizeof (true)},
	{CKA_PRIVATE, &true, sizeof (true)},
	{CKA_SIGN, &true, sizeof (true)},
	};

#define	NUMBER_DSA_PRI_TEMPLATES (sizeof (ckDsaPriKeyTemplate) / \
					sizeof (CK_ATTRIBUTE))
#define	MAX_DSA_PRI_TEMPLATES (sizeof (ckDsaPriKeyTemplate) / \
				sizeof (CK_ATTRIBUTE))
	CK_MECHANISM keyGenMech = {CKM_DSA_KEY_PAIR_GEN, NULL, 0};

	SETATTR(ckDsaPriKeyTemplate, 2, CKA_TOKEN,
	    (storekey ? &true : &false), sizeof (CK_BBOOL));

	ckrv = C_GenerateKeyPair(hSession, &keyGenMech,
	    ckDsaPubKeyTemplate,
	    (sizeof (ckDsaPubKeyTemplate)/sizeof (CK_ATTRIBUTE)),
	    ckDsaPriKeyTemplate,
	    (sizeof (ckDsaPriKeyTemplate)/sizeof (CK_ATTRIBUTE)),
	    pubKey, priKey);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_KEYGEN_FAILED);
	}

	return (ckrv);
}

static CK_RV
genrsa_keypair(KMF_HANDLE *kmfh, CK_ULONG modulusBits,
	boolean_t storekey, KMF_BIGINT *rsaexp,
	CK_OBJECT_HANDLE *pubKey,
	CK_OBJECT_HANDLE *priKey)
{
	CK_RV ckrv = CKR_OK;
	CK_SESSION_HANDLE hSession = kmfh->pk11handle;
	CK_ATTRIBUTE rsaPubKeyTemplate[16];
	CK_ATTRIBUTE rsaPriKeyTemplate[16];
	CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
	int numpubattr = 0, numpriattr = 0;
	static CK_BYTE	PubExpo[3] = {0x01, 0x00, 0x01};
	static CK_BBOOL	true = TRUE;
	static CK_BBOOL	false = FALSE;

	SETATTR(rsaPubKeyTemplate, numpubattr, CKA_TOKEN,
	    (storekey ? &true : &false), sizeof (CK_BBOOL));
	numpubattr++;

	SETATTR(rsaPubKeyTemplate, numpubattr, CKA_MODULUS_BITS,
	    &modulusBits, sizeof (modulusBits));
	numpubattr++;

	if (rsaexp != NULL && (rsaexp->len > 0 && rsaexp->val != NULL)) {
		SETATTR(rsaPubKeyTemplate, numpubattr,
		    CKA_PUBLIC_EXPONENT,
		    rsaexp->val, rsaexp->len);
		numpubattr++;
	} else {
		SETATTR(rsaPubKeyTemplate, numpubattr,
		    CKA_PUBLIC_EXPONENT, &PubExpo, sizeof (PubExpo));
		numpubattr++;
	}
	SETATTR(rsaPubKeyTemplate, numpubattr, CKA_ENCRYPT,
	    &true, sizeof (true));
	numpubattr++;
	SETATTR(rsaPubKeyTemplate, numpubattr, CKA_VERIFY,
	    &true, sizeof (true));
	numpubattr++;
	SETATTR(rsaPubKeyTemplate, numpubattr, CKA_WRAP,
	    &true, sizeof (true));
	numpubattr++;

	SETATTR(rsaPriKeyTemplate, numpriattr, CKA_TOKEN,
	    (storekey ? &true : &false), sizeof (CK_BBOOL));
	numpriattr++;
	SETATTR(rsaPriKeyTemplate, numpriattr, CKA_PRIVATE, &true,
	    sizeof (true));
	numpriattr++;
	SETATTR(rsaPriKeyTemplate, numpriattr, CKA_DECRYPT, &true,
	    sizeof (true));
	numpriattr++;
	SETATTR(rsaPriKeyTemplate, numpriattr, CKA_SIGN, &true,
	    sizeof (true));
	numpriattr++;
	SETATTR(rsaPriKeyTemplate, numpriattr, CKA_UNWRAP, &true,
	    sizeof (true));
	numpriattr++;

	ckrv = C_GenerateKeyPair(hSession, &keyGenMech,
	    rsaPubKeyTemplate, numpubattr,
	    rsaPriKeyTemplate, numpriattr,
	    pubKey, priKey);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (ckrv);
	}

	return (ckrv);
}

static CK_RV
genecc_keypair(KMF_HANDLE *kmfh,
	boolean_t ontoken,
	KMF_OID *curveoid,
	CK_OBJECT_HANDLE *pubKey,
	CK_OBJECT_HANDLE *priKey)
{
	CK_RV ckrv;
	CK_SESSION_HANDLE hSession = kmfh->pk11handle;
	CK_MECHANISM keyGenMech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
	const ulong_t publicKey = CKO_PUBLIC_KEY;
	const ulong_t privateKey = CKO_PRIVATE_KEY;
	const ulong_t keytype = CKK_EC;
	static CK_BBOOL	true = TRUE;
	static CK_BBOOL	false = FALSE;
	CK_ATTRIBUTE public_template[6];
	CK_ATTRIBUTE private_template[6];
	int numpubattr, numpriattr;

	numpubattr = 0;
	SETATTR(public_template, numpubattr, CKA_CLASS,
	    &publicKey, sizeof (publicKey));
	numpubattr++;
	SETATTR(public_template, numpubattr, CKA_KEY_TYPE,
	    &keytype, sizeof (keytype));
	numpubattr++;
	SETATTR(public_template, numpubattr, CKA_EC_PARAMS,
	    curveoid->Data, curveoid->Length);
	numpubattr++;
	SETATTR(public_template, numpubattr, CKA_TOKEN,
	    ontoken ? &true : &false, sizeof (true));
	numpubattr++;
	SETATTR(public_template, numpubattr, CKA_VERIFY,
	    &true, sizeof (true));
	numpubattr++;
	SETATTR(public_template, numpubattr, CKA_PRIVATE,
	    &false, sizeof (false));
	numpubattr++;

	numpriattr = 0;
	SETATTR(private_template, numpriattr, CKA_CLASS,
	    &privateKey, sizeof (privateKey));
	numpriattr++;
	SETATTR(private_template, numpriattr, CKA_KEY_TYPE,
	    &keytype, sizeof (keytype));
	numpriattr++;
	SETATTR(private_template, numpriattr, CKA_TOKEN,
	    ontoken ? &true : &false, sizeof (true));
	numpriattr++;
	SETATTR(private_template, numpriattr, CKA_PRIVATE,
	    &true, sizeof (true));
	numpriattr++;
	SETATTR(private_template, numpriattr, CKA_SIGN,
	    &true, sizeof (true));
	numpriattr++;
	SETATTR(private_template, numpriattr, CKA_DERIVE,
	    &true, sizeof (true));
	numpriattr++;

	ckrv = C_GenerateKeyPair(hSession, &keyGenMech,
	    public_template, numpubattr,
	    private_template, numpriattr,
	    pubKey, priKey);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (ckrv);
	}

	return (ckrv);
}

KMF_RETURN
KMFPK11_CreateKeypair(KMF_HANDLE_T handle,
	int numattr,
	KMF_ATTRIBUTE *attlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_DATA IDInput, IDOutput;
	KMF_CREDENTIAL *cred;
	KMF_KEY_ALG keytype = KMF_RSA;
	KMF_KEY_HANDLE *pubkey, *privkey;

	CK_RV			ckrv = 0;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_ATTRIBUTE labelattr[1];
	CK_ATTRIBUTE idattr[1];
	CK_OBJECT_HANDLE pubKey, priKey;

	char IDHashData[SHA1_HASH_LENGTH];
	static CK_ULONG	modulusBits = 1024;
	uint32_t	modulusBits_size = sizeof (CK_ULONG);
	SHA1_CTX ctx;
	boolean_t storekey = TRUE;
	char *keylabel = NULL;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	/* "storekey" is optional. Default is TRUE */
	(void) kmf_get_attr(KMF_STOREKEY_BOOL_ATTR, attlist, numattr,
	    &storekey, NULL);

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attlist, numattr);
	if (cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, cred);
	if (rv != KMF_OK)
		return (rv);

	/* keytype is optional.  KMF_RSA is default */
	(void) kmf_get_attr(KMF_KEYALG_ATTR, attlist, numattr,
	    (void *)&keytype, NULL);

	pubkey = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attlist, numattr);
	if (pubkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	privkey = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attlist, numattr);
	if (privkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(pubkey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(privkey, 0, sizeof (KMF_KEY_HANDLE));
	if (keytype == KMF_RSA) {
		CK_BYTE *modulus = NULL;
		CK_ULONG modulusLength = 0;
		KMF_BIGINT *rsaexp = NULL;
		CK_ATTRIBUTE modattr[1];

		rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attlist, numattr,
		    &modulusBits, &modulusBits_size);
		if (rv == KMF_ERR_ATTR_NOT_FOUND)
			/* Default modulusBits = 1024 */
			rv = KMF_OK;
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		rsaexp = kmf_get_attr_ptr(KMF_RSAEXP_ATTR, attlist, numattr);

		/* Generate the RSA keypair */
		ckrv = genrsa_keypair(kmfh, modulusBits, storekey,
		    rsaexp, &pubKey, &priKey);

		if (ckrv != CKR_OK)
			return (KMF_ERR_BAD_PARAMETER);

		privkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		privkey->keyalg = KMF_RSA;
		privkey->keyclass = KMF_ASYM_PRI;
		privkey->keyp = (void *)priKey;

		pubkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		pubkey->keyalg = KMF_RSA;
		pubkey->keyclass = KMF_ASYM_PUB;
		pubkey->keyp = (void *)pubKey;

		SETATTR(modattr, 0, CKA_MODULUS, NULL, modulusLength);
		/* Get the Modulus field to use as input for creating the ID */
		ckrv = C_GetAttributeValue(kmfh->pk11handle,
		    (CK_OBJECT_HANDLE)pubKey, modattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_BAD_PARAMETER);
		}

		modulusLength = modattr[0].ulValueLen;
		modulus = malloc(modulusLength);
		if (modulus == NULL)
			return (KMF_ERR_MEMORY);

		modattr[0].pValue = modulus;
		ckrv = C_GetAttributeValue(kmfh->pk11handle,
		    (CK_OBJECT_HANDLE)pubKey, modattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			free(modulus);
			return (KMF_ERR_BAD_PARAMETER);
		}

		IDInput.Data = modulus;
		IDInput.Length = modulusLength;

	} else if (keytype == KMF_DSA) {
		CK_BYTE *keyvalue;
		CK_ULONG valueLen;
		CK_ATTRIBUTE valattr[1];

		/* Generate the DSA keypair */
		ckrv = gendsa_keypair(kmfh, storekey, &pubKey, &priKey);
		if (ckrv != CKR_OK)
			return (KMF_ERR_BAD_PARAMETER);

		privkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		privkey->keyalg = KMF_DSA;
		privkey->keyclass = KMF_ASYM_PRI;
		privkey->keyp = (void *)priKey;

		pubkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		pubkey->keyalg = KMF_DSA;
		pubkey->keyclass = KMF_ASYM_PUB;
		pubkey->keyp = (void *)pubKey;

		/* Get the Public Value to use as input for creating the ID */
		SETATTR(valattr, 0, CKA_VALUE, NULL, &valueLen);

		ckrv = C_GetAttributeValue(hSession,
		    (CK_OBJECT_HANDLE)pubKey, valattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_BAD_PARAMETER);
		}

		valueLen = valattr[0].ulValueLen;
		keyvalue = malloc(valueLen);
		if (keyvalue == NULL)
			return (KMF_ERR_MEMORY);

		valattr[0].pValue = keyvalue;
		ckrv = C_GetAttributeValue(hSession,
		    (CK_OBJECT_HANDLE)pubKey, valattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			free(keyvalue);
			return (KMF_ERR_BAD_PARAMETER);
		}

		IDInput.Data = keyvalue;
		IDInput.Length = valueLen;
	} else if (keytype == KMF_ECDSA) {
		CK_BYTE *keyvalue;
		CK_ULONG valueLen;
		CK_ATTRIBUTE valattr[1];
		KMF_OID *eccoid = kmf_get_attr_ptr(KMF_ECC_CURVE_OID_ATTR,
		    attlist, numattr);

		if (eccoid == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		ckrv = genecc_keypair(kmfh, storekey, eccoid,
		    &pubKey, &priKey);
		if (ckrv != CKR_OK)
			return (KMF_ERR_BAD_PARAMETER);

		privkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		privkey->keyalg = KMF_ECDSA;
		privkey->keyclass = KMF_ASYM_PRI;
		privkey->keyp = (void *)priKey;

		pubkey->kstype = KMF_KEYSTORE_PK11TOKEN;
		pubkey->keyalg = KMF_ECDSA;
		pubkey->keyclass = KMF_ASYM_PUB;
		pubkey->keyp = (void *)pubKey;

		/* Get the EC_POINT to use as input for creating the ID */
		SETATTR(valattr, 0, CKA_EC_POINT, NULL, &valueLen);

		ckrv = C_GetAttributeValue(hSession,
		    (CK_OBJECT_HANDLE)pubKey, valattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_BAD_PARAMETER);
		}

		valueLen = valattr[0].ulValueLen;
		keyvalue = malloc(valueLen);
		if (keyvalue == NULL)
			return (KMF_ERR_MEMORY);

		valattr[0].pValue = keyvalue;
		ckrv = C_GetAttributeValue(hSession,
		    (CK_OBJECT_HANDLE)pubKey, valattr, 1);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			free(keyvalue);
			return (KMF_ERR_BAD_PARAMETER);
		}

		IDInput.Data = keyvalue;
		IDInput.Length = valueLen;
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attlist, numattr);
	if (keylabel != NULL && strlen(keylabel)) {
		SETATTR(labelattr, 0, CKA_LABEL, keylabel, strlen(keylabel));

		/* Set the CKA_LABEL if one was indicated */
		if ((ckrv = C_SetAttributeValue(hSession, pubKey,
		    labelattr, 1)) != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			rv = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		pubkey->keylabel = (char *)strdup(keylabel);
		if (pubkey->keylabel == NULL) {
			rv = KMF_ERR_MEMORY;
			goto cleanup;
		}
		if ((ckrv = C_SetAttributeValue(hSession, priKey,
		    labelattr, 1)) != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			rv = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		privkey->keylabel = (char *)strdup(keylabel);
		if (privkey->keylabel == NULL) {
			rv = KMF_ERR_MEMORY;
			goto cleanup;
		}
	} else {
		rv = KMF_OK;
	}

	/* Now, assign a CKA_ID value so it can be searched */
	/* ID_Input was assigned above in the RSA or DSA keygen section */
	IDOutput.Data = (uchar_t *)IDHashData;
	IDOutput.Length = sizeof (IDHashData);

	SHA1Init(&ctx);
	SHA1Update(&ctx, IDInput.Data, IDInput.Length);
	SHA1Final(IDOutput.Data, &ctx);

	IDOutput.Length = SHA1_DIGEST_LENGTH;

	free(IDInput.Data);

	if (rv != CKR_OK) {
		goto cleanup;
	}
	SETATTR(idattr, 0, CKA_ID, IDOutput.Data, IDOutput.Length);
	if ((ckrv = C_SetAttributeValue(hSession, pubKey,
	    idattr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto cleanup;
	}
	if ((ckrv = C_SetAttributeValue(hSession, priKey,
	    idattr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto cleanup;
	}

cleanup:
	if (rv != KMF_OK) {
		if (pubKey != CK_INVALID_HANDLE)
			(void) C_DestroyObject(hSession, pubKey);
		if (priKey != CK_INVALID_HANDLE)
			(void) C_DestroyObject(hSession, priKey);

		if (privkey->keylabel)
			free(privkey->keylabel);
		if (pubkey->keylabel)
			free(pubkey->keylabel);
	}
	return (rv);
}

KMF_RETURN
KMFPK11_DeleteKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_RV ckrv = CKR_OK;
	KMF_RETURN rv = KMF_OK;
	KMF_KEY_HANDLE *key;
	KMF_CREDENTIAL cred;
	boolean_t destroy = B_TRUE;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL || key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyclass != KMF_ASYM_PUB &&
	    key->keyclass != KMF_ASYM_PRI &&
	    key->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	/* "destroy" is optional. Default is TRUE */
	(void) kmf_get_attr(KMF_DESTROY_BOOL_ATTR, attrlist, numattr,
	    (void *)&destroy, NULL);

	if (destroy) {
		rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
		    (void *)&cred, NULL);
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		rv = pk11_authenticate(handle, &cred);
		if (rv != KMF_OK) {
			return (rv);
		}
	}

	if (!key->israw && destroy)
		ckrv = C_DestroyObject(kmfh->pk11handle,
		    (CK_OBJECT_HANDLE)key->keyp);

	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		/* Report authentication failures to the caller */
		if (ckrv == CKR_PIN_EXPIRED || ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	}
	return (rv);
}

KMF_RETURN
KMFPK11_SignData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *keyp,
	KMF_OID *algOID,
	KMF_DATA *tobesigned,
	KMF_DATA *output)
{
	KMF_RETURN		rv = KMF_OK;
	CK_RV			ckrv;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_MECHANISM		mechanism;
	CK_MECHANISM_TYPE	mechtype, hashmech;
	CK_KEY_TYPE		keytype;
	KMF_ALGORITHM_INDEX	AlgId;
	KMF_DATA		hashData = { 0, NULL };
	uchar_t			digest[1024];
	CK_ATTRIBUTE		subprime = { CKA_SUBPRIME, NULL, 0 };

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (keyp == NULL || algOID == NULL ||
	    tobesigned == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* These functions are available to the plugin from libkmf */
	AlgId = x509_algoid_to_algid(algOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get the PKCS11 signing key type and mechtype */
	if (get_pk11_data(AlgId, &keytype, &mechtype, &hashmech, 0))
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(digest, 0, sizeof (digest));
	hashData.Data = digest;
	hashData.Length = sizeof (digest);
	rv = PKCS_DigestData(handle, hSession, hashmech, tobesigned, &hashData,
	    (mechtype == CKM_RSA_PKCS));
	if (rv)
		return (rv);

	if (mechtype == CKM_DSA && hashmech == CKM_SHA256) {
		/*
		 * FIPS 186-3 says that when signing with DSA
		 * the hash must be truncated to the size of the
		 * subprime.
		 */
		ckrv = C_GetAttributeValue(hSession,
		    (CK_OBJECT_HANDLE)keyp->keyp,
		    &subprime, 1);
		if (ckrv != CKR_OK)  {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}
		hashData.Length = subprime.ulValueLen;
	}

	/* the mechtype from the 'get_pk11_info' refers to the signing */
	mechanism.mechanism = mechtype;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	ckrv = C_SignInit(hSession, &mechanism, (CK_OBJECT_HANDLE)keyp->keyp);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	ckrv = C_Sign(hSession,	hashData.Data, hashData.Length,
	    output->Data, (CK_ULONG *)&output->Length);

	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	return (KMF_OK);
}

KMF_RETURN
KMFPK11_GetErrorString(KMF_HANDLE_T handle, char **msgstr)
{
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	*msgstr = NULL;
	if (kmfh->lasterr.errcode != 0) {
		char *e = pkcs11_strerror(kmfh->lasterr.errcode);
		if (e == NULL || (*msgstr = (char *)strdup(e)) == NULL) {
			return (KMF_ERR_MEMORY);
		}
	}

	return (KMF_OK);
}

static CK_RV
getObjectKeytype(KMF_HANDLE_T handle, CK_OBJECT_HANDLE obj,
	CK_ULONG *keytype)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templ;
	CK_ULONG len = sizeof (CK_ULONG);
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	templ.type = CKA_KEY_TYPE;
	templ.pValue = keytype;
	templ.ulValueLen = len;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, &templ, 1);

	return (rv);

}

static CK_RV
getObjectLabel(KMF_HANDLE_T handle, CK_OBJECT_HANDLE obj,
	char **outlabel)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templ;
	char	Label[BUFSIZ];
	CK_ULONG len = sizeof (Label);
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	(void) memset(Label, 0, len);
	templ.type = CKA_LABEL;
	templ.pValue = Label;
	templ.ulValueLen = len;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, &templ, 1);
	if (rv == CKR_OK) {
		*outlabel = (char *)strdup(Label);
	} else {
		*outlabel = NULL;
	}
	return (rv);
}

static CK_RV
getObjectKeyclass(KMF_HANDLE_T handle, CK_OBJECT_HANDLE obj,
	KMF_KEY_CLASS *keyclass)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templ;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_OBJECT_CLASS class;

	templ.type = CKA_CLASS;
	templ.pValue = &class;
	templ.ulValueLen = sizeof (CK_OBJECT_CLASS);

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, &templ, 1);
	if (rv == CKR_OK) {
		if (class == CKO_PUBLIC_KEY) {
			*keyclass = KMF_ASYM_PUB;
		} else if (class == CKO_PRIVATE_KEY) {
			*keyclass = KMF_ASYM_PRI;
		} else if (class == CKO_SECRET_KEY) {
			*keyclass = KMF_SYMMETRIC;
		}
	} else {
		*keyclass = KMF_KEYCLASS_NONE;
	}
	return (rv);
}

KMF_RETURN
KMFPK11_FindPrikeyByCert(KMF_HANDLE_T handle, int numattr,
    KMF_ATTRIBUTE *attrlist)
{
	KMF_X509_SPKI *pubkey;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv = CKR_OK;
	CK_ATTRIBUTE templ[4];
	CK_OBJECT_HANDLE pri_obj = CK_INVALID_HANDLE;
	CK_ULONG obj_count;
	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_BBOOL true = TRUE;
	KMF_DATA Id = { 0, NULL };
	KMF_KEY_HANDLE *key = NULL;
	KMF_DATA *cert = NULL;
	KMF_CREDENTIAL cred;
	KMF_ENCODE_FORMAT format = KMF_FORMAT_UNDEF;
	CK_ULONG keytype;

	/* Get the key handle */
	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get the optional encoded format */
	(void) kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist, numattr,
	    (void *)&format, NULL);

	/* Decode the signer cert so we can get the SPKI data */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL || cert->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if ((rv = DerDecodeSignedCertificate(cert,
	    &SignerCert)) != KMF_OK)
		return (rv);

	/* Get the public key info from the signer certificate */
	pubkey = &SignerCert->certificate.subjectPublicKeyInfo;

	/* Generate an ID from the SPKI data */
	rv = GetIDFromSPKI(pubkey, &Id);
	if (rv != KMF_OK) {
		goto errout;
	}

	/* Get the credential and login */
	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, &cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* Start searching */
	SETATTR(templ, 0, CKA_CLASS, &objClass, sizeof (objClass));
	SETATTR(templ, 1, CKA_TOKEN, &true, sizeof (true));
	SETATTR(templ, 2, CKA_PRIVATE, &true, sizeof (true));
	SETATTR(templ, 3, CKA_ID, Id.Data, Id.Length);

	if ((ckrv = C_FindObjectsInit(kmfh->pk11handle, templ, 4)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto errout;
	}

	if ((ckrv = C_FindObjects(kmfh->pk11handle, &pri_obj, 1,
	    &obj_count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto errout;
	}

	if (obj_count == 0) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_KEY_NOT_FOUND;
		goto errout;
	}

	key->kstype = KMF_KEYSTORE_PK11TOKEN;
	key->keyclass = KMF_ASYM_PRI;
	key->keyp = (void *)pri_obj;
	key->israw = FALSE;

	(void) C_FindObjectsFinal(kmfh->pk11handle);

	ckrv = getObjectLabel(handle, (CK_OBJECT_HANDLE)key->keyp,
	    &key->keylabel);
	if (ckrv != CKR_OK) {
		SET_ERROR(handle, ckrv);
		rv = KMF_ERR_INTERNAL;
	} else {
		rv = KMF_OK;
	}

	/*
	 * The key->keyalg value is needed if we need to convert the key
	 * to raw key.  However, the key->keyalg value will not be set if
	 * this function is not called thru the kmf_find_prikey_by_cert()
	 * framework function. To be safe, we will get the keytype from
	 * the key object and set key->keyalg value here.
	 */
	ckrv = getObjectKeytype(handle, (CK_OBJECT_HANDLE)key->keyp,
	    &keytype);
	if (ckrv != CKR_OK) {
		SET_ERROR(handle, ckrv);
		rv = KMF_ERR_INTERNAL;
	} else {
		rv = KMF_OK;
	}

	if (keytype == CKK_RSA)
		key->keyalg = KMF_RSA;
	else if (keytype == CKK_DSA)
		key->keyalg = KMF_DSA;
	else if (keytype == CKK_EC)
		key->keyalg = KMF_ECDSA;
	else {
		/* For asymmetric keys, we only support RSA and DSA */
		rv = KMF_ERR_KEY_NOT_FOUND;
		goto errout;
	}

	if (rv == KMF_OK && format == KMF_FORMAT_RAWKEY) {
		KMF_RAW_KEY_DATA *rkey = NULL;
		rv = keyObj2RawKey(handle, key, &rkey);
		if (rv == KMF_OK) {
			key->keyp = rkey;
			key->israw = TRUE;
		}
	}

errout:
	if (Id.Data != NULL)
		free(Id.Data);

	if (SignerCert != NULL) {
		kmf_free_signed_cert(SignerCert);
		free(SignerCert);
	}
	return (rv);
}

KMF_RETURN
KMFPK11_DecryptData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *algOID, KMF_DATA *ciphertext,
	KMF_DATA *output)
{
	CK_RV			ckrv;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_MECHANISM		mechanism;
	CK_MECHANISM_TYPE	mechtype;
	CK_KEY_TYPE		keytype;
	KMF_ALGORITHM_INDEX	AlgId;
	CK_ULONG out_len = 0, block_len = 0, total_decrypted = 0;
	uint8_t *in_data, *out_data;
	int i, blocks;
	CK_ATTRIBUTE ckTemplate[1];

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (key == NULL || algOID == NULL ||
	    ciphertext == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	AlgId = x509_algoid_to_algid(algOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the Algorithm ID to a PKCS#11 mechanism */
	if (get_pk11_data(AlgId, &keytype, &mechtype, NULL, 0))
		return (KMF_ERR_BAD_PARAMETER);

	mechanism.mechanism = mechtype;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	SETATTR(ckTemplate, 0, CKA_MODULUS, (CK_BYTE *)NULL,
	    sizeof (CK_ULONG));

	/* Get the modulus length */
	ckrv = C_GetAttributeValue(hSession,
	    (CK_OBJECT_HANDLE)key->keyp, ckTemplate, 1);

	if (ckrv != CKR_OK)  {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	block_len = ckTemplate[0].ulValueLen;

	/* Compute the number of times to do single-part decryption */
	blocks = ciphertext->Length/block_len;

	out_data = output->Data;
	in_data = ciphertext->Data;
	out_len = block_len - 11;

	for (i = 0; i < blocks; i++) {
		ckrv = C_DecryptInit(hSession, &mechanism,
		    (CK_OBJECT_HANDLE)key->keyp);

		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}

		ckrv = C_Decrypt(hSession, in_data, block_len,
		    out_data, (CK_ULONG *)&out_len);

		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}

		out_data += out_len;
		total_decrypted += out_len;
		in_data += block_len;

	}

	output->Length = total_decrypted;
	return (KMF_OK);
}

static void
attr2bigint(CK_ATTRIBUTE_PTR attr, KMF_BIGINT *big)
{
	big->val = attr->pValue;
	big->len = attr->ulValueLen;
}

static KMF_RETURN
get_bigint_attr(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
	CK_ATTRIBUTE_TYPE attrtype, KMF_BIGINT *bigint)
{
	CK_RV ckrv;
	CK_ATTRIBUTE attr;

	attr.type = attrtype;
	attr.pValue = NULL;
	attr.ulValueLen = 0;

	if ((ckrv = C_GetAttributeValue(sess, obj,
	    &attr, 1)) != CKR_OK) {
		/* Mask this error so the caller can continue */
		if (ckrv == CKR_ATTRIBUTE_TYPE_INVALID)
			return (KMF_OK);
		else
			return (KMF_ERR_INTERNAL);
	}
	if (attr.ulValueLen > 0 && bigint != NULL) {
		attr.pValue = malloc(attr.ulValueLen);
		if (attr.pValue == NULL)
			return (KMF_ERR_MEMORY);

		if ((ckrv = C_GetAttributeValue(sess, obj,
		    &attr, 1)) != CKR_OK)
		if (ckrv != CKR_OK) {
			free(attr.pValue);
			return (KMF_ERR_INTERNAL);
		}

		bigint->val = attr.pValue;
		bigint->len = attr.ulValueLen;
	}
	return (KMF_OK);
}

static KMF_RETURN
get_raw_rsa(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_RSA_KEY *rawrsa)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE rsa_pri_attrs[2] = {
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 }
	};
	CK_ULONG count = sizeof (rsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int i;

	if (rawrsa == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(rawrsa, 0, sizeof (KMF_RAW_RSA_KEY));
	if ((ckrv = C_GetAttributeValue(sess, obj,
	    rsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		/* Tell the caller know why the key data cannot be retrieved. */
		if (ckrv == CKR_ATTRIBUTE_SENSITIVE)
			return (KMF_ERR_SENSITIVE_KEY);
		else if (ckrv == CKR_KEY_UNEXTRACTABLE)
			return (KMF_ERR_UNEXTRACTABLE_KEY);
		else
			return (KMF_ERR_INTERNAL);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (rsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    rsa_pri_attrs[i].ulValueLen == 0) {
			rsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((rsa_pri_attrs[i].pValue =
		    malloc(rsa_pri_attrs[i].ulValueLen)) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
	}
	/* Now that we have space, really get the attributes */
	if ((ckrv = C_GetAttributeValue(sess, obj,
	    rsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto end;
	}
	i = 0;
	attr2bigint(&(rsa_pri_attrs[i++]), &rawrsa->mod);
	attr2bigint(&(rsa_pri_attrs[i++]), &rawrsa->pubexp);

	/* Now get the optional parameters */
	rv = get_bigint_attr(sess, obj, CKA_PRIVATE_EXPONENT, &rawrsa->priexp);
	if (rv != KMF_OK)
		goto end;
	rv = get_bigint_attr(sess, obj, CKA_PRIME_1, &rawrsa->prime1);
	if (rv != KMF_OK)
		goto end;
	rv = get_bigint_attr(sess, obj, CKA_PRIME_2, &rawrsa->prime2);
	if (rv != KMF_OK)
		goto end;
	rv = get_bigint_attr(sess, obj, CKA_EXPONENT_1, &rawrsa->exp1);
	if (rv != KMF_OK)
		goto end;
	rv = get_bigint_attr(sess, obj, CKA_EXPONENT_2, &rawrsa->exp2);
	if (rv != KMF_OK)
		goto end;
	rv = get_bigint_attr(sess, obj, CKA_COEFFICIENT, &rawrsa->coef);
	if (rv != KMF_OK)
		goto end;

end:
	if (rv != KMF_OK) {
		for (i = 0; i < count; i++) {
			if (rsa_pri_attrs[i].pValue != NULL)
				free(rsa_pri_attrs[i].pValue);
		}
		if (rawrsa->priexp.val)
			free(rawrsa->priexp.val);
		if (rawrsa->prime1.val)
			free(rawrsa->prime1.val);
		if (rawrsa->prime2.val)
			free(rawrsa->prime2.val);
		if (rawrsa->exp1.val)
			free(rawrsa->exp1.val);
		if (rawrsa->exp2.val)
			free(rawrsa->exp2.val);
		if (rawrsa->coef.val)
			free(rawrsa->coef.val);
		(void) memset(rawrsa, 0, sizeof (KMF_RAW_RSA_KEY));
	}
	return (rv);
}

#define	DSA_PRIME_BUFSIZE	CHARLEN2BIGNUMLEN(1024)	/* 8192 bits */
#define	DSA_PRIVATE_BUFSIZE	BIG_CHUNKS_FOR_160BITS	/* 160 bits */

/*
 * This function calculates the pubkey value from the prime,
 * base and private key values of a DSA key.
 */
static KMF_RETURN
compute_dsa_pubvalue(KMF_RAW_DSA_KEY *rawdsa)
{
	KMF_RETURN rv = KMF_OK;
	BIGNUM p, g, x, y;
	BIG_ERR_CODE err;
	uchar_t *pubvalue;
	uint32_t pubvalue_len;

	if ((err = big_init1(&p, DSA_PRIME_BUFSIZE, NULL, 0)) != BIG_OK) {
		rv = KMF_ERR_MEMORY;
		return (rv);
	}
	bytestring2bignum(&p, rawdsa->prime.val, rawdsa->prime.len);

	if ((err = big_init1(&g, DSA_PRIME_BUFSIZE, NULL, 0)) != BIG_OK) {
		rv = KMF_ERR_MEMORY;
		goto ret1;
	}
	bytestring2bignum(&g, rawdsa->base.val, rawdsa->base.len);

	if ((err = big_init1(&x, DSA_PRIVATE_BUFSIZE, NULL, 0)) != BIG_OK) {
		rv = KMF_ERR_MEMORY;
		goto ret2;
	}
	bytestring2bignum(&x, rawdsa->value.val, rawdsa->value.len);

	if ((err = big_init1(&y, DSA_PRIME_BUFSIZE, NULL, 0)) != BIG_OK) {
		rv = KMF_ERR_MEMORY;
		goto ret3;
	}

	err = big_modexp(&y, &g, &x, &p, NULL);
	if (err != BIG_OK) {
		rv = KMF_ERR_INTERNAL;
		goto ret3;
	}

	pubvalue_len = y.len * (int)sizeof (uint32_t);
	if ((pubvalue = malloc(pubvalue_len)) == NULL) {
		rv = KMF_ERR_MEMORY;
		goto ret4;
	}
	bignum2bytestring(pubvalue, &y, pubvalue_len);

	rawdsa->pubvalue.val = pubvalue;
	rawdsa->pubvalue.len = pubvalue_len;

ret4:
	big_finish(&y);
ret3:
	big_finish(&x);
ret2:
	big_finish(&g);
ret1:
	big_finish(&p);
	return (rv);
}

static KMF_RETURN
get_raw_ec(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_EC_KEY *rawec)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	ec_attrs[2] = {
		{ CKA_EC_PARAMS, NULL, 0},
		{ CKA_VALUE, NULL, 0}
	};
	CK_ULONG	count = sizeof (ec_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	if ((ckrv = C_GetAttributeValue(sess, obj,
	    ec_attrs, 2)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);

		/* Tell the caller know why the key data cannot be retrieved. */
		if (ckrv == CKR_ATTRIBUTE_SENSITIVE)
			return (KMF_ERR_SENSITIVE_KEY);
		else if (ckrv == CKR_KEY_UNEXTRACTABLE)
			return (KMF_ERR_UNEXTRACTABLE_KEY);
		return (KMF_ERR_INTERNAL);
	}
	for (i = 0; i < count; i++) {
		if (ec_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    ec_attrs[i].ulValueLen == 0) {
			ec_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((ec_attrs[i].pValue =
		    malloc(ec_attrs[i].ulValueLen)) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
	}
	if ((ckrv = C_GetAttributeValue(sess, obj,
	    ec_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto end;
	}

	rawec->params.Data = ec_attrs[0].pValue;
	rawec->params.Length = ec_attrs[0].ulValueLen;
	rawec->value.val = ec_attrs[1].pValue;
	rawec->value.len = ec_attrs[1].ulValueLen;

end:
	if (rv != KMF_OK) {
		for (i = 0; i < count; i++) {
			if (ec_attrs[i].pValue != NULL)
				free(ec_attrs[i].pValue);
		}
		(void) memset(rawec, 0, sizeof (KMF_RAW_EC_KEY));
	}
	return (rv);
}

static KMF_RETURN
get_raw_dsa(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_DSA_KEY *rawdsa)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	dsa_pri_attrs[8] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};
	CK_ULONG	count = sizeof (dsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	if ((ckrv = C_GetAttributeValue(sess, obj,
	    dsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);

		/* Tell the caller know why the key data cannot be retrieved. */
		if (ckrv == CKR_ATTRIBUTE_SENSITIVE)
			return (KMF_ERR_SENSITIVE_KEY);
		else if (ckrv == CKR_KEY_UNEXTRACTABLE)
			return (KMF_ERR_UNEXTRACTABLE_KEY);
		return (KMF_ERR_INTERNAL);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (dsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    dsa_pri_attrs[i].ulValueLen == 0) {
			dsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((dsa_pri_attrs[i].pValue =
		    malloc(dsa_pri_attrs[i].ulValueLen)) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
	}
	if ((ckrv = C_GetAttributeValue(sess, obj,
	    dsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto end;
	}

	/* Fill in all the temp variables.  They are all required. */
	i = 0;
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->prime);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->subprime);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->base);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->value);

	/* Compute the public key value and store it */
	rv = compute_dsa_pubvalue(rawdsa);

end:
	if (rv != KMF_OK) {
		for (i = 0; i < count; i++) {
			if (dsa_pri_attrs[i].pValue != NULL)
				free(dsa_pri_attrs[i].pValue);
		}
		(void) memset(rawdsa, 0, sizeof (KMF_RAW_DSA_KEY));
	}
	return (rv);
}

static KMF_RETURN
get_raw_sym(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_SYM_KEY *rawsym)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV	ckrv;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	sym_attr[1];
	CK_ULONG	value_len = 0;

	/* find the key length first */
	sym_attr[0].type = CKA_VALUE;
	sym_attr[0].pValue = NULL;
	sym_attr[0].ulValueLen = value_len;
	if ((ckrv = C_GetAttributeValue(sess, obj, sym_attr, 1)) != CKR_OK) {
		rawsym->keydata.val = NULL;
		rawsym->keydata.len = 0;
		if (ckrv == CKR_ATTRIBUTE_SENSITIVE) {
			return (KMF_ERR_SENSITIVE_KEY);
		} else if (ckrv == CKR_KEY_UNEXTRACTABLE) {
			return (KMF_ERR_UNEXTRACTABLE_KEY);
		} else {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}
	}

	/* Allocate memory for pValue */
	sym_attr[0].pValue = malloc(sym_attr[0].ulValueLen);
	if (sym_attr[0].pValue == NULL) {
		return (KMF_ERR_MEMORY);
	}

	/* get the key data */
	if ((ckrv = C_GetAttributeValue(sess, obj, sym_attr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		free(sym_attr[0].pValue);
		return (KMF_ERR_INTERNAL);
	}

	rawsym->keydata.val = sym_attr[0].pValue;
	rawsym->keydata.len = sym_attr[0].ulValueLen;
	return (rv);
}

static KMF_RETURN
keyObj2RawKey(KMF_HANDLE_T handle, KMF_KEY_HANDLE *inkey,
	KMF_RAW_KEY_DATA **outkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_RAW_KEY_DATA *rkey;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	rkey = malloc(sizeof (KMF_RAW_KEY_DATA));
	if (rkey == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset(rkey, 0, sizeof (KMF_RAW_KEY_DATA));

	rkey->keytype = inkey->keyalg;

	if (inkey->keyalg == KMF_RSA) {
		rv = get_raw_rsa(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
		    &rkey->rawdata.rsa);
	} else if (inkey->keyalg == KMF_DSA) {
		rv = get_raw_dsa(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
		    &rkey->rawdata.dsa);
	} else if (inkey->keyalg == KMF_AES ||
	    inkey->keyalg == KMF_RC4 ||
	    inkey->keyalg == KMF_DES ||
	    inkey->keyalg == KMF_DES3 ||
	    inkey->keyalg == KMF_GENERIC_SECRET) {
		rv = get_raw_sym(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
		    &rkey->rawdata.sym);
		/*
		 * If sensitive or non-extractable, mark them as such
		 * but return "OK" status so the keys get counted
		 * when doing FindKey operations.
		 */
		if (rv == KMF_ERR_SENSITIVE_KEY) {
			rkey->sensitive = B_TRUE;
			rv = KMF_OK;
		} else if (rv == KMF_ERR_UNEXTRACTABLE_KEY) {
			rkey->not_extractable = B_TRUE;
			rv = KMF_OK;
		}
	} else if (inkey->keyalg == KMF_ECDSA) {
		rv = get_raw_ec(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
		    &rkey->rawdata.ec);
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
	}

	if (rv == KMF_OK) {
		*outkey = rkey;
	} else if (rkey != NULL) {
		free(rkey);
		*outkey = NULL;
	}

	return (rv);
}


static KMF_RETURN
kmf2pk11keytype(KMF_KEY_ALG keyalg, CK_KEY_TYPE *type)
{
	switch (keyalg) {
	case KMF_RSA:
		*type = CKK_RSA;
		break;
	case KMF_DSA:
		*type = CKK_DSA;
		break;
	case KMF_ECDSA:
		*type = CKK_EC;
		break;
	case KMF_AES:
		*type = CKK_AES;
		break;
	case KMF_RC4:
		*type = CKK_RC4;
		break;
	case KMF_DES:
		*type = CKK_DES;
		break;
	case KMF_DES3:
		*type = CKK_DES3;
		break;
	case KMF_GENERIC_SECRET:
		*type = CKK_GENERIC_SECRET;
		break;
	default:
		return (KMF_ERR_BAD_KEY_TYPE);
	}

	return (KMF_OK);
}

static int
IDStringToData(char *idstr, KMF_DATA *iddata)
{
	int len, i;
	char *iddup, *byte;
	uint_t lvalue;

	if (idstr == NULL || !strlen(idstr))
		return (-1);

	iddup = (char *)strdup(idstr);
	if (iddup == NULL)
		return (KMF_ERR_MEMORY);

	len = strlen(iddup) / 3  + 1;
	iddata->Data = malloc(len);
	if (iddata->Data == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(iddata->Data, 0, len);
	iddata->Length = len;

	byte = strtok(iddup, ":");
	if (byte == NULL) {
		free(iddup);
		free(iddata->Data);
		iddata->Data = NULL;
		iddata->Length = 0;
		return (-1);
	}

	i = 0;
	do {
		(void) sscanf(byte, "%x", &lvalue);
		iddata->Data[i++] = (uchar_t)(lvalue & 0x000000FF);
		byte = strtok(NULL, ":");
	} while (byte != NULL && i < len);

	iddata->Length = i;
	free(iddup);
	return (0);
}

KMF_RETURN
KMFPK11_FindKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	uint32_t want_keys, i;
	CK_RV ckrv;
	CK_ATTRIBUTE pTmpl[10];
	CK_OBJECT_CLASS class;
	CK_BBOOL true = TRUE;
	CK_ULONG alg;
	boolean_t is_token = B_TRUE, is_private = B_FALSE;
	KMF_KEY_HANDLE *keys;
	uint32_t *numkeys;
	KMF_CREDENTIAL *cred = NULL;
	KMF_KEY_CLASS keyclass = KMF_KEYCLASS_NONE;
	char *findLabel, *idstr;
	KMF_KEY_ALG keytype = KMF_KEYALG_NONE;
	KMF_ENCODE_FORMAT format;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	numkeys = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (*numkeys > 0)
		want_keys = *numkeys;
	else
		want_keys = MAXINT; /* count them all */

	/* keyclass is optional */
	(void) kmf_get_attr(KMF_KEYCLASS_ATTR, attrlist, numattr,
	    (void *)&keyclass, NULL);

	if (keyclass == KMF_ASYM_PUB) {
		class = CKO_PUBLIC_KEY;
	} else if (keyclass == KMF_ASYM_PRI) {
		class = CKO_PRIVATE_KEY;
	} else if (keyclass == KMF_SYMMETRIC) {
		class = CKO_SECRET_KEY;
	}

	rv = kmf_get_attr(KMF_TOKEN_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_token, NULL);
	if (rv != KMF_OK)
		return (rv);

	i = 0;
	if (is_token) {
		SETATTR(pTmpl, i, CKA_TOKEN, &true, sizeof (true));
		i++;
	}

	if (keyclass != KMF_KEYCLASS_NONE) {
		SETATTR(pTmpl, i, CKA_CLASS, &class, sizeof (class));
		i++;
	}

	findLabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);

	if (findLabel != NULL && strlen(findLabel)) {
		SETATTR(pTmpl, i, CKA_LABEL, findLabel, strlen(findLabel));
		i++;
	}
	/* keytype is optional */
	(void) kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
	    (void *)&keytype, NULL);

	if (keytype != 0) {
		rv = kmf2pk11keytype(keytype, &alg);
		if (rv != KMF_OK) {
			return (KMF_ERR_BAD_KEY_TYPE);
		}
		SETATTR(pTmpl, i, CKA_KEY_TYPE, &alg, sizeof (alg));
		i++;
	}

	idstr = kmf_get_attr_ptr(KMF_IDSTR_ATTR, attrlist, numattr);

	if (idstr != NULL) {
		KMF_DATA iddata = { 0, NULL };

		/*
		 * ID String parameter is assumed to be of form:
		 * XX:XX:XX:XX:XX ... :XX
		 * where XX is a hex number.
		 *
		 * We must convert this back to binary in order to
		 * use it in a search.
		 */
		rv = IDStringToData(idstr, &iddata);
		if (rv == KMF_OK) {
			SETATTR(pTmpl, i, CKA_ID, iddata.Data, iddata.Length);
			i++;
		} else {
			return (rv);
		}
	}

	/* is_private is optional */
	(void) kmf_get_attr(KMF_PRIVATE_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_private, NULL);

	if (is_private) {
		SETATTR(pTmpl, i, CKA_PRIVATE, &true, sizeof (true));
		i++;
	}

	/*
	 * Authenticate if the object is a token object,
	 * a private or secred key, or if the user passed in credentials.
	 */
	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred != NULL) {
		rv = pk11_authenticate(handle, cred);
		if (rv != KMF_OK)
			return (rv);
	}

	keys = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	/* it is okay to have "keys" contains NULL */

	ckrv = C_FindObjectsInit(kmfh->pk11handle, pTmpl, i);
	if (ckrv == CKR_OK) {
		CK_ULONG obj_count, n = 0;
		while (ckrv == CKR_OK && n < want_keys) {
			CK_OBJECT_HANDLE hObj;

			ckrv = C_FindObjects(kmfh->pk11handle, &hObj,
			    1, &obj_count);
			if (ckrv == CKR_OK && obj_count == 1) {
				if (keys != NULL) {
					CK_ULONG keytype;
					keys[n].kstype = KMF_KEYSTORE_PK11TOKEN;
					keys[n].israw = FALSE;
					keys[n].keyp = (void *)hObj;

					ckrv = getObjectKeytype(handle,
					    (CK_OBJECT_HANDLE)keys[n].keyp,
					    &keytype);
					if (ckrv != CKR_OK)
						goto end;

					ckrv = getObjectLabel(handle,
					    (CK_OBJECT_HANDLE)keys[n].keyp,
					    &(keys[n].keylabel));
					if (ckrv != CKR_OK)
						goto end;

					if (keyclass == KMF_KEYCLASS_NONE) {
						ckrv = getObjectKeyclass(handle,
						    (CK_OBJECT_HANDLE)
						    keys[n].keyp,
						    &(keys[n].keyclass));
						if (ckrv != CKR_OK)
							goto end;
					} else {
						keys[n].keyclass = keyclass;
					}
					if (keytype == CKK_RSA) {
						keys[n].keyalg = KMF_RSA;
					} else if (keytype == CKK_DSA) {
						keys[n].keyalg = KMF_DSA;
					} else if (keytype == CKK_EC) {
						keys[n].keyalg = KMF_ECDSA;
					} else if (keytype == CKK_AES) {
						keys[n].keyalg = KMF_AES;
						keys[n].keyclass =
						    KMF_SYMMETRIC;
					} else if (keytype == CKK_RC4) {
						keys[n].keyalg = KMF_RC4;
						keys[n].keyclass =
						    KMF_SYMMETRIC;
					} else if (keytype == CKK_DES) {
						keys[n].keyalg = KMF_DES;
						keys[n].keyclass =
						    KMF_SYMMETRIC;
					} else if (keytype == CKK_DES3) {
						keys[n].keyalg = KMF_DES3;
						keys[n].keyclass =
						    KMF_SYMMETRIC;
					} else if (keytype ==
					    CKK_GENERIC_SECRET) {
						keys[n].keyalg =
						    KMF_GENERIC_SECRET;
						keys[n].keyclass =
						    KMF_SYMMETRIC;
					}

				}
				n++;
			} else {
				break;
			}
		}
		ckrv = C_FindObjectsFinal(kmfh->pk11handle);

		/* "numkeys" indicates the number that were actually found */
		*numkeys = n;
	}

	if (ckrv == KMF_OK && keys != NULL && (*numkeys) > 0) {
		if ((rv = kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist,
		    numattr, (void *)&format, NULL)) == KMF_OK) {
			if (format == KMF_FORMAT_RAWKEY ||
			    format == KMF_FORMAT_PEM) {
				/* Convert keys to "rawkey" format */
				for (i = 0; i < (*numkeys); i++) {
					KMF_RAW_KEY_DATA *rkey = NULL;
					rv = keyObj2RawKey(handle, &keys[i],
					    &rkey);
					if (rv == KMF_OK) {
						keys[i].keyp = rkey;
						keys[i].israw = TRUE;
					} else {
						break;
					}
				}
			}
		} else {
			rv = KMF_OK; /* format is optional */
		}
	}

end:
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		/* Report authentication failures to the caller */
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	} else if ((*numkeys) == 0) {
		rv = KMF_ERR_KEY_NOT_FOUND;
	}

	return (rv);
}

static char *
convertDate(char *fulldate)
{
	struct tm tms;
	char newtime[9];

	(void) strptime(fulldate, "%b %d %T %Y %Z", &tms);

	if (tms.tm_year < 69)
		tms.tm_year += 100;

	(void) strftime(newtime, sizeof (newtime), "m%d", &tms);

	newtime[8] = 0;

	/* memory returned must be freed by the caller */
	return ((char *)strdup(newtime));
}

static KMF_RETURN
store_raw_key(KMF_HANDLE_T handle,
	KMF_ATTRIBUTE *attrlist, int numattr,
	KMF_RAW_KEY_DATA *rawkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int i;
	CK_RV		ckrv = CKR_OK;
	CK_ATTRIBUTE	templ[32];
	CK_OBJECT_HANDLE keyobj;
	CK_KEY_TYPE	keytype;
	CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
	CK_BBOOL	cktrue = TRUE;
	CK_DATE		startdate, enddate;
	KMF_DATA	id = { 0, NULL };
	KMF_DATA	subject = { 0, NULL };
	KMF_X509EXT_KEY_USAGE kuext;
	KMF_X509_CERTIFICATE *x509 = NULL;
	CK_BBOOL	kufound = B_FALSE;
	KMF_DATA	*cert = NULL;
	char		*notbefore = NULL, *start = NULL;
	char		*notafter = NULL, *end = NULL;
	char		*keylabel = NULL;
	KMF_CREDENTIAL	*cred = NULL;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (rawkey->keytype == KMF_RSA)
		keytype = CKK_RSA;
	else if (rawkey->keytype == KMF_DSA)
		keytype = CKK_DSA;
	else if (rawkey->keytype == KMF_ECDSA)
		keytype = CKK_EC;
	else
		return (KMF_ERR_BAD_PARAMETER);

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred != NULL) {
		rv = pk11_authenticate(handle, cred);
		if (rv != KMF_OK)
			return (rv);
	}

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);
	/*
	 * If the caller did not specify a label, see if the raw key
	 * came with one (possible if it came from a PKCS#12 file).
	 */
	if (keylabel == NULL) {
		keylabel = rawkey->label;
	}

	i = 0;
	SETATTR(templ, i, CKA_CLASS, &oClass, sizeof (CK_OBJECT_CLASS)); i++;
	SETATTR(templ, i, CKA_KEY_TYPE, &keytype, sizeof (keytype)); i++;
	SETATTR(templ, i, CKA_TOKEN, &cktrue, sizeof (cktrue)); i++;
	SETATTR(templ, i, CKA_PRIVATE, &cktrue, sizeof (cktrue)); i++;
	if (keytype != CKK_EC)
		SETATTR(templ, i, CKA_DECRYPT, &cktrue, sizeof (cktrue)); i++;

	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert != NULL) {
		id.Data = NULL;
		id.Length = 0;
		rv = kmf_get_cert_id_data(cert, &id);
		if (rv != KMF_OK) {
			goto cleanup;
		}

		rv = DerDecodeSignedCertificate((const KMF_DATA *)cert, &x509);
		if (rv != KMF_OK) {
			goto cleanup;
		}

		rv = DerEncodeName(&x509->certificate.subject, &subject);
		if (rv != KMF_OK) {
			goto cleanup;
		}
		SETATTR(templ, i, CKA_SUBJECT, subject.Data, subject.Length);
		i++;

		rv = kmf_get_cert_start_date_str(handle, cert, &notbefore);
		if (rv != KMF_OK) {
			goto cleanup;
		}
		start = convertDate(notbefore);
		free(notbefore);

		rv = kmf_get_cert_end_date_str(handle, cert, &notafter);
		if (rv != KMF_OK) {
			goto cleanup;
		}
		end = convertDate(notafter);
		free(notafter);
		if (id.Data != NULL && id.Data != NULL && id.Length > 0) {
			SETATTR(templ, i, CKA_ID, id.Data, id.Length);
			i++;
		}
		if (start != NULL) {
			/*
			 * This makes some potentially dangerous assumptions:
			 *  1. that the startdate in the parameter block is
			 * properly formatted as YYYYMMDD
			 *  2. That the CK_DATE structure is always the same.
			 */
			(void) memcpy(&startdate, start, sizeof (CK_DATE));
			SETATTR(templ, i, CKA_START_DATE, &startdate,
			    sizeof (startdate));
			i++;
		}
		if (end != NULL) {
			(void) memcpy(&enddate, end, sizeof (CK_DATE));
			SETATTR(templ, i, CKA_END_DATE, &enddate,
			    sizeof (enddate));
			i++;
		}

		if ((rv = kmf_get_cert_ku(cert, &kuext)) != KMF_OK &&
		    rv != KMF_ERR_EXTENSION_NOT_FOUND)
			goto cleanup;

		kufound = (rv == KMF_OK);
		rv = KMF_OK; /* reset if we got KMF_ERR_EXTENSION_NOT_FOUND */
	}

	/*
	 * Only set the KeyUsage stuff if the KU extension was present.
	 */
	if (kufound) {
		CK_BBOOL	condition;

		condition = (kuext.KeyUsageBits & KMF_keyEncipherment) ?
		    B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_UNWRAP, &condition, sizeof (CK_BBOOL));
		i++;
		condition = (kuext.KeyUsageBits & KMF_dataEncipherment) ?
		    B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_DECRYPT, &condition, sizeof (CK_BBOOL));
		i++;
		condition = (kuext.KeyUsageBits & KMF_digitalSignature) ?
		    B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_SIGN, &condition,	sizeof (CK_BBOOL));
		i++;
		condition = (kuext.KeyUsageBits & KMF_digitalSignature) ?
		    B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_SIGN_RECOVER, &condition,
		    sizeof (CK_BBOOL));
		i++;

	}

	if (keylabel != NULL) {
		SETATTR(templ, i, CKA_LABEL, keylabel, strlen(keylabel));
		i++;
	}
	if (id.Data == NULL && rawkey->id.Data != NULL) {
		SETATTR(templ, i, CKA_ID, rawkey->id.Data,
		    rawkey->id.Length);
		i++;
	}
	if (keytype == CKK_RSA) {
		SETATTR(templ, i, CKA_MODULUS,
		    rawkey->rawdata.rsa.mod.val,
		    rawkey->rawdata.rsa.mod.len);
		i++;
		SETATTR(templ, i, CKA_PUBLIC_EXPONENT,
		    rawkey->rawdata.rsa.pubexp.val,
		    rawkey->rawdata.rsa.pubexp.len);
		i++;
		if (rawkey->rawdata.rsa.priexp.val != NULL) {
			SETATTR(templ, i, CKA_PRIVATE_EXPONENT,
			    rawkey->rawdata.rsa.priexp.val,
			    rawkey->rawdata.rsa.priexp.len);
			i++;
		}
		if (rawkey->rawdata.rsa.prime1.val != NULL) {
			SETATTR(templ, i, CKA_PRIME_1,
			    rawkey->rawdata.rsa.prime1.val,
			    rawkey->rawdata.rsa.prime1.len);
			i++;
		}
		if (rawkey->rawdata.rsa.prime2.val != NULL) {
			SETATTR(templ, i, CKA_PRIME_2,
			    rawkey->rawdata.rsa.prime2.val,
			    rawkey->rawdata.rsa.prime2.len);
			i++;
		}
		if (rawkey->rawdata.rsa.exp1.val != NULL) {
			SETATTR(templ, i, CKA_EXPONENT_1,
			    rawkey->rawdata.rsa.exp1.val,
			    rawkey->rawdata.rsa.exp1.len);
			i++;
		}
		if (rawkey->rawdata.rsa.exp2.val != NULL) {
			SETATTR(templ, i, CKA_EXPONENT_2,
			    rawkey->rawdata.rsa.exp2.val,
			    rawkey->rawdata.rsa.exp2.len);
			i++;
		}
		if (rawkey->rawdata.rsa.coef.val != NULL) {
			SETATTR(templ, i, CKA_COEFFICIENT,
			    rawkey->rawdata.rsa.coef.val,
			    rawkey->rawdata.rsa.coef.len);
			i++;
		}
	} else if (keytype == CKK_DSA) {
		SETATTR(templ, i, CKA_PRIME,
		    rawkey->rawdata.dsa.prime.val,
		    rawkey->rawdata.dsa.prime.len);
		i++;
		SETATTR(templ, i, CKA_SUBPRIME,
		    rawkey->rawdata.dsa.subprime.val,
		    rawkey->rawdata.dsa.subprime.len);
		i++;
		SETATTR(templ, i, CKA_BASE,
		    rawkey->rawdata.dsa.base.val,
		    rawkey->rawdata.dsa.base.len);
		i++;
		SETATTR(templ, i, CKA_VALUE,
		    rawkey->rawdata.dsa.value.val,
		    rawkey->rawdata.dsa.value.len);
		i++;
	} else if (keytype == CKK_EC) {
		SETATTR(templ, i, CKA_SIGN, &cktrue, sizeof (cktrue));
		i++;
		SETATTR(templ, i, CKA_DERIVE, &cktrue, sizeof (cktrue));
		i++;
		SETATTR(templ, i, CKA_VALUE,
		    rawkey->rawdata.ec.value.val,
		    rawkey->rawdata.ec.value.len);
		i++;
		SETATTR(templ, i, CKA_EC_PARAMS,
		    rawkey->rawdata.ec.params.Data,
		    rawkey->rawdata.ec.params.Length);
		i++;
	}

	ckrv = C_CreateObject(kmfh->pk11handle, templ, i, &keyobj);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);

		/* Report authentication failures to the caller */
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	}
cleanup:
	if (start != NULL)
		free(start);
	if (end != NULL)
		free(end);
	kmf_free_data(&id);
	kmf_free_data(&subject);
	kmf_free_signed_cert(x509);
	free(x509);

	return (rv);
}

KMF_RETURN
KMFPK11_CreateSymKey(KMF_HANDLE_T handle,
    int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_RV			ckrv;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_OBJECT_HANDLE	keyhandle;
	CK_MECHANISM		keyGenMech;
	CK_OBJECT_CLASS		class = CKO_SECRET_KEY;
	CK_ULONG		secKeyType;
	CK_ULONG		secKeyLen;	/* for RC4 and AES */
	CK_BBOOL		true = TRUE;
	CK_BBOOL		false = FALSE;
	CK_ATTRIBUTE		templ[15];
	CK_BYTE			*keydata = NULL;
	int			i = 0;
	KMF_KEY_HANDLE		*symkey;
	KMF_KEY_ALG		keytype;
	uint32_t		keylen = 0;
	uint32_t		attrkeylen = 0;
	uint32_t		keylen_size = sizeof (uint32_t);
	char			*keylabel = NULL;
	KMF_CREDENTIAL		*cred = NULL;
	uint32_t		is_sensitive = B_FALSE;
	uint32_t		is_not_extractable = B_FALSE;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	symkey = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (symkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
	    (void *)&keytype, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);
	if (keylabel == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_SENSITIVE_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_sensitive, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_NON_EXTRACTABLE_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_not_extractable, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * For AES, RC4, DES and 3DES, call C_GenerateKey() to create a key.
	 *
	 * For a generic secret key, because it may not be supported in
	 * C_GenerateKey() for some PKCS11 providers, we will handle it
	 * differently.
	 */
	if (keytype == KMF_GENERIC_SECRET) {
		rv = create_generic_secret_key(handle, numattr,
		    attrlist, &keyhandle);
		if (rv != KMF_OK)
			goto out;
		else
			goto setup;
	}

	rv = kmf_get_attr(KMF_KEY_DATA_ATTR, attrlist, numattr,
	    NULL, &attrkeylen);
	if (rv == KMF_OK && attrkeylen > 0) {
		keydata = kmf_get_attr_ptr(KMF_KEY_DATA_ATTR, attrlist,
		    numattr);
	} else {
		keydata = NULL;
		attrkeylen = 0;
		rv = KMF_OK;
	}
	if (keydata != NULL) {
		if (keytype == KMF_DES && attrkeylen != 8) {
			rv = KMF_ERR_BAD_KEY_SIZE;
			goto out;
		}
		if (keytype == KMF_DES3 && attrkeylen != 24) {
			rv = KMF_ERR_BAD_KEY_SIZE;
			goto out;
		}
		/*
		 * This may override what the user gave on the
		 * command line.
		 */
		keylen = attrkeylen * 8; /* bytes to bits */
	} else {
		/*
		 * If keydata was not given, key length must be
		 * provided.
		 */
		rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr,
		    &keylen, &keylen_size);
		if (rv == KMF_ERR_ATTR_NOT_FOUND &&
		    (keytype == KMF_DES || keytype == KMF_DES3))
			/* keylength is not required for DES and 3DES */
			rv = KMF_OK;
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);
	}

	if ((keylen % 8) != 0) {
		return (KMF_ERR_BAD_KEY_SIZE);
	}
	secKeyLen = keylen / 8;  /* in bytes for RC4/AES */

	/*
	 * Only set CKA_VALUE_LEN if the key data was not given and
	 * we are creating an RC4 or AES key.
	 */
	if (keydata == NULL &&
	    (keytype == KMF_AES || keytype == KMF_RC4)) {
		SETATTR(templ, i, CKA_VALUE_LEN, &secKeyLen,
		    sizeof (secKeyLen));
		i++;
	}

	/* Other keytypes */
	keyGenMech.pParameter = NULL_PTR;
	keyGenMech.ulParameterLen = 0;
	switch (keytype) {
		case KMF_AES:
			keyGenMech.mechanism = CKM_AES_KEY_GEN;
			secKeyType = CKK_AES;
			break;
		case KMF_RC4:
			keyGenMech.mechanism = CKM_RC4_KEY_GEN;
			secKeyType = CKK_RC4;
			break;
		case KMF_DES:
			keyGenMech.mechanism = CKM_DES_KEY_GEN;
			secKeyType = CKK_DES;
			break;
		case KMF_DES3:
			keyGenMech.mechanism = CKM_DES3_KEY_GEN;
			secKeyType = CKK_DES3;
			break;
		default:
			return (KMF_ERR_BAD_KEY_TYPE);
	}
	if (keydata != NULL) {
		SETATTR(templ, i, CKA_VALUE, keydata, secKeyLen);
		i++;
	}
	SETATTR(templ, i, CKA_CLASS, &class, sizeof (class));
	i++;
	SETATTR(templ, i, CKA_KEY_TYPE, &secKeyType, sizeof (secKeyType));
	i++;

	if (keylabel != NULL) {
		SETATTR(templ, i, CKA_LABEL, keylabel, strlen(keylabel));
		i++;
	}

	if (is_sensitive == B_TRUE) {
		SETATTR(templ, i, CKA_SENSITIVE, &true, sizeof (true));
	} else {
		SETATTR(templ, i, CKA_SENSITIVE, &false, sizeof (false));
	}
	i++;

	if (is_not_extractable == B_TRUE) {
		SETATTR(templ, i, CKA_EXTRACTABLE, &false, sizeof (false));
	} else {
		SETATTR(templ, i, CKA_EXTRACTABLE, &true, sizeof (true));
	}
	i++;

	SETATTR(templ, i, CKA_TOKEN, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_PRIVATE, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_ENCRYPT, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_DECRYPT, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_SIGN, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_VERIFY, &true, sizeof (true));
	i++;

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* If the key data was given, use C_CreateObject */
	if (keydata != NULL) {
		ckrv = C_CreateObject(hSession, templ, i, &keyhandle);
	} else {
		ckrv = C_GenerateKey(hSession, &keyGenMech, templ, i,
		    &keyhandle);
	}
	if (ckrv != CKR_OK) {
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_KEYGEN_FAILED;
		SET_ERROR(kmfh, ckrv);
		goto out;
	}

setup:
	symkey->kstype = KMF_KEYSTORE_PK11TOKEN;
	symkey->keyalg = keytype;
	symkey->keyclass = KMF_SYMMETRIC;
	symkey->israw = FALSE;
	symkey->keyp = (void *)keyhandle;

out:
	return (rv);
}

KMF_RETURN
KMFPK11_GetSymKeyValue(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
    KMF_RAW_SYM_KEY *rkey)
{
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (symkey == NULL || rkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	else if (symkey->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	/*
	 * If the key is already in "raw" format, copy the data
	 * to the new record if possible.
	 */
	if (symkey->israw) {
		KMF_RAW_KEY_DATA *rawkey = (KMF_RAW_KEY_DATA *)symkey->keyp;

		if (rawkey == NULL)
			return (KMF_ERR_BAD_KEYHANDLE);
		if (rawkey->sensitive)
			return (KMF_ERR_SENSITIVE_KEY);
		if (rawkey->not_extractable)
			return (KMF_ERR_UNEXTRACTABLE_KEY);

		if (rawkey->rawdata.sym.keydata.val == NULL ||
		    rawkey->rawdata.sym.keydata.len == 0)
			return (KMF_ERR_GETKEYVALUE_FAILED);

		rkey->keydata.len = rawkey->rawdata.sym.keydata.len;
		if ((rkey->keydata.val = malloc(rkey->keydata.len)) == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(rkey->keydata.val,
		    rawkey->rawdata.sym.keydata.val, rkey->keydata.len);
	} else {
		rv = get_raw_sym(kmfh, (CK_OBJECT_HANDLE)symkey->keyp, rkey);
	}

	return (rv);
}

KMF_RETURN
KMFPK11_SetTokenPin(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN	ret = KMF_OK;
	CK_RV		rv = CKR_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	session = NULL;
	KMF_CREDENTIAL	*oldcred;
	KMF_CREDENTIAL	*newcred;
	CK_SLOT_ID	slotid;
	CK_USER_TYPE	user = CKU_USER;

	if (handle == NULL || attrlist == NULL || numattr == 0)
		return (KMF_ERR_BAD_PARAMETER);

	oldcred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (oldcred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	newcred = kmf_get_attr_ptr(KMF_NEWPIN_ATTR, attrlist, numattr);
	if (newcred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_SLOT_ID_ATTR, attrlist, numattr,
	    (void *)&slotid, NULL);
	if (rv != KMF_OK) {
		char *tokenlabel = NULL;
		/*
		 * If a slot wasn't given, the user must pass
		 * a token label so we can find the slot here.
		 */
		tokenlabel = kmf_get_attr_ptr(KMF_TOKEN_LABEL_ATTR, attrlist,
		    numattr);
		if (tokenlabel == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		rv = kmf_pk11_token_lookup(handle, tokenlabel, &slotid);
		if (rv != KMF_OK)
			return (rv);
	}
	rv = kmf_get_attr(KMF_PK11_USER_TYPE_ATTR, attrlist, numattr,
	    (void *)&user, NULL);
	if (rv != CKR_OK)
		user = CKU_USER;

	rv = C_OpenSession(slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION,
	    NULL, NULL, &session);
	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		ret = KMF_ERR_UNINITIALIZED;
		goto end;
	}

	rv = C_Login(session, user, (CK_BYTE *)oldcred->cred,
	    oldcred->credlen);
	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		if (rv == CKR_PIN_INCORRECT ||
		    rv == CKR_PIN_INVALID ||
		    rv == CKR_PIN_EXPIRED ||
		    rv == CKR_PIN_LOCKED)
			ret = KMF_ERR_AUTH_FAILED;
		else
			ret = KMF_ERR_INTERNAL;

		goto end;
	}

	rv = C_SetPIN(session,
	    (CK_BYTE *)oldcred->cred, oldcred->credlen,
	    (CK_BYTE *)newcred->cred, newcred->credlen);

	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		if (rv == CKR_PIN_INCORRECT ||
		    rv == CKR_PIN_INVALID ||
		    rv == CKR_PIN_EXPIRED ||
		    rv == CKR_PIN_LOCKED)
			ret = KMF_ERR_AUTH_FAILED;
		else
			ret = KMF_ERR_INTERNAL;
	}
end:
	if (session != NULL)
		(void) C_CloseSession(session);
	return (ret);
}

static KMF_RETURN
create_generic_secret_key(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist, CK_OBJECT_HANDLE *key)
{
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_RV			ckrv;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_OBJECT_CLASS		class = CKO_SECRET_KEY;
	CK_ULONG		secKeyType = CKK_GENERIC_SECRET;
	CK_ULONG		secKeyLen;
	CK_BBOOL		true = TRUE;
	CK_BBOOL		false = FALSE;
	CK_ATTRIBUTE		templ[15];
	int			i;
	int			random_fd = -1;
	int			nread;
	int			freebuf = 0;
	char			*buf = NULL;
	uint32_t		keylen = 0, attrkeylen = 0;
	char			*keylabel = NULL;
	KMF_CREDENTIAL		*cred;
	uint32_t is_sensitive, is_not_extractable;

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);
	if (keylabel == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_SENSITIVE_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_sensitive, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_NON_EXTRACTABLE_BOOL_ATTR, attrlist, numattr,
	    (void *)&is_not_extractable, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_KEY_DATA_ATTR, attrlist, numattr,
	    NULL, &attrkeylen);
	if (rv == KMF_OK && attrkeylen > 0) {
		buf = kmf_get_attr_ptr(KMF_KEY_DATA_ATTR, attrlist,
		    numattr);
		secKeyLen = attrkeylen;
	} else {
		buf = NULL;
		rv = KMF_OK;
	}
	if (buf == NULL) {
		/*
		 * If the key data was not given, key length must
		 * be provided.
		 */
		rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr,
		    &keylen, NULL);
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		/*
		 * Check the key size.
		 */
		if ((keylen % 8) != 0) {
			return (KMF_ERR_BAD_KEY_SIZE);
		} else {
			secKeyLen = keylen/8;  /* in bytes */
		}

		/*
		 * Generate a random number with the key size first.
		 */
		buf = malloc(secKeyLen);
		if (buf == NULL)
			return (KMF_ERR_MEMORY);

		freebuf = 1;
		while ((random_fd = open(DEV_RANDOM, O_RDONLY)) < 0) {
			if (errno != EINTR)
				break;
		}

		if (random_fd < 0) {
			rv = KMF_ERR_KEYGEN_FAILED;
			goto out;
		}

		nread = read(random_fd, buf, secKeyLen);
		if (nread <= 0 || nread != secKeyLen) {
			rv = KMF_ERR_KEYGEN_FAILED;
			goto out;
		}
	}

	/*
	 * Authenticate into the token and call C_CreateObject to generate
	 * a generic secret token key.
	 */
	rv = pk11_authenticate(handle, cred);
	if (rv != KMF_OK) {
		goto out;
	}

	i = 0;
	SETATTR(templ, i, CKA_CLASS, &class, sizeof (class));
	i++;
	SETATTR(templ, i, CKA_KEY_TYPE, &secKeyType, sizeof (secKeyType));
	i++;
	SETATTR(templ, i, CKA_VALUE, buf, secKeyLen);
	i++;

	if (keylabel != NULL) {
		SETATTR(templ, i, CKA_LABEL, keylabel, strlen(keylabel));
		i++;
	}

	if (is_sensitive == B_TRUE) {
		SETATTR(templ, i, CKA_SENSITIVE, &true, sizeof (true));
	} else {
		SETATTR(templ, i, CKA_SENSITIVE, &false, sizeof (false));
	}
	i++;

	if (is_not_extractable == B_TRUE) {
		SETATTR(templ, i, CKA_EXTRACTABLE, &false, sizeof (false));
	} else {
		SETATTR(templ, i, CKA_EXTRACTABLE, &true, sizeof (true));
	}
	i++;

	SETATTR(templ, i, CKA_TOKEN, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_PRIVATE, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_SIGN, &true, sizeof (true));
	i++;

	ckrv = C_CreateObject(hSession, templ, i, key);
	if (ckrv != CKR_OK) {
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_KEYGEN_FAILED;
		SET_ERROR(kmfh, ckrv);
	}

out:
	if (buf != NULL && freebuf)
		free(buf);

	if (random_fd != -1)
		(void) close(random_fd);

	return (rv);
}

KMF_RETURN
KMFPK11_StoreKey(KMF_HANDLE_T handle,
	int numattr,
	KMF_ATTRIBUTE *attlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_CREDENTIAL cred = { NULL, 0 };
	KMF_KEY_HANDLE *key;
	KMF_RAW_KEY_DATA *rawkey = NULL;
	CK_BBOOL btrue = TRUE;
	CK_ATTRIBUTE tokenattr[1];
	CK_OBJECT_HANDLE newobj;
	CK_RV ckrv;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, &cred);
	if (rv != KMF_OK)
		return (rv);

	key = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attlist, numattr);
	if (key == NULL) {
		key = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attlist,
		    numattr);
		if (key == NULL)
			rawkey = kmf_get_attr_ptr(KMF_RAW_KEY_ATTR, attlist,
			    numattr);
	}
	if (key == NULL && rawkey == NULL)
		return (KMF_ERR_ATTR_NOT_FOUND);

	if (rawkey != NULL) {
		rv = store_raw_key(handle, attlist, numattr, rawkey);
	} else if (key && key->kstype == KMF_KEYSTORE_PK11TOKEN) {

		SETATTR(tokenattr, 0, CKA_TOKEN, &btrue, sizeof (btrue));
		/* Copy the key object to the token */
		ckrv = C_CopyObject(kmfh->pk11handle,
		    (CK_OBJECT_HANDLE)key->keyp, tokenattr, 1, &newobj);
		if (ckrv != CKR_OK)  {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}

		/* Replace the object handle with the new token-based one */
		ckrv = C_DestroyObject(kmfh->pk11handle,
		    (CK_OBJECT_HANDLE)key->keyp);
		if (ckrv != CKR_OK)  {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}
		key->keyp = (void *)newobj;
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
	}

	return (rv);
}


KMF_RETURN
KMFPK11_ExportPK12(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_CREDENTIAL *cred = NULL;
	KMF_CREDENTIAL *p12cred = NULL;
	char *filename = NULL;
	KMF_X509_DER_CERT *certlist = NULL;
	KMF_KEY_HANDLE *keylist = NULL;
	uint32_t numcerts;
	uint32_t numkeys;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_ATTRIBUTE fc_attrlist[16];
	int i;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	/* First get the required attributes */
	cred =  kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	p12cred =  kmf_get_attr_ptr(KMF_PK12CRED_ATTR, attrlist, numattr);
	if (p12cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	filename = kmf_get_attr_ptr(KMF_OUTPUT_FILENAME_ATTR, attrlist,
	    numattr);
	if (filename == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Find all the certificates that match the searching criteria */
	i = 0;
	kmf_set_attr_at_index(fc_attrlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	i++;

	kmf_set_attr_at_index(fc_attrlist, i,
	    KMF_COUNT_ATTR, &numcerts, sizeof (uint32_t));
	i++;

	certlabel = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);
	if (certlabel != NULL) {
		kmf_set_attr_at_index(fc_attrlist, i,
		    KMF_CERT_LABEL_ATTR, certlabel, strlen(certlabel));
		i++;
	}

	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	if (issuer != NULL) {
		kmf_set_attr_at_index(fc_attrlist, i,
		    KMF_ISSUER_NAME_ATTR, issuer, strlen(issuer));
		i++;
	}

	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	if (subject != NULL) {
		kmf_set_attr_at_index(fc_attrlist, i,
		    KMF_SUBJECT_NAME_ATTR, subject, strlen(subject));
		i++;
	}

	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);
	if (serial != NULL) {
		kmf_set_attr_at_index(fc_attrlist, i,
		    KMF_BIGINT_ATTR, serial, sizeof (KMF_BIGINT));
		i++;
	}

	rv = KMFPK11_FindCert(handle, i, fc_attrlist);

	if (rv == KMF_OK && numcerts > 0) {
		certlist = (KMF_X509_DER_CERT *)malloc(numcerts *
		    sizeof (KMF_X509_DER_CERT));
		if (certlist == NULL)
			return (KMF_ERR_MEMORY);

		(void) memset(certlist, 0, numcerts *
		    sizeof (KMF_X509_DER_CERT));

		kmf_set_attr_at_index(fc_attrlist, i, KMF_X509_DER_CERT_ATTR,
		    certlist, sizeof (KMF_X509_DER_CERT));
		i++;

		rv = kmf_find_cert(handle, i, fc_attrlist);
		if (rv != KMF_OK) {
			free(certlist);
			return (rv);
		}
	} else {
		return (rv);
	}

	/* For each certificate, find the matching private key */
	numkeys = 0;
	for (i = 0; i < numcerts; i++) {
		KMF_ATTRIBUTE fk_attrlist[16];
		int j = 0;
		KMF_KEY_HANDLE newkey;
		KMF_ENCODE_FORMAT format = KMF_FORMAT_RAWKEY;

		kmf_set_attr_at_index(fk_attrlist, j,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		j++;

		kmf_set_attr_at_index(fk_attrlist, j,
		    KMF_ENCODE_FORMAT_ATTR, &format, sizeof (format));
		j++;

		kmf_set_attr_at_index(fk_attrlist, j,
		    KMF_CREDENTIAL_ATTR, cred, sizeof (KMF_CREDENTIAL));
		j++;

		kmf_set_attr_at_index(fk_attrlist, j,
		    KMF_CERT_DATA_ATTR, &certlist[i].certificate,
		    sizeof (KMF_DATA));
		j++;

		kmf_set_attr_at_index(fk_attrlist, j,
		    KMF_KEY_HANDLE_ATTR, &newkey, sizeof (KMF_KEY_HANDLE));
		j++;

		rv = KMFPK11_FindPrikeyByCert(handle, j, fk_attrlist);
		if (rv == KMF_OK) {
			numkeys++;
			keylist = realloc(keylist,
			    numkeys * sizeof (KMF_KEY_HANDLE));
			if (keylist == NULL) {
				rv = KMF_ERR_MEMORY;
				goto out;
			}
			keylist[numkeys - 1] = newkey;
		} else if (rv == KMF_ERR_KEY_NOT_FOUND) {
			/* it is OK if a key is not found */
			rv = KMF_OK;
		}
	}

	if (rv != KMF_OK)
		goto out;

	rv = kmf_build_pk12(handle, numcerts, certlist, numkeys, keylist,
	    p12cred, filename);

out:
	if (certlist != NULL) {
		for (i = 0; i < numcerts; i++)
			kmf_free_kmf_cert(handle, &certlist[i]);
		free(certlist);
	}
	if (keylist != NULL) {
		for (i = 0; i < numkeys; i++)
			kmf_free_kmf_key(handle, &keylist[i]);
		free(keylist);
	}

	return (rv);
}

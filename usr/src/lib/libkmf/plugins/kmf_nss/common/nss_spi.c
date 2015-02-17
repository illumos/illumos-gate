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
 * NSS keystore wrapper
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <synch.h>

#include <kmfapiP.h>
#include <ber_der.h>
/* NSS related headers */

#include <mps/nss.h>
#include <mps/cert.h>
#include <mps/certdb.h>
#include <mps/secoid.h>
#include <mps/secder.h>
#include <mps/secerr.h>
#include <mps/cryptohi.h>
#include <mps/keyhi.h>
#include <mps/keythi.h>
#include <mps/pk11func.h>
#include <mps/pk11pqg.h>
#include <mps/pkcs12.h>
#include <mps/p12plcy.h>
#include <mps/prerror.h>

#define	NSS_OK		0

mutex_t init_lock = DEFAULTMUTEX;
static int nss_initialized = 0;

KMF_RETURN
NSS_ConfigureKeystore(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_FindCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

void
NSS_FreeKMFCert(KMF_HANDLE_T, KMF_X509_DER_CERT *);

KMF_RETURN
NSS_StoreCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_ImportCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_DeleteCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_CreateKeypair(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_StoreKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_EncodePubKeyData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
NSS_SignData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
NSS_ImportCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_DeleteCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_FindCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_FindKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_FindCertInCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_GetErrorString(KMF_HANDLE_T, char **);

KMF_RETURN
NSS_DeleteKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_FindPrikeyByCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_DecryptData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
NSS_ExportPK12(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_CreateSymKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
NSS_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_SYM_KEY *);

KMF_RETURN
NSS_SetTokenPin(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

static
KMF_PLUGIN_FUNCLIST nss_plugin_table =
{
	1,				/* Version */
	NSS_ConfigureKeystore,
	NSS_FindCert,
	NSS_FreeKMFCert,
	NSS_StoreCert,
	NSS_ImportCert,
	NSS_ImportCRL,
	NSS_DeleteCert,
	NSS_DeleteCRL,
	NSS_CreateKeypair,
	NSS_FindKey,
	NSS_EncodePubKeyData,
	NSS_SignData,
	NSS_DeleteKey,
	NULL    /* ListCRL */,
	NSS_FindCRL,
	NSS_FindCertInCRL,
	NSS_GetErrorString,
	NSS_FindPrikeyByCert,
	NSS_DecryptData,
	NSS_ExportPK12,
	NSS_CreateSymKey,
	NSS_GetSymKeyValue,
	NSS_SetTokenPin,
	NSS_StoreKey,
	NULL /* Finalize */
};

/* additions for importing and exporting PKCS 12 files */
typedef struct p12uContextStr {
	char		*filename;	/* name of file */
	PRFileDesc	*file;		/* pointer to file */
	PRBool		error;		/* error occurred? */
	int		errorValue;	/* which error occurred? */
} p12uContext;

#define	SET_ERROR(h, c) h->lasterr.kstype = KMF_KEYSTORE_NSS; \
	h->lasterr.errcode = c;

KMF_PLUGIN_FUNCLIST *
KMF_Plugin_Initialize()
{
	(void) SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
	(void) SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
	(void) SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
	(void) SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
	(void) SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
	(void) SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
	(void) SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

	return (&nss_plugin_table);
}

static char *
/*ARGSUSED*/
nss_getpassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	if (retry)
		return (NULL);
	if (arg != NULL)
		return ((char *)strdup(arg));
	else
		return (NULL);
}

static KMF_RETURN
nss_authenticate(KMF_HANDLE_T handle,
	PK11SlotInfo *nss_slot, KMF_CREDENTIAL *cred)
{

	SECStatus nssrv = SECSuccess;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	/* If a password was given, try to login to the slot */
	if (cred == NULL || cred->cred == NULL || cred->credlen == 0 ||
	    nss_slot == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (PK11_IsLoggedIn(nss_slot, NULL)) {
		return (KMF_OK);
	}

	PK11_SetPasswordFunc(nss_getpassword);
	nssrv = PK11_Authenticate(nss_slot, PR_TRUE, (void *)cred->cred);

	if (nssrv != SECSuccess) {
		SET_ERROR(kmfh, nssrv);
		PK11_FreeSlot(nss_slot);
		return (KMF_ERR_AUTH_FAILED);
	}

	return (KMF_OK);
}

static SECStatus
Init_NSS_DBs(const char *configdir,
	const char *certPrefix,
	const char *keyPrefix,
	const char *secmodName)
{
	SECStatus rv = NSS_OK;

	(void) mutex_lock(&init_lock);

	/* If another thread already did it, return OK. */
	if (nss_initialized) {
		(void) mutex_unlock(&init_lock);
		return (SECSuccess);
	}

	rv = NSS_Initialize((configdir && strlen(configdir)) ?
	    configdir : "./", certPrefix, keyPrefix,
	    secmodName ? secmodName : "secmod.db", NSS_INIT_COOPERATE);
	if (rv != SECSuccess) {
		goto end;
	}

	nss_initialized++;
end:
	(void) mutex_unlock(&init_lock);
	return (rv);
}

/*
 * When it is called the first time, it will intialize NSS.  Once the NSS
 * is initialized, this function returns KMF_KEYSTORE_ALREADY_INITIALIZED
 * if it is called again.
 */
KMF_RETURN
NSS_ConfigureKeystore(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char    *configdir;
	char    *certPrefix;
	char    *keyPrefix;
	char    *secModName;

	configdir = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	certPrefix = kmf_get_attr_ptr(KMF_CERTPREFIX_ATTR, attrlist, numattr);
	keyPrefix = kmf_get_attr_ptr(KMF_KEYPREFIX_ATTR, attrlist, numattr);
	secModName = kmf_get_attr_ptr(KMF_SECMODNAME_ATTR, attrlist, numattr);

	(void) mutex_lock(&init_lock);
	if (nss_initialized == 0) {
		SECStatus err;

		(void) mutex_unlock(&init_lock);
		err = Init_NSS_DBs(configdir, certPrefix,
		    keyPrefix, secModName);
		if (err != SECSuccess) {
			SET_ERROR(kmfh, err);
			return (KMF_ERR_INTERNAL);
		}
	} else {
		rv = KMF_KEYSTORE_ALREADY_INITIALIZED;
		(void) mutex_unlock(&init_lock);
	}

	return (rv);
}

/*
 * This function sets up the slot to be used for other operations.
 * This function is basically called by every NSS SPI function.
 * For those functions that can only be performed in the internal slot, the
 * boolean "internal_slot_only" argument needs to be TRUE.
 * A slot pointer will be returned when this function is executed successfully.
 */
KMF_RETURN
do_nss_init(void *handle, int numattr,
	KMF_ATTRIBUTE *attrlist,
	boolean_t internal_slot_only,
	PK11SlotInfo **nss_slot)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *slotlabel = NULL;

	if (!nss_initialized)
		return (KMF_ERR_PLUGIN_INIT);

	slotlabel = kmf_get_attr_ptr(KMF_TOKEN_LABEL_ATTR, attrlist, numattr);
	/*
	 * NSS Is already initialized, but we need to find
	 * the right slot.
	 */
	if (slotlabel == NULL ||
	    strcmp(slotlabel, "internal") == 0) {
		*nss_slot = PK11_GetInternalKeySlot();
	} else if (internal_slot_only == TRUE)  {
		rv = KMF_ERR_SLOTNAME;
		goto end;
	} else {
		*nss_slot = PK11_FindSlotByName(slotlabel);
	}

	if (*nss_slot == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_SLOTNAME;
		goto end;
	}

	/*
	 * If the token was not yet initialized, return an error.
	 */
	if (PK11_NeedUserInit(*nss_slot)) {
		rv = KMF_ERR_UNINITIALIZED_TOKEN;
	}

end:
	return (rv);
}

static KMF_RETURN
nss2kmf_cert(CERTCertificate *nss_cert, KMF_X509_DER_CERT *kmf_cert)
{
	kmf_cert->kmf_private.keystore_type = KMF_KEYSTORE_NSS;
	kmf_cert->kmf_private.flags = KMF_FLAG_CERT_VALID;

	kmf_cert->certificate.Length = nss_cert->derCert.len;

	if ((kmf_cert->certificate.Data = malloc(nss_cert->derCert.len)) ==
	    NULL) {
		kmf_cert->certificate.Length = 0;
		return (KMF_ERR_MEMORY);
	}
	(void) memcpy(kmf_cert->certificate.Data, nss_cert->derCert.data,
	    nss_cert->derCert.len);
	if (nss_cert->nickname != NULL)
		kmf_cert->kmf_private.label =
		    (char *)strdup(nss_cert->nickname);
	return (KMF_OK);
}

static KMF_RETURN
nss_getcert_by_label(KMF_HANDLE *kmfh,
	char *name, KMF_X509_DER_CERT *kmf_cert,
	uint32_t *num_certs, KMF_CERT_VALIDITY find_criteria)
{
	KMF_RETURN rv = KMF_OK;
	CERTCertificate *nss_cert;
	SECCertTimeValidity validity;

	nss_cert = PK11_FindCertFromNickname(name, NULL);
	if (nss_cert == NULL) {
		*num_certs = 0;
		SET_ERROR(kmfh, PORT_GetError());
		*num_certs = 0;
		return (KMF_ERR_CERT_NOT_FOUND);
	} else {
		*num_certs = 1;
	}

	switch (find_criteria) {
	case KMF_ALL_CERTS:
		break;
	case KMF_NONEXPIRED_CERTS:
		validity = CERT_CheckCertValidTimes(nss_cert, PR_Now(),
		    PR_FALSE);
		if (validity != secCertTimeValid) {
			/* this is an invalid cert, reject it */
			*num_certs = 0;
			CERT_DestroyCertificate(nss_cert);
			return (KMF_OK);
		}
		break;
	case KMF_EXPIRED_CERTS:
		validity = CERT_CheckCertValidTimes(nss_cert, PR_Now(),
		    PR_FALSE);
		if (validity == secCertTimeValid) {
			/* this is a valid cert, reject it in this case. */
			*num_certs = 0;
			CERT_DestroyCertificate(nss_cert);
			return (KMF_OK);
		}
		break;
	default:
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (kmf_cert != NULL)
		rv = nss2kmf_cert(nss_cert, kmf_cert);

	/* We copied the data we need, so cleanup the internal record */
	CERT_DestroyCertificate(nss_cert);

	if (rv != KMF_OK)
		*num_certs = 0;

	return (rv);
}

static KMF_RETURN
nss_find_matching_certs(PK11SlotInfo *slot,
	char *issuer, char *subject, KMF_BIGINT *serial,
	CERTCertList **certlist, KMF_CERT_VALIDITY find_criteria)
{
	KMF_RETURN rv = KMF_OK;
	SECStatus ret;
	CERTCertList *list;
	CERTCertListNode *node;
	KMF_X509_NAME issuerDN, subjectDN;
	boolean_t findIssuer = FALSE;
	boolean_t findSubject = FALSE;
	boolean_t findSerial = FALSE;

	if (issuer != NULL && strlen(issuer)) {
		rv = kmf_dn_parser(issuer,  &issuerDN);
		if (rv != KMF_OK)
			return (rv);
		findIssuer = TRUE;
	}
	if (subject != NULL && strlen(subject)) {
		rv = kmf_dn_parser(subject, &subjectDN);
		if (rv != KMF_OK)
			return (rv);
		findSubject = TRUE;
	}
	if (serial != 0 && serial->val != NULL && serial->len > 0)
		findSerial = TRUE;

	list = PK11_ListCertsInSlot(slot);
	if (list) {
		node = CERT_LIST_HEAD(list);
		while (!CERT_LIST_END(node, list)) {
			KMF_X509_NAME cmpDN;
			KMF_DATA der;
			boolean_t match;
			CERTCertListNode *freenode;

			if (findIssuer) {
				der.Data = node->cert->derIssuer.data;
				der.Length = node->cert->derIssuer.len;
				rv = DerDecodeName(&der, &cmpDN);
				if (rv == KMF_OK) {
					match = !KMF_CompareRDNs(&issuerDN,
					    &cmpDN);
					kmf_free_dn(&cmpDN);
					if (!match)
						goto delete_and_cont;
				} else {
					goto delete_and_cont;
				}
			}
			if (findSubject) {
				der.Data = node->cert->derSubject.data;
				der.Length = node->cert->derSubject.len;
				rv = DerDecodeName(&der, &cmpDN);
				if (rv == KMF_OK) {
					match = !KMF_CompareRDNs(&subjectDN,
					    &cmpDN);
					kmf_free_dn(&cmpDN);
					if (!match)
						goto delete_and_cont;
				} else {
					goto delete_and_cont;
				}
			}
			if (findSerial) {
				SECItem *sernum;

				sernum = &node->cert->serialNumber;

				if (serial->len != sernum->len)
					goto delete_and_cont;

				if (memcmp(sernum->data, serial->val,
				    serial->len))
					goto delete_and_cont;
			}

			/* select the certs using find criteria */
			switch (find_criteria) {
			case KMF_ALL_CERTS:
				break;
			case KMF_NONEXPIRED_CERTS:
				ret = CERT_CertTimesValid(node->cert);
				if (ret == SECFailure) {
					/* this is an invalid cert */
					goto skip;
				}
				break;

			case KMF_EXPIRED_CERTS:
				ret = CERT_CertTimesValid(node->cert);
				if (ret != SECFailure) {
					/* this is a valid cert */
					goto skip;
				}
				break;
			}
skip:
			node = CERT_LIST_NEXT(node);
			continue;
delete_and_cont:
			freenode = node;
			node = CERT_LIST_NEXT(node);
			CERT_RemoveCertListNode(freenode);
		}
	}

	if (rv == KMF_OK && certlist != NULL) {
		*certlist = list;
	} else {
		CERT_DestroyCertList(list);
	}
	return (rv);
}

static KMF_RETURN
convertCertList(void *kmfhandle,
	CERTCertList *nsscerts, KMF_X509_DER_CERT *kmfcerts,
	uint32_t *numcerts)
{
	KMF_RETURN rv = KMF_OK;
	CERTCertListNode *node;
	uint32_t maxcerts = *numcerts;

	maxcerts = *numcerts;
	if (maxcerts == 0)
		maxcerts = 0xFFFFFFFF;

	*numcerts = 0;

	/*
	 * Don't copy more certs than the caller wanted.
	 */
	for (node = CERT_LIST_HEAD(nsscerts);
	    !CERT_LIST_END(node, nsscerts) && rv == KMF_OK &&
	    (*numcerts) < maxcerts;
	    node = CERT_LIST_NEXT(node), (*numcerts)++) {
		if (kmfcerts != NULL)
			rv = nss2kmf_cert(node->cert, &kmfcerts[*numcerts]);
	}

	/*
	 * If we failed, delete any certs allocated so far.
	 */
	if (rv != KMF_OK) {
		int i;
		for (i = 0; i < *numcerts; i++)
			kmf_free_kmf_cert(kmfhandle, &kmfcerts[i]);

		*numcerts = 0;
	}
	return (rv);
}

KMF_RETURN
NSS_FindCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	CERTCertList *certlist = NULL;
	uint32_t maxcerts;
	uint32_t *num_certs;
	KMF_X509_DER_CERT *kmfcerts = NULL;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY  validity;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}
	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK)
		return (rv);

	num_certs = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (num_certs == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	maxcerts = *num_certs;
	if (maxcerts == 0)
		maxcerts = 0xFFFFFFFF;
	*num_certs = 0;

	/* Get the optional returned certificate list  */
	kmfcerts = kmf_get_attr_ptr(KMF_X509_DER_CERT_ATTR, attrlist, numattr);

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

	if (certlabel != NULL) {
		/* This will only find 1 certificate */
		rv = nss_getcert_by_label(kmfh,	certlabel, kmfcerts, num_certs,
		    validity);
	} else {
		/*
		 * Build a list of matching certs.
		 */
		rv = nss_find_matching_certs(nss_slot, issuer, subject, serial,
		    &certlist, validity);

		/*
		 * If the caller supplied a pointer to storage for
		 * a list of certs, convert up to 'maxcerts' of the
		 * matching certs.
		 */
		if (rv == KMF_OK && certlist != NULL) {
			rv = convertCertList(handle, certlist, kmfcerts,
			    &maxcerts);
			CERT_DestroyCertList(certlist);
			if (rv == KMF_OK)
				*num_certs = maxcerts;
		}
	}

	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (rv == KMF_OK && *num_certs == 0)
		rv = KMF_ERR_CERT_NOT_FOUND;

	return (rv);
}

void
/*ARGSUSED*/
NSS_FreeKMFCert(KMF_HANDLE_T handle,
	KMF_X509_DER_CERT *kmf_cert)
{
	if (kmf_cert != NULL) {
		if (kmf_cert->certificate.Data != NULL) {
			free(kmf_cert->certificate.Data);
			kmf_cert->certificate.Data = NULL;
			kmf_cert->certificate.Length = 0;
		}
		if (kmf_cert->kmf_private.label != NULL) {
			free(kmf_cert->kmf_private.label);
			kmf_cert->kmf_private.label = NULL;
		}
	}
}

KMF_RETURN
NSS_DeleteCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	int nssrv;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CERTCertificate *cert = NULL;
	PK11SlotInfo *nss_slot = NULL;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY  validity;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}
	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK)
		return (rv);

	/* Get the search criteria attributes.  They are all optional. */
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

	/* Start finding the matched certificates and delete them. */
	if (certlabel != NULL) {
		cert = PK11_FindCertFromNickname(certlabel, NULL);
		if (cert == NULL) {
			return (KMF_ERR_CERT_NOT_FOUND);
		}

		switch (validity) {
		case KMF_ALL_CERTS:
			break;
		case KMF_NONEXPIRED_CERTS:
			nssrv = CERT_CertTimesValid(cert);
			if (nssrv == SECFailure) {
				/* this is an invalid cert - skip it */
				goto out;
			}
			break;
		case KMF_EXPIRED_CERTS:
			nssrv = CERT_CertTimesValid(cert);
			if (nssrv != SECFailure) {
				/* this is a valid cert - skip it */
				goto out;
			}
			break;
		}
		/* delete it from database */
		nssrv = SEC_DeletePermCertificate(cert);
		if (nssrv) {
			SET_ERROR(kmfh, nssrv);
			rv = KMF_ERR_INTERNAL;
		}
	} else {
		CERTCertListNode *node;
		CERTCertList *certlist = NULL;

		rv = nss_find_matching_certs(nss_slot, issuer, subject, serial,
		    &certlist, validity);

		for (node = CERT_LIST_HEAD(certlist);
		    !CERT_LIST_END(node, certlist) && rv == KMF_OK;
		    node = CERT_LIST_NEXT(node)) {

			nssrv = SEC_DeletePermCertificate(node->cert);
			if (nssrv) {
				SET_ERROR(kmfh, nssrv);
				rv = KMF_ERR_INTERNAL;
			}
		}

		if (rv == KMF_OK && certlist != NULL) {
			CERT_DestroyCertList(certlist);
		} else if (rv == KMF_OK && certlist == NULL) {
			rv = KMF_ERR_CERT_NOT_FOUND;
		}
	}
out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (cert != NULL) {
		CERT_DestroyCertificate(cert);
	}

	return (rv);
}

static void
InitRandom(char *filename)
{
	char buf[2048];
	int fd;
	PRInt32 count;

	fd = open(filename, O_RDONLY);
	if (!fd)
		return;

	count = read(fd, buf, sizeof (buf));
	if (count > 0) {
		(void) PK11_RandomUpdate(buf, count);
	}

	(void) close(fd);
}

KMF_RETURN
NSS_CreateKeypair(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11RSAGenParams rsaparams;
	void *nssparams;
	CK_MECHANISM_TYPE mechanism;
	ulong_t publicExponent = 0x010001;
	PK11SlotInfo *nss_slot = NULL;
	SECKEYPrivateKey *NSSprivkey = NULL;
	SECKEYPublicKey *NSSpubkey = NULL;
	SECKEYECParams *ecparams = NULL;
	PQGParams *pqgParams = NULL;
	KMF_CREDENTIAL cred;
	boolean_t storekey = TRUE;
	uint32_t keylen = 1024, len;
	uint32_t keylen_size = sizeof (uint32_t);
	KMF_KEY_ALG keytype = KMF_RSA;
	KMF_KEY_HANDLE *pubkey = NULL;
	KMF_KEY_HANDLE *privkey = NULL;
	char *keylabel = NULL;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}
	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (rv);

	rv = nss_authenticate(handle, nss_slot, &cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* "storekey" is optional. Default is TRUE */
	(void) kmf_get_attr(KMF_STOREKEY_BOOL_ATTR, attrlist, numattr,
	    &storekey, NULL);

	/* keytype is optional.  KMF_RSA is default */
	(void) kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
	    (void *)&keytype, NULL);

	rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr,
	    &keylen, &keylen_size);
	if (rv == KMF_ERR_ATTR_NOT_FOUND)
		/* Default keylen = 1024 */
		rv = KMF_OK;
	else if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	pubkey = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attrlist, numattr);
	privkey = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attrlist, numattr);
	if (pubkey == NULL || privkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(pubkey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(privkey, 0, sizeof (KMF_KEY_HANDLE));

	rv = kmf_get_attr(KMF_KEYLABEL_ATTR, attrlist, numattr,	NULL, &len);
	if (rv == KMF_OK && len > 0) {
		keylabel = malloc(len + 1);
		if (keylabel == NULL)
			return (KMF_ERR_MEMORY);
		/* Now fill in the label value */
		(void) memset(keylabel, 0, len + 1);
		rv = kmf_get_attr(KMF_KEYLABEL_ATTR, attrlist, numattr,
		    keylabel, NULL);
		if (rv != KMF_OK) {
			free(keylabel);
			goto cleanup;
		}
	}

	/* Get some random bits */
	InitRandom("/dev/urandom");
	if (keytype == KMF_RSA) {
		KMF_BIGINT rsaexp;

		rsaparams.keySizeInBits = keylen;
		/*
		 * NSS only allows for a 4 byte exponent.
		 * Ignore the exponent parameter if it is too big.
		 */
		if ((rv = kmf_get_attr(KMF_RSAEXP_ATTR, attrlist, numattr,
		    &rsaexp, NULL)) == KMF_OK) {
			if (rsaexp.len > 0 &&
			    rsaexp.len <= sizeof (publicExponent) &&
			    rsaexp.val != NULL) {
				(void) memcpy(&publicExponent, rsaexp.val,
				    rsaexp.len);
			}
		}
		rsaparams.pe = publicExponent;
		mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
		nssparams = &rsaparams;
	} else if (keytype == KMF_DSA) {
		PQGVerify *pqgVerify = NULL;
		int ks;
		SECStatus	nssrv, passed;

		mechanism = CKM_DSA_KEY_PAIR_GEN;

		ks = PQG_PBITS_TO_INDEX(keylen);
		nssrv = PK11_PQG_ParamGen(ks, &pqgParams, &pqgVerify);
		if (nssrv != SECSuccess) {
			SET_ERROR(kmfh, rv);
			PK11_PQG_DestroyVerify(pqgVerify);
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		nssrv = PK11_PQG_VerifyParams(pqgParams, pqgVerify, &passed);
		if (nssrv != SECSuccess || passed != SECSuccess) {
			SET_ERROR(kmfh, rv);
			rv = KMF_ERR_KEYGEN_FAILED;
		}

		PK11_PQG_DestroyVerify(pqgVerify);

		if (rv != KMF_OK) {
			SET_ERROR(kmfh, PORT_GetError());
			goto cleanup;
		}

		nssparams = pqgParams;
	} else if (keytype == KMF_ECDSA) {
		KMF_OID *eccoid = kmf_get_attr_ptr(KMF_ECC_CURVE_OID_ATTR,
		    attrlist, numattr);
		if (eccoid == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		ecparams = SECITEM_AllocItem(NULL, NULL, (eccoid->Length));
		if (!ecparams)
			return (KMF_ERR_MEMORY);

		(void) memcpy(ecparams->data, eccoid->Data, eccoid->Length);

		mechanism = CKM_EC_KEY_PAIR_GEN;
		nssparams = ecparams;
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	NSSprivkey = PK11_GenerateKeyPair(nss_slot, mechanism, nssparams,
	    &NSSpubkey,
	    storekey, /* isPermanent */
	    PR_TRUE, /* isSensitive */
	    (void *)cred.cred);

	if (NSSprivkey == NULL || NSSpubkey == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_KEYGEN_FAILED;
	} else {
		if (keylabel != NULL && strlen(keylabel)) {
			(void) PK11_SetPrivateKeyNickname(NSSprivkey,
			    keylabel);
			(void) PK11_SetPublicKeyNickname(NSSpubkey, keylabel);
		}
		/* Now, convert it to a KMF_KEY object for the framework */
		privkey->kstype = KMF_KEYSTORE_NSS;
		privkey->keyalg = keytype;
		privkey->keyclass = KMF_ASYM_PRI;
		privkey->keylabel = PK11_GetPrivateKeyNickname(NSSprivkey);
		privkey->keyp = (void *)NSSprivkey;

		pubkey->kstype = KMF_KEYSTORE_NSS;
		pubkey->keyalg = keytype;
		pubkey->keyp = (void *)NSSpubkey;
		pubkey->keyclass = KMF_ASYM_PUB;
		pubkey->keylabel = PK11_GetPublicKeyNickname(NSSpubkey);

		rv = KMF_OK;
	}
cleanup:
	if (rv != KMF_OK) {
		if (NSSpubkey)
			(void) PK11_DeleteTokenPublicKey(NSSpubkey);
		if (NSSprivkey)
			(void) PK11_DeleteTokenPrivateKey(NSSprivkey, PR_TRUE);

		privkey->keyp = NULL;
		pubkey->keyp = NULL;
	}

	if (keylabel)
		free(keylabel);

	if (pqgParams != NULL)
		PK11_PQG_DestroyParams(pqgParams);

	if (ecparams != NULL)
		SECITEM_FreeItem(ecparams, PR_TRUE);

	if (nss_slot != NULL)
		PK11_FreeSlot(nss_slot);

	return (rv);
}

KMF_RETURN
NSS_SignData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
    KMF_OID *AlgOID, KMF_DATA *tobesigned,
    KMF_DATA *output)
{
	KMF_RETURN		ret = KMF_OK;
	KMF_ALGORITHM_INDEX	AlgId;
	SECOidTag		signAlgTag;
	SECKEYPrivateKey	*NSSprivkey = NULL;
	SECStatus		rv;
	SECItem			signed_data;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;

	signed_data.data = 0;
	if (key == NULL || AlgOID == NULL ||
	    tobesigned == NULL || output == NULL ||
	    tobesigned->Data == NULL ||
	    output->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the OID to a NSS algorithm */
	AlgId = x509_algoid_to_algid(AlgOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	NSSprivkey = (SECKEYPrivateKey *)key->keyp;

	if (AlgId == KMF_ALGID_MD5WithRSA)
		signAlgTag = SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_MD2WithRSA)
		signAlgTag = SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_SHA1WithRSA)
		signAlgTag = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_SHA256WithRSA)
		signAlgTag = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_SHA384WithRSA)
		signAlgTag = SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_SHA512WithRSA)
		signAlgTag = SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION;
	else if (AlgId == KMF_ALGID_SHA1WithDSA)
		signAlgTag = SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST;
	else if (AlgId == KMF_ALGID_SHA1WithECDSA || AlgId == KMF_ALGID_ECDSA)
		signAlgTag = SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST;
	else if (AlgId == KMF_ALGID_SHA256WithECDSA)
		signAlgTag = SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE;
	else if (AlgId == KMF_ALGID_SHA384WithECDSA)
		signAlgTag = SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE;
	else if (AlgId == KMF_ALGID_SHA512WithECDSA)
		signAlgTag = SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE;
	else	/* NSS does not support DSA with SHA2 hashes (FIPS 186-3) */
		return (KMF_ERR_BAD_PARAMETER);

	rv = SEC_SignData(&signed_data, tobesigned->Data,
	    tobesigned->Length, NSSprivkey, signAlgTag);

	if (rv != 0) {
		SET_ERROR(kmfh, rv);
		return (KMF_ERR_INTERNAL);
	}

	if (signed_data.len <= output->Length) {
		(void) memcpy(output->Data, signed_data.data, signed_data.len);
		output->Length = signed_data.len;
	} else {
		output->Length = 0;
		ret = KMF_ERR_BAD_PARAMETER;
	}
	free(signed_data.data);

	return (ret);
}

KMF_RETURN
NSS_EncodePubKeyData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *keyp,
	KMF_DATA *encoded)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	SECItem *rvitem;
	CERTSubjectPublicKeyInfo *spki = NULL;

	if (keyp == NULL || encoded == NULL || keyp->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	spki = SECKEY_CreateSubjectPublicKeyInfo(keyp->keyp);
	if (spki == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		return (KMF_ERR_MEMORY);
	}

	rvitem = SEC_ASN1EncodeItem(NULL, NULL, spki,
	    CERT_SubjectPublicKeyInfoTemplate);
	if (rvitem != NULL) {
		encoded->Data = malloc(rvitem->len);
		if (encoded->Data == NULL) {
			ret = KMF_ERR_MEMORY;
		} else {
			(void) memcpy(encoded->Data, rvitem->data, rvitem->len);
			encoded->Length = rvitem->len;
		}
		SECITEM_FreeItem(rvitem, TRUE);
	} else {
		SET_ERROR(kmfh, PORT_GetError());
		encoded->Data = NULL;
		encoded->Length = 0;
		ret = KMF_ERR_ENCODING;
	}
	SECKEY_DestroySubjectPublicKeyInfo(spki);

	return (ret);
}

KMF_RETURN
NSS_DeleteKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	PK11SlotInfo *nss_slot = NULL;
	KMF_KEY_HANDLE *key;
	KMF_CREDENTIAL cred;
	boolean_t delete_token = B_TRUE;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}
	/*
	 * "delete_token" means to clear it from the token storage as well
	 * as from memory.
	 */
	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL || key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_DESTROY_BOOL_ATTR, attrlist, numattr,
	    (void *)&delete_token, NULL);
	if (rv != KMF_OK)
		/* "delete_token" is optional. Default is TRUE */
		rv = KMF_OK;

	if (delete_token) {
		SECStatus nssrv = SECSuccess;
		if (key->keyclass != KMF_ASYM_PUB &&
		    key->keyclass != KMF_ASYM_PRI &&
		    key->keyclass != KMF_SYMMETRIC)
			return (KMF_ERR_BAD_KEY_CLASS);

		rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
		if (rv != KMF_OK) {
			return (rv);
		}

		rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
		    (void *)&cred, NULL);
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		rv = nss_authenticate(handle, nss_slot, &cred);
		if (rv != KMF_OK) {
			return (rv);
		}

		if (key->keyclass == KMF_ASYM_PUB) {
			nssrv = PK11_DeleteTokenPublicKey(
			    (SECKEYPublicKey *)key->keyp);
		} else if (key->keyclass == KMF_ASYM_PRI) {
			nssrv = PK11_DeleteTokenPrivateKey(
			    (SECKEYPrivateKey *)key->keyp, PR_TRUE);
		} else if (key->keyclass == KMF_SYMMETRIC) {
			nssrv = PK11_DeleteTokenSymKey(
			    (PK11SymKey *) key->keyp);
			if (nssrv == SECSuccess)
				PK11_FreeSymKey((PK11SymKey *) key->keyp);
		}
		if (nssrv != SECSuccess) {
			SET_ERROR(handle, PORT_GetError());
			rv = KMF_ERR_INTERNAL;
		}
	} else {
		if (key->keyclass == KMF_ASYM_PUB) {
			SECKEY_DestroyPublicKey((SECKEYPublicKey *)key->keyp);
		} else if (key->keyclass == KMF_ASYM_PRI) {
			SECKEY_DestroyPrivateKey((SECKEYPrivateKey *)key->keyp);
		} else if (key->keyclass == KMF_SYMMETRIC) {
			PK11_FreeSymKey((PK11SymKey *) key->keyp);
		} else {
			return (KMF_ERR_BAD_KEY_CLASS);
		}
	}
	key->keyp = NULL;

	return (rv);
}

KMF_RETURN
NSS_GetErrorString(KMF_HANDLE_T handle, char **msgstr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *str;

	/* Get the error string in the default language */
	str = (char *)PR_ErrorToName((PRErrorCode)kmfh->lasterr.errcode);

	if (str != NULL) {
		*msgstr = (char *)strdup(str);
		if ((*msgstr) == NULL)
			ret = KMF_ERR_MEMORY;
	} else {
		*msgstr = NULL;
	}

	return (ret);
}

KMF_RETURN
NSS_FindPrikeyByCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	KMF_CREDENTIAL cred;
	KMF_KEY_HANDLE *key = NULL;
	KMF_DATA *cert = NULL;
	CERTCertificate *nss_cert = NULL;
	SECKEYPrivateKey* privkey = NULL;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK)
		return (rv);

	/* Get the credential */
	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);
	rv = nss_authenticate(handle, nss_slot, &cred);
	if (rv != KMF_OK)
		return (rv);

	/* Get the key handle */
	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get the cert data and decode it */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL || cert->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	nss_cert = CERT_DecodeCertFromPackage((char *)cert->Data,
	    cert->Length);
	if (nss_cert == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		return (KMF_ERR_BAD_CERT_FORMAT);
	}

	privkey = PK11_FindPrivateKeyFromCert(nss_slot, nss_cert, NULL);
	if (privkey == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		return (KMF_ERR_KEY_NOT_FOUND);
	}

	key->kstype = KMF_KEYSTORE_NSS;
	key->keyclass = KMF_ASYM_PRI;
	key->keyp = (void *)privkey;
	key->keylabel = PK11_GetPrivateKeyNickname(privkey);

	CERT_DestroyCertificate(nss_cert);

	return (KMF_OK);
}


KMF_RETURN
NSS_DecryptData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *AlgOID, KMF_DATA *ciphertext,
	KMF_DATA *output)
{
	KMF_RETURN		ret = KMF_OK;
	SECKEYPrivateKey	*NSSprivkey = NULL;
	SECStatus		rv;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	unsigned int in_len = 0, out_len = 0;
	unsigned int total_decrypted = 0, modulus_len = 0;
	uint8_t *in_data, *out_data;
	int i, blocks;

	if (key == NULL || AlgOID == NULL ||
	    ciphertext == NULL || output == NULL ||
	    ciphertext->Data == NULL ||
	    output->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	NSSprivkey = (SECKEYPrivateKey *)key->keyp;
	modulus_len = PK11_GetPrivateModulusLen(NSSprivkey);

	blocks = ciphertext->Length/modulus_len;
	out_data = output->Data;
	in_data = ciphertext->Data;
	out_len = modulus_len - 11;
	in_len = modulus_len;

	for (i = 0; i < blocks; i++) {
		rv = PK11_PrivDecryptPKCS1(NSSprivkey, out_data,
		    &out_len, ciphertext->Length, in_data, in_len);

		if (rv != 0) {
			SET_ERROR(kmfh, rv);
			return (KMF_ERR_INTERNAL);
		}

		out_data += out_len;
		total_decrypted += out_len;
		in_data += in_len;
	}

	output->Length = total_decrypted;

	return (ret);
}

static KMF_KEY_ALG
pk11keytype2kmf(CK_KEY_TYPE type)
{
	switch (type) {
	case CKK_RSA:
		return (KMF_RSA);
	case CKK_DSA:
		return (KMF_RSA);
	case CKK_AES:
		return (KMF_AES);
	case CKK_RC4:
		return (KMF_RC4);
	case CKK_DES:
		return (KMF_DES);
	case CKK_DES3:
		return (KMF_DES3);
	case CKK_EC:
		return (KMF_ECDSA);
	default:
		/* not supported */
		return (KMF_KEYALG_NONE);
	}
}

KMF_RETURN
NSS_FindKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv;
	SECKEYPrivateKeyList *prilist;
	SECKEYPrivateKeyListNode *prinode;
	SECKEYPublicKeyList *publist;
	SECKEYPublicKeyListNode *pubnode;
	PK11SlotInfo *nss_slot = NULL;
	PK11SymKey *symlist = NULL;
	int count;
	uint32_t maxkeys;
	KMF_KEY_HANDLE *keys;
	uint32_t *numkeys;
	KMF_CREDENTIAL *cred = NULL;
	KMF_KEY_CLASS keyclass;
	char *findLabel;
	char *nick;
	int match = 0;
	KMF_KEY_ALG keytype = KMF_KEYALG_NONE;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	numkeys = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* It is OK if this is NULL, we dont need a cred to find public keys */
	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);

	if (cred != NULL) {
		rv = nss_authenticate(handle, nss_slot, cred);
		if (rv != KMF_OK) {
			return (rv);
		}
	}

	maxkeys = *numkeys;
	if (maxkeys == 0)
		maxkeys = 0xFFFFFFFF;
	*numkeys = 0;

	rv = kmf_get_attr(KMF_KEYCLASS_ATTR, attrlist, numattr,
	    (void *)&keyclass, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	findLabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);

	if (keyclass == KMF_ASYM_PUB) {
		publist = PK11_ListPublicKeysInSlot(nss_slot, findLabel);
		if (publist == NULL) {
			rv = KMF_ERR_KEY_NOT_FOUND;
			goto cleanup;
		}
	} else if (keyclass == KMF_ASYM_PRI) {
		prilist = PK11_ListPrivKeysInSlot(nss_slot, findLabel, NULL);
		if (prilist == NULL) {
			rv = KMF_ERR_KEY_NOT_FOUND;
			goto cleanup;
		}
	} else if (keyclass == KMF_SYMMETRIC) {
		symlist = PK11_ListFixedKeysInSlot(nss_slot, findLabel, NULL);
		if (symlist == NULL) {
			rv = KMF_ERR_KEY_NOT_FOUND;
			goto cleanup;
		}
	} else {
		rv = KMF_ERR_BAD_KEY_CLASS;
		goto cleanup;
	}

	keys = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	/* it is okay to have "keys" contains NULL */

	if (keyclass == KMF_ASYM_PUB) {
		for (count = 0, pubnode = PUBKEY_LIST_HEAD(publist);
		    !PUBKEY_LIST_END(pubnode, publist) && count < maxkeys;
		    pubnode = PUBKEY_LIST_NEXT(pubnode)) {
			match = 0;
			/*
			 * Due to bug in NSS, we have to manually match
			 * the labels to be sure we have a match.
			 */
			nick = PK11_GetPublicKeyNickname(pubnode->key);
			if (findLabel) {
				match = (nick &&
				    (strcmp(nick, findLabel) == 0));
			} else {
				/* always match if findLabel is NULL */
				match = 1;
			}
			if (keys != NULL && match) {
				keys[count].kstype = KMF_KEYSTORE_NSS;
				keys[count].keyclass = KMF_ASYM_PUB;
				keys[count].keyp = (void *)pubnode->key;
				keys[count].keylabel = nick;

				if (pubnode->key->keyType == rsaKey)
					keys[count].keyalg = KMF_RSA;
				else if (pubnode->key->keyType == dsaKey)
					keys[count].keyalg = KMF_DSA;
				else if (pubnode->key->keyType == ecKey)
					keys[count].keyalg = KMF_ECDSA;
			}
			if (match)
				count++;
		}
		*numkeys = count;
	} else if (keyclass == KMF_ASYM_PRI) {
		for (count = 0, prinode = PRIVKEY_LIST_HEAD(prilist);
		    !PRIVKEY_LIST_END(prinode, prilist) && count < maxkeys;
		    prinode = PRIVKEY_LIST_NEXT(prinode)) {
			match = 0;
			/*
			 * Due to bug in NSS, we have to manually match
			 * the labels to be sure we have a match.
			 */
			nick = PK11_GetPrivateKeyNickname(prinode->key);
			if (findLabel) {
				match = (nick &&
				    (strcmp(nick, findLabel) == 0));
			} else {
				/* always match if findLabel is NULL */
				match = 1;
			}
			if (keys != NULL && match) {
				keys[count].kstype = KMF_KEYSTORE_NSS;
				keys[count].keyclass = KMF_ASYM_PRI;
				keys[count].keyp = (void *)prinode->key;
				keys[count].keylabel = nick;

				if (prinode->key->keyType == rsaKey)
					keys[count].keyalg = KMF_RSA;
				else if (prinode->key->keyType == dsaKey)
					keys[count].keyalg = KMF_DSA;
				else if (prinode->key->keyType == ecKey)
					keys[count].keyalg = KMF_ECDSA;
			}
			if (match)
				count++;
		}
		*numkeys = count;
	} else if (keyclass == KMF_SYMMETRIC) {
		count = 0;
		rv = kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
		    (void *)&keytype, NULL);
		if (rv != KMF_OK)
			rv = KMF_OK;
		while (symlist && count < maxkeys) {
			PK11SymKey *symkey = symlist;
			CK_KEY_TYPE type;
			KMF_KEY_ALG keyalg;

			match = 0;
			type = PK11_GetSymKeyType(symkey);
			keyalg = pk11keytype2kmf(type);

			symlist = PK11_GetNextSymKey(symkey);

			/*
			 * If keytype is specified in the searching parameter,
			 * check the keytype and skip the key if its keytype
			 * doesn't match.
			 */
			if (keytype != KMF_KEYALG_NONE && keytype != keyalg) {
				/* free that key since we arent using it */
				PK11_FreeSymKey(symkey);
				continue;
			}
			/*
			 * Due to bug in NSS, we have to manually match
			 * the labels to be sure we have a match.
			 */
			nick = PK11_GetSymKeyNickname(symkey);
			if (findLabel) {
				match = (nick &&
				    (strcmp(nick, findLabel) == 0));
			} else {
				/* always match if findLabel is NULL */
				match = 1;
			}

			if (keys != NULL && match) {
				keys[count].kstype = KMF_KEYSTORE_NSS;
				keys[count].keyclass = KMF_SYMMETRIC;
				keys[count].keyp = (void *) symkey;
				keys[count].keylabel = nick;
				keys[count].keyalg = keyalg;
			} else {
				PK11_FreeSymKey(symkey);
			}
			if (match)
				count++;
		}
		/*
		 * Cleanup memory for unused keys.
		 */
		while (symlist != NULL) {
			PK11SymKey *symkey = symlist;

			PK11_FreeSymKey(symkey);
			symlist = PK11_GetNextSymKey(symkey);
		}
		*numkeys = count;
	}

cleanup:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	return (rv);
}

static SECStatus
p12u_SwapUnicodeBytes(SECItem *uniItem)
{
	unsigned int i;
	unsigned char a;
	if ((uniItem == NULL) || (uniItem->len % 2)) {
		return (SECFailure);
		}
	for (i = 0; i < uniItem->len; i += 2) {
		a = uniItem->data[i];
		uniItem->data[i] = uniItem->data[i+1];
		uniItem->data[i+1] = a;
	}
	return (SECSuccess);
}

static PRBool
p12u_ucs2_ascii_conversion_function(
	PRBool		toUnicode,
	unsigned char	*inBuf,
	unsigned int	inBufLen,
	unsigned char	*outBuf,
	unsigned int	maxOutBufLen,
	unsigned int	*outBufLen,
	PRBool		swapBytes)
{
	SECItem it = { siBuffer, NULL, 0 };
	SECItem *dup = NULL;
	PRBool ret;

	it.data = inBuf;
	it.len = inBufLen;
	dup = SECITEM_DupItem(&it);
	/*
	 * If converting Unicode to ASCII, swap bytes before conversion
	 * as neccessary.
	 */
	if (!toUnicode && swapBytes) {
		if (p12u_SwapUnicodeBytes(dup) != SECSuccess) {
			SECITEM_ZfreeItem(dup, PR_TRUE);
			return (PR_FALSE);
		}
	}
	/* Perform the conversion. */
	ret = PORT_UCS2_UTF8Conversion(toUnicode, dup->data, dup->len,
	    outBuf, maxOutBufLen, outBufLen);
	if (dup)
		SECITEM_ZfreeItem(dup, PR_TRUE);

	return (ret);
}

static PRBool
p12u_OpenFile(p12uContext *p12ctx, PRBool fileRead)
{
	if (!p12ctx || !p12ctx->filename) {
		return (PR_FALSE);
	}

	if (fileRead) {
		p12ctx->file = PR_Open(p12ctx->filename, PR_RDONLY, 0400);
	} else {
		p12ctx->file = PR_Open(p12ctx->filename,
		    PR_CREATE_FILE | PR_RDWR | PR_TRUNCATE, 0600);
	}

	if (!p12ctx->file) {
		p12ctx->error = PR_TRUE;
		return (PR_FALSE);
	}

	return (PR_TRUE);
}

static void
p12u_DestroyContext(p12uContext **ppCtx, PRBool removeFile)
{
	if (!ppCtx || !(*ppCtx)) {
		return;
	}

	if ((*ppCtx)->file != NULL) {
		(void) PR_Close((*ppCtx)->file);
	}

	if ((*ppCtx)->filename != NULL) {
		if (removeFile) {
			(void) PR_Delete((*ppCtx)->filename);
		}
		free((*ppCtx)->filename);
	}

	free(*ppCtx);
	*ppCtx = NULL;
}

static p12uContext *
p12u_InitContext(PRBool fileImport, char *filename)
{
	p12uContext *p12ctx;

	p12ctx = PORT_ZNew(p12uContext);
	if (!p12ctx) {
		return (NULL);
	}

	p12ctx->error = PR_FALSE;
	p12ctx->errorValue = 0;
	p12ctx->filename = strdup(filename);

	if (!p12u_OpenFile(p12ctx, fileImport)) {
		p12u_DestroyContext(&p12ctx, PR_FALSE);
		return (NULL);
	}

	return (p12ctx);
}

static void
p12u_WriteToExportFile(void *arg, const char *buf, unsigned long len)
{
	p12uContext *p12cxt = arg;
	int writeLen;

	if (!p12cxt || (p12cxt->error == PR_TRUE)) {
		return;
	}

	if (p12cxt->file == NULL) {
		p12cxt->errorValue = SEC_ERROR_PKCS12_UNABLE_TO_WRITE;
		p12cxt->error = PR_TRUE;
		return;
	}

	writeLen = PR_Write(p12cxt->file, (unsigned char *)buf, (int32)len);

	if (writeLen != (int)len) {
		(void) PR_Close(p12cxt->file);
		free(p12cxt->filename);
		p12cxt->filename = NULL;
		p12cxt->file = NULL;
		p12cxt->errorValue = SEC_ERROR_PKCS12_UNABLE_TO_WRITE;
		p12cxt->error = PR_TRUE;
	}
}

#define	HANDLE_NSS_ERROR(r) {\
	SET_ERROR(kmfh, PORT_GetError()); \
	rv = r; \
	goto out; }

static KMF_RETURN
add_cert_to_bag(SEC_PKCS12ExportContext *p12ecx,
	CERTCertificate *cert, SECItem *pwitem)
{
	KMF_RETURN rv = KMF_OK;
	SEC_PKCS12SafeInfo *keySafe = NULL, *certSafe = NULL;

	keySafe = SEC_PKCS12CreateUnencryptedSafe(p12ecx);
	if (PK11_IsFIPS()) {
		certSafe = keySafe;
	} else {
		certSafe = SEC_PKCS12CreatePasswordPrivSafe(p12ecx, pwitem,
		    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC);
	}

	if (!certSafe || !keySafe) {
		rv = KMF_ERR_INTERNAL;
		goto out;
	}

	if (SEC_PKCS12AddCertAndKey(p12ecx, certSafe, NULL, cert,
	    CERT_GetDefaultCertDB(), keySafe, NULL, PR_TRUE, pwitem,
	    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC)
	    != SECSuccess) {
		rv = KMF_ERR_INTERNAL;
	}
out:
	return (rv);
}

KMF_RETURN
NSS_ExportPK12(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE  *)handle;
	SEC_PKCS12ExportContext *p12ecx = NULL;
	p12uContext *p12ctx = NULL;
	CERTCertList *certlist = NULL;
	CERTCertificate *nsscert = NULL;
	CERTCertListNode* node = NULL;
	PK11SlotInfo	*slot = NULL;
	SECItem pwitem = { siBuffer, NULL, 0 };
	KMF_CREDENTIAL *cred = NULL;
	KMF_CREDENTIAL *p12cred = NULL;
	char *certlabel = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	char *filename = NULL;

	if (kmfh == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &slot);
	if (rv != KMF_OK)
		return (rv);

	cred = kmf_get_attr_ptr(KMF_CREDENTIAL_ATTR, attrlist, numattr);
	if (cred == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = nss_authenticate(handle, slot, cred);
	if (rv != KMF_OK)
		return (rv);

	p12cred = kmf_get_attr_ptr(KMF_PK12CRED_ATTR, attrlist, numattr);
	if (p12cred  == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	filename = kmf_get_attr_ptr(KMF_OUTPUT_FILENAME_ATTR, attrlist,
	    numattr);
	if (filename == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get optional search criteria attributes */
	certlabel = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);
	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);

	/*
	 * Find the certificate(s) first.
	 */
	if (certlabel != NULL) {
		nsscert = PK11_FindCertFromNickname(certlabel, NULL);
		if (nsscert == NULL) {
			HANDLE_NSS_ERROR(KMF_ERR_CERT_NOT_FOUND)
		}
	} else {
		rv = nss_find_matching_certs(slot, issuer, subject, serial,
		    &certlist, 0);

		if (rv == KMF_OK && certlist == NULL) {
			return (KMF_ERR_CERT_NOT_FOUND);
		}
		if (rv != KMF_OK)
			return (rv);
	}

	/*
	 * The KMF_CREDENTIAL holds the password to use for
	 * encrypting the PKCS12 key information.
	 */
	pwitem.data = (uchar_t *)p12cred->cred;
	pwitem.len = p12cred->credlen;

	p12ctx = p12u_InitContext(PR_FALSE, filename);
	if (!p12ctx) {
		HANDLE_NSS_ERROR(KMF_ERR_OPEN_FILE)
	}

	PORT_SetUCS2_ASCIIConversionFunction(
	    p12u_ucs2_ascii_conversion_function);

	p12ecx = SEC_PKCS12CreateExportContext(NULL, NULL, slot, NULL);
	if (!p12ecx) {
		HANDLE_NSS_ERROR(KMF_ERR_OPEN_FILE)
	}

	if (SEC_PKCS12AddPasswordIntegrity(p12ecx, &pwitem, SEC_OID_SHA1)
	    != SECSuccess) {
		HANDLE_NSS_ERROR(KMF_ERR_INTERNAL)
	}

	/*
	 * NSS actually supports storing a list of keys and certs
	 * in the PKCS#12 PDU.  Nice feature.
	 */
	if (certlist != NULL) {
		for (node = CERT_LIST_HEAD(certlist);
		    !CERT_LIST_END(node, certlist) && rv == KMF_OK;
		    node = CERT_LIST_NEXT(node)) {
			rv = add_cert_to_bag(p12ecx, node->cert, &pwitem);
		}
	} else if (nsscert != NULL) {
		rv = add_cert_to_bag(p12ecx, nsscert, &pwitem);
	}

	if (SEC_PKCS12Encode(p12ecx, p12u_WriteToExportFile, p12ctx)
	    != SECSuccess) {
		HANDLE_NSS_ERROR(KMF_ERR_ENCODING)
	}
out:
	if (nsscert)
		CERT_DestroyCertificate(nsscert);

	if (certlist)
		CERT_DestroyCertList(certlist);

	if (p12ctx)
		p12u_DestroyContext(&p12ctx, PR_FALSE);

	if (p12ecx)
		SEC_PKCS12DestroyExportContext(p12ecx);

	return (rv);
}

#define	SETATTR(t, n, atype, value, size) \
	t[n].type = atype; \
	t[n].pValue = (CK_BYTE *)value; \
	t[n].ulValueLen = (CK_ULONG)size;

KMF_RETURN
NSS_CreateSymKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	PK11SymKey *nsskey = NULL;
	CK_MECHANISM_TYPE keyType;
	SECStatus nssrv;
	int keySize;
	KMF_KEY_HANDLE *symkey;
	KMF_CREDENTIAL cred;
	uint32_t keylen;
	uint32_t keylen_size = sizeof (uint32_t);
	KMF_KEY_ALG keytype;
	char *keylabel = NULL;

	if (kmfh == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	symkey = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (symkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr, (void *)&keytype,
	    NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr, &keylen,
	    &keylen_size);
	if (rv == KMF_ERR_ATTR_NOT_FOUND &&
	    (keytype == KMF_DES || keytype == KMF_DES3))
		/* keylength is not required for DES and 3DES */
		rv = KMF_OK;
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);
	if (keylabel == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	switch (keytype) {
	case KMF_AES:
		keyType = CKM_AES_KEY_GEN;
		keySize = keylen;
		if (keySize == 0 || (keySize % 8) != 0)
			return (KMF_ERR_BAD_KEY_SIZE);
		break;
	case KMF_RC4:
		keyType = CKM_RC4_KEY_GEN;
		keySize = keylen;
		if (keySize == 0 || (keySize % 8) != 0)
			return (KMF_ERR_BAD_KEY_SIZE);
		break;
	case KMF_DES:
		keyType = CKM_DES_KEY_GEN;
		keySize = 0; /* required by PK11_TokenKeyGen()  */
		break;
	case KMF_DES3:
		keyType = CKM_DES3_KEY_GEN;
		keySize = 0; /* required by PK11_TokenKeyGen() */
		break;
	case KMF_GENERIC_SECRET:
		keyType = CKM_GENERIC_SECRET_KEY_GEN;
		keySize = keylen;
		if (keySize == 0 || (keySize % 8) != 0)
			return (KMF_ERR_BAD_KEY_SIZE);
		break;
	default:
		rv = KMF_ERR_BAD_KEY_TYPE;
		goto out;
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = nss_authenticate(handle, nss_slot, &cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* convert key length to bytes */
	nsskey = PK11_TokenKeyGen(nss_slot, keyType, NULL, keySize / 8,  NULL,
	    PR_TRUE, (void *)cred.cred);
	if (nsskey == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_KEYGEN_FAILED;
		goto out;
	}

	nssrv = PK11_SetSymKeyNickname(nsskey, keylabel);
	if (nssrv != SECSuccess) {
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_KEYGEN_FAILED;
		goto out;
	}

	symkey->kstype = KMF_KEYSTORE_NSS;
	symkey->keyalg = keytype;
	symkey->keyclass = KMF_SYMMETRIC;
	symkey->israw = FALSE;
	symkey->keyp = (void *)nsskey;

out:
	if (nss_slot != NULL)
		PK11_FreeSlot(nss_slot);

	if (rv != KMF_OK && nsskey != NULL) {
		(void) PK11_DeleteTokenSymKey(nsskey);
		PK11_FreeSymKey(nsskey);
	}
	return (rv);
}

KMF_RETURN
NSS_GetSymKeyValue(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
	KMF_RAW_SYM_KEY *rkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	SECItem *value = NULL;
	PK11SymKey *nsskey;
	SECStatus nss_rv;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (symkey == NULL || rkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	else if (symkey->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (symkey->israw) {
		KMF_RAW_KEY_DATA *rawkey = (KMF_RAW_KEY_DATA *)symkey->keyp;

		if (rawkey == NULL ||
		    rawkey->rawdata.sym.keydata.val == NULL ||
		    rawkey->rawdata.sym.keydata.len == 0)
			return (KMF_ERR_BAD_KEYHANDLE);

		rkey->keydata.len = rawkey->rawdata.sym.keydata.len;
		if ((rkey->keydata.val = malloc(rkey->keydata.len)) == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(rkey->keydata.val,
		    rawkey->rawdata.sym.keydata.val, rkey->keydata.len);
	} else {
		nsskey = (PK11SymKey *)(symkey->keyp);
		if (nsskey == NULL)
			return (KMF_ERR_BAD_KEYHANDLE);

		nss_rv = PK11_ExtractKeyValue(nsskey);
		if (nss_rv != SECSuccess) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_GETKEYVALUE_FAILED;
			goto out;
		}

		value = PK11_GetKeyData(nsskey);
		if (value == NULL) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_GETKEYVALUE_FAILED;
			goto out;
		}

		if (value->len == 0 || value->data == NULL) {
			rv = KMF_ERR_GETKEYVALUE_FAILED;
			goto out;
		}

		rkey->keydata.val = malloc(value->len);
		if (rkey->keydata.val == NULL) {
			rv = KMF_ERR_MEMORY;
			goto out;
		}
		(void) memcpy(rkey->keydata.val, value->data, value->len);
		rkey->keydata.len = value->len;
		(void) memset(value->data, 0, value->len);
	}
out:
	if (value != NULL)
		SECITEM_FreeItem(value, PR_TRUE);
	return (rv);
}

KMF_RETURN
NSS_SetTokenPin(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int rv;
	PK11SlotInfo *nss_slot = NULL;
	KMF_CREDENTIAL oldcred, newcred;

	if (handle == NULL || attrlist == NULL || numattr == 0)
		return (KMF_ERR_BAD_PARAMETER);

	ret = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&oldcred, NULL);
	if (ret != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);
	ret = kmf_get_attr(KMF_NEWPIN_ATTR, attrlist, numattr,
	    (void *)&newcred, NULL);
	if (ret != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	ret = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	/* If it was uninitialized, set it */
	if (ret == KMF_ERR_UNINITIALIZED_TOKEN) {
		rv = PK11_InitPin(nss_slot, NULL, newcred.cred);
		if (rv != SECSuccess) {
			SET_ERROR(kmfh, PORT_GetError());
			ret = KMF_ERR_AUTH_FAILED;
		} else {
			ret = KMF_OK;
		}
	} else if (ret == KMF_OK) {
		ret = nss_authenticate(handle, nss_slot, &oldcred);
		if (ret != KMF_OK) {
			return (ret);
		}
		rv = PK11_ChangePW(nss_slot, oldcred.cred, newcred.cred);
		if (rv != SECSuccess) {
			SET_ERROR(kmfh, PORT_GetError());
			ret = KMF_ERR_AUTH_FAILED;
		}
	}

	return (ret);
}

KMF_RETURN
NSS_StoreKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	KMF_CREDENTIAL cred = { NULL, 0 };
	KMF_KEY_HANDLE *pubkey = NULL, *prikey = NULL;
	KMF_RAW_KEY_DATA *rawkey = NULL;
	char *keylabel = NULL;
	SECStatus ckrv = SECSuccess;
	SECItem nickname = { siBuffer, NULL, 0 };
	CERTCertificate *nss_cert = NULL;

	if (kmfh == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	rv = kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    (void *)&cred, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	rv = nss_authenticate(handle, nss_slot, &cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	pubkey = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attrlist, numattr);
	if (pubkey == NULL) {
		/* look for private key */
		prikey = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attrlist,
		    numattr);
		if (prikey == NULL)
			/* look for raw key */
			rawkey = kmf_get_attr_ptr(KMF_RAW_KEY_ATTR,
			    attrlist, numattr);
	}

	/* If no keys were found, return error */
	if (pubkey == NULL && prikey == NULL && rawkey == NULL)
		return (KMF_ERR_ATTR_NOT_FOUND);

	keylabel = kmf_get_attr_ptr(KMF_KEYLABEL_ATTR, attrlist, numattr);
	if (keylabel != NULL) {
		nickname.data = (uchar_t *)keylabel;
		nickname.len = strlen(keylabel);
	}

	if (rawkey != NULL) {
		uchar_t ver = 0;
		SECKEYPrivateKeyInfo rpk;
		KMF_DATA derkey = { 0, NULL };
		KMF_DATA *cert;

		cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
		if (cert == NULL)
			return (rv);
		/*
		 * Decode the cert into an NSS CERT object so we can access the
		 * SPKI and KeyUsage data later.
		 */
		nss_cert = CERT_DecodeCertFromPackage((char *)cert->Data,
		    cert->Length);

		if (nss_cert == NULL) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_BAD_CERT_FORMAT;
			goto cleanup;
		}

		(void) memset(&rpk, 0, sizeof (rpk));
		rpk.arena = NULL;
		rpk.version.type = siUnsignedInteger;
		rpk.version.data = &ver;
		rpk.version.len = 1;
		if (rawkey->keytype == KMF_RSA) {
			rv = DerEncodeRSAPrivateKey(&derkey,
			    &rawkey->rawdata.rsa);
			if (rv != KMF_OK)
				goto cleanup;
		} else if (rawkey->keytype == KMF_DSA) {
			rv = DerEncodeDSAPrivateKey(&derkey,
			    &rawkey->rawdata.dsa);
			if (rv != KMF_OK)
				goto cleanup;
		} else if (rawkey->keytype == KMF_ECDSA) {
			rv = DerEncodeECPrivateKey(&derkey,
			    &rawkey->rawdata.ec);
			if (rv != KMF_OK)
				goto cleanup;
		}
		rpk.algorithm = nss_cert->subjectPublicKeyInfo.algorithm;
		rpk.privateKey.data = derkey.Data;
		rpk.privateKey.len = derkey.Length;
		rpk.attributes = NULL;

		ckrv = PK11_ImportPrivateKeyInfo(nss_slot, &rpk, &nickname,
		    &nss_cert->subjectPublicKeyInfo.subjectPublicKey, TRUE,
		    TRUE, nss_cert->keyUsage, NULL);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_INTERNAL;
		}
		kmf_free_data(&derkey);
	} else if (pubkey != NULL && pubkey->kstype == KMF_KEYSTORE_NSS) {
		CK_OBJECT_HANDLE pk;
		SECKEYPublicKey *publicKey = (SECKEYPublicKey *) pubkey->keyp;

		pk = PK11_ImportPublicKey(nss_slot, publicKey, PR_TRUE);
		if (pk == CK_INVALID_HANDLE) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_INTERNAL;
		}
	} else if (prikey != NULL && prikey->kstype == KMF_KEYSTORE_NSS) {
		SECKEYPrivateKey *pk;
		SECKEYPrivateKey *privKey = (SECKEYPrivateKey *) prikey->keyp;

		pk = PK11_LoadPrivKey(nss_slot, privKey, NULL, PR_TRUE,
		    PR_TRUE);
		if (pk == CK_INVALID_HANDLE) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_INTERNAL;
		}
		/* We stored it, but don't need the handle anymore */
		SECKEY_DestroyPrivateKey(pk);
	}

cleanup:
	if (nss_cert != NULL)
		CERT_DestroyCertificate(nss_cert);
	PK11_FreeSlot(nss_slot);
	return (rv);
}

/*
 * This function is called by NSS_StoreCert() and NSS_ImportCert().
 * The "label" and "trust_flag" arguments can be NULL.
 */
static KMF_RETURN
store_cert(KMF_HANDLE_T handle, PK11SlotInfo *nss_slot, KMF_DATA *cert,
    char *label, char *trust_flag)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	SECStatus nss_rv;
	CERTCertDBHandle *certHandle = CERT_GetDefaultCertDB();
	CERTCertificate *nss_cert = NULL;
	CERTCertTrust *nss_trust = NULL;

	if (nss_slot == NULL || cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	nss_cert = CERT_DecodeCertFromPackage((char *)cert->Data,
	    cert->Length);
	if (nss_cert == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

	/* Store the cert into the NSS database */
	nss_rv = PK11_ImportCert(nss_slot, nss_cert, CK_INVALID_HANDLE,
	    label, 0);
	if (nss_rv) {
		SET_ERROR(kmfh, nss_rv);
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

	/* If trust_flag is NULL, then we are done */
	if (trust_flag == NULL)
		goto out;

	nss_trust = (CERTCertTrust *) malloc(sizeof (CERTCertTrust));
	if (nss_trust == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	nss_rv = CERT_DecodeTrustString(nss_trust, trust_flag);
	if (nss_rv) {
		SET_ERROR(kmfh, nss_rv);
		ret = KMF_ERR_BAD_PARAMETER;
		goto out;
	}

	nss_rv = CERT_ChangeCertTrust(certHandle, nss_cert, nss_trust);
	if (nss_rv) {
		SET_ERROR(kmfh, nss_rv);
		ret = KMF_ERR_BAD_PARAMETER;
	}

out:
	if (nss_cert != NULL) {
		CERT_DestroyCertificate(nss_cert);
	}

	if (nss_trust != NULL) {
		free(nss_trust);
	}

	return (ret);
}


KMF_RETURN
NSS_StoreCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	PK11SlotInfo *nss_slot = NULL;
	KMF_DATA *cert = NULL;
	char *label = NULL;
	char *trust_flag = NULL;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (ret != KMF_OK)
		return (ret);

	/* Get the cert data  */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL || cert->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* The label attribute is optional */
	label = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);

	/* The trustflag attriburte is optional */
	trust_flag = kmf_get_attr_ptr(KMF_TRUSTFLAG_ATTR, attrlist, numattr);

	ret = store_cert(handle, nss_slot, cert, label, trust_flag);

out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	return (ret);
}


KMF_RETURN
NSS_ImportCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	PK11SlotInfo *nss_slot = NULL;
	KMF_DATA cert = { 0, NULL };
	KMF_DATA cert_der = { 0, NULL };
	KMF_DATA *cptr = NULL;
	KMF_ENCODE_FORMAT format;
	char *label = NULL;
	char *trust_flag = NULL;
	char *certfile = NULL;

	if (handle == NULL || attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (ret != KMF_OK)
		return (ret);

	/* Get the input cert filename attribute */
	certfile = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist, numattr);
	if (certfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Check the cert file and auto-detect the file format of it. */
	ret = kmf_is_cert_file(handle, certfile, &format);
	if (ret != KMF_OK)
		return (ret);

	ret = kmf_read_input_file(handle, certfile, &cert);
	if (ret != KMF_OK) {
		return (ret);
	}

	/*
	 * If the imported cert is in PEM format, convert it to
	 * DER format in order to store it in NSS token.
	 */
	if (format == KMF_FORMAT_PEM) {
		int derlen;
		ret = kmf_pem_to_der(cert.Data, cert.Length,
		    &cert_der.Data, &derlen);
		if (ret != KMF_OK) {
			goto cleanup;
		}
		cert_der.Length = (size_t)derlen;
		cptr = &cert_der;
	} else {
		cptr = &cert;
	}

	label = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);
	trust_flag = kmf_get_attr_ptr(KMF_TRUSTFLAG_ATTR, attrlist, numattr);
	ret = store_cert(handle, nss_slot, cptr, label, trust_flag);

cleanup:
	if (format == KMF_FORMAT_PEM) {
		kmf_free_data(&cert_der);
	}

	kmf_free_data(&cert);

	return (ret);
}


KMF_RETURN
NSS_ImportCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	CERTSignedCrl *nss_crl = NULL;
	KMF_ENCODE_FORMAT format;
	int importOptions;
	SECItem crlDER;
	KMF_DATA crl1;
	KMF_DATA crl2;
	char *crlfilename;
	boolean_t crlcheck = FALSE;

	if (attrlist == NULL || numattr == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (ret != KMF_OK) {
		return (ret);
	}

	crlfilename = kmf_get_attr_ptr(KMF_CRL_FILENAME_ATTR, attrlist,
	    numattr);
	if (crlfilename == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	/*
	 * Check if the input CRL file is a valid CRL file and auto-detect
	 * the encoded format of the file.
	 */
	ret = kmf_is_crl_file(handle, crlfilename, &format);
	if (ret != KMF_OK)
		return (ret);

	ret = kmf_get_attr(KMF_CRL_CHECK_ATTR, attrlist, numattr,
	    &crlcheck, NULL);
	if (ret != KMF_OK)
		ret = KMF_OK; /* CRL_CHECK is optional */

	/* set importOptions */
	if (crlcheck == B_FALSE) {
		importOptions = CRL_IMPORT_DEFAULT_OPTIONS |
		    CRL_IMPORT_BYPASS_CHECKS;
	} else {
		importOptions = CRL_IMPORT_DEFAULT_OPTIONS;
	}


	/* Read in the CRL file */
	crl1.Data = NULL;
	crl2.Data = NULL;
	ret = kmf_read_input_file(handle, crlfilename, &crl1);
	if (ret != KMF_OK) {
		return (ret);
	}

	/* If the input CRL is in PEM format, convert it to DER first. */
	if (format == KMF_FORMAT_PEM) {
		int len;
		ret = kmf_pem_to_der(crl1.Data, crl1.Length,
		    &crl2.Data, &len);
		if (ret != KMF_OK) {
			goto out;
		}
		crl2.Length = (size_t)len;
	}

	crlDER.data = format == KMF_FORMAT_ASN1 ? crl1.Data : crl2.Data;
	crlDER.len = format == KMF_FORMAT_ASN1 ? crl1.Length : crl2.Length;

	nss_crl = PK11_ImportCRL(nss_slot, &crlDER, NULL, SEC_CRL_TYPE,
	    NULL, importOptions, NULL, CRL_DECODE_DEFAULT_OPTIONS);

	if (nss_crl == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		ret = KMF_ERR_BAD_CRLFILE;
		goto out;
	}

out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (crl1.Data != NULL) {
		free(crl1.Data);
	}

	if (crl2.Data != NULL) {
		free(crl2.Data);
	}

	if (nss_crl != NULL) {
		(void) SEC_DestroyCrl(nss_crl);
	}

	return (ret);
}

KMF_RETURN
NSS_DeleteCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CERTSignedCrl *crl = NULL;
	CERTCertificate *cert = NULL;
	PK11SlotInfo *nss_slot = NULL;
	CERTCrlHeadNode *crlList = NULL;
	CERTCrlNode *crlNode = NULL;
	PRArenaPool *arena = NULL;
	CERTName *name = NULL;
	CERTCertDBHandle *certHandle = CERT_GetDefaultCertDB();
	char *issuername, *subjectname;

	/* check params */
	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	issuername = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist,
	    numattr);
	subjectname = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist,
	    numattr);

	/* Caller must specify issuer or subject but not both */
	if ((issuername == NULL && subjectname == NULL) ||
	    (issuername != NULL && subjectname != NULL))
		return (KMF_ERR_BAD_PARAMETER);

	/* Find the CRL based on the deletion criteria. */
	if (issuername != NULL) {
		/*
		 * If the deletion is based on the issuer's certificate
		 * nickname, we will get the issuer's cert first, then
		 * get the CRL from the cert.
		 */
		cert = CERT_FindCertByNicknameOrEmailAddr(certHandle,
		    issuername);
		if (!cert) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_CERT_NOT_FOUND;
			goto out;
		}

		crl = SEC_FindCrlByName(certHandle, &cert->derSubject,
		    SEC_CRL_TYPE);
		if (crl == NULL) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_CRL_NOT_FOUND;
			goto out;
		}
	} else {
		/*
		 * If the deletion is based on the CRL's subject name, we will
		 * get all the CRLs from the internal database and search
		 * for the CRL with the same subject name.
		 */
		boolean_t found = B_FALSE;
		int nssrv;

		nssrv = SEC_LookupCrls(certHandle, &crlList, SEC_CRL_TYPE);
		if (nssrv) {
			SET_ERROR(kmfh, nssrv);
			rv = KMF_ERR_CRL_NOT_FOUND;
			goto out;
		}

		if (crlList == NULL) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_CRL_NOT_FOUND;
			goto out;
		}

		/* Allocate space for name */
		arena = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);
		if (arena == NULL) {
			rv = KMF_ERR_MEMORY;
			goto out;
		}

		name = PORT_ArenaZAlloc(arena, sizeof (*name));
		if (name == NULL) {
			rv = KMF_ERR_MEMORY;
			goto out;
		}
		name->arena = arena;

		crlNode  = crlList->first;
		while (crlNode && !found) {
			char *asciiname = NULL;
			SECItem* issuer;

			name = &crlNode->crl->crl.name;
			if (!name) {
				SET_ERROR(kmfh, PORT_GetError());
				rv = KMF_ERR_CRL_NOT_FOUND;
				break;
			}

			asciiname = CERT_NameToAscii(name);
			if (asciiname == NULL) {
				SET_ERROR(kmfh, PORT_GetError());
				rv = KMF_ERR_CRL_NOT_FOUND;
				break;
			}

			if (strcmp(subjectname, asciiname) == 0) {
				found = B_TRUE;
				issuer = &crlNode->crl->crl.derName;
				crl = SEC_FindCrlByName(certHandle, issuer,
				    SEC_CRL_TYPE);
				if (crl == NULL) {
					/* We found a cert but no CRL */
					SET_ERROR(kmfh,  PORT_GetError());
					rv = KMF_ERR_CRL_NOT_FOUND;
				}
			}
			PORT_Free(asciiname);
			crlNode = crlNode->next;
		}

		if (rv) {
			goto out;
		}
	}

	if (crl) {
		(void) SEC_DeletePermCRL(crl);
	}

out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (crlList != NULL) {
		PORT_FreeArena(crlList->arena, PR_FALSE);
	}

	if (arena != NULL) {
		PORT_FreeArena(arena, PR_FALSE);
	}

	if (cert != NULL) {
		CERT_DestroyCertificate(cert);
	}

	if (crl != NULL) {
		(void) SEC_DestroyCrl(crl);
	}

	return (rv);
}

KMF_RETURN
NSS_FindCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	CERTCrlHeadNode *crlList = NULL;
	CERTCrlNode *crlNode = NULL;
	PRArenaPool *arena = NULL;
	CERTName *name = NULL;
	SECStatus nssrv;
	char *asciiname = NULL;
	int crl_num;
	int i, *CRLCount;
	CERTCertDBHandle *certHandle = CERT_GetDefaultCertDB();
	char **CRLNameList;

	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	CRLCount = kmf_get_attr_ptr(KMF_CRL_COUNT_ATTR,	attrlist, numattr);
	if (CRLCount == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CRLNameList = (char **)kmf_get_attr_ptr(KMF_CRL_NAMELIST_ATTR,
	    attrlist, numattr);

	/* Look up Crls */
	nssrv = SEC_LookupCrls(certHandle, &crlList, SEC_CRL_TYPE);
	if (nssrv) {
		SET_ERROR(kmfh, rv);
		rv = KMF_ERR_CRL_NOT_FOUND;
		goto out;
	}

	/* Allocate space for name first */
	arena = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);
	if (arena == NULL) {
		rv = KMF_ERR_MEMORY;
		goto out;
	}

	name = PORT_ArenaZAlloc(arena, sizeof (*name));
	if (name == NULL) {
		rv = KMF_ERR_MEMORY;
		goto out;
	}
	name->arena = arena;

	/*
	 * Loop thru the crlList and create a crl list with CRL's subject name.
	 */
	crlNode  = crlList->first;
	crl_num = 0;
	while (crlNode) {
		char *subj_name;

		/* Get the CRL subject name */
		name = &crlNode->crl->crl.name;
		if (!name) {
			SET_ERROR(kmfh, PORT_GetError());
			rv = KMF_ERR_CRL_NOT_FOUND;
			break;
		}


		if (CRLNameList != NULL) {
			asciiname = CERT_NameToAscii(name);
			if (asciiname == NULL) {
				SET_ERROR(kmfh, PORT_GetError());
				rv = KMF_ERR_CRL_NOT_FOUND;
				break;
			}
			subj_name = strdup(asciiname);
			PORT_Free(asciiname);
			if (subj_name == NULL) {
				rv = KMF_ERR_MEMORY;
				break;
			}
			CRLNameList[crl_num] = subj_name;
		}

		crl_num++;
		crlNode = crlNode->next;
	}

	if (rv == KMF_OK) {
		/* success */
		*CRLCount = crl_num;
	}

out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (crlList != NULL) {
		PORT_FreeArena(crlList->arena, PR_FALSE);
	}

	if (arena != NULL) {
		PORT_FreeArena(arena, PR_FALSE);
	}

	/* If failed, free memory allocated for the returning rlist */
	if (rv && (CRLNameList != NULL)) {
		for (i = 0; i < crl_num; i++) {
			free(CRLNameList[i]);
		}
	}

	return (rv);
}

KMF_RETURN
NSS_FindCertInCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	PK11SlotInfo *nss_slot = NULL;
	CERTCertificate *cert = NULL;
	CERTSignedCrl *crl = NULL;
	CERTCrlEntry *entry;
	boolean_t match = B_FALSE;
	int i;
	CERTCertDBHandle *certHandle = CERT_GetDefaultCertDB();
	char *certlabel;
	KMF_DATA *certdata;

	/* check params */
	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	rv = do_nss_init(handle, numattr, attrlist, FALSE, &nss_slot);
	if (rv != KMF_OK) {
		return (rv);
	}

	certlabel = kmf_get_attr_ptr(KMF_CERT_LABEL_ATTR, attrlist, numattr);

	/* Find the certificate first */
	if (certlabel != NULL) {
		cert = CERT_FindCertByNicknameOrEmailAddr(certHandle,
		    certlabel);
	} else {
		SECItem derCert = { siBuffer, NULL, 0 };

		certdata = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR,
		    attrlist, numattr);

		if (certdata == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		derCert.data = certdata->Data;
		derCert.len = certdata->Length;

		cert = CERT_FindCertByDERCert(certHandle, &derCert);
	}

	if (cert == NULL) {
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_CERT_NOT_FOUND;
		goto out;
	}

	/* Find the CRL with the same issuer as the given certificate. */
	crl = SEC_FindCrlByName(certHandle, &cert->derIssuer, SEC_CRL_TYPE);
	if (crl == NULL) {
		/*
		 * Could not find the CRL issued by the same issuer. This
		 * usually means that the CRL is not installed in the DB.
		 */
		SET_ERROR(kmfh, PORT_GetError());
		rv = KMF_ERR_CRL_NOT_FOUND;
		goto out;

	}

	/* Check if the certificate's serialNumber is revoked in the CRL */
	i = 0;
	while ((entry = (crl->crl).entries[i++]) != NULL) {
		if (SECITEM_CompareItem(&(cert->serialNumber),
		    &(entry->serialNumber)) == SECEqual) {
			match = B_TRUE;
			break;
		}
	}

	if (!match) {
		rv = KMF_ERR_NOT_REVOKED;
	}

out:
	if (nss_slot != NULL) {
		PK11_FreeSlot(nss_slot);
	}

	if (cert != NULL) {
		CERT_DestroyCertificate(cert);
	}

	if (crl != NULL) {
		(void) SEC_DestroyCrl(crl);
	}

	return (rv);
}

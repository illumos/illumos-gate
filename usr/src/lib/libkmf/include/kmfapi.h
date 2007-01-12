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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Constant definitions and function prototypes for the KMF library.
 * Commonly used data types are defined in "kmftypes.h".
 */

#ifndef _KMFAPI_H
#define	_KMFAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmftypes.h>
#include <security/cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Setup operations.
 */
extern KMF_RETURN KMF_Initialize(KMF_HANDLE_T *, char *, char *);
extern KMF_RETURN KMF_ConfigureKeystore(KMF_HANDLE_T, KMF_CONFIG_PARAMS *);
extern KMF_RETURN KMF_Finalize(KMF_HANDLE_T);

/*
 * Key operations.
 */
extern KMF_RETURN KMF_SignDataWithKey(KMF_HANDLE_T,
	KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_VerifyDataWithKey(KMF_HANDLE_T,
	KMF_KEY_HANDLE *, KMF_ALGORITHM_INDEX, KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_CreateKeypair(KMF_HANDLE_T,
	KMF_CREATEKEYPAIR_PARAMS *, KMF_KEY_HANDLE *, KMF_KEY_HANDLE *);

extern KMF_RETURN KMF_DeleteKeyFromKeystore(KMF_HANDLE_T,
	KMF_DELETEKEY_PARAMS *, KMF_KEY_HANDLE *);

extern KMF_RETURN KMF_SignCertRecord(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	KMF_X509_CERTIFICATE *, KMF_DATA *);

extern KMF_RETURN KMF_FindKey(KMF_HANDLE_T, KMF_FINDKEY_PARAMS *,
	KMF_KEY_HANDLE *, uint32_t *);

extern KMF_RETURN KMF_StorePrivateKey(KMF_HANDLE_T, KMF_STOREKEY_PARAMS *,
	KMF_RAW_KEY_DATA *);

extern KMF_RETURN KMF_CreateSymKey(KMF_HANDLE_T, KMF_CREATESYMKEY_PARAMS *,
	KMF_KEY_HANDLE *);

extern KMF_RETURN KMF_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	KMF_RAW_SYM_KEY *);

/*
 * Certificate operations.
 */
extern KMF_RETURN KMF_FindCert(KMF_HANDLE_T, KMF_FINDCERT_PARAMS *,
	KMF_X509_DER_CERT *, uint32_t *);

extern KMF_RETURN KMF_EncodeCertRecord(KMF_X509_CERTIFICATE *,
	KMF_DATA *);
extern KMF_RETURN KMF_SignCertWithKey(KMF_HANDLE_T, const KMF_DATA *,
	KMF_KEY_HANDLE *, KMF_DATA *);
extern KMF_RETURN KMF_SignCertWithCert(KMF_HANDLE_T,
	KMF_CRYPTOWITHCERT_PARAMS *,
	const KMF_DATA *, KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_SignDataWithCert(KMF_HANDLE_T,
	KMF_CRYPTOWITHCERT_PARAMS *, KMF_DATA *, KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_VerifyCertWithKey(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	const KMF_DATA *);
extern KMF_RETURN KMF_VerifyCertWithCert(KMF_HANDLE_T, const KMF_DATA *,
	const KMF_DATA *);
extern KMF_RETURN KMF_VerifyDataWithCert(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *,
	const KMF_DATA *);

extern KMF_RETURN KMF_EncryptWithCert(KMF_HANDLE_T, KMF_DATA *,
	KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_DecryptWithCert(KMF_HANDLE_T,
	KMF_CRYPTOWITHCERT_PARAMS *, KMF_DATA *, KMF_DATA *, KMF_DATA *);

extern KMF_RETURN KMF_StoreCert(KMF_HANDLE_T,
	KMF_STORECERT_PARAMS *, KMF_DATA *);
extern KMF_RETURN KMF_ImportCert(KMF_HANDLE_T, KMF_IMPORTCERT_PARAMS *);
extern KMF_RETURN KMF_DeleteCertFromKeystore(KMF_HANDLE_T,
	KMF_DELETECERT_PARAMS *);

extern KMF_RETURN KMF_ValidateCert(KMF_HANDLE_T,
	KMF_VALIDATECERT_PARAMS *, int  *);

extern KMF_RETURN KMF_CreateCertFile(KMF_DATA *, KMF_ENCODE_FORMAT, char *);

extern KMF_RETURN KMF_DownloadCert(KMF_HANDLE_T, char *, char *, int,
	unsigned int, char *, KMF_ENCODE_FORMAT *);
extern KMF_RETURN KMF_IsCertFile(KMF_HANDLE_T, char *, KMF_ENCODE_FORMAT *);

extern KMF_RETURN KMF_CheckCertDate(KMF_HANDLE_T, KMF_DATA *);

/*
 * CRL operations.
 */
extern KMF_RETURN KMF_ImportCRL(KMF_HANDLE_T, KMF_IMPORTCRL_PARAMS *);
extern KMF_RETURN KMF_DeleteCRL(KMF_HANDLE_T, KMF_DELETECRL_PARAMS *);
extern KMF_RETURN KMF_ListCRL(KMF_HANDLE_T, KMF_LISTCRL_PARAMS *, char **);
extern KMF_RETURN KMF_FindCRL(KMF_HANDLE_T, KMF_FINDCRL_PARAMS *,
	char **, int *);

extern KMF_RETURN KMF_FindCertInCRL(KMF_HANDLE_T,
	KMF_FINDCERTINCRL_PARAMS *);
extern KMF_RETURN KMF_VerifyCRLFile(KMF_HANDLE_T,
	KMF_VERIFYCRL_PARAMS *);

extern KMF_RETURN KMF_CheckCRLDate(KMF_HANDLE_T,
	KMF_CHECKCRLDATE_PARAMS *);
extern KMF_RETURN KMF_DownloadCRL(KMF_HANDLE_T, char *, char *,
	int, unsigned int, char *, KMF_ENCODE_FORMAT *);
extern KMF_RETURN KMF_IsCRLFile(KMF_HANDLE_T, char *, KMF_ENCODE_FORMAT *);

/*
 * CSR operations.
 */
extern KMF_RETURN KMF_SetCSRPubKey(KMF_HANDLE_T,
	KMF_KEY_HANDLE *, KMF_CSR_DATA *);
extern KMF_RETURN KMF_SetCSRVersion(KMF_CSR_DATA *, uint32_t);
extern KMF_RETURN KMF_SetCSRSubjectName(KMF_CSR_DATA *, KMF_X509_NAME *);
extern KMF_RETURN KMF_CreateCSRFile(KMF_DATA *, KMF_ENCODE_FORMAT, char *);
extern KMF_RETURN KMF_SetCSRExtension(KMF_CSR_DATA *, KMF_X509_EXTENSION *);
extern KMF_RETURN KMF_SetCSRSignatureAlgorithm(KMF_CSR_DATA *,
	KMF_ALGORITHM_INDEX);
extern KMF_RETURN KMF_SetCSRSubjectAltName(KMF_CSR_DATA *, char *,
	int, KMF_GENERALNAMECHOICES);
extern KMF_RETURN KMF_SetCSRKeyUsage(KMF_CSR_DATA *, int, uint16_t);
extern KMF_RETURN KMF_SignCSR(KMF_HANDLE_T, const KMF_CSR_DATA *,
	KMF_KEY_HANDLE *, KMF_DATA *);

/*
 * GetCert operations.
 */
extern KMF_RETURN KMF_GetCertExtensionData(const KMF_DATA *, KMF_OID *,
	KMF_X509_EXTENSION *);

extern KMF_RETURN KMF_GetCertCriticalExtensions(const KMF_DATA *,
	KMF_X509_EXTENSION **, int *);

extern KMF_RETURN KMF_GetCertNonCriticalExtensions(const KMF_DATA *,
	KMF_X509_EXTENSION **, int *);

extern KMF_RETURN KMF_GetCertKeyUsageExt(const KMF_DATA *,
	KMF_X509EXT_KEY_USAGE *);

extern KMF_RETURN KMF_GetCertEKU(const KMF_DATA *, KMF_X509EXT_EKU *);

extern KMF_RETURN KMF_GetCertBasicConstraintExt(const KMF_DATA *,
	KMF_BOOL *, KMF_X509EXT_BASICCONSTRAINTS *);

extern KMF_RETURN KMF_GetCertPoliciesExt(const KMF_DATA *,
	KMF_BOOL *, KMF_X509EXT_CERT_POLICIES *);

extern KMF_RETURN KMF_GetCertAuthInfoAccessExt(const KMF_DATA *,
	KMF_X509EXT_AUTHINFOACCESS *);

extern KMF_RETURN KMF_GetCertCRLDistributionPointsExt(const KMF_DATA *,
	KMF_X509EXT_CRLDISTPOINTS *);

extern KMF_RETURN KMF_GetCertVersionString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertSubjectNameString(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN KMF_GetCertIssuerNameString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertSerialNumberString(KMF_HANDLE_T, const KMF_DATA *,
	char **);

extern KMF_RETURN KMF_GetCertStartDateString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertEndDateString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertPubKeyAlgString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertSignatureAlgString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertPubKeyDataString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertEmailString(KMF_HANDLE_T,
	const KMF_DATA *, char **);

extern KMF_RETURN KMF_GetCertExtensionString(KMF_HANDLE_T, const KMF_DATA *,
	KMF_PRINTABLE_ITEM, char **);

extern KMF_RETURN KMF_GetCertIDData(const KMF_DATA *, KMF_DATA *);
extern KMF_RETURN KMF_GetCertIDString(const KMF_DATA *, char **);
extern KMF_RETURN KMF_GetCertValidity(const KMF_DATA *, time_t *, time_t *);

/*
 * SetCert operations
 */
extern KMF_RETURN KMF_SetCertPubKey(KMF_HANDLE_T, KMF_KEY_HANDLE *,
	KMF_X509_CERTIFICATE *);

extern KMF_RETURN KMF_SetCertSubjectName(KMF_X509_CERTIFICATE *,
	KMF_X509_NAME *);

extern KMF_RETURN KMF_SetCertKeyUsage(KMF_X509_CERTIFICATE *, int, uint16_t);

extern KMF_RETURN KMF_SetCertIssuerName(KMF_X509_CERTIFICATE *,
	KMF_X509_NAME *);

extern KMF_RETURN KMF_SetCertSignatureAlgorithm(KMF_X509_CERTIFICATE *,
	KMF_ALGORITHM_INDEX);

extern KMF_RETURN KMF_SetCertValidityTimes(KMF_X509_CERTIFICATE *,
	time_t, uint32_t);

extern KMF_RETURN KMF_SetCertSerialNumber(KMF_X509_CERTIFICATE *,
	KMF_BIGINT *);

extern KMF_RETURN KMF_SetCertVersion(KMF_X509_CERTIFICATE *, uint32_t);

extern KMF_RETURN KMF_SetCertIssuerAltName(KMF_X509_CERTIFICATE *,
	int, KMF_GENERALNAMECHOICES, char *);

extern KMF_RETURN KMF_SetCertSubjectAltName(KMF_X509_CERTIFICATE *,
	int, KMF_GENERALNAMECHOICES, char *);

extern KMF_RETURN KMF_AddCertEKU(KMF_X509_CERTIFICATE *, KMF_OID *, int);

extern KMF_RETURN KMF_SetCertExtension(KMF_X509_CERTIFICATE *,
	KMF_X509_EXTENSION *);

extern KMF_RETURN KMF_SetCertBasicConstraintExt(KMF_X509_CERTIFICATE *,
	KMF_BOOL, KMF_X509EXT_BASICCONSTRAINTS *);

extern KMF_RETURN KMF_ExportPK12(KMF_HANDLE_T, KMF_EXPORTP12_PARAMS *, char *);
extern KMF_RETURN KMF_ImportPK12(KMF_HANDLE_T, char *, KMF_CREDENTIAL *,
	KMF_DATA **, int *, KMF_RAW_KEY_DATA **, int *);
extern KMF_RETURN KMF_ImportKeypair(KMF_HANDLE_T, char *, KMF_CREDENTIAL *,
	KMF_DATA **, int *, KMF_RAW_KEY_DATA **, int *);

/*
 * Get OCSP response operation.
 */
extern KMF_RETURN KMF_GetOCSPForCert(KMF_HANDLE_T, KMF_DATA *,	KMF_DATA *,
	KMF_DATA *);

extern KMF_RETURN KMF_CreateOCSPRequest(KMF_HANDLE_T, KMF_OCSPREQUEST_PARAMS *,
	char *);

extern KMF_RETURN KMF_GetEncodedOCSPResponse(KMF_HANDLE_T, char *, char *, int,
	char *, int, char *, unsigned int);

extern KMF_RETURN KMF_GetOCSPStatusForCert(KMF_HANDLE_T,
	KMF_OCSPRESPONSE_PARAMS_INPUT *,
	KMF_OCSPRESPONSE_PARAMS_OUTPUT *);

/*
 * Policy Operations
 */
extern KMF_RETURN KMF_SetPolicy(KMF_HANDLE_T, char *, char *);

/*
 * Error handling.
 */
extern KMF_RETURN KMF_GetPluginErrorString(KMF_HANDLE_T, char **);
extern KMF_RETURN KMF_GetKMFErrorString(KMF_RETURN, char **);

/*
 * Miscellaneous
 */
extern KMF_RETURN KMF_DNParser(char *, KMF_X509_NAME *);
extern KMF_RETURN KMF_DN2Der(KMF_X509_NAME *, KMF_DATA *);
extern KMF_RETURN KMF_ReadInputFile(KMF_HANDLE_T, char *, KMF_DATA *);
extern KMF_RETURN KMF_Der2Pem(KMF_OBJECT_TYPE, unsigned char *,
	int, unsigned char **, int *);
extern KMF_RETURN KMF_Pem2Der(unsigned char *, int, unsigned char **, int *);
extern char *KMF_OID2String(KMF_OID *);
extern KMF_RETURN KMF_String2OID(char *, KMF_OID *);
extern int KMF_CompareRDNs(KMF_X509_NAME *, KMF_X509_NAME *);
extern KMF_RETURN KMF_GetFileFormat(char *, KMF_ENCODE_FORMAT *);
extern uint16_t KMF_StringToKeyUsage(char *);
extern KMF_RETURN KMF_SetTokenPin(KMF_HANDLE_T, KMF_SETPIN_PARAMS *,
	KMF_CREDENTIAL *);
extern KMF_RETURN KMF_HexString2Bytes(unsigned char *, unsigned char **,
	size_t *);

/*
 * Memory cleanup operations
 */
extern void KMF_FreeDN(KMF_X509_NAME *);
extern void KMF_FreeKMFCert(KMF_HANDLE_T, KMF_X509_DER_CERT *);
extern void KMF_FreeData(KMF_DATA *);
extern void KMF_FreeAlgOID(KMF_X509_ALGORITHM_IDENTIFIER *);
extern void KMF_FreeExtension(KMF_X509_EXTENSION *);
extern void KMF_FreeTBSCSR(KMF_TBS_CSR *);
extern void KMF_FreeSignedCSR(KMF_CSR_DATA *);
extern void KMF_FreeTBSCert(KMF_X509_TBS_CERT *);
extern void KMF_FreeSignedCert(KMF_X509_CERTIFICATE *);
extern void KMF_FreeString(char *);
extern void KMF_FreeEKU(KMF_X509EXT_EKU *);
extern void KMF_FreeSPKI(KMF_X509_SPKI *);
extern void KMF_FreeKMFKey(KMF_HANDLE_T, KMF_KEY_HANDLE *);
extern void KMF_FreeBigint(KMF_BIGINT *);
extern void KMF_FreeRawKey(KMF_RAW_KEY_DATA *);
extern void KMF_FreeRawSymKey(KMF_RAW_SYM_KEY *);
extern void KMF_FreeCRLDistributionPoints(KMF_X509EXT_CRLDISTPOINTS *);

/* APIs for PKCS#11 token */
extern KMF_RETURN KMF_PK11TokenLookup(KMF_HANDLE_T, char *, CK_SLOT_ID *);
extern CK_SESSION_HANDLE KMF_GetPK11Handle(KMF_HANDLE_T);

#ifdef __cplusplus
}
#endif
#endif /* _KMFAPI_H */

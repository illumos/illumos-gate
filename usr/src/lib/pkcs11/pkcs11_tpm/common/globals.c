/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "tpmtok_int.h"

CK_BBOOL	initialized = FALSE;

pthread_mutex_t  native_mutex;
pthread_mutex_t   pkcs_mutex, obj_list_mutex,
	sess_list_mutex, login_mutex;

void *xproclock;

DL_NODE  *sess_list	= NULL;
DL_NODE  *sess_obj_list  = NULL;
DL_NODE  *publ_token_obj_list = NULL;
DL_NODE  *priv_token_obj_list = NULL;
DL_NODE  *object_map	= NULL;

CK_STATE  global_login_state = 0;

LW_SHM_TYPE *global_shm;

CK_ULONG next_session_handle = 1;
CK_ULONG next_object_handle = 1;

TOKEN_DATA  *nv_token_data = NULL;

extern CK_RV LW_Initialize();
extern CK_RV SC_GetFunctionList();
extern CK_RV SC_GetTokenInfo();
extern CK_RV SC_GetMechanismList();
extern CK_RV SC_GetMechanismInfo();
extern CK_RV SC_InitToken();
extern CK_RV SC_InitPIN();
extern CK_RV SC_SetPIN();
extern CK_RV SC_OpenSession();
extern CK_RV SC_CloseSession();
extern CK_RV SC_CloseAllSessions();
extern CK_RV SC_GetSessionInfo();
extern CK_RV SC_GetOperationState();
extern CK_RV SC_SetOperationState();
extern CK_RV SC_Login();
extern CK_RV SC_Logout();
extern CK_RV SC_CreateObject();
extern CK_RV SC_CopyObject();
extern CK_RV SC_DestroyObject();
extern CK_RV SC_GetObjectSize();
extern CK_RV SC_GetAttributeValue();
extern CK_RV SC_SetAttributeValue();
extern CK_RV SC_FindObjectsInit();
extern CK_RV SC_FindObjects();
extern CK_RV SC_FindObjectsFinal();
extern CK_RV SC_EncryptInit();
extern CK_RV SC_Encrypt();
extern CK_RV SC_EncryptUpdate();
extern CK_RV SC_EncryptFinal();
extern CK_RV SC_DecryptInit();
extern CK_RV SC_Decrypt();
extern CK_RV SC_DecryptUpdate();
extern CK_RV SC_DecryptFinal();
extern CK_RV SC_DigestInit();
extern CK_RV SC_Digest();
extern CK_RV SC_DigestUpdate();
extern CK_RV SC_DigestKey();
extern CK_RV SC_DigestFinal();
extern CK_RV SC_SignInit();
extern CK_RV SC_Sign();
extern CK_RV SC_SignUpdate();
extern CK_RV SC_SignFinal();
extern CK_RV SC_SignRecoverInit();
extern CK_RV SC_SignRecover();
extern CK_RV SC_VerifyInit();
extern CK_RV SC_Verify();
extern CK_RV SC_VerifyUpdate();
extern CK_RV SC_VerifyFinal();
extern CK_RV SC_VerifyRecoverInit();
extern CK_RV SC_VerifyRecover();
extern CK_RV SC_DigestEncryptUpdate();
extern CK_RV SC_DecryptDigestUpdate();
extern CK_RV SC_SignEncryptUpdate();
extern CK_RV SC_DecryptVerifyUpdate();
extern CK_RV SC_GenerateKey();
extern CK_RV SC_GenerateKeyPair();
extern CK_RV SC_WrapKey();
extern CK_RV SC_UnwrapKey();
extern CK_RV SC_DeriveKey();
extern CK_RV SC_SeedRandom();
extern CK_RV SC_GenerateRandom();
extern CK_RV SC_GetFunctionStatus();
extern CK_RV SC_CancelFunction();
extern CK_RV SC_WaitForSlotEvent();

CK_BYTE  ber_rsaEncryption[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};
CK_BYTE  ber_md5WithRSAEncryption[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04
};
CK_BYTE  ber_sha1WithRSAEncryption[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05
};

CK_BYTE  ber_AlgMd5[] =    {
    0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x02, 0x05, 0x05, 0x00
};
CK_BYTE  ber_AlgSha1[] =   {
    0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
    0x00
};
CK_BYTE  ber_AlgIdRSAEncryption[] = {
    0x30, 0x0D, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00
};

CK_ULONG ber_rsaEncryptionLen = sizeof (ber_rsaEncryption);
CK_ULONG ber_md5WithRSAEncryptionLen = sizeof (ber_md5WithRSAEncryption);
CK_ULONG ber_sha1WithRSAEncryptionLen = sizeof (ber_sha1WithRSAEncryption);

CK_ULONG ber_AlgMd5Len =    sizeof (ber_AlgMd5);
CK_ULONG ber_AlgSha1Len =   sizeof (ber_AlgSha1);
CK_ULONG ber_AlgIdRSAEncryptionLen = sizeof (ber_AlgIdRSAEncryption);

MECH_LIST_ELEMENT mech_list[] = {
	{ CKM_RSA_PKCS_KEY_PAIR_GEN,	{512, 2048, CKF_HW |
	    CKF_GENERATE_KEY_PAIR } },
	{ CKM_RSA_PKCS, {512, 2048, CKF_HW   | CKF_ENCRYPT | CKF_DECRYPT |
	    CKF_WRAP	 | CKF_UNWRAP  | CKF_SIGN | CKF_VERIFY  |
	    CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER } },

	{ CKM_RSA_PKCS_OAEP,	{512, 2048, CKF_HW   | CKF_ENCRYPT |
	    CKF_DECRYPT | CKF_WRAP	 | CKF_UNWRAP  |
	    CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER }},

#if 0
	/* No RSA_X_509 support for now... */
	{ CKM_RSA_X_509, {512, 2048, CKF_HW  |
	    CKF_ENCRYPT	| CKF_DECRYPT |
	    CKF_WRAP	 | CKF_UNWRAP  |
	    CKF_SIGN	 | CKF_VERIFY  |
	    CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER } },
#endif

	{CKM_MD5_RSA_PKCS,
	{512, 2048, CKF_HW	| CKF_SIGN    | CKF_VERIFY } },

	{ CKM_SHA1_RSA_PKCS,
	{512, 2048, CKF_HW	| CKF_SIGN    | CKF_VERIFY } },

	{CKM_SHA_1,
	{0,    0, CKF_DIGEST } },

	{CKM_SHA_1_HMAC,
	{0,    0, CKF_SIGN | CKF_VERIFY } },

	{CKM_SHA_1_HMAC_GENERAL,
	{0,    0, CKF_SIGN | CKF_VERIFY } },

	{CKM_MD5,
	{0,    0, CKF_DIGEST } },

	{CKM_MD5_HMAC,
	{0,    0, CKF_SIGN | CKF_VERIFY } },

	{CKM_MD5_HMAC_GENERAL,
	{0,    0, CKF_SIGN | CKF_VERIFY } },
};

CK_ULONG  mech_list_len = (sizeof (mech_list) / sizeof (MECH_LIST_ELEMENT));

/*
 * default SO pin hash values
 *
 * default SO pin = "87654321"
 */
CK_BYTE default_so_pin_md5[MD5_DIGEST_LENGTH] = {
	0x5E, 0x86, 0x67, 0xA4, 0x39, 0xC6, 0x8F, 0x51,
	0x45, 0xDD, 0x2F, 0xCB, 0xEC, 0xF0, 0x22, 0x09
};

CK_BYTE default_so_pin_sha[SHA1_DIGEST_LENGTH] = {
	0xA7, 0xD5, 0x79, 0xBA, 0x76, 0x39, 0x80, 0x70,
	0xEA, 0xE6, 0x54, 0xC3, 0x0F, 0xF1, 0x53, 0xA4,
	0xC2, 0x73, 0x27, 0x2A
};

/* SH - 1 of "12345678" */
CK_BYTE default_user_pin_sha[SHA1_DIGEST_LENGTH] = {
	0x7c, 0x22, 0x2f, 0xb2, 0x92, 0x7d, 0x82, 0x8a,
	0xf2, 0x2f, 0x59, 0x21, 0x34, 0xe8, 0x93, 0x24,
	0x80, 0x63, 0x7c, 0x0d
};

CK_BYTE user_pin_md5[MD5_DIGEST_LENGTH];
CK_BYTE so_pin_md5[MD5_DIGEST_LENGTH];

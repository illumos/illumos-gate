/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* crypto/engine/hw_pk11_err.c */
/* This product includes software developed by the OpenSSL Project for 
 * use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 * This project also referenced hw_pkcs11-0.9.7b.patch written by 
 * Afchine Madjlessi.
 */
/* ====================================================================
 * Copyright (c) 2000-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/err.h>
#include "hw_pk11_err.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA pk11_str_functs[]=
{
    {ERR_PACK(0,PK11_F_INIT,0),			"PK11_INIT"},
    {ERR_PACK(0,PK11_F_FINISH,0),		"PK11_FINISH"},
    {ERR_PACK(0,PK11_F_DESTROY,0),		"PK11_DESTROY"},
    {ERR_PACK(0,PK11_F_CTRL,0),			"PK11_CTRL"},
    {ERR_PACK(0,PK11_F_RSA_INIT,0),		"PK11_RSA_INIT"},
    {ERR_PACK(0,PK11_F_RSA_FINISH,0),		"PK11_RSA_FINISH"},
    {ERR_PACK(0,PK11_F_GET_PUB_RSA_KEY,0),	"PK11_GET_PUB_RSA_KEY"},
    {ERR_PACK(0,PK11_F_GET_PRIV_RSA_KEY,0),	"PK11_GET_PRIV_RSA_KEY"},
    {ERR_PACK(0,PK11_F_RSA_GEN_KEY,0),		"PK11_RSA_GEN_KEY"},
    {ERR_PACK(0,PK11_F_RSA_PUB_ENC,0),		"PK11_RSA_PUB_ENC"},
    {ERR_PACK(0,PK11_F_RSA_PRIV_ENC,0),		"PK11_RSA_PRIV_ENC"},
    {ERR_PACK(0,PK11_F_RSA_PUB_DEC,0),		"PK11_RSA_PUB_DEC"},
    {ERR_PACK(0,PK11_F_RSA_PRIV_DEC,0),		"PK11_RSA_PRIV_DEC"},
    {ERR_PACK(0,PK11_F_RSA_SIGN,0),		"PK11_RSA_SIGN"},
    {ERR_PACK(0,PK11_F_RSA_VERIFY,0),		"PK11_RSA_VERIFY"},
    {ERR_PACK(0,PK11_F_RAND_ADD,0),		"PK11_RAND_ADD"},
    {ERR_PACK(0,PK11_F_RAND_BYTES,0),		"PK11_RAND_BYTES"},
    {ERR_PACK(0,PK11_F_GET_SESSION,0),		"PK11_GET_SESSION"},
    {ERR_PACK(0,PK11_F_FREE_SESSION,0),		"PK11_FREE_SESSION"},
    {ERR_PACK(0,PK11_F_LOAD_PUBKEY,0),		"PK11_LOAD_PUBKEY"},
    {ERR_PACK(0,PK11_F_LOAD_PRIVKEY,0),		"PK11_LOAD_PRIV_KEY"},
    {ERR_PACK(0,PK11_F_RSA_PUB_ENC_LOW,0),	"PK11_RSA_PUB_ENC_LOW"},
    {ERR_PACK(0,PK11_F_RSA_PRIV_ENC_LOW,0),	"PK11_RSA_PRIV_ENC_LOW"},
    {ERR_PACK(0,PK11_F_RSA_PUB_DEC_LOW,0),	"PK11_RSA_PUB_DEC_LOW"},
    {ERR_PACK(0,PK11_F_RSA_PRIV_DEC_LOW,0),	"PK11_RSA_PRIV_DEC_LOW"},
    {ERR_PACK(0,PK11_F_DSA_SIGN,0),		"PK11_DSA_SIGN"},
    {ERR_PACK(0,PK11_F_DSA_VERIFY,0),		"PK11_DSA_VERIFY"},
    {ERR_PACK(0,PK11_F_DSA_INIT,0),		"PK11_DSA_INIT"},
    {ERR_PACK(0,PK11_F_DSA_FINISH,0),		"PK11_DSA_FINISH"},
    {ERR_PACK(0,PK11_F_GET_PUB_DSA_KEY,0),	"PK11_GET_PUB_DSA_KEY"},
    {ERR_PACK(0,PK11_F_GET_PRIV_DSA_KEY,0),	"PK11_GET_PRIV_DSA_KEY"},
    {ERR_PACK(0,PK11_F_DH_INIT,0),		"PK11_DH_INIT"},
    {ERR_PACK(0,PK11_F_DH_FINISH,0),		"PK11_DH_FINISH"},
    {ERR_PACK(0,PK11_F_MOD_EXP_DH,0),		"PK11_MOD_EXP_DH"},
    {ERR_PACK(0,PK11_F_GET_DH_KEY,0),		"PK11_GET_DH_KEY"},
    {ERR_PACK(0,PK11_F_FREE_ALL_SESSIONS,0),	"PK11_FREE_ALL_SESSIONS"},
    {ERR_PACK(0,PK11_F_SETUP_SESSION,0),	"PK11_SETUP_SESSION"},
    {ERR_PACK(0,PK11_F_DESTROY_OBJECT,0),	"PK11_DESTROY_OBJECT"},
    {ERR_PACK(0,PK11_F_CIPHER_INIT,0),		"PK11_CIPHER_INIT"},
    {ERR_PACK(0,PK11_F_CIPHER_DO_CIPHER,0),	"PK11_CIPHER_DO_CIPHER"},
    {ERR_PACK(0,PK11_F_GET_CIPHER_KEY,0),	"PK11_GET_CIPHER_KEY"},
    {ERR_PACK(0,PK11_F_DIGEST_INIT,0),		"PK11_DIGEST_INIT"},
    {ERR_PACK(0,PK11_F_DIGEST_UPDATE,0),	"PK11_DIGEST_UPDATE"},
    {ERR_PACK(0,PK11_F_DIGEST_FINAL,0),		"PK11_DIGEST_FINAL"},
    {ERR_PACK(0,PK11_F_CHOOSE_SLOT,0),		"PK11_CHOOSE_SLOT"},
    {ERR_PACK(0,PK11_F_CIPHER_FINAL,0),		"PK11_CIPHER_FINAL"},
    {ERR_PACK(0,PK11_F_LIBRARY_INIT,0),		"PK11_LIBRARY_INIT"},
    {ERR_PACK(0,PK11_F_LOAD,0),			"ENGINE_LOAD_PK11"},
    {ERR_PACK(0,PK11_F_DH_GEN_KEY,0),		"PK11_DH_GEN_KEY"},
    {ERR_PACK(0,PK11_F_DH_COMP_KEY,0),		"PK11_DH_COMP_KEY"},
    {ERR_PACK(0,PK11_F_DIGEST_COPY,0),		"PK11_DIGEST_COPY"},
    {ERR_PACK(0,PK11_F_CIPHER_CLEANUP,0),	"PK11_CIPHER_CLEANUP"},
    {ERR_PACK(0,PK11_F_ACTIVE_ADD,0),		"PK11_ACTIVE_ADD"},
    {ERR_PACK(0,PK11_F_ACTIVE_DELETE,0),	"PK11_ACTIVE_DELETE"},
    {ERR_PACK(0,PK11_F_CHECK_HW_MECHANISMS,0),	"PK11_CHECK_HW_MECHANISMS"},
    {ERR_PACK(0,PK11_F_INIT_SYMMETRIC,0),	"PK11_INIT_SYMMETRIC"},
    {ERR_PACK(0,PK11_F_ADD_AES_CTR_NIDS,0),	"PK11_ADD_AES_CTR_NIDS"},
    {0,NULL}
};

static ERR_STRING_DATA pk11_str_reasons[]=
{
    {PK11_R_ALREADY_LOADED                 ,"PKCS#11 DSO already loaded"},
    {PK11_R_DSO_FAILURE                    ,"unable to load PKCS#11 DSO"},
    {PK11_R_NOT_LOADED                     ,"PKCS#11 DSO not loaded"},
    {PK11_R_PASSED_NULL_PARAMETER          ,"null parameter passed"},
    {PK11_R_COMMAND_NOT_IMPLEMENTED        ,"command not implemented"},
    {PK11_R_INITIALIZE                     ,"C_Initialize failed"},
    {PK11_R_FINALIZE                       ,"C_Finalize failed"},
    {PK11_R_GETINFO                        ,"C_GetInfo faile"},
    {PK11_R_GETSLOTLIST                    ,"C_GetSlotList failed"},
    {PK11_R_NO_MODULUS_OR_NO_EXPONENT      ,"no modulus or no exponent"},
    {PK11_R_ATTRIBUT_SENSITIVE_OR_INVALID  ,"attr sensitive or invalid"},
    {PK11_R_GETATTRIBUTVALUE               ,"C_GetAttributeValue failed"},
    {PK11_R_NO_MODULUS                     ,"no modulus"},
    {PK11_R_NO_EXPONENT                    ,"no exponent"},
    {PK11_R_FINDOBJECTSINIT                ,"C_FindObjectsInit failed"},
    {PK11_R_FINDOBJECTS                    ,"C_FindObjects failed"},
    {PK11_R_FINDOBJECTSFINAL               ,"C_FindObjectsFinal failed"},
    {PK11_R_CREATEOBJECT                   ,"C_CreateObject failed"},
    {PK11_R_DESTROYOBJECT                  ,"C_DestroyObject failed"},
    {PK11_R_OPENSESSION                    ,"C_OpenSession failed"},
    {PK11_R_CLOSESESSION                   ,"C_CloseSession failed"},
    {PK11_R_ENCRYPTINIT                    ,"C_EncryptInit failed"},
    {PK11_R_ENCRYPT                        ,"C_Encrypt failed"},
    {PK11_R_SIGNINIT                       ,"C_SignInit failed"},
    {PK11_R_SIGN                           ,"C_Sign failed"},
    {PK11_R_DECRYPTINIT                    ,"C_DecryptInit failed"},
    {PK11_R_DECRYPT                        ,"C_Decrypt failed"},
    {PK11_R_VERIFYINIT                     ,"C_VerifyRecover failed"},
    {PK11_R_VERIFY                         ,"C_Verify failed	"},
    {PK11_R_VERIFYRECOVERINIT              ,"C_VerifyRecoverInit failed"},
    {PK11_R_VERIFYRECOVER                  ,"C_VerifyRecover failed"},
    {PK11_R_GEN_KEY                        ,"C_GenerateKeyPair failed"},
    {PK11_R_SEEDRANDOM                     ,"C_SeedRandom failed"},
    {PK11_R_GENERATERANDOM                 ,"C_GenerateRandom failed"},
    {PK11_R_INVALID_MESSAGE_LENGTH         ,"invalid message length"},
    {PK11_R_UNKNOWN_ALGORITHM_TYPE         ,"unknown algorithm type"},
    {PK11_R_UNKNOWN_ASN1_OBJECT_ID         ,"unknown asn1 onject id"},
    {PK11_R_UNKNOWN_PADDING_TYPE           ,"unknown padding type"},
    {PK11_R_PADDING_CHECK_FAILED           ,"padding check failed"},
    {PK11_R_DIGEST_TOO_BIG                 ,"digest too big"},
    {PK11_R_MALLOC_FAILURE                 ,"malloc failure"},
    {PK11_R_CTRL_COMMAND_NOT_IMPLEMENTED   ,"ctl command not implemented"},
    {PK11_R_DATA_GREATER_THAN_MOD_LEN      ,"data is bigger than mod"},
    {PK11_R_DATA_TOO_LARGE_FOR_MODULUS     ,"data is too larger for mod"},
    {PK11_R_MISSING_KEY_COMPONENT          ,"a dsa component is missing"},
    {PK11_R_INVALID_SIGNATURE_LENGTH       ,"invalid signature length"},
    {PK11_R_INVALID_DSA_SIGNATURE_R        ,"missing r in dsa verify"},
    {PK11_R_INVALID_DSA_SIGNATURE_S        ,"missing s in dsa verify"},
    {PK11_R_INCONSISTENT_KEY               ,"inconsistent key type"},
    {PK11_R_ENCRYPTUPDATE                  ,"C_EncryptUpdate failed"},
    {PK11_R_DECRYPTUPDATE                  ,"C_DecryptUpdate failed"},
    {PK11_R_DIGESTINIT                     ,"C_DigestInit failed"},
    {PK11_R_DIGESTUPDATE                   ,"C_DigestUpdate failed"},
    {PK11_R_DIGESTFINAL                    ,"C_DigestFinal failed"},
    {PK11_R_ENCRYPTFINAL                   ,"C_EncryptFinal failed"},
    {PK11_R_DECRYPTFINAL                   ,"C_DecryptFinal failed"},
    {PK11_R_NO_PRNG_SUPPORT                ,"Slot does not support PRNG"},
    {PK11_R_GETTOKENINFO                   ,"C_GetTokenInfo failed"},
    {PK11_R_DERIVEKEY                      ,"C_DeriveKey failed"},
    {PK11_R_GET_OPERATION_STATE            ,"C_GetOperationState failed"},
    {PK11_R_SET_OPERATION_STATE            ,"C_SetOperationState failed"},
    {PK11_R_INVALID_HANDLE            	   ,"invalid PKCS#11 object handle"},
    {PK11_R_KEY_OR_IV_LEN_PROBLEM	   ,"IV or key length incorrect"},
    {PK11_R_INVALID_OPERATION_TYPE	   ,"invalid operation type"},
    {PK11_R_ADD_NID_FAILED		   ,"failed to add NID"},
    {0,NULL}
};
#endif	/* OPENSSL_NO_ERR */

static int pk11_lib_error_code=0;
static int pk11_error_init=1;

static void ERR_load_pk11_strings(void)
{
    if (pk11_lib_error_code == 0)
	pk11_lib_error_code = ERR_get_next_error_library();

    if (pk11_error_init)
    {
	pk11_error_init=0;
#ifndef OPENSSL_NO_ERR
	ERR_load_strings(pk11_lib_error_code,pk11_str_functs);
	ERR_load_strings(pk11_lib_error_code,pk11_str_reasons);
#endif
    }
}

static void ERR_unload_pk11_strings(void)
{
    if (pk11_error_init == 0)
    {
#ifndef OPENSSL_NO_ERR
	ERR_unload_strings(pk11_lib_error_code,pk11_str_functs);
	ERR_unload_strings(pk11_lib_error_code,pk11_str_reasons);
#endif
	pk11_error_init = 1;
    }
}

void ERR_pk11_error(int function, int reason, char *file, int line)
{
    if (pk11_lib_error_code == 0)
	pk11_lib_error_code=ERR_get_next_error_library();
    ERR_PUT_error(pk11_lib_error_code,function,reason,file,line);
}

void PK11err_add_data(int function, int reason, CK_RV rv)
{
	char tmp_buf[20];

	PK11err(function, reason);
	(void) snprintf(tmp_buf, sizeof (tmp_buf), "%lx", rv);
	ERR_add_error_data(2, "PK11 CK_RV=0X", tmp_buf);
}

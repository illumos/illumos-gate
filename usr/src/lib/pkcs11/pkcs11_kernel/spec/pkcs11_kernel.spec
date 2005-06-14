#ident	"%Z%%M%	%I%	%E% SMI"
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#

function	C_Initialize
include		<security/cryptoki.h>
declaration	CK_RV C_Initialize (CK_VOID_PTR pInitArgs)
version		SUNW_1.1
exception	$return != 0
end

function	C_Finalize
include		<security/cryptoki.h>
declaration	CK_RV C_Finalize (CK_VOID_PTR pReserved)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetInfo
include		<security/cryptoki.h>
declaration	CK_RV C_GetInfo (CK_INFO_PTR pInfo)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetFunctionList
include		<security/cryptoki.h>
declaration	CK_RV C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetSlotList
include		<security/cryptoki.h>
declaration	CK_RV C_GetSlotList (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetSlotInfo
include		<security/cryptoki.h>
declaration	CK_RV C_GetSlotInfo (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetTokenInfo
include		<security/cryptoki.h>
declaration	CK_RV C_GetTokenInfo (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetMechanismList
include		<security/cryptoki.h>
declaration	CK_RV C_GetMechanismList (CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetMechanismInfo
include		<security/cryptoki.h>
declaration	CK_RV C_GetMechanismInfo (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
version		SUNW_1.1
exception	$return != 0
end

function	C_InitToken
include		<security/cryptoki.h>
declaration	CK_RV C_InitToken (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
version		SUNW_1.1
exception	$return != 0
end

function	C_InitPIN
include		<security/cryptoki.h>
declaration	CK_RV C_InitPIN (CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SetPIN
include		<security/cryptoki.h>
declaration	CK_RV C_SetPIN (CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_OpenSession
include		<security/cryptoki.h>
declaration	CK_RV C_OpenSession (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_CloseSession
include		<security/cryptoki.h>
declaration	CK_RV C_CloseSession (CK_SESSION_HANDLE hSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_CloseAllSessions
include		<security/cryptoki.h>
declaration	CK_RV C_CloseAllSessions (CK_SLOT_ID slotID)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetSessionInfo
include		<security/cryptoki.h>
declaration	CK_RV C_GetSessionInfo (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetOperationState
include		<security/cryptoki.h>
declaration	CK_RV C_GetOperationState (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperStateLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SetOperationState
include		<security/cryptoki.h>
declaration	CK_RV C_SetOperationState (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_Login
include		<security/cryptoki.h>
declaration	CK_RV C_Login (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_Logout
include		<security/cryptoki.h>
declaration	CK_RV C_Logout (CK_SESSION_HANDLE hSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_CreateObject
include		<security/cryptoki.h>
declaration	CK_RV C_CreateObject (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
version		SUNW_1.1
exception	$return != 0
end

function	C_CopyObject
include		<security/cryptoki.h>
declaration	CK_RV C_CopyObject (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
version		SUNW_1.1
exception	$return != 0
end

function	C_DestroyObject
include		<security/cryptoki.h>
declaration	CK_RV C_DestroyObject (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetObjectSize
include		<security/cryptoki.h>
declaration	CK_RV C_GetObjectSize (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetAttributeValue
include		<security/cryptoki.h>
declaration	CK_RV C_GetAttributeValue (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_SetAttributeValue
include		<security/cryptoki.h>
declaration	CK_RV C_SetAttributeValue (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_FindObjectsInit
include		<security/cryptoki.h>
declaration	CK_RV C_FindObjectsInit (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_FindObjects
include		<security/cryptoki.h>
declaration	CK_RV C_FindObjects (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
version		SUNW_1.1
exception	$return != 0
end

function	C_FindObjectsFinal
include		<security/cryptoki.h>
declaration	CK_RV C_FindObjectsFinal (CK_SESSION_HANDLE hSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_EncryptInit
include		<security/cryptoki.h>
declaration	CK_RV C_EncryptInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_Encrypt
include		<security/cryptoki.h>
declaration	CK_RV C_Encrypt (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_EncryptUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_EncryptUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_EncryptFinal
include		<security/cryptoki.h>
declaration	CK_RV C_EncryptFinal (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DecryptInit
include		<security/cryptoki.h>
declaration	CK_RV C_DecryptInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_Decrypt
include		<security/cryptoki.h>
declaration	CK_RV C_Decrypt (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DecryptUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_DecryptUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DecryptFinal
include		<security/cryptoki.h>
declaration	CK_RV C_DecryptFinal (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DigestInit
include		<security/cryptoki.h>
declaration	CK_RV C_DigestInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
version		SUNW_1.1
exception	$return != 0
end

function	C_Digest
include		<security/cryptoki.h>
declaration	CK_RV C_Digest (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DigestUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_DigestUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DigestKey
include		<security/cryptoki.h>
declaration	CK_RV C_DigestKey (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_DigestFinal
include		<security/cryptoki.h>
declaration	CK_RV C_DigestFinal (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignInit
include		<security/cryptoki.h>
declaration	CK_RV C_SignInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_Sign
include		<security/cryptoki.h>
declaration	CK_RV C_Sign (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_SignUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignFinal
include		<security/cryptoki.h>
declaration	CK_RV C_SignFinal (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignRecoverInit
include		<security/cryptoki.h>
declaration	CK_RV C_SignRecoverInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignRecover
include		<security/cryptoki.h>
declaration	CK_RV C_SignRecover (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_VerifyInit
include		<security/cryptoki.h>
declaration	CK_RV C_VerifyInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_Verify
include		<security/cryptoki.h>
declaration	CK_RV C_Verify (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_VerifyUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_VerifyUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_VerifyFinal
include		<security/cryptoki.h>
declaration	CK_RV C_VerifyFinal (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_VerifyRecoverInit
include		<security/cryptoki.h>
declaration	CK_RV C_VerifyRecoverInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_VerifyRecover
include		<security/cryptoki.h>
declaration	CK_RV C_VerifyRecover (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DigestEncryptUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_DigestEncryptUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DecryptDigestUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_DecryptDigestUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_SignEncryptUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_SignEncryptUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_DecryptVerifyUpdate
include		<security/cryptoki.h>
declaration	CK_RV C_DecryptVerifyUpdate (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_GenerateKey
include		<security/cryptoki.h>
declaration	CK_RV C_GenerateKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_GenerateKeyPair
include		<security/cryptoki.h>
declaration	CK_RV C_GenerateKeyPair (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPubKeyAttrCnt, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttrCnt, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_WrapKey
include		<security/cryptoki.h>
declaration	CK_RV C_WrapKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_UnwrapKey
include		<security/cryptoki.h>
declaration	CK_RV C_UnwrapKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_DeriveKey
include		<security/cryptoki.h>
declaration	CK_RV C_DeriveKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
version		SUNW_1.1
exception	$return != 0
end

function	C_SeedRandom
include		<security/cryptoki.h>
declaration	CK_RV C_SeedRandom (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_GenerateRandom
include		<security/cryptoki.h>
declaration	CK_RV C_GenerateRandom (CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
version		SUNW_1.1
exception	$return != 0
end

function	C_GetFunctionStatus
include		<security/cryptoki.h>
declaration	CK_RV C_GetFunctionStatus (CK_SESSION_HANDLE hSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_CancelFunction
include		<security/cryptoki.h>
declaration	CK_RV C_CancelFunction (CK_SESSION_HANDLE hSession)
version		SUNW_1.1
exception	$return != 0
end

function	C_WaitForSlotEvent
include		<security/cryptoki.h>
declaration	CK_RV C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
version		SUNW_1.1
exception	$return != 0
end

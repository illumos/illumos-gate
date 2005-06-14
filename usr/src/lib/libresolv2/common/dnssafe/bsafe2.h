/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _BSAFE_H_
#define _BSAFE_H_ 1

#ifndef T_CALL
#define T_CALL
#endif

#include "atypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BE_ALGORITHM_ALREADY_SET 0x0200
#define BE_ALGORITHM_INFO 0x0201
#define BE_ALGORITHM_NOT_INITIALIZED 0x0202
#define BE_ALGORITHM_NOT_SET 0x0203
#define BE_ALGORITHM_OBJ 0x0204
#define BE_ALG_OPERATION_UNKNOWN 0x0205
#define BE_ALLOC 0x0206
#define BE_CANCEL 0x0207
#define BE_DATA 0x0208
#define BE_EXPONENT_EVEN 0x0209
#define BE_EXPONENT_LEN 0x020a
#define BE_HARDWARE 0x020b
#define BE_INPUT_DATA 0x020c
#define BE_INPUT_LEN 0x020d
#define BE_KEY_ALREADY_SET 0x020e
#define BE_KEY_INFO 0x020f
#define BE_KEY_LEN 0x0210
#define BE_KEY_NOT_SET 0x0211
#define BE_KEY_OBJ 0x0212
#define BE_KEY_OPERATION_UNKNOWN 0x0213
#define BE_MEMORY_OBJ 0x0214
#define BE_MODULUS_LEN 0x0215
#define BE_NOT_INITIALIZED 0x0216
#define BE_NOT_SUPPORTED 0x0217
#define BE_OUTPUT_LEN 0x0218
#define BE_OVER_32K 0x0219
#define BE_RANDOM_NOT_INITIALIZED 0x021a
#define BE_RANDOM_OBJ 0x021b
#define BE_SIGNATURE 0x021c
#define BE_WRONG_ALGORITHM_INFO 0x021d
#define BE_WRONG_KEY_INFO 0x021e
#define BE_INPUT_COUNT 0x021f
#define BE_OUTPUT_COUNT 0x0220
#define BE_METHOD_NOT_IN_CHOOSER 0x221

typedef POINTER B_KEY_OBJ;
typedef POINTER B_ALGORITHM_OBJ;

typedef int (T_CALL *B_INFO_TYPE) PROTO_LIST ((POINTER *));

typedef struct B_ALGORITHM_METHOD B_ALGORITHM_METHOD;
typedef B_ALGORITHM_METHOD **B_ALGORITHM_CHOOSER;

/* Routines supplied by the implementor.
 */
void T_CALL T_memset PROTO_LIST ((POINTER, int, unsigned int));
void T_CALL T_memcpy PROTO_LIST ((POINTER, CPOINTER, unsigned int));
void T_CALL T_memmove PROTO_LIST ((POINTER, POINTER, unsigned int));
int T_CALL T_memcmp PROTO_LIST ((CPOINTER, CPOINTER, unsigned int));
POINTER T_CALL T_malloc PROTO_LIST ((unsigned int));
POINTER T_CALL T_realloc PROTO_LIST ((POINTER, unsigned int));
void T_CALL T_free PROTO_LIST ((POINTER));

/* The key object.
 */
int T_CALL B_CreateKeyObject PROTO_LIST ((B_KEY_OBJ *));
void T_CALL B_DestroyKeyObject PROTO_LIST ((B_KEY_OBJ *));
int T_CALL B_SetKeyInfo PROTO_LIST ((B_KEY_OBJ, B_INFO_TYPE, POINTER));
int T_CALL B_GetKeyInfo PROTO_LIST ((POINTER *, B_KEY_OBJ, B_INFO_TYPE));

/* The algorithm object.
 */
int T_CALL B_CreateAlgorithmObject PROTO_LIST ((B_ALGORITHM_OBJ *));
void T_CALL B_DestroyAlgorithmObject PROTO_LIST ((B_ALGORITHM_OBJ *));
int T_CALL B_SetAlgorithmInfo PROTO_LIST
  ((B_ALGORITHM_OBJ, B_INFO_TYPE, POINTER));
int T_CALL B_GetAlgorithmInfo PROTO_LIST
  ((POINTER *, B_ALGORITHM_OBJ, B_INFO_TYPE));

unsigned int B_IntegerBits PROTO_LIST ((unsigned char *, unsigned int));

/* Algorithm operations.
 */
int T_CALL B_RandomInit PROTO_LIST
  ((B_ALGORITHM_OBJ, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int T_CALL B_RandomUpdate PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int, A_SURRENDER_CTX *));
int T_CALL B_GenerateRandomBytes PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int, A_SURRENDER_CTX *));

int T_CALL B_DigestInit PROTO_LIST
  ((B_ALGORITHM_OBJ, B_KEY_OBJ, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int T_CALL B_DigestUpdate PROTO_LIST
  ((B_ALGORITHM_OBJ, const unsigned char *, unsigned int, A_SURRENDER_CTX *));
int T_CALL B_DigestFinal PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int *, unsigned int,
    A_SURRENDER_CTX *));

int T_CALL B_EncryptInit PROTO_LIST
  ((B_ALGORITHM_OBJ, B_KEY_OBJ, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int T_CALL B_EncryptUpdate PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int *, unsigned int,
    unsigned char *, unsigned int, B_ALGORITHM_OBJ, A_SURRENDER_CTX *));
int T_CALL B_EncryptFinal PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int *, unsigned int,
    B_ALGORITHM_OBJ, A_SURRENDER_CTX *));

int T_CALL B_DecryptInit PROTO_LIST
  ((B_ALGORITHM_OBJ, B_KEY_OBJ, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int T_CALL B_DecryptUpdate PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int *, unsigned int,
    const unsigned char *, unsigned int, B_ALGORITHM_OBJ, A_SURRENDER_CTX *));
int T_CALL B_DecryptFinal PROTO_LIST
  ((B_ALGORITHM_OBJ, unsigned char *, unsigned int *, unsigned int,
    B_ALGORITHM_OBJ, A_SURRENDER_CTX *));



int T_CALL B_GenerateInit PROTO_LIST
  ((B_ALGORITHM_OBJ, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
int T_CALL B_GenerateKeypair PROTO_LIST
  ((B_ALGORITHM_OBJ, B_KEY_OBJ, B_KEY_OBJ, B_ALGORITHM_OBJ,
    A_SURRENDER_CTX *));
int T_CALL B_GenerateParameters PROTO_LIST
  ((B_ALGORITHM_OBJ, B_ALGORITHM_OBJ, B_ALGORITHM_OBJ, A_SURRENDER_CTX *));


/* Information for password-based encryption (PBE) algorithms.
 */
typedef struct {
  unsigned char *salt;                                        /* salt value */
  unsigned int iterationCount;                           /* iteration count */
} B_PBE_PARAMS;

/* Information for MAC algorithm.
 */
typedef struct {
  unsigned int macLen;                               /* length of MAC value */
} B_MAC_PARAMS;


/* Information for BSAFE 1.x compatible encryption algorithms.
 */


typedef struct {
  unsigned int threshold;                                 /* share threshold */
} B_SECRET_SHARING_PARAMS;

/* Key Info Types.
 */
int T_CALL KI_8Byte PROTO_LIST ((POINTER *));
int T_CALL KI_Item PROTO_LIST ((POINTER *));
int T_CALL KI_PKCS_RSAPrivate PROTO_LIST ((POINTER *));
int T_CALL KI_RSAPublic PROTO_LIST ((POINTER *));
int T_CALL KI_RSA_CRT PROTO_LIST ((POINTER *));

/* Algorithm Info Types.
 */
int T_CALL AI_MD5 PROTO_LIST ((POINTER *));
int T_CALL AI_MD5Random PROTO_LIST ((POINTER *));
int T_CALL AI_PKCS_RSAPrivate PROTO_LIST ((POINTER *));
int T_CALL AI_PKCS_RSAPublic PROTO_LIST ((POINTER *));
int T_CALL AI_RSAKeyGen PROTO_LIST ((POINTER *));
int T_CALL AI_RSAPrivate PROTO_LIST ((POINTER *));
int T_CALL AI_RSAPublic PROTO_LIST ((POINTER *));


/* Algorithm methods for use int the algorithm chooser.
 */
extern B_ALGORITHM_METHOD T_CALL AM_MD5;
extern B_ALGORITHM_METHOD T_CALL AM_MD5_RANDOM;
extern B_ALGORITHM_METHOD T_CALL AM_RSA_CRT_DECRYPT;
extern B_ALGORITHM_METHOD T_CALL AM_RSA_CRT_ENCRYPT;
extern B_ALGORITHM_METHOD T_CALL AM_RSA_DECRYPT;
extern B_ALGORITHM_METHOD T_CALL AM_RSA_ENCRYPT;
extern B_ALGORITHM_METHOD T_CALL AM_RSA_KEY_GEN;

#ifdef __cplusplus
}
#endif

#endif

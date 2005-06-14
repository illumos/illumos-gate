/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "bkey.h"
#include "kinfotyp.h"
#include "kifulprv.h"
#include "port_after.h"

typedef struct {
  ITEM modulus;                                                  /* modulus */
  ITEM publicExponent;                       /* exponent for the public key */
  ITEM privateExponent;                     /* exponent for the private key */
  ITEM prime[2];                                           /* prime factors */
  ITEM primeExponent[2];                     /* exponents for prime factors */
  ITEM coefficient;                                      /* CRT coefficient */
} FULL_PRIVATE_KEY;

static int KITFullPrivateKeyAddInfo PROTO_LIST ((B_Key *, POINTER));

static B_KeyInfoType KITFullPrivate =
  {KITFullPrivateKeyAddInfo, B_KeyInfoTypeMakeError};

/* Create a FULL_PRIVATE_KEY value and only copy inthe entries
     that are not (ITEM *)NULL_PTR.
   primes and primeExponents point to a 2 entry ITEM array.
 */
int CacheFullPrivateKey
  (key, modulus, publicExponent, privateExponent, primes,
   primeExponents, coefficient)
B_Key *key;
ITEM *modulus;
ITEM *publicExponent;
ITEM *privateExponent;
ITEM *primes;
ITEM *primeExponents;
ITEM *coefficient;
{
  FULL_PRIVATE_KEY *fullKey;
  int status;

  /* Allocate memory for FULL_PRIVATE_KEY value.
   */
  if ((status = B_MemoryPoolAlloc
       (&key->infoCache.memoryPool, (POINTER *)&fullKey,
        sizeof (FULL_PRIVATE_KEY))) != 0)
    return (status);
  
  /* Pre-zeroize and only copy in values that are not NULL.
   */
  T_memset ((POINTER)fullKey, 0, sizeof (*fullKey));
  if (modulus != (ITEM *)NULL_PTR)
    fullKey->modulus = *modulus;
  if (publicExponent != (ITEM *)NULL_PTR)
    fullKey->publicExponent = *publicExponent;
  if (privateExponent != (ITEM *)NULL_PTR)
    fullKey->privateExponent = *privateExponent;
  if (primes != (ITEM *)NULL_PTR) {
    fullKey->prime[0] = primes[0];
    fullKey->prime[1] = primes[1];
  }
  if (primeExponents != (ITEM *)NULL_PTR) {
    fullKey->primeExponent[0] = primeExponents[0];
    fullKey->primeExponent[1] = primeExponents[1];
  }
  if (coefficient != (ITEM *)NULL_PTR)
    fullKey->coefficient = *coefficient;
  
  return (B_InfoCacheAddInfo
          (&key->infoCache, (POINTER)&KITFullPrivate, (POINTER)fullKey));
}

/* Select the key object's full private key and set all of the supplied
     fields which are not (ITEM *)NULL_PTR.
   primes and primeExponents point to a 2 entry ITEM array.
   If one of the fields is not (ITEM *)NULL_PTR, but the full key's
     field is null, return BE_WRONG_KEY_INFO.
 */
int GetFullPrivateKeyInfo
  (modulus, publicExponent, privateExponent, primes, primeExponents,
   coefficient, key)
ITEM *modulus;
ITEM *publicExponent;
ITEM *privateExponent;
ITEM *primes;
ITEM *primeExponents;
ITEM *coefficient;
B_Key *key;
{
  FULL_PRIVATE_KEY *fullKey;
  int status;
  
  if ((status = B_KeyGetInfo
       (key, (POINTER *)&fullKey, &KITFullPrivate)) != 0)
    return (status);

  if (modulus != (ITEM *)NULL_PTR) {
    if (fullKey->modulus.data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    *modulus = fullKey->modulus;
  }
  if (publicExponent != (ITEM *)NULL_PTR) {
    if (fullKey->publicExponent.data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    *publicExponent = fullKey->publicExponent;
  }
  if (privateExponent != (ITEM *)NULL_PTR) {
    if (fullKey->privateExponent.data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    *privateExponent = fullKey->privateExponent;
  }
  if (primes != (ITEM *)NULL_PTR) {
    if (fullKey->prime[0].data == (unsigned char *)NULL_PTR ||
        fullKey->prime[1].data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    primes[0] = fullKey->prime[0];
    primes[1] = fullKey->prime[1];
  }
  if (primeExponents != (ITEM *)NULL_PTR) {
    if (fullKey->primeExponent[0].data == (unsigned char *)NULL_PTR ||
        fullKey->primeExponent[1].data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    primeExponents[0] = fullKey->primeExponent[0];
    primeExponents[1] = fullKey->primeExponent[1];
  }
  if (coefficient != (ITEM *)NULL_PTR) {
    if (fullKey->coefficient.data == (unsigned char *)NULL_PTR)
      return (BE_WRONG_KEY_INFO);
    *coefficient = fullKey->coefficient;
  }
  
  return (0);
}

/* This is not intended to be called from B_SetKeyInfo.
   Get returns BE_WRONG_KEY_INFO.
 */
static int KITFullPrivateKeyAddInfo (key, info)
B_Key *key;
POINTER info;
{
UNUSED_ARG (key)
UNUSED_ARG (info)
  return (BE_ALG_OPERATION_UNKNOWN);
}


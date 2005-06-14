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
#include "keyobj.h"
#include "port_after.h"

#define THE_KEY_WRAP ((KeyWrap *)keyObject)

static char KEY_TYPE_TAG = 0;

int B_CreateKeyObject (keyObject)
B_KEY_OBJ *keyObject;
{
  KeyWrap *keyWrap;

  if ((*keyObject = T_malloc (sizeof (*keyWrap))) == NULL_PTR)
    return (BE_ALLOC);

  keyWrap = (KeyWrap *)*keyObject;

  /* First construct base class */
  B_KEY_Constructor (&keyWrap->key);
  
  keyWrap->typeTag = &KEY_TYPE_TAG;
  keyWrap->selfCheck = keyWrap;
  return (0);
}

void B_DestroyKeyObject (keyObject)
B_KEY_OBJ *keyObject;
{
  KeyWrap *keyWrap = (KeyWrap *)*keyObject;

  /* Need to explicitly check for NULL_PTR since KeyWrapCheck does not.
   */
  if (*keyObject == NULL_PTR)
    return;
  
  if (KeyWrapCheck (keyWrap) == 0) {
    /* zeroize self check to invalidate memory. */
    keyWrap->selfCheck = (KeyWrap *)NULL_PTR;

    /* Call base class descructor */
    B_KEY_Destructor (&keyWrap->key);

    T_free ((POINTER)keyWrap);
  }

  *keyObject = NULL_PTR;
}

int B_SetKeyInfo (keyObject, infoType, info)
B_KEY_OBJ keyObject;
B_INFO_TYPE infoType;
POINTER info;
{
  B_KeyInfoType *keyInfoType;
  int status;
  
  if ((status = KeyWrapCheck (THE_KEY_WRAP)) != 0)
    return (status);

  /* Get the KeyInfoType from the B_INFO_TYPE, which returns
       zero for an AlgorithmInfoType, non-zero for KeyInfoType
   */
  if ((*infoType) ((POINTER *)&keyInfoType) == 0)
    return (BE_ALG_OPERATION_UNKNOWN);
  
  return (B_KeySetInfo (&THE_KEY_WRAP->key, keyInfoType, info));
}

int B_GetKeyInfo (info, keyObject, infoType)
POINTER *info;
B_KEY_OBJ keyObject;
B_INFO_TYPE infoType;
{
  B_KeyInfoType *keyInfoType;
  int status;
  
  if ((status = KeyWrapCheck (THE_KEY_WRAP)) != 0)
    return (status);

  /* Get the KeyInfoType from the B_INFO_TYPE, which returns
       zero for an AlgorithmInfoType, non-zero for KeyInfoType
   */
  if ((*infoType) ((POINTER *)&keyInfoType) == 0)
    return (BE_ALG_OPERATION_UNKNOWN);
  
  return (B_KeyGetInfo (&THE_KEY_WRAP->key, info, keyInfoType));
}

/* Return 0 if this is a valid KeyWrap object, else BE_KEY_OBJ.
   If keyWrap is NULL_PTR, return 0 and expect the lower routines
     to check for NULL.
 */
int KeyWrapCheck (keyWrap)
KeyWrap *keyWrap;
{
  if (keyWrap == (KeyWrap *)NULL_PTR)
    return (0);

  return ((keyWrap->selfCheck == keyWrap && keyWrap->typeTag == &KEY_TYPE_TAG)
          ? 0 : BE_KEY_OBJ);
}


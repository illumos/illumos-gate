/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "bsafe2.h"
#include "algae.h"
#include "balgmeth.h"
#include "bkey.h"
#include "algchoic.h"
#include "port_after.h"

/* In C++:
ResizeContext::ResizeContext ()
{
  T_memset ((POINTER)&z, 0, sizeof (z));
}
 */
void ResizeContextConstructor (resizeContext)
ResizeContext *resizeContext;
{
  T_memset ((POINTER)&resizeContext->z, 0, sizeof (resizeContext->z));
}

/* In C++:
ResizeContext::~ResizeContext ()
{
  T_memset (z.context, 0, z.contextSize);
  T_free (z.context);
}
 */
void ResizeContextDestructor (resizeContext)
ResizeContext *resizeContext;
{
  T_memset (resizeContext->z.context, 0, resizeContext->z.contextSize);
  T_free (resizeContext->z.context);
}

/* If the resizeContext's context is already the requested size, do nothing.
   Otherwise, this memsets the existing context to zero, then allocates
     the context as a buffer of the requested size.
   If the allocate fails, the context size is set to
     zero so that later calls will not zeroize non-existing buffers.
 */
int ResizeContextMakeNewContext (resizeContext, contextSize)
ResizeContext *resizeContext;
unsigned int contextSize;
{
  if (resizeContext->z.contextSize == contextSize)
    return (0);

  /* Take care of zeroizing the previous context.
   */
  T_memset (resizeContext->z.context, 0, resizeContext->z.contextSize);

  if ((resizeContext->z.context = T_realloc
       (resizeContext->z.context, contextSize)) == NULL_PTR) {
    resizeContext->z.contextSize = 0;
    return (BE_ALLOC);
  }
    
  resizeContext->z.contextSize = contextSize;
  return (0);
}

int AlgaChoiceChoose (algaChoice, encryptFlag, key, chooser, surrenderContext)
AlgaChoice *algaChoice;
int encryptFlag;
B_Key *key;
B_ALGORITHM_CHOOSER chooser;
A_SURRENDER_CTX *surrenderContext;
{
  POINTER keyInfo;
  int status, overallStatus;

  /* Each alga init callback returns BE_NOT_SUPPORTED if the Query fails.
     Each also may return a more specific error like BE_MODULUS_LEN if the
       method is not supported, so return the more specific error if possible.
   */
  overallStatus = BE_METHOD_NOT_IN_CHOOSER;

  for (; *chooser != (B_ALGORITHM_METHOD *)NULL_PTR; chooser++) {
    if ((*chooser)->algorithmInfoType != algaChoice->_algorithmInfoType ||
        (*chooser)->encryptFlag != encryptFlag)
      /* Wrong type of algorithm, or the encryptFlag is wrong */
      continue;

    if ((*chooser)->keyInfoType != (struct B_KeyInfoType *)NULL_PTR) {
      if ((status = B_KeyGetInfo
           (key, &keyInfo, (*chooser)->keyInfoType)) != 0) {
        if (IS_FATAL_BSAFE_ERROR (status))
          return (status);
      
        /* Update the overall status with this more specific error. */
        overallStatus = status;
        continue;
      }
    }
    else
      keyInfo = NULL_PTR;

    if ((status = (*algaChoice->_InitAlga)
         (algaChoice, keyInfo, *chooser, surrenderContext)) != 0) {
      if (IS_FATAL_BSAFE_ERROR (status))
        return (status);

      /* Update the overall status with this more specific error. */
      overallStatus = status;
      continue;
    }

    /* Succeeded */
    algaChoice->_alga = (*chooser)->alga;
    return (0);
  }

  return (overallStatus);
}

/* Convert the ALGAE error to a BSAFE2 error.
   This does not check for zero since BSAFE should not bother to call
     this function if there is no error.
 */
int ConvertAlgaeError (type)
int type;
{
  switch (type) {
  case AE_CANCEL:
    return (BE_CANCEL);
  case AE_DATA:
    return (BE_DATA);
  case AE_EXPONENT_EVEN:
    return (BE_EXPONENT_EVEN);
  case AE_EXPONENT_LEN:
    return (BE_EXPONENT_LEN);
  case AE_INPUT_DATA:
    return (BE_INPUT_DATA);
  case AE_INPUT_LEN:
    return (BE_INPUT_LEN);
  case AE_KEY_INFO:
    return (BE_KEY_INFO);
  case AE_KEY_LEN:
    return (BE_KEY_LEN);
  case AE_MODULUS_LEN:
    return (BE_MODULUS_LEN);
  case AE_NOT_INITIALIZED:
    return (BE_NOT_INITIALIZED);
  case AE_NOT_SUPPORTED:
    return (BE_NOT_SUPPORTED);
  case AE_OUTPUT_LEN:
    return (BE_OUTPUT_LEN);
  case AE_PARAMS:
    return (BE_ALGORITHM_INFO);
    
#if USE_ALLOCED_FRAME
  case AE_ALLOC:
    return (BE_ALLOC);
#endif

  default:
    return (BE_DATA);
  }
}


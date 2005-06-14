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

#ifndef _AHGEN_H_
#define _AHGEN_H_ 1

#include "btypechk.h"

/* Use the THIS_GENERATE macro to define the type of object in the
     virtual function prototype.  It defaults to the most base class, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
#ifndef THIS_GENERATE
#define THIS_GENERATE struct AHGenerate
#endif

struct AHGenerate;

typedef struct {
  void (*Destructor) PROTO_LIST ((THIS_GENERATE *));
  int (*GenerateInit) PROTO_LIST
    ((THIS_GENERATE *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
  int (*GenerateKeypair) PROTO_LIST
    ((THIS_GENERATE *, B_Key *, B_Key *, B_Algorithm *, A_SURRENDER_CTX *));
  int (*GenerateParameters) PROTO_LIST
    ((THIS_GENERATE *, B_Algorithm *, B_Algorithm *, A_SURRENDER_CTX *));
} AHGenerateVTable;

typedef struct AHGenerate {
  B_TypeCheck typeCheck;                                        /* inherited */
  AHGenerateVTable *vTable;                                  /* pure virtual */
} AHGenerate;

/* The constructor does not set the vTable since this is a pure base class.
 */
void AHGenerateConstructor PROTO_LIST ((AHGenerate *));
/* No destructor because it is pure virtual. Also, do not call destructor
     for B_TypeCheck, since this will just re-invoke this virtual
     destructor. */

#endif

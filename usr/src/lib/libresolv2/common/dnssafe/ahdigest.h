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

#ifndef _AHDIGEST_H_
#define _AHDIGEST_H_ 1

#include "btypechk.h"

/* Use the THIS_DIGEST macro to define the type of object in the
     virtual function prototype.  It defaults to the most base class, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
#ifndef THIS_DIGEST
#define THIS_DIGEST struct AHDigest
#endif

struct AHDigest;

typedef struct {
  void (*Destructor) PROTO_LIST ((THIS_DIGEST *));
  int (*DigestInit) PROTO_LIST
    ((THIS_DIGEST *, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));
  int (*DigestUpdate) PROTO_LIST
    ((THIS_DIGEST *, const unsigned char *, unsigned int, A_SURRENDER_CTX *));
  int (*DigestFinal) PROTO_LIST
    ((THIS_DIGEST *, unsigned char *, unsigned int *, unsigned int,
      A_SURRENDER_CTX *));
} AHDigestVTable;

typedef struct AHDigest {
  B_TypeCheck typeCheck;                                        /* inherited */
  AHDigestVTable *vTable;                                    /* pure virtual */
} AHDigest;

/* The constructor does not set the vTable since this is a pure base class.
 */
void AHDigestConstructor PROTO_LIST ((AHDigest *));
/* No destructor because it is pure virtual. Also, do not call destructor
     for B_TypeCheck, since this will just re-invoke this virtual
     destructor. */

#endif

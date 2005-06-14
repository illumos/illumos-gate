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

#ifndef _AHRSAEPU_H_
#define _AHRSAEPU_H_

#include "ahrsaenc.h"

/* structure is identical to base class, so just re-typedef. */
typedef AH_RSAEncryption AH_RSAEncryptionPublic;

AH_RSAEncryptionPublic *AH_RSAEncrypPublicConstructor PROTO_LIST
  ((AH_RSAEncryptionPublic *));

#endif

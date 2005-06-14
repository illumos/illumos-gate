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

#ifndef _BKEY_H_
#define _BKEY_H_ 1

#include "binfocsh.h"

typedef struct {
  B_InfoCache infoCache;                                        /* inherited */

  /* For now we don't need to worry about a reserved field.
  struct {
    POINTER reserved;  
  } z;
   */
} B_Key;

#define B_KEY_Constructor(key) (B_InfoCacheConstructor (&(key)->infoCache))
#define B_KEY_Destructor(key) (B_INFO_CACHE_Destructor (&(key)->infoCache))

struct B_KeyInfoType;
int B_KeySetInfo PROTO_LIST ((B_Key *, struct B_KeyInfoType *, POINTER));
int B_KeyGetInfo PROTO_LIST ((B_Key *, POINTER *, struct B_KeyInfoType *));
int B_KeyAddItemInfo PROTO_LIST ((B_Key *, unsigned char *, unsigned int));

#endif

/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1994, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

typedef struct {
  int (*Query) PROTO_LIST ((unsigned int *, POINTER));
  int (*Init) PROTO_LIST ((POINTER, POINTER, A_SURRENDER_CTX *));
  int (*Update) PROTO_LIST
    ((POINTER, const unsigned char *, unsigned int, A_SURRENDER_CTX *));
  int (*Final) PROTO_LIST
    ((POINTER, unsigned char *, unsigned int *, unsigned int,
      A_SURRENDER_CTX *));
  int (*GetMaxOutputLen) PROTO_LIST ((POINTER, unsigned int *));
} A_DIGEST_ALGA;


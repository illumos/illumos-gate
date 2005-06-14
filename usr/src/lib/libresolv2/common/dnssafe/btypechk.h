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

#ifndef _BTYPECHK_H_
#define _BTYPECHK_H_ 1

struct B_TypeCheck;

typedef void (*B_TYPE_CHECK_DESTRUCTOR) PROTO_LIST ((struct B_TypeCheck *));

typedef struct B_TypeCheck {
  B_TYPE_CHECK_DESTRUCTOR _Destructor;
} B_TypeCheck;

#define B_TYPE_CHECK_Constructor(typeCheck, Destructor)\
  (typeCheck)->_Destructor = (Destructor)
#define B_TYPE_CHECK_Destructor(typeCheck)\
  (*(typeCheck)->_Destructor) (typeCheck)

#endif

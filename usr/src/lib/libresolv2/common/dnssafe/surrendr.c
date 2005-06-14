/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1992, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#include "port_before.h"
#include "global.h"
#include "algae.h"
#include "surrendr.h"
#include "port_after.h"

/* Returns 0, AE_CANCEL.
 */
int CheckSurrender (surrenderContext)
A_SURRENDER_CTX *surrenderContext;
{
  if (surrenderContext == (A_SURRENDER_CTX *)NULL_PTR)
    return (0);

  if ((*surrenderContext->Surrender) (surrenderContext->handle))
    return (AE_CANCEL);
  return (0);
}

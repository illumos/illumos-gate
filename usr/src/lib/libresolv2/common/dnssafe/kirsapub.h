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

extern B_KeyInfoType KIT_RSAPublic;

int KIT_RSAPublicAddInfo PROTO_LIST ((B_Key *, POINTER));
int KIT_RSAPublicMakeInfo PROTO_LIST ((POINTER *, B_Key *));


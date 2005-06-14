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

#ifndef _SECRCBC_H_
#define _SECRCBC_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*SECRET_CRYPT) PROTO_LIST
  ((POINTER, unsigned char *, unsigned char *));

int SecretCBCEncryptUpdate PROTO_LIST
  ((POINTER, unsigned char *, unsigned char *, unsigned int *, SECRET_CRYPT,
    unsigned char *, unsigned int *, unsigned int, unsigned char *,
    unsigned int));
int SecretCBCEncryptFinal PROTO_LIST ((unsigned int));
int SecretCBCDecryptUpdate PROTO_LIST
  ((POINTER, unsigned char *, unsigned char *, unsigned int *, SECRET_CRYPT,
    unsigned char *, unsigned int *, unsigned int, unsigned char *,
    unsigned int));
int SecretCBCDecryptFinal PROTO_LIST
  ((POINTER, unsigned char *, unsigned char *, unsigned int, SECRET_CRYPT,
    unsigned char *, unsigned int *, unsigned int));

#ifdef __cplusplus
}
#endif

#endif

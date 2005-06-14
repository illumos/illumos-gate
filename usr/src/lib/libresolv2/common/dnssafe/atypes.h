/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1992, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _ATYPES_H_
#define _ATYPES_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ITEM_
#define _ITEM_ 1
typedef struct {
  unsigned char *data;
  unsigned int len;
} ITEM;
#endif

typedef struct {
  int (T_CALL *Surrender) PROTO_LIST ((POINTER));
  POINTER handle;
  POINTER reserved;
} A_SURRENDER_CTX;

typedef struct {
  ITEM modulus;
  ITEM publicExponent;
  ITEM privateExponent;
  ITEM prime[2];                                            /* prime factors */
  ITEM primeExponent[2];                      /* exponents for prime factors */
  ITEM coefficient;                                       /* CRT coefficient */
} A_PKCS_RSA_PRIVATE_KEY;

typedef struct {
  ITEM modulus;
  ITEM prime[2];                                            /* prime factors */
  ITEM primeExponent[2];                      /* exponents for prime factors */
  ITEM coefficient;                                       /* CRT coefficient */
} A_RSA_CRT_KEY;

typedef struct {
  ITEM modulus;                                                   /* modulus */
  ITEM exponent;                                                 /* exponent */
} A_RSA_KEY;

typedef struct {
  unsigned int modulusBits;
  ITEM publicExponent;
} A_RSA_KEY_GEN_PARAMS;

#ifdef __cplusplus
}
#endif

#endif

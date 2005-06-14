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

#ifndef _DIGRAND_H_
#define _DIGRAND_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

/* Use the THIS_DIGEST_RANDOM macro to define the type of object in the
     virtual function prototype.  It defaults to the most base class, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
#ifndef THIS_DIGEST_RANDOM
#define THIS_DIGEST_RANDOM struct A_DigestRandom
#endif

struct A_DigestRandom;

typedef struct {
  void (*DigestUpdate) PROTO_LIST
    ((THIS_DIGEST_RANDOM *, unsigned char *, unsigned int));
  void (*DigestFinal) PROTO_LIST ((THIS_DIGEST_RANDOM *, unsigned char *));
} A_DigestRandomVTable;

typedef struct A_DigestRandom {
  unsigned char *_state;                                  /* input to digest */
  unsigned char *_output;                        /* current output of digest */
  unsigned int _outputAvailable;
  unsigned char *_digest;
  unsigned int _digestLen;
  A_DigestRandomVTable *vTable;
} A_DigestRandom;

void A_DigestRandomInit PROTO_LIST
  ((A_DigestRandom *, unsigned int, unsigned char *));
void A_DigestRandomUpdate PROTO_LIST
  ((A_DigestRandom *, unsigned char *, unsigned int));
void A_DigestRandomGenerateBytes PROTO_LIST
  ((A_DigestRandom *, unsigned char *, unsigned int));

#ifdef __cplusplus
}
#endif

#endif

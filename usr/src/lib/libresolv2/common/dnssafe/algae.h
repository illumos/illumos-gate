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

#ifndef _ALGAE_H_
#define _ALGAE_H_ 1

#ifndef T_CALL
#define T_CALL
#endif

/* Used to reduce the stack size in routines with big scratch buffers.
   If set to 1, this will make ALGAE allocate these buffers on the heap.
 */
#ifndef USE_ALLOCED_FRAME
#define USE_ALLOCED_FRAME 1
#endif

#include "atypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AE_CANCEL 0x0001
#define AE_DATA 0x0002
#define AE_EXPONENT_EVEN 0x0003
#define AE_EXPONENT_LEN 0x0004
#define AE_INPUT_DATA 0x0005
#define AE_INPUT_LEN 0x0006
#define AE_MODULUS_LEN 0x0007
#define AE_NEED_RANDOM 0x0008
#define AE_NOT_SUPPORTED 0x0009
#define AE_OUTPUT_LEN 0x000a
#define AE_NOT_INITIALIZED 0x000b
#define AE_KEY_LEN 0x000c
#define AE_KEY_INFO 0x000d
#define AE_SEQUENCE 0x000e
#define AE_PARAMS 0x000f

#if USE_ALLOCED_FRAME
/* Needed only for big number code heap allocation of scratch arrays.
 */
#define AE_ALLOC 0x0080
POINTER T_malloc PROTO_LIST ((unsigned int));
void T_free PROTO_LIST ((POINTER));
#endif

/* Routines supplied by the implementor.
 */
void T_memset PROTO_LIST ((POINTER, int, unsigned int));
void T_memcpy PROTO_LIST ((POINTER, CPOINTER, unsigned int));
void T_memmove PROTO_LIST ((POINTER, POINTER, unsigned int));
int T_memcmp PROTO_LIST ((CPOINTER, CPOINTER, unsigned int));

unsigned int A_IntegerBits PROTO_LIST ((const unsigned char *, unsigned int));

#ifdef __cplusplus
}
#endif

#endif

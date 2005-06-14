/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * k5-platform.h
 *
 * Copyright 2003  by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.	Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Some platform-dependent definitions to sync up the C support level.
 * Some to a C99-ish level, some related utility code.
 *
 * Currently: make "static" work; 64-bit types and load/store
 * code; SIZE_MAX.
 */

#ifndef K5_PLATFORM_H
#define K5_PLATFORM_H

/* 64-bit support: krb5_ui_8 and krb5_int64.
#include "autoconf.h"

   This should move to krb5.h eventually, but without the namespace
   pollution from the autoconf macros.  */
#if defined(HAVE_STDINT_H) || defined(HAVE_INTTYPES_H)
# ifdef HAVE_STDINT_H
#  include <stdint.h>
# endif
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# define INT64_TYPE int64_t
# define UINT64_TYPE uint64_t
#elif defined(_WIN32)
# define INT64_TYPE signed __int64
# define UINT64_TYPE unsigned __int64
#else /* not Windows, and neither stdint.h nor inttypes.h */
# define INT64_TYPE signed long long
# define UINT64_TYPE unsigned long long
#endif

#ifndef SIZE_MAX
# define SIZE_MAX ((size_t)((size_t)0 - 1))
#endif

/* Read and write integer values as (unaligned) octet strings in
   specific byte orders.

   Add per-platform optimizations later if needed.  (E.g., maybe x86
   unaligned word stores and gcc/asm instructions for byte swaps,
   etc.)  */

static void
store_16_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >>  8) & 0xff;
    p[1] = (val      ) & 0xff;
}
static void
store_16_le (unsigned int val, unsigned char *p)
{
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static void
store_32_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >> 24) & 0xff;
    p[1] = (val >> 16) & 0xff;
    p[2] = (val >>  8) & 0xff;
    p[3] = (val      ) & 0xff;
}
static void
store_32_le (unsigned int val, unsigned char *p)
{
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static void
store_64_be (UINT64_TYPE val, unsigned char *p)
{
    p[0] = (unsigned char)((val >> 56) & 0xff);
    p[1] = (unsigned char)((val >> 48) & 0xff);
    p[2] = (unsigned char)((val >> 40) & 0xff);
    p[3] = (unsigned char)((val >> 32) & 0xff);
    p[4] = (unsigned char)((val >> 24) & 0xff);
    p[5] = (unsigned char)((val >> 16) & 0xff);
    p[6] = (unsigned char)((val >>  8) & 0xff);
    p[7] = (unsigned char)((val      ) & 0xff);
}
static void
store_64_le (UINT64_TYPE val, unsigned char *p)
{
    p[7] = (unsigned char)((val >> 56) & 0xff);
    p[6] = (unsigned char)((val >> 48) & 0xff);
    p[5] = (unsigned char)((val >> 40) & 0xff);
    p[4] = (unsigned char)((val >> 32) & 0xff);
    p[3] = (unsigned char)((val >> 24) & 0xff);
    p[2] = (unsigned char)((val >> 16) & 0xff);
    p[1] = (unsigned char)((val >>  8) & 0xff);
    p[0] = (unsigned char)((val      ) & 0xff);
}
static unsigned short
load_16_be (unsigned char *p)
{
    return (p[1] | (p[0] << 8));
}
static unsigned short
load_16_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8));
}
static unsigned int
load_32_be (unsigned char *p)
{
    return (p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24));
}
static unsigned int
load_32_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}
static UINT64_TYPE
load_64_be (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_be(p) << 32) | load_32_be(p+4);
}
static UINT64_TYPE
load_64_le (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_le(p+4) << 32) | load_32_le(p);
}

#endif /* K5_PLATFORM_H */

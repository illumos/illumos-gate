/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * k5-platform.h
 *
 * Copyright 2003, 2004, 2005 Massachusetts Institute of Technology.
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
 * Currently:
 * + make "static inline" work
 * + 64-bit types and load/store code
 * + SIZE_MAX
 * + shared library init/fini hooks
 * + consistent getpwnam/getpwuid interfaces
 */

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


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/krb5/crc-32.h
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Definitions for the CRC-32 checksum
 */


#ifndef KRB5_CRC32__
#define KRB5_CRC32__

#define CRC32_CKSUM_LENGTH	4

void
mit_crc32 (const krb5_pointer in, const size_t in_length, unsigned long *c);

#ifdef CRC32_SHIFT4
void mit_crc32_shift4(const krb5_pointer /* in */,
		    const size_t /* in_length */,
		    unsigned long * /* cksum */);
#endif

#endif /* KRB5_CRC32__ */

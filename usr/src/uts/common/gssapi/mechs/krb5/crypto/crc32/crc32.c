/*
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/crypto/crc32/crc.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * CRC-32/AUTODIN-II routines
 */

#include <k5-int.h>
#include <gssapiP_generic.h>
#include <crc-32.h>
#include <sys/crc32.h>

static uint32_t const crc_table[256] = { CRC32_TABLE };

void
mit_crc32(in, in_length, cksum)
	krb5_const krb5_pointer in;
	krb5_const size_t in_length;
	unsigned long *cksum;
{
	unsigned int crc;

	CRC32(crc, in, in_length, 0, crc_table);

	*cksum = crc;
}

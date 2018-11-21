/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	SB_TO_UTF8_H
#define	SB_TO_UTF8_H


#include "common_defs.h"


/*
 * The values in u8 data field is a UTF-8 byte streams saved in uint_t and
 * with that data field, we only cover characters from U+0000 to U+10 FFFF.
 */
static const to_utf8_table_component_t sb_u8_tbl[256] = {
#if defined(US_ASCII)
#include "tbls/us-ascii_to_utf8.tbl"

#elif defined(ISO_8859_1)
#include "tbls/iso-8859-1_to_utf8.tbl"

#elif defined(ISO_8859_2)
#include "tbls/iso-8859-2_to_utf8.tbl"

#elif defined(ISO_8859_3)
#include "tbls/iso-8859-3_to_utf8.tbl"

#elif defined(ISO_8859_4)
#include "tbls/iso-8859-4_to_utf8.tbl"

#elif defined(ISO_8859_5)
#include "tbls/iso-8859-5_to_utf8.tbl"

#elif defined(ISO_8859_6)
#include "tbls/iso-8859-6_to_utf8.tbl"

#elif defined(ISO_8859_7)
#include "tbls/iso-8859-7_to_utf8.tbl"

#elif defined(ISO_8859_8)
#include "tbls/iso-8859-8_to_utf8.tbl"

#elif defined(ISO_8859_9)
#include "tbls/iso-8859-9_to_utf8.tbl"

#elif defined(ISO_8859_10)
#include "tbls/iso-8859-10_to_utf8.tbl"

#elif defined(ISO_8859_13)
#include "tbls/iso-8859-13_to_utf8.tbl"

#elif defined(ISO_8859_14)
#include "tbls/iso-8859-14_to_utf8.tbl"

#elif defined(ISO_8859_15)
#include "tbls/iso-8859-15_to_utf8.tbl"

#elif defined(ISO_8859_16)
#include "tbls/iso-8859-16_to_utf8.tbl"

#elif defined(KOI8_R)
#include "tbls/koi8-r_to_utf8.tbl"

#elif defined(KOI8_U)
#include "tbls/koi8-u_to_utf8.tbl"

#elif defined(PTCP154)
#include "tbls/ptcp154_to_utf8.tbl"

#elif defined(CP437)
#include "tbls/cp437_to_utf8.tbl"

#elif defined(CP720)
#include "tbls/cp720_to_utf8.tbl"

#elif defined(CP737)
#include "tbls/cp737_to_utf8.tbl"

#elif defined(CP775)
#include "tbls/cp775_to_utf8.tbl"

#elif defined(CP850)
#include "tbls/cp850_to_utf8.tbl"

#elif defined(CP852)
#include "tbls/cp852_to_utf8.tbl"

#elif defined(CP855)
#include "tbls/cp855_to_utf8.tbl"

#elif defined(CP857)
#include "tbls/cp857_to_utf8.tbl"

#elif defined(CP860)
#include "tbls/cp860_to_utf8.tbl"

#elif defined(CP861)
#include "tbls/cp861_to_utf8.tbl"

#elif defined(CP862)
#include "tbls/cp862_to_utf8.tbl"

#elif defined(CP863)
#include "tbls/cp863_to_utf8.tbl"

#elif defined(CP864)
#include "tbls/cp864_to_utf8.tbl"

#elif defined(CP865)
#include "tbls/cp865_to_utf8.tbl"

#elif defined(CP866)
#include "tbls/cp866_to_utf8.tbl"

#elif defined(CP869)
#include "tbls/cp869_to_utf8.tbl"

#elif defined(CP874)
#include "tbls/cp874_to_utf8.tbl"

#elif defined(CP1250)
#include "tbls/cp1250_to_utf8.tbl"

#elif defined(CP1251)
#include "tbls/cp1251_to_utf8.tbl"

#elif defined(CP1252)
#include "tbls/cp1252_to_utf8.tbl"

#elif defined(CP1253)
#include "tbls/cp1253_to_utf8.tbl"

#elif defined(CP1254)
#include "tbls/cp1254_to_utf8.tbl"

#elif defined(CP1255)
#include "tbls/cp1255_to_utf8.tbl"

#elif defined(CP1256)
#include "tbls/cp1256_to_utf8.tbl"

#elif defined(CP1257)
#include "tbls/cp1257_to_utf8.tbl"

#elif defined(CP1258)
#include "tbls/cp1258_to_utf8.tbl"

#else
#error	"Error - nothing defined."
#endif
};

#endif	/* SB_TO_UTF8_H */

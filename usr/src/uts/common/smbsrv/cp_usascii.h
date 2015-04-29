/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_CP_USASCII_H
#define	_SMBSRV_CP_USASCII_H

/*
 * This file specifies the codepage mapping the US-ASCII Character Set,
 * which is a subset of the Latin-1 character set.
 */

#include <smbsrv/string.h>

#ifdef __cplusplus
extern "C" {
#endif

const smb_codepage_t usascii_codepage[256] = {
	{ CODEPAGE_ISNONE,  0x0000, 0x0000 },    /* 0x0000 */
	{ CODEPAGE_ISNONE,  0x0001, 0x0001 },    /* 0x0001 */
	{ CODEPAGE_ISNONE,  0x0002, 0x0002 },    /* 0x0002 */
	{ CODEPAGE_ISNONE,  0x0003, 0x0003 },    /* 0x0003 */
	{ CODEPAGE_ISNONE,  0x0004, 0x0004 },    /* 0x0004 */
	{ CODEPAGE_ISNONE,  0x0005, 0x0005 },    /* 0x0005 */
	{ CODEPAGE_ISNONE,  0x0006, 0x0006 },    /* 0x0006 */
	{ CODEPAGE_ISNONE,  0x0007, 0x0007 },    /* 0x0007 */
	{ CODEPAGE_ISNONE,  0x0008, 0x0008 },    /* 0x0008 */
	{ CODEPAGE_ISNONE,  0x0009, 0x0009 },    /* 0x0009 */
	{ CODEPAGE_ISNONE,  0x000a, 0x000a },    /* 0x000a */
	{ CODEPAGE_ISNONE,  0x000b, 0x000b },    /* 0x000b */
	{ CODEPAGE_ISNONE,  0x000c, 0x000c },    /* 0x000c */
	{ CODEPAGE_ISNONE,  0x000d, 0x000d },    /* 0x000d */
	{ CODEPAGE_ISNONE,  0x000e, 0x000e },    /* 0x000e */
	{ CODEPAGE_ISNONE,  0x000f, 0x000f },    /* 0x000f */
	{ CODEPAGE_ISNONE,  0x0010, 0x0010 },    /* 0x0010 */
	{ CODEPAGE_ISNONE,  0x0011, 0x0011 },    /* 0x0011 */
	{ CODEPAGE_ISNONE,  0x0012, 0x0012 },    /* 0x0012 */
	{ CODEPAGE_ISNONE,  0x0013, 0x0013 },    /* 0x0013 */
	{ CODEPAGE_ISNONE,  0x0014, 0x0014 },    /* 0x0014 */
	{ CODEPAGE_ISNONE,  0x0015, 0x0015 },    /* 0x0015 */
	{ CODEPAGE_ISNONE,  0x0016, 0x0016 },    /* 0x0016 */
	{ CODEPAGE_ISNONE,  0x0017, 0x0017 },    /* 0x0017 */
	{ CODEPAGE_ISNONE,  0x0018, 0x0018 },    /* 0x0018 */
	{ CODEPAGE_ISNONE,  0x0019, 0x0019 },    /* 0x0019 */
	{ CODEPAGE_ISNONE,  0x001a, 0x001a },    /* 0x001a */
	{ CODEPAGE_ISNONE,  0x001b, 0x001b },    /* 0x001b */
	{ CODEPAGE_ISNONE,  0x001c, 0x001c },    /* 0x001c */
	{ CODEPAGE_ISNONE,  0x001d, 0x001d },    /* 0x001d */
	{ CODEPAGE_ISNONE,  0x001e, 0x001e },    /* 0x001e */
	{ CODEPAGE_ISNONE,  0x001f, 0x001f },    /* 0x001f */
	{ CODEPAGE_ISNONE,  0x0020, 0x0020 },    /* 0x0020 */
	{ CODEPAGE_ISNONE,  0x0021, 0x0021 },    /* 0x0021 */
	{ CODEPAGE_ISNONE,  0x0022, 0x0022 },    /* 0x0022 */
	{ CODEPAGE_ISNONE,  0x0023, 0x0023 },    /* 0x0023 */
	{ CODEPAGE_ISNONE,  0x0024, 0x0024 },    /* 0x0024 */
	{ CODEPAGE_ISNONE,  0x0025, 0x0025 },    /* 0x0025 */
	{ CODEPAGE_ISNONE,  0x0026, 0x0026 },    /* 0x0026 */
	{ CODEPAGE_ISNONE,  0x0027, 0x0027 },    /* 0x0027 */
	{ CODEPAGE_ISNONE,  0x0028, 0x0028 },    /* 0x0028 */
	{ CODEPAGE_ISNONE,  0x0029, 0x0029 },    /* 0x0029 */
	{ CODEPAGE_ISNONE,  0x002a, 0x002a },    /* 0x002a */
	{ CODEPAGE_ISNONE,  0x002b, 0x002b },    /* 0x002b */
	{ CODEPAGE_ISNONE,  0x002c, 0x002c },    /* 0x002c */
	{ CODEPAGE_ISNONE,  0x002d, 0x002d },    /* 0x002d */
	{ CODEPAGE_ISNONE,  0x002e, 0x002e },    /* 0x002e */
	{ CODEPAGE_ISNONE,  0x002f, 0x002f },    /* 0x002f */
	{ CODEPAGE_ISNONE,  0x0030, 0x0030 },    /* 0x0030 */
	{ CODEPAGE_ISNONE,  0x0031, 0x0031 },    /* 0x0031 */
	{ CODEPAGE_ISNONE,  0x0032, 0x0032 },    /* 0x0032 */
	{ CODEPAGE_ISNONE,  0x0033, 0x0033 },    /* 0x0033 */
	{ CODEPAGE_ISNONE,  0x0034, 0x0034 },    /* 0x0034 */
	{ CODEPAGE_ISNONE,  0x0035, 0x0035 },    /* 0x0035 */
	{ CODEPAGE_ISNONE,  0x0036, 0x0036 },    /* 0x0036 */
	{ CODEPAGE_ISNONE,  0x0037, 0x0037 },    /* 0x0037 */
	{ CODEPAGE_ISNONE,  0x0038, 0x0038 },    /* 0x0038 */
	{ CODEPAGE_ISNONE,  0x0039, 0x0039 },    /* 0x0039 */
	{ CODEPAGE_ISNONE,  0x003a, 0x003a },    /* 0x003a */
	{ CODEPAGE_ISNONE,  0x003b, 0x003b },    /* 0x003b */
	{ CODEPAGE_ISNONE,  0x003c, 0x003c },    /* 0x003c */
	{ CODEPAGE_ISNONE,  0x003d, 0x003d },    /* 0x003d */
	{ CODEPAGE_ISNONE,  0x003e, 0x003e },    /* 0x003e */
	{ CODEPAGE_ISNONE,  0x003f, 0x003f },    /* 0x003f */
	{ CODEPAGE_ISNONE,  0x0040, 0x0040 },    /* 0x0040 */
	{ CODEPAGE_ISUPPER, 0x0041, 0x0061 },    /* 0x0041 */
	{ CODEPAGE_ISUPPER, 0x0042, 0x0062 },    /* 0x0042 */
	{ CODEPAGE_ISUPPER, 0x0043, 0x0063 },    /* 0x0043 */
	{ CODEPAGE_ISUPPER, 0x0044, 0x0064 },    /* 0x0044 */
	{ CODEPAGE_ISUPPER, 0x0045, 0x0065 },    /* 0x0045 */
	{ CODEPAGE_ISUPPER, 0x0046, 0x0066 },    /* 0x0046 */
	{ CODEPAGE_ISUPPER, 0x0047, 0x0067 },    /* 0x0047 */
	{ CODEPAGE_ISUPPER, 0x0048, 0x0068 },    /* 0x0048 */
	{ CODEPAGE_ISUPPER, 0x0049, 0x0069 },    /* 0x0049 */
	{ CODEPAGE_ISUPPER, 0x004a, 0x006a },    /* 0x004a */
	{ CODEPAGE_ISUPPER, 0x004b, 0x006b },    /* 0x004b */
	{ CODEPAGE_ISUPPER, 0x004c, 0x006c },    /* 0x004c */
	{ CODEPAGE_ISUPPER, 0x004d, 0x006d },    /* 0x004d */
	{ CODEPAGE_ISUPPER, 0x004e, 0x006e },    /* 0x004e */
	{ CODEPAGE_ISUPPER, 0x004f, 0x006f },    /* 0x004f */
	{ CODEPAGE_ISUPPER, 0x0050, 0x0070 },    /* 0x0050 */
	{ CODEPAGE_ISUPPER, 0x0051, 0x0071 },    /* 0x0051 */
	{ CODEPAGE_ISUPPER, 0x0052, 0x0072 },    /* 0x0052 */
	{ CODEPAGE_ISUPPER, 0x0053, 0x0073 },    /* 0x0053 */
	{ CODEPAGE_ISUPPER, 0x0054, 0x0074 },    /* 0x0054 */
	{ CODEPAGE_ISUPPER, 0x0055, 0x0075 },    /* 0x0055 */
	{ CODEPAGE_ISUPPER, 0x0056, 0x0076 },    /* 0x0056 */
	{ CODEPAGE_ISUPPER, 0x0057, 0x0077 },    /* 0x0057 */
	{ CODEPAGE_ISUPPER, 0x0058, 0x0078 },    /* 0x0058 */
	{ CODEPAGE_ISUPPER, 0x0059, 0x0079 },    /* 0x0059 */
	{ CODEPAGE_ISUPPER, 0x005a, 0x007a },    /* 0x005a */
	{ CODEPAGE_ISNONE,  0x005b, 0x005b },    /* 0x005b */
	{ CODEPAGE_ISNONE,  0x005c, 0x005c },    /* 0x005c */
	{ CODEPAGE_ISNONE,  0x005d, 0x005d },    /* 0x005d */
	{ CODEPAGE_ISNONE,  0x005e, 0x005e },    /* 0x005e */
	{ CODEPAGE_ISNONE,  0x005f, 0x005f },    /* 0x005f */
	{ CODEPAGE_ISNONE,  0x0060, 0x0060 },    /* 0x0060 */
	{ CODEPAGE_ISLOWER, 0x0041, 0x0061 },    /* 0x0061 */
	{ CODEPAGE_ISLOWER, 0x0042, 0x0062 },    /* 0x0062 */
	{ CODEPAGE_ISLOWER, 0x0043, 0x0063 },    /* 0x0063 */
	{ CODEPAGE_ISLOWER, 0x0044, 0x0064 },    /* 0x0064 */
	{ CODEPAGE_ISLOWER, 0x0045, 0x0065 },    /* 0x0065 */
	{ CODEPAGE_ISLOWER, 0x0046, 0x0066 },    /* 0x0066 */
	{ CODEPAGE_ISLOWER, 0x0047, 0x0067 },    /* 0x0067 */
	{ CODEPAGE_ISLOWER, 0x0048, 0x0068 },    /* 0x0068 */
	{ CODEPAGE_ISLOWER, 0x0049, 0x0069 },    /* 0x0069 */
	{ CODEPAGE_ISLOWER, 0x004a, 0x006a },    /* 0x006a */
	{ CODEPAGE_ISLOWER, 0x004b, 0x006b },    /* 0x006b */
	{ CODEPAGE_ISLOWER, 0x004c, 0x006c },    /* 0x006c */
	{ CODEPAGE_ISLOWER, 0x004d, 0x006d },    /* 0x006d */
	{ CODEPAGE_ISLOWER, 0x004e, 0x006e },    /* 0x006e */
	{ CODEPAGE_ISLOWER, 0x004f, 0x006f },    /* 0x006f */
	{ CODEPAGE_ISLOWER, 0x0050, 0x0070 },    /* 0x0070 */
	{ CODEPAGE_ISLOWER, 0x0051, 0x0071 },    /* 0x0071 */
	{ CODEPAGE_ISLOWER, 0x0052, 0x0072 },    /* 0x0072 */
	{ CODEPAGE_ISLOWER, 0x0053, 0x0073 },    /* 0x0073 */
	{ CODEPAGE_ISLOWER, 0x0054, 0x0074 },    /* 0x0074 */
	{ CODEPAGE_ISLOWER, 0x0055, 0x0075 },    /* 0x0075 */
	{ CODEPAGE_ISLOWER, 0x0056, 0x0076 },    /* 0x0076 */
	{ CODEPAGE_ISLOWER, 0x0057, 0x0077 },    /* 0x0077 */
	{ CODEPAGE_ISLOWER, 0x0058, 0x0078 },    /* 0x0078 */
	{ CODEPAGE_ISLOWER, 0x0059, 0x0079 },    /* 0x0079 */
	{ CODEPAGE_ISLOWER, 0x005a, 0x007a },    /* 0x007a */
	{ CODEPAGE_ISNONE,  0x007b, 0x007b },    /* 0x007b */
	{ CODEPAGE_ISNONE,  0x007c, 0x007c },    /* 0x007c */
	{ CODEPAGE_ISNONE,  0x007d, 0x007d },    /* 0x007d */
	{ CODEPAGE_ISNONE,  0x007e, 0x007e },    /* 0x007e */
	{ CODEPAGE_ISNONE,  0x007f, 0x007f },    /* 0x007f */
	{ CODEPAGE_ISNONE,  0x0080, 0x0080 },    /* 0x0080 */
	{ CODEPAGE_ISNONE,  0x0081, 0x0081 },    /* 0x0081 */
	{ CODEPAGE_ISNONE,  0x0082, 0x0082 },    /* 0x0082 */
	{ CODEPAGE_ISNONE,  0x0083, 0x0083 },    /* 0x0083 */
	{ CODEPAGE_ISNONE,  0x0084, 0x0084 },    /* 0x0084 */
	{ CODEPAGE_ISNONE,  0x0085, 0x0085 },    /* 0x0085 */
	{ CODEPAGE_ISNONE,  0x0086, 0x0086 },    /* 0x0086 */
	{ CODEPAGE_ISNONE,  0x0087, 0x0087 },    /* 0x0087 */
	{ CODEPAGE_ISNONE,  0x0088, 0x0088 },    /* 0x0088 */
	{ CODEPAGE_ISNONE,  0x0089, 0x0089 },    /* 0x0089 */
	{ CODEPAGE_ISNONE,  0x008a, 0x008a },    /* 0x008a */
	{ CODEPAGE_ISNONE,  0x008b, 0x008b },    /* 0x008b */
	{ CODEPAGE_ISNONE,  0x008c, 0x008c },    /* 0x008c */
	{ CODEPAGE_ISNONE,  0x008d, 0x008d },    /* 0x008d */
	{ CODEPAGE_ISNONE,  0x008e, 0x008e },    /* 0x008e */
	{ CODEPAGE_ISNONE,  0x008f, 0x008f },    /* 0x008f */
	{ CODEPAGE_ISNONE,  0x0090, 0x0090 },    /* 0x0090 */
	{ CODEPAGE_ISNONE,  0x0091, 0x0091 },    /* 0x0091 */
	{ CODEPAGE_ISNONE,  0x0092, 0x0092 },    /* 0x0092 */
	{ CODEPAGE_ISNONE,  0x0093, 0x0093 },    /* 0x0093 */
	{ CODEPAGE_ISNONE,  0x0094, 0x0094 },    /* 0x0094 */
	{ CODEPAGE_ISNONE,  0x0095, 0x0095 },    /* 0x0095 */
	{ CODEPAGE_ISNONE,  0x0096, 0x0096 },    /* 0x0096 */
	{ CODEPAGE_ISNONE,  0x0097, 0x0097 },    /* 0x0097 */
	{ CODEPAGE_ISNONE,  0x0098, 0x0098 },    /* 0x0098 */
	{ CODEPAGE_ISNONE,  0x0099, 0x0099 },    /* 0x0099 */
	{ CODEPAGE_ISNONE,  0x009a, 0x009a },    /* 0x009a */
	{ CODEPAGE_ISNONE,  0x009b, 0x009b },    /* 0x009b */
	{ CODEPAGE_ISNONE,  0x009c, 0x009c },    /* 0x009c */
	{ CODEPAGE_ISNONE,  0x009d, 0x009d },    /* 0x009d */
	{ CODEPAGE_ISNONE,  0x009e, 0x009e },    /* 0x009e */
	{ CODEPAGE_ISNONE,  0x009f, 0x009f },    /* 0x009f */
	{ CODEPAGE_ISNONE,  0x00a0, 0x00a0 },    /* 0x00a0 */
	{ CODEPAGE_ISNONE,  0x00a1, 0x00a1 },    /* 0x00a1 */
	{ CODEPAGE_ISNONE,  0x00a2, 0x00a2 },    /* 0x00a2 */
	{ CODEPAGE_ISNONE,  0x00a3, 0x00a3 },    /* 0x00a3 */
	{ CODEPAGE_ISNONE,  0x00a4, 0x00a4 },    /* 0x00a4 */
	{ CODEPAGE_ISNONE,  0x00a5, 0x00a5 },    /* 0x00a5 */
	{ CODEPAGE_ISNONE,  0x00a6, 0x00a6 },    /* 0x00a6 */
	{ CODEPAGE_ISNONE,  0x00a7, 0x00a7 },    /* 0x00a7 */
	{ CODEPAGE_ISNONE,  0x00a8, 0x00a8 },    /* 0x00a8 */
	{ CODEPAGE_ISNONE,  0x00a9, 0x00a9 },    /* 0x00a9 */
	{ CODEPAGE_ISNONE,  0x00aa, 0x00aa },    /* 0x00aa */
	{ CODEPAGE_ISNONE,  0x00ab, 0x00ab },    /* 0x00ab */
	{ CODEPAGE_ISNONE,  0x00ac, 0x00ac },    /* 0x00ac */
	{ CODEPAGE_ISNONE,  0x00ad, 0x00ad },    /* 0x00ad */
	{ CODEPAGE_ISNONE,  0x00ae, 0x00ae },    /* 0x00ae */
	{ CODEPAGE_ISNONE,  0x00af, 0x00af },    /* 0x00af */
	{ CODEPAGE_ISNONE,  0x00b0, 0x00b0 },    /* 0x00b0 */
	{ CODEPAGE_ISNONE,  0x00b1, 0x00b1 },    /* 0x00b1 */
	{ CODEPAGE_ISNONE,  0x00b2, 0x00b2 },    /* 0x00b2 */
	{ CODEPAGE_ISNONE,  0x00b3, 0x00b3 },    /* 0x00b3 */
	{ CODEPAGE_ISNONE,  0x00b4, 0x00b4 },    /* 0x00b4 */
	{ CODEPAGE_ISNONE,  0x00b5, 0x00b5 },    /* 0x00b5 */
	{ CODEPAGE_ISNONE,  0x00b6, 0x00b6 },    /* 0x00b6 */
	{ CODEPAGE_ISNONE,  0x00b7, 0x00b7 },    /* 0x00b7 */
	{ CODEPAGE_ISNONE,  0x00b8, 0x00b8 },    /* 0x00b8 */
	{ CODEPAGE_ISNONE,  0x00b9, 0x00b9 },    /* 0x00b9 */
	{ CODEPAGE_ISNONE,  0x00ba, 0x00ba },    /* 0x00ba */
	{ CODEPAGE_ISNONE,  0x00bb, 0x00bb },    /* 0x00bb */
	{ CODEPAGE_ISNONE,  0x00bc, 0x00bc },    /* 0x00bc */
	{ CODEPAGE_ISNONE,  0x00bd, 0x00bd },    /* 0x00bd */
	{ CODEPAGE_ISNONE,  0x00be, 0x00be },    /* 0x00be */
	{ CODEPAGE_ISNONE,  0x00bf, 0x00bf },    /* 0x00bf */
	{ CODEPAGE_ISNONE,  0x00c0, 0x00c0 },    /* 0x00c0 */
	{ CODEPAGE_ISNONE,  0x00c1, 0x00c1 },    /* 0x00c1 */
	{ CODEPAGE_ISNONE,  0x00c2, 0x00c2 },    /* 0x00c2 */
	{ CODEPAGE_ISNONE,  0x00c3, 0x00c3 },    /* 0x00c3 */
	{ CODEPAGE_ISNONE,  0x00c4, 0x00c4 },    /* 0x00c4 */
	{ CODEPAGE_ISNONE,  0x00c5, 0x00c5 },    /* 0x00c5 */
	{ CODEPAGE_ISNONE,  0x00c6, 0x00c6 },    /* 0x00c6 */
	{ CODEPAGE_ISNONE,  0x00c7, 0x00c7 },    /* 0x00c7 */
	{ CODEPAGE_ISNONE,  0x00c8, 0x00c8 },    /* 0x00c8 */
	{ CODEPAGE_ISNONE,  0x00c9, 0x00c9 },    /* 0x00c9 */
	{ CODEPAGE_ISNONE,  0x00ca, 0x00ca },    /* 0x00ca */
	{ CODEPAGE_ISNONE,  0x00cb, 0x00cb },    /* 0x00cb */
	{ CODEPAGE_ISNONE,  0x00cc, 0x00cc },    /* 0x00cc */
	{ CODEPAGE_ISNONE,  0x00cd, 0x00cd },    /* 0x00cd */
	{ CODEPAGE_ISNONE,  0x00ce, 0x00ce },    /* 0x00ce */
	{ CODEPAGE_ISNONE,  0x00cf, 0x00cf },    /* 0x00cf */
	{ CODEPAGE_ISNONE,  0x00d0, 0x00d0 },    /* 0x00d0 */
	{ CODEPAGE_ISNONE,  0x00d1, 0x00d1 },    /* 0x00d1 */
	{ CODEPAGE_ISNONE,  0x00d2, 0x00d2 },    /* 0x00d2 */
	{ CODEPAGE_ISNONE,  0x00d3, 0x00d3 },    /* 0x00d3 */
	{ CODEPAGE_ISNONE,  0x00d4, 0x00d4 },    /* 0x00d4 */
	{ CODEPAGE_ISNONE,  0x00d5, 0x00d5 },    /* 0x00d5 */
	{ CODEPAGE_ISNONE,  0x00d6, 0x00d6 },    /* 0x00d6 */
	{ CODEPAGE_ISNONE,  0x00d7, 0x00d7 },    /* 0x00d7 */
	{ CODEPAGE_ISNONE,  0x00d8, 0x00d8 },    /* 0x00d8 */
	{ CODEPAGE_ISNONE,  0x00d9, 0x00d9 },    /* 0x00d9 */
	{ CODEPAGE_ISNONE,  0x00da, 0x00da },    /* 0x00da */
	{ CODEPAGE_ISNONE,  0x00db, 0x00db },    /* 0x00db */
	{ CODEPAGE_ISNONE,  0x00dc, 0x00dc },    /* 0x00dc */
	{ CODEPAGE_ISNONE,  0x00dd, 0x00dd },    /* 0x00dd */
	{ CODEPAGE_ISNONE,  0x00de, 0x00de },    /* 0x00de */
	{ CODEPAGE_ISNONE,  0x00df, 0x00df },    /* 0x00df */
	{ CODEPAGE_ISNONE,  0x00e0, 0x00e0 },    /* 0x00e0 */
	{ CODEPAGE_ISNONE,  0x00e1, 0x00e1 },    /* 0x00e1 */
	{ CODEPAGE_ISNONE,  0x00e2, 0x00e2 },    /* 0x00e2 */
	{ CODEPAGE_ISNONE,  0x00e3, 0x00e3 },    /* 0x00e3 */
	{ CODEPAGE_ISNONE,  0x00e4, 0x00e4 },    /* 0x00e4 */
	{ CODEPAGE_ISNONE,  0x00e5, 0x00e5 },    /* 0x00e5 */
	{ CODEPAGE_ISNONE,  0x00e6, 0x00e6 },    /* 0x00e6 */
	{ CODEPAGE_ISNONE,  0x00e7, 0x00e7 },    /* 0x00e7 */
	{ CODEPAGE_ISNONE,  0x00e8, 0x00e8 },    /* 0x00e8 */
	{ CODEPAGE_ISNONE,  0x00e9, 0x00e9 },    /* 0x00e9 */
	{ CODEPAGE_ISNONE,  0x00ea, 0x00ea },    /* 0x00ea */
	{ CODEPAGE_ISNONE,  0x00eb, 0x00eb },    /* 0x00eb */
	{ CODEPAGE_ISNONE,  0x00ec, 0x00ec },    /* 0x00ec */
	{ CODEPAGE_ISNONE,  0x00ed, 0x00ed },    /* 0x00ed */
	{ CODEPAGE_ISNONE,  0x00ee, 0x00ee },    /* 0x00ee */
	{ CODEPAGE_ISNONE,  0x00ef, 0x00ef },    /* 0x00ef */
	{ CODEPAGE_ISNONE,  0x00f0, 0x00f0 },    /* 0x00f0 */
	{ CODEPAGE_ISNONE,  0x00f1, 0x00f1 },    /* 0x00f1 */
	{ CODEPAGE_ISNONE,  0x00f2, 0x00f2 },    /* 0x00f2 */
	{ CODEPAGE_ISNONE,  0x00f3, 0x00f3 },    /* 0x00f3 */
	{ CODEPAGE_ISNONE,  0x00f4, 0x00f4 },    /* 0x00f4 */
	{ CODEPAGE_ISNONE,  0x00f5, 0x00f5 },    /* 0x00f5 */
	{ CODEPAGE_ISNONE,  0x00f6, 0x00f6 },    /* 0x00f6 */
	{ CODEPAGE_ISNONE,  0x00f7, 0x00f7 },    /* 0x00f7 */
	{ CODEPAGE_ISNONE,  0x00f8, 0x00f8 },    /* 0x00f8 */
	{ CODEPAGE_ISNONE,  0x00f9, 0x00f9 },    /* 0x00f9 */
	{ CODEPAGE_ISNONE,  0x00fa, 0x00fa },    /* 0x00fa */
	{ CODEPAGE_ISNONE,  0x00fb, 0x00fb },    /* 0x00fb */
	{ CODEPAGE_ISNONE,  0x00fc, 0x00fc },    /* 0x00fc */
	{ CODEPAGE_ISNONE,  0x00fd, 0x00fd },    /* 0x00fd */
	{ CODEPAGE_ISNONE,  0x00fe, 0x00fe },    /* 0x00fe */
	{ CODEPAGE_ISNONE,  0x00ff, 0x00ff } };  /* 0x00ff */

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_CP_USASCII_H */

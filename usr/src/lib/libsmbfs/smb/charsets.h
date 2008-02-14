/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *      @(#)charsets.h
 *      (c) 2004   Apple Computer, Inc.  All Rights Reserved
 *
 *
 *      charsets.h -- Routines converting between UTF-8, 16-bit
 *			little-endian Unicode, 16-bit host-byte-order
 *			Unicode, and various Windows code pages.
 *
 *      MODIFICATION HISTORY:
 *       28-Nov-2004     Guy Harris	New today
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef __CHARSETS_H__
#define	__CHARSETS_H__

extern char *convert_wincs_to_utf8(const char *windows_string);
extern char *convert_utf8_to_wincs(const char *utf8_string);
extern char *convert_leunicode_to_utf8(unsigned short *windows_string);
extern char *convert_unicode_to_utf8(unsigned short *windows_string, int len);
extern unsigned short *convert_utf8_to_leunicode(const char *utf8_string);

#endif /* __CHARSETS_H__ */

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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBSRV_CODEPAGE_H
#define	_SMBSRV_CODEPAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/string.h>
#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Labels to define whether a code page table entry is an uppercase
 * character, a lowercase character or neither. One of these values
 * should appear in the ctype field of the code page tables.
 */
#define	CODEPAGE_ISNONE		0x00
#define	CODEPAGE_ISUPPER	0x01
#define	CODEPAGE_ISLOWER	0x02

/*
 * The structure of a code page entry. Each code page table will
 * consist of an array of 256 codepage entries.
 *
 * ctype indicates case of the value.
 * upper indicates the uppercase equivalent value.
 * lower indicates the lowercase equivalent value.
 */
typedef struct codepage {
	unsigned char ctype;
	mts_wchar_t upper;
	mts_wchar_t lower;
} codepage_t;

/*
 * Global pointer to the current code page. This is
 * defaulted to a standard ASCII table.
 */
extern codepage_t usascii_codepage[];

/*
 * This buffer is used to store the language string for display.
 */
#define	CODEPAGE_BUFSIZ		48

extern int oem_language_set(char *language);
extern unsigned int oem_get_smb_cpid(void);
extern unsigned int oem_get_telnet_cpid(void);

extern int codepage_isupper(int c);
extern int codepage_islower(int c);
extern int codepage_toupper(int c);
extern int codepage_tolower(int c);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_CODEPAGE_H */

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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBSRV_STRING_H
#define	_SMBSRV_STRING_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	_smb_between(l, c, u) ((l) <= (c) && (c) <= (u))

#define	smb_isalpha(c)	(smb_islower(c) || smb_isupper(c))
#define	smb_isdigit(c)	_smb_between('0', (c), '9')
#define	smb_isalnum(c)	(smb_isalpha(c) || smb_isdigit(c))
#define	smb_isxdigit(c)	(smb_isdigit(c) ||			\
    _smb_between('a', (c), 'f') ||				\
    _smb_between('A', (c), 'F'))
#define	smb_isblank(c)	((c) == ' ' || (c) == '\t')
#define	smb_isspace(c)  ((c) == ' ' ||		\
	    (c) == '\t' ||			\
	    (c) == '\n' ||			\
	    (c) == '\r' ||			\
	    (c) == '\f')
#define	smb_isascii(c)	(!((c) &~ 0x7F))

/* These macros only apply to ASCII */
#define	smb_isalpha_ascii(c)	\
	(_smb_between('a', (c), 'z') || _smb_between('A', (c), 'Z'))
#define	smb_isalnum_ascii(c)	(smb_isalpha_ascii(c) || smb_isdigit(c))

#define	smb_isprint(c)	_smb_between('!', (c), '~')
#define	smb_iscntrl(c)	((((c) >= 0) && ((c) <= 0x1f)) || ((c) == 0x7f))
#define	smb_ispunct(c)  (smb_isprint(c) && !smb_isxdigit(c) && !smb_isspace(c))

/*
 * These id's should correspond to oemcpg_table smb_oem.c.
 */
typedef enum codepage_id {
	OEM_CPG_850 = 0,
	OEM_CPG_950,
	OEM_CPG_1252,
	OEM_CPG_949,
	OEM_CPG_936,
	OEM_CPG_932,
	OEM_CPG_852,
	OEM_CPG_1250,
	OEM_CPG_1253,
	OEM_CPG_737,
	OEM_CPG_1254,
	OEM_CPG_857,
	OEM_CPG_1251,
	OEM_CPG_866,
	OEM_CPG_1255,
	OEM_CPG_862,
	OEM_CPG_1256,
	OEM_CPG_720
} codepage_id_t;

/*
 * Maximum number of bytes per multi-byte character.
 */
#define	MTS_MB_CUR_MAX		3
#define	MTS_MB_CHAR_MAX		MTS_MB_CUR_MAX

typedef	uint16_t smb_wchar_t;

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
typedef struct smb_codepage {
	unsigned char ctype;
	smb_wchar_t upper;
	smb_wchar_t lower;
} smb_codepage_t;

void smb_codepage_init(void);

int smb_isupper(int);
int smb_islower(int);
int smb_toupper(int);
int smb_tolower(int);
char *smb_strupr(char *);
char *smb_strlwr(char *);
int smb_isstrupr(const char *);
int smb_isstrlwr(const char *);
int smb_strcasecmp(const char *, const char *, size_t);

int smb_match(char *patn, char *str);
int smb_match_ci(char *patn, char *str);
int smb_match83(char *patn, char *str83);

size_t smb_mbstowcs(smb_wchar_t *, const char *, size_t);
size_t smb_wcstombs(char *, const smb_wchar_t *, size_t);
int smb_mbtowc(smb_wchar_t *, const char *, size_t);
int smb_wctomb(char *, smb_wchar_t);

size_t smb_wcequiv_strlen(const char *);
size_t smb_sbequiv_strlen(const char *);

int smb_stombs(char *, char *, int);
int smb_mbstos(char *, const char *);

size_t ucstooem(char *, const smb_wchar_t *, size_t, uint32_t);
size_t oemtoucs(smb_wchar_t *, const char *, size_t, uint32_t);

char *strsubst(char *, char, char);
char *strsep(char **, const char *);
char *strcanon(char *, const char *);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_STRING_H */

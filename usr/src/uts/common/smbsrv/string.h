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

#ifndef	_SMBSRV_STRING_H
#define	_SMBSRV_STRING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char *strsubst(char *, char, char);
extern char *strsep(char **, const char *);
extern char *strcanon(char *, const char *);

extern char *utf8_strupr(char *);
extern char *utf8_strlwr(char *);
extern int utf8_isstrupr(const char *);
extern int utf8_isstrlwr(const char *);
extern int utf8_strcasecmp(const char *, const char *);
extern int utf8_strncasecmp(const char *, const char *, int);
extern int utf8_isstrascii(const char *);

extern int smb_match(char *patn, char *str);
extern int smb_match_ci(char *patn, char *str);
extern int smb_match83(char *patn, char *str83);

/*
 * Maximum number of bytes per multi-byte character.
 */
#define	MTS_MB_CUR_MAX		3
#define	MTS_MB_CHAR_MAX		MTS_MB_CUR_MAX

size_t mts_mbstowcs(mts_wchar_t *, const char *, size_t);
size_t mts_wcstombs(char *, const mts_wchar_t *, size_t);
int mts_mbtowc(mts_wchar_t *, const char *, size_t);
int mts_wctomb(char *, mts_wchar_t);

size_t mts_wcequiv_strlen(const char *);
size_t mts_sbequiv_strlen(const char *);

int mts_stombs(char *, char *, int);
int mts_mbstos(char *, const char *);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_STRING_H */

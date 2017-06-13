/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_STRING_H
#define	_MDB_STRING_H

#include <sys/types.h>
#include <strings.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NTOS_UPCASE	0x1	/* Use upper-case hexadecimal digits */
#define	NTOS_UNSIGNED	0x2	/* Value is meant to be unsigned */
#define	NTOS_SIGNPOS	0x4	/* Prefix positive values with sign '+' */
#define	NTOS_SHOWBASE	0x8	/* Show base under appropriate circumstances */

extern const char *numtostr(uintmax_t, int, uint_t);
extern uintmax_t mdb_strtonum(const char *, int);
extern ulong_t strntoul(const char *, size_t, int);
extern int strisnum(const char *);
extern int strisbasenum(const char *);
extern int strtoi(const char *);

extern char *strdup(const char *);
extern char *strndup(const char *, size_t);
extern void strfree(char *);

extern size_t stresc2chr(char *);
extern char *strchr2esc(const char *, size_t);
extern char *strchr2adb(const char *, size_t);

extern char *strnchr(const char *, int, size_t);

extern char *strsplit(char *, char);
extern char *strrsplit(char *, char);
extern const char *strnpbrk(const char *, const char *, size_t);
extern char *strabbr(char *, size_t);

extern const char *strbasename(const char *);
extern char *strdirname(char *);

extern const char *strbadid(const char *);
extern int strisprint(const char *);

extern char *mdb_inet_ntop(int, const void *, char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_STRING_H */

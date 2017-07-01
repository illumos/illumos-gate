/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#ifndef _WINTYPES_H
#define	_WINTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * While we don't want to, this expects that we have Win32 style type names.
 * Deal with conversions between Win32 and reality. Remember that Windows is an
 * ILP32 system, but it is a LLP64 system.
 */

typedef uint8_t BYTE;
typedef uint8_t *LPBYTE;
typedef const uint8_t *LPCBYTE;
typedef const void *LPCVOID;
typedef uint32_t DWORD;
typedef uint32_t *LPDWORD;
typedef int32_t	LONG;
typedef char *LPSTR;
typedef const char *LPCSTR;

/*
 * Include a few deprecated types because folks still use them.
 */
typedef char *LPTSTR;
typedef const char *LPCTSTR;
typedef char *LPCWSTR;

#ifdef __cplusplus
}
#endif

#endif /* _WINTYPES_H */

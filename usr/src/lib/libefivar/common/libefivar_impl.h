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
 * Copyright 2026 Argo Technology East
 */

/*
 * Internal helpers shared between libefivar source files.  Not part
 * of the stable ABI.
 */

#ifndef	_LIBEFIVAR_IMPL_H
#define	_LIBEFIVAR_IMPL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Convert a NUL-terminated ASCII string to a freshly malloc()ed UCS-2
 * little-endian buffer including a trailing UCS-2 NUL.  *dstsize_p
 * receives the byte count.  Returns 0 on success, -1 on error
 * (errno == ENOMEM or EILSEQ for non-ASCII input).
 */
extern int _efivar_ascii_to_ucs2(const char *, uint16_t **, size_t *);

/*
 * Convert a buffer of UCS-2 little-endian code units (size in bytes,
 * with or without a trailing UCS-2 NUL) into a freshly malloc()ed
 * NUL-terminated UTF-8 string.  Code points above 0x7f are rendered
 * as '?'.
 */
extern int _efivar_ucs2_to_ascii(const uint16_t *, size_t, char **);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBEFIVAR_IMPL_H */

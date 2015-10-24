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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _ENDIAN_H
#define	_ENDIAN_H

/*
 * Shim to use sys/byteorder.h in case the endian.h is not available.
 */

#include <sys/byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef htole16
#define	htole16	LE_16
#endif
#ifndef htole32
#define	htole32	LE_32
#endif
#ifndef le16toh
#define	le16toh	LE_16
#endif
#ifndef le32toh
#define	le32toh	LE_32
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ENDIAN_H */

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
 * Copyright 2020 Robert Mustacchi
 */

#ifndef _UNICODE_H
#define	_UNICODE_H

/*
 * Common definitions for dealing with Unicode.
 *
 * UTF-16 encodes data as a series of two byte values. However, there are more
 * than 16-bit of code points. Code points inside of the first 16-bits are
 * referred to as existing in the 'basic multilingual plane' (BMP). Those
 * outside of it are in the 'supplementary plane'. When such a code point is
 * encountered, it is encoded as a series of two uint16_t values.
 *
 * A value which is up to 20 bits (the current limit of the unicode code point
 * space) is encoded by splitting it into two 10-bit values. The upper 10 bits
 * are ORed with 0xd800 and the lower 10 bits are ORed with 0xdc00.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Range of Unicode code points reserved for surrogate characters.
 */
#define	UNICODE_SUR_MIN		0xd800
#define	UNICODE_SUR_MAX		0xdfff

/*
 * Range of Unicode code points in supplementary planes.
 */
#define	UNICODE_SUP_START	0x10000
#define	UNICODE_SUP_MAX		0x10ffff

/*
 * Starting constants for surrogate pairs.
 */
#define	UNICODE_SUR_UPPER	0xd800
#define	UNICODE_SUR_LOWER	0xdc00

/*
 * Macros to extract the value from a surrogate pair and to take a code point
 * and transform it into the surrogate version.
 */
#define	UNICODE_SUR_UVALUE(x)	(((x) & 0x3ff) << 10)
#define	UNICODE_SUR_LVALUE(x)	((x) & 0x3ff)
#define	UNICODE_SUR_UMASK(x)	(((x) >> 10) & 0x3ff)
#define	UNICODE_SUR_LMASK(x)	((x) & 0x3ff)

#ifdef __cplusplus
}
#endif

#endif /* _UNICODE_H */

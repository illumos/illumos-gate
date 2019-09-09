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
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 */

#ifndef _LZ4_H
#define	_LZ4_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern size_t lz4_compress(void *, void *, size_t, size_t, int);
extern int lz4_decompress(void *, void *, size_t, size_t, int);

#ifdef __cplusplus
}
#endif

#endif /* _LZ4_H */

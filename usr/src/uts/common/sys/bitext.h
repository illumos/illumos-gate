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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _SYS_BITEXT_H
#define	_SYS_BITEXT_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A bunch of routines to make working with bits and registers easier. This is
 * designed to be a replacement for the BITX macro and provide additional error
 * handling. See bitx64(9F), bitdel64(9F), and bitset64(9F) for more
 * information.
 */

extern uint8_t bitx8(uint8_t, uint_t, uint_t);
extern uint16_t bitx16(uint16_t, uint_t, uint_t);
extern uint32_t bitx32(uint32_t, uint_t, uint_t);
extern uint64_t bitx64(uint64_t, uint_t, uint_t);

extern uint8_t bitset8(uint8_t, uint_t, uint_t, uint8_t);
extern uint16_t bitset16(uint16_t, uint_t, uint_t, uint16_t);
extern uint32_t bitset32(uint32_t, uint_t, uint_t, uint32_t);
extern uint64_t bitset64(uint64_t, uint_t, uint_t, uint64_t);

extern uint64_t bitdel64(uint64_t, uint_t, uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BITEXT_H */

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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _ENDIAN_H
#define	_ENDIAN_H

/*
 * Endian conversion routines, see endian(3C)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/isa_defs.h>
#include <inttypes.h>

#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321
#define	__PDP_ENDIAN	3412

#if	defined(_LITTLE_ENDIAN)
#define	__BYTE_ORDER	LITTLE_ENDIAN
#elif	defined(_BIG_ENDIAN)
#define	__BYTE_ORDER	BIG_ENDIAN
#else
#error	"Unknown byte order"
#endif	/* _LITTLE_ENDIAN */

#define	LITTLE_ENDIAN	__LITTLE_ENDIAN
#define	BIG_ENDIAN	__BIG_ENDIAN
#define	BYTE_ORDER	__BYTE_ORDER

extern uint16_t htobe16(uint16_t);
extern uint32_t htobe32(uint32_t);
extern uint64_t htobe64(uint64_t);

extern uint16_t htole16(uint16_t);
extern uint32_t htole32(uint32_t);
extern uint64_t htole64(uint64_t);

/* Supply both the old and new BSD names */
extern uint16_t betoh16(uint16_t);
extern uint16_t letoh16(uint16_t);
extern uint16_t be16toh(uint16_t);
extern uint16_t le16toh(uint16_t);

extern uint32_t betoh32(uint32_t);
extern uint32_t letoh32(uint32_t);
extern uint32_t be32toh(uint32_t);
extern uint32_t le32toh(uint32_t);

extern uint64_t betoh64(uint64_t);
extern uint64_t letoh64(uint64_t);
extern uint64_t be64toh(uint64_t);
extern uint64_t le64toh(uint64_t);

#ifdef __cplusplus
}
#endif

#endif /* _ENDIAN_H */

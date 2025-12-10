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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _VIRTIO_ENDIAN_H
#define	_VIRTIO_ENDIAN_H

/*
 * VIRTIO FRAMEWORK: Helpers to convert between guest and host
 *
 * For design and usage documentation, see the comments in "virtio.h".
 *
 * NOTE: Client drivers should not use definitions from this file.
 */

#include <sys/types.h>
#include <sys/byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Modern VirtIO uses little endian whereas legacy VirtIO uses the guest's
 * native endianess. We must therefore convert multi-byte values in the modern
 * interface.
 */

static inline uint16_t
virtio_le16toh(uint16_t val)
{
	return (LE_16(val));
}

static inline uint32_t
virtio_le32toh(uint32_t val)
{
	return (LE_32(val));
}

static inline uint64_t
virtio_le64toh(uint64_t val)
{
	return (LE_64(val));
}

static inline uint16_t
virtio_htole16(uint16_t val)
{
	return (LE_16(val));
}

static inline uint32_t
virtio_htole32(uint32_t val)
{
	return (LE_32(val));
}

static inline uint64_t
virtio_htole64(uint64_t val)
{
	return (LE_64(val));
}

static inline uint16_t
virtio_gtoh16(uint16_t val, bool modern)
{
	return (modern ? LE_16(val) : val);
}

static inline uint32_t
virtio_gtoh32(uint32_t val, bool modern)
{
	return (modern ? LE_32(val) : val);
}

static inline uint64_t
virtio_gtoh64(uint64_t val, bool modern)
{
	return (modern ? LE_64(val) : val);
}

static inline uint16_t
virtio_htog16(uint16_t val, bool modern)
{
	return (modern ? LE_16(val) : val);
}

static inline uint32_t
virtio_htog32(uint32_t val, bool modern)
{
	return (modern ? LE_32(val) : val);
}

static inline uint64_t
virtio_htog64(uint64_t val, bool modern)
{
	return (modern ? LE_64(val) : val);
}

#define	viq_modern(q) ((q)->viq_virtio->vio_mode != VIRTIO_MODE_LEGACY)
#define	viq_htog16(q, x) virtio_htog16((x), viq_modern(q))
#define	viq_htog32(q, x) virtio_htog32((x), viq_modern(q))
#define	viq_htog64(q, x) virtio_htog64((x), viq_modern(q))
#define	viq_gtoh16(q, x) virtio_gtoh16((x), viq_modern(q))
#define	viq_gtoh32(q, x) virtio_gtoh32((x), viq_modern(q))
#define	viq_gtoh64(q, x) virtio_gtoh64((x), viq_modern(q))

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_ENDIAN_H */

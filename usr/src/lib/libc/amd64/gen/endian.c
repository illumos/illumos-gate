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
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * General, no-op functions for endian(3C). The rest are in byteorder.s.
 */

#include <endian.h>

uint16_t
htole16(uint16_t in)
{
	return (in);
}

uint32_t
htole32(uint32_t in)
{
	return (in);
}

uint64_t
htole64(uint64_t in)
{
	return (in);
}

uint16_t
letoh16(uint16_t in)
{
	return (in);
}

uint16_t
le16toh(uint16_t in)
{
	return (in);
}

uint32_t
letoh32(uint32_t in)
{
	return (in);
}

uint32_t
le32toh(uint32_t in)
{
	return (in);
}

uint64_t
letoh64(uint64_t in)
{
	return (in);
}

uint64_t
le64toh(uint64_t in)
{
	return (in);
}

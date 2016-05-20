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
 * endian(3C) routines
 */

uint16_t
htole16(uint16_t in)
{
	return (((in & 0xff) << 8) | ((in & 0xff00) >> 8));
}

uint32_t
htole32(uint32_t in)
{
	return (((in & 0xffUL) << 24) |
	    (in & 0xff00UL) << 8 |
	    (in & 0xff0000UL) >> 8 |
	    ((in & 0xff000000UL) >> 24));
}

uint64_t
htole64(uint64_t in)
{
	return (((in & 0xffULL) << 56) |
	    ((in & 0xff00ULL) << 40) |
	    ((in & 0xff0000ULL) << 24) |
	    ((in & 0xff000000ULL) << 8) |
	    ((in & 0xff00000000ULL) >> 8) |
	    ((in & 0xff0000000000ULL) >> 24) |
	    ((in & 0xff000000000000ULL) >> 40) |
	    ((in & 0xff00000000000000ULL) >> 56));
}

uint16_t
letoh16(uint16_t in)
{
	return (((in & 0xff) << 8) | ((in & 0xff00) >> 8));
}

uint16_t
le16toh(uint16_t in)
{
	return (((in & 0xff) << 8) | ((in & 0xff00) >> 8));
}

uint32_t
letoh32(uint32_t in)
{
	return (((in & 0xffUL) << 24) |
	    (in & 0xff00UL) << 8 |
	    (in & 0xff0000UL) >> 8 |
	    ((in & 0xff000000UL) >> 24));
}

uint32_t
le32toh(uint32_t in)
{
	return (((in & 0xffUL) << 24) |
	    (in & 0xff00UL) << 8 |
	    (in & 0xff0000UL) >> 8 |
	    ((in & 0xff000000UL) >> 24));
}

uint64_t
letoh64(uint64_t in)
{
	return (((in & 0xffULL) << 56) |
	    ((in & 0xff00ULL) << 40) |
	    ((in & 0xff0000ULL) << 24) |
	    ((in & 0xff000000ULL) << 8) |
	    ((in & 0xff00000000ULL) >> 8) |
	    ((in & 0xff0000000000ULL) >> 24) |
	    ((in & 0xff000000000000ULL) >> 40) |
	    ((in & 0xff00000000000000ULL) >> 56));
}

uint64_t
le64toh(uint64_t in)
{
	return (((in & 0xffULL) << 56) |
	    ((in & 0xff00ULL) << 40) |
	    ((in & 0xff0000ULL) << 24) |
	    ((in & 0xff000000ULL) << 8) |
	    ((in & 0xff00000000ULL) >> 8) |
	    ((in & 0xff0000000000ULL) >> 24) |
	    ((in & 0xff000000000000ULL) >> 40) |
	    ((in & 0xff00000000000000ULL) >> 56));
}

/* Anything to or from big-endian is a no-op */

uint16_t
htobe16(uint16_t in)
{
	return (in);
}

uint32_t
htobe32(uint32_t in)
{
	return (in);
}

uint64_t
htobe64(uint64_t in)
{
	return (in);
}

uint16_t
betoh16(uint16_t in)
{
	return (in);
}

uint16_t
be16toh(uint16_t in)
{
	return (in);
}

uint32_t
betoh32(uint32_t in)
{
	return (in);
}

uint32_t
be32toh(uint32_t in)
{
	return (in);
}

uint64_t
betoh64(uint64_t in)
{
	return (in);
}

uint64_t
be64toh(uint64_t in)
{
	return (in);
}

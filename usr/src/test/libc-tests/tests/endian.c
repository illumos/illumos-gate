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

/*
 * Test endian(3C).
 */

#include <sys/types.h>
#include <endian.h>
#include <sys/debug.h>

#ifndef BIG_ENDIAN
#error "Missing BIG_ENDIAN definition"
#endif

#ifndef LITTLE_ENDIAN
#error "Missing LITTLE_ENDIAN definition"
#endif

static void
endian_fromhost(void)
{
	uint16_t val16 = 0x1122;
	uint32_t val32 = 0x11223344;
	uint64_t val64 = 0x1122334455667788ULL;
	uint16_t ebe16, ele16, test16;
	uint32_t ebe32, ele32, test32;
	uint64_t ebe64, ele64, test64;

#ifdef	_LITTLE_ENDIAN
	ebe16 = 0x2211;
	ebe32 = 0x44332211UL;
	ebe64 = 0x8877665544332211ULL;
	ele16 = 0x1122;
	ele32 = 0x11223344UL;
	ele64 = 0x1122334455667788ULL;
#elif	_BIG_ENDIAN
	ele16 = 0x2211;
	ele32 = 0x44332211UL;
	ele64 = 0x8877665544332211ULL;
	ebe16 = 0x1122;
	ebe32 = 0x11223344UL;
	ebe64 = 0x1122334455667788ULL;
#else
#error	"Unknown byte order"
#endif	/* _LITTLE_ENDIAN */

	test16 = htobe16(val16);
	VERIFY3U(test16, ==, ebe16);
	test32 = htobe32(val32);
	VERIFY3U(test32, ==, ebe32);
	test64 = htobe64(val64);
	VERIFY3U(test64, ==, ebe64);

	test16 = htole16(val16);
	VERIFY3U(test16, ==, ele16);
	test32 = htole32(val32);
	VERIFY3U(test32, ==, ele32);
	test64 = htole64(val64);
	VERIFY3U(test64, ==, ele64);
}

static void
endian_frombig(void)
{
	uint16_t val16 = 0x1122;
	uint32_t val32 = 0x11223344;
	uint64_t val64 = 0x1122334455667788ULL;
	uint16_t e16, test16;
	uint32_t e32, test32;
	uint64_t e64, test64;

#ifdef	_LITTLE_ENDIAN
	e16 = 0x2211;
	e32 = 0x44332211UL;
	e64 = 0x8877665544332211ULL;
#elif	_BIG_ENDIAN
	e16 = 0x1122;
	e32 = 0x11223344UL;
	e64 = 0x1122334455667788ULL;
#else
#error	"Unknown byte order"
#endif	/* _LITTLE_ENDIAN */

	test16 = be16toh(val16);
	VERIFY3U(test16, ==, e16);
	test16 = betoh16(val16);
	VERIFY3U(test16, ==, e16);

	test32 = be32toh(val32);
	VERIFY3U(test32, ==, e32);
	test32 = betoh32(val32);
	VERIFY3U(test32, ==, e32);

	test64 = be64toh(val64);
	VERIFY3U(test64, ==, e64);
	test64 = betoh64(val64);
	VERIFY3U(test64, ==, e64);
}

static void
endian_fromlittle(void)
{
	uint16_t val16 = 0x1122;
	uint32_t val32 = 0x11223344;
	uint64_t val64 = 0x1122334455667788ULL;
	uint16_t e16, test16;
	uint32_t e32, test32;
	uint64_t e64, test64;

#ifdef	_LITTLE_ENDIAN
	e16 = 0x1122;
	e32 = 0x11223344UL;
	e64 = 0x1122334455667788ULL;
#elif	_BIG_ENDIAN
	e16 = 0x2211;
	e32 = 0x44332211UL;
	e64 = 0x8877665544332211ULL;
#else
#error	"Unknown byte order"
#endif	/* _LITTLE_ENDIAN */

	test16 = le16toh(val16);
	VERIFY3U(test16, ==, e16);
	test16 = letoh16(val16);
	VERIFY3U(test16, ==, e16);

	test32 = le32toh(val32);
	VERIFY3U(test32, ==, e32);
	test32 = letoh32(val32);
	VERIFY3U(test32, ==, e32);

	test64 = le64toh(val64);
	VERIFY3U(test64, ==, e64);
	test64 = letoh64(val64);
	VERIFY3U(test64, ==, e64);
}

int
main(void)
{
	endian_fromhost();
	endian_frombig();
	endian_fromlittle();
	return (0);
}

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

/*
 * Various functions for manipulating regions of bits in standard sized
 * integers. Meant to be a replacement for the extant BITX macro and provide
 * additional functionality. See bitx64(9F), bitdel64(9F), and bitset64(9f) for
 * more information.
 */

#include <sys/debug.h>
#include <sys/stdint.h>

uint8_t
bitx8(uint8_t reg, uint_t high, uint_t low)
{
	uint8_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 8);
	ASSERT3U(low, <, 8);

	mask = (1 << (high - low + 1)) - 1;
	return ((reg >> low) & mask);
}

uint16_t
bitx16(uint16_t reg, uint_t high, uint_t low)
{
	uint16_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 16);
	ASSERT3U(low, <, 16);

	mask = (1 << (high - low + 1)) - 1;
	return ((reg >> low) & mask);
}


uint32_t
bitx32(uint32_t reg, uint_t high, uint_t low)
{
	uint32_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 32);
	ASSERT3U(low, <, 32);

	mask = (1UL << (high - low + 1)) - 1;

	return ((reg >> low) & mask);
}

uint64_t
bitx64(uint64_t reg, uint_t high, uint_t low)
{
	uint64_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 64);
	ASSERT3U(low, <, 64);

	mask = (1ULL << (high - low + 1)) - 1ULL;
	return ((reg >> low) & mask);
}

uint8_t
bitset8(uint8_t reg, uint_t high, uint_t low, uint8_t val)
{
	uint8_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 8);
	ASSERT3U(low, <, 8);

	mask = (1 << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

uint16_t
bitset16(uint16_t reg, uint_t high, uint_t low, uint16_t val)
{
	uint16_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 16);
	ASSERT3U(low, <, 16);

	mask = (1 << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

uint32_t
bitset32(uint32_t reg, uint_t high, uint_t low, uint32_t val)
{
	uint32_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 32);
	ASSERT3U(low, <, 32);

	mask = (1UL << (high - low + 1)) - 1;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

uint64_t
bitset64(uint64_t reg, uint_t high, uint_t low, uint64_t val)
{
	uint64_t mask;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 64);
	ASSERT3U(low, <, 64);

	mask = (1ULL << (high - low + 1)) - 1ULL;
	ASSERT0(~mask & val);

	reg &= ~(mask << low);
	reg |= val << low;

	return (reg);
}

uint64_t
bitdel64(uint64_t val, uint_t high, uint_t low)
{
	uint64_t high_val = 0;
	uint64_t low_val = 0;

	ASSERT3U(high, >=, low);
	ASSERT3U(high, <, 64);
	ASSERT3U(low, <, 64);

	if (low != 0) {
		low_val = bitx64(val, low - 1, 0);
	}

	if (high != 63) {
		high_val = bitx64(val, 63, high + 1);
	}

	return ((high_val << low) | low_val);
}

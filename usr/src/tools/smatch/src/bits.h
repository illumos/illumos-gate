/* SPDX-License-Identifier: MIT */
/*
 * Helper functions for manipulation & testing of integer values
 * like zero or sign-extensions.
 *
 * Copyright (C) 2017 Luc Van Oostenryck
 *
 */

#ifndef BITS_H
#define BITS_H

static inline unsigned long long sign_bit(unsigned size)
{
	return 1ULL << (size - 1);
}

static inline unsigned long long sign_mask(unsigned size)
{
	unsigned long long sbit = sign_bit(size);
	return sbit - 1;
}

static inline unsigned long long bits_mask(unsigned size)
{
	unsigned long long sbit = sign_bit(size);
	return sbit | (sbit - 1);
}


static inline long long zero_extend(long long val, unsigned size)
{
	return val & bits_mask(size);
}

static inline long long sign_extend(long long val, unsigned size)
{
	if (val & sign_bit(size))
		val |= ~sign_mask(size);
	return val;
}

///
// sign extend @val but only if exactly representable
static inline long long sign_extend_safe(long long val, unsigned size)
{
	unsigned long long mask = bits_mask(size);
	if (!(val & ~mask))
		val = sign_extend(val, size);
	return val;
}

static inline long long bits_extend(long long val, unsigned size, int is_signed)
{
	val = zero_extend(val, size);
	if (is_signed)
		val = sign_extend(val, size);
	return val;
}

#endif

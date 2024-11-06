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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This provides a standard implementation for the C23 stdbit.h non-generic
 * functions suitable for both libc and the kernel. These are implemented
 * generally leveraging compiler builtins which should not use the FPU.
 *
 * It's worth remembering that the 'long' type varies in our two environments:
 * ILP32 and LP64. As such, that's why we generally calculate type bit widths by
 * using the sizeof (type) * CHAR_BITS.
 */

#include <sys/stdbit.h>
#ifndef _KERNEL
#include <limits.h>
#else
#include <sys/types.h>
#endif

/*
 * Count Leading Zeros functions. These leverage a builtin which is undefined at
 * zero. The builtin will promote everything to an unsigned int, therefore we
 * need to make sure to subtract resulting values there to make sure we're not
 * counting sign extension bits.
 */
unsigned int
stdc_leading_zeros_uc(unsigned char uc)
{
	if (uc == 0) {
		return (CHAR_BIT * sizeof (unsigned char));
	}

	return (__builtin_clz(uc) -
	    (sizeof (unsigned int) - sizeof (unsigned char)) * CHAR_BIT);
}

unsigned int
stdc_leading_zeros_us(unsigned short us)
{
	if (us == 0) {
		return (CHAR_BIT * sizeof (unsigned short));
	}

	return (__builtin_clz(us) -
	    (sizeof (unsigned int) - sizeof (unsigned short)) * CHAR_BIT);
}

unsigned int
stdc_leading_zeros_ui(unsigned int ui)
{
	if (ui == 0) {
		return (CHAR_BIT * sizeof (unsigned int));
	}

	return (__builtin_clz(ui));
}

unsigned int
stdc_leading_zeros_ul(unsigned long ul)
{
	if (ul == 0) {
		return (CHAR_BIT * sizeof (unsigned long));
	}

	return (__builtin_clzl(ul));
}

unsigned int
stdc_leading_zeros_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (CHAR_BIT * sizeof (unsigned long long));
	}

	return (__builtin_clzll(ull));
}

/*
 * Count Leading Ones functions. We simply invert these functions and then treat
 * it as a leading zeros problem.
 */
unsigned int
stdc_leading_ones_uc(unsigned char uc)
{
	return (stdc_leading_zeros_uc(~uc));
}

unsigned int
stdc_leading_ones_us(unsigned short us)
{
	return (stdc_leading_zeros_us(~us));
}

unsigned int
stdc_leading_ones_ui(unsigned int ui)
{
	return (stdc_leading_zeros_ui(~ui));
}

unsigned int
stdc_leading_ones_ul(unsigned long ul)
{
	return (stdc_leading_zeros_ul(~ul));
}

unsigned int
stdc_leading_ones_ull(unsigned long long ull)
{
	return (stdc_leading_zeros_ull(~ull));
}

/*
 * Count Trailing Zeros functions. These leverage a builtin check which is
 * undefined at zero. While the builtin promotes smaller values to an unsigned
 * int, we don't need to adjust the value like with count leading zeros.
 */
unsigned int
stdc_trailing_zeros_uc(unsigned char uc)
{
	if (uc == 0) {
		return (CHAR_BIT * sizeof (unsigned char));
	}

	return (__builtin_ctz(uc));
}

unsigned int
stdc_trailing_zeros_us(unsigned short us)
{
	if (us == 0) {
		return (CHAR_BIT * sizeof (unsigned short));
	}

	return (__builtin_ctz(us));
}

unsigned int
stdc_trailing_zeros_ui(unsigned int ui)
{
	if (ui == 0) {
		return (CHAR_BIT * sizeof (unsigned int));
	}

	return (__builtin_ctz(ui));
}

unsigned int
stdc_trailing_zeros_ul(unsigned long ul)
{
	if (ul == 0) {
		return (CHAR_BIT * sizeof (unsigned long));
	}

	return (__builtin_ctzl(ul));
}

unsigned int
stdc_trailing_zeros_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (CHAR_BIT * sizeof (unsigned long long));
	}

	return (__builtin_ctzll(ull));
}

/*
 * Count Trailing Ones functions. We treat these as just the inverse of the
 * leading zeros problem.
 */
unsigned int
stdc_trailing_ones_uc(unsigned char uc)
{
	return (stdc_trailing_zeros_uc(~uc));
}

unsigned int
stdc_trailing_ones_us(unsigned short us)
{
	return (stdc_trailing_zeros_us(~us));
}

unsigned int
stdc_trailing_ones_ui(unsigned int ui)
{
	return (stdc_trailing_zeros_ui(~ui));
}

unsigned int
stdc_trailing_ones_ul(unsigned long ul)
{
	return (stdc_trailing_zeros_ul(~ul));
}

unsigned int
stdc_trailing_ones_ull(unsigned long long ull)
{
	return (stdc_trailing_zeros_ull(~ull));
}

/*
 * First Leading Zero functions. We cannot use an inversed find first set here
 * because the builtin operates on signed integers. As this is looking for the
 * least significant zero, a different way to phrase this is how many leading
 * ones exist. That indicates the first zero index is that plus one as long as
 * we're not at the maximum unsigned integer value for the range, which we need
 * to special case as zero.
 */
unsigned int
stdc_first_leading_zero_uc(unsigned char uc)
{
	if (uc == UCHAR_MAX) {
		return (0);
	}

	return (stdc_leading_ones_uc(uc) + 1);
}

unsigned int
stdc_first_leading_zero_us(unsigned short us)
{
	if (us == USHRT_MAX) {
		return (0);
	}

	return (stdc_leading_ones_us(us) + 1);
}

unsigned int
stdc_first_leading_zero_ui(unsigned int ui)
{
	if (ui == UINT_MAX) {
		return (0);
	}

	return (stdc_leading_ones_ui(ui) + 1);
}

unsigned int
stdc_first_leading_zero_ul(unsigned long ul)
{
	if (ul == ULONG_MAX) {
		return (0);
	}

	return (stdc_leading_ones_ul(ul) + 1);
}

unsigned int
stdc_first_leading_zero_ull(unsigned long long ull)
{
	if (ull == ULLONG_MAX) {
		return (0);
	}

	return (stdc_leading_ones_ull(ull) + 1);
}

/*
 * First Leading One functions. This is looking for the most significant one.
 * Like with finding the most significant zero, this can be phrased as counting
 * the number of leading zeroes and then adding one to get the index. Here we
 * need to special case zero rather than the maximum integer.
 */
unsigned int
stdc_first_leading_one_uc(unsigned char uc)
{
	if (uc == 0) {
		return (0);
	}

	return (stdc_leading_zeros_uc(uc) + 1);
}

unsigned int
stdc_first_leading_one_us(unsigned short us)
{
	if (us == 0) {
		return (0);
	}

	return (stdc_leading_zeros_us(us) + 1);
}

unsigned int
stdc_first_leading_one_ui(unsigned int ui)
{
	if (ui == 0) {
		return (0);
	}

	return (stdc_leading_zeros_ui(ui) + 1);
}

unsigned int
stdc_first_leading_one_ul(unsigned long ul)
{
	if (ul == 0) {
		return (0);
	}

	return (stdc_leading_zeros_ul(ul) + 1);
}

unsigned int
stdc_first_leading_one_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (0);
	}

	return (stdc_leading_zeros_ull(ull) + 1);
}

/*
 * First Trailing Zero functions. These look for the least-significant zero. We
 * can do this in the same way we found the most-significant zero: count
 * trailing ones as that value + 1 is where the first trailing zero is. Again,
 * we need to avoid the maximum integer in each class.
 */
unsigned int
stdc_first_trailing_zero_uc(unsigned char uc)
{
	if (uc == UCHAR_MAX) {
		return (0);
	}

	return (stdc_trailing_ones_uc(uc) + 1);
}

unsigned int
stdc_first_trailing_zero_us(unsigned short us)
{
	if (us == USHRT_MAX) {
		return (0);
	}

	return (stdc_trailing_ones_us(us) + 1);
}

unsigned int
stdc_first_trailing_zero_ui(unsigned int ui)
{
	if (ui == UINT_MAX) {
		return (0);
	}

	return (stdc_trailing_ones_ui(ui) + 1);
}

unsigned int
stdc_first_trailing_zero_ul(unsigned long ul)
{
	if (ul == ULONG_MAX) {
		return (0);
	}

	return (stdc_trailing_ones_ul(ul) + 1);
}

unsigned int
stdc_first_trailing_zero_ull(unsigned long long ull)
{
	if (ull == ULLONG_MAX) {
		return (0);
	}

	return (stdc_trailing_ones_ull(ull) + 1);
}

/*
 * First Trailing One functions. We do the same manipulation that we did with
 * trailing zeros. Again, here we need to special case zero values as there are
 * no ones there.
 */
unsigned int
stdc_first_trailing_one_uc(unsigned char uc)
{
	if (uc == 0) {
		return (0);
	}

	return (stdc_trailing_zeros_uc(uc) + 1);
}

unsigned int
stdc_first_trailing_one_us(unsigned short us)
{
	if (us == 0) {
		return (0);
	}

	return (stdc_trailing_zeros_us(us) + 1);
}

unsigned int
stdc_first_trailing_one_ui(unsigned int ui)
{
	if (ui == 0) {
		return (0);
	}

	return (stdc_trailing_zeros_ui(ui) + 1);
}

unsigned int
stdc_first_trailing_one_ul(unsigned long ul)
{
	if (ul == 0) {
		return (0);
	}

	return (stdc_trailing_zeros_ul(ul) + 1);
}

unsigned int
stdc_first_trailing_one_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (0);
	}

	return (stdc_trailing_zeros_ull(ull) + 1);
}

/*
 * Count Zeros and Count Ones functions. These can just defer to the popcnt
 * builtin. The Count Ones is simply the return value there. Count zeros is
 * going to be always our bit size minus the popcnt. We don't have to worry
 * about integer promotion here because promotion will only add 0s, not 1s for
 * unsigned values.
 */
unsigned int
stdc_count_zeros_uc(unsigned char uc)
{
	return (CHAR_BIT * sizeof (unsigned char) - __builtin_popcount(uc));
}

unsigned int
stdc_count_zeros_us(unsigned short us)
{
	return (CHAR_BIT * sizeof (unsigned short) - __builtin_popcount(us));
}

unsigned int
stdc_count_zeros_ui(unsigned int ui)
{
	return (CHAR_BIT * sizeof (unsigned int) - __builtin_popcount(ui));
}

unsigned int
stdc_count_zeros_ul(unsigned long ul)
{
	return (CHAR_BIT * sizeof (unsigned long) - __builtin_popcountl(ul));
}

unsigned int
stdc_count_zeros_ull(unsigned long long ull)
{
	return (CHAR_BIT * sizeof (unsigned long long) -
	    __builtin_popcountll(ull));
}

unsigned int
stdc_count_ones_uc(unsigned char uc)
{
	return (__builtin_popcount(uc));
}

unsigned int
stdc_count_ones_us(unsigned short us)
{
	return (__builtin_popcount(us));
}

unsigned int
stdc_count_ones_ui(unsigned int ui)
{
	return (__builtin_popcount(ui));
}

unsigned int
stdc_count_ones_ul(unsigned long ul)
{
	return (__builtin_popcountl(ul));
}

unsigned int
stdc_count_ones_ull(unsigned long long ull)
{
	return (__builtin_popcountll(ull));
}

/*
 * Single Bit Check functions. These are supposed to return true if they only
 * have a single 1 bit set. We simply implement this by calling the
 * corresponding count ones function and checking its return value. There is
 * probably a more clever algorithm out there.
 */
bool
stdc_has_single_bit_uc(unsigned char uc)
{
	return (stdc_count_ones_uc(uc) == 1);
}

bool
stdc_has_single_bit_us(unsigned short us)
{
	return (stdc_count_ones_us(us) == 1);
}

bool
stdc_has_single_bit_ui(unsigned int ui)
{
	return (stdc_count_ones_ui(ui) == 1);
}

bool
stdc_has_single_bit_ul(unsigned long ul)
{
	return (stdc_count_ones_ul(ul) == 1);
}

bool
stdc_has_single_bit_ull(unsigned long long ull)
{
	return (stdc_count_ones_ull(ull) == 1);
}

/*
 * Bit Width functions. This is asking us to calculate 1 + floor(log2(val)).
 * When we are taking the floor of this, then we can simply calculate this as
 * finding the first leading one. Because the first leading one logic uses the
 * standard's 'most-significant' index logic, we then have to subtract the
 * corresponding size.
 */
unsigned int
stdc_bit_width_uc(unsigned char uc)
{
	if (uc == 0) {
		return (0);
	}

	return (CHAR_BIT * sizeof (unsigned char) + 1 -
	    stdc_first_leading_one_uc(uc));
}

unsigned int
stdc_bit_width_us(unsigned short us)
{
	if (us == 0) {
		return (0);
	}

	return (CHAR_BIT * sizeof (unsigned short) + 1 -
	    stdc_first_leading_one_us(us));
}

unsigned int
stdc_bit_width_ui(unsigned int ui)
{
	if (ui == 0) {
		return (0);
	}

	return (CHAR_BIT * sizeof (unsigned int) + 1 -
	    stdc_first_leading_one_ui(ui));
}

unsigned int
stdc_bit_width_ul(unsigned long ul)
{
	if (ul == 0) {
		return (0);
	}

	return (CHAR_BIT * sizeof (unsigned long) + 1 -
	    stdc_first_leading_one_ul(ul));
}

unsigned int
stdc_bit_width_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (0);
	}

	return (CHAR_BIT * sizeof (unsigned long long) + 1 -
	    stdc_first_leading_one_ull(ull));
}

/*
 * Bit Floor functions. These are trying to find the smallest power of two that
 * is not greater than the value specified. We can use the bit width, subtract
 * one, and then shift. This is defined by the spec such that a value of 0
 * returns 0.
 */
unsigned char
stdc_bit_floor_uc(unsigned char uc)
{
	if (uc == 0) {
		return (0);
	}

	return (1U << (stdc_bit_width_uc(uc) - 1));
}

unsigned short
stdc_bit_floor_us(unsigned short us)
{
	if (us == 0) {
		return (0);
	}

	return (1U << (stdc_bit_width_us(us) - 1));
}

unsigned int
stdc_bit_floor_ui(unsigned int ui)
{
	if (ui == 0) {
		return (0);
	}

	return (1U << (stdc_bit_width_ui(ui) - 1));
}

unsigned long
stdc_bit_floor_ul(unsigned long ul)
{
	if (ul == 0) {
		return (0);
	}

	return (1UL << (stdc_bit_width_ul(ul) - 1));
}

unsigned long long
stdc_bit_floor_ull(unsigned long long ull)
{
	if (ull == 0) {
		return (0);
	}

	return (1ULL << (stdc_bit_width_ull(ull) - 1));
}

/*
 * Bit Ceiling functions. These are meant to return the next power of two that
 * is greater than the value. If the value cannot fit, then it is supposed to
 * return 0. Whenever we have a value greater than the signed maximum, then
 * we're going to end up having to return zero. We don't have explicit checks
 * for the value being representable because we're using shifts which by
 * definition will shift in zero values and then integer rules will cause the
 * value to be truncated.
 *
 * However, there is a slight challenge with this assumption. It is undefined
 * behavior to shift a value by more bits than its bit width. For example, the
 * bit width of the unsigned char 0xf0 is 8. 1 << 8 for an unsigned char is
 * undefined (while integer promotion rules do come into effect you can see this
 * at higher values). As a result, there are two ways to deal with this. We can
 * either make it so we never shift by the maximum value of bits by doing 2 <<
 * (width - 1), or we can use an if statement to explicitly check for these
 * values. For now, we do the former (reducing the branch predictor's burden),
 * which also means that instead of checking just for zero, we need to check for
 * 1 as well so we don't underflow the bit shift quantity!
 *
 * When a value is an exact power of two, then it by definition fits, so we
 * always subtract one from the input value to make sure we end up getting it to
 * fit. This results in us only needing to special case zero.
 */
unsigned char
stdc_bit_ceil_uc(unsigned char uc)
{
	if (uc <= 1) {
		return (1);
	}

	return (2U << (stdc_bit_width_uc(uc - 1) - 1));
}

unsigned short
stdc_bit_ceil_us(unsigned short us)
{
	if (us <= 1) {
		return (1);
	}

	return (2U << (stdc_bit_width_us(us - 1) - 1));
}

unsigned int
stdc_bit_ceil_ui(unsigned int ui)
{
	if (ui <= 1) {
		return (1);
	}

	return (2U << (stdc_bit_width_ui(ui - 1) - 1));
}

unsigned long
stdc_bit_ceil_ul(unsigned long ul)
{
	if (ul <= 1) {
		return (1);
	}

	return (2UL << (stdc_bit_width_ul(ul - 1) - 1));
}

unsigned long long
stdc_bit_ceil_ull(unsigned long long ull)
{
	if (ull <= 1) {
		return (1);
	}

	return (2ULL << (stdc_bit_width_ull(ull - 1) - 1));
}

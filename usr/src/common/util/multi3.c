/*
 * Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 * See https://llvm.org/LICENSE.txt for license information.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <sys/byteorder.h>

#define	CHAR_BIT 8

typedef int		di_int __attribute__((mode(DI)));
typedef unsigned int	du_int __attribute__((mode(DI)));
typedef int		ti_int __attribute__((mode(TI)));

typedef union {
	ti_int all;
	struct {
#if _LITTLE_ENDIAN
		du_int low;
		di_int high;
#else
		di_int high;
		du_int low;
#endif /* _LITTLE_ENDIAN */
	} s;
} twords;

/* Returns: a * b */
static
ti_int
__mulddi3(du_int a, du_int b)
{
	twords r;
	const int bits_in_dword_2 = (int)(sizeof (di_int) * CHAR_BIT) / 2;
	const du_int lower_mask = (du_int)~0 >> bits_in_dword_2;
	r.s.low = (a & lower_mask) * (b & lower_mask);
	du_int t = r.s.low >> bits_in_dword_2;
	r.s.low &= lower_mask;
	t += (a >> bits_in_dword_2) * (b & lower_mask);
	r.s.low += (t & lower_mask) << bits_in_dword_2;
	r.s.high = t >> bits_in_dword_2;
	t = r.s.low >> bits_in_dword_2;
	r.s.low &= lower_mask;
	t += (b >> bits_in_dword_2) * (a & lower_mask);
	r.s.low += (t & lower_mask) << bits_in_dword_2;
	r.s.high += t >> bits_in_dword_2;
	r.s.high += (a >> bits_in_dword_2) * (b >> bits_in_dword_2);
	return (r.all);
}

/* Returns: a * b */
ti_int
__multi3(ti_int a, ti_int b)
{
	twords x;
	x.all = a;
	twords y;
	y.all = b;
	twords r;
	r.all = __mulddi3(x.s.low, y.s.low);
	r.s.high += x.s.high * y.s.low + x.s.low * y.s.high;
	return (r.all);
}

/*
 * University of Illinois/NCSA Open Source License
 *
 * Copyright (c) 2003-2012 University of Illinois at Urbana-Champaign.
 * All rights reserved.
 *
 * Developed by:
 *
 *     LLVM Team
 *
 *     University of Illinois at Urbana-Champaign
 *
 *     http://llvm.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * with the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimers.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimers in the
 *       documentation and/or other materials provided with the distribution.
 *
 *     * Neither the names of the LLVM Team, University of Illinois at
 *       Urbana-Champaign, nor the names of its contributors may be used to
 *       endorse or promote products derived from this Software without specific
 *       prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
 * THE SOFTWARE.
 */

/*
 * C compiler runtime logic for popcount() related builtins taken from LLVM. See
 * also the Hacker's Delight 2nd Edition.
 */

int
__popcountdi2(unsigned long long val)
{
	unsigned long long x2 = (unsigned long long)val;
	x2 = x2 - ((x2 >> 1) & 0x5555555555555555uLL);
	/* Every 2 bits holds the sum of every pair of bits (32) */
	x2 = ((x2 >> 2) & 0x3333333333333333uLL) + (x2 & 0x3333333333333333uLL);
	/*
	 * Every 4 bits holds the sum of every 4-set of bits (3 significant
	 * bits) (16)
	 */
	x2 = (x2 + (x2 >> 4)) & 0x0F0F0F0F0F0F0F0FuLL;
	/*
	 * Every 8 bits holds the sum of every 8-set of bits (4 significant
	 * bits) (8).
	 */
	unsigned x = (unsigned)(x2 + (x2 >> 32));
	/*
	 * The lower 32 bits hold four 16 bit sums (5 significant bits). The
	 * upper 32 bits are garbage.
	 */
	x = x + (x >> 16);
	/*
	 * The lower 16 bits hold two 32 bit sums (6 significant bits). The
	 * upper 16 bits are garbage. Extract the 7 significant bits.
	 */
	return ((x + (x >> 8)) & 0x0000007F);
}

int
__popcountsi2(unsigned val)
{
	unsigned x = (unsigned)val;
	x = x - ((x >> 1) & 0x55555555);
	/* Every 2 bits holds the sum of every pair of bits */
	x = ((x >> 2) & 0x33333333) + (x & 0x33333333);
	/*
	 * Every 4 bits holds the sum of every 4-set of bits (3 significant
	 * bits).
	 */
	x = (x + (x >> 4)) & 0x0F0F0F0F;
	/*
	 * Every 8 bits holds the sum of every 8-set of bits (4 significant
	 * bits).
	 */
	x = (x + (x >> 16));
	/*
	 * The lower 16 bits hold two 8 bit sums (5 significant bits). The
	 * upper 16 bits are garbage. Extract the 6 significant bits.
	 */
	return ((x + (x >> 8)) & 0x0000003F);  /* (6 significant bits) */
}

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.pools;

import java.math.BigInteger;

public class UnsignedInt64 extends BigInteger {
	/**
	 * The minimum value is 0.
	 */
	public final static BigInteger MIN_VALUE = new BigInteger("0");

	/**
	 * The maximum value is 18446744073709551615.
	 */
	public final static BigInteger MAX_VALUE = new BigInteger(
	    "18446744073709551615");

	/**
	 * Constructs a UnsignedInt64 with the same value as the given
	 * string, interpreted in base 10.
	 *
	 * @throws NumberFormatException if the given value is outside
	 * the representable range.
	 */
	public UnsignedInt64(String string) throws NumberFormatException
	{
		super(string);
		validate(this);
	}

	/**
	 * Constructs a UnsignedInt64 with the same value as the given
	 * string, interpreted in the given base.
	 *
	 * @throws NumberFormatException if the given value is outside
	 * the representable range.
	 */
	public UnsignedInt64(String string, int radix)
	    throws NumberFormatException
	{
		super(string, radix);
		validate(this);
	}

	/**
	 * Constructs a UnsignedInt64 with the same value as the given
	 * byte array, interpreted as a two's-complement number in
	 * big-endian byte order (the most significant byte has the
	 * lowest index).
	 *
	 * @throws NumberFormatException if the given value is outside
	 * the representable range.
	 */
	public UnsignedInt64(byte[] bytes) throws NumberFormatException
	{
		super(bytes);
		validate(this);
	}

	/**
	 * Constructs an UnsignedInt64 with the same value as the given
	 * BigInteger.
	 *
	 * @throws NumberFormatException if the given value is outside
	 * the representable range.
	 */
	public UnsignedInt64(BigInteger value) throws NumberFormatException
	{
		super(value.toByteArray());
		validate(this);
	}

	/**
	 * Check that the supplied parameter is a valid value for an
	 * UnsignedInt64.
	 *
	 * @param v A BigInteger to be checked if it's value is legal
	 * as an UnsignedInt64.
	 * @throws NumberFormatException if the given value is outside
	 * the representable range.
	 */
	private void validate(BigInteger v)
	{
		if (v.compareTo(MIN_VALUE) < 0 || v.compareTo(MAX_VALUE) > 0)
			throw(new NumberFormatException());
	}
}

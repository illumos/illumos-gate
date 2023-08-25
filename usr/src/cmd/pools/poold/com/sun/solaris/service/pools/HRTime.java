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
import java.lang.Comparable;

/**
 * hrtime_t-like (see gethrtime(3C)) uptime-based time value (i.e., resilient
 * to changes to the host's clock) for comparison of timestamps of sampled
 * data.
 */
public class HRTime implements Comparable {
	/**
	 * The native <code>hrtime_t</code> value.
	 */
	private UnsignedInt64 value;

	/**
	 * Constructor.
	 */
	public HRTime()
	{
		this.value = timestamp();
	}

	/**
	 * Constructs a new HRTime with the value of the given
	 * UnsignedInt64.
	 *
	 * @param value The timestamp to be used.
	 */
	public HRTime(UnsignedInt64 value)
	{
		this.value = value;
	}

	/**
	 * Computes the difference between this time and another, older,
	 * time.
	 *
	 * @param older the time from which to compute the delta.
	 * @throws IllegalArgumentException if the given time is not
	 * earlier than this one.
	 */
	public HRTime deltaFrom(HRTime older)
	{
		if (older.compareTo(value) > 0)
			throw(new IllegalArgumentException());
		else
			return (new HRTime(new UnsignedInt64(value
			    .subtract(older.getValue()))));
	}

	/**
	 * Returns this HRTime's value.
	 */
	public UnsignedInt64 getValue()
	{
		return (value);
	}

	/**
	 * Return a string representation of this instance.
	 */
	public String toString()
	{
		return (value.toString());
	}

	public int compareTo(Object o) {
		HRTime other = (HRTime) o;

		return (value.compareTo(other.getValue()));
	}

	/**
	 * Return the current timestamp.
	 */
	private native UnsignedInt64 timestamp();
}

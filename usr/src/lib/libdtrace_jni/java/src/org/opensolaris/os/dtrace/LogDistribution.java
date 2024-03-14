/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.util.*;
import java.io.*;
import java.beans.*;

/**
 * A power-of-two logarithmic frequency distribution aggregated by the
 * DTrace {@code quantize()} action.  Aggregated values fall into
 * consecutive ranges, each twice as large as the previous range.  Each
 * range, known as a bucket, begins at two to the power of <i>n</i> and
 * ends at one less than the beginning of the next bucket, two to the
 * power of <i>n + 1</i>.  The zero bucket is the degenerate case and
 * holds the frequency of the base value zero.  For example, the first
 * bucket after 0 starts at 1 (2 to the power of 0) and ends at 1 (one
 * less than 2 to the power of 1).  The next bucket starts at 2 (2 to
 * the power of 1) and ends at 3 (one less than 2 to the power of 2).
 * Each bucket frequency is incremented for each aggregated value that
 * falls into its range.  Buckets are typically identified by their
 * lower bound: 1, 2, 4, 8, etc.  Mirroring these are buckets with
 * negative ranges: -1, -2, -4, -8, etc.  The range of an entire {@code
 * LogDistribution} is (<code>-2<sup>63</sup> ..
 * 2<sup>63</sup></code>).
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see LinearDistribution
 * @see Aggregation
 *
 * @author Tom Erickson
 */
public final class LogDistribution extends Distribution
        implements Serializable, Comparable <LogDistribution>
{
    static final long serialVersionUID = -1279719751212721961L;

    static final int ZERO_BUCKET_INDEX = 63;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(LogDistribution.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"buckets"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /**
     * Called by native C code
     */
    private
    LogDistribution(long[] buckets)
    {
	super(0, 2, buckets); // initializes using base 0, power of 2
    }

    /**
     * Creates a logarithmic distribution with the given frequencies.
     * Supports XML persistence.
     *
     * @param frequencies list of frequencies in bucket ranges bounded
     * by consucutive powers of two
     * @throws NullPointerException if {@code frequencies} is {@code
     * null}
     * @throws IllegalArgumentException if any bucket does not have the
     * expected range (bounded by consecutive powers of two)
     */
    public
    LogDistribution(List <Bucket> frequencies)
    {
	super(frequencies);
	initialize();
    }

    /**
     * Gets a two element array: the first elelemt is the range minimum
     * (inclusive), the second element is the range maximum (inclusive).
     */
    @Override
    long[]
    getBucketRange(int i, int len, long base, long constant)
    {
	long min = LocalConsumer._quantizeBucket(i);
	long max = (LocalConsumer._quantizeBucket(i + 1) - 1);

	long[] range = new long[] {min, max};
	return range;
    }

    @Override
    long[]
    getBucketRange(int i, int len)
    {
	return getBucketRange(i, len, 0, 2);
    }

    public Number
    getValue()
    {
	double total = 0;
	List <Distribution.Bucket> buckets = getBuckets();
	for (Distribution.Bucket bucket : buckets) {
	    total += ((double)bucket.getFrequency() * (double)bucket.getMin());
	}
	return (Double.valueOf(total));
    }

    private long
    getZeroBucketValue()
    {
	Distribution.Bucket b = get(ZERO_BUCKET_INDEX);
	return b.getFrequency();
    }

    /**
     * Compares the {@code double} values of {@link #getValue()} for
     * overall magnitude, and if those are equal, compares the
     * frequencies at the zero bucket (the bucket whose range has a
     * minimum and maximum value of zero).
     */
    public int
    compareTo(LogDistribution d)
    {
	Number v1 = getValue();
	Number v2 = d.getValue();
	double d1 = v1.doubleValue();
	double d2 = v2.doubleValue();
	int cmp = (d1 < d2 ? -1 : (d1 > d2 ? 1 : 0));
	if (cmp == 0) {
	    long z1 = getZeroBucketValue();
	    long z2 = d.getZeroBucketValue();
	    cmp = (z1 < z2 ? -1 : (z1 > z2 ? 1 : 0));
	}
	return (cmp);
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	try {
	    initialize();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }
}

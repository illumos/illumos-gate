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
 * A linear frequency distribution aggregated by the DTrace {@code
 * lquantize()} action.  Aggregated values fall into consecutive ranges
 * bounded by the step parameter of the {@code lquantize()} action.
 * Each range, known as a bucket, begins at the {@code lquantize()}
 * lower bound, or base, plus a multiple of the {@code lquantize()}
 * step, unless it is the first bucket, which is the frequency of all
 * aggregated values less than the base.  The last bucket counts all
 * aggregated values greater than or equal to the {@code lquantize()}
 * upper bound.  For example
 * <pre>		{@code @ = lquantize(n, 0, 100, 10);}</pre>
 * results in a distribution with a base of 0, an upper bound of 100,
 * and a step of 10.  It has twelve buckets starting with {@code n < 0}
 * and ending with {@code n >= 100}.  The buckets in between are {@code
 * 0 .. 9}, {@code 10 .. 19}, etc.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see LogDistribution
 * @see Aggregation
 *
 * @author Tom Erickson
 */
public final class LinearDistribution extends Distribution
        implements Serializable, Comparable <LinearDistribution>
{
    static final long serialVersionUID = 7100080045858770132L;

    /** @serial */
    private long base;
    /** @serial */
    private long step;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(LinearDistribution.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"base", "step", "buckets" });
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
    LinearDistribution(long lowerBound, long frequencyStep,
	    long[] frequencies)
    {
	// initializes using lowerBound and frequencyStep
	super(lowerBound, frequencyStep, frequencies);
	base = lowerBound;
	step = frequencyStep;
    }

    /**
     * Creates a linear distribution with the given base, step, and
     * frequencies.  Supports XML persistence.
     *
     * @param lowerBound also known as the <i>base</i>; the minimum of
     * the second bucket in this distribution (the first bucket contains
     * the frequency of everything lower than the base)
     * @param bucketStep the distance between the lower bound of one
     * bucket and the lower bound of the next consecutive bucket
     * (excluding the first bucket)
     * @param frequencies list of frequencies in each bucket range
     * @throws NullPointerException if {@code frequencies} is {@code
     * null}
     * @throws IllegalArgumentException if the given step is less than
     * one, or if any bucket does not have the expected range
     * (consecutive steps)
     */
    public
    LinearDistribution(long lowerBound, long bucketStep,
	    List <Bucket> frequencies)
    {
	super(frequencies); // makes defensive copy
	base = lowerBound;
	step = bucketStep;
	initialize(); // checks class invariants, calculates total
	if (step < 1) {
	    throw new IllegalArgumentException("step is less than one");
	}
    }

    /**
     * Gets a two element array: the first elelemt is the range minimum
     * (inclusive), the second element is the range maximum (inclusive).
     */
    @Override
    long[]
    getBucketRange(int i, int len, long base, long step)
    {
	long min;
	long max;
	if (i == 0) {
	    // first bucket is everything less than the base
	    min = Long.MIN_VALUE;
	} else {
	    min = (base + ((i - 1) * step));
	}

	if (i == (len - 1)) {
	    // last bucket is everything greater than or equal to
	    // the upper bound
	    max = Long.MAX_VALUE;
	} else {
	    max = ((base + (i * step)) - 1);
	}

	long[] range = new long[] {min, max};
	return range;
    }

    @Override
    long[]
    getBucketRange(int i, int len)
    {
	return getBucketRange(i, len, base, step);
    }

    /**
     * Gets the lower bound of this distribution.  In a linear
     * distribution, the first bucket holds the frequency of all values
     * less than the base, so the base is the minimum of the second
     * bucket's range.
     *
     * @return the lower bound of this distribution
     */
    public long
    getBase()
    {
	return base;
    }

    /**
     * Gets the difference between the lower bounds of consecutive
     * buckets after the first.
     *
     * @return the step between the lower bounds of consecutive buckets
     * after the first
     */
    public long
    getStep()
    {
	return step;
    }

    public Number
    getValue()
    {
	double total = 0;
	List <Distribution.Bucket> buckets = getBuckets();
	int len = buckets.size();
	Distribution.Bucket bucket;

	if (len > 0) {
	    bucket = buckets.get(0);
	    total = (double)bucket.getFrequency() * (double)(getBase() - 1);
	}
	for (int i = 1; i < (len - 1); ++i) {
	    bucket = buckets.get(i);
	    total += (double)bucket.getFrequency() * (double)bucket.getMin();
	}
	if (len > 1) {
	    bucket = buckets.get(len - 1);
	    // There doesn't seem to be any reason to add one to the
	    // minimum of the last bucket range, but that's how it's
	    // implemented in libdtrace dt_aggregate.c.
	    total += (double)bucket.getFrequency() *
		    (double)(bucket.getMin() + 1);
	}
	return (Double.valueOf(total));
    }

    private long
    getZeroBucketValue()
    {
	for (Distribution.Bucket b : this) {
	    if (b.getMin() == 0) {
		return b.getFrequency();
	    }
	}
	return 0;
    }

    /**
     * Compares the {@code double} values of {@link #getValue()} for
     * overall magnitude, and if those are equal, compares the
     * frequencies at zero if the distributions include a bucket whose
     * range has a minimum of zero.
     */
    public int
    compareTo(LinearDistribution d)
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
	if (step < 1) {
	    throw new InvalidObjectException("step is less than one");
	}
    }

    /**
     * Gets a string representation of this linear distribution useful
     * for logging and not intended for display.  The exact details of
     * the representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(LinearDistribution.class.toString());
	buf.append("[base = ");
	buf.append(getBase());
	buf.append(", step = ");
	buf.append(getStep());
	buf.append(", buckets = ");
	List <Bucket> list = getDisplayRange();
	if (list.isEmpty()) {
	    buf.append("<empty>");
	} else {
	    buf.append(Arrays.toString(getDisplayRange().toArray()));
	}
	buf.append(", total = ");
	buf.append(getTotal());
	buf.append(']');
	return buf.toString();
    }
}

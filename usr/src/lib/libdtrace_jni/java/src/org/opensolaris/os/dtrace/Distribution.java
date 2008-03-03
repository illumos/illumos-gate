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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.util.*;
import java.io.*;
import java.beans.*;

/**
 * A frequency distribution aggregated by the DTrace {@code quantize()}
 * or {@code lquantize()} action.  Each aggregated value falls into a
 * range known as a bucket and counts toward the frequency of that
 * bucket.  Bucket ranges are consecutive, with the maximum of one
 * bucket's range always one less than the minimum of the next bucket's
 * range.  By convention each bucket is identified by the minimum of its
 * range.
 *
 * @author Tom Erickson
 */
public abstract class Distribution implements AggregationValue,
       Iterable <Distribution.Bucket>, Serializable
{
    static final long serialVersionUID = 1186243118882654932L;

    /** @serial */
    private List <Bucket> buckets;
    private transient double total;
    private transient boolean initialized;

    /**
     * Package level access, called by subclasses LinearDistribution and
     * LogDistribution, but not available outside the API.
     *
     * @param base  the lower bound of this distribution, or zero if not
     * applicable
     * @param constant  the constant term of the distribution function
     * used to calculate the lower bound of any bucket given the lower
     * bound of the previous bucket, for example the step in a linear
     * distribution or the log base in a logarithmic distribution.
     * @param frequencies  for each bucket, the number of aggregated
     * values falling into that bucket's range; each element must be a
     * positive integer
     * @throws NullPointerException if frequencies is null
     * @throws IllegalArgumentException if any element of frequencies
     * does not have the expected range as defined by checkBucketRange()
     */
    Distribution(long base, long constant, long[] frequencies)
    {
	total = 0;
	long frequency;
	for (int i = 0, len = frequencies.length; i < len; ++i) {
	    frequency = frequencies[i];
	    total += frequency;
	}

	buckets = createBuckets(base, constant, frequencies);
	initialized = true;
    }

    /**
     * Supports XML persistence of subclasses.  Sub-class implementation
     * must call initialize() after setting any state specific to that
     * subclass for determining bucket ranges.
     *
     * @throws NullPointerException if frequencies is null
     * @throws IllegalArgumentException if any element of frequencies
     * does not have the expected range as defined by checkBucketRange()
     */
    Distribution(List <Bucket> frequencies)
    {
	// defensively copy frequencies list
	int len = frequencies.size();
	// don't need gratuitous capacity % added by constructor that
	// takes a Collection argument; list will not be modified
	buckets = new ArrayList <Bucket> (len);
	buckets.addAll(frequencies);
    }

    final void
    initialize()
    {
        // Called by constructor and readObject() (deserialization).
	// 1. Check class invariants, throw exception if deserialized
	//    state inconsistent with a Distribution that can result
	//    from the public constructor.
	// 2. Compute total (transient property derived from buckets)
	total = 0;
	long frequency;
	Bucket bucket;
	int len = buckets.size();
	for (int i = 0; i < len; ++i) {
	    bucket = buckets.get(i);
	    frequency = bucket.getFrequency();
	    // relies on package-private getBucketRange()
	    // implementation
	    checkBucketRange(i, len, bucket);
	    total += frequency;
	}
	initialized = true;
    }

    // Must be called by public instance methods (since the AbstractList
    // methods all depend on get() and size(), it is sufficient to call
    // checkInit() only in those inherited methods).
    private void
    checkInit()
    {
	if (!initialized) {
	    throw new IllegalStateException("Uninitialized");
	}
    }

    /**
     * Gets a two element array: the first elelemt is the range minimum
     * (inclusive), the second element is the range maximum (inclusive).
     * Implemented by subclasses LinearDistribution and LogDistribution
     * to define bucket ranges for this distribution and not available
     * outside the API.  Used by the private general purpose constructor
     * called from native code.  Implementation must not use
     * subclass-specific state, since subclass state has not yet been
     * allocated.
     *
     * @see #Distribution(long base, long constant, long[] frequencies)
     */
    abstract long[]
    getBucketRange(int i, int len, long base, long constant);

    /**
     * Used by public constructors and deserialization only after
     * state specific to the subclass is available to the method.
     */
    abstract long[]
    getBucketRange(int i, int len);

    private List <Distribution.Bucket>
    createBuckets(long base, long constant, long[] frequencies)
    {
	int len = frequencies.length;
	Bucket bucket;
	List <Bucket> buckets = new ArrayList <Bucket> (len);
	long min; // current bucket
	long max; // next bucket minus one
	long[] range; // two element array: { min, max }

	for (int i = 0; i < len; ++i) {
	    range = getBucketRange(i, len, base, constant);
	    min = range[0];
	    max = range[1];
	    bucket = new Distribution.Bucket(min, max, frequencies[i]);
	    buckets.add(bucket);
	}

	return buckets;
    }

    /**
     * Validates that bucket has the expected range for the given bucket
     * index.  Uses {@code base} and {@code constant} constructor args
     * to check invariants specific to each subclass, since state
     * derived from these args in a subclass is not yet available in the
     * superclass constructor.
     *
     * @throws IllegalArgumentException if bucket does not have the
     * expected range for the given bucket index {@code i}
     */
    private void
    checkBucketRange(int i, int bucketCount, Distribution.Bucket bucket,
	    long base, long constant)
    {
	long[] range = getBucketRange(i, bucketCount, base, constant);
	checkBucketRange(i, bucket, range);
    }

    private void
    checkBucketRange(int i, int bucketCount, Distribution.Bucket bucket)
    {
	long[] range = getBucketRange(i, bucketCount);
	checkBucketRange(i, bucket, range);
    }

    private void
    checkBucketRange(int i, Distribution.Bucket bucket, long[] range)
    {
	long min = range[0];
	long max = range[1];

	if (bucket.getMin() != min) {
	    throw new IllegalArgumentException("bucket min " +
		    bucket.getMin() + " at index " + i + ", expected " + min);
	}
	if (bucket.getMax() != max) {
	    throw new IllegalArgumentException("bucket max " +
		    bucket.getMax() + " at index " + i + ", expected " + max);
	}
    }

    /**
     * Gets a modifiable list of this distribution's buckets ordered by
     * bucket range.  Modifying the returned list has no effect on this
     * distribution.  Supports XML persistence.
     *
     * @return a modifiable list of this distribution's buckets ordered
     * by bucket range
     */
    public List <Bucket>
    getBuckets()
    {
	checkInit();
	return new ArrayList <Bucket> (buckets);
    }

    /**
     * Gets a read-only {@code List} view of this distribution.
     *
     * @return a read-only {@code List} view of this distribution
     */
    public List <Bucket>
    asList()
    {
	checkInit();
	return Collections. <Bucket> unmodifiableList(buckets);
    }

    /**
     * Gets the number of buckets in this distribution.
     *
     * @return non-negative bucket count
     */
    public int
    size()
    {
	checkInit();
	return buckets.size();
    }

    /**
     * Gets the bucket at the given distribution index (starting at
     * zero).
     *
     * @return non-null distribution bucket at the given zero-based
     * index
     */
    public Bucket
    get(int index)
    {
	checkInit();
	return buckets.get(index);
    }

    /**
     * Gets an iterator over the buckets of this distribution.
     *
     * @return an iterator over the buckets of this distribution
     */
    public Iterator<Bucket>
    iterator()
    {
	checkInit();
	return buckets.iterator();
    }

    /**
     * Compares the specified object with this {@code Distribution}
     * instance for equality.  Defines equality as having the same
     * buckets with the same values.
     *
     * @return {@code true} if and only if the specified object is of
     * type {@code Distribution} and both instances have the same size
     * and equal buckets at corresponding distribution indexes
     */
    public boolean
    equals(Object o)
    {
	checkInit();
	if (o instanceof Distribution) {
	    Distribution d = (Distribution)o;
	    return buckets.equals(d.buckets);
	}
	return false;
    }

    /**
     * Overridden to ensure that equals instances have equal hash codes.
     */
    public int
    hashCode()
    {
	checkInit();
	return buckets.hashCode();
    }

    /**
     * Gets the total frequency across all buckets.
     *
     * @return sum of the frequency of all buckets in this distribution
     */
    public double
    getTotal()
    {
	checkInit();
	return total;
    }

    /**
     * Gets the numeric value of this distribution used to compare
     * distributions by overall magnitude, defined as the sum total of
     * each bucket's frequency times the minimum of its range.
     */
    public abstract Number getValue();

    /**
     * Called by native code
     */
    private void
    normalizeBuckets(long normal)
    {
	for (Bucket b : buckets) {
	    b.frequency /= normal;
	}
    }

    /**
     * A range inclusive at both endpoints and a count of aggregated
     * values that fall in that range.  Buckets in a {@link
     * Distribution} are consecutive, such that the max of one bucket is
     * always one less than the min of the next bucket (or {@link
     * Long#MAX_VALUE} if it is the last bucket in the {@code
     * Distribution}).
     * <p>
     * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
     */
    public static final class Bucket implements Serializable {
	static final long serialVersionUID = 4863264115375406295L;

	/** @serial */
	private final long min;
	/** @serial */
	private final long max;
	/** @serial */
	private long frequency; // non-final so native code can normalize

	static {
	    try {
		BeanInfo info = Introspector.getBeanInfo(Bucket.class);
		PersistenceDelegate persistenceDelegate =
			new DefaultPersistenceDelegate(
			new String[] {"min", "max", "frequency"})
		{
		    /*
		     * Need to prevent DefaultPersistenceDelegate from using
		     * overridden equals() method, resulting in a
		     * StackOverFlowError.  Revert to PersistenceDelegate
		     * implementation.  See
		     * http://forum.java.sun.com/thread.jspa?threadID=
		     * 477019&tstart=135
		     */
		    protected boolean
		    mutatesTo(Object oldInstance, Object newInstance)
		    {
			return (newInstance != null && oldInstance != null &&
				(oldInstance.getClass() ==
				newInstance.getClass()));
		    }
		};
		BeanDescriptor d = info.getBeanDescriptor();
		d.setValue("persistenceDelegate", persistenceDelegate);
	    } catch (IntrospectionException e) {
		System.out.println(e);
	    }
	}

	/**
	 * Creates a distribution bucket with the given range and
	 * frequency.
	 *
	 * @param rangeMinimumInclusive sets the lower bound (inclusive)
	 * returned by {@link #getMin()}
	 * @param rangeMaximumInclusive sets the upper bound (inclusive)
	 * returned by {@link #getMax()}
	 * @param valuesInRange sets the value frequency in this
	 * bucket's range returned by {@link #getFrequency()}
	 * @throws IllegalArgumentException if {@code
	 * rangeMaximumInclusive} is less than {@code
	 * rangeMinimumInclusive}
	 */
	public
	Bucket(long rangeMinimumInclusive, long rangeMaximumInclusive,
		long valuesInRange)
	{
	    if (rangeMaximumInclusive < rangeMinimumInclusive) {
		throw new IllegalArgumentException("upper bound " +
			rangeMaximumInclusive + " is less than lower bound " +
			rangeMinimumInclusive);
	    }

	    min = rangeMinimumInclusive;
	    max = rangeMaximumInclusive;
	    frequency = valuesInRange;
	}

	/**
	 * Gets the lower bound of this bucket's range (inclusive).
	 */
	public long
	getMin()
	{
	    return min;
	}

	/**
	 * Gets the upper bound of this bucket's range (inclusive).
	 */
	public long
	getMax()
	{
	    return max;
	}

	/**
	 * Gets the number of values in a {@link Distribution} that fall
	 * into the range defined by this bucket.
	 */
	public long
	getFrequency()
	{
	    return frequency;
	}

	/**
	 * Compares the specified object with this distribution bucket
	 * for equality.  Defines equality of two distribution buckets
	 * as having the same range and the same frequency.
	 *
	 * @return false if the specified object is not a {@code
	 * Distribution.Bucket}
	 */
	@Override
	public boolean
	equals(Object o)
	{
	    if (o instanceof Bucket) {
		Bucket b = (Bucket)o;
		return ((min == b.min) &&
			(max == b.max) &&
			(frequency == b.frequency));
	    }
	    return false;
	}

	/**
	 * Overridden to ensure that equal buckets have equal hashcodes.
	 */
	@Override
	public int
	hashCode()
	{
	    int hash = 17;
	    hash = (37 * hash) + ((int)(min ^ (min >>> 32)));
	    hash = (37 * hash) + ((int)(max ^ (max >>> 32)));
	    hash = (37 * hash) + ((int)(frequency ^ (frequency >>> 32)));
	    return hash;
	}

	private void
	readObject(ObjectInputStream s)
		throws IOException, ClassNotFoundException
	{
	    s.defaultReadObject();
	    // check class invariants (as constructor does)
	    if (max < min) {
		throw new InvalidObjectException("upper bound " +
			max + " is less than lower bound " + min);
	    }
	}

	/**
	 * Gets a string representation of this distribution bucket
	 * useful for logging and not intended for display.  The exact
	 * details of the representation are unspecified and subject to
	 * change, but the following format may be regarded as typical:
	 * <pre><code>
	 * class-name[property1 = value1, property2 = value2]
	 * </code></pre>
	 */
	public String
	toString()
	{
	    StringBuilder buf = new StringBuilder();
	    buf.append(Bucket.class.getName());
	    buf.append("[min = ");
	    buf.append(min);
	    buf.append(", max = ");
	    buf.append(max);
	    buf.append(", frequency = ");
	    buf.append(frequency);
	    buf.append(']');
	    return buf.toString();
	}
    }

    /**
     * Gets a list of buckets of interest by excluding empty buckets at
     * both ends of the distribution.  Leaves one empty bucket on each
     * end if possible to convey the distribution context more
     * effectively in a display.
     *
     * @return an unmodifiable sublist that includes the range starting
     * from the first bucket with a non-zero frequency and ending with
     * the last bucket with a non-zero frequency, plus one empty bucket
     * before and after that range if possible
     */
    public List <Bucket>
    getDisplayRange()
    {
	checkInit();
	int min = -1;
	int max = -1;
	int len = size();
	Bucket b;
	// Get first non-empty bucket
	for (int i = 0; i < len; ++i) {
	    b = buckets.get(i);
	    if (b.getFrequency() > 0L) {
		min = i;
		break;
	    }
	}
	if (min < 0) {
	    return Collections. <Bucket> emptyList();
	}
	// Get last non-empty bucket
	for (int i = (len - 1); i >= 0; --i) {
	    b = buckets.get(i);
	    if (b.getFrequency() > 0L) {
		max = i;
		break;
	    }
	}
	// If possible, pad non-empty range with one empty bucket at
	// each end.
	if (min > 0) {
	    --min;
	}
	if (max < (len - 1)) {
	    ++max;
	}

	// subList inclusive at low index, exclusive at high index
	return Collections. <Bucket>
		unmodifiableList(buckets).subList(min, max + 1);
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();

	// Defensively copy buckets _before_ validating.  Subclass
	// validates by calling initialize() after reading any state
	// specific to that subclass needed for validation.
	int len = buckets.size();
	ArrayList <Bucket> copy = new ArrayList <Bucket> (len);
	copy.addAll(buckets);
	buckets = copy;
    }

    /**
     * Gets a string representation of this {@code Distribution} useful
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
	checkInit();
	StringBuilder buf = new StringBuilder();
	buf.append(Distribution.class.getName());
	buf.append("[buckets = ");
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

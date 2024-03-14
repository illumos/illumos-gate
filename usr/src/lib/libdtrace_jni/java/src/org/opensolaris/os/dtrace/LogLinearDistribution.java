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
 * Copyright 2011, Richard Lowe
 */

package org.opensolaris.os.dtrace;

import java.beans.*;
import java.io.*;
import java.util.*;

/**
 * A log/linear distribution aggregated by the DTrace {@code llquantize()}
 * action.  Aggregated values are aggregated logarithmicly by order of
 * magnitude (between the low and high magnitude arguments of the {@code
 * llquantize()} action, but linearly within each order of magnitude bounded
 * by the step parameter of the {@code llquantize()} action.
 *
 * @see LinearDistribution
 * @see LogLinearDistribution
 * @see Aggregation
 */
public final class LogLinearDistribution extends Distribution
    implements Serializable, Comparable <LogLinearDistribution>
{
    static final long serialVersionUID = 6271156690706677711L;

    static final long UINT16_MAX = 0xffff;

    static final long FACTOR_SHIFT = 48;
    static final long LOW_SHIFT = 32;
    static final long HIGH_SHIFT = 16;
    static final long NSTEP_SHIFT = 0;

    private static long unpack(long x, long thing) {
        return (x & (UINT16_MAX << thing)) >> thing;
    }

    /** @serial */
    private long encValue;
    /** @serial */
    private long base;

    static {
        try {
            BeanInfo info = Introspector.getBeanInfo(
                LogLinearDistribution.class);
            PersistenceDelegate persistenceDelegate =
              new DefaultPersistenceDelegate(
                  new String[] { "encValue", "base", "buckets" });
            BeanDescriptor d = info.getBeanDescriptor();
            d.setValue("persistenceDelegate", persistenceDelegate);
        } catch (IntrospectionException e) {
            System.out.println(e);
        }
    }

    /**
     * Called by the native C code
     */
    private LogLinearDistribution(long constant, long[] frequencies) {
        super(0, constant, frequencies);
        encValue = constant;
    }


    /**
     * Creates a log/linear distribution with the given parameters, base value
     * and frequencies.  Used by XML Persistence.
     *
     * @param enc The encoded representation of the high, low, step and steps
     *  {@code llquantize()} paramaters.
     * @param base The base value of the distirbution
     * @param frequencies list of frequencies in each bucket range
     */
    public LogLinearDistribution(long enc, long base,
        List<Bucket> frequencies) {
        super(frequencies);

        encValue = enc;
        base = base;

        initialize();
    }

    /**
     * Creates a log/linear distribution with the given parameters, base
     * values and frequencies.
     *
     * @param scaleFactor factor
     * @param lowMagnitude the low magnitude
     * @param highMagnitude the high magnitude
     * @param bucketSteps number of linear steps per magnitude
     * @param baseVal basue value
     * @param frequencies list of frequencies in each bucket range
     */
    public LogLinearDistribution(long scaleFactor, long lowMagnitude,
        long highMagnitude, long bucketSteps, long baseVal,
        List<Bucket> frequencies) {

        super(frequencies);

        encValue = (scaleFactor << FACTOR_SHIFT) | (lowMagnitude << LOW_SHIFT) |
          (highMagnitude << HIGH_SHIFT) | (bucketSteps << NSTEP_SHIFT);
        base = baseVal;

        initialize();
    }

    private long[][] rangeCache = null;

    private void fillRangeCache(long constant, int len) {
        long value = 1;
        long next, step;
        long low, high, nsteps, factor;
        int order, bucket = 0;

        low = unpack(constant, LOW_SHIFT);
        high = unpack(constant, HIGH_SHIFT);
        nsteps = unpack(constant, NSTEP_SHIFT);
        factor = unpack(constant, FACTOR_SHIFT);

        if (rangeCache == null)
            rangeCache = new long[len][2];

        for (order = 0; order < low; order++)
            value *= factor;

        base = value;

        rangeCache[bucket][0] = Long.MIN_VALUE;
        rangeCache[bucket][1] = value - 1;
        bucket++;

        next = value * factor;
        step = (next > nsteps) ? (next / nsteps) : 1;

        while (order <= high) {
            rangeCache[bucket][0] = value;
            rangeCache[bucket][1] = value + step - 1;
            bucket++;

            if ((value += step) != next)
                continue;

            next = value * factor;
            step = (next > nsteps) ? (next / nsteps) : 1;
            order++;
        }

        rangeCache[bucket][0] = value;
        rangeCache[bucket][1] = Long.MAX_VALUE;
    }

    /**
     * Gets a two element array: the first element is the range minimum
     * (inclusive), the second element is the range maximum (inclusive).
     */
    @Override
    long[] getBucketRange(int i, int len, long base, long constant) {
        if (rangeCache == null)
            fillRangeCache(constant, len);

        return rangeCache[i];
    }

    @Override
    long[] getBucketRange(int i, int len) {
        return getBucketRange(i, len, 0, encValue);
    }

    public Number getValue() {
        double total = 0;

        List<Distribution.Bucket> buckets = getBuckets();
        for (Distribution.Bucket bucket : buckets)
            total += ((double)bucket.getFrequency() * (double)bucket.getMin());

        return (Double.valueOf(total));
    }

    private long getZeroBucketValue() {
        for (Distribution.Bucket b : this) {
            if (b.getMin() == 0) {
                return b.getFrequency();
            }
        }
        return 0;
    }

    /**
     * Compares the {@code double} values of {@link #getValue()} for overall
     * magnitude, and if those are equal, compares frequencies at zero if the
     * distrubions includea bucket whose range has a minimum of zero.
     */
    public int compareTo(LogLinearDistribution d) {
        Number v1 = getValue();
        Number v2 = getValue();
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

    public long getBase() {
        return base;
    }

    public long getEncValue() {
        return encValue;
    }

    private void readObject(ObjectInputStream s)
        throws IOException, ClassNotFoundException {
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

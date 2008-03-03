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

import java.io.*;
import java.beans.*;
import java.math.BigInteger;

/**
 * A {@code long} value aggregated by the DTrace {@code stddev()} action.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Aggregation
 * @author Tom Erickson
 */
public final class StddevValue extends AbstractAggregationValue {
    static final long serialVersionUID = 6409878160513885375L;

    /** @serial */
    private final long total;
    /** @serial */
    private final long count;
    /** @serial */
    private final BigInteger totalSquares;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(StddevValue.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"value", "total", "count", "totalSquares"})
	    {
		@Override
		protected Expression
		instantiate(Object oldInstance, Encoder out)
		{
		    StddevValue stddev = (StddevValue)oldInstance;
		    return new Expression(oldInstance, oldInstance.getClass(),
			    "new", new Object[] {
			    stddev.getValue().longValue(),
			    stddev.getTotal(), stddev.getCount(),
			    stddev.getTotalSquares().toString() });
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    // ported from dt_sqrt_128 in lib/libdtrace/common/dt_consume.c
    private static long
    squareRoot128(BigInteger n)
    {
	long result = 0;
	BigInteger diff = BigInteger.valueOf(0);
	BigInteger nextTry = BigInteger.valueOf(0);
	int bitPairs = (n.bitLength() / 2);
	int bitPos = (bitPairs * 2) + 1;
	int nextTwoBits;

	for (int i = 0; i <= bitPairs; i++) {
	    // Bring down the next pair of bits.
	    nextTwoBits = n.testBit(bitPos)
		    ? (n.testBit(bitPos - 1) ? 0x3 : 0x2)
		    : (n.testBit(bitPos - 1) ? 0x1 : 0x0);

	    diff = diff.shiftLeft(2);
	    diff = diff.add(BigInteger.valueOf(nextTwoBits));

	    // nextTry = R << 2 + 1
	    nextTry = BigInteger.valueOf(result);
	    nextTry = nextTry.shiftLeft(2);
	    nextTry = nextTry.setBit(0);

	    result <<= 1;
	    if (nextTry.compareTo(diff) <= 0) {
		diff = diff.subtract(nextTry);
		result++;
	    }

	    bitPos -= 2;
	}

	return (result);
    }

    // ported from dt_stddev in lib/libdtrace/common/dt_consume.c
    private static long
    standardDeviation(long stddevCount, long stddevTotal,
	    BigInteger stddevTotalSquares)
    {
	BigInteger averageOfSquares = stddevTotalSquares.divide(
		BigInteger.valueOf(stddevCount));
	long avg = (stddevTotal / stddevCount);
	if (avg < 0) {
	    avg = -avg;
	}
	BigInteger squareOfAverage = BigInteger.valueOf(avg);
	squareOfAverage = squareOfAverage.pow(2);
	BigInteger stddev = averageOfSquares.subtract(squareOfAverage);
	return squareRoot128(stddev);
    }

    /*
     * Called by native code.
     */
    private
    StddevValue(long stddevCount, long stddevTotal,
	    BigInteger stddevTotalSquares)
    {
	super(stddevCount == 0 ? 0 : standardDeviation(stddevCount,
		stddevTotal, stddevTotalSquares));
	total = stddevTotal;
	count = stddevCount;
	totalSquares = stddevTotalSquares;
	if (totalSquares == null) {
	    throw new NullPointerException("totalSquares is null");
	}
	if (count < 0) {
	    throw new IllegalArgumentException("count is negative");
	}
    }

    /**
     * Creates a value aggregated by the DTrace {@code stddev()} action.
     * Supports XML persistence.
     *
     * @param v standard deviation
     * @param stddevTotal sum total of all values included in the standard
     * deviation
     * @param stddevCount number of values included in the standard
     * deviation
     * @param stddevTotalSquaresString decimal string representation of
     * the 128-bit sum total of the squares of all values included in
     * the standard deviation
     * @throws IllegalArgumentException if the given count is negative
     * or if the given standard deviation is not the value expected for
     * the given total, total of squares, and count
     * @throws NumberFormatException if the given total squares is not a
     * valid integer representation
     */
    public
    StddevValue(long v, long stddevTotal, long stddevCount,
	    String stddevTotalSquaresString)
    {
	super(v);
	total = stddevTotal;
	count = stddevCount;
	totalSquares = new BigInteger(stddevTotalSquaresString);
	validate();
    }

    private final void
    validate()
    {
	if (count < 0) {
	    throw new IllegalArgumentException("count is negative");
	}
	long stddev = super.getValue().longValue();
	if (count == 0) {
	    if (stddev != 0) {
		throw new IllegalArgumentException(
			"count of values is zero, stddev is non-zero (" +
			stddev + ")");
	    }
	} else {
	    if (stddev != standardDeviation(count, total, totalSquares)) {
		throw new IllegalArgumentException(
			getValue().toString() + " is not the expected " +
			"standard deviation of total " + total + ", count " +
			count + ", and total squares " + totalSquares);
	    }
	}
    }

    // Needed to support XML persistence since XMLDecoder cannot find
    // the public method of the non-public superclass.

    /**
     * Gets the standard deviation of the aggregated values.
     *
     * @return standard deviation of the aggregated values
     */
    public Long
    getValue()
    {
	return (Long)super.getValue();
    }

    /**
     * Gets the sum total of the aggregated values.
     *
     * @return the sum total of the aggregated values
     */
    public long
    getTotal()
    {
	return total;
    }

    /**
     * Gets the number of aggregated values included in the standard
     * deviation.
     *
     * @return the number of aggregated values included in the standard
     * deviation
     */
    public long
    getCount()
    {
	return count;
    }

    /**
     * Gets the sum total of the squares of the aggregated values.
     *
     * @return the sum total of the squares of the aggregated values
     */
    public BigInteger
    getTotalSquares()
    {
	return totalSquares;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// check invariants
	try {
	    validate();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }
}

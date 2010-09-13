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

import java.io.*;
import java.beans.*;

/**
 * A {@code long} value aggregated by the DTrace {@code avg()} action.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Aggregation
 * @author Tom Erickson
 */
public final class AvgValue extends AbstractAggregationValue {
    static final long serialVersionUID = 1633169020110237906L;

    /** @serial */
    private final long total;
    /** @serial */
    private final long count;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(AvgValue.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"value", "total", "count"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /**
     * Creates a value aggregated by the DTrace {@code avg()} action.
     * Supports XML persistence.
     *
     * @param v average
     * @param averagedTotal sum total of all values averaged
     * @param averagedValueCount number of values averaged
     * @throws IllegalArgumentException if the given count is negative
     * or if the given average is not the value expected for the given
     * total and count
     */
    public
    AvgValue(long v, long averagedTotal, long averagedValueCount)
    {
	super(v);
	total = averagedTotal;
	count = averagedValueCount;
	validate();
    }

    private final void
    validate()
    {
	if (count < 0) {
	    throw new IllegalArgumentException("count is negative");
	}
	long average = super.getValue().longValue();
	if (count == 0) {
	    if (average != 0) {
		throw new IllegalArgumentException(
			"count of values is zero, average is non-zero (" +
			average + ")");
	    }
	} else {
	    if (average != (total / count)) {
		throw new IllegalArgumentException(
			getValue().toString() + " is not the expected " +
			"average of total " + total + " and count " +
			count);
	    }
	}
    }

    // Needed to support XML persistence since XMLDecoder cannot find
    // the public method of the non-public superclass.

    /**
     * Gets the average of the aggregated values.
     *
     * @return average of the aggregated values, equal to <code>({@link
     * #getTotal()} / {@link #getCount()})</code> rounded down
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
     * Gets the number of aggregated values included in the average.
     *
     * @return the number of aggregated values included in the average
     */
    public long
    getCount()
    {
	return count;
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

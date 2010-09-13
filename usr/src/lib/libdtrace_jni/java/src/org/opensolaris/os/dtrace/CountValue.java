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
 * A {@code long} value aggregated by the DTrace {@code count()} action.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Aggregation
 * @author Tom Erickson
 */
public final class CountValue extends AbstractAggregationValue {
    static final long serialVersionUID = 5948954123445410783L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(CountValue.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"value"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /**
     * Creates a value aggregated by the DTrace {@code count()} action.
     * Supports XML persistence.
     *
     * @param v aggregated value count
     * @throws IllegalArgumentException if the given count is negative
     */
    public
    CountValue(long v)
    {
	super(v);
	validate();
    }

    private final void
    validate()
    {
	long count = super.getValue().longValue();
	if (count < 0) {
	    throw new IllegalArgumentException("count is negative");
	}
    }

    // Needed to support XML persistence since XMLDecoder cannot find
    // the public method of the non-public superclass.

    /**
     * Gets the number of aggregated values.
     *
     * @return the number of aggregated values
     */
    public Long
    getValue()
    {
	return (Long)super.getValue();
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

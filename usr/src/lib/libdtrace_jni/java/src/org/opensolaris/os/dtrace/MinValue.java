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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.beans.*;

/**
 * A {@code long} value aggregated by the DTrace {@code min()} action.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Aggregation
 * @author Tom Erickson
 */
public final class MinValue extends AbstractAggregationValue {
    static final long serialVersionUID = -3903522347795401289L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(MinValue.class);
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
     * Creates a value aggregated by the DTrace {@code min()} action.
     * Supports XML persistence.
     *
     * @param v minimum of the aggregated values
     */
    public
    MinValue(long v)
    {
	super(v);
    }

    // Needed to support XML persistence since XMLDecoder cannot find
    // the public method of the non-public superclass.

    /**
     * Gets the minimum of the aggregated values.
     *
     * @return the minimum of the aggregated values
     */
    public Long
    getValue()
    {
	return (Long)super.getValue();
    }
}

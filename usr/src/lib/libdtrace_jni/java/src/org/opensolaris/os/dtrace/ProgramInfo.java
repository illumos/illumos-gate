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
 * Information about a {@link Program} including stability and matching
 * probe count.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#getProgramInfo(Program program)
 * @see Consumer#enable(Program program)
 *
 * @author Tom Erickson
 */
public final class ProgramInfo implements Serializable {
    static final long serialVersionUID = 663862981171935056L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(ProgramInfo.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] { "minimumProbeAttributes",
		    "minimumStatementAttributes",
		    "matchingProbeCount" })
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
			    oldInstance.getClass() == newInstance.getClass());
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    e.printStackTrace();
	}
    }

    /** @serial */
    private final InterfaceAttributes minimumProbeAttributes;
    /** @serial */
    private final InterfaceAttributes minimumStatementAttributes;
    /** @serial */
    private final int matchingProbeCount;

    /**
     * Creates a {@code ProgamInfo} instance with the given properties.
     * Supports XML persistence.
     *
     * @param minProbeAttr minimum stability levels of the
     * program probe descriptions
     * @param minStatementAttr minimum stability levels of the
     * program action statements (including D variables)
     * @param matchingProbes non-negative count of probes matching the
     * program probe description
     * @throws NullPointerException if {@code minProbeAttr} or {@code
     * minStatementAttr} is {@code null}
     * @throws IllegalArgumentException if {@code matchingProbes} is
     * negative
     */
    public
    ProgramInfo(InterfaceAttributes minProbeAttr,
	    InterfaceAttributes minStatementAttr,
	    int matchingProbes)
    {
	// Called by native code.  Any change to this constructor requires a
	// similar change in the native invocation.
	minimumProbeAttributes = minProbeAttr;
	minimumStatementAttributes = minStatementAttr;
	matchingProbeCount = matchingProbes;
	validate();
    }

    private final void
    validate()
    {
	if (minimumProbeAttributes == null) {
	    throw new NullPointerException("minimumProbeAttributes is null");
	}
	if (minimumStatementAttributes == null) {
	    throw new NullPointerException(
		    "minimumStatementAttributes is null");
	}
	if (matchingProbeCount < 0) {
	    throw new IllegalArgumentException(
		    "matchingProbeCount is negative");
	}
    }

    /**
     * Gets the minimum stability levels of the probe descriptions used
     * in a compiled {@link Program}.
     *
     * @return non-null interface attributes describing the minimum
     * stability of the probe descriptions in a D program
     */
    public InterfaceAttributes
    getMinimumProbeAttributes()
    {
	return minimumProbeAttributes;
    }

    /**
     * Gets the minimum stability levels of the action statements
     * including D variables used in a compiled {@link Program}.
     *
     * @return non-null interface attributes describing the minimum
     * stability of the action statements (including D variables) in a D
     * program
     */
    public InterfaceAttributes
    getMinimumStatementAttributes()
    {
	return minimumStatementAttributes;
    }

    /**
     * Gets the number of DTrace probes that match the probe
     * descriptions in a compiled {@link Program}.  This count may be
     * very high for programs that use {@link ProbeDescription}
     * wildcarding (field omission) and globbing (pattern matching
     * syntax).
     *
     * @return non-negative count of probes on the system matching the
     * program descriptions in a compiled D program
     */
    public int
    getMatchingProbeCount()
    {
	return matchingProbeCount;
    }

    /**
     * Compares the specified object with this program information for
     * equality.  Defines equality as having the same information,
     * including stability attributes and matching probe counts.
     * Different D programs may have equal program information.
     *
     * @return {@code true} if and only if the specified object is also
     * a {@code ProgramInfo} instance and has all the same information
     * as this instance
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o == this) {
	    return true;
	}
	if (o instanceof ProgramInfo) {
	    ProgramInfo i = (ProgramInfo)o;
	    return (minimumProbeAttributes.equals(
		    i.minimumProbeAttributes) &&
		    minimumStatementAttributes.equals(
		    i.minimumStatementAttributes) &&
		    (matchingProbeCount == i.matchingProbeCount));
	}
	return false;
    }

    /**
     * Overridden to ensure that equal {@code ProgramInfo} instances
     * have equal hashcodes.
     */
    @Override
    public int
    hashCode()
    {
        int hash = 17;
	hash = (37 * hash) + minimumProbeAttributes.hashCode();
	hash = (37 * hash) + minimumStatementAttributes.hashCode();
	hash = (37 * hash) + matchingProbeCount;
	return hash;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Check constructor invariants
	try {
	    validate();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }

    /**
     * Gets a string representation of this {@code ProgramInfo} useful
     * for logging and not intended for display.  The exact details of
     * the representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    @Override
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(ProgramInfo.class.getName());
	buf.append("[minimumProbeAttributes = ");
	buf.append(minimumProbeAttributes);
	buf.append(", minimumStatementAttributes = ");
	buf.append(minimumStatementAttributes);
	buf.append(", matchingProbeCount = ");
	buf.append(matchingProbeCount);
	buf.append(']');
	return buf.toString();
    }
}

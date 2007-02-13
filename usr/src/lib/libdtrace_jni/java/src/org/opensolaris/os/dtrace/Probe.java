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
 * A {@link ProbeDescription} identifying a single probe combined with
 * information about the identified probe.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#listProbes(ProbeDescription filter)
 * @see Consumer#listProgramProbes(Program program)
 *
 * @author Tom Erickson
 */
public final class Probe implements Serializable {
    static final long serialVersionUID = 8917481979541675727L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Probe.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"description", "info"})
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
	    System.out.println(e);
	}
    }

    /** @serial */
    private final ProbeDescription description;
    /** @serial */
    private final ProbeInfo info;

    /**
     * Creates a {@code Probe} instance with the given identifying
     * description and associated probe information.  Supports XML
     * persistence.
     *
     * @param probeDescription probe description that identifies a
     * single DTrace probe
     * @param probeInfo information about the identified probe, {@code
     * null} indicating that the information could not be obtained
     * @throws NullPointerException if the given probe description is
     * {@code null}
     */
    public
    Probe(ProbeDescription probeDescription, ProbeInfo probeInfo)
    {
	description = probeDescription;
	info = probeInfo;
	validate();
    }

    private final void
    validate()
    {
	if (description == null) {
	    throw new NullPointerException("description is null");
	}
    }

    /**
     * Gets the probe description identifying a single probe described
     * by this instance.
     *
     * @return non-null probe description matching a single probe on the
     * system
     */
    public ProbeDescription
    getDescription()
    {
	return description;
    }

    /**
     * Gets information including attributes and argument types of the
     * probe identified by {@link #getDescription()}.
     *
     * @return information about the probe identified by {@link
     * #getDescription()}, or {@code null} if that information could not
     * be obtained for any reason
     */
    public ProbeInfo
    getInfo()
    {
	return info;
    }

    /**
     * Compares the specified object with this {@code Probe} instance
     * for equality.  Defines equality as having the same probe
     * description.
     *
     * @return {@code true} if and only if the specified object is also
     * a {@code Probe} and both instances return equal values from
     * {@link #getDescription()}.
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof Probe) {
	    Probe p = (Probe)o;
	    return description.equals(p.description);
	}
	return false;
    }

    /**
     * Overridden to ensure that equal instances have equal hash codes.
     */
    @Override
    public int
    hashCode()
    {
	return description.hashCode();
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Check class invariants
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
     * Returns a string representation of this {@code Probe} useful for
     * logging and not intended for display.  The exact details of the
     * representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Probe.class.getName());
	buf.append("[description = ");
	buf.append(description);
	buf.append(", info = ");
	buf.append(info);
	buf.append(']');
	return buf.toString();
    }
}

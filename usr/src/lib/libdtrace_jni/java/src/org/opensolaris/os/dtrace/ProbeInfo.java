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
 * Probe stability information.  Does not identify a probe, but gives
 * information about a single probe identified by a {@link
 * ProbeDescription}.  A {@code ProbeDescription} can match multiple
 * probes using pattern syntax (globbing) and wildcarding (field
 * omission), but it does not normally make sense to associate a {@code
 * ProbeInfo} with a {@code ProbeDescription} unless that description
 * matches exactly one probe on the system.  A {@link Probe} pairs a
 * {@code ProbeDescription} with information about the DTrace probe it
 * identifies.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#listProbeDetail(ProbeDescription filter)
 * @see Consumer#listProgramProbeDetail(Program program)
 *
 * @author Tom Erickson
 */
public final class ProbeInfo implements Serializable {
    static final long serialVersionUID = 1057402669978245904L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(ProbeInfo.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"probeAttributes",
		    "argumentAttributes"})
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
    private final InterfaceAttributes probeAttributes;
    /** @serial */
    private final InterfaceAttributes argumentAttributes;

    /**
     * Creates a {@code ProbeInfo} instance from the given attributes.
     * Supports XML persistence.
     *
     * @throws NullPointerException if any parameter is null
     */
    public
    ProbeInfo(InterfaceAttributes singleProbeAttributes,
	    InterfaceAttributes argAttributes)
    {
	probeAttributes = singleProbeAttributes;
	argumentAttributes = argAttributes;
	validate();
    }

    private final void
    validate()
    {
	if (probeAttributes == null) {
	    throw new NullPointerException("probeAttributes is null");
	}
	if (argumentAttributes == null) {
	    throw new NullPointerException("argumentAttributes is null");
	}
    }

    /**
     * Gets the interface attributes of a probe.
     *
     * @return non-null attributes including stability levels and
     * dependency class
     */
    public InterfaceAttributes
    getProbeAttributes()
    {
	return probeAttributes;
    }

    /**
     * Gets the interface attributes of the arguments to a probe.
     *
     * @return non-null attributes including stability levels and
     * dependency class of the arguments to a probe
     */
    public InterfaceAttributes
    getArgumentAttributes()
    {
	return argumentAttributes;
    }

    /**
     * Compares the specified object with this {@code ProbeInfo}
     * instance for equality.  Defines equality as having equal probe
     * attributes and equal argument attributes.
     *
     * @return {@code true} if and only if the specified object is also
     * a {@code ProbeInfo} and both instances have the same attributes
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof ProbeInfo) {
	    ProbeInfo i = (ProbeInfo)o;
	    return (probeAttributes.equals(i.probeAttributes) &&
		    argumentAttributes.equals(i.argumentAttributes));
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
	int hash = 17;
	hash = (37 * hash) + probeAttributes.hashCode();
	hash = (37 * hash) + argumentAttributes.hashCode();
	return hash;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Must copy before checking class invariants
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
     * Gets a string representation of this {@code ProbeInfo} useful for
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
	buf.append(ProbeInfo.class.getName());
	buf.append("[probeAttributes = ");
	buf.append(probeAttributes);
	buf.append(", argumentAttributes = ");
	buf.append(argumentAttributes);
	buf.append(']');
	return buf.toString();
    }
}

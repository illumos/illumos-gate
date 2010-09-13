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
 * An error encountered in the native DTrace library while tracing probe
 * data.  Each of the fault name constants beginning with {@code
 * DTRACEFLT_} identifies a specific fault with a name that is
 * guaranteed not to change across API versions.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see ConsumerListener#errorEncountered(ErrorEvent e)
 *
 * @author Tom Erickson
 */
public final class Error implements Serializable {
    static final long serialVersionUID = 5069931629562700614L;

    /**
     * Invalid address.
     */
    public static final String DTRACEFLT_BADADDR = "DTRACEFLT_BADADDR";
    /**
     * Invalid alignment.
     */
    public static final String DTRACEFLT_BADALIGN = "DTRACEFLT_BADALIGN";
    /**
     * Illegal operation.
     */
    public static final String DTRACEFLT_ILLOP = "DTRACEFLT_ILLOP";
    /**
     * Divide-by-zero.
     */
    public static final String DTRACEFLT_DIVZERO = "DTRACEFLT_DIVZERO";
    /**
     * Out of scratch space.
     */
    public static final String DTRACEFLT_NOSCRATCH = "DTRACEFLT_NOSCRATCH";
    /**
     * Invalid kernel access.
     */
    public static final String DTRACEFLT_KPRIV = "DTRACEFLT_KPRIV";
    /**
     * Invalid user access.
     */
    public static final String DTRACEFLT_UPRIV = "DTRACEFLT_UPRIV";
    /**
     * Tuple stack overflow.
     */
    public static final String DTRACEFLT_TUPOFLOW = "DTRACEFLT_TUPOFLOW";
    /**
     * Library-level fault.
     */
    public static final String DTRACEFLT_LIBRARY = "DTRACEFLT_LIBRARY";

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Error.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"probeDescription",
		    "enabledProbeID", "CPU", "action", "offset",
		    "fault", "address", "defaultMessage"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    e.printStackTrace();
	}
    }

    /** @serial */
    private final ProbeDescription probeDescription;
    /** @serial */
    private final int epid;
    /** @serial */
    private final int cpu;
    /** @serial */
    private final int action;
    /** @serial */
    private final int offset;
    /** @serial */
    private final String fault;
    /** @serial */
    private final long address;
    /** @serial */
    private final String defaultMessage;

    /**
     * Creates a DTrace error with the given properties.  Supports XML
     * persistence.
     *
     * @param pdesc probe description that identifies the error-inducing
     * probe among all the probes on the system
     * @param enabledProbeID identifies the error-inducing probe among
     * all probes enabled by the same {@link Consumer}
     * @param errorCPU non-negative ID of the CPU where the error was
     * encountered, or a negative number if the CPU is unknown
     * @param errorAction integer that identifies the error-inducing
     * action as the nth action (starting at one) in the error-inducing
     * probe, or zero if the error is in the predicate rather than in an
     * action
     * @param errorOffset error offset in compiled DTrace Intermediate
     * Format (DIF), or a negative number if the offset is not available
     * @param faultName name of the specific fault, or {@code null}
     * if the fault is unknown to the Java DTrace API
     * @param faultAddress address of fault, or -1 if address is not
     * applicable to the specific fault
     * @param errorMessage default message from the native DTrace
     * library preconstructed from the properties of this error
     * @throws NullPointerException if the given probe description or
     * default message is {@code null}
     */
    public
    Error(ProbeDescription pdesc, int enabledProbeID, int errorCPU,
	    int errorAction, int errorOffset, String faultName,
	    long faultAddress, String errorMessage)
    {
	probeDescription = pdesc;
	epid = enabledProbeID;
	cpu = errorCPU;
	action = errorAction;
	offset = errorOffset;
	fault = faultName;
	address = faultAddress;
	defaultMessage = errorMessage;
	validate();
    }

    private final void
    validate()
    {
	if (probeDescription == null) {
	    throw new NullPointerException(
		    "enabled probe description is null");
	}
	if (defaultMessage == null) {
	    throw new NullPointerException("default message is null");
	}
    }

    /**
     * Gets the probe description that identifies the error-inducing
     * probe among all the probes on the system.
     *
     * @return non-null probe description
     */
    public ProbeDescription
    getProbeDescription()
    {
	return probeDescription;
    }

    /**
     * Gets the enabled probe ID.  The "epid" is different from {@link
     * ProbeDescription#getID()} because it identifies a probe among all
     * the probes enabled by a {@link Consumer}, rather than among all
     * the probes on the system.
     *
     * @return the enabled probe ID
     */
    public int
    getEnabledProbeID()
    {
	return epid;
    }

    /**
     * Gets the CPU that encountered the error.
     *
     * @return non-negative CPU ID, or a negative number if the CPU is
     * unknown
     */
    public int
    getCPU()
    {
	return cpu;
    }

    /**
     * Gets the error-inducing action as the <i>nth</i> action (starting
     * at one) in the error-inducing probe, or zero if the error is in
     * the predicate rather than in an action.  Note that some actions
     * in a D program consist of multiple actions internally within the
     * DTrace library.
     *
     * @return zero if the error is in the probe predicate, otherwise
     * the <i>nth</i> action (<i>n</i> starting at one) from the start
     * of the probe that induced the error
     */
    public int
    getAction()
    {
	return action;
    }

    /**
     * Gets the error offset in compiled DTrace Intermediate Format
     * (DIF), or a negative number if the offset is not available.
     *
     * @return the error offset in compiled DTrace Intermediate Format
     * (DIF), or a negative number if the offset is not available
     */
    public int
    getOffset()
    {
	return offset;
    }

    /**
     * Gets the name identifying the specific fault.  The names are
     * guaranteed not to change across API versions as long as the fault
     * cases they identify still exist.
     *
     * @return name of the specific fault or {@code null} if the
     * fault is unknown to the Java DTrace API
     */
    public String
    getFault()
    {
	return fault;
    }

    /**
     * Gets the address of the fault, if any.
     *
     * @return address of fault, or -1 if address is not applicable to
     * the specific fault (the fault is not one of {@link
     * #DTRACEFLT_BADADDR} or {@link #DTRACEFLT_BADALIGN})
     */
    public long
    getAddress()
    {
	return address;
    }

    /**
     * Gets the default message from the native DTrace library
     * preconstructed from the properties of this error.
     *
     * @return non-null preconstructed message
     */
    public String
    getDefaultMessage()
    {
	return defaultMessage;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// check class invariants
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
     * Gets a string representation of this error useful for logging and
     * not intended for display.  The exact details of the
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
	buf.append(Error.class.getName());
	buf.append("[probeDescription = ");
	buf.append(probeDescription);
	buf.append(", epid = ");
	buf.append(epid);
	buf.append(", cpu = ");
	buf.append(cpu);
	buf.append(", action = ");
	buf.append(action);
	buf.append(", offset = ");
	buf.append(offset);
	buf.append(", fault = ");
	buf.append(fault);
	buf.append(", address = ");
	buf.append(address);
	buf.append(", defaultMessage = ");
	buf.append(defaultMessage);
	buf.append(']');
	return buf.toString();
    }
}

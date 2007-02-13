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

import java.io.Serializable;
import java.io.*;
import java.beans.*;

/**
 * Detail about one or more records dropped by DTrace (not reported to
 * {@link ConsumerListener#dataReceived(DataEvent e)
 * ConsumerListener.dataReceived()}) due to inadequte buffer space.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see ConsumerListener#dataDropped(DropEvent e)
 *
 * @author Tom Erickson
 */
public final class Drop implements Serializable {
    static final long serialVersionUID = 26653827678657381L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Drop.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"CPU", "kind", "count", "total",
		    "defaultMessage"})
	    {
		protected Expression
		instantiate(Object oldInstance, Encoder out)
		{
		    Drop drop = (Drop)oldInstance;
		    return new Expression(oldInstance, oldInstance.getClass(),
			    "new", new Object[] { drop.getCPU(),
			    drop.getKind().name(), drop.getCount(),
			    drop.getTotal(), drop.getDefaultMessage() });
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    e.printStackTrace();
	}
    }

    /**
     * Indicates what kind of buffer space experienced the data drop
     * (such as principal buffer or aggregation buffer) and possibly a
     * reason.
     */
    public enum Kind {
	/** Drop to principal buffer */
	PRINCIPAL("Principal buffer"),
	/** Drop to aggregation buffer */
	AGGREGATION("Aggregation"),
	/** Dynamic drop */
	DYNAMIC("Dynamic"),
	/** Dynamic drop due to rinsing */
	DYNRINSE("Dynamic (rinse)"),
	/** Dynamic drop due to dirtiness */
	DYNDIRTY("Dynamic (dirty)"),
	/** Speculative drop */
	SPEC("Speculation"),
	/** Speculative drop due to business */
	SPECBUSY("Speculation (busy)"),
	/** Speculative drop due to unavailability */
	SPECUNAVAIL("Speculation (unavailable)"),
	/** Stack string table overflow */
	STKSTROVERFLOW("Stack string table overflow"),
	/** Error in ERROR probe */
	DBLERROR("error in ERROR probe"),
	/** Unrecognized value from native DTrace library */
	UNKNOWN("Unknown");

	private String s;

	private
	Kind(String displayString)
	{
	    s = displayString;
	}

	/**
	 * Overridden to get the default display value.  To
	 * internationalize the display value, use {@link Enum#name()}
	 * instead as an I18N lookup key.
	 */
	public String
	toString()
	{
	    return s;
	}
    }

    /** @serial */
    private final int cpu;
    /** @serial */
    private final Kind kind;
    /** @serial */
    private final long count;
    /** @serial */
    private final long total;
    /** @serial */
    private final String defaultMessage;

    /**
     * Creates a {@code Drop} instance with the given CPU, drop kind,
     * drop counts, and default message.  Supports XML persistence.
     *
     * @param dropCPU cpu where drops occurred
     * @param dropKindName name of enumeration value indicating the kind
     * of buffer space where the drop occurred and possibly a reason
     * @param dropCount number of drops
     * @param totalDrops total number of drops since the source {@link
     * Consumer} started running
     * @param defaultDropMessage drop message provided by DTrace
     * @throws IllegalArgumentException if there is no {@code Drop.Kind}
     * value with the given name or if {@code dropCount} or {@code
     * totalDrops} is negative
     * @throws NullPointerException if the given {@code Drop.Kind} name
     * or default message is {@code null}
     */
    public
    Drop(int dropCPU, String dropKindName, long dropCount, long totalDrops,
	    String defaultDropMessage)
    {
	cpu = dropCPU;
	kind = Enum.valueOf(Kind.class, dropKindName);
	count = dropCount;
	total = totalDrops;
	defaultMessage = defaultDropMessage;
	validate();
    }

    private final void
    validate()
    {
	if (count < 0) {
	    throw new IllegalArgumentException("count is negative");
	}
	if (total < 0) {
	    throw new IllegalArgumentException("total is negative");
	}
	if (defaultMessage == null) {
	    throw new NullPointerException("default message is null");
	}
    }

    /**
     * Gets the CPU where the drops occurred.
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
     * Gets the kind of drop for all drops included in {@link
     * #getCount()}.
     *
     * @return non-null drop kind
     */
    public Kind
    getKind()
    {
	return kind;
    }

    /**
     * Gets the number of drops reported by this {@code Drop} instance.
     *
     * @return non-negative drop count
     */
    public long
    getCount()
    {
	return count;
    }

    /**
     * Gets the total number of drops since the source {@link Consumer}
     * started running.
     *
     * @return non-negative drop total since tracing started
     */
    public long
    getTotal()
    {
	return total;
    }

    /**
     * Gets the message provided by DTrace.
     *
     * @return non-null message provided by DTrace
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
     * Gets a string representation of this drop instance, not intended
     * for display.  The exact details of the representation are
     * unspecified and subject to change, but the following format may
     * be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Drop.class.getName());
	buf.append("[cpu = ");
	buf.append(cpu);
	buf.append(", kind = ");
	buf.append(kind);
	buf.append(", count = ");
	buf.append(count);
	buf.append(", total = ");
	buf.append(total);
	buf.append(", defaultMessage = ");
	buf.append(defaultMessage);
	buf.append(']');
	return buf.toString();
    }
}

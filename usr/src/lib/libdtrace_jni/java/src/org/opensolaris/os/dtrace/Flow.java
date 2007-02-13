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
 * Description of control flow across function boundaries including
 * direction (entry or return) and depth in the call stack.  This
 * information is added to {@link ProbeData} instances only when the
 * {@link Option#flowindent flowindent} option is used:
 * <pre><code>
 *     Consumer consumer = new LocalConsumer();
 *     consumer.open();
 *     consumer.setOption(Option.flowindent);
 *     ...
 * </code></pre>
 * See the <a
 * href="http://docs.sun.com/app/docs/doc/817-6223/6mlkidlk1?a=view">
 * <b>Examples</b></a> section of the <b>{@code fbt}
 * Provider</b> chapter of the <i>Solaris Dynamic Tracing Guide</i>.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#setOption(String option)
 * @see Option#flowindent
 *
 * @author Tom Erickson
 */
public final class Flow implements Serializable {
    static final long serialVersionUID = -9178272444872063901L;

    /**
     * Indicates direction of flow across a boundary, such as entering
     * or returing from a function.
     */
    public enum Kind {
	/** Entry into a function. */
	ENTRY,
	/** Return from a function. */
	RETURN,
	/** No function boundary crossed. */
	NONE
    }

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Flow.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"kind", "depth"})
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

		protected Expression
		instantiate(Object oldInstance, Encoder out)
		{
		    Flow flow = (Flow)oldInstance;
		    return new Expression(oldInstance, oldInstance.getClass(),
			    "new", new Object[] { flow.getKind().name(),
			    flow.getDepth() });
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    e.printStackTrace();
	}
    }

    /** @serial */
    private final Kind kind;
    /** @serial */
    private final int depth;

    /**
     * Creates a {@code Flow} instance with the given flow kind and
     * depth.  Supports XML persistence.
     *
     * @param flowKindName name of enumeration value indicating the
     * direction of flow
     * @param flowDepth current depth in the call stack
     * @throws IllegalArgumentException if there is no {@code Flow.Kind}
     * value with the given name or if the given {@code flowDepth} is
     * negative
     * @throws NullPointerException if the given {@code Flow.Kind} name
     * is {@code null}
     */
    public
    Flow(String flowKindName, int flowDepth)
    {
	kind = Enum.valueOf(Kind.class, flowKindName);
	depth = flowDepth;
	if (depth < 0) {
	    throw new IllegalArgumentException("depth is negative");
	}
    }

    /**
     * Gets the direction of the flow of control (entry or return)
     * across a function boundary.
     *
     * @return non-null flow kind indicating direction of flow (entry or
     * return) across a function boundary
     */
    public Kind
    getKind()
    {
	return kind;
    }

    /**
     * Gets the current depth in the call stack.
     *
     * @return A non-negative sum of the function entries minus the
     * function returns up until the moment described by this control
     * flow instance.  For example, if the traced flow of control
     * entered two functions but only returned from one, the depth is
     * one (2 entries minus 1 return).
     */
    public int
    getDepth()
    {
	return depth;
    }

    /**
     * Compares the specified object with this {@code Flow} instance for
     * equality.  Defines equality as having the same flow kind and
     * depth.
     *
     * @return {@code true} if and only if the specified object is of
     * type {@code Flow} and both instances have equal flow kind and
     * depth.
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof Flow) {
	    Flow f = (Flow)o;
	    return ((kind == f.kind) && (depth == f.depth));
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
	hash = (37 * hash) + kind.hashCode();
	hash = (37 * hash) + depth;
	return hash;
    }

    private void
    readObject(ObjectInputStream s)
	    throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// check class invariants
	if (kind == null) {
	    throw new InvalidObjectException("kind is null");
	}
	if (depth < 0) {
	    throw new InvalidObjectException("depth is negative");
	}
    }

    /**
     * Gets a string representation of this {@code Flow} instance useful
     * for logging and not intended for display.  The exact details of
     * the representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Flow.class.getName());
	buf.append("[kind = ");
	buf.append(kind);
	buf.append(", depth = ");
	buf.append(depth);
	buf.append(']');
	return buf.toString();
    }
}

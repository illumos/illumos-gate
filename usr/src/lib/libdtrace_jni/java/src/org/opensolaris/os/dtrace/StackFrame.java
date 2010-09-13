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
 * A single stack frame in a {@link StackValueRecord}.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @author Tom Erickson
 */
public final class StackFrame implements Serializable {
    static final long serialVersionUID = 8617210929132692711L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(StackFrame.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"frame"})
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
    private final String frame;

    /**
     * Creates a single stack frame.  Supports XML persistence.
     *
     * @param f human-readable string representation of this stack frame
     * @throws NullPointerException if the given string representation
     * is {@code null}
     */
    public
    StackFrame(String f)
    {
	frame = f;
	validate();
    }

    private final void
    validate()
    {
	if (frame == null) {
	    throw new NullPointerException("frame is null");
	}
    }

    /**
     * Gets the human-readable string representation of this stack
     * frame.  Supports XML persistence.
     *
     * @return the human-readable string representation of this stack frame.
     */
    public String
    getFrame()
    {
	return frame;
    }

    /**
     * Compares the specified object with this {@code StackFrame} for
     * equality.  Returns {@code true} if and only if the specified
     * object is also a {@code StackFrame} and both instances have the
     * same human-readable string representation.
     *
     * @return {@code true} if and only if the specified object is also
     * a {@code StackFrame} and both instances have the same
     * human-readable string representation
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof StackFrame) {
	    StackFrame s = (StackFrame)o;
	    return frame.equals(s.frame);
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
	return frame.hashCode();
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
     * Gets the string representation of this stack frame, in this case
     * the same value returned by {@link #getFrame()}.
     */
    public String
    toString()
    {
	return frame;
    }
}

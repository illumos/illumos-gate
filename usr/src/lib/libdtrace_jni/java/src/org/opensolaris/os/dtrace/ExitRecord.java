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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.io.Serializable;
import java.beans.*;

/**
 * A record indicating that the DTrace {@code exit()} action is about to
 * stop the source {@link Consumer}.  The exit status is whatever value
 * was passed to the {@code exit()} action in the D program.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @author Tom Erickson
 */
public final class ExitRecord implements Record, Serializable {
    static final long serialVersionUID = -2062716683135961493L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(ExitRecord.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"status"})
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
    private final int status;

    /**
     * Creates an exit record with the given status.
     *
     * @param exitStatus value passed to the D {@code exit()} action
     */
    public
    ExitRecord(int exitStatus)
    {
	status = exitStatus;
    }

    /**
     * Gets the exit status of a DTrace {@link Consumer}.
     *
     * @return the value passed to the D {@code exit()} action
     */
    public int
    getStatus()
    {
	return status;
    }

    /**
     * Compares the specified object with this {@code ExitRecord} for
     * equality. Returns {@code true} if and only if the specified
     * object is also an {@code ExitRecord} and both records have the
     * same status.
     *
     * @return {@code true} if and only if the specified object is also
     * an {@code ExitRecord} and both records have the same status
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof ExitRecord) {
	    ExitRecord r = (ExitRecord)o;
	    return (status == r.status);
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
	return status;
    }

    /**
     * Gets a string representation of the exit status.
     *
     * @return the string form of {@link #getStatus()} returned by
     * {@link Integer#toString(int i)}
     */
    public String
    toString()
    {
	return Integer.toString(status);
    }
}

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
import java.util.EventObject;

/**
 * Notification that DTrace has encountered an error.
 *
 * @see ConsumerListener#errorEncountered(ErrorEvent e)
 *
 * @author Tom Erickson
 */
public class ErrorEvent extends EventObject {
    static final long serialVersionUID = 2236600660422267215L;

    /** @serial */
    private Error error;

    /**
     * Creates an {@link ConsumerListener#errorEncountered(ErrorEvent e)
     * errorEncountered()} event that reports an error encountered in
     * the native DTrace library during tracing.
     *
     * @param source the {@link Consumer} that is the source of this event
     * @param dtraceError the error encountered by DTrace
     * @throws NullPointerException if the given error is {@code null}
     */
    public
    ErrorEvent(Object source, Error dtraceError)
    {
	super(source);
	error = dtraceError;
	validate();
    }

    private final void
    validate()
    {
	if (error == null) {
	    throw new NullPointerException("error is null");
	}
    }

    /**
     * Gets the error reported by DTrace.
     *
     * @return non-null error reported by DTrace
     */
    public Error
    getError()
    {
	return error;
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

    /**
     * Gets a string representation of this event useful for logging and
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
	buf.append(ErrorEvent.class.getName());
	buf.append("[source = ");
	buf.append(getSource());
	buf.append(", error = ");
	buf.append(error);
	buf.append(']');
	return buf.toString();
    }
}

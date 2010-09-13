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

import java.util.EventObject;

/**
 * An event indicating a state change in a DTrace {@link Consumer}.
 *
 * @see ConsumerListener
 *
 * @author Tom Erickson
 */
public class ConsumerEvent extends EventObject {
    static final long serialVersionUID = 1659441401142401810L;

    /** @serial */
    private long timestamp;

    /**
     * Creates a consumer event with the given source {@link Consumer}
     * and nanosecond timestamp.
     *
     * @param source  the {@link Consumer} that is the source of the
     * event
     * @param timeNanos  nanosecond timestamp of this event
     */
    public
    ConsumerEvent(Object source, long timeNanos)
    {
	super(source);
	timestamp = timeNanos;
    }

    /**
     * Gets the nanosecond timestamp of this event.
     *
     * @return nanosecond timestamp of the event on the system where the
     * consumer opened a native DTrace library handle
     */
    public long
    getTimestamp()
    {
	return timestamp;
    }
}

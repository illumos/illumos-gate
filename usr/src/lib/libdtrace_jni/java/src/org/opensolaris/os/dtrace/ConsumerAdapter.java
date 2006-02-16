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

/**
 * An abstract adapter class for getting events from a {@link Consumer}.
 * The methods in this class are empty except for a few that implement
 * the default behavior of terminating a consumer by throwing an
 * exception.  This class exists as a convenience for implementing
 * consumer listeners.
 *
 * @see Consumer#addConsumerListener(ConsumerListener l)
 *
 * @author Tom Erickson
 */
public abstract class ConsumerAdapter implements ConsumerListener {
    /** Empty method */
    public void dataReceived(DataEvent e) throws ConsumerException {}

    /**
     * Terminates a running {@link Consumer} by throwing an exception.
     *
     * @throws ConsumerException
     */
    public void
    dataDropped(DropEvent e) throws ConsumerException
    {
	Drop drop = e.getDrop();
	throw new ConsumerException(drop.getDefaultMessage(), drop);
    }

    /**
     * Terminates a running {@link Consumer} by throwing an exception.
     *
     * @throws ConsumerException
     */
    public void
    errorEncountered(ErrorEvent e) throws ConsumerException
    {
	Error error = e.getError();
	throw new ConsumerException(error.getDefaultMessage(), error);
    }

    /** Empty method */
    public void processStateChanged(ProcessEvent e) throws ConsumerException {}
    /** Empty method */
    public void consumerStarted(ConsumerEvent e) {}
    /** Empty method */
    public void consumerStopped(ConsumerEvent e) {}
    /** Empty method */
    public void intervalBegan(ConsumerEvent e) {}
    /** Empty method */
    public void intervalEnded(ConsumerEvent e) {}
}

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
 * Exception thrown by a {@link ConsumerListener} to terminate a running
 * {@link Consumer}.
 *
 * @author Tom Erickson
 */
public class ConsumerException extends Exception {
    static final long serialVersionUID = -2125855097525822644L;

    /** @serial */
    private Object notificationObject;

    /**
     * Creates a consumer exception with the given message.
     *
     * @see #ConsumerException(String message, Object
     * dtraceNotificationObject)
     */
    public
    ConsumerException(String message)
    {
	super(message);
    }

    /**
     * Creates an exception thrown by a {@link ConsumerListener}
     * implementation to terminate a running {@link Consumer}, usually
     * in response to a drop or an error reported by the native DTrace
     * library.  Optionally includes the object reported by the native
     * DTrace library so it can be used by an {@link ExceptionHandler}
     * to display details about why the consumer terminated.
     *
     * @param message   default display message explaining why the
     * consumer was terminated.
     * @param notification usually the object passed to a {@link
     * ConsumerListener} from DTrace that prompted this exception.  The
     * notification could be any of the following: <ul> <li>a {@link
     * Drop} passed to {@link ConsumerListener#dataDropped(DropEvent e)
     * dataDropped()}</li> <li>an {@link Error} passed to {@link
     * ConsumerListener#errorEncountered(ErrorEvent e)
     * errorEncountered()}</li> <li>a {@link ProcessState} passed to
     * {@link ConsumerListener#processStateChanged(ProcessEvent e)
     * processStateChanged()}</li> </ul> or it could be a user-defined
     * object that describes anything unexpected in {@link
     * ConsumerListener#dataReceived(DataEvent e) dataReceived()} or
     * that defines an arbitrary error threshold.  An {@link
     * ExceptionHandler} should be defined to handle any type of
     * notification object set by user code.  May be {@code null}.
     * @see Consumer#go(ExceptionHandler h)
     */
    public
    ConsumerException(String message, Object notification)
    {
	super(message);
	notificationObject = notification;
    }

    /**
     * Gets the optional object from the {@link ConsumerListener} that
     * communicates to the {@link ExceptionHandler} why the listener
     * threw this exception.  Usually this is the object from DTrace
     * (such as an {@link org.opensolaris.os.dtrace.Error Error}) that
     * prompted the exception, simply forwarded to the exception
     * handler.
     *
     * @return an object that communicates to the {@link
     * ExceptionHandler} why the {@link ConsumerListener} threw this
     * exception, may be {@code null}
     * @see Consumer#go(ExceptionHandler h)
     * @see #ConsumerException(String message,
     * Object dtraceNotificationObject)
     */
    public Object
    getNotificationObject()
    {
	return notificationObject;
    }
}

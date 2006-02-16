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
 * User-defined application behavior after an exception terminates
 * a running DTrace consumer.  The {@link Consumer} that threw the
 * exception is stopped automatically whether or not an {@code
 * ExceptionHandler} is set, but a handler must be set to do anything
 * other than print a stack trace to {@code stderr}.
 *
 * @see Consumer#go(ExceptionHandler handler)
 *
 * @author Tom Erickson
 */
public interface ExceptionHandler {
    /**
     * Defines what to do after an exception terminates a running {@link
     * Consumer}.  For example, a handler might be implemented to
     * display details about what went wrong.
     *
     * @param e  a {@link DTraceException} if encountered in the native
     * DTrace library, a {@link ConsumerException} if thrown from a
     * {@link ConsumerListener} method to terminate the consumer, or a
     * {@link RuntimeException} to indicate an unexpected error in the
     * Java DTrace API.
     */
    public void handleException(Throwable e);
}

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
 * Indicates that the user has requested something directly or
 * indirectly that exceeds a configured limit.
 *
 * @author Tom Erickson
 */
class ResourceLimitException extends RuntimeException {
    static final long serialVersionUID = -304127017066919362L;

    /**
     * Creates a {@code ResourceLimitException} with the specified
     * detail message.
     *
     * @param message  the detail message pertaining to this exception
     */
    public
    ResourceLimitException(String message)
    {
	super(message);
    }
}

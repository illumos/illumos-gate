/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.common;

import com.sun.dhcpmgr.data.ActionError;

/**
 * This interface is implemented by users of the ImportController to
 * allow it to communicate progress information during the import process.
 * @see ImportController
 */
public interface Importer {
    /**
     * Callback to initialize the importer's progress display
     * @param length The number of steps expected for the import process.
     */
    public void initializeProgress(int length);

    /**
     * Callback to update progress display
     * @param done The number of steps completed.
     * @param message The message corresponding to this step.
     */
    public void updateProgress(int done, String message)
	throws InterruptedException;

    /**
     * Callback to display an error message.
     * @param message The message to display
     */
    public void displayError(String message);

    /**
     * Callback to display a list of error messages.
     * @param msg Message identifying contect for the errors
     * @param label The type of objects for which the errors occurred
     * @param errors An array of ActionError
     */
    public void displayErrors(String msg, String label, ActionError [] errors);
}

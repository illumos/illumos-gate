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
 * This interface is implemented by users of the ExportController to
 * allow it to communicate progress information during the export process.
 * @see ExportController
 */
public interface Exporter {
    /**
     * Callback to initialize the exporter's progress display.
     * @param length The number of steps expected for the export process.
     */
    public void initializeProgress(int length);

    /**
     * Callback to update progress display.
     * @param done The number of steps completed.
     * @param message The message corresponding to this step.
     */
    public void updateProgress(int done, String message)
	throws InterruptedException;

    /**
     * Callback to display a single error message.
     * @param message The message to display.
     */
    public void displayError(String message);

    /**
     * Callback to display a set of errors from the delete process.
     * @param contextMsg Message identifying the context for the errors
     * @param label The type of objects for which the errors occurred
     * @param errs An array of errors to be displayed.
     */
    public void displayErrors(String contextMsg, String label,
	ActionError [] errs);
}

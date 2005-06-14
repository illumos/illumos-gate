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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.ProgressMonitor;
import javax.swing.SwingUtilities;
import java.awt.Component;

/**
 * Provides a framework for doing long-running operations and keeping the
 * user apprised of the results.  Also provides an exception if Cancel is
 * pressed in the progress dialog.
 */
public class ProgressManager {
    private ProgressMonitor monitor;
    private int count;
    private String message;
    private Runnable progressUpdater;
    
    /**
     * Create a new ProgressManager; see ProgressMonitor for description
     * of the parameters here.
     * @see javax.swing.ProgressMonitor
     */
    public ProgressManager(Component comp, Object msg, String note, int min,
            int max) {
	// Initialize count so we can auto-increment
	count = min;
	monitor = new ProgressMonitor(comp, msg, note, min, max);
	// Create background object to update monitor
        progressUpdater = new Runnable() {
            public void run() {
	        monitor.setProgress(count);
	        monitor.setNote(message);
	    }
        };
    }

    /**
     * Update the progress display.  Throws InterruptedException if user
     * has pressed the Cancel button on the progress dialog
     * @param progress the amount of the task that has been completed
     * @param msg the message to be displayed at this time
     * @throws java.lang.InterruptedException
     */
    public void update(int progress, String msg) throws InterruptedException {
        count = progress;
	message = msg;
    	SwingUtilities.invokeLater(progressUpdater);
	if (monitor.isCanceled()) {
	    throw new InterruptedException();
	}
    }

    /**
     * Update the progress display, automatically incrementing the count
     * by one.  Throws InterruptedException if the user has pressed the
     * Cancel button in the progress dialog
     * @param msg the message to be display at this time
     * @throws java.lang.InterruptedException
     */
    public void update(String msg) throws InterruptedException {
	update(count+1, msg);
    }

}

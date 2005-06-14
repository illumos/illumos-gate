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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import javax.swing.SwingUtilities;
import javax.swing.JScrollPane;
import javax.swing.JOptionPane;
import java.awt.Frame;
import java.awt.Dimension;

import com.sun.dhcpmgr.ui.ProgressManager;

/**
 * This abstract class provides a common implementation of the functions
 * shared by the dialogs which perform multiple operations such as adding
 * and deleting addresses or networks.  It provides a framework within
 * which subclasses may execute such operations in a background thread
 * and use progress meters and capture and display multiple error messages.
 * Nearly all of the methods here are defined as protected because they're
 * really implementation details for the dialogs and need not be visible
 * outside that context.
 */
public abstract class MultipleOperationDialog extends DhcpmgrDialog {
    // Progress Manager provides convenient handling of progress dialogs
    protected ProgressManager progManager;
    // ErrorTable provides a convenient storehouse for sets of errors
    protected ErrorTable messageTable;

    public MultipleOperationDialog(Frame f, boolean allowsReset) {
        super(f, allowsReset);
    }

    /**
     * Initiate the action in a background thread when the user presses OK;
     * subclasses should not need to override this, instead they provide
     * an implementation of getOperationThread() where the actions needed
     * are executed.
     */
    protected void doOk() {
        progManager = new ProgressManager(this, getProgressMessage(), "", 0,
            getProgressLength());
	messageTable = new ErrorTable(getErrorHeading(), getErrorClass());
	getOperationThread().start();
    }

    /**
     * Update progress meter; subclasses should call as each operation is
     * completed.  InterruptedException is thrown by the ProgressManager
     * if user pressed Cancel in the progress dialog that was popped up.
     * Typically the subclass should abort its operation thread when this
     * occurs.
     */
    protected void updateProgress(int progress, String msg)
            throws InterruptedException {
	progManager.update(progress, msg);
    }

    /**
     * Get thread which will perform the operation
     */
    protected abstract Thread getOperationThread();

    /**
     * Get message to display in progress dialog
     */
    protected abstract String getProgressMessage();

    /**
     * Get length of operation
     */
    protected abstract int getProgressLength();

    /**
     * Get rid of dialog when we're done
     */
    public void closeDialog() {
    	Runnable finisher = new Runnable() {
	    public void run() {
	        fireActionPerformed();
		setVisible(false);
		dispose();
	    }
	};
	SwingUtilities.invokeLater(finisher);
    }

    /**
     * Display the errors
     */
    protected void displayErrors(final String msg) {
	/*
	 * Use a Runnable and invokeAndWait as we're usually called from
	 * the operation thread, not the AWT thread.
	 */
	Runnable errorDisplay = new Runnable() {
            public void run() {
	   	JScrollPane scrollPane = new JScrollPane(messageTable);
		Dimension d = messageTable.getPreferredScrollableViewportSize();
		d.height = 80;
		messageTable.setPreferredScrollableViewportSize(d);
		Object [] objs = new Object[] { msg, scrollPane };
		JOptionPane.showMessageDialog(MultipleOperationDialog.this,
		    objs, ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	};
	try {
	    SwingUtilities.invokeAndWait(errorDisplay);
	} catch (Throwable e) {
	    // If this failed we're basically in a bailout situation
	    e.printStackTrace();
	}
    }

    /**
     * Return the heading for the error table
     */
    protected abstract String getErrorHeading();

    /**
     * Return the class for the error data; default to String, subclass can
     * override as needed.
     */
    protected Class getErrorClass() {
        return String.class;
    }

    /**
     * Add an error to the error table; obj must be of the class returned by
     * getErrorClass
     */
    protected void addError(Object obj, String msg) {
        messageTable.addError(obj, msg);
    }

    /**
     * Test for errors occurred
     */
    protected boolean errorsOccurred() {
    	return !messageTable.isEmpty();
    }
}

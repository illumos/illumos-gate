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
package com.sun.dhcpmgr.client;

import java.awt.*;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.event.*;

import com.sun.dhcpmgr.ui.*;

/**
 * This class provides a skeletal implementation of a SUNW data store
 * module to minimize the effort required to implement a SUNW data store.
 */
public abstract class SUNWModule extends DSModule {

    /**
     * The default path for the module.
     */
    protected String path;

    /**
     * The description for the module.
     */
    protected String description;

    /**
     * The component for the module.
     */
    protected Box box;

    /**
     * The text field from which to retrieve the path.
     */
    protected JTextField directory;

    /**
     * The datastore specific stuff.
     */
    protected String additionalInfo = null;

    // Defined in DSModule.
    //
    public String getDescription() {
	return description;
    } // getDescription

    // Defined in DSModule.
    //
    public Component getComponent() {
	return box;
    } // getComponent

    // Defined in DSModule.
    //
    public String getPath() {
	return directory.getText();
    } // getPath

    // Defined in DSModule.
    //
    public String getAdditionalInfo() {
	return additionalInfo;
    } // getAdditionalInfo

    /**
     * This class implements a listener for the directory text field and sets
     * the foward enabled button when the text field is valid (non-empty).
     */
    protected class PathListener implements DocumentListener {

	/**
	 * Empty constructor.
	 */
	public PathListener() {
	} // constructor

	/**
	 * Called when a text update occurs in the text field.
	 * @param e the event.
	 */
	public void insertUpdate(DocumentEvent e) {
	    Document doc = e.getDocument();
	    int length = doc.getLength();
	    if (length == 0 && getForwardEnabled()) {
		setForwardEnabled(false);
	    } else if (length != 0 && !getForwardEnabled()) {
		setForwardEnabled(true);
	    }
	} // insertUpdate

	/**
	 * Called when a text change occurs in the text field.
	 * @param e the event.
	 */
	public void changedUpdate(DocumentEvent e) {
	    insertUpdate(e);
	} // changedUpdate

	/**
	 * Called when a text remove occurs in the text field.
	 * @param e the event.
	 */	public void removeUpdate(DocumentEvent e) {
	    insertUpdate(e);
	} // insertUpdate

    } // PathListener

} // SUNWModule

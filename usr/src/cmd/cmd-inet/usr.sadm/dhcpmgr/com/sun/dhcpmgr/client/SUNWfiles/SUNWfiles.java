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
package com.sun.dhcpmgr.client.SUNWfiles;

import java.awt.*;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.event.*;

import com.sun.dhcpmgr.client.*;
import com.sun.dhcpmgr.ui.*;

/**
 * This class makes the SUNWfiles data store manageable by the dhcpmgr.
 */
public class SUNWfiles extends SUNWModule {

    private static final String DEFAULT_PATH = "/var/dhcp";

    /**
     * The constructor for the SUNWfiles module.
     */
    public SUNWfiles() {

	// Initialize the path and description attributes.
	//
	path =  new String(DEFAULT_PATH);
	description = ResourceStrings.getString("description");

	box = Box.createVerticalBox();

	// Explanatory text.
	//
	JComponent c = Wizard.createTextArea(
	    ResourceStrings.getString("explanation"), 3, 45);
	box.add(c);
	box.add(Box.createVerticalStrut(5));

	// Path entry field.
	//
	JPanel fieldPanel = new JPanel(new FieldLayout());
	fieldPanel.add(FieldLayout.LABEL,
	    new JLabel(ResourceStrings.getString("path_label")));
	directory = new JTextField(path, 20);
	fieldPanel.add(FieldLayout.FIELD, directory);
	box.add(fieldPanel);

	// Add a listener to set forward button (or not).
	//
	directory.getDocument().addDocumentListener(new PathListener());

	// By default forward button is enabled for this data store.
	//
	setForwardEnabled(true);

    } // constructor

} // SUNWfiles

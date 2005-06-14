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
package com.sun.dhcpmgr.client.SUNWnisplus;

import java.awt.*;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.event.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.client.*;
import com.sun.dhcpmgr.ui.*;

/**
 * This class makes the SUNWnisplus data store manageable by the dhcpmgr.
 */
public class SUNWnisplus extends SUNWModule {

    /**
     * The constructor for the SUNWnisplus module.
     */
    public SUNWnisplus() {

	// Initialize the path and description attributes.
	//
	try {
	    DhcpServiceMgr svr = DataManager.get().getDhcpServiceMgr();
	    path = svr.getStringOption(StandardOptions.CD_NISPLUS_DMAIN, "");
	} catch (Throwable e) {
	    path = new String("");
	}
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

} // SUNWnisplus

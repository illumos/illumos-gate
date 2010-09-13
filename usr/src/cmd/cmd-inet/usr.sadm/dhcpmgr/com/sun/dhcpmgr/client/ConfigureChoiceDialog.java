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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.event.*;
import java.awt.*;

import com.sun.dhcpmgr.ui.*;

/**
 * Dialog to select which type of server we want: full DHCP or just a BOOTP
 * relay. This is implemented as a singleton modal so the caller can't do
 * anything until it returns a selection.
 */
public class ConfigureChoiceDialog extends JDialog
	implements ButtonPanelListener {
    private ButtonPanel buttonPanel;
    private ButtonGroup buttonGroup;
    private JRadioButton dhcp, bootp;
    /**
     * Returned if user decides choice is "none of the above"
     */
    public static final int CANCELLED = 0;
    /**
     * Return value if user wants DHCP service
     */
    public static final int DHCP = 1;
    /**
     * Return value if user wants BOOTP relay
     */
    public static final int BOOTP = 2;
    private static int value = CANCELLED;
    
    // Must use the showDialog method to get one of these.
    private ConfigureChoiceDialog(Frame f) {
	super(f, true);
	setTitle(ResourceStrings.getString("configure_choice_title"));
	setLocationRelativeTo(f);

	getContentPane().setLayout(new BorderLayout());
	
	JPanel panel = new JPanel(new BorderLayout());
	panel.setBorder(
	    BorderFactory.createCompoundBorder(
	    BorderFactory.createEtchedBorder(), 
	    BorderFactory.createEmptyBorder(10, 20, 10, 20)));
	
	// Explanatory text at the top
	panel.add(Wizard.createTextArea(
	    ResourceStrings.getString("configure_choice_explain"), 5, 30), 
	    BorderLayout.NORTH);
	
	// Just show the choices as a set of radio buttons
	buttonGroup = new ButtonGroup();
	dhcp = new JRadioButton(
	    ResourceStrings.getString("configure_dhcp_server"), true);
	dhcp.setToolTipText(ResourceStrings.getString("configure_dhcp_server"));
	buttonGroup.add(dhcp);
	Box box = Box.createVerticalBox();
	box.add(dhcp);
	box.add(Box.createVerticalStrut(5));
	bootp = new JRadioButton(
	    ResourceStrings.getString("configure_bootp_relay"), false);
	bootp.setToolTipText(
	    ResourceStrings.getString("configure_bootp_relay"));
	buttonGroup.add(bootp);
	box.add(bootp);
	panel.add(box, BorderLayout.SOUTH);
	getContentPane().add(panel, BorderLayout.NORTH);
	
	buttonPanel = new ButtonPanel(false);
	buttonPanel.addButtonPanelListener(this);
	buttonPanel.setOkEnabled(true);
	getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }
    
    public void buttonPressed(int buttonId) {
	switch (buttonId) {
	case OK:
	    if (dhcp.isSelected()) {
		value = DHCP;
	    } else {
		value = BOOTP;
	    }
	    setVisible(false);
	    break;
	case CANCEL:
	    value = CANCELLED;
	    setVisible(false);
	    break;
	case HELP:
	    DhcpmgrApplet.showHelp("server_config");
	    break;
	}
    }
    
    public static int showDialog(Frame f) {
	ConfigureChoiceDialog d = new ConfigureChoiceDialog(f);
	d.pack();
	d.setVisible(true);
	d.dispose();
	return value;
    }
}

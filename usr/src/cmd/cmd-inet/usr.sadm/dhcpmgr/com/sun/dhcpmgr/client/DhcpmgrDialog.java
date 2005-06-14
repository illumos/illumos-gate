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

import javax.swing.JDialog;
import javax.swing.BoxLayout;
import javax.swing.JSeparator;
import javax.swing.JPanel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Frame;
import java.util.Vector;
import java.util.Enumeration;

import com.sun.dhcpmgr.ui.ButtonPanel;
import com.sun.dhcpmgr.ui.ButtonPanelListener;

/**
 * This abstract class provides a framework for building all of the dialogs
 * used by DHCP Mgr.  Subclasses must implement the abstract methods defined
 * here as well as override any other appropriate methods.  Most of these
 * methods are declared protected because they are implementation details
 * which need not be visible outside the dialog we're actually implementing.
 */
public abstract class DhcpmgrDialog extends JDialog
	implements ButtonPanelListener {
    // Listeners receive action events when user presses OK
    private Vector listeners;
    // ButtonPanel is protected so subclasses can manipulate directly
    protected ButtonPanel buttonPanel;

    public DhcpmgrDialog(Frame f, boolean allowsReset) {
        super(f);
        listeners = new Vector();
	// Layout is subclass main panel, then a separator, then buttons
	getContentPane().setLayout(new BoxLayout(getContentPane(),
	    BoxLayout.Y_AXIS));
	// Create buttonPanel first so subclasses can modify it if need be
	buttonPanel = new ButtonPanel(allowsReset);
	buttonPanel.addButtonPanelListener(this);
	getContentPane().add(getMainPanel());
	getContentPane().add(new JSeparator());
	getContentPane().add(buttonPanel);
	// Position relative to our owning frame
	setLocationRelativeTo(f);
    }

    /**
     * Return the main display panel
     */
    protected abstract JPanel getMainPanel();

    public void addActionListener(ActionListener l) {
	listeners.addElement(l);
    }
    
    public void removeActionListener(ActionListener l) {
	listeners.removeElement(l);
    }
    
    /**
     * fire the action event
     */
    protected abstract void fireActionPerformed();

    protected void fireActionPerformed(Object source, String command) {
	ActionEvent e = new ActionEvent(source, ActionEvent.ACTION_PERFORMED,
	    command);
	Enumeration en = listeners.elements();
	while (en.hasMoreElements()) {
	    ActionListener l = (ActionListener)en.nextElement();
	    l.actionPerformed(e);
	}
    }

    /**
     * Handle user clicks on the dialog buttons
     */
    public void buttonPressed(int buttonId) {
        switch (buttonId) {
	case OK:
	    doOk();
	    break;
	case CANCEL:
	    doCancel();
	    break;
	case HELP:
	    doHelp();
	    break;
	case RESET:
	    doReset();
	    break;
	default:
	    break;
	 }
    }

    /**
     * Handle user pressing OK button
     */
    protected abstract void doOk();

    /**
     * Handle user pressing Cancel button, default is to disappear
     */
    protected void doCancel() {
    	setVisible(false);
	dispose();
    }

    /**
     * Handle user pressing Reset; this default implementation does
     * nothing, subclasses should override.
     */
    protected void doReset() {
    	// Do nothing
    }

    /**
     * Handle user pressing Help
     */
    protected void doHelp() {
        DhcpmgrApplet.showHelp(getHelpKey());
    }

    /**
     * Return the help key
     */
    protected abstract String getHelpKey();
}

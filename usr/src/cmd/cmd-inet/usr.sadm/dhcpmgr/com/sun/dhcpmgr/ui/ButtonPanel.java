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
 * Copyright 1998-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.*;
import java.awt.event.*;
import java.util.*;

/**
 * A simple panel with the buttons commonly used in a dialog.  Register as
 * a ButtonPanelListener in order to receive the events from this class.
 * @see ButtonPanelListener
 */
public class ButtonPanel extends JPanel {

    // Convert action events on each button to button panel notifications 
    class ButtonAdaptor implements ActionListener {
	public void actionPerformed(ActionEvent e) {
	    int buttonId = -1;
	    Object source = e.getSource();
	    if (source == okButton) {
		buttonId = ButtonPanelListener.OK;
	    } else if (source == resetButton) {
		buttonId = ButtonPanelListener.RESET;
	    } else if (source == cancelButton) {
		buttonId = ButtonPanelListener.CANCEL;
	    } else if (source == helpButton) {
		buttonId = ButtonPanelListener.HELP;
	    }
	    Enumeration en = listeners.elements();
	    while (en.hasMoreElements()) {
		ButtonPanelListener l = (ButtonPanelListener)en.nextElement();
		l.buttonPressed(buttonId);
	    }
	}
    }
    
    JButton okButton, resetButton, cancelButton, helpButton;
    ButtonAdaptor adaptor;
    Vector listeners;
    
    /**
     * Construct a ButtonPanel with OK, Cancel, and Help buttons, and
     * the reset button display controlled by the parameter.
     * @param showReset true if Reset button is to be included
     */
    public ButtonPanel(boolean showReset) {
    	this(showReset, true);
    }

    /**
     * Construct a ButtonPanel with reset and help buttons controlled
     * by the parameters passed, and always showing OK and Cancel.
     * @param showReset true if Reset button is to be included
     * @param showHelp true if Help button is to be included
     */
    public ButtonPanel(boolean showReset, boolean showHelp) {
	super();
	setLayout(new ButtonLayout(ALIGNMENT.RIGHT));
	// Create event handler
	adaptor = new ButtonAdaptor();
	listeners = new Vector();

	Mnemonic mn = new Mnemonic(ResourceStrings.getString("ok_button"));	
	okButton = new JButton(mn.getString());
	okButton.setToolTipText(mn.getString());
	okButton.setMnemonic(mn.getMnemonic());

	okButton.setEnabled(false);
	okButton.addActionListener(adaptor);
	add(okButton);
	
	// Only show reset if requested
	if (showReset) {
	    Mnemonic mnReset = 
		new Mnemonic(ResourceStrings.getString("reset_button"));
	    resetButton = new JButton(mnReset.getString());
	    resetButton.setToolTipText(mnReset.getString());
	    resetButton.setMnemonic(mnReset.getMnemonic());

	    resetButton.addActionListener(adaptor);
	    add(resetButton);
	} else {
	    resetButton = null;
	}

	Mnemonic mnCancel = 
	    new Mnemonic(ResourceStrings.getString("cancel_button"));
        cancelButton = new JButton(mnCancel.getString());
        cancelButton.setToolTipText(mnCancel.getString());
        cancelButton.setMnemonic(mnCancel.getMnemonic());

	cancelButton.addActionListener(adaptor);
	add(cancelButton);
	
	if (showHelp) {
	    Mnemonic mnHelp = 
		new Mnemonic(ResourceStrings.getString("help_button"));
            helpButton = new JButton(mnHelp.getString());
            helpButton.setToolTipText(mnHelp.getString());
            helpButton.setMnemonic(mnHelp.getMnemonic());

	    helpButton.addActionListener(adaptor);
	    add(helpButton);
	} else {
	    helpButton = null;
	}
    }
    
    public void addButtonPanelListener(ButtonPanelListener l) {
	listeners.addElement(l);
    }
    
    public void removeButtonPanelListener(ButtonPanelListener l) {
	listeners.removeElement(l);
    }
    
    public void setOkEnabled(boolean state) {
	okButton.setEnabled(state);
    }
    
    public boolean isOkEnabled() {
	return okButton.isEnabled();
    }

}
